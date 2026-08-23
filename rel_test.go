package hopper

import (
	"context"
	"slices"
	"strings"
	"testing"
)

// The SQL literal list and the Go predicate must classify every rel identically;
// they are two spellings of one rule, and a drift between them would silently
// change what queries mean without failing a build.
func TestContainmentRelsSQLMatchesPredicate(t *testing.T) {
	all := []Rel{RelContained, RelUnpacked, RelFetched, RelRegistry}
	inSQL := func(r Rel) bool {
		return slices.Contains(strings.Split(strings.Trim(containmentRelsSQL, "()"), ", "), "'"+string(r)+"'")
	}
	for _, r := range all {
		if r.IsContainment() != inSQL(r) {
			t.Errorf("rel %q: IsContainment()=%v but SQL membership=%v",
				r, r.IsContainment(), inSQL(r))
		}
	}
}

// KnownSHA256 answers "can you produce these bytes", not "do you have a row".
// The distinction is the whole point: a producer that hears "known" never sends
// the bytes, so a wrong yes loses them permanently while a wrong no costs one
// redundant upload.
func TestKnownSHA256ReportsOnlyRetrievableBytes(t *testing.T) {
	ctx := context.Background()
	db := openTestDB(t)

	const (
		topLevel  = "a1" + "00000000000000000000000000000000000000000000000000000000000000"
		archive   = "b2" + "00000000000000000000000000000000000000000000000000000000000000"
		member    = "c3" + "00000000000000000000000000000000000000000000000000000000000000"
		dep       = "d4" + "00000000000000000000000000000000000000000000000000000000000000"
		gone      = "e5" + "00000000000000000000000000000000000000000000000000000000000000"
		neverSeen = "f6" + "00000000000000000000000000000000000000000000000000000000000000"
	)

	// A standalone artifact with its own bytes on disk.
	mustInsert(t, ctx, db, &Sample{SHA256: topLevel, Path: "unknown/uploads/a1/00/pkg.tgz"})
	// The archive, and a member genuinely inside it: recoverable by extraction.
	mustInsert(t, ctx, db, &Sample{SHA256: archive, Path: "unknown/foraged/npm/app.tgz"})
	mustInsert(t, ctx, db, &Sample{
		SHA256: member, Path: "unknown/foraged/npm/app.tgz!!lib/index.js",
		Parent: archive, LocationRel: string(RelContained),
	})
	// A dependency the archive merely *named*. Its bytes were never inside the
	// archive, so there is nothing to extract them from — the case that made
	// hopper claim artifacts it had never held.
	mustInsert(t, ctx, db, &Sample{
		SHA256: dep, Path: "unknown/foraged/npm/app.tgz!!evil-1.0.0.tgz",
		Parent: archive, LocationRel: string(RelFetched),
	})
	// Bytes hopper knows are gone from disk.
	mustInsert(t, ctx, db, &Sample{SHA256: gone, Path: "unknown/foraged/npm/vanished.tgz"})
	if err := db.SetSkip(ctx, gone, "missing"); err != nil {
		t.Fatalf("SetSkip: %v", err)
	}

	known, err := db.KnownSHA256(ctx, []string{topLevel, archive, member, dep, gone, neverSeen})
	if err != nil {
		t.Fatalf("KnownSHA256: %v", err)
	}
	has := func(sha string) bool { return slices.Contains(known, sha) }

	for _, tc := range []struct {
		sha, name string
		want      bool
		why       string
	}{
		{topLevel, "top-level", true, "its own bytes are on disk"},
		{archive, "archive", true, "its own bytes are on disk"},
		{member, "contained member", true, "extractable from the archive that contains it"},
		{dep, "fetched dependency", false, "never inside the archive that named it"},
		{gone, "missing", false, "hopper already recorded the bytes as gone"},
		{neverSeen, "absent", false, "no row at all"},
	} {
		if has(tc.sha) != tc.want {
			t.Errorf("%s: known=%v, want %v — %s", tc.name, has(tc.sha), tc.want, tc.why)
		}
	}
}

// depObservation is a fetched dependency as explode sees it: named by an
// archive, never inside it.
func depObservation(sha, archive string) *Sample {
	return &Sample{
		SHA256: sha, Path: "unknown/foraged/npm/app.tgz!!evil-1.0.0.tgz",
		Parent: archive, LocationRel: string(RelFetched),
		Label: "bad", LabelSource: "promoter", // inherited from the archive
	}
}

// Every path that writes a samples row must project through containmentColumns.
// One writer forgetting is how a dependency silently becomes an archive member
// again — invisible to the bloom pool, promoter, cyclotron, and prism's feed —
// so each entry point is covered separately rather than trusting the shared
// helper to be reached.
func TestNoWriterRecordsAReferenceAsAMember(t *testing.T) {
	ctx := context.Background()
	archive := strings.Repeat("a", 64)

	for _, tc := range []struct {
		name  string
		write func(t *testing.T, db *DB, s *Sample)
	}{
		{"InsertSample", func(t *testing.T, db *DB, s *Sample) {
			t.Helper()
			if err := db.InsertSample(ctx, s); err != nil {
				t.Fatalf("InsertSample: %v", err)
			}
		}},
		{"InsertSampleBatch", func(t *testing.T, db *DB, s *Sample) {
			t.Helper()
			if _, _, err := db.InsertSampleBatch(ctx, []*Sample{s}); err != nil {
				t.Fatalf("InsertSampleBatch: %v", err)
			}
		}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			db := openTestDBContext(t, ctx)
			mustInsert(t, ctx, db, &Sample{SHA256: archive, Path: "unknown/foraged/npm/app.tgz"})
			dep := strings.Repeat("d", 64)
			tc.write(t, db, depObservation(dep, archive))

			got, err := db.SampleBySHA256(ctx, dep)
			if err != nil {
				t.Fatalf("SampleBySHA256: %v", err)
			}
			if got.Parent != "" {
				t.Errorf("parent = %q, want \"\" — a reference is contained by nothing", got.Parent)
			}
			if got.Path != "" {
				t.Errorf("path = %q, want \"\" — hopper holds no bytes for it yet", got.Path)
			}

			// The edge still exists: that is what "referenced by" is rendered from.
			locs, err := db.LocationsForSHA(ctx, dep)
			if err != nil || len(locs) != 1 {
				t.Fatalf("LocationsForSHA = %v, %v; want one observation", locs, err)
			}
			if locs[0].ParentSHA256 != archive || locs[0].Rel != string(RelFetched) {
				t.Errorf("edge = parent %q rel %q, want %q/fetched",
					locs[0].ParentSHA256, locs[0].Rel, archive)
			}

			if n, err := db.ContainmentViolations(ctx, 10); err != nil || n != 0 {
				t.Errorf("ContainmentViolations = %d, %v; want 0", n, err)
			}
		})
	}
}

// The repair clears containment columns the ledger doesn't support, and leaves
// genuine members alone. Rows are planted through the DB directly because the
// writers no longer produce this shape — it is the legacy state on disk.
func TestRepairReferenceParentsClearsOnlyReferences(t *testing.T) {
	ctx := context.Background()
	db := openTestDB(t)

	archive := strings.Repeat("a", 64)
	member := strings.Repeat("b", 64)
	dep := strings.Repeat("d", 64)
	mustInsert(t, ctx, db, &Sample{SHA256: archive, Path: "unknown/foraged/npm/app.tgz"})
	mustInsert(t, ctx, db, &Sample{
		SHA256: member, Path: "unknown/foraged/npm/app.tgz!!lib/index.js",
		Parent: archive, LocationRel: string(RelContained), Label: "bad", LabelSource: "promoter",
	})
	mustInsert(t, ctx, db, depObservation(dep, archive))

	// Re-damage the dependency row the way pre-fix explode left it, bypassing
	// the writers so the repair has something to find.
	if _, err := db.lite.ExecContext(ctx,
		`UPDATE samples SET parent = ?, path = ?, label = 'bad', label_source = 'promoter' WHERE sha256 = ?`,
		archive, "unknown/foraged/npm/app.tgz!!evil-1.0.0.tgz", dep); err != nil {
		t.Fatalf("plant damaged row: %v", err)
	}
	if n, err := db.ContainmentViolations(ctx, 10); err != nil || n != 1 {
		t.Fatalf("ContainmentViolations before repair = %d, %v; want 1", n, err)
	}

	// Clear the done marker the migration set at open, so the repair runs here.
	if _, err := db.lite.ExecContext(ctx, `DELETE FROM hopper_kv WHERE key LIKE 'repair:samples:%'`); err != nil {
		t.Fatalf("clear marker: %v", err)
	}
	if err := db.repairReferenceParents(ctx); err != nil {
		t.Fatalf("repairReferenceParents: %v", err)
	}

	repaired, err := db.SampleBySHA256(ctx, dep)
	if err != nil {
		t.Fatalf("SampleBySHA256(dep): %v", err)
	}
	if repaired.Parent != "" || repaired.Path != "" {
		t.Errorf("dep after repair: parent=%q path=%q, want both empty", repaired.Parent, repaired.Path)
	}
	// An inherited label is the dangerous leftover: a "good" carried over from
	// the archive would promote a dependency nobody vouched for into the
	// known-good bloom, and a known-good coordinate is never fetched again.
	if repaired.Label != "unknown" || repaired.LabelSource != "" {
		t.Errorf("dep after repair: label=%q source=%q, want unknown/\"\"",
			repaired.Label, repaired.LabelSource)
	}

	kept, err := db.SampleBySHA256(ctx, member)
	if err != nil {
		t.Fatalf("SampleBySHA256(member): %v", err)
	}
	if kept.Parent != archive {
		t.Errorf("contained member parent = %q, want %q — genuine containment is untouched", kept.Parent, archive)
	}
	if kept.Label != "bad" {
		t.Errorf("contained member label = %q, want bad — inheritance is legitimate for a member", kept.Label)
	}

	if n, err := db.ContainmentViolations(ctx, 10); err != nil || n != 0 {
		t.Errorf("ContainmentViolations after repair = %d, %v; want 0", n, err)
	}
}

// A damaged row whose path was healed to real bytes on disk keeps that path.
// The upload that landed after explode froze parent repaired path but could not
// repair parent (it is absent from the ON CONFLICT SET list), so these rows have
// a valid byte pointer and a wrong containment claim. Clearing both would strand
// bytes hopper actually holds — and KnownSHA256 would then report them unknown
// forever, so nothing would ever serve them.
func TestRepairKeepsRealPathsAndClearsVirtualOnes(t *testing.T) {
	ctx := context.Background()
	db := openTestDB(t)

	archive := strings.Repeat("a", 64)
	healed := strings.Repeat("e", 64)
	virtual := strings.Repeat("f", 64)
	mustInsert(t, ctx, db, &Sample{SHA256: archive, Path: "unknown/foraged/npm/app.tgz"})
	for _, sha := range []string{healed, virtual} {
		mustInsert(t, ctx, db, &Sample{
			SHA256: sha, Path: "unknown/foraged/npm/app.tgz!!dep.tgz",
			Parent: archive, LocationRel: string(RelFetched),
		})
	}

	// Plant the two damaged shapes explode leaves behind.
	if _, err := db.lite.ExecContext(ctx,
		`UPDATE samples SET parent = ?, path = ? WHERE sha256 = ?`,
		archive, "unknown/uploads/ee/ee/dep.tgz", healed); err != nil {
		t.Fatalf("plant healed row: %v", err)
	}
	if _, err := db.lite.ExecContext(ctx,
		`UPDATE samples SET parent = ?, path = ? WHERE sha256 = ?`,
		archive, "unknown/foraged/npm/app.tgz!!dep.tgz", virtual); err != nil {
		t.Fatalf("plant virtual row: %v", err)
	}
	if _, err := db.lite.ExecContext(ctx, `DELETE FROM hopper_kv WHERE key LIKE 'repair:samples:%'`); err != nil {
		t.Fatalf("clear marker: %v", err)
	}
	if err := db.repairReferenceParents(ctx); err != nil {
		t.Fatalf("repairReferenceParents: %v", err)
	}

	got, err := db.SampleBySHA256(ctx, healed)
	if err != nil {
		t.Fatalf("SampleBySHA256(healed): %v", err)
	}
	if got.Path != "unknown/uploads/ee/ee/dep.tgz" {
		t.Errorf("healed row path = %q, want the real disk path preserved", got.Path)
	}
	if got.Parent != "" {
		t.Errorf("healed row parent = %q, want cleared", got.Parent)
	}

	gotVirtual, err := db.SampleBySHA256(ctx, virtual)
	if err != nil {
		t.Fatalf("SampleBySHA256(virtual): %v", err)
	}
	if gotVirtual.Path != "" {
		t.Errorf("virtual row path = %q, want cleared — nothing can extract it", gotVirtual.Path)
	}
}

// The feed lists artifacts, and a fetched dependency is one: some package named
// it, but nothing contains it. It was excluded because TopLevelOnly rejected any
// row with a parented edge, which is the same conflation — an edge is not
// containment. A contained archive member stays out, since it has no identity
// apart from the archive that holds it.
func TestFeedListsDependenciesButNotArchiveMembers(t *testing.T) {
	ctx := context.Background()
	db := openTestDB(t)

	archive := strings.Repeat("a", 64)
	member := strings.Repeat("b", 64)
	dep := strings.Repeat("d", 64)

	mustInsert(t, ctx, db, &Sample{SHA256: archive, Path: "unknown/foraged/npm/app.tgz"})
	mustInsert(t, ctx, db, &Sample{
		SHA256: member, Path: "unknown/foraged/npm/app.tgz!!lib/index.js",
		Parent: archive, LocationRel: string(RelContained),
	})
	mustInsert(t, ctx, db, &Sample{
		SHA256: dep, Path: "unknown/uploads/dd/dd/evil-1.0.0.tgz",
		Parent: archive, LocationRel: string(RelFetched),
	})
	for _, sha := range []string{archive, member, dep} {
		mustAnalyze(t, ctx, db, sha, 1)
	}

	rows, err := db.FeedSamples(ctx, &FeedQuery{TopLevelOnly: true, Limit: 50})
	if err != nil {
		t.Fatalf("FeedSamples: %v", err)
	}
	listed := map[string]bool{}
	for _, r := range rows {
		listed[r.SHA256] = true
	}

	if !listed[dep] {
		t.Error("fetched dependency missing from the feed — it is an artifact in its own right")
	}
	if !listed[archive] {
		t.Error("archive missing from the feed")
	}
	if listed[member] {
		t.Error("contained member listed — it has no identity apart from its archive")
	}
}

// KnownSHA256Versions is the currency half of the /api/known contract: each
// known digest carries its stored traits_version so a dependency-mirroring
// worker can skip re-posting verdicts hopper already holds at the same
// analyzer version. The retrievability rules are identical to KnownSHA256
// (same query), so this test pins only the version attachment: an analyzed
// sample reports its version, an unanalyzed one reports "", and a
// non-retrievable or absent sha stays out of the map entirely.
func TestKnownSHA256VersionsAttachesTraitsVersion(t *testing.T) {
	ctx := context.Background()
	db := openTestDB(t)

	const (
		analyzed   = "aa" + "00000000000000000000000000000000000000000000000000000000000000"
		unanalyzed = "bb" + "00000000000000000000000000000000000000000000000000000000000000"
		absent     = "cc" + "00000000000000000000000000000000000000000000000000000000000000"
	)
	mustInsert(t, ctx, db, &Sample{SHA256: analyzed, Path: "unknown/uploads/aa/00/a.tgz"})
	mustInsert(t, ctx, db, &Sample{SHA256: unanalyzed, Path: "unknown/uploads/bb/00/b.tgz"})
	if _, err := db.lite.ExecContext(ctx,
		`UPDATE samples SET traits_version = 'abc12' WHERE sha256 = ?`, analyzed); err != nil {
		t.Fatalf("set traits_version: %v", err)
	}

	got, err := db.KnownSHA256Versions(ctx, []string{analyzed, unanalyzed, absent})
	if err != nil {
		t.Fatalf("KnownSHA256Versions: %v", err)
	}
	if len(got) != 2 {
		t.Fatalf("got %d entries (%v), want exactly the two retrievable samples", len(got), got)
	}
	if got[analyzed] != "abc12" {
		t.Errorf("analyzed sample version = %q, want abc12", got[analyzed])
	}
	if v, ok := got[unanalyzed]; !ok || v != "" {
		t.Errorf("unanalyzed sample = (%q, %v), want present with empty version", v, ok)
	}
	if _, ok := got[absent]; ok {
		t.Error("absent sha reported known")
	}
}
