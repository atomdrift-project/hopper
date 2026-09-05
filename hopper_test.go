package hopper

import (
	"bytes"
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"
	"time"
)

func openTestDB(t *testing.T) *DB {
	t.Helper()
	return openTestDBContext(t, context.Background())
}

func openTestDBContext(t *testing.T, ctx context.Context) *DB {
	t.Helper()
	db, err := Open(ctx, filepath.Join(t.TempDir(), "test.db"), "hopper-test")
	if err != nil {
		t.Fatalf("Open: %v", err)
	}
	if err := db.Migrate(ctx); err != nil {
		t.Fatalf("Migrate: %v", err)
	}
	t.Cleanup(func() { db.Close() })
	return db
}

func mustInsert(t *testing.T, ctx context.Context, db *DB, s *Sample) {
	t.Helper()
	// The insert layer rejects samples with empty paths. Many existing
	// tests build minimal Sample literals without a Path; give them a
	// synthetic one derived from the sha so they still exercise the DB
	// without needing every test updated.
	if s.Path == "" {
		s.Path = "test/" + s.SHA256
	}
	if err := db.InsertSample(ctx, s); err != nil {
		t.Fatalf("InsertSample: %v", err)
	}
}

func mustAnalyze(t *testing.T, ctx context.Context, db *DB, sha string, score int) {
	t.Helper()
	mustAnalyzeWithTraits(t, ctx, db, sha, score, "")
}

// mustAnalyzeWithTraits is mustAnalyze plus an optional comma-separated list
// of trait literals (e.g. `{"l":5,"c":1.0}`) inserted into the depth-0 entry.
func mustAnalyzeWithTraits(t *testing.T, ctx context.Context, db *DB, sha string, score int, traits string) {
	t.Helper()
	// Include a non-empty type so UpdateCleaveResult actually persists the row;
	// an empty type triggers the belt-and-suspenders delete path.
	result := fmt.Appendf(nil, `{"fs":[{"sha":%q,"type":"elf","x":%d,"dp":0,"ts":[%s]}]}`, sha, score, traits)
	if err := db.UpdateCleaveResult(ctx, sha, result, nil, ""); err != nil {
		t.Fatalf("UpdateCleaveResult: %v", err)
	}
}

func TestMembersByParentAndSamplesBySHAs(t *testing.T) {
	ctx := context.Background()
	db := openTestDB(t)

	const archive = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
	// Three members of one archive, distinct scores (generated from fs[0].x).
	// Paths are this archive's member locations; member() builds a row that
	// InsertSampleBatch fans out into both samples and sample_locations.
	member := func(sha string, score int) *Sample {
		return &Sample{
			SHA256:       sha,
			Source:       "test",
			Label:        "bad",
			LabelSource:  "test",
			Parent:       archive,
			Path:         archive + "!!pkg/" + sha[:4] + ".js",
			CleaveResult: fmt.Appendf(nil, `{"fs":[{"sha":%q,"type":"js","x":%d,"dp":1}]}`, sha, score),
		}
	}
	m1 := "1111111111111111111111111111111111111111111111111111111111111111"
	m2 := "2222222222222222222222222222222222222222222222222222222222222222"
	m3 := "3333333333333333333333333333333333333333333333333333333333333333"
	if _, _, err := db.InsertSampleBatch(ctx, []*Sample{member(m1, 30), member(m2, 90), member(m3, 60)}); err != nil {
		t.Fatalf("InsertSampleBatch: %v", err)
	}

	// Capped list: highest score first, total reflects every member.
	members, total, err := db.MembersByParent(ctx, archive, 2)
	if err != nil {
		t.Fatalf("MembersByParent: %v", err)
	}
	if total != 3 {
		t.Errorf("total = %d, want 3", total)
	}
	if len(members) != 2 {
		t.Fatalf("len(members) = %d, want 2 (capped)", len(members))
	}
	if members[0].SHA256 != m2 || members[1].SHA256 != m3 {
		t.Errorf("order = [%s, %s], want highest-score-first [m2(90), m3(60)]", members[0].SHA256[:4], members[1].SHA256[:4])
	}
	if members[0].Score != 90 || members[0].FileType != "js" {
		t.Errorf("member[0] = score %d type %q, want score 90 type js", members[0].Score, members[0].FileType)
	}
	if members[0].Path != archive+"!!pkg/2222.js" {
		t.Errorf("member[0].Path = %q, want the per-archive location", members[0].Path)
	}

	// Light listing must not load the heavy blob; the heavy fetch must.
	heavy, err := db.SamplesBySHAs(ctx, []string{m1, m2})
	if err != nil {
		t.Fatalf("SamplesBySHAs: %v", err)
	}
	if len(heavy) != 2 {
		t.Fatalf("len(heavy) = %d, want 2", len(heavy))
	}
	for _, s := range heavy {
		if len(s.CleaveResult) == 0 {
			t.Errorf("SamplesBySHAs(%s) returned empty CleaveResult", s.SHA256[:4])
		}
	}

	// An archive with no members yields nothing, not an error.
	none, total, err := db.MembersByParent(ctx, m1, 10)
	if err != nil {
		t.Fatalf("MembersByParent(no members): %v", err)
	}
	if total != 0 || len(none) != 0 {
		t.Errorf("no-member parent: total=%d members=%d, want 0/0", total, len(none))
	}
}

func TestMembersWithSamplesAndParentArchives(t *testing.T) {
	ctx := context.Background()
	db := openTestDB(t)

	const arc1 = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
	const arc2 = "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb"
	member := func(sha, parent string, score int) *Sample {
		return &Sample{
			SHA256:       sha,
			Source:       "test",
			Label:        "bad",
			LabelSource:  "test",
			Parent:       parent,
			Path:         parent + "!!pkg/" + sha[:4] + ".js",
			CleaveResult: fmt.Appendf(nil, `{"fs":[{"sha":%q,"type":"js","x":%d,"dp":1}]}`, sha, score),
		}
	}
	m1 := "1111111111111111111111111111111111111111111111111111111111111111"
	m2 := "2222222222222222222222222222222222222222222222222222222222222222"
	m3 := "3333333333333333333333333333333333333333333333333333333333333333"
	// arc1 as a real sample row (so the parent-archive join resolves) plus three
	// members; m1 is also a member of arc2 so the backlink dedup is exercised.
	arc1Sample := &Sample{SHA256: arc1, Source: "test", Label: "bad", LabelSource: "test", Filename: "evil.zip", Path: "/feeds/evil.zip"}
	arc2Sample := &Sample{SHA256: arc2, Source: "test", Label: "bad", LabelSource: "test", Filename: "evil2.zip", Path: "/feeds/evil2.zip"}
	if _, _, err := db.InsertSampleBatch(ctx, []*Sample{
		arc1Sample, arc2Sample, member(m1, arc1, 30), member(m2, arc1, 90), member(m3, arc1, 60), member(m1, arc2, 30),
	}); err != nil {
		t.Fatalf("InsertSampleBatch: %v", err)
	}

	// Top-N by score, hydrated with heavy blobs, plus a linked member that scores
	// below the cap but must still be included.
	got, err := db.MembersWithSamplesByParent(ctx, arc1, 2, []string{m1}, nil)
	if err != nil {
		t.Fatalf("MembersWithSamplesByParent: %v", err)
	}
	shas := map[string]bool{}
	for _, s := range got {
		shas[s.SHA256] = true
		if len(s.CleaveResult) == 0 {
			t.Errorf("member %s returned empty CleaveResult; heavy blob must be hydrated", s.SHA256[:4])
		}
	}
	if !shas[m2] || !shas[m3] {
		t.Errorf("top-2 by score missing: got %v, want m2(90)+m3(60)", keys(shas))
	}
	if !shas[m1] {
		t.Errorf("linked member m1 dropped despite below-cap score; got %v", keys(shas))
	}

	// No edges for this parent: the fallback SHAs hydrate instead (un-backfilled
	// archive path), still one query.
	fb, err := db.MembersWithSamplesByParent(ctx, m1, 2, nil, []string{m2})
	if err != nil {
		t.Fatalf("MembersWithSamplesByParent(fallback): %v", err)
	}
	if len(fb) != 1 || fb[0].SHA256 != m2 {
		t.Errorf("fallback = %v, want [m2]", keys2(fb))
	}

	// Backlinks: m1 belongs to arc1 and arc2; arc1 resolves to its sample row,
	// each parent appears once.
	refs, err := db.ParentArchivesForChild(ctx, m1, 10)
	if err != nil {
		t.Fatalf("ParentArchivesForChild: %v", err)
	}
	seen := map[string]hopperParentRefView{}
	for _, r := range refs {
		if _, dup := seen[r.SHA256]; dup {
			t.Errorf("parent %s returned more than once; dedup failed", r.SHA256[:4])
		}
		seen[r.SHA256] = hopperParentRefView{filename: r.Filename, childPath: r.Path}
	}
	if len(seen) != 2 {
		t.Fatalf("parents = %d, want 2 (arc1+arc2)", len(seen))
	}
	if seen[arc1].filename != "evil.zip" {
		t.Errorf("arc1 filename = %q, want evil.zip", seen[arc1].filename)
	}
	if seen[arc1].childPath != arc1+"!!pkg/1111.js" {
		t.Errorf("arc1 child path = %q, want m1's location within arc1", seen[arc1].childPath)
	}
}

type hopperParentRefView struct{ filename, childPath string }

func keys(m map[string]bool) []string {
	out := make([]string, 0, len(m))
	for k := range m {
		out = append(out, k[:4])
	}
	return out
}

func keys2(ss []*Sample) []string {
	out := make([]string, 0, len(ss))
	for _, s := range ss {
		out = append(out, s.SHA256[:4])
	}
	return out
}

// TestExplodeRefreshesStaleMember locks the freshness-gated refresh: a file
// first analyzed standalone (or by an older archive) keeps a stale result that
// ON CONFLICT would freeze, but a newer archive that re-analyzes the same
// content supersedes it — while an older archive can never overwrite a newer
// result.
func TestExplodeRefreshesStaleMember(t *testing.T) {
	ctx := context.Background()
	db := openTestDB(t)

	member := strings.Repeat("d", 64)
	staleAt := time.Now().Add(-48 * time.Hour).UTC()

	// Pre-existing stale standalone analysis: no findings, old date.
	seed := &Sample{
		SHA256: member, Source: "forage", Label: "unknown", LabelSource: "forage",
		Path: "forage/secure.js", FileType: "javascript", AnalyzedAt: &staleAt,
		CleaveResult: fmt.Appendf(nil, `{"fs":[{"sha":%q,"type":"javascript","dp":1}]}`, member),
	}
	if _, _, err := db.InsertSampleBatch(ctx, []*Sample{seed}); err != nil {
		t.Fatalf("seed stale member: %v", err)
	}

	explode := func(archive string, at time.Time, traitID string) {
		t.Helper()
		parent := &Sample{
			SHA256: archive, Source: "test", Label: "bad", LabelSource: "test",
			Path: "bad/arch.zip", FileType: "zip", AnalyzedAt: &at,
			CleaveResult: fmt.Appendf(nil,
				`{"files":[{"id":0,"sha":%q,"type":"zip","depth":0,"path":"arch.zip"},`+
					`{"id":1,"sha":%q,"type":"javascript","depth":1,"path":"arch.zip!!secure.js",`+
					`"traits":[{"id":%q,"crit":5,"conf":0.95}]}]}`, archive, member, traitID),
		}
		if _, err := db.ExplodeArchiveMembers(ctx, parent); err != nil {
			t.Fatalf("ExplodeArchiveMembers: %v", err)
		}
	}

	// A newer archive's rich analysis supersedes the stale standalone row.
	fresh := time.Now().UTC()
	explode(strings.Repeat("a", 64), fresh, "obf/eval-fresh")
	got, err := db.SampleBySHA256(ctx, member)
	if err != nil {
		t.Fatalf("SampleBySHA256: %v", err)
	}
	if !strings.Contains(string(got.CleaveResult), "obf/eval-fresh") {
		t.Errorf("member not refreshed by newer archive: %s", got.CleaveResult)
	}
	if got.AnalyzedAt == nil || !got.AnalyzedAt.After(staleAt) {
		t.Errorf("analyzed_at not advanced: %v", got.AnalyzedAt)
	}

	// An older archive must not overwrite the now-newer result.
	explode(strings.Repeat("b", 64), staleAt.Add(-time.Hour), "obf/eval-older")
	got, err = db.SampleBySHA256(ctx, member)
	if err != nil {
		t.Fatalf("SampleBySHA256: %v", err)
	}
	if strings.Contains(string(got.CleaveResult), "obf/eval-older") {
		t.Errorf("older archive wrongly overwrote newer analysis: %s", got.CleaveResult)
	}
	if !strings.Contains(string(got.CleaveResult), "obf/eval-fresh") {
		t.Errorf("newer analysis lost: %s", got.CleaveResult)
	}
}

// TestStoreResultAtomicMembers locks the core reliability contract: StoreResult
// writes the parent's truncated analysis AND every member row in one
// transaction, so a stored parent always has its members (no "truncated parent,
// zero members" data-loss state). It also covers the non-archive case and the
// freshness gate for a member that already exists with older analysis.
func TestStoreResultAtomicMembers(t *testing.T) {
	ctx := context.Background()
	db := openTestDB(t)

	archive := strings.Repeat("a", 64)
	m1 := strings.Repeat("b", 64)
	m2 := strings.Repeat("c", 64)

	// The archive must already exist as a claimed, unanalyzed row (the worker
	// claimed it before POSTing its result).
	mustInsert(t, ctx, db, &Sample{
		SHA256: archive, Source: "test", Label: "bad", LabelSource: "test",
		Path: "bad/app.zip",
	})

	// A worker's full envelope: container + two members, each with per-line ctx.
	full := fmt.Appendf(nil, `{"v":8,"files":[
		{"id":0,"sha":%q,"type":"zip","depth":0,"path":"app.zip","traits":[{"id":"c2/beacon","crit":4,"conf":0.9,"from":[{"file":1},{"file":2}]}]},
		{"id":1,"sha":%q,"type":"javascript","depth":1,"path":"app.zip!!a.js","traits":[{"id":"exec/eval","crit":5,"conf":0.9}],"ctx":[{"ln":1,"addr":0,"b":"abc"}]},
		{"id":2,"sha":%q,"type":"javascript","depth":1,"path":"app.zip!!b.js","traits":[{"id":"net/http","crit":3,"conf":0.8}],"ctx":[{"ln":1,"addr":0,"b":"xyz"}]}
	]}`, archive, m1, m2)

	stats, err := db.StoreResult(ctx, archive, full, []byte(`{"prob":0.9}`), nil, nil, "tv1")
	if err != nil {
		t.Fatalf("StoreResult: %v", err)
	}
	if stats.Members != 2 || stats.MembersStored != 2 {
		t.Fatalf("stats = %+v, want 2 members, 2 stored", stats)
	}

	// Parent is stored and compacted; members exist as their own rows with full
	// single-file analysis — atomically, in the same commit.
	parent, err := db.SampleBySHA256(ctx, archive)
	if err != nil || len(parent.CleaveResult) == 0 {
		t.Fatalf("parent not stored: %v", err)
	}
	for _, m := range []string{m1, m2} {
		row, err := db.SampleBySHA256(ctx, m)
		if err != nil {
			t.Fatalf("member %s missing — atomicity violated: %v", m[:4], err)
		}
		if row.Parent != archive {
			t.Errorf("member %s parent = %q, want %q", m[:4], row.Parent, archive)
		}
		if len(row.CleaveResult) == 0 {
			t.Errorf("member %s has no analysis", m[:4])
		}
	}

	// Non-archive: a single-file result stores the parent and yields no members.
	solo := strings.Repeat("d", 64)
	mustInsert(t, ctx, db, &Sample{SHA256: solo, Source: "test", Label: "unknown", LabelSource: "test", Path: "x/solo.js"})
	soloStats, err := db.StoreResult(ctx, solo,
		fmt.Appendf(nil, `{"v":8,"files":[{"id":0,"sha":%q,"type":"javascript","depth":0,"path":"solo.js"}]}`, solo),
		nil, nil, nil, "tv1")
	if err != nil {
		t.Fatalf("StoreResult(non-archive): %v", err)
	}
	if soloStats.Members != 0 {
		t.Errorf("non-archive members = %d, want 0", soloStats.Members)
	}
}

// TestStoreResultTombstonesUnsupportedFileType locks the tombstone contract: when
// the worker's analysis cannot classify the file (empty file_type), StoreResult
// marks the row skip='unsupported' and preserves it, rather than deleting it.
// Preserving the row is what keeps a concurrent store of the same content SHA
// from hitting an absent-sample error and retrying forever; the skip is what
// drops it from the claim queue so it is not endlessly re-analyzed.
func TestStoreResultTombstonesUnsupportedFileType(t *testing.T) {
	ctx := context.Background()
	db := openTestDB(t)

	// A claimed, unanalyzed row whose cheap ingest classifier gave it a type.
	sha := strings.Repeat("e", 64)
	mustInsert(t, ctx, db, &Sample{
		SHA256: sha, Source: "test", Label: "unknown", LabelSource: "test",
		Path: "unknown/mystery.bin", FileType: "elf",
	})

	// A result the authoritative pass could not classify: no fs[] entry for the
	// sha → parsed file_type is empty.
	stats, err := db.StoreResult(ctx, sha, []byte(`{"fs":[]}`), nil, nil, nil, "tv1")
	if err != nil {
		t.Fatalf("StoreResult(unsupported): %v", err)
	}
	if stats.Members != 0 {
		t.Errorf("members = %d, want 0", stats.Members)
	}

	// The row is preserved (not deleted) and tombstoned skip='unsupported'.
	row, err := db.SampleBySHA256(ctx, sha)
	if err != nil {
		t.Fatalf("row should be preserved, got err=%v", err)
	}
	if row.Skip != "unsupported" {
		t.Errorf("skip = %q, want %q", row.Skip, "unsupported")
	}

	// Tombstoning an already-absent row is a harmless no-op, not an error — this
	// is what lets a store racing a concurrent delete of the same SHA succeed
	// instead of erroring out.
	absent := strings.Repeat("f", 64)
	if _, err := db.StoreResult(ctx, absent, []byte(`{"fs":[]}`), nil, nil, nil, "tv1"); err != nil {
		t.Errorf("StoreResult(unsupported, absent row) = %v, want nil", err)
	}
}

// TestStoreResultRecordsFetchedRel locks the provenance edge: a member whose
// cleave node carries rel="fetched" (content retrieved from a URL the parent
// references — never actually inside it) records that edge type on its
// sample_locations row, while an ordinary contained member records "". Without
// this, a fetched web page is indistinguishable from an extracted archive
// member and renders as "found in archive" — a false containment claim.
func TestStoreResultRecordsFetchedRel(t *testing.T) {
	ctx := context.Background()
	db := openTestDB(t)

	archive := strings.Repeat("a", 64)
	contained := strings.Repeat("b", 64)
	fetched := strings.Repeat("f", 64)

	mustInsert(t, ctx, db, &Sample{
		SHA256: archive, Source: "test", Label: "bad", LabelSource: "test",
		Path: "bad/app.elf",
	})

	full := fmt.Appendf(nil, `{"v":8,"files":[
		{"id":0,"sha":%q,"type":"elf","depth":0,"path":"app.elf"},
		{"id":1,"sha":%q,"type":"javascript","depth":1,"path":"app.elf!!a.js"},
		{"id":2,"sha":%q,"type":"unknown","depth":1,"path":"compatibility","pid":0,"rel":"fetched","via":"https://example.test/compatibility"}
	]}`, archive, contained, fetched)
	if _, err := db.StoreResult(ctx, archive, full, []byte(`{"prob":0.1}`), nil, nil, "tv1"); err != nil {
		t.Fatalf("StoreResult: %v", err)
	}

	relFor := func(sha string) string {
		t.Helper()
		locs, err := db.LocationsForSHA(ctx, sha)
		if err != nil || len(locs) == 0 {
			t.Fatalf("LocationsForSHA(%s) = %v, %v", sha[:4], locs, err)
		}
		return locs[0].Rel
	}
	if got := relFor(contained); got != "" {
		t.Errorf("contained member rel = %q, want \"\"", got)
	}
	if got := relFor(fetched); got != "fetched" {
		t.Errorf("fetched member rel = %q, want \"fetched\"", got)
	}

	// The backlink query surfaces the edge type so a renderer can say
	// "referenced by" instead of "found in".
	parents, err := db.ParentArchivesForChild(ctx, fetched, 5)
	if err != nil || len(parents) != 1 {
		t.Fatalf("ParentArchivesForChild = %v, %v; want one parent", parents, err)
	}
	if parents[0].SHA256 != archive || parents[0].Rel != "fetched" {
		t.Errorf("parent ref = %s rel %q, want %s rel \"fetched\"", parents[0].SHA256[:4], parents[0].Rel, archive[:4])
	}

	// Direct location upsert roundtrips rel too (the walker/mirror path).
	if err := db.UpsertLocation(ctx, &SampleLocation{
		SHA256: fetched, Path: "unknown/uploads/f" + fetched[:2], Rel: "fetched",
	}); err != nil {
		t.Fatalf("UpsertLocation: %v", err)
	}
}

// TestRepairQueue locks the repair tier end to end: QueueMissingMembersForRepair
// flags only truncated top-level archives that lack member rows (priority 1),
// RepairCandidates returns exactly those, and an interactive RequestRescan
// outranks a repair flag (priority 2) so it drains from the forced tier instead.
func TestRepairQueue(t *testing.T) {
	ctx := context.Background()
	db := openTestDB(t)

	broken := strings.Repeat("a", 64)   // truncated, no members → repair candidate
	repaired := strings.Repeat("b", 64) // truncated, has a member → not
	member := strings.Repeat("c", 64)
	plain := strings.Repeat("d", 64)   // not truncated → not
	skipped := strings.Repeat("e", 64) // truncated but skipped → not

	insert := func(sha, skip string, truncated bool) {
		t.Helper()
		body := fmt.Sprintf(`{"files":[{"sha":%q,"type":"zip"}]}`, sha)
		if truncated {
			body = fmt.Sprintf(`{"files":[{"sha":%q,"type":"zip"}],"truncated":true}`, sha)
		}
		mustInsert(t, ctx, db, &Sample{
			SHA256: sha, Source: "test", Label: "bad", LabelSource: "test",
			Path: "bad/" + sha + ".zip", Skip: skip, CleaveResult: []byte(body),
		})
	}
	insert(broken, "", true)
	insert(repaired, "", true)
	insert(plain, "", false)
	insert(skipped, "skip-benign-archive-item", true)
	mustInsert(t, ctx, db, &Sample{
		SHA256: member, Source: "test", Label: "bad", LabelSource: "test",
		Path: "bad/" + repaired + ".zip!!m.js", Parent: repaired,
		CleaveResult: []byte(`{"files":[{"sha":"` + member + `","type":"javascript"}]}`),
	})

	n, err := db.QueueMissingMembersForRepair(ctx)
	if err != nil {
		t.Fatalf("QueueMissingMembersForRepair: %v", err)
	}
	if n != 1 {
		t.Fatalf("flagged %d archives, want only the memberless one", n)
	}
	cands, err := db.RepairCandidates(ctx, 50)
	if err != nil {
		t.Fatalf("RepairCandidates: %v", err)
	}
	if len(cands) != 1 || cands[0].SHA256 != broken {
		t.Fatalf("repair candidates = %+v, want only %s", cands, broken[:4])
	}

	// An interactive rescan of the same archive promotes it to priority 2, so it
	// leaves the repair tier for the forced (ahead-of-new) tier.
	if err := db.RequestRescan(ctx, broken, 0); err != nil {
		t.Fatalf("RequestRescan: %v", err)
	}
	afterPromote, err := db.RepairCandidates(ctx, 50)
	if err != nil {
		t.Fatalf("RepairCandidates: %v", err)
	}
	if len(afterPromote) != 0 {
		t.Errorf("after interactive rescan, repair tier should be empty, got %+v", afterPromote)
	}
	forced, err := db.ForcedRescanCandidates(ctx, time.Now(), 50)
	if err != nil {
		t.Fatalf("ForcedRescanCandidates: %v", err)
	}
	if len(forced) != 1 || forced[0].SHA256 != broken {
		t.Errorf("forced tier = %+v, want %s after interactive rescan", forced, broken[:4])
	}
}

func TestReconcileLocationParentEdgesBackfill(t *testing.T) {
	ctx := context.Background()
	db := openTestDB(t)

	archive := strings.Repeat("a", 64)
	child := strings.Repeat("b", 64)
	// Simulate a legacy member: a child row with samples.parent set but no
	// sample_locations edge (the pre-fan-out state). Raw insert bypasses
	// InsertSampleBatch's edge fan-out so we reproduce exactly that gap.
	cleave := fmt.Sprintf(`{"fs":[{"sha":%q,"type":"js","x":42,"dp":1}]}`, child)
	if _, err := db.lite.ExecContext(ctx, `
		INSERT INTO samples (sha256, source, label, label_source, path, parent, cleave_result)
		VALUES (?, 'test', 'bad', 'test', ?, ?, ?)`,
		child, archive+"!!pkg/evil.js", archive, cleave); err != nil {
		t.Fatal(err)
	}
	if _, total, err := db.MembersByParent(ctx, archive, 10); err != nil || total != 0 {
		t.Fatalf("pre-backfill: expected no edge yet, got total=%d err=%v", total, err)
	}
	// Migrate (in openTestDB) already marked the backfill done on the empty DB;
	// clear the marker so the reconcile runs against our injected legacy row.
	if _, err := db.lite.ExecContext(ctx, `DELETE FROM hopper_kv WHERE key LIKE 'backfill:locations:parent%'`); err != nil {
		t.Fatal(err)
	}

	if err := db.reconcileLocationParentEdges(ctx); err != nil {
		t.Fatalf("reconcile: %v", err)
	}

	members, total, err := db.MembersByParent(ctx, archive, 10)
	if err != nil {
		t.Fatalf("MembersByParent: %v", err)
	}
	if total != 1 || len(members) != 1 || members[0].SHA256 != child {
		t.Fatalf("post-backfill: expected the child listed, got total=%d members=%d", total, len(members))
	}
	if members[0].Score != 42 || members[0].FileType != "js" {
		t.Errorf("member score/type = %d/%q, want 42/js", members[0].Score, members[0].FileType)
	}

	// Idempotent + gated: a second run is a no-op (done marker set) and leaves a
	// single edge, never a duplicate.
	if err := db.reconcileLocationParentEdges(ctx); err != nil {
		t.Fatalf("reconcile (2nd): %v", err)
	}
	var edges int
	if err := db.lite.QueryRowContext(ctx,
		`SELECT count(*) FROM sample_locations WHERE parent_sha256 = ?`, archive).Scan(&edges); err != nil {
		t.Fatal(err)
	}
	if edges != 1 {
		t.Errorf("expected 1 edge after idempotent re-run, got %d", edges)
	}
}

func TestMigrateDoesNotRunBackfill(t *testing.T) {
	db := openTestDB(t)
	ctx := context.Background()

	sha := "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
	cleave := `{"fs":[{"sha":"` + sha + `","type":"elf","f":"H₂O","x":7,"dp":0,"ts":[{"l":5},{"l":3}]}]}`
	if _, err := db.lite.ExecContext(ctx, `
		INSERT INTO samples (sha256, source, label, label_source, path, cleave_result)
		VALUES (?, 'test', 'bad', 'test', ?, ?)`,
		sha, "test/"+sha, cleave); err != nil {
		t.Fatal(err)
	}

	if err := db.Migrate(ctx); err != nil {
		t.Fatal(err)
	}

	var elements string
	var maxCrit, suspiciousCount int
	if err := db.lite.QueryRowContext(ctx, `
		SELECT elements, max_crit, suspicious_count FROM samples WHERE sha256 = ?`, sha,
	).Scan(&elements, &maxCrit, &suspiciousCount); err != nil {
		t.Fatal(err)
	}
	if elements != "" || maxCrit != 0 || suspiciousCount != 0 {
		t.Fatalf("Migrate backfilled legacy row: elements=%q max_crit=%d suspicious_count=%d", elements, maxCrit, suspiciousCount)
	}

	pending, err := db.BackfillPending(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if pending.CleaveColumns != 1 {
		t.Fatalf("pending cleave columns = %d, want 1", pending.CleaveColumns)
	}
}

func TestInsertAndLookup(t *testing.T) {
	db := openTestDB(t)
	ctx := context.Background()

	s := &Sample{
		SHA256:      "abc123def456",
		Source:      "test",
		Filename:    "malware.exe",
		Label:       "bad",
		LabelSource: "test",
		Path:        "/data/bad/malware.exe",
		Status:      "bad-review",
	}
	if err := db.InsertSample(ctx, s); err != nil {
		t.Fatalf("InsertSample: %v", err)
	}

	got, err := db.SampleBySHA256(ctx, "abc123def456")
	if err != nil {
		t.Fatalf("SampleBySHA256: %v", err)
	}
	if got.SHA256 != s.SHA256 {
		t.Errorf("SHA256 = %q, want %q", got.SHA256, s.SHA256)
	}
	if got.Label != "bad" {
		t.Errorf("Label = %q, want %q", got.Label, "bad")
	}
	if got.Status != "bad-review" {
		t.Errorf("Status = %q, want %q", got.Status, "bad-review")
	}
	if got.Path != s.Path {
		t.Errorf("Path = %q, want %q", got.Path, s.Path)
	}
}

// TestInsertPreservesCanonicalAndParent guards against placeholder/arg-list
// drift in the single-insert path. Both canonical_sha256 (defaults to the
// row's own sha via a $1-reuse in the SQL) and parent (from s.Parent) must
// land in the correct columns — a swap here previously went unnoticed
// because mock shas have no A-F chars that'd trigger the hex CHECK.
func TestInsertPreservesCanonicalAndParent(t *testing.T) {
	db := openTestDB(t)
	ctx := context.Background()

	const (
		sha    = "child1"
		parent = "parent1"
	)
	// Parent must exist first — no FK check, but exercises a non-empty
	// sha2 argument to the insert.
	mustInsert(t, ctx, db, &Sample{SHA256: parent, Source: "test", Label: "bad", LabelSource: "test"})
	mustInsert(t, ctx, db, &Sample{
		SHA256:      sha,
		Source:      "test",
		Label:       "bad",
		LabelSource: "test",
		Path:        "bad/archive!!child",
		Parent:      parent,
	})

	got, err := db.SampleBySHA256(ctx, sha)
	if err != nil {
		t.Fatal(err)
	}
	// canonical_sha256 defaults to sha256 for top-level rows; for a row
	// with Parent set, the insert still copies sha into the column (the
	// sample's own content is its canonical identity — the archive
	// relationship is separate, in parent).
	if got.CanonicalSHA256 != sha {
		t.Errorf("CanonicalSHA256 = %q, want %q (must not be swapped with Parent)", got.CanonicalSHA256, sha)
	}
	if got.Parent != parent {
		t.Errorf("Parent = %q, want %q (must not be swapped with canonical)", got.Parent, parent)
	}
}

func TestInsertDuplicate(t *testing.T) {
	db := openTestDB(t)
	ctx := context.Background()

	s := &Sample{SHA256: "dup1", Source: "test", Label: "bad", LabelSource: "test"}
	if err := db.InsertSample(ctx, s); err != nil {
		t.Fatal(err)
	}
	// Duplicate insert should succeed silently.
	if err := db.InsertSample(ctx, s); err != nil {
		t.Fatalf("duplicate insert should not error: %v", err)
	}
}

func TestNotFound(t *testing.T) {
	db := openTestDB(t)
	_, err := db.SampleBySHA256(context.Background(), "nonexistent")
	if err == nil {
		t.Fatal("expected error")
	}
	if !errors.Is(err, ErrNotFound) {
		t.Errorf("expected ErrNotFound, got %v", err)
	}
}

func TestSetStatus(t *testing.T) {
	db := openTestDB(t)
	ctx := context.Background()

	mustInsert(t, ctx, db, &Sample{SHA256: "s1", Source: "test", Label: "bad", LabelSource: "test", Status: "bad-review"})
	if err := db.SetStatus(ctx, "s1", "bad-reversed"); err != nil {
		t.Fatal(err)
	}
	got, err := db.SampleBySHA256(ctx, "s1")
	if err != nil {
		t.Fatalf("SampleBySHA256: %v", err)
	}
	if got.Status != "bad-reversed" {
		t.Errorf("Status = %q, want %q", got.Status, "bad-reversed")
	}
}

func TestUpdateCleaveResult(t *testing.T) {
	db := openTestDB(t)
	ctx := context.Background()

	mustInsert(t, ctx, db, &Sample{SHA256: "c1", Source: "test", Label: "bad", LabelSource: "test"})
	if err := db.UpdateCleaveResult(ctx, "c1", []byte(`{"fs":[{"sha":"c1","type":"elf","dp":0,"ts":[{"i":"test","l":4}]}]}`), nil, ""); err != nil {
		t.Fatal(err)
	}
	got, err := db.SampleBySHA256(ctx, "c1")
	if err != nil {
		t.Fatalf("SampleBySHA256: %v", err)
	}
	if got.CleaveResult == nil {
		t.Error("CleaveResult should not be nil")
	}
	if got.AnalyzedAt == nil {
		t.Error("AnalyzedAt should be set")
	}
	if got.FirstAnalyzedAt == nil {
		t.Error("FirstAnalyzedAt should be set")
	}
}

func TestUpdateCleaveResultPreservesFirstAnalyzedAt(t *testing.T) {
	db := openTestDB(t)
	ctx := context.Background()

	mustInsert(t, ctx, db, &Sample{SHA256: "fa1", Source: "test", Label: "bad", LabelSource: "test"})
	result := []byte(`{"fs":[{"sha":"fa1","type":"elf","dp":0,"x":1}]}`)
	if err := db.UpdateCleaveResult(ctx, "fa1", result, nil, "old"); err != nil {
		t.Fatal(err)
	}
	first, err := db.SampleBySHA256(ctx, "fa1")
	if err != nil {
		t.Fatal(err)
	}
	if first.FirstAnalyzedAt == nil || first.AnalyzedAt == nil {
		t.Fatalf("first analysis timestamps missing: %+v", first)
	}

	time.Sleep(2 * time.Millisecond)
	result = []byte(`{"fs":[{"sha":"fa1","type":"elf","dp":0,"x":2}]}`)
	if err := db.UpdateCleaveResult(ctx, "fa1", result, nil, "new"); err != nil {
		t.Fatal(err)
	}
	second, err := db.SampleBySHA256(ctx, "fa1")
	if err != nil {
		t.Fatal(err)
	}
	if second.FirstAnalyzedAt == nil || !second.FirstAnalyzedAt.Equal(*first.FirstAnalyzedAt) {
		t.Fatalf("first_analyzed_at = %v, want preserved %v", second.FirstAnalyzedAt, first.FirstAnalyzedAt)
	}
	if second.AnalyzedAt == nil || !second.AnalyzedAt.After(*first.AnalyzedAt) {
		t.Fatalf("analyzed_at = %v, want after %v", second.AnalyzedAt, first.AnalyzedAt)
	}
}

func TestUpdateSample(t *testing.T) {
	db := openTestDB(t)
	ctx := context.Background()

	mustInsert(t, ctx, db, &Sample{SHA256: "u1", Source: "test", Label: "bad", LabelSource: "test", Status: "bad-review"})
	if err := db.UpdateSample(ctx, "u1", "bad-reversed", []byte(`{"fs":[{"sha":"u1","type":"elf","dp":0,"ts":[{"i":"test","l":5}]}]}`), ""); err != nil {
		t.Fatal(err)
	}
	got, err := db.SampleBySHA256(ctx, "u1")
	if err != nil {
		t.Fatalf("SampleBySHA256: %v", err)
	}
	if got.Status != "bad-reversed" {
		t.Errorf("Status = %q, want %q", got.Status, "bad-reversed")
	}
}

func TestReclassify(t *testing.T) {
	db := openTestDB(t)
	ctx := context.Background()

	mustInsert(t, ctx, db, &Sample{SHA256: "r1", Source: "test", Label: "bad", LabelSource: "test"})
	if err := db.Reclassify(ctx, "r1", "good", "manual"); err != nil {
		t.Fatal(err)
	}
	got, err := db.SampleBySHA256(ctx, "r1")
	if err != nil {
		t.Fatalf("SampleBySHA256: %v", err)
	}
	if got.Label != "good" {
		t.Errorf("Label = %q, want %q", got.Label, "good")
	}
	if got.LabelSource != "manual" {
		t.Errorf("LabelSource = %q, want %q", got.LabelSource, "manual")
	}
}

func TestSamplesInPipelineStage(t *testing.T) {
	db := openTestDB(t)
	ctx := context.Background()

	mustInsert(t, ctx, db, &Sample{SHA256: "a", Source: "test", Label: "bad", LabelSource: "test", Status: "bad-review"})
	mustInsert(t, ctx, db, &Sample{SHA256: "b", Source: "test", Label: "bad", LabelSource: "test", Status: "bad-review"})
	mustInsert(t, ctx, db, &Sample{SHA256: "c", Source: "test", Label: "bad", LabelSource: "test", Status: "bad"})

	got, err := db.SamplesInPipelineStage(ctx, "bad-review", 10)
	if err != nil {
		t.Fatal(err)
	}
	if len(got) != 2 {
		t.Errorf("got %d samples, want 2", len(got))
	}
}

func TestAnalysisRatesSince(t *testing.T) {
	db := openTestDB(t)
	ctx := context.Background()

	now := time.Now().UTC()
	ins := func(sha, parent string, first, analyzed *time.Time) {
		t.Helper()
		var firstS, analyzedS any
		if first != nil {
			firstS = first.UTC().Format(time.RFC3339Nano)
		}
		if analyzed != nil {
			analyzedS = analyzed.UTC().Format(time.RFC3339Nano)
		}
		if _, err := db.lite.ExecContext(ctx, `
			INSERT INTO samples (sha256, source, label, label_source, path, parent, analyzed_at, first_analyzed_at)
			VALUES (?, 'test', 'bad', 'test', ?, ?, ?, ?)`,
			sha, "test/"+sha, parent, analyzedS, firstS); err != nil {
			t.Fatal(err)
		}
	}
	hex := func(c byte) string { return strings.Repeat(string(c), 64) }

	recent := now.Add(-5 * time.Minute) // inside the 60m window
	older := now.Add(-240 * time.Hour)  // a much earlier first analysis
	stale := now.Add(-90 * time.Minute) // outside the 60m window

	ins(hex('a'), "", &recent, &recent)      // top-level first-time analysis: top-level, not rescan
	ins(hex('b'), "", &older, &recent)       // top-level rescan inside the window: counts in both
	ins(hex('c'), "", &older, &stale)        // top-level rescan, but before the window: excluded
	ins(hex('d'), "", nil, &recent)          // top-level analyzed, first never stamped: top-level, not rescan
	ins(hex('e'), "", nil, nil)              // never analyzed: excluded
	ins(hex('0'), hex('f'), &older, &recent) // archive CHILD rescan: excluded by the parent filter

	r, err := db.AnalysisRatesSince(ctx, 60*time.Minute)
	if err != nil {
		t.Fatalf("AnalysisRatesSince: %v", err)
	}
	if r.TopLevel != 3 { // a, b, d
		t.Errorf("TopLevel = %d, want 3", r.TopLevel)
	}
	if r.Rescans != 1 { // b only — child excluded by parent, d has no first, a is first-time
		t.Errorf("Rescans = %d, want 1", r.Rescans)
	}
}

func TestCountByLabel(t *testing.T) {
	db := openTestDB(t)
	ctx := context.Background()

	mustInsert(t, ctx, db, &Sample{SHA256: "a", Source: "test", Label: "bad", LabelSource: "test"})
	mustInsert(t, ctx, db, &Sample{SHA256: "b", Source: "test", Label: "bad", LabelSource: "test"})
	mustInsert(t, ctx, db, &Sample{SHA256: "c", Source: "test", Label: "good", LabelSource: "test"})

	counts, err := db.CountByLabel(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if counts["bad"] != 2 {
		t.Errorf("bad = %d, want 2", counts["bad"])
	}
	if counts["good"] != 1 {
		t.Errorf("good = %d, want 1", counts["good"])
	}
}

func TestCountByStatus(t *testing.T) {
	db := openTestDB(t)
	ctx := context.Background()

	mustInsert(t, ctx, db, &Sample{SHA256: "a", Source: "test", Label: "bad", LabelSource: "test", Status: "bad"})
	mustInsert(t, ctx, db, &Sample{SHA256: "b", Source: "test", Label: "bad", LabelSource: "test", Status: "bad-review"})
	mustInsert(t, ctx, db, &Sample{SHA256: "c", Source: "test", Label: "good", LabelSource: "test", Status: "good"})

	counts, err := db.CountByStatus(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if counts["bad"] != 1 {
		t.Errorf("bad = %d, want 1", counts["bad"])
	}
	if counts["bad-review"] != 1 {
		t.Errorf("bad-review = %d, want 1", counts["bad-review"])
	}
}

func TestSamplesByStatusInPaths(t *testing.T) {
	db := openTestDB(t)
	ctx := context.Background()

	mustInsert(t, ctx, db, &Sample{SHA256: "a", Source: "test", Label: "bad", LabelSource: "test", Status: "bad-review", Path: "/data/bad/elf/s1"})
	mustInsert(t, ctx, db, &Sample{SHA256: "b", Source: "test", Label: "bad", LabelSource: "test", Status: "bad-review", Path: "/data/bad/pe/s2"})
	mustInsert(t, ctx, db, &Sample{SHA256: "c", Source: "test", Label: "good", LabelSource: "test", Status: "good", Path: "/data/good/s3"})

	got, err := db.SamplesByStatusInPaths(ctx, "bad-review", []string{"/data/bad/elf"}, 10)
	if err != nil {
		t.Fatal(err)
	}
	if len(got) != 1 || got[0].SHA256 != "a" {
		t.Errorf("got %d samples, want 1 with sha256=a", len(got))
	}

	got, err = db.SamplesByStatusInPaths(ctx, "bad-review", []string{"/data/bad/elf", "/data/bad/pe"}, 10)
	if err != nil {
		t.Fatal(err)
	}
	if len(got) != 2 {
		t.Errorf("got %d samples, want 2", len(got))
	}

	// Empty prefixes returns nil.
	got, err = db.SamplesByStatusInPaths(ctx, "bad-review", nil, 10)
	if err != nil {
		t.Fatal(err)
	}
	if got != nil {
		t.Errorf("empty prefixes should return nil, got %d", len(got))
	}
}

func TestFalsePositivesInPaths(t *testing.T) {
	db := openTestDB(t)
	ctx := context.Background()

	mustInsert(t, ctx, db, &Sample{
		SHA256:      "fp1",
		Source:      "test",
		Label:       "good",
		LabelSource: "test",
		Path:        "/data/good/app1",
		Score:       90,
	})
	// Include a hostile-level trait so fp1 passes the detection filter
	// (max_crit >= 5 OR suspicious_count >= 2).
	mustAnalyzeWithTraits(t, ctx, db, "fp1", 90, `{"l":5,"c":1.0}`)
	mustInsert(t, ctx, db, &Sample{
		SHA256:      "fp2",
		Source:      "test",
		Label:       "good",
		LabelSource: "test",
		Path:        "/data/good/app2",
		Score:       90,
		Skip:        "misclassified",
	})
	mustInsert(t, ctx, db, &Sample{
		SHA256:      "fp3",
		Source:      "test",
		Label:       "good",
		LabelSource: "test",
		Path:        "/data/good/app3",
		Score:       70,
	})
	mustInsert(t, ctx, db, &Sample{
		SHA256:      "fp4",
		Source:      "test",
		Label:       "bad",
		LabelSource: "test",
		Path:        "/data/good/app4",
		Score:       90,
	})
	mustInsert(t, ctx, db, &Sample{
		SHA256:      "fp5",
		Source:      "test",
		Label:       "good",
		LabelSource: "test",
		Path:        "/other/good/app5",
		Score:       90,
	})
	mustInsert(t, ctx, db, &Sample{
		SHA256:      "fp6",
		Source:      "test",
		Label:       "good",
		LabelSource: "test",
		Path:        "/data/good/app6",
		Status:      "good-review",
		Score:       90,
	})

	got, err := db.FalsePositivesInPaths(ctx, []string{"/data/good"}, 10)
	if err != nil {
		t.Fatal(err)
	}
	if len(got) != 1 || got[0].SHA256 != "fp1" {
		t.Fatalf("got %+v, want only fp1", got)
	}
}

func TestFalsePositivesExcludeArchiveChildren(t *testing.T) {
	db := openTestDB(t)
	ctx := context.Background()

	mustInsert(t, ctx, db, &Sample{
		SHA256:      "fp-parent",
		Source:      "test",
		Label:       "good",
		LabelSource: "test",
		Path:        "/data/good/pkg.vsix",
		Score:       90,
	})
	mustAnalyzeWithTraits(t, ctx, db, "fp-parent", 90, `{"l":5,"c":1.0}`)
	mustInsert(t, ctx, db, &Sample{
		SHA256:      "fp-child",
		Source:      "test",
		Label:       "good",
		LabelSource: "test",
		Path:        "/data/good/pkg.vsix!!extension/dist/server.js",
		Parent:      "fp-parent",
		Score:       95,
	})
	mustAnalyzeWithTraits(t, ctx, db, "fp-child", 95, `{"l":5,"c":1.0}`)

	got, err := db.FalsePositives(ctx, 10)
	if err != nil {
		t.Fatal(err)
	}
	if len(got) != 1 || got[0].SHA256 != "fp-parent" {
		t.Fatalf("FalsePositives got %+v, want only fp-parent", got)
	}

	light, err := db.FalsePositivesLight(ctx, 10)
	if err != nil {
		t.Fatal(err)
	}
	if len(light) != 1 || light[0].SHA256 != "fp-parent" {
		t.Fatalf("FalsePositivesLight got %+v, want only fp-parent", light)
	}
}

func TestFalseNegativesInPaths(t *testing.T) {
	db := openTestDB(t)
	ctx := context.Background()

	mustInsert(t, ctx, db, &Sample{
		SHA256:      "fn1",
		Source:      "test",
		Label:       "bad",
		LabelSource: "test",
		Path:        "/data/bad/app1",
		Score:       40,
	})
	mustAnalyze(t, ctx, db, "fn1", 40)
	mustInsert(t, ctx, db, &Sample{
		SHA256:      "fn2",
		Source:      "test",
		Label:       "bad",
		LabelSource: "test",
		Path:        "/data/bad/app2",
		Score:       40,
		Skip:        "misclassified",
	})
	mustInsert(t, ctx, db, &Sample{
		SHA256:      "fn3",
		Source:      "test",
		Label:       "bad",
		LabelSource: "test",
		Path:        "/data/bad/app3",
		Score:       90,
	})
	mustInsert(t, ctx, db, &Sample{
		SHA256:      "fn4",
		Source:      "test",
		Label:       "good",
		LabelSource: "test",
		Path:        "/data/bad/app4",
		Score:       40,
	})
	mustInsert(t, ctx, db, &Sample{
		SHA256:      "fn5",
		Source:      "test",
		Label:       "bad",
		LabelSource: "test",
		Path:        "/other/bad/app5",
		Score:       40,
	})
	mustInsert(t, ctx, db, &Sample{
		SHA256:      "fn6",
		Source:      "test",
		Label:       "bad",
		LabelSource: "test",
		Path:        "/data/bad/app6",
		Status:      "bad-review",
		Score:       40,
	})

	got, err := db.FalseNegativesInPaths(ctx, []string{"/data/bad"}, 10)
	if err != nil {
		t.Fatal(err)
	}
	if len(got) != 1 || got[0].SHA256 != "fn1" {
		t.Fatalf("got %+v, want only fn1", got)
	}
}

func TestFalseNegativesExcludeArchiveChildren(t *testing.T) {
	db := openTestDB(t)
	ctx := context.Background()

	mustInsert(t, ctx, db, &Sample{
		SHA256:      "fn-parent",
		Source:      "test",
		Label:       "bad",
		LabelSource: "test",
		Path:        "/data/bad/pkg.vsix",
		Score:       0,
	})
	mustAnalyze(t, ctx, db, "fn-parent", 0)
	mustInsert(t, ctx, db, &Sample{
		SHA256:      "fn-child",
		Source:      "test",
		Label:       "bad",
		LabelSource: "test",
		Path:        "/data/bad/pkg.vsix!!extension/dist/server.js",
		Parent:      "fn-parent",
		Score:       0,
	})
	mustAnalyze(t, ctx, db, "fn-child", 0)

	got, err := db.FalseNegatives(ctx, 10)
	if err != nil {
		t.Fatal(err)
	}
	if len(got) != 1 || got[0].SHA256 != "fn-parent" {
		t.Fatalf("FalseNegatives got %+v, want only fn-parent", got)
	}

	light, err := db.FalseNegativesLight(ctx, 10)
	if err != nil {
		t.Fatal(err)
	}
	if len(light) != 1 || light[0].SHA256 != "fn-parent" {
		t.Fatalf("FalseNegativesLight got %+v, want only fn-parent", light)
	}
}

func TestTruePositives(t *testing.T) {
	db := openTestDB(t)
	ctx := context.Background()

	mustInsert(t, ctx, db, &Sample{
		SHA256:      "tp1",
		Source:      "test",
		Label:       "bad",
		LabelSource: "test",
		Score:       95,
	})
	mustAnalyze(t, ctx, db, "tp1", 95)
	mustInsert(t, ctx, db, &Sample{
		SHA256:      "tp2",
		Source:      "test",
		Label:       "bad",
		LabelSource: "test",
		Score:       95,
		Skip:        "misclassified",
	})
	mustAnalyze(t, ctx, db, "tp2", 95)
	mustInsert(t, ctx, db, &Sample{
		SHA256:      "tp3",
		Source:      "test",
		Label:       "bad",
		LabelSource: "test",
		Score:       70,
	})
	mustAnalyze(t, ctx, db, "tp3", 70)
	mustInsert(t, ctx, db, &Sample{
		SHA256:      "tp4",
		Source:      "test",
		Label:       "good",
		LabelSource: "test",
		Score:       95,
	})
	mustAnalyze(t, ctx, db, "tp4", 95)

	got, err := db.TruePositives(ctx, 85, 10)
	if err != nil {
		t.Fatal(err)
	}
	if len(got) != 1 || got[0].SHA256 != "tp1" {
		t.Fatalf("got %+v, want only tp1", got)
	}
}

func TestBenignReview(t *testing.T) {
	db := openTestDB(t)
	ctx := context.Background()

	// br1: hostile trait (max_crit=5) -> qualifies for benign-review.
	mustInsert(t, ctx, db, &Sample{
		SHA256:      "br1",
		Source:      "test",
		Label:       "good",
		LabelSource: "marker",
		Skip:        "misclassified",
	})
	mustAnalyzeWithTraits(t, ctx, db, "br1", 92, `{"l":5,"c":1.0}`)
	// br2: only one suspicious trait, no hostile -> not in queue.
	mustInsert(t, ctx, db, &Sample{
		SHA256:      "br2",
		Source:      "test",
		Label:       "good",
		LabelSource: "marker",
		Skip:        "misclassified",
	})
	mustAnalyzeWithTraits(t, ctx, db, "br2", 60, `{"l":4,"c":1.0}`)
	// br3: not marker-sourced -> excluded regardless of traits.
	mustInsert(t, ctx, db, &Sample{
		SHA256:      "br3",
		Source:      "test",
		Label:       "good",
		LabelSource: "test",
		Skip:        "misclassified",
	})
	mustAnalyzeWithTraits(t, ctx, db, "br3", 92, `{"l":5,"c":1.0}`)
	// br4: claimed -> excluded.
	mustInsert(t, ctx, db, &Sample{
		SHA256:      "br4",
		Source:      "test",
		Label:       "good",
		LabelSource: "marker",
		Skip:        "misclassified",
		Status:      "claimed",
	})
	mustAnalyzeWithTraits(t, ctx, db, "br4", 92, `{"l":5,"c":1.0}`)

	got, err := db.BenignReview(ctx, 0, 10)
	if err != nil {
		t.Fatal(err)
	}
	if len(got) != 1 || got[0].SHA256 != "br1" {
		t.Fatalf("got %+v, want only br1", got)
	}
}

func TestBadReview(t *testing.T) {
	db := openTestDB(t)
	ctx := context.Background()

	// mr1: no traits -> looks benign, qualifies for bad-review.
	mustInsert(t, ctx, db, &Sample{
		SHA256:      "mr1",
		Source:      "test",
		Label:       "bad",
		LabelSource: "marker",
		Skip:        "misclassified",
	})
	mustAnalyze(t, ctx, db, "mr1", 20)
	// mr2: two suspicious traits -> doesn't look benign, excluded.
	mustInsert(t, ctx, db, &Sample{
		SHA256:      "mr2",
		Source:      "test",
		Label:       "bad",
		LabelSource: "marker",
		Skip:        "misclassified",
	})
	mustAnalyzeWithTraits(t, ctx, db, "mr2", 90, `{"l":4,"c":1.0},{"l":4,"c":1.0}`)
	// mr3: not marker-sourced -> excluded.
	mustInsert(t, ctx, db, &Sample{
		SHA256:      "mr3",
		Source:      "test",
		Label:       "bad",
		LabelSource: "test",
		Skip:        "misclassified",
	})
	mustAnalyze(t, ctx, db, "mr3", 20)
	// mr4: claimed -> excluded.
	mustInsert(t, ctx, db, &Sample{
		SHA256:      "mr4",
		Source:      "test",
		Label:       "bad",
		LabelSource: "marker",
		Skip:        "misclassified",
		Status:      "claimed",
	})
	mustAnalyze(t, ctx, db, "mr4", 20)

	got, err := db.BadReview(ctx, 0, 10)
	if err != nil {
		t.Fatal(err)
	}
	if len(got) != 1 || got[0].SHA256 != "mr1" {
		t.Fatalf("got %+v, want only mr1", got)
	}
}

func TestCountByStatusInPaths(t *testing.T) {
	db := openTestDB(t)
	ctx := context.Background()

	mustInsert(t, ctx, db, &Sample{SHA256: "a", Source: "test", Label: "bad", LabelSource: "test", Status: "bad", Path: "/data/bad/s1"})
	mustInsert(t, ctx, db, &Sample{SHA256: "b", Source: "test", Label: "bad", LabelSource: "test", Status: "bad", Path: "/data/bad/s2"})
	mustInsert(t, ctx, db, &Sample{SHA256: "c", Source: "test", Label: "bad", LabelSource: "test", Status: "bad-review", Path: "/other/s3"})

	counts, err := db.CountByStatusInPaths(ctx, []string{"/data/bad"})
	if err != nil {
		t.Fatal(err)
	}
	if counts["bad"] != 2 {
		t.Errorf("bad = %d, want 2", counts["bad"])
	}
	if counts["bad-review"] != 0 {
		t.Errorf("bad-review = %d, want 0 (filtered out)", counts["bad-review"])
	}
}

func TestAgesByPaths(t *testing.T) {
	db := openTestDB(t)
	ctx := context.Background()

	mustInsert(t, ctx, db, &Sample{SHA256: "a", Source: "test", Label: "bad", LabelSource: "test", Path: "/data/s1"})
	mustInsert(t, ctx, db, &Sample{SHA256: "b", Source: "test", Label: "bad", LabelSource: "test", Path: "/other/s2"})

	ages, err := db.AgesByPaths(ctx, []string{"/data"}, 0)
	if err != nil {
		t.Fatal(err)
	}
	if len(ages) != 1 {
		t.Errorf("got %d ages, want 1", len(ages))
	}
	if _, ok := ages["/data/s1"]; !ok {
		t.Error("expected /data/s1 in ages")
	}
}

func TestUnanalyzed(t *testing.T) {
	db := openTestDB(t)
	ctx := context.Background()

	mustInsert(t, ctx, db, &Sample{SHA256: "a", Source: "test", Label: "bad", LabelSource: "test"})
	mustInsert(t, ctx, db, &Sample{SHA256: "b", Source: "test", Label: "bad", LabelSource: "test"})
	if err := db.UpdateCleaveResult(ctx, "b", []byte(`{"fs":[{"sha":"b","type":"elf","dp":0}]}`), nil, ""); err != nil {
		t.Fatal(err)
	}

	got, err := db.Unanalyzed(ctx, 10)
	if err != nil {
		t.Fatal(err)
	}
	if len(got) != 1 || got[0].SHA256 != "a" {
		t.Errorf("got %d unanalyzed, want 1 with sha256=a", len(got))
	}
}

func TestReports(t *testing.T) {
	db := openTestDB(t)
	ctx := context.Background()

	mustInsert(t, ctx, db, &Sample{SHA256: "r1", Source: "test", Label: "bad", LabelSource: "test"})

	if err := db.InsertReport(ctx, &Report{SHA256: "r1", Type: "re", Content: "# Report 1", Provider: "claude"}); err != nil {
		t.Fatal(err)
	}
	time.Sleep(time.Millisecond) // ensure distinct created_at in SQLite
	if err := db.InsertReport(ctx, &Report{SHA256: "r1", Type: "re", Content: "# Report 2", Provider: "gemini"}); err != nil {
		t.Fatal(err)
	}
	if err := db.InsertReport(ctx, &Report{SHA256: "r1", Type: "gap", Content: "# Gap", Provider: "claude"}); err != nil {
		t.Fatal(err)
	}

	all, err := db.ReportsBySHA256(ctx, "r1")
	if err != nil {
		t.Fatal(err)
	}
	if len(all) != 3 {
		t.Errorf("got %d reports, want 3", len(all))
	}

	latest, err := db.LatestReport(ctx, "r1", "re")
	if err != nil {
		t.Fatal(err)
	}
	if latest.Content != "# Report 2" {
		t.Errorf("latest RE content = %q, want %q", latest.Content, "# Report 2")
	}

	_, err = db.LatestReport(ctx, "r1", "fpr")
	if !errors.Is(err, ErrNotFound) {
		t.Errorf("expected ErrNotFound for missing report type, got %v", err)
	}
}

func TestSamplesByLabel(t *testing.T) {
	db := openTestDB(t)
	ctx := context.Background()

	mustInsert(t, ctx, db, &Sample{SHA256: "a", Source: "test", Label: "bad", LabelSource: "test"})
	mustInsert(t, ctx, db, &Sample{SHA256: "b", Source: "test", Label: "good", LabelSource: "test"})
	mustInsert(t, ctx, db, &Sample{SHA256: "c", Source: "test", Label: "bad", LabelSource: "test"})

	got, err := db.SamplesByLabel(ctx, "bad", 10)
	if err != nil {
		t.Fatal(err)
	}
	if len(got) != 2 {
		t.Errorf("got %d, want 2", len(got))
	}
}

func TestDeleteAll(t *testing.T) {
	db := openTestDB(t)
	ctx := context.Background()

	mustInsert(t, ctx, db, &Sample{SHA256: "d1", Source: "test", Label: "bad", LabelSource: "test"})
	mustInsert(t, ctx, db, &Sample{SHA256: "d2", Source: "test", Label: "good", LabelSource: "test"})
	if err := db.InsertReport(ctx, &Report{SHA256: "d1", Type: "re", Content: "report"}); err != nil {
		t.Fatal(err)
	}

	if err := db.DeleteAll(ctx); err != nil {
		t.Fatal(err)
	}

	counts, err := db.CountByLabel(ctx)
	if err != nil {
		t.Fatal(err)
	}
	total := 0
	for _, n := range counts {
		total += n
	}
	if total != 0 {
		t.Errorf("expected 0 samples after DeleteAll, got %d", total)
	}
}

func TestSetSkip(t *testing.T) {
	db := openTestDB(t)
	ctx := context.Background()

	mustInsert(t, ctx, db, &Sample{SHA256: "sk1", Source: "test", Label: "bad", LabelSource: "test"})
	if err := db.SetSkip(ctx, "sk1", skipBenignArchiveItem); err != nil {
		t.Fatal(err)
	}
	got, err := db.SampleBySHA256(ctx, "sk1")
	if err != nil {
		t.Fatal(err)
	}
	if got.Skip != skipBenignArchiveItem {
		t.Errorf("Skip = %q, want %q", got.Skip, skipBenignArchiveItem)
	}

	// Clear skip.
	if err := db.SetSkip(ctx, "sk1", ""); err != nil {
		t.Fatal(err)
	}
	got, err = db.SampleBySHA256(ctx, "sk1")
	if err != nil {
		t.Fatal(err)
	}
	if got.Skip != "" {
		t.Errorf("Skip = %q, want empty", got.Skip)
	}
}

func TestPGMigrationPartition(t *testing.T) {
	// The serving path runs core DDL synchronously and defers index work.
	// Nothing that needs ACCESS EXCLUSIVE on an existing index (DROP/CREATE
	// INDEX, or a DO block that issues DROP INDEX) may run before hopper is
	// serving: a logical-replica COPY holds ACCESS SHARE for hours.
	var coreN, indexN int
	sawPathRewrite := false
	for _, ddl := range pgRuntimeMigrations() {
		if isDeferrableIndexDDL(ddl) {
			indexN++
			if strings.Contains(ddl, "NOT ILIKE '%path <>%'") {
				sawPathRewrite = true
			}
			continue
		}
		coreN++
		s := strings.TrimSpace(ddl)
		u := strings.ToUpper(s)
		if strings.HasPrefix(s, "CREATE INDEX") {
			t.Errorf("CREATE INDEX leaked into the synchronous core phase: %q", ddl)
		}
		if strings.HasPrefix(u, "DROP INDEX") {
			t.Errorf("DROP INDEX leaked into the synchronous core phase: %q", ddl)
		}
		if strings.HasPrefix(u, "ANALYZE ") {
			t.Errorf("ANALYZE leaked into the synchronous core phase: %q", ddl)
		}
		if strings.HasPrefix(u, "DO $$") && strings.Contains(u, "DROP INDEX") {
			t.Errorf("index-rewrite DO leaked into the synchronous core phase: %q", ddl)
		}
	}
	if coreN == 0 || indexN == 0 {
		t.Fatalf("expected both core and index DDL, got core=%d index=%d", coreN, indexN)
	}
	if !sawPathRewrite {
		t.Fatal("expected the path <> index-rewrite DO to be deferred")
	}

	// pg_trgm: the extension is core (cheap), the GIN index is deferred.
	if isDeferrableIndexDDL(trgmExtensionDDL) {
		t.Error("trgm extension should run as core DDL, not be deferred")
	}
	if !isDeferrableIndexDDL(trgmIndexDDL) {
		t.Error("trgm GIN index should be deferred with the other indexes")
	}
}

func TestIndexRewriteHelpers(t *testing.T) {
	name, ok := concurrentDropIndexDDL(`DROP INDEX IF EXISTS idx_samples_claimed`)
	if !ok || name != "idx_samples_claimed" {
		t.Fatalf("concurrentDropIndexDDL = %q, %v", name, ok)
	}
	if _, ok := concurrentDropIndexDDL(`ALTER TABLE samples DROP COLUMN IF EXISTS forced_rescan_at`); ok {
		t.Fatal("DROP COLUMN must not look like DROP INDEX")
	}

	pathDDL := ""
	claimDDL := ""
	statusDDL := ""
	for _, ddl := range pgRuntimeMigrations() {
		if strings.Contains(ddl, "NOT ILIKE '%path <>%'") {
			pathDDL = ddl
		}
		if strings.Contains(ddl, "idx_samples_claimable") && strings.Contains(ddl, "DROP INDEX") {
			claimDDL = ddl
		}
		if strings.Contains(ddl, "NOT ILIKE '%status <>%'") {
			statusDDL = ddl
		}
	}
	// idx_samples_status is the partial-index rewrite. Its predicate MUST stay
	// known to indexRewriteHasKnownPredicate: an unknown one falls through to
	// execMigrationWithLockRetry, which runs the raw DO block and takes ACCESS
	// EXCLUSIVE on samples — a lock that waits behind a logical-replication
	// COPY and would wedge the very replica this index shrink exists to unblock.
	if statusDDL == "" {
		t.Fatal("missing idx_samples_status partial rewrite DO block")
	}
	if !isIndexRewriteDO(statusDDL) || !isDeferrableIndexDDL(statusDDL) {
		t.Fatal("status <> rewrite must be a deferrable index-rewrite DO")
	}
	if !indexRewriteHasKnownPredicate(statusDDL) {
		t.Fatal("status rewrite predicate must be known, or it takes ACCESS EXCLUSIVE")
	}
	fullStatus := `CREATE INDEX idx_samples_status ON public.samples USING btree (status, updated_at)`
	if !indexDefNeedsRewrite(statusDDL, fullStatus) {
		t.Fatal("unconditional idx_samples_status must be rewritten to the partial")
	}
	partialStatus := fullStatus + ` WHERE (status <> ''::text)`
	if indexDefNeedsRewrite(statusDDL, partialStatus) {
		t.Fatal("partial idx_samples_status must not be rewritten again")
	}
	if pathDDL == "" || claimDDL == "" {
		t.Fatalf("missing rewrite DO blocks: path=%t claimable=%t", pathDDL != "", claimDDL != "")
	}
	if !isIndexRewriteDO(pathDDL) || !isDeferrableIndexDDL(pathDDL) {
		t.Fatal("path <> rewrite must be a deferrable index-rewrite DO")
	}
	// The guard rewrites whatever partials still carry a pre-path <> ''
	// predicate. Three left the list when good-stale/new-stale/new-interesting
	// were retired with their queues, so the bound tracks the survivors rather
	// than a fixed count that a retirement would break again.
	names := indexNamesInDDL(pathDDL)
	if len(names) < 6 {
		t.Fatalf("path rewrite indexes = %v", names)
	}
	old := `CREATE INDEX idx_samples_bad_miss_newest ON public.samples USING btree (created_at DESC, id DESC) WHERE ((label = 'bad'::text) AND (parent = ''::text))`
	if !indexDefNeedsRewrite(pathDDL, old) {
		t.Fatal("old bad index missing path <> must be stale")
	}
	fresh := old + ` AND (path <> ''::text)`
	if indexDefNeedsRewrite(pathDDL, fresh) {
		t.Fatal("index already carrying path <> must not be rewritten")
	}
	if !indexRewriteHasKnownPredicate(claimDDL) {
		t.Fatal("claimable rewrite should have a known predicate")
	}
}

func TestRetryDeferredMigrationsSoftFail(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	calls := 0
	build := func(context.Context) error {
		calls++
		if calls == 1 {
			cancel()
			return errors.New("lock timeout")
		}
		t.Fatal("must not retry after ctx cancel")
		return nil
	}
	if err := retryDeferredMigrations(ctx, build); err != nil {
		t.Fatalf("retryDeferredMigrations returned %v, want nil (soft fail)", err)
	}
	if calls != 1 {
		t.Fatalf("calls = %d, want 1", calls)
	}
}

func TestReapStuckSamples(t *testing.T) {
	db := openTestDB(t)
	ctx := context.Background()

	// poison: handed out MaxClaimAttempts times, never analyzed → reaped.
	mustInsert(t, ctx, db, &Sample{SHA256: "poison", Source: "test", Label: "unknown", LabelSource: "test"})
	// fresh: handed out once, well under the threshold → left alone.
	mustInsert(t, ctx, db, &Sample{SHA256: "fresh", Source: "test", Label: "unknown", LabelSource: "test"})
	// done: analyzed, so it must never be reaped no matter how many attempts.
	mustInsert(t, ctx, db, &Sample{SHA256: "done", Source: "test", Label: "unknown", LabelSource: "test"})
	mustAnalyze(t, ctx, db, "done", 1)

	for range MaxClaimAttempts {
		if err := db.IncrementAttempts(ctx, []string{"poison", "done"}); err != nil {
			t.Fatal(err)
		}
	}
	if err := db.IncrementAttempts(ctx, []string{"fresh"}); err != nil {
		t.Fatal(err)
	}

	pendingBefore, err := db.CountPending(ctx)
	if err != nil {
		t.Fatal(err)
	}

	n, err := db.ReapStuck(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if n != 1 {
		t.Fatalf("ReapStuck reaped %d, want 1 (only the poison sample)", n)
	}

	if got := skipOf(t, ctx, db, "poison"); got != "stuck" {
		t.Errorf("poison skip = %q, want %q", got, "stuck")
	}
	if got := skipOf(t, ctx, db, "fresh"); got != "" {
		t.Errorf("fresh skip = %q, want empty (under attempt threshold)", got)
	}
	if got := skipOf(t, ctx, db, "done"); got != "" {
		t.Errorf("done skip = %q, want empty (analyzed rows are never poison)", got)
	}

	// Reaping a stuck sample removes it from the pending pool.
	pendingAfter, err := db.CountPending(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if pendingAfter != pendingBefore-1 {
		t.Errorf("pending = %d after reap, want %d", pendingAfter, pendingBefore-1)
	}

	// Idempotent: a second pass finds nothing new.
	if n, err := db.ReapStuck(ctx); err != nil || n != 0 {
		t.Fatalf("second ReapStuck = (%d, %v), want (0, nil)", n, err)
	}
}

func TestReapOversizedSamples(t *testing.T) {
	db := openTestDB(t)
	ctx := context.Background()

	// huge: bigger than any worker's advertised cap → reaped.
	mustInsert(t, ctx, db, &Sample{SHA256: "huge", Source: "test", Label: "unknown", LabelSource: "test", SizeBytes: MaxJobBytes + 1})
	// fits: exactly at the cap → left alone (workers accept it).
	mustInsert(t, ctx, db, &Sample{SHA256: "fits", Source: "test", Label: "unknown", LabelSource: "test", SizeBytes: MaxJobBytes})
	// bigdone: oversized but already analyzed → never reaped.
	mustInsert(t, ctx, db, &Sample{SHA256: "bigdone", Source: "test", Label: "unknown", LabelSource: "test", SizeBytes: MaxJobBytes + 1})
	mustAnalyze(t, ctx, db, "bigdone", 1)

	n, err := db.ReapOversized(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if n != 1 {
		t.Fatalf("ReapOversized reaped %d, want 1 (only the pending oversized sample)", n)
	}

	if got := skipOf(t, ctx, db, "huge"); got != "oversized" {
		t.Errorf("huge skip = %q, want %q", got, "oversized")
	}
	if got := skipOf(t, ctx, db, "fits"); got != "" {
		t.Errorf("fits skip = %q, want empty (at the cap, still claimable)", got)
	}
	if got := skipOf(t, ctx, db, "bigdone"); got != "" {
		t.Errorf("bigdone skip = %q, want empty (analyzed rows are never reaped)", got)
	}

	// Idempotent: a second pass finds nothing new.
	if n, err := db.ReapOversized(ctx); err != nil || n != 0 {
		t.Fatalf("second ReapOversized = (%d, %v), want (0, nil)", n, err)
	}
}

func TestSetNote(t *testing.T) {
	db := openTestDB(t)
	ctx := context.Background()

	mustInsert(t, ctx, db, &Sample{SHA256: "n1", Source: "test", Label: "bad", LabelSource: "test"})
	if err := db.SetNote(ctx, "n1", "analysis timed out"); err != nil {
		t.Fatal(err)
	}
	got, err := db.SampleBySHA256(ctx, "n1")
	if err != nil {
		t.Fatal(err)
	}
	if got.Note != "analysis timed out" {
		t.Errorf("Note = %q, want %q", got.Note, "analysis timed out")
	}
	if got.LastErrorAt == nil {
		t.Fatal("LastErrorAt not set")
	}

	if err := db.SetNote(ctx, "n1", ""); err != nil {
		t.Fatal(err)
	}
	got, err = db.SampleBySHA256(ctx, "n1")
	if err != nil {
		t.Fatal(err)
	}
	if got.Note != "" {
		t.Errorf("Note = %q, want empty", got.Note)
	}
	if got.LastErrorAt != nil {
		t.Errorf("LastErrorAt = %v, want nil", got.LastErrorAt)
	}
}

func TestInsertSampleBatchPersistsProvenance(t *testing.T) {
	db := openTestDB(t)
	ctx := context.Background()

	at := time.Date(2026, 6, 12, 16, 33, 17, 0, time.UTC)
	prov := []byte(`{"schema_version":"1.0","registry":{"source_id":"npm"}}`)
	s := &Sample{
		SHA256: "pv1", Source: "forager", Label: "bad", LabelSource: "forager",
		Path: "bad/pv1", SizeBytes: 10, Provenance: prov, FetchedAt: &at,
	}
	if _, _, err := db.InsertSampleBatch(ctx, []*Sample{s}); err != nil {
		t.Fatal(err)
	}

	var gotProv []byte
	var gotFetched sql.NullString
	if err := db.lite.QueryRowContext(ctx,
		`SELECT provenance, fetched_at FROM samples WHERE sha256 = ?`, "pv1").
		Scan(&gotProv, &gotFetched); err != nil {
		t.Fatal(err)
	}
	if !json.Valid(gotProv) {
		t.Fatalf("provenance not persisted/valid: %q", gotProv)
	}
	var meta struct {
		Registry struct {
			SourceID string `json:"source_id"`
		} `json:"registry"`
	}
	if err := json.Unmarshal(gotProv, &meta); err != nil || meta.Registry.SourceID != "npm" {
		t.Errorf("provenance round-trip = %q", gotProv)
	}
	if !gotFetched.Valid || !strings.Contains(gotFetched.String, "2026-06-12") {
		t.Errorf("fetched_at = %q, want it to carry 2026-06-12", gotFetched.String)
	}
}

func TestInsertSampleBatch(t *testing.T) {
	db := openTestDB(t)
	ctx := context.Background()

	samples := []*Sample{
		{SHA256: "b1", Source: "test", Label: "bad", LabelSource: "test", Path: "test/b1", SizeBytes: 100},
		{SHA256: "b2", Source: "test", Label: "good", LabelSource: "test", Path: "test/b2", SizeBytes: 200},
		{SHA256: "b3", Source: "test", Label: "bad", LabelSource: "test", Path: "test/b3", SizeBytes: 300},
	}
	_, needs, err := db.InsertSampleBatch(ctx, samples)
	if err != nil {
		t.Fatal(err)
	}
	// Note: n might be 0 currently because we don't distinguish INSERT vs UPDATE easily in PG/SQLite drivers
	// but needs should be 3.
	if len(needs) != 3 {
		t.Errorf("needs analysis = %d, want 3", len(needs))
	}

	// Duplicate batch: should still return needs analysis if they haven't been analyzed.
	_, needs, err = db.InsertSampleBatch(ctx, samples)
	if err != nil {
		t.Fatal(err)
	}
	if len(needs) != 3 {
		t.Errorf("duplicate batch needs analysis = %d, want 3", len(needs))
	}

	// Mock an analysis result.
	if err := db.UpdateLitmusResult(ctx, "b1", []byte("{}")); err != nil {
		t.Fatal(err)
	}

	// Third batch: b1 should now be missing from needs.
	_, needs, err = db.InsertSampleBatch(ctx, samples)
	if err != nil {
		t.Fatal(err)
	}
	if len(needs) != 2 {
		t.Errorf("needs analysis = %d, want 2 (b1 has result)", len(needs))
	}

	// Empty batch.
	n, needs, err := db.InsertSampleBatch(ctx, nil)
	if err != nil {
		t.Fatal(err)
	}
	if n != 0 || len(needs) != 0 {
		t.Errorf("empty batch n=%d needs=%d, want 0,0", n, len(needs))
	}
}

func TestClassifyLabelTransition(t *testing.T) {
	tests := []struct {
		name                           string
		stored, storedSrc, storedSkip  string
		in, inSrc                      string
		wantCategory, wantFrom, wantTo string
	}{
		{"promote unknown to good", "unknown", "forager", "", "good", "forager", "promoted", "unknown", "good"},
		{"promote unknown to bad", "unknown", "forager", "", "bad", "forager", "promoted", "unknown", "bad"},
		{"conflict good then bad", "good", "forager", "", "bad", "forager", "conflict", "good", "bad"},
		{"conflict bad then good", "bad", "forager", "", "good", "forager", "conflict", "bad", "bad"},
		{"unknown does not demote good", "good", "forager", "", "unknown", "forager", "", "", ""},
		{"equal labels no change", "bad", "forager", "", "bad", "forager", "", "", ""},
		{"promote unknown to sighted", "unknown", "forager", "", "sighted", "forager", "promoted", "unknown", "sighted"},
		{"promote sighted to good", "sighted", "forager", "", "good", "forager", "promoted", "sighted", "good"},
		{"promote sighted to bad", "sighted", "forager", "", "bad", "promoter", "promoted", "sighted", "bad"},
		{"sighted does not demote good", "good", "forager", "", "sighted", "forager", "", "", ""},
		{"sighted does not demote bad", "bad", "forager", "", "sighted", "forager", "", "", ""},
		{"cleared marker rehabilitates to sighted dir", "good", "marker", "", "sighted", "forager", "rehabilitated", "good", "sighted"},
		{"incoming marker is logged in go", "unknown", "forager", "", "good", "marker", "", "", ""},
		{"rehabilitate cleared marker", "bad", "marker", "misclassified", "bad", "forager", "rehabilitated", "bad", "bad"},
		{"rehabilitate flipped marker", "good", "marker", "misclassified", "bad", "forager", "rehabilitated", "good", "bad"},
		{"stale marker already clean no change", "bad", "marker", "", "bad", "forager", "", "", ""},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			cat, from, to := classifyLabelTransition(tt.stored, tt.storedSrc, tt.storedSkip, tt.in, tt.inSrc)
			if cat != tt.wantCategory || from != tt.wantFrom || to != tt.wantTo {
				t.Errorf("classifyLabelTransition = (%q,%q,%q), want (%q,%q,%q)",
					cat, from, to, tt.wantCategory, tt.wantFrom, tt.wantTo)
			}
		})
	}
}

// TestLabelPrecedenceOnReobservation exercises the ON CONFLICT pool-precedence
// resolution end-to-end through InsertSampleBatch (the same path the load
// pipeline uses), one rule per subtest.
func TestLabelPrecedenceOnReobservation(t *testing.T) {
	reobserve := func(t *testing.T, ctx context.Context, db *DB, s *Sample) {
		t.Helper()
		if _, _, err := db.InsertSampleBatch(ctx, []*Sample{s}); err != nil {
			t.Fatalf("InsertSampleBatch: %v", err)
		}
	}
	want := func(t *testing.T, ctx context.Context, db *DB, sha, label, source, skip string) {
		t.Helper()
		got, err := db.SampleBySHA256(ctx, sha)
		if err != nil {
			t.Fatalf("SampleBySHA256(%s): %v", sha, err)
		}
		if got.Label != label || got.LabelSource != source || got.Skip != skip {
			t.Errorf("%s: got (label=%q source=%q skip=%q), want (label=%q source=%q skip=%q)",
				sha, got.Label, got.LabelSource, got.Skip, label, source, skip)
		}
	}

	t.Run("promote unknown to good", func(t *testing.T) {
		db := openTestDB(t)
		ctx := context.Background()
		reobserve(t, ctx, db, &Sample{SHA256: "p1", Source: "test", Label: "unknown", LabelSource: "forager", Path: "unknown/p1", SizeBytes: 8})
		reobserve(t, ctx, db, &Sample{SHA256: "p1", Source: "test", Label: "good", LabelSource: "forager", Path: "good/p1", SizeBytes: 8})
		want(t, ctx, db, "p1", "good", "forager", "")
	})

	t.Run("promote unknown to bad", func(t *testing.T) {
		db := openTestDB(t)
		ctx := context.Background()
		reobserve(t, ctx, db, &Sample{SHA256: "p2", Source: "test", Label: "unknown", LabelSource: "forager", Path: "unknown/p2", SizeBytes: 8})
		reobserve(t, ctx, db, &Sample{SHA256: "p2", Source: "test", Label: "bad", LabelSource: "forager", Path: "bad/p2", SizeBytes: 8})
		want(t, ctx, db, "p2", "bad", "forager", "")
	})

	t.Run("conflict good then bad", func(t *testing.T) {
		db := openTestDB(t)
		ctx := context.Background()
		reobserve(t, ctx, db, &Sample{SHA256: "c1", Source: "test", Label: "good", LabelSource: "forager", Path: "good/c1", SizeBytes: 8})
		reobserve(t, ctx, db, &Sample{SHA256: "c1", Source: "test", Label: "bad", LabelSource: "forager", Path: "bad/c1", SizeBytes: 8})
		want(t, ctx, db, "c1", "bad", "conflict", "conflict")
	})

	t.Run("conflict bad then good resolves to bad", func(t *testing.T) {
		db := openTestDB(t)
		ctx := context.Background()
		reobserve(t, ctx, db, &Sample{SHA256: "c2", Source: "test", Label: "bad", LabelSource: "forager", Path: "bad/c2", SizeBytes: 8})
		reobserve(t, ctx, db, &Sample{SHA256: "c2", Source: "test", Label: "good", LabelSource: "forager", Path: "good/c2", SizeBytes: 8})
		want(t, ctx, db, "c2", "bad", "conflict", "conflict")
	})

	t.Run("unknown does not demote", func(t *testing.T) {
		db := openTestDB(t)
		ctx := context.Background()
		reobserve(t, ctx, db, &Sample{SHA256: "d1", Source: "test", Label: "good", LabelSource: "forager", Path: "good/d1", SizeBytes: 8})
		reobserve(t, ctx, db, &Sample{SHA256: "d1", Source: "test", Label: "unknown", LabelSource: "forager", Path: "unknown/d1", SizeBytes: 8})
		want(t, ctx, db, "d1", "good", "forager", "")
	})

	t.Run("promote unknown to sighted", func(t *testing.T) {
		db := openTestDB(t)
		ctx := context.Background()
		reobserve(t, ctx, db, &Sample{SHA256: "s1", Source: "test", Label: "unknown", LabelSource: "forager", Path: "unknown/s1", SizeBytes: 8})
		reobserve(t, ctx, db, &Sample{SHA256: "s1", Source: "test", Label: "sighted", LabelSource: "forager", Path: "sighted/s1", SizeBytes: 8})
		want(t, ctx, db, "s1", "sighted", "forager", "")
	})

	t.Run("sighted does not demote good", func(t *testing.T) {
		db := openTestDB(t)
		ctx := context.Background()
		reobserve(t, ctx, db, &Sample{SHA256: "s2", Source: "test", Label: "good", LabelSource: "forager", Path: "good/s2", SizeBytes: 8})
		reobserve(t, ctx, db, &Sample{SHA256: "s2", Source: "test", Label: "sighted", LabelSource: "forager", Path: "sighted/s2", SizeBytes: 8})
		want(t, ctx, db, "s2", "good", "forager", "")
	})

	t.Run("sighted does not demote bad", func(t *testing.T) {
		db := openTestDB(t)
		ctx := context.Background()
		reobserve(t, ctx, db, &Sample{SHA256: "s3", Source: "test", Label: "bad", LabelSource: "forager", Path: "bad/s3", SizeBytes: 8})
		reobserve(t, ctx, db, &Sample{SHA256: "s3", Source: "test", Label: "sighted", LabelSource: "forager", Path: "sighted/s3", SizeBytes: 8})
		want(t, ctx, db, "s3", "bad", "forager", "")
	})

	t.Run("promote sighted to bad", func(t *testing.T) {
		db := openTestDB(t)
		ctx := context.Background()
		reobserve(t, ctx, db, &Sample{SHA256: "s4", Source: "test", Label: "sighted", LabelSource: "forager", Path: "sighted/s4", SizeBytes: 8})
		reobserve(t, ctx, db, &Sample{SHA256: "s4", Source: "test", Label: "bad", LabelSource: "promoter", Path: "bad/s4", SizeBytes: 8})
		want(t, ctx, db, "s4", "bad", "promoter", "")
	})

	t.Run("promote sighted to good", func(t *testing.T) {
		db := openTestDB(t)
		ctx := context.Background()
		reobserve(t, ctx, db, &Sample{SHA256: "s5", Source: "test", Label: "sighted", LabelSource: "forager", Path: "sighted/s5", SizeBytes: 8})
		reobserve(t, ctx, db, &Sample{SHA256: "s5", Source: "test", Label: "good", LabelSource: "forager", Path: "good/s5", SizeBytes: 8})
		want(t, ctx, db, "s5", "good", "forager", "")
	})

	t.Run("incoming marker is authoritative", func(t *testing.T) {
		db := openTestDB(t)
		ctx := context.Background()
		reobserve(t, ctx, db, &Sample{SHA256: "m1", Source: "test", Label: "unknown", LabelSource: "forager", Path: "unknown/m1", SizeBytes: 8})
		// A good/ file carrying a .BAD marker: Go flips it before insert.
		reobserve(t, ctx, db, &Sample{SHA256: "m1", Source: "test", Label: "bad", LabelSource: "marker", Skip: "misclassified", Path: "good/m1", SizeBytes: 8})
		want(t, ctx, db, "m1", "bad", "marker", "misclassified")
	})

	t.Run("rehabilitate after marker removed", func(t *testing.T) {
		db := openTestDB(t)
		ctx := context.Background()
		// Stored quarantine from a good/ file with a .BAD marker.
		reobserve(t, ctx, db, &Sample{SHA256: "r1", Source: "test", Label: "bad", LabelSource: "marker", Skip: "misclassified", Path: "good/r1", SizeBytes: 8})
		// Moved into bad/ with the marker dropped: plain pool observation.
		reobserve(t, ctx, db, &Sample{SHA256: "r1", Source: "test", Label: "bad", LabelSource: "forager", Path: "bad/r1", SizeBytes: 8})
		want(t, ctx, db, "r1", "bad", "forager", "")
	})

	t.Run("missing auto-heals on re-observation", func(t *testing.T) {
		db := openTestDB(t)
		ctx := context.Background()
		reobserve(t, ctx, db, &Sample{SHA256: "g1", Source: "test", Label: "bad", LabelSource: "forager", Path: "bad/g1", SizeBytes: 8})
		if err := db.SetSkip(ctx, "g1", "missing"); err != nil {
			t.Fatal(err)
		}
		reobserve(t, ctx, db, &Sample{SHA256: "g1", Source: "test", Label: "bad", LabelSource: "forager", Path: "bad/g1", SizeBytes: 8})
		want(t, ctx, db, "g1", "bad", "forager", "")
	})

	t.Run("missing returning as conflict is quarantined", func(t *testing.T) {
		db := openTestDB(t)
		ctx := context.Background()
		reobserve(t, ctx, db, &Sample{SHA256: "g2", Source: "test", Label: "good", LabelSource: "forager", Path: "good/g2", SizeBytes: 8})
		if err := db.SetSkip(ctx, "g2", "missing"); err != nil {
			t.Fatal(err)
		}
		reobserve(t, ctx, db, &Sample{SHA256: "g2", Source: "test", Label: "bad", LabelSource: "forager", Path: "bad/g2", SizeBytes: 8})
		want(t, ctx, db, "g2", "bad", "conflict", "conflict")
	})

	t.Run("hard skip preserved on promotion", func(t *testing.T) {
		db := openTestDB(t)
		ctx := context.Background()
		reobserve(t, ctx, db, &Sample{SHA256: "h1", Source: "test", Label: "unknown", LabelSource: "forager", Skip: "corrupt", Path: "unknown/h1", SizeBytes: 8})
		reobserve(t, ctx, db, &Sample{SHA256: "h1", Source: "test", Label: "good", LabelSource: "forager", Path: "good/h1", SizeBytes: 8})
		want(t, ctx, db, "h1", "good", "forager", "corrupt")
	})

	t.Run("archive member never changes top-level label", func(t *testing.T) {
		db := openTestDB(t)
		ctx := context.Background()
		reobserve(t, ctx, db, &Sample{SHA256: "a1", Source: "test", Label: "good", LabelSource: "forager", Path: "good/a1", SizeBytes: 8})
		// Same content hash seen inside a bad archive (parent set).
		reobserve(t, ctx, db, &Sample{SHA256: "a1", Source: "test", Label: "bad", LabelSource: "forager", Parent: "archivesha", Path: "bad/arc.zip!!a1", SizeBytes: 8})
		want(t, ctx, db, "a1", "good", "forager", "")
	})
}

func TestConflictReview(t *testing.T) {
	db := openTestDB(t)
	ctx := context.Background()

	// Create a good+bad conflict and an ordinary bad sample.
	if _, _, err := db.InsertSampleBatch(ctx, []*Sample{{SHA256: "k1", Source: "test", Label: "good", LabelSource: "forager", Path: "good/k1", SizeBytes: 8}}); err != nil {
		t.Fatal(err)
	}
	if _, _, err := db.InsertSampleBatch(ctx, []*Sample{{SHA256: "k1", Source: "test", Label: "bad", LabelSource: "forager", Path: "bad/k1", SizeBytes: 8}}); err != nil {
		t.Fatal(err)
	}
	if _, _, err := db.InsertSampleBatch(ctx, []*Sample{{SHA256: "k2", Source: "test", Label: "bad", LabelSource: "forager", Path: "bad/k2", SizeBytes: 8}}); err != nil {
		t.Fatal(err)
	}

	got, err := db.ConflictReview(ctx, 0, 100)
	if err != nil {
		t.Fatal(err)
	}
	if len(got) != 1 || got[0].SHA256 != "k1" {
		t.Fatalf("ConflictReview returned %d rows (%v), want just k1", len(got), got)
	}
}

func TestInsertSampleBatchMarksReplaced(t *testing.T) {
	db := openTestDB(t)
	ctx := context.Background()

	// Insert an unanalyzed sample at a known path.
	mustInsert(t, ctx, db, &Sample{SHA256: "old1", Source: "test", Label: "bad", LabelSource: "test", Path: "/data/pkg.whl", SizeBytes: 100})

	// Re-insert the same path with a different SHA256 (file was replaced on disk).
	batch := []*Sample{
		{SHA256: "new1", Source: "test", Label: "bad", LabelSource: "test", Path: "/data/pkg.whl", SizeBytes: 200},
	}
	_, _, err := db.InsertSampleBatch(ctx, batch)
	if err != nil {
		t.Fatal(err)
	}

	// The old row should be marked as replaced.
	old, err := db.SampleBySHA256(ctx, "old1")
	if err != nil {
		t.Fatal(err)
	}
	if old.Skip != "replaced" {
		t.Errorf("old sample skip = %q, want 'replaced'", old.Skip)
	}

	// The new row should remain claimable (skip empty).
	nw, err := db.SampleBySHA256(ctx, "new1")
	if err != nil {
		t.Fatal(err)
	}
	if nw.Skip != "" {
		t.Errorf("new sample skip = %q, want empty", nw.Skip)
	}
}

func TestInsertSampleBatchDoesNotReplaceAnalyzed(t *testing.T) {
	db := openTestDB(t)
	ctx := context.Background()

	// Insert a sample and give it analysis results.
	mustInsert(t, ctx, db, &Sample{SHA256: "analyzed1", Source: "test", Label: "bad", LabelSource: "test", Path: "/data/pkg2.whl", SizeBytes: 100})
	cleave := []byte(`{"fs":[{"sha":"analyzed1","f":"H2O","x":5,"type":"zip","dp":0,"ts":[]}]}`)
	if err := db.UpdateCleaveResult(ctx, "analyzed1", cleave, nil, ""); err != nil {
		t.Fatal(err)
	}

	// Re-insert the same path with a different SHA256.
	batch := []*Sample{
		{SHA256: "new2", Source: "test", Label: "bad", LabelSource: "test", Path: "/data/pkg2.whl", SizeBytes: 200},
	}
	if _, _, err := db.InsertSampleBatch(ctx, batch); err != nil {
		t.Fatal(err)
	}

	// The analyzed row should NOT be marked as replaced.
	old, err := db.SampleBySHA256(ctx, "analyzed1")
	if err != nil {
		t.Fatal(err)
	}
	if old.Skip != "" {
		t.Errorf("analyzed sample skip = %q, want empty", old.Skip)
	}
}

func TestStaleSamples(t *testing.T) {
	db := openTestDB(t)
	ctx := context.Background()

	mustInsert(t, ctx, db, &Sample{SHA256: "st1", Source: "test", Label: "bad", LabelSource: "test", Path: "/data/s1"})
	mustInsert(t, ctx, db, &Sample{SHA256: "st2", Source: "test", Label: "bad", LabelSource: "test", Path: "/data/s2"})
	mustInsert(t, ctx, db, &Sample{SHA256: "st3", Source: "test", Label: "bad", LabelSource: "test", Path: "/other/s3"})

	// All samples were just inserted, so using a future threshold should return all under /data.
	future := time.Now().Add(time.Hour)
	got, err := db.StaleSamples(ctx, []string{"/data"}, future, 10)
	if err != nil {
		t.Fatal(err)
	}
	if len(got) != 2 {
		t.Errorf("got %d stale samples, want 2", len(got))
	}

	// Threshold in the past: no samples are stale.
	past := time.Date(2020, 1, 1, 0, 0, 0, 0, time.UTC)
	got, err = db.StaleSamples(ctx, []string{"/data"}, past, 10)
	if err != nil {
		t.Fatal(err)
	}
	if len(got) != 0 {
		t.Errorf("got %d stale samples with past threshold, want 0", len(got))
	}
}

func TestClaimJobsForceRescan(t *testing.T) {
	ctx := t.Context()
	db := openTestDB(t)

	mustInsert(t, ctx, db, &Sample{SHA256: "fr1", Source: "test", Label: "bad", Path: "bad/pkg/a.bin"})
	mustInsert(t, ctx, db, &Sample{SHA256: "fr2", Source: "test", Label: "bad", Path: "bad/other/b.bin"})
	mustInsert(t, ctx, db, &Sample{SHA256: "fr3", Source: "test", Label: "bad", Path: "bad/pkg/skipped.bin", Skip: "unsupported"})

	// Seed prior analysis results so the rows look already-analyzed.
	for _, sha := range []string{"fr1", "fr2", "fr3"} {
		result := fmt.Appendf(nil, `{"fs":[{"sha":%q,"type":"elf","x":50,"dp":0,"ts":[{"l":5,"c":1.0}]}]}`, sha)
		if err := db.UpdateCleaveResult(ctx, sha, result, nil, "oldtv"); err != nil {
			t.Fatalf("UpdateCleaveResult(%s): %v", sha, err)
		}
		if err := db.UpdateLitmusResult(ctx, sha, []byte(`{"prob":0.9}`)); err != nil {
			t.Fatalf("UpdateLitmusResult(%s): %v", sha, err)
		}
	}

	// hopperStart in the future so all three rows' analyzed_at is "before"
	// start. Only fr1 should be returned: fr2 is outside the prefix, fr3 is
	// marked skip.
	hopperStart := time.Now().Add(time.Hour)
	jobs, err := db.ForceRescanCandidates(ctx, hopperStart, []string{"bad/pkg"}, 10)
	if err != nil {
		t.Fatal(err)
	}
	if len(jobs) != 1 || jobs[0].SHA256 != "fr1" {
		t.Fatalf("force-rescan candidates: got %+v, want [fr1]", jobs)
	}

	// Candidate fetches must not mutate samples. Prior analysis stays put.
	rescanned, err := db.SampleBySHA256(ctx, "fr1")
	if err != nil {
		t.Fatal(err)
	}
	if rescanned.CleaveResult == nil || rescanned.LitmusResult == nil || rescanned.TraitsVersion != "oldtv" {
		t.Fatalf("fr1 data was reset at fetch time: %+v", rescanned)
	}
	for _, sha := range []string{"fr2", "fr3"} {
		s, err := db.SampleBySHA256(ctx, sha)
		if err != nil {
			t.Fatal(err)
		}
		if s.CleaveResult == nil || s.LitmusResult == nil || s.TraitsVersion != "oldtv" {
			t.Fatalf("%s unexpectedly affected: %+v", sha, s)
		}
	}

	// Empty prefixes: caller is opting out of Tier 2.
	jobs, err = db.ForceRescanCandidates(ctx, hopperStart, nil, 10)
	if err != nil {
		t.Fatal(err)
	}
	if len(jobs) != 0 {
		t.Fatalf("empty prefixes should return no candidates: got %+v", jobs)
	}
}

func TestClaimJobsStaleTraitsOrdering(t *testing.T) {
	ctx := t.Context()
	db := openTestDB(t)

	type sample struct {
		sha    string
		label  string
		score  int
		traits string
		litmus string
	}
	samples := []sample{
		// Disagrees with label and closest to the litmus boundary: first.
		{sha: "1111111111111111111111111111111111111111111111111111111111111111", label: "bad", score: 0, traits: "", litmus: `{"prob":0.49}`},
		// Disagrees with label but farther from the boundary: second.
		{sha: "2222222222222222222222222222222222222222222222222222222222222222", label: "good", score: 50, traits: `{"l":5,"c":1.0}`, litmus: `{"prob":0.10}`},
		// Does not disagree, but is near the boundary: third.
		{sha: "3333333333333333333333333333333333333333333333333333333333333333", label: "good", score: 0, traits: "", litmus: `{"prob":0.51}`},
		// Does not disagree and is farther from the boundary: last.
		{sha: "4444444444444444444444444444444444444444444444444444444444444444", label: "bad", score: 50, traits: `{"l":5,"c":1.0}`, litmus: `{"prob":0.90}`},
	}
	for _, s := range samples {
		mustInsert(t, ctx, db, &Sample{SHA256: s.sha, Source: "test", Label: s.label, LabelSource: "test"})
		mustAnalyzeWithTraits(t, ctx, db, s.sha, s.score, s.traits)
		if err := db.UpdateLitmusResult(ctx, s.sha, []byte(s.litmus)); err != nil {
			t.Fatal(err)
		}
	}
	old := time.Now().Add(-96 * time.Hour).UTC().Format(time.RFC3339Nano)
	if _, err := db.lite.ExecContext(ctx,
		`UPDATE samples SET analyzed_at = ?, traits_version = 'old-traits'`,
		old); err != nil {
		t.Fatal(err)
	}

	jobs, err := db.StaleTraitsCandidates(ctx, "new-traits", 72*time.Hour, time.Now(), 4)
	if err != nil {
		t.Fatal(err)
	}
	want := []string{samples[0].sha, samples[1].sha, samples[2].sha, samples[3].sha}
	if len(jobs) != len(want) {
		t.Fatalf("got %d jobs, want %d: %+v", len(jobs), len(want), jobs)
	}
	for i := range want {
		if jobs[i].SHA256 != want[i] {
			t.Fatalf("job %d sha = %s, want %s; jobs=%+v", i, jobs[i].SHA256, want[i], jobs)
		}
	}
}

// A reference-only row — a registry sidecar or a fetched dependency whose bytes
// never reached hopper — is claimable on every other count (parent = ” by
// design, cleave_result set, traits stale) but has no path, so no worker can be
// served its bytes. The stale-traits tier must not hand one out: nothing would
// clean up after the failed claim, since reapStuck only reaps rows with
// cleave_result IS NULL and prune only marks 'missing' when no location survives.
func TestStaleTraitsSkipsRowsWithNoServablePath(t *testing.T) {
	ctx := t.Context()
	db := openTestDB(t)

	const (
		archive  = "a100000000000000000000000000000000000000000000000000000000000000"
		servable = "b100000000000000000000000000000000000000000000000000000000000000"
		fetched  = "c100000000000000000000000000000000000000000000000000000000000000"
		sidecar  = "d100000000000000000000000000000000000000000000000000000000000000"
	)
	mustInsert(t, ctx, db, &Sample{
		SHA256: archive, Source: "test", Label: "unknown", LabelSource: "test",
		Path: "incoming/pkg.tgz",
	})
	// A top-level sample with real bytes on disk: the tier's normal customer.
	mustInsert(t, ctx, db, &Sample{
		SHA256: servable, Source: "test", Label: "unknown", LabelSource: "test",
		Path: "incoming/standalone.bin",
	})
	// Reference edges: containmentColumns blanks samples.path for both.
	mustInsert(t, ctx, db, &Sample{
		SHA256: fetched, Source: "test", Label: "unknown", LabelSource: "test",
		Path: "incoming/pkg.tgz!!dep-1.0.0.tgz", Parent: archive,
		LocationRel: string(RelFetched),
	})
	mustInsert(t, ctx, db, &Sample{
		SHA256: sidecar, Source: "test", Label: "unknown", LabelSource: "test",
		Path: "incoming/pkg.tgz!!pkg@1.0.0.registry.json", Parent: archive,
		LocationRel: string(RelRegistry),
	})
	for _, sha := range []string{servable, fetched, sidecar} {
		mustAnalyzeWithTraits(t, ctx, db, sha, 0, "")
	}
	old := time.Now().Add(-96 * time.Hour).UTC().Format(time.RFC3339Nano)
	if _, err := db.lite.ExecContext(ctx,
		`UPDATE samples SET analyzed_at = ?, traits_version = 'old-traits'`, old); err != nil {
		t.Fatal(err)
	}

	// Guard the premise: without the path filter these rows would qualify, so
	// the assertion below tests the filter rather than some other exclusion.
	for _, sha := range []string{fetched, sidecar} {
		var parent, path string
		if err := db.lite.QueryRowContext(ctx,
			`SELECT parent, path FROM samples WHERE sha256 = ?`, sha).Scan(&parent, &path); err != nil {
			t.Fatal(err)
		}
		if parent != "" || path != "" {
			t.Fatalf("%s: parent=%q path=%q, want both empty", sha, parent, path)
		}
	}

	jobs, err := db.StaleTraitsCandidates(ctx, "new-traits", 72*time.Hour, time.Now(), 10)
	if err != nil {
		t.Fatal(err)
	}
	if len(jobs) != 1 || jobs[0].SHA256 != servable {
		t.Fatalf("got %+v, want only the servable sample %s", jobs, servable)
	}
}

// A first analysis is not a renewal; a second one is, and whether it learned
// anything is decided by the traits version rather than by the fact of the
// re-run. The distinction is what separates a deliberate rescan from a producer
// re-posting a verdict hopper already holds.
func TestStoreResultReportsRenewals(t *testing.T) {
	ctx := t.Context()
	db := openTestDB(t)

	const sha = "e100000000000000000000000000000000000000000000000000000000000000"
	mustInsert(t, ctx, db, &Sample{
		SHA256: sha, Source: "test", Label: "unknown", LabelSource: "test",
		Path: "incoming/thing.bin",
	})
	result := []byte(`{"files":[{"sha":"` + sha + `","type":"elf","depth":0}]}`)

	first, err := db.StoreResult(ctx, sha, result, nil, nil, nil, "traits-1")
	if err != nil {
		t.Fatal(err)
	}
	if first.Renewed() {
		t.Error("a first analysis must not report as a renewal")
	}
	if first.Redundant("traits-1") {
		t.Error("a first analysis cannot be redundant")
	}

	// Same analyzer: the re-run could not have learned anything.
	same, err := db.StoreResult(ctx, sha, result, nil, nil, nil, "traits-1")
	if err != nil {
		t.Fatal(err)
	}
	if !same.Renewed() {
		t.Error("re-analyzing an analyzed sample is a renewal")
	}
	if !same.Redundant("traits-1") {
		t.Error("a renewal at the same traits version is redundant")
	}
	if same.PriorTraitsVersion != "traits-1" {
		t.Errorf("prior traits = %q, want traits-1", same.PriorTraitsVersion)
	}
	if same.PriorAnalyzedAt.IsZero() {
		t.Error("a renewal must carry the analysis time it replaced")
	}

	// Analyzer moved: a real refresh, not waste.
	moved, err := db.StoreResult(ctx, sha, result, nil, nil, nil, "traits-2")
	if err != nil {
		t.Fatal(err)
	}
	if !moved.Renewed() {
		t.Error("still a renewal")
	}
	if moved.Redundant("traits-2") {
		t.Error("a renewal under a new traits version learned something")
	}
}

func TestRelativizePaths(t *testing.T) {
	ctx := t.Context()
	db := openTestDB(t)
	root := filepath.ToSlash(filepath.Join(t.TempDir(), "data"))
	mustInsert(t, ctx, db, &Sample{SHA256: "rp1", Source: "test", Label: "bad", Path: root + "/bad/pkg/a.bin"})
	mustInsert(t, ctx, db, &Sample{SHA256: "rp2", Source: "test", Label: "bad", Path: root + "-other/bad/pkg/a.bin"})
	mustInsert(t, ctx, db, &Sample{SHA256: "rp3", Source: "test", Label: "bad", Path: "bad/pkg/already.bin"})
	// A legacy-style absolute path that happens to live outside the current
	// dataRoot — should be left alone (no implicit "/data/" marker fallback).
	mustInsert(t, ctx, db, &Sample{SHA256: "rp4", Source: "test", Label: "bad", Path: "/moved/archive/data/good/pkg/b.bin"})

	n, err := db.RelativizePaths(ctx, root)
	if err != nil {
		t.Fatal(err)
	}
	if n != 1 {
		t.Fatalf("RelativizePaths affected %d rows, want 1", n)
	}

	rel, err := db.SampleBySHA256(ctx, "rp1")
	if err != nil {
		t.Fatal(err)
	}
	if rel.Path != "bad/pkg/a.bin" {
		t.Fatalf("rp1 path = %q, want relative path", rel.Path)
	}

	outside, err := db.SampleBySHA256(ctx, "rp2")
	if err != nil {
		t.Fatal(err)
	}
	if outside.Path != root+"-other/bad/pkg/a.bin" {
		t.Fatalf("rp2 path = %q, want unchanged outside path", outside.Path)
	}

	// rp4 has /data/ in the path but is NOT under dataRoot — stays
	// untouched.
	marker, err := db.SampleBySHA256(ctx, "rp4")
	if err != nil {
		t.Fatal(err)
	}
	if marker.Path != "/moved/archive/data/good/pkg/b.bin" {
		t.Fatalf("rp4 path = %q, want unchanged (no /data/ marker fallback)", marker.Path)
	}
}

// TestRelativizePathsLocationConflicts covers the case that trips up a
// naïve UPDATE … WHERE NOT EXISTS: a sample has both the absolute and
// relative form of the same location, left over from a prior deployment
// or a backfill race. RelativizePaths must collapse them without tripping
// the UNIQUE (sha256, path) constraint.
func TestRelativizePathsLocationConflicts(t *testing.T) {
	ctx := t.Context()
	db := openTestDB(t)
	root := filepath.ToSlash(filepath.Join(t.TempDir(), "data"))

	// Fresh walker inserted an absolute path; prior backfill (or a
	// previous relativize pass) already has the relative equivalent.
	mustInsert(t, ctx, db, &Sample{SHA256: "conflict1", Source: "test", Label: "bad", Path: root + "/bad/foo.exe"})
	if err := db.UpsertLocation(ctx, &SampleLocation{SHA256: "conflict1", Path: "bad/foo.exe"}); err != nil {
		t.Fatal(err)
	}

	if _, err := db.RelativizePaths(ctx, root); err != nil {
		t.Fatalf("RelativizePaths: %v", err)
	}

	locs, err := db.LocationsForSHA(ctx, "conflict1")
	if err != nil {
		t.Fatal(err)
	}
	if len(locs) != 1 || locs[0].Path != "bad/foo.exe" {
		t.Fatalf("conflict1 locations = %+v, want single path=bad/foo.exe", locs)
	}
}

func TestExplodeArchiveMembers(t *testing.T) {
	db := openTestDB(t)
	ctx := context.Background()

	cleaveJSON := []byte(`{"fs":[
		{"sha":"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa","type":"elf","path":"pkg/bin","dp":0,"sz":1000,"ts":[{"l":5,"c":0.9}]},
		{"sha":"bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb","type":"py","path":"pkg/setup.py","dp":1,"sz":500,"ts":[{"l":5,"c":0.95}]},
		{"sha":"cccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc","type":"txt","path":"pkg/readme.txt","dp":1,"sz":50,"ts":[{"l":1,"c":1.0}]}
	]}`)

	parentLitmus := []byte(`{"v":"4","prob":0.97,"class":1,"version":"vtest","thresholds":[0.5,0.9],"fs":[{"id":0,"prob":0.97,"class":1},{"id":1,"prob":0.91,"class":1},{"id":2,"prob":0.12,"class":0}]}`)
	analyzedAt := time.Date(2026, 4, 27, 7, 30, 0, 0, time.UTC)
	parent := &Sample{
		SHA256:          "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
		Source:          "test",
		Label:           "bad",
		LabelSource:     "test",
		Path:            "bad/archive.zip",
		CleaveResult:    cleaveJSON,
		LitmusResult:    parentLitmus,
		CanonicalSHA256: "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
		AnalyzedAt:      &analyzedAt,
	}
	mustInsert(t, ctx, db, parent)

	n, err := db.ExplodeArchiveMembers(ctx, parent)
	if err != nil {
		t.Fatal(err)
	}
	if n != 2 { // dp=0 is skipped, dp=1 entries inserted
		t.Errorf("exploded = %d, want 2", n)
	}

	// Idempotent explosion: should return 0 NEWly inserted, but same number of members.
	n, err = db.ExplodeArchiveMembers(ctx, parent)
	if err != nil {
		t.Fatal(err)
	}
	if n != 0 {
		t.Errorf("duplicate explosion inserted = %d, want 0", n)
	}

	// The txt file with only level 1 findings should have skip="skip-benign-archive-item"
	// and a virtual path combining parent.Path with its in-archive path.
	txt, err := db.SampleBySHA256(ctx, "cccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc")
	if err != nil {
		t.Fatal(err)
	}
	if txt.Skip != skipBenignArchiveItem {
		t.Errorf("txt Skip = %q, want %q", txt.Skip, skipBenignArchiveItem)
	}
	if txt.Parent != parent.SHA256 {
		t.Errorf("txt Parent = %q, want %q", txt.Parent, parent.SHA256)
	}
	if want := "bad/archive.zip!!pkg/readme.txt"; txt.Path != want {
		t.Errorf("txt Path = %q, want %q", txt.Path, want)
	}

	// The py file with hostile level findings should NOT be skipped.
	py, err := db.SampleBySHA256(ctx, "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb")
	if err != nil {
		t.Fatal(err)
	}
	if py.Skip != "" {
		t.Errorf("py Skip = %q, want empty", py.Skip)
	}
	if want := "bad/archive.zip!!pkg/setup.py"; py.Path != want {
		t.Errorf("py Path = %q, want %q", py.Path, want)
	}

	// Regression guard for the "archive orphan" class: Explode must persist
	// cleave_result (single-file wrapper derived from the parent's fs[]
	// entry) AND member-specific litmus_result on every member.
	// Before the insert column-list fix, these fields were silently
	// dropped because neither insertSampleBatch* listed them, leaving
	// members with NULL cleave_result — invisible to ClaimJobs and hence
	// undead in the queue forever.
	wantLitmusScores := map[string]float64{
		"bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb": 0.91,
		"cccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc": 0.12,
	}
	for sha, wantScore := range wantLitmusScores {
		m, err := db.SampleBySHA256(ctx, sha)
		if err != nil {
			t.Fatal(err)
		}
		if len(m.CleaveResult) == 0 {
			t.Errorf("%s: cleave_result missing — explode inserted nothing into the column", sha[:12])
		} else if !bytes.Contains(m.CleaveResult, []byte(sha)) {
			t.Errorf("%s: cleave_result doesn't reference own sha: %s", sha[:12], m.CleaveResult)
		}
		if bytes.Equal(m.LitmusResult, parentLitmus) {
			t.Errorf("%s: litmus_result inherited parent envelope: %q", sha[:12], m.LitmusResult)
		}
		var litmus struct {
			Prob float64 `json:"prob"`
		}
		if err := json.Unmarshal(m.LitmusResult, &litmus); err != nil {
			t.Errorf("%s: parse member litmus_result: %v", sha[:12], err)
		} else if litmus.Prob != wantScore {
			t.Errorf("%s: member litmus prob = %v, want %v", sha[:12], litmus.Prob, wantScore)
		}
		if m.LitmusScore != wantScore {
			t.Errorf("%s: litmus_score = %v, want %v", sha[:12], m.LitmusScore, wantScore)
		}
		if m.AnalyzedAt == nil || !m.AnalyzedAt.Equal(analyzedAt) {
			t.Errorf("%s: analyzed_at = %v, want inherited %v", sha[:12], m.AnalyzedAt, analyzedAt)
		}
	}
}

// TestLitmusResultForMemberAcceptsV4AndV5 exercises the per-member envelope
// extraction directly. The function must inherit envelope-level metadata
// (version/threshold/level for v=5, version/thresholds for v=4) onto the
// per-member result so downstream consumers can interpret it standalone.
// TestMemberEnvelopeBatchedBuildMatchesSingle verifies that building an
// archive's members in batches (as storeResultPG now does, to bound memory)
// yields exactly the same members — identity, cleave slice, and per-member
// litmus slice — as building them all at once. It also guards the parse-once
// litmus index: every member must resolve a distinct, non-empty litmus result.
// TestMemberEnvelopeCarriesTraitsVersion pins the traits version onto exploded
// members. /api/known reports a stored verdict "current" only when
// samples.traits_version matches the producer's, and scan skips re-posting
// exactly those. Members used to inherit no version at all, so they were never
// current, so every archive containing a popular dependency re-posted its
// verdict — and the rev-less member envelope then overwrote the cleave_result of
// any standalone row for the same sha, destroying the signal that would have
// stopped it. Measured 2026-09-05: source 'x' (exploded) carried a version on
// 2.0% of rows against 73-100% for every real producer.
func TestMemberEnvelopeCarriesTraitsVersion(t *testing.T) {
	sha := fmt.Sprintf("%064x", 1)
	file := fmt.Sprintf(`{"sha":%q,"type":"elf","path":"pkg/f.so","depth":1,"size":100}`, sha)
	mkParent := func(envelope, resolved string) *Sample {
		return &Sample{
			SHA256: fmt.Sprintf("%064x", 99), Source: "s", Label: "bad", Path: "bad/pkg.tar",
			CleaveResult:  []byte(`{` + envelope + `"files":[` + file + `]}`),
			TraitsVersion: resolved,
		}
	}

	for _, tc := range []struct {
		name     string
		envelope string
		resolved string
		want     string
	}{
		{"resolved version wins", `"rev":"aaaaa",`, "bbbbb", "bbbbb"},
		{"falls back to envelope rev (v8)", `"rev":"aaaaa",`, "", "aaaaa"},
		{"falls back to envelope tv (v7)", `"tv":"ccccc",`, "", "ccccc"},
		{"unknown stays empty", ``, "", ""},
	} {
		t.Run(tc.name, func(t *testing.T) {
			members := memberSamplesFromEnvelope(mkParent(tc.envelope, tc.resolved))
			if len(members) != 1 {
				t.Fatalf("got %d members, want 1", len(members))
			}
			if got := members[0].TraitsVersion; got != tc.want {
				t.Errorf("member TraitsVersion = %q, want %q", got, tc.want)
			}
			// The stored envelope must be self-describing too: ParseCleaveResult
			// reads "rev" back out, so a member that is later re-stored keeps its
			// version rather than silently reverting to none.
			if got := ParseCleaveResult(sha, members[0].CleaveResult).TraitsVersion; got != tc.want {
				t.Errorf("round-tripped member envelope rev = %q, want %q", got, tc.want)
			}
			if tc.want == "" && bytes.Contains(members[0].CleaveResult, []byte(`"rev"`)) {
				t.Errorf("unknown version must omit rev, got %s", members[0].CleaveResult)
			}
		})
	}
}

func TestMemberEnvelopeBatchedBuildMatchesSingle(t *testing.T) {
	mk := func(i int) string { return fmt.Sprintf("%064x", i+1) } // distinct lowercase-hex sha256

	var files, litFiles []string
	for i := range 5 {
		files = append(files, fmt.Sprintf(
			`{"sha":%q,"type":"elf","path":"pkg/f%d.so","depth":1,"size":%d,"traits":[{"crit":5,"conf":0.9}]}`,
			mk(i), i, 100+i))
		litFiles = append(litFiles, fmt.Sprintf(`{"id":%d,"prob":0.9%d,"class":1}`, i, i))
	}
	parent := &Sample{
		SHA256: mk(99), Source: "s", Feed: "fd", Ecosystem: "e",
		Label: "bad", LabelSource: "ls", Path: "bad/pkg.tar",
		CleaveResult: []byte(`{"files":[` + strings.Join(files, ",") + `]}`),
		LitmusResult: []byte(`{"v":"7","version":"vt","lvl":3,"files":[` + strings.Join(litFiles, ",") + `]}`),
	}

	single := memberSamplesFromEnvelope(parent)
	if len(single) != 5 {
		t.Fatalf("single build: got %d members, want 5", len(single))
	}

	env := newMemberEnvelope(parent)
	batched := append(env.buildRange(0, 2), env.buildRange(2, env.len())...)
	if len(batched) != len(single) {
		t.Fatalf("batched build: got %d members, want %d", len(batched), len(single))
	}
	for i := range single {
		a, b := single[i], batched[i]
		if a.SHA256 != b.SHA256 || a.Path != b.Path || a.Skip != b.Skip ||
			a.FileType != b.FileType || a.SizeBytes != b.SizeBytes {
			t.Errorf("member %d identity mismatch:\n single=%+v\n batched=%+v", i, a, b)
		}
		if !bytes.Equal(a.CleaveResult, b.CleaveResult) {
			t.Errorf("member %d cleave mismatch:\n single=%s\n batched=%s", i, a.CleaveResult, b.CleaveResult)
		}
		if !bytes.Equal(a.LitmusResult, b.LitmusResult) {
			t.Errorf("member %d litmus mismatch:\n single=%s\n batched=%s", i, a.LitmusResult, b.LitmusResult)
		}
	}
	if len(single[0].LitmusResult) == 0 {
		t.Error("expected a per-member litmus result, got empty")
	}
	if bytes.Equal(single[0].LitmusResult, single[1].LitmusResult) {
		t.Error("expected distinct per-member litmus results from the parse-once index")
	}
}

func TestLitmusResultForMemberAcceptsV4AndV5(t *testing.T) {
	cases := []struct {
		name        string
		parent      []byte
		wantPresent []string // envelope-level keys that must appear on the member
		wantAbsent  []string // envelope-level keys that must NOT appear on the member
	}{
		{
			name:        "v4 envelope",
			parent:      []byte(`{"v":"4","prob":0.97,"class":1,"version":"vtest","thresholds":[0.5,0.9],"fs":[{"id":0,"prob":0.91,"class":1}]}`),
			wantPresent: []string{"v", "version", "thresholds"},
			wantAbsent:  []string{"threshold", "level"},
		},
		{
			name:        "v5 envelope",
			parent:      []byte(`{"v":"5","prob":0.97,"class":1,"version":"vtest","threshold":0.9,"level":3,"fs":[{"id":0,"prob":0.91,"class":1,"threshold":0.9}]}`),
			wantPresent: []string{"v", "version", "threshold", "level"},
			wantAbsent:  []string{"thresholds"},
		},
		{
			name:        "v5 envelope with null level (manual thresholds)",
			parent:      []byte(`{"v":"5","prob":0.97,"class":1,"version":"vtest","threshold":0.9,"level":null,"fs":[{"id":0,"prob":0.91,"class":1,"threshold":0.9}]}`),
			wantPresent: []string{"v", "version", "threshold", "level"},
			wantAbsent:  []string{"thresholds"},
		},
		{
			name:        "v7 envelope",
			parent:      []byte(`{"v":"7","prob":0.97,"lvl":3,"conf":97,"version":"vtest","files":[{"id":0,"prob":0.91,"lvl":3,"conf":97}]}`),
			wantPresent: []string{"v", "version", "lvl", "conf"},
			wantAbsent:  []string{"thresholds", "threshold", "level", "l"},
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got := litmusResultForMember(tc.parent, 0)
			if got == nil {
				t.Fatal("got nil; want member envelope")
			}
			var out map[string]json.RawMessage
			if err := json.Unmarshal(got, &out); err != nil {
				t.Fatalf("unmarshal member: %v", err)
			}
			// Member's own prob must survive.
			if _, ok := out["prob"]; !ok {
				t.Error("member missing prob")
			}
			for _, k := range tc.wantPresent {
				if _, ok := out[k]; !ok {
					t.Errorf("missing envelope-level key %q on member; got: %s", k, got)
				}
			}
			for _, k := range tc.wantAbsent {
				if _, ok := out[k]; ok {
					t.Errorf("unexpected envelope-level key %q on member; got: %s", k, got)
				}
			}
		})
	}
}

func TestBackfillArchiveMemberAnalyzedAt(t *testing.T) {
	db := openTestDB(t)
	ctx := context.Background()

	parentSHA := "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
	childSHA := "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb"
	parentCleave := []byte(`{"fs":[{"sha":"` + parentSHA + `","type":"zip","dp":0}]}`)
	parentLitmus := []byte(`{"prob":0.97}`)

	mustInsert(t, ctx, db, &Sample{SHA256: parentSHA, Source: "test", Label: "bad", LabelSource: "test"})
	if err := db.UpdateCleaveResult(ctx, parentSHA, parentCleave, nil, ""); err != nil {
		t.Fatal(err)
	}
	if err := db.UpdateLitmusResult(ctx, parentSHA, parentLitmus); err != nil {
		t.Fatal(err)
	}
	parent, err := db.SampleBySHA256(ctx, parentSHA)
	if err != nil {
		t.Fatal(err)
	}
	if parent.AnalyzedAt == nil {
		t.Fatal("parent analyzed_at missing")
	}

	childCleave := []byte(`{"fs":[{"sha":"` + childSHA + `","type":"py","dp":1}]}`)
	if _, _, err := db.InsertSampleBatch(ctx, []*Sample{{
		SHA256:       childSHA,
		Source:       "test",
		Label:        "bad",
		LabelSource:  "test",
		Path:         "bad/archive.zip!!pkg/x.py",
		Parent:       parentSHA,
		CleaveResult: childCleave,
		LitmusResult: parentLitmus,
	}}); err != nil {
		t.Fatal(err)
	}
	child, err := db.SampleBySHA256(ctx, childSHA)
	if err != nil {
		t.Fatal(err)
	}
	if child.AnalyzedAt != nil {
		t.Fatalf("precondition: child analyzed_at = %v, want nil", child.AnalyzedAt)
	}

	if _, err := db.Backfill(ctx); err != nil {
		t.Fatal(err)
	}
	child, err = db.SampleBySHA256(ctx, childSHA)
	if err != nil {
		t.Fatal(err)
	}
	if child.AnalyzedAt == nil || !child.AnalyzedAt.Equal(*parent.AnalyzedAt) {
		t.Fatalf("child analyzed_at = %v, want parent analyzed_at %v", child.AnalyzedAt, parent.AnalyzedAt)
	}
}

func TestBackfillArchiveMemberLitmusResult(t *testing.T) {
	db := openTestDB(t)
	ctx := context.Background()

	parentSHA := "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
	childSHA := "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb"
	parentCleave := []byte(`{"fs":[
		{"sha":"` + parentSHA + `","type":"zip","path":"archive.zip","dp":0},
		{"sha":"` + childSHA + `","type":"py","path":"pkg/x.py","dp":1}
	]}`)
	parentLitmus := []byte(`{"v":"4","prob":0.97,"class":1,"version":"vtest","fs":[{"id":0,"prob":0.97,"class":1},{"id":1,"prob":0.41,"class":0}]}`)
	childCleave := []byte(`{"fs":[{"sha":"` + childSHA + `","type":"py","path":"pkg/x.py","dp":1}]}`)

	if _, _, err := db.InsertSampleBatch(ctx, []*Sample{{
		SHA256:       parentSHA,
		Source:       "test",
		Label:        "bad",
		LabelSource:  "test",
		Path:         "bad/archive.zip",
		CleaveResult: parentCleave,
		LitmusResult: parentLitmus,
	}}); err != nil {
		t.Fatal(err)
	}
	if _, _, err := db.InsertSampleBatch(ctx, []*Sample{{
		SHA256:       childSHA,
		Source:       "test",
		Label:        "bad",
		LabelSource:  "test",
		Path:         "bad/archive.zip!!pkg/x.py",
		Parent:       parentSHA,
		CleaveResult: childCleave,
		LitmusResult: parentLitmus,
	}}); err != nil {
		t.Fatal(err)
	}

	if _, err := db.Backfill(ctx); err != nil {
		t.Fatal(err)
	}
	child, err := db.SampleBySHA256(ctx, childSHA)
	if err != nil {
		t.Fatal(err)
	}
	if bytes.Equal(child.LitmusResult, parentLitmus) {
		t.Fatalf("child litmus_result still inherited parent envelope: %s", child.LitmusResult)
	}
	var litmus struct {
		Prob float64 `json:"prob"`
	}
	if err := json.Unmarshal(child.LitmusResult, &litmus); err != nil {
		t.Fatal(err)
	}
	if litmus.Prob != 0.41 || child.LitmusScore != 0.41 {
		t.Fatalf("child litmus prob/score = %v/%v, want 0.41/0.41", litmus.Prob, child.LitmusScore)
	}
}

func TestExplodeArchiveMembersViaSampleParentInfoAnalyzedAt(t *testing.T) {
	db := openTestDB(t)
	ctx := context.Background()

	parentSHA := "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
	childSHA := "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb"
	cleaveJSON := []byte(`{"fs":[
		{"sha":"` + parentSHA + `","type":"zip","path":"archive.zip","dp":0,"ts":[{"l":5,"c":0.9}]},
		{"sha":"` + childSHA + `","type":"py","path":"pkg/x.py","dp":1,"ts":[{"l":5,"c":0.9}]}
	]}`)
	litmusJSON := []byte(`{"v":"4","prob":0.97,"class":1,"fs":[{"id":0,"prob":0.97,"class":1},{"id":1,"prob":0.83,"class":1}]}`)

	mustInsert(t, ctx, db, &Sample{
		SHA256:      parentSHA,
		Source:      "test",
		Label:       "bad",
		LabelSource: "test",
		Path:        "bad/archive.zip",
	})
	if err := db.UpdateCleaveResult(ctx, parentSHA, cleaveJSON, nil, ""); err != nil {
		t.Fatal(err)
	}
	if err := db.UpdateLitmusResult(ctx, parentSHA, litmusJSON); err != nil {
		t.Fatal(err)
	}

	parent, err := db.SampleParentInfo(ctx, parentSHA)
	if err != nil {
		t.Fatal(err)
	}
	if parent.AnalyzedAt == nil {
		t.Fatal("SampleParentInfo did not fetch analyzed_at")
	}
	if parent.FirstAnalyzedAt == nil {
		t.Fatal("SampleParentInfo did not fetch first_analyzed_at")
	}
	parent.CleaveResult = cleaveJSON

	if _, err := db.ExplodeArchiveMembers(ctx, parent); err != nil {
		t.Fatal(err)
	}
	child, err := db.SampleBySHA256(ctx, childSHA)
	if err != nil {
		t.Fatal(err)
	}
	if child.AnalyzedAt == nil || !child.AnalyzedAt.Equal(*parent.AnalyzedAt) {
		t.Fatalf("child analyzed_at = %v, want parent analyzed_at %v", child.AnalyzedAt, parent.AnalyzedAt)
	}
	if child.FirstAnalyzedAt == nil || !child.FirstAnalyzedAt.Equal(*parent.FirstAnalyzedAt) {
		t.Fatalf("child first_analyzed_at = %v, want parent first_analyzed_at %v", child.FirstAnalyzedAt, parent.FirstAnalyzedAt)
	}
}

// TestExplodeArchiveMembersCleaveFormat verifies that we strip cleave's
// "<archive-path>!!<member>" prefix before joining the member to our own
// parent.Path. Historical bug: we were blindly prepending parent.Path +
// "!" on top of cleave's already-qualified path, producing triple-nested
// stored paths like "bad/foo.tgz!/abs/data/bad/foo.tgz!!member.py".
func TestExplodeArchiveMembersCleaveFormat(t *testing.T) {
	db := openTestDB(t)
	ctx := context.Background()

	mSha := "2222222222222222222222222222222222222222222222222222222222222222"
	nSha := "3333333333333333333333333333333333333333333333333333333333333333"
	// Absolute-path format (what cleave emits for depth-1 members) and
	// nested-archive format (depth-2; the last "!!" is still the boundary).
	cleaveJSON := []byte(`{"fs":[
		{"sha":"1111111111111111111111111111111111111111111111111111111111111111","type":"tar.gz","path":"/abs/data/bad/archive.tgz","dp":0},
		{"sha":"` + mSha + `","type":"py","path":"/abs/data/bad/archive.tgz!!package/setup.py","dp":1,"sz":100,"ts":[{"l":5,"c":0.95}]},
		{"sha":"` + nSha + `","type":"txt","path":"inner.tgz!!inner.tgz!deep/note.txt","dp":2,"sz":50,"ts":[{"l":5,"c":0.9}]}
	]}`)
	parent := &Sample{
		SHA256:       "1111111111111111111111111111111111111111111111111111111111111111",
		Source:       "test",
		Label:        "bad",
		LabelSource:  "test",
		Path:         "bad/archive.tgz",
		CleaveResult: cleaveJSON,
	}
	mustInsert(t, ctx, db, parent)
	if _, err := db.ExplodeArchiveMembers(ctx, parent); err != nil {
		t.Fatal(err)
	}

	// dp=1 member: last "!!" separates archive from member → "package/setup.py".
	m, err := db.SampleBySHA256(ctx, mSha)
	if err != nil {
		t.Fatal(err)
	}
	if want := "bad/archive.tgz!!package/setup.py"; m.Path != want {
		t.Errorf("dp=1 member path = %q, want %q", m.Path, want)
	}
	if m.Filename != "package/setup.py" {
		t.Errorf("dp=1 member filename = %q, want %q", m.Filename, "package/setup.py")
	}

	// dp=2 nested member: after last "!!", the in-archive portion is
	// "inner.tgz!deep/note.txt". Joined with parent: "bad/archive.tgz!!inner.tgz!deep/note.txt".
	n, err := db.SampleBySHA256(ctx, nSha)
	if err != nil {
		t.Fatal(err)
	}
	if want := "bad/archive.tgz!!inner.tgz!deep/note.txt"; n.Path != want {
		t.Errorf("dp=2 member path = %q, want %q", n.Path, want)
	}
}

// TestExplodeArchiveMembersV8Format is the regression guard for the v8 JSON
// migration: members are addressed with "depth"/"traits"/"size" rather than
// pre-v8 "dp"/"ts"/"sz". Reading the old names left every member at depth 0,
// so explosion skipped them all and an archive's children never reached
// sample_locations — collapsing the per-file Content view.
func TestExplodeArchiveMembersV8Format(t *testing.T) {
	db := openTestDB(t)
	ctx := context.Background()

	parentSHA := "1111111111111111111111111111111111111111111111111111111111111111"
	mSha := "2222222222222222222222222222222222222222222222222222222222222222"
	cleaveJSON := []byte(`{"v":8,"files":[
		{"sha":"` + parentSHA + `","type":"tar.gz","path":"/abs/data/bad/archive.tgz"},
		{"sha":"` + mSha + `","type":"py","path":"/abs/data/bad/archive.tgz!!package/setup.py","depth":1,"size":100,"traits":[{"crit":5,"conf":0.95}]}
	]}`)
	parent := &Sample{
		SHA256:       parentSHA,
		Source:       "test",
		Label:        "bad",
		LabelSource:  "test",
		Path:         "bad/archive.tgz",
		CleaveResult: cleaveJSON,
	}
	mustInsert(t, ctx, db, parent)
	n, err := db.ExplodeArchiveMembers(ctx, parent)
	if err != nil {
		t.Fatal(err)
	}
	if n != 1 {
		t.Fatalf("exploded %d members, want 1 (the depth-1 member)", n)
	}
	m, err := db.SampleBySHA256(ctx, mSha)
	if err != nil {
		t.Fatalf("v8 member not exploded into samples: %v", err)
	}
	if want := "bad/archive.tgz!!package/setup.py"; m.Path != want {
		t.Errorf("member path = %q, want %q", m.Path, want)
	}
	if m.SizeBytes != 100 {
		t.Errorf("member size = %d, want 100 (v8 \"size\")", m.SizeBytes)
	}
	// The parent→member edge must exist so MembersByParent can find it.
	members, total, err := db.MembersByParent(ctx, parentSHA, 10)
	if err != nil {
		t.Fatal(err)
	}
	if total != 1 || len(members) != 1 || members[0].SHA256 != mSha {
		t.Errorf("MembersByParent = %+v (total %d), want the v8 member", members, total)
	}
}

// TestExplodeDoesNotClobberWalkerPath is the regression guard for the
// content-collision orphan class: when a sha has been inserted by the
// walker (top-level, parent=”) and the same sha then appears inside an
// archive via ExplodeArchiveMembers, the archive-member upsert must NOT
// overwrite samples.path with the virtual "<archive>!<member>" form —
// that would leave the samples row pointing at a non-existent disk path,
// marked tier-1 claimable, and workers would all report "missing on disk".
// Observed in prod on shared code (vendored deps, copies of the same
// library across versions). The sample_locations table still records the
// archive observation separately; only the denormalized samples row is
// protected from Explode clobber.
func TestExplodeDoesNotClobberWalkerPath(t *testing.T) {
	db := openTestDB(t)
	ctx := context.Background()

	const sharedSHA = "7777777777777777777777777777777777777777777777777777777777777777"

	// Step 1: walker sees the file as a top-level sample.
	mustInsert(t, ctx, db, &Sample{
		SHA256:      sharedSHA,
		Source:      "test",
		Label:       "good",
		LabelSource: "test",
		Path:        "good/vendor/shared/lib.js",
	})

	// Step 2: an archive with the same content inside is analyzed and
	// ExplodeArchiveMembers inserts a member with parent=<archive-sha>.
	cleaveJSON := []byte(`{"fs":[
		{"sha":"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa","type":"zip","path":"bad/pkg.zip","dp":0},
		{"sha":"` + sharedSHA + `","type":"js","path":"pkg/lib.js","dp":1,"sz":500,"ts":[{"l":5,"c":0.9}]}
	]}`)
	parent := &Sample{
		SHA256:       "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
		Source:       "test",
		Label:        "bad",
		LabelSource:  "test",
		Path:         "bad/pkg.zip",
		CleaveResult: cleaveJSON,
	}
	mustInsert(t, ctx, db, parent)
	if _, err := db.ExplodeArchiveMembers(ctx, parent); err != nil {
		t.Fatal(err)
	}

	// The samples row for sharedSHA must still point at the walker's
	// top-level path, with parent=''. If Explode's upsert had
	// clobbered it, samples.path would be "bad/pkg.zip!!pkg/lib.js" and
	// samples.parent would still be '' — the orphan state.
	got, err := db.SampleBySHA256(ctx, sharedSHA)
	if err != nil {
		t.Fatal(err)
	}
	if got.Path != "good/vendor/shared/lib.js" {
		t.Errorf("Path = %q, want walker path %q (Explode clobbered?)",
			got.Path, "good/vendor/shared/lib.js")
	}
	if got.Parent != "" {
		t.Errorf("Parent = %q, want '' (top-level observation wins)", got.Parent)
	}

	// sample_locations should hold BOTH observations — walker's and
	// Explode's — since they're different (sha, path) pairs.
	locs, err := db.LocationsForSHA(ctx, sharedSHA)
	if err != nil {
		t.Fatal(err)
	}
	if len(locs) != 2 {
		t.Fatalf("locations = %d, want 2 (walker + archive)", len(locs))
	}
	var sawWalker, sawArchive bool
	for _, l := range locs {
		switch l.Path {
		case "good/vendor/shared/lib.js":
			sawWalker = true
			if l.ParentSHA256 != "" {
				t.Errorf("walker location has parent_sha256 = %q, want empty", l.ParentSHA256)
			}
		case "bad/pkg.zip!!pkg/lib.js":
			sawArchive = true
			if l.ParentSHA256 != parent.SHA256 {
				t.Errorf("archive location parent_sha256 = %q, want %q", l.ParentSHA256, parent.SHA256)
			}
		default:
			t.Errorf("unexpected location: %s", l.Path)
		}
	}
	if !sawWalker || !sawArchive {
		t.Errorf("want both walker and archive locations; walker=%v archive=%v", sawWalker, sawArchive)
	}
}

// TestExplodeResultsSurviveReingest guards the "walker arrives after Explode"
// case: if the walker re-hashes an archive member that's already on disk
// as a standalone file, its InsertSample call must NOT null out the
// cleave_result / litmus_result that Explode wrote earlier. The fix in
// the ON CONFLICT clause leaves the analysis columns untouched on update.
func TestExplodeResultsSurviveReingest(t *testing.T) {
	db := openTestDB(t)
	ctx := context.Background()

	memberSHA := "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb"
	cleaveJSON := []byte(`{"fs":[
		{"sha":"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa","type":"elf","path":"pkg/bin","dp":0,"sz":1000,"ts":[{"l":5,"c":0.9}]},
		{"sha":"` + memberSHA + `","type":"py","path":"pkg/setup.py","dp":1,"sz":500,"ts":[{"l":5,"c":0.95}]}
	]}`)
	parent := &Sample{
		SHA256:          "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
		Source:          "test",
		Label:           "bad",
		LabelSource:     "test",
		Path:            "bad/archive.zip",
		CleaveResult:    cleaveJSON,
		LitmusResult:    []byte(`{"v":"4","prob":0.9,"class":1,"fs":[{"id":0,"prob":0.9,"class":1},{"id":1,"prob":0.82,"class":1}]}`),
		CanonicalSHA256: "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
	}
	mustInsert(t, ctx, db, parent)
	if _, err := db.ExplodeArchiveMembers(ctx, parent); err != nil {
		t.Fatal(err)
	}

	// Member now has cleave_result + litmus_result from explosion.
	before, err := db.SampleBySHA256(ctx, memberSHA)
	if err != nil {
		t.Fatal(err)
	}
	if len(before.CleaveResult) == 0 || len(before.LitmusResult) == 0 {
		t.Fatalf("precondition: Explode should have set both results, got cleave=%d bytes litmus=%d bytes", len(before.CleaveResult), len(before.LitmusResult))
	}

	// Simulate the walker re-ingesting this same content as a standalone
	// file on disk — it has no analysis to contribute. The ON CONFLICT
	// path must leave the existing results alone.
	walkerInsert := &Sample{
		SHA256:      memberSHA,
		Source:      "test",
		Label:       "unknown",
		LabelSource: "test",
		Path:        "bad/extracted/setup.py",
	}
	if _, err := db.InsertSampleNew(ctx, walkerInsert); err != nil {
		t.Fatal(err)
	}

	after, err := db.SampleBySHA256(ctx, memberSHA)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(after.CleaveResult, before.CleaveResult) {
		t.Errorf("cleave_result clobbered by re-ingest:\n  before = %s\n  after  = %s", before.CleaveResult, after.CleaveResult)
	}
	if !bytes.Equal(after.LitmusResult, before.LitmusResult) {
		t.Errorf("litmus_result clobbered by re-ingest:\n  before = %s\n  after  = %s", before.LitmusResult, after.LitmusResult)
	}
}

// TestInsertSampleBatchPersistsResults covers the batch-insert path with
// cleave/litmus preset on the Sample struct. Before the column-list fix
// the batch path silently dropped these fields.
func TestInsertSampleBatchPersistsResults(t *testing.T) {
	db := openTestDB(t)
	ctx := context.Background()

	cleave := []byte(`{"fs":[{"sha":"bloc1","type":"py"}]}`)
	litmus := []byte(`{"score":0.5}`)
	batch := []*Sample{
		{SHA256: "bloc1", Source: "test", Path: "x/1", CleaveResult: cleave, LitmusResult: litmus},
		{SHA256: "bloc2", Source: "test", Path: "x/2", CleaveResult: cleave}, // no litmus
		{SHA256: "bloc3", Source: "test", Path: "x/3"},                       // neither
	}
	if _, _, err := db.InsertSampleBatch(ctx, batch); err != nil {
		t.Fatal(err)
	}

	got1, err := db.SampleBySHA256(ctx, "bloc1")
	if err != nil {
		t.Fatalf("SampleBySHA256(bloc1): %v", err)
	}
	if !bytes.Equal(got1.CleaveResult, cleave) {
		t.Errorf("bloc1 cleave_result = %q, want %q", got1.CleaveResult, cleave)
	}
	if !bytes.Equal(got1.LitmusResult, litmus) {
		t.Errorf("bloc1 litmus_result = %q, want %q", got1.LitmusResult, litmus)
	}
	got2, err := db.SampleBySHA256(ctx, "bloc2")
	if err != nil {
		t.Fatalf("SampleBySHA256(bloc2): %v", err)
	}
	if !bytes.Equal(got2.CleaveResult, cleave) {
		t.Errorf("bloc2 cleave_result = %q, want %q", got2.CleaveResult, cleave)
	}
	if len(got2.LitmusResult) != 0 {
		t.Errorf("bloc2 litmus_result = %q, want empty (nothing was supplied)", got2.LitmusResult)
	}
	got3, err := db.SampleBySHA256(ctx, "bloc3")
	if err != nil {
		t.Fatalf("SampleBySHA256(bloc3): %v", err)
	}
	if len(got3.CleaveResult) != 0 {
		t.Errorf("bloc3 cleave_result = %q, want empty", got3.CleaveResult)
	}
}

func TestExplodeArchiveMembersEmpty(t *testing.T) {
	db := openTestDB(t)
	ctx := context.Background()

	// No cleave result → 0 members.
	n, err := db.ExplodeArchiveMembers(ctx, &Sample{SHA256: "e1"})
	if err != nil {
		t.Fatal(err)
	}
	if n != 0 {
		t.Errorf("exploded empty = %d, want 0", n)
	}
}

// TestLocationsDualWrite verifies that both the single-insert and batch-insert
// paths populate sample_locations alongside samples, that re-observing an
// unchanged (sha, path) pair rewrites nothing at all, and that a second
// observation of the same sha at a new path adds a second location.
func TestLocationsDualWrite(t *testing.T) {
	db := openTestDB(t)
	ctx := context.Background()

	// Single insert path.
	mustInsert(t, ctx, db, &Sample{SHA256: "loc1", Path: "bad/a.exe", Source: "harvest", Feed: "feed-a"})
	locs, err := db.LocationsForSHA(ctx, "loc1")
	if err != nil {
		t.Fatal(err)
	}
	if len(locs) != 1 || locs[0].Path != "bad/a.exe" || locs[0].Source != "harvest" || locs[0].Feed != "feed-a" {
		t.Fatalf("single-insert location = %+v, want path=bad/a.exe source=harvest feed=feed-a", locs)
	}
	firstSeen := locs[0].FirstSeenAt
	firstLastSeen := locs[0].LastSeenAt

	// Re-observing an unchanged (sha, path) must be a complete no-op: no new
	// row, and no rewrite of the existing one. Rewriting here is what buried
	// the logical replicas — every walk re-observes nearly the whole corpus,
	// and no such update can be HOT, so each one costs an entry in every index.
	time.Sleep(5 * time.Millisecond)
	mustInsert(t, ctx, db, &Sample{SHA256: "loc1", Path: "bad/a.exe", Source: "harvest", Feed: "feed-a"})
	locs, err = db.LocationsForSHA(ctx, "loc1")
	if err != nil {
		t.Fatal(err)
	}
	if len(locs) != 1 {
		t.Fatalf("after re-observe, locations = %d, want 1", len(locs))
	}
	if !locs[0].FirstSeenAt.Equal(firstSeen) {
		t.Errorf("first_seen_at moved: got %v, want %v", locs[0].FirstSeenAt, firstSeen)
	}
	if !locs[0].LastSeenAt.Equal(firstLastSeen) {
		t.Errorf("unchanged re-observe rewrote the row: last_seen_at was %v, now %v", firstLastSeen, locs[0].LastSeenAt)
	}

	// Observing the same sha at a new path adds a second row (this is the
	// behavior the old schema's ON CONFLICT path-clobber destroyed).
	mustInsert(t, ctx, db, &Sample{SHA256: "loc1", Path: "good/a.exe", Source: "harvest", Feed: "feed-b"})
	locs, err = db.LocationsForSHA(ctx, "loc1")
	if err != nil {
		t.Fatal(err)
	}
	if len(locs) != 2 {
		t.Fatalf("two-path observe = %d locations, want 2", len(locs))
	}

	// Batch insert path: three samples, each should produce one location row.
	batch := []*Sample{
		{SHA256: "bloc1", Path: "x/1", Source: "harvest"},
		{SHA256: "bloc2", Path: "x/2", Source: "harvest"},
		{SHA256: "bloc3", Path: "x/3", Source: "harvest"},
	}
	if _, _, err := db.InsertSampleBatch(ctx, batch); err != nil {
		t.Fatal(err)
	}
	for _, s := range batch {
		locs, err := db.LocationsForSHA(ctx, s.SHA256)
		if err != nil {
			t.Fatal(err)
		}
		if len(locs) != 1 || locs[0].Path != s.Path {
			t.Errorf("batch %s location = %+v, want path=%s", s.SHA256, locs, s.Path)
		}
	}

	// Backfill path: ExplodeArchiveMembers writes through InsertSampleBatch,
	// so members should land in sample_locations with virtual paths.
	parentSHA := "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
	memberSHA := "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb"
	parent := &Sample{
		SHA256: parentSHA, Path: "bad/archive.zip", Source: "harvest", Label: "bad", LabelSource: "test",
		CleaveResult: []byte(`{"fs":[{"sha":"` + memberSHA + `","type":"py","path":"pkg/x.py","dp":1,"ts":[{"l":5,"c":0.9}]}]}`),
	}
	mustInsert(t, ctx, db, parent)
	if _, err := db.ExplodeArchiveMembers(ctx, parent); err != nil {
		t.Fatal(err)
	}
	memberLocs, err := db.LocationsForSHA(ctx, memberSHA)
	if err != nil {
		t.Fatal(err)
	}
	if len(memberLocs) != 1 || memberLocs[0].Path != "bad/archive.zip!!pkg/x.py" || memberLocs[0].ParentSHA256 != parentSHA {
		t.Errorf("member location = %+v, want virtual path + parent_sha256", memberLocs)
	}
}

func TestOldestIncomingLocations(t *testing.T) {
	db := openTestDB(t)
	ctx := context.Background()
	now := time.Now().UTC()
	mtime := now.Add(-90 * time.Minute)

	// incoming-nomtime carries no mtime at all. That is not an edge case: it is
	// the shape every direct-inserted collector row has, and it is most of the
	// hot pool by bytes. The drain must see it.
	mustInsert(t, ctx, db, &Sample{
		SHA256: "incoming-old", Path: "incoming/forager/a.bin", Filename: "a.bin",
		Label: "unknown", LabelSource: "forager", Mtime: &mtime,
	})
	mustInsert(t, ctx, db, &Sample{
		SHA256: "incoming-new", Path: "incoming/forager/b.bin", Filename: "b.bin",
		Label: "unknown", LabelSource: "forager", Mtime: &mtime,
	})
	mustInsert(t, ctx, db, &Sample{
		SHA256: "incoming-nomtime", Path: "incoming/forager/c.bin", Filename: "c.bin",
		Label: "unknown", LabelSource: "forager",
	})
	mustInsert(t, ctx, db, &Sample{
		SHA256: "already-cold", Path: "pending/foraged/d.bin", Filename: "d.bin",
		Label: "unknown", Mtime: &mtime,
	})
	// Classified but still sitting in the hot pool. A workflow move is refused
	// for anything that is not "unknown", so offering it to the drain would be
	// handing over work guaranteed to fail — and on the real pool this is the
	// majority case, not a corner: 4.0M of 4.75M hot rows were labelled "good"
	// on 2026-09-01. It is deliberately the oldest row of all, so a regression
	// that drops the filter puts it first and fails loudly.
	mustInsert(t, ctx, db, &Sample{
		SHA256: "incoming-labelled", Path: "incoming/forager/e.bin", Filename: "e.bin",
		Label: "good", LabelSource: "promoter", Mtime: &mtime,
	})

	// first_seen_at defaults to insert time, so backdate it to pin the drain
	// order. The intended order is the exact reverse of both sha256 order and
	// insertion order, so a regression to either fails here instead of passing
	// by coincidence. Every row shares one mtime for the same reason.
	for _, seen := range []struct {
		sha string
		at  time.Time
	}{
		{"incoming-old", now.Add(-3 * time.Hour)},
		{"incoming-nomtime", now.Add(-2 * time.Hour)},
		{"incoming-new", now.Add(-80 * time.Minute)},
		{"already-cold", now.Add(-4 * time.Hour)},
		{"incoming-labelled", now.Add(-5 * time.Hour)},
	} {
		if _, err := db.lite.ExecContext(ctx,
			`UPDATE sample_locations SET first_seen_at = ? WHERE sha256 = ?`,
			seen.at.Format(time.RFC3339Nano), seen.sha); err != nil {
			t.Fatal(err)
		}
	}

	locs, err := db.OldestIncomingLocations(ctx, IncomingQuery{Before: now.Add(-time.Hour), Limit: 10, Class: IncomingUnknown})
	if err != nil {
		t.Fatal(err)
	}
	got := make([]string, 0, len(locs))
	for _, loc := range locs {
		got = append(got, loc.SHA256)
	}
	want := []string{"incoming-old", "incoming-nomtime", "incoming-new"}
	if !slices.Equal(got, want) {
		t.Fatalf("oldest incoming = %v, want %v", got, want)
	}
	for _, loc := range locs {
		if loc.SHA256 == "incoming-nomtime" && loc.Mtime != nil {
			t.Errorf("incoming-nomtime mtime = %v, want nil", loc.Mtime)
		}
	}

	// The cursor is what lets a sweep step past rows it has already dealt with.
	// Resuming from the first result must return the rest, in order, and never
	// the row it resumed from.
	page1, err := db.OldestIncomingLocations(ctx, IncomingQuery{
		Before: now.Add(-time.Hour), Limit: 1, Class: IncomingUnknown,
	})
	if err != nil || len(page1) != 1 {
		t.Fatalf("first page = %+v, %v", page1, err)
	}
	page2, err := db.OldestIncomingLocations(ctx, IncomingQuery{
		Before: now.Add(-time.Hour), Limit: 10, Class: IncomingUnknown,
		After: IncomingCursor{FirstSeenAt: page1[0].FirstSeenAt, SHA256: page1[0].SHA256},
	})
	if err != nil {
		t.Fatal(err)
	}
	got = got[:0]
	for _, loc := range page2 {
		got = append(got, loc.SHA256)
	}
	if !slices.Equal(got, want[1:]) {
		t.Fatalf("resumed page = %v, want %v", got, want[1:])
	}

	// The classified half is a separate population, not a filtered view of the
	// same one: it must return exactly the row the unknown feed refuses, and
	// carry the label that says where it belongs.
	classified, err := db.OldestIncomingLocations(ctx, IncomingQuery{Before: now.Add(-time.Hour), Limit: 10, Class: IncomingClassified})
	if err != nil {
		t.Fatal(err)
	}
	if len(classified) != 1 || classified[0].SHA256 != "incoming-labelled" {
		t.Fatalf("classified feed = %+v, want only incoming-labelled", classified)
	}
	if classified[0].Label != "good" {
		t.Errorf("classified label = %q, want good — the caller echoes this back as its ruling", classified[0].Label)
	}
	if _, err := db.OldestIncomingLocations(ctx, IncomingQuery{Before: now, Limit: 10, Class: IncomingClass("sideways")}); err == nil {
		t.Error("an unknown class was accepted; a typo would silently drain the wrong half")
	}

	// before is a first_seen_at cutoff, not an mtime one: the grace period that
	// keeps a just-catalogued (possibly still-being-written) file out of a batch.
	recent, err := db.OldestIncomingLocations(ctx, IncomingQuery{Before: now.Add(-150 * time.Minute), Limit: 10, Class: IncomingUnknown})
	if err != nil {
		t.Fatal(err)
	}
	if len(recent) != 1 || recent[0].SHA256 != "incoming-old" {
		t.Fatalf("before cutoff = %+v, want only incoming-old", recent)
	}
}

func TestCanonicalSHA(t *testing.T) {
	tests := []struct {
		name   string
		sha    string
		result string
		want   string
	}{
		{"empty result", "ffff", "", "ffff"},
		{"invalid json", "ffff", "{bad", "ffff"},
		{"no files", "ffff", `{"fs":[]}`, "ffff"},
		{"self is min", "aaaa", `{"fs":[{"sha":"bbbb"}]}`, "aaaa"},
		{
			"embedded is min",
			"zzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzz",
			`{"fs":[{"sha":"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"}]}`,
			"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
		},
		{
			"short sha ignored",
			"zzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzz",
			`{"fs":[{"sha":"short"}]}`,
			"zzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzz",
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := canonicalSHA(tt.sha, []byte(tt.result))
			if got != tt.want {
				t.Errorf("got %q, want %q", got, tt.want)
			}
		})
	}
}

func TestInsertSampleNew(t *testing.T) {
	db := openTestDB(t)
	ctx := context.Background()

	isNew, err := db.InsertSampleNew(ctx, &Sample{SHA256: "new1", Source: "test", Label: "bad", LabelSource: "test", Path: "test/new1"})
	if err != nil {
		t.Fatal(err)
	}
	if !isNew {
		t.Error("first insert should be new")
	}

	isNew, err = db.InsertSampleNew(ctx, &Sample{SHA256: "new1", Source: "test", Label: "bad", LabelSource: "test", Path: "test/new1"})
	if err != nil {
		t.Fatal(err)
	}
	if isNew {
		t.Error("duplicate insert should not be new")
	}
}

func TestSamplesByEmbeddedSHA256(t *testing.T) {
	db := openTestDB(t)
	ctx := context.Background()

	// Fixture carries two parallel layouts:
	//   - fs[]/sha/type is what parseCleaveFile reads (UpdateCleaveResult needs
	//     a non-empty type or it deletes the row).
	//   - files[]/sha256 is what SamplesByEmbeddedSHA256's JSON query reads.
	cleave := []byte(`{"fs":[{"sha":"parent1","type":"archive","dp":0}],` +
		`"files":[{"sha256":"embedded1","formula":"H2O","score":10},` +
		`{"sha256":"embedded2","formula":"O2","score":5}]}`)
	s := &Sample{SHA256: "parent1", Source: "test", Path: "test/parent1", CleaveResult: cleave}
	if _, err := db.InsertSampleNew(ctx, s); err != nil {
		t.Fatal(err)
	}
	if err := db.UpdateCleaveResult(ctx, s.SHA256, cleave, nil, ""); err != nil {
		t.Fatal(err)
	}

	samples, err := db.SamplesByEmbeddedSHA256(ctx, "embedded1", 10)
	if err != nil {
		t.Fatal(err)
	}
	if len(samples) != 1 {
		t.Errorf("expected 1 sample, got %d", len(samples))
	} else if samples[0].SHA256 != "parent1" {
		t.Errorf("expected parent1, got %s", samples[0].SHA256)
	}

	cleaveV7 := []byte(`{"v":"7","files":[{"sha":"parent7","type":"archive","dp":0},{"sha":"embedded7","type":"elf","dp":1,"mol":"O2","risk":5}]}`)
	s = &Sample{SHA256: "parent7", Source: "test", Path: "test/parent7", CleaveResult: cleaveV7}
	if _, err := db.InsertSampleNew(ctx, s); err != nil {
		t.Fatal(err)
	}
	if _, err := db.lite.ExecContext(ctx,
		`UPDATE samples SET cleave_result = ? WHERE sha256 = ?`,
		string(cleaveV7), s.SHA256); err != nil {
		t.Fatal(err)
	}

	samples, err = db.SamplesByEmbeddedSHA256(ctx, "embedded7", 10)
	if err != nil {
		t.Fatal(err)
	}
	if len(samples) != 1 {
		t.Errorf("expected 1 v7 sample, got %d", len(samples))
	} else if samples[0].SHA256 != "parent7" {
		t.Errorf("expected parent7, got %s", samples[0].SHA256)
	}
}

func TestRecomputeCanonicalSHA256(t *testing.T) {
	db := openTestDB(t)
	ctx := context.Background()

	parent2 := "5123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef"
	embedded2 := "1123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef"

	// embedded2 is smaller than parent2
	cleave := []byte(`{"files": [{"sha256": "` + embedded2 + `", "formula": "H2O", "score": 10}]}`)
	s := &Sample{SHA256: parent2, Source: "test", Path: "test/" + parent2, CleaveResult: cleave, CanonicalSHA256: parent2}
	if _, err := db.InsertSampleNew(ctx, s); err != nil {
		t.Fatal(err)
	}

	// Manually set cleave_result and "wrong" canonical_sha256 since InsertSampleNew doesn't set cleave_result
	// and UpdateCleaveResult would set the correct canonical.
	if _, err := db.lite.ExecContext(ctx, "UPDATE samples SET cleave_result = ?, canonical_sha256 = ? WHERE sha256 = ?", string(cleave), parent2, parent2); err != nil {
		t.Fatal(err)
	}

	n, err := db.RecomputeCanonicalSHA256(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if n != 1 {
		t.Errorf("expected 1 row updated, got %d", n)
	}

	s2, err := db.SampleBySHA256(ctx, parent2)
	if err != nil {
		t.Fatal(err)
	}
	if s2.CanonicalSHA256 != embedded2 {
		t.Errorf("expected canonical %s, got %s", embedded2, s2.CanonicalSHA256)
	}
}

func TestFeedSamples(t *testing.T) {
	db := openTestDB(t)
	ctx := context.Background()

	s1 := &Sample{SHA256: "s1", Source: "test", Feed: "feed1", Ecosystem: "eco1", Label: "bad"}
	s2 := &Sample{SHA256: "s2", Source: "test", Feed: "feed2", Ecosystem: "eco2", Label: "bad"}
	mustInsert(t, ctx, db, s1)
	mustInsert(t, ctx, db, s2)

	// Update with cleave result and analyzed_at. Each row needs its own
	// payload with the matching sha so parseCleaveFile pulls a non-empty
	// file_type — otherwise UpdateCleaveResult treats the row as
	// unclassified and deletes it.
	resultFor := func(sha string) []byte {
		return []byte(`{"fs":[{"sha":"` + sha + `","type":"elf","dp":0}]}`)
	}
	if err := db.UpdateCleaveResult(ctx, "s1", resultFor("s1"), nil, ""); err != nil {
		t.Fatal(err)
	}
	if err := db.UpdateCleaveResult(ctx, "s2", resultFor("s2"), nil, ""); err != nil {
		t.Fatal(err)
	}
	// FeedEcosystems is scoped to the feed's own population, which includes
	// litmus_result IS NOT NULL (see feedEcosystemsPG for why the dropdown
	// carries the feed's predicates). Analyze both so they are feed-eligible.
	for _, sha := range []string{"s1", "s2"} {
		if err := db.UpdateLitmusResult(ctx, sha, []byte(`{"prob":0.1,"lvl":9000}`)); err != nil {
			t.Fatalf("UpdateLitmusResult(%s): %v", sha, err)
		}
	}

	q := FeedQuery{Source: "test", Limit: 10}
	samples, err := db.FeedSamples(ctx, &q)
	if err != nil {
		t.Fatal(err)
	}
	if len(samples) != 2 {
		t.Fatalf("expected 2 samples, got %d", len(samples))
	}

	q.Feeds = []string{"feed1"}
	samples, err = db.FeedSamples(ctx, &q)
	if err != nil {
		t.Fatal(err)
	}
	if len(samples) != 1 || samples[0].SHA256 != "s1" {
		t.Errorf("expected only s1, got %v", samples)
	}

	sources, err := db.FeedSources(ctx, "test", "bad")
	if err != nil {
		t.Fatal(err)
	}
	if len(sources) != 2 {
		t.Errorf("expected 2 sources, got %v", sources)
	}

	ecos, err := db.FeedEcosystems(ctx, "test", "bad", time.Time{})
	if err != nil {
		t.Fatal(err)
	}
	if len(ecos) != 2 {
		t.Errorf("expected 2 ecosystems, got %v", ecos)
	}

	// A since within the window keeps both freshly-inserted ecosystems; a
	// since in the future excludes them, exercising both filter branches.
	recent, err := db.FeedEcosystems(ctx, "test", "bad", time.Now().Add(-72*time.Hour))
	if err != nil {
		t.Fatal(err)
	}
	if len(recent) != 2 {
		t.Errorf("expected 2 recent ecosystems, got %v", recent)
	}
	future, err := db.FeedEcosystems(ctx, "test", "bad", time.Now().Add(time.Hour))
	if err != nil {
		t.Fatal(err)
	}
	if len(future) != 0 {
		t.Errorf("expected 0 ecosystems past the cutoff, got %v", future)
	}

	count, err := db.FeedSamplesCount(ctx, &q)
	if err != nil {
		t.Fatal(err)
	}
	if count != 1 {
		t.Errorf("expected count 1, got %d", count)
	}

	// Test default sort order (should be mtime)
	t1 := time.Date(2020, 1, 1, 0, 0, 0, 0, time.UTC)
	t2 := time.Date(2021, 1, 1, 0, 0, 0, 0, time.UTC)
	s3 := &Sample{SHA256: "s3", Source: "test", Mtime: &t1}
	s4 := &Sample{SHA256: "s4", Source: "test", Mtime: &t2}
	mustInsert(t, ctx, db, s3)
	mustInsert(t, ctx, db, s4)
	if err := db.UpdateCleaveResult(ctx, "s3", resultFor("s3"), nil, ""); err != nil {
		t.Fatal(err)
	}
	if err := db.UpdateCleaveResult(ctx, "s4", resultFor("s4"), nil, ""); err != nil {
		t.Fatal(err)
	}

	q = FeedQuery{Source: "test", Limit: 10}
	samples, err = db.FeedSamples(ctx, &q)
	if err != nil {
		t.Fatal(err)
	}
	// Filter out s1, s2 which might have nil mtime or default sorting
	var sorted []string
	for _, s := range samples {
		if s.SHA256 == "s3" || s.SHA256 == "s4" {
			sorted = append(sorted, s.SHA256)
		}
	}
	if len(sorted) != 2 || sorted[0] != "s4" || sorted[1] != "s3" {
		t.Errorf("expected [s4 s3] sorted by mtime (default), got %v", sorted)
	}

	// Explicit analyzed_at sort
	q.OrderBy = "analyzed_at"
	_, err = db.FeedSamples(ctx, &q)
	if err != nil {
		t.Fatal(err)
	}

	// Explicit created_at sort
	q.OrderBy = "created_at"
	_, err = db.FeedSamples(ctx, &q)
	if err != nil {
		t.Fatal(err)
	}
}

// TestFeedTopLevelOnlyExcludesArchiveChildren locks the TopLevelOnly contract:
// a sample that appears inside any archive per the sample_locations ledger is
// not top-level, even when its own parent column is empty. That combination is
// exactly what scan's dependency mirroring produces (a fetched payload
// uploaded as its own sample) — and children may have multiple parents, which
// the single-valued parent column cannot represent.
func TestFeedTopLevelOnlyExcludesArchiveChildren(t *testing.T) {
	db := openTestDB(t)
	ctx := context.Background()

	const archive = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
	resultFor := func(sha string) []byte {
		return []byte(`{"fs":[{"sha":"` + sha + `","type":"elf","dp":0}]}`)
	}

	// A genuinely top-level sample: empty parent, no parented locations.
	mustInsert(t, ctx, db, &Sample{SHA256: "top", Source: "test"})
	if err := db.UpdateCleaveResult(ctx, "top", resultFor("top"), nil, ""); err != nil {
		t.Fatal(err)
	}

	// A mirrored dependency: its samples.parent is empty (it was uploaded as
	// its own sample), but the locations ledger records it as a member of an
	// archive.
	mustInsert(t, ctx, db, &Sample{SHA256: "dep", Source: "test"})
	if err := db.UpdateCleaveResult(ctx, "dep", resultFor("dep"), nil, ""); err != nil {
		t.Fatal(err)
	}
	if err := db.UpsertLocation(ctx, &SampleLocation{
		SHA256:       "dep",
		Path:         "bad/feed/" + archive + "/" + archive + ".elf!!dep",
		ParentSHA256: archive,
		Filename:     "dep",
		Source:       "test",
	}); err != nil {
		t.Fatalf("UpsertLocation: %v", err)
	}

	q := FeedQuery{Source: "test", TopLevelOnly: true, Limit: 10}
	samples, err := db.FeedSamples(ctx, &q)
	if err != nil {
		t.Fatal(err)
	}
	if len(samples) != 1 || samples[0].SHA256 != "top" {
		t.Fatalf("TopLevelOnly feed = %+v, want just top", samples)
	}
	n, err := db.FeedSamplesCount(ctx, &q)
	if err != nil {
		t.Fatal(err)
	}
	if n != 1 {
		t.Fatalf("TopLevelOnly count = %d, want 1", n)
	}

	// Without TopLevelOnly both remain reachable.
	q.TopLevelOnly = false
	samples, err = db.FeedSamples(ctx, &q)
	if err != nil {
		t.Fatal(err)
	}
	if len(samples) != 2 {
		t.Fatalf("unfiltered feed = %d rows, want 2", len(samples))
	}
}

// TestFeedExcludesRegistrySidecars locks that the feed never lists provenance
// sidecars — the `*.registry.json` snapshots cleave types "registry", stored
// top-level beside a package. They describe an artifact rather than being one,
// so both FeedSamples and FeedSamplesCount must drop them.
func TestFeedExcludesRegistrySidecars(t *testing.T) {
	db := openTestDB(t)
	ctx := context.Background()

	// file_type is GENERATED from cleave_result's depth-0 type, so the sidecar
	// gets file_type='registry' by carrying that type in its result.
	resultWithType := func(sha, typ string) []byte {
		return []byte(`{"fs":[{"sha":"` + sha + `","type":"` + typ + `","dp":0}]}`)
	}

	mustInsert(t, ctx, db, &Sample{SHA256: "pkg", Source: "test"})
	if err := db.UpdateCleaveResult(ctx, "pkg", resultWithType("pkg", "npm"), nil, ""); err != nil {
		t.Fatal(err)
	}
	mustInsert(t, ctx, db, &Sample{SHA256: "sidecar", Source: "test"})
	if err := db.UpdateCleaveResult(ctx, "sidecar", resultWithType("sidecar", "registry"), nil, ""); err != nil {
		t.Fatal(err)
	}

	q := FeedQuery{Source: "test", Limit: 10}
	samples, err := db.FeedSamples(ctx, &q)
	if err != nil {
		t.Fatal(err)
	}
	if len(samples) != 1 || samples[0].SHA256 != "pkg" {
		t.Fatalf("feed = %+v, want just pkg (registry sidecar excluded)", samples)
	}
	n, err := db.FeedSamplesCount(ctx, &q)
	if err != nil {
		t.Fatal(err)
	}
	if n != 1 {
		t.Fatalf("feed count = %d, want 1 (registry sidecar excluded)", n)
	}
}

// TestFeedSamplesProjectionOmitsBlobs locks the feed projection contract:
// FeedSamples must not carry cleave_result (the archive member tree — up to
// megabytes) or llm_result, which the feed never renders, while it must keep
// litmus_result, from which each row's criticality is derived. The detail-page
// path (SampleBySHA256) still returns every blob. Guards both the PG
// (pgSampleColsFeed) and SQLite (liteSampleColsFeed) projections against a
// regression that would reintroduce the per-row blob load.
func TestFeedSamplesProjectionOmitsBlobs(t *testing.T) {
	db := openTestDB(t)
	ctx := context.Background()

	s := &Sample{SHA256: "feedproj1", Source: "test", Ecosystem: "eco1", Label: "bad"}
	mustInsert(t, ctx, db, s)

	// StoreResult persists all three JSON blobs atomically. The cleave payload
	// yields a non-empty file_type so the row is kept, not deleted, and its
	// traits feed the derived top_traits column.
	cleave := []byte(`{"files":[{"sha":"feedproj1","type":"elf","traits":[
		{"id":"micro-behaviors/net/beacon","crit":4},
		{"id":"objectives/exfil/dns-tunnel","crit":5},
		{"id":"metadata/pkg/obfuscated","crit":4},
		{"id":"micro-behaviors/fs/tmp-write","crit":4},
		{"id":"metadata/pkg/minified","crit":2}]}]}`)
	litmus := []byte(`{"class":1,"l":1}`)
	llm := []byte(`{"summary":"benign helper"}`)
	if _, err := db.StoreResult(ctx, "feedproj1", cleave, litmus, llm, nil, ""); err != nil {
		t.Fatal(err)
	}

	// The detail-page path keeps every blob.
	full, err := db.SampleBySHA256(ctx, "feedproj1")
	if err != nil {
		t.Fatal(err)
	}
	if len(full.CleaveResult) == 0 || len(full.LitmusResult) == 0 || len(full.LLMResult) == 0 {
		t.Fatalf("SampleBySHA256 must keep all blobs: cleave=%d litmus=%d llm=%d",
			len(full.CleaveResult), len(full.LitmusResult), len(full.LLMResult))
	}

	// The feed drops the one blob it never renders (cleave_result) but keeps
	// litmus_result (criticality source) and the small llm_result (per-row
	// rationale).
	rows, err := db.FeedSamples(ctx, &FeedQuery{Source: "test", Limit: 10})
	if err != nil {
		t.Fatal(err)
	}
	if len(rows) != 1 {
		t.Fatalf("expected 1 feed row, got %d", len(rows))
	}
	r := rows[0]
	if r.CleaveResult != nil {
		t.Errorf("feed row must omit cleave_result, got %d bytes", len(r.CleaveResult))
	}
	if len(r.LLMResult) == 0 {
		t.Error("feed row must retain llm_result (rationale source)")
	}
	if len(r.LitmusResult) == 0 {
		t.Error("feed row must retain litmus_result (criticality source)")
	}
	// top_traits: hostile first, then suspicious in emitted order, capped at
	// 3 — the crit-2 trait never qualifies.
	wantTraits := `[{"id":"objectives/exfil/dns-tunnel","crit":5},` +
		`{"id":"micro-behaviors/net/beacon","crit":4},` +
		`{"id":"metadata/pkg/obfuscated","crit":4}]`
	if r.TopTraits != wantTraits {
		t.Errorf("TopTraits = %q, want %q", r.TopTraits, wantTraits)
	}
	// No provenance sidecar: the registry scalars stay zero rather than erroring.
	if r.RegistryTitle != "" || r.RegistryDownloads != 0 {
		t.Errorf("no-sidecar row must have zero registry scalars, got %q/%d", r.RegistryTitle, r.RegistryDownloads)
	}

	// A sidecar with a registry record surfaces its marketplace title,
	// description, and install count on the feed row.
	sidecar := []byte(`{"schema_version":1,"registry":{"record":{"ecosystem":"chrome","name":"abcdef","title":"Volume Max — Sound Booster","description":"Boost your volume up to 600%.","downloads_total":412033}}}`)
	if ok, err := db.SetProvenance(ctx, &Sample{SHA256: "feedproj1", Provenance: sidecar}); err != nil || !ok {
		t.Fatalf("SetProvenance: ok=%v err=%v", ok, err)
	}
	rows, err = db.FeedSamples(ctx, &FeedQuery{Source: "test", Limit: 10})
	if err != nil {
		t.Fatal(err)
	}
	if len(rows) != 1 {
		t.Fatalf("expected 1 feed row, got %d", len(rows))
	}
	if rows[0].RegistryTitle != "Volume Max — Sound Booster" {
		t.Errorf("RegistryTitle = %q, want the sidecar's record title", rows[0].RegistryTitle)
	}
	if rows[0].RegistryDescription != "Boost your volume up to 600%." {
		t.Errorf("RegistryDescription = %q, want the sidecar's record description", rows[0].RegistryDescription)
	}
	if rows[0].RegistryDownloads != 412033 {
		t.Errorf("RegistryDownloads = %d, want 412033", rows[0].RegistryDownloads)
	}

	// The detail path surfaces the same registry scalars.
	full, err = db.SampleBySHA256(ctx, "feedproj1")
	if err != nil {
		t.Fatal(err)
	}
	if full.RegistryTitle != "Volume Max — Sound Booster" || full.RegistryDownloads != 412033 {
		t.Errorf("SampleBySHA256 registry scalars = %q/%d, want title/412033", full.RegistryTitle, full.RegistryDownloads)
	}
}

// TestFeedSamplesSearch exercises the free-text Search predicate: a
// case-insensitive filename substring or an exact sha256, applied in SQL so it
// spans the whole index rather than an in-memory page. LIKE metacharacters in
// the term must match literally, not as wildcards.
func TestFeedSamplesSearch(t *testing.T) {
	db := openTestDB(t)
	ctx := context.Background()

	resultFor := func(sha string) []byte {
		return []byte(`{"fs":[{"sha":"` + sha + `","type":"elf","dp":0}]}`)
	}
	insert := func(sha, filename, pkg string) {
		mustInsert(t, ctx, db, &Sample{SHA256: sha, Source: "test", Filename: filename, Package: pkg})
		if err := db.UpdateCleaveResult(ctx, sha, resultFor(sha), nil, ""); err != nil {
			t.Fatal(err)
		}
	}
	insert("abc123def", "requests.tar.gz", "requests")
	insert("beef0001", "left-pad.js", "left-pad")
	insert("cafe0002", "100%_real.bin", "")
	// The filename embeds no "xz-utils" substring, so this row is reachable
	// only through the exact package-name disjunct.
	insert("d00d0003", "xz-5.6.1.tar.gz", "xz-utils")
	// An underscore is a LIKE metacharacter; the package disjunct must match it
	// literally (equality, not escaped LIKE).
	insert("d00d0004", "pd.tgz", "python_dateutil")

	shas := func(q FeedQuery) []string {
		q.Source = "test"
		q.Limit = 10
		samples, err := db.FeedSamples(ctx, &q)
		if err != nil {
			t.Fatal(err)
		}
		count, err := db.FeedSamplesCount(ctx, &q)
		if err != nil {
			t.Fatal(err)
		}
		if count != len(samples) {
			t.Errorf("count %d disagrees with %d rows for %q", count, len(samples), q.Search)
		}
		out := make([]string, len(samples))
		for i, s := range samples {
			out[i] = s.SHA256
		}
		slices.Sort(out)
		return out
	}

	tests := []struct {
		name   string
		search string
		want   []string
	}{
		{"empty matches all", "", []string{"abc123def", "beef0001", "cafe0002", "d00d0003", "d00d0004"}},
		{"filename substring", "requests", []string{"abc123def"}},
		{"filename case-insensitive", "REQUESTS", []string{"abc123def"}},
		{"sha exact match", "beef0001", []string{"beef0001"}},
		{"sha partial no longer matches", "beef000", nil},
		{"no match", "nonexistent", nil},
		{"percent is literal not wildcard", "100%", []string{"cafe0002"}},
		// A bare "%" is a literal percent sign, so it matches only the
		// filename that contains one — not every row, as it would if the
		// term leaked through as a LIKE wildcard.
		{"bare percent is literal", "%", []string{"cafe0002"}},
		// Exact package name reaches a row whose filename embeds no such
		// substring, and is case-folded like the rest of the box.
		{"exact package name", "xz-utils", []string{"d00d0003"}},
		{"package name case-insensitive", "XZ-Utils", []string{"d00d0003"}},
		{"package underscore matched literally", "python_dateutil", []string{"d00d0004"}},
		// Package matching is exact, not substring: a fragment of a package
		// name (present in no filename either) matches nothing.
		{"package is exact not substring", "utils", nil},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := shas(FeedQuery{Search: tt.search})
			if !slices.Equal(got, tt.want) {
				t.Errorf("Search(%q) = %v, want %v", tt.search, got, tt.want)
			}
		})
	}
}

// TestFeedSamplesPURL covers the package-identity filter: PURLBase matches the
// version-less purl_base exactly (every release of the package), and PURLVersion
// pins one release. Both are exact equality, so a partial or wrong coordinate
// matches nothing, and select/count agree.
func TestFeedSamplesPURL(t *testing.T) {
	db := openTestDB(t)
	ctx := context.Background()

	resultFor := func(sha string) []byte {
		return []byte(`{"fs":[{"sha":"` + sha + `","type":"elf","dp":0}]}`)
	}
	insert := func(sha, purlBase, version string) {
		mustInsert(t, ctx, db, &Sample{
			SHA256: sha, Source: "test", PURLBase: purlBase, Version: version,
		})
		if err := db.UpdateCleaveResult(ctx, sha, resultFor(sha), nil, ""); err != nil {
			t.Fatal(err)
		}
	}
	insert("npm1", "pkg:npm/lodash", "4.17.21")
	insert("npm2", "pkg:npm/lodash", "4.17.20")
	insert("pypi1", "pkg:pypi/requests", "2.31.0")

	shas := func(q FeedQuery) []string {
		q.Source = "test"
		q.Limit = 10
		samples, err := db.FeedSamples(ctx, &q)
		if err != nil {
			t.Fatal(err)
		}
		count, err := db.FeedSamplesCount(ctx, &q)
		if err != nil {
			t.Fatal(err)
		}
		if count != len(samples) {
			t.Errorf("count %d disagrees with %d rows for %q@%q", count, len(samples), q.PURLBase, q.PURLVersion)
		}
		out := make([]string, len(samples))
		for i, s := range samples {
			out[i] = s.SHA256
		}
		slices.Sort(out)
		return out
	}

	tests := []struct {
		name    string
		base    string
		version string
		want    []string
	}{
		{"base matches every version", "pkg:npm/lodash", "", []string{"npm1", "npm2"}},
		{"base plus version pins one release", "pkg:npm/lodash", "4.17.21", []string{"npm1"}},
		{"other package", "pkg:pypi/requests", "", []string{"pypi1"}},
		{"unknown base matches nothing", "pkg:npm/nope", "", nil},
		{"wrong version matches nothing", "pkg:npm/lodash", "9.9.9", nil},
		{"version alone pins across packages", "", "2.31.0", []string{"pypi1"}},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := shas(FeedQuery{PURLBase: tt.base, PURLVersion: tt.version})
			if !slices.Equal(got, tt.want) {
				t.Errorf("PURL(%q,%q) = %v, want %v", tt.base, tt.version, got, tt.want)
			}
		})
	}
}

// TestSampleByPURL is the beamline point lookup: newest analyzed top-level
// row for a package identity, full envelope (cleave kept), members and
// unanalyzed rows skipped. Empty base is ErrNotFound without a table scan.
func TestSampleByPURL(t *testing.T) {
	db := openTestDB(t)
	ctx := context.Background()

	analyze := func(sha string) {
		t.Helper()
		if err := db.UpdateCleaveResult(ctx, sha, []byte(`{"fs":[{"sha":"`+sha+`","type":"elf","dp":0}]}`), nil, ""); err != nil {
			t.Fatal(err)
		}
		if err := db.UpdateLitmusResult(ctx, sha, []byte(`{"v":"7","prob":0.01,"lvl":-1}`)); err != nil {
			t.Fatal(err)
		}
	}
	mustInsert(t, ctx, db, &Sample{SHA256: "old", Source: "test", PURLBase: "pkg:npm/lodash", Version: "4.17.20"})
	analyze("old")
	// A registry artifact that some archive also bundles. It was fetched from a
	// registry, so it has provenance, a version and a purl_base of its own —
	// being copied into someone else's archive is a fact about the archive, and
	// must not hide the package from its own PURL.
	mustInsert(t, ctx, db, &Sample{
		SHA256: "bundled", Source: "forager", PURLBase: "pkg:npm/lodash", Version: "4.17.19",
		Parent: "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
	})
	analyze("bundled")
	time.Sleep(20 * time.Millisecond)
	mustInsert(t, ctx, db, &Sample{SHA256: "new", Source: "test", PURLBase: "pkg:npm/lodash", Version: "4.17.21"})
	analyze("new")
	mustInsert(t, ctx, db, &Sample{SHA256: "pending", Source: "test", PURLBase: "pkg:npm/lodash", Version: "4.17.22"})
	// A faithful archive member. explodeMembers copies feed, ecosystem, label
	// and parent lineage but never package, version or purl_base: a member has
	// no identity of its own, and that — not containment — is what keeps it out
	// of a PURL lookup. The previous fixture hand-assigned it a purl_base no
	// ingest path can produce.
	mustInsert(t, ctx, db, &Sample{
		SHA256: "inside", Source: SourceExploded,
		Parent: "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
		Path:   "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa!!lib.js",
	})
	analyze("inside")

	got, err := db.SampleByPURL(ctx, "pkg:npm/lodash", "4.17.20")
	if err != nil {
		t.Fatalf("versioned: %v", err)
	}
	if got.SHA256 != "old" {
		t.Errorf("versioned sha = %q, want old", got.SHA256)
	}
	if len(got.CleaveResult) == 0 {
		t.Error("versioned dropped cleave_result (feed projection?)")
	}

	got, err = db.SampleByPURL(ctx, "pkg:npm/lodash", "")
	if err != nil {
		t.Fatalf("versionless: %v", err)
	}
	if got.SHA256 != "new" {
		t.Errorf("versionless sha = %q, want newest analyzed (new), not pending or member", got.SHA256)
	}

	if _, err := db.SampleByPURL(ctx, "pkg:npm/lodash", "4.17.22"); !errors.Is(err, ErrNotFound) {
		t.Errorf("unanalyzed version: err = %v, want ErrNotFound", err)
	}
	if _, err := db.SampleByPURL(ctx, "pkg:npm/lodash", "9.9.9"); !errors.Is(err, ErrNotFound) {
		t.Errorf("archive member: err = %v, want ErrNotFound", err)
	}
	got, err = db.SampleByPURL(ctx, "pkg:npm/lodash", "4.17.19")
	if err != nil {
		t.Fatalf("bundled release: %v", err)
	}
	if got.SHA256 != "bundled" {
		t.Errorf("bundled sha = %q, want bundled: an archive holding a copy must not hide the release", got.SHA256)
	}
	if _, err := db.SampleByPURL(ctx, "pkg:npm/nope", "1.0.0"); !errors.Is(err, ErrNotFound) {
		t.Errorf("miss: err = %v, want ErrNotFound", err)
	}
	if _, err := db.SampleByPURL(ctx, "", ""); !errors.Is(err, ErrNotFound) {
		t.Errorf("empty base: err = %v, want ErrNotFound", err)
	}
}

// TestFeedSamplesLitmusClassesV6V7 locks in the compact level → 0/1/2 class
// derivation used by the LitmusClasses filter, mirroring prism's envelopeClass:
// -1 benign, null manual-mode hostile, 0..=CriticalLevel hostile, above
// suspicious. It guards the regression where the hostile filter dropped compact
// litmus rows.
func TestFeedSamplesLitmusClassesV6V7(t *testing.T) {
	db := openTestDB(t)
	ctx := context.Background()

	// class is the expected 0/1/2 bucket under the standard bands. Boundary
	// levels are derived from CriticalLevel/SuspiciousCeiling so the fixtures
	// track the operating point instead of hardcoding it.
	rows := []struct {
		sha    string
		litmus string
		class  int
	}{
		{"v6null", `{"v":"6","l":null}`, 2},                                  // manual-mode hostile, fail-safe
		{"v6lo", `{"v":"6","l":0}`, 2},                                       // fires at the strictest level
		{"v6inband", fmt.Sprintf(`{"v":"6","l":%d}`, CriticalLevel/2), 2},    // well inside the hostile band
		{"v6crit", fmt.Sprintf(`{"v":"6","l":%d}`, CriticalLevel), 2},        // at the critical line: hostile
		{"v6susp", fmt.Sprintf(`{"v":"6","l":%d}`, CriticalLevel+1), 1},      // just above the line: suspicious
		{"v6benign", `{"v":"6","l":-1}`, 0},                                  // never fires
		{"v6loose", fmt.Sprintf(`{"v":"6","l":%d}`, SuspiciousCeiling+1), 0}, // above the ceiling: benign, not suspicious
		{"v7null", `{"v":"7","lvl":null}`, 2},
		{"v7lo", `{"v":"7","lvl":0}`, 2},
		{"v7crit", fmt.Sprintf(`{"v":"7","lvl":%d}`, CriticalLevel), 2},        // at the critical line: hostile
		{"v7susp", fmt.Sprintf(`{"v":"7","lvl":%d}`, CriticalLevel+1), 1},      // just above the line: suspicious
		{"v7ceil", fmt.Sprintf(`{"v":"7","lvl":%d}`, SuspiciousCeiling), 1},    // at the ceiling: still suspicious
		{"v7loose", fmt.Sprintf(`{"v":"7","lvl":%d}`, SuspiciousCeiling+1), 0}, // above the ceiling: benign, not suspicious
		{"v7benign", `{"v":"7","lvl":-1}`, 0},
		{"legacy2", `{"v":"4","class":2}`, 2},
		{"legacy1", `{"v":"4","class":1}`, 1},
	}
	for _, r := range rows {
		mustInsert(t, ctx, db, &Sample{SHA256: r.sha, Source: "v6test", Label: "bad"})
		if err := db.UpdateCleaveResult(ctx, r.sha, []byte(`{"fs":[{"sha":"`+r.sha+`","type":"elf","dp":0}]}`), nil, ""); err != nil {
			t.Fatal(err)
		}
		if err := db.UpdateLitmusResult(ctx, r.sha, []byte(r.litmus)); err != nil {
			t.Fatal(err)
		}
	}

	for class := range 3 {
		// Pin the standard critical-level cutoff explicitly so the expectations
		// above are deterministic regardless of the package default.
		q := FeedQuery{Source: "v6test", Limit: 100, CriticalLevel: CriticalLevel, LitmusClasses: []int{class}}
		samples, err := db.FeedSamples(ctx, &q)
		if err != nil {
			t.Fatal(err)
		}
		got := make(map[string]bool, len(samples))
		for _, s := range samples {
			got[s.SHA256] = true
		}
		count, err := db.FeedSamplesCount(ctx, &q)
		if err != nil {
			t.Fatal(err)
		}
		if count != len(samples) {
			t.Errorf("class=%d: count %d != len(samples) %d", class, count, len(samples))
		}
		for _, r := range rows {
			if want := r.class == class; got[r.sha] != want {
				t.Errorf("class=%d filter: %s (level-class %d) present=%v, want %v", class, r.sha, r.class, got[r.sha], want)
			}
		}
	}

	// A caller-pinned cutoff moves the line: with a stricter cutoff one below the
	// critical line, v6crit (hostile at the default cutoff, since it fires exactly
	// at the line) becomes suspicious. This is the consumer-owned override knob
	// (the FeedQuery equivalent of scan's `-l`).
	q := FeedQuery{Source: "v6test", Limit: 100, CriticalLevel: CriticalLevel - 1, LitmusClasses: []int{1}}
	samples, err := db.FeedSamples(ctx, &q)
	if err != nil {
		t.Fatal(err)
	}
	var found bool
	for _, s := range samples {
		if s.SHA256 == "v6crit" {
			found = true
		}
	}
	if !found {
		t.Errorf("stricter cutoff: expected v6crit (fires at the critical line) to be classed suspicious")
	}
}

func TestFeedQueryRequireLitmus(t *testing.T) {
	tests := []struct {
		name string
		q    FeedQuery
		want bool
	}{
		{"explicit", FeedQuery{RequireLitmus: true}, true},
		{"no filter", FeedQuery{}, false},
		{"hostile band", FeedQuery{LitmusClasses: []int{2}}, true},
		{"suspicious+hostile", FeedQuery{LitmusClasses: []int{1, 2}}, true},
		{"includes benign", FeedQuery{LitmusClasses: []int{0, 2}}, false},
		{"benign only", FeedQuery{LitmusClasses: []int{0}}, false},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := tt.q.requireLitmus(); got != tt.want {
				t.Errorf("requireLitmus() = %v, want %v", got, tt.want)
			}
		})
	}
}

func TestFeedQueryClassExpr(t *testing.T) {
	// Default cutoff reads the indexed litmus_class column.
	if got := (&FeedQuery{}).feedClassExpr(); got != "litmus_class" {
		t.Errorf("default cutoff: feedClassExpr() = %q, want %q", got, "litmus_class")
	}
	if got := (&FeedQuery{CriticalLevel: CriticalLevel}).feedClassExpr(); got != "litmus_class" {
		t.Errorf("explicit default cutoff: feedClassExpr() = %q, want %q", got, "litmus_class")
	}
	// A non-default cutoff must re-derive from litmus_result (the column is
	// pinned to CriticalLevel) and inline the cutoff as a literal — never leave a
	// dangling bound parameter (the $12 / 42P18 regression).
	got := (&FeedQuery{CriticalLevel: 3}).feedClassExpr()
	if got == "litmus_class" {
		t.Fatal("non-default cutoff must not use the litmus_class column")
	}
	if !strings.Contains(got, "litmus_result->>'class'") || !strings.Contains(got, "<= 3") {
		t.Errorf("non-default cutoff expr missing derivation or inlined cutoff: %q", got)
	}
	// The suspicious band is capped at the L100 ceiling: firings looser than it
	// read benign, so the derived expr must inline the ceiling too.
	if !strings.Contains(got, fmt.Sprintf("<= %d THEN 1", SuspiciousCeiling)) {
		t.Errorf("non-default cutoff expr missing the L%d suspicious ceiling: %q", SuspiciousCeiling, got)
	}
}

func TestFeedArrayFilter(t *testing.T) {
	// No values: the ANY form, and the parameter stays referenced by the
	// cardinality guard so it can never dangle untyped (42P18).
	got := feedArrayFilter("ecosystem", "$4", "::text[]", 0)
	if !strings.Contains(got, "= ANY($4)") {
		t.Errorf("no values: want the ANY form, got %q", got)
	}
	if !strings.Contains(got, "cardinality($4::text[])") {
		t.Errorf("no values: parameter must stay referenced, got %q", got)
	}

	// Exactly one value must read that value back out of the SAME parameter by
	// subscript — never interpolated, so a user-supplied ecosystem or domain
	// cannot reach the SQL text. The ANY form cannot be walked in index order, so
	// it forces a sort to return one page; this is what avoids it.
	got = feedArrayFilter("ecosystem", "$4", "::text[]", 1)
	if strings.Contains(got, "ANY") {
		t.Errorf("single value must not use ANY, got %q", got)
	}
	if !strings.Contains(got, "ecosystem = ($4::text[])[1]") {
		t.Errorf("single value: want subscripted scalar equality, got %q", got)
	}

	// Several values genuinely need the array form.
	got = feedArrayFilter("ecosystem", "$4", "::text[]", 2)
	if !strings.Contains(got, "= ANY($4)") {
		t.Errorf("multi value: want the ANY form, got %q", got)
	}
}

func TestFeedQueryFilters(t *testing.T) {
	// Every criticality prism's dropdown offers is exactly one class, and prism
	// passes exactly one ecosystem and one domain, so all of these are the
	// single-value path in practice.
	for _, tt := range []struct {
		name string
		got  string
		want string
	}{
		{"class", (&FeedQuery{LitmusClasses: []int{2}}).feedClassFilter("$5"), "litmus_class = ($5::int[])[1]"},
		{"feeds", (&FeedQuery{Feeds: []string{"npm"}}).feedFeedsFilter("$3"), "feed = ($3::text[])[1]"},
		{"ecosystems", (&FeedQuery{Ecosystems: []string{"go"}}).feedEcosystemsFilter("$4"), "ecosystem = ($4::text[])[1]"},
		{"domains", (&FeedQuery{Domains: []string{"x.io"}}).feedDomainsFilter("$9"), "domain = ($9::text[])[1]"},
	} {
		if !strings.Contains(tt.got, tt.want) {
			t.Errorf("%s: want %q in %q", tt.name, tt.want, tt.got)
		}
		if strings.Contains(tt.got, "ANY") {
			t.Errorf("%s: single value must not use ANY, got %q", tt.name, tt.got)
		}
	}

	// Multi-value ranges (parseCritExpr ">=1") keep the array form.
	if got := (&FeedQuery{LitmusClasses: []int{1, 2}}).feedClassFilter("$5"); !strings.Contains(got, "= ANY($5)") {
		t.Errorf("multi-class: want the ANY form, got %q", got)
	}

	// A non-default cutoff re-derives the class inline; the scalar path must
	// compare that derivation, not the litmus_class column.
	got := (&FeedQuery{CriticalLevel: 3, LitmusClasses: []int{2}}).feedClassFilter("$5")
	if !strings.Contains(got, "litmus_result->>'class'") || !strings.HasSuffix(got, "= ($5::int[])[1])") {
		t.Errorf("non-default cutoff must compare the derived expr by subscript: %q", got)
	}
}

func TestPool(t *testing.T) {
	db := openTestDB(t)
	if db.Pool() != nil {
		t.Error("Pool() should be nil for SQLite")
	}
}

func TestWorkflowLatestReadyUsesFirstAnalyzedAt(t *testing.T) {
	db := openTestDB(t)
	ctx := context.Background()

	oldFirst := time.Date(2026, 5, 1, 10, 0, 0, 0, time.UTC)
	newFirst := time.Date(2026, 5, 2, 10, 0, 0, 0, time.UTC)
	oldCreated := time.Date(2026, 5, 3, 10, 0, 0, 0, time.UTC)
	newCreated := time.Date(2026, 5, 1, 9, 0, 0, 0, time.UTC)

	for _, sha := range []string{"ready-old", "ready-new"} {
		mustInsert(t, ctx, db, &Sample{SHA256: sha, Source: "test", Label: "bad", LabelSource: "test"})
		if err := db.UpdateCleaveResult(ctx, sha, []byte(`{"fs":[{"sha":"`+sha+`","type":"elf","dp":0}]}`), nil, ""); err != nil {
			t.Fatal(err)
		}
		if err := db.UpdateLitmusResult(ctx, sha, []byte(`{"prob":0.9,"class":1}`)); err != nil {
			t.Fatal(err)
		}
	}
	if _, err := db.lite.ExecContext(ctx,
		`UPDATE samples SET created_at = ?, first_analyzed_at = ?, analyzed_at = ? WHERE sha256 = ?`,
		oldCreated.Format(time.RFC3339Nano), oldFirst.Format(time.RFC3339Nano), oldFirst.Format(time.RFC3339Nano), "ready-old"); err != nil {
		t.Fatal(err)
	}
	if _, err := db.lite.ExecContext(ctx,
		`UPDATE samples SET created_at = ?, first_analyzed_at = ?, analyzed_at = ? WHERE sha256 = ?`,
		newCreated.Format(time.RFC3339Nano), newFirst.Format(time.RFC3339Nano), newFirst.Format(time.RFC3339Nano), "ready-new"); err != nil {
		t.Fatal(err)
	}

	rows, err := db.WorkflowLatestReady(ctx, 2)
	if err != nil {
		t.Fatal(err)
	}
	if len(rows) != 2 || rows[0].SHA256 != "ready-new" || rows[1].SHA256 != "ready-old" {
		t.Fatalf("latest ready order = %+v, want ready-new then ready-old", rows)
	}
	if rows[0].FirstAnalyzedAt == nil || !rows[0].FirstAnalyzedAt.Equal(newFirst) {
		t.Fatalf("first analyzed = %v, want %v", rows[0].FirstAnalyzedAt, newFirst)
	}
	h, err := db.WorkflowHealth(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if !h.LatestReady.Equal(newFirst) {
		t.Fatalf("health latest ready = %v, want %v", h.LatestReady, newFirst)
	}
}

func TestStripSubscripts(t *testing.T) {
	tests := []struct {
		in, want string
	}{
		{"O₃(C₂Er₂As)H₃(F₃OsPo₃)Md₃(PtBi)", "O(CErAs)H(FOsPo)Md(PtBi)"},
		{"", ""},
		{"NoPo", "NoPo"},
		{"H₁₀", "H"},
	}
	for _, tt := range tests {
		got := stripSubscripts(tt.in)
		if got != tt.want {
			t.Errorf("stripSubscripts(%q) = %q, want %q", tt.in, got, tt.want)
		}
	}
}

func TestParseCleaveFile(t *testing.T) {
	result := []byte(`{"fs":[{"sha":"aaa","f":"O₃H₂","x":16,"dp":0}]}`)
	fi := parseCleaveFile("aaa", result)
	if fi.Formula != "O₃H₂" {
		t.Errorf("Formula = %q", fi.Formula)
	}
	if fi.Elements != "OH" {
		t.Errorf("Elements = %q", fi.Elements)
	}
	if fi.Score != 16 {
		t.Errorf("Score = %d", fi.Score)
	}

	// Empty result.
	fi = parseCleaveFile("aaa", nil)
	if fi.Formula != "" || fi.Score != 0 {
		t.Errorf("expected empty for nil result, got %+v", fi)
	}

	// Invalid JSON.
	fi = parseCleaveFile("aaa", []byte("{bad"))
	if fi.Formula != "" {
		t.Errorf("expected empty for bad JSON, got %+v", fi)
	}
}

func TestParseCleaveResultV5KeepsMetadataAndIgnoresFacts(t *testing.T) {
	result := []byte(`{"v":"5","tv":"abcde","fs":[{"sha":"aaa","type":"pe","f":"O₃","x":16,"dp":0,"ts":[{"l":4},{"l":5}],"ff":{"id":"pe","m":{"binary":{"overall_entropy":7.2}},"v":{"pe.machine":"x86_64"}}}]}`)
	parsed := ParseCleaveResult("aaa", result)
	if parsed.TraitsVersion != "abcde" {
		t.Fatalf("TraitsVersion = %q", parsed.TraitsVersion)
	}
	if parsed.FileInfo.FileType != "pe" || parsed.FileInfo.Formula != "O₃" || parsed.FileInfo.Score != 16 {
		t.Fatalf("FileInfo = %+v", parsed.FileInfo)
	}
	if parsed.FileInfo.MaxCrit != 5 || parsed.FileInfo.SuspiciousCount != 2 {
		t.Fatalf("crit summary = max %d suspicious %d", parsed.FileInfo.MaxCrit, parsed.FileInfo.SuspiciousCount)
	}
}

func TestParseCleaveResultV7KeepsMetadata(t *testing.T) {
	result := []byte(`{"v":"7","tv":"abcde","files":[{"sha":"aaa","type":"pe","mol":"O₃","risk":16,"dp":0,"find":[{"crit":4},{"crit":5}],"fact":{"id":"pe","met":{"binary":{"overall_entropy":7.2}},"val":{"pe.machine":"x86_64"}}}]}`)
	parsed := ParseCleaveResult("aaa", result)
	if parsed.TraitsVersion != "abcde" {
		t.Fatalf("TraitsVersion = %q", parsed.TraitsVersion)
	}
	if parsed.FileInfo.FileType != "pe" || parsed.FileInfo.Formula != "O₃" || parsed.FileInfo.Score != 16 {
		t.Fatalf("FileInfo = %+v", parsed.FileInfo)
	}
	if parsed.FileInfo.MaxCrit != 5 || parsed.FileInfo.SuspiciousCount != 2 {
		t.Fatalf("crit summary = max %d suspicious %d", parsed.FileInfo.MaxCrit, parsed.FileInfo.SuspiciousCount)
	}
}

// A fetch/dependency-verdict trait carries a machine-readable dep object
// ({locator, sha, type}) that must ride through into top_traits verbatim —
// hopper is a pass-through; scan produces the shape and prism consumes it.
// Traits without a dep must stay bare {id, crit}, exactly as before.
func TestParseCleaveResultForwardsDependencyIdentity(t *testing.T) {
	depSHA := strings.Repeat("d", 64)
	result := []byte(`{"rev":"abcde","files":[{"sha":"aaa","type":"gzip","mol":"O₂","risk":40,"depth":0,"traits":[
		{"id":"fetch/dependency-verdict","crit":5,"desc":"Malicious dependency: pkg:npm/zaboodle@1.49 | ` + depSHA + `","dep":{"locator":"pkg:npm/zaboodle@1.49","sha":"` + depSHA + `","type":"javascript"}},
		{"id":"micro-behaviors/net/beacon","crit":4}]}]}`)
	parsed := ParseCleaveResult("aaa", result)

	var top []TopTrait
	if err := json.Unmarshal([]byte(parsed.FileInfo.TopTraits), &top); err != nil {
		t.Fatalf("top_traits does not parse: %v (%q)", err, parsed.FileInfo.TopTraits)
	}
	if len(top) != 2 {
		t.Fatalf("expected 2 top traits, got %d: %q", len(top), parsed.FileInfo.TopTraits)
	}

	var dep struct {
		Locator string `json:"locator"`
		SHA     string `json:"sha"`
		Type    string `json:"type"`
	}
	if err := json.Unmarshal(top[0].Dep, &dep); err != nil {
		t.Fatalf("dep does not parse: %v (%q)", err, top[0].Dep)
	}
	if dep.Locator != "pkg:npm/zaboodle@1.49" || dep.SHA != depSHA || dep.Type != "javascript" {
		t.Errorf("dep = %+v, want the scan-emitted identity verbatim", dep)
	}

	// The ordinary trait stays bare: no dep key at all, not "dep":null.
	if top[1].Dep != nil {
		t.Errorf("non-dependency trait must carry no dep, got %q", top[1].Dep)
	}
	if strings.Contains(parsed.FileInfo.TopTraits, `"dep":null`) {
		t.Errorf("encoded top_traits must omit absent deps, got %q", parsed.FileInfo.TopTraits)
	}
}

// Rows scanned before scan emitted dep (or hopper learned the field) decode
// into a TopTrait with a nil Dep — the consumer's fallback-to-generic-chip
// path — and old bare entries re-encode without inventing a dep key.
func TestTopTraitsDependencyIdentityBackwardCompat(t *testing.T) {
	var top []TopTrait
	if err := json.Unmarshal([]byte(`[{"id":"fetch/dependency-verdict","crit":5}]`), &top); err != nil {
		t.Fatal(err)
	}
	if top[0].Dep != nil {
		t.Errorf("pre-dep row must decode to nil Dep, got %q", top[0].Dep)
	}
	if got := encodeTopTraits(top); got != `[{"id":"fetch/dependency-verdict","crit":5}]` {
		t.Errorf("re-encode must stay bare, got %q", got)
	}
}

func TestUpdateCleaveResultSetsFormulaAndScore(t *testing.T) {
	db := openTestDB(t)
	ctx := context.Background()

	mustInsert(t, ctx, db, &Sample{SHA256: "fs1", Source: "test", Label: "bad", LabelSource: "test"})
	result := []byte(`{"fs":[{"sha":"fs1","type":"elf","f":"O₃(C₂Er₂As)","x":42,"dp":0}]}`)
	if err := db.UpdateCleaveResult(ctx, "fs1", result, nil, ""); err != nil {
		t.Fatal(err)
	}

	got, err := db.SampleBySHA256(ctx, "fs1")
	if err != nil {
		t.Fatal(err)
	}
	if got.Formula != "O₃(C₂Er₂As)" {
		t.Errorf("Formula = %q", got.Formula)
	}
	if got.Elements != "O(CErAs)" {
		t.Errorf("Elements = %q", got.Elements)
	}
	if got.Score != 42 {
		t.Errorf("Score = %d", got.Score)
	}
}

func TestUpdateCleaveResultCompactsArchiveStorage(t *testing.T) {
	db := openTestDB(t)
	ctx := context.Background()

	parentSHA := "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb"
	childSHA := "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
	result := []byte(`{"tv":"abcde","fs":[` +
		`{"sha":"` + parentSHA + `","type":"zip","path":"archive.zip","dp":0,"x":7},` +
		`{"sha":"` + childSHA + `","type":"py","path":"pkg/x.py","dp":1,"x":3}` +
		`]}`)
	mustInsert(t, ctx, db, &Sample{SHA256: parentSHA, Source: "test", Label: "bad", LabelSource: "test"})
	if err := db.UpdateCleaveResult(ctx, parentSHA, result, nil, "abcde"); err != nil {
		t.Fatal(err)
	}

	got, err := db.SampleBySHA256(ctx, parentSHA)
	if err != nil {
		t.Fatal(err)
	}
	if got.CanonicalSHA256 != childSHA {
		t.Fatalf("canonical = %s, want embedded child %s", got.CanonicalSHA256, childSHA)
	}
	var stored struct {
		TraitsVersion string                       `json:"tv"`
		Files         []map[string]json.RawMessage `json:"files"`
		Truncated     bool                         `json:"truncated"`
		OmittedFiles  int                          `json:"omitted_files"`
	}
	if err := json.Unmarshal(got.CleaveResult, &stored); err != nil {
		t.Fatal(err)
	}
	// The child is kept as a lightweight stub in the existing files[] schema —
	// not dropped, not moved to a side structure — so its id/sha/path survive
	// for `from`-reference resolution and on-demand hydration.
	if len(stored.Files) != 2 {
		t.Fatalf("stored files = %d, want 2 (parent + child stub): %s", len(stored.Files), got.CleaveResult)
	}
	if !stored.Truncated || stored.OmittedFiles != 0 || stored.TraitsVersion != "abcde" {
		t.Fatalf("stored compact metadata: truncated=%v omitted=%d tv=%q", stored.Truncated, stored.OmittedFiles, stored.TraitsVersion)
	}
	parentSHAJSON, err := json.Marshal(parentSHA)
	if err != nil {
		t.Fatalf("marshal parent sha: %v", err)
	}
	if !bytes.Equal(stored.Files[0]["sha"], parentSHAJSON) {
		t.Fatalf("files[0] sha = %s, want parent", stored.Files[0]["sha"])
	}
	childStub := stored.Files[1]
	childSHAJSON, err := json.Marshal(childSHA)
	if err != nil {
		t.Fatalf("marshal child sha: %v", err)
	}
	if !bytes.Equal(childStub["sha"], childSHAJSON) {
		t.Fatalf("child stub sha = %s, want %s", childStub["sha"], childSHA)
	}
	if _, ok := childStub["path"]; !ok {
		t.Errorf("child stub should retain path: %+v", childStub)
	}
	// The heavy, per-trait field (x) must be stripped from the stub.
	if _, ok := childStub["x"]; ok {
		t.Errorf("child stub should not retain heavy fields, got %+v", childStub)
	}
}

func TestDeleteSample(t *testing.T) {
	db := openTestDB(t)
	ctx := context.Background()

	mustInsert(t, ctx, db, &Sample{SHA256: "del1", Source: "test", Label: "bad", LabelSource: "test"})
	mustInsert(t, ctx, db, &Sample{SHA256: "del2", Source: "test", Label: "good", LabelSource: "test"})
	if err := db.InsertReport(ctx, &Report{SHA256: "del1", Type: "re", Content: "r"}); err != nil {
		t.Fatal(err)
	}

	if err := db.DeleteSample(ctx, "del1"); err != nil {
		t.Fatalf("DeleteSample: %v", err)
	}

	if _, err := db.SampleBySHA256(ctx, "del1"); !errors.Is(err, ErrNotFound) {
		t.Errorf("del1 should be gone, got err=%v", err)
	}
	if _, err := db.SampleBySHA256(ctx, "del2"); err != nil {
		t.Errorf("del2 should still exist, got err=%v", err)
	}
	reports, err := db.ReportsBySHA256(ctx, "del1")
	if err != nil {
		t.Fatal(err)
	}
	if len(reports) != 0 {
		t.Errorf("reports for del1 should be gone, got %d", len(reports))
	}

	// Idempotent: deleting a non-existent sample is not an error.
	if err := db.DeleteSample(ctx, "doesnotexist"); err != nil {
		t.Errorf("DeleteSample(missing): %v", err)
	}
}

func TestUpdateCleaveResultDeletesOnEmptyFileType(t *testing.T) {
	db := openTestDB(t)
	ctx := context.Background()

	mustInsert(t, ctx, db, &Sample{SHA256: "nc1", Source: "test", Label: "bad", LabelSource: "test"})
	// Report with no fs[] entry → parseCleaveFile returns empty file_type →
	// the row should be deleted, not updated.
	if err := db.UpdateCleaveResult(ctx, "nc1", []byte(`{"fs":[]}`), nil, ""); err != nil {
		t.Fatalf("UpdateCleaveResult: %v", err)
	}
	if _, err := db.SampleBySHA256(ctx, "nc1"); !errors.Is(err, ErrNotFound) {
		t.Errorf("nc1 should be deleted, got err=%v", err)
	}
}

func TestUpdateSampleDeletesOnEmptyFileType(t *testing.T) {
	db := openTestDB(t)
	ctx := context.Background()

	mustInsert(t, ctx, db, &Sample{SHA256: "us1", Source: "test", Label: "bad", LabelSource: "test", Status: "pending"})
	if err := db.UpdateSample(ctx, "us1", "done", []byte(`{"fs":[]}`), ""); err != nil {
		t.Fatalf("UpdateSample: %v", err)
	}
	if _, err := db.SampleBySHA256(ctx, "us1"); !errors.Is(err, ErrNotFound) {
		t.Errorf("us1 should be deleted, got err=%v", err)
	}
}

func TestPurgeUnsupported(t *testing.T) {
	db := openTestDB(t)
	ctx := context.Background()

	// Analyzed + recognized → stays.
	mustInsert(t, ctx, db, &Sample{SHA256: "keep1", Source: "test", Label: "bad", LabelSource: "test"})
	mustAnalyze(t, ctx, db, "keep1", 90)

	// Unanalyzed → stays (P3 will catch it when analysis runs).
	mustInsert(t, ctx, db, &Sample{SHA256: "keep2", Source: "test", Label: "bad", LabelSource: "test"})

	// Analyzed but unrecognized: simulate a historical row by writing a
	// cleave_result with an empty fs[] (no fs[0], so GENERATED file_type
	// evaluates to '').
	mustInsert(t, ctx, db, &Sample{SHA256: "junk1", Source: "test", Label: "bad", LabelSource: "test"})
	if _, err := db.lite.ExecContext(ctx,
		`UPDATE samples SET cleave_result = ? WHERE sha256 = ?`,
		`{"fs":[]}`, "junk1"); err != nil {
		t.Fatal(err)
	}
	if err := db.InsertReport(ctx, &Report{SHA256: "junk1", Type: "re", Content: "stale"}); err != nil {
		t.Fatal(err)
	}

	// Dry run: should count but not delete.
	n, err := db.PurgeUnsupported(ctx, true)
	if err != nil {
		t.Fatalf("PurgeUnsupported dry-run: %v", err)
	}
	if n != 1 {
		t.Errorf("dry-run count = %d, want 1", n)
	}
	if _, err := db.SampleBySHA256(ctx, "junk1"); err != nil {
		t.Errorf("junk1 should still exist after dry-run, got err=%v", err)
	}

	// Apply: deletes junk1 and its report, leaves keep1/keep2 alone.
	n, err = db.PurgeUnsupported(ctx, false)
	if err != nil {
		t.Fatalf("PurgeUnsupported apply: %v", err)
	}
	if n != 1 {
		t.Errorf("apply count = %d, want 1", n)
	}
	if _, err := db.SampleBySHA256(ctx, "junk1"); !errors.Is(err, ErrNotFound) {
		t.Errorf("junk1 should be gone, got err=%v", err)
	}
	if _, err := db.SampleBySHA256(ctx, "keep1"); err != nil {
		t.Errorf("keep1 should still exist, got err=%v", err)
	}
	if _, err := db.SampleBySHA256(ctx, "keep2"); err != nil {
		t.Errorf("keep2 should still exist, got err=%v", err)
	}
	reports, err := db.ReportsBySHA256(ctx, "junk1")
	if err != nil {
		t.Fatal(err)
	}
	if len(reports) != 0 {
		t.Errorf("junk1 reports should be gone, got %d", len(reports))
	}
}

// TestApplyCleanupBatches exercises a CleanupStage with BatchSize set — the
// path added for registry_metadata_only, whose real row count (6.2M) made a
// single-transaction delete a bad idea. A batch size smaller than the total
// row count forces the loop to run more than once, so this only passes if
// every batch actually deletes its rows and the loop correctly re-queries
// the (shrinking) predicate rather than looping forever or stopping early.
func TestApplyCleanupBatches(t *testing.T) {
	db := openTestDB(t)
	ctx := context.Background()

	const total = 10
	for i := range total {
		sha := fmt.Sprintf("batch-junk-%d", i)
		mustInsert(t, ctx, db, &Sample{
			SHA256:   sha,
			Filename: fmt.Sprintf("pkg-%d@1.0.0.registry.json", i),
			Source:   "test",
			Label:    "unknown",
		})
		// mustInsert gives every sample a synthetic non-empty path —
		// InsertSample rejects an empty one, same as production's real
		// upload path. The rows this stage targets never went through that
		// path at all (they were verdict-only /api/result posts), so force
		// the state directly, the same way TestPurgeUnsupported simulates a
		// historical row shape InsertSample wouldn't produce.
		if _, err := db.lite.ExecContext(ctx, `UPDATE samples SET path = '' WHERE sha256 = ?`, sha); err != nil {
			t.Fatal(err)
		}
		if err := db.InsertReport(ctx, &Report{SHA256: sha, Type: "re", Content: "stale"}); err != nil {
			t.Fatal(err)
		}
	}
	// A sample this stage must not touch: real path, doesn't match the
	// filename pattern.
	mustInsert(t, ctx, db, &Sample{SHA256: "keep", Filename: "real.tgz", Path: "incoming/scan/real.tgz", Source: "test", Label: "unknown"})

	stage := CleanupStage{
		Name:      "test_batch",
		predicate: "path = '' AND filename LIKE '%.registry.json'",
		BatchSize: 3, // smaller than total, so this must loop more than once
	}

	n, err := db.CountCleanup(ctx, stage)
	if err != nil {
		t.Fatalf("CountCleanup: %v", err)
	}
	if n != total {
		t.Fatalf("dry-run count = %d, want %d", n, total)
	}

	deleted, err := db.ApplyCleanup(ctx, stage)
	if err != nil {
		t.Fatalf("ApplyCleanup: %v", err)
	}
	if deleted != total {
		t.Errorf("deleted = %d, want %d", deleted, total)
	}
	for i := range total {
		sha := fmt.Sprintf("batch-junk-%d", i)
		if _, err := db.SampleBySHA256(ctx, sha); !errors.Is(err, ErrNotFound) {
			t.Errorf("%s should be gone, got err=%v", sha, err)
		}
		reports, err := db.ReportsBySHA256(ctx, sha)
		if err != nil {
			t.Fatal(err)
		}
		if len(reports) != 0 {
			t.Errorf("%s reports should be gone, got %d", sha, len(reports))
		}
	}
	if _, err := db.SampleBySHA256(ctx, "keep"); err != nil {
		t.Errorf("keep should still exist, got err=%v", err)
	}

	// Re-running against an already-clean stage must not error or loop
	// forever — the first batch query returns zero rows and the loop exits.
	if n, err := db.ApplyCleanup(ctx, stage); err != nil || n != 0 {
		t.Errorf("re-apply on a clean stage = (%d, %v), want (0, nil)", n, err)
	}
}

func TestSanitizeJSONB(t *testing.T) {
	tests := []struct {
		name string
		in   string
		want string
	}{
		{"empty", "", ""},
		{"no escapes", `{"a":"b"}`, `{"a":"b"}`},
		// Single-backslash \u0000 is encoded to the sentinel (restored on read).
		{"null escape", `{"v":"\u0000"}`, `{"v":"` + nulSentinel + `"}`},
		// Double-backslash \\u0000 is a literal backslash + "u0000" — must be preserved.
		{"escaped backslash u0000", `{"v":"\\u0000"}`, `{"v":"\\u0000"}`},
		// \x86 (single backslash) → \u0086
		{"hex escape", `{"v":"\x86"}`, `{"v":"\u0086"}`},
		// \\x86 is a literal backslash + "x86" — must be preserved.
		{"escaped backslash x86", `{"v":"\\x86"}`, `{"v":"\\x86"}`},
		// Mixed: real null inside a range pattern, encoded to the sentinel.
		{"null in range", `{"v":"/[^\u0000-\u001f]/"}`, `{"v":"/[^` + nulSentinel + `-\u001f]/"}`},
		// \\u0000 inside a JS regex pattern should be left alone.
		{"escaped null in range", `{"v":"/[^\\u0000-\\u001f]/"}`, `{"v":"/[^\\u0000-\\u001f]/"}`},
		// \x00 is a NUL, encoded to the sentinel.
		{"hex null", `{"v":"\x00"}`, `{"v":"` + nulSentinel + `"}`},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := string(sanitizeJSONB([]byte(tt.in)))
			if got != tt.want {
				t.Errorf("sanitizeJSONB(%q)\n  got  %q\n  want %q", tt.in, got, tt.want)
			}
		})
	}
}

// TestNULCodecRoundTrip proves restoreNULs inverts sanitizeJSONB's NUL encoding
// for input free of pre-existing sentinels: a NUL written to the DB reads back
// unchanged (\x00 normalizes to \u0000 on the way in).
func TestNULCodecRoundTrip(t *testing.T) {
	cases := []string{
		`{"v":"\u0000"}`,
		`{"d":"a\u0000b\u0000c"}`,
		`{"x":"\x00"}`,
		`{"plain":"no nulls here"}`,
		`{"nested":{"s":"x\u0000y"}}`,
	}
	for _, in := range cases {
		enc := sanitizeJSONB([]byte(in))
		if bytes.Contains(enc, []byte(`\u0000`)) {
			t.Errorf("encoded form still holds a raw NUL escape: %s", enc)
		}
		got := string(restoreNULs(enc))
		want := strings.ReplaceAll(in, `\x00`, `\u0000`)
		if got != want {
			t.Errorf("round-trip\n in   %q\n enc  %q\n got  %q\n want %q", in, enc, got, want)
		}
	}
}

// TestSanitizeJSONBIdempotent confirms encoding already-encoded data is a no-op,
// so read-modify-write backfill paths never double-encode a sentinel.
func TestSanitizeJSONBIdempotent(t *testing.T) {
	for _, in := range []string{`{"v":"\u0000"}`, `{"v":"\x00\x86"}`, `{"v":"plain"}`} {
		once := sanitizeJSONB([]byte(in))
		twice := sanitizeJSONB(once)
		if !bytes.Equal(once, twice) {
			t.Errorf("not idempotent for %q:\n once  %q\n twice %q", in, once, twice)
		}
	}
}

// TestRestoreJSONBSampleColumns checks a Sample's JSON columns come back with
// NULs restored at the read boundary.
func TestRestoreJSONBSampleColumns(t *testing.T) {
	s := &Sample{
		CleaveResult: sanitizeJSONB([]byte(`{"d":"a\u0000b"}`)),
		LitmusResult: sanitizeJSONB([]byte(`{"m":"\u0000"}`)),
	}
	s.restoreJSONB()
	if string(s.CleaveResult) != `{"d":"a\u0000b"}` {
		t.Errorf("CleaveResult = %s", s.CleaveResult)
	}
	if string(s.LitmusResult) != `{"m":"\u0000"}` {
		t.Errorf("LitmusResult = %s", s.LitmusResult)
	}
}

func TestScrubNULs(t *testing.T) {
	s := &Sample{
		SHA256:   "abc",
		Path:     "pkg/bin\x00.exe",
		Filename: "evil\x00.sh",
		Package:  "left\x00pad",
		Version:  "1.0\x000",
		Elements: "C\x00H4",
		Label:    "bad", // no NUL, must be untouched
	}
	s.scrubNULs()

	for field, got := range map[string]string{
		"Path": s.Path, "Filename": s.Filename, "Package": s.Package,
		"Version": s.Version, "Elements": s.Elements,
	} {
		if strings.IndexByte(got, 0) >= 0 {
			t.Errorf("scrubNULs left a NUL in %s: %q", field, got)
		}
	}
	if s.Path != "pkg/bin.exe" {
		t.Errorf("Path = %q, want %q", s.Path, "pkg/bin.exe")
	}
	if s.Label != "bad" {
		t.Errorf("Label = %q, want unchanged %q", s.Label, "bad")
	}
}

// ageLocation backdates a sample's standalone location so reconciliation treats
// it as not-seen-this-walk, simulating a file that has moved away.
func loc(sha, path string) SampleLocationKey { return SampleLocationKey{SHA256: sha, Path: path} }

// stageWalk resets the staging table and records the given files as present in
// the current walk, exactly as runDirPipeline streams them in during a real
// walk. Files not listed are, by definition, not present this walk.
func stageWalk(t *testing.T, ctx context.Context, db *DB, present ...SampleLocationKey) {
	t.Helper()
	if err := db.StartWalkStaging(ctx); err != nil {
		t.Fatalf("StartWalkStaging: %v", err)
	}
	if err := db.StageLocations(ctx, present); err != nil {
		t.Fatalf("StageLocations: %v", err)
	}
}

func skipOf(t *testing.T, ctx context.Context, db *DB, sha string) string {
	t.Helper()
	s, err := db.SampleBySHA256(ctx, sha)
	if err != nil {
		t.Fatalf("SampleBySHA256(%s): %v", sha, err)
	}
	return s.Skip
}

func labelOf(t *testing.T, ctx context.Context, db *DB, sha string) string {
	t.Helper()
	s, err := db.SampleBySHA256(ctx, sha)
	if err != nil {
		t.Fatalf("SampleBySHA256(%s): %v", sha, err)
	}
	return s.Label
}

// TestReconcilePoolsRelabel covers the pool-placement label transitions:
// demotion (bad→good), promotion (good→bad), the both-pools conflict, and the
// marker exemption.
func TestReconcilePoolsRelabel(t *testing.T) {
	db := openTestDB(t)
	ctx := context.Background()

	// dem: stored bad, but its only copy is now in good/ → demote to good.
	mustInsert(t, ctx, db, &Sample{SHA256: "dem", Path: "good/dem.bin", Label: "bad", LabelSource: "local"})
	// pro: stored good, but now in bad/ → promote to bad.
	mustInsert(t, ctx, db, &Sample{SHA256: "pro", Path: "bad/pro.bin", Label: "good", LabelSource: "local"})
	// conf: present in both good/ and bad/ at once → bad + skip='conflict'.
	mustInsert(t, ctx, db, &Sample{SHA256: "conf", Path: "good/conf.bin", Label: "good", LabelSource: "local"})
	mustInsert(t, ctx, db, &Sample{SHA256: "conf", Path: "bad/conf.bin", Label: "good", LabelSource: "local"})
	// mark: a marker label must never be overridden by pool placement.
	mustInsert(t, ctx, db, &Sample{SHA256: "mark", Path: "bad/mark.bin", Label: "good", LabelSource: "marker", Skip: "misclassified"})

	stageWalk(t, ctx, db,
		loc("dem", "good/dem.bin"),
		loc("pro", "bad/pro.bin"),
		loc("conf", "good/conf.bin"), loc("conf", "bad/conf.bin"),
		loc("mark", "bad/mark.bin"),
	)
	if _, err := db.ReconcilePools(ctx, func(p string) string { return p }, true); err != nil {
		t.Fatalf("ReconcilePools: %v", err)
	}

	if got := labelOf(t, ctx, db, "dem"); got != "good" {
		t.Errorf("dem label = %q, want good (demoted)", got)
	}
	if got := labelOf(t, ctx, db, "pro"); got != "bad" {
		t.Errorf("pro label = %q, want bad (promoted)", got)
	}
	if got := labelOf(t, ctx, db, "conf"); got != "bad" {
		t.Errorf("conf label = %q, want bad (conflict)", got)
	}
	if got := skipOf(t, ctx, db, "conf"); got != "conflict" {
		t.Errorf("conf skip = %q, want conflict", got)
	}
	if got := labelOf(t, ctx, db, "mark"); got != "good" {
		t.Errorf("marker sample relabeled to %q, want good (untouched)", got)
	}

	// dem, pro, conf each produced one audit row; mark did not change.
	var events int
	if err := db.lite.QueryRowContext(ctx,
		`SELECT count(*) FROM label_events WHERE sha256 IN ('dem','pro','conf','mark')`).Scan(&events); err != nil {
		t.Fatal(err)
	}
	if events != 3 {
		t.Errorf("label_events = %d, want 3", events)
	}
}

// TestReconcilePoolsMissing covers marking standalone files missing (including
// already-analyzed ones) vs unsupported.
func TestReconcilePoolsMissing(t *testing.T) {
	db := openTestDB(t)
	ctx := context.Background()

	realFile := filepath.Join(t.TempDir(), "present.bin")
	if err := os.WriteFile(realFile, []byte("MZ...."), 0o644); err != nil {
		t.Fatal(err)
	}
	disk := func(p string) string {
		if p == "bad/present.bin" {
			return realFile
		}
		return filepath.Join(t.TempDir(), "nope", p) // never exists
	}

	// seen: present this walk. gone: analyzed then moved away. unsup: on disk
	// but not enumerated this walk.
	mustInsert(t, ctx, db, &Sample{SHA256: "seen", Path: "bad/seen.bin", Label: "bad"})
	mustInsert(t, ctx, db, &Sample{SHA256: "gone", Path: "bad/gone.bin", Label: "bad"})
	mustAnalyze(t, ctx, db, "gone", 5)
	mustInsert(t, ctx, db, &Sample{SHA256: "unsup", Path: "bad/present.bin", Label: "bad"})

	stageWalk(t, ctx, db, loc("seen", "bad/seen.bin"))
	st, err := db.ReconcilePools(ctx, disk, true)
	if err != nil {
		t.Fatalf("ReconcilePools: %v", err)
	}
	if st.MarkedMissing != 1 || st.MarkedUnsupported != 1 {
		t.Errorf("stats missing=%d unsupported=%d, want 1/1", st.MarkedMissing, st.MarkedUnsupported)
	}
	if got := skipOf(t, ctx, db, "seen"); got != "" {
		t.Errorf("seen skip = %q, want empty", got)
	}
	if got := skipOf(t, ctx, db, "gone"); got != "missing" {
		t.Errorf("gone skip = %q, want missing (analyzed file moved away)", got)
	}
	if got := skipOf(t, ctx, db, "unsup"); got != "unsupported" {
		t.Errorf("unsup skip = %q, want unsupported", got)
	}
}

// TestReconcilePoolsDatasetIncomplete verifies the --dataset-incomplete contract
// (markMissing=false): relabelling still applies to files whose standalone copy
// is present in a local pool this walk, but locally-absent files are never marked
// skip='missing'/'unsupported' — they stay trainable.
func TestReconcilePoolsDatasetIncomplete(t *testing.T) {
	db := openTestDB(t)
	ctx := context.Background()

	disk := func(p string) string {
		return filepath.Join(t.TempDir(), "nope", p) // never exists
	}

	// moved: standalone copy now in good/ this walk → relabel bad→good must apply.
	// gone: not seen this walk and absent on disk → must stay trainable, not missing.
	mustInsert(t, ctx, db, &Sample{SHA256: "moved", Path: "bad/moved.bin", Label: "bad"})
	mustInsert(t, ctx, db, &Sample{SHA256: "gone", Path: "bad/gone.bin", Label: "bad"})

	stageWalk(t, ctx, db, loc("moved", "good/moved.bin"))
	st, err := db.ReconcilePools(ctx, disk, false)
	if err != nil {
		t.Fatalf("ReconcilePools: %v", err)
	}
	if st.MarkedMissing != 0 || st.MarkedUnsupported != 0 {
		t.Errorf("stats missing=%d unsupported=%d, want 0/0 (dataset-incomplete)",
			st.MarkedMissing, st.MarkedUnsupported)
	}
	if got := labelOf(t, ctx, db, "moved"); got != "good" {
		t.Errorf("moved label = %q, want good (relabel must still work)", got)
	}
	if got := skipOf(t, ctx, db, "gone"); got != "" {
		t.Errorf("gone skip = %q, want empty (locally-absent file must stay trainable)", got)
	}
}

// TestReconcilePoolsDatasetIncompleteEmptyTree models the outage-node startup:
// /data/samples is empty (walk_staging has no present files) while the
// authoritative DB is fully populated. With markMissing=false the reconcile must
// be a complete no-op — nothing marked missing/unsupported, nothing relabeled,
// and an already-missing row is not revived — so an empty local tree can never
// mass-mark the authoritative rows missing (and replicate that loss).
func TestReconcilePoolsDatasetIncompleteEmptyTree(t *testing.T) {
	db := openTestDB(t)
	ctx := context.Background()

	mustInsert(t, ctx, db, &Sample{SHA256: "a", Path: "bad/a.bin", Label: "bad"})
	mustInsert(t, ctx, db, &Sample{SHA256: "b", Path: "good/b.bin", Label: "good"})
	// An already-missing row must not be revived by an empty walk either.
	mustInsert(t, ctx, db, &Sample{SHA256: "c", Path: "bad/c.bin", Label: "bad"})
	if err := db.SetSkip(ctx, "c", "missing"); err != nil {
		t.Fatalf("SetSkip: %v", err)
	}

	stageWalk(t, ctx, db) // empty present-set: nothing on local disk
	disk := func(p string) string { return filepath.Join(t.TempDir(), "nope", p) }
	st, err := db.ReconcilePools(ctx, disk, false)
	if err != nil {
		t.Fatalf("ReconcilePools: %v", err)
	}
	if st.Relabeled != 0 || st.MarkedMissing != 0 || st.MarkedUnsupported != 0 || st.CascadedMissing != 0 {
		t.Errorf("stats = %+v, want all zero (empty tree must not touch authoritative rows)", st)
	}
	if got := skipOf(t, ctx, db, "a"); got != "" {
		t.Errorf("a skip = %q, want empty", got)
	}
	if got := skipOf(t, ctx, db, "c"); got != "missing" {
		t.Errorf("c skip = %q, want missing (unchanged, not revived)", got)
	}
}

// TestReconcilePoolsCascade covers missing cascading to archive members, the
// shared-archive veto, and revival when an archive reappears.
func TestReconcilePoolsCascade(t *testing.T) {
	db := openTestDB(t)
	ctx := context.Background()
	gone := func(p string) string { return filepath.Join(t.TempDir(), "nope", p) }

	// Good archive G and bad archive P.
	mustInsert(t, ctx, db, &Sample{SHA256: "G", Path: "good/pkg.tgz", Label: "good"})
	mustInsert(t, ctx, db, &Sample{SHA256: "P", Path: "bad/arch.tgz", Label: "bad"})

	// C1 lives only inside P. C2 lives inside P AND inside live G (shared file).
	mustInsert(t, ctx, db, &Sample{SHA256: "C1", Parent: "P", Path: "bad/arch.tgz!!evil.js", Label: "bad"})
	mustInsert(t, ctx, db, &Sample{SHA256: "C2", Parent: "P", Path: "bad/arch.tgz!!shared.js", Label: "bad"})
	// Second containment edge for C2: also a member of live archive G.
	mustInsert(t, ctx, db, &Sample{SHA256: "C2", Parent: "G", Path: "good/pkg.tgz!!shared.js", Label: "good"})

	// P moved away; only G is present this walk.
	stageWalk(t, ctx, db, loc("G", "good/pkg.tgz"))
	st, err := db.ReconcilePools(ctx, gone, true)
	if err != nil {
		t.Fatalf("ReconcilePools: %v", err)
	}
	if got := skipOf(t, ctx, db, "P"); got != "missing" {
		t.Errorf("P skip = %q, want missing", got)
	}
	if got := skipOf(t, ctx, db, "C1"); got != "missing" {
		t.Errorf("C1 skip = %q, want missing (orphaned member)", got)
	}
	if got := skipOf(t, ctx, db, "C2"); got != "" {
		t.Errorf("C2 skip = %q, want empty (shared with live archive — veto)", got)
	}
	if st.CascadedMissing != 1 {
		t.Errorf("CascadedMissing = %d, want 1", st.CascadedMissing)
	}

	// P reappears: both archives present this walk → C1 revives.
	stageWalk(t, ctx, db, loc("G", "good/pkg.tgz"), loc("P", "bad/arch.tgz"))
	st2, err := db.ReconcilePools(ctx, func(p string) string { return p }, true)
	if err != nil {
		t.Fatalf("ReconcilePools revive: %v", err)
	}
	if got := skipOf(t, ctx, db, "C1"); got != "" {
		t.Errorf("C1 skip = %q after revival, want empty", got)
	}
	if st2.Revived != 1 {
		t.Errorf("Revived = %d, want 1", st2.Revived)
	}
}

// TestReconcilePoolsMovedToNewPath covers a file moved within a pool (or
// between pools) to a path with no prior location row: staging the new path
// relabels the sample rather than marking it missing.
func TestReconcilePoolsMovedToNewPath(t *testing.T) {
	db := openTestDB(t)
	ctx := context.Background()

	mustInsert(t, ctx, db, &Sample{SHA256: "mv", Path: "good/x.bin", Label: "good", LabelSource: "local"})

	// Seen this walk only at a new bad/ path.
	stageWalk(t, ctx, db, loc("mv", "bad/x.bin"))
	st, err := db.ReconcilePools(ctx, func(p string) string { return p }, true)
	if err != nil {
		t.Fatalf("ReconcilePools: %v", err)
	}
	if st.ObservedLocations != 1 {
		t.Fatalf("ObservedLocations = %d, want 1", st.ObservedLocations)
	}
	if got := labelOf(t, ctx, db, "mv"); got != "bad" {
		t.Errorf("mv label = %q, want bad (relabeled after good→bad move)", got)
	}
	if got := skipOf(t, ctx, db, "mv"); got != "" {
		t.Errorf("mv skip = %q, want empty (must not be marked missing)", got)
	}
	locs, err := db.TopLevelLocationsForSHA(ctx, "mv")
	if err != nil {
		t.Fatal(err)
	}
	var found bool
	for _, location := range locs {
		found = found || location.Path == "bad/x.bin"
	}
	if !found {
		t.Fatalf("new path not learned from staging: %+v", locs)
	}
}

func TestReconcilePoolsFifteenPercentAggregateGuard(t *testing.T) {
	db := openTestDB(t)
	ctx := context.Background()
	for i := range 100 {
		sha := fmt.Sprintf("guard-%03d", i)
		mustInsert(t, ctx, db, &Sample{SHA256: sha, Path: fmt.Sprintf("pending/%03d.bin", i), Label: "unknown"})
		if i < 84 {
			if err := db.StageLocations(ctx, []SampleLocationKey{{SHA256: sha, Path: fmt.Sprintf("pending/%03d.bin", i)}}); err != nil {
				t.Fatal(err)
			}
		}
	}
	if _, err := db.ReconcilePools(ctx, func(string) string { return filepath.Join(t.TempDir(), "gone") }, true); err == nil || !strings.Contains(err.Error(), ">15%") {
		t.Fatalf("ReconcilePools error = %v, want 15%% guard", err)
	}
	if got := skipOf(t, ctx, db, "guard-099"); got != "" {
		t.Fatalf("guarded sample skip = %q, want unchanged", got)
	}
}

func TestReconcilePoolsFifteenPercentPerPoolGuard(t *testing.T) {
	db := openTestDB(t)
	ctx := context.Background()
	for i := range 1000 {
		root := "pending"
		seen := true
		if i < 100 {
			root = "incoming"
			seen = i < 84
		}
		sha := fmt.Sprintf("pool-guard-%04d", i)
		path := fmt.Sprintf("%s/%04d.bin", root, i)
		mustInsert(t, ctx, db, &Sample{SHA256: sha, Path: path, Label: "unknown"})
		if seen {
			if err := db.StageLocations(ctx, []SampleLocationKey{{SHA256: sha, Path: path}}); err != nil {
				t.Fatal(err)
			}
		}
	}
	_, err := db.ReconcilePools(ctx, func(string) string { return filepath.Join(t.TempDir(), "gone") }, true)
	if err == nil || !strings.Contains(err.Error(), `"incoming" pool`) {
		t.Fatalf("ReconcilePools error = %v, want per-incoming-pool guard", err)
	}
}

// TestReconcilePoolsFifteenPercentRelabelGuard covers the other half of a bad
// walk: not files that vanished, but files seen in the wrong pool. A mount
// shadowing bad/ with good/ would relabel the whole corpus benign in a single
// pass — worse than any amount of missing-marking — so it trips the same
// breaker and the batch is rolled back whole.
func TestReconcilePoolsFifteenPercentRelabelGuard(t *testing.T) {
	db := openTestDB(t)
	ctx := context.Background()
	for i := range 1000 {
		sha := fmt.Sprintf("relabel-guard-%04d", i)
		// Recorded as bad/, seen in good/ this walk: a pool-wide flip, far past 15%.
		mustInsert(t, ctx, db, &Sample{SHA256: sha, Path: fmt.Sprintf("bad/%04d.bin", i), Label: "bad"})
		if err := db.StageLocations(ctx, []SampleLocationKey{
			{SHA256: sha, Path: fmt.Sprintf("good/%04d.bin", i)},
		}); err != nil {
			t.Fatal(err)
		}
	}
	_, err := db.ReconcilePools(ctx, func(p string) string { return p }, true)
	if err == nil || !strings.Contains(err.Error(), "different label") {
		t.Fatalf("ReconcilePools error = %v, want relabel guard", err)
	}
	if got := labelOf(t, ctx, db, "relabel-guard-0000"); got != "bad" {
		t.Fatalf("guarded sample label = %q, want bad (batch rolled back)", got)
	}
}

// TestReconcilePoolsRelabelGuardAllowsRevival checks the guard does not block a
// revive. A sample marked missing sits outside the active population the limit
// is a share of, so counting revives would make the limit unmeetable exactly
// when storage came back — the case the reconcile exists to handle.
func TestReconcilePoolsRelabelGuardAllowsRevival(t *testing.T) {
	db := openTestDB(t)
	ctx := context.Background()
	for i := range 200 {
		sha := fmt.Sprintf("revive-%04d", i)
		path := fmt.Sprintf("bad/%04d.bin", i)
		mustInsert(t, ctx, db, &Sample{SHA256: sha, Path: path, Label: "bad", Skip: "missing"})
		if err := db.StageLocations(ctx, []SampleLocationKey{{SHA256: sha, Path: path}}); err != nil {
			t.Fatal(err)
		}
	}
	if _, err := db.ReconcilePools(ctx, func(p string) string { return p }, true); err != nil {
		t.Fatalf("ReconcilePools() = %v, want revival to pass the guard", err)
	}
	if got := skipOf(t, ctx, db, "revive-0000"); got != "" {
		t.Fatalf("revived sample skip = %q, want cleared", got)
	}
}

// TestReconcilePoolsBadUnknownGood walks a sample through bad/ → unknown/ →
// good/. unknown/ asserts no pool, so the label is retained there; the final
// good/ placement demotes it.
func TestReconcilePoolsBadUnknownGood(t *testing.T) {
	db := openTestDB(t)
	ctx := context.Background()
	keep := func(p string) string { return p }

	mustInsert(t, ctx, db, &Sample{SHA256: "t", Path: "bad/t.bin", Label: "bad", LabelSource: "local"})

	// → unknown/: label retained (unknown/ does not downgrade), still present.
	stageWalk(t, ctx, db, loc("t", "unknown/t.bin"))
	if _, err := db.ReconcilePools(ctx, keep, true); err != nil {
		t.Fatal(err)
	}
	if got := labelOf(t, ctx, db, "t"); got != "bad" {
		t.Errorf("in unknown/ label = %q, want bad (unknown does not downgrade)", got)
	}
	if got := skipOf(t, ctx, db, "t"); got != "" {
		t.Errorf("in unknown/ skip = %q, want empty (present)", got)
	}

	// → good/: now demoted to good.
	stageWalk(t, ctx, db, loc("t", "good/t.bin"))
	if _, err := db.ReconcilePools(ctx, keep, true); err != nil {
		t.Fatal(err)
	}
	if got := labelOf(t, ctx, db, "t"); got != "good" {
		t.Errorf("after move to good/ label = %q, want good", got)
	}
}

func TestReconcilePoolsIncomingDoesNotDeriveNestedCategoryLabels(t *testing.T) {
	db := openTestDB(t)
	ctx := context.Background()

	mustInsert(t, ctx, db, &Sample{
		SHA256: "hot", Path: "incoming/bad/foraged/hot.bin", Label: "bad", LabelSource: "forager",
	})
	mustInsert(t, ctx, db, &Sample{
		SHA256: "feed", Path: "incoming/sighted/foraged/feed.bin", Label: "unknown", LabelSource: "forager",
	})
	stageWalk(t, ctx, db,
		loc("hot", "incoming/bad/foraged/hot.bin"),
		loc("feed", "incoming/sighted/foraged/feed.bin"),
	)
	if _, err := db.ReconcilePools(ctx, func(p string) string { return p }, true); err != nil {
		t.Fatal(err)
	}
	if got := labelOf(t, ctx, db, "hot"); got != "bad" {
		t.Errorf("incoming evidence label = %q, want bad", got)
	}
	if got := labelOf(t, ctx, db, "feed"); got != "unknown" {
		t.Errorf("incoming/sighted label = %q, want unknown", got)
	}
}

// TestReconcilePoolsRemovedThenReadded covers removal from bad/ (→ missing,
// label retained) followed by re-adding the same content to bad/ at a different
// path (→ revived, skip cleared).
func TestReconcilePoolsRemovedThenReadded(t *testing.T) {
	db := openTestDB(t)
	ctx := context.Background()

	mustInsert(t, ctx, db, &Sample{SHA256: "rb", Path: "bad/a.bin", Label: "bad", LabelSource: "local"})
	mustAnalyze(t, ctx, db, "rb", 5)

	// Removed from bad/ entirely (nothing present this walk) → missing.
	gone := func(p string) string { return filepath.Join(t.TempDir(), "nope", p) }
	stageWalk(t, ctx, db)
	if _, err := db.ReconcilePools(ctx, gone, true); err != nil {
		t.Fatal(err)
	}
	if got := skipOf(t, ctx, db, "rb"); got != "missing" {
		t.Fatalf("after removal skip = %q, want missing", got)
	}
	if got := labelOf(t, ctx, db, "rb"); got != "bad" {
		t.Errorf("after removal label = %q, want bad (retained)", got)
	}

	// Re-added to bad/ at a different path → revived (skip cleared).
	stageWalk(t, ctx, db, loc("rb", "bad/b.bin"))
	if _, err := db.ReconcilePools(ctx, func(p string) string { return p }, true); err != nil {
		t.Fatal(err)
	}
	if got := skipOf(t, ctx, db, "rb"); got != "" {
		t.Errorf("after re-add skip = %q, want empty (revived)", got)
	}
	if got := labelOf(t, ctx, db, "rb"); got != "bad" {
		t.Errorf("after re-add label = %q, want bad", got)
	}
}

func TestUnanalyzedCandidatesSkipsMarkedSamples(t *testing.T) {
	db := openTestDB(t)
	ctx := context.Background()

	// Insert 3 unanalyzed samples: one normal, two with skip set.
	mustInsert(t, ctx, db, &Sample{SHA256: "claim1", Path: "/data/a.exe", Label: "bad"})
	mustInsert(t, ctx, db, &Sample{SHA256: "claim2", Path: "/data/b.exe", Label: "bad", Skip: "unsupported"})
	mustInsert(t, ctx, db, &Sample{SHA256: "claim3", Path: "/data/c.exe", Label: "bad", Skip: "missing"})

	jobs, err := db.UnanalyzedCandidates(ctx, time.Now(), 10)
	if err != nil {
		t.Fatal(err)
	}
	if len(jobs) != 1 {
		t.Fatalf("got %d jobs, want 1", len(jobs))
	}
	if jobs[0].SHA256 != "claim1" {
		t.Errorf("got sha256 = %q, want 'claim1'", jobs[0].SHA256)
	}
}

// TestUnanalyzedCandidatesRetriesOldErrorsAfterRestart verifies that the
// hopperStart cutoff lets a freshly restarted process pick up samples whose
// last_error_at predates this run.
func TestUnanalyzedCandidatesRetriesOldErrorsAfterRestart(t *testing.T) {
	db := openTestDB(t)
	ctx := context.Background()

	mustInsert(t, ctx, db, &Sample{SHA256: "err1", Path: "/data/a.exe", Label: "bad"})
	if err := db.SetNote(ctx, "err1", "worker failed"); err != nil {
		t.Fatal(err)
	}

	currentRunStart := time.Now().Add(-time.Hour)
	jobs, err := db.UnanalyzedCandidates(ctx, currentRunStart, 10)
	if err != nil {
		t.Fatal(err)
	}
	if len(jobs) != 0 {
		t.Fatalf("current-run error returned as candidate: got %+v, want none", jobs)
	}

	restartAfterError := time.Now().Add(time.Hour)
	jobs, err = db.UnanalyzedCandidates(ctx, restartAfterError, 10)
	if err != nil {
		t.Fatal(err)
	}
	if len(jobs) != 1 || jobs[0].SHA256 != "err1" {
		t.Fatalf("old error after restart: got %+v, want err1", jobs)
	}
}

func TestUnanalyzedCandidatesUsesRandomPivot(t *testing.T) {
	db := openTestDB(t)
	ctx := context.Background()

	lowest := strings.Repeat("0", 64)
	mustInsert(t, ctx, db, &Sample{SHA256: lowest, Path: "/data/lowest.exe", Label: "bad"})
	for i := 1; i < 256; i++ {
		sha := fmt.Sprintf("%02x%s", i, strings.Repeat("0", 62))
		mustInsert(t, ctx, db, &Sample{SHA256: sha, Path: "/data/" + sha, Label: "bad"})
	}

	sawNonLowestFirst := false
	for range 20 {
		jobs, err := db.UnanalyzedCandidates(ctx, time.Now(), 5)
		if err != nil {
			t.Fatal(err)
		}
		if len(jobs) != 5 {
			t.Fatalf("got %d jobs, want 5", len(jobs))
		}
		if jobs[0].SHA256 != lowest {
			sawNonLowestFirst = true
			break
		}
	}
	if !sawNonLowestFirst {
		t.Fatal("random candidate pivot kept returning the lowest SHA first")
	}
}

// TestRequestRescanQueuesTier0 covers the happy path: an analyzed sample
// becomes eligible for rescan after the cooldown elapses, RequestRescan
// clears its analysis fields + stamps forced_rescan_at, and the next
// ForcedRescanCandidates call returns it.
func TestRequestRescanQueuesTier0(t *testing.T) {
	db := openTestDB(t)
	ctx := context.Background()

	const sha = "aaaaaa00000000000000000000000000000000000000000000000000000000aa"
	mustInsert(t, ctx, db, &Sample{SHA256: sha, Source: "test", Label: "good", LabelSource: "test"})
	mustAnalyze(t, ctx, db, sha, 1)

	// Backdate analyzed_at so the cooldown predicate accepts the request.
	if _, err := db.lite.ExecContext(ctx,
		`UPDATE samples SET analyzed_at = ? WHERE sha256 = ?`,
		time.Now().Add(-time.Hour).UTC().Format(time.RFC3339Nano), sha); err != nil {
		t.Fatalf("backdate: %v", err)
	}

	if err := db.RequestRescan(ctx, sha, 15*time.Minute); err != nil {
		t.Fatalf("RequestRescan: %v", err)
	}

	jobs, err := db.ForcedRescanCandidates(ctx, time.Now(), 10)
	if err != nil {
		t.Fatalf("ForcedRescanCandidates: %v", err)
	}
	if len(jobs) != 1 || jobs[0].SHA256 != sha {
		t.Fatalf("ForcedRescanCandidates = %+v, want one job for %s", jobs, sha)
	}
}

// TestRequestRescanHonorsCooldown covers the defense-in-depth path: a
// sample analyzed within the cooldown window is rejected with
// ErrRescanNotEligible even if the caller asks.
func TestRequestRescanHonorsCooldown(t *testing.T) {
	db := openTestDB(t)
	ctx := context.Background()

	const sha = "bbbbbb00000000000000000000000000000000000000000000000000000000bb"
	mustInsert(t, ctx, db, &Sample{SHA256: sha, Source: "test", Label: "good", LabelSource: "test"})
	mustAnalyze(t, ctx, db, sha, 1)

	if err := db.RequestRescan(ctx, sha, 15*time.Minute); !errors.Is(err, ErrRescanNotEligible) {
		t.Fatalf("RequestRescan within cooldown: err = %v, want ErrRescanNotEligible", err)
	}
}

// TestRequestRescanRejectsArchiveChild covers the parent-non-empty gate:
// an archive member is never eligible for rescan (the parent archive
// owns its analysis).
func TestRequestRescanRejectsArchiveChild(t *testing.T) {
	db := openTestDB(t)
	ctx := context.Background()

	const parent = "cccccc00000000000000000000000000000000000000000000000000000000cc"
	const child = "dddddd00000000000000000000000000000000000000000000000000000000dd"
	mustInsert(t, ctx, db, &Sample{SHA256: parent, Source: "test", Label: "bad", LabelSource: "test"})
	mustInsert(t, ctx, db, &Sample{SHA256: child, Source: "test", Label: "bad", LabelSource: "test", Parent: parent})

	if err := db.RequestRescan(ctx, child, 15*time.Minute); !errors.Is(err, ErrRescanNotEligible) {
		t.Fatalf("RequestRescan on archive child: err = %v, want ErrRescanNotEligible", err)
	}
}

// TestUpdateCleaveResultClearsForcedRescan covers the queue-drain path:
// when a worker submits fresh analysis for a forced-rescan sample, the
// forced_rescan_at marker clears so the row drops out of Tier 0.
func TestUpdateCleaveResultClearsForcedRescan(t *testing.T) {
	db := openTestDB(t)
	ctx := context.Background()

	const sha = "eeeeee00000000000000000000000000000000000000000000000000000000ee"
	mustInsert(t, ctx, db, &Sample{SHA256: sha, Source: "test", Label: "good", LabelSource: "test"})
	mustAnalyze(t, ctx, db, sha, 1)
	if _, err := db.lite.ExecContext(ctx,
		`UPDATE samples SET analyzed_at = ? WHERE sha256 = ?`,
		time.Now().Add(-time.Hour).UTC().Format(time.RFC3339Nano), sha); err != nil {
		t.Fatalf("backdate: %v", err)
	}
	if err := db.RequestRescan(ctx, sha, 15*time.Minute); err != nil {
		t.Fatalf("RequestRescan: %v", err)
	}

	mustAnalyze(t, ctx, db, sha, 2) // simulates a worker finishing the rescan

	jobs, err := db.ForcedRescanCandidates(ctx, time.Now(), 10)
	if err != nil {
		t.Fatalf("ForcedRescanCandidates: %v", err)
	}
	if len(jobs) != 0 {
		t.Fatalf("ForcedRescanCandidates after re-analysis = %+v, want empty", jobs)
	}
}

// TestForcedRescanCandidatesOrder verifies FIFO ordering by forced_rescan_at.
func TestForcedRescanCandidatesOrder(t *testing.T) {
	db := openTestDB(t)
	ctx := context.Background()

	shas := []string{
		"aabbcc0000000000000000000000000000000000000000000000000000000010",
		"aabbcc0000000000000000000000000000000000000000000000000000000020",
		"aabbcc0000000000000000000000000000000000000000000000000000000030",
	}
	for i, sha := range shas {
		mustInsert(t, ctx, db, &Sample{SHA256: sha, Source: "test", Label: "good", LabelSource: "test"})
		mustAnalyze(t, ctx, db, sha, 1)
		// Stamp the queue fields explicitly so the test isn't dependent on
		// RequestRescan's now()-based ordering (which is rate-limited by the
		// SQLite clock resolution).
		ts := time.Now().Add(time.Duration(i) * time.Second).Format(time.RFC3339Nano)
		if _, err := db.lite.ExecContext(ctx,
			`UPDATE samples SET cleave_result = NULL, rescan_priority = 2, rescan_requested_at = ? WHERE sha256 = ?`,
			ts, sha); err != nil {
			t.Fatalf("stamp: %v", err)
		}
	}

	jobs, err := db.ForcedRescanCandidates(ctx, time.Now(), 10)
	if err != nil {
		t.Fatalf("ForcedRescanCandidates: %v", err)
	}
	if len(jobs) != len(shas) {
		t.Fatalf("got %d jobs, want %d", len(jobs), len(shas))
	}
	for i, j := range jobs {
		if j.SHA256 != shas[i] {
			t.Fatalf("jobs[%d] = %s, want %s (FIFO order)", i, j.SHA256, shas[i])
		}
	}
}

// TestForcedRescanCandidatesHoldsBackErrors covers the Tier 0 error-backoff
// guard. Tier 0 drains before every other tier, so a sample that fails analysis
// would otherwise sit at the head of the FIFO and be re-offered on every poll,
// starving the forced rescans queued behind it. A row that errored during this
// run is withheld; a restart (a hopperStart later than the error) offers it
// again, matching Tier 1's contract.
//
// The guard deliberately keys on last_error_at rather than attempts: attempts
// is never reset, so an attempts ceiling here would make a sample rescanned
// MaxClaimAttempts times over its life permanently unrescannable.
func TestForcedRescanCandidatesHoldsBackErrors(t *testing.T) {
	db := openTestDB(t)
	ctx := context.Background()

	const sha = "bbccdd0000000000000000000000000000000000000000000000000000000011"
	mustInsert(t, ctx, db, &Sample{SHA256: sha, Source: "test", Label: "good", LabelSource: "test"})
	mustAnalyze(t, ctx, db, sha, 1)
	if _, err := db.lite.ExecContext(ctx,
		`UPDATE samples SET analyzed_at = ? WHERE sha256 = ?`,
		time.Now().Add(-time.Hour).UTC().Format(time.RFC3339Nano), sha); err != nil {
		t.Fatalf("backdate: %v", err)
	}
	if err := db.RequestRescan(ctx, sha, 15*time.Minute); err != nil {
		t.Fatalf("RequestRescan: %v", err)
	}

	runStart := time.Now().Add(-time.Hour)
	jobs, err := db.ForcedRescanCandidates(ctx, runStart, 10)
	if err != nil {
		t.Fatalf("ForcedRescanCandidates: %v", err)
	}
	if len(jobs) != 1 || jobs[0].SHA256 != sha {
		t.Fatalf("queued sample = %+v, want one job for %s", jobs, sha)
	}

	// A worker picks it up and fails.
	if err := db.SetNote(ctx, sha, "worker failed"); err != nil {
		t.Fatalf("SetNote: %v", err)
	}
	jobs, err = db.ForcedRescanCandidates(ctx, runStart, 10)
	if err != nil {
		t.Fatalf("ForcedRescanCandidates after error: %v", err)
	}
	if len(jobs) != 0 {
		t.Fatalf("errored sample still offered: got %+v, want none", jobs)
	}

	// A restart gives it one more chance.
	jobs, err = db.ForcedRescanCandidates(ctx, time.Now().Add(time.Hour), 10)
	if err != nil {
		t.Fatalf("ForcedRescanCandidates after restart: %v", err)
	}
	if len(jobs) != 1 || jobs[0].SHA256 != sha {
		t.Fatalf("after restart = %+v, want one job for %s", jobs, sha)
	}
}

// TestForcedRescanCandidatesIgnoresAttempts guards the deliberate absence of an
// attempts ceiling in Tier 0. attempts counts every claim a sample has ever had
// and is never reset — not by StoreResult, and ReapStuck only reaps rows that
// are still unanalyzed — so a ceiling here would quietly retire the rescan
// button for the samples operators revisit most.
func TestForcedRescanCandidatesIgnoresAttempts(t *testing.T) {
	db := openTestDB(t)
	ctx := context.Background()

	const sha = "bbccdd0000000000000000000000000000000000000000000000000000000012"
	mustInsert(t, ctx, db, &Sample{SHA256: sha, Source: "test", Label: "good", LabelSource: "test"})
	mustAnalyze(t, ctx, db, sha, 1)
	if _, err := db.lite.ExecContext(ctx,
		`UPDATE samples SET analyzed_at = ?, attempts = ? WHERE sha256 = ?`,
		time.Now().Add(-time.Hour).UTC().Format(time.RFC3339Nano), MaxClaimAttempts*3, sha); err != nil {
		t.Fatalf("stamp attempts: %v", err)
	}
	if err := db.RequestRescan(ctx, sha, 15*time.Minute); err != nil {
		t.Fatalf("RequestRescan: %v", err)
	}

	jobs, err := db.ForcedRescanCandidates(ctx, time.Now(), 10)
	if err != nil {
		t.Fatalf("ForcedRescanCandidates: %v", err)
	}
	if len(jobs) != 1 || jobs[0].SHA256 != sha {
		t.Fatalf("well-travelled sample = %+v, want one job for %s", jobs, sha)
	}
}

// TestRequestRescanPreservesEnvelope verifies the no-null-window guarantee:
// while a forced rescan is pending, readers still see the prior cleave/litmus
// envelope, the analyzed_at timestamp, and the traits version. The row only
// transitions to its new state when a worker stores fresh analysis.
func TestRequestRescanPreservesEnvelope(t *testing.T) {
	db := openTestDB(t)
	ctx := context.Background()

	const sha = "ffffff00000000000000000000000000000000000000000000000000000000ff"
	mustInsert(t, ctx, db, &Sample{SHA256: sha, Source: "test", Label: "good", LabelSource: "test"})
	mustAnalyzeWithTraits(t, ctx, db, sha, 1, `{"l":2}`)
	if _, err := db.lite.ExecContext(ctx,
		`UPDATE samples SET analyzed_at = ?, traits_version = 'abc12' WHERE sha256 = ?`,
		time.Now().Add(-time.Hour).UTC().Format(time.RFC3339Nano), sha); err != nil {
		t.Fatalf("backdate: %v", err)
	}

	// Snapshot before the rescan request.
	var beforeCleave, beforeTraits string
	var beforeAnalyzedAt sql.NullString
	if err := db.lite.QueryRowContext(ctx,
		`SELECT cleave_result, traits_version, analyzed_at FROM samples WHERE sha256 = ?`,
		sha).Scan(&beforeCleave, &beforeTraits, &beforeAnalyzedAt); err != nil {
		t.Fatalf("snapshot before: %v", err)
	}
	if beforeCleave == "" || beforeTraits != "abc12" || !beforeAnalyzedAt.Valid {
		t.Fatalf("setup invariants violated: cleave=%q traits=%q analyzed_at_valid=%v",
			beforeCleave, beforeTraits, beforeAnalyzedAt.Valid)
	}

	if err := db.RequestRescan(ctx, sha, 15*time.Minute); err != nil {
		t.Fatalf("RequestRescan: %v", err)
	}

	// After the rescan request the row must remain in Tier 0 *and* still
	// expose its cached envelope to readers.
	jobs, err := db.ForcedRescanCandidates(ctx, time.Now(), 10)
	if err != nil {
		t.Fatalf("ForcedRescanCandidates: %v", err)
	}
	if len(jobs) != 1 || jobs[0].SHA256 != sha {
		t.Fatalf("ForcedRescanCandidates = %+v, want one job for %s", jobs, sha)
	}

	var afterCleave, afterTraits string
	var afterAnalyzedAt sql.NullString
	var forcedAt sql.NullString
	if err := db.lite.QueryRowContext(ctx,
		`SELECT cleave_result, traits_version, analyzed_at, rescan_requested_at FROM samples WHERE sha256 = ?`,
		sha).Scan(&afterCleave, &afterTraits, &afterAnalyzedAt, &forcedAt); err != nil {
		t.Fatalf("snapshot after: %v", err)
	}
	if afterCleave != beforeCleave {
		t.Fatalf("cleave_result changed: before=%q after=%q", beforeCleave, afterCleave)
	}
	if afterTraits != beforeTraits {
		t.Fatalf("traits_version changed: before=%q after=%q", beforeTraits, afterTraits)
	}
	if afterAnalyzedAt.String != beforeAnalyzedAt.String {
		t.Fatalf("analyzed_at changed: before=%q after=%q", beforeAnalyzedAt.String, afterAnalyzedAt.String)
	}
	if !forcedAt.Valid {
		t.Fatalf("forced_rescan_at not set after RequestRescan")
	}
}

// TestRequestRescanIdempotent verifies that asking to rescan a row that
// is already queued is a no-op success: the original forced_rescan_at
// timestamp is preserved (so FIFO position holds) and no error is
// returned even if the cooldown would otherwise reject the call.
func TestRequestRescanIdempotent(t *testing.T) {
	db := openTestDB(t)
	ctx := context.Background()

	const sha = "abcdef00000000000000000000000000000000000000000000000000000000ab"
	mustInsert(t, ctx, db, &Sample{SHA256: sha, Source: "test", Label: "good", LabelSource: "test"})
	mustAnalyze(t, ctx, db, sha, 1)
	if _, err := db.lite.ExecContext(ctx,
		`UPDATE samples SET analyzed_at = ? WHERE sha256 = ?`,
		time.Now().Add(-time.Hour).UTC().Format(time.RFC3339Nano), sha); err != nil {
		t.Fatalf("backdate: %v", err)
	}

	if err := db.RequestRescan(ctx, sha, 15*time.Minute); err != nil {
		t.Fatalf("RequestRescan first call: %v", err)
	}
	var firstForcedAt string
	if err := db.lite.QueryRowContext(ctx,
		`SELECT rescan_requested_at FROM samples WHERE sha256 = ?`,
		sha).Scan(&firstForcedAt); err != nil {
		t.Fatalf("read first forced_rescan_at: %v", err)
	}

	// Bring analyzed_at back into the cooldown window to prove the second
	// call short-circuits via the forced_rescan_at branch rather than the
	// cooldown branch.
	if _, err := db.lite.ExecContext(ctx,
		`UPDATE samples SET analyzed_at = ? WHERE sha256 = ?`,
		time.Now().UTC().Format(time.RFC3339Nano), sha); err != nil {
		t.Fatalf("re-stamp analyzed_at: %v", err)
	}

	if err := db.RequestRescan(ctx, sha, 15*time.Minute); err != nil {
		t.Fatalf("RequestRescan second call (already queued): %v", err)
	}
	var secondForcedAt string
	if err := db.lite.QueryRowContext(ctx,
		`SELECT rescan_requested_at FROM samples WHERE sha256 = ?`,
		sha).Scan(&secondForcedAt); err != nil {
		t.Fatalf("read second forced_rescan_at: %v", err)
	}
	if secondForcedAt != firstForcedAt {
		t.Fatalf("forced_rescan_at moved: first=%q second=%q (FIFO position should not change on idempotent re-request)",
			firstForcedAt, secondForcedAt)
	}
}

func TestKVGetNotFound(t *testing.T) {
	db := openTestDB(t)
	if _, err := db.KVGet(context.Background(), "nope"); !errors.Is(err, ErrNotFound) {
		t.Errorf("KVGet missing key: err = %v, want ErrNotFound", err)
	}
}

func TestKVSetIfAbsentAndGet(t *testing.T) {
	db := openTestDB(t)
	ctx := context.Background()

	if err := db.KVSetIfAbsent(ctx, "k1", "first"); err != nil {
		t.Fatalf("KVSetIfAbsent first: %v", err)
	}
	if got, err := db.KVGet(ctx, "k1"); err != nil || got != "first" {
		t.Fatalf("KVGet after first set: got=%q err=%v", got, err)
	}

	// Second SetIfAbsent on the same key must NOT overwrite.
	if err := db.KVSetIfAbsent(ctx, "k1", "second"); err != nil {
		t.Fatalf("KVSetIfAbsent second: %v", err)
	}
	if got, err := db.KVGet(ctx, "k1"); err != nil || got != "first" {
		t.Errorf("KVSetIfAbsent overwrote: got=%q err=%v, want first", got, err)
	}

	// Independent keys coexist.
	if err := db.KVSetIfAbsent(ctx, "k2", "other"); err != nil {
		t.Fatalf("KVSetIfAbsent k2: %v", err)
	}
	if got, err := db.KVGet(ctx, "k2"); err != nil || got != "other" {
		t.Errorf("KVGet k2: got=%q err=%v, want other", got, err)
	}
}

func TestUpdateEcosystem(t *testing.T) {
	db := openTestDB(t)
	ctx := context.Background()

	mustInsert(t, ctx, db, &Sample{SHA256: "e1", Source: "test", Ecosystem: "objectivesee", Label: "bad"})
	mustInsert(t, ctx, db, &Sample{SHA256: "e2", Source: "test", Ecosystem: "objectivesee", Label: "bad"})
	mustInsert(t, ctx, db, &Sample{SHA256: "e3", Source: "test", Ecosystem: "macos", Label: "bad"})
	mustInsert(t, ctx, db, &Sample{SHA256: "e4", Source: "test", Ecosystem: "c_linux", Label: "bad"})

	assertEcosystems := func(want string) {
		t.Helper()
		got, err := db.DistinctEcosystems(ctx)
		if err != nil {
			t.Fatal(err)
		}
		if strings.Join(got, ",") != want {
			t.Fatalf("DistinctEcosystems = %v, want %q", got, want)
		}
	}

	assertEcosystems("c_linux,macos,objectivesee")

	// One call remaps several values at once: a junk value collapses onto an
	// existing canonical one (objectivesee→macos) while another is cleared
	// (c_linux→""). Each sample also has a sample_locations row. Rows changed:
	// e1,e2 (objectivesee) + e4 (c_linux) = 3 samples + 3 locations = 6.
	n, err := db.UpdateEcosystems(ctx, map[string]string{"objectivesee": "macos", "c_linux": ""})
	if err != nil {
		t.Fatal(err)
	}
	if n != 6 {
		t.Errorf("UpdateEcosystems rows = %d, want 6 (3 samples + 3 locations)", n)
	}
	assertEcosystems("macos")

	// Clearing to empty drops the value from the distinct set entirely.
	if _, err := db.UpdateEcosystems(ctx, map[string]string{"macos": ""}); err != nil {
		t.Fatal(err)
	}
	assertEcosystems("")

	// An empty mapping is a no-op rather than a malformed statement.
	if n, err := db.UpdateEcosystems(ctx, nil); err != nil || n != 0 {
		t.Fatalf("UpdateEcosystems(nil) = %d, %v; want 0, nil", n, err)
	}
}

// TestTriageMostRecent verifies that the per-dataset limit applies globally —
// the most recently added rows across all file types, not capped per type.
func TestTriageMostRecent(t *testing.T) {
	ctx := context.Background()
	db := openTestDB(t)

	var n int
	// analyze inserts a top-level sample with the given label, then records a
	// cleave result whose single trait sets file_type and max_crit. level<5
	// with one trait => max_crit<5 && suspicious_count<2 (a "bad" miss); level>=5
	// => flagged (a "good"/"new" hit). Samples are inserted oldest-first, so
	// later inserts are the most recently added (higher created_at and id).
	analyze := func(label, fileType string, level int) string {
		n++
		sha := fmt.Sprintf("%064x", n)
		mustInsert(t, ctx, db, &Sample{SHA256: sha, Source: "test", Label: label, LabelSource: "test"})
		result := fmt.Appendf(nil, `{"fs":[{"sha":%q,"type":%q,"x":0,"dp":0,"ts":[{"l":%d}]}]}`, sha, fileType, level)
		if err := db.UpdateCleaveResult(ctx, sha, result, nil, ""); err != nil {
			t.Fatalf("UpdateCleaveResult: %v", err)
		}
		return sha
	}

	counts := func(samples []*Sample) map[string]int {
		m := map[string]int{}
		for _, s := range samples {
			m[s.FileType]++
		}
		return m
	}

	// bad misses: 3 apk then 2 deb; good/new hits mirror the structure. The deb
	// rows are added last, so a global most-recent limit favors them.
	var sightedClaims []Sighting
	for range 3 {
		analyze("bad", "apk", 1)
		analyze("good", "apk", 5)
		analyze("unknown", "apk", 5)
		sightedClaims = append(sightedClaims, Sighting{Source: "feed", Subject: analyze("sighted", "apk", 1)})
	}
	for range 2 {
		analyze("bad", "deb", 1)
		analyze("good", "deb", 5)
		analyze("unknown", "deb", 5)
		sightedClaims = append(sightedClaims, Sighting{Source: "feed", Subject: analyze("sighted", "deb", 1)})
	}
	if _, err := db.AddSightings(ctx, sightedClaims); err != nil {
		t.Fatalf("AddSightings(sighted): %v", err)
	}

	for _, tc := range []struct {
		name  string
		fetch func(context.Context, int, TriageFilter) ([]*Sample, error)
	}{
		{"bad", func(ctx context.Context, n int, f TriageFilter) ([]*Sample, error) {
			return db.TriageBad(ctx, n, time.Now().Add(-BadFreshness), f)
		}},
		{"good", db.TriageGood},
		{"new", db.TriageNew},
		{"sighted", db.TriageSighted},
	} {
		got, err := tc.fetch(ctx, 2, TriageFilter{})
		if err != nil {
			t.Fatalf("%s: %v", tc.name, err)
		}
		// Limit 2 returns exactly 2 rows total (global cap), and they are the
		// most recent — both deb, not split across file types.
		if len(got) != 2 {
			t.Errorf("%s: total = %d, want 2 (global cap)", tc.name, len(got))
		}
		if c := counts(got); c["deb"] != 2 {
			t.Errorf("%s: deb = %d, want 2 (most recent), counts %v", tc.name, c["deb"], c)
		}
	}

	// The file-type filter still narrows to a single type, capped by the limit.
	got, err := db.TriageBad(ctx, 2, time.Time{}, TriageFilter{FileType: "apk"})
	if err != nil {
		t.Fatalf("TriageBad(apk): %v", err)
	}
	if c := counts(got); c["apk"] != 2 || len(got) != 2 {
		t.Errorf("TriageBad(apk) = %v (len %d), want only 2 apk", c, len(got))
	}
}

// TestTriageThresholds pins the detection boundaries: good surfaces samples
// that trip Cleave detection (max_crit >= 5 OR suspicious_count >= 2); new
// surfaces any sample with at least one suspicious-or-hostile finding; bad is
// the exact inverse of detection (max_crit < 5 AND suspicious_count < 2).
func TestTriageThresholds(t *testing.T) {
	ctx := context.Background()
	db := openTestDB(t)

	var n int
	// analyze inserts a top-level sample with the given label and a cleave result
	// carrying one trait per level in levels (l>=5 hostile, l==4 suspicious). It
	// returns the sha so callers can assert membership.
	analyze := func(label string, levels ...int) string {
		n++
		sha := fmt.Sprintf("%064x", n)
		mustInsert(t, ctx, db, &Sample{SHA256: sha, Source: "test", Label: label, LabelSource: "test"})
		ts := make([]string, len(levels))
		for i, l := range levels {
			ts[i] = fmt.Sprintf(`{"l":%d}`, l)
		}
		result := fmt.Appendf(nil, `{"fs":[{"sha":%q,"type":"apk","x":0,"dp":0,"ts":[%s]}]}`,
			sha, strings.Join(ts, ","))
		if err := db.UpdateCleaveResult(ctx, sha, result, nil, ""); err != nil {
			t.Fatalf("UpdateCleaveResult: %v", err)
		}
		return sha
	}

	has := func(samples []*Sample, sha string) bool {
		for _, s := range samples {
			if s.SHA256 == sha {
				return true
			}
		}
		return false
	}

	// good: detection needs a hostile finding, a second suspicious-or-hostile
	// finding, or a litmus class of suspicious or higher — a lone suspicious
	// finding no longer qualifies. new: a lone suspicious finding qualifies.
	goodLoneSusp := analyze("good", 4)
	goodTwoSusp := analyze("good", 4, 4)
	goodHostile := analyze("good", 5)
	goodBenign := analyze("good", 1, 3)
	newSusp := analyze("unknown", 4)
	newBenign := analyze("unknown", 2)

	// Litmus-only disagreement is not a Cleave false positive. TriageHighest's
	// premium route-balanced review owns those rows; TriageGood requires a
	// concrete trait finding it can repair.
	goodLitmusSusp := analyze("good", 1)
	if err := db.UpdateLitmusResult(ctx, goodLitmusSusp, []byte(`{"l":100}`)); err != nil {
		t.Fatalf("UpdateLitmusResult: %v", err)
	}
	goodLitmusBenign := analyze("good", 1)
	if err := db.UpdateLitmusResult(ctx, goodLitmusBenign, []byte(`{"l":5000}`)); err != nil {
		t.Fatalf("UpdateLitmusResult: %v", err)
	}

	// bad: any hostile finding or two suspicious findings is already detected;
	// only samples below both thresholds are repair candidates.
	badConfident := analyze("bad", 5, 4)
	badLoneHostile := analyze("bad", 5)
	badTwoSusp := analyze("bad", 4, 4)
	badBenign := analyze("bad", 1)

	good, err := db.TriageGood(ctx, 100, TriageFilter{})
	if err != nil {
		t.Fatalf("TriageGood: %v", err)
	}
	if !has(good, goodTwoSusp) || !has(good, goodHostile) {
		t.Errorf("TriageGood missing a detected sample")
	}
	if has(good, goodLoneSusp) || has(good, goodBenign) || has(good, goodLitmusSusp) || has(good, goodLitmusBenign) {
		t.Errorf("TriageGood included an undetected sample")
	}

	gotNew, err := db.TriageNew(ctx, 100, TriageFilter{})
	if err != nil {
		t.Fatalf("TriageNew: %v", err)
	}
	if !has(gotNew, newSusp) {
		t.Errorf("TriageNew missing suspicious sample")
	}
	if has(gotNew, newBenign) {
		t.Errorf("TriageNew included an all-benign sample")
	}

	bad, err := db.TriageBad(ctx, 100, time.Time{}, TriageFilter{})
	if err != nil {
		t.Fatalf("TriageBad: %v", err)
	}
	if has(bad, badConfident) || has(bad, badLoneHostile) || has(bad, badTwoSusp) {
		t.Errorf("TriageBad included a detected sample")
	}
	if !has(bad, badBenign) {
		t.Errorf("TriageBad missing a detection-miss sample")
	}

	// sighted: no detection threshold — every analyzed sample with a qualifying
	// ledger claim needs triage, whether cleave flags it or not.
	sightedConfident := analyze("sighted", 5, 4)
	sightedBenign := analyze("sighted", 1)
	if _, err := db.AddSightings(ctx, []Sighting{
		{Source: "feed-a", Subject: sightedConfident},
		{Source: "feed-b", Subject: sightedBenign},
	}); err != nil {
		t.Fatalf("AddSightings(sighted): %v", err)
	}

	sighted, err := db.TriageSighted(ctx, 100, TriageFilter{})
	if err != nil {
		t.Fatalf("TriageSighted: %v", err)
	}
	if !has(sighted, sightedConfident) || !has(sighted, sightedBenign) {
		t.Errorf("TriageSighted must surface every claimed sample regardless of detection state")
	}
	if has(sighted, badBenign) {
		t.Errorf("TriageSighted included a bad sample without qualifying evidence")
	}
}

// TestTriageExcludesEmptyPathReferences locks that reference-only rows —
// registry sidecars and fetched deps, which [containmentColumns] stores with
// samples.path ” — never enter the queues cyclotron polls. Without this they
// match TriageNew (suspicious_count from the exploded stub) and burn a HEAD
// /api/file probe each cycle for bytes hopper will never serve.
func TestTriageExcludesEmptyPathReferences(t *testing.T) {
	ctx := context.Background()
	db := openTestDB(t)

	const (
		archive = "aa00000000000000000000000000000000000000000000000000000000000000"
		sidecar = "bb00000000000000000000000000000000000000000000000000000000000000"
		fetched = "cc00000000000000000000000000000000000000000000000000000000000000"
		realSHA = "dd00000000000000000000000000000000000000000000000000000000000000"
	)

	mustInsert(t, ctx, db, &Sample{
		SHA256: archive, Source: "test", Label: "unknown", LabelSource: "test",
		Path: "incoming/pkg.tgz",
	})
	// Virtual !! path satisfies validSample; LocationRel blanks samples.path.
	mustInsert(t, ctx, db, &Sample{
		SHA256: sidecar, Source: "test", Label: "unknown", LabelSource: "test",
		Path: "incoming/pkg.tgz!!pkg@1.0.0.registry.json", Parent: archive,
		LocationRel: string(RelRegistry),
	})
	mustInsert(t, ctx, db, &Sample{
		SHA256: fetched, Source: "test", Label: "unknown", LabelSource: "test",
		Path: "incoming/pkg.tgz!!dep-1.0.0.tgz", Parent: archive,
		LocationRel: string(RelFetched),
	})
	mustInsert(t, ctx, db, &Sample{
		SHA256: realSHA, Source: "test", Label: "unknown", LabelSource: "test",
		Path: "incoming/real.bin",
	})

	for _, sha := range []string{sidecar, fetched, realSHA} {
		got, err := db.SampleBySHA256(ctx, sha)
		if err != nil {
			t.Fatalf("SampleBySHA256(%s): %v", sha, err)
		}
		switch sha {
		case realSHA:
			if got.Path == "" {
				t.Fatalf("real sample path unexpectedly empty")
			}
		default:
			if got.Path != "" || got.Parent != "" {
				t.Fatalf("%s: path=%q parent=%q, want both empty (reference projection)",
					sha, got.Path, got.Parent)
			}
		}
	}

	analyze := func(sha, typ string) {
		t.Helper()
		cleave := fmt.Appendf(nil,
			`{"fs":[{"sha":%q,"type":%q,"dp":0,"ts":[{"l":5},{"l":4},{"l":4},{"l":4}]}]}`,
			sha, typ)
		litmus := []byte(`{"class":2,"l":2}`)
		if _, err := db.StoreResult(ctx, sha, cleave, litmus, nil, nil, ""); err != nil {
			t.Fatalf("StoreResult(%s): %v", sha, err)
		}
	}
	analyze(sidecar, "registry")
	analyze(fetched, "npm")
	analyze(realSHA, "elf")

	has := func(samples []*Sample, sha string) bool {
		for _, s := range samples {
			if s.SHA256 == sha {
				return true
			}
		}
		return false
	}

	gotNew, err := db.TriageNew(ctx, 100, TriageFilter{})
	if err != nil {
		t.Fatalf("TriageNew: %v", err)
	}
	if !has(gotNew, realSHA) {
		t.Errorf("TriageNew missing real on-disk sample")
	}
	if has(gotNew, sidecar) || has(gotNew, fetched) {
		t.Errorf("TriageNew included empty-path reference sample(s): %+v", gotNew)
	}

	gotFallout, err := db.TriageFallout(ctx, 100, time.Time{}, TriageFilter{})
	if err != nil {
		t.Fatalf("TriageFallout: %v", err)
	}
	if !has(gotFallout, realSHA) {
		t.Errorf("TriageFallout missing real on-disk sample")
	}
	if has(gotFallout, sidecar) || has(gotFallout, fetched) {
		t.Errorf("TriageFallout included empty-path reference sample(s)")
	}
}

// TestTriageSecondOpinion pins the second-opinion candidacy rules: a
// good-labeled sample qualifies on a trusted-source sighting or on sightings
// from two-plus distinct sources, is deferred while its analysis is fresh, is
// drained permanently by a reports row of type "second", and — to stay
// disjoint from TriageGood's set — never trips detection.
func TestTriageSecondOpinion(t *testing.T) {
	ctx := context.Background()
	db := openTestDB(t)

	var n int
	// analyzeLevels inserts an analyzed top-level sample with one trait per
	// level and records the given sightings for it, in that order so
	// AddSightings flips samples.corroborated.
	analyzeLevels := func(label, purlBase string, levels []int, sources ...string) string {
		n++
		sha := fmt.Sprintf("%064x", n)
		mustInsert(t, ctx, db, &Sample{SHA256: sha, Source: "test", Label: label, LabelSource: "test", PURLBase: purlBase})
		ts := make([]string, len(levels))
		for i, l := range levels {
			ts[i] = fmt.Sprintf(`{"l":%d}`, l)
		}
		result := fmt.Appendf(nil, `{"fs":[{"sha":%q,"type":"apk","x":0,"dp":0,"ts":[%s]}]}`,
			sha, strings.Join(ts, ","))
		if err := db.UpdateCleaveResult(ctx, sha, result, nil, ""); err != nil {
			t.Fatalf("UpdateCleaveResult: %v", err)
		}
		var sightings []Sighting
		for _, src := range sources {
			sightings = append(sightings, Sighting{Source: src, Subject: sha})
		}
		if len(sightings) > 0 {
			if _, err := db.AddSightings(ctx, sightings); err != nil {
				t.Fatalf("AddSightings: %v", err)
			}
		}
		return sha
	}
	benign := []int{1}
	analyze := func(label, purlBase string, sources ...string) string {
		return analyzeLevels(label, purlBase, benign, sources...)
	}

	has := func(samples []*Sample, sha string) bool {
		for _, s := range samples {
			if s.SHA256 == sha {
				return true
			}
		}
		return false
	}

	trustedOne := analyze("good", "", "bazaar")
	vendorOne := analyze("good", "", "aikido")
	vendorTwo := analyze("good", "", "aikido", "socket")
	unseen := analyze("good", "")
	badTrusted := analyze("bad", "", "bazaar")
	drained := analyze("good", "", "virussign")
	reported := analyze("good", "", "virussign")
	// Detection-trippers belong to TriageGood, not here (disjoint queues).
	detectedHostile := analyzeLevels("good", "", []int{5}, "bazaar")
	detectedTwoSusp := analyzeLevels("good", "", []int{4, 4}, "bazaar")

	// A purl-cited sample qualifies via its purl_base subject.
	purlCited := analyze("good", "pkg:npm/evil-pkg")
	if _, err := db.AddSightings(ctx, []Sighting{{Source: "osm", Subject: "pkg:npm/evil-pkg"}}); err != nil {
		t.Fatalf("AddSightings(purl): %v", err)
	}

	// A "second" report drains; a report of any other type does not.
	if err := db.InsertReport(ctx, &Report{SHA256: drained, Type: "second", Provider: "claude"}); err != nil {
		t.Fatalf("InsertReport: %v", err)
	}
	if err := db.InsertReport(ctx, &Report{SHA256: reported, Type: "re", Provider: "claude"}); err != nil {
		t.Fatalf("InsertReport: %v", err)
	}

	// Every sample above was analyzed just now, so a future cutoff admits all
	// eligible rows and a past cutoff (the settling window) admits none.
	future := time.Now().Add(time.Hour)
	got, err := db.TriageSecondOpinion(ctx, 100, TrustedBadSources, future, TriageFilter{})
	if err != nil {
		t.Fatalf("TriageSecondOpinion: %v", err)
	}
	for _, want := range []struct {
		name string
		sha  string
	}{
		{"trusted single source", trustedOne},
		{"two vendor sources", vendorTwo},
		{"purl-cited trusted source", purlCited},
		{"non-second report", reported},
	} {
		if !has(got, want.sha) {
			t.Errorf("TriageSecondOpinion missing %s", want.name)
		}
	}
	for _, wantNot := range []struct {
		name string
		sha  string
	}{
		{"lone vendor source", vendorOne},
		{"no sightings", unseen},
		{"bad-labeled", badTrusted},
		{"second-report drained", drained},
		{"detection-tripping (hostile trait)", detectedHostile},
		{"detection-tripping (two suspicious)", detectedTwoSusp},
	} {
		if has(got, wantNot.sha) {
			t.Errorf("TriageSecondOpinion included %s", wantNot.name)
		}
	}

	past := time.Now().Add(-time.Hour)
	got, err = db.TriageSecondOpinion(ctx, 100, TrustedBadSources, past, TriageFilter{})
	if err != nil {
		t.Fatalf("TriageSecondOpinion(past): %v", err)
	}
	if len(got) != 0 {
		t.Errorf("TriageSecondOpinion(past cutoff) = %d rows, want 0 (settling window)", len(got))
	}

	// An empty trusted list still admits the two-source arm.
	got, err = db.TriageSecondOpinion(ctx, 100, nil, future, TriageFilter{})
	if err != nil {
		t.Fatalf("TriageSecondOpinion(nil trusted): %v", err)
	}
	if !has(got, vendorTwo) || has(got, trustedOne) {
		t.Errorf("TriageSecondOpinion(nil trusted): want only the two-source arm, got %d rows", len(got))
	}
}

// TestTriageSecondOpinionEvidenceRefresh pins the re-admission rule: a
// "second" report drains only while it is newer than the newest trusted
// sighting; a trusted source citing the sample after its review re-admits it,
// an untrusted one does not.
func TestTriageSecondOpinionEvidenceRefresh(t *testing.T) {
	ctx := context.Background()
	db := openTestDB(t)

	sha := fmt.Sprintf("%064x", 7777)
	mustInsert(t, ctx, db, &Sample{SHA256: sha, Source: "test", Label: "good", LabelSource: "test"})
	result := fmt.Appendf(nil, `{"fs":[{"sha":%q,"type":"apk","x":0,"dp":0,"ts":[{"l":1}]}]}`, sha)
	if err := db.UpdateCleaveResult(ctx, sha, result, nil, ""); err != nil {
		t.Fatalf("UpdateCleaveResult: %v", err)
	}
	if _, err := db.AddSightings(ctx, []Sighting{{Source: "bazaar", Subject: sha}}); err != nil {
		t.Fatalf("AddSightings: %v", err)
	}

	future := time.Now().Add(time.Hour)
	selected := func(want bool, when string) {
		t.Helper()
		got, err := db.TriageSecondOpinion(ctx, 100, TrustedBadSources, future, TriageFilter{})
		if err != nil {
			t.Fatalf("TriageSecondOpinion (%s): %v", when, err)
		}
		found := false
		for _, s := range got {
			if s.SHA256 == sha {
				found = true
			}
		}
		if found != want {
			t.Errorf("%s: selected = %v, want %v", when, found, want)
		}
	}

	selected(true, "before any review")

	// Report newer than the sighting → drained. (Sleeps order the ISO-8601
	// text timestamps, which have millisecond resolution in SQLite.)
	time.Sleep(5 * time.Millisecond)
	if err := db.InsertReport(ctx, &Report{SHA256: sha, Type: "second", Provider: "claude"}); err != nil {
		t.Fatalf("InsertReport: %v", err)
	}
	selected(false, "after review")

	// An untrusted sighting arriving after the review is not new evidence.
	time.Sleep(5 * time.Millisecond)
	if _, err := db.AddSightings(ctx, []Sighting{{Source: "aikido", Subject: sha}}); err != nil {
		t.Fatalf("AddSightings(aikido): %v", err)
	}
	selected(false, "after untrusted sighting")

	// A trusted sighting arriving after the review re-admits the sample…
	if _, err := db.AddSightings(ctx, []Sighting{{Source: "virussign", Subject: sha}}); err != nil {
		t.Fatalf("AddSightings(virussign): %v", err)
	}
	selected(true, "after new trusted sighting")

	// …until the follow-up review drains it again.
	time.Sleep(5 * time.Millisecond)
	if err := db.InsertReport(ctx, &Report{SHA256: sha, Type: "second", Provider: "claude"}); err != nil {
		t.Fatalf("InsertReport(2): %v", err)
	}
	selected(false, "after follow-up review")
}

// TestTriageAcquit pins the acquit candidacy rules: a bad-labeled,
// confidently-detected sample with a non-feed provenance sidecar and no
// sighting from anyone qualifies; feed-discovered, cited, provenance-less,
// detection-gap, conflict, young, and acquit-reported rows do not.
func TestTriageAcquit(t *testing.T) {
	ctx := context.Background()
	db := openTestDB(t)

	registryProv := []byte(`{"schema_version":"1","artifact":{"sha256":"x"},"fetch":{"category":"good"}}`)
	feedProv := []byte(`{"schema_version":"1","artifact":{"sha256":"x"},"fetch":{"category":"bad"},"feed":{"collector":"bazaar","category":"bad"}}`)

	var n int
	analyze := func(label string, prov []byte, levels []int, sources ...string) string {
		n++
		sha := fmt.Sprintf("%063x1", n)
		mustInsert(t, ctx, db, &Sample{SHA256: sha, Source: "test", Label: label, LabelSource: "test", Provenance: prov})
		ts := make([]string, len(levels))
		for i, l := range levels {
			ts[i] = fmt.Sprintf(`{"l":%d}`, l)
		}
		result := fmt.Appendf(nil, `{"fs":[{"sha":%q,"type":"apk","x":0,"dp":0,"ts":[%s]}]}`,
			sha, strings.Join(ts, ","))
		if err := db.UpdateCleaveResult(ctx, sha, result, nil, ""); err != nil {
			t.Fatalf("UpdateCleaveResult: %v", err)
		}
		var sightings []Sighting
		for _, src := range sources {
			sightings = append(sightings, Sighting{Source: src, Subject: sha})
		}
		if len(sightings) > 0 {
			if _, err := db.AddSightings(ctx, sightings); err != nil {
				t.Fatalf("AddSightings: %v", err)
			}
		}
		return sha
	}
	detected := []int{5, 4} // hostile + a second suspicious finding

	uncited := analyze("bad", registryProv, detected)
	reported := analyze("bad", registryProv, detected)
	feedBorn := analyze("bad", feedProv, detected)
	noProv := analyze("bad", nil, detected)
	cited := analyze("bad", registryProv, detected, "aikido")
	gap := analyze("bad", registryProv, []int{4}) // lone suspicious: TriageBad's set
	goodRow := analyze("good", registryProv, detected)
	conflicted := analyze("bad", registryProv, detected)
	if err := db.SetSkip(ctx, conflicted, "conflict"); err != nil {
		t.Fatalf("SetSkip: %v", err)
	}
	// A non-acquit report does not drain; an acquit report does.
	if err := db.InsertReport(ctx, &Report{SHA256: uncited, Type: "second", Provider: "claude"}); err != nil {
		t.Fatalf("InsertReport(second): %v", err)
	}
	if err := db.InsertReport(ctx, &Report{SHA256: reported, Type: "acquit", Provider: "claude"}); err != nil {
		t.Fatalf("InsertReport(acquit): %v", err)
	}

	got, err := db.TriageAcquit(ctx, 100, time.Now().Add(time.Hour), TriageFilter{})
	if err != nil {
		t.Fatalf("TriageAcquit: %v", err)
	}
	selected := map[string]bool{}
	for _, s := range got {
		selected[s.SHA256] = true
	}
	if !selected[uncited] {
		t.Error("TriageAcquit missing the qualifying uncited sample")
	}
	for _, tc := range []struct {
		name string
		sha  string
	}{
		{"feed-discovered provenance", feedBorn},
		{"no provenance sidecar", noProv},
		{"cited by a source", cited},
		{"detection-gap (bad queue's set)", gap},
		{"good-labeled", goodRow},
		{"conflict-skipped", conflicted},
		{"acquit-reported", reported},
	} {
		if selected[tc.sha] {
			t.Errorf("TriageAcquit included %s", tc.name)
		}
	}

	// The grace window: a past cutoff excludes everything created since.
	got, err = db.TriageAcquit(ctx, 100, time.Now().Add(-time.Hour), TriageFilter{})
	if err != nil {
		t.Fatalf("TriageAcquit(past): %v", err)
	}
	if len(got) != 0 {
		t.Errorf("TriageAcquit(past cutoff) = %d rows, want 0 (grace window)", len(got))
	}
}

// TestLitmusClass pins the Go mirror of the SQL class derivation.
func TestLitmusClass(t *testing.T) {
	cases := []struct {
		in   string
		want int
	}{
		{"", 0},                   // no litmus result
		{`{"class":2}`, 2},        // legacy class field wins
		{`{"class":0,"l":10}`, 0}, // ... even over a hostile-looking level
		{`{}`, 2},                 // present envelope, no level: manual-mode hostile
		{`{"l":-1}`, 0},           // never fires
		{`{"l":25}`, 2},           // at the hostile cutoff (CriticalLevel)
		{`{"l":26}`, 1},           // just past the cutoff: suspicious
		{`{"lvl":3000}`, 1},       // at the ceiling, via the v7 'lvl' key
		{`{"l":3001}`, 0},         // looser than SuspiciousCeiling: benign
	}
	for _, c := range cases {
		if got := LitmusClass([]byte(c.in)); got != c.want {
			t.Errorf("LitmusClass(%q) = %d, want %d", c.in, got, c.want)
		}
	}
}

// sha64 builds a syntactically valid lowercase-hex sha256 from a single hex
// digit, so prune tests can use distinct, readable sample identities.
func sha64(d byte) string { return strings.Repeat(string(d), 64) }

func TestPruneMissingLocations(t *testing.T) {
	ctx := context.Background()
	db := openTestDB(t)
	root := t.TempDir()

	writeUnder := func(rel string) {
		p := filepath.Join(root, rel)
		if err := os.MkdirAll(filepath.Dir(p), 0o755); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(p, []byte("x"), 0o644); err != nil {
			t.Fatal(err)
		}
	}
	locCount := func(sha string) int {
		var n int
		if err := db.lite.QueryRowContext(ctx, `SELECT count(*) FROM sample_locations WHERE sha256=?`, sha).Scan(&n); err != nil {
			t.Fatal(err)
		}
		return n
	}
	skipOf := func(sha string) string {
		s, err := db.SampleBySHA256(ctx, sha)
		if err != nil {
			t.Fatalf("SampleBySHA256(%s): %v", sha, err)
		}
		return s.Skip
	}

	var (
		present = sha64('1') // top-level, file on disk → kept
		gone    = sha64('2') // top-level, no file → pruned + marked missing
		twoLoc  = sha64('3') // two locations, one missing → stays active
		archive = sha64('4') // parent archive
		member  = sha64('5') // archive member, no standalone file → never pruned
	)

	writeUnder("bad/present.js")
	mustInsert(t, ctx, db, &Sample{SHA256: present, Source: "test", Label: "bad", LabelSource: "test", Path: "bad/present.js"})

	mustInsert(t, ctx, db, &Sample{SHA256: gone, Source: "test", Label: "bad", LabelSource: "test", Path: "bad/gone.js"})

	writeUnder("bad/twoloc-a.js")
	mustInsert(t, ctx, db, &Sample{SHA256: twoLoc, Source: "test", Label: "bad", LabelSource: "test", Path: "bad/twoloc-a.js"})
	mustInsert(t, ctx, db, &Sample{SHA256: twoLoc, Source: "test", Label: "bad", LabelSource: "test", Path: "bad/twoloc-b.js"}) // missing on disk

	// Archive member: parent set, pseudo-path with the !! delimiter, no real
	// file. Must be invisible to prune or every member would be marked missing.
	mustInsert(t, ctx, db, &Sample{SHA256: member, Source: "test", Label: "bad", LabelSource: "test", Parent: archive, Path: archive + "!!pkg/x.js"})

	// maxFraction 1.0: 2 of 4 top-level locations are missing (>0.40 default cap).
	removed, err := db.PruneMissingLocations(ctx, root, 1.0)
	if err != nil {
		t.Fatalf("PruneMissingLocations: %v", err)
	}
	if removed != 2 {
		t.Fatalf("removed = %d, want 2 (gone + twoloc-b)", removed)
	}

	if got := locCount(present); got != 1 || skipOf(present) != "" {
		t.Errorf("present: loc=%d skip=%q, want loc=1 skip=''", got, skipOf(present))
	}
	if got := locCount(gone); got != 0 {
		t.Errorf("gone: loc=%d, want 0", got)
	}
	if got := skipOf(gone); got != "missing" {
		t.Errorf("gone: skip=%q, want 'missing'", got)
	}
	if got := locCount(twoLoc); got != 1 || skipOf(twoLoc) != "" {
		t.Errorf("twoLoc: loc=%d skip=%q, want loc=1 skip='' (survives on its present location)", got, skipOf(twoLoc))
	}
	if got := locCount(member); got != 1 {
		t.Errorf("member: loc=%d, want 1 (archive members are never stat-pruned)", got)
	}
	for sha, wantPath := range map[string]string{
		gone:   "bad/gone.js",
		twoLoc: "bad/twoloc-b.js",
	} {
		retired, err := db.RetiredLocationsForSHA(ctx, sha)
		if err != nil {
			t.Fatal(err)
		}
		if len(retired) != 1 || retired[0].Path != wantPath || retired[0].Reason != "prune" || retired[0].SuccessorPath != "" {
			t.Errorf("retired locations for %s = %+v", sha[:6], retired)
		}
	}
	if retired, err := db.RetiredLocationsForSHA(ctx, present); err != nil || len(retired) != 0 {
		t.Errorf("present retired locations = %+v, %v", retired, err)
	}

	// A label_event records the missing transition for audit.
	var events int
	if err := db.lite.QueryRowContext(ctx,
		`SELECT count(*) FROM label_events WHERE sha256=? AND reason='prune-missing' AND to_skip='missing'`, gone).Scan(&events); err != nil {
		t.Fatal(err)
	}
	if events != 1 {
		t.Errorf("label_events for gone = %d, want 1", events)
	}

	// Revive: the bytes reappear at a new path; the next walk-style insert
	// clears skip='missing' back to '' and records a fresh location.
	writeUnder("bad/gone-again.js")
	mustInsert(t, ctx, db, &Sample{SHA256: gone, Source: "test", Label: "bad", LabelSource: "test", Path: "bad/gone-again.js"})
	if got := skipOf(gone); got != "" {
		t.Errorf("after revive: gone skip=%q, want '' (re-observed file clears missing)", got)
	}
	if got := locCount(gone); got != 1 {
		t.Errorf("after revive: gone loc=%d, want 1", got)
	}
}

func TestPruneMissingLocationsSafetyCap(t *testing.T) {
	ctx := context.Background()
	db := openTestDB(t)
	root := t.TempDir()

	a, b := sha64('a'), sha64('b')
	mustInsert(t, ctx, db, &Sample{SHA256: a, Source: "test", Label: "bad", LabelSource: "test", Path: "bad/a.js"})
	mustInsert(t, ctx, db, &Sample{SHA256: b, Source: "test", Label: "bad", LabelSource: "test", Path: "bad/b.js"})

	// Both files are missing → 100% would be pruned, exceeding the 40% cap.
	_, err := db.PruneMissingLocations(ctx, root, 0.40)
	var se *PruneSafetyExceeded
	if !errors.As(err, &se) {
		t.Fatalf("err = %v, want *PruneSafetyExceeded", err)
	}
	if se.Victims != 2 || se.Total != 2 {
		t.Errorf("cap report victims=%d total=%d, want 2/2", se.Victims, se.Total)
	}
	// Nothing deleted, nothing marked.
	for _, sha := range []string{a, b} {
		var n int
		if err := db.lite.QueryRowContext(ctx, `SELECT count(*) FROM sample_locations WHERE sha256=?`, sha).Scan(&n); err != nil {
			t.Fatal(err)
		}
		if n != 1 {
			t.Errorf("%s loc=%d, want 1 (cap aborts before any delete)", sha[:6], n)
		}
		s, err := db.SampleBySHA256(ctx, sha)
		if err != nil {
			t.Fatal(err)
		}
		if s.Skip != "" {
			t.Errorf("%s skip=%q, want '' (cap aborts before any mark)", sha[:6], s.Skip)
		}
		if retired, err := db.RetiredLocationsForSHA(ctx, sha); err != nil || len(retired) != 0 {
			t.Errorf("%s retired locations = %+v, %v; cap must be atomic", sha[:6], retired, err)
		}
	}
}

func TestRepairMissingLocations(t *testing.T) {
	ctx := context.Background()
	db := openTestDB(t)
	root := t.TempDir()

	writeUnder := func(rel string) {
		p := filepath.Join(root, rel)
		if err := os.MkdirAll(filepath.Dir(p), 0o755); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(p, []byte("x"), 0o644); err != nil {
			t.Fatal(err)
		}
	}
	// addLocation records a location the way a past walk would have, without
	// going through InsertSample/mustInsert — mustInsert's pool-relabel path
	// would auto-revive a live match, which is exactly the full-walk behavior
	// repair-missing exists to substitute for (see ReconcilePools). Tests here
	// must exercise repair-missing's own stat-known-locations logic instead.
	addLocation := func(sha, path string, lastSeen time.Time) {
		if _, err := db.lite.ExecContext(ctx,
			`INSERT INTO sample_locations (sha256, path, parent_sha256, first_seen_at, last_seen_at)
			 VALUES (?, ?, '', ?, ?)`,
			sha, path, now(), lastSeen.UTC().Format(time.RFC3339Nano)); err != nil {
			t.Fatalf("insert location: %v", err)
		}
	}
	markMissing := func(sha, path string) {
		if _, err := db.lite.ExecContext(ctx,
			`UPDATE samples SET skip = 'missing', path = ? WHERE sha256 = ?`, path, sha); err != nil {
			t.Fatalf("mark missing: %v", err)
		}
	}
	skipOf := func(sha string) string {
		s, err := db.SampleBySHA256(ctx, sha)
		if err != nil {
			t.Fatalf("SampleBySHA256(%s): %v", sha, err)
		}
		return s.Skip
	}
	pathOf := func(sha string) string {
		s, err := db.SampleBySHA256(ctx, sha)
		if err != nil {
			t.Fatalf("SampleBySHA256(%s): %v", sha, err)
		}
		return s.Path
	}

	var (
		revivedElsewhere = sha64('1') // missing at current path; an older known location still has the bytes
		stillGone        = sha64('2') // missing; no known location has bytes anywhere
		poolTieBreak     = sha64('3') // missing; two live candidates, only one under the label's own pool dir
	)

	mustInsert(t, ctx, db, &Sample{SHA256: revivedElsewhere, Source: "test", Label: "bad", LabelSource: "test", Path: "bad/old.js"})
	writeUnder("bad/old.js")
	// Simulate: the file was later "moved" out from under hopper (path
	// corruption, a bad migration, whatever) and got marked missing, without a
	// fresh walk ever re-observing bad/old.js as a new location.
	markMissing(revivedElsewhere, "bad/renamed-away.js")

	mustInsert(t, ctx, db, &Sample{SHA256: stillGone, Source: "test", Label: "bad", LabelSource: "test", Path: "bad/gone.js"})
	markMissing(stillGone, "bad/gone.js")

	mustInsert(t, ctx, db, &Sample{SHA256: poolTieBreak, Source: "test", Label: "bad", LabelSource: "test", Path: "bad/original.js"})
	writeUnder("sighted/dup.js")
	writeUnder("bad/dup.js")
	addLocation(poolTieBreak, "sighted/dup.js", time.Now().Add(-time.Hour)) // more recently seen…
	addLocation(poolTieBreak, "bad/dup.js", time.Now().Add(-2*time.Hour))   // …but this is the label's own pool dir
	markMissing(poolTieBreak, "bad/original.js")

	// Dry-run: reports the fix but writes nothing.
	stats, err := db.RepairMissingLocations(ctx, root, false)
	if err != nil {
		t.Fatalf("RepairMissingLocations dry-run: %v", err)
	}
	if stats.Checked != 3 || stats.Fixed != 2 || stats.StillMissing != 1 {
		t.Errorf("dry-run stats = %+v, want {Checked:3 Fixed:2 StillMissing:1}", stats)
	}
	if skipOf(revivedElsewhere) != "missing" {
		t.Errorf("dry-run must not write: revivedElsewhere skip=%q", skipOf(revivedElsewhere))
	}

	// Apply: the fixes land.
	stats, err = db.RepairMissingLocations(ctx, root, true)
	if err != nil {
		t.Fatalf("RepairMissingLocations apply: %v", err)
	}
	if stats.Checked != 3 || stats.Fixed != 2 || stats.StillMissing != 1 {
		t.Errorf("apply stats = %+v, want {Checked:3 Fixed:2 StillMissing:1}", stats)
	}
	if got := skipOf(revivedElsewhere); got != "" {
		t.Errorf("revivedElsewhere skip=%q, want ''", got)
	}
	if got := pathOf(revivedElsewhere); got != "bad/old.js" {
		t.Errorf("revivedElsewhere path=%q, want 'bad/old.js'", got)
	}
	if got := skipOf(stillGone); got != "missing" {
		t.Errorf("stillGone skip=%q, want still 'missing'", got)
	}
	if got := skipOf(poolTieBreak); got != "" {
		t.Errorf("poolTieBreak skip=%q, want ''", got)
	}
	if got := pathOf(poolTieBreak); got != "bad/dup.js" {
		t.Errorf("poolTieBreak path=%q, want 'bad/dup.js' (label-pool match beats the more-recently-seen sighted/dup.js)", got)
	}

	var events int
	if err := db.lite.QueryRowContext(ctx,
		`SELECT count(*) FROM label_events WHERE sha256=? AND reason='repair-missing' AND from_skip='missing' AND to_skip=''`,
		revivedElsewhere).Scan(&events); err != nil {
		t.Fatal(err)
	}
	if events != 1 {
		t.Errorf("label_events for revivedElsewhere = %d, want 1", events)
	}
}

func TestPackageVersionPresentDoesNotChangeLabel(t *testing.T) {
	ctx := t.Context()
	db := openTestDB(t)
	purlBase := "pkg:npm/example"
	version := "1.2.3"
	presentSHA := sha64('8')
	missingSHA := sha64('9')
	metadataOnlySHA := sha64('7')
	for _, sample := range []*Sample{
		{SHA256: presentSHA, Path: "incoming/example-1.2.3.tgz", PURLBase: purlBase, Version: version, Label: "unknown", LabelSource: "forager"},
		{SHA256: missingSHA, Path: "incoming/example-2.0.0.tgz", PURLBase: purlBase, Version: "2.0.0", Label: "unknown", LabelSource: "forager", Skip: "missing"},
	} {
		if err := db.InsertSample(ctx, sample); err != nil {
			t.Fatal(err)
		}
	}
	// Producer inserts reject a sample with no bytes. Feed imports and old
	// catalogs can still contain such rows, which is the state this probe must
	// not confuse with an acquired package.
	if _, err := db.lite.ExecContext(ctx, `
		INSERT INTO samples (sha256, path, purl_base, version, label, label_source)
		VALUES (?, '', ?, '3.0.0', 'unknown', 'feed')`, metadataOnlySHA, purlBase); err != nil {
		t.Fatalf("insert metadata-only package row: %v", err)
	}

	present, err := db.PackageVersionPresent(ctx, purlBase, version)
	if err != nil || !present {
		t.Fatalf("PackageVersionPresent = %v, %v; want true, nil", present, err)
	}
	missing, err := db.PackageVersionPresent(ctx, purlBase, "2.0.0")
	if err != nil || missing {
		t.Fatalf("missing PackageVersionPresent = %v, %v; want false, nil", missing, err)
	}
	metadataOnly, err := db.PackageVersionPresent(ctx, purlBase, "3.0.0")
	if err != nil || metadataOnly {
		t.Fatalf("metadata-only PackageVersionPresent = %v, %v; want false, nil", metadataOnly, err)
	}
	blank, err := db.PackageVersionPresent(ctx, "", version)
	if err != nil || blank {
		t.Fatalf("blank PackageVersionPresent = %v, %v; want false, nil", blank, err)
	}

	sample, err := db.SampleBySHA256(ctx, presentSHA)
	if err != nil {
		t.Fatal(err)
	}
	if sample.Label != "unknown" || sample.LabelSource != "forager" {
		t.Fatalf("presence probe changed label state: %+v", sample)
	}
}

func mustRelabel(t *testing.T, ctx context.Context, db *DB, sha, label, source string) {
	t.Helper()
	if err := db.Reclassify(ctx, sha, label, source); err != nil {
		t.Fatalf("Reclassify(%s): %v", sha[:4], err)
	}
}

func TestCascadeLabel(t *testing.T) {
	ctx := context.Background()
	db := openTestDB(t)

	// label/source assertion helper.
	want := func(sha, label, source string) {
		t.Helper()
		s, err := db.SampleBySHA256(ctx, sha)
		if err != nil {
			t.Fatalf("SampleBySHA256(%s): %v", sha[:4], err)
		}
		if s.Label != label || s.LabelSource != source {
			t.Errorf("%s = {%q,%q}, want {%q,%q}", sha[:4], s.Label, s.LabelSource, label, source)
		}
	}
	countEvents := func(reason string) int {
		t.Helper()
		var n int
		if err := db.lite.QueryRowContext(ctx,
			`SELECT count(*) FROM label_events WHERE reason=?`, reason).Scan(&n); err != nil {
			t.Fatal(err)
		}
		return n
	}
	// member inserts a sample carried by archive `parent` with the given score,
	// fanned out into sample_locations by InsertSampleBatch.
	member := func(sha, parent string, score int) *Sample {
		return &Sample{
			SHA256: sha, Source: "test", Label: "unknown", LabelSource: "forager", Parent: parent,
			Path:         parent + "!!pkg/" + sha[:4] + ".js",
			CleaveResult: fmt.Appendf(nil, `{"fs":[{"sha":%q,"type":"js","x":%d,"dp":1}]}`, sha, score),
		}
	}

	// --- Demote: archive marked bad. ---
	archA := sha64('a')
	mustInsert(t, ctx, db, &Sample{SHA256: archA, Source: "test", Label: "unknown", LabelSource: "forager", Path: "unknown/a.tgz"})
	var (
		aHigh = sha64('b') // unknown, score 90 → demoted
		aMid  = sha64('c') // unknown, score 30 (== floor) → demoted
		aLow  = sha64('d') // unknown, score 10 (< floor) → untouched
		aGood = sha64('e') // good → untouched (no whitewash backward either)
		aBad  = sha64('f') // independently bad → untouched
	)
	if _, _, err := db.InsertSampleBatch(ctx, []*Sample{
		member(aHigh, archA, 90), member(aMid, archA, 30), member(aLow, archA, 10),
		member(aGood, archA, 90), member(aBad, archA, 90),
	}); err != nil {
		t.Fatalf("InsertSampleBatch: %v", err)
	}
	mustRelabel(t, ctx, db, aGood, "good", "test")
	mustRelabel(t, ctx, db, aBad, "bad", "test")

	n, err := db.CascadeLabel(ctx, archA, "bad", "promoter:interactive")
	if err != nil {
		t.Fatalf("CascadeLabel demote: %v", err)
	}
	if n != 2 {
		t.Errorf("demote cascaded %d members, want 2 (aHigh, aMid)", n)
	}
	want(archA, "bad", "promoter:interactive")
	want(aHigh, "bad", cascadeSource(archA))
	want(aMid, "bad", cascadeSource(archA))
	want(aLow, "unknown", "forager") // below score floor
	want(aGood, "good", "test")      // independent label preserved
	want(aBad, "bad", "test")        // independent label preserved
	if got := countEvents("cascade-demote"); got != 2 {
		t.Errorf("cascade-demote events = %d, want 2", got)
	}

	// --- Promote: archive marked good, including revert of a prior cascade-demote. ---
	archB := sha64('g')
	mustInsert(t, ctx, db, &Sample{SHA256: archB, Source: "test", Label: "unknown", LabelSource: "forager", Path: "unknown/g.tgz"})
	var (
		bUnk      = sha64('h') // unknown → promoted to good
		bBadIndep = sha64('i') // independently bad → untouched (no whitewash)
		bCascade  = sha64('j') // bad via this parent's cascade → reverted to good
	)
	if _, _, err := db.InsertSampleBatch(ctx, []*Sample{
		member(bUnk, archB, 5), member(bBadIndep, archB, 90), member(bCascade, archB, 90),
	}); err != nil {
		t.Fatalf("InsertSampleBatch: %v", err)
	}
	mustRelabel(t, ctx, db, bBadIndep, "bad", "test")
	mustRelabel(t, ctx, db, bCascade, "bad", cascadeSource(archB))

	n, err = db.CascadeLabel(ctx, archB, "good", "promoter:interactive")
	if err != nil {
		t.Fatalf("CascadeLabel promote: %v", err)
	}
	if n != 2 {
		t.Errorf("promote cascaded %d members, want 2 (bUnk promote, bCascade revert)", n)
	}
	want(archB, "good", "promoter:interactive")
	want(bUnk, "good", "promoter:interactive")     // unlabeled member follows
	want(bBadIndep, "bad", "test")                 // independent bad not whitewashed
	want(bCascade, "good", "promoter:interactive") // this parent's demote reverted
	if got := countEvents("cascade-promote"); got != 1 {
		t.Errorf("cascade-promote events = %d, want 1", got)
	}
	if got := countEvents("cascade-revert"); got != 1 {
		t.Errorf("cascade-revert events = %d, want 1", got)
	}
}

// TestCascadeLabelSightedMembers verifies that feed-claimed (sighted) members
// follow a verified parent the way unknown members do: a good parent vouches
// for them, a bad parent drags the suspicious ones along, and the demote
// score floor still applies.
func TestCascadeLabelSightedMembers(t *testing.T) {
	ctx := context.Background()
	db := openTestDB(t)

	want := func(sha, label, source string) {
		t.Helper()
		s, err := db.SampleBySHA256(ctx, sha)
		if err != nil {
			t.Fatalf("SampleBySHA256(%s): %v", sha[:4], err)
		}
		if s.Label != label || s.LabelSource != source {
			t.Errorf("%s = {%q,%q}, want {%q,%q}", sha[:4], s.Label, s.LabelSource, label, source)
		}
	}
	member := func(sha, parent string, score int) *Sample {
		return &Sample{
			SHA256: sha, Source: "test", Label: "sighted", LabelSource: "forager", Parent: parent,
			Path:         parent + "!!pkg/" + sha[:4] + ".js",
			CleaveResult: fmt.Appendf(nil, `{"fs":[{"sha":%q,"type":"js","x":%d,"dp":1}]}`, sha, score),
		}
	}

	// Bad parent: sighted members at/above the score floor demote, below stays.
	archA := sha64('k')
	mustInsert(t, ctx, db, &Sample{SHA256: archA, Source: "test", Label: "sighted", LabelSource: "forager", Path: "sighted/k.tgz"})
	aHot, aCold := sha64('l'), sha64('m')
	if _, _, err := db.InsertSampleBatch(ctx, []*Sample{member(aHot, archA, 90), member(aCold, archA, 10)}); err != nil {
		t.Fatalf("InsertSampleBatch: %v", err)
	}
	n, err := db.CascadeLabel(ctx, archA, "bad", "promoter")
	if err != nil {
		t.Fatalf("CascadeLabel demote: %v", err)
	}
	if n != 1 {
		t.Errorf("demote cascaded %d members, want 1 (aHot)", n)
	}
	want(aHot, "bad", cascadeSource(archA))
	want(aCold, "sighted", "forager") // below the score floor

	// Good parent: sighted members are vouched for regardless of score.
	archB := sha64('n')
	mustInsert(t, ctx, db, &Sample{SHA256: archB, Source: "test", Label: "sighted", LabelSource: "forager", Path: "sighted/n.tgz"})
	bMem := sha64('o')
	if _, _, err := db.InsertSampleBatch(ctx, []*Sample{member(bMem, archB, 90)}); err != nil {
		t.Fatalf("InsertSampleBatch: %v", err)
	}
	if _, err := db.CascadeLabel(ctx, archB, "good", "operator"); err != nil {
		t.Fatalf("CascadeLabel promote: %v", err)
	}
	want(bMem, "good", "operator")
}

func TestCascadeBackfill(t *testing.T) {
	ctx := context.Background()
	db := openTestDB(t)

	want := func(sha, label, source string) {
		t.Helper()
		s, err := db.SampleBySHA256(ctx, sha)
		if err != nil {
			t.Fatalf("SampleBySHA256(%s): %v", sha[:4], err)
		}
		if s.Label != label || s.LabelSource != source {
			t.Errorf("%s = {%q,%q}, want {%q,%q}", sha[:4], s.Label, s.LabelSource, label, source)
		}
	}
	member := func(sha, parent string, score int) *Sample {
		return &Sample{
			SHA256: sha, Source: "test", Label: "unknown", LabelSource: "forager", Parent: parent,
			Path:         parent + "!!pkg/" + sha[:4] + ".js",
			CleaveResult: fmt.Appendf(nil, `{"fs":[{"sha":%q,"type":"js","x":%d,"dp":1}]}`, sha, score),
		}
	}

	// An archive labeled bad before CascadeLabel existed: members still unknown.
	archBad := sha64('a')
	mustInsert(t, ctx, db, &Sample{SHA256: archBad, Source: "test", Label: "bad", LabelSource: "promoter:interactive", Path: "q/a.tgz"})
	var (
		bHigh  = sha64('b') // unknown, score 90 → demoted
		bLow   = sha64('c') // unknown, score 10 → left (below floor)
		shared = sha64('d') // unknown, score 90, also under archGood → bad wins (bad-first)
	)
	// An archive labeled good before CascadeLabel existed.
	archGood := sha64('e')
	mustInsert(t, ctx, db, &Sample{SHA256: archGood, Source: "test", Label: "good", LabelSource: "promoter:interactive", Path: "q/e.tgz"})
	gUnk := sha64('f') // unknown → promoted

	if _, _, err := db.InsertSampleBatch(ctx, []*Sample{
		member(bHigh, archBad, 90), member(bLow, archBad, 10), member(shared, archBad, 90),
		member(gUnk, archGood, 5),
	}); err != nil {
		t.Fatalf("InsertSampleBatch: %v", err)
	}
	// Give `shared` a second location under the good archive, so it is a member
	// of both. Bad-first must resolve it to bad.
	if _, err := db.lite.ExecContext(ctx,
		`INSERT INTO sample_locations (sha256, path, parent_sha256, first_seen_at, last_seen_at)
		 VALUES (?, ?, ?, ?, ?)`,
		shared, archGood+"!!pkg/dd.js", archGood, now(), now()); err != nil {
		t.Fatalf("insert shared location: %v", err)
	}

	// Pending probe should see work before the backfill.
	if pending, err := db.CascadeBackfillPending(ctx); err != nil || !pending {
		t.Fatalf("CascadeBackfillPending before = %v, %v; want true, nil", pending, err)
	}

	// Dry-run changes nothing and sums each archive independently, so `shared`
	// is counted in both the demote (archBad) and promote (archGood) totals.
	dry, err := db.CascadeBackfill(ctx, true)
	if err != nil {
		t.Fatalf("CascadeBackfill dry-run: %v", err)
	}
	if dry.BadArchives != 1 || dry.MembersDemoted != 2 {
		t.Errorf("dry-run bad = {%d archives, %d demoted}, want {1, 2}", dry.BadArchives, dry.MembersDemoted)
	}
	if dry.GoodArchives != 1 || dry.MembersPromoted != 2 {
		t.Errorf("dry-run good = {%d archives, %d promoted}, want {1, 2 (incl. shared)}", dry.GoodArchives, dry.MembersPromoted)
	}
	want(bHigh, "unknown", "forager") // dry-run wrote nothing
	want(gUnk, "unknown", "forager")

	// Apply: bad-first means `shared` is demoted, then the good pass skips it.
	got, err := db.CascadeBackfill(ctx, false)
	if err != nil {
		t.Fatalf("CascadeBackfill apply: %v", err)
	}
	if got.MembersDemoted != 2 || got.MembersPromoted != 1 {
		t.Errorf("apply = {%d demoted, %d promoted}, want {2, 1} (shared resolved bad-first)", got.MembersDemoted, got.MembersPromoted)
	}
	want(bHigh, "bad", cascadeSource(archBad))
	want(shared, "bad", cascadeSource(archBad)) // bad-first wins over the good archive
	want(bLow, "unknown", "forager")            // below the demote floor
	want(gUnk, "good", "promoter:interactive")  // promoted from the good archive

	// Nothing left to do, and re-running is a no-op.
	if pending, err := db.CascadeBackfillPending(ctx); err != nil || pending {
		t.Fatalf("CascadeBackfillPending after = %v, %v; want false, nil", pending, err)
	}
	again, err := db.CascadeBackfill(ctx, false)
	if err != nil {
		t.Fatalf("CascadeBackfill re-run: %v", err)
	}
	if again.MembersDemoted != 0 || again.MembersPromoted != 0 {
		t.Errorf("re-run = {%d demoted, %d promoted}, want {0, 0} (idempotent)", again.MembersDemoted, again.MembersPromoted)
	}
}

// TestReferenceEdgeMembersLabelledUnknown pins the label a reference-edge member
// is born with. A fetched/registry edge must not inherit the parent's label (a
// package naming a dependency says nothing about that dependency's bytes), but
// "unlabelled" has to mean labelUnknown, not "". Every triage selector matches
// the four pool labels exactly, so a member stored as "" is invisible to all of
// them and never gets judged on its own bytes — and nothing heals it later,
// since labelRank scores "" and 'unknown' alike and the upsert promotes only on
// a strictly greater rank. Contained members must still inherit.
func TestReferenceEdgeMembersLabelledUnknown(t *testing.T) {
	mk := func(i int) string { return fmt.Sprintf("%064x", i+1) }

	for _, tc := range []struct {
		name      string
		rel       Rel
		wantLabel string
		wantSrc   string
	}{
		{"contained inherits", RelContained, "bad", "ls"},
		{"unpacked inherits", RelUnpacked, "bad", "ls"},
		{"fetched stays unknown", RelFetched, labelUnknown, ""},
		{"registry stays unknown", RelRegistry, labelUnknown, ""},
	} {
		t.Run(tc.name, func(t *testing.T) {
			parent := &Sample{
				SHA256: mk(99), Source: "s", Feed: "fd", Ecosystem: "e",
				Label: "bad", LabelSource: "ls", Path: "bad/pkg.tar",
				CleaveResult: fmt.Appendf(nil,
					`{"files":[{"sha":%q,"type":"elf","path":"pkg/f.so","depth":1,"size":100,`+
						`"rel":%q,"traits":[{"crit":5,"conf":0.9}]}]}`, mk(0), string(tc.rel)),
			}
			members := memberSamplesFromEnvelope(parent)
			if len(members) != 1 {
				t.Fatalf("got %d members, want 1", len(members))
			}
			if got := members[0].Label; got != tc.wantLabel {
				t.Errorf("label = %q, want %q", got, tc.wantLabel)
			}
			if got := members[0].LabelSource; got != tc.wantSrc {
				t.Errorf("label_source = %q, want %q", got, tc.wantSrc)
			}
		})
	}
}

// TestNormalizeLabelCoercesZeroValue guards the write-boundary invariant: the
// label column is NOT NULL DEFAULT 'unknown', but every insert names the column
// explicitly, so the default never fires and a caller leaving Sample.Label at
// Go's zero value would otherwise persist "". Callers that do set a label keep
// it untouched.
func TestNormalizeLabelCoercesZeroValue(t *testing.T) {
	for _, tc := range []struct{ in, want string }{
		{"", labelUnknown},
		{labelUnknown, labelUnknown},
		{"good", "good"},
		{"bad", "bad"},
		{labelSighted, labelSighted},
	} {
		s := &Sample{SHA256: "a", Path: "p", Label: tc.in}
		normalizeLabel(s)
		if s.Label != tc.want {
			t.Errorf("normalizeLabel(%q) = %q, want %q", tc.in, s.Label, tc.want)
		}
	}
	normalizeLabel(nil) // must not panic
}

// TestMaxMemberLitmusClass covers the question TriageHighest's population asks:
// the selector keys on a hot MEMBER's class but returns the root archive, so a
// consumer holding a fresh scan of the archive needs the max over members, not
// the envelope's own class.
func TestMaxMemberLitmusClass(t *testing.T) {
	// Envelope-level lvl is benign; one member scores hostile.
	mixed := []byte(`{"v":"7","lvl":50000,"files":[
		{"id":0,"prob":0.01,"class":0},
		{"id":1,"prob":0.99,"class":2},
		{"id":2,"prob":0.30,"class":1}]}`)
	if got := MaxMemberLitmusClass(mixed); got != 2 {
		t.Errorf("mixed envelope = %d, want 2 (the hottest member)", got)
	}
	// The envelope's own class would have said otherwise — that is the bug this
	// helper exists to avoid.
	if env := LitmusClass(mixed); env >= 2 {
		t.Fatalf("fixture is not discriminating: envelope class = %d", env)
	}

	// All members cold: the archive has left the queue.
	cold := []byte(`{"v":"7","lvl":50000,"files":[
		{"id":0,"prob":0.01,"class":0},
		{"id":1,"prob":0.02,"class":0}]}`)
	if got := MaxMemberLitmusClass(cold); got != 0 {
		t.Errorf("cold envelope = %d, want 0", got)
	}

	// No member array: fall back to the envelope's own class.
	plain := []byte(`{"class":2}`)
	if got := MaxMemberLitmusClass(plain); got != 2 {
		t.Errorf("member-less envelope = %d, want the envelope class 2", got)
	}
	if got := MaxMemberLitmusClass(nil); got != 0 {
		t.Errorf("nil envelope = %d, want 0", got)
	}
}

// TestCandidateQueriesCarryCreatedAt verifies that every claim tier selects
// samples.created_at into ClaimJob.CreatedAt. That field is the entire basis of
// the hand-out age metric, and a tier that forgets it does not fail — it
// silently contributes nothing, so the queue-lag panel under-reports by exactly
// the tiers that dropped it, which is the failure this pins down.
//
// Runs against the SQLite backend, where created_at is a DATETIME string that
// has to survive sqliteNullTime's layout list; the PG path scans a native
// timestamptz and cannot fail this way.
func TestCandidateQueriesCarryCreatedAt(t *testing.T) {
	db := openTestDB(t)
	ctx := context.Background()

	mustInsert(t, ctx, db, &Sample{SHA256: "agefresh", Path: "/data/fresh.exe", Label: "bad"})
	mustInsert(t, ctx, db, &Sample{SHA256: "ageupload", Path: "/data/up.exe", Label: "bad", Source: "upload"})
	if _, err := db.QueueRescan(ctx, []string{"agefresh"}); err != nil {
		t.Fatal(err)
	}

	before := time.Now().Add(-time.Minute)
	tiers := map[string]func() ([]ClaimJob, error){
		"unanalyzed": func() ([]ClaimJob, error) { return db.UnanalyzedCandidates(ctx, time.Now(), 10) },
		"upload":     func() ([]ClaimJob, error) { return db.UploadCandidates(ctx, 10) },
		"repair":     func() ([]ClaimJob, error) { return db.RepairCandidates(ctx, 10) },
	}
	for name, fn := range tiers {
		jobs, err := fn()
		if err != nil {
			t.Fatalf("%s candidates: %v", name, err)
		}
		if len(jobs) == 0 {
			t.Fatalf("%s candidates returned nothing; the fixture no longer exercises this tier", name)
		}
		for _, j := range jobs {
			if j.CreatedAt.IsZero() {
				t.Errorf("%s tier: %s has zero CreatedAt; the tier query dropped created_at", name, j.SHA256)
				continue
			}
			if j.CreatedAt.Before(before) {
				t.Errorf("%s tier: %s CreatedAt = %v, want a just-inserted timestamp after %v",
					name, j.SHA256, j.CreatedAt, before)
			}
		}
	}
}

// Purgatory outranks every observed label so a walk or feed claim cannot undo
// an operator's greyware ruling, and the SQL rendering must agree with the Go
// one or the upsert and the logging path disagree about the same transition.
func TestLabelRankPurgatoryOutranksObservations(t *testing.T) {
	for _, lower := range []string{labelBad, labelGood, labelSighted, labelUnknown, ""} {
		if labelRank(labelPurgatory) <= labelRank(lower) {
			t.Fatalf("purgatory rank %d does not outrank %q (%d)",
				labelRank(labelPurgatory), lower, labelRank(lower))
		}
	}
	// Ordering below purgatory is unchanged.
	if labelRank(labelBad) <= labelRank(labelGood) ||
		labelRank(labelGood) <= labelRank(labelSighted) ||
		labelRank(labelSighted) <= labelRank(labelUnknown) {
		t.Fatal("existing label precedence changed")
	}
	rankSQL := labelRankSQL("x")
	for _, want := range []string{"'purgatory' THEN 4", "'bad' THEN 3", "'good' THEN 2", "'sighted' THEN 1"} {
		if !strings.Contains(rankSQL, want) {
			t.Fatalf("labelRankSQL missing %q: %s", want, rankSQL)
		}
	}
}

// TestFeedSamplesCreatedWindow covers the half-open [Since, Until) created_at
// bound: what it includes at each edge, that select and count agree on it, and
// that walking Until down over a capped Limit reaches every row in a period —
// the paging prism's fallout log does to render a whole week without the row
// cap deciding how much history it shows.
func TestFeedSamplesCreatedWindow(t *testing.T) {
	db := openTestDB(t)
	ctx := context.Background()

	// Monday 00:00 UTC, the kind of boundary a calendar week is cut on.
	weekStart := time.Date(2026, 8, 24, 0, 0, 0, 0, time.UTC)
	created := map[string]time.Time{
		"aa01": weekStart.Add(-time.Second),                  // the instant before the window
		"aa02": weekStart,                                    // the window's first instant
		"aa03": weekStart.Add(36 * time.Hour),                // mid-week
		"aa04": weekStart.Add(6*24*time.Hour + 23*time.Hour), // last day
		"aa05": weekStart.AddDate(0, 0, 7),                   // the next week's first instant
	}
	for sha, at := range created {
		mustInsert(t, ctx, db, &Sample{SHA256: sha, Source: "test"})
		if err := db.UpdateCleaveResult(ctx, sha, []byte(`{"fs":[{"sha":"`+sha+`","type":"elf","dp":0}]}`), nil, ""); err != nil {
			t.Fatal(err)
		}
		if _, err := db.lite.ExecContext(ctx,
			`UPDATE samples SET created_at = ? WHERE sha256 = ?`,
			at.Format(time.RFC3339Nano), sha); err != nil {
			t.Fatal(err)
		}
	}

	shas := func(q FeedQuery) []string {
		q.Source = "test"
		q.OrderBy = "created_at"
		if q.Limit == 0 {
			q.Limit = 10
		}
		samples, err := db.FeedSamples(ctx, &q)
		if err != nil {
			t.Fatal(err)
		}
		count, err := db.FeedSamplesCount(ctx, &q)
		if err != nil {
			t.Fatal(err)
		}
		if q.Limit >= 10 && count != len(samples) {
			t.Errorf("count %d disagrees with %d rows", count, len(samples))
		}
		out := make([]string, len(samples))
		for i, s := range samples {
			out[i] = s.SHA256
		}
		return out
	}

	weekEnd := weekStart.AddDate(0, 0, 7)
	for _, tt := range []struct {
		name         string
		since, until time.Time
		want         []string
	}{
		{"unbounded", time.Time{}, time.Time{}, []string{"aa05", "aa04", "aa03", "aa02", "aa01"}},
		{"one week", weekStart, weekEnd, []string{"aa04", "aa03", "aa02"}},
		{"open end", weekStart, time.Time{}, []string{"aa05", "aa04", "aa03", "aa02"}},
		{"open start", time.Time{}, weekEnd, []string{"aa04", "aa03", "aa02", "aa01"}},
		{"empty period", weekEnd.AddDate(0, 0, 7), weekEnd.AddDate(0, 0, 14), nil},
	} {
		t.Run(tt.name, func(t *testing.T) {
			if got := shas(FeedQuery{Since: tt.since, Until: tt.until}); !slices.Equal(got, tt.want) {
				t.Errorf("[%v, %v) = %v, want %v", tt.since, tt.until, got, tt.want)
			}
		})
	}

	// Paging a period out one row at a time: each page asks for what is left
	// below the oldest row it has seen. The cap bounds the page, never the
	// period, and no row is served twice or skipped.
	t.Run("pages the whole period", func(t *testing.T) {
		var walked []string
		until := weekEnd
		for range 10 {
			page := shas(FeedQuery{Since: weekStart, Until: until, Limit: 1})
			if len(page) == 0 {
				break
			}
			walked = append(walked, page...)
			until = created[page[len(page)-1]]
		}
		want := []string{"aa04", "aa03", "aa02"}
		if !slices.Equal(walked, want) {
			t.Errorf("paged walk = %v, want %v", walked, want)
		}
	})
}

// TestValidSampleRejectsTrivialFiles pins the shared ingest floor: an empty
// file (recognized by its digest, whatever size the caller reported) and any
// row under MinSampleSize are refused, while a row whose size was never
// learned still passes.
func TestValidSampleRejectsTrivialFiles(t *testing.T) {
	sha := fmt.Sprintf("%064x", 1)
	tests := []struct {
		name   string
		sample *Sample
		want   bool
	}{
		{"empty digest", &Sample{SHA256: emptySHA256, Path: "incoming/empty", SizeBytes: 8}, false},
		{"empty digest with claimed size", &Sample{SHA256: emptySHA256, Path: "incoming/empty", SizeBytes: 42}, false},
		{"below floor", &Sample{SHA256: sha, Path: "incoming/tiny", SizeBytes: MinSampleSize - 1}, false},
		{"at floor", &Sample{SHA256: sha, Path: "incoming/small", SizeBytes: MinSampleSize}, true},
		{"size unknown", &Sample{SHA256: sha, Path: "incoming/f"}, true},
	}
	for _, tt := range tests {
		if got := validSample(tt.sample); got != tt.want {
			t.Errorf("%s: validSample = %v, want %v", tt.name, got, tt.want)
		}
	}
}

// TestMemberSamplesFromEnvelopeSkipsTrivialMembers verifies that the archive
// member path drops empty and under-floor members. It bypasses validSample on
// the Postgres side, so the filter has to hold here.
func TestMemberSamplesFromEnvelopeSkipsTrivialMembers(t *testing.T) {
	keep := fmt.Sprintf("%064x", 7)
	tiny := fmt.Sprintf("%064x", 8)
	parent := &Sample{
		SHA256: fmt.Sprintf("%064x", 99), Label: "bad", LabelSource: "ls", Path: "bad/pkg.tar",
		CleaveResult: []byte(`{"files":[` +
			fmt.Sprintf(`{"sha":%q,"type":"elf","path":"pkg/real.so","depth":1,"size":100},`, keep) +
			fmt.Sprintf(`{"sha":%q,"type":"text","path":"pkg/tiny.txt","depth":1,"size":3},`, tiny) +
			fmt.Sprintf(`{"sha":%q,"type":"text","path":"pkg/empty.txt","depth":1,"size":0}`, emptySHA256) +
			`]}`),
	}

	members := memberSamplesFromEnvelope(parent)
	if len(members) != 1 {
		t.Fatalf("got %d members, want 1: %+v", len(members), members)
	}
	if members[0].SHA256 != keep {
		t.Errorf("kept member = %s, want %s", members[0].SHA256, keep)
	}
}
