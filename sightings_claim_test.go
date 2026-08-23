package hopper

import (
	"fmt"
	"testing"
	"time"
)

func addSightings(t *testing.T, db *DB, s ...Sighting) {
	t.Helper()
	if _, err := db.AddSightings(t.Context(), s); err != nil {
		t.Fatalf("AddSightings: %v", err)
	}
}

func sightingsFor(t *testing.T, db *DB, subject string) []Sighting {
	t.Helper()
	got, err := db.SightingsFor(t.Context(), []string{subject})
	if err != nil {
		t.Fatalf("SightingsFor: %v", err)
	}
	return got[subject]
}

// One source can make two SEPARATE claims about one package: ossf carries a
// report for @whalent/agent 0.3.230-0.3.302 and another for 0.3.358. Keyed on
// (source, subject) alone, the second silently replaced the first.
func TestSightingsKeepOneClaimPerVersionRange(t *testing.T) {
	db := openTestDB(t)
	// Stored in the ledger's canonical spelling: normalizeSubject percent-
	// encodes the scope, and SightingsFor matches on exactly what is stored.
	const written = "pkg:npm/@whalent/agent"
	subject := normalizeSubject(written)

	addSightings(t, db,
		Sighting{Source: "ossf", Subject: written, Affected: "0.3.230, 0.3.302", Note: "MAL-2026-10721"},
		Sighting{Source: "ossf", Subject: written, Affected: "0.3.358", Note: "MAL-0000"},
		Sighting{Source: "ossf", Subject: written, Note: "the package as a whole"},
	)

	got := sightingsFor(t, db, subject)
	if len(got) != 3 {
		t.Fatalf("got %d claims, want one per distinct version range: %+v", len(got), got)
	}
	seen := map[string]string{}
	for _, s := range got {
		seen[s.Affected] = s.Note
	}
	for affected, note := range map[string]string{
		"0.3.230, 0.3.302": "MAL-2026-10721",
		"0.3.358":          "MAL-0000",
		"":                 "the package as a whole",
	} {
		if seen[affected] != note {
			t.Errorf("claim for %q = %q, want %q", affected, seen[affected], note)
		}
	}
}

// Adopting a feed must not present its whole history as today's news. The last
// bulk load of this ledger put 103,825 rows in on one day; every one of them
// would have answered "reported in the last 48 hours".
func TestFirstBulkImportIsBackdated(t *testing.T) {
	db := openTestDB(t)

	backlog := make([]Sighting, sightingSeedBatch)
	for i := range backlog {
		backlog[i] = Sighting{Source: "aikido", Subject: fmt.Sprintf("pkg:npm/p%d", i)}
	}
	addSightings(t, db, backlog...)

	got := sightingsFor(t, db, "pkg:npm/p0")
	if len(got) != 1 {
		t.Fatalf("got %d sightings, want 1", len(got))
	}
	if got[0].FirstSeen.After(time.Now().Add(-24 * time.Hour)) {
		t.Errorf("FirstSeen = %v; a backlog import must not read as news", got[0].FirstSeen)
	}

	// What arrives AFTER the source is known is news, however small the batch.
	addSightings(t, db, Sighting{Source: "aikido", Subject: "pkg:npm/fresh"})
	fresh := sightingsFor(t, db, "pkg:npm/fresh")
	if len(fresh) != 1 || fresh[0].FirstSeen.Before(time.Now().Add(-time.Hour)) {
		t.Errorf("FirstSeen = %+v; a later arrival is news", fresh)
	}
}

// A per-hash lookup contributes one row at a time. Backdating it would hide
// real new evidence — which is exactly how it broke TriageSecondOpinion.
func TestSmallFirstBatchIsNews(t *testing.T) {
	db := openTestDB(t)
	sha := fmt.Sprintf("%064x", 1234)

	addSightings(t, db, Sighting{Source: "virustotal", Subject: sha, Note: "17 of 70 engines"})

	got := sightingsFor(t, db, sha)
	if len(got) != 1 {
		t.Fatalf("got %d sightings, want 1", len(got))
	}
	if got[0].FirstSeen.Before(time.Now().Add(-time.Hour)) {
		t.Errorf("FirstSeen = %v; one row from an unknown source is news, not a backlog", got[0].FirstSeen)
	}
}

// The source's date and ours answer different questions. A 2019 VirusTotal
// record looked up today is not a zero-day.
func TestPublishedAtIsSeparateFromFirstSeen(t *testing.T) {
	db := openTestDB(t)
	sha := fmt.Sprintf("%064x", 4321)
	published := time.Date(2019, 3, 1, 12, 0, 0, 0, time.UTC)

	addSightings(t, db, Sighting{Source: "virustotal", Subject: sha, PublishedAt: published})

	got := sightingsFor(t, db, sha)
	if len(got) != 1 {
		t.Fatalf("got %d sightings, want 1", len(got))
	}
	if !got[0].PublishedAt.Equal(published) {
		t.Errorf("PublishedAt = %v, want %v", got[0].PublishedAt, published)
	}
	if got[0].FirstSeen.Before(time.Now().Add(-time.Hour)) {
		t.Errorf("FirstSeen = %v, want the moment we learned it", got[0].FirstSeen)
	}
}

// A feed that publishes no date must not have one invented for it.
func TestUndatedSourceHasNoPublishedAt(t *testing.T) {
	db := openTestDB(t)
	addSightings(t, db, Sighting{Source: "malshare", Subject: fmt.Sprintf("%064x", 99)})

	got := sightingsFor(t, db, fmt.Sprintf("%064x", 99))
	if len(got) != 1 {
		t.Fatalf("got %d sightings, want 1", len(got))
	}
	if !got[0].PublishedAt.IsZero() {
		t.Errorf("PublishedAt = %v, want zero — the source publishes no date", got[0].PublishedAt)
	}
}

// Mirrors of one corpus are one voice. A writer that says nothing about its
// operator gets the family map, so counts do not change under the migration.
func TestOperatorDefaultsToTheFamily(t *testing.T) {
	db := openTestDB(t)
	const subject = "pkg:npm/evil"

	addSightings(t, db,
		Sighting{Source: "osv", Subject: subject},
		Sighting{Source: "ossf", Subject: subject},
		Sighting{Source: "aikido", Subject: subject, Operator: "aikido"},
	)

	operators := map[string]int{}
	for _, s := range sightingsFor(t, db, subject) {
		operators[s.Operator]++
	}
	if operators["ossf-malpkgs"] != 2 {
		t.Errorf("osv and ossf report %v, want both folded onto one corpus", operators)
	}
	if len(operators) != 2 {
		t.Errorf("got %d operators for 3 sources, want 2 — mirrors count once: %v", len(operators), operators)
	}
}

// Every row written before the column existed meant malware, so that is what an
// unsaid claim means. A capability scanner's suspicion must be storable as what
// it is, or it corroborates malware.
func TestClaimDefaultsToMaliciousAndKeepsWhatIsSaid(t *testing.T) {
	db := openTestDB(t)
	const subject = "pkg:github/acme/skills"

	addSightings(t, db,
		Sighting{Source: "osv", Subject: subject},
		Sighting{Source: "manifest", Subject: subject, Claim: ClaimSuspicious, Affected: "1.0"},
		Sighting{Source: "ghsa", Subject: subject, Claim: ClaimVulnerable, Affected: "<2.0"},
	)

	claims := map[string]SightingClaim{}
	for _, s := range sightingsFor(t, db, subject) {
		claims[s.Source] = s.Claim
	}
	for source, want := range map[string]SightingClaim{
		"osv":      ClaimMalicious,
		"manifest": ClaimSuspicious,
		"ghsa":     ClaimVulnerable,
	} {
		if claims[source] != want {
			t.Errorf("%s claim = %q, want %q", source, claims[source], want)
		}
	}
}

// Re-recording what we already know must not move the clock, or every re-walk
// of a feed would present its whole contents as new.
func TestRewritingAClaimKeepsItsFirstSeen(t *testing.T) {
	db := openTestDB(t)
	const subject = "pkg:npm/steady"

	addSightings(t, db, Sighting{Source: "lpm", Subject: subject, Note: "first"})
	before := sightingsFor(t, db, subject)[0].FirstSeen

	time.Sleep(5 * time.Millisecond)
	addSightings(t, db, Sighting{Source: "lpm", Subject: subject, Note: "reworded"})

	after := sightingsFor(t, db, subject)
	if len(after) != 1 {
		t.Fatalf("got %d rows, want the claim updated in place", len(after))
	}
	if !after[0].FirstSeen.Equal(before) {
		t.Errorf("FirstSeen moved from %v to %v", before, after[0].FirstSeen)
	}
	if after[0].Note != "reworded" {
		t.Errorf("note = %q, want the source's newer words", after[0].Note)
	}
}

// FileName is evidence, never identity: the same payload reaches a malware
// repository under many names, and building a subject from one of them is what
// put 1,050 unmatchable rows in this table.
func TestFileNameIsCarried(t *testing.T) {
	db := openTestDB(t)
	sha := fmt.Sprintf("%064x", 555)

	addSightings(t, db, Sighting{Source: "bazaar", Subject: sha, FileName: "Prestige Launcher.exe"})

	got := sightingsFor(t, db, sha)
	if len(got) != 1 || got[0].FileName != "Prestige Launcher.exe" {
		t.Errorf("got %+v, want the name it was seen under", got)
	}
}

// A caller holding the ordinary spelling of a scoped package must not be told
// the ledger knows nothing, while the row sits under the canonical one. Silence
// is the most dangerous wrong answer here and reads exactly like the truthful
// kind.
func TestSightingsForAcceptsEitherSpelling(t *testing.T) {
	db := openTestDB(t)
	const written = "pkg:npm/@scope/pkg"
	canon := normalizeSubject(written)
	if canon == written {
		t.Skip("nothing to prove: this subject is already canonical")
	}

	addSightings(t, db, Sighting{Source: "ghsa", Subject: written, Note: "MAL-1"})

	got, err := db.SightingsFor(t.Context(), []string{written})
	if err != nil {
		t.Fatalf("SightingsFor: %v", err)
	}
	if len(got[written]) != 1 {
		t.Errorf("asking with %q found %d sightings, want 1", written, len(got[written]))
	}
	// And the canonical spelling still answers, for callers that hold it.
	if len(got[canon]) != 1 {
		t.Errorf("asking with %q found %d sightings, want 1", canon, len(got[canon]))
	}
}

// A version-pinned PURL and its version-less base are the same subject to this
// ledger, and a caller that has the pinned one should not have to know that.
func TestSightingsForFoldsAVersionedPURL(t *testing.T) {
	db := openTestDB(t)
	addSightings(t, db, Sighting{Source: "osv", Subject: "pkg:npm/evil", Affected: "1.2.3"})

	got, err := db.SightingsFor(t.Context(), []string{"pkg:npm/evil@1.2.3"})
	if err != nil {
		t.Fatalf("SightingsFor: %v", err)
	}
	if len(got["pkg:npm/evil@1.2.3"]) != 1 {
		t.Errorf("a pinned purl found %d sightings, want the base subject's 1", len(got["pkg:npm/evil@1.2.3"]))
	}
}

// Dropping a source is the bootstrap half of a reseed: the old rows record only
// that somebody flagged something, and a re-walk cannot correct them in place
// because a version-less row and a versioned one are different keys.
func TestDropSightingsRemovesOnlyTheNamedSources(t *testing.T) {
	db := openTestDB(t)
	const subject = "pkg:npm/evil"

	addSightings(t, db,
		Sighting{Source: "aikido", Subject: subject},
		Sighting{Source: "osv", Subject: subject},
		Sighting{Source: "virustotal", Subject: subject},
	)

	counts, err := db.DropSightings(t.Context(), []string{"aikido", "osv"}, true)
	if err != nil {
		t.Fatalf("DropSightings(dry run): %v", err)
	}
	if counts["aikido"] != 1 || counts["osv"] != 1 {
		t.Errorf("dry run counted %v, want one row each", counts)
	}
	if len(sightingsFor(t, db, subject)) != 3 {
		t.Fatal("a dry run must not delete anything")
	}

	if _, err := db.DropSightings(t.Context(), []string{"aikido", "osv"}, false); err != nil {
		t.Fatalf("DropSightings: %v", err)
	}
	left := sightingsFor(t, db, subject)
	if len(left) != 1 || left[0].Source != "virustotal" {
		t.Errorf("left %+v, want only the source nobody asked to drop", left)
	}
}

// The corroborated flag is denormalized, and a drop deliberately leaves it
// alone: recomputing it costs two sequential scans of a 91.7-million row table,
// and the rebuild that follows a drop re-cites most of what was orphaned. The
// reconcile is a separate, batched step run once afterwards.
func TestDropSightingsLeavesTheFlagForTheReconcile(t *testing.T) {
	ctx := t.Context()
	db := openTestDB(t)

	sha := fmt.Sprintf("%064x", 31337)
	mustInsert(t, ctx, db, &Sample{SHA256: sha, Source: "test", Label: "unknown", LabelSource: "test"})
	addSightings(t, db, Sighting{Source: "aikido", Subject: sha})

	corroborated := func() bool {
		t.Helper()
		s, err := db.SampleBySHA256(ctx, sha)
		if err != nil {
			t.Fatalf("SampleBySHA256: %v", err)
		}
		return s.Corroborated
	}
	if !corroborated() {
		t.Fatal("recording a sighting should corroborate the sample")
	}

	if _, err := db.DropSightings(ctx, []string{"aikido"}, false); err != nil {
		t.Fatalf("DropSightings: %v", err)
	}
	if !corroborated() {
		t.Error("the drop must not pay for the reconcile; the flag stands until asked")
	}

	cleared, err := db.ReconcileCorroborated(ctx)
	if err != nil {
		t.Fatalf("ReconcileCorroborated: %v", err)
	}
	if cleared != 1 {
		t.Errorf("cleared %d samples, want the one with no remaining citation", cleared)
	}
	if corroborated() {
		t.Error("a sample whose only evidence was dropped is not corroborated")
	}

	// Idempotent: a second pass has nothing left to do, so an interrupted run
	// can simply be repeated.
	again, err := db.ReconcileCorroborated(ctx)
	if err != nil {
		t.Fatalf("ReconcileCorroborated (again): %v", err)
	}
	if again != 0 {
		t.Errorf("second pass cleared %d, want none", again)
	}
}

// A sample still cited by something else keeps its flag.
func TestDropSightingsKeepsCorroborationWithRemainingEvidence(t *testing.T) {
	ctx := t.Context()
	db := openTestDB(t)

	sha := fmt.Sprintf("%064x", 31338)
	mustInsert(t, ctx, db, &Sample{SHA256: sha, Source: "test", Label: "unknown", LabelSource: "test"})
	addSightings(t, db,
		Sighting{Source: "aikido", Subject: sha},
		Sighting{Source: "virustotal", Subject: sha},
	)

	if _, err := db.DropSightings(ctx, []string{"aikido"}, false); err != nil {
		t.Fatalf("DropSightings: %v", err)
	}
	if _, err := db.ReconcileCorroborated(ctx); err != nil {
		t.Fatalf("ReconcileCorroborated: %v", err)
	}
	s, err := db.SampleBySHA256(ctx, sha)
	if err != nil {
		t.Fatalf("SampleBySHA256: %v", err)
	}
	if !s.Corroborated {
		t.Error("evidence remains, so the flag should stand")
	}
}
