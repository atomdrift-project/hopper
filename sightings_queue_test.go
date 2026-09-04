package hopper

import (
	"context"
	"testing"
	"time"
)

// mustPendingSample inserts a top-level sample and leaves it unanalyzed, so it
// sits in the claim queue the way a freshly-walked file does.
func mustPendingSample(t *testing.T, ctx context.Context, db *DB, sha, purlBase string) {
	t.Helper()
	mustInsert(t, ctx, db, &Sample{
		SHA256:      sha,
		Source:      "forager",
		Label:       "unknown",
		LabelSource: "forager",
		PURLBase:    purlBase,
		Path:        "incoming/" + sha,
		SizeBytes:   8,
	})
}

func corroborated(t *testing.T, ctx context.Context, db *DB, sha string) bool {
	t.Helper()
	var flag bool
	if err := db.lite.QueryRowContext(ctx,
		`SELECT corroborated FROM samples WHERE sha256 = ?`, sha).Scan(&flag); err != nil {
		t.Fatalf("read corroborated for %s: %v", sha, err)
	}
	return flag
}

const (
	shaSightingFirst = "1a11111111111111111111111111111111111111111111111111111111111111"
	shaSampleFirst   = "1b11111111111111111111111111111111111111111111111111111111111111"
	shaPurlFirst     = "1c11111111111111111111111111111111111111111111111111111111111111"
	shaUncited       = "1d11111111111111111111111111111111111111111111111111111111111111"
)

// TestCorroboratedSurvivesEitherArrivalOrder is the invariant the sighted claim
// tier rests on: however a citation and the bytes it names reach us, the flag
// ends up true.
//
// The sighting-first order is the one that used to lose. AddSightings is
// delta-guarded, so re-pushing an unchanged feed snapshot returns no subject and
// marks nothing, and a sample inserted afterwards stayed unflagged forever —
// 9,845 pending production rows on 2026-08-24, three quarters of the sighted
// backlog. Nothing on the sightings side can fix that; there is no event left to
// fire on. The ingest side has to look.
func TestCorroboratedSurvivesEitherArrivalOrder(t *testing.T) {
	ctx := context.Background()
	db := openTestDB(t)

	// Sighting first, then the bytes it names.
	if _, err := db.AddSightings(ctx, []Sighting{
		{Source: "osv", Subject: shaSightingFirst, Note: "malware"},
	}); err != nil {
		t.Fatalf("AddSightings: %v", err)
	}
	mustPendingSample(t, ctx, db, shaSightingFirst, "")
	if !corroborated(t, ctx, db, shaSightingFirst) {
		t.Error("sample that arrived after its sighting is not corroborated")
	}

	// Bytes first, then the citation.
	mustPendingSample(t, ctx, db, shaSampleFirst, "")
	if corroborated(t, ctx, db, shaSampleFirst) {
		t.Fatal("sample is corroborated before anything cited it")
	}
	if _, err := db.AddSightings(ctx, []Sighting{
		{Source: "osv", Subject: shaSampleFirst, Note: "malware"},
	}); err != nil {
		t.Fatalf("AddSightings: %v", err)
	}
	if !corroborated(t, ctx, db, shaSampleFirst) {
		t.Error("sample cited after it arrived is not corroborated")
	}

	// The same, by package identity rather than digest: a feed names the
	// package, and a later release of it lands.
	if _, err := db.AddSightings(ctx, []Sighting{
		{Source: "ossf", Subject: "pkg:npm/evil", Note: "malware"},
	}); err != nil {
		t.Fatalf("AddSightings: %v", err)
	}
	mustPendingSample(t, ctx, db, shaPurlFirst, "pkg:npm/evil")
	if !corroborated(t, ctx, db, shaPurlFirst) {
		t.Error("sample whose purl_base was already cited is not corroborated")
	}

	// A sample nothing cites stays unflagged, or the tier means nothing.
	mustPendingSample(t, ctx, db, shaUncited, "pkg:npm/fine")
	if corroborated(t, ctx, db, shaUncited) {
		t.Error("uncited sample is corroborated")
	}
}

// TestCorroboratedSurvivesAWriterThatSkipsAddSightings is the reason the
// invariant lives in the database rather than in Go.
//
// AddSightings maintained the flag; canonicalizeSightingSubjects, which re-keys
// a subject as INSERT + DELETE, did not, and neither would a row inserted by
// hand in psql. Writing directly to the ledger here stands in for all of them:
// if this passes, no writer can add a citation the flag does not follow.
func TestCorroboratedSurvivesAWriterThatSkipsAddSightings(t *testing.T) {
	ctx := context.Background()
	db := openTestDB(t)

	const sha = "2a22222222222222222222222222222222222222222222222222222222222222"
	mustPendingSample(t, ctx, db, sha, "pkg:npm/direct")

	if _, err := db.lite.ExecContext(ctx,
		`INSERT INTO sightings (source, subject, affected, claim, note)
		 VALUES ('hand-written', ?, '', 'malicious', 'bypasses AddSightings')`,
		sha); err != nil {
		t.Fatalf("direct sightings insert: %v", err)
	}
	if !corroborated(t, ctx, db, sha) {
		t.Error("a direct INSERT into sightings did not flip samples.corroborated")
	}

	// And by purl_base, which is the arm a single-column rule makes easy to
	// drop: the two statements are separate precisely so neither is OR'd into
	// a scan, which also means either one can go missing on its own.
	const purlSHA = "2b22222222222222222222222222222222222222222222222222222222222222"
	mustPendingSample(t, ctx, db, purlSHA, "pkg:pypi/handwritten")
	if _, err := db.lite.ExecContext(ctx,
		`INSERT INTO sightings (source, subject, affected, claim, note)
		 VALUES ('hand-written', 'pkg:pypi/handwritten', '', 'malicious', '')`); err != nil {
		t.Fatalf("direct sightings insert: %v", err)
	}
	if !corroborated(t, ctx, db, purlSHA) {
		t.Error("a direct INSERT naming a purl_base did not flip samples.corroborated")
	}
}

// TestCorroboratedIsNotGradedByClaim pins the semantics the claim tiers depend
// on: any citation counts. A 'suspicious' claim ranks a sample exactly as a
// 'malicious' one does. The graded notion of corroboration is the
// DISTINCT-operator count over the ledger, which is a different question and
// deliberately not this bit.
func TestCorroboratedIsNotGradedByClaim(t *testing.T) {
	ctx := context.Background()
	db := openTestDB(t)

	const sha = "3a33333333333333333333333333333333333333333333333333333333333333"
	mustPendingSample(t, ctx, db, sha, "")
	if _, err := db.AddSightings(ctx, []Sighting{
		{Source: "capability-scanner", Subject: sha, Claim: ClaimSuspicious, Note: "reads /etc/passwd"},
	}); err != nil {
		t.Fatalf("AddSightings: %v", err)
	}
	if !corroborated(t, ctx, db, sha) {
		t.Error("a 'suspicious' claim did not corroborate; the tier would skip it")
	}
}

// TestSightedCandidatesReturnsOnlyCitedPendingWork guards the tier's predicate.
// It drains before the main backlog, so anything that leaks in jumps 537k rows
// of queue ahead of its turn.
func TestSightedCandidatesReturnsOnlyCitedPendingWork(t *testing.T) {
	ctx := context.Background()
	db := openTestDB(t)

	const (
		cited    = "4a44444444444444444444444444444444444444444444444444444444444444"
		uncited  = "4b44444444444444444444444444444444444444444444444444444444444444"
		analyzed = "4c44444444444444444444444444444444444444444444444444444444444444"
	)
	for _, sha := range []string{cited, uncited, analyzed} {
		mustPendingSample(t, ctx, db, sha, "")
	}
	if _, err := db.AddSightings(ctx, []Sighting{
		{Source: "osv", Subject: cited, Note: "malware"},
		{Source: "osv", Subject: analyzed, Note: "malware"},
	}); err != nil {
		t.Fatalf("AddSightings: %v", err)
	}
	// A cited sample that already has results is finished work, not queue work.
	mustAnalyze(t, ctx, db, analyzed, 10)

	jobs, err := db.SightedCandidates(ctx, time.Now(), 10)
	if err != nil {
		t.Fatalf("SightedCandidates: %v", err)
	}
	if len(jobs) != 1 || jobs[0].SHA256 != cited {
		t.Fatalf("SightedCandidates = %+v, want exactly the cited pending sample %s", jobs, cited)
	}
}

// TestStaleTraitsPrefersCorroborated pins corroborated as the LEADING sort key
// of the rescan tier: a stale verdict on a sample the outside world has cited is
// refreshed before one nothing has, even when every other ranking signal favours
// the uncited row.
//
// The uncited sample here is a label disagreement sitting on the litmus
// boundary — the top of the old ordering. If corroboration is not leading, it
// comes back first and this fails.
func TestStaleTraitsPrefersCorroborated(t *testing.T) {
	ctx := context.Background()
	db := openTestDB(t)

	const (
		citedDull      = "5a55555555555555555555555555555555555555555555555555555555555555"
		uncitedUrgent  = "5b55555555555555555555555555555555555555555555555555555555555555"
		uncitedOrdinar = "5c55555555555555555555555555555555555555555555555555555555555555"
	)
	// citedDull agrees with its label and sits far from the boundary: last by
	// every signal except corroboration.
	mustInsert(t, ctx, db, &Sample{SHA256: citedDull, Source: "test", Label: "bad", LabelSource: "test"})
	mustAnalyzeWithTraits(t, ctx, db, citedDull, 50, `{"l":5,"c":1.0}`)
	if err := db.UpdateLitmusResult(ctx, citedDull, []byte(`{"prob":0.99}`)); err != nil {
		t.Fatal(err)
	}
	// uncitedUrgent disagrees with its label and is closest to the boundary.
	mustInsert(t, ctx, db, &Sample{SHA256: uncitedUrgent, Source: "test", Label: "bad", LabelSource: "test"})
	mustAnalyzeWithTraits(t, ctx, db, uncitedUrgent, 0, "")
	if err := db.UpdateLitmusResult(ctx, uncitedUrgent, []byte(`{"prob":0.49}`)); err != nil {
		t.Fatal(err)
	}
	mustInsert(t, ctx, db, &Sample{SHA256: uncitedOrdinar, Source: "test", Label: "good", LabelSource: "test"})
	mustAnalyzeWithTraits(t, ctx, db, uncitedOrdinar, 0, "")
	if err := db.UpdateLitmusResult(ctx, uncitedOrdinar, []byte(`{"prob":0.90}`)); err != nil {
		t.Fatal(err)
	}

	if _, err := db.AddSightings(ctx, []Sighting{
		{Source: "osv", Subject: citedDull, Note: "malware"},
	}); err != nil {
		t.Fatalf("AddSightings: %v", err)
	}

	old := time.Now().Add(-96 * time.Hour).UTC().Format(time.RFC3339Nano)
	if _, err := db.lite.ExecContext(ctx,
		`UPDATE samples SET analyzed_at = ?, traits_version = 'old-traits'`, old); err != nil {
		t.Fatal(err)
	}

	jobs, err := db.StaleTraitsCandidates(ctx, "new-traits", 72*time.Hour, time.Now(), 3)
	if err != nil {
		t.Fatalf("StaleTraitsCandidates: %v", err)
	}
	if len(jobs) != 3 {
		t.Fatalf("got %d jobs, want 3: %+v", len(jobs), jobs)
	}
	if jobs[0].SHA256 != citedDull {
		t.Errorf("first job = %s, want the corroborated sample %s; corroborated is not "+
			"leading the ordering. jobs=%+v", jobs[0].SHA256, citedDull, jobs)
	}
	// Below the corroborated rows, the original ranking must be untouched.
	if jobs[1].SHA256 != uncitedUrgent {
		t.Errorf("second job = %s, want %s; the disagreement/boundary ordering was lost",
			jobs[1].SHA256, uncitedUrgent)
	}
}

// TestCorroborationSettlesInsideTheWrite is the whole point of putting the
// invariant in the database: after any single write to the ledger, the flag is
// already correct. Not after a sweep, not after a command someone remembers to
// run — on the next read.
//
// The last case is the one that makes clearing safe to do eagerly: two sources
// citing one subject, one of them dropped. Anything that cleared on the first
// delete would uncorroborate a sample that is still cited.
func TestCorroborationSettlesInsideTheWrite(t *testing.T) {
	ctx := context.Background()
	db := openTestDB(t)

	const (
		single = "6a66666666666666666666666666666666666666666666666666666666666666"
		shared = "6b66666666666666666666666666666666666666666666666666666666666666"
	)
	mustPendingSample(t, ctx, db, single, "")
	mustPendingSample(t, ctx, db, shared, "")

	if _, err := db.AddSightings(ctx, []Sighting{
		{Source: "aikido", Subject: single, Note: "malware"},
		{Source: "aikido", Subject: shared, Note: "malware"},
		{Source: "osv", Subject: shared, Note: "malware"},
	}); err != nil {
		t.Fatalf("AddSightings: %v", err)
	}
	if !corroborated(t, ctx, db, single) || !corroborated(t, ctx, db, shared) {
		t.Fatal("recording a sighting did not corroborate immediately")
	}
	// Instantly queueable, which is the behaviour the flag exists to produce.
	jobs, err := db.SightedCandidates(ctx, time.Now(), 10)
	if err != nil {
		t.Fatalf("SightedCandidates: %v", err)
	}
	if len(jobs) != 2 {
		t.Fatalf("got %d sighted jobs immediately after the sighting landed, want 2: %+v", len(jobs), jobs)
	}

	// Dropping the only source that cited `single` clears it in the same
	// transaction; `shared` keeps its flag because osv still cites it.
	if _, err := db.DropSightings(ctx, []string{"aikido"}, false); err != nil {
		t.Fatalf("DropSightings: %v", err)
	}
	if corroborated(t, ctx, db, single) {
		t.Error("sample whose last citation was dropped is still corroborated")
	}
	if !corroborated(t, ctx, db, shared) {
		t.Error("sample still cited by osv lost its flag; the drop cleared too much")
	}

	// And the repair tool finds nothing, because there is nothing left to fix.
	cleared, err := db.ReconcileCorroborated(ctx)
	if err != nil {
		t.Fatalf("ReconcileCorroborated: %v", err)
	}
	if cleared != 0 {
		t.Errorf("reconcile cleared %d after the writes already settled; want 0", cleared)
	}
}

// TestCitedSamplesSkipTheRescanAgeGate covers the reason a sighting on an
// already-analyzed sample does anything at all.
//
// rescanAge defaults to 30 days and exists to stop the tier churning through
// freshly-analyzed rows. That gate is what made a citation land on deaf ears: a
// sample analyzed last week that a feed cites today would wait three more weeks.
// A citation is the signal that says this row is worth the churn.
//
// The last case is the guard that keeps this from becoming a rescan treadmill:
// being cited does NOT exempt a sample from traits_version. Re-running the
// analyzer that already judged it cannot learn anything — the analyzer does not
// read the ledger — and StoreResult calls that renewal a failed upstream guard.
func TestCitedSamplesSkipTheRescanAgeGate(t *testing.T) {
	ctx := context.Background()
	db := openTestDB(t)

	const (
		citedStale   = "7a77777777777777777777777777777777777777777777777777777777777777"
		uncitedFresh = "7b77777777777777777777777777777777777777777777777777777777777777"
		citedCurrent = "7c77777777777777777777777777777777777777777777777777777777777777"
	)
	for _, sha := range []string{citedStale, uncitedFresh, citedCurrent} {
		mustInsert(t, ctx, db, &Sample{SHA256: sha, Source: "test", Label: "unknown", LabelSource: "test"})
		mustAnalyze(t, ctx, db, sha, 10)
	}
	if _, err := db.AddSightings(ctx, []Sighting{
		{Source: "osv", Subject: citedStale, Note: "malware"},
		{Source: "osv", Subject: citedCurrent, Note: "malware"},
	}); err != nil {
		t.Fatalf("AddSightings: %v", err)
	}

	// Everything analyzed an hour ago — far inside a 30-day age gate. citedCurrent
	// carries the analyzer we are asking about; the other two are a version behind.
	recent := time.Now().Add(-time.Hour).UTC().Format(time.RFC3339Nano)
	if _, err := db.lite.ExecContext(ctx,
		`UPDATE samples SET analyzed_at = ?, traits_version = 'old-traits'`, recent); err != nil {
		t.Fatal(err)
	}
	if _, err := db.lite.ExecContext(ctx,
		`UPDATE samples SET traits_version = 'new-traits' WHERE sha256 = ?`, citedCurrent); err != nil {
		t.Fatal(err)
	}

	jobs, err := db.StaleTraitsCandidates(ctx, "new-traits", 30*24*time.Hour, time.Now(), 10)
	if err != nil {
		t.Fatalf("StaleTraitsCandidates: %v", err)
	}
	if len(jobs) != 1 {
		t.Fatalf("got %d jobs, want only the cited stale one: %+v", len(jobs), jobs)
	}
	if jobs[0].SHA256 != citedStale {
		t.Errorf("job = %s, want %s (a citation must lift the age gate)", jobs[0].SHA256, citedStale)
	}
	// uncitedFresh is absent: the gate still applies to everything nothing cites.
	// citedCurrent is absent: a citation does not buy a redundant re-analysis.
}
