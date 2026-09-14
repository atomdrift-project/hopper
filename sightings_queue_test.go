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

// TestRescanAgeIgnoresCorroboration pins a deliberate REMOVAL. The rescan tier
// used to lead its sort with corroborated, and to let a cited sample skip the
// age gate entirely.
//
// Both are gone. The bypass was only ever safe because traits_version gated the
// row behind it; with the tier keyed on age alone, "corroborated OR old enough"
// re-admits every cited sample on every poll, re-analyzing it forever and
// firing StoreResult's Redundant() warning as routine noise. A citation is a
// deadline, and deadlines are the sighted tier's job — it claims at the TOP of
// the ladder, where this one sits at the bottom.
func TestRescanAgeIgnoresCorroboration(t *testing.T) {
	ctx := context.Background()
	db := openTestDB(t)

	const (
		citedFresh = "5a55555555555555555555555555555555555555555555555555555555555555"
		uncitedOld = "5b55555555555555555555555555555555555555555555555555555555555555"
	)
	for _, sha := range []string{citedFresh, uncitedOld} {
		mustInsert(t, ctx, db, &Sample{SHA256: sha, Source: "test", Label: "bad", LabelSource: "test"})
		mustAnalyzeWithTraits(t, ctx, db, sha, 0, "")
	}
	if _, err := db.AddSightings(ctx, []Sighting{
		{Source: "osv", Subject: citedFresh, Note: "malware"},
	}); err != nil {
		t.Fatalf("AddSightings: %v", err)
	}

	fresh := time.Now().Add(-1 * time.Hour).UTC().Format(time.RFC3339Nano)
	old := time.Now().Add(-400 * 24 * time.Hour).UTC().Format(time.RFC3339Nano)
	if _, err := db.lite.ExecContext(ctx,
		`UPDATE samples SET analyzed_at = ? WHERE sha256 = ?`, fresh, citedFresh); err != nil {
		t.Fatal(err)
	}
	if _, err := db.lite.ExecContext(ctx,
		`UPDATE samples SET analyzed_at = ? WHERE sha256 = ?`, old, uncitedOld); err != nil {
		t.Fatal(err)
	}

	// Guard the premise: the citation did land, so this tests the absent bypass
	// rather than an absent sighting.
	var corroborated int
	if err := db.lite.QueryRowContext(ctx,
		`SELECT corroborated FROM samples WHERE sha256 = ?`, citedFresh).Scan(&corroborated); err != nil {
		t.Fatal(err)
	}
	if corroborated != 1 {
		t.Fatalf("premise: %s is not corroborated", citedFresh)
	}

	jobs, err := db.RescanAgeCandidates(ctx, 75*24*time.Hour, time.Now(), 10)
	if err != nil {
		t.Fatalf("RescanAgeCandidates: %v", err)
	}
	if len(jobs) != 1 || jobs[0].SHA256 != uncitedOld {
		t.Fatalf("got %+v, want only the old uncited sample %s; a citation must not "+
			"pull a freshly-analyzed row back into the age queue", jobs, uncitedOld)
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
