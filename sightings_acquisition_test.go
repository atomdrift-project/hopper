package hopper

import (
	"context"
	"database/sql"
	"path/filepath"
	"testing"
	"time"
)

func TestRecentAcquisitionSightingsPreservesRetrievalHints(t *testing.T) {
	ctx := context.Background()
	db := openTestDB(t)
	const sha = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
	if _, err := db.AddSightings(ctx, []Sighting{
		{Source: "triage", Subject: sha, Handle: "analysis-123", Claim: ClaimMalicious},
		{Source: "detector", Subject: "pkg:npm/suspect", Affected: "1.2.3", Claim: ClaimSuspicious},
		{Source: "advisory", Subject: "pkg:npm/legit", Affected: "<2", Claim: ClaimVulnerable},
	}); err != nil {
		t.Fatalf("AddSightings: %v", err)
	}

	got, err := db.RecentAcquisitionSightings(ctx, time.Now().Add(-time.Hour))
	if err != nil {
		t.Fatalf("RecentAcquisitionSightings: %v", err)
	}
	if len(got) != 2 {
		t.Fatalf("recent acquisition sightings = %+v, want malicious and suspicious only", got)
	}
	for _, s := range got {
		if s.Source == "triage" && s.Handle != "analysis-123" {
			t.Fatalf("triage handle = %q, want analysis-123", s.Handle)
		}
		if s.Claim == ClaimVulnerable {
			t.Fatalf("vulnerability entered acquisition candidates: %+v", s)
		}
	}
}

// A claimed target is terminal. The recovery chain behind one target walks
// mirrors, Wayback, jsDelivr, unpkg, Software Heritage and socket.dev, and it
// must run at most once no matter how the pass that started it ended.
//
// This replaced a lease-expiry retry. Measured 2026-09-08: passes ran 27
// minutes against a 30-minute lease on a 3-minute schedule, so unfinished
// targets were re-claimed roughly every half hour, forever. One Wayback CDX
// query was re-issued 52 times in a day.
func TestSightingAcquisitionIsTerminalOnceClaimed(t *testing.T) {
	ctx := context.Background()
	db := openTestDB(t)
	const target = "sha256:bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb"

	claimed, err := db.TryClaimSightingAcquisition(ctx, target, time.Minute)
	if err != nil || !claimed {
		t.Fatalf("first claim = %v, %v; want true", claimed, err)
	}
	// Concurrent pass: loses the race, does no duplicate work.
	if claimed, err = db.TryClaimSightingAcquisition(ctx, target, time.Minute); err != nil || claimed {
		t.Fatalf("concurrent claim = %v, %v; want false", claimed, err)
	}
	if err := db.FinishSightingAcquisition(ctx, target, false, time.Hour, "not found"); err != nil {
		t.Fatalf("finish failed attempt: %v", err)
	}
	if claimed, err = db.TryClaimSightingAcquisition(ctx, target, time.Minute); err != nil || claimed {
		t.Fatalf("claim after failure = %v, %v; want false: a failed attempt is still an attempt", claimed, err)
	}
	// The old behaviour: a due next_attempt reopened the target. It must not.
	if _, err := db.lite.ExecContext(ctx,
		`UPDATE sighting_acquisitions SET next_attempt = ? WHERE target = ?`,
		time.Now().Add(-time.Minute), target); err != nil {
		t.Fatalf("expire retry: %v", err)
	}
	if claimed, err = db.TryClaimSightingAcquisition(ctx, target, time.Minute); err != nil || claimed {
		t.Fatalf("claim with next_attempt in the past = %v, %v; want false", claimed, err)
	}
	// An operator, and only an operator, can spend the fetches again.
	n, err := db.ReopenAcquisitions(ctx, []string{target}, false, false)
	if err != nil || n != 1 {
		t.Fatalf("ReopenAcquisitions = %d, %v; want 1", n, err)
	}
	if claimed, err = db.TryClaimSightingAcquisition(ctx, target, time.Minute); err != nil || !claimed {
		t.Fatalf("claim after reopen = %v, %v; want true", claimed, err)
	}
	if err := db.FinishSightingAcquisition(ctx, target, true, 0, ""); err != nil {
		t.Fatalf("finish success: %v", err)
	}
	// Acquired targets are never reopened: we hold the bytes.
	if n, err = db.ReopenAcquisitions(ctx, []string{target}, false, false); err != nil || n != 0 {
		t.Fatalf("reopen of an acquired target = %d, %v; want 0", n, err)
	}
}

// Abandonment is a per-target fact about a lost process, NOT about a slow or
// unsuccessful fetch.
//
// The distinction is the whole point of the metric. A target we genuinely
// worked -- walked every mirror, every archive, found nothing -- reports that
// failure, gets finished_at, and must never be counted here: it is a recovery
// that ran, and re-running it would find nothing again. Only a target claimed
// and then lost, because the pass died before recording an outcome, is work
// nobody will ever redo. forager keeps the two separable by bounding one
// target's chain (acquisitionTargetTimeout) well under this grace and writing
// the outcome on a detached context.
func TestRetiredWithoutOutcomeIsVisible(t *testing.T) {
	ctx := context.Background()
	db := openTestDB(t)
	const lost = "pkg:npm/lost@1.0.0"
	const done = "pkg:npm/done@1.0.0"

	for _, target := range []string{lost, done} {
		if ok, err := db.TryClaimSightingAcquisition(ctx, target, time.Minute); err != nil || !ok {
			t.Fatalf("claim %s = %v, %v", target, ok, err)
		}
	}
	// Only one reports an outcome; the other is the killed pass.
	if err := db.FinishSightingAcquisition(ctx, done, false, time.Hour, "not found"); err != nil {
		t.Fatalf("finish: %v", err)
	}
	// Backdate the lost claim. A just-claimed row is microseconds old, which is
	// below the resolution of the age arithmetic and makes the assertion race
	// the clock; a real one is minutes to hours old.
	if _, err := db.lite.ExecContext(ctx,
		`UPDATE sighting_acquisitions SET last_attempt = ? WHERE target = ?`,
		time.Now().UTC().Add(-90*time.Minute), lost); err != nil {
		t.Fatalf("backdate lost claim: %v", err)
	}

	n, oldest, err := db.AcquisitionsRetiredWithoutOutcome(ctx, 0)
	if err != nil {
		t.Fatalf("AcquisitionsRetiredWithoutOutcome: %v", err)
	}
	if n != 1 {
		t.Errorf("retired without outcome = %d, want 1: only %s was lost. %s was worked "+
			"and failed, which is a recorded outcome, not abandonment", n, lost, done)
	}
	if oldest < time.Hour {
		t.Errorf("oldest age = %v, want ~90m for the backdated lost target", oldest)
	}

	// The grace period must not report an attempt that is still in flight: at a
	// 3h grace the 90-minute-old claim is still young enough to be running.
	if n, _, err = db.AcquisitionsRetiredWithoutOutcome(ctx, 3*time.Hour); err != nil || n != 0 {
		t.Errorf("with a 3h grace = %d, %v; want 0: the attempt is still young", n, err)
	}

	// The preview must predict the action, through the same predicate: a
	// dry-run that answers a different question than the delete is how an
	// operator reopens a set they did not intend to.
	preview, err := db.ReopenAcquisitions(ctx, nil, true, true)
	if err != nil || preview != 1 {
		t.Fatalf("dry-run = %d, %v; want 1", preview, err)
	}
	if ok, _ := db.TryClaimSightingAcquisition(ctx, lost, time.Minute); ok {
		t.Error("dry-run reopened a target instead of only counting it")
	}

	// Reopening only the lost one leaves the failed-but-finished target alone.
	reopened, err := db.ReopenAcquisitions(ctx, nil, true, false)
	if err != nil || reopened != 1 {
		t.Fatalf("ReopenAcquisitions(onlyUnfinished) = %d, %v; want 1", reopened, err)
	}
	if ok, err := db.TryClaimSightingAcquisition(ctx, done, time.Minute); err != nil || ok {
		t.Errorf("finished target became claimable after an unfinished-only reopen: %v, %v", ok, err)
	}
}

func TestSightingBackfillModeSurvivesProducerBatches(t *testing.T) {
	ctx := context.Background()
	db := openTestDB(t)
	published := time.Date(2022, 1, 2, 3, 4, 5, 0, time.UTC)
	for _, subject := range []string{"pkg:npm/old-one", "pkg:npm/old-two"} {
		if _, err := db.AddSightingsBackfill(ctx, []Sighting{{
			Source: "history", Subject: subject, Affected: "1.0.0",
			Claim: ClaimMalicious, PublishedAt: published,
		}}); err != nil {
			t.Fatalf("AddSightingsBackfill(%s): %v", subject, err)
		}
	}
	got, err := db.RecentAcquisitionSightings(ctx, time.Now().Add(-24*time.Hour))
	if err != nil {
		t.Fatal(err)
	}
	if len(got) != 0 {
		t.Fatalf("historical rows from later producer batches became recent: %+v", got)
	}
	for _, subject := range []string{"pkg:npm/old-one", "pkg:npm/old-two"} {
		rows, err := db.SightingsFor(ctx, []string{subject})
		if err != nil {
			t.Fatal(err)
		}
		if len(rows[subject]) != 1 || !rows[subject][0].FirstSeen.Equal(published) {
			t.Fatalf("%s first_seen = %+v, want %v", subject, rows[subject], published)
		}
	}
}

// Migrating a database whose sighting_acquisitions table predates finished_at
// must succeed. schema.sql is applied BEFORE the runtime migrations and its
// CREATE TABLE IF NOT EXISTS is a no-op on an existing table, so any statement
// there naming a column a later migration adds fails on every cluster that
// already exists -- while passing every test that starts from an empty file.
//
// That shipped on 2026-09-08 and crash-looped the production loader every 18
// seconds with `column "finished_at" does not exist (SQLSTATE 42703)`.
func TestMigrateOverPreFinishedAtSchema(t *testing.T) {
	ctx := context.Background()
	path := filepath.Join(t.TempDir(), "old.db")

	// Build the table in its pre-finished_at shape, then migrate onto it.
	old, err := sql.Open("sqlite3", path)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := old.ExecContext(ctx, `
		CREATE TABLE sighting_acquisitions (
			target       TEXT PRIMARY KEY,
			attempts     INTEGER NOT NULL DEFAULT 0,
			acquired     INTEGER NOT NULL DEFAULT 0,
			last_attempt DATETIME,
			next_attempt DATETIME NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%fZ', 'now')),
			last_error   TEXT NOT NULL DEFAULT ''
		)`); err != nil {
		t.Fatal(err)
	}
	if _, err := old.ExecContext(ctx,
		`INSERT INTO sighting_acquisitions (target, attempts, acquired, last_attempt)
		 VALUES ('pkg:npm/legacy@1.0.0', 1, 0, ?)`, time.Now().UTC().Add(-2*time.Hour)); err != nil {
		t.Fatal(err)
	}
	if err := old.Close(); err != nil {
		t.Fatal(err)
	}

	db, err := Open(ctx, path, "hopper-test")
	if err != nil {
		t.Fatalf("open pre-finished_at database: %v", err)
	}
	defer db.Close()
	if err := db.Migrate(ctx); err != nil {
		t.Fatalf("migrating a database that predates finished_at: %v", err)
	}

	// The adoption must have run, so the legacy row is not reported abandoned.
	n, _, err := db.AcquisitionsRetiredWithoutOutcome(ctx, 0)
	if err != nil {
		t.Fatalf("AcquisitionsRetiredWithoutOutcome: %v", err)
	}
	if n != 0 {
		t.Errorf("rows predating finished_at reported as abandoned = %d, want 0", n)
	}
}
