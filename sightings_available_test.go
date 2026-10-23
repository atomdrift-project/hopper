package hopper

import (
	"context"
	"fmt"
	"testing"
	"time"
)

// An unattempted hash without bytes is not work Cyclotron can investigate.
// The metric must follow KnownSHA256's retrievability rules, while keeping
// package claims and the existing live/backfill distinction intact.
func TestOldestUnattemptedSightingRequiresHashSample(t *testing.T) {
	db := openDisposablePG(t)
	ctx := context.Background()
	now := time.Now().UTC()
	sha := func(n int) string { return fmt.Sprintf("%064x", n) }
	claim := func(subject string, age time.Duration) Sighting {
		return Sighting{Source: "test", Subject: subject, Claim: ClaimMalicious, FirstSeen: now.Add(-age)}
	}
	addClaims := func(claims ...Sighting) {
		t.Helper()
		if _, err := db.AddSightings(ctx, claims); err != nil {
			t.Fatal(err)
		}
		// Live ingest assigns arrival time itself; backdate only the fixture.
		for _, c := range claims {
			if _, err := db.pool.Exec(ctx, `UPDATE sightings SET first_seen = $1 WHERE source = $2 AND subject = $3 AND affected = $4`,
				c.FirstSeen, c.Source, c.Subject, c.Affected); err != nil {
				t.Fatal(err)
			}
		}
	}
	checkAge := func(want time.Duration, present bool) {
		t.Helper()
		age, ok, err := db.OldestUnattemptedSighting(ctx)
		if err != nil || ok != present {
			t.Fatalf("oldest = %v, %v, %v; want present=%v", age, ok, err, present)
		}
		if present && (age < want-time.Minute || age > want+time.Minute) {
			t.Fatalf("oldest age = %v, want approximately %v", age, want)
		}
	}

	// Missing catalog entry, catalog-only entry, known-missing bytes, and a
	// reference to content that was never inside its supposed parent.
	if _, err := db.pool.Exec(ctx, `INSERT INTO samples (sha256, path) VALUES ($1, '')`, sha(2)); err != nil {
		t.Fatal(err)
	}
	mustInsert(t, ctx, db, &Sample{SHA256: sha(3), Path: "pending/gone.bin"})
	if err := db.SetSkip(ctx, sha(3), "missing"); err != nil {
		t.Fatal(err)
	}
	mustInsert(t, ctx, db, &Sample{SHA256: sha(4), Path: "pending/parent.zip"})
	mustInsert(t, ctx, db, &Sample{
		SHA256: sha(5), Path: "pending/parent.zip!!dependency.bin", Parent: sha(4), LocationRel: string(RelFetched),
	})
	addClaims(
		claim(sha(1), 96*time.Hour), claim(sha(2), 95*time.Hour),
		claim(sha(3), 94*time.Hour), claim(sha(5), 93*time.Hour),
	)
	checkAge(0, false)

	// Bytes that arrive later immediately make the existing claim count.
	mustInsert(t, ctx, db, &Sample{SHA256: sha(1), Path: "pending/arrived.bin"})
	checkAge(96*time.Hour, true)
	if err := db.MarkSightingsAttempted(ctx, []Sighting{claim(sha(1), 96*time.Hour)}); err != nil {
		t.Fatal(err)
	}
	checkAge(0, false)

	// Real archive members are available through extraction and still count.
	mustInsert(t, ctx, db, &Sample{
		SHA256: sha(6), Path: "pending/parent.zip!!member.bin", Parent: sha(4), LocationRel: string(RelContained),
	})
	addClaims(claim(sha(6), 4*time.Hour))
	checkAge(4*time.Hour, true)
	if err := db.MarkSightingsAttempted(ctx, []Sighting{claim(sha(6), 4*time.Hour)}); err != nil {
		t.Fatal(err)
	}

	// Package acquisition remains visible even before we have those bytes.
	addClaims(claim("pkg:npm/not-yet-fetched", 3*time.Hour))
	checkAge(3*time.Hour, true)
	if err := db.MarkSightingsAttempted(ctx, []Sighting{claim("pkg:npm/not-yet-fetched", 3*time.Hour)}); err != nil {
		t.Fatal(err)
	}

	// Historical claims stay excluded even when their sample is available.
	if _, err := db.AddSightingsBackfill(ctx, []Sighting{{
		Source: "history", Subject: sha(4), Claim: ClaimMalicious, PublishedAt: now.Add(-365 * 24 * time.Hour),
	}}); err != nil {
		t.Fatal(err)
	}
	checkAge(0, false)
}
