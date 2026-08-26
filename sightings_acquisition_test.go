package hopper

import (
	"context"
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

func TestSightingAcquisitionLeaseRetryAndCompletion(t *testing.T) {
	ctx := context.Background()
	db := openTestDB(t)
	const target = "sha256:bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb"

	claimed, err := db.TryClaimSightingAcquisition(ctx, target, time.Minute)
	if err != nil || !claimed {
		t.Fatalf("first claim = %v, %v; want true", claimed, err)
	}
	if claimed, err = db.TryClaimSightingAcquisition(ctx, target, time.Minute); err != nil || claimed {
		t.Fatalf("live lease claim = %v, %v; want false", claimed, err)
	}
	if err := db.FinishSightingAcquisition(ctx, target, false, time.Hour, "not found"); err != nil {
		t.Fatalf("finish failed attempt: %v", err)
	}
	if claimed, err = db.TryClaimSightingAcquisition(ctx, target, time.Minute); err != nil || claimed {
		t.Fatalf("backoff claim = %v, %v; want false", claimed, err)
	}
	if _, err := db.lite.ExecContext(ctx,
		`UPDATE sighting_acquisitions SET next_attempt = ? WHERE target = ?`,
		time.Now().Add(-time.Minute), target); err != nil {
		t.Fatalf("expire retry: %v", err)
	}
	if claimed, err = db.TryClaimSightingAcquisition(ctx, target, time.Minute); err != nil || !claimed {
		t.Fatalf("due retry claim = %v, %v; want true", claimed, err)
	}
	if err := db.FinishSightingAcquisition(ctx, target, true, 0, ""); err != nil {
		t.Fatalf("finish success: %v", err)
	}
	if claimed, err = db.TryClaimSightingAcquisition(ctx, target, time.Minute); err != nil || claimed {
		t.Fatalf("completed claim = %v, %v; want false", claimed, err)
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
