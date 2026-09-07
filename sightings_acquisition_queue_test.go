package hopper

import (
	"context"
	"testing"
	"time"
)

// The queue's defining property: a claim stays on offer until something has
// tried it, and no clock, cadence or window can take it out of the queue in the
// meantime.
//
// This is the 2026-09-07 Shai-Hulud regression test. The selector this replaced
// asked for claims newer than a caller-supplied cutoff, so a claim arriving
// while no pass was running fell between two spans and was never offered again.
// Four of that day's seven citations of the reactivated packages died that way,
// and nothing in the system could tell afterwards that they had.
func TestUnattemptedSightingsSurviveUntilAttempted(t *testing.T) {
	ctx := context.Background()
	db := openTestDB(t)

	claims := []Sighting{
		{Source: "stepsecurity", Subject: "pkg:npm/blueai-cli", Affected: "0.7.0", Claim: ClaimSuspicious},
		{Source: "lpm", Subject: "pkg:npm/blueai-cli", Affected: "0.7.0", Claim: ClaimMalicious},
		{Source: "ghsa", Subject: "pkg:npm/feishu-docx-mcp", Affected: ">= 0", Claim: ClaimMalicious},
		{Source: "osv", Subject: "pkg:npm/legit", Affected: "1.0", Claim: ClaimVulnerable},
	}
	if _, err := db.AddSightings(ctx, claims); err != nil {
		t.Fatal(err)
	}

	// A vulnerability names a defect in working software, so it is not fetch
	// work and must never enter the queue.
	first, err := db.UnattemptedSightings(ctx, 100)
	if err != nil {
		t.Fatal(err)
	}
	if len(first) != 3 {
		t.Fatalf("queue depth = %d, want the three malicious/suspicious claims only", len(first))
	}

	// Asking again changes nothing. Reading is not attempting: a pass that reads
	// a claim and then dies must leave it for the next pass.
	again, err := db.UnattemptedSightings(ctx, 100)
	if err != nil {
		t.Fatal(err)
	}
	if len(again) != len(first) {
		t.Fatalf("queue depth changed on a second read: %d then %d", len(first), len(again))
	}

	// Stamping the unresolvable claim removes it. This is the case that matters
	// most: ">= 0" is a range no fetch can resolve, and leaving it un-stamped
	// would park it at the head of a newest-first queue forever.
	if err := db.MarkSightingsAttempted(ctx, []Sighting{claims[2]}); err != nil {
		t.Fatal(err)
	}
	after, err := db.UnattemptedSightings(ctx, 100)
	if err != nil {
		t.Fatal(err)
	}
	if len(after) != 2 {
		t.Fatalf("queue depth = %d after stamping one claim, want 2", len(after))
	}
	for _, s := range after {
		if s.Subject == "pkg:npm/feishu-docx-mcp" {
			t.Error("a stamped claim was offered again; attempts must happen once")
		}
	}

	// Two sources naming the same coordinate are two claims, keyed separately,
	// and stamping one must not silently retire the other.
	if err := db.MarkSightingsAttempted(ctx, []Sighting{claims[0]}); err != nil {
		t.Fatal(err)
	}
	last, err := db.UnattemptedSightings(ctx, 100)
	if err != nil {
		t.Fatal(err)
	}
	if len(last) != 1 || last[0].Source != "lpm" {
		t.Fatalf("remaining queue = %+v, want lpm's independent claim still pending", last)
	}
}

// Newest first, because a claim's value decays: one minutes old names an
// artifact the registry is probably still serving, one from last year names
// bytes that have most likely been withdrawn. Oldest-first would put every fresh
// citation behind the entire historical backlog -- 500,713 rows of it as of
// 2026-09-07 -- which is the same defect sightedCandidatesSQL carried.
func TestUnattemptedSightingsAreNewestFirst(t *testing.T) {
	ctx := context.Background()
	db := openTestDB(t)

	for i, name := range []string{"oldest", "middle", "newest"} {
		if _, err := db.AddSightings(ctx, []Sighting{
			{Source: name, Subject: "pkg:npm/" + name, Affected: "1.0.0", Claim: ClaimMalicious},
		}); err != nil {
			t.Fatal(err)
		}
		if i < 2 {
			time.Sleep(2 * time.Millisecond)
		}
	}

	got, err := db.UnattemptedSightings(ctx, 100)
	if err != nil {
		t.Fatal(err)
	}
	if len(got) != 3 {
		t.Fatalf("queue depth = %d, want 3", len(got))
	}
	if got[0].Source != "newest" {
		t.Errorf("head of queue = %q, want the newest claim", got[0].Source)
	}

	// A bounded pass takes from the head, so the freshest claim is served first
	// even when the backlog behind it is arbitrarily deep.
	one, err := db.UnattemptedSightings(ctx, 1)
	if err != nil {
		t.Fatal(err)
	}
	if len(one) != 1 || one[0].Source != "newest" {
		t.Errorf("a one-row pass took %+v, want the newest claim", one)
	}
}
