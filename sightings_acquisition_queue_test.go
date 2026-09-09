package hopper

import (
	"context"
	"fmt"
	"strings"
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
	first, err := db.UnattemptedSightings(ctx, 100, "")
	if err != nil {
		t.Fatal(err)
	}
	if len(first) != 3 {
		t.Fatalf("queue depth = %d, want the three malicious/suspicious claims only", len(first))
	}

	// Asking again changes nothing. Reading is not attempting: a pass that reads
	// a claim and then dies must leave it for the next pass.
	again, err := db.UnattemptedSightings(ctx, 100, "")
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
	after, err := db.UnattemptedSightings(ctx, 100, "")
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
	last, err := db.UnattemptedSightings(ctx, 100, "")
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

	got, err := db.UnattemptedSightings(ctx, 100, "")
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
	one, err := db.UnattemptedSightings(ctx, 1, "")
	if err != nil {
		t.Fatal(err)
	}
	if len(one) != 1 || one[0].Source != "newest" {
		t.Errorf("a one-row pass took %+v, want the newest claim", one)
	}
}

// The fast lane's read: one source's claims, newest first.
//
// It exists because the ordinary read is a bounded LIMIT off the queue head, so
// a caller that reads the head and then discards everything not from its source
// would re-read the same rows on every pass and never reach its own. Filtering
// has to happen in the query.
func TestUnattemptedSightingsFilterBySource(t *testing.T) {
	ctx := context.Background()
	db := openTestDB(t)

	// A crowd from one source, then a single claim from another. Newest last, so
	// an unfiltered read of one row would never return the osv claim.
	var crowd []Sighting
	for i := range 20 {
		crowd = append(crowd, Sighting{
			Source: "noise", Subject: fmt.Sprintf("pkg:npm/noise-%02d", i),
			Affected: "1.0.0", Claim: ClaimMalicious,
		})
	}
	if _, err := db.AddSightings(ctx, crowd); err != nil {
		t.Fatal(err)
	}
	if _, err := db.AddSightings(ctx, []Sighting{
		{Source: "osv", Subject: "pkg:npm/freshly-reported", Affected: "2.0.0", Claim: ClaimMalicious},
	}); err != nil {
		t.Fatal(err)
	}

	only, err := db.UnattemptedSightings(ctx, 5, "osv")
	if err != nil {
		t.Fatal(err)
	}
	if len(only) != 1 || only[0].Source != "osv" {
		t.Fatalf("filtered read = %+v, want just the osv claim", only)
	}

	// An empty source is still the whole queue.
	all, err := db.UnattemptedSightings(ctx, 100, "")
	if err != nil {
		t.Fatal(err)
	}
	if len(all) != 21 {
		t.Fatalf("unfiltered read = %d, want all 21", len(all))
	}
}

// The queue orders on when the ATTACK happened, not on when we noticed it.
//
// first_seen is a fact about our polling. A source that backfills, or one added
// today, lands old attacks carrying new first_seen values, and under a
// first_seen ordering those outrank a genuinely fresh citation. published_at is
// what the source says happened.
//
// COALESCE because coverage is partial: measured 2026-09-08, 57% of the queue
// carried an event date and two of the largest sources carried none at all. For
// those, when we first saw it is the best evidence of when it happened.
func TestQueueOrdersByEventDateNotDiscoveryDate(t *testing.T) {
	ctx := context.Background()
	db := openTestDB(t)

	// Recorded last, but the source says the attack is from last year.
	old := time.Now().Add(-365 * 24 * time.Hour)
	if _, err := db.AddSightings(ctx, []Sighting{
		{
			Source: "fresh-event", Subject: "pkg:npm/todays-attack", Affected: "1.0.0",
			Claim: ClaimMalicious, PublishedAt: time.Now().Add(-time.Minute),
		},
	}); err != nil {
		t.Fatal(err)
	}
	time.Sleep(2 * time.Millisecond)
	if _, err := db.AddSightings(ctx, []Sighting{
		{
			Source: "stale-event", Subject: "pkg:npm/last-years-attack", Affected: "2.0.0",
			Claim: ClaimMalicious, PublishedAt: old,
		},
	}); err != nil {
		t.Fatal(err)
	}
	// No event date at all: falls back to when we saw it, which is now.
	time.Sleep(2 * time.Millisecond)
	if _, err := db.AddSightings(ctx, []Sighting{
		{Source: "no-event", Subject: "pkg:npm/undated", Affected: "3.0.0", Claim: ClaimMalicious},
	}); err != nil {
		t.Fatal(err)
	}

	got, err := db.UnattemptedSightings(ctx, 10, "")
	if err != nil {
		t.Fatal(err)
	}
	if len(got) != 3 {
		t.Fatalf("queue depth = %d, want 3", len(got))
	}
	// Last year's attack was recorded second but must sort last, behind both the
	// fresh event and the undated claim we saw moments ago.
	if got[len(got)-1].Source != "stale-event" {
		t.Errorf("queue order = %s/%s/%s; last year's attack must not outrank today's just because we logged it later",
			got[0].Source, got[1].Source, got[2].Source)
	}
	// And the oldest-first read is the exact mirror.
	oldest, err := db.OldestUnattemptedSightings(ctx, 1)
	if err != nil {
		t.Fatal(err)
	}
	if len(oldest) != 1 || oldest[0].Source != "stale-event" {
		t.Errorf("oldest-first head = %+v, want last year's attack", oldest)
	}
}

// Every provider drains from its own end of the queue.
//
// The providers share nothing — each has its own request gate — so npm fetching
// at 60 packages a minute costs a digest corpus fetching at two precisely
// nothing. A single date-ordered queue made them wait for each other anyway and
// handed every turn to whichever publishes most often: measured 2026-09-08,
// 441,728 npm claims sat behind triage and bazaar digests that were merely more
// recent, and the next 300 claims at the head held no package coordinate at all.
func TestQueueDrainsPerProvider(t *testing.T) {
	ctx := context.Background()
	db := openTestDB(t)

	// A digest corpus publishing constantly, and npm work that is slightly older
	// — the exact shape that starved npm.
	var digests []Sighting
	for i := range 30 {
		digests = append(digests, Sighting{
			Source: "bazaar", Claim: ClaimMalicious,
			Subject: fmt.Sprintf("%064x", i), PublishedAt: time.Now().Add(-time.Minute),
		})
	}
	if _, err := db.AddSightings(ctx, digests); err != nil {
		t.Fatal(err)
	}
	if _, err := db.AddSightings(ctx, []Sighting{
		{
			Source: "stepsecurity", Subject: "pkg:npm/blueai-cli", Affected: "0.7.0",
			Claim: ClaimMalicious, PublishedAt: time.Now().Add(-2 * time.Hour),
		},
	}); err != nil {
		t.Fatal(err)
	}

	providers, err := db.AcquisitionProviders(ctx)
	if err != nil {
		t.Fatal(err)
	}
	byName := map[string]int{}
	for _, p := range providers {
		byName[p.Provider] = p.Queued
	}
	if byName["npm"] != 1 || byName["bazaar"] != 30 {
		t.Fatalf("provider queues = %v; want npm=1 bazaar=30", byName)
	}

	// The npm claim is two hours older than every digest, so a shared queue would
	// put it thirty-first. Its own queue puts it first.
	got, err := db.UnattemptedForProvider(ctx, "npm", 10)
	if err != nil {
		t.Fatal(err)
	}
	if len(got) != 1 || got[0].Subject != "pkg:npm/blueai-cli" {
		t.Fatalf("npm queue = %+v, want the npm claim regardless of the digest flood", got)
	}
	// And a digest read never returns a package coordinate.
	digestHead, err := db.UnattemptedForProvider(ctx, "bazaar", 5)
	if err != nil {
		t.Fatal(err)
	}
	for _, s := range digestHead {
		if strings.HasPrefix(s.Subject, "pkg:") {
			t.Errorf("bazaar queue returned a package coordinate: %s", s.Subject)
		}
	}
}
