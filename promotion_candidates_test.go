package hopper

import (
	"context"
	"strings"
	"testing"
	"time"
)

func TestPromotionCandidates(t *testing.T) {
	ctx := context.Background()
	db := openTestDB(t)

	old := time.Now().Add(-90 * 24 * time.Hour)
	recent := time.Now().Add(-1 * time.Hour)

	sha := func(prefix byte) string {
		return strings.Repeat(string(prefix), 64)
	}

	// cand builds an eligible candidate unless a field is overridden by the caller.
	cand := func(s string, mut func(*Sample)) *Sample {
		c := &Sample{
			SHA256:      s,
			Source:      "test",
			Label:       "unknown",
			LabelSource: "test",
			Path:        "unknown/foraged/npm/" + s[:8] + ".tgz",
			Mtime:       &old,
		}
		if mut != nil {
			mut(c)
		}
		return c
	}

	// Three eligible candidates, distinct sha bytes so ordering and paging are
	// observable.
	mustInsert(t, ctx, db, cand(sha('1'), nil))
	mustInsert(t, ctx, db, cand(sha('3'), nil))
	mustInsert(t, ctx, db, cand(sha('5'), nil))

	// Ineligible rows that every filter must reject.
	mustInsert(t, ctx, db, cand(sha('6'), func(s *Sample) { s.Label = "good" }))                            // wrong label
	mustInsert(t, ctx, db, cand(sha('7'), func(s *Sample) { s.Parent = sha('1') }))                         // archive member
	mustInsert(t, ctx, db, cand(sha('8'), func(s *Sample) { s.Skip = "missing" }))                          // training-skipped
	mustInsert(t, ctx, db, cand(sha('9'), func(s *Sample) { s.Mtime = &recent }))                           // too young
	mustInsert(t, ctx, db, cand(sha('a'), func(s *Sample) { s.Mtime = nil }))                               // unknown mtime
	mustInsert(t, ctx, db, cand(sha('b'), func(s *Sample) { s.Path = "good/foraged-promote/npm/x.tgz" }))   // other pool
	mustInsert(t, ctx, db, cand(sha('c'), func(s *Sample) { s.Path = "unknown/foraged-review/npm/x.tgz" })) // sibling review queue

	const prefix = "unknown/foraged/"
	cutoff := time.Now().Add(-30 * 24 * time.Hour)

	// Full sweep from the keyspace floor returns exactly the three eligible rows,
	// in sha order. The "-review" sibling must NOT appear — that exclusion is how
	// the review queue self-excludes from re-discovery.
	got, err := db.PromotionCandidates(ctx, prefix, cutoff, "", 100)
	if err != nil {
		t.Fatalf("PromotionCandidates: %v", err)
	}
	want := []string{sha('1'), sha('3'), sha('5')}
	if len(got) != len(want) {
		t.Fatalf("got %d candidates, want %d: %v", len(got), len(want), shas(got))
	}
	for i, s := range got {
		if s.SHA256 != want[i] {
			t.Errorf("candidate %d = %s, want %s", i, s.SHA256, want[i])
		}
	}

	// Keyset paging: a page of 2, then the cursor past the last sha yields the
	// remainder with no overlap.
	page1, err := db.PromotionCandidates(ctx, prefix, cutoff, "", 2)
	if err != nil {
		t.Fatalf("page1: %v", err)
	}
	if len(page1) != 2 || page1[0].SHA256 != sha('1') || page1[1].SHA256 != sha('3') {
		t.Fatalf("page1 = %v, want [1.. 3..]", shas(page1))
	}
	page2, err := db.PromotionCandidates(ctx, prefix, cutoff, page1[1].SHA256, 2)
	if err != nil {
		t.Fatalf("page2: %v", err)
	}
	if len(page2) != 1 || page2[0].SHA256 != sha('5') {
		t.Fatalf("page2 = %v, want [5..]", shas(page2))
	}

	// A cursor at the top of the keyspace returns nothing (drives the sweep's
	// wrap-around in the client).
	tail, err := db.PromotionCandidates(ctx, prefix, cutoff, sha('5'), 2)
	if err != nil {
		t.Fatalf("tail: %v", err)
	}
	if len(tail) != 0 {
		t.Fatalf("tail = %v, want empty", shas(tail))
	}
}

func shas(samples []*Sample) []string {
	out := make([]string, len(samples))
	for i, s := range samples {
		out[i] = s.SHA256[:4]
	}
	return out
}
