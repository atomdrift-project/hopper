package hopper

import (
	"context"
	"fmt"
	"strings"
	"testing"
	"time"
)

// The contract that makes a depth number worth showing: a queue's count and its
// selection describe the SAME population. They share a predicate constant, so
// this should hold by construction — the test exists because "by construction"
// has quietly stopped being true in this file before, and a depth that silently
// stops matching its queue is worse than no depth at all.
func TestTriageDepthMatchesSelection(t *testing.T) {
	ctx := t.Context()
	db := openTestDB(t)

	// One sample per shape the countable selectors partition on, so every
	// predicate has both members and non-members to discriminate.
	var n int
	add := func(label string, crit, suspicious int, path string) string {
		n++
		sha := fmt.Sprintf("%063x1", n)
		s := &Sample{
			SHA256: sha, Source: "test", Label: label, LabelSource: "test",
			Path: path, PURLBase: "pkg:npm/pkg" + fmt.Sprint(n), Version: "1.0.0",
		}
		mustInsert(t, ctx, db, s)
		var traits strings.Builder
		for i := range crit {
			if i > 0 {
				traits.WriteString(",")
			}
			traits.WriteString(`{"l":5}`)
		}
		for i := range suspicious {
			if crit > 0 || i > 0 {
				traits.WriteString(",")
			}
			traits.WriteString(`{"l":4}`)
		}
		result := fmt.Appendf(nil, `{"fs":[{"sha":%q,"type":"npm","x":1,"dp":0,"ts":[%s]}]}`, sha, traits.String())
		if err := db.UpdateCleaveResult(ctx, sha, result, nil, ""); err != nil {
			t.Fatalf("UpdateCleaveResult: %v", err)
		}
		return sha
	}

	// Deliberately DISTINCT member counts per queue (bad 1, good 2, new 3,
	// sighted 4). With one member each, any two predicates agree by accident and
	// the agreement assertion passes even when the count is reading the wrong
	// population — which is exactly how this test first failed to catch a
	// swapped predicate.
	add("bad", 0, 0, "bad/quiet.whl") // bad, undetected → bad queue (1)
	add("bad", 1, 1, "bad/loud.whl")  // bad, detected   → excluded

	add("good", 1, 0, "good/hostile.whl") // good queue (2)
	add("good", 0, 2, "good/two-sus.whl") // suspicious_count=2 also qualifies
	add("good", 0, 0, "good/clean.whl")   // silent    → excluded
	add("good", 0, 1, "good/one-sus.whl") // count=1   → excluded

	add("unknown", 0, 1, "npm/sus1.tgz")    // new queue (3)
	add("unknown", 1, 0, "npm/sus2.tgz")    // hostile counts toward suspicious_count
	add("unknown", 0, 3, "npm/sus3.tgz")    //
	add("unknown", 0, 0, "npm/quiet.tgz")   // silent      → excluded
	add("unknown", 0, 1, "review/held.tgz") // review pool → excluded

	var sighted []Sighting
	for _, sha := range []string{
		add("sighted", 0, 0, "feed/a.bin"), // sighted queue (4): no finding predicate
		add("sighted", 1, 1, "feed/b.bin"),
		add("sighted", 0, 2, "feed/c.bin"),
		add("sighted", 0, 0, "feed/d.bin"),
	} {
		sighted = append(sighted, Sighting{Source: "feed", Subject: sha})
	}
	if _, err := db.AddSightings(ctx, sighted); err != nil {
		t.Fatalf("AddSightings(sighted fixtures): %v", err)
	}

	// popular discriminates on ranked-package membership as well as on max_crit,
	// and lands on 5 — distinct from every other queue above.
	var ranked []PopularPackage
	for _, i := range []int{3, 4, 5, 6, 7, 8, 9, 10} {
		ranked = append(ranked, PopularPackage{
			PURLBase: fmt.Sprintf("pkg:npm/pkg%d", i), Ecosystem: "npm", Rank: i, Source: "poppy",
		})
	}
	if err := db.SetPopularPackages(ctx, ranked); err != nil {
		t.Fatalf("SetPopularPackages: %v", err)
	}

	// Pin the populations outright. Agreement alone cannot tell a count reading
	// the wrong predicate from one reading the right one, if both happen to
	// return the same number.
	wantDepth := map[string]int64{"bad": 1, "good": 2, "new": 3, "sighted": 4}

	const wide = 1000
	for _, tc := range []struct {
		name   string
		count  func(context.Context, TriageFilter) (int64, error)
		selekt func(context.Context, int, TriageFilter) ([]*Sample, error)
	}{
		{"bad", func(ctx context.Context, f TriageFilter) (int64, error) {
			return db.CountTriageBad(ctx, time.Time{}, f)
		}, func(ctx context.Context, n int, f TriageFilter) ([]*Sample, error) {
			return db.TriageBad(ctx, n, time.Time{}, f)
		}},
		{"good", db.CountTriageGood, db.TriageGood},
		{"new", db.CountTriageNew, db.TriageNew},
		{"sighted", db.CountTriageSighted, db.TriageSighted},
		{"popular", func(ctx context.Context, f TriageFilter) (int64, error) {
			return db.CountTriagePopular(ctx, time.Time{}, f)
		}, func(ctx context.Context, n int, f TriageFilter) ([]*Sample, error) {
			return db.TriagePopular(ctx, n, time.Time{}, f)
		}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			// Both orderings: a -stale queue counts the same population through
			// a different filter, and the filter clause is shared code that the
			// count path has to thread correctly too.
			for _, f := range []TriageFilter{{}, {Order: TriageStale, ExcludeReportType: tc.name}} {
				got, err := tc.count(ctx, f)
				if err != nil {
					t.Fatalf("count: %v", err)
				}
				selected, err := tc.selekt(ctx, wide, f)
				if err != nil {
					t.Fatalf("select: %v", err)
				}
				if got != int64(len(selected)) {
					t.Errorf("filter %+v: depth = %d, selection = %d — the count and the "+
						"queue no longer describe the same population", f, got, len(selected))
				}
				if got == 0 {
					t.Errorf("filter %+v: fixture produced no members; the test would pass vacuously", f)
				}
				if want, ok := wantDepth[tc.name]; ok && got != want {
					t.Errorf("filter %+v: depth = %d, want %d — the count is reading the wrong population",
						f, got, want)
				}
			}
		})
	}
}

// The scored queues report a POPULATION, not a selection, so they get their own
// contract: the divider must actually divide, and the drain must actually
// exclude. Without this the numbers are unfalsifiable — any constant would look
// plausible on a dashboard.
func TestScoredDepthsSplitOnTheDivider(t *testing.T) {
	ctx := t.Context()
	db := openTestDB(t)

	var n int
	add := func(label string, score float64) {
		n++
		sha := fmt.Sprintf("%063x1", n)
		mustInsert(t, ctx, db, &Sample{
			SHA256: sha, Source: "test", Label: label, LabelSource: "test",
			Path: fmt.Sprintf("%s/s%d.whl", label, n),
		})
		result := fmt.Appendf(nil, `{"fs":[{"sha":%q,"type":"npm","x":1,"dp":0,"ts":[{"l":4}]}]}`, sha)
		if err := db.UpdateCleaveResult(ctx, sha, result, nil, ""); err != nil {
			t.Fatalf("UpdateCleaveResult: %v", err)
		}
		litmus := fmt.Appendf(nil, `{"lvl":0,"prob":%g}`, score)
		if err := db.UpdateLitmusResult(ctx, sha, litmus); err != nil {
			t.Fatalf("UpdateLitmusResult: %v", err)
		}
	}

	// Straddle the divider exactly: 0.5 belongs to highest (>=), not lowest (<).
	add("good", 0.90) // good scored hostile  → highest
	add("good", 0.50) // exactly the divider  → highest
	add("good", 0.49) // model agrees it is benign → neither
	add("bad", 0.10)  // bad scored clean     → lowest
	add("bad", 0.49)  // still below          → lowest
	add("bad", 0.50)  // model agrees it is bad → neither

	future := time.Now().Add(time.Hour)
	past := time.Now().Add(-time.Hour)

	got, err := db.CountTriageHighest(ctx, TriageScoreDivider, future, past, TriageFilter{})
	if err != nil {
		t.Fatalf("CountTriageHighest: %v", err)
	}
	if got != 2 {
		t.Errorf("highest depth = %d, want 2 (0.90 and the boundary 0.50)", got)
	}
	got, err = db.CountTriageLowest(ctx, TriageScoreDivider, future, past, TriageFilter{})
	if err != nil {
		t.Fatalf("CountTriageLowest: %v", err)
	}
	if got != 2 {
		t.Errorf("lowest depth = %d, want 2 (0.10 and 0.49; 0.50 is not below the divider)", got)
	}

	// createdBefore must bound the population, or the depth ignores the grace
	// window the queues themselves respect.
	got, err = db.CountTriageHighest(ctx, TriageScoreDivider, past, past, TriageFilter{})
	if err != nil {
		t.Fatalf("CountTriageHighest: %v", err)
	}
	if got != 0 {
		t.Errorf("highest depth with an exhausted grace window = %d, want 0", got)
	}
}

// The cap is what keeps a depth query's cost bounded by us rather than by
// whichever queue happens to be largest.
func TestTriageDepthIsCapped(t *testing.T) {
	if TriageDepthCap <= 0 {
		t.Fatalf("TriageDepthCap = %d; an unbounded count is the thing this exists to prevent", TriageDepthCap)
	}
}

// The merged fallout predicate: a sample qualifies if it is UNDESCRIBED (no
// interpretation) or UNCORROBORATED (nobody outside has cited it), and drops out
// only when both are satisfied. Measurement said these are one population — over
// a 7-day window the undescribed set was a strict subset of the uncorroborated
// one — but "strict subset today" is a snapshot, and the OR is what keeps the
// smaller half from being silently dropped if that ever stops being true.
func TestTriageFalloutTakesUndescribedOrUncorroborated(t *testing.T) {
	ctx := t.Context()
	db := openTestDB(t)

	var n int
	add := func(interpreted, corroborated bool) string {
		n++
		sha := fmt.Sprintf("%063x1", n)
		mustInsert(t, ctx, db, &Sample{
			SHA256: sha, Source: "test", Label: "unknown", LabelSource: "test",
			Path: fmt.Sprintf("npm/s%d.tgz", n),
		})
		res := fmt.Appendf(nil, `{"fs":[{"sha":%q,"type":"npm","x":1,"dp":0,"ts":[{"l":5}]}]}`, sha)
		if err := db.UpdateCleaveResult(ctx, sha, res, nil, ""); err != nil {
			t.Fatalf("UpdateCleaveResult: %v", err)
		}
		// litmus_class 2 is the /fallout page's population.
		if err := db.UpdateLitmusResult(ctx, sha, []byte(`{"lvl":0,"prob":0.99,"class":2}`)); err != nil {
			t.Fatalf("UpdateLitmusResult: %v", err)
		}
		if interpreted {
			if _, err := db.lite.ExecContext(ctx,
				`UPDATE samples SET llm_result = '{"interpretation":"a described sample"}' WHERE sha256 = ?`,
				sha); err != nil {
				t.Fatalf("set llm_result: %v", err)
			}
		}
		if corroborated {
			if _, err := db.lite.ExecContext(ctx,
				`UPDATE samples SET corroborated = 1 WHERE sha256 = ?`, sha); err != nil {
				t.Fatalf("set corroborated: %v", err)
			}
		}
		return sha
	}

	neither := add(false, false)    // undescribed AND uncorroborated → selected
	undescribed := add(false, true) // described? no. corroborated → still selected
	uncorrob := add(true, false)    // described but uncorroborated    → still selected
	settled := add(true, true)      // described AND corroborated       → the only exclusion

	got, err := db.TriageFallout(ctx, 100, time.Time{}, TriageFilter{})
	if err != nil {
		t.Fatalf("TriageFallout: %v", err)
	}
	selected := map[string]bool{}
	for _, s := range got {
		selected[s.SHA256] = true
	}
	for _, want := range []struct {
		sha, why string
	}{
		{neither, "undescribed and uncorroborated"},
		{undescribed, "undescribed (corroborated, but still has no rationale)"},
		{uncorrob, "uncorroborated (described, but nobody outside cited it)"},
	} {
		if !selected[want.sha] {
			t.Errorf("fallout dropped a sample that is %s", want.why)
		}
	}
	if selected[settled] {
		t.Error("fallout selected a sample that is both described and corroborated; " +
			"nothing is left to ask about it")
	}
}

// A sighting whose subject is a digest dressed as a package must be stored as
// the digest, both on the way in and when the canonicaliser sweeps what is
// already there. This is the ledger side of forager's sightingSubject bug: the
// producer minted pkg:<eco>/<64 hex> and nothing here refused it, so 1,050 rows
// named nothing at all — 901 of them samples we hold, 767 convicted malware
// reading as uncorroborated to the acquit queue.
func TestSightingDigestWearingAPURLIsFoldedBack(t *testing.T) {
	const sha = "00027cd3ed57fe8dce74c50beb4179e430ce731cfccd6ec61d98d8e92806e219"
	for _, subject := range []string{
		"pkg:npm/" + sha,
		"pkg:pypi/" + sha,
		"pkg:npm/" + sha + "@1.0.0",
		"pkg:npm/" + strings.ToUpper(sha),
	} {
		if got := normalizeSubject(subject); got != sha {
			t.Errorf("normalizeSubject(%.28s…) = %q, want the bare digest", subject, got)
		}
	}
	// A real package is untouched, including one whose name is short hex.
	for subject, want := range map[string]string{
		"pkg:npm/left-pad":   "pkg:npm/left-pad",
		"pkg:npm/deadbeef":   "pkg:npm/deadbeef",
		"pkg:npm/lodash@1.2": "pkg:npm/lodash",
	} {
		if got := normalizeSubject(subject); got != want {
			t.Errorf("normalizeSubject(%q) = %q, want %q", subject, got, want)
		}
	}
}

// The stored-row repair: AddSightings folds on the way in, and the canonicaliser
// folds what predates the fix, preserving the row rather than discarding it.
func TestAddSightingsStoresTheDigest(t *testing.T) {
	ctx := t.Context()
	db := openTestDB(t)
	const sha = "00027cd3ed57fe8dce74c50beb4179e430ce731cfccd6ec61d98d8e92806e219"

	if _, err := db.AddSightings(ctx, []Sighting{{
		Source: "bazaar", Subject: "pkg:npm/" + sha, URL: "https://mb-api.abuse.ch/api/v1/",
	}}); err != nil {
		t.Fatalf("AddSightings: %v", err)
	}
	got, err := db.SightingsFor(ctx, []string{sha})
	if err != nil {
		t.Fatalf("SightingsFor: %v", err)
	}
	if len(got[sha]) != 1 {
		t.Fatalf("SightingsFor(%s) = %+v, want the citation keyed on the digest", sha, got)
	}
	if got[sha][0].URL == "" {
		t.Error("the row's provenance must survive the fold")
	}
}
