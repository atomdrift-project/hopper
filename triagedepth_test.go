package hopper

import (
	"fmt"
	"strings"
	"testing"
	"time"
)

// Every registered queue must be able to answer a depth, and answering it must
// execute. Since 2026-09-02 a depth IS the queue's own selection run to the cap
// and counted, so the two can no longer describe different populations -- what
// is left to check is that every queue actually has the selection, and that the
// selection runs.
//
// The population-agreement assertion this replaces was real and it was not
// enough: it covered five queues, two of which (good, new) had already been
// retired from the registry, and the two it did not cover -- highest and lowest
// -- are exactly the two that drifted, by two orders of magnitude, for the eight
// hours it took someone to look at a dashboard. A registry-wide loop is the only
// shape that cannot be out of date.
func TestEveryQueueReportsADepth(t *testing.T) {
	ctx := t.Context()
	db := openTestDB(t)

	for _, name := range TriageQueueNames() {
		t.Run(name, func(t *testing.T) {
			q := TriageQueues[name]
			if q.Select == nil {
				t.Fatalf("%s has no Select; a queue with no selection has no depth either", name)
			}
			got, capped, err := q.Count(ctx, db)
			if err != nil {
				t.Fatalf("Count: %v", err)
			}
			if got < 0 {
				t.Errorf("depth = %d", got)
			}
			if capped {
				t.Errorf("depth = %d and capped on an empty fixture DB; the cap cannot be reachable here", got)
			}
		})
	}
}

// The per-route K is a batching device, so counting through it would report
// roughly routes*K rather than the population the routes are drawn from. The
// two score-ranked queues lift it for their count, and this is what proves the
// lift is wired up: with more than K eligible members on one route, the count
// must see past the bound that the selection stops at.
func TestScoredDepthsSeePastThePerRouteBound(t *testing.T) {
	ctx := t.Context()
	db := openTestDB(t)

	// One route, comfortably more than triagePerRouteK members, all eligible.
	const members = triagePerRouteK + 7
	for i := range members {
		sha := fmt.Sprintf("%063x1", i+1)
		mustInsert(t, ctx, db, &Sample{
			SHA256: sha, Source: "test", Label: "good", LabelSource: "test",
			Path: fmt.Sprintf("good/pin%d.whl", i),
		})
		result := fmt.Appendf(nil, `{"fs":[{"sha":%q,"type":"npm","x":1,"dp":0,"ts":[{"l":4}]}]}`, sha)
		if err := db.UpdateCleaveResult(ctx, sha, result, nil, ""); err != nil {
			t.Fatalf("UpdateCleaveResult: %v", err)
		}
		if err := db.UpdateLitmusResult(ctx, sha, []byte(`{"lvl":0,"prob":1.0}`)); err != nil {
			t.Fatalf("UpdateLitmusResult: %v", err)
		}
	}

	// Called directly rather than through the registry: the registry's closures
	// pin createdBefore to OutlierGrace, and backdating fixtures far enough to
	// clear a 48-hour age floor would test the floor rather than the bound this
	// is about. Everything else is the queue's own query.
	if TriageQueues["highest"].CountSelect == nil {
		t.Fatal("highest has no CountSelect; its count would report the per-route bound")
	}
	future := time.Now().Add(time.Hour)
	selected, err := db.TriageHighest(ctx, TriageDepthCap, triagePerRouteK, future, time.Time{}, time.Time{}, TriageFilter{})
	if err != nil {
		t.Fatalf("select at the batching bound: %v", err)
	}
	counted, err := db.TriageHighest(ctx, TriageDepthCap, TriageDepthCap, future, time.Time{}, time.Time{}, TriageFilter{})
	if err != nil {
		t.Fatalf("select with the bound lifted: %v", err)
	}
	if len(selected) != triagePerRouteK {
		t.Fatalf("selection returned %d from one route, want the per-route bound of %d; "+
			"without the bound applied this test cannot tell the two apart", len(selected), triagePerRouteK)
	}
	if len(counted) != members {
		t.Errorf("depth = %d, want %d (every eligible member); the count is stopping at the "+
			"per-route bound instead of counting the population behind it", len(counted), members)
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
