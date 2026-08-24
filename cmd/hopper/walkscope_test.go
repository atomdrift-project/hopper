package main

import (
	"testing"
	"time"
)

// mark builds a stamp that was read successfully.
func mark(at time.Time) reconcileMark { return reconcileMark{at: at, ok: true} }

// absent is a stamp that was missing, unreadable or unparseable. All three read
// the same way on purpose: none of them is evidence that a pass happened.
var absent = reconcileMark{}

// The rule that decides whether a start re-walks the whole corpus.
//
// It must fail safe — anything that is not positive evidence of a recent pass
// reconciles — while still being an actual once-a-day guard, which means a pass
// that STARTED counts even if it never finished. Gating on completion alone is
// what turned nineteen restarts in twenty hours into thirty-six concurrent
// full-tree walks.
func TestWalkScopeFailsSafe(t *testing.T) {
	now := time.Date(2026, 8, 24, 12, 0, 0, 0, time.UTC)
	recent := now.Add(-30 * time.Minute)
	stale := now.Add(-2 * reconcileWalkInterval)
	future := now.Add(2 * time.Hour)

	tests := []struct {
		name          string
		done, attempt reconcileMark
		wantReconcile bool
		why           string
	}{
		{
			"finished recently", mark(recent), absent, false,
			"a pass inside the window makes a restart incremental",
		},
		{
			"finished long ago", mark(stale), absent, true,
			"past the window the guarantee requires a full pass",
		},
		{
			"never recorded", absent, absent, true,
			"a fresh cluster must reconcile",
		},
		{
			"unreadable stamps", absent, absent, true,
			"an unanswerable database must not skip reconcile",
		},
		{
			"finished in the future", mark(future), absent, true,
			"a moved clock must not suppress reconcile forever",
		},

		// The case the guard exists for.
		{
			"started recently, never finished", absent, mark(recent), false,
			"a full pass already under way today must not be joined by another",
		},
		{
			"started long ago, never finished", absent, mark(stale), true,
			"an attempt older than the window has stopped being a reason to wait",
		},
		{
			"started in the future", absent, mark(future), true,
			"a moved clock must not suppress reconcile forever, on either stamp",
		},

		// A finished pass is better evidence than an abandoned one, and a stale
		// finish must not be rescued by a recent abandoned attempt being older.
		{
			"finished recently despite an old attempt", mark(recent), mark(stale), false,
			"the completed pass is what counts",
		},
		{
			"both stale", mark(stale), mark(stale), true,
			"neither stamp is current, so a full pass is due",
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := decideWalkScope(tt.done, tt.attempt, false, now)
			if got.reconcile != tt.wantReconcile {
				t.Errorf("reconcile = %v, want %v — %s", got.reconcile, tt.wantReconcile, tt.why)
			}
			if got.reconcile && !got.cutoff.IsZero() {
				t.Errorf("a reconcile pass must walk everything, got cutoff %v", got.cutoff)
			}
			if !got.reconcile && got.cutoff.IsZero() {
				t.Error("an incremental pass needs a cutoff, got the zero time (which means full)")
			}
		})
	}
}

// The incremental cutoff is the previous pass's START, never "now": anything
// written while that pass ran must be re-examined, not assumed seen.
func TestWalkScopeCutoffIsConservative(t *testing.T) {
	now := time.Date(2026, 8, 24, 12, 0, 0, 0, time.UTC)
	started := now.Add(-time.Hour)

	got := decideWalkScope(mark(started), absent, false, now)
	if got.reconcile {
		t.Fatal("a one-hour-old reconcile is current; want incremental")
	}
	if !got.cutoff.Equal(started) {
		t.Errorf("cutoff = %v, want the pass start %v", got.cutoff, started)
	}

	// An abandoned attempt bounds the catch-up the same way.
	got = decideWalkScope(absent, mark(started), false, now)
	if got.reconcile {
		t.Fatal("an attempt from an hour ago is current; want incremental")
	}
	if !got.cutoff.Equal(started) {
		t.Errorf("cutoff = %v, want the attempt start %v", got.cutoff, started)
	}
	if !got.unfinished {
		t.Error("a decision resting on an abandoned pass must say so; that is the line that explains a late reconcile")
	}
}

// --force-walk is the only way past the guard, and it must work from every
// state — including the one where a pass is recorded as having just finished.
func TestWalkScopeForceOverridesEveryStamp(t *testing.T) {
	now := time.Date(2026, 8, 24, 12, 0, 0, 0, time.UTC)
	recent := mark(now.Add(-time.Minute))

	for _, tt := range []struct {
		name          string
		done, attempt reconcileMark
	}{
		{"just finished", recent, absent},
		{"just started", absent, recent},
		{"nothing recorded", absent, absent},
	} {
		t.Run(tt.name, func(t *testing.T) {
			got := decideWalkScope(tt.done, tt.attempt, true, now)
			if !got.reconcile {
				t.Error("--force-walk must reconcile whatever the stamps say")
			}
			if !got.cutoff.IsZero() {
				t.Errorf("a forced pass walks everything, got cutoff %v", got.cutoff)
			}
			if !got.forced {
				t.Error("a forced pass must be reported as forced, so the log says why it is running")
			}
		})
	}
}

// A restart storm must not become a full-walk storm. This is the outage in
// miniature: one pass starts, and every start that follows inside the day walks
// incrementally instead of launching another full one beside it.
func TestWalkScopeSurvivesARestartStorm(t *testing.T) {
	start := time.Date(2026, 8, 24, 0, 0, 0, 0, time.UTC)

	// The first start reconciles, and stamps the attempt.
	first := decideWalkScope(absent, absent, false, start)
	if !first.reconcile {
		t.Fatal("the first start of a fresh cluster must reconcile")
	}
	attempt := mark(start)

	// It never finishes. Nineteen restarts follow over the next twenty hours.
	for i := 1; i <= 19; i++ {
		at := start.Add(time.Duration(i) * time.Hour)
		got := decideWalkScope(absent, attempt, false, at)
		if got.reconcile {
			t.Fatalf("restart %d at %v started a second full walk; the first is still running", i, at)
		}
	}

	// A day after the attempt, a reconcile is genuinely due again.
	due := start.Add(reconcileWalkInterval)
	if got := decideWalkScope(absent, attempt, false, due); !got.reconcile {
		t.Error("a day after the abandoned pass, a full walk must be due again")
	}
}
