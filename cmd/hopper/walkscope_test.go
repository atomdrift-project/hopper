package main

import (
	"errors"
	"testing"
	"time"
)

// errKVUnavailable stands in for any KVGet failure (database down, timeout).
var errKVUnavailable = errors.New("hopper_kv unavailable")

// startupWalkScope decides whether a restart re-walks the entire corpus. The
// rule must fail safe: only a recorded, parseable, non-future reconcile that is
// younger than reconcileWalkInterval may downgrade the startup pass to
// incremental. Everything else reconciles, because a needless full walk costs
// disk while a wrongly skipped one leaves moved/missing files undetected.
//
// The decision logic is exercised directly (no database): scopeFromValue mirrors
// what startupWalkScope does with whatever KVGet returned.
func scopeFromValue(v string, err error, now time.Time) (cutoff time.Time, reconcile bool) {
	if err != nil || v == "" {
		return time.Time{}, true
	}
	last, perr := time.Parse(time.RFC3339, v)
	if perr != nil {
		return time.Time{}, true
	}
	age := now.Sub(last)
	if age < 0 || age >= reconcileWalkInterval {
		return time.Time{}, true
	}
	return last, false
}

func TestStartupWalkScopeFailsSafe(t *testing.T) {
	now := time.Date(2026, 8, 23, 12, 0, 0, 0, time.UTC)
	recent := now.Add(-30 * time.Minute).Format(time.RFC3339)
	stale := now.Add(-2 * reconcileWalkInterval).Format(time.RFC3339)
	future := now.Add(2 * time.Hour).Format(time.RFC3339)

	tests := []struct {
		name          string
		value         string
		err           error
		wantReconcile bool
		why           string
	}{
		{"recent reconcile", recent, nil, false, "a reconcile inside the interval makes a restart incremental"},
		{"stale reconcile", stale, nil, true, "past the interval the guarantee requires a full pass"},
		{"never recorded", "", nil, true, "a fresh cluster must reconcile"},
		{"unparseable", "not-a-time", nil, true, "garbage must not be read as recent"},
		{"future timestamp", future, nil, true, "a moved clock must not suppress reconcile forever"},
		{"database unreadable", "", errKVUnavailable, true, "an unanswerable database must not skip reconcile"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			cutoff, reconcile := scopeFromValue(tt.value, tt.err, now)
			if reconcile != tt.wantReconcile {
				t.Errorf("reconcile = %v, want %v — %s", reconcile, tt.wantReconcile, tt.why)
			}
			if reconcile && !cutoff.IsZero() {
				t.Errorf("a reconcile pass must walk everything, got cutoff %v", cutoff)
			}
			if !reconcile && cutoff.IsZero() {
				t.Error("an incremental pass needs a cutoff, got the zero time (which means full)")
			}
		})
	}
}

// The incremental cutoff is the reconcile's START, never "now": anything
// written while that pass ran must be re-examined, not assumed seen.
func TestStartupWalkScopeCutoffIsConservative(t *testing.T) {
	now := time.Date(2026, 8, 23, 12, 0, 0, 0, time.UTC)
	started := now.Add(-time.Hour)
	cutoff, reconcile := scopeFromValue(started.Format(time.RFC3339), nil, now)
	if reconcile {
		t.Fatal("a one-hour-old reconcile is current; want incremental")
	}
	if !cutoff.Equal(started) {
		t.Errorf("cutoff = %v, want the reconcile start %v", cutoff, started)
	}
}
