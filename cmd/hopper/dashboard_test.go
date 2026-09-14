package main

import (
	"testing"
	"time"
)

func TestFormatETA(t *testing.T) {
	tests := []struct {
		d    time.Duration
		want string
	}{
		{30 * time.Second, "30s"},
		{90 * time.Second, "1m30s"},
		{2*time.Hour + 5*time.Minute, "2h05m"},
		{25 * time.Hour, "1d01h"},                      // days branch: 1 day, 1 hour
		{104*24*time.Hour + 30*time.Minute, "104d00h"}, // large rescan ETA reads in days, not 2496h
	}
	for _, tt := range tests {
		if got := formatETA(tt.d); got != tt.want {
			t.Errorf("formatETA(%s) = %q, want %q", tt.d, got, tt.want)
		}
	}
}

// etaSeries builds n queue-depth samples 5 minutes apart (the sampler's real
// interval), starting at 10,000 deep and stepping by delta each sample.
func etaSeries(n int, delta int64) []queuePoint {
	base := time.Now().Add(-time.Duration(n) * 5 * time.Minute)
	pts := make([]queuePoint, n)
	for i := range pts {
		pts[i] = queuePoint{T: base.Add(time.Duration(i) * 5 * time.Minute), Pending: 10000 + int64(i)*delta}
	}
	return pts
}

func pendingOf(p queuePoint) int64 { return p.Pending }

// TestQueueETAUsesObservedSlope covers the two failures that made every earlier
// ETA optimistic: a divisor counting work that drains a different queue, and no
// arrival term at all. A slope has neither, so the cases below are stated in
// terms of what the depth actually did.
func TestQueueETAUsesObservedSlope(t *testing.T) {
	// Draining by 100 every 5 minutes = 1/3 per second. 6000 deep => ~5h.
	eta, drain := queueETA(6000, etaSeries(24, -100), pendingOf)
	if eta == "" {
		t.Fatalf("a steadily draining queue must produce an ETA (drain=%v)", drain)
	}
	if drain <= 0 {
		t.Errorf("drain = %v, want positive for a falling depth", drain)
	}
	if want := formatETA(time.Duration(float64(6000)/drain) * time.Second); eta != want {
		t.Errorf("eta = %q, want %q", eta, want)
	}

	// THE REGRESSION. Ingestion outruns drain, so the depth climbs. The old
	// depth/rate model had no arrival term and reported a cheerful few hours
	// here; the honest answer is that there is no ETA.
	eta, drain = queueETA(50000, etaSeries(24, +500), pendingOf)
	if eta != "" {
		t.Errorf("a growing queue must not report an ETA, got %q", eta)
	}
	if drain >= 0 {
		t.Errorf("drain = %v, want negative for a rising depth", drain)
	}

	// Flat: not draining, and not a divide-by-zero either.
	if eta, _ = queueETA(50000, etaSeries(24, 0), pendingOf); eta != "" {
		t.Errorf("a flat queue must not report an ETA, got %q", eta)
	}

	// Too little history to call a slope: two samples ten minutes apart could
	// straddle a burst. Silence beats a number the window cannot support.
	if eta, _ = queueETA(6000, etaSeries(2, -100), pendingOf); eta != "" {
		t.Errorf("insufficient history must not report an ETA, got %q", eta)
	}

	// An empty queue has nothing to wait for.
	if eta, _ = queueETA(0, etaSeries(24, -100), pendingOf); eta != "" {
		t.Errorf("an empty queue must not report an ETA, got %q", eta)
	}
}
