package main

import (
	"strings"
	"testing"
	"time"

	"github.com/atomdrift-project/hopper"
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
	eta, drain, measured := queueETA(6000, etaSeries(24, -100), pendingOf)
	if eta == "" {
		t.Fatalf("a steadily draining queue must produce an ETA (drain=%v)", drain)
	}
	if drain <= 0 {
		t.Errorf("drain = %v, want positive for a falling depth", drain)
	}
	if !measured {
		t.Error("measured = false with a full window of samples")
	}
	if want := formatETA(time.Duration(float64(6000)/drain) * time.Second); eta != want {
		t.Errorf("eta = %q, want %q", eta, want)
	}

	// THE REGRESSION. Ingestion outruns drain, so the depth climbs. The old
	// depth/rate model had no arrival term and reported a cheerful few hours
	// here; the honest answer is that there is no ETA.
	eta, drain, measured = queueETA(50000, etaSeries(24, +500), pendingOf)
	if eta != "" {
		t.Errorf("a growing queue must not report an ETA, got %q", eta)
	}
	if drain >= 0 {
		t.Errorf("drain = %v, want negative for a rising depth", drain)
	}
	if !measured {
		t.Error("a full window of samples must be measured even when growing")
	}

	// Flat: not draining, and not a divide-by-zero either.
	if eta, _, measured = queueETA(50000, etaSeries(24, 0), pendingOf); eta != "" || !measured {
		t.Errorf("a flat queue must not report an ETA, got %q", eta)
	}

	// Too little history to call a slope: two samples ten minutes apart could
	// straddle a burst. Silence beats a number the window cannot support.
	if eta, _, measured = queueETA(6000, etaSeries(2, -100), pendingOf); eta != "" || measured {
		// measured=false is the whole point: rendering thin history as "not
		// draining" told a live dashboard its queue was stalled while 21
		// rescans/sec were landing.
		t.Errorf("insufficient history: eta=%q measured=%v, want empty and false", eta, measured)
	}

	// An empty queue has nothing to wait for.
	if eta, _, _ = queueETA(0, etaSeries(24, -100), pendingOf); eta != "" {
		t.Errorf("an empty queue must not report an ETA, got %q", eta)
	}
}

// TestQueueETAClampsInsteadOfOverflowing covers the arithmetic, not the policy.
// depth/drain is unbounded as drain approaches zero, and converting the result
// straight to a Duration wraps int64 — which printed a large NEGATIVE age rather
// than a long one. The clamp has to happen before the conversion.
func TestQueueETAClampsInsteadOfOverflowing(t *testing.T) {
	// 24 samples five minutes apart, falling by 1 each: a drain of ~1/300 per
	// second against a backlog of 3.2M, i.e. ~30 years.
	eta, drain, _ := queueETA(3_200_000, etaSeries(24, -1), pendingOf)
	if drain <= 0 {
		t.Fatalf("drain = %v, want positive", drain)
	}
	if eta == "" {
		t.Fatal("a draining queue should still report something")
	}
	if strings.HasPrefix(eta, "-") {
		t.Errorf("eta = %q: negative duration, the int64 overflow is back", eta)
	}
	if want := formatETA(etaMax); eta != want {
		t.Errorf("eta = %q, want it clamped to %q", eta, want)
	}

	// The case that genuinely wraps int64. A least-squares fit over noisy
	// samples yields arbitrarily small positive slopes, so this is reachable:
	// a 3.2M backlog that nets one item lower across the whole six-hour window
	// is ~4.6e-5/s, i.e. 6.9e10 seconds, i.e. 6.9e19 nanoseconds against an
	// int64 ceiling of 9.2e18.
	base := time.Now().Add(-6 * time.Hour)
	pts := make([]queuePoint, 24)
	for i := range pts {
		depth := int64(3_200_000)
		if i == len(pts)-1 {
			depth-- // one item lower, six hours later
		}
		pts[i] = queuePoint{T: base.Add(time.Duration(i) * 15 * time.Minute), Pending: depth}
	}
	eta, drain, _ = queueETA(3_200_000, pts, pendingOf)
	if drain <= 0 {
		t.Fatalf("drain = %v, want a small positive slope", drain)
	}
	if strings.HasPrefix(eta, "-") {
		t.Fatalf("eta = %q: negative duration, the int64 overflow is back", eta)
	}
	if want := formatETA(etaMax); eta != want {
		t.Errorf("eta = %q, want it clamped to %q", eta, want)
	}
}

// TestFlowRatesSurvivesRestartsAndOldCaches covers the two ways the cumulative
// counters lie. Completed is an in-memory session counter that resets to its DB
// baseline on restart, and rows written before the `added` column carry zero;
// plotting either raw draws a cliff that reads as "ingest stopped".
func TestFlowRatesSurvivesRestartsAndOldCaches(t *testing.T) {
	base := time.Now().Add(-time.Hour)
	at := func(i int) time.Time { return base.Add(time.Duration(i) * 5 * time.Minute) }

	// Two legacy rows (added=0), then a restart that drops Completed.
	pts := []queuePoint{
		{T: at(0), Added: 0, Completed: 900},
		{T: at(1), Added: 0, Completed: 1000},
		{T: at(2), Added: 5000, Completed: 1100},
		{T: at(3), Added: 5300, Completed: 40}, // restart: counter reset
		{T: at(4), Added: 5600, Completed: 340},
		{T: at(5), Added: 5900, Completed: 640},
	}
	f := flowRates(pts)
	if !f.usable {
		t.Fatal("usable = false with three real intervals")
	}
	if len(f.in) != 3 {
		t.Fatalf("len(in) = %d, want 3; legacy added=0 rows must be skipped", len(f.in))
	}
	for i, v := range f.out {
		if v < 0 {
			t.Errorf("out[%d] = %v: a counter reset must clamp to zero, not plot negative work", i, v)
		}
	}
	for i, v := range f.in {
		if v <= 0 {
			t.Errorf("in[%d] = %v, want a positive arrival rate", i, v)
		}
	}
}

// TestSystemStatusPromotesTheWorstProblem pins the triage rule. A dashboard that
// reports five problems at equal weight has not triaged anything, so the
// headline carries the most actionable one and the rest trail as facts.
func TestSystemStatusPromotesTheWorstProblem(t *testing.T) {
	stale := hopper.WorkflowHealth{
		LatestAdded:    time.Now().Add(-3 * time.Hour),
		LatestAnalyzed: time.Now().Add(-2 * time.Second),
	}
	backlogs := []hopper.WorkflowBacklog{
		{OldestPending: time.Now().Add(-71 * 24 * time.Hour), NewestPending: time.Now().Add(-33 * 24 * time.Hour)},
	}
	var buf strings.Builder
	writeSystemStatus(&buf, &statusInputs{health: stale, backlogs: backlogs, pendingLitmus: 169196})
	out := buf.String()
	if !strings.Contains(out, "No sample ingested in") {
		t.Errorf("a stalled ingest must be the headline, got %q", out)
	}
	if !strings.Contains(out, "status-bad") {
		t.Errorf("a stalled ingest must render red, got %q", out)
	}
	// The unpromoted backlog still gets said, quietly.
	if !strings.Contains(out, "no litmus score") {
		t.Errorf("secondary issues must still appear in the facts line, got %q", out)
	}

	// All clear.
	var ok strings.Builder
	writeSystemStatus(&ok, &statusInputs{health: hopper.WorkflowHealth{
		LatestAdded: time.Now().Add(-10 * time.Second), LatestAnalyzed: time.Now().Add(-5 * time.Second),
	}})
	if !strings.Contains(ok.String(), "Pipeline healthy") || !strings.Contains(ok.String(), "status-ok") {
		t.Errorf("a healthy pipeline must say so plainly, got %q", ok.String())
	}
}

// TestClaimTierOrderMatchesLadder is the guard the static order promises. The
// ladder is built per request and its shape varies by caller, so the panel's
// order is a hand-written list -- which means it can drift from the scheduler it
// claims to describe, and a ladder panel in the wrong order is worse than none.
func TestClaimTierOrderMatchesLadder(t *testing.T) {
	s := &apiServer{
		tracker:             newWorkerTracker(),
		forceRescanPrefixes: []string{"incoming/"}, // make the conditional tier appear
	}
	// A large slot count so no tier is filtered out by minSlots.
	var built []string
	for _, tier := range s.claimLadder(4096) {
		built = append(built, tier.name)
	}
	want := claimTierOrder()
	if len(built) != len(want) {
		t.Fatalf("ladder has %d tiers %v, claimTierOrder has %d %v", len(built), built, len(want), want)
	}
	for i := range want {
		if built[i] != want[i] {
			t.Errorf("position %d: ladder has %q, claimTierOrder has %q", i, built[i], want[i])
		}
	}
}

// TestSparklineScalesFromZero pins the scaling choice. Queue depths that drift
// by a fraction of a percent are flat in every sense a reader cares about;
// scaling from the series minimum would draw that as a dramatic slope.
func TestSparklineScalesFromZero(t *testing.T) {
	flat := []float64{3_400_000, 3_401_000, 3_400_500, 3_401_200}
	out := sparkline(flat, "#818cf8")
	if out == "" {
		t.Fatal("no sparkline rendered")
	}
	// Every y must sit near the top of the box: values are ~100% of the max.
	for pair := range strings.FieldsSeq(strings.SplitN(strings.SplitN(out, `points="`, 2)[1], `"`, 2)[0]) {
		y := strings.SplitN(pair, ",", 2)[1]
		if y[0] != '1' && y[0] != '2' {
			t.Errorf("y=%s: a near-flat series must render flat, not swing the full box", y)
		}
	}
	if got := trendArrow(flat); !strings.Contains(got, "flat") {
		t.Errorf("trendArrow = %q, want flat for a <2%% drift", got)
	}
	if got := trendArrow([]float64{1000, 500}); !strings.Contains(got, "shrinking") {
		t.Errorf("trendArrow = %q, want shrinking", got)
	}
	if got := trendArrow([]float64{500, 1000}); !strings.Contains(got, "growing") {
		t.Errorf("trendArrow = %q, want growing", got)
	}
	if got := sparkline([]float64{5}, "#fff"); got != "" {
		t.Errorf("a single point is not a trend, got %q", got)
	}
}

// TestClaimLadderFlagsStarvation covers the row the panel exists for: a tier
// with work waiting that has handed out nothing. That is the starvation case,
// and in a strictly ordered ladder it is the expected consequence of the tiers
// above being busy -- which is only visible if the panel says so.
func TestClaimLadderFlagsStarvation(t *testing.T) {
	var buf strings.Builder
	writeClaimLadder(&buf,
		map[string]int64{tierUnanalyzed: 900},
		map[string]int64{tierUnanalyzed: 130, tierRescanAge: 3_100_000},
		nil)
	out := buf.String()
	if !strings.Contains(out, "idle with work waiting") {
		t.Errorf("a tier with depth and no claims must be called out:\n%s", out)
	}
	if !strings.Contains(out, tierLabel(tierRescanAge)) {
		t.Errorf("every tier must appear, even idle ones:\n%s", out)
	}
	if !strings.Contains(out, "ladder-bar") {
		t.Errorf("an active tier must render a share bar:\n%s", out)
	}
}
