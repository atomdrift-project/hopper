package main

import (
	"math"
	"slices"
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
	if want := coarsenETA(time.Duration(float64(6000) / drain * float64(time.Second))); eta != want {
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

// TestQueueETARefusesUnusableEstimates covers the arithmetic and the policy
// together, because here they are the same decision.
//
// depth/drain is unbounded as drain approaches zero, and converting the result
// straight to a Duration wraps int64 -- a 2,200-year backlog once rendered as
// "-59s". Printing the clamp instead ("~365d00h") would trade a wrong number for
// a fake-precise one, so an estimate past etaMax is refused and the caller says
// "not draining".
//
// The threshold is deliberately absolute rather than a relative "has this series
// moved much" test: 0.25% of a 3.47M queue is 8,520 rows in six hours, a real
// ~102-day drain worth reporting, while the same fraction of a 233-row queue is
// noise. Size decides, so the guard is stated in time, not percent.
func TestQueueETARefusesUnusableEstimates(t *testing.T) {
	// Barely moving against a huge backlog: past etaMax, so no estimate.
	eta, drain, measured := queueETA(3_200_000, etaSeries(24, -1), pendingOf)
	if eta != "" {
		t.Errorf("an unusably distant ETA must be refused, got %q", eta)
	}
	if !measured {
		t.Error("refusing an estimate is still a measurement")
	}
	if drain <= 0 {
		t.Errorf("drain = %v, want the measured slope reported even with no ETA", drain)
	}

	// A slow but real drain on a large queue DOES get an estimate: 24 samples
	// falling 100 each is ~0.33/s, which against 3.2M rows is ~111 days.
	eta, _, _ = queueETA(3_200_000, etaSeries(24, -100), pendingOf)
	if eta == "" {
		t.Fatal("a real multi-week drain must still be reported")
	}
	if strings.HasPrefix(eta, "-") {
		t.Errorf("eta = %q: negative duration, the int64 overflow is back", eta)
	}
	if !strings.Contains(eta, "d") {
		t.Errorf("eta = %q, want a multi-day estimate", eta)
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

// TestFlowVerdictIgnoresWalkBursts is the cry-wolf guard. On 2026-09-15 the live
// dashboard read "Falling behind by 773.1/s" in red while a walk re-inserted a
// million rows — a routine, bounded, entirely expected operation. A verdict that
// goes critical during normal work teaches its reader to ignore it.
func TestFlowVerdictIgnoresWalkBursts(t *testing.T) {
	steady := make([]float64, 24)
	for i := range steady {
		steady[i] = 2 // draining calmly
	}
	// A walk lands in the middle: three intervals of heavy insertion.
	burst := slices.Clone(steady)
	burst[10], burst[11], burst[12] = -800, -900, -750

	if losing, _ := flowVerdict(flowSeries{net: burst, usable: true}); losing {
		t.Error("a short burst inside a draining window must not read as losing ground")
	}
	// The mean is dragged negative by the burst; the median is not. That
	// difference is the entire point of using one over the other.
	if mean(burst) >= 0 {
		t.Fatalf("premise: mean(burst) = %v, expected the burst to drag it negative", mean(burst))
	}
	if med := medianOf(burst); med <= 0 {
		t.Errorf("medianOf(burst) = %v, want it to survive the burst", med)
	}

	// Sustained growth IS losing ground, and must still be reported -- but the
	// RATE it reports has to be representative. Here the backlog grows steadily
	// at 5/s with two extreme spikes; persistence correctly says "losing", and
	// the median is what keeps the headline from claiming 200/s on the strength
	// of two samples. This is the case the median exists for: the persistence
	// test alone cannot tell a typical rate from an outlier-dragged one.
	sustained := make([]float64, 24)
	for i := range sustained {
		sustained[i] = -5
	}
	sustained[3], sustained[17] = -2400, -2600
	losing, netRate := flowVerdict(flowSeries{net: sustained, usable: true})
	if !losing {
		t.Error("a persistently growing backlog must read as losing ground")
	}
	if netRate >= 0 {
		t.Errorf("netRate = %v, want negative", netRate)
	}
	if netRate < -20 {
		t.Errorf("netRate = %v: two spikes are dictating the headline; "+
			"a typical interval was -5/s", netRate)
	}

	// A bare majority of negative intervals is not enough on its own.
	mixed := make([]float64, 20)
	for i := range mixed {
		if i%2 == 0 {
			mixed[i] = -3
		} else {
			mixed[i] = 3
		}
	}
	if losing, _ := flowVerdict(flowSeries{net: mixed, usable: true}); losing {
		t.Error("an evenly split window must not read as losing ground")
	}

	// No data is not good news.
	if losing, _ := flowVerdict(flowSeries{}); losing {
		t.Error("an unusable series must not assert a verdict")
	}
}

// TestFlowDetailAgreesWithVerdict pins the consistency the live dashboard broke.
// It rendered "Gaining ground   in 1283/s · out 749/s · net -534/s" — the
// headline and its own detail line disagreeing, because the verdict came from
// queue depth while the detail came from a session counter that resets on
// restart and therefore under-reported completions for the rest of the window.
func TestFlowDetailAgreesWithVerdict(t *testing.T) {
	base := time.Now().Add(-2 * time.Hour)
	// A restart 5 samples in: Completed collapses to a fresh baseline while the
	// arrival watermark and the depth both keep going.
	var pts []queuePoint
	for i := range 24 {
		completed := int64(5_000_000 + i*300)
		if i >= 5 {
			completed = int64(i * 300) // counter reset
		}
		pts = append(pts, queuePoint{
			T:       base.Add(time.Duration(i) * 5 * time.Minute),
			Added:   int64(1_000_000 + i*400),
			Pending: int64(1000 - i*2), // depth falling: we ARE gaining ground
			Rescan:  0,
			// Completed is the unreliable one; out must not depend on it.
			Completed: completed,
		})
	}
	f := flowRates(pts)
	if !f.hasRates {
		t.Fatal("expected in/out rates from a series carrying the watermark")
	}
	losing, net := flowVerdict(f)
	if losing {
		t.Errorf("depth is falling; verdict should not be losing (net=%v)", net)
	}
	// out - in must reproduce the same net the headline asserts, by construction.
	if got, want := mean(f.out)-mean(f.in), mean(f.net); math.Abs(got-want) > 1e-9 {
		t.Errorf("out-in = %v but net = %v; the detail line can contradict the headline", got, want)
	}
	for i, v := range f.out {
		if v < 0 {
			t.Errorf("out[%d] = %v, want no negative completion rate", i, v)
		}
	}
}

// TestSystemStatusSeparatesChronicFromAcute pins the distinction the screenshot
// exposed: the headline read "168,906 files have no litmus score, oldest 138d"
// on every render, and had for months. A top line that never changes is one
// nobody reads, so a standing backlog is stated in the facts while the headline
// stays reserved for what actually changed.
func TestSystemStatusSeparatesChronicFromAcute(t *testing.T) {
	fresh := hopper.WorkflowHealth{
		LatestAdded:    time.Now().Add(-5 * time.Second),
		LatestAnalyzed: time.Now().Add(-3 * time.Second),
	}
	chronic := []hopper.WorkflowBacklog{
		{OldestPending: time.Now().Add(-138 * 24 * time.Hour)},
	}

	var buf strings.Builder
	writeSystemStatus(&buf, &statusInputs{health: fresh, backlogs: chronic, pendingLitmus: 168906})
	out := buf.String()
	if strings.Contains(out, "168,906 files have no litmus score</span>") {
		t.Error("a months-old backlog must not own the headline")
	}
	if !strings.Contains(out, "Healthy, with a standing backlog") {
		t.Errorf("want the standing-backlog headline, got %q", out)
	}
	if strings.Contains(out, "status-ok") {
		t.Error("a standing backlog is not an all-clear")
	}
	// Still reported, just not shouted.
	if !strings.Contains(out, "168,906 files have no litmus score") {
		t.Errorf("the backlog must still appear in the facts, got %q", out)
	}

	// An acute problem outranks it and takes the headline back.
	var acute strings.Builder
	writeSystemStatus(&acute, &statusInputs{
		health:        hopper.WorkflowHealth{LatestAdded: time.Now().Add(-3 * time.Hour), LatestAnalyzed: time.Now()},
		backlogs:      chronic,
		pendingLitmus: 168906,
	})
	if !strings.Contains(acute.String(), "No sample ingested in") {
		t.Errorf("an acute problem must own the headline, got %q", acute.String())
	}
	if !strings.Contains(acute.String(), "168,906 files have no litmus score") {
		t.Errorf("the chronic condition must still be listed, got %q", acute.String())
	}
}
