package main

import (
	"math"
	"strings"
	"testing"
	"time"

	"github.com/atomdrift-project/hopper/store"
)

// The tally splits completions by why each file was queued, not by how long
// ago it arrived, and counts arrivals from both halves: the files already
// served and the files still waiting.
func TestScanTallyFlows(t *testing.T) {
	start := time.Date(2026, 11, 27, 9, 0, 30, 0, time.UTC)
	tally := newScanTally(start)
	now := start.Add(30*time.Minute + 30*time.Second) // 09:31:00
	since := tally.since(now)
	if want := time.Date(2026, 11, 27, 9, 1, 0, 0, time.UTC); !since.Equal(want) {
		t.Fatalf("since %v, want counting to start at the first whole minute, %v", since, want)
	}

	// Results over the half hour: 900 first scans of files queued weeks ago
	// (the backlog), 60 of files queued and served within the span (sighted),
	// and 30 rescans of files queued within it.
	weeksAgo := start.Add(-21 * 24 * time.Hour)
	for i := range 900 {
		tally.add(since.Add(time.Duration(i)*2*time.Second), []store.QueuedScan{{QueuedAt: weeksAgo, Priority: store.QueueNew}})
	}
	for i := range 60 {
		at := since.Add(time.Duration(i) * 30 * time.Second)
		tally.add(at, []store.QueuedScan{{QueuedAt: at, Priority: store.QueueSighted}})
	}
	for i := range 30 {
		at := since.Add(time.Duration(i) * time.Minute)
		tally.add(at, []store.QueuedScan{{QueuedAt: at, Priority: store.QueueStale}})
	}
	// Completed before counting started: not in the span.
	tally.add(start, []store.QueuedScan{{QueuedAt: start, Priority: store.QueueNew}})

	// The store counted, of files queued since, 1,000 first scans and 6 rescans
	// still waiting.
	queued := make(map[store.Priority]int64)
	queued[store.QueueNew], queued[store.QueueUpload], queued[store.QueueRepair] = 990, 10, 6
	flows := tally.flows(queued, since, now)
	secs := (30 * time.Minute).Seconds()
	first, again := flows[classFirst], flows[classRescan]
	if want := float64(900+60) / secs; !near(first.out, want) {
		t.Errorf("first-scan out %.4f/s, want %.4f: every completed first scan, however old its file", first.out, want)
	}
	if want := float64(60+1000) / secs; !near(first.in, want) {
		t.Errorf("first-scan in %.4f/s, want %.4f: those served plus those waiting", first.in, want)
	}
	if want := 30 / secs; !near(again.out, want) {
		t.Errorf("rescan out %.4f/s, want %.4f: only the rescans", again.out, want)
	}
	if want := float64(30+6) / secs; !near(again.in, want) {
		t.Errorf("rescan in %.4f/s, want %.4f", again.in, want)
	}
	if first.span != 30*time.Minute || again.span != 30*time.Minute {
		t.Errorf("spans %v, %v; want the 30 minutes counted", first.span, again.span)
	}

	// Too soon after a restart to measure.
	if f := tally.flows(queued, since, since.Add(flowMinSpan-time.Second)); f[classFirst].span != 0 {
		t.Errorf("flow over less than %v reported: %+v", flowMinSpan, f)
	}
}

// Past the rate window, the oldest minutes leave the span and their slots are
// reused for new ones.
func TestScanTallyWindow(t *testing.T) {
	start := time.Date(2026, 11, 27, 9, 0, 0, 0, time.UTC)
	tally := newScanTally(start)
	first := []store.QueuedScan{{QueuedAt: start.Add(-time.Hour), Priority: store.QueueNew}}
	for m := range 3 * tallyMinutes {
		tally.add(start.Add(time.Duration(m)*time.Minute+time.Second), first)
	}
	now := start.Add(time.Duration(3*tallyMinutes) * time.Minute)
	since := tally.since(now)
	if got := now.Sub(since); got != analysisRateWindow-time.Minute {
		t.Errorf("span %v, want the window less the minute under way", got)
	}
	flows := tally.flows(nil, since, now)
	if want := 1.0 / 60; !near(flows[classFirst].out, want) {
		t.Errorf("out %.5f/s, want one a minute, %.5f/s", flows[classFirst].out, want)
	}
	// Every file was queued long before the span: none arrived in it.
	if flows[classFirst].in != 0 {
		t.Errorf("in %.5f/s, want 0", flows[classFirst].in)
	}
}

// The ETA is the depth over completions net of arrivals, and a queue taking in
// as much as it serves, or more, gets no number at all.
func TestDrainETA(t *testing.T) {
	measured := time.Hour
	for _, tc := range []struct {
		name  string
		depth int64
		flow  queueFlow
		want  string
	}{
		{"empty", 0, queueFlow{}, "caught up"},
		{"just restarted", 1000, queueFlow{}, "measuring"},
		{"cleared in seconds", 300, queueFlow{in: 10, out: 10, span: measured}, "keeping up"},
		{"arrivals equal throughput", 1_000_000, queueFlow{in: 6, out: 6, span: measured}, "not draining"},
		{"arrivals beat throughput", 1_000_000, queueFlow{in: 6.5, out: 6, span: measured}, "not draining"},
		{"nothing served", 41_769, queueFlow{in: 0.01, span: measured}, "not draining"},
		// 1,036,800 files at 6.6/s out against 5.4/s in: 1.2/s net, 10 days.
		{"draining net of arrivals", 1_036_800, queueFlow{in: 5.4, out: 6.6, span: measured}, "~10d00h"},
		{"draining, ignoring arrivals would say 2d", 1_036_800, queueFlow{in: 0, out: 6, span: measured}, "~2d00h"},
		{"barely draining", 1_000_000, queueFlow{in: 1, out: 1.00001, span: measured}, "over a year"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if got := drainETA(tc.depth, tc.flow); got != tc.want {
				t.Errorf("drainETA(%d, %+v) = %q, want %q", tc.depth, tc.flow, got, tc.want)
			}
		})
	}
}

// The card shows intake beside throughput, so a queue that is not draining
// says why.
func TestDrainMeta(t *testing.T) {
	got := drainMeta(1_025_181, queueFlow{in: 6.5, out: 6, span: time.Hour})
	for _, want := range []string{"in <em>23,400</em>/h", "out <em>21,600</em>/h", "not draining"} {
		if !strings.Contains(got, want) {
			t.Errorf("meta %q, want %q", got, want)
		}
	}
	if got := drainMeta(1000, queueFlow{}); !strings.Contains(got, "measuring") || strings.Contains(got, "/h") {
		t.Errorf("unmeasured meta %q, want measuring and no rates", got)
	}
}

func near(got, want float64) bool { return math.Abs(got-want) <= 1e-9+1e-6*math.Abs(want) }
