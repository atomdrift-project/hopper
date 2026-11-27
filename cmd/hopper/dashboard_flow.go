package main

import (
	"fmt"
	"strings"
	"sync"
	"time"

	"github.com/atomdrift-project/hopper/store"
)

// dashboard_flow.go measures how the verdict store's queue moves, for the
// dashboard's ETAs and the analysis-rate gauge: per class of queued scan
// (first scans and rescans), the files arriving and the scans results
// complete, over the same span.
//
// The store keeps only a file's latest scan, so it cannot tell afterwards
// whether a scan was a file's first. The queue row a result completes can:
// its priority says why the file was queued (store.Priority.IsRescan). Those
// rows are deleted as results land, so hopper counts them as they go, here.

// flowMinSpan is the least time a flow is measured over before it is
// reported: the first minutes after a restart tell a burst from a trend no
// better than a single sample would.
const flowMinSpan = 10 * time.Minute

// tallyMinutes is how many minutes of completions the tally keeps: the rate
// window.
const tallyMinutes = int64(analysisRateWindow / time.Minute)

// Scan classes, as the tally indexes them and the metrics label them.
const (
	classFirst = iota
	classRescan
)

var scanClasses = [...]string{classFirst: "first", classRescan: "rescan"}

// classOf is the scan class of a queue priority.
func classOf(p store.Priority) int {
	if p.IsRescan() {
		return classRescan
	}
	return classFirst
}

// completedScans counts the queued scans this process's results complete.
var completedScans = newScanTally(time.Now())

// scanTally counts queued scans completed, by class, in whole minutes over
// the last tallyMinutes: once by the minute each completed, and once by the
// minute its file was queued. The second is what an arrival rate needs of
// the scans already done; the queue still holds the rest (store.Health.Queued).
type scanTally struct {
	done   [tallyMinutes]tallyMinute // by the minute the scan completed
	served [tallyMinutes]tallyMinute // by the minute its file was queued
	start  int64                     // the first whole minute counted, in Unix minutes
	mu     sync.Mutex
}

// tallyMinute is one minute's counts, by scan class.
type tallyMinute struct {
	minute int64 // Unix minutes
	n      [len(scanClasses)]int64
}

// newScanTally starts a tally at now. The minute now falls in is partly over,
// so counting starts with the next: every span it reports is whole minutes.
func newScanTally(now time.Time) *scanTally {
	return &scanTally{start: now.Unix()/60 + 1}
}

// add counts the queued scans one result completed at now.
func (t *scanTally) add(now time.Time, completed []store.QueuedScan) {
	if len(completed) == 0 {
		return
	}
	m := now.Unix() / 60
	t.mu.Lock()
	defer t.mu.Unlock()
	for _, c := range completed {
		class := classOf(c.Priority)
		bump(&t.done, m, class)
		// A queue time ahead of hopper's clock is the database's clock
		// running fast, not a file queued in the future.
		if q := min(c.QueuedAt.Unix()/60, m); q > m-tallyMinutes {
			bump(&t.served, q, class)
		}
	}
}

// bump counts one scan of class in minute, reusing the slot of the minute
// tallyMinutes before it.
func bump(ring *[tallyMinutes]tallyMinute, minute int64, class int) {
	b := &ring[minute%tallyMinutes]
	if b.minute != minute {
		*b = tallyMinute{minute: minute}
	}
	b.n[class]++
}

// since is where a flow measured at now starts: the rate window back, or
// when counting started if that is later. It falls on a whole minute.
func (t *scanTally) since(now time.Time) time.Time {
	first := max(t.start, now.Unix()/60-tallyMinutes+1)
	return time.Unix(first*60, 0)
}

// queueFlow is how one class of queued scans moved over span: files queued
// and scans completed, per second. A zero span is a flow not yet measured.
type queueFlow struct {
	in, out float64
	span    time.Duration
}

// flows measures both classes from since to now: queued holds, by priority,
// the files queued since since that are still waiting, as the store counted
// them at now. Unmeasured when the span is shorter than flowMinSpan.
func (t *scanTally) flows(queued map[store.Priority]int64, since, now time.Time) (flows [len(scanClasses)]queueFlow) {
	span := now.Sub(since)
	if span < flowMinSpan {
		return flows
	}
	from, to := since.Unix()/60, now.Unix()/60
	var done, arrived [len(scanClasses)]int64
	t.mu.Lock()
	for i := range t.done {
		if d := &t.done[i]; d.minute >= from && d.minute <= to {
			for c, n := range d.n {
				done[c] += n
			}
		}
		if s := &t.served[i]; s.minute >= from && s.minute <= to {
			for c, n := range s.n {
				arrived[c] += n
			}
		}
	}
	t.mu.Unlock()
	for p, n := range queued {
		arrived[classOf(p)] += n
	}
	secs := span.Seconds()
	for c := range flows {
		flows[c] = queueFlow{in: float64(arrived[c]) / secs, out: float64(done[c]) / secs, span: span}
	}
	return flows
}

// drainETA says how long a queue of depth files takes to empty at flow f:
// the time it takes the scans completed, net of the files arriving, to work
// through it. A queue arriving as fast as it is served, or faster, is "not
// draining": there is no honest number for it.
func drainETA(depth int64, f queueFlow) string {
	switch {
	case depth <= 0:
		return "caught up"
	case f.span == 0:
		return "measuring"
	case f.out > 0 && float64(depth)/f.out < keepingUpSeconds:
		// A backlog the fleet clears in a few minutes is a pipeline running,
		// whatever arrives meanwhile.
		return "keeping up"
	case f.in >= f.out:
		return "not draining"
	}
	secs := float64(depth) / (f.out - f.in)
	if secs >= etaMax.Seconds() {
		return "over a year"
	}
	return coarsenETA(time.Duration(secs * float64(time.Second)))
}

// drainMeta is a queue card's sub-line for a store queue: files arriving and
// scans completed an hour, then how long it takes to drain.
func drainMeta(depth int64, f queueFlow) string {
	eta := drainETA(depth, f)
	var parts []string
	if f.span > 0 {
		parts = append(parts, fmt.Sprintf("in <em>%s</em>/h &middot; out <em>%s</em>/h",
			fmtN(int64(f.in*3600)), fmtN(int64(f.out*3600))))
	}
	switch eta {
	case "caught up", "keeping up":
		parts = append(parts, eta)
	case "measuring":
		parts = append(parts, `<span class="queue-note">measuring&hellip;</span>`)
	case "not draining":
		parts = append(parts, `<span class="queue-note">not draining</span>`)
	default:
		parts = append(parts, "ETA <em>"+htmlEscape(eta)+"</em>")
	}
	return strings.Join(parts, " &middot; ")
}

// corpusReading is the store's health with the queue's flows measured at the
// same moment, so that the arrivals the store counted and the completions
// this process counted cover one span.
type corpusReading struct {
	*store.Health

	flows [len(scanClasses)]queueFlow
}
