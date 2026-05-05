package main

import (
	"sync"
	"time"

	"codeberg.org/atomdrift/hopper/website"
)

// pollTracker enforces a minimum interval between polls of the same source.
// State is in-memory and per-process — for one-shot CLI invocations this is
// effectively a no-op (the tracker starts empty), but a wrapper that calls
// runSource repeatedly within one process (a future loop / daemon mode)
// will see the cap take effect.
//
// Two intervals are tracked, indexed by [website.SourceKind]:
//
//   - vendor: small upstream sites (cpuid.com, nssm.cc, …); long interval
//     to be polite (default 20h).
//   - large:  GitHub Releases, signed CDNs, Google-scale APIs; short
//     interval is fine (default 1h).
type pollTracker struct {
	lastPoll  map[string]time.Time
	intervals map[website.SourceKind]time.Duration
	mu        sync.Mutex
}

func newPollTracker(vendor, large time.Duration) *pollTracker {
	return &pollTracker{
		lastPoll: map[string]time.Time{},
		intervals: map[website.SourceKind]time.Duration{
			website.KindVendorWebsite: vendor,
			website.KindLargeInfra:    large,
		},
	}
}

// shouldPoll reports whether s is due for a fresh poll. The first call for
// a given source always returns true; subsequent calls within the source's
// per-kind interval return false.
func (p *pollTracker) shouldPoll(s website.Source) bool {
	p.mu.Lock()
	defer p.mu.Unlock()
	last, ok := p.lastPoll[s.Name()]
	if !ok {
		return true
	}
	interval, ok := p.intervals[website.KindOf(s)]
	if !ok || interval == 0 {
		return true
	}
	return time.Since(last) >= interval
}

// markPolled records that s was just polled. Idempotent under repeated
// calls within one tick of time.Now().
func (p *pollTracker) markPolled(s website.Source) {
	p.mu.Lock()
	defer p.mu.Unlock()
	p.lastPoll[s.Name()] = time.Now()
}
