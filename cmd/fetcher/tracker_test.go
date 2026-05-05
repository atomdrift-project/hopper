package main

import (
	"context"
	"net/http"
	"testing"
	"time"

	"codeberg.org/atomdrift/hopper/website"
)

// stubSource is a minimal Source for tracker tests; only Name matters.
type stubSource struct{ name string }

func (s *stubSource) Name() string      { return s.name }
func (*stubSource) Hostname() string    { return "stub.test" }
func (*stubSource) MonitorPage() string { return "https://stub.test/" }
func (*stubSource) Discover(_ context.Context, _ *http.Client) ([]website.Target, error) {
	return nil, nil
}

// pickASource returns one source from Default() that classifies as kind k,
// so the tracker test exercises real classification rather than guessing.
func pickASource(t *testing.T, k website.SourceKind) website.Source {
	t.Helper()
	for _, s := range website.Default() {
		if website.KindOf(s) == k {
			return s
		}
	}
	t.Fatalf("no source of kind %q registered", k)
	return nil
}

func TestPollTrackerHonorsKindIntervals(t *testing.T) {
	vendor := pickASource(t, website.KindVendorWebsite)
	large := pickASource(t, website.KindLargeInfra)

	// Pick small but distinct intervals so the test is fast yet the asymmetry
	// is real: vendor 200ms, large 50ms.
	tracker := newPollTracker(200*time.Millisecond, 50*time.Millisecond)

	if !tracker.shouldPoll(vendor) {
		t.Fatal("first call for vendor must allow poll")
	}
	if !tracker.shouldPoll(large) {
		t.Fatal("first call for large must allow poll")
	}
	tracker.markPolled(vendor)
	tracker.markPolled(large)

	// Immediately afterward both should be capped.
	if tracker.shouldPoll(vendor) {
		t.Error("vendor should be within cap immediately after marking")
	}
	if tracker.shouldPoll(large) {
		t.Error("large should be within cap immediately after marking")
	}

	// Wait past large's interval but not vendor's: large unblocks first.
	time.Sleep(100 * time.Millisecond)
	if tracker.shouldPoll(vendor) {
		t.Error("vendor should still be capped at 100ms (interval 200ms)")
	}
	if !tracker.shouldPoll(large) {
		t.Error("large should be free to poll at 100ms (interval 50ms)")
	}
}

func TestPollTrackerZeroIntervalAlwaysAllows(t *testing.T) {
	s := pickASource(t, website.KindVendorWebsite)
	tracker := newPollTracker(0, 0)
	tracker.markPolled(s)
	if !tracker.shouldPoll(s) {
		t.Error("zero interval should never cap")
	}
}

func TestPollTrackerUnknownSourceAllows(t *testing.T) {
	// A source whose Name isn't in largeInfraSources falls back to
	// KindVendorWebsite — verified here via a stub.
	stub := &stubSource{name: "totally-fake-source-123"}
	tracker := newPollTracker(time.Hour, time.Minute)
	if !tracker.shouldPoll(stub) {
		t.Fatal("first call must allow")
	}
	tracker.markPolled(stub)
	if tracker.shouldPoll(stub) {
		t.Error("vendor-cap (1h) should still apply to unclassified source")
	}
}
