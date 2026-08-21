package main

import (
	"net/http"
	"net/http/httptest"
	"testing"
)

// newLaneServer builds an apiServer whose result pools mirror production
// sizing: a shared pool of total slots, of which resultReservedSlots are
// unavailable to workers.
func newLaneServer(total int) *apiServer {
	return &apiServer{
		resultSem:       make(chan struct{}, total),
		workerResultSem: make(chan struct{}, total-min(resultReservedSlots, total-1)),
	}
}

// TestRenewalLaneHeader pins the classification. A client that does not send
// the header — including one too old to know about it — must land in the
// worker lane, so the reservation can only ever be opted into deliberately.
func TestRenewalLaneHeader(t *testing.T) {
	tests := []struct {
		name   string
		header string
		set    bool
		want   bool
	}{
		{"declared", "renew", true, true},
		{"case-insensitive", "ReNeW", true, true},
		{"padded", "  renew  ", true, true},
		{"absent", "", false, false},
		{"empty", "", true, false},
		{"unknown value", "worker", true, false},
		{"unknown lane name", "priority", true, false},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			r := httptest.NewRequest(http.MethodPost, "/api/result", http.NoBody)
			if tt.set {
				r.Header.Set(laneHeader, tt.header)
			}
			if got := renewalLane(r); got != tt.want {
				t.Errorf("renewalLane(%q, set=%v) = %v, want %v", tt.header, tt.set, got, tt.want)
			}
		})
	}
}

// TestWorkersCannotTakeReservedSlots is the property the whole change exists
// for: however deep the worker backlog, a renewal still gets in.
func TestWorkersCannotTakeReservedSlots(t *testing.T) {
	const total, reserved = 8, resultReservedSlots
	api := newLaneServer(total)
	ctx := t.Context()

	// Saturate with workers, as a deep queue backlog does.
	admitted := 0
	for range total * 2 {
		if err := api.acquireResult(ctx, false); err != nil {
			break
		}
		admitted++
	}
	if want := total - reserved; admitted != want {
		t.Fatalf("admitted %d worker results, want %d (%d total - %d reserved)",
			admitted, want, total, reserved)
	}

	// The reservation must still be there.
	for i := range reserved {
		if err := api.acquireResult(ctx, true); err != nil {
			t.Fatalf("renewal %d shed while %d slots were reserved: %v", i+1, reserved, err)
		}
	}
	// And once genuinely full, a renewal sheds too — the reservation is a
	// floor, not an unbounded lane.
	if err := api.acquireResult(ctx, true); err == nil {
		t.Error("a renewal was admitted past the shared pool's capacity")
	}
}

// TestRenewalsUseSpareWorkerCapacity: the reservation is a floor, not a
// partition. An idle fleet must not leave slots stranded.
func TestRenewalsUseSpareWorkerCapacity(t *testing.T) {
	const total = 8
	api := newLaneServer(total)
	for i := range total {
		if err := api.acquireResult(t.Context(), true); err != nil {
			t.Fatalf("renewal %d shed with an idle worker fleet: %v", i+1, err)
		}
	}
}

// TestReleaseReturnsBothSlots guards the leak that would slowly strangle the
// worker lane: a worker takes two tokens and must give back two.
func TestReleaseReturnsBothSlots(t *testing.T) {
	const total = 8
	api := newLaneServer(total)
	for range 50 {
		if err := api.acquireResult(t.Context(), false); err != nil {
			t.Fatalf("worker shed after clean releases: %v", err)
		}
		api.releaseResult(false)
	}
	if len(api.resultSem) != 0 || len(api.workerResultSem) != 0 {
		t.Errorf("slots leaked: shared=%d worker=%d", len(api.resultSem), len(api.workerResultSem))
	}
	for range 50 {
		if err := api.acquireResult(t.Context(), true); err != nil {
			t.Fatalf("renewal shed after clean releases: %v", err)
		}
		api.releaseResult(true)
	}
	if len(api.resultSem) != 0 || len(api.workerResultSem) != 0 {
		t.Errorf("slots leaked: shared=%d worker=%d", len(api.resultSem), len(api.workerResultSem))
	}
}

// TestWorkerAcquireDoesNotLeakOnSharedSaturation covers the half-acquired
// path: the worker slot is taken, the shared slot is not, and the worker slot
// must be handed back rather than held forever.
func TestWorkerAcquireDoesNotLeakOnSharedSaturation(t *testing.T) {
	api := &apiServer{
		resultSem:       make(chan struct{}, 1),
		workerResultSem: make(chan struct{}, 4),
	}
	// A renewal holds the only shared slot.
	if err := api.acquireResult(t.Context(), true); err != nil {
		t.Fatalf("renewal: %v", err)
	}
	before := len(api.workerResultSem)
	if err := api.acquireResult(t.Context(), false); err == nil {
		t.Fatal("worker admitted with no shared slot free")
	}
	if got := len(api.workerResultSem); got != before {
		t.Errorf("worker pool holds %d after a failed acquire, want %d", got, before)
	}
}

// TestSmallHostKeepsAWorkerSlot: on a two-slot host the reservation must not
// starve workers entirely, or the queue stops draining.
func TestSmallHostKeepsAWorkerSlot(t *testing.T) {
	for _, total := range []int{2, 3, 4} {
		api := newLaneServer(total)
		if cap(api.workerResultSem) < 1 {
			t.Errorf("total=%d leaves workers %d slots, want at least 1", total, cap(api.workerResultSem))
		}
		if err := api.acquireResult(t.Context(), false); err != nil {
			t.Errorf("total=%d: worker shed on an idle server: %v", total, err)
		}
	}
}
