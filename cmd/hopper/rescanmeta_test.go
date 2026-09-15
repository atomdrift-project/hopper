package main

import (
	"strings"
	"testing"

	"github.com/atomdrift-project/hopper"
)

// TestRescanMetaShowsEveryTier locks the regression this card was rebuilt for.
// On 2026-09-13 it rendered "0 pending / stale traits disabled" on a host whose
// repair tier held 123,921 rows and was actively handing them out: the count
// was the stale-traits tier alone, and that tier was switched off. The card must
// report the tiers that DO have work, and must not describe an absent tier as an
// empty one.
func TestRescanMetaShowsEveryTier(t *testing.T) {
	prod := hopper.RescanDepths{Forced: 17, Repair: 123921} // age tier empty
	if prod.Total() != 123938 {
		t.Fatalf("Total() = %d, want 123938", prod.Total())
	}
	meta := rescanMeta(prod, "", 0.025, true, true)
	for _, want := range []string{"123,921", "repair", "17", "forced"} {
		if !strings.Contains(meta, want) {
			t.Errorf("meta %q missing %q", meta, want)
		}
	}
	if strings.Contains(meta, "caught up") {
		t.Errorf("a non-empty rescan queue must not read as caught up: %q", meta)
	}

	// Genuinely empty. The age tier cannot be switched off, so "caught up" is
	// now the only honest reading of an empty queue.
	empty := rescanMeta(hopper.RescanDepths{}, "", 0, true, true)
	if !strings.Contains(empty, "caught up") {
		t.Errorf("empty enabled queue should read caught up, got %q", empty)
	}

	// Thin history must NOT read as stalled. The live dashboard rendered
	// "not draining" beside 21 rescans/sec because a restart had cleared the
	// sampled series and there was no slope to fit yet.
	warming := rescanMeta(prod, "", 0, false, true)
	if strings.Contains(warming, "not draining") {
		t.Errorf("unmeasured queue reported as stalled: %q", warming)
	}
	if !strings.Contains(warming, "measuring") {
		t.Errorf("unmeasured queue should say so, got %q", warming)
	}

	// A failed count leaves the struct zero-valued, and zero renders as "caught
	// up" -- the one reading that stops an operator investigating. Unavailable
	// must look unavailable.
	unknown := rescanMeta(hopper.RescanDepths{}, "", 0, true, false)
	if strings.Contains(unknown, "caught up") {
		t.Errorf("a failed depth count must never read as caught up: %q", unknown)
	}
	if !strings.Contains(unknown, "unavailable") {
		t.Errorf("a failed depth count must say so, got %q", unknown)
	}
}
