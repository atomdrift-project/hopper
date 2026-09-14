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
	prod := hopper.RescanDepths{Forced: 17, Repair: 123921} // StaleTraitsEnabled false
	if prod.Total() != 123938 {
		t.Fatalf("Total() = %d, want 123938", prod.Total())
	}
	meta := rescanMeta(prod, "", 0.025)
	for _, want := range []string{"123,921", "repair", "17", "forced", "stale traits off"} {
		if !strings.Contains(meta, want) {
			t.Errorf("meta %q missing %q", meta, want)
		}
	}
	if strings.Contains(meta, "caught up") {
		t.Errorf("a switched-off stale-traits tier must not read as caught up: %q", meta)
	}

	// Genuinely empty, tier enabled: "caught up" is the honest answer.
	empty := rescanMeta(hopper.RescanDepths{StaleTraitsEnabled: true}, "", 0)
	if !strings.Contains(empty, "caught up") {
		t.Errorf("empty enabled queue should read caught up, got %q", empty)
	}
	if strings.Contains(empty, "stale traits off") {
		t.Errorf("enabled tier reported as off: %q", empty)
	}
}
