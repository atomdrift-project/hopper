package hopper

import (
	"fmt"
	"strings"
	"testing"
)

// TestCleaveTriggerKnowsAllTraitKeys guards against the v8 regression where the
// cleave compact report renamed each file's trait array 'find' -> 'traits' but
// the samples_derive_cleave_cols trigger still read only 'find', deriving
// max_crit=0 for every post-v8 sample and silently dropping all new malware out
// of the bloom's bad tiers and every criticality gate.
//
// The trigger DDL must COALESCE across every key in cleaveTraitArrayKeys. If a
// future cleave format renames the array again, add the key to that list and to
// the trigger; this test fails until the trigger learns it.
func TestCleaveTriggerKnowsAllTraitKeys(t *testing.T) {
	const marker = "samples_derive_cleave_cols() RETURNS trigger"
	var trigger string
	for _, stmt := range pgRuntimeMigrations() {
		if strings.Contains(stmt, marker) {
			trigger = stmt
			break
		}
	}
	if trigger == "" {
		t.Fatalf("could not find the %q DDL in pgRuntimeMigrations()", marker)
	}

	for _, key := range cleaveTraitArrayKeys {
		ref := fmt.Sprintf("->'%s'", key)
		if !strings.Contains(trigger, ref) {
			t.Errorf("samples_derive_cleave_cols trigger does not read trait key %q (expected %q in the finds COALESCE); "+
				"a cleave report stored under that key would derive max_crit=0", key, ref)
		}
	}
}
