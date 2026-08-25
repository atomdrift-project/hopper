package hopper

import (
	"strings"
	"testing"
)

func TestLitmusLevelDeriveTriggerReadsModelLevel(t *testing.T) {
	const marker = "samples_derive_litmus_score() RETURNS trigger"
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
	for _, want := range []string{
		"NEW.lvl :=",
		"NEW.litmus_result->'ml'->>'lvl'",
		"NEW.litmus_result->>'lvl'",
		"NEW.litmus_result->>'l'",
	} {
		if !strings.Contains(trigger, want) {
			t.Errorf("litmus derive trigger does not contain %q", want)
		}
	}
}
