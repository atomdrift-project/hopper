package main

import (
	"os"
	"testing"

	"github.com/atomdrift-project/hopper"
)

// TestServingAppNameMatchesCLI is the guard for the bug that made hopper's pool
// sizing dead code: poolSize branched on "hopper" while cliAppName had started
// producing "hopper-<subcommand>". Nothing failed — the daemon just quietly ran
// on the generic 4-connection pool. If either side is renamed, this fails.
func TestServingAppNameMatchesCLI(t *testing.T) {
	saved := os.Args
	t.Cleanup(func() { os.Args = saved })

	os.Args = []string{"hopper", "load", "--data", "/data/samples"}
	if got := cliAppName(); got != hopper.ServingAppName {
		t.Errorf("cliAppName() for the serving daemon = %q, but poolSize sizes %q.\n"+
			"These must match or the daemon silently falls back to the generic pool.",
			got, hopper.ServingAppName)
	}
}

// TestCliAppNameIsPrefixed documents the shape the constant has to track.
func TestCliAppNameIsPrefixed(t *testing.T) {
	saved := os.Args
	t.Cleanup(func() { os.Args = saved })

	for _, tc := range []struct{ arg, want string }{
		{"load", "hopper-load"},
		{"serve-replica", "hopper-serve-replica"},
		{"", "hopper-cli"},
	} {
		os.Args = []string{"hopper"}
		if tc.arg != "" {
			os.Args = append(os.Args, tc.arg)
		}
		if got := string(cliAppName()); got != tc.want {
			t.Errorf("cliAppName(%q) = %q, want %q", tc.arg, got, tc.want)
		}
	}
}
