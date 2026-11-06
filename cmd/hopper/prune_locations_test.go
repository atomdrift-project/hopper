package main

import (
	"encoding/json"
	"os"
	"path/filepath"
	"reflect"
	"testing"

	"github.com/atomdrift-project/hopper"
)

func TestLocationPruneCheckpoint(t *testing.T) {
	saved := locationPruneCheckpoint{
		Root: t.TempDir(), MaxPaths: 0, GoodMaxPaths: 256, UnknownMaxPaths: 512, DryRun: true, Version: locationPruneCheckpointVersion, CapLabels: "good,unknown",
		Stats: hopper.LocationPruneStats{Phase: "obsolete", AfterID: 20, ThroughID: 100},
	}
	name := filepath.Join(t.TempDir(), "checkpoint.json")
	if err := writeLocationPruneCheckpoint(name, &saved); err != nil {
		t.Fatal(err)
	}
	data, err := os.ReadFile(name)
	if err != nil {
		t.Fatal(err)
	}
	var read locationPruneCheckpoint
	if err := json.Unmarshal(data, &read); err != nil || !reflect.DeepEqual(read, saved) {
		t.Fatalf("checkpoint: %+v, %v", read, err)
	}
	for _, tc := range []struct {
		name, phase string
		complete    bool
		want        []string
	}{
		{"obsolete-incomplete", "obsolete", false, []string{"obsolete", "cap"}},
		{"obsolete-complete", "obsolete", true, []string{"cap"}},
		{"cap-incomplete", "cap", false, []string{"cap"}},
		{"cap-complete", "cap", true, nil},
	} {
		t.Run(tc.name, func(t *testing.T) {
			saved.Stats.Phase, saved.Stats.Complete = tc.phase, tc.complete
			opts := hopper.LocationPruneOptions{DataRoot: saved.Root, MaxPaths: saved.MaxPaths, GoodMaxPaths: saved.GoodMaxPaths, UnknownMaxPaths: saved.UnknownMaxPaths, CapLabels: []string{"good", "unknown"}, DryRun: true}
			got, err := resumeLocationPrune("all", &saved, &opts)
			if err != nil || !reflect.DeepEqual(got, tc.want) || opts.ThroughID != 100 || opts.AfterID != 20 {
				t.Fatalf("resume: %v %+v %v", got, opts, err)
			}
			opts.DryRun = false
			if _, err := resumeLocationPrune("all", &saved, &opts); err == nil {
				t.Fatal("preview checkpoint accepted for applying")
			}
		})
	}
}
