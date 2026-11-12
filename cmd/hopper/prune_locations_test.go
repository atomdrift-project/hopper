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
		Root: t.TempDir(), DryRun: true, Version: locationPruneCheckpointVersion,
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
	for _, complete := range []bool{false, true} {
		saved.Stats.Complete = complete
		opts := hopper.LocationPruneOptions{DataRoot: saved.Root, DryRun: true}
		got, err := resumeLocationPrune(&saved, &opts)
		if err != nil || got != complete || opts.ThroughID != 100 || opts.AfterID != 20 {
			t.Fatalf("resume: %v %+v %v", got, opts, err)
		}
		opts.DryRun = false
		if _, err := resumeLocationPrune(&saved, &opts); err == nil {
			t.Fatal("preview checkpoint accepted for applying")
		}
	}
	for _, version := range []int{5, 6} {
		saved.Version = version
		opts := hopper.LocationPruneOptions{DataRoot: saved.Root, DryRun: true}
		if _, err := resumeLocationPrune(&saved, &opts); err == nil {
			t.Fatal("old policy checkpoint accepted")
		}
	}
}
