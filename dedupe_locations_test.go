package hopper

import (
	"bytes"
	"context"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func TestPlanLocationDedupe(t *testing.T) {
	base := time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC)
	candidate := func(path string, dev uint64, age int) dedupeLocation {
		return dedupeLocation{location: &SampleLocation{Path: path, FirstSeenAt: base.Add(time.Duration(age) * time.Hour)}, device: dev}
	}
	tests := []struct {
		name, label, skip, source, want string
		consolidate                     bool
		paths                           []dedupeLocation
		removed, groups                 int
	}{
		{name: "same filesystem preserves both labels", label: "good", consolidate: true, paths: []dedupeLocation{candidate("bad/a", 1, 0), candidate("good/b", 1, 1)}, want: "good/b", groups: 1},
		{name: "classification before age", label: "good", consolidate: true, paths: []dedupeLocation{candidate("bad/a", 1, 0), candidate("good/b", 2, 1)}, want: "good/b", removed: 1},
		{name: "oldest within winning label", label: "good", consolidate: true, paths: []dedupeLocation{candidate("good/a", 1, 2), candidate("good/z", 2, 1)}, want: "good/z", removed: 1},
		{name: "path breaks age tie", label: "good", consolidate: true, paths: []dedupeLocation{candidate("good/z", 1, 0), candidate("good/a", 2, 0)}, want: "good/a", removed: 1},
		{name: "conflict skip", label: "bad", skip: "conflict", consolidate: true, paths: []dedupeLocation{candidate("bad/a", 1, 0), candidate("good/b", 2, 1)}},
		{name: "conflict source", label: "bad", source: "conflict", consolidate: true, paths: []dedupeLocation{candidate("bad/a", 1, 0), candidate("good/b", 2, 1)}},
		{name: "no winning copy", label: "bad", consolidate: true, paths: []dedupeLocation{candidate("sighted/a", 1, 0), candidate("good/b", 2, 1)}},
		{name: "workflow copy survives", label: "good", consolidate: true, paths: []dedupeLocation{candidate("incoming/a", 1, 0), candidate("good/b", 2, 1)}, want: "good/b"},
		{name: "empty label is unresolved", consolidate: true, paths: []dedupeLocation{candidate("incoming/a", 1, 0), candidate("good/b", 2, 1)}},
		{name: "default only links", label: "good", paths: []dedupeLocation{candidate("bad/a", 1, 0), candidate("good/b", 2, 1)}},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			plan := planLocationDedupe(tt.paths, tt.label, tt.skip, tt.source, tt.consolidate)
			got := ""
			if plan.survivor != nil {
				got = plan.survivor.location.Path
			}
			if got != tt.want || len(plan.remove) != tt.removed || len(plan.link) != tt.groups {
				t.Fatalf("survivor=%q removed=%d groups=%d", got, len(plan.remove), len(plan.link))
			}
		})
	}
}

func TestConsolidateLocation(t *testing.T) {
	for _, backend := range testBackends {
		t.Run(backend.name, func(t *testing.T) {
			db := backend.open(t)
			ctx := context.Background()
			root := t.TempDir()
			content := []byte("identical archive bytes")
			sha := moveTestSHA(content)
			oldRel, newRel := "bad/old.tgz", "good/old.tgz"
			oldAbs := writeDedupeFile(t, root, oldRel, content)
			newAbs := writeDedupeFile(t, root, newRel, content)
			mustInsert(t, ctx, db, &Sample{SHA256: sha, Path: oldRel, Label: "good", LabelSource: "test"})
			if err := db.UpsertLocation(ctx, &SampleLocation{SHA256: sha, Path: newRel}); err != nil {
				t.Fatal(err)
			}
			child := strings.Repeat("a", 64)
			mustInsert(t, ctx, db, &Sample{SHA256: child, Path: oldRel + "!!lib.js", Parent: sha, Label: "good"})
			locs, err := db.TopLevelLocationsForSHA(ctx, sha)
			if err != nil {
				t.Fatal(err)
			}
			var cs []dedupeLocation
			for _, l := range locs {
				dev := uint64(1)
				if l.Path == newRel {
					dev = 2
				}
				cs = append(cs, dedupeLocation{location: l, device: dev})
			}
			// Device identities are simulated; all filesystem and catalog mutations are real.
			plan := planLocationDedupe(cs, "good", "", "test", true)
			dry, err := db.applyLocationDedupe(ctx, root, sha, "good", plan, true)
			if err != nil || dry.Removed != 1 {
				t.Fatalf("dry run: %+v %v", dry, err)
			}
			if _, err := os.Stat(oldAbs); err != nil {
				t.Fatal(err)
			}
			if err := os.WriteFile(oldAbs+ProvenanceSidecarSuffix, []byte(`{"fetch":{"at":"2026-01-01T00:00:00Z"}}`), 0o644); err != nil {
				t.Fatal(err)
			}
			result, err := db.applyLocationDedupe(ctx, root, sha, "good", plan, false)
			if err != nil || result.Removed != 1 {
				t.Fatalf("apply: %+v %v", result, err)
			}
			if _, err := os.Stat(oldAbs); !errors.Is(err, os.ErrNotExist) {
				t.Fatalf("old file remains: %v", err)
			}
			if got, err := os.ReadFile(newAbs); err != nil || !bytes.Equal(got, content) {
				t.Fatalf("survivor: %q %v", got, err)
			}
			if _, err := os.Stat(newAbs + ProvenanceSidecarSuffix); err != nil {
				t.Fatal(err)
			}
			s, err := db.SampleBySHA256(ctx, sha)
			if err != nil || s.Path != newRel || s.Label != "good" {
				t.Fatalf("sample: %+v %v", s, err)
			}
			children, err := db.LocationsForSHA(ctx, child)
			if err != nil || len(children) != 1 || children[0].Path != newRel+"!!lib.js" {
				t.Fatalf("children: %+v %v", children, err)
			}
			history, err := db.RetiredLocationsForSHA(ctx, sha)
			if err != nil || len(history) != 1 || history[0].SuccessorPath != newRel {
				t.Fatalf("history: %+v %v", history, err)
			}
			again, err := db.DedupeLocations(ctx, root, sha, true, false)
			if err != nil || again.Removed != 0 || again.Linked != 0 {
				t.Fatalf("repeat: %+v %v", again, err)
			}
		})
	}
}

func TestConsolidateRejectsChangedLabel(t *testing.T) {
	for _, backend := range testBackends {
		t.Run(backend.name, func(t *testing.T) {
			db := backend.open(t)
			ctx := context.Background()
			root := t.TempDir()
			content := []byte("duplicate bytes")
			sha := moveTestSHA(content)
			oldRel, newRel := "bad/a", "good/b"
			a := writeDedupeFile(t, root, oldRel, content)
			writeDedupeFile(t, root, newRel, content)
			mustInsert(t, ctx, db, &Sample{SHA256: sha, Path: oldRel, Label: "bad", LabelSource: "test"})
			if err := db.UpsertLocation(ctx, &SampleLocation{SHA256: sha, Path: newRel}); err != nil {
				t.Fatal(err)
			}
			_, err := db.MoveLocation(ctx, MoveLocationOptions{DataRoot: root, SHA256: sha, OldPath: oldRel, NewPath: newRel, ExpectedLabel: "good"})
			if !errors.Is(err, ErrLocationLabelChanged) {
				t.Fatalf("expected classification guard, got %v", err)
			}
			if _, err := os.Stat(a); err != nil {
				t.Fatal(err)
			}
			locs, err := db.TopLevelLocationsForSHA(ctx, sha)
			if err != nil || len(locs) != 2 {
				t.Fatalf("locations: %+v %v", locs, err)
			}
		})
	}
}

func TestDedupeLocationsSameFilesystem(t *testing.T) {
	db := openTestDB(t)
	ctx := context.Background()
	root := t.TempDir()
	content := []byte("same filesystem bytes")
	sha := moveTestSHA(content)
	a := writeDedupeFile(t, root, "good/a", content)
	b := writeDedupeFile(t, root, "bad/b", content)
	mustInsert(t, ctx, db, &Sample{SHA256: sha, Path: "good/a", Label: "good"})
	if err := db.UpsertLocation(ctx, &SampleLocation{SHA256: sha, Path: "bad/b"}); err != nil {
		t.Fatal(err)
	}
	result, err := db.DedupeLocations(ctx, root, sha, true, false)
	if err != nil || result.Linked != 1 || result.Removed != 0 {
		t.Fatalf("dedupe: %+v %v", result, err)
	}
	ai, err := os.Stat(a)
	if err != nil {
		t.Fatal(err)
	}
	bi, err := os.Stat(b)
	if err != nil {
		t.Fatal(err)
	}
	if !os.SameFile(ai, bi) {
		t.Fatal("not hard-linked")
	}
	if _, err := os.Stat(filepath.Dir(a)); err != nil {
		t.Fatal(err)
	}
}

func TestConsolidateRecoversUnlinkedSource(t *testing.T) {
	for _, backend := range testBackends {
		t.Run(backend.name, func(t *testing.T) {
			db := backend.open(t)
			ctx := context.Background()
			root := t.TempDir()
			content := []byte("recover after source unlink")
			sha := moveTestSHA(content)
			old, last := "bad/a.tgz", "good/a.tgz"
			writeDedupeFile(t, root, last, content)
			mustInsert(t, ctx, db, &Sample{SHA256: sha, Path: old, Label: "good", LabelSource: "test"})
			if err := db.UpsertLocation(ctx, &SampleLocation{SHA256: sha, Path: last}); err != nil {
				t.Fatal(err)
			}
			child := strings.Repeat("e", 64)
			mustInsert(t, ctx, db, &Sample{SHA256: child, Parent: sha, Path: old + "!!lib.js", Label: "good"})
			result, err := db.DedupeLocations(ctx, root, sha, true, false)
			if err != nil || result.Removed != 1 {
				t.Fatalf("recovery: %+v %v", result, err)
			}
			locs, err := db.TopLevelLocationsForSHA(ctx, sha)
			if err != nil || len(locs) != 1 || locs[0].Path != last {
				t.Fatalf("locations: %+v %v", locs, err)
			}
			locs, err = db.LocationsForSHA(ctx, child)
			if err != nil || len(locs) != 1 || locs[0].Path != last+"!!lib.js" {
				t.Fatalf("children: %+v %v", locs, err)
			}
		})
	}
}

func TestConsolidateCorruptSurvivorPreservesSource(t *testing.T) {
	db := openTestDB(t)
	ctx := context.Background()
	root := t.TempDir()
	content := []byte("source must survive")
	sha := moveTestSHA(content)
	old, last := "bad/a.tgz", "good/a.tgz"
	src := writeDedupeFile(t, root, old, content)
	writeDedupeFile(t, root, last, []byte("different bytes"))
	mustInsert(t, ctx, db, &Sample{SHA256: sha, Path: old, Label: "good", LabelSource: "test"})
	if err := db.UpsertLocation(ctx, &SampleLocation{SHA256: sha, Path: last}); err != nil {
		t.Fatal(err)
	}
	locs, err := db.TopLevelLocationsForSHA(ctx, sha)
	if err != nil {
		t.Fatal(err)
	}
	var cs []dedupeLocation
	for _, loc := range locs {
		dev := uint64(1)
		if loc.Path == last {
			dev = 2
		}
		cs = append(cs, dedupeLocation{location: loc, device: dev})
	}
	_, err = db.applyLocationDedupe(ctx, root, sha, "good", planLocationDedupe(cs, "good", "", "test", true), false)
	if err == nil {
		t.Fatal("accepted corrupt survivor")
	}
	if got, err := os.ReadFile(src); err != nil || !bytes.Equal(got, content) {
		t.Fatalf("source changed: %q %v", got, err)
	}
}
