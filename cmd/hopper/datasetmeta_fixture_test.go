package main

import (
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/atomdrift-project/hopper"
)

// TestAttachDatasetMetadataFixtures walks a real dataset tree named by
// HOPPER_DATASET_FIXTURES (…/datasets/<x>/samples/<registry>/…) and reports
// what each artifact would receive. Skipped when the variable is unset.
func TestAttachDatasetMetadataFixtures(t *testing.T) {
	root := os.Getenv("HOPPER_DATASET_FIXTURES")
	if root == "" {
		t.Skip("HOPPER_DATASET_FIXTURES not set")
	}
	n := 0
	err := filepath.WalkDir(root, func(path string, d os.DirEntry, err error) error {
		if err != nil || d.IsDir() || isDatasetMetadataPath(path) {
			return err
		}
		n++
		s := &hopper.Sample{SHA256: strings.Repeat("ab", 32), SizeBytes: 5, Label: "bad", Path: path, Filename: filepath.Base(path)}
		fillSampleProvenance(s, extractPathProvenance(path, "bad"), filepath.Base(path))
		attachDatasetMetadata(s, path)
		if s.Provenance == nil {
			t.Errorf("%s: no provenance attached", path)
			return nil
		}
		var sc hopper.Sidecar
		if err := json.Unmarshal(s.Provenance, &sc); err != nil {
			t.Errorf("%s: %v", path, err)
			return nil
		}
		if err := sc.Validate(); err != nil {
			t.Errorf("%s: %v", path, err)
		}
		t.Logf("%s\n  package=%q version=%q eco=%q feed=%q purl_base=%q\n  url=%q domain=%q fetched_at=%v\n  registry: format=%s status=%s raw=%d bytes; feed raw=%s",
			strings.TrimPrefix(path, root), s.Package, s.Version, s.Ecosystem, s.Feed, s.PURLBase,
			s.URL, s.Domain, s.FetchedAt, sc.Registry.Format, sc.Registry.Status, len(sc.Registry.Raw), sc.Feed.Raw)
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
	if n == 0 {
		t.Fatal("no artifacts under fixture root")
	}
}
