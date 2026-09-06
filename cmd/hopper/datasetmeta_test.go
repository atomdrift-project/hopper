package main

import (
	"context"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/klauspost/compress/zstd"

	"github.com/atomdrift-project/hopper"
)

const bkcRoot = "/data/samples/bad/datasets/various/Backstabber's Knife Collection/Backstabber's Knife Collection/samples/npm"

func TestParseDatasetLayout(t *testing.T) {
	tests := []struct {
		path string
		want datasetLayout
		ok   bool
	}{
		{
			path: bkcRoot + "/@servicetitan/forge/0.5.6/forge-0.5.6.tgz",
			want: datasetLayout{dataset: "Backstabber's Knife Collection", registry: "npm", name: "@servicetitan/forge", version: "0.5.6"},
			ok:   true,
		},
		{
			path: bkcRoot + "/ngx-bootstrap/20.0.6/meta.json.zst",
			want: datasetLayout{dataset: "Backstabber's Knife Collection", registry: "npm", name: "ngx-bootstrap", version: "20.0.6"},
			ok:   true,
		},
		// No "datasets" ancestor: a forager tree, where metadata.json is a sample.
		{path: "/data/samples/bad/foraged/javascript/npmjs.org/npm/samples/npm/x/1.0.0/metadata.json"},
		// Too shallow: no version directory.
		{path: "/data/samples/bad/datasets/x/samples/npm/meta.json.zst"},
		{path: "/data/samples/bad/datasets/x/samples/npm/lodash/meta.json.zst"},
	}
	for _, tc := range tests {
		got, ok := parseDatasetLayout(tc.path)
		if ok != tc.ok || got != tc.want {
			t.Errorf("parseDatasetLayout(%q) = %+v, %v; want %+v, %v", tc.path, got, ok, tc.want, tc.ok)
		}
	}
}

func TestIsDatasetMetadataPath(t *testing.T) {
	yes := []string{
		bkcRoot + "/@servicetitan/forge/0.5.6/meta.json.zst",
		bkcRoot + "/buffer-fetch/1.0.2/metadata.json",
		bkcRoot + "/buffer-fetch/1.0.2/maintainers.json",
	}
	no := []string{
		bkcRoot + "/@servicetitan/forge/0.5.6/forge-0.5.6.tgz",
		bkcRoot + "/foo/1.0.0/index.js",
		"/data/samples/good/Darwin-25.3.0/usr/libexec/x.mlmodelc/metadata.json",
		"/data/samples/bad/foraged/python/pythonhosted.org/backstabbers/_unknown/meta.json.zst",
	}
	for _, p := range yes {
		if !isDatasetMetadataPath(p) {
			t.Errorf("isDatasetMetadataPath(%q) = false, want true", p)
		}
	}
	for _, p := range no {
		if isDatasetMetadataPath(p) {
			t.Errorf("isDatasetMetadataPath(%q) = true, want false", p)
		}
	}
}

func TestDatasetFeedID(t *testing.T) {
	tests := map[string]string{
		"Backstabber's Knife Collection": "backstabbers-knife-collection",
		"MalOSS":                         "maloss",
		"  weird -- name!! ":             "weird-name",
	}
	for in, want := range tests {
		if got := datasetFeedID(in); got != want {
			t.Errorf("datasetFeedID(%q) = %q, want %q", in, got, want)
		}
	}
}

const forgeManifest = `{"name":"@servicetitan/forge","version":"0.5.6","dist":{"tarball":"https://registry.npmjs.org/@servicetitan/forge/-/forge-0.5.6.tgz","shasum":"f68b"},"scripts":{"preinstall":"node setup.mjs"}}`

func forgeLayout() datasetLayout {
	return datasetLayout{dataset: "Backstabber's Knife Collection", registry: "npm", name: "@servicetitan/forge", version: "0.5.6"}
}

func TestParseNPMRegistryDocumentManifest(t *testing.T) {
	doc, err := parseNPMRegistryDocument([]byte(forgeManifest), forgeLayout())
	if err != nil {
		t.Fatal(err)
	}
	if doc.format != formatNPMManifest || doc.name != "@servicetitan/forge" || doc.version != "0.5.6" {
		t.Errorf("doc = %+v", doc)
	}
	if doc.tarball != "https://registry.npmjs.org/@servicetitan/forge/-/forge-0.5.6.tgz" {
		t.Errorf("tarball = %q", doc.tarball)
	}
	if string(doc.raw) != forgeManifest || doc.trimmed {
		t.Errorf("manifest must be stored verbatim, got trimmed=%v raw=%s", doc.trimmed, doc.raw)
	}
	if got := npmRegistryDocURL(doc); got != "https://registry.npmjs.org/@servicetitan/forge/0.5.6" {
		t.Errorf("url = %q", got)
	}
}

func TestParseNPMRegistryDocumentPackument(t *testing.T) {
	small := `{"_id":"@servicetitan/forge","name":"@servicetitan/forge","dist-tags":{"latest":"0.5.6"},` +
		`"versions":{"0.5.5":{"name":"@servicetitan/forge","version":"0.5.5"},"0.5.6":` + forgeManifest + `},` +
		`"time":{"created":"2026-01-01T00:00:00Z","0.5.5":"2026-01-02T00:00:00Z","0.5.6":"2026-01-03T00:00:00Z","modified":"2026-01-03T00:00:00Z"},` +
		`"readme":"hello"}`
	doc, err := parseNPMRegistryDocument([]byte(small), forgeLayout())
	if err != nil {
		t.Fatal(err)
	}
	if doc.format != formatNPMPackument || doc.trimmed || string(doc.raw) != small {
		t.Errorf("a packument under the cap must round-trip verbatim: trimmed=%v", doc.trimmed)
	}
	if got := npmRegistryDocURL(doc); got != "https://registry.npmjs.org/@servicetitan/forge" {
		t.Errorf("url = %q", got)
	}

	// Inflate past MaxRawBytes with a fat readme: the trim keeps the release
	// we hold, drops the rest, and leaves every other top-level key alone.
	big := strings.Replace(small, `"readme":"hello"`, `"readme":"`+strings.Repeat("x", hopper.MaxRawBytes)+`"`, 1)
	doc, err = parseNPMRegistryDocument([]byte(big), forgeLayout())
	if err != nil {
		t.Fatal(err)
	}
	if !doc.trimmed || len(doc.raw) > hopper.MaxRawBytes {
		t.Fatalf("trimmed=%v len=%d", doc.trimmed, len(doc.raw))
	}
	var got struct {
		ID       string                     `json:"_id"`
		DistTags map[string]string          `json:"dist-tags"`
		Versions map[string]json.RawMessage `json:"versions"`
		Time     map[string]string          `json:"time"`
		Readme   *string                    `json:"readme"`
	}
	if err := json.Unmarshal(doc.raw, &got); err != nil {
		t.Fatal(err)
	}
	if got.ID != "@servicetitan/forge" || got.DistTags["latest"] != "0.5.6" {
		t.Errorf("top-level keys not preserved: %+v", got)
	}
	if len(got.Versions) != 1 || string(got.Versions["0.5.6"]) != forgeManifest {
		t.Errorf("versions = %v, want only 0.5.6 verbatim", got.Versions)
	}
	if len(got.Time) != 3 || got.Time["0.5.6"] == "" || got.Time["created"] == "" || got.Time["modified"] == "" {
		t.Errorf("time = %v, want created/modified/0.5.6", got.Time)
	}
	if got.Readme != nil {
		t.Error("readme should be dropped")
	}
}

func TestParseNPMRegistryDocumentRejectsMismatch(t *testing.T) {
	layout := forgeLayout()
	cases := map[string]string{
		"other version":      strings.Replace(forgeManifest, `"version":"0.5.6"`, `"version":"0.5.7"`, 1),
		"other package":      strings.Replace(forgeManifest, `"name":"@servicetitan/forge"`, `"name":"forge"`, 1),
		"not a document":     `[1,2,3]`,
		"missing version":    `{"name":"@servicetitan/forge"}`,
		"packument w/o vers": `{"name":"@servicetitan/forge","versions":{"0.5.5":{"name":"@servicetitan/forge","version":"0.5.5"}}}`,
	}
	for name, raw := range cases {
		if _, err := parseNPMRegistryDocument([]byte(raw), layout); err == nil {
			t.Errorf("%s: want error", name)
		}
	}
}

// writeZstd compresses data to path the way the dataset's meta.json.zst files
// are written.
func writeZstd(t *testing.T, path string, data []byte) {
	t.Helper()
	enc, err := zstd.NewWriter(nil)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, enc.EncodeAll(data, nil), 0o644); err != nil {
		t.Fatal(err)
	}
}

// datasetFixture lays out one BKC-style artifact directory under a temp root
// and returns the artifact path.
func datasetFixture(t *testing.T, docName string, doc []byte, maintainers string) string {
	t.Helper()
	dir := filepath.Join(t.TempDir(), "bad", "datasets", "various", "Backstabber's Knife Collection", "samples", "npm", "@servicetitan", "forge", "0.5.6")
	mustMkdirAll(t, dir)
	artifact := filepath.Join(dir, "forge-0.5.6.tgz")
	if err := os.WriteFile(artifact, []byte("tarball"), 0o644); err != nil {
		t.Fatal(err)
	}
	if strings.HasSuffix(docName, ".zst") {
		writeZstd(t, filepath.Join(dir, docName), doc)
	} else if err := os.WriteFile(filepath.Join(dir, docName), doc, 0o644); err != nil {
		t.Fatal(err)
	}
	if maintainers != "" {
		if err := os.WriteFile(filepath.Join(dir, maintainersName), []byte(maintainers), 0o644); err != nil {
			t.Fatal(err)
		}
	}
	return artifact
}

func TestAttachDatasetMetadata(t *testing.T) {
	artifact := datasetFixture(t, "meta.json.zst", []byte(forgeManifest), `["st-team", "rgdelato"]`)
	metaMtime := time.Date(2026, 9, 4, 22, 30, 0, 0, time.UTC)
	if err := os.Chtimes(filepath.Join(filepath.Dir(artifact), "meta.json.zst"), metaMtime, metaMtime); err != nil {
		t.Fatal(err)
	}

	// Mirror hashFile: the path parse and filename guess run first.
	s := &hopper.Sample{SHA256: strings.Repeat("ab", 32), SizeBytes: 7, Label: "bad", Path: artifact, Filename: "forge-0.5.6.tgz"}
	fillSampleProvenance(s, extractPathProvenance(artifact, "bad"), "forge-0.5.6.tgz")
	if s.Package != "forge" {
		t.Fatalf("precondition: filename parse gives %q", s.Package)
	}
	attachDatasetMetadata(s, artifact)

	if s.Provenance == nil {
		t.Fatal("provenance not attached")
	}
	var sc hopper.Sidecar
	if err := json.Unmarshal(s.Provenance, &sc); err != nil {
		t.Fatal(err)
	}
	if err := sc.Validate(); err != nil {
		t.Errorf("stored sidecar invalid: %v", err)
	}
	if sc.Artifact.SHA256 != s.SHA256 || sc.Artifact.Filename != "forge-0.5.6.tgz" || sc.Artifact.SizeBytes != 7 {
		t.Errorf("artifact = %+v", sc.Artifact)
	}
	if sc.Fetch.Collector != datasetCollector || sc.Fetch.Category != "bad" || !sc.Fetch.At.Equal(metaMtime) {
		t.Errorf("fetch = %+v", sc.Fetch)
	}
	if sc.Feed == nil || sc.Feed.SourceID != "backstabbers-knife-collection" || sc.Feed.Format != datasetFeedFormat {
		t.Fatalf("feed = %+v", sc.Feed)
	}
	var feedRaw struct {
		Dataset     string   `json:"dataset"`
		Maintainers []string `json:"maintainers"`
	}
	if err := json.Unmarshal(sc.Feed.Raw, &feedRaw); err != nil || feedRaw.Dataset != "Backstabber's Knife Collection" || len(feedRaw.Maintainers) != 2 {
		t.Errorf("feed raw = %s (%v)", sc.Feed.Raw, err)
	}
	if sc.Registry == nil || sc.Registry.Format != formatNPMManifest || sc.Registry.SourceID != "npm" || sc.Registry.Status != hopper.MetadataComplete {
		t.Fatalf("registry = %+v", sc.Registry)
	}
	if string(sc.Registry.Raw) != forgeManifest {
		t.Errorf("registry raw = %s", sc.Registry.Raw)
	}
	if sc.Package.PURL != "pkg:npm/%40servicetitan/forge@0.5.6" {
		t.Errorf("purl = %q", sc.Package.PURL)
	}

	// Columns: the document's claims replace the filename guess.
	if s.Package != "@servicetitan/forge" || s.Version != "0.5.6" {
		t.Errorf("package/version = %q/%q", s.Package, s.Version)
	}
	if s.Ecosystem != "javascript" {
		t.Errorf("ecosystem = %q, want the runtime name", s.Ecosystem)
	}
	if s.Feed != "backstabbers-knife-collection" {
		t.Errorf("feed = %q", s.Feed)
	}
	if s.PURLBase != "pkg:npm/%40servicetitan/forge" {
		t.Errorf("purl_base = %q", s.PURLBase)
	}
	if s.URL != "https://registry.npmjs.org/@servicetitan/forge/-/forge-0.5.6.tgz" || s.Domain != "npmjs.org" {
		t.Errorf("url/domain = %q/%q", s.URL, s.Domain)
	}
	if s.FetchedAt == nil || !s.FetchedAt.Equal(metaMtime) {
		t.Errorf("fetched_at = %v", s.FetchedAt)
	}
}

func TestAttachDatasetMetadataUncompressedAndAbsent(t *testing.T) {
	// metadata.json (older captures) is read too.
	artifact := datasetFixture(t, "metadata.json", []byte(forgeManifest), "")
	s := &hopper.Sample{SHA256: strings.Repeat("ab", 32), SizeBytes: 7, Label: "bad", Path: artifact}
	attachDatasetMetadata(s, artifact)
	if s.Provenance == nil || s.Package != "@servicetitan/forge" {
		t.Errorf("metadata.json not attached: package=%q", s.Package)
	}

	// A mismatched document is refused rather than mis-attached.
	other := strings.Replace(forgeManifest, `"version":"0.5.6"`, `"version":"9.9.9"`, 1)
	artifact = datasetFixture(t, "meta.json.zst", []byte(other), "")
	s = &hopper.Sample{SHA256: strings.Repeat("ab", 32), Label: "bad", Path: artifact, Package: "forge"}
	attachDatasetMetadata(s, artifact)
	if s.Provenance != nil || s.Package != "forge" {
		t.Errorf("mismatched document must not attach: %s", s.Provenance)
	}

	// A real forager sidecar takes precedence.
	artifact = datasetFixture(t, "meta.json.zst", []byte(forgeManifest), "")
	s = &hopper.Sample{SHA256: strings.Repeat("ab", 32), Label: "bad", Path: artifact, Provenance: []byte(`{"schema_version":"1.0"}`)}
	attachDatasetMetadata(s, artifact)
	if string(s.Provenance) != `{"schema_version":"1.0"}` {
		t.Error("existing provenance overwritten")
	}

	// Outside a dataset tree nothing happens, even with a document beside it.
	dir := t.TempDir()
	plain := filepath.Join(dir, "forge-0.5.6.tgz")
	for _, p := range []string{plain, filepath.Join(dir, "metadata.json")} {
		if err := os.WriteFile(p, []byte(forgeManifest), 0o644); err != nil {
			t.Fatal(err)
		}
	}
	s = &hopper.Sample{SHA256: strings.Repeat("ab", 32), Label: "bad", Path: plain}
	attachDatasetMetadata(s, plain)
	if s.Provenance != nil {
		t.Error("non-dataset path must not attach")
	}
}

func TestStartEnumerationSkipsDatasetMetadata(t *testing.T) {
	useTestPathLister(t)
	artifact := datasetFixture(t, "meta.json.zst", []byte(forgeManifest), `["st-team"]`)
	root := filepath.Dir(artifact)

	var got []string
	stream := startEnumeration(context.Background(), root, time.Time{})
	for lp := range stream.paths {
		got = append(got, filepath.Base(lp.path))
	}
	if err := <-stream.done; err != nil {
		t.Fatal(err)
	}
	if len(got) != 1 || got[0] != "forge-0.5.6.tgz" {
		t.Fatalf("enumeration = %v, want only the artifact", got)
	}
}
