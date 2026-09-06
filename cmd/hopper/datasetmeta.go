package main

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"time"

	"github.com/klauspost/compress/zstd"

	"github.com/atomdrift-project/hopper"
	"github.com/atomdrift-project/hopper/pkgparse"
)

// Dataset registry metadata.
//
// Some curated corpora — Backstabber's Knife Collection is the first — do not
// arrive through forager, so no ".forage.json" sidecar exists, but they ship
// each artifact in its own directory next to the registry document it was
// published with:
//
//	.../datasets/<group>/<dataset>/samples/<registry>/<name...>/<version>/
//	    <name>-<version>.tgz   the artifact
//	    meta.json.zst          zstd npm packument, or the one version's manifest
//	    metadata.json          uncompressed packument (older captures)
//	    maintainers.json       ["login", ...] at capture time
//
// The walk treats those documents the way it treats a forager sidecar: they
// are provenance for the artifact beside them, never samples of their own. The
// artifact's row gets a synthesized [hopper.Sidecar] whose Registry record
// holds the document and whose Feed record names the dataset — the collection
// itself is the evidence that told us the package is malware, and a sidecar
// with no feed record would put every strongly-detected sample into the
// acquit triage queue as an unsupported conviction (see TriageAcquit).

// The per-artifact documents are hopper.DatasetMetadataNames.
// metadataDocumentNames are tried in order for the registry record; the
// maintainers list is folded into the feed record.
var (
	metadataDocumentNames = []string{"meta.json.zst", "metadata.json"}
	maintainersName       = "maintainers.json"
)

// maxDatasetMetadataBytes caps the decompressed document: a packument for a
// package with thousands of releases runs to several MB (duckdb: 6.8 MB), and
// a hostile zstd bomb must not be able to pin a hash worker.
const maxDatasetMetadataBytes = 64 << 20

// datasetCollector is the Fetch.Collector a synthesized sidecar records: the
// bytes were not fetched by hopper but by whoever assembled the dataset, and
// the walk is where they and their registry record met.
const datasetCollector = "hopper-walk"

// datasetFeedFormat is the Format of the synthesized Feed record. Its Raw is
// {"dataset": <directory name>, "maintainers": [...]} — the corpus's own
// per-sample claim, kept beside (not inside) the registry document.
const datasetFeedFormat = "hopper.dataset.v1"

// datasetLayout is what the directory grammar above says about a file.
type datasetLayout struct {
	dataset  string // "Backstabber's Knife Collection" — the directory name
	registry string // "npm" — the component after samples/
	name     string // "@servicetitan/forge" — every component between registry and version
	version  string // "0.5.6"
}

// parseDatasetLayout recovers the dataset grammar from path. ok is false when
// the path is not <…>/datasets/<…>/samples/<registry>/<name…>/<version>/<file>:
// the "datasets" ancestor is what distinguishes a curated corpus from a
// forager or upload tree, where a file that happens to be named metadata.json
// is a sample.
func parseDatasetLayout(path string) (datasetLayout, bool) {
	parts := strings.Split(filepath.ToSlash(path), "/")
	datasets := -1
	for i, p := range parts {
		if p == "datasets" {
			datasets = i
			break
		}
	}
	if datasets < 0 {
		return datasetLayout{}, false
	}
	samples := -1
	for i := len(parts) - 1; i > datasets; i-- {
		if parts[i] == "samples" {
			samples = i
			break
		}
	}
	// registry, at least one name component, version, file.
	if samples < datasets+2 || len(parts)-samples < 5 {
		return datasetLayout{}, false
	}
	if slices.Contains(parts[samples+1:len(parts)-1], "") {
		return datasetLayout{}, false
	}
	return datasetLayout{
		dataset:  parts[samples-1],
		registry: parts[samples+1],
		name:     strings.Join(parts[samples+2:len(parts)-2], "/"),
		version:  parts[len(parts)-2],
	}, true
}

// isDatasetMetadataPath reports whether path is a dataset registry document —
// provenance for the artifact beside it, which enumeration must not ingest as
// a sample.
func isDatasetMetadataPath(path string) bool {
	if !slices.Contains(hopper.DatasetMetadataNames, filepath.Base(path)) {
		return false
	}
	_, ok := parseDatasetLayout(path)
	return ok
}

// datasetFeedID is the samples.feed / Feed.SourceID spelling of a dataset
// directory name: "Backstabber's Knife Collection" → "backstabbers-knife-collection".
func datasetFeedID(dataset string) string {
	var b strings.Builder
	dash := false
	for _, r := range strings.ToLower(dataset) {
		switch {
		case r >= 'a' && r <= 'z', r >= '0' && r <= '9':
			b.WriteRune(r)
			dash = false
		case r == '\'':
			// "Backstabber's" → "backstabbers", not "backstabber-s".
		default:
			if b.Len() > 0 && !dash {
				b.WriteByte('-')
				dash = true
			}
		}
	}
	return strings.TrimSuffix(b.String(), "-")
}

// attachDatasetMetadata is the dataset counterpart of attachSidecarProvenance:
// when the artifact at path sits in a dataset directory with a registry
// document, it synthesizes the provenance sidecar onto s and projects the
// document's claims (name, version, PURL, tarball URL, feed) into the scalar
// columns, overriding the filename guesses fillSampleProvenance made. A sample
// that already carries provenance (a real forager sidecar) is left alone, as
// is anything the grammar or the document does not fit — a dataset we do not
// understand is walked exactly as before. Called while s.Path is still the
// absolute on-disk path.
func attachDatasetMetadata(s *hopper.Sample, path string) {
	if s.Provenance != nil {
		return
	}
	layout, ok := parseDatasetLayout(path)
	if !ok || layout.registry != "npm" {
		return
	}
	dir := filepath.Dir(path)
	raw, at, ok := readDatasetDocument(dir)
	if !ok {
		return
	}
	doc, err := parseNPMRegistryDocument(raw, layout)
	if err != nil {
		slog.Debug("dataset metadata ignored", "path", path, "error", err)
		return
	}
	maintainers := readMaintainers(dir)

	sc := datasetSidecar(layout, doc, maintainers, hopper.Artifact{
		Filename:  filepath.Base(path),
		SHA256:    s.SHA256,
		SizeBytes: s.SizeBytes,
	}, at, s.Label)
	sc.Finalize()
	if err := sc.Validate(); err != nil {
		slog.Debug("dataset metadata sidecar invalid", "path", path, "error", err)
		return
	}
	data, err := json.Marshal(sc)
	if err != nil {
		return
	}
	s.Provenance = data
	applySidecarClaims(s, sc)
	// The sidecar names the registry ("npm"); the column holds the runtime.
	if eco := pkgparse.NormalizeEcosystem(sc.Package.Ecosystem); eco != "" {
		s.Ecosystem = eco
	}
}

// readDatasetDocument returns the first registry document found in dir,
// decompressed, with its mtime — the closest thing the dataset records to the
// moment the registry was consulted.
func readDatasetDocument(dir string) (raw []byte, at time.Time, ok bool) {
	for _, name := range metadataDocumentNames {
		p := filepath.Join(dir, name)
		info, err := os.Stat(p)
		if err != nil || !info.Mode().IsRegular() {
			continue
		}
		data, err := readMaybeZstd(p)
		if err != nil {
			slog.Debug("dataset metadata unreadable", "path", p, "error", err)
			continue
		}
		return data, info.ModTime(), true
	}
	return nil, time.Time{}, false
}

// readMaybeZstd reads a file, transparently decompressing a ".zst" name, with
// the decompressed size capped at maxDatasetMetadataBytes.
func readMaybeZstd(path string) ([]byte, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer f.Close() //nolint:errcheck // read-only file

	var r io.Reader = f
	if strings.HasSuffix(path, ".zst") {
		zr, err := zstd.NewReader(f, zstd.WithDecoderLowmem(true), zstd.WithDecoderConcurrency(1))
		if err != nil {
			return nil, fmt.Errorf("zstd: %w", err)
		}
		defer zr.Close()
		r = zr
	}
	data, err := io.ReadAll(io.LimitReader(r, maxDatasetMetadataBytes+1))
	if err != nil {
		return nil, err
	}
	if len(data) > maxDatasetMetadataBytes {
		return nil, fmt.Errorf("document exceeds %d bytes", maxDatasetMetadataBytes)
	}
	return data, nil
}

// readMaintainers returns the maintainers.json array beside an artifact, or
// nil when absent or not a JSON array.
func readMaintainers(dir string) json.RawMessage {
	data, err := os.ReadFile(filepath.Join(dir, maintainersName))
	if err != nil {
		return nil
	}
	data = bytes.TrimSpace(data)
	if !json.Valid(data) || len(data) == 0 || data[0] != '[' {
		return nil
	}
	return data
}

// Registry document formats. A packument is the registry's whole-package
// document (GET /<name>); a manifest is the one release's document
// (GET /<name>/<version>) — the object a packument holds under versions[v].
const (
	formatNPMPackument = "npm.packument"
	formatNPMManifest  = "npm.manifest"
)

// npmDocument is a registry document reduced to what the sidecar needs.
type npmDocument struct {
	name    string
	version string
	tarball string
	format  string
	raw     json.RawMessage
	// trimmed is set when raw is a packument with its other releases removed.
	trimmed bool
}

// npmManifestFields are the manifest keys the sidecar reads.
type npmManifestFields struct {
	Name    string `json:"name"`
	Version string `json:"version"`
	Dist    struct {
		Tarball string `json:"tarball"`
	} `json:"dist"`
}

var errNotRegistryDocument = errors.New("not an npm registry document")

// parseNPMRegistryDocument accepts either document shape and checks it against
// the directory it was found in: a document naming another package or release
// is rejected rather than attached, because wrong provenance is worse than
// none. A packument is trimmed to the one release the directory holds: the
// other releases' manifests (and the top-level readme) are what make a
// popular package's packument run to megabytes, far over hopper's MaxRawBytes
// cap, and the artifact beside it is exactly one release.
func parseNPMRegistryDocument(raw []byte, layout datasetLayout) (npmDocument, error) {
	var top map[string]json.RawMessage
	if err := json.Unmarshal(raw, &top); err != nil {
		return npmDocument{}, fmt.Errorf("%w: %w", errNotRegistryDocument, err)
	}
	var doc npmDocument
	var manifest json.RawMessage
	if versionsRaw, isPackument := top["versions"]; isPackument {
		var versions map[string]json.RawMessage
		if err := json.Unmarshal(versionsRaw, &versions); err != nil {
			return npmDocument{}, fmt.Errorf("%w: versions: %w", errNotRegistryDocument, err)
		}
		manifest = versions[layout.version]
		if manifest == nil {
			return npmDocument{}, fmt.Errorf("packument has no version %q", layout.version)
		}
		doc.format = formatNPMPackument
		doc.raw, doc.trimmed = trimPackument(top, layout.version, manifest, raw)
	} else {
		manifest = raw
		doc.format = formatNPMManifest
		doc.raw = raw
	}

	var m npmManifestFields
	if err := json.Unmarshal(manifest, &m); err != nil {
		return npmDocument{}, fmt.Errorf("%w: manifest: %w", errNotRegistryDocument, err)
	}
	if m.Name == "" || m.Version == "" {
		return npmDocument{}, fmt.Errorf("%w: manifest lacks name/version", errNotRegistryDocument)
	}
	if m.Version != layout.version {
		return npmDocument{}, fmt.Errorf("document is %s@%s, directory is %s", m.Name, m.Version, layout.version)
	}
	if !strings.EqualFold(m.Name, layout.name) {
		return npmDocument{}, fmt.Errorf("document is %s, directory is %s", m.Name, layout.name)
	}
	doc.name = m.Name
	doc.version = m.Version
	doc.tarball = m.Dist.Tarball
	return doc, nil
}

// trimPackument rewrites a packument to carry only the given release: every
// top-level key is kept verbatim except versions (reduced to the one
// manifest), time (reduced to created/modified/the release) and readme
// (dropped). A packument that already fits under MaxRawBytes is returned as
// is, so a small document round-trips byte-for-byte.
func trimPackument(top map[string]json.RawMessage, version string, manifest, raw json.RawMessage) (json.RawMessage, bool) {
	if len(raw) <= hopper.MaxRawBytes {
		return raw, false
	}
	out := make(map[string]json.RawMessage, len(top))
	for k, v := range top {
		switch k {
		case "versions", "readme":
			continue
		case "time":
			var times map[string]json.RawMessage
			if err := json.Unmarshal(v, &times); err == nil {
				kept := make(map[string]json.RawMessage, 3)
				for _, tk := range []string{"created", "modified", version} {
					if t, ok := times[tk]; ok {
						kept[tk] = t
					}
				}
				if b, err := json.Marshal(kept); err == nil {
					out[k] = b
					continue
				}
			}
			out[k] = v
		default:
			out[k] = v
		}
	}
	versions, err := json.Marshal(map[string]json.RawMessage{version: manifest})
	if err != nil {
		return raw, false
	}
	out["versions"] = versions
	trimmed, err := json.Marshal(out)
	if err != nil {
		return raw, false
	}
	return trimmed, true
}

// npmRegistryDocURL is where the registry serves the document shape we hold.
func npmRegistryDocURL(doc npmDocument) string {
	u := "https://registry.npmjs.org/" + doc.name
	if doc.format == formatNPMManifest {
		u += "/" + doc.version
	}
	return u
}

// datasetFeedRaw is the Feed record's Raw: the dataset's own per-sample claim.
type datasetFeedRaw struct {
	Dataset     string          `json:"dataset"`
	Maintainers json.RawMessage `json:"maintainers,omitempty"`
}

// datasetSidecar assembles the provenance record for one dataset artifact. The
// registry record is what the dataset captured of the registry; the feed
// record is the dataset's own claim about the sample (which corpus, which
// maintainers); the package reference is taken from the document, which knows
// the exact name (scope, case) the filename parse can only guess at.
func datasetSidecar(
	layout datasetLayout, doc npmDocument, maintainers json.RawMessage,
	artifact hopper.Artifact, at time.Time, label string,
) *hopper.Sidecar {
	feedID := datasetFeedID(layout.dataset)
	feedRaw, err := json.Marshal(datasetFeedRaw{Dataset: layout.dataset, Maintainers: maintainers})
	if err != nil {
		// Only an invalid maintainers document could fail, and readMaintainers
		// already refused that; keep the dataset name at least.
		feedRaw, err = json.Marshal(datasetFeedRaw{Dataset: layout.dataset})
	}
	if err != nil {
		feedRaw = nil
	}

	purl, _ := pkgparse.SourcePURL(layout.registry, "", doc.name, doc.version, "")
	registryStatus := hopper.MetadataComplete
	if doc.trimmed {
		registryStatus = hopper.MetadataPartial
	}
	return &hopper.Sidecar{
		SchemaVersion: hopper.SidecarSchemaVersion,
		Artifact:      artifact,
		Package: hopper.PackageRef{
			Ecosystem: layout.registry,
			Name:      doc.name,
			Version:   doc.version,
			PURL:      purl,
			Feed:      feedID,
		},
		Fetch: hopper.Fetch{
			Collector: datasetCollector,
			Category:  label,
			At:        at,
			URL:       doc.tarball,
		},
		Feed: &hopper.MetadataRecord{
			SourceID: feedID,
			Format:   datasetFeedFormat,
			At:       at,
			Status:   hopper.MetadataComplete,
			Raw:      feedRaw,
		},
		Registry: &hopper.MetadataRecord{
			SourceID:  layout.registry,
			Ecosystem: layout.registry,
			Format:    doc.format,
			URL:       npmRegistryDocURL(doc),
			At:        at,
			Status:    registryStatus,
			Raw:       doc.raw,
		},
	}
}
