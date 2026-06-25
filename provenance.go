package hopper

import (
	"encoding/json"
	"errors"
	"fmt"
	"time"
)

// SidecarSchemaVersion is the version of the provenance sidecar format. It is
// the same record forager writes next to every downloaded sample and the same
// envelope an upload carries to POST /api/upload. Bump only on incompatible
// changes; readers and the upload validator dispatch on it.
const SidecarSchemaVersion = "1.0"

// MaxRawBytes caps a single metadata record's verbatim payload so an oversized
// upstream document (e.g. a full npm packument carrying every version) cannot
// bloat a sidecar or an upload. A record over the cap drops Raw and downgrades
// Status to [MetadataPartial] rather than failing.
const MaxRawBytes = 256 << 10 // 256 KiB

// Metadata record completeness.
const (
	MetadataComplete = "complete"
	MetadataPartial  = "partial"
	MetadataMissing  = "missing"
)

// Sidecar is the per-artifact provenance record. forager writes it next to
// every downloaded sample (the on-disk ".forage.json"), and an HTTP uploader
// sends it as the required envelope alongside the bytes. The same data is
// projected into hopper's scalar columns and provenance JSONB at insert time
// from one serialization, so file, wire, and database never drift.
//
// It lives in hopper — the common dependency of every producer (forager) and
// consumer (hopper's upload handler, prism) — so the schema has exactly one
// definition and the writer and the validator share [Sidecar.Finalize].
//
// Four orthogonal parts: the bytes ([Artifact]); the act of acquiring them
// ([Fetch]); how the package was discovered ([Sidecar.Feed] — the triggering
// event or delta); and the package's authoritative current state
// ([Sidecar.Registry] — the snapshot looked up at fetch time). Feed answers
// "how was this found", Registry answers "what is it now"; either may be
// absent. Both store their source's response as-is.
//
// They are distinct named fields, not a generic list, because they are
// different kinds with a fixed 0..1 cardinality per capture — not N of one
// kind. A genuinely new kind (e.g. a VCS or advisory record) should become a
// new named field, never a role-tagged list element.
// The field order mirrors the documented four-part structure rather than the
// densest memory layout; a Sidecar is allocated once per download, so the
// marginal padding does not matter.
type Sidecar struct { //nolint:govet // fieldalignment: clarity over a few bytes
	SchemaVersion string          `json:"schema_version"`
	Artifact      Artifact        `json:"artifact"`
	Package       PackageRef      `json:"package,omitzero"`
	Fetch         Fetch           `json:"fetch"`
	Feed          *MetadataRecord `json:"feed,omitempty"`
	Registry      *MetadataRecord `json:"registry,omitempty"`
}

// PackageRef is the scalar identity of the software an artifact belongs to, as
// the producer understood it at fetch time. It makes the sidecar self-describing
// — a reader (hopper's upload handler, or the load-walk fallback) can populate
// the ecosystem/package/version/feed columns without re-deriving them from the
// on-disk path. Every field is empty for an artifact with no known origin (a
// human-submitted file). These are claims: hopper records them but derives a
// sample's authoritative label from analysis, never from them.
type PackageRef struct {
	Ecosystem string `json:"ecosystem,omitempty"`
	Name      string `json:"name,omitempty"`
	Version   string `json:"version,omitempty"`
	// PURL is the full versioned canonical Package URL (e.g.
	// "pkg:npm/lodash@4.17.21"), empty for ecosystems without a defined PURL
	// type. Its version-less form is projected into the samples.purl_base column.
	PURL string `json:"purl,omitempty"`
	Feed string `json:"feed,omitempty"` // discovery channel, e.g. "npm", "aikido"
}

// Artifact describes the saved bytes and the producer's own measurement of
// them. The filename + sha256 bind the sidecar to its artifact even if the two
// are separated; on upload, hopper re-hashes the bytes and rejects a mismatch.
type Artifact struct {
	Filename  string `json:"filename"`
	SHA256    string `json:"sha256"`
	SizeBytes int64  `json:"size_bytes"`
}

// Fetch describes the act of acquiring the artifact bytes. All times are UTC.
// URL is where the artifact itself came from; the metadata source URLs live on
// [Sidecar.Feed] and [Sidecar.Registry]. Collector identifies the producer
// (e.g. "forager+0a45da172e3f" or "prism"); Category is the producer's claimed
// bucket (good | new | bad | submitted) — a claim hopper records but does not
// trust to set a sample's authoritative label.
type Fetch struct {
	Collector    string    `json:"collector"`
	Category     string    `json:"category"`
	At           time.Time `json:"at"`
	URL          string    `json:"url,omitempty"`
	ETag         string    `json:"etag,omitempty"`
	LastModified string    `json:"last_modified,omitempty"`
}

// MetadataRecord is one source's view of the package, stored as-is in Raw. The
// JSON value is preserved unmodified, though whitespace is normalized (by the
// JSON encoder and by hopper's JSONB column) — so this is value fidelity, not
// byte fidelity. Its semantic role comes from which [Sidecar] field holds it
// (Feed vs Registry); Format is the parse dispatch key (e.g. "aur.rpc.v5",
// "npm.packument", "aikido.v1"); URL is the explicit source it was fetched
// from; At is when it was fetched (UTC).
type MetadataRecord struct {
	SourceID  string          `json:"source_id"`
	Ecosystem string          `json:"ecosystem,omitempty"`
	Format    string          `json:"format"`
	URL       string          `json:"url"`
	At        time.Time       `json:"at"`
	Status    string          `json:"status"`
	Raw       json.RawMessage `json:"raw,omitempty"`
	// Record is the normalized, ecosystem-agnostic account of the package — a
	// `fletch::Registry` document — when the producer has already parsed the raw
	// source(s) into the common shape a consumer reasons over. It is the read
	// path: scan applies it directly as a scan's root registry, so a
	// hopper-sourced analysis sees the same registry facts a live fetch would,
	// without re-parsing or re-fetching. Raw beneath it then holds the verbatim
	// source document(s) the record was derived from — for the fletch registry
	// collector, the full array of every provider document it fetched — the
	// re-parsing backup. Empty for a feed record or a producer that ships only Raw.
	Record json.RawMessage `json:"record,omitempty"`
}

// Finalize enforces the invariants every conforming sidecar must hold — schema
// version, UTC times, and the per-record Raw cap — so neither an on-disk file
// nor a database projection can carry a non-conforming record. Idempotent. The
// producer calls it before writing/sending; hopper calls it on receipt before
// [Sidecar.Validate] so an oversized Raw is trimmed rather than rejected.
func (sc *Sidecar) Finalize() {
	sc.SchemaVersion = SidecarSchemaVersion
	sc.Fetch.At = sc.Fetch.At.UTC()
	for _, rec := range []*MetadataRecord{sc.Feed, sc.Registry} {
		if rec == nil {
			continue
		}
		rec.At = rec.At.UTC()
		if len(rec.Raw) > MaxRawBytes {
			rec.Raw = nil
			rec.Status = MetadataPartial
		}
	}
}

// Validate reports whether the sidecar carries the required core every uploader
// must supply: a known schema version, the artifact identity (filename + a
// well-formed sha256), and the fetch core (collector, category, time). The
// optional Feed/Registry claims are not required — a human upload has neither.
// Validate does not check that SizeBytes or SHA256 match the actual bytes; the
// upload handler verifies those against what it streamed.
func (sc *Sidecar) Validate() error {
	if sc.SchemaVersion != SidecarSchemaVersion {
		return fmt.Errorf("unsupported schema_version %q (want %q)", sc.SchemaVersion, SidecarSchemaVersion)
	}
	if sc.Artifact.Filename == "" {
		return errors.New("artifact.filename is required")
	}
	if !isSHA256Hex(sc.Artifact.SHA256) {
		return errors.New("artifact.sha256 must be 64 lowercase hex chars")
	}
	if sc.Artifact.SizeBytes < 0 {
		return errors.New("artifact.size_bytes must be non-negative")
	}
	if sc.Fetch.Collector == "" {
		return errors.New("fetch.collector is required")
	}
	if sc.Fetch.Category == "" {
		return errors.New("fetch.category is required")
	}
	if sc.Fetch.At.IsZero() {
		return errors.New("fetch.at is required")
	}
	return nil
}

// isSHA256Hex reports whether s is exactly 64 lowercase hexadecimal digits.
func isSHA256Hex(s string) bool {
	if len(s) != 64 {
		return false
	}
	for i := range len(s) {
		c := s[i]
		if (c < '0' || c > '9') && (c < 'a' || c > 'f') {
			return false
		}
	}
	return true
}
