package main

import (
	"encoding/json"
	"log/slog"
	"net/http"
	"strings"
	"sync"
	"time"
	"unicode"

	"github.com/atomdrift-project/hopper"
	"github.com/atomdrift-project/hopper/pkgparse"
	"go.opentelemetry.io/otel"
	"go.opentelemetry.io/otel/metric"
)

// An upload is filed under the source "upload", the trust-boundary marker,
// whoever sent it. Who did is recorded beside it, in the location's feed when
// the producer named no feed of its own, and shown as upload:<uploader>. A sample usually reaches hopper through
// relays (poppy asks beamline, beamline asks postdoc, postdoc uploads), so the
// last hop's User-Agent says little: the first atomdrift service a request
// reaches names its caller in originHeader, and every relay passes it on.
// Nothing about an upload's handling depends on the name; it is a label.

// originHeader names the client an upload is on behalf of: 1 to 32 characters
// of [a-z0-9-], after sanitizeOrigin.
const originHeader = "Atomdrift-Origin"

// maxOriginLen is the longest origin, in characters.
const maxOriginLen = 32

// otherUploader is the uploader of a request whose origin names a client
// hopper does not know. Recording it as sent would let any caller of a public
// relay add a value to the feed facets and a series to hopper.uploads.
const otherUploader = "other"

// uploaders maps the names a client goes by, as an origin or as a User-Agent
// product token, to the uploader it is recorded as. postdoc's server uploads
// through scan's hopper client, so they arrive as atomdrift-scan; prism is
// the website.
var uploaders = map[string]string{
	"website":                       "website",
	"prism":                         "website",
	"postdoc":                       "postdoc",
	"scan":                          "scan",
	"atomdrift-scan":                "scan",
	"beamline":                      "beamline",
	"poppy":                         "poppy",
	"forager":                       "forager",
	"atomdrift-supplychain-forager": "forager",
}

// sanitizeOrigin is name with everything outside [A-Za-z0-9-] dropped,
// lowercased, and cut to maxOriginLen characters: the rule every relay
// applies, applied again here.
func sanitizeOrigin(name string) string {
	var b strings.Builder
	for i := 0; i < len(name) && b.Len() < maxOriginLen; i++ {
		switch c := name[i]; {
		case c >= 'a' && c <= 'z', c >= '0' && c <= '9', c == '-':
			b.WriteByte(c)
		case c >= 'A' && c <= 'Z':
			b.WriteByte(c + 'a' - 'A')
		default: // dropped
		}
	}
	return b.String()
}

// uploaderOf names who an upload request is on behalf of, "" when nothing
// says. In order: the origin a relay named; the request's own User-Agent,
// every browser being the website, and anything else by its product token
// (the text before the first "/" or space); a browser's fetch metadata, which
// prism's form posts carried when they came to hopper directly. A name that
// is no client hopper knows is otherUploader.
func uploaderOf(r *http.Request) string {
	name := sanitizeOrigin(r.Header.Get(originHeader))
	relayed := name != ""
	if !relayed {
		agent := strings.TrimSpace(r.UserAgent())
		if len(agent) >= 8 && strings.EqualFold(agent[:8], "mozilla/") {
			return "website"
		}
		if i := strings.IndexFunc(agent, func(c rune) bool { return c == '/' || unicode.IsSpace(c) }); i >= 0 {
			agent = agent[:i]
		}
		name = sanitizeOrigin(agent)
	}
	if uploader, ok := uploaders[name]; ok {
		return uploader
	}
	switch {
	case !relayed && (r.Header.Get("Sec-Fetch-Site") != "" || r.Header.Get("Origin") != ""):
		return "website"
	case name == "":
		return ""
	default:
		return otherUploader
	}
}

// uploadLabel is how a location filed by an upload is shown:
// upload:<uploader>, when source is "upload" and feed is an uploader hopper
// records (an upload stored before uploaders were, or by the legacy schema,
// may hold the producer's feed there). Otherwise "".
func uploadLabel(source, feed string) string {
	name, known := uploaders[feed]
	if source != "upload" || (feed != otherUploader && (!known || name != feed)) {
		return ""
	}
	return "upload:" + feed
}

// sourceFeed renders where a file came from: upload:<uploader> for an upload
// whose uploader is recorded, otherwise its source and feed as source/feed.
func sourceFeed(source, feed string) string {
	if label := uploadLabel(source, feed); label != "" {
		return label
	}
	if feed == "" {
		return source
	}
	return source + "/" + feed
}

// uploadSample builds the row for a stored upload. Source is always "upload"
// (the trust-boundary marker, distinct from a co-located forager's trusted
// "forager" direct-insert) and Label is always "unknown" — neither is taken
// from the producer. When provenance is present, its scalar claims fill the
// descriptive columns and the finalized sidecar is preserved verbatim in the
// provenance JSONB.
func uploadSample(sha, filename, relPath string, size int64, prov *hopper.Sidecar) *hopper.Sample {
	// An uploaded artifact is observed now — nothing else records when it
	// arrived, and the row is only as old as this write. mtime is what the
	// promotion queue ages against, so leaving it NULL kept every upload out of
	// promotion entirely rather than merely young: a row with no mtime never
	// satisfies the age gate, no matter how long it sits.
	now := time.Now().UTC()
	sample := &hopper.Sample{
		SHA256:      sha,
		Source:      "upload",
		Filename:    filename,
		Path:        relPath,
		Label:       "unknown",
		LabelSource: "upload",
		SizeBytes:   size,
		Mtime:       &now,
	}
	if prov != nil {
		// Capture time when the producer recorded one: a dependency fetched from a
		// registry was published before we saw it, and the age gate should measure
		// from when the bytes existed, not from when they reached us.
		if !prov.Fetch.At.IsZero() {
			at := prov.Fetch.At
			sample.Mtime = &at
		}
		if provJSON, err := json.Marshal(prov); err == nil {
			sample.Provenance = provJSON
		}
		applySidecarClaims(sample, prov)
	}
	// Fill name/version gaps from the filename, mirroring the walker's
	// fillSampleProvenance: producer claims win, the parse only fills blanks.
	// Uploaded dependencies often carry a version-less PURL ("pkg:npm/pg")
	// whose release is visible only in the filename ("pg-8.23.0.tgz").
	parsedName, parsedVersion, _ := pkgparse.ParseFilename(filename)
	if sample.Package == "" {
		sample.Package = parsedName
	}
	if sample.Version == "" {
		if v := pkgparse.VersionForName(filename, sample.Package); v != "" {
			sample.Version = v
		} else {
			sample.Version = parsedVersion
		}
	}
	inferWheelIdentity(sample, filename)
	return sample
}

// uploadsCounter counts accepted uploads by uploader: one of the names in
// uploaders, otherUploader, or "none".
var uploadsCounter = sync.OnceValue(func() metric.Int64Counter {
	c, err := otel.Meter(meterName).Int64Counter(
		"hopper.uploads",
		metric.WithDescription("Uploads accepted, by the client they were on behalf of."),
		metric.WithUnit("{upload}"),
	)
	if err != nil {
		slog.Warn("metrics: hopper.uploads counter unavailable", "error", err)
		return nil
	}
	return c
})
