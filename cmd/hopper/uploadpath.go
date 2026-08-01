package main

import (
	"net/url"
	"path"
	"slices"
	"strings"

	"github.com/atomdrift-project/hopper"
	"github.com/atomdrift-project/hopper/pkgparse"
	"golang.org/x/net/publicsuffix"
)

// Where an upload lands on disk. hopper always picks the path — a producer's
// claims steer it but never name it — and the layout mirrors the one forager
// writes, so a package fetched by a forager node and the same package pushed by
// a scan worker are stored the same way.
//
// Two tiers, chosen by whether the producer supplied an immutable coordinate:
//
//	<bucket>/<producer>/pkg/<type>/<namespace…>/<name>/<version>/<filename>
//	<bucket>/<producer>/sha/<domain>/<aa>/<bb>/<sha256>/<filename>
//
// The coordinate tier is a projection of the PURL and nothing else (see
// [pkgparse.PURLPath]), which makes it reversible: a filesystem walk recovers
// type, name, version and purl_base from the path alone. The digest tier is for
// bytes with no coordinate — a URL fetch, a human submission, a local file — so
// the content hash is the identity, with the origin domain carried alongside it
// as the only human-legible handle such a tree has.
//
// Origin is otherwise deliberately absent from the coordinate tier: where the
// bytes were served from is a fact about the fetch, recorded on the row, not
// part of what the package is.
const (
	// uploadBucket is the pool an upload enters. Analysis, not the producer,
	// decides a sample's label, so every upload starts unlabelled and promoter
	// moves it later.
	uploadBucket = "unknown"
	// coordinateTier holds samples keyed by an immutable package coordinate.
	coordinateTier = "pkg"
	// digestTier holds samples keyed by their content hash.
	digestTier = "sha"
	// unknownDomain fills the digest tier's domain slot when an upload carries
	// no fetch URL. It matches the placeholder forager writes, so
	// [unknownToEmpty] maps it back to an empty column on the way in.
	unknownDomain = "_unknown"
)

// uploadProducers are the producers permitted their own tree. The producer is
// read from a sidecar's fetch.collector, which is a claim arriving over a
// lightly trusted boundary — so it selects among fixed segments rather than
// naming one, and an unlisted producer falls back to [uploadDir]. Passing the
// collector through would let an uploader mint directories at will.
var uploadProducers = []string{"forager", "prism", "scan"}

func isUploadProducer(name string) bool { return slices.Contains(uploadProducers, name) }

// uploadRelDir returns the directory an upload is stored in, relative to the
// data root, along with whether that directory is derived from the digest.
//
// digestKeyed is what makes an existing file at the target safe to keep: when
// the path contains the full sha, any occupant is necessarily these same bytes.
// In the coordinate tier — and in the legacy shard, which is keyed on only the
// first four hex digits — an occupant may belong to a different sample, and the
// caller must not overwrite it.
func uploadRelDir(sha string, prov *hopper.Sidecar) (dir string, digestKeyed bool) {
	// The collector names the producer, either bare or with an instance
	// ("scan+build07", "forager+0a45da172e3f"). An absent or unlisted one leaves
	// producer outside the allowlist and falls to the legacy root.
	var producer string
	if prov != nil {
		producer, _, _ = strings.Cut(prov.Fetch.Collector, "+")
		producer = strings.ToLower(strings.TrimSpace(producer))
	}
	if !isUploadProducer(producer) {
		return path.Join(uploadDir, sha[:2], sha[2:4]), false
	}
	if coord, ok := pkgparse.PURLPath(prov.Package.PURL); ok {
		return path.Join(uploadBucket, producer, coordinateTier, coord), false
	}
	return path.Join(uploadBucket, producer, digestTier, uploadDomain(prov.Fetch.URL), sha[:2], sha[2:4], sha), true
}

// uploadDomain is the registered domain (eTLD+1) of the host that served an
// artifact's bytes, matching the value forager records and the samples.domain
// column groups by. A host with no recognized public suffix — an IP literal, a
// .local name — keeps its bare hostname, and anything unparseable or unsafe as
// a path component becomes the placeholder rather than being rewritten into
// some other host's directory.
func uploadDomain(rawURL string) string {
	u, err := url.Parse(rawURL)
	if err != nil {
		return unknownDomain
	}
	host := u.Hostname()
	if host == "" {
		return unknownDomain // no URL at all, or one with no host (file://…)
	}
	domain, err := publicsuffix.EffectiveTLDPlusOne(host)
	if err != nil {
		domain = host
	}
	if domain = strings.ToLower(domain); !pkgparse.SafePathSegment(domain) {
		return unknownDomain
	}
	return domain
}

// parseUploadDirs recovers provenance from the components of an upload tree,
// between the producer segment and the filename. The coordinate tier round-trips
// through [pkgparse.ParsePURLPath]; the digest tier carries only its origin
// domain, since a content hash says nothing about what the bytes are.
func parseUploadDirs(dirs []string) pathProvenance {
	if len(dirs) < 2 {
		return pathProvenance{}
	}
	switch dirs[0] {
	case coordinateTier:
		parts, ok := pkgparse.ParsePURLPath(strings.Join(dirs[1:], "/"))
		if !ok {
			return pathProvenance{}
		}
		return pathProvenance{
			ecosystem: parts.Type,
			pkg:       parts.Name,
			version:   parts.Version,
			purl:      parts.PURL,
		}
	case digestTier:
		return pathProvenance{domain: unknownToEmpty(dirs[1])}
	}
	return pathProvenance{}
}
