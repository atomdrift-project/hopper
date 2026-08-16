package main

import (
	"path"
	"strings"
	"testing"

	"github.com/atomdrift-project/hopper"
)

// sidecar builds the minimal provenance the path router reads.
func sidecar(collector, purl, fetchURL string) *hopper.Sidecar {
	return &hopper.Sidecar{
		Artifact: hopper.Artifact{Filename: "x.tgz"},
		Package:  hopper.PackageRef{PURL: purl},
		Fetch:    hopper.Fetch{Collector: collector, Category: "submitted", URL: fetchURL},
	}
}

const testSHA = "3fa9c1084b2e07d6551f0c9a8e4b7d2036f1a5c8e9b0d4732a6c8517fe93b0d1"

func TestUploadRelDir(t *testing.T) {
	t.Parallel()
	tests := []struct {
		name            string
		prov            *hopper.Sidecar
		want            string
		wantDigestKeyed bool
	}{
		{
			name: "scan dependency with a coordinate",
			prov: sidecar("scan+build07", "pkg:npm/lodash@4.17.21", "https://registry.npmjs.org/lodash/-/lodash-4.17.21.tgz"),
			want: "incoming/scan/pkg/npm/lodash/4.17.21",
		},
		{
			name: "scoped coordinate keeps the scope as a level",
			prov: sidecar("scan+build07", "pkg:npm/%40vue/cli@5.0.8", ""),
			want: "incoming/scan/pkg/npm/@vue/cli/5.0.8",
		},
		{
			// The origin host is a fact about the fetch, not about what the
			// package is, so it stays on the row and out of this tier.
			name: "coordinate tier ignores the fetch host",
			prov: sidecar("scan+build07", "pkg:pypi/requests@2.31.0", "https://files.pythonhosted.org/packages/x/requests-2.31.0.tar.gz"),
			want: "incoming/scan/pkg/pypi/requests/2.31.0",
		},
		{
			name:            "scan URL fetch with no coordinate",
			prov:            sidecar("scan+build07", "", "https://cdn.example.com/releases/tool.tgz"),
			want:            "incoming/scan/sha/example.com/3f/a9/" + testSHA,
			wantDigestKeyed: true,
		},
		{
			name:            "scan local file has no origin at all",
			prov:            sidecar("scan+build07", "", ""),
			want:            "incoming/scan/sha/_unknown/3f/a9/" + testSHA,
			wantDigestKeyed: true,
		},
		{
			name:            "prism submission",
			prov:            sidecar("prism", "", ""),
			want:            "incoming/prism/sha/_unknown/3f/a9/" + testSHA,
			wantDigestKeyed: true,
		},
		{
			name: "forager node upload",
			prov: sidecar("forager+0a45da172e3f", "pkg:npm/evil@1.0.0", "https://registry.npmjs.org/evil/-/evil-1.0.0.tgz"),
			want: "incoming/forager/pkg/npm/evil/1.0.0",
		},
		{
			// A version-less PURL is not an immutable coordinate: two fetches of
			// it are not the same artifact, so the digest is the only honest key.
			name:            "version-less coordinate falls back to the digest",
			prov:            sidecar("scan+build07", "pkg:npm/lodash", "https://registry.npmjs.org/lodash/-/lodash-4.17.21.tgz"),
			want:            "incoming/scan/sha/npmjs.org/3f/a9/" + testSHA,
			wantDigestKeyed: true,
		},
		{
			// The collector is a producer claim; an unlisted one must never mint
			// a directory of its own choosing.
			name: "unlisted producer falls back to the fallback root",
			prov: sidecar("some-new-tool+1", "pkg:npm/lodash@4.17.21", ""),
			want: "incoming/uploads/3f/a9",
		},
		{
			name: "no provenance at all falls back to the fallback root",
			prov: nil,
			want: "incoming/uploads/3f/a9",
		},
		{
			name: "producer name is matched case-insensitively",
			prov: sidecar("SCAN+Build07", "pkg:npm/lodash@4.17.21", ""),
			want: "incoming/scan/pkg/npm/lodash/4.17.21",
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			got, digestKeyed := uploadRelDir(testSHA, tt.prov)
			if got != tt.want {
				t.Errorf("uploadRelDir() = %q, want %q", got, tt.want)
			}
			if digestKeyed != tt.wantDigestKeyed {
				t.Errorf("digestKeyed = %v, want %v", digestKeyed, tt.wantDigestKeyed)
			}
		})
	}
}

// TestUploadRelDirContained is the security property: a producer supplies the
// PURL and the URL that the path is built from, so no claim may escape the tree
// it is routed into, however it is spelled.
func TestUploadRelDirContained(t *testing.T) {
	t.Parallel()
	hostile := []*hopper.Sidecar{
		sidecar("scan", "pkg:npm/../../../etc@1.0.0", ""),
		sidecar("scan", "pkg:npm/%2e%2e%2f%2e%2e/x@1.0.0", ""),
		sidecar("scan", "pkg:npm/a%2Fb@1.0.0", ""),
		sidecar("scan", "pkg:%2e%2e/x@1.0.0", ""),
		sidecar("scan", "", "https://../../etc/passwd"),
		sidecar("scan", "", "https://[::1]/x"),
		sidecar("../../etc", "", ""),
		sidecar("scan/../prism", "", ""),
	}
	for _, prov := range hostile {
		got, _ := uploadRelDir(testSHA, prov)
		if got != path.Clean(got) {
			t.Errorf("uploadRelDir() = %q, which is not already clean", got)
		}
		if strings.HasPrefix(got, "/") || strings.Contains(got, "..") {
			t.Errorf("uploadRelDir() = %q escapes the data root", got)
		}
		if !strings.HasPrefix(got, uploadBucket+"/") {
			t.Errorf("uploadRelDir() = %q left the %s bucket", got, uploadBucket)
		}
	}
}

// TestUploadPathRoundTrip is what the layout buys: a path written from a
// coordinate reads back as that coordinate, so a filesystem walk recovers a
// sample's identity with no sidecar and no lookup table.
func TestUploadPathRoundTrip(t *testing.T) {
	t.Parallel()
	tests := []struct {
		purl string
		want pathProvenance
	}{
		{
			purl: "pkg:npm/lodash@4.17.21",
			want: pathProvenance{ecosystem: "npm", pkg: "lodash", version: "4.17.21", purl: "pkg:npm/lodash@4.17.21"},
		},
		{
			purl: "pkg:npm/%40vue/cli@5.0.8",
			want: pathProvenance{ecosystem: "npm", pkg: "@vue/cli", version: "5.0.8", purl: "pkg:npm/%40vue/cli@5.0.8"},
		},
		{
			purl: "pkg:deb/debian/curl@8.5.0",
			want: pathProvenance{ecosystem: "deb", pkg: "debian/curl", version: "8.5.0", purl: "pkg:deb/debian/curl@8.5.0"},
		},
	}
	for _, tt := range tests {
		t.Run(tt.purl, func(t *testing.T) {
			t.Parallel()
			dir, _ := uploadRelDir(testSHA, sidecar("scan+build07", tt.purl, ""))
			got := extractPathProvenance("/srv/data/"+dir+"/artifact.tgz", "unknown")
			if got != tt.want {
				t.Errorf("extractPathProvenance(%q) = %+v, want %+v", dir, got, tt.want)
			}
		})
	}
}

// TestUploadPathRoundTripDigestTier recovers what a digest-keyed path carries:
// the origin domain, and nothing else — a content hash says nothing about what
// the bytes are.
func TestUploadPathRoundTripDigestTier(t *testing.T) {
	t.Parallel()
	for _, tt := range []struct {
		name       string
		fetchURL   string
		wantDomain string
	}{
		{"known origin", "https://cdn.example.com/tool.tgz", "example.com"},
		{"no origin", "", ""},
	} {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			dir, _ := uploadRelDir(testSHA, sidecar("scan+build07", "", tt.fetchURL))
			got := extractPathProvenance("/srv/data/"+dir+"/tool.tgz", "unknown")
			if got != (pathProvenance{domain: tt.wantDomain}) {
				t.Errorf("extractPathProvenance(%q) = %+v, want domain %q only", dir, got, tt.wantDomain)
			}
		})
	}
}

// TestUploadProducerNotMatchedDeepInPath guards the walk against a producer name
// appearing as an ordinary package name. Only the segment directly under the
// label roots an upload tree.
func TestUploadProducerNotMatchedDeepInPath(t *testing.T) {
	t.Parallel()
	got := extractPathProvenance("/srv/data/unknown/foraged/javascript/npmjs.org/_/scan/scan-1.0.0.tgz", "unknown")
	want := pathProvenance{ecosystem: "javascript", domain: "npmjs.org", feed: "npmjs.org", pkg: "scan"}
	if got != want {
		t.Errorf("extractPathProvenance() = %+v, want %+v", got, want)
	}
}

func TestUploadDomain(t *testing.T) {
	t.Parallel()
	tests := []struct{ url, want string }{
		{"https://registry.npmjs.org/lodash/-/lodash-4.17.21.tgz", "npmjs.org"},
		{"https://files.pythonhosted.org/packages/x.tar.gz", "pythonhosted.org"},
		{"https://EXAMPLE.COM/x", "example.com"},
		{"https://sub.deep.example.co.uk/x", "example.co.uk"},
		{"", unknownDomain},
		{"not a url", unknownDomain},
		{"file:///local/path", unknownDomain},
		{"https://localhost/x", "localhost"}, // no public suffix: keep the bare host
	}
	for _, tt := range tests {
		t.Run(tt.url, func(t *testing.T) {
			t.Parallel()
			if got := uploadDomain(tt.url); got != tt.want {
				t.Errorf("uploadDomain(%q) = %q, want %q", tt.url, got, tt.want)
			}
		})
	}
}
