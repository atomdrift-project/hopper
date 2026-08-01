package pkgparse

import "testing"

func TestPURLPath(t *testing.T) {
	t.Parallel()
	tests := []struct {
		name string
		purl string
		want string
	}{
		{"plain npm", "pkg:npm/lodash@4.17.21", "npm/lodash/4.17.21"},
		{"scoped npm keeps the scope as a level", "pkg:npm/%40vue/cli@5.0.8", "npm/@vue/cli/5.0.8"},
		{"scoped npm accepts the unescaped spelling", "pkg:npm/@vue/cli@5.0.8", "npm/@vue/cli/5.0.8"},
		{"pypi", "pkg:pypi/requests@2.31.0", "pypi/requests/2.31.0"},
		{"multi-segment golang namespace", "pkg:golang/github.com/foo/bar@1.2.3", "golang/github.com/foo/bar/1.2.3"},
		{"distro vendor is a namespace", "pkg:deb/debian/curl@8.5.0", "deb/debian/curl/8.5.0"},
		{"epoch survives in the version", "pkg:alpm/arch/containers-common@1:0.47.4-4", "alpm/arch/containers-common/1:0.47.4-4"},
		{"qualifiers are dropped", "pkg:deb/debian/curl@8.5.0?arch=amd64", "deb/debian/curl/8.5.0"},
		{"legacy spelling canonicalizes first", "pkg:chrome/abcdefg@2.1.0", "chrome-extension/abcdefg/2.1.0"},
		{"type case is folded", "PKG:NPM/Left-Pad@1.3.0", "npm/Left-Pad/1.3.0"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			got, ok := PURLPath(tt.purl)
			if !ok {
				t.Fatalf("PURLPath(%q) rejected the coordinate", tt.purl)
			}
			if got != tt.want {
				t.Errorf("PURLPath(%q) = %q, want %q", tt.purl, got, tt.want)
			}
		})
	}
}

// TestPURLPathRejects covers every input that must fall back to digest-keyed
// storage. Traversal is the one that matters most: a path segment is taken from
// a producer claim, so "../.." must never survive into a directory name.
func TestPURLPathRejects(t *testing.T) {
	t.Parallel()
	tests := []struct {
		name string
		purl string
	}{
		{"not a purl", "https://example.com/x.tgz"},
		{"no type separator", "pkg:npm"},
		{"version-less is not an immutable coordinate", "pkg:npm/lodash"},
		{"empty version", "pkg:npm/lodash@"},
		{"empty name", "pkg:npm/@1.0.0"},
		{"parent traversal, escaped", "pkg:npm/%2e%2e/%2e%2e/etc@1.0.0"},
		{"parent traversal, literal", "pkg:npm/../../etc@1.0.0"},
		{"separator smuggled into a segment", "pkg:npm/a%2Fb@1.0.0"},
		{"NUL in a segment", "pkg:npm/a%00b@1.0.0"},
		{"newline in a segment", "pkg:npm/a%0Ab@1.0.0"},
		{"truncated escape", "pkg:npm/lodash%4@1.0.0"},
		{"non-hex escape", "pkg:npm/lodash%zz@1.0.0"},
		{"reserved device name", "pkg:npm/nul@1.0.0"},
		{"reserved device name with extension", "pkg:npm/con.js@1.0.0"},
		{"trailing dot is stripped by windows", "pkg:npm/evil.exe.@1.0.0"},
		{"namespace deeper than the bound", "pkg:golang/a/b/c/d/e/f/g/h/i@1.0.0"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			if got, ok := PURLPath(tt.purl); ok {
				t.Errorf("PURLPath(%q) = %q, want rejection", tt.purl, got)
			}
		})
	}
}

// TestPURLPathRoundTrip is the property the storage layout rests on: a path
// written from a coordinate reads back as that same coordinate, so a filesystem
// walk recovers a sample's identity with no sidecar and no lookup table.
func TestPURLPathRoundTrip(t *testing.T) {
	t.Parallel()
	tests := []struct {
		purl     string
		wantName string
	}{
		{"pkg:npm/lodash@4.17.21", "lodash"},
		{"pkg:npm/%40vue/cli@5.0.8", "@vue/cli"},
		{"pkg:pypi/requests@2.31.0", "requests"},
		{"pkg:golang/github.com/foo/bar@1.2.3", "github.com/foo/bar"},
		{"pkg:deb/debian/curl@8.5.0", "debian/curl"},
		{"pkg:alpm/aur/yay@12.4.2", "aur/yay"},
		{"pkg:cargo/serde@1.0.197", "serde"},
		{"pkg:vscode-extension/ms-python/python@2024.1.0", "ms-python/python"},
	}
	for _, tt := range tests {
		t.Run(tt.purl, func(t *testing.T) {
			t.Parallel()
			path, ok := PURLPath(tt.purl)
			if !ok {
				t.Fatalf("PURLPath(%q) rejected the coordinate", tt.purl)
			}
			got, ok := ParsePURLPath(path)
			if !ok {
				t.Fatalf("ParsePURLPath(%q) rejected the path", path)
			}
			if got.PURL != tt.purl {
				t.Errorf("round trip of %q via %q = %q", tt.purl, path, got.PURL)
			}
			if got.Name != tt.wantName {
				t.Errorf("Name = %q, want %q (namespace must stay with the name)", got.Name, tt.wantName)
			}
			// A recovered coordinate must project back onto the same directory,
			// or a re-ingested sample would migrate on every walk.
			if again, ok := PURLPath(got.PURL); !ok || again != path {
				t.Errorf("reprojecting %q gave %q (ok=%v), want %q", got.PURL, again, ok, path)
			}
		})
	}
}

// TestParsePURLPathRejects guards the read direction against paths that were
// never written by PURLPath — a hand-made directory, or a walk that wandered
// into the wrong tier.
func TestParsePURLPathRejects(t *testing.T) {
	t.Parallel()
	for _, rel := range []string{
		"",
		"npm",
		"npm/lodash",              // no version component
		"npm/../4.17.21",          // traversal
		"NPM/lodash/4.17.21",      // a type is always lowercase
		"npm extra/lodash/1.0.0",  // space is not valid in a type
		"a/b/c/d/e/f/g/h/i/j/k/l", // deeper than the bound
	} {
		t.Run(rel, func(t *testing.T) {
			t.Parallel()
			if got, ok := ParsePURLPath(rel); ok {
				t.Errorf("ParsePURLPath(%q) = %+v, want rejection", rel, got)
			}
		})
	}
}
