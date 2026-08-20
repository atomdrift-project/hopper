package pkgparse

import "testing"

func TestVersionlessPURL(t *testing.T) {
	cases := map[string]string{
		"pkg:npm/lodash@4.17.21":         "pkg:npm/lodash",
		"pkg:npm/@zynkit/jwtbytes@0.5.2": "pkg:npm/@zynkit/jwtbytes",
		"pkg:cargo/serde@1.0.0":          "pkg:cargo/serde",
		"pkg:npm/no-version":             "pkg:npm/no-version",
		// A versionless scoped name's '@' is part of the namespace, not a
		// version separator: reading it as one collapsed every scoped npm
		// package onto the single identity "pkg:npm/".
		"pkg:npm/@zynkit/jwtbytes": "pkg:npm/@zynkit/jwtbytes",
		"pkg:npm/@scope/name@2.0":  "pkg:npm/@scope/name",
		"":                         "",
		// Qualifiers are part of the identity and survive the strip.
		"pkg:alpm/arch/yay@12.0-1?repository_url=https://aur.archlinux.org": "pkg:alpm/arch/yay?repository_url=https://aur.archlinux.org",
		"pkg:alpm/arch/yay?repository_url=https://aur.archlinux.org":        "pkg:alpm/arch/yay?repository_url=https://aur.archlinux.org",
		// The non-spec "?qualifiers@version" ordering older composers emitted:
		// the misplaced version is stripped out of the qualifier tail too.
		"pkg:alpm/arch/yay?repository_url=https://aur.archlinux.org@12.0-1": "pkg:alpm/arch/yay?repository_url=https://aur.archlinux.org",
		// A qualifier value containing '@' (URL userinfo) is not a version.
		"pkg:generic/thing?repository_url=https://user@example.com/repo": "pkg:generic/thing?repository_url=https://user@example.com/repo",
		// Artifact-selection qualifiers (arch/distro/kind) are not identity
		// and are dropped; repository_url is kept even among them.
		"pkg:rpm/fedora/curl@7.50.3-1.fc25?arch=x86_64&distro=fedora-25":                   "pkg:rpm/fedora/curl",
		"pkg:deb/debian/curl@7.50.3-1?arch=amd64":                                          "pkg:deb/debian/curl",
		"pkg:vscode-extension/pub/name@1.0.3?arch=x64&repository_url=https://open-vsx.org": "pkg:vscode-extension/pub/name?repository_url=https://open-vsx.org",
	}
	for in, want := range cases {
		if got := VersionlessPURL(in); got != want {
			t.Errorf("VersionlessPURL(%q) = %q, want %q", in, got, want)
		}
	}
}

// TestPURLVersion locks PURLVersion as the exact complement of VersionlessPURL:
// for every case above, base + version must reconstitute the coordinate the
// (purl_base, version) columns store.
func TestPURLVersion(t *testing.T) {
	cases := map[string]string{
		"pkg:npm/lodash@4.17.21":         "4.17.21",
		"pkg:npm/@zynkit/jwtbytes@0.5.2": "0.5.2",
		"pkg:npm/@zynkit/jwtbytes":       "",
		"pkg:npm/no-version":             "",
		"":                               "",
		"pkg:alpm/arch/yay@12.0-1?repository_url=https://aur.archlinux.org": "12.0-1",
		"pkg:alpm/arch/yay?repository_url=https://aur.archlinux.org":        "",
		// The non-spec "?qualifiers@version" ordering, which VersionlessPURL
		// also strips: the misplaced version is still the version.
		"pkg:alpm/arch/yay?repository_url=https://aur.archlinux.org@12.0-1": "12.0-1",
		// A qualifier value containing '@' (URL userinfo) is not a version.
		"pkg:generic/thing?repository_url=https://user@example.com/repo": "",
		// A subpath trails the version rather than being part of it.
		"pkg:golang/github.com/a/b@v1.2.3#sub/dir": "v1.2.3",
		"pkg:golang/github.com/a/b#sub/dir":        "",
	}
	for in, want := range cases {
		if got := PURLVersion(in); got != want {
			t.Errorf("PURLVersion(%q) = %q, want %q", in, got, want)
		}
	}
}
