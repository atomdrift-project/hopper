package pkgparse

import (
	"encoding/json"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
)

// Cross-tool consistency: every PURL this package generates must read back in
// fletch — the fetcher that ultimately acts on it — as the same coordinates,
// route to a registry, and (for deterministic ecosystems) resolve a download
// URL. fletch's `purl` subcommand reports all of that offline (its network
// backend refuses every request), so these tests are hermetic and fast; they
// skip when no fletch binary is available.

// fletchBin locates the fletch CLI: $FLETCH_BIN wins, then the sibling
// checkout's cargo build outputs. Skips the test when neither exists.
func fletchBin(t *testing.T) string {
	t.Helper()
	if b := os.Getenv("FLETCH_BIN"); b != "" {
		return b
	}
	for _, rel := range []string{
		"../../fletch/target/debug/fletch",
		"../../fletch/target/release/fletch",
	} {
		abs, err := filepath.Abs(rel)
		if err != nil {
			continue
		}
		if _, err := os.Stat(abs); err == nil {
			return abs
		}
	}
	t.Skip("fletch binary not found; set FLETCH_BIN or `cargo build` in ../fletch")
	return ""
}

// fletchProbe mirrors the JSON `fletch purl` prints: the parsed coordinates,
// the registry endpoint the type routes to, and the resolved artifact URL.
type fletchProbe struct {
	Type        string `json:"type"`
	Path        string `json:"path"`
	Version     string `json:"version"`
	Normalized  string `json:"normalized"`
	Identity    string `json:"identity"`
	RegistryURL string `json:"registry_url"`
	DownloadURL string `json:"download_url"`
}

func probeFletch(t *testing.T, bin, purl string) fletchProbe {
	t.Helper()
	out, err := exec.Command(bin, "purl", purl).Output()
	if err != nil {
		t.Fatalf("fletch purl %q: %v", purl, err)
	}
	var p fletchProbe
	if err := json.Unmarshal(out, &p); err != nil {
		t.Fatalf("fletch purl %q: bad JSON %q: %v", purl, out, err)
	}
	return p
}

func TestFletchReadsGeneratedPURLs(t *testing.T) {
	bin := fletchBin(t)
	cases := []struct {
		name                            string
		eco, domain, pkg, version, arch string
		wantType, wantPath, wantVersion string
		// substring the registry route must contain ("" = just non-empty)
		wantRegistryHas string
		wantDownload    bool
	}{
		{
			"npm", "npm", "npmjs.org", "lodash", "4.17.21", "",
			"npm", "lodash", "4.17.21", "registry.npmjs.org", true,
		},
		{
			"cargo", "rust", "", "serde", "1.0.0", "",
			"cargo", "serde", "1.0.0", "crates.io", true,
		},
		{
			"pypi", "python", "pypi.org", "requests", "2.31.0", "",
			"pypi", "requests", "2.31.0", "pypi.org", false,
		},
		{
			"aur", "aur", "archlinux.org", "yay", "12.3.0-1", "x86_64",
			"alpm", "aur/yay", "12.3.0-1", "aur.archlinux.org", true,
		},
		{
			"arch official", "arch", "archlinux.org", "pacman", "6.0.1-1", "x86_64",
			"alpm", "arch/pacman", "6.0.1-1", "archlinux.org", false,
		},
		{
			"fedora rpm", "fedora", "fedoraproject.org", "curl", "8.0.0-1.fc40", "x86_64",
			"rpm", "fedora/curl", "8.0.0-1.fc40", "fedoraproject.org", false,
		},
		{
			"debian deb", "debian", "debian.org", "wget", "1.21.4-1", "amd64",
			"deb", "debian/wget", "1.21.4-1", "debian", false,
		},
		{
			"alpine apk", "alpine", "alpinelinux.org", "musl", "1.2.4-r0", "",
			"apk", "alpine/musl", "1.2.4-r0", "alpine", false,
		},
		{
			"chrome", "chrome", "google.com", "khkimiladblfhhmefghkpkoikghmdddf", "", "",
			"chrome-extension", "khkimiladblfhhmefghkpkoikghmdddf", "", "", true,
		},
		{
			"vscode pinned", "vscode", "vsassets.io", "saoudrizwan.claude-dev", "1.0.0", "",
			"vscode-extension", "saoudrizwan/claude-dev", "1.0.0", "", true,
		},
		{
			"openvsx", "vscode", "open-vsx.org", "jinryx/crontally", "1.0.3", "",
			"vscode-extension", "jinryx/crontally", "1.0.3", "open-vsx.org", false,
		},
		{
			"github repo", "github_repo", "github.com", "EvilOrg/BadRepo", "", "",
			"github", "evilorg/badrepo", "", "api.github.com", true,
		},
		{
			// A tag rides the tag qualifier, so fletch reads no version; the
			// repository_url qualifier routes the metadata lookup.
			"oci tagged image", "docker", "docker.com", "nginx", "1.25", "",
			"oci", "nginx", "", "hub.docker.com", true,
		},
		{
			// A sha256 digest IS the version — the content-addressed identity
			// both exporters (crane and fletch's oci module) agree on. Quay
			// (unlike ghcr) has an anonymous metadata API, so a registry
			// route must also resolve.
			"oci digest image", "oci", "docker.com", "quay.io/owner/img", "sha256:244fd47e07d10", "",
			"oci", "img", "sha256:244fd47e07d10", "quay.io", true,
		},
		{
			"clawhub skill", "clawhub", "clawhub.ai", "Owner/Cool-Skill", "1.0.2", "",
			"clawhub", "owner/cool-skill", "1.0.2", "clawhub.ai", true,
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			purl, ok := SourcePURL(tc.eco, tc.domain, tc.pkg, tc.version, tc.arch)
			if !ok {
				t.Fatalf("SourcePURL(%q,%q,%q,%q,%q) resolved no purl", tc.eco, tc.domain, tc.pkg, tc.version, tc.arch)
			}
			p := probeFletch(t, bin, purl)
			if p.Type != tc.wantType {
				t.Errorf("%s: fletch type = %q, want %q", purl, p.Type, tc.wantType)
			}
			if p.Path != tc.wantPath {
				t.Errorf("%s: fletch path = %q, want %q", purl, p.Path, tc.wantPath)
			}
			if p.Version != tc.wantVersion {
				t.Errorf("%s: fletch version = %q, want %q", purl, p.Version, tc.wantVersion)
			}
			if p.Normalized != purl {
				t.Errorf("%s: fletch normalize = %q; generated form must already be canonical", purl, p.Normalized)
			}
			if p.RegistryURL == "" || !strings.Contains(p.RegistryURL, tc.wantRegistryHas) {
				t.Errorf("%s: fletch registry route = %q, want it to contain %q", purl, p.RegistryURL, tc.wantRegistryHas)
			}
			if tc.wantDownload && p.DownloadURL == "" {
				t.Errorf("%s: fletch resolved no download URL", purl)
			}
		})
	}
}

func TestFletchRoutesLegacyAndCanonicalIdentically(t *testing.T) {
	bin := fletchBin(t)
	// Every legacy spelling and its canonical fold must land on the same
	// registry endpoint and the same artifact URL in fletch — otherwise the
	// canonicalizer changes what a purl *means*, not just how it is spelled.
	legacy := []string{
		"pkg:aur/yay@12.0.0-1",
		"pkg:alpm/arch/yay@12.0.0-1?repository_url=https://aur.archlinux.org",
		"pkg:chrome/khkimiladblfhhmefghkpkoikghmdddf",
		"pkg:openvsx/jinryx/crontally@1.0.3",
		"pkg:vscode/saoudrizwan/claude-dev@1.0.0",
		"pkg:debian/curl@7.50.3-1",
		"pkg:fedora/curl@8.0.0-1.fc40",
		"pkg:arch/pacman@6.0.1-1",
		"pkg:alpine/musl@1.2.4-r0",
	}
	for _, in := range legacy {
		t.Run(in, func(t *testing.T) {
			canon := CanonicalizePURL(in)
			if canon == in {
				t.Fatalf("CanonicalizePURL(%q) did not remap; case expects a legacy spelling", in)
			}
			got, want := probeFletch(t, bin, in), probeFletch(t, bin, canon)
			if got.RegistryURL == "" || got.RegistryURL != want.RegistryURL {
				t.Errorf("registry route diverges: %q → %q but %q → %q", in, got.RegistryURL, canon, want.RegistryURL)
			}
			if got.DownloadURL != want.DownloadURL {
				t.Errorf("download URL diverges: %q → %q but %q → %q", in, got.DownloadURL, canon, want.DownloadURL)
			}
		})
	}
}

// TestDifferentialCanonicalization sweeps a combinatorial corpus — every
// scheme/type/path/version/qualifier shape crossed, including adversarial and
// degenerate ones — through both canonicalizers and holds them to two
// invariants:
//
//  1. When fletch's normalize produces a canonical form, CanonicalizePURL
//     produces the byte-identical string (and is a fixed point on it).
//  2. When fletch rejects the input (no canonical form exists),
//     CanonicalizePURL passes the (trimmed) input through untouched — it never
//     half-rewrites something the Rust side considers invalid.
//
// Together these are the testable statement of "the Go and Rust
// implementations behave identically wherever a canonical form exists".
func TestDifferentialCanonicalization(t *testing.T) {
	bin := fletchBin(t)

	schemes := []string{"pkg:", "PKG:", " pkg:"}
	types := []string{
		"npm", "PyPI", "composer", "cargo", "golang", "generic", "",
		"rpm", "RPM", "deb", "apk", "alpm", "ALPM",
		"aur", "arch", "debian", "fedora", "alpine",
		"chrome", "vscode", "openvsx", "chrome-extension", "vscode-extension",
	}
	paths := []string{
		"lodash", "Left-Pad", "%40scope/pkg", "@scope/pkg",
		"fedora/curl", "Fedora/Curl", "aur/yay", "AUR/Yay", "",
		"Ruamel.Yaml", "Symfony/Console", "Ünicode-Ñame",
	}
	versions := []string{"", "@1.0.0", "@1:0.47.4-4", "@1.2.3-1", "@"}
	qualifiers := []string{
		"",
		"?arch=x86_64",
		"?repository_url=https://aur.archlinux.org",
		"?arch=x86_64&repository_url=https://aur.archlinux.org",
		"?distro=fedora-25",
		"?repository_url=https://aur.archlinux.org@1.2-1",
		"?repository_url=https://user@example.com/repo",
	}

	var corpus []string
	for _, s := range schemes {
		for _, ty := range types {
			for _, p := range paths {
				for _, v := range versions {
					for _, q := range qualifiers {
						corpus = append(corpus, s+ty+"/"+p+v+q)
					}
				}
			}
		}
	}
	t.Logf("differential corpus: %d purls", len(corpus))

	cmd := exec.Command(bin, "purl", "-")
	cmd.Stdin = strings.NewReader(strings.Join(corpus, "\n") + "\n")
	out, err := cmd.Output()
	if err != nil {
		t.Fatalf("fletch purl -: %v", err)
	}
	lines := strings.Split(strings.TrimRight(string(out), "\n"), "\n")
	if len(lines) != len(corpus) {
		t.Fatalf("fletch emitted %d probes for %d inputs", len(lines), len(corpus))
	}

	var mismatches, rejected, normalized int
	for i, in := range corpus {
		var p fletchProbe
		if err := json.Unmarshal([]byte(lines[i]), &p); err != nil {
			t.Fatalf("probe %d (%q): bad JSON %q: %v", i, in, lines[i], err)
		}
		goCanon := CanonicalizePURL(in)
		if p.Normalized == "" {
			rejected++
			if goCanon != strings.TrimSpace(in) {
				mismatches++
				if mismatches <= 10 {
					t.Errorf("fletch rejects %q but CanonicalizePURL rewrites it to %q", in, goCanon)
				}
			}
			continue
		}
		normalized++
		if goCanon != p.Normalized {
			mismatches++
			if mismatches <= 10 {
				t.Errorf("divergence on %q: Go %q, fletch %q", in, goCanon, p.Normalized)
			}
			continue
		}
		if again := CanonicalizePURL(goCanon); again != goCanon {
			mismatches++
			if mismatches <= 10 {
				t.Errorf("CanonicalizePURL not a fixed point on %q: %q → %q", in, goCanon, again)
			}
		}
	}
	if mismatches > 10 {
		t.Errorf("… and %d further mismatches suppressed", mismatches-10)
	}
	t.Logf("normalized: %d, rejected-and-passed-through: %d", normalized, rejected)
}

func TestCanonicalFormMatchesFletchNormalize(t *testing.T) {
	bin := fletchBin(t)
	// The Go canonicalizer and fletch's normalize are the same function in two
	// languages: for every spelling, byte-identical output. This is the
	// mechanical lockstep test — a fold added to one side without the other
	// fails here.
	corpus := []string{
		"pkg:npm/lodash@4.17.21",
		"pkg:npm/%40babel/core@7.24.0",
		// Both spellings of an npm scope. The literal one is why this test
		// exists: each side read the leading '@' as a version separator, and
		// with no scoped case in this corpus the twins drifted unnoticed —
		// fletch rejecting the purl outright while Go passed it through.
		// (The degenerate "pkg:npm/@1.0.0" is deliberately absent: there the
		// two sides differ by contract, Go passing through where fletch
		// rejects, so it belongs in each side's own tests, not the lockstep.)
		"pkg:npm/@babel/core@7.24.0",
		"pkg:npm/@scope/name",
		"pkg:npm/@scope/name@1.0.0?arch=x64",
		"pkg:chrome/KhKimila@25.7.1",
		"pkg:vscode/Saoudrizwan/Claude-Dev",
		"pkg:openvsx/jinryx/crontally@1.0.3",
		"pkg:aur/yay@12.0.0-1",
		"pkg:aur/yay?repository_url=https://aur.archlinux.org",
		"pkg:alpm/aur/Foo-Bar@1.0-1",
		"pkg:alpm/arch/yay@12.3.0-1?arch=x86_64&repository_url=https://aur.archlinux.org",
		"pkg:alpm/arch/claude-desktop-hardened-bin?repository_url=https://aur.archlinux.org@1.20186.0-1",
		"pkg:debian/curl",
		"pkg:fedora/curl@8.0.0-1.fc40",
		"pkg:rpm/fedora/curl@7.50.3-1.fc25?arch=i386&distro=fedora-25",
		"pkg:rpm/centerim@4.22.10-1.el6?arch=i686&epoch=1&distro=fedora-25",
		"pkg:rpm/Fedora/curl@1.0",
		"pkg:deb/curl@7.50.3-1?arch=i386&distro=jessie",
		"pkg:deb/curl@7.50.3-1?arch=amd64&distro=ubuntu-22.04",
		"pkg:alpine/musl",
		"pkg:arch/pacman@6.0.1-1?arch=x86_64",
		"PKG:NPM/Left-Pad@1.3.0",
		"pkg:ALPM/aur/Yay@1.0-1",
		"pkg:alpm/arch/containers-common@1:0.47.4-4?arch=x86_64",
	}
	for _, in := range corpus {
		t.Run(in, func(t *testing.T) {
			goCanon := CanonicalizePURL(in)
			p := probeFletch(t, bin, in)
			if p.Normalized == "" {
				t.Fatalf("fletch normalize(%q) rejected a purl the Go side canonicalizes to %q", in, goCanon)
			}
			if goCanon != p.Normalized {
				t.Errorf("lockstep drift: CanonicalizePURL(%q) = %q, fletch normalize = %q", in, goCanon, p.Normalized)
			}
		})
	}
}
