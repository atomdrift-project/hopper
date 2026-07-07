package pkgparse

import "testing"

func TestSourcePURLIdentity(t *testing.T) {
	cases := []struct {
		name             string
		eco, domain, pkg string
		want             string
		wantOK           bool
	}{
		// Language registries resolve from the ecosystem (domain agrees).
		{"npm eco", "javascript", "npmjs.org", "@scope/evil", "pkg:npm/%40scope/evil", true},
		{"pypi eco", "python", "pypi.org", "Mailconfirmer", "pkg:pypi/mailconfirmer", true},

		// Browser / editor extensions → spec types.
		{"chrome", "chrome", "google.com", "khkimiladblfhhmefghkpkoikghmdddf", "pkg:chrome-extension/khkimiladblfhhmefghkpkoikghmdddf", true},
		{"vscode marketplace", "vscode", "vsassets.io", "saoudrizwan.claude-dev", "pkg:vscode-extension/saoudrizwan/claude-dev", true},
		{"openvsx by domain", "vscode", "open-vsx.org", "jinryx/crontally", "pkg:vscode-extension/jinryx/crontally?repository_url=https://open-vsx.org", true},

		// Invented types where the spec defines none.
		{"firefox", "firefox", "mozilla.org", "velobench-shop-essentials", "pkg:firefox/velobench-shop-essentials", true},
		{"wordpress", "wordpress", "wordpress.org", "generate-security-txt", "pkg:wordpress/generate-security-txt", true},

		// Distros → spec deb/rpm/apk/alpm with distro namespace, from the ecosystem.
		{"debian eco", "debian", "debian.org", "libatopology2t64", "pkg:deb/debian/libatopology2t64", true},
		{"fedora eco", "fedora", "fedoraproject.org", "atari800", "pkg:rpm/fedora/atari800", true},
		{"arch eco", "arch", "archlinux.org", "franki-os-git", "pkg:alpm/arch/franki-os-git", true},
		// AUR → the spec form: arch vendor namespace, AUR named in a repository_url
		// qualifier (never "aur" in the namespace, which the spec reserves for the vendor).
		{"aur eco", "aur", "archlinux.org", "bamboo-end-store-bin", "pkg:alpm/arch/bamboo-end-store-bin?repository_url=https://aur.archlinux.org", true},
		{"wolfi eco", "wolfi", "wolfi.dev", "py3.11-jupyterlab-bin", "pkg:apk/wolfi/py3.11-jupyterlab-bin", true},

		// Mislabelled ecosystem ("linux"/"macos") recovered from the domain.
		{"mislabel linux->arch", "linux", "archlinux.org", "podman", "pkg:alpm/arch/podman", true},
		{"mislabel macos->debian", "macos", "debian.org", "nvi", "pkg:deb/debian/nvi", true},

		// Nothing resolvable → empty, never a wrong PURL.
		{"junk no domain", "datasets", "", "something", "", false},
		{"empty name", "python", "pypi.org", "", "", false},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got, ok := SourcePURLIdentity(tc.eco, tc.domain, tc.pkg)
			if ok != tc.wantOK {
				t.Fatalf("SourcePURLIdentity(%q,%q,%q) ok = %v, want %v", tc.eco, tc.domain, tc.pkg, ok, tc.wantOK)
			}
			if got != tc.want {
				t.Errorf("SourcePURLIdentity(%q,%q,%q) = %q, want %q", tc.eco, tc.domain, tc.pkg, got, tc.want)
			}
		})
	}
}

func TestSourcePURL(t *testing.T) {
	cases := []struct {
		name                      string
		eco, domain, pkg, version string
		want                      string
		wantOK                    bool
	}{
		// Versioned across families: language, distro (AUR with its qualifier after
		// the version), and an extension. Empty version yields the bare identity.
		{"npm versioned", "npm", "npmjs.org", "lodash", "4.17.21", "pkg:npm/lodash@4.17.21", true},
		{"aur versioned", "aur", "archlinux.org", "bamboo-end-store-bin", "1.2.2-1", "pkg:alpm/arch/bamboo-end-store-bin@1.2.2-1?repository_url=https://aur.archlinux.org", true},
		{"openvsx versioned", "vscode", "open-vsx.org", "jinryx/crontally", "1.0.3", "pkg:vscode-extension/jinryx/crontally@1.0.3?repository_url=https://open-vsx.org", true},
		{"aur no version", "aur", "archlinux.org", "yay", "", "pkg:alpm/arch/yay?repository_url=https://aur.archlinux.org", true},
		// Case-insensitive types (deb/apk/alpm) lowercase the name per spec; rpm is
		// case-sensitive and keeps it.
		{"alpm lowercases name", "aur", "archlinux.org", "Foo-Bar", "1.0-1", "pkg:alpm/arch/foo-bar@1.0-1?repository_url=https://aur.archlinux.org", true},
		{"deb lowercases name", "debian", "debian.org", "LibFoo", "1.0", "pkg:deb/debian/libfoo@1.0", true},
		{"rpm preserves case", "fedora", "fedoraproject.org", "LibFoo", "1.0", "pkg:rpm/fedora/LibFoo@1.0", true},

		// Language normalization: scoped npm percent-encodes the @; pypi lowercases
		// and dashes underscores; composer lowercases vendor/name.
		{"npm scoped", "npm", "", "@babel/core", "7.24.0", "pkg:npm/%40babel/core@7.24.0", true},
		{"pypi normalizes", "pypi", "", "ruamel_yaml", "0.18.6", "pkg:pypi/ruamel-yaml@0.18.6", true},
		{"composer lowercased", "packagist", "", "Symfony/Console", "6.4.0", "pkg:composer/symfony/console@6.4.0", true},
		// huggingface keeps owner/model and is case-sensitive.
		{"huggingface", "huggingface", "", "microsoft/resnet-50", "main", "pkg:huggingface/microsoft/resnet-50@main", true},

		// Runtime/language aliases resolve to their dominant registry.
		{"lang ruby", "ruby", "", "rails", "7.1.3", "pkg:gem/rails@7.1.3", true},
		{"lang rust", "rust", "", "serde", "1.0.0", "pkg:cargo/serde@1.0.0", true},
		{"lang java", "java", "", "org.apache:commons", "1.0", "pkg:maven/org.apache/commons@1.0", true},
		{"lang php", "php", "", "symfony/console", "6.4.0", "pkg:composer/symfony/console@6.4.0", true},

		// Malformed coordinate for the type → no PURL.
		{"maven missing group", "maven", "", "commons-lang3", "3.14.0", "", false},
		{"composer missing vendor", "packagist", "", "console", "6.4.0", "", false},

		{"junk", "datasets", "", "x", "1.0", "", false},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got, ok := SourcePURL(tc.eco, tc.domain, tc.pkg, tc.version)
			if ok != tc.wantOK {
				t.Fatalf("SourcePURL(%q,%q,%q,%q) ok = %v, want %v", tc.eco, tc.domain, tc.pkg, tc.version, ok, tc.wantOK)
			}
			if got != tc.want {
				t.Errorf("SourcePURL(%q,%q,%q,%q) = %q, want %q", tc.eco, tc.domain, tc.pkg, tc.version, got, tc.want)
			}
		})
	}
}

func TestCanonicalizePURL(t *testing.T) {
	cases := []struct{ in, want string }{
		// Legacy fletch spellings fold onto the spec form.
		{"pkg:chrome/khkimila", "pkg:chrome-extension/khkimila"},
		{"pkg:chrome/khkimila@1.2.3", "pkg:chrome-extension/khkimila@1.2.3"},
		{"pkg:vscode/saoudrizwan/claude-dev", "pkg:vscode-extension/saoudrizwan/claude-dev"},
		{"pkg:openvsx/jinryx/crontally", "pkg:vscode-extension/jinryx/crontally?repository_url=https://open-vsx.org"},
		{"pkg:openvsx/jinryx/crontally@1.0.3", "pkg:vscode-extension/jinryx/crontally@1.0.3?repository_url=https://open-vsx.org"},
		{"pkg:debian/curl", "pkg:deb/debian/curl"},
		{"pkg:arch/pacman@6.0", "pkg:alpm/arch/pacman@6.0"},
		{"pkg:fedora/curl", "pkg:rpm/fedora/curl"},
		{"pkg:alpine/musl", "pkg:apk/alpine/musl"},

		// Both AUR spellings fold onto the spec form (arch vendor + repository_url):
		// the bare legacy type, and the older aur-in-namespace variation. A version
		// keeps its place before the qualifier.
		{"pkg:aur/yay", "pkg:alpm/arch/yay?repository_url=https://aur.archlinux.org"},
		{"pkg:aur/yay@12.0.0-1", "pkg:alpm/arch/yay@12.0.0-1?repository_url=https://aur.archlinux.org"},
		{"pkg:alpm/aur/bamboo-end-store-bin@1.2.2-1", "pkg:alpm/arch/bamboo-end-store-bin@1.2.2-1?repository_url=https://aur.archlinux.org"},
		{"pkg:alpm/aur/Foo-Bar", "pkg:alpm/arch/foo-bar?repository_url=https://aur.archlinux.org"},

		// Already-canonical or unremapped types pass through untouched.
		{"pkg:npm/lodash@1.0.0", "pkg:npm/lodash@1.0.0"},
		{"pkg:alpm/arch/pacman@6.0.1-1?arch=x86_64", "pkg:alpm/arch/pacman@6.0.1-1?arch=x86_64"},
		{"pkg:chrome-extension/khkimila", "pkg:chrome-extension/khkimila"},
		{"pkg:vscode-extension/pub/name?repository_url=https://open-vsx.org", "pkg:vscode-extension/pub/name?repository_url=https://open-vsx.org"},
		{"not-a-purl", "not-a-purl"},
	}
	for _, tc := range cases {
		if got := CanonicalizePURL(tc.in); got != tc.want {
			t.Errorf("CanonicalizePURL(%q) = %q, want %q", tc.in, got, tc.want)
		}
	}
}
