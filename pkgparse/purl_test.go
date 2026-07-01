package pkgparse

import "testing"

func TestBuildPURL(t *testing.T) {
	cases := []struct {
		name          string
		eco, pkg, ver string
		want          string
		wantOK        bool
	}{
		// Registry-form inputs (the live forager path).
		{"npm plain", "npm", "lodash", "4.17.21", "pkg:npm/lodash@4.17.21", true},
		{"npm scoped", "npm", "@babel/core", "7.24.0", "pkg:npm/%40babel/core@7.24.0", true},
		{"npm no version", "npm", "express", "", "pkg:npm/express", true},
		{"pypi lower", "pypi", "Django", "5.0.1", "pkg:pypi/django@5.0.1", true},
		{"pypi underscore", "pypi", "ruamel_yaml", "0.18.6", "pkg:pypi/ruamel-yaml@0.18.6", true},
		{"pypi alias pip", "pip", "requests", "2.31.0", "pkg:pypi/requests@2.31.0", true},
		{"golang alias go", "go", "rsc.io/quote", "v1.5.2", "pkg:golang/rsc.io/quote@v1.5.2", true},
		{"crates", "crates", "serde", "1.0.197", "pkg:cargo/serde@1.0.197", true},
		{"cargo alias", "cargo", "tokio", "1.36.0", "pkg:cargo/tokio@1.36.0", true},
		{"composer", "packagist", "Symfony/Console", "6.4.0", "pkg:composer/symfony/console@6.4.0", true},
		{"nuget", "nuget", "Newtonsoft.Json", "13.0.3", "pkg:nuget/Newtonsoft.Json@13.0.3", true},
		{"gem", "rubygems", "rails", "7.1.3", "pkg:gem/rails@7.1.3", true},
		{"huggingface", "huggingface", "microsoft/resnet-50", "main", "pkg:huggingface/microsoft/resnet-50@main", true},

		// Runtime/language-form inputs — the cases the old forager mapping dropped.
		{"language javascript", "javascript", "@scope/evil", "1.0.0", "pkg:npm/%40scope/evil@1.0.0", true},
		{"language python", "python", "Mailconfirmer", "3.3.27", "pkg:pypi/mailconfirmer@3.3.27", true},
		{"language ruby", "ruby", "rails", "7.1.3", "pkg:gem/rails@7.1.3", true},
		{"language rust", "rust", "serde", "1.0.0", "pkg:cargo/serde@1.0.0", true},
		{"language java", "java", "org.apache:commons", "1.0", "pkg:maven/org.apache/commons@1.0", true},
		{"language dotnet", "dotnet", "Newtonsoft.Json", "13.0.3", "pkg:nuget/Newtonsoft.Json@13.0.3", true},
		{"language php", "php", "symfony/console", "6.4.0", "pkg:composer/symfony/console@6.4.0", true},

		// Malformed coordinate for the type → no PURL.
		{"maven missing group", "maven", "commons-lang3", "3.14.0", "", false},
		{"composer missing vendor", "packagist", "console", "6.4.0", "", false},

		// Non-language ecosystems aren't handled by BuildPURL (use SourcePURLIdentity).
		{"chrome via BuildPURL", "chrome", "abcdefghij", "1.0", "", false},
		{"empty", "", "", "", "", false},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got, ok := BuildPURL(tc.eco, tc.pkg, tc.ver)
			if ok != tc.wantOK {
				t.Fatalf("BuildPURL(%q,%q,%q) ok = %v, want %v", tc.eco, tc.pkg, tc.ver, ok, tc.wantOK)
			}
			if got != tc.want {
				t.Errorf("BuildPURL(%q,%q,%q) = %q, want %q", tc.eco, tc.pkg, tc.ver, got, tc.want)
			}
		})
	}
}

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

		// Already-canonical or unremapped types pass through untouched.
		{"pkg:npm/lodash@1.0.0", "pkg:npm/lodash@1.0.0"},
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
