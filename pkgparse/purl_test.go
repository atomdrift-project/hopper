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
		{"openvsx by domain", "vscode", "open-vsx.org", "jinryx/crontally", "pkg:vscode-extension/jinryx/crontally?repository_url=https:%2F%2Fopen-vsx.org", true},

		// Invented types where the spec defines none.
		{"firefox", "firefox", "mozilla.org", "velobench-shop-essentials", "pkg:firefox/velobench-shop-essentials", true},
		{"wordpress", "wordpress", "wordpress.org", "generate-security-txt", "pkg:wordpress/generate-security-txt", true},

		// Distros → spec deb/rpm/apk/alpm with distro namespace, from the ecosystem.
		{"debian eco", "debian", "debian.org", "libatopology2t64", "pkg:deb/debian/libatopology2t64", true},
		{"fedora eco", "fedora", "fedoraproject.org", "atari800", "pkg:rpm/fedora/atari800", true},
		{"arch eco", "arch", "archlinux.org", "franki-os-git", "pkg:alpm/arch/franki-os-git", true},
		// AUR → its own alpm namespace, distinguishing it from the official repos.
		{"aur eco", "aur", "archlinux.org", "bamboo-end-store-bin", "pkg:alpm/aur/bamboo-end-store-bin", true},
		{"wolfi eco", "wolfi", "wolfi.dev", "py3.11-jupyterlab-bin", "pkg:apk/wolfi/py3.11-jupyterlab-bin", true},

		// Mislabelled ecosystem ("linux"/"macos") recovered from the domain.
		{"mislabel linux->arch", "linux", "archlinux.org", "podman", "pkg:alpm/arch/podman", true},
		{"mislabel macos->debian", "macos", "debian.org", "nvi", "pkg:deb/debian/nvi", true},

		// GitHub-hosted code: every label converges on pkg:github/owner/repo,
		// lowercased. Identity requires exactly owner/repo — anything else
		// emits nothing rather than a coordinate for the wrong repo.
		{"github repo eco", "github_repo", "github.com", "EvilOrg/BadRepo", "pkg:github/evilorg/badrepo", true},
		{"github actions eco", "github_actions", "github.com", "actions/checkout", "pkg:github/actions/checkout", true},
		{"github release eco", "github_release", "github.com", "owner/tool", "pkg:github/owner/tool", true},
		{"github by domain", "agent", "github.com", "owner/skill-repo", "pkg:github/owner/skill-repo", true},
		{"github bare name", "github_repo", "github.com", "norepo", "", false},
		{"github extra segments", "github_repo", "github.com", "a/b/c", "", false},

		// Container images → the ratified pkg:oci type: bare image name,
		// registry path on the repository_url qualifier (slashes
		// percent-encoded per the standard), Docker Hub implied for host-less
		// refs.
		{"oci ghcr ref", "oci", "docker.com", "ghcr.io/EvilOrg/BadImg", "pkg:oci/badimg?repository_url=ghcr.io%2Fevilorg%2Fbadimg", true},
		{"docker bare image", "docker", "docker.com", "nginx", "pkg:oci/nginx?repository_url=docker.io%2Flibrary%2Fnginx", true},
		{"docker namespaced image", "docker", "docker.com", "library/nginx", "pkg:oci/nginx?repository_url=docker.io%2Flibrary%2Fnginx", true},

		// Agent skills: ClawHub is its own registry; a skills.sh skill is its
		// backing GitHub repo (owner/repo[/skill] → the repo identity).
		{"clawhub owned slug", "clawhub", "clawhub.ai", "Owner/Cool-Skill", "pkg:clawhub/owner/cool-skill", true},
		{"clawhub bare slug", "clawhub", "clawhub.ai", "coolskill", "pkg:clawhub/coolskill", true},
		{"skills.sh three segments", "skills_sh", "skills.sh", "Owner/Repo/skill-name", "pkg:github/owner/repo", true},
		{"skills.sh two segments", "skills_sh", "skills.sh", "owner/repo", "pkg:github/owner/repo", true},
		{"skills.sh bare name", "skills_sh", "skills.sh", "norepo", "", false},

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
		name                            string
		eco, domain, pkg, version, arch string
		want                            string
		wantOK                          bool
	}{
		// Versioned across families: language, distro, and an extension. Empty
		// version yields the bare identity.
		{"npm versioned", "npm", "npmjs.org", "lodash", "4.17.21", "", "pkg:npm/lodash@4.17.21", true},
		{"aur versioned", "aur", "archlinux.org", "bamboo-end-store-bin", "1.2.2-1", "", "pkg:alpm/aur/bamboo-end-store-bin@1.2.2-1", true},
		{"openvsx versioned", "vscode", "open-vsx.org", "jinryx/crontally", "1.0.3", "", "pkg:vscode-extension/jinryx/crontally@1.0.3?repository_url=https:%2F%2Fopen-vsx.org", true},
		{"aur no version", "aur", "archlinux.org", "yay", "", "", "pkg:alpm/aur/yay", true},
		// Case-insensitive types (deb/apk/alpm) lowercase the name per spec; rpm is
		// case-sensitive and keeps it.
		{"alpm lowercases name", "aur", "archlinux.org", "Foo-Bar", "1.0-1", "", "pkg:alpm/aur/foo-bar@1.0-1", true},
		{"deb lowercases name", "debian", "debian.org", "LibFoo", "1.0", "", "pkg:deb/debian/libfoo@1.0", true},
		{"rpm preserves case", "fedora", "fedoraproject.org", "LibFoo", "1.0", "", "pkg:rpm/fedora/LibFoo@1.0", true},

		// The artifact architecture rides in as the spec's `arch` qualifier on
		// the distro types that define it; other types ignore it.
		{"rpm with arch", "fedora", "fedoraproject.org", "curl", "7.50.3-1.fc25", "i386", "pkg:rpm/fedora/curl@7.50.3-1.fc25?arch=i386", true},
		{"deb with arch", "debian", "debian.org", "curl", "7.50.3-1", "amd64", "pkg:deb/debian/curl@7.50.3-1?arch=amd64", true},
		{"alpm with arch", "arch", "archlinux.org", "pacman", "6.0.1-1", "x86_64", "pkg:alpm/arch/pacman@6.0.1-1?arch=x86_64", true},
		{"aur with arch", "aur", "archlinux.org", "yay", "12.3.0-1", "x86_64", "pkg:alpm/aur/yay@12.3.0-1?arch=x86_64", true},
		{"npm ignores arch", "npm", "npmjs.org", "lodash", "4.17.21", "x64", "pkg:npm/lodash@4.17.21", true},
		// An epoch-carrying version keeps its ':' literal, per the spec's
		// canonical test vectors ("containers-common@1:0.47.4-4").
		{"alpm epoch version", "aur", "archlinux.org", "containers-common", "1:0.47.4-4", "x86_64", "pkg:alpm/aur/containers-common@1:0.47.4-4?arch=x86_64", true},

		// Language normalization: scoped npm percent-encodes the @; pypi lowercases
		// and dashes underscores; composer lowercases vendor/name.
		{"npm scoped", "npm", "", "@babel/core", "7.24.0", "", "pkg:npm/%40babel/core@7.24.0", true},
		{"pypi normalizes", "pypi", "", "ruamel_yaml", "0.18.6", "", "pkg:pypi/ruamel-yaml@0.18.6", true},
		// Full PEP 503: dots are separators too, and runs collapse — matching
		// filefacts' manifest parser, so a requirements.txt spelling and a
		// download-derived spelling of one project share a key.
		{"pypi dotted", "pypi", "", "ruamel.yaml", "0.18.6", "", "pkg:pypi/ruamel-yaml@0.18.6", true},
		{"pypi separator runs", "pypi", "", "backports__zoneinfo", "1.0", "", "pkg:pypi/backports-zoneinfo@1.0", true},
		{"composer lowercased", "packagist", "", "Symfony/Console", "6.4.0", "", "pkg:composer/symfony/console@6.4.0", true},
		// huggingface keeps owner/model and is case-sensitive.
		{"huggingface", "huggingface", "", "microsoft/resnet-50", "main", "", "pkg:huggingface/microsoft/resnet-50@main", true},

		// Runtime/language aliases resolve to their dominant registry.
		{"lang ruby", "ruby", "", "rails", "7.1.3", "", "pkg:gem/rails@7.1.3", true},
		{"lang rust", "rust", "", "serde", "1.0.0", "", "pkg:cargo/serde@1.0.0", true},
		{"lang java", "java", "", "org.apache:commons", "1.0", "", "pkg:maven/org.apache/commons@1.0", true},
		{"lang php", "php", "", "symfony/console", "6.4.0", "", "pkg:composer/symfony/console@6.4.0", true},

		// pkg:oci per spec: version carries only the sha256:… digest (':'
		// literal); a mutable tag rides the tag qualifier, sorted after
		// repository_url; the repository path percent-encodes its slashes.
		{
			"oci digest version", "oci", "docker.com", "ghcr.io/owner/img", "sha256:244fd47e07d10", "",
			"pkg:oci/img@sha256:244fd47e07d10?repository_url=ghcr.io%2Fowner%2Fimg", true,
		},
		{
			"oci tag version", "docker", "docker.com", "nginx", "1.25-alpine", "",
			"pkg:oci/nginx?repository_url=docker.io%2Flibrary%2Fnginx&tag=1.25-alpine", true,
		},
		// GitHub versions are commits or tags, passed through opaquely.
		{
			"github versioned", "github_repo", "github.com", "EvilOrg/BadRepo", "244fd47", "",
			"pkg:github/evilorg/badrepo@244fd47", true,
		},

		// Malformed coordinate for the type → no PURL.
		{"maven missing group", "maven", "", "commons-lang3", "3.14.0", "", "", false},
		{"composer missing vendor", "packagist", "", "console", "6.4.0", "", "", false},

		{"junk", "datasets", "", "x", "1.0", "", "", false},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got, ok := SourcePURL(tc.eco, tc.domain, tc.pkg, tc.version, tc.arch)
			if ok != tc.wantOK {
				t.Fatalf("SourcePURL(%q,%q,%q,%q) ok = %v, want %v", tc.eco, tc.domain, tc.pkg, tc.version, ok, tc.wantOK)
			}
			if got != tc.want {
				t.Errorf("SourcePURL(%q,%q,%q,%q) = %q, want %q", tc.eco, tc.domain, tc.pkg, tc.version, got, tc.want)
			}
			// Generation emits canonical form: canonicalizing it is a no-op.
			if got != "" {
				if c := CanonicalizePURL(got); c != got {
					t.Errorf("SourcePURL output %q is not canonical (CanonicalizePURL → %q)", got, c)
				}
			}
		})
	}
}

func TestCanonicalizePURL(t *testing.T) {
	cases := []struct{ in, want string }{
		// Legacy fletch spellings fold onto the spec form.
		{"pkg:chrome/khkimiladblfhhmefghkpkoikghmdddf", "pkg:chrome-extension/khkimiladblfhhmefghkpkoikghmdddf"},
		{"pkg:chrome/khkimiladblfhhmefghkpkoikghmdddf@1.2.3", "pkg:chrome-extension/khkimiladblfhhmefghkpkoikghmdddf@1.2.3"},
		{"pkg:vscode/saoudrizwan/claude-dev", "pkg:vscode-extension/saoudrizwan/claude-dev"},
		{"pkg:openvsx/jinryx/crontally", "pkg:vscode-extension/jinryx/crontally?repository_url=https:%2F%2Fopen-vsx.org"},
		{"pkg:openvsx/jinryx/crontally@1.0.3", "pkg:vscode-extension/jinryx/crontally@1.0.3?repository_url=https:%2F%2Fopen-vsx.org"},
		{"pkg:debian/curl", "pkg:deb/debian/curl"},
		{"pkg:arch/pacman@6.0", "pkg:alpm/arch/pacman@6.0"},
		{"pkg:fedora/curl", "pkg:rpm/fedora/curl"},

		// The purl-spec rpm examples: an already-canonical purl passes through;
		// a namespace-less one recovers its vendor from the distro qualifier
		// (the spec's rpm note: the repository is implied by `distro`). The
		// vendor namespace is case-insensitive and lowercased; a distro value
		// that names no vendor we model (a bare deb codename) never recovers.
		{"pkg:rpm/fedora/curl@7.50.3-1.fc25?arch=i386&distro=fedora-25", "pkg:rpm/fedora/curl@7.50.3-1.fc25?arch=i386&distro=fedora-25"},
		{"pkg:rpm/centerim@4.22.10-1.el6?arch=i686&epoch=1&distro=fedora-25", "pkg:rpm/fedora/centerim@4.22.10-1.el6?arch=i686&distro=fedora-25&epoch=1"},
		{"pkg:rpm/Fedora/curl@1.0", "pkg:rpm/fedora/curl@1.0"},
		{"pkg:deb/curl@7.50.3-1?arch=i386&distro=jessie", "pkg:deb/curl@7.50.3-1?arch=i386&distro=jessie"},
		{"pkg:deb/curl@7.50.3-1?arch=amd64&distro=ubuntu-22.04", "pkg:deb/ubuntu/curl@7.50.3-1?arch=amd64&distro=ubuntu-22.04"},
		{"pkg:alpine/musl", "pkg:apk/alpine/musl"},

		// All AUR spellings fold onto the aur-namespace form: the bare legacy
		// type, and the vendor-plus-qualifier form we generated before (its
		// repository_url qualifier is dropped; others are kept).
		{"pkg:aur/yay", "pkg:alpm/aur/yay"},
		{"pkg:aur/yay@12.0.0-1", "pkg:alpm/aur/yay@12.0.0-1"},
		{"pkg:aur/yay?repository_url=https://aur.archlinux.org", "pkg:alpm/aur/yay"},
		{"pkg:alpm/aur/bamboo-end-store-bin@1.2.2-1", "pkg:alpm/aur/bamboo-end-store-bin@1.2.2-1"},
		{"pkg:alpm/aur/Foo-Bar", "pkg:alpm/aur/foo-bar"},
		{"pkg:alpm/arch/yay@12.0.0-1?repository_url=https://aur.archlinux.org", "pkg:alpm/aur/yay@12.0.0-1"},
		{"pkg:alpm/arch/yay@12.3.0-1?arch=x86_64&repository_url=https://aur.archlinux.org", "pkg:alpm/aur/yay@12.3.0-1?arch=x86_64"},

		// The non-spec "?qualifiers@version" ordering older exports composed
		// (purl_base || '@' || version onto a qualifier-bearing base) is
		// repaired to the spec "@version?qualifiers" order — and an AUR
		// repository_url folds onto the aur namespace in the same pass.
		{
			"pkg:alpm/arch/claude-desktop-hardened-bin?repository_url=https://aur.archlinux.org@1.20186.0-1",
			"pkg:alpm/aur/claude-desktop-hardened-bin@1.20186.0-1",
		},
		{
			"pkg:vscode-extension/pub/name?repository_url=https://open-vsx.org@1.0.3",
			"pkg:vscode-extension/pub/name@1.0.3?repository_url=https:%2F%2Fopen-vsx.org",
		},
		// A qualifier value containing '@' (URL userinfo) is not a version, and
		// a repository_url naming something other than the AUR is kept.
		{
			"pkg:alpm/arch/yay?repository_url=https://user@example.com/repo",
			"pkg:alpm/arch/yay?repository_url=https:%2F%2Fuser%40example.com%2Frepo",
		},

		// The scheme and type are case-insensitive per spec, and pasted input
		// arrives padded: both fold, for remapped and unremapped types alike.
		{"PKG:NPM/Left-Pad@1.3.0", "pkg:npm/Left-Pad@1.3.0"},

		// PyPI folds per PEP 503; composer lowercases; npm never folds
		// (legacy mixed-case names are grandfathered and distinct).
		{"pkg:pypi/Ruamel.Yaml@0.18.6", "pkg:pypi/ruamel-yaml@0.18.6"},
		{"pkg:composer/Symfony/Console@6.4.0", "pkg:composer/symfony/console@6.4.0"},
		{"pkg:CHROME/KHKIMILADBLFHHMEFGHKPKOIKGHMDDDF", "pkg:chrome-extension/khkimiladblfhhmefghkpkoikghmdddf"},
		{"  pkg:npm/lodash@1.0.0  ", "pkg:npm/lodash@1.0.0"},
		{"pkg:RPM/Fedora/curl@1.0", "pkg:rpm/fedora/curl@1.0"},

		// An npm scope's leading '@' is part of the name, not the version
		// separator. Read as a separator it left an empty coordinate, and the
		// degenerate guard then passed the input through — so a scoped package
		// kept whichever spelling it arrived in while renderPURL emitted the
		// escaped form, giving one package two purl_base keys. Both spellings
		// now fold onto the escaped one, which is the spec's canonical form
		// and what this package already generates.
		{"pkg:npm/@babel/core@7.24.0", "pkg:npm/%40babel/core@7.24.0"},
		{"pkg:npm/%40babel/core@7.24.0", "pkg:npm/%40babel/core@7.24.0"},
		{"pkg:npm/@scope/name", "pkg:npm/%40scope/name"},
		{"pkg:npm/@scope/name@1.0.0?arch=x64", "pkg:npm/%40scope/name@1.0.0?arch=x64"},
		// The sigil is a scope only when a '/' closes it. These name nothing,
		// so they stay degenerate and pass through untouched.
		{"pkg:npm/@1.0.0", "pkg:npm/@1.0.0"},
		{"pkg:npm/@1.0.0?repository_url=https://x/y", "pkg:npm/@1.0.0?repository_url=https://x/y"},
		{"pkg:npm/@", "pkg:npm/@"},

		// Already-canonical or unremapped types pass through untouched.
		{"pkg:npm/lodash@1.0.0", "pkg:npm/lodash@1.0.0"},
		{"pkg:alpm/arch/pacman@6.0.1-1?arch=x86_64", "pkg:alpm/arch/pacman@6.0.1-1?arch=x86_64"},
		{"pkg:chrome-extension/khkimiladblfhhmefghkpkoikghmdddf", "pkg:chrome-extension/khkimiladblfhhmefghkpkoikghmdddf"},
		{"pkg:vscode-extension/pub/name?repository_url=https://open-vsx.org", "pkg:vscode-extension/pub/name?repository_url=https:%2F%2Fopen-vsx.org"},
		{"not-a-purl", "not-a-purl"},
	}
	for _, tc := range cases {
		if got := CanonicalizePURL(tc.in); got != tc.want {
			t.Errorf("CanonicalizePURL(%q) = %q, want %q", tc.in, got, tc.want)
		}
		// Idempotent: a canonical form is a fixed point, so a purl that passes
		// through more than once can never drift onto a second spelling.
		if again := CanonicalizePURL(tc.want); again != tc.want {
			t.Errorf("CanonicalizePURL(%q) = %q, not a fixed point", tc.want, again)
		}
	}
}

// The `canonicalize-purls` repair rewrites a stored samples.purl_base whenever
// VersionlessPURL(CanonicalizePURL(pb)) differs from it — see
// canonicalizePURLBasesPG, which computes exactly this per row. The repair
// itself is Postgres-only, so pin the decision it makes here: a legacy scoped
// spelling must move onto the canonical one, and the canonical one must be a
// fixed point or a resumable repair would rewrite the same rows forever.
func TestCanonicalizePURLBaseRewriteRule(t *testing.T) {
	rewrite := func(pb string) string { return VersionlessPURL(CanonicalizePURL(pb)) }

	// Rows stored before CanonicalizePURL folded the scope sigil: the literal
	// spelling passed through untouched, so these are the rows the repair has
	// to find and move.
	for _, tc := range []struct{ stored, want string }{
		{"pkg:npm/@zynkit/jwtbytes", "pkg:npm/%40zynkit/jwtbytes"},
		{"pkg:npm/@babel/core", "pkg:npm/%40babel/core"},
	} {
		got := rewrite(tc.stored)
		if got != tc.want {
			t.Errorf("rewrite(%q) = %q, want %q", tc.stored, got, tc.want)
		}
		if again := rewrite(got); again != got {
			t.Errorf("rewrite is not a fixed point: %q -> %q", got, again)
		}
	}

	// Rows already canonical must not be rewritten, or every run would churn
	// the whole table and re-key the sightings ledger for nothing.
	for _, pb := range []string{
		"pkg:npm/%40babel/core",
		"pkg:npm/left-pad",
		"pkg:alpm/aur/yay",
		"pkg:pypi/ruamel-yaml",
	} {
		if got := rewrite(pb); got != pb {
			t.Errorf("rewrite(%q) = %q, want unchanged", pb, got)
		}
	}
}
