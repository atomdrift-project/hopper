package pkgparse

import (
	"sort"
	"strings"
)

// This is the single source of truth for building canonical Package URLs (PURLs,
// see https://github.com/package-url/purl-spec) from the coordinates hopper
// stores. It is dependency-free so it can be shared: forager computes the PURL at
// ingestion, hopper's backfill rebuilds it for older rows, and both must produce
// exactly what fletch (src/registry.rs) parses when it fetches a PURL. We emit
// the purl-spec ratified spellings (chrome-extension, vscode-extension,
// deb/rpm/apk/alpm with the vendor as namespace); fletch accepts both these and
// its older legacy spellings, and the crosscheck_test suite drives every
// generated form through `fletch purl` to prove the two tools read the same
// coordinates — that shared reading is what the bloom's decide_purl matches.

// languageType maps an ecosystem — a registry name or the runtime/language form
// stored in samples.ecosystem (see runtimeMap) — to its PURL type for the
// language registries. Where a language spans registries the dominant one is
// chosen (javascript→npm not jsr, python→pypi not conda), which is the best
// identity a no-provenance row affords. ok is false for anything that is not one
// of these language registries; callers fall through to the richer source-aware
// resolver or leave the PURL empty.
func languageType(ecosystem string) (string, bool) {
	switch strings.ToLower(strings.TrimSpace(ecosystem)) {
	case "npm", "javascript", "js", "web", "node", "nodejs":
		return "npm", true
	case "pypi", "pip", "python":
		return "pypi", true
	case "rubygems", "gem", "gems", "ruby":
		return "gem", true
	case "crates", "cargo", "crates.io", "rust":
		return "cargo", true
	case "golang", "go", "gomod", "go-module":
		return "golang", true
	case "maven", "java":
		return "maven", true
	case "nuget", "dotnet", ".net", "csharp", "c#":
		return "nuget", true
	case "packagist", "composer", "php":
		return "composer", true
	case "huggingface", "hf":
		return "huggingface", true
	default:
		return "", false
	}
}

// SourcePURL builds the versioned canonical PURL from a sample's stored ecosystem,
// download domain, package coordinate, and version, across every registry family
// fletch can fetch. It is the one resolver forager (at ingestion), hopper (at
// backfill), and fletch (at fetch) share, so a package has a single identity
// everywhere. Resolution order:
//
//   - VS Code editor extensions resolve openvsx vs the Microsoft marketplace from
//     the domain (the ecosystem column folds both into "vscode").
//   - A known ecosystem value wins next: language registries, app stores
//     (chrome/firefox/wordpress/jetbrains/snap), and distros (debian/arch/…) all
//     name their own PURL type.
//   - The download domain is the fallback and the authority for rows the ecosystem
//     column mislabels (a Debian package tagged "linux"/"macos" still resolves via
//     debian.org).
//
// version may be empty (yielding the version-less identity), as may arch — the
// purl-spec `arch` qualifier value (from [ParseFilename]), emitted only for the
// distro types whose spec defines it (deb/rpm/apk/alpm). Returns ok=false when
// no confident type resolves, leaving the PURL empty rather than emitting one
// fletch could not fetch.
func SourcePURL(ecosystem, domain, name, version, arch string) (string, bool) {
	name = strings.TrimSpace(name)
	if name == "" {
		return "", false
	}
	eco := strings.ToLower(strings.TrimSpace(ecosystem))
	dom := strings.ToLower(strings.TrimSpace(domain))

	// VS Code / Open VSX share the ecosystem "vscode"; the registry is only
	// distinguishable by where it was downloaded from.
	if eco == "vscode" || eco == "openvsx" {
		if dom == "open-vsx.org" {
			return buildTyped("openvsx", name, version, arch)
		}
		return buildTyped("vscode", name, version, arch)
	}

	if typ, ok := ecosystemType(eco); ok {
		return buildTyped(typ, name, version, arch)
	}
	if typ, ok := domainType(dom); ok {
		return buildTyped(typ, name, version, arch)
	}
	return "", false
}

// SourcePURLIdentity returns the version-less purl_base — a package's identity
// across versions, promoted to the indexed samples.purl_base column. It is
// [SourcePURL] with an empty version and no arch: identity is the release
// coordinate, never a particular artifact of it. See there for the resolution
// order.
func SourcePURLIdentity(ecosystem, domain, name string) (string, bool) {
	return SourcePURL(ecosystem, domain, name, "", "")
}

// ecosystemType maps a known samples.ecosystem value to its fletch PURL type: the
// language registries, the app/extension stores, and the OS distros (which name
// their own type). Junk classifiers ("linux", "macos", "datasets", …) are absent
// on purpose so those rows fall through to the download domain.
func ecosystemType(eco string) (string, bool) {
	if t, ok := languageType(eco); ok {
		return t, true
	}
	switch eco {
	// Agent-skill registries are identity-preserving too. ClawHub is its own
	// registry (an invented type, like jetbrains/homebrew); skills.sh entries
	// resolve to their backing repository later via domain/name normalization.
	case "chrome", "firefox", "wordpress", "jetbrains", "snap", "jsr", "conda",
		"hex", "cran", "cpan", "pub", "clojars",
		"arch", "aur", "debian", "ubuntu", "fedora", "opensuse", "rpmfusion",
		"alpine", "wolfi", "netbsd", "freebsd", "openbsd", "clawhub", "skills_sh":
		return eco, true
	// GitHub-hosted code under every label forager and the walker use for it
	// (release downloads, actions, repo archives, and the samples.ecosystem
	// value they all normalize to). The identity is the repository — the
	// pkg:github type fletch fetches as a source archive.
	case "github", "github_repo", "github_actions", "github_release":
		return "github", true
	// Container images under both forager registry labels ("docker" for the
	// Docker Hub goodfeed, "oci" for ghcr/quay/generic refs) → the ratified
	// pkg:oci type, host-qualified via repository_url.
	case "oci", "docker":
		return "oci", true
	default:
		return "", false
	}
}

// domainType maps a download domain (the eTLD+1 stored in samples.domain) to a
// fletch PURL type. It is the authority for rows the ecosystem column mislabels.
// Registrable-domain collisions that can't be told apart here (aur vs the official
// Arch repos both live at archlinux.org) resolve to the more general type.
func domainType(dom string) (string, bool) {
	switch dom {
	case "npmjs.org", "npmjs.com":
		return "npm", true
	case "jsr.io":
		return "jsr", true
	case "pypi.org", "pythonhosted.org":
		return "pypi", true
	case "anaconda.org":
		return "conda", true
	case "rubygems.org":
		return "gem", true
	case "crates.io":
		return "cargo", true
	case "golang.org", "go.dev":
		return "golang", true
	case "maven.org":
		return "maven", true
	case "nuget.org":
		return "nuget", true
	case "packagist.org":
		return "composer", true
	case "hex.pm":
		return "hex", true
	case "huggingface.co":
		return "huggingface", true
	case "open-vsx.org":
		return "openvsx", true
	case "visualstudio.com", "vsassets.io":
		return "vscode", true
	case "mozilla.org":
		return "firefox", true
	case "wordpress.org":
		return "wordpress", true
	case "archlinux.org":
		return "arch", true
	case "debian.org":
		return "debian", true
	case "ubuntu.com":
		return "ubuntu", true
	case "fedoraproject.org":
		return "fedora", true
	case "opensuse.org":
		return "opensuse", true
	case "alpinelinux.org":
		return "alpine", true
	case "wolfi.dev":
		return "wolfi", true
	case "netbsd.org":
		return "netbsd", true
	case "freebsd.org":
		return "freebsd", true
	case "openbsd.org":
		return "openbsd", true
	case "brew.sh":
		return "homebrew", true
	case "snapcraft.io":
		return "snap", true
	case "github.com":
		return "github", true
	case "docker.com", "docker.io":
		return "oci", true
	case "clawhub.ai":
		return "clawhub", true
	case "skills.sh":
		return "skills_sh", true
	default:
		return "", false
	}
}

// buildTyped renders a PURL for an already-resolved registry key, in the
// spec-compliant / common-practice form we generate (the canonicalizer below
// folds our older non-spec spellings onto these). The key names a registry;
// the emitted PURL type follows the purl-spec where one exists — deb/rpm/apk/alpm
// with the distro as namespace, chrome-extension, vscode-extension (Open VSX via a
// repository_url qualifier) — and an invented type where the spec defines none
// (firefox, wordpress, jetbrains, snap, homebrew, the BSDs). arch is emitted as
// the spec's `arch` qualifier on the distro types that define it; every other
// type ignores it.
func buildTyped(key, name, version, arch string) (string, bool) {
	name = strings.TrimSpace(name)
	if name == "" {
		return "", false
	}
	switch key {
	case "npm", "jsr":
		// Scoped packages: "@scope/name" -> namespace "@scope".
		if scope, pkg, found := strings.Cut(name, "/"); found && strings.HasPrefix(name, "@") {
			return renderPURL(key, scope, pkg, version, ""), true
		}
		return renderPURL(key, "", name, version, ""), true
	case "pypi":
		// PEP 503: the registry's own name equivalence (lowercase, separator
		// runs collapsed), so every spelling of a project shares one identity.
		return renderPURL(key, "", pep503(name), version, ""), true
	case "maven":
		group, artifact, found := strings.Cut(name, ":")
		if !found || group == "" || artifact == "" {
			return "", false
		}
		return renderPURL(key, group, artifact, version, ""), true
	case "composer":
		vendor, pkg, found := strings.Cut(asciiLower(name), "/")
		if !found || vendor == "" || pkg == "" {
			return "", false
		}
		return renderPURL(key, vendor, pkg, version, ""), true
	case "golang":
		if i := strings.LastIndex(name, "/"); i > 0 {
			return renderPURL(key, name[:i], name[i+1:], version, ""), true
		}
		return renderPURL(key, "", name, version, ""), true
	case "huggingface":
		if owner, model, found := strings.Cut(name, "/"); found {
			return renderPURL(key, owner, model, version, ""), true
		}
		return renderPURL(key, "", name, version, ""), true
	case "github":
		// The repository is the identity: exactly owner/repo, lowercased (the
		// purl-spec github type marks both case-insensitive). A bare name or
		// extra path segments has no certain repo identity — emit nothing
		// rather than a coordinate fletch would fetch as the wrong repo.
		owner, repo, found := strings.Cut(name, "/")
		if !found || owner == "" || repo == "" || strings.Contains(repo, "/") {
			return "", false
		}
		return renderPURL(key, asciiLower(owner), asciiLower(repo), version, ""), true

	case "skills_sh":
		// A skills.sh skill names owner/repo[/skill] and installs from the
		// backing GitHub repository (see forager's DownloadSkillsSH): the repo
		// archive is the artifact that gets hashed, so skills sharing a repo
		// share bytes and correctly share the repo's pkg:github identity.
		parts := strings.SplitN(name, "/", 3)
		if len(parts) < 2 || parts[0] == "" || parts[1] == "" {
			return "", false
		}
		return renderPURL("github", asciiLower(parts[0]), asciiLower(parts[1]), version, ""), true

	case "clawhub":
		// ClawHub skill: owner/slug when the publisher is known (slugs are not
		// unique across publishers), bare slug otherwise. Lowercased — the
		// registry treats both as case-insensitive handles.
		if owner, slug, found := strings.Cut(name, "/"); found {
			if owner == "" || slug == "" || strings.Contains(slug, "/") {
				return "", false
			}
			return renderPURL(key, asciiLower(owner), asciiLower(slug), version, ""), true
		}
		return renderPURL(key, "", asciiLower(name), version, ""), true

	case "oci":
		// The ratified pkg:oci type (purl-spec types/oci-definition.json): the
		// bare image name, lowercased, no namespace; the registry-qualified
		// repository path rides the repository_url qualifier — slashes
		// percent-encoded per the standard's character-encoding clause (':'
		// is never encoded) — so docker.io/library/nginx and ghcr.io/evil/nginx
		// stay distinct identities. Bare and un-namespaced refs normalize onto
		// Docker Hub's implied coordinates ("nginx" → docker.io/library/nginx),
		// matching forager's docker goodfeed and osm's container reports. The
		// spec reserves version for the sha256:… digest; a mutable tag rides
		// the tag qualifier instead (lexicographic key order: repository_url
		// before tag).
		ref := asciiLower(name)
		if first, _, ok := strings.Cut(ref, "/"); !ok || !strings.ContainsAny(first, ".:") {
			if !strings.Contains(ref, "/") {
				ref = "library/" + ref
			}
			ref = "docker.io/" + ref
		}
		img := lastSegment(ref)
		if img == "" {
			return "", false
		}
		qualifier := "repository_url=" + escapePURL(ref)
		digest := ""
		if v := strings.TrimSpace(version); v != "" {
			if strings.HasPrefix(strings.ToLower(v), "sha256:") {
				digest = asciiLower(v)
			} else {
				qualifier += "&tag=" + escapePURL(v)
			}
		}
		return renderPURL(key, "", img, digest, qualifier), true

	// Editor extensions → the ratified pkg:vscode-extension type; Open VSX is the
	// same type distinguished by a repository_url qualifier (it defaults to the
	// Microsoft marketplace). Id is "publisher.name" (marketplace) or
	// "publisher/name" (Open VSX), lowercased to canonical form.
	case "vscode":
		pub, ext := splitExtensionID(name)
		return renderPURL("vscode-extension", pub, ext, version, ""), true
	case "openvsx":
		pub, ext := splitExtensionID(name)
		return renderPURL("vscode-extension", pub, ext, version, openVSXQualifier), true

	// Chrome Web Store → the ratified pkg:chrome-extension type (no namespace).
	case "chrome":
		return renderPURL("chrome-extension", "", lastSegment(name), version, ""), true

	default:
		// Distros → the spec deb/rpm/apk/alpm types with the distro as
		// namespace (the AUR is its own alpm namespace, pkg:alpm/aur/<name>,
		// which fletch routes to the AUR RPC), carrying the artifact's
		// architecture as the spec's `arch` qualifier when known. `arch` sorts
		// before any other qualifier key we emit, keeping the spec's canonical
		// key order.
		if d, ok := distroSpec(key); ok {
			q := d.qualifier
			if arch != "" {
				if q != "" {
					q = "arch=" + arch + "&" + q
				} else {
					q = "arch=" + arch
				}
			}
			return renderPURL(d.typ, d.namespace, d.name(name), version, q), true
		}
		// Registries the spec doesn't cover (firefox, wordpress, jetbrains, snap,
		// homebrew, the BSDs, and the language registries gem/cargo/nuget/hex/
		// cran/cpan/pub/conda/clojars): emit pkg:<key>/<name>, last segment only.
		return renderPURL(key, "", lastSegment(name), version, ""), true
	}
}

// distroPURL is the purl-spec rendering of a distro registry key: the type, the
// namespace (the distro/vendor the spec places there), an optional qualifier, and
// whether the spec lowercases the package name.
type distroPURL struct {
	typ       string // deb, rpm, apk, or alpm
	namespace string // the vendor: debian, fedora, arch, …
	qualifier string // optional, e.g. the AUR's repository_url
	// lowerName is true where the spec says the name is case-insensitive and must
	// be lowercased (deb, apk, alpm). rpm is deliberately excluded: its spec marks
	// the name case-sensitive.
	lowerName bool
}

// distroSpec maps a distro registry key to its purl-spec rendering: Debian-family
// → deb, RPM-family → rpm, Alpine-family → apk, Arch-family → alpm. The AUR is
// carried as its own alpm namespace (pkg:alpm/aur/<name>): distinguishing it from
// the official repos is what the namespace is for, and the bare name is what the
// AUR RPC and fletch's fetcher key on. (We previously emitted the arch vendor
// plus a repository_url qualifier; the canonicalizer folds that spelling onto
// this one.)
func distroSpec(key string) (distroPURL, bool) {
	switch key {
	case "debian":
		return distroPURL{"deb", "debian", "", true}, true
	case "ubuntu":
		return distroPURL{"deb", "ubuntu", "", true}, true
	case "fedora":
		return distroPURL{"rpm", "fedora", "", false}, true
	case "opensuse":
		return distroPURL{"rpm", "opensuse", "", false}, true
	case "rpmfusion":
		return distroPURL{"rpm", "rpmfusion", "", false}, true
	case "arch":
		return distroPURL{"alpm", "arch", "", true}, true
	case "aur":
		return distroPURL{"alpm", "aur", "", true}, true
	case "alpine":
		return distroPURL{"apk", "alpine", "", true}, true
	case "wolfi":
		return distroPURL{"apk", "wolfi", "", true}, true
	default:
		return distroPURL{}, false
	}
}

// distroName renders a distro package name per the type's spec: the bare package
// (any vendor path dropped), lowercased where the spec requires it.
func (d distroPURL) name(raw string) string {
	name := lastSegment(raw)
	if d.lowerName {
		return asciiLower(name)
	}
	return name
}

// CanonicalizePURL rewrites a PURL onto the spec/common-practice form we generate,
// folding the non-spec spellings we emitted before (and that fletch still fetches)
// so old and new identities compare equal: pkg:chrome→chrome-extension,
// pkg:vscode/pub/name & pkg:openvsx/pub/name→vscode-extension (Open VSX keeping its
// repository_url qualifier), the bare distro types pkg:debian|arch|fedora|…→
// deb/rpm/apk/alpm with the distro namespace, and both AUR spellings (bare
// pkg:aur/<name> and the vendor-plus-qualifier
// pkg:alpm/arch/<name>?repository_url=…aur.archlinux.org)→pkg:alpm/aur/<name>,
// the AUR as its own alpm namespace. For the spec distro types (deb/rpm/apk/alpm)
// it lowercases the vendor namespace (case-insensitive per spec) and recovers a
// missing one from the distro=<vendor>-<release> qualifier (see [distroPath]).
// It also repairs the non-spec "?qualifiers@version" ordering older exports
// composed (purl_base || '@' || version glued the version after a
// qualifier-bearing base), restoring the spec "@version?qualifiers" order.
// Inputs already in canonical form, or of a type we don't remap, are returned
// unchanged. A string that isn't a PURL is returned as-is.
func CanonicalizePURL(purl string) string {
	out := encodePURLPath(canonicalizePURL(purl))
	// Conservative in what we emit. The purl-spec's type definitions say which
	// coordinates can exist at all — pypi has no namespace, a chrome extension
	// id is 32 letters a-p — and a string that violates one has no canonical
	// form to fold onto. Rewriting it anyway (lowercasing the type, say) mints
	// a key for a package that cannot exist, and every consumer that looks it
	// up misses. fletch's purl::normalize refuses these outright; this returns
	// the input untouched, which is the same statement in a function that has
	// no way to say "no".
	//
	// Liberal in what we accept: this runs on the CANONICAL form, not the raw
	// input, so every legacy spelling still folds first. "pkg:aur/yay?
	// repository_url=…aur.archlinux.org" becomes "pkg:alpm/aur/yay" and passes;
	// only what is still invalid after folding is refused.
	if !purlTypeAllows(out) {
		return strings.TrimSpace(purl)
	}
	return out
}

// encodePURLPath percent-encodes the coordinate path, leaving the '/' segment
// separators literal.
//
// The spec requires non-ASCII to be UTF-8 encoded and then percent-encoded, so
// "pkg:npm/Ünicode" and "pkg:npm/%C3%9Cnicode" are one package; passing the raw
// bytes through made them two keys. It runs on the canonical output rather than
// the input so every type-specific fold (case, PEP 503, distro namespaces) has
// already happened — encoding first would hide those letters behind %XX where
// the folds could not see them.
//
// Decoding each segment before re-encoding keeps it idempotent, and a segment
// with a malformed escape is left alone rather than mangled further.
func encodePURLPath(purl string) string {
	if len(purl) < 4 || !strings.EqualFold(purl[:4], "pkg:") {
		return purl
	}
	typ, rest, ok := strings.Cut(purl[4:], "/")
	if !ok {
		return purl
	}
	path, tail := rest, ""
	if i := strings.IndexAny(rest, "@?"); i >= 0 {
		path, tail = rest[:i], rest[i:]
	}
	if !purlPathNeedsEncoding(path) {
		return purl
	}
	segments := strings.Split(path, "/")
	for i, seg := range segments {
		decoded, ok := unescapePURL(seg)
		if !ok {
			continue
		}
		segments[i] = escapePURL(decoded)
	}
	return "pkg:" + typ + "/" + strings.Join(segments, "/") + tail
}

// purlPathNeedsEncoding reports whether any byte of the path is neither a
// segment separator nor already canonical, so the common all-ASCII path costs
// one scan and no allocation.
func purlPathNeedsEncoding(path string) bool {
	for i := range len(path) {
		if c := path[i]; c != '/' && c != '%' && !purlUnreserved(c) {
			return true
		}
	}
	return false
}

// purlTypeAllows reports whether a canonical PURL satisfies its type's
// definition. It mirrors fletch's apply_type_rules; the two must agree, because
// a coordinate one tool keys and the other refuses is a lookup that silently
// finds nothing.
func purlTypeAllows(purl string) bool {
	if len(purl) < 4 || !strings.EqualFold(purl[:4], "pkg:") {
		return true // not ours to judge; canonicalizePURL passed it through
	}
	typ, rest, ok := strings.Cut(purl[4:], "/")
	if !ok {
		return true
	}
	path, tail := rest, ""
	if i := strings.IndexAny(rest, "@?"); i >= 0 {
		path, tail = rest[:i], rest[i:]
	}
	namespace, name := "", path
	if i := strings.LastIndexByte(path, '/'); i >= 0 {
		namespace, name = path[:i], path[i+1:]
	}

	switch purlNamespaceRequirement(typ) {
	case purlNamespaceRequired:
		// The spec's rpm note says a missing repository is implied by `distro`,
		// and this project recovers an AUR namespace from repository_url the
		// same way, so neither counts as a missing namespace.
		if namespace == "" && !recoverableDistroNamespace(typ, tail) {
			return false
		}
	case purlNamespaceForbidden:
		if namespace != "" {
			return false
		}
	}

	switch typ {
	case "chrome-extension":
		// A Chrome Web Store id is exactly 32 characters drawn from a-p, and a
		// store version is one to four dot-separated numbers.
		if len(name) != 32 {
			return false
		}
		for i := range len(name) {
			if name[i] < 'a' || name[i] > 'p' {
				return false
			}
		}
		if v, _, _ := strings.Cut(strings.TrimPrefix(tail, "@"), "?"); strings.HasPrefix(tail, "@") {
			if !chromeVersionShape(v) {
				return false
			}
		}
	case "cpan":
		// A distribution name uses dashes; "::" spells a module, not a release.
		if strings.Contains(name, "::") {
			return false
		}
	case "julia":
		if _, _, found := cutQualifier(tail, "uuid"); !found {
			return false
		}
	case "swid":
		if _, _, found := cutQualifier(tail, "tag_id"); !found {
			return false
		}
	}
	return true
}

const (
	purlNamespaceOptional  = 0
	purlNamespaceRequired  = 1
	purlNamespaceForbidden = -1
)

// purlNamespaceRequirement is the purl-spec type definitions' namespace rule.
// Kept as one table so it can be diffed against fletch's twin by eye.
func purlNamespaceRequirement(typ string) int {
	switch typ {
	case "alpm", "apk", "bitbucket", "composer", "deb", "git", "github", "golang",
		"huggingface", "maven", "qpkg", "rpm", "swift", "vscode-extension":
		return purlNamespaceRequired
	case "bazel", "bitnami", "cargo", "chrome-extension", "cocoapods", "conda", "cran",
		"gem", "hackage", "julia", "mlflow", "nuget", "oci", "opam", "otp", "pub",
		"pypi", "vcpkg":
		return purlNamespaceForbidden
	default:
		return purlNamespaceOptional
	}
}

// recoverableDistroNamespace reports whether a missing distro namespace is
// implied by a qualifier rather than absent.
func recoverableDistroNamespace(typ, tail string) bool {
	if val, _, found := cutQualifier(tail, "distro"); found {
		vendor, _, _ := strings.Cut(val, "-")
		if d, ok := distroSpec(vendor); ok && d.typ == typ {
			return true
		}
	}
	if typ == "alpm" {
		if val, _, found := cutQualifier(tail, "repository_url"); found &&
			strings.Contains(val, "aur.archlinux.org") {
			return true
		}
	}
	return false
}

// chromeVersionShape reports whether v is a Chrome Web Store version: one to
// four dot-separated runs of digits.
func chromeVersionShape(v string) bool {
	if v == "" {
		return true // no version at all is fine; an empty one is not a version
	}
	segments := strings.Split(v, ".")
	if len(segments) > 4 {
		return false
	}
	for _, s := range segments {
		if s == "" {
			return false
		}
		for i := range len(s) {
			if s[i] < '0' || s[i] > '9' {
				return false
			}
		}
	}
	return true
}

func canonicalizePURL(purl string) string {
	// The `pkg` scheme and the type are case-insensitive per spec (and pasted
	// purls arrive padded), so fold their case and trim before anything else —
	// matching fletch's purl::normalize, which must produce identical output.
	purl = strings.TrimSpace(purl)
	if len(purl) < 4 || !strings.EqualFold(purl[:4], "pkg:") {
		return purl
	}
	typ, rest, ok := strings.Cut(purl[4:], "/")
	if !ok {
		return purl
	}
	typ = asciiLower(typ)

	// Split the remainder into path and the version/qualifier tail so we can
	// re-key the type without disturbing "@version" or "?qualifiers".
	//
	// A *leading* '@' opens an npm scope ("@scope/name"), never a version: a
	// coordinate path cannot begin with its own version separator. Searching
	// from 0 would take the whole path as the tail, leaving an empty name that
	// the guard below then passes through unchanged — so every scoped package
	// kept whichever spelling it arrived in, while renderPURL emits the escaped
	// "%40scope". Two keys for one package. purlVersionIndex already guards the
	// same trap; this is the site that missed it.
	//
	// It is a scope only when a '/' closes it. Where the next delimiter is a
	// version or a qualifier instead, the '@' really does open a version over
	// an empty name ("pkg:npm/@1.0.0"), which must still reach the guard.
	scopeSigil := 0
	if strings.HasPrefix(rest, "@") {
		if i := strings.IndexAny(rest[1:], "/@?"); i >= 0 && rest[1+i] == '/' {
			scopeSigil = 1
		}
	}
	path, tail := rest, ""
	if i := strings.IndexAny(rest[scopeSigil:], "@?"); i >= 0 {
		path, tail = rest[:scopeSigil+i], rest[scopeSigil+i:]
	}
	// A degenerate coordinate (empty type or name) has no canonical form —
	// the Rust twin (fletch's purl::normalize) rejects these outright — so
	// pass the input through untouched rather than half-rewriting it.
	if typ == "" || lastSegment(path) == "" {
		return purl
	}
	// Fold a literal npm scope onto the escaped spelling renderPURL produces,
	// so a purl this package generated and one pasted in by hand are the same
	// key. Mirrors fletch's purl::normalize; distro namespaces are vendors and
	// never carry the sigil, so this is a no-op for them.
	if scope, found := strings.CutPrefix(path, "@"); found {
		path = "%40" + scope
	}
	// Repair the non-spec "?qualifiers@version" ordering older exports emitted
	// (a version appended to a qualifier-bearing purl_base): move the trailing
	// version back before the qualifiers. The chunk after the last '@' is only
	// a version when it is free of '='/'&'/'/', any of which would mark it as
	// part of a qualifier value (e.g. a repository_url with userinfo) instead.
	// (No change flag: the unchanged-input paths below compare their rebuilt
	// output against the input, which detects this repair, a recovered or
	// re-cased namespace, and a folded scheme/type alike.)
	if strings.HasPrefix(tail, "?") {
		if i := strings.LastIndexByte(tail, '@'); i > 0 {
			if v := tail[i+1:]; v != "" && !strings.ContainsAny(v, "=&/") {
				tail = "@" + v + tail[:i]
			}
		}
	}

	// An empty version is the same as no version — "pkg:npm/x@" and "pkg:npm/x"
	// name one coordinate — so drop the bare sigil rather than keying twice.
	if ver, quals, hasQ := strings.Cut(tail, "?"); ver == "@" {
		tail = ""
		if hasQ {
			tail = "?" + quals
		}
	}
	// Qualifier values arrive in whatever spelling the producer used; fold them
	// onto the canonical encoding before any branch inspects or rebuilds the
	// tail, so every return path below emits one spelling.
	tail = canonicalQualifiers(tail)

	switch typ {
	// The extension types are case-insensitive per spec (store ids are
	// lowercase), so their bodies are lowercased — matching buildTyped and
	// fletch's purl::normalize. The ratified spellings are handled alongside
	// the legacy ones so an already-ratified input still gets its case folded.
	case "chrome", "chrome-extension":
		return "pkg:chrome-extension/" + asciiLower(lastSegment(path)) + tail
	case "vscode", "vscode-extension":
		return "pkg:vscode-extension/" + asciiLower(path) + tail
	case "openvsx":
		return "pkg:vscode-extension/" + asciiLower(path) + addQualifier(tail, openVSXQualifier)
	// PyPI treats '-'/'_'/'.' as one separator and names as case-insensitive
	// (PEP 503, the registry's own equivalence); composer names are
	// case-insensitive per spec and lowercased. npm is deliberately NOT
	// folded: legacy mixed-case names were grandfathered in and stay distinct.
	case "pypi":
		return "pkg:pypi/" + pep503(path) + tail
	case "composer":
		return "pkg:composer/" + asciiLower(path) + tail
	case "deb", "rpm", "apk":
		if out := "pkg:" + typ + "/" + distroPath(typ, path, tail) + tail; out != purl {
			return out
		}
		return purl
	case "alpm":
		vendored := distroPath(typ, path, tail)
		// The AUR is its own alpm namespace: pkg:alpm/aur/<name>. Fold the
		// earlier vendor-plus-qualifier spelling we generated
		// (pkg:alpm/arch/<name>?repository_url=…aur.archlinux.org) onto it,
		// dropping that qualifier. A repository_url naming anything else, and
		// the other alpm namespaces (the official repos), are already
		// canonical.
		if val, rest, found := cutQualifier(tail, "repository_url"); found && strings.Contains(val, "aur.archlinux.org") {
			return "pkg:alpm/aur/" + asciiLower(lastSegment(vendored)) + rest
		}
		if name, found := strings.CutPrefix(vendored, "aur/"); found {
			return "pkg:alpm/aur/" + asciiLower(name) + tail
		}
		if out := "pkg:alpm/" + vendored + tail; out != purl {
			return out
		}
		return purl
	}
	if d, ok := distroSpec(typ); ok {
		ns := d.namespace
		// An AUR repository_url wins over the mapped vendor: a legacy bare
		// type carrying it (pkg:aur/x redundantly, or pkg:arch/x pointing at
		// the AUR) folds onto the aur namespace with the now-redundant
		// qualifier dropped — the same fold the alpm case applies, so a
		// single pass converges to the fixed point.
		if d.typ == "alpm" {
			if val, rest, found := cutQualifier(tail, "repository_url"); found && strings.Contains(val, "aur.archlinux.org") {
				ns, tail = "aur", rest
			}
		}
		return "pkg:" + d.typ + "/" + ns + "/" + d.name(path) + addQualifier(tail, d.qualifier)
	}
	if out := "pkg:" + typ + "/" + path + tail; out != purl {
		return out
	}
	return purl
}

// distroPath canonicalizes the vendor namespace of a spec distro type's
// (deb/rpm/apk/alpm) coordinate path. The spec marks the namespace
// case-insensitive and lowercased in canonical form, so an existing vendor is
// lowercased. A *missing* vendor is recovered from a distro=<vendor>-<release>
// qualifier — the spec's rpm note says the repository is implied by `distro` —
// but only when the vendor prefix names a distro this project models for that
// type (fedora-25 → fedora; a bare codename like jessie never matches). The
// qualifier itself is left in place: identity layers strip it downstream.
func distroPath(typ, path, tail string) string {
	// deb, apk and alpm define their name as case-insensitive and lowercase it
	// in canonical form. rpm deliberately does NOT: only its namespace folds,
	// because an rpm name is case sensitive. Applying one rule to all four
	// would either split "pkg:deb/debian/Curl" from "pkg:deb/debian/curl" or
	// merge two distinct rpm packages, so the difference is per type.
	foldName := typ == "deb" || typ == "apk" || typ == "alpm"
	if ns, name, found := strings.Cut(path, "/"); found {
		if foldName {
			name = asciiLower(name)
		}
		return asciiLower(ns) + "/" + name
	}
	if foldName {
		path = asciiLower(path)
	}
	if val, _, found := cutQualifier(tail, "distro"); found {
		vendor, _, _ := strings.Cut(val, "-")
		vendor = asciiLower(vendor)
		if d, ok := distroSpec(vendor); ok && d.typ == typ && d.namespace == vendor {
			return vendor + "/" + path
		}
	}
	return path
}

// VersionlessPURL strips the "@version" from a Package URL, yielding the
// identity form stored in samples.purl_base (e.g. "pkg:npm/lodash@4.17.21" →
// "pkg:npm/lodash"). The version separator is the last '@' before the
// qualifiers; a scoped npm name's '@' sits earlier (or is percent-encoded), so
// it is never mistaken for it. A trailing "@version" *inside* the qualifier
// tail — the non-spec ordering older composers emitted — is stripped too, when
// the chunk after the '@' is free of '='/'&'/'/' and so can't be part of a
// qualifier value.
//
// Of the qualifiers, only repository_url survives: it selects which registry
// the name lives in (Open VSX vs the Microsoft marketplace), which *is*
// identity. Artifact-selection qualifiers an SBOM-style client may stamp on
// (arch, distro, kind, …) select which artifact of a release, not which
// package — keeping them would split purl_base grouping against forager's
// bare coordinates. Mirrors scan's fletch::purl::identity, minus the version.
// Callers wanting a canonical identity compose [CanonicalizePURL] first.
// Empty in, empty out.
func VersionlessPURL(fullPURL string) string {
	body, quals, hasQuals := strings.Cut(fullPURL, "?")
	if i := purlVersionIndex(body); i > 0 {
		body = body[:i]
	}
	if !hasQuals {
		return body
	}
	if i := strings.LastIndexByte(quals, '@'); i > 0 && !strings.ContainsAny(quals[i+1:], "=&/") {
		quals = quals[:i]
	}
	kept := make([]string, 0, 1)
	for q := range strings.SplitSeq(quals, "&") {
		if k, _, _ := strings.Cut(q, "="); strings.EqualFold(k, "repository_url") {
			kept = append(kept, q)
		}
	}
	if len(kept) == 0 {
		return body
	}
	return body + "?" + strings.Join(kept, "&")
}

// purlVersionIndex returns the index within body — a PURL with its qualifier
// tail already removed — of the '@' separating the version from the name, or
// -1 when the coordinate is versionless. Only an '@' inside the final name
// segment is that separator: a scoped npm namespace ("pkg:npm/@scope/name")
// carries one earlier, and reading it as a version collapses every scoped
// package onto the single identity "pkg:npm/". A "#subpath" trails the version
// rather than being part of the name, so the search stops before it.
func purlVersionIndex(body string) int {
	name, _, _ := strings.Cut(body, "#")
	start := strings.LastIndexByte(name, '/') + 1
	if i := strings.IndexByte(name[start:], '@'); i > 0 {
		return start + i
	}
	return -1
}

// PURLVersion returns the version of a Package URL, or "" when it carries
// none. It is the exact complement of [VersionlessPURL]: together the two split
// one canonical PURL into the (purl_base, version) pair samples stores, so a
// lookup composed from them addresses the row the same PURL was ingested as.
// Like VersionlessPURL it also understands the non-spec "?qualifiers@version"
// ordering older composers emitted.
func PURLVersion(fullPURL string) string {
	body, quals, hasQuals := strings.Cut(fullPURL, "?")
	if i := purlVersionIndex(body); i > 0 {
		version, _, _ := strings.Cut(body[i+1:], "#")
		return version
	}
	if hasQuals {
		if i := strings.LastIndexByte(quals, '@'); i > 0 && !strings.ContainsAny(quals[i+1:], "=&/") {
			return quals[i+1:]
		}
	}
	return ""
}

// cutQualifier removes the named qualifier from a PURL version/qualifier tail,
// returning its value and the tail without it (the "?" goes too when it was the
// only qualifier). found is false — and the tail returned unchanged — when the
// key isn't present.
func cutQualifier(tail, key string) (value, rest string, found bool) {
	ver, quals, hasQ := strings.Cut(tail, "?")
	if !hasQ {
		return "", tail, false
	}
	kept := make([]string, 0, 4)
	for q := range strings.SplitSeq(quals, "&") {
		if k, v, _ := strings.Cut(q, "="); !found && strings.EqualFold(k, key) {
			value, found = v, true
			continue
		}
		kept = append(kept, q)
	}
	if !found {
		return "", tail, false
	}
	if len(kept) == 0 {
		return value, ver, true
	}
	return value, ver + "?" + strings.Join(kept, "&"), true
}

// addQualifier merges one qualifier into a PURL version/qualifier tail
// ("@v", "?k=v", "@v?k=v", or ""), leaving an already-present key untouched. An
// empty qualifier is a no-op, so distro keys without one pass their tail through.
// canonicalQualifiers re-encodes a purl's qualifier VALUES to the spec's
// canonical percent-encoding, leaving keys and ordering alone.
//
// The spec's own test vectors encode reserved characters in qualifier values —
// "repository_url=repo.spring.io%2Frelease" — and fletch's purl::normalize does
// the same. Passing an input's spelling through instead meant
// "?repository_url=https://x" and "?repository_url=https:%2F%2Fx" were two keys
// for one package, and the two implementations disagreed on which was canonical.
//
// Decoding before re-encoding is what makes this idempotent: an already-encoded
// value decodes to the same bytes and comes back unchanged, so canonicalizing
// twice is canonicalizing once. A value with a malformed escape is left exactly
// as it arrived — it is not this function's job to guess at a broken purl, and
// rewriting it would invent a coordinate nobody published.
// openVSXQualifier distinguishes Open VSX from the Visual Studio Marketplace,
// which share the vscode-extension type. The value is written pre-encoded
// because that is the canonical spelling — see canonicalQualifiers.
const openVSXQualifier = "repository_url=https:%2F%2Fopen-vsx.org"

func canonicalQualifiers(tail string) string {
	ver, quals, ok := strings.Cut(tail, "?")
	if !ok || quals == "" {
		return tail
	}
	parts := strings.Split(quals, "&")
	keys := make([]string, len(parts))
	for i, q := range parts {
		key, val, hasEq := strings.Cut(q, "=")
		keys[i] = asciiLower(key)
		if !hasEq || val == "" {
			continue
		}
		decoded, ok := unescapePURL(val)
		if !ok {
			continue
		}
		parts[i] = key + "=" + escapePURL(decoded)
	}
	// The spec orders qualifiers by key, and fletch holds them in a BTreeMap,
	// so the same set written in two orders is one canonical string. Sorted by
	// the lowercased key because keys are case-insensitive; stable so a
	// repeated key keeps the order it arrived in rather than shuffling.
	sort.SliceStable(parts, func(i, j int) bool { return keys[i] < keys[j] })
	return ver + "?" + strings.Join(parts, "&")
}

func addQualifier(tail, qualifier string) string {
	if qualifier == "" {
		return tail
	}
	key, _, _ := strings.Cut(qualifier, "=")
	ver, quals, hasQ := strings.Cut(tail, "?")
	if !hasQ {
		return tail + "?" + qualifier
	}
	for q := range strings.SplitSeq(quals, "&") {
		if k, _, _ := strings.Cut(q, "="); strings.EqualFold(k, key) {
			return tail // already qualified; don't duplicate
		}
	}
	return ver + "?" + quals + "&" + qualifier
}

// splitExtensionID splits a VS Code / Open VSX coordinate into publisher and name,
// lowercased to canonical form. Marketplace ids use "publisher.name"; Open VSX
// exports "publisher/name". A bare id yields an empty publisher.
func splitExtensionID(name string) (publisher, ext string) {
	name = asciiLower(name)
	if pub, e, found := strings.Cut(name, "/"); found {
		return pub, e
	}
	if pub, e, found := strings.Cut(name, "."); found {
		return pub, e
	}
	return "", name
}

// asciiLower lowercases ASCII letters only, leaving every other byte
// untouched — the exact fold Rust's to_ascii_lowercase applies, so the two
// canonicalizers stay byte-identical even on non-ASCII names (which
// strings.ToLower would case-fold differently).
func asciiLower(s string) string {
	lower := func(r rune) rune {
		if r >= 'A' && r <= 'Z' {
			return r + ('a' - 'A')
		}
		return r
	}
	return strings.Map(lower, s)
}

// pep503 normalizes a PyPI project name per PEP 503 — ASCII-lowercase, any run
// of '-'/'_'/'.' collapsed to a single '-' — the registry's own name
// equivalence. filefacts' manifest parser and fletch's purl::normalize apply
// the same fold, so a requirements.txt spelling and a download-derived
// spelling of one project always share a key.
func pep503(name string) string {
	var b strings.Builder
	b.Grow(len(name))
	sep := false
	for _, r := range name {
		if r == '-' || r == '_' || r == '.' {
			if !sep {
				b.WriteByte('-')
				sep = true
			}
			continue
		}
		sep = false
		if r >= 'A' && r <= 'Z' {
			r += 'a' - 'A'
		}
		b.WriteRune(r)
	}
	return b.String()
}

// lastSegment returns the final "/"-separated segment (fletch drops any vendor
// path for the app-store and distro types).
func lastSegment(name string) string {
	if i := strings.LastIndex(name, "/"); i >= 0 {
		return name[i+1:]
	}
	return name
}

// renderPURL assembles a canonical PURL string, percent-encoding each path
// segment per RFC 3986 (the PURL spec's encoding rules) while keeping "/" as the
// namespace-segment separator. qualifier, if non-empty, is appended verbatim as
// the "?key=value" component (already-canonical form, e.g. Open VSX's
// repository_url).
func renderPURL(typ, namespace, name, version, qualifier string) string {
	var b strings.Builder
	b.WriteString("pkg:")
	b.WriteString(typ)
	b.WriteByte('/')
	if namespace != "" {
		for i, seg := range strings.Split(namespace, "/") {
			if i > 0 {
				b.WriteByte('/')
			}
			b.WriteString(escapePURL(seg))
		}
		b.WriteByte('/')
	}
	b.WriteString(escapePURL(name))
	if version != "" {
		b.WriteByte('@')
		b.WriteString(escapePURL(version))
	}
	if qualifier != "" {
		b.WriteByte('?')
		b.WriteString(qualifier)
	}
	return b.String()
}

const purlUpperhex = "0123456789ABCDEF"

// escapePURL percent-encodes a single PURL segment, leaving only the RFC 3986
// unreserved characters (A-Z a-z 0-9 - . _ ~) untouched. This encodes npm's "@"
// to "%40" and any other reserved byte automatically.
func escapePURL(s string) string {
	if !purlNeedsEscape(s) {
		return s
	}
	var b strings.Builder
	b.Grow(len(s) + 8)
	for i := range len(s) {
		if c := s[i]; purlUnreserved(c) {
			b.WriteByte(c)
		} else {
			b.WriteByte('%')
			b.WriteByte(purlUpperhex[c>>4])
			b.WriteByte(purlUpperhex[c&0x0f])
		}
	}
	return b.String()
}

func purlNeedsEscape(s string) bool {
	for i := range len(s) {
		if !purlUnreserved(s[i]) {
			return true
		}
	}
	return false
}

func purlUnreserved(c byte) bool {
	switch {
	case c >= 'A' && c <= 'Z', c >= 'a' && c <= 'z', c >= '0' && c <= '9':
		return true
	case c == '-', c == '.', c == '_', c == '~':
		return true
	case c == ':':
		// The spec's canonical test vectors keep ':' literal (an rpm/deb/alpm
		// epoch: "attr@1:2.4.47-2%2Bb1", "containers-common@1:0.47.4-4") —
		// only '+' and the truly reserved bytes are percent-encoded.
		return true
	default:
		return false
	}
}
