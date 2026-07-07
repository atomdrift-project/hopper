package pkgparse

import "strings"

// This is the single source of truth for building canonical Package URLs (PURLs,
// see https://github.com/package-url/purl-spec) from the coordinates hopper
// stores. It is dependency-free so it can be shared: forager computes the PURL at
// ingestion, hopper's backfill rebuilds it for older rows, and both must produce
// exactly what fletch (src/registry.rs) parses when it fetches a PURL — the type
// vocabulary here mirrors fletch's resolver so a stored purl_base round-trips to a
// real registry lookup. Note fletch uses its own spellings, not the purl-spec
// ratified ones (chrome not chrome-extension, vscode + a separate openvsx type not
// vscode-extension, the distro name as the type not deb/rpm/apk); we stay
// consistent with the fetcher, since that is what the bloom's decide_purl matches.

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
// version may be empty (yielding the version-less identity). Returns ok=false when
// no confident type resolves, leaving the PURL empty rather than emitting one
// fletch could not fetch.
func SourcePURL(ecosystem, domain, name, version string) (string, bool) {
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
			return buildTyped("openvsx", name, version)
		}
		return buildTyped("vscode", name, version)
	}

	if typ, ok := ecosystemType(eco); ok {
		return buildTyped(typ, name, version)
	}
	if typ, ok := domainType(dom); ok {
		return buildTyped(typ, name, version)
	}
	return "", false
}

// SourcePURLIdentity returns the version-less purl_base — a package's identity
// across versions, promoted to the indexed samples.purl_base column. It is
// [SourcePURL] with an empty version; see there for the resolution order.
func SourcePURLIdentity(ecosystem, domain, name string) (string, bool) {
	return SourcePURL(ecosystem, domain, name, "")
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
	case "chrome", "firefox", "wordpress", "jetbrains", "snap", "jsr", "conda",
		"hex", "cran", "cpan", "pub", "clojars",
		"arch", "aur", "debian", "ubuntu", "fedora", "opensuse", "rpmfusion",
		"alpine", "wolfi", "netbsd", "freebsd", "openbsd":
		return eco, true
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
// (firefox, wordpress, jetbrains, snap, homebrew, the BSDs).
func buildTyped(key, name, version string) (string, bool) {
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
		// PEP 503: lowercase, underscores to dashes.
		return renderPURL(key, "", strings.ToLower(strings.ReplaceAll(name, "_", "-")), version, ""), true
	case "maven":
		group, artifact, found := strings.Cut(name, ":")
		if !found || group == "" || artifact == "" {
			return "", false
		}
		return renderPURL(key, group, artifact, version, ""), true
	case "composer":
		vendor, pkg, found := strings.Cut(strings.ToLower(name), "/")
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

	// Editor extensions → the ratified pkg:vscode-extension type; Open VSX is the
	// same type distinguished by a repository_url qualifier (it defaults to the
	// Microsoft marketplace). Id is "publisher.name" (marketplace) or
	// "publisher/name" (Open VSX), lowercased to canonical form.
	case "vscode":
		pub, ext := splitExtensionID(name)
		return renderPURL("vscode-extension", pub, ext, version, ""), true
	case "openvsx":
		pub, ext := splitExtensionID(name)
		return renderPURL("vscode-extension", pub, ext, version, "repository_url=https://open-vsx.org"), true

	// Chrome Web Store → the ratified pkg:chrome-extension type (no namespace).
	case "chrome":
		return renderPURL("chrome-extension", "", lastSegment(name), version, ""), true

	default:
		// Distros → the spec deb/rpm/apk/alpm types with the distro as namespace,
		// plus any repository qualifier the spec needs (the AUR names itself in a
		// repository_url; fletch routes that back to the AUR RPC).
		if d, ok := distroSpec(key); ok {
			return renderPURL(d.typ, d.namespace, d.name(name), version, d.qualifier), true
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
// → deb, RPM-family → rpm, Alpine-family → apk, Arch-family → alpm. The AUR is not
// a vendor but a repository within the arch vendor, so the spec keeps arch in the
// namespace and names the AUR in a repository_url qualifier (fletch routes that
// back to the AUR RPC); every other distro carries no qualifier.
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
		return distroPURL{"alpm", "arch", "repository_url=https://aur.archlinux.org", true}, true
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
		return strings.ToLower(name)
	}
	return name
}

// CanonicalizePURL rewrites a PURL onto the spec/common-practice form we generate,
// folding the non-spec spellings we emitted before (and that fletch still fetches)
// so old and new identities compare equal: pkg:chrome→chrome-extension,
// pkg:vscode/pub/name & pkg:openvsx/pub/name→vscode-extension (Open VSX keeping its
// repository_url qualifier), the bare distro types pkg:debian|arch|fedora|…→
// deb/rpm/apk/alpm with the distro namespace, and both AUR spellings (bare
// pkg:aur/<name> and the older pkg:alpm/aur/<name>)→pkg:alpm/arch/<name> with a
// repository_url qualifier naming the AUR. Inputs already in canonical form, or of
// a type we don't remap, are returned unchanged. A string that isn't a PURL is
// returned as-is.
func CanonicalizePURL(purl string) string {
	body, ok := strings.CutPrefix(purl, "pkg:")
	if !ok {
		return purl
	}
	typ, rest, ok := strings.Cut(body, "/")
	if !ok {
		return purl
	}
	typ = strings.ToLower(typ)

	// Split the remainder into path and the version/qualifier tail so we can
	// re-key the type without disturbing "@version" or "?qualifiers".
	path, tail := rest, ""
	if i := strings.IndexAny(rest, "@?"); i >= 0 {
		path, tail = rest[:i], rest[i:]
	}

	switch typ {
	case "chrome":
		return "pkg:chrome-extension/" + lastSegment(path) + tail
	case "vscode":
		return "pkg:vscode-extension/" + path + tail
	case "openvsx":
		return "pkg:vscode-extension/" + path + addQualifier(tail, "repository_url=https://open-vsx.org")
	case "alpm":
		// Fold the legacy AUR-in-namespace spelling (pkg:alpm/aur/<name>) onto the
		// spec form: the AUR is a repository within the arch vendor, carried as a
		// repository_url qualifier. Any other alpm namespace is already canonical.
		if name, found := strings.CutPrefix(path, "aur/"); found {
			aur, _ := distroSpec("aur")
			return "pkg:alpm/arch/" + aur.name(name) + addQualifier(tail, aur.qualifier)
		}
		return purl
	}
	if d, ok := distroSpec(typ); ok {
		return "pkg:" + d.typ + "/" + d.namespace + "/" + d.name(path) + addQualifier(tail, d.qualifier)
	}
	return purl
}

// addQualifier merges one qualifier into a PURL version/qualifier tail
// ("@v", "?k=v", "@v?k=v", or ""), leaving an already-present key untouched. An
// empty qualifier is a no-op, so distro keys without one pass their tail through.
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
	name = strings.ToLower(name)
	if pub, e, found := strings.Cut(name, "/"); found {
		return pub, e
	}
	if pub, e, found := strings.Cut(name, "."); found {
		return pub, e
	}
	return "", name
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
	default:
		return false
	}
}
