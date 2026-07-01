package pkgparse

import "strings"

// This is the single source of truth for building canonical Package URLs (PURLs,
// see https://github.com/package-url/purl-spec) from package coordinates. It is
// dependency-free so it can be shared: forager computes the PURL once at
// ingestion (where the authoritative registry coordinate is known) and records it
// on the sample; hopper's backfill rebuilds it for older rows from the stored
// ecosystem/package columns. Keeping one implementation means the live path and
// the backfill can never disagree on a package's identity.

// purlType maps an ecosystem to its PURL type. It accepts both registry names
// ("npm", "pypi") and the runtime/language forms stored in samples.ecosystem
// ("javascript", "python") — see runtimeMap. Where a language spans several
// registries the dominant one is chosen (javascript→npm not jsr, python→pypi not
// conda); a no-provenance backfill only has the language, so this is the best
// identity available and is correct for the overwhelming majority. ok is false
// for ecosystems with no well-defined or unambiguous PURL type (OS distributions,
// containers, browser/IDE stores, niche registries); callers leave those without
// a PURL rather than emit a wrong one.
func purlType(ecosystem string) (string, bool) {
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
		// jsr, conda, clojars, hex, cpan, cran, pub, luarocks, powershell,
		// wordpress, vscode, chrome, OS distros, containers, github, … —
		// ambiguous or not a package registry we emit PURLs for (yet).
		return "", false
	}
}

// BuildPURL returns the canonical PURL for a package coordinate and whether one
// can be formed for this ecosystem. ecosystem may be a registry name or a runtime
// ecosystem (see purlType); name uses each ecosystem's native separator (maven
// "group:artifact", composer "vendor/package", npm "@scope/name", golang module
// path); version may be empty.
func BuildPURL(ecosystem, name, version string) (string, bool) {
	typ, ok := purlType(ecosystem)
	if !ok {
		return "", false
	}
	namespace, base, ok := splitPURL(typ, name)
	if !ok || base == "" {
		return "", false
	}
	return renderPURL(typ, namespace, base, version), true
}

// PURLIdentity returns the version-less PURL — the package's stable identity
// across versions (e.g. "pkg:npm/lodash"), the value stored in samples.purl_base.
// Built from the coordinate, never by stripping the version off a full PURL, so an
// encoded "@" in a name can't confuse it.
func PURLIdentity(ecosystem, name string) (string, bool) {
	return BuildPURL(ecosystem, name, "")
}

// splitPURL divides a coordinate into PURL namespace and name and applies the
// type's normalization rules. ok is false when the coordinate is malformed for
// the type (e.g. maven without a group).
func splitPURL(typ, name string) (namespace, base string, ok bool) {
	name = strings.TrimSpace(name)
	switch typ {
	case "npm":
		// Scoped packages: "@scope/name" -> namespace "@scope", name "name".
		if scope, pkg, found := strings.Cut(name, "/"); found && strings.HasPrefix(name, "@") {
			return scope, pkg, true
		}
		return "", name, true

	case "maven":
		// "group:artifact" -> namespace group, name artifact. Group is required.
		group, artifact, found := strings.Cut(name, ":")
		if !found || group == "" || artifact == "" {
			return "", "", false
		}
		return group, artifact, true

	case "composer":
		// Packagist is always "vendor/package", lowercased.
		vendor, pkg, found := strings.Cut(strings.ToLower(name), "/")
		if !found || vendor == "" || pkg == "" {
			return "", "", false
		}
		return vendor, pkg, true

	case "golang":
		// Module path: namespace is everything before the last segment.
		if i := strings.LastIndex(name, "/"); i > 0 {
			return name[:i], name[i+1:], true
		}
		return "", name, true

	case "huggingface":
		// "owner/model" -> namespace owner, name model; bare names allowed.
		if owner, model, found := strings.Cut(name, "/"); found {
			return owner, model, true
		}
		return "", name, true

	case "pypi":
		// PEP 503 / PURL: lowercase and treat underscores as dashes.
		return "", strings.ToLower(strings.ReplaceAll(name, "_", "-")), true

	default:
		// cargo, nuget, gem: single-segment names, case preserved.
		return "", name, true
	}
}

// renderPURL assembles a canonical PURL string, percent-encoding each path
// segment per RFC 3986 (the PURL spec's encoding rules) while keeping "/" as the
// namespace-segment separator.
func renderPURL(typ, namespace, name, version string) string {
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
	for i := 0; i < len(s); i++ {
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
	for i := 0; i < len(s); i++ {
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
