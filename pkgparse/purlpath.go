package pkgparse

import "strings"

// This file projects a PURL onto the directory a sample of that coordinate is
// stored under, and reads it back. The two directions are inverses, which is
// what lets a filesystem walk recover a sample's identity from its path alone —
// no sidecar, no lookup table, and no per-ecosystem vocabulary to keep in sync.
//
// Only the identity travels to disk. Qualifiers are dropped: they disambiguate
// registries (Open VSX vs the Microsoft marketplace) rather than naming a
// different package, and the full PURL survives on the row either way.

// maxPURLPathSegments bounds how many components a coordinate may occupy.
// Real namespaces are shallow — golang's "github.com/foo/bar" is the deepest
// shape in practice — so anything beyond this is a malformed or hostile claim,
// and the caller stores those bytes under their digest instead.
const maxPURLPathSegments = 8

// maxPURLSegmentBytes bounds one component. Comfortably above the longest real
// package name and far below NAME_MAX, so a stored path is always well-formed.
const maxPURLSegmentBytes = 128

// reservedDeviceNames are the names Windows treats as devices in any directory,
// with or without an extension. The corpus is occasionally rsync'd onto Windows
// analyst boxes, where a directory or file with one of these stems is
// unreachable, so a coordinate that lands on one is stored by digest instead.
var reservedDeviceNames = map[string]struct{}{
	"con": {}, "prn": {}, "aux": {}, "nul": {},
	"com1": {}, "com2": {}, "com3": {}, "com4": {}, "com5": {},
	"com6": {}, "com7": {}, "com8": {}, "com9": {},
	"lpt1": {}, "lpt2": {}, "lpt3": {}, "lpt4": {}, "lpt5": {},
	"lpt6": {}, "lpt7": {}, "lpt8": {}, "lpt9": {},
}

// SafePathSegment reports whether s can stand as one component of a stored
// path: non-empty and within the length bound, free of separators, NULs and
// control bytes, not a dot-only name ("." / ".." / "..."), no leading or
// trailing dot or space (Windows strips those silently, so "evil.exe." would
// resolve back to "evil.exe" elsewhere), and not a reserved device name.
//
// It validates rather than rewrites. A rewrite would quietly map two distinct
// coordinates onto one directory and break the path↔PURL round trip, so a
// caller holding an unsafe value must fall back to a digest-keyed path.
func SafePathSegment(s string) bool {
	if s == "" || len(s) > maxPURLSegmentBytes {
		return false
	}
	if strings.Trim(s, ".") == "" {
		return false
	}
	if s[0] == '.' || s[0] == ' ' || s[len(s)-1] == '.' || s[len(s)-1] == ' ' {
		return false
	}
	for i := range len(s) {
		// NUL falls under the control-byte test.
		if c := s[i]; c == '/' || c == '\\' || c < 0x20 || c == 0x7f {
			return false
		}
	}
	return !ReservedDeviceName(s)
}

// ReservedDeviceName reports whether name's stem is one Windows treats as a
// device, with or without an extension ("nul", "CON.js"). Such a name is
// unreachable once the corpus is copied to a Windows host, so neither a stored
// filename nor a directory component may use one.
func ReservedDeviceName(name string) bool {
	stem := asciiLower(name)
	if i := strings.IndexByte(stem, '.'); i >= 0 {
		stem = stem[:i]
	}
	_, reserved := reservedDeviceNames[stem]
	return reserved
}

// PURLPath projects a PURL onto its storage directory,
// "<type>/<namespace…>/<name>/<version>", with every component percent-decoded
// so the tree reads the way the ecosystem writes it ("npm/@vue/cli/5.0.8").
// The input is canonicalized first, so the legacy spellings resolve to the same
// directory as the ratified ones.
//
// ok is false for anything that is not a usable immutable coordinate: a
// malformed PURL, a version-less one (two fetches of "pkg:npm/lodash" are not
// the same artifact, so its digest is the only honest key), or one whose
// decoded components cannot safely become path segments.
func PURLPath(purl string) (string, bool) {
	purl = strings.TrimSpace(CanonicalizePURL(purl))
	if len(purl) < 4 || !strings.EqualFold(purl[:4], "pkg:") {
		return "", false
	}
	body := purl[4:]
	if i := strings.IndexByte(body, '?'); i >= 0 {
		body = body[:i] // qualifiers identify a registry, not a package
	}
	typ, rest, found := strings.Cut(body, "/")
	typ = asciiLower(typ)
	if !found || !validPURLType(typ) {
		return "", false
	}
	// Every component is escaped by renderPURL, so the only literal "@" left is
	// the version separator.
	at := strings.LastIndexByte(rest, '@')
	if at < 0 {
		return "", false
	}
	version, ok := unescapePURL(rest[at+1:])
	if !ok || !SafePathSegment(version) {
		return "", false
	}
	segs := strings.Split(rest[:at], "/")
	if len(segs) > maxPURLPathSegments {
		return "", false
	}
	for i, seg := range segs {
		decoded, ok := unescapePURL(seg)
		if !ok || !SafePathSegment(decoded) {
			return "", false
		}
		segs[i] = decoded
	}
	return typ + "/" + strings.Join(segs, "/") + "/" + version, true
}

// PURLPathParts is the coordinate recovered from a storage path. Name carries
// any namespace ("@vue/cli", "github.com/foo/bar"), matching the package column
// forager writes, and PURL is the qualifier-less canonical form.
type PURLPathParts struct {
	Type    string
	Name    string
	Version string
	PURL    string
}

// ParsePURLPath reads back what [PURLPath] wrote: the directory portion of a
// stored path, relative to the tier root and with the filename already removed.
//
// It inverts PURLPath up to the two things PURLPath deliberately discards.
// Qualifiers never reach disk. And escaping is normalized: both "pkg:npm/@vue/cli"
// and "pkg:npm/%40vue/cli" name one package and share one directory, so the
// recovered PURL comes back in the escaped spelling [SourcePURL] emits.
func ParsePURLPath(rel string) (PURLPathParts, bool) {
	segs := strings.Split(strings.Trim(rel, "/"), "/")
	// type + at least one name component + version.
	if len(segs) < 3 || len(segs) > maxPURLPathSegments+2 {
		return PURLPathParts{}, false
	}
	typ, version := segs[0], segs[len(segs)-1]
	name := segs[1 : len(segs)-1]
	if !validPURLType(typ) || !SafePathSegment(version) {
		return PURLPathParts{}, false
	}
	for _, seg := range name {
		if !SafePathSegment(seg) {
			return PURLPathParts{}, false
		}
	}
	// renderPURL escapes each component and joins the namespace with "/", so
	// re-rendering the decoded pieces reproduces the canonical spelling.
	namespace := strings.Join(name[:len(name)-1], "/")
	return PURLPathParts{
		Type:    typ,
		Name:    strings.Join(name, "/"),
		Version: version,
		PURL:    renderPURL(typ, namespace, name[len(name)-1], version, ""),
	}, true
}

// validPURLType reports whether s is a plausible PURL type. The spec restricts
// types to lowercase ASCII letters, digits, ".", "+" and "-", and every type
// hopper and fletch agree on ("npm", "chrome-extension", …) fits that.
func validPURLType(s string) bool {
	if s == "" || len(s) > maxPURLSegmentBytes {
		return false
	}
	for i := range len(s) {
		c := s[i]
		if (c < 'a' || c > 'z') && (c < '0' || c > '9') && c != '.' && c != '+' && c != '-' {
			return false
		}
	}
	// A type is also a directory name, so it inherits the segment rules.
	return SafePathSegment(s)
}

// unescapePURL reverses [escapePURL], decoding %XX back to the byte it stands
// for. ok is false for a truncated or non-hex escape, which marks the PURL as
// malformed rather than something to guess at.
func unescapePURL(s string) (string, bool) {
	if !strings.ContainsRune(s, '%') {
		return s, true
	}
	var b strings.Builder
	b.Grow(len(s))
	for i := 0; i < len(s); i++ {
		if s[i] != '%' {
			b.WriteByte(s[i])
			continue
		}
		if i+2 >= len(s) {
			return "", false
		}
		hi, hiOK := unhex(s[i+1])
		lo, loOK := unhex(s[i+2])
		if !hiOK || !loOK {
			return "", false
		}
		b.WriteByte(hi<<4 | lo)
		i += 2
	}
	return b.String(), true
}

// unhex decodes one hexadecimal digit to its 0-15 value.
func unhex(c byte) (byte, bool) {
	switch {
	case c >= '0' && c <= '9':
		return c - '0', true
	case c >= 'a' && c <= 'f':
		return c - 'a' + 10, true
	case c >= 'A' && c <= 'F':
		return c - 'A' + 10, true
	}
	return 0, false
}
