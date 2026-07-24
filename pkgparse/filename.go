// Package pkgparse extracts package name and version from a download
// filename. Used by hopper's walker (when scanning files) and forager's
// relayout (when migrating legacy paths to the new layout). Lives here
// because forager depends on hopper but not vice versa, so a shared
// helper that both consume must live in hopper.
//
// The parser is regex-based and conservative: when no recognized format
// matches, it returns ("", "") rather than guessing. This means the
// downstream "_unknown" path placeholder fires for files we don't
// confidently recognize — preferable to a wrong parse that splits a
// filename at the wrong boundary.
package pkgparse

import (
	"regexp"
	"strings"
)

// filenamePatterns matches the (name, version) split for the package
// formats forager downloads. Patterns are tried in order; the first
// match wins. Each must use named groups "name" and "version" so
// ParseFilename can extract them generically.
//
// Versions must start with a digit (or "v" prefix on opt-in patterns)
// so trailing non-version segments can never be misclassified as the
// version. Hyphenated package names like "ztunnel-1.29-compat" are
// handled by the greedy `(.+)` name capture combined with anchored
// trailing constraints (e.g. -r\d+\.apk for apk).
var filenamePatterns = []*regexp.Regexp{
	// Greedy-name patterns first: distro packages whose version+release
	// has its own anchor (e.g. -rN, .arch.rpm) so we can rely on greedy
	// `(.+)` for the name and let the trailing constraints lock in the
	// boundary at the LAST hyphen-digit before the version-anchor.

	// alpine/wolfi apk: <name>-<version>-r<rel>.apk. The arch is not in the
	// filename (it lives in the repository path), so no arch group.
	regexp.MustCompile(`^(?P<name>.+)-(?P<version>\d+\.\S*-r\d+)\.apk$`),

	// debian deb: <name>_<version>_<arch>.deb.
	regexp.MustCompile(`^(?P<name>[^_]+)_(?P<version>[^_]+)_(?P<arch>[^_]+)\.deb$`),

	// rpm: <name>-<version>-<release>.<arch>.rpm. Combine version+release.
	regexp.MustCompile(`^(?P<name>.+)-(?P<version>\d[\w.+~]*-[\w.+~]+)\.(?P<arch>\w+)\.rpm$`),

	// archlinux .pkg.tar.zst: <name>-<version>-<release>-<arch>.pkg.tar.zst
	regexp.MustCompile(`^(?P<name>.+)-(?P<version>\d[\w.+~]*-\d+)-(?P<arch>\w+)\.pkg\.tar\.\w+$`),

	// conda: <name>-<version>-<build>.conda.
	regexp.MustCompile(`^(?P<name>.+)-(?P<version>\d[\w.+~]*-[\w.+~]+)\.conda$`),

	// docker / OCI image tarballs with underscore separators.
	// Multiple underscore segments (registry_namespace_image_version);
	// greedy name gives "registry_namespace_image", version is the digit-
	// led tail.
	regexp.MustCompile(`^(?P<name>.+)_(?P<version>\d[\w.+~-]*?)\.(?:tgz|tar\.gz|tar\.bz2|tar\.xz|tar\.zst|tar)$`),

	// CRAN / GNU autotools tarballs with single underscore separator.
	// Anchored to no-underscore name so it doesn't grab docker images.
	regexp.MustCompile(`^(?P<name>[^_]+)_(?P<version>\d[\w.+~-]*?)\.(?:tgz|tar\.gz|tar\.bz2|tar\.xz|tar\.zst|tar)$`),

	// golang module zip with major-version suffix in the name and the
	// actual version after: github.com-X-Y-vN-vN.N.N.zip. Without this
	// rule the non-greedy generic regex would split before the first
	// vN, leaving "vN-" attached to the version.
	regexp.MustCompile(`^(?P<name>.+-v\d+)-(?P<version>v\d[\w.+~-]*)\.zip$`),

	// Non-greedy-name patterns: tarball / wheel / crate / jar / gem /
	// nupkg / vsix / crx / xpi / AppImage. Non-greedy `(.+?)` captures
	// the shortest plausible name so the version captures all trailing
	// build metadata (semver build suffixes like "1.0.6+spec-1.1.0").
	// Version may carry an optional "v" prefix.
	regexp.MustCompile(`^(?P<name>.+?)-(?P<version>v?\d[\w.+~-]*)\.` +
		`(?:tgz|tar\.gz|tar\.bz2|tar\.xz|tar\.zst|tar|whl|crate|jar|gem|nupkg|zip|vsix|crx|xpi|AppImage)$`),

	// nuget with dot-separated name + version (Microsoft.X.Y.Z.W.nupkg).
	// Non-greedy name so version grabs the trailing dotted-int sequence.
	regexp.MustCompile(`^(?P<name>.+?)\.(?P<version>\d[\w.+~-]*)\.nupkg$`),

	// portableapps installer: <Name>Portable_<version>.paf.exe.
	regexp.MustCompile(`^(?P<name>.+?)_(?P<version>\d[\w.+~-]*)\.paf\.exe$`),

	// generic last-ditch: any name-version.ext shape (dotted ext OK).
	regexp.MustCompile(`^(?P<name>.+?)-(?P<version>v?\d[\w.+~]*)\.[\w.]+$`),
}

// ParseFilename extracts package name, version, and — for the distro formats
// whose filenames carry one (deb/rpm/alpm) — the package architecture from a
// download filename. arch is the purl-spec `arch` qualifier value, "" when the
// format doesn't encode one (apk keeps it in the repository path). Returns
// ("", "", "") when no recognized format matches.
//
// Examples:
//
//	"lodash-4.17.21.tgz"             → ("lodash", "4.17.21", "")
//	"zfs-2.4.1-r0.apk"               → ("zfs", "2.4.1-r0", "")
//	"ztunnel-1.29-compat-1.29.0-r0.apk" → ("ztunnel-1.29-compat", "1.29.0-r0", "")
//	"curl-8.0.0-1.fc40.x86_64.rpm"   → ("curl", "8.0.0-1.fc40", "x86_64")
//	"wget_1.21.4-1ubuntu3_amd64.deb" → ("wget", "1.21.4-1ubuntu3", "amd64")
//	"python-3.12.0-1-x86_64.pkg.tar.zst" → ("python", "3.12.0-1", "x86_64")
//	"NotepadPPPortable_8.9.4.paf.exe" → ("NotepadPPPortable", "8.9.4", "")
//	"github.com-gorilla-mux-v1.8.1.zip" → ("github.com-gorilla-mux", "v1.8.1", "")
//	"cjpalhdlnbpafiamejdnhcphjbkeiagm.crx" → ("", "", "")  (no version)
//	"evil.exe"                        → ("", "", "")
func ParseFilename(filename string) (name, version, arch string) {
	for _, re := range filenamePatterns {
		m := re.FindStringSubmatch(filename)
		if m == nil {
			continue
		}
		nameIdx := re.SubexpIndex("name")
		versionIdx := re.SubexpIndex("version")
		if nameIdx <= 0 || versionIdx <= 0 {
			continue
		}
		if archIdx := re.SubexpIndex("arch"); archIdx > 0 {
			arch = m[archIdx]
		}
		return m[nameIdx], m[versionIdx], arch
	}
	return "", "", ""
}

// archiveExtensions are the suffixes VersionForName strips before splitting,
// compound forms first so ".tar.gz" wins over ".gz"-less ".tar".
var archiveExtensions = []string{
	".tar.gz", ".tar.bz2", ".tar.xz", ".tar.zst", ".paf.exe",
	".tgz", ".tar", ".whl", ".crate", ".jar", ".gem", ".nupkg",
	".zip", ".vsix", ".crx", ".xpi", ".AppImage", ".conda", ".apk",
}

// versionShape is the loose validity check for a name-anchored version tail:
// digit-led (optional "v"), then the usual version alphabet.
var versionShape = regexp.MustCompile(`^v?\d[\w.+~-]*$`)

// VersionForName extracts the version from a download filename when the
// package name is already known (e.g. from a forager path component or feed
// metadata), anchoring the split at the name instead of re-deriving both
// halves jointly. ParseFilename must guess the name/version boundary, and for
// digit-bearing names it guesses wrong: "@kl-starfish-test-01-1.0.0.tgz"
// splits at the first hyphen-digit, yielding version "01-1.0.0". With the
// name in hand there is no ambiguity: flatten it the way the download layouts
// do, strip it, and what remains (minus the archive extension) is the version.
//
// Flattenings tried, in order:
//
//	@scope/pkg	→ @scope-pkg   (npm scoped tarballs in forager layout)
//	@scope/pkg	→ scope__pkg   (jsr.io tarballs)
//	a/b/c      → a-b-c        (go module zips)
//	@scope/pkg	→ pkg          (npm registry-native tarball name)
//	name as-is
//
// Returns "" when the name doesn't prefix the filename or the remainder
// doesn't look like a version; callers should then fall back to
// ParseFilename's joint guess.
func VersionForName(filename, name string) string {
	if name == "" || filename == "" {
		return ""
	}
	// Only formats whose filenames are exactly <name><sep><version>.<ext>.
	// deb/rpm/alpm carry release+arch after the version; their anchored
	// ParseFilename patterns split them correctly, so defer to that.
	base := ""
	for _, ext := range archiveExtensions {
		if before, ok := strings.CutSuffix(filename, ext); ok {
			base = before
			break
		}
	}
	if base == "" {
		return ""
	}

	flat := strings.ReplaceAll(name, "/", "-")
	candidates := []string{
		flat,
		strings.ReplaceAll(strings.TrimPrefix(name, "@"), "/", "__"),
		strings.TrimPrefix(flat, "@"),
	}
	if i := strings.LastIndex(name, "/"); i >= 0 {
		candidates = append(candidates, name[i+1:])
	}
	candidates = append(candidates, name)

	for _, c := range candidates {
		for _, sep := range []string{"-", "_"} {
			rest, ok := strings.CutPrefix(base, c+sep)
			if !ok {
				continue
			}
			if versionShape.MatchString(rest) {
				return rest
			}
		}
	}
	return ""
}
