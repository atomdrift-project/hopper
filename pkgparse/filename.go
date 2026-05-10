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

import "regexp"

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

	// alpine/wolfi apk: <name>-<version>-r<rel>.apk.
	regexp.MustCompile(`^(?P<name>.+)-(?P<version>\d+\.\S*-r\d+)\.apk$`),

	// debian deb: <name>_<version>_<arch>.deb.
	regexp.MustCompile(`^(?P<name>[^_]+)_(?P<version>[^_]+)_[^_]+\.deb$`),

	// rpm: <name>-<version>-<release>.<arch>.rpm. Combine version+release.
	regexp.MustCompile(`^(?P<name>.+)-(?P<version>\d[\w.+~]*-[\w.+~]+)\.[\w_]+\.rpm$`),

	// archlinux .pkg.tar.zst: <name>-<version>-<release>-<arch>.pkg.tar.zst
	regexp.MustCompile(`^(?P<name>.+)-(?P<version>\d[\w.+~]*-\d+)-[\w_]+\.pkg\.tar\.[\w]+$`),

	// conda: <name>-<version>-<build>.conda.
	regexp.MustCompile(`^(?P<name>.+)-(?P<version>\d[\w.+~]*-[\w._+~]+)\.conda$`),

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
	regexp.MustCompile(`^(?P<name>.+?)-(?P<version>v?\d[\w.+~-]*)\.(?:tgz|tar\.gz|tar\.bz2|tar\.xz|tar\.zst|tar|whl|crate|jar|gem|nupkg|zip|vsix|crx|xpi|AppImage)$`),

	// nuget with dot-separated name + version (Microsoft.X.Y.Z.W.nupkg).
	// Non-greedy name so version grabs the trailing dotted-int sequence.
	regexp.MustCompile(`^(?P<name>.+?)\.(?P<version>\d[\w.+~-]*)\.nupkg$`),

	// portableapps installer: <Name>Portable_<version>.paf.exe.
	regexp.MustCompile(`^(?P<name>.+?)_(?P<version>\d[\w.+~-]*)\.paf\.exe$`),

	// generic last-ditch: any name-version.ext shape (dotted ext OK).
	regexp.MustCompile(`^(?P<name>.+?)-(?P<version>v?\d[\w.+~]*)\.[\w.]+$`),
}

// ParseFilename extracts package name and version from a download
// filename. Returns ("", "") when no recognized format matches.
//
// Examples:
//
//	"lodash-4.17.21.tgz"             → ("lodash", "4.17.21")
//	"zfs-2.4.1-r0.apk"               → ("zfs", "2.4.1-r0")
//	"ztunnel-1.29-compat-1.29.0-r0.apk" → ("ztunnel-1.29-compat", "1.29.0-r0")
//	"curl-8.0.0-1.fc40.x86_64.rpm"   → ("curl", "8.0.0-1.fc40")
//	"wget_1.21.4-1ubuntu3_amd64.deb" → ("wget", "1.21.4-1ubuntu3")
//	"NotepadPPPortable_8.9.4.paf.exe" → ("NotepadPPPortable", "8.9.4")
//	"github.com-gorilla-mux-v1.8.1.zip" → ("github.com-gorilla-mux", "v1.8.1")
//	"cjpalhdlnbpafiamejdnhcphjbkeiagm.crx" → ("", "")  (no version)
//	"evil.exe"                        → ("", "")
func ParseFilename(filename string) (name, version string) {
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
		return m[nameIdx], m[versionIdx]
	}
	return "", ""
}
