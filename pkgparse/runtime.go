package pkgparse

import "strings"

// runtimeMap is the single source of truth for the registry/classifier →
// ecosystem taxonomy. Keys are the names that appear in samples.ecosystem
// (registry names, the dir-name classifiers used by the legacy harvest
// walker, file-type tags from the hash-corpus feeds, cleave's own type
// names, and already-canonical values); values are the ecosystem the
// software belongs to.
//
// OS distributions keep their own identity (arch, fedora, alpine, debian,
// freebsd, …) rather than folding into a generic "linux"/"bsd" — distro is
// the dimension consumers filter on. forager's EcosystemForLanguage
// delegates here, so the on-disk layout, forager's direct-insert, and
// hopper's reconcile walker all produce identical ecosystems.
//
// Examples:
//
//	"npm"      → "javascript"
//	"pypi"     → "python"
//	"aur"      → "arch"
//	"openvsx"  → "vscode"
//	"dll"      → "windows"   (file-type tag: no registry, so the OS answers)
//	"macho"    → "macos"
//	"pdf"      → "document"
//	"datasets" → "" (junk classifier; falls through to NormalizeEcosystem
//	                 which returns "" so callers can leave the field empty)
//
// The map's keys must match exactly (case-insensitive, leading/trailing
// whitespace trimmed). Use NormalizeEcosystem to apply it.
var runtimeMap = map[string]string{
	// Language registries.
	"npm":                "javascript",
	"jsr":                "javascript",
	"pypi":               "python",
	"conda":              "python",
	"rubygems":           "ruby",
	"crates":             "rust",
	"golang":             "go",
	"maven":              "java",
	"clojars":            "java",
	"nuget":              "dotnet",
	"powershell_gallery": "powershell",
	"packagist":          "php",
	"hex":                "erlang",
	"cpan":               "perl",
	"cran":               "r",
	"hackage":            "haskell",
	"pub":                "dart",
	"luarocks":           "lua",
	"wordpress":          "wordpress",
	// Application hosts.
	"vscode":    "vscode",
	"openvsx":   "vscode",
	"jetbrains": "jetbrains",
	"chrome":    "chrome",
	"edge":      "edge",
	"mozilla":   "firefox",
	// ML model hubs.
	"huggingface": "huggingface",
	// Agent skills.
	"skills_sh": "agent",
	"clawhub":   "openclaw",
	// OS targets. Distros keep their own identity; *_source variants fold
	// into their base distro.
	"homebrew":       "macos",
	"macupdate":      "macos",
	"freebsd":        "freebsd",
	"freebsd_source": "freebsd",
	"netbsd":         "netbsd",
	"netbsd_source":  "netbsd",
	"openbsd":        "openbsd",
	"openbsd_source": "openbsd",
	"alpine":         "alpine",
	"wolfi":          "wolfi",
	"debian":         "debian",
	"ubuntu":         "ubuntu",
	"fedora":         "fedora",
	"rpmfusion":      "fedora",
	"opensuse":       "opensuse",
	"guru":           "gentoo",
	"gentoo":         "gentoo",
	"arch":           "arch",
	"archlinux":      "arch",
	"aur":            "arch",
	"snap":           "snap",
	"scoop":          "windows",
	"winget":         "windows",
	"chocolatey":     "windows",
	"portableapps":   "windows",
	// Containers.
	"docker": "container",
	"oci":    "container",
	// Github.
	"github":         "github",
	"github_actions": "github",
	"github_repo":    "github",
	"github_release": "github",
	"repos":          "github",
	// Legacy file-extension classifiers from old harvest layout.
	"elf":    "linux",
	"sh":     "linux",
	"exe":    "windows",
	"ps1":    "windows",
	"office": "windows",
	"jar":    "java",
	"js":     "javascript",
	"web":    "javascript",
	// File-type tags. A hash-corpus provider (MalwareBazaar, tria.ge,
	// MalShare, vx-underground) has no registry to name, so what reaches this
	// table is the provider's own file-type tag or the sample's extension —
	// and for a sample hopper has already analyzed, cleave's type name. Both
	// vocabularies land here, which is why "pe" and "exe" both resolve: they
	// are the same fact spelled by two different tools.
	//
	// The answer is the OS that runs the bytes, not a registry, so these are
	// the one place the generic "windows"/"linux" values get produced. A tag
	// that names no single platform (zip, rar, 7z, iso, html, txt, xml, json,
	// svg, and the cross-platform scripting languages) is deliberately absent:
	// "" is the honest answer and the column stays empty.
	//
	// Watch for collisions when extending this block — a key here is also a
	// key for registries above. "pub" is Dart's registry, not Publisher;
	// "apk" is Android's package, not Alpine's (Alpine ships as "alpine");
	// "r" is the R language, not a file type.
	"pe":    "windows",
	"dll":   "windows",
	"msi":   "windows",
	"msp":   "windows",
	"appx":  "windows",
	"cab":   "windows",
	"nsis":  "windows",
	"lnk":   "windows",
	"chm":   "windows",
	"hta":   "windows",
	"scr":   "windows",
	"cpl":   "windows",
	"sys":   "windows",
	"reg":   "windows",
	"bat":   "windows",
	"cmd":   "windows",
	"psm1":  "windows",
	"psd1":  "windows",
	"vbs":   "windows",
	"vbe":   "windows",
	"vba":   "windows",
	"jse":   "windows",
	"wsf":   "windows",
	"pif":   "windows",
	"batch": "windows", // cleave's name for a .bat script
	"deb":   "linux",
	"rpm":   "linux", // shared by fedora/opensuse/rhel: the OS is the honest answer
	"shell": "linux", // cleave's name for a POSIX shell script; "sh" above is the legacy tag
	"so":    "linux",
	"macho": "macos",
	"dmg":   "macos",
	"apk":   "android",
	"dex":   "android",
	// Extension packages. These are registry artifacts, not corpus bytes, so
	// they resolve to the marketplace that ships them — a poisoned extension
	// is a supply-chain catch and has to keep its own sector.
	"crx":        "chrome",
	"xpi":        "firefox",
	"vsix":       "vscode",
	"java_class": "java",
	// Documents. A maldoc's runtime is a document reader, not an operating
	// system, so the office family and PDF get their own ecosystem rather
	// than folding into "windows" the way the legacy "office" classifier
	// does. "ole"/"cfb" are the container .doc and .xls ship inside.
	"pdf":  "document",
	"doc":  "document",
	"docm": "document",
	"docx": "document",
	"dot":  "document",
	"dotm": "document",
	"xls":  "document",
	"xlsb": "document",
	"xlsm": "document",
	"xlsx": "document",
	"ppt":  "document",
	"pptm": "document",
	"pptx": "document",
	"odt":  "document",
	"ods":  "document",
	"odp":  "document",
	"rtf":  "document",
	"one":  "document",
	"vsd":  "document",
	"eml":  "document",
	"msg":  "document",
	"ole":  "document",
	"cfb":  "document",
	// Already-canonical runtime names map to themselves.
	"javascript": "javascript",
	"python":     "python",
	"ruby":       "ruby",
	"rust":       "rust",
	"go":         "go",
	"java":       "java",
	"dotnet":     "dotnet",
	"powershell": "powershell",
	"php":        "php",
	"erlang":     "erlang",
	"perl":       "perl",
	"r":          "r",
	"haskell":    "haskell",
	"dart":       "dart",
	"lua":        "lua",
	"linux":      "linux",
	"bsd":        "bsd",
	"macos":      "macos",
	"windows":    "windows",
	"android":    "android",
	"document":   "document",
	"firefox":    "firefox",
	"agent":      "agent",
	"openclaw":   "openclaw",
	"container":  "container",
	// The distro ecosystems (arch, fedora, alpine, …) self-map via their
	// entries in the OS-targets block above, so re-normalizing a stored
	// distro value is already idempotent.
}

// NormalizeEcosystem maps a registry/classifier name to its canonical
// runtime ecosystem (what runs the software). Returns "" for unknown
// inputs so callers can decide how to handle them — the dashboard
// dropdown filters out empty values, and the walker stores empty as
// "no ecosystem known" rather than polluting the column.
//
// Case-insensitive; trims whitespace. Inputs that are already canonical
// (e.g. "javascript") map to themselves so the function is idempotent.
func NormalizeEcosystem(s string) string {
	s = strings.ToLower(strings.TrimSpace(s))
	if s == "" {
		return ""
	}
	return runtimeMap[s]
}
