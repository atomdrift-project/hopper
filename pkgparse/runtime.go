package pkgparse

import "strings"

// runtimeMap is the single source of truth for the registry/classifier →
// ecosystem taxonomy. Keys are the names that appear in samples.ecosystem
// (registry names, the dir-name classifiers used by the legacy harvest
// walker, and already-canonical values); values are the ecosystem the
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
//	"datasets" → "" (junk classifier; falls through to NormalizeEcosystem
//	                 which returns "" so callers can leave the field empty)
//
// The map's keys must match exactly (case-insensitive, leading/trailing
// whitespace trimmed). Use NormalizeEcosystem to apply it.
var runtimeMap = map[string]string{
	// Language registries.
	"npm":                "javascript",
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
	"vscode":  "vscode",
	"openvsx": "vscode",
	"chrome":  "chrome",
	"edge":    "edge",
	"mozilla": "firefox",
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
	"fedora":         "fedora",
	"rpmfusion":      "fedora",
	"arch":           "arch",
	"archlinux":      "arch",
	"aur":            "arch",
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
