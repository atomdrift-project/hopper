package pkgparse

import "testing"

func TestNormalizeEcosystem(t *testing.T) {
	tests := map[string]string{
		// Distros keep their own identity (not folded to linux/bsd).
		"arch":      "arch",
		"archlinux": "arch",
		"aur":       "arch",
		"fedora":    "fedora",
		"rpmfusion": "fedora",
		"alpine":    "alpine",
		"wolfi":     "wolfi",
		"debian":    "debian",
		"freebsd":   "freebsd",
		"netbsd":    "netbsd",
		"openbsd":   "openbsd",
		"macupdate": "macos",
		"homebrew":  "macos",
		// Language registries.
		"npm":    "javascript",
		"pypi":   "python",
		"crates": "rust",
		// Legacy classifiers still resolve to a runtime.
		"elf": "linux",
		"sh":  "linux",
		// Unknown clears.
		"datasets": "",
		"":         "",
	}
	for in, want := range tests {
		if got := NormalizeEcosystem(in); got != want {
			t.Errorf("NormalizeEcosystem(%q) = %q, want %q", in, got, want)
		}
	}

	// Case-insensitive and whitespace-trimmed.
	if got := NormalizeEcosystem("  AUR  "); got != "arch" {
		t.Errorf(`NormalizeEcosystem("  AUR  ") = %q, want "arch"`, got)
	}
}

// TestNormalizeEcosystemIdempotent guards against a canonical value being
// cleared on a second pass — the reconcile walker and normalize-ecosystems
// command both re-run the normalizer over stored values.
func TestNormalizeEcosystemIdempotent(t *testing.T) {
	for _, eco := range []string{"arch", "fedora", "alpine", "debian", "freebsd", "linux", "javascript", "python"} {
		if got := NormalizeEcosystem(eco); got != eco {
			t.Errorf("NormalizeEcosystem(%q) = %q, want %q (must be idempotent)", eco, got, eco)
		}
	}
}

// TestRuntimeMapValuesSelfMap derives the idempotency guard from the table
// itself: every ecosystem the map can produce must normalize to itself.
// Without this, adding "foo" → "bar" without a "bar" → "bar" self-map would
// silently clear stored "bar" values on the next reconcile pass.
func TestRuntimeMapValuesSelfMap(t *testing.T) {
	for in, out := range runtimeMap {
		if got := NormalizeEcosystem(out); got != out {
			t.Errorf("runtimeMap[%q] = %q, but NormalizeEcosystem(%q) = %q; add a %q self-map entry", in, out, out, got, out)
		}
	}
}

// TestNormalizeEcosystemFileTypes pins the file-type half of the table: a
// hash-corpus provider (MalwareBazaar, tria.ge, …) has no registry to name, so
// the tag it does supply has to answer with the OS that runs the bytes.
// Without these, every corpus sample landed with an empty ecosystem and the
// fallout log had no dimension to filter on.
func TestNormalizeEcosystemFileTypes(t *testing.T) {
	tests := map[string]string{
		// Windows-native, both spellings: cleave types a portable executable
		// "pe", MalwareBazaar tags the same bytes "exe".
		"pe":  "windows",
		"exe": "windows",
		"dll": "windows",
		"msi": "windows",
		"lnk": "windows",
		"vbs": "windows",
		"hta": "windows",
		"PS1": "windows", // case-folded
		// Other platforms. cleave spells a shell script "shell" and a .bat
		// "batch"; the corpus feeds' own tags are "sh" and "bat". Both
		// vocabularies have to land, or the sample keeps an empty ecosystem
		// and no filter can reach it.
		"shell": "linux",
		"sh":    "linux",
		"batch": "windows",
		"bat":   "windows",
		"rpm":   "linux",
		// Extension packages stay with their marketplace: a poisoned
		// extension is a supply-chain catch, not commodity malware.
		"crx":   "chrome",
		"xpi":   "firefox",
		"vsix":  "vscode",
		"elf":   "linux",
		"deb":   "linux",
		"macho": "macos",
		"dmg":   "macos",
		"apk":   "android",
		"dex":   "android",
		// Documents are a reader, not an OS.
		"pdf":  "document",
		"doc":  "document",
		"docx": "document",
		"xlsm": "document",
		"rtf":  "document",
		"ole":  "document",
		// Platform-agnostic containers and text stay empty: "" is the honest
		// answer, and the column is left alone rather than guessing.
		"zip":  "",
		"rar":  "",
		"7z":   "",
		"iso":  "",
		"html": "",
		"json": "",
	}
	for in, want := range tests {
		if got := NormalizeEcosystem(in); got != want {
			t.Errorf("NormalizeEcosystem(%q) = %q, want %q", in, got, want)
		}
	}
	// A provider's tag arrives with whatever spacing the feed gave it.
	if got := NormalizeEcosystem("  DLL  "); got != "windows" {
		t.Errorf(`NormalizeEcosystem("  DLL  ") = %q, want "windows"`, got)
	}
}

// TestFileTypeTagsDoNotShadowRegistries guards the one hazard in sharing a
// table between registry names and file-type tags: several tags are spelled
// exactly like a registry. Adding "pub" → document (Publisher) would silently
// break Dart, and "apk" → alpine would mislabel every Android sample. If a
// future tag collides, this test says so instead of the taxonomy quietly
// shifting under the feed.
func TestFileTypeTagsDoNotShadowRegistries(t *testing.T) {
	registries := map[string]string{
		"pub":    "dart",       // Dart's registry, not Microsoft Publisher
		"r":      "r",          // the R language, not a file type
		"jar":    "java",       // runtime, not a Windows payload
		"js":     "javascript", // runtime, not a dropper script
		"sh":     "linux",
		"alpine": "alpine", // Alpine ships .apk files; "apk" means Android here
		"npm":    "javascript",
		"debian": "debian", // distro keeps its identity; only the "deb" tag folds to linux
	}
	for in, want := range registries {
		if got := NormalizeEcosystem(in); got != want {
			t.Errorf("NormalizeEcosystem(%q) = %q, want %q — a file-type tag has shadowed a registry", in, got, want)
		}
	}
}
