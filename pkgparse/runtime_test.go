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
