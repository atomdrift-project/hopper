package hopper

import (
	"path/filepath"
	"strings"
	"testing"
)

// TestResolveMovePathSystemdEscapedName pins the case that stranded the hot pool:
// systemd escapes "-" as \x2d in unit names, so an exploded OS image contains
// files whose names carry a literal backslash. Those are ordinary filenames on
// Unix and must resolve, or draino re-feeds them forever and the pool never drains.
func TestResolveMovePathSystemdEscapedName(t *testing.T) {
	if filepath.Separator == '\\' {
		t.Skip("backslash is a separator on this platform")
	}
	root := t.TempDir()
	rel := `incoming/forager/cachyos/airootfs.sfs.d/usr/lib/systemd/system/system-systemd\x2dcryptsetup.slice`

	gotRoot, resolved, err := resolveMovePath(root, rel)
	if err != nil {
		t.Fatalf("resolveMovePath(%q) = error %v, want success", rel, err)
	}
	if want := filepath.Clean(root); gotRoot != want {
		t.Errorf("root = %q, want %q", gotRoot, want)
	}
	if want := filepath.Join(filepath.Clean(root), rel); resolved != want {
		t.Errorf("resolved = %q, want %q", resolved, want)
	}
	if !strings.HasPrefix(resolved, filepath.Clean(root)+string(filepath.Separator)) {
		t.Errorf("resolved %q escaped root %q", resolved, root)
	}
}

// TestResolveMovePathRejectsTraversal confirms that relaxing the backslash rule
// did not weaken containment, which is what the check was really there for.
// Note that `..\..\outside` is deliberately absent: on Unix that is one legal
// filename component, not a traversal, and Join keeps it under root.
func TestResolveMovePathRejectsTraversal(t *testing.T) {
	root := t.TempDir()
	for _, rel := range []string{
		"",
		"/etc/passwd",
		"../outside",
		"incoming/../../outside",
		"incoming/./doubled",
	} {
		if _, _, err := resolveMovePath(root, rel); err == nil {
			t.Errorf("resolveMovePath(%q) = nil error, want rejection", rel)
		}
	}
}
