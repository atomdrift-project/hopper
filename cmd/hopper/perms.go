package main

import (
	"errors"
	"io/fs"
	"os"
	"path/filepath"
)

// sharedDirMode is setgid + rwxrwxr-x. /data/samples is shared by forager,
// hopper, and promoter, which all run in the samples group, so directories must
// be group-writable, and setgid makes new children inherit the samples group.
const sharedDirMode = os.ModeSetgid | 0o775

// sampleFileMode is the read-only mode for uploaded sample files on disk:
// owner- and group-readable, never writable, never world-readable. The shared
// 'samples' group (forager, hopper, promoter) can read them via the setgid
// upload dirs; nothing outside the group needs to. (os.CreateTemp defaults to
// 0600, which would otherwise leave an uploaded sample readable only by hopper.)
const sampleFileMode os.FileMode = 0o440

// mkdirSharedAll creates path and its parents, forcing sharedDirMode on every
// component it creates — a plain mkdir is subject to umask (which strips
// group-write) and does not reliably set setgid. Pre-existing directories,
// including any owned by another service sharing the tree, are left as-is: a
// chmod EPERM on the already-existing target is ignored, never fatal.
func mkdirSharedAll(path string) error {
	abs, err := filepath.Abs(path)
	if err != nil {
		return err
	}
	// Topmost component that does not yet exist; that and everything below it
	// are what os.MkdirAll is about to create and we therefore own.
	// G703 nolints below: callers pass paths validated by resolveDataPath to
	// stay within the data root, so these are not attacker-controlled traversals.
	firstNew := ""
	for p := abs; p != "/" && p != "."; p = filepath.Dir(p) {
		if _, err := os.Stat(p); err == nil {
			break
		}
		firstNew = p
	}
	if err := os.MkdirAll(abs, sharedDirMode); err != nil {
		return err
	}
	if firstNew == "" {
		// Whole path pre-existed; align the target best-effort.
		err := os.Chmod(abs, sharedDirMode)
		if err != nil && !errors.Is(err, fs.ErrPermission) {
			return err
		}
		return nil
	}
	for p := abs; ; p = filepath.Dir(p) {
		if err := os.Chmod(p, sharedDirMode); err != nil {
			return err
		}
		if p == firstNew {
			return nil
		}
	}
}
