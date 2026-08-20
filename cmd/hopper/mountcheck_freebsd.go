//go:build freebsd

package main

import (
	"path/filepath"
	"syscall"
)

// isMountPoint reports whether path is the root of a mounted filesystem, and
// names the device or remote it was mounted from when the platform can say.
func isMountPoint(path string) (mounted bool, source string, err error) {
	var st syscall.Statfs_t
	if err := syscall.Statfs(path, &st); err != nil {
		return false, "", err
	}
	mountedAt := int8String(st.Mntonname[:])
	return filepath.Clean(mountedAt) == filepath.Clean(path), int8String(st.Mntfromname[:]), nil
}

func int8String(in []int8) string {
	out := make([]byte, 0, len(in))
	for _, c := range in {
		if c == 0 {
			break
		}
		out = append(out, byte(c))
	}
	return string(out)
}
