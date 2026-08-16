//go:build freebsd

package main

import (
	"path/filepath"
	"syscall"
)

func isMountPoint(path string) (bool, string, error) {
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
