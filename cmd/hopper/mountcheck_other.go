//go:build !linux && !freebsd

package main

import (
	"os"
	"path/filepath"
)

// isMountPoint reports whether path is the root of a mounted filesystem, and
// names the device or remote it was mounted from when the platform can say.
func isMountPoint(path string) (mounted bool, source string, err error) {
	info, err := os.Stat(path)
	if err != nil {
		return false, "", err
	}
	parent, err := os.Stat(filepath.Dir(path))
	if err != nil {
		return false, "", err
	}
	dev, _ := fileStat(info)
	parentDev, _ := fileStat(parent)
	return dev != parentDev, "", nil
}
