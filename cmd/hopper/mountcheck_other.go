//go:build !linux && !freebsd

package main

import (
	"os"
	"path/filepath"
)

func isMountPoint(path string) (bool, string, error) {
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
