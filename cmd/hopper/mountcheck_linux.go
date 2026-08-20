//go:build linux

package main

import (
	"bufio"
	"fmt"
	"os"
	"path/filepath"
	"slices"
	"strconv"
	"strings"
)

// isMountPoint reports whether path is the root of a mounted filesystem, and
// names the device or remote it was mounted from when the platform can say.
func isMountPoint(path string) (mounted bool, source string, err error) {
	want, err := filepath.EvalSymlinks(path)
	if err != nil {
		return false, "", err
	}
	f, err := os.Open("/proc/self/mountinfo")
	if err != nil {
		return false, "", err
	}
	defer f.Close() //nolint:errcheck // read-only proc file
	s := bufio.NewScanner(f)
	for s.Scan() {
		fields := strings.Fields(s.Text())
		if len(fields) < 10 {
			continue
		}
		mountpoint, err := unescapeMountField(fields[4])
		if err != nil || filepath.Clean(mountpoint) != filepath.Clean(want) {
			continue
		}
		sep := slices.Index(fields, "-")
		if sep < 0 || sep+2 >= len(fields) {
			return true, "", nil
		}
		return true, fields[sep+2], nil
	}
	return false, "", s.Err()
}

func unescapeMountField(s string) (string, error) {
	var out strings.Builder
	for i := 0; i < len(s); i++ {
		if s[i] != '\\' {
			out.WriteByte(s[i])
			continue
		}
		if i+3 >= len(s) {
			return "", fmt.Errorf("truncated mount escape %q", s[i:])
		}
		v, err := strconv.ParseUint(s[i+1:i+4], 8, 8)
		if err != nil {
			return "", err
		}
		out.WriteByte(byte(v))
		i += 3
	}
	return out.String(), nil
}
