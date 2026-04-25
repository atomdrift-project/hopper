//go:build !linux

package main

import "syscall"

// statDev returns the device number as uint64. On non-Linux unix systems
// (notably darwin), Stat_t.Dev is int32, so a conversion is required. The
// value is used as an opaque cache key, so any well-defined Go conversion
// is correct.
func statDev(st *syscall.Stat_t) uint64 {
	return uint64(st.Dev) //nolint:gosec // Dev is opaque cache-key material; sign-extension is benign
}
