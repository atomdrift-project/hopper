//go:build linux

package main

import "syscall"

// statDev returns the device number as uint64. On Linux, Stat_t.Dev is
// already uint64, so this is a direct read.
func statDev(st *syscall.Stat_t) uint64 { return st.Dev }
