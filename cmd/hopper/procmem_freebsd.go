//go:build freebsd && (amd64 || arm64)

package main

import (
	"encoding/binary"
	"fmt"
	"os"

	"golang.org/x/sys/unix"
)

// Offsets into the 64-bit struct kinfo_proc (sys/user.h). Its layout is ABI —
// KINFO_PROC_SIZE is fixed so ps(1) and top(1) work across releases — and the
// pid check below catches a mismatch rather than reading garbage.
const (
	kinfoPIDOffset    = 72  // ki_pid
	kinfoRSSizeOffset = 264 // ki_rssize, in pages
)

// procMemoryBytes returns pid's resident set size from kern.proc.pid, the
// record ps(1) reads. FreeBSD keeps no per-process swap figure, so unlike Linux
// this is RSS alone.
//
// FreeBSD hosts have no /proc. Until this existed the watchdog read it, failed,
// took the error for an exited process, and never enforced the budget: smaug's
// worker ran at 59 GB against 48 with nothing watching.
func procMemoryBytes(pid int) (uint64, error) {
	kp, err := unix.SysctlRaw("kern.proc.pid", pid)
	if err != nil {
		return 0, fmt.Errorf("kern.proc.pid.%d: %w", pid, err)
	}
	if len(kp) < kinfoRSSizeOffset+8 {
		return 0, fmt.Errorf("kern.proc.pid.%d: %d-byte kinfo_proc is too short", pid, len(kp))
	}
	if got := int32(binary.NativeEndian.Uint32(kp[kinfoPIDOffset:])); int(got) != pid { //nolint:gosec // ki_pid is a pid_t
		return 0, fmt.Errorf("kern.proc.pid.%d: kinfo_proc names pid %d; layout changed?", pid, got)
	}
	pages := binary.NativeEndian.Uint64(kp[kinfoRSSizeOffset:])
	return pages * uint64(os.Getpagesize()), nil //nolint:gosec // page size is positive
}
