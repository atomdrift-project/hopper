//go:build linux || freebsd

package main

import (
	"os/exec"
	"syscall"
)

// dieWithParent asks the kernel to kill the walker when hopper dies, however
// hopper dies.
//
// exec.CommandContext already stops a walker on an orderly shutdown, but that
// path needs a parent alive to run it. An abrupt death leaves the walker
// running, holding the sample tree's disks for as long as it takes to finish a
// pass nobody is reading any more. Measured 2026-08-24: thirty-six orphaned
// enumerations from nineteen previous incarnations, the oldest eleven hours
// old, between them saturating the pool that result ingestion, corpus lookups
// and logical replication all read from.
//
// The known hazard is that the signal is armed against the death of the thread
// that forked, not the process, and Go may retire that thread. The cost if it
// fires early is bounded and already handled: the walk ends, whatever it
// emitted stays emitted, `cleave iter-files exited with error` is logged, and
// the next pass picks up the rest. The cost of not arming it is the outage
// above.
func dieWithParent(cmd *exec.Cmd) {
	if cmd.SysProcAttr == nil {
		cmd.SysProcAttr = &syscall.SysProcAttr{}
	}
	cmd.SysProcAttr.Pdeathsig = syscall.SIGKILL
}
