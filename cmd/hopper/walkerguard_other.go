//go:build !linux && !freebsd

package main

import "os/exec"

// dieWithParent is a no-op where the kernel offers no parent-death signal.
// Walkers are still stopped by context cancellation on an orderly shutdown;
// what is missing is only the guarantee after an abrupt one.
func dieWithParent(_ *exec.Cmd) {}
