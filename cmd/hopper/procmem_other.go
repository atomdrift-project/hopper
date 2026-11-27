//go:build !linux && !(freebsd && (amd64 || arm64))

package main

import "errors"

// procMemoryBytes has no kernel source here; the watchdog says so once and
// leaves the budget to the worker's own throttle.
func procMemoryBytes(int) (uint64, error) {
	return 0, errors.ErrUnsupported
}
