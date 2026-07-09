package main

import (
	"os"
	"testing"
)

func TestProcMemoryBytesSelf(t *testing.T) {
	if _, err := os.Stat("/proc/self/status"); err != nil {
		t.Skip("no /proc on this platform")
	}
	got, err := procMemoryBytes(os.Getpid())
	if err != nil {
		t.Fatalf("procMemoryBytes(self) = %v", err)
	}
	// A running Go test binary has at least a few hundred kB resident and
	// well under a terabyte; anything outside that means the kB parse or the
	// field selection is wrong (e.g. reading VmSize or dropping the unit).
	if got < 100<<10 || got > 1<<40 {
		t.Fatalf("procMemoryBytes(self) = %d bytes, implausible for a test binary", got)
	}
}

func TestProcMemoryBytesNoSuchPID(t *testing.T) {
	if _, err := os.Stat("/proc/self/status"); err != nil {
		t.Skip("no /proc on this platform")
	}
	// PID 0 never has a /proc entry.
	if _, err := procMemoryBytes(0); err == nil {
		t.Fatal("procMemoryBytes(0) succeeded, want error")
	}
}
