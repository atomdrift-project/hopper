//go:build freebsd && (amd64 || arm64)

package main

import (
	"os"
	"os/exec"
	"strconv"
	"strings"
	"testing"
)

// The kinfo_proc offsets must agree with ps(1), which reads the same record.
func TestProcMemoryBytesMatchesPS(t *testing.T) {
	got, err := procMemoryBytes(os.Getpid())
	if err != nil {
		t.Fatalf("procMemoryBytes(self) = %v", err)
	}
	out, err := exec.Command("ps", "-o", "rss=", "-p", strconv.Itoa(os.Getpid())).Output()
	if err != nil {
		t.Fatalf("ps: %v", err)
	}
	kb, err := strconv.ParseUint(strings.TrimSpace(string(out)), 10, 64)
	if err != nil {
		t.Fatalf("parse ps rss %q: %v", out, err)
	}
	// RSS moves between the two reads; a wrong offset is off by orders of magnitude.
	if want := kb << 10; got < want/2 || got > want*2 {
		t.Fatalf("procMemoryBytes(self) = %d bytes, ps says %d", got, want)
	}
}

func TestProcMemoryBytesNoSuchProcess(t *testing.T) {
	// Above PID_MAX (99999), so it can never exist.
	if _, err := procMemoryBytes(999999); err == nil {
		t.Fatal("procMemoryBytes(999999) succeeded, want error")
	}
}
