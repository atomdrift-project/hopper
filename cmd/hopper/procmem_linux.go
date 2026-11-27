package main

import (
	"errors"
	"fmt"
	"os"
	"strconv"
	"strings"
)

// procMemoryBytes returns pid's VmRSS+VmSwap from /proc — the kernel's own
// accounting, immune to allocator-level undercounting inside the process.
// Swap is included because the service cgroup runs with a small swap quota:
// pages a bloated worker pushed there still hold the budget it was given.
func procMemoryBytes(pid int) (uint64, error) {
	data, err := os.ReadFile("/proc/" + strconv.Itoa(pid) + "/status")
	if err != nil {
		return 0, err
	}
	var kb uint64
	seen := false
	for line := range strings.Lines(string(data)) {
		if !strings.HasPrefix(line, "VmRSS:") && !strings.HasPrefix(line, "VmSwap:") {
			continue
		}
		fields := strings.Fields(line)
		if len(fields) < 2 {
			continue
		}
		v, err := strconv.ParseUint(fields[1], 10, 64) // value is in kB
		if err != nil {
			return 0, fmt.Errorf("parse %q: %w", strings.TrimSpace(line), err)
		}
		kb += v
		seen = true
	}
	if !seen {
		return 0, errors.New("no VmRSS line in /proc status")
	}
	return kb << 10, nil
}
