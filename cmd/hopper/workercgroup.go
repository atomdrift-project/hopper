package main

import (
	"errors"
	"fmt"
	"io/fs"
	"log/slog"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"sync/atomic"
)

// workercgroup.go carves a delegated cgroup v2 subtree so the kernel — not
// just 1-minute supervision — bounds the scan workers' memory:
//
//	hopper.service/            (systemd-delegated: Delegate=memory)
//	├── master/   hopper itself, memory.min-protected
//	└── workers/  litmus + cleave children, hard memory.max, oom.group=1
//
// Why: in the 2026-07-09 incident a worker outgrew its budget by 25 GB of
// off-heap memory and the shared cgroup's reclaim evicted the *master's*
// executable pages — the broker died for the workers' sins. With this split
// the kernel accounts the entire worker process tree (including rizin/yara
// grandchildren that pid-level supervision can't see, and whatever they
// allocate after entering workers/), OOM-kills the whole tree together the
// instant it blows its cap (memory.oom.group), and the master's working set
// is never on the same reclaim LRU.
//
// Everything here is best-effort: without a delegated subtree (laptop runs,
// non-systemd rc.d, missing cgroup2) setup logs at debug and hopper behaves
// exactly as before — the litmusServer RSS watchdog remains as the portable
// second line of defense.

const (
	// workerCgroupSlack scales --max-rss-gb into workers/memory.max. It sits
	// above the watchdog's rssKillFactor on purpose: the supervised kill
	// captures a SIGUSR1 backtrace first and is the preferred path, so the
	// kernel line only fires for growth too fast for a 1-minute poll.
	workerCgroupSlack = 1.5
	// masterMemoryMin is carved out for hopper's own working set (text +
	// heap; live heap is ~tens of MB, RSS spikes are reclaimable MADV_FREE
	// pages). Service-level reclaim triggered by worker pressure skips
	// memory below this floor, so the accept loops keep their pages.
	masterMemoryMin = uint64(1) << 30
)

// workerCgroupDir holds the workers/ cgroup path once delegation succeeds;
// nil means isolation is off. Children are spawned normally and then moved
// in via cgroup.procs (see moveToWorkerCgroup) rather than cloned in with
// CLONE_INTO_CGROUP: the unit's SystemCallFilter seccomp policy ENOSYSes
// clone3 (observed on the 2026-07-09 deploy — every spawn failed with
// "function not implemented"), and a microseconds-wide window in master/
// before the move is a far better trade than depending on the seccomp
// allowlist knowing clone3 on every host.
var workerCgroupDir atomic.Pointer[string]

// setupWorkerCgroup builds the subtree and publishes the workers/ fd. Call
// once, before the first worker spawn. budgetGB is --max-rss-gb; with no
// budget (<=0) the workers get no hard cap but still land in their own
// cgroup, which alone keeps their reclaim pressure off the master's floor.
func setupWorkerCgroup(budgetGB int) {
	base, err := ownCgroupDir()
	if err != nil {
		slog.Debug("worker cgroup isolation off: cannot resolve own cgroup", "error", err)
		return
	}
	master := filepath.Join(base, "master")
	workers := filepath.Join(base, "workers")
	if err := mkdirAllowExist(master); err != nil {
		// The common, expected case: not a delegated subtree (no systemd,
		// Delegate= unset), so the mkdir is denied. Not a fault.
		slog.Debug("worker cgroup isolation off: subtree not writable (Delegate= unset?)", "error", err)
		return
	}
	if err := mkdirAllowExist(workers); err != nil {
		slog.Warn("worker cgroup isolation off: cannot create workers/", "error", err)
		return
	}
	// Adopt the master role before enabling controllers: cgroup v2 forbids
	// processes in a cgroup that has controller-enabled children ("no
	// internal processes"), so the order is move → enable → configure.
	if err := os.WriteFile(filepath.Join(master, "cgroup.procs"), []byte(strconv.Itoa(os.Getpid())), 0); err != nil {
		slog.Warn("worker cgroup isolation off: cannot enter master/", "error", err)
		return
	}
	if err := os.WriteFile(filepath.Join(base, "cgroup.subtree_control"), []byte("+memory"), 0); err != nil {
		// Undo the self-move so we don't sit in an unconfigured child.
		if mvErr := os.WriteFile(filepath.Join(base, "cgroup.procs"), []byte(strconv.Itoa(os.Getpid())), 0); mvErr != nil {
			slog.Warn("could not move back out of master/ after failed delegation", "error", mvErr)
		}
		slog.Warn("worker cgroup isolation off: cannot enable memory controller (Delegate=memory needed)", "error", err)
		return
	}
	// Configuration below is genuinely best-effort: the structural win (own
	// LRU + whole-tree accounting for workers) exists as soon as children
	// spawn into workers/, caps or not.
	if err := os.WriteFile(filepath.Join(master, "memory.min"), fmt.Appendf(nil, "%d", masterMemoryMin), 0); err != nil {
		slog.Warn("could not set master memory.min", "error", err)
	}
	if budgetGB > 0 {
		capBytes := uint64(float64(uint64(budgetGB)<<30) * workerCgroupSlack)
		if err := os.WriteFile(filepath.Join(workers, "memory.max"), fmt.Appendf(nil, "%d", capBytes), 0); err != nil {
			slog.Warn("could not set workers memory.max", "error", err)
		}
	}
	// One worker tree lives or dies together: a partial OOM kill inside
	// litmus (say, one rizin child) leaves a wedged half-worker that the
	// liveness watchdog takes 25 minutes to notice. Group kill + supervisor
	// restart is faster and cleaner.
	if err := os.WriteFile(filepath.Join(workers, "memory.oom.group"), []byte("1"), 0); err != nil {
		slog.Warn("could not set workers memory.oom.group", "error", err)
	}
	workerCgroupDir.Store(&workers)
	slog.Info("worker cgroup isolation on", "workers", workers, "budget_gb", budgetGB, "slack", workerCgroupSlack)
}

// moveToWorkerCgroup migrates a freshly spawned child into the workers/
// cgroup. No-op when delegation is off. Best-effort: on failure the child
// simply stays in master/, where the litmusServer RSS watchdog still bounds
// it — log and carry on, never fail the spawn over accounting placement.
func moveToWorkerCgroup(pid int) {
	dir := workerCgroupDir.Load()
	if dir == nil {
		return
	}
	if err := os.WriteFile(filepath.Join(*dir, "cgroup.procs"), []byte(strconv.Itoa(pid)), 0); err != nil {
		slog.Warn("could not move child into workers cgroup", "pid", pid, "error", err)
	}
}

// ownCgroupDir returns this process's cgroup v2 directory under the unified
// hierarchy mount.
func ownCgroupDir() (string, error) {
	data, err := os.ReadFile("/proc/self/cgroup")
	if err != nil {
		return "", err
	}
	rel, err := parseCgroupV2Path(string(data))
	if err != nil {
		return "", err
	}
	return "/sys/fs/cgroup" + rel, nil // rel always starts with "/"
}

// parseCgroupV2Path extracts the v2 (unified) entry — "0::<path>" — from
// /proc/self/cgroup content. Split out for testability.
func parseCgroupV2Path(content string) (string, error) {
	for line := range strings.Lines(content) {
		if rel, ok := strings.CutPrefix(strings.TrimSpace(line), "0::"); ok {
			if rel == "" || !strings.HasPrefix(rel, "/") {
				return "", errors.New("malformed cgroup v2 entry: " + strings.TrimSpace(line))
			}
			return rel, nil
		}
	}
	return "", errors.New("no cgroup v2 entry in /proc/self/cgroup")
}

func mkdirAllowExist(path string) error {
	// Mode is nominal: cgroupfs assigns its own file ownership/permissions.
	if err := os.Mkdir(path, 0o750); err != nil && !errors.Is(err, fs.ErrExist) {
		return err
	}
	return nil
}
