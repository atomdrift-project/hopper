package main

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"syscall"
	"time"

	"github.com/atomdrift-project/hopper"
)

// litmusServer manages a local litmus worker subprocess. In pull mode,
// litmus polls hopper's /api/next for work instead of hopper pushing
// requests to it.
const (
	restartRecoveryDelay = 15 * time.Second
	litmusTmpSentinel    = ".hopper-litmus-managed"
	livenessTimeout      = 25 * time.Minute
	// startupTimeout is the budget for a freshly spawned worker to check in
	// for the very first time, and is deliberately far longer than
	// livenessTimeout. The two measure different things: livenessTimeout only
	// has to cover the gap between two polls of a worker already in its steady
	// state, while startup does bounded-but-slow work that scales with the
	// corpus and the host — rule compilation, model load, and building the
	// local sample index. Charging that against the wedge timeout is a
	// deadlock: on 2026-08-01 a 3.5 M-file data dir on a saturated spindle
	// took longer to index than the 25 min wedge window, so the worker was
	// SIGKILLed mid-walk and restarted forever, never once polling for work.
	startupTimeout = 2 * time.Hour
	// wedgeDumpDelay is how long the liveness watchdog waits after sending
	// SIGUSR1 (which makes litmus dump every thread's backtrace to its log)
	// before SIGKILLing a wedged worker, so the dump has time to flush.
	wedgeDumpDelay = 10 * time.Second
	// rssKillFactor is how far past --max-rss-gb the worker's kernel-reported
	// memory (VmRSS+VmSwap) may grow before the watchdog kills it. litmus
	// throttles itself against the budget, but its accounting is
	// allocator-level and misses off-heap growth (mmap'd archives, native
	// libs): a 2026-07-09 incident had the worker at 73 GB against a 48 GB
	// budget while self-reporting 40 GB, pinning the service cgroup into
	// memory.high direct-reclaim purgatory that starved hopper's own accept
	// loops. The margin leaves the worker's own throttle room to work; only a
	// blowout it demonstrably isn't handling triggers the kill.
	rssKillFactor = 1.25
	// rssKillStrikes is how many consecutive watchdog ticks (1/min) the
	// worker must be over budget before it is killed, so a transient spike
	// from one huge archive isn't a death sentence.
	rssKillStrikes = 2
	// litmusLogMaxAge bounds how long a departed worker's stdout/stderr log is
	// kept. Every spawn opens a fresh litmus-*.log and a --verbose worker emits
	// 0.5-1.3 GB apiece, so nothing reclaimed them: on 2026-08-10 a worker
	// crash-looping since 08-04 had left 3,579 files totalling 14 GB. Two days
	// keeps the previous night's crash available to debug while bounding the
	// directory to what a sustained restart loop can produce in that window.
	litmusLogMaxAge = 48 * time.Hour
	// litmusLogSweepInterval is how often the liveness watchdog ages out logs.
	// Spawns sweep too, but a worker healthy for days would never trigger one,
	// so retention cannot rest on restarts alone.
	litmusLogSweepInterval = 1 * time.Hour
)

type litmusServer struct {
	cmd        *exec.Cmd
	tracker    *workerTracker                    // for liveness checks
	logPath    atomic.Pointer[string]            // current worker's stdout/stderr log file
	health     atomic.Pointer[localWorkerHealth] // published for the dashboard banner
	bin        string                            // path to litmus binary
	hopperURL  string                            // hopper API base URL for the worker to poll
	dataDir    string                            // data root for --data-dir
	llmURL     string                            // --interpret endpoint (SCAN_LLM); empty leaves the pass off
	workerName string                            // qualified name used to look up in tracker
	tmpDir     string
	pid        atomic.Int64
	spawnedAt  atomic.Int64 // UnixNano when the current process started; 0 if none
	restarts   atomic.Int64
	mu         sync.Mutex
	maxRSSGB   int
	maxWorkers int
	stopped    atomic.Bool
	building   atomic.Bool
	verbose    bool
}

// localWorkerHealth is the current state of the in-process scan (atomscan) worker,
// published for the web dashboard's status banner. since marks when the present
// ok-state began, so a persistent failure shows a stable "down since <time>".
// detail holds the last few log/output lines for the failure so the banner is
// enough to debug from without SSHing to read the worker log.
type localWorkerHealth struct {
	since  time.Time
	reason string
	detail string
	ok     bool
}

// setHealth publishes the worker's health. reason is a one-line summary; detail
// is the recent log/output tail (may be empty). since is preserved while the
// ok-state is unchanged, so an ongoing failure keeps its original onset stamp.
func (s *litmusServer) setHealth(ok bool, reason, detail string) {
	since := time.Now()
	if prev := s.health.Load(); prev != nil && prev.ok == ok {
		since = prev.since
	}
	s.health.Store(&localWorkerHealth{ok: ok, reason: reason, detail: detail, since: since})
}

// healthSnapshot returns the published worker health, or nil if never set.
func (s *litmusServer) healthSnapshot() *localWorkerHealth { return s.health.Load() }

// workerLogTail returns the last n lines of the current worker's log file, for
// the dashboard banner's failure detail. Empty if there is no log yet.
func (s *litmusServer) workerLogTail(n int) string {
	if p := s.logPath.Load(); p != nil {
		return lastNLines(tailLogFile(*p), n)
	}
	return ""
}

// litmusConfig holds options for starting a litmus worker.
type litmusConfig struct {
	Bin        string // path to the Atomdrift Scan binary (codename: litmus); default "atomscan"
	HopperURL  string // hopper API URL (e.g. http://127.0.0.1:8081)
	DataDir    string // data root for local file access
	LLMURL     string // OpenAI-compatible endpoint for the --interpret pass; empty disables it
	MaxRSSGB   int    // memory limit in GB (0 = let litmus decide, -1 = disable in-process throttling)
	MaxWorkers int    // max concurrent analysis workers
	Verbose    bool   // enable debug logging in litmus
}

func newLitmusServer(cfg litmusConfig) *litmusServer {
	if cfg.Bin == "" {
		cfg.Bin = "atomscan"
	}
	if cfg.MaxWorkers < 1 {
		cfg.MaxWorkers = max(2, runtime.NumCPU()/2)
	}
	return &litmusServer{
		bin:        cfg.Bin,
		hopperURL:  cfg.HopperURL,
		dataDir:    cfg.DataDir,
		llmURL:     cfg.LLMURL,
		maxRSSGB:   cfg.MaxRSSGB,
		maxWorkers: cfg.MaxWorkers,
		verbose:    cfg.Verbose,
	}
}

func closeLogFile(name string, f *os.File) {
	if f == nil {
		return
	}
	if err := f.Close(); err != nil {
		slog.Warn("failed to close litmus log file", "log", sanitizeLogString(name), "error", err)
	}
}

// tailLogFile returns the last few lines of path, capped at maxBytes bytes
// and maxLines lines. Returns "" on any error so callers can include it
// unconditionally in a slog record.
func tailLogFile(path string) string {
	if path == "" {
		return ""
	}
	const (
		maxBytes = 4096
		maxLines = 30
	)
	f, err := os.Open(path)
	if err != nil {
		return ""
	}
	defer f.Close() //nolint:errcheck // best-effort read
	fi, err := f.Stat()
	if err != nil {
		return ""
	}
	size := fi.Size()
	offset := int64(0)
	if size > maxBytes {
		offset = size - maxBytes
	}
	buf := make([]byte, size-offset)
	n, _ := f.ReadAt(buf, offset) //nolint:errcheck // partial read is fine; n==0 below filters empty
	if n == 0 {
		return ""
	}
	if n == 0 {
		return ""
	}
	out := string(buf[:n])
	// If we seeked into the middle of a line, drop the partial first line.
	if offset > 0 {
		if i := strings.IndexByte(out, '\n'); i >= 0 {
			out = out[i+1:]
		}
	}
	out = strings.TrimRight(out, "\n")
	if out == "" {
		return ""
	}
	lines := strings.Split(out, "\n")
	if len(lines) > maxLines {
		lines = lines[len(lines)-maxLines:]
	}
	return sanitizeLogString(strings.Join(lines, "\n"))
}

func sanitizeLogString(s string) string {
	return strings.Map(func(r rune) rune {
		if r < ' ' && r != '\t' {
			return -1
		}
		return r
	}, s)
}

// killGroup sends sig to the process group led by pid. Litmus is started
// with Setpgid so its rizin/yara children share the group; signaling the
// group guarantees we don't leak descendants when tearing the worker down.
// ESRCH (group already gone) is treated as success.
func killGroup(reason string, pid int, sig syscall.Signal, attrs ...any) {
	if pid <= 0 {
		return
	}
	if err := syscall.Kill(-pid, sig); err != nil && !errors.Is(err, syscall.ESRCH) {
		slog.Warn(reason, append(attrs, "pid", pid, "signal", sig.String(), "error", err)...)
	}
}

func (s *litmusServer) currentPID() int {
	return int(s.pid.Load())
}

// spawnTime reports when the current litmus process started, or the zero
// time if none is running. The watchdog treats a fresh start as activity so
// a just-restarted process is never judged by the previous process's
// heartbeat.
func (s *litmusServer) spawnTime() time.Time {
	ns := s.spawnedAt.Load()
	if ns == 0 {
		return time.Time{}
	}
	return time.Unix(0, ns)
}

func (s *litmusServer) ensureTmpDirLocked() (string, error) {
	if s.tmpDir == "" {
		dir, err := os.MkdirTemp("", "hopper-litmus-*")
		if err != nil {
			return "", fmt.Errorf("create litmus tmp dir: %w", err)
		}
		s.tmpDir = dir
		if err := ensureLitmusTmpSentinel(filepath.Join(dir, litmusTmpSentinel)); err != nil {
			return "", fmt.Errorf("stamp litmus tmp dir: %w", err)
		}
		sweepStaleLitmusTmpDirs(dir)
	} else if err := ensureLitmusTmpSentinel(filepath.Join(s.tmpDir, litmusTmpSentinel)); err != nil {
		return "", fmt.Errorf("stamp litmus tmp dir: %w", err)
	}

	sweepLitmusTmpChildren(s.tmpDir, 0)
	return s.tmpDir, nil
}

func ensureLitmusTmpSentinel(path string) error {
	if info, err := os.Lstat(path); err == nil {
		if info.Mode()&os.ModeNamedPipe != 0 {
			return nil
		}
		_ = os.Remove(path) //nolint:errcheck // replace legacy/foreign regular marker
	}
	if err := syscall.Mkfifo(path, 0o600); err != nil && !errors.Is(err, syscall.EEXIST) {
		return fmt.Errorf("mkfifo %s: %w", path, err)
	}
	return nil
}

func safeRemoveLitmusTmpDir(path, root string) {
	cleanPath := filepath.Clean(path)
	cleanRoot := filepath.Clean(root)
	if cleanPath == "" || cleanPath == cleanRoot || filepath.Dir(cleanPath) != cleanRoot {
		slog.Warn("refusing to remove litmus tmp dir outside tmp root", "path", cleanPath, "root", cleanRoot)
		return
	}
	if info, err := os.Lstat(cleanPath); err != nil {
		if !errors.Is(err, os.ErrNotExist) {
			slog.Warn("stat litmus tmp dir failed", "path", cleanPath, "error", err)
		}
		return
	} else if !info.IsDir() || info.Mode()&os.ModeSymlink != 0 {
		slog.Warn("refusing to remove non-directory litmus tmp path", "path", cleanPath)
		return
	}
	if _, err := os.Stat(filepath.Join(cleanPath, litmusTmpSentinel)); err != nil {
		slog.Warn("refusing to remove litmus tmp dir without sentinel", "path", cleanPath, "error", err)
		return
	}
	if err := os.RemoveAll(cleanPath); err != nil {
		slog.Warn("remove litmus tmp dir failed", "path", cleanPath, "error", err)
	}
}

func sweepStaleLitmusTmpDirs(current string) {
	root := os.TempDir()
	entries, err := os.ReadDir(root)
	if err != nil {
		slog.Warn("read tmp root for litmus sweep failed", "root", root, "error", err)
		return
	}
	cleanCurrent := filepath.Clean(current)
	for _, entry := range entries {
		name := entry.Name()
		if !strings.HasPrefix(name, "hopper-litmus-") {
			continue
		}
		full := filepath.Join(root, name)
		if filepath.Clean(full) == cleanCurrent {
			continue
		}
		safeRemoveLitmusTmpDir(full, root)
	}
}

// sweepStaleLitmusLogs removes litmus-*.log files last written more than
// litmusLogMaxAge ago. Called on every spawn, just before the new log is
// created: the outgoing worker's log was written moments ago, so an active log
// is never a candidate no matter how long that worker ran. Best-effort
// throughout — a log that cannot be reaped must never block a worker start.
func sweepStaleLitmusLogs(logDir string) {
	entries, err := os.ReadDir(logDir)
	if err != nil {
		slog.Warn("read litmus log dir for sweep failed", "dir", logDir, "error", err)
		return
	}
	cutoff := time.Now().Add(-litmusLogMaxAge)
	removed, freed := 0, int64(0)
	for _, entry := range entries {
		name := entry.Name()
		if !strings.HasPrefix(name, "litmus-") || !strings.HasSuffix(name, ".log") {
			continue
		}
		info, err := entry.Info()
		if err != nil || !info.Mode().IsRegular() || info.ModTime().After(cutoff) {
			continue
		}
		full := filepath.Join(logDir, name)
		if err := os.Remove(full); err != nil {
			slog.Warn("remove stale litmus log failed", "path", full, "error", err)
			continue
		}
		removed++
		freed += info.Size()
	}
	if removed > 0 {
		slog.Info("swept stale litmus logs",
			"dir", logDir, "removed", removed, "freed_mb", freed/(1<<20), "max_age", litmusLogMaxAge)
	}
}

func sweepLitmusTmpChildren(root string, maxAge time.Duration) {
	cleanRoot := filepath.Clean(root)
	if _, err := os.Stat(filepath.Join(cleanRoot, litmusTmpSentinel)); err != nil {
		slog.Warn("refusing to sweep litmus tmp children without sentinel", "root", cleanRoot, "error", err)
		return
	}
	entries, err := os.ReadDir(cleanRoot)
	if err != nil {
		slog.Warn("read litmus tmp dir failed", "root", cleanRoot, "error", err)
		return
	}
	cutoff := time.Now().Add(-maxAge)
	for _, entry := range entries {
		if entry.Name() == litmusTmpSentinel {
			continue
		}
		full := filepath.Join(cleanRoot, entry.Name())
		info, err := os.Lstat(full)
		if err != nil {
			slog.Warn("stat litmus tmp child failed", "path", full, "error", err)
			continue
		}
		if info.Mode()&os.ModeSymlink != 0 || info.ModTime().After(cutoff) {
			continue
		}
		if err := os.RemoveAll(full); err != nil {
			slog.Warn("remove stale litmus tmp child failed", "path", full, "error", err)
		}
	}
}

// Start launches the litmus worker subprocess. The caller is responsible
// for rebuilding the binary (via updateSiblingTool) before calling Start
// so that the worker runs the latest version from the first request.
func (s *litmusServer) Start(ctx context.Context) error {
	s.mu.Lock()
	defer s.mu.Unlock()

	if s.cmd != nil {
		return errors.New("litmus server already started")
	}

	return s.startLocked(ctx)
}

// updateSiblingTool runs `git pull && make install` in dir, treating pull
// failures as non-fatal so a dirty working tree still rebuilds. Both litmus
// and cleave follow the same repo layout and Makefile convention.
func updateSiblingTool(ctx context.Context, name, dir string) {
	if _, err := os.Stat(dir); err != nil {
		slog.Warn("tool source not found, using installed version", "tool", name, "dir", dir)
		return
	}

	slog.Info("updating tool", "tool", name, "dir", dir)

	pull := exec.CommandContext(ctx, "git", "pull")
	pull.Dir = dir
	pulled := true
	if out, err := pull.CombinedOutput(); err != nil {
		pulled = false
		slog.Warn("git pull failed, building from current working tree anyway",
			"tool", name, "error", err, "output", string(out))
	}

	install := exec.CommandContext(ctx, "make", "install")
	install.Dir = dir
	if out, err := install.CombinedOutput(); err != nil {
		slog.Error("make install failed, using installed version",
			"tool", name, "error", err, "output", string(out), "pulled", pulled)
		return
	}

	slog.Info("tool updated successfully", "tool", name, "pulled", pulled)
}

// workerArgs builds the atomscan argv for the local worker. Pure so the
// composition is testable without spawning: the flags here are the only thing
// that distinguishes this worker from a remote fleet one, and a missing flag is
// invisible at runtime (see --interpret below).
func (s *litmusServer) workerArgs() []string {
	args := []string{}
	if s.verbose {
		args = append(args, "--verbose")
	}
	args = append(args, "worker",
		"--url", s.hopperURL,
		"--name", "local",
	)
	if s.dataDir != "" {
		args = append(args, "--data-dir", s.dataDir)
	}
	if s.maxRSSGB != 0 {
		args = append(args, "--max-rss-gb", strconv.Itoa(s.maxRSSGB))
	}
	if s.maxWorkers > 0 {
		args = append(args, "--workers", strconv.Itoa(s.maxWorkers))
	}
	// LLM second-opinion pass, exactly as the remote fleet runs it: the
	// `--interpret` flag plus SCAN_LLM naming the endpoint (see scan's
	// scripts/worker/worker-linux.sh). Without it this worker stores no
	// llm_result at all, and since it claims the largest share of the queue
	// that left ~half of every hostile sample with a verdict and no rationale —
	// the gaps on prism's /fallout page. Gated on a configured endpoint rather
	// than always-on: bare `--interpret` would aim at localhost:8000, and a
	// missing endpoint costs a health-gate wait per sample.
	if s.llmURL != "" {
		args = append(args, "--interpret")
	}
	return args
}

func (s *litmusServer) startLocked(ctx context.Context) error {
	args := s.workerArgs()

	tmpDir, err := s.ensureTmpDirLocked()
	if err != nil {
		return err
	}

	cmd := exec.CommandContext(ctx, s.bin, args...) //nolint:gosec // binary path is trusted configuration
	// Run litmus as the leader of its own process group so we can signal the
	// whole tree (rizin/yara children spawned by the worker) at once. Killing
	// only the parent leaves orphaned descendants behind.
	cmd.SysProcAttr = &syscall.SysProcAttr{Setpgid: true}
	// Soft trait validation for the worker's own startup gate (see
	// preflightCleaveValidate): reject a bundle only for load/detection flaws,
	// not authoring hygiene. Ignored by litmus builds predating soft support.
	cmd.Env = append(os.Environ(), "TMPDIR="+tmpDir, "CLEAVE_VALIDATE_SOFT=1")
	if s.llmURL != "" {
		cmd.Env = append(cmd.Env, "SCAN_LLM="+s.llmURL)
	}

	logDir := xdgLogDir()
	if err := os.MkdirAll(logDir, 0o750); err != nil {
		return fmt.Errorf("create litmus log directory: %w", err)
	}
	sweepStaleLitmusLogs(logDir)

	logFile, err := os.CreateTemp(logDir, "litmus-*.log")
	if err != nil {
		return fmt.Errorf("create litmus log file: %w", err)
	}
	logName := logFile.Name()
	s.logPath.Store(&logName)

	cmd.Stdout = logFile
	cmd.Stderr = logFile

	if err := cmd.Start(); err != nil {
		closeLogFile(logFile.Name(), logFile)
		return fmt.Errorf("start litmus: %w", err)
	}
	s.cmd = cmd
	// Stamp the spawn time before publishing the pid so the watchdog never
	// pairs a fresh pid with a previous process's spawn time.
	s.spawnedAt.Store(time.Now().UnixNano())
	s.pid.Store(int64(cmd.Process.Pid))

	// The systemd unit protects hopper with OOMScoreAdjust=-800 and children
	// inherit it, which makes a runaway worker exactly as OOM-proof as the
	// master it is starving (observed 2026-07-09: the cgroup OOM killer had
	// no preferred victim, so nothing died and the whole service sat in
	// reclaim throttling instead). Shed the inherited shield: +500 makes the
	// worker the cgroup's designated casualty, Monitor respawns it, and its
	// claims are retried. Raising another same-uid process's score needs no
	// privilege; failure is non-fatal because the livenessWatchdog memory
	// check still bounds the damage.
	oomPath := "/proc/" + strconv.Itoa(cmd.Process.Pid) + "/oom_score_adj"
	if err := os.WriteFile(oomPath, []byte("500"), 0); err != nil {
		slog.Warn("could not raise litmus oom_score_adj; worker keeps inherited OOM protection",
			"pid", cmd.Process.Pid, "error", err)
	}
	// Under the kernel-enforced budget from (nearly) birth — see
	// workercgroup.go for why this is a post-spawn move, not CLONE_INTO_CGROUP.
	moveToWorkerCgroup(cmd.Process.Pid)

	slog.Info("starting litmus worker",
		"pid", cmd.Process.Pid,
		"log", sanitizeLogString(logFile.Name()),
		"args", sanitizeLogString(strings.Join(args, " ")))

	// Brief startup check: if the process crashes immediately, report it.
	time.Sleep(500 * time.Millisecond)
	if cmd.ProcessState != nil {
		closeLogFile(logFile.Name(), logFile)
		s.cmd = nil
		s.pid.Store(0)
		s.spawnedAt.Store(0)
		return errors.New("litmus worker exited immediately")
	}

	slog.Info("litmus worker started", "pid", cmd.Process.Pid)
	s.setHealth(true, "running", "")
	// The child inherited its own dup of the log fd at Start, so the parent's
	// copy is dead weight; close it. Without this the Monitor restart loop leaks
	// one fd per spawn for the life of the process.
	closeLogFile(logFile.Name(), logFile)
	return nil
}

// Stop kills the litmus server.
func (s *litmusServer) Stop() {
	s.stopped.Store(true)
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.cmd != nil && s.cmd.Process != nil {
		slog.Info("stopping litmus server", "pid", s.cmd.Process.Pid, "url", s.hopperURL)
		killGroup("failed to kill litmus group during stop", s.cmd.Process.Pid, syscall.SIGKILL, "url", s.hopperURL)
		if err := s.cmd.Wait(); err != nil {
			slog.Debug("litmus exited during stop", "pid", s.cmd.Process.Pid, "error", err)
		}
		s.cmd = nil
		s.pid.Store(0)
		slog.Info("litmus server stopped")
	}
	if s.tmpDir != "" {
		safeRemoveLitmusTmpDir(s.tmpDir, os.TempDir())
		s.tmpDir = ""
	}
}

// Monitor watches the litmus process and restarts it on crash or wedge.
// A liveness watchdog kills litmus if the local worker hasn't checked in
// within livenessTimeout, which triggers a restart via the normal crash path.
// Blocks until ctx is cancelled or Stop is called.
func (s *litmusServer) Monitor(ctx context.Context) error {
	// Liveness watchdog: kill litmus if the local worker stops checking in.
	if s.tracker != nil && s.workerName != "" {
		go s.livenessWatchdog(ctx)
	}

	for {
		pid := s.currentPID()
		err := s.waitExit(ctx)
		s.pid.Store(0)
		if ctx.Err() != nil || s.stopped.Load() {
			return ctx.Err()
		}
		// No process to wait on — another goroutine (e.g. rebuild) may be
		// starting one. Wait briefly instead of spinning.
		if err != nil && err.Error() == "no process" {
			select {
			case <-time.After(2 * time.Second):
				continue
			case <-ctx.Done():
				return ctx.Err()
			}
		}
		// If the build goroutine is restarting litmus with a new binary,
		// don't count this as a crash — the kill was intentional.
		if s.building.Load() {
			slog.Info("litmus exited during rebuild, waiting for rebuild goroutine to restart it",
				"pid", pid)
			// Wait for the rebuild goroutine to finish restarting before
			// we loop back and call waitExit on the new process.
			for s.building.Load() && ctx.Err() == nil {
				time.Sleep(500 * time.Millisecond)
			}
			continue
		}
		restarts := int(s.restarts.Add(1))
		logPath := ""
		if p := s.logPath.Load(); p != nil {
			logPath = *p
		}
		slog.Warn("litmus server crashed",
			"pid", pid,
			"url", s.hopperURL,
			"error", err,
			"restarts", restarts,
			"log", sanitizeLogString(logPath),
			"tail", tailLogFile(logPath))
		s.setHealth(false, fmt.Sprintf("crashed (restart %d): %v", restarts, err), s.workerLogTail(3))

		delay := min(time.Duration(1<<min(restarts-1, 7))*time.Second, 2*time.Minute)
		slog.Info("restarting litmus server",
			"previous_pid", pid,
			"url", s.hopperURL,
			"delay", delay,
			"attempt", restarts)
		select {
		case <-time.After(delay):
		case <-ctx.Done():
			return ctx.Err()
		}

		if s.stopped.Load() {
			return nil
		}

		// Clear stale claims from the dead process so the new instance
		// isn't starved by the unproven-worker claim limit.
		if s.tracker != nil && s.workerName != "" {
			s.tracker.resetClaims(s.workerName)
		}

		s.mu.Lock()
		if s.cmd != nil {
			// Another goroutine (e.g., the rebuild goroutine in Start)
			// already restarted litmus while we were waiting for the lock.
			s.mu.Unlock()
			slog.Info("litmus already restarted by another goroutine, skipping",
				"pid", s.currentPID())
			continue
		}
		err = s.startLocked(ctx)
		s.mu.Unlock()
		if err != nil {
			slog.Error("failed to restart litmus",
				"previous_pid", pid,
				"url", s.hopperURL,
				"attempt", restarts,
				"next_delay", time.Duration(1<<min(restarts, 4))*time.Second,
				"error", err)
			s.setHealth(false, fmt.Sprintf("restart failed (attempt %d): %v", restarts, err), s.workerLogTail(3))
			continue
		}
		slog.Info("litmus restart waiting for recovery window",
			"pid", s.currentPID(),
			"url", s.hopperURL,
			"delay", restartRecoveryDelay,
			"attempt", restarts)
		select {
		case <-time.After(restartRecoveryDelay):
		case <-ctx.Done():
			return ctx.Err()
		}
		slog.Info("litmus server restarted",
			"restarts", restarts,
			"pid", s.currentPID(),
			"url", s.hopperURL)
	}
}

// livenessWatchdog periodically checks whether the local worker has polled
// hopper recently. If it hasn't checked in within livenessTimeout, the litmus
// process is killed — Monitor will detect the exit and restart it.
func (s *litmusServer) livenessWatchdog(ctx context.Context) {
	ticker := time.NewTicker(1 * time.Minute)
	defer ticker.Stop()
	// Memory-breach strike counter, keyed to the pid it was observed on so a
	// restart never inherits the previous process's strikes.
	var breachPID, breaches int
	var lastLogSweep time.Time
	for {
		select {
		case <-ticker.C:
		case <-ctx.Done():
			return
		}
		if s.stopped.Load() || s.building.Load() {
			continue
		}
		if time.Since(lastLogSweep) >= litmusLogSweepInterval {
			lastLogSweep = time.Now()
			sweepStaleLitmusLogs(xdgLogDir())
		}
		pid := s.currentPID()
		if pid == 0 {
			continue // no process running (between restarts)
		}
		// Ground-truth memory check against the kernel's accounting (see
		// rssKillFactor). The worker's own self-reported number is not
		// consulted here: the failure mode being defended against is exactly
		// the one where that number is wrong.
		if s.maxRSSGB > 0 {
			budget := uint64(s.maxRSSGB) << 30
			limit := uint64(float64(budget) * rssKillFactor)
			mem, err := procMemoryBytes(pid)
			switch {
			case err != nil:
				// Process may have just exited; Monitor handles that.
			case mem > limit:
				if pid == breachPID {
					breaches++
				} else {
					breachPID, breaches = pid, 1
				}
				slog.Warn("local litmus worker over memory budget",
					"worker", s.workerName,
					"pid", pid,
					"mem_gb", mem>>30,
					"budget_gb", s.maxRSSGB,
					"strike", breaches,
					"strikes_to_kill", rssKillStrikes)
				if breaches >= rssKillStrikes {
					breachPID, breaches = 0, 0
					if !s.dumpAndKill(ctx, pid, "failed to kill over-budget litmus group") {
						return
					}
				}
				continue
			default:
				if pid == breachPID {
					breachPID, breaches = 0, 0
				}
			}
		}
		// Which clock applies depends on whether this process has ever been
		// heard from. Before its first check-in it is still starting up, and
		// is judged from its spawn against the generous startupTimeout; the
		// previous process's heartbeat is ignored, since it never advances
		// until the new process checks in and would otherwise kill it on
		// sight, wedging the restart loop. After the first check-in the
		// tighter livenessTimeout applies to the gap since that check-in.
		seen := s.tracker.lastSeen(s.workerName)
		ref, budget, phase := s.spawnTime(), startupTimeout, "starting"
		if seen.After(ref) {
			ref, budget, phase = seen, livenessTimeout, "running"
		}
		if ref.IsZero() {
			continue // nothing has started yet
		}
		idle := time.Since(ref)
		if idle <= budget {
			continue
		}
		lastSeen := "never"
		if !seen.IsZero() {
			lastSeen = seen.Format(time.RFC3339)
		}
		slog.Warn("local litmus worker appears wedged, dumping backtrace then killing",
			"worker", s.workerName,
			"phase", phase,
			"last_seen", lastSeen,
			"idle", idle.Round(time.Second),
			"budget", budget,
			"pid", pid)
		if !s.dumpAndKill(ctx, pid, "failed to kill wedged litmus group") {
			return
		}
	}
}

// dumpAndKill asks litmus to dump every thread's backtrace (SIGUSR1, handled
// in litmus/src/main.rs) into its log so the failure is diagnosable, gives
// the dump a moment to flush, then SIGKILLs the whole group. Signal the
// process directly, not the group: only litmus handles SIGUSR1, and the
// default disposition would terminate its rizin/yara children. Returns false
// if ctx was cancelled while waiting for the dump to flush.
func (s *litmusServer) dumpAndKill(ctx context.Context, pid int, killMsg string) bool {
	if err := syscall.Kill(pid, syscall.SIGUSR1); err != nil && !errors.Is(err, syscall.ESRCH) {
		slog.Warn("failed to signal litmus for backtrace", "pid", pid, "error", err)
	}
	select {
	case <-time.After(wedgeDumpDelay):
	case <-ctx.Done():
		return false
	}
	s.mu.Lock()
	// Guard against the process having been replaced during the dump
	// window (e.g. a concurrent rebuild) so we never kill a newer pid.
	if s.cmd != nil && s.cmd.Process != nil && s.cmd.Process.Pid == pid {
		killGroup(killMsg, pid, syscall.SIGKILL, "worker", s.workerName)
	}
	s.mu.Unlock()
	return true
}

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

func (s *litmusServer) waitExit(ctx context.Context) error {
	s.mu.Lock()
	cmd := s.cmd
	s.mu.Unlock()
	if cmd == nil {
		return errors.New("no process")
	}
	done := make(chan error, 1)
	go func() { done <- cmd.Wait() }()
	select {
	case err := <-done:
		// Clear cmd so we don't double-Wait on the same process.
		s.mu.Lock()
		if s.cmd == cmd {
			s.cmd = nil
		}
		s.mu.Unlock()
		return err
	case <-ctx.Done():
		return ctx.Err()
	}
}

// extractCanonicalSHA computes the minimum SHA256 across files in the raw cleave report.
func extractCanonicalSHA(sha256 string, raw json.RawMessage) string {
	return hopper.ParseCleaveResult(sha256, raw).CanonicalSHA
}

const updateErrorDelay = 30 * time.Second

// updateRulesTimeout bounds a single `update-rules` run. The subcommand fetches
// over the network, and binding it only to the process-lifetime context would
// let one stalled fetch hang forever — wedging both the startup stage and
// superviseLocalWorker's retry loop, which could then never re-validate. Sized
// to match preflightCleaveValidate's gate so a cold bundle fetch still fits.
const updateRulesTimeout = 5 * time.Minute

// refreshToolRules runs `<bin> update-rules` to pull the latest trait/rule and
// model bundles for one tool; tool names it in logs ("litmus", "cleave").
//
// This is the only thing that advances a tool's bundles: both tools resolve
// them from a data directory that is bootstrap-installed once and then reused
// as-is forever, so a bundle left stale there is never repaired on its own. The
// binaries themselves are rebuilt separately (Start's updateSiblingTool).
//
// Failure is non-fatal — we log it, pause briefly so a concurrent rebuild or
// fetch can settle, and leave the retry to the caller.
func refreshToolRules(ctx context.Context, tool, bin string) {
	if bin == "" {
		slog.Warn("skipping update-rules: no binary configured", "tool", tool)
		return
	}

	// Bound the command, but pause on the parent context: when the command
	// itself times out its context is already done, and the pause still has to
	// hold off the caller's next attempt.
	cmdCtx, cancel := context.WithTimeout(ctx, updateRulesTimeout)
	defer cancel()

	cmd := exec.CommandContext(cmdCtx, bin, "update-rules")
	out, err := cmd.CombinedOutput()
	if err == nil {
		slog.Info("update-rules succeeded", "tool", tool, "bin", bin, "output", lastLines(out, 5))
		return
	}

	attrs := []any{"tool", tool, "error", err, "output", lastLines(out, 30)}
	if cmdCtx.Err() != nil && ctx.Err() == nil {
		attrs = append(attrs, "timeout", updateRulesTimeout)
	}
	attrs = append(attrs, commandDiagnostics(cmd)...)
	slog.Warn("update-rules failed (non-fatal)", attrs...)
	slog.Info("pausing after update-rules error", "tool", tool, "delay", updateErrorDelay)
	select {
	case <-time.After(updateErrorDelay):
	case <-ctx.Done():
	}
}

// preflightCleaveValidate runs `cleave validate` synchronously so we discover
// broken traits once, here. Litmus' own model-benign validation is intentionally
// not a Hopper startup gate: host-local benign corpora can vary by distro.
func preflightCleaveValidate(ctx context.Context, bin string) (detail string, err error) {
	ctx, cancel := context.WithTimeout(ctx, 5*time.Minute)
	defer cancel()
	cmd := exec.CommandContext(ctx, bin, "validate")
	// Soft validation: reject a trait bundle only for flaws that break loading
	// or lose detections, never for authoring hygiene (taxonomy, size, dedup,
	// style, precision). Sent as an env toggle rather than a `--soft` flag so a
	// cleave predating soft support ignores it and validates as before, instead
	// of hard-failing the gate on an unknown flag.
	cmd.Env = append(os.Environ(), "CLEAVE_VALIDATE_SOFT=1")
	out, err := cmd.CombinedOutput()
	if err != nil {
		attrs := []any{
			"error", err,
			"output", lastLines(out, 30),
		}
		attrs = append(attrs, commandDiagnostics(cmd)...)
		slog.Error("cleave validate failed; local scan worker startup deferred",
			attrs...)
		return lastLines(out, 3), fmt.Errorf("%w: %s", err, lastReasonLine(out))
	}
	slog.Info("cleave validate passed", "bin", bin, "output", sanitizeLogString(strings.TrimSpace(string(out))))
	return "", nil
}

// lastReasonLine extracts the most informative single line from a tool's output
// — the trailing non-empty line, e.g. cleave's "Error: Traits not found ..." —
// for use as a one-line status reason. Sanitized for logs and HTML.
func lastReasonLine(out []byte) string {
	s := strings.TrimSpace(string(out))
	if i := strings.LastIndexByte(s, '\n'); i >= 0 {
		s = strings.TrimSpace(s[i+1:])
	}
	return sanitizeLogString(s)
}

// lastNLines returns the trailing n lines of s, sanitized — used for the
// dashboard banner's failure detail.
func lastNLines(s string, n int) string {
	s = strings.TrimRight(s, "\n")
	if s == "" {
		return ""
	}
	lines := strings.Split(s, "\n")
	if len(lines) > n {
		lines = lines[len(lines)-n:]
	}
	return sanitizeLogString(strings.Join(lines, "\n"))
}

// superviseLocalWorker keeps the in-process scan (atomscan) worker running for the
// life of ctx and never gives up. It loops: validate cleave traits (retrying —
// a fresh fetch may still be landing, or may have failed, in which case it
// re-pulls cleave's traits), then start the worker and hand off to Monitor,
// which restarts it on every crash. Every failure is logged and published to the
// dashboard banner via setHealth; the worker is never permanently disabled and
// never blocks ingestion — remote workers keep analyzing regardless.
func superviseLocalWorker(ctx context.Context, litmus *litmusServer, cleaveBin string) {
	for attempt := 1; ctx.Err() == nil; attempt++ {
		if detail, err := preflightCleaveValidate(ctx, cleaveBin); err != nil {
			delay := workerRetryDelay(attempt)
			litmus.setHealth(false, "cleave validate failed: "+err.Error(), detail)
			slog.Error("local scan worker not started: cleave validate failed; retrying",
				"error", err, "cleave_bin", cleaveBin, "attempt", attempt, "retry_in", delay)
			// Re-pull cleave's traits — the bundle that just failed to validate.
			// It must be cleave's own, not litmus': cleave resolves traits from a
			// data dir it populates once and then never refreshes, so stale traits
			// there are repaired only by this call. Refreshing any other tool here
			// would leave the failure untouched and retry forever.
			refreshToolRules(ctx, "cleave", cleaveBin)
			if !sleepCtx(ctx, delay) {
				return
			}
			continue
		}
		if err := litmus.Start(ctx); err != nil {
			delay := workerRetryDelay(attempt)
			litmus.setHealth(false, "failed to start: "+err.Error(), litmus.workerLogTail(3))
			slog.Error("local scan worker failed to start; retrying",
				"error", err, "attempt", attempt, "retry_in", delay)
			if !sleepCtx(ctx, delay) {
				return
			}
			continue
		}
		// Started. Monitor publishes crash health itself and restarts the worker
		// on every crash; it returns only when ctx is cancelled or Stop is called.
		if err := litmus.Monitor(ctx); err != nil && ctx.Err() == nil {
			litmus.setHealth(false, "monitor exited: "+err.Error(), "")
			slog.Error("local scan worker monitor exited unexpectedly; re-validating",
				"error", err)
			continue
		}
		return
	}
}

// workerRetryDelay is the exponential backoff (capped at 1 minute) between local
// scan worker startup attempts.
func workerRetryDelay(attempt int) time.Duration {
	if attempt < 1 {
		attempt = 1
	}
	return min(time.Duration(1<<min(attempt-1, 6))*time.Second, time.Minute)
}

// sleepCtx sleeps for d or until ctx is cancelled; returns false if ctx ended.
func sleepCtx(ctx context.Context, d time.Duration) bool {
	select {
	case <-time.After(d):
		return true
	case <-ctx.Done():
		return false
	}
}

func commandDiagnostics(cmd *exec.Cmd) []any {
	wd := cmd.Dir
	if wd == "" {
		if cwd, err := os.Getwd(); err == nil {
			wd = cwd
		}
	}
	resolved := cmd.Path
	if lp, err := exec.LookPath(cmd.Path); err == nil {
		resolved = lp
	}
	unsetKeys := []string{
		"CLEAVE_TRAITS_DIR",
		"SCAN_MODELS_DIR",
		"XDG_CONFIG_HOME",
		"XDG_DATA_HOME",
	}
	setKeys := []string{
		"HOME",
		"XDG_CACHE_HOME",
		"PATH",
	}
	attrs := []any{
		"cwd", wd,
		"argv", cmd.Args,
		"command", shellCommand(cmd.Args),
		"resolved_bin", resolved,
		"traits_dir", resolvedTraitsDir(cmd),
		"models_dir", resolvedModelsDir(cmd),
		"reproduce", reproduceCommand(cmd, wd, unsetKeys, setKeys),
		"reproduce_as_hopper", "sudo -u hopper " + reproduceCommand(cmd, wd, unsetKeys, setKeys),
	}
	for _, key := range append(setKeys, unsetKeys...) {
		if val, ok := cmdEnvValue(cmd, key); ok && val != "" {
			attrs = append(attrs, key, val)
		}
	}
	return attrs
}

func cmdEnvValue(cmd *exec.Cmd, key string) (string, bool) {
	prefix := key + "="
	for _, entry := range cmd.Environ() {
		if val, ok := strings.CutPrefix(entry, prefix); ok {
			return val, true
		}
	}
	return "", false
}

// dataHome is the platform data directory the tools resolve their bundles
// against — Rust's dirs::data_dir, which both cleave and atomscan use:
// $XDG_DATA_HOME when set, else $HOME/.local/share. Returns "" when neither is
// known, so callers fall through to a bare relative path exactly as the tools
// do. Read from the command's own environment so these paths describe the run
// we are reporting on, not hopper's.
func dataHome(cmd *exec.Cmd) string {
	if val, ok := cmdEnvValue(cmd, "XDG_DATA_HOME"); ok && val != "" {
		return val
	}
	if home := cmdHome(cmd); home != "" {
		return filepath.Join(home, ".local", "share")
	}
	return ""
}

// resolvedTraitsDir mirrors cleave's traits_repo::resolve_and_ensure so the
// diagnostics name the directory cleave actually reads: explicit override, then
// a workspace-local "traits" checkout, then <data dir>/atomdrift/cleave/traits.
// The atomdrift segment is load-bearing — dropping it names a path that does not
// exist and sends the reader hunting the wrong bundle.
func resolvedTraitsDir(cmd *exec.Cmd) string {
	if val, ok := cmdEnvValue(cmd, "CLEAVE_TRAITS_DIR"); ok && val != "" {
		return val
	}
	// cleave probes "traits" relative to its own working directory, so resolve
	// the probe against cmd.Dir; an empty Dir means it inherits ours, which is
	// what the bare relative path already means.
	local := filepath.Join(cmd.Dir, "traits")
	if info, err := os.Stat(local); err == nil && info.IsDir() {
		return local
	}
	return filepath.Join(dataHome(cmd), "atomdrift", "cleave", "traits")
}

func resolvedModelsDir(cmd *exec.Cmd) string {
	if val, ok := cmdEnvValue(cmd, "SCAN_MODELS_DIR"); ok && val != "" {
		return val
	}
	return filepath.Join(dataHome(cmd), "atomdrift", "scan", "models")
}

func cmdHome(cmd *exec.Cmd) string {
	if val, ok := cmdEnvValue(cmd, "HOME"); ok && val != "" {
		return val
	}
	if home, err := os.UserHomeDir(); err == nil {
		return home
	}
	return ""
}

func reproduceCommand(cmd *exec.Cmd, wd string, unsetKeys, setKeys []string) string {
	var parts []string
	if wd != "" {
		parts = append(parts, "cd", shellQuote(wd), "&&")
	}
	parts = append(parts, "env")
	for _, key := range unsetKeys {
		if _, ok := cmdEnvValue(cmd, key); !ok {
			parts = append(parts, "-u", key)
		}
	}
	for _, key := range setKeys {
		if val, ok := cmdEnvValue(cmd, key); ok {
			parts = append(parts, key+"="+shellQuote(val))
		}
	}
	parts = append(parts, shellCommand(cmd.Args))
	return strings.Join(parts, " ")
}

func shellCommand(argv []string) string {
	quoted := make([]string, 0, len(argv))
	for _, arg := range argv {
		quoted = append(quoted, shellQuote(arg))
	}
	return strings.Join(quoted, " ")
}

func shellQuote(s string) string {
	if s == "" {
		return "''"
	}
	if strings.IndexFunc(s, func(r rune) bool {
		return (r < 'A' || r > 'Z') &&
			(r < 'a' || r > 'z') &&
			(r < '0' || r > '9') &&
			!strings.ContainsRune("._/:-", r)
	}) == -1 {
		return s
	}
	return "'" + strings.ReplaceAll(s, "'", "'\"'\"'") + "'"
}

// lastLines returns the trailing maxLines of b, sanitized for slog.
func lastLines(b []byte, maxLines int) string {
	s := strings.TrimRight(string(b), "\n")
	if s == "" {
		return ""
	}
	lines := strings.Split(s, "\n")
	if len(lines) > maxLines {
		lines = lines[len(lines)-maxLines:]
	}
	return sanitizeLogString(strings.Join(lines, "\n"))
}

// litmusTraitsVersion runs `litmus -f json version` and returns the
// first 5 characters of the traits commit hash. Returns "" on any error.
func litmusTraitsVersion(ctx context.Context, bin string) string {
	ctx, cancel := context.WithTimeout(ctx, 10*time.Second)
	defer cancel()

	cmd := exec.CommandContext(ctx, bin, "-f", "json", "version")
	out, err := cmd.Output()
	if err != nil {
		stderr := ""
		var ee *exec.ExitError
		if errors.As(err, &ee) && len(ee.Stderr) > 0 {
			stderr = string(ee.Stderr)
			if len(stderr) > 256 {
				stderr = stderr[:256]
			}
		}
		slog.Warn("failed to get litmus traits version (is litmus up to date?)",
			"bin", bin, "error", err, "stderr", stderr)
		return ""
	}

	var v struct {
		Traits string `json:"traits"`
	}
	if err := json.Unmarshal(out, &v); err != nil {
		snippet := string(out)
		if len(snippet) > 128 {
			snippet = snippet[:128]
		}
		slog.Warn("failed to parse litmus version output", "error", err, "output", snippet)
		return ""
	}

	if len(v.Traits) < 5 {
		slog.Warn("litmus traits version too short", "traits", v.Traits)
		return v.Traits
	}
	return v.Traits[:5]
}

// Restarts returns the number of times litmus has been restarted.
func (s *litmusServer) Restarts() int { return int(s.restarts.Load()) }

// Workers returns the max concurrent analysis workers.
func (s *litmusServer) Workers() int { return s.maxWorkers }

func freePort(ctx context.Context) (string, net.Listener, error) {
	var lc net.ListenConfig
	l, err := lc.Listen(ctx, "tcp", "127.0.0.1:0")
	if err != nil {
		return "", nil, err
	}
	addr, ok := l.Addr().(*net.TCPAddr)
	if !ok {
		if err := l.Close(); err != nil {
			slog.Warn("failed to close listener with unexpected address", "error", err)
		}
		return "", nil, errors.New("unexpected listener address type")
	}
	return strconv.Itoa(addr.Port), l, nil
}
