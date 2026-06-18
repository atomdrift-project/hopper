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

	"codeberg.org/atomdrift/hopper"
)

// litmusServer manages a local litmus worker subprocess. In pull mode,
// litmus polls hopper's /api/next for work instead of hopper pushing
// requests to it.
const (
	restartRecoveryDelay = 15 * time.Second
	litmusTmpSentinel    = ".hopper-litmus-managed"
	livenessTimeout      = 25 * time.Minute
	// wedgeDumpDelay is how long the liveness watchdog waits after sending
	// SIGUSR1 (which makes litmus dump every thread's backtrace to its log)
	// before SIGKILLing a wedged worker, so the dump has time to flush.
	wedgeDumpDelay = 10 * time.Second
)

type litmusServer struct {
	cmd        *exec.Cmd
	tracker    *workerTracker                    // for liveness checks
	logPath    atomic.Pointer[string]            // current worker's stdout/stderr log file
	health     atomic.Pointer[localWorkerHealth] // published for the dashboard banner
	bin        string                            // path to litmus binary
	hopperURL  string                            // hopper API base URL for the worker to poll
	dataDir    string                            // data root for --data-dir
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

// localWorkerHealth is the current state of the in-process scan (ascan) worker,
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
	Bin        string // path to the Atomdrift Scan binary (codename: litmus); default "ascan"
	HopperURL  string // hopper API URL (e.g. http://127.0.0.1:8081)
	DataDir    string // data root for local file access
	MaxRSSGB   int    // memory limit in GB (0 = let litmus decide, -1 = disable in-process throttling)
	MaxWorkers int    // max concurrent analysis workers
	Verbose    bool   // enable debug logging in litmus
}

func newLitmusServer(cfg litmusConfig) *litmusServer {
	if cfg.Bin == "" {
		cfg.Bin = "ascan"
	}
	if cfg.MaxWorkers < 1 {
		cfg.MaxWorkers = max(2, runtime.NumCPU()/2)
	}
	return &litmusServer{
		bin:        cfg.Bin,
		hopperURL:  cfg.HopperURL,
		dataDir:    cfg.DataDir,
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
		//nolint:gosec // value is sanitized before logging; this is a false positive on slog taint flow.
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

func (s *litmusServer) startLocked(ctx context.Context) error {
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

	tmpDir, err := s.ensureTmpDirLocked()
	if err != nil {
		return err
	}

	cmd := exec.CommandContext(ctx, s.bin, args...) //nolint:gosec // bin path is from trusted CLI flag
	// Run litmus as the leader of its own process group so we can signal the
	// whole tree (rizin/yara children spawned by the worker) at once. Killing
	// only the parent leaves orphaned descendants behind.
	cmd.SysProcAttr = &syscall.SysProcAttr{Setpgid: true}
	// Soft trait validation for the worker's own startup gate (see
	// preflightCleaveValidate): reject a bundle only for load/detection flaws,
	// not authoring hygiene. Ignored by litmus builds predating soft support.
	cmd.Env = append(os.Environ(), "TMPDIR="+tmpDir, "CLEAVE_VALIDATE_SOFT=1")

	logDir := xdgLogDir()
	if err := os.MkdirAll(logDir, 0o750); err != nil {
		return fmt.Errorf("create litmus log directory: %w", err)
	}

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

	//nolint:gosec // values are sanitized or derived locally; this is a false positive on structured slog fields.
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
	for {
		select {
		case <-ticker.C:
		case <-ctx.Done():
			return
		}
		if s.stopped.Load() || s.building.Load() {
			continue
		}
		pid := s.currentPID()
		if pid == 0 {
			continue // no process running (between restarts)
		}
		// Count a fresh (re)start as activity: a just-spawned process must
		// be given the full liveness window to load its model and start
		// polling, rather than being judged by the previous process's
		// heartbeat — which never advances until the new process checks in
		// and would otherwise kill it on sight, wedging the restart loop.
		ref := s.tracker.lastSeen(s.workerName)
		if started := s.spawnTime(); started.After(ref) {
			ref = started
		}
		if ref.IsZero() {
			continue // nothing has started yet
		}
		idle := time.Since(ref)
		if idle <= livenessTimeout {
			continue
		}
		// Ask litmus to dump every thread's backtrace (SIGUSR1, handled in
		// litmus/src/main.rs) into its log so the wedge is diagnosable, give
		// it a moment to flush, then SIGKILL the whole group. Signal the
		// process directly, not the group: only litmus handles SIGUSR1, and
		// the default disposition would terminate its rizin/yara children.
		slog.Warn("local litmus worker appears wedged, dumping backtrace then killing",
			"worker", s.workerName,
			"last_seen", s.tracker.lastSeen(s.workerName).Format(time.RFC3339),
			"idle", idle.Round(time.Second),
			"pid", pid)
		if err := syscall.Kill(pid, syscall.SIGUSR1); err != nil && !errors.Is(err, syscall.ESRCH) {
			slog.Warn("failed to signal wedged litmus for backtrace", "pid", pid, "error", err)
		}
		select {
		case <-time.After(wedgeDumpDelay):
		case <-ctx.Done():
			return
		}
		s.mu.Lock()
		// Guard against the process having been replaced during the dump
		// window (e.g. a concurrent rebuild) so we never kill a newer pid.
		if s.cmd != nil && s.cmd.Process != nil && s.cmd.Process.Pid == pid {
			killGroup("failed to kill wedged litmus group", pid, syscall.SIGKILL,
				"worker", s.workerName)
		}
		s.mu.Unlock()
	}
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

// refreshLitmusRules runs `litmus update-rules` to pull the latest rule and
// model bundles. The binary itself is already rebuilt by Start's background
// goroutine via updateSiblingTool. If update-rules fails we pause briefly
// so a concurrent rebuild has time to settle before we check the version.
func refreshLitmusRules(ctx context.Context, bin string) {
	ur := exec.CommandContext(ctx, bin, "update-rules")
	if out, err := ur.CombinedOutput(); err != nil {
		attrs := []any{"error", err, "output", string(out)}
		attrs = append(attrs, commandDiagnostics(ur)...)
		slog.Warn("litmus update-rules failed (non-fatal)", attrs...)
		slog.Info("pausing after litmus update-rules error", "delay", updateErrorDelay)
		select {
		case <-time.After(updateErrorDelay):
		case <-ctx.Done():
		}
	} else {
		slog.Info("litmus update-rules succeeded", "bin", bin)
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

// superviseLocalWorker keeps the in-process scan (ascan) worker running for the
// life of ctx and never gives up. It loops: validate cleave traits (retrying —
// a fresh fetch may still be landing, or may have failed, in which case it
// re-pulls rules), then start the worker and hand off to Monitor, which restarts
// it on every crash. Every failure is logged and published to the dashboard
// banner via setHealth; the worker is never permanently disabled and never
// blocks ingestion — remote workers keep analyzing regardless.
func superviseLocalWorker(ctx context.Context, litmus *litmusServer, litmusBin, cleaveBin string) {
	for attempt := 1; ctx.Err() == nil; attempt++ {
		if detail, err := preflightCleaveValidate(ctx, cleaveBin); err != nil {
			delay := workerRetryDelay(attempt)
			litmus.setHealth(false, "cleave validate failed: "+err.Error(), detail)
			slog.Error("local scan worker not started: cleave validate failed; retrying",
				"error", err, "cleave_bin", cleaveBin, "attempt", attempt, "retry_in", delay)
			// Re-pull rules in case the traits fetch genuinely failed, not just a
			// startup race where they were still landing.
			refreshLitmusRules(ctx, litmusBin)
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

func resolvedTraitsDir(cmd *exec.Cmd) string {
	if val, ok := cmdEnvValue(cmd, "CLEAVE_TRAITS_DIR"); ok && val != "" {
		return val
	}
	if looksLikeTraitsDir("traits") {
		return "traits"
	}
	home := cmdHome(cmd)
	if home == "" {
		return filepath.Join("cleave", "traits")
	}
	return filepath.Join(home, ".local", "share", "cleave", "traits")
}

func resolvedModelsDir(cmd *exec.Cmd) string {
	if val, ok := cmdEnvValue(cmd, "SCAN_MODELS_DIR"); ok && val != "" {
		return val
	}
	home := cmdHome(cmd)
	if home == "" {
		return filepath.Join("atomdrift", "scan", "models")
	}
	return filepath.Join(home, ".local", "share", "atomdrift", "scan", "models")
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

func looksLikeTraitsDir(path string) bool {
	info, err := os.Stat(path)
	return err == nil && info.IsDir()
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
