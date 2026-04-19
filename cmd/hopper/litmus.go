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
	"runtime"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"time"
)

const restartRecoveryDelay = 15 * time.Second

// litmusServer manages a local litmus worker subprocess. In pull mode,
// litmus polls hopper's /api/next for work instead of hopper pushing
// requests to it.
const livenessTimeout = 25 * time.Minute

type litmusServer struct {
	cmd        *exec.Cmd
	bin        string         // path to litmus binary
	hopperURL  string         // hopper API base URL for the worker to poll
	dataDir    string         // data root for --data-dir
	tracker    *workerTracker // for liveness checks
	workerName string         // qualified name used to look up in tracker
	mu         sync.Mutex
	maxRSSGB   int
	maxWorkers int
	verbose    bool
	stopped    atomic.Bool
	building   atomic.Bool
	pid        atomic.Int64
	restarts   atomic.Int64
}

// litmusConfig holds options for starting a litmus worker.
type litmusConfig struct {
	Bin        string // path to litmus binary (default: "litmus")
	HopperURL  string // hopper API URL (e.g. http://127.0.0.1:8081)
	DataDir    string // data root for local file access
	MaxRSSGB   int    // memory limit in GB (0 = let litmus decide)
	MaxWorkers int    // max concurrent analysis workers
	Verbose    bool   // enable debug logging in litmus
}

func newLitmusServer(cfg litmusConfig) *litmusServer {
	if cfg.Bin == "" {
		cfg.Bin = "litmus"
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

func sanitizeLogString(s string) string {
	return strings.Map(func(r rune) rune {
		if r < ' ' && r != '\t' {
			return -1
		}
		return r
	}, s)
}

func killProcess(reason string, proc *os.Process, attrs ...any) {
	if proc == nil {
		return
	}
	if err := proc.Kill(); err != nil {
		slog.Warn(reason, append(attrs, "error", err)...)
	}
}

func (s *litmusServer) currentPID() int {
	return int(s.pid.Load())
}

// Start launches the litmus worker subprocess. The litmus binary is rebuilt
// from source in the background so startup is not blocked.
func (s *litmusServer) Start(ctx context.Context) error {
	s.mu.Lock()
	defer s.mu.Unlock()

	if s.cmd != nil {
		return errors.New("litmus server already started")
	}

	// Start the server with the currently installed binary so it can
	// serve traffic immediately. The rebuild runs in the background and
	// only briefly sets building=true during the actual restart swap.
	if err := s.startLocked(ctx); err != nil {
		return err
	}

	go func() {
		updateSiblingTool(ctx, "litmus", "../litmus")

		// Only mark building during the brief restart window so the
		// existing process serves traffic throughout the build.
		s.building.Store(true)
		defer s.building.Store(false)

		// Restart so the newly built binary takes effect. Reuse the
		// same port — it is free because we kill the old process first,
		// and keeping it stable avoids races with the pool and health
		// checkers that already know the URL.
		if s.tracker != nil && s.workerName != "" {
			s.tracker.resetClaims(s.workerName)
		}
		s.mu.Lock()
		if s.cmd != nil && s.cmd.Process != nil {
			slog.Info("restarting litmus with updated binary", "pid", s.cmd.Process.Pid)
			killProcess("failed to kill litmus for rebuild", s.cmd.Process, "pid", s.cmd.Process.Pid)
			// Do NOT call cmd.Wait here — the Monitor goroutine may
			// have already reaped the process via waitExit, and
			// cmd.Wait() is not safe for concurrent use. The kill is
			// best-effort; if the process is already dead, that's fine.
			s.cmd = nil
			s.pid.Store(0)
		}
		if err := s.startLocked(ctx); err != nil {
			slog.Error("failed to restart litmus after rebuild", "error", err)
		}
		s.mu.Unlock()
	}()

	return nil
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
	if s.maxRSSGB > 0 {
		args = append(args, "--max-rss-gb", strconv.Itoa(s.maxRSSGB))
	}
	if s.maxWorkers > 0 {
		args = append(args, "--workers", strconv.Itoa(s.maxWorkers))
	}

	cmd := exec.CommandContext(ctx, s.bin, args...) //nolint:gosec // bin path is from trusted CLI flag

	logDir := xdgLogDir()
	if err := os.MkdirAll(logDir, 0o750); err != nil {
		return fmt.Errorf("create litmus log directory: %w", err)
	}

	logFile, err := os.CreateTemp(logDir, "litmus-*.log")
	if err != nil {
		return fmt.Errorf("create litmus log file: %w", err)
	}

	cmd.Stdout = logFile
	cmd.Stderr = logFile

	if err := cmd.Start(); err != nil {
		closeLogFile(logFile.Name(), logFile)
		return fmt.Errorf("start litmus: %w", err)
	}
	s.cmd = cmd
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
		return errors.New("litmus worker exited immediately")
	}

	slog.Info("litmus worker started", "pid", cmd.Process.Pid)
	return nil
}

// Stop kills the litmus server.
func (s *litmusServer) Stop() {
	s.stopped.Store(true)
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.cmd != nil && s.cmd.Process != nil {
		slog.Info("stopping litmus server", "pid", s.cmd.Process.Pid, "url", s.hopperURL)
		killProcess("failed to kill litmus server during stop", s.cmd.Process, "pid", s.cmd.Process.Pid)
		if err := s.cmd.Wait(); err != nil {
			slog.Debug("litmus exited during stop", "pid", s.cmd.Process.Pid, "error", err)
		}
		s.cmd = nil
		s.pid.Store(0)
		slog.Info("litmus server stopped")
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
		slog.Warn("litmus server crashed",
			"pid", pid,
			"url", s.hopperURL,
			"error", err,
			"restarts", restarts)

		delay := time.Duration(1<<min(restarts-1, 7)) * time.Second // cap at 128s (~2min)
		if delay > 2*time.Minute {
			delay = 2 * time.Minute
		}
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
		lastSeen := s.tracker.lastSeen(s.workerName)
		if lastSeen.IsZero() {
			continue // worker hasn't registered yet (still starting up)
		}
		idle := time.Since(lastSeen)
		if idle <= livenessTimeout {
			continue
		}
		pid := s.currentPID()
		if pid == 0 {
			continue
		}
		slog.Warn("local litmus worker appears wedged, killing process",
			"worker", s.workerName,
			"last_seen", lastSeen.Format(time.RFC3339),
			"idle", idle.Round(time.Second),
			"pid", pid)
		s.mu.Lock()
		if s.cmd != nil && s.cmd.Process != nil {
			_ = s.cmd.Process.Kill() //nolint:errcheck // best-effort; Monitor will handle the exit
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
	var report struct {
		Files []struct {
			SHA256 string `json:"sha"`
			Score  int    `json:"x"`
			Depth  int    `json:"dp"`
		} `json:"fs"`
	}
	if json.Unmarshal(raw, &report) != nil {
		return sha256
	}
	canonical := sha256
	for _, f := range report.Files {
		if len(f.SHA256) == 64 && f.SHA256 < canonical {
			canonical = f.SHA256
		}
	}
	return canonical
}

// litmusTraitsVersion runs `litmus version --format=json` and returns the
// first 3 characters of the traits commit hash. Returns "" on any error.
func litmusTraitsVersion(ctx context.Context, bin string) string {
	ctx, cancel := context.WithTimeout(ctx, 10*time.Second)
	defer cancel()

	out, err := exec.CommandContext(ctx, bin, "version", "--format=json").Output()
	if err != nil {
		slog.Warn("failed to get litmus traits version", "bin", bin, "error", err)
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

	if len(v.Traits) < 3 {
		slog.Warn("litmus traits version too short", "traits", v.Traits)
		return v.Traits
	}
	return v.Traits[:3]
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
