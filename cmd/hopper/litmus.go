package main

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net"
	"net/http"
	"os"
	"os/exec"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/codeGROOVE-dev/retry"
)

// litmusServer manages a litmus API server subprocess.
type litmusServer struct {
	client      *http.Client
	cmd         *exec.Cmd
	bin         string // path to litmus binary
	url         string // base URL (e.g. http://127.0.0.1:PORT)
	port        string
	dirs        []string
	mu          sync.Mutex
	maxRSSGB    int
	maxWorkers  int
	timeoutSecs int
	verbose     bool
	stopped     atomic.Bool

	// inFlight tracks what each hopper analysis worker is currently doing.
	inFlight sync.Map // worker ID (int) → *workerState
}

type workerState struct {
	File      string
	StartedAt time.Time
}

// litmusConfig holds options for starting a litmus server.
type litmusConfig struct {
	Bin         string   // path to litmus binary (default: "litmus")
	Dirs        []string // directories to allow for /analyze-path
	MaxRSSGB    int      // memory limit in GB (0 = let litmus decide)
	MaxWorkers  int      // max concurrent analysis requests to send
	TimeoutSecs int      // per-request analysis timeout (0 = litmus default: 600s)
	Verbose     bool     // enable debug logging in litmus
}
func newLitmusServer(cfg litmusConfig) *litmusServer {
	if cfg.Bin == "" {
		cfg.Bin = "litmus"
	}
	if cfg.MaxWorkers < 1 {
		cfg.MaxWorkers = 8
	}
	return &litmusServer{
		bin:         cfg.Bin,
		dirs:        cfg.Dirs,
		maxRSSGB:    cfg.MaxRSSGB,
		maxWorkers:  cfg.MaxWorkers,
		timeoutSecs: cfg.TimeoutSecs,
		verbose:     cfg.Verbose,
		client: &http.Client{
			// Slightly longer than litmus's analysis timeout so litmus always
			// has a chance to return 504 before the client gives up.
			Timeout: time.Duration(cfg.TimeoutSecs+60) * time.Second,
		},
	}
}

// Start launches the litmus server and waits for it to become healthy.
// It picks a random available port.
func (s *litmusServer) Start(ctx context.Context) error {
	s.mu.Lock()
	defer s.mu.Unlock()

	if s.cmd != nil {
		return errors.New("litmus server already started")
	}

	updateLitmus(ctx)

	var lastErr error
	for range 3 {
		port, l, err := freePort(ctx)
		if err != nil {
			return fmt.Errorf("find free port: %w", err)
		}
		s.port = port
		s.url = "http://127.0.0.1:" + port

		if err := s.startLocked(ctx, l); err != nil {
			lastErr = err
			slog.Warn("failed to start litmus, retrying with new port", "port", port, "error", err)
			continue
		}
		return nil
	}
	return fmt.Errorf("litmus failed to start after 3 attempts: %w", lastErr)
}

// updateLitmus attempts to build and install the latest litmus from ../litmus.
// On failure it logs the error and falls back to whatever version is already installed.
func updateLitmus(ctx context.Context) {
	dir := "../litmus"
	if _, err := os.Stat(dir); err != nil {
		slog.Warn("litmus source not found, using installed version", "dir", dir)
		return
	}

	slog.Info("updating litmus", "dir", dir)

	pull := exec.CommandContext(ctx, "git", "pull")
	pull.Dir = dir
	if out, err := pull.CombinedOutput(); err != nil {
		slog.Error("git pull failed for litmus, using installed version", "error", err, "output", string(out))
		return
	}

	install := exec.CommandContext(ctx, "make", "install")
	install.Dir = dir
	if out, err := install.CombinedOutput(); err != nil {
		slog.Error("make install failed for litmus, using installed version", "error", err, "output", string(out))
		return
	}

	slog.Info("litmus updated successfully")
}

func (s *litmusServer) startLocked(ctx context.Context, l net.Listener) error {
	if l != nil {
		l.Close()
	}
	bind := "127.0.0.1:" + s.port

	args := []string{"serve", "--bind", bind}
	if len(s.dirs) > 0 {
		args = append(args, "--allowed-dirs", strings.Join(s.dirs, ","))
	}
	if s.maxRSSGB > 0 {
		args = append(args, "--max-rss-gb", strconv.Itoa(s.maxRSSGB))
	}
	if s.timeoutSecs > 0 {
		args = append(args, "--timeout-secs", strconv.Itoa(s.timeoutSecs))
	}
	if s.verbose {
		args = append(args, "--verbose")
	}

	cmd := exec.CommandContext(ctx, s.bin, args...) //nolint:gosec // bin path is from trusted CLI flag

	logDir := xdgLogDir()
	_ = os.MkdirAll(logDir, 0o755) // best-effort

	logFile, err := os.CreateTemp(logDir, "litmus-*.log")
	if err != nil {
		return fmt.Errorf("create litmus log file: %w", err)
	}

	cmd.Stdout = logFile
	cmd.Stderr = logFile

	if err := cmd.Start(); err != nil {
		logFile.Close() //nolint:errcheck
		return fmt.Errorf("start litmus: %w", err)
	}
	s.cmd = cmd

	slog.Info("starting litmus server", "bind", bind, "pid", cmd.Process.Pid, "log", logFile.Name())

	if err := s.waitHealthy(ctx); err != nil {
		cmd.Process.Kill() //nolint:errcheck,gosec // best-effort kill
		cmd.Wait()         // cleanup zombie
		s.cmd = nil
		return fmt.Errorf("litmus not healthy: %w", err)
	}

	slog.Info("litmus server ready", "url", s.url)
	return nil
}

// Stop kills the litmus server.
func (s *litmusServer) Stop() {
	s.stopped.Store(true)
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.cmd != nil && s.cmd.Process != nil {
		s.cmd.Process.Kill() //nolint:errcheck,gosec // best-effort kill
		s.cmd.Wait()         //nolint:errcheck,gosec // collecting zombie
		s.cmd = nil
		slog.Info("litmus server stopped")
	}
}

// Monitor watches the litmus process and restarts it on crash.
// Blocks until ctx is cancelled, Stop is called, or restart limit (10) is exceeded.
func (s *litmusServer) Monitor(ctx context.Context) error {
	const maxRestarts = 10
	restarts := 0
	for {
		err := s.waitExit(ctx)
		if ctx.Err() != nil || s.stopped.Load() {
			return ctx.Err()
		}
		restarts++
		slog.Warn("litmus server crashed", "error", err, "restarts", restarts)
		if restarts > maxRestarts {
			return fmt.Errorf("litmus crashed %d times, giving up", restarts)
		}

		delay := time.Duration(1<<min(restarts-1, 4)) * time.Second
		slog.Info("restarting litmus server", "delay", delay)
		select {
		case <-time.After(delay):
		case <-ctx.Done():
			return ctx.Err()
		}

		if s.stopped.Load() {
			return nil
		}

		s.mu.Lock()
		err = s.startLocked(ctx, nil)
		s.mu.Unlock()
		if err != nil {
			slog.Error("failed to restart litmus", "error", err)
			continue
		}
		slog.Info("litmus server restarted", "restarts", restarts)
	}
}


func (s *litmusServer) waitExit(ctx context.Context) error {
	if s.cmd == nil {
		return errors.New("no process")
	}
	done := make(chan error, 1)
	go func() { done <- s.cmd.Wait() }()
	select {
	case err := <-done:
		return err
	case <-ctx.Done():
		return ctx.Err()
	}
}

func (s *litmusServer) waitHealthy(ctx context.Context) error {
	deadline := time.After(120 * time.Second) // litmus loads model + YARA, may take longer than cleave
	ticker := time.NewTicker(500 * time.Millisecond)
	defer ticker.Stop()

	for {
		select {
		case <-deadline:
			return errors.New("timeout waiting for litmus to start")
		case <-ctx.Done():
			return ctx.Err()
		case <-ticker.C:
			req, err := http.NewRequestWithContext(ctx, http.MethodGet, s.url+"/_/health", http.NoBody)
			if err != nil {
				continue
			}
			resp, err := s.client.Do(req) //nolint:gosec // URL is constructed from localhost + port
			if err != nil {
				continue
			}
			resp.Body.Close() //nolint:errcheck,gosec // health check
			if resp.StatusCode == http.StatusOK {
				return nil
			}
		}
	}
}

// TrackWorker registers a worker as analyzing a file. Call with "" to clear.
func (s *litmusServer) TrackWorker(workerID int, file string) {
	if file == "" {
		s.inFlight.Delete(workerID)
	} else {
		s.inFlight.Store(workerID, &workerState{File: file, StartedAt: time.Now()})
	}
}

// workerSummary returns counts and the oldest in-flight file for logging.
func (s *litmusServer) workerSummary() (busy, idle int, oldestMs int64, oldestFile string) {
	now := time.Now()
	total := s.maxWorkers
	s.inFlight.Range(func(_, v any) bool {
		ws := v.(*workerState)
		busy++
		elapsed := now.Sub(ws.StartedAt).Milliseconds()
		if elapsed > oldestMs {
			oldestMs = elapsed
			oldestFile = ws.File
		}
		return true
	})
	idle = total - busy
	return
}

// WatchHealth periodically polls litmus /_/health and /_/requests, logs the
// state, and kills litmus if any request has been stuck longer than the
// configured timeout. Runs alongside Monitor; call in a separate goroutine.
func (s *litmusServer) WatchHealth(ctx context.Context) {
	ticker := time.NewTicker(15 * time.Second)
	defer ticker.Stop()

	stuckThreshold := time.Duration(s.timeoutSecs) * time.Second
	if stuckThreshold == 0 {
		stuckThreshold = 600 * time.Second
	}
	// Kill if any request exceeds 2x the timeout — it's clearly stuck.
	killThreshold := 2 * stuckThreshold

	healthFailures := 0
	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
		}

		if s.stopped.Load() {
			return
		}

		health := s.pollHealth(ctx)
		if health == nil {
			healthFailures++
			if healthFailures >= 3 {
				slog.Error("litmus health check failed repeatedly, killing to force restart", "failures", healthFailures)
				s.mu.Lock()
				if s.cmd != nil && s.cmd.Process != nil {
					s.cmd.Process.Kill() //nolint:errcheck,gosec // Monitor will restart
				}
				s.mu.Unlock()
				healthFailures = 0
			}
			continue
		}
		healthFailures = 0

		busy, idle, workerOldestMs, workerOldestFile := s.workerSummary()

		level := slog.LevelDebug
		if health.ActiveTasks > 0 || busy > 0 {
			level = slog.LevelInfo
		}
		slog.Default().Log(ctx, level, "litmus health",
			"live_tasks", health.LiveTasks,
			"orphaned_tasks", health.OrphanedTasks,
			"active_tasks", health.ActiveTasks,
			"max_concurrent", health.MaxConcurrent,
			"load", fmt.Sprintf("%.2f", health.Load),
			"rss_mb", health.RSSMB,
			"litmus_oldest_ms", health.OldestRequestMs,
			"litmus_oldest_name", health.OldestRequestName,
			"hopper_busy", busy,
			"hopper_idle", idle,
			"hopper_oldest_ms", workerOldestMs,
			"hopper_oldest_file", workerOldestFile,
		)

		if health.OldestRequestMs > killThreshold.Milliseconds() {
			slog.Error("litmus has stuck request, killing to force restart",
				"oldest_request_ms", health.OldestRequestMs,
				"oldest_request_name", health.OldestRequestName,
				"kill_threshold_ms", killThreshold.Milliseconds(),
			)
			s.mu.Lock()
			if s.cmd != nil && s.cmd.Process != nil {
				s.cmd.Process.Kill() //nolint:errcheck,gosec // Monitor will restart
			}
			s.mu.Unlock()
		}
	}
}

type litmusHealth struct {
	ActiveTasks       int     `json:"active_tasks"`
	LiveTasks         int     `json:"live_tasks"`
	OrphanedTasks     int     `json:"orphaned_tasks"`
	MaxConcurrent     int     `json:"max_concurrent_tasks"`
	Load              float64 `json:"load"`
	RSSMB             int     `json:"rss_mb"`
	OldestRequestMs   int64
	OldestRequestName string
}

func (s *litmusServer) pollHealth(ctx context.Context) *litmusHealth {
	// Poll health.
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, s.url+"/_/health", http.NoBody)
	if err != nil {
		return nil
	}
	resp, err := s.client.Do(req)
	if err != nil {
		return nil
	}
	body, _ := io.ReadAll(io.LimitReader(resp.Body, 4096))
	resp.Body.Close() //nolint:errcheck

	var h litmusHealth
	if json.Unmarshal(body, &h) != nil {
		return nil
	}

	// Poll in-flight requests for oldest.
	req, err = http.NewRequestWithContext(ctx, http.MethodGet, s.url+"/_/requests", http.NoBody)
	if err != nil {
		return &h
	}
	resp, err = s.client.Do(req)
	if err != nil {
		return &h
	}
	body, _ = io.ReadAll(io.LimitReader(resp.Body, 32768))
	resp.Body.Close() //nolint:errcheck

	var reqList struct {
		Requests []struct {
			Name      string `json:"name"`
			ElapsedMs int64  `json:"elapsed_ms"`
		} `json:"requests"`
	}
	if json.Unmarshal(body, &reqList) == nil && len(reqList.Requests) > 0 {
		// Requests are sorted by elapsed descending — first is oldest.
		h.OldestRequestMs = reqList.Requests[0].ElapsedMs
		h.OldestRequestName = reqList.Requests[0].Name
	}

	return &h
}

// analyzeResult holds the split litmus response for storage in hopper.
type analyzeResult struct {
	ML        json.RawMessage // ml section → litmus_result column
	Raw       json.RawMessage // raw section → cleave_result column
	Canonical string          // canonical SHA256 from raw.fs[]
	TotalMs   int64           // server-reported total analysis time (from X-Total-Ms header)
}

var errRetryable = errors.New("service unavailable")

// Analyze sends a file to the litmus server for analysis.
// Returns the split response (ml + raw sections) and extracted canonical SHA.
// Retries on 503 (litmus at capacity) with exponential backoff.
func (s *litmusServer) Analyze(ctx context.Context, sha256, path string) (*analyzeResult, error) {
	body, err := json.Marshal(struct {
		Path string `json:"path"`
	}{Path: path})
	if err != nil {
		return nil, err
	}

	r, err := retry.DoWithData(
		func() (*analyzeResult, error) {
			return s.doAnalyze(ctx, sha256, body)
		},
		retry.Attempts(12),
		retry.Context(ctx),
		retry.Delay(2*time.Second),
		retry.MaxDelay(30*time.Second),
		retry.DelayType(retry.CombineDelay(retry.BackOffDelay, retry.RandomDelay)),
		retry.MaxJitter(3*time.Second),
		retry.RetryIf(func(err error) bool {
			return errors.Is(err, errRetryable) || isRetryableNetError(err)
		}),
		retry.OnRetry(func(attempt uint, _ error) {
			slog.Debug("litmus at capacity, retrying", "path", path, "attempt", attempt+1)
		}),
		retry.LastErrorOnly(true),
	)
	if err != nil {
		return nil, fmt.Errorf("litmus: %s: %w", path, err)
	}
	return r, nil
}

func (s *litmusServer) doAnalyze(ctx context.Context, sha256 string, body []byte) (*analyzeResult, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, s.url+"/analyze-path", bytes.NewReader(body))
	if err != nil {
		return nil, err
	}
	req.Header.Set("Content-Type", "application/json")

	resp, err := s.client.Do(req) //nolint:gosec // URL is constructed from localhost + port
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close() //nolint:errcheck // HTTP response

	if resp.StatusCode == http.StatusServiceUnavailable {
		return nil, errRetryable
	}
	if resp.StatusCode != http.StatusOK {
		msg, _ := io.ReadAll(io.LimitReader(resp.Body, 512)) //nolint:errcheck // best-effort error body
		return nil, fmt.Errorf("litmus: %d %s", resp.StatusCode, msg)
	}

	raw, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, fmt.Errorf("litmus: read response: %w", err)
	}

	// Split the {"ml": {...}, "raw": {...}} envelope.
	var envelope struct {
		ML  json.RawMessage `json:"ml"`
		Raw json.RawMessage `json:"raw"`
	}
	if err := json.Unmarshal(raw, &envelope); err != nil {
		return nil, fmt.Errorf("litmus: parse envelope: %w", err)
	}

	canonical := extractCanonicalSHA(sha256, envelope.Raw)

	var totalMs int64
	if v := resp.Header.Get("X-Total-Ms"); v != "" {
		totalMs, _ = strconv.ParseInt(v, 10, 64)
	}

	return &analyzeResult{
		ML:        envelope.ML,
		Raw:       envelope.Raw,
		Canonical: canonical,
		TotalMs:   totalMs,
	}, nil
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
		l.Close() //nolint:errcheck,gosec // cleanup
		return "", nil, errors.New("unexpected listener address type")
	}
	return strconv.Itoa(addr.Port), l, nil
}
func isRetryableNetError(err error) bool {
	if err == nil {
		return false
	}
	if errors.Is(err, io.EOF) || errors.Is(err, io.ErrUnexpectedEOF) {
		return true
	}
	var netErr net.Error
	if errors.As(err, &netErr) && netErr.Timeout() {
		return true
	}
	// Common connection-level errors (refused, reset, broken pipe).
	s := err.Error()
	return strings.Contains(s, "connection refused") ||
		strings.Contains(s, "connection reset") ||
		strings.Contains(s, "broken pipe")
}

