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
	client     *http.Client
	cmd        *exec.Cmd
	bin        string // path to litmus binary
	url        string // base URL (e.g. http://127.0.0.1:PORT)
	port       string
	dirs       []string
	mu         sync.Mutex
	maxRSSGB   int
	maxWorkers int

	// consecutive503 tracks how many 503s we've seen in a row across all workers.
	// When this exceeds the restart threshold, we kill and restart the server
	// to clear orphaned tasks.
	consecutive503 atomic.Int64
}

// litmusConfig holds options for starting a litmus server.
type litmusConfig struct {
	Bin        string   // path to litmus binary (default: "litmus")
	Dirs       []string // directories to allow for /analyze-path
	MaxRSSGB   int      // memory limit in GB (0 = let litmus decide)
	MaxWorkers int      // max concurrent analysis requests to send
}

func newLitmusServer(cfg litmusConfig) *litmusServer {
	if cfg.Bin == "" {
		cfg.Bin = "litmus"
	}
	if cfg.MaxWorkers < 1 {
		cfg.MaxWorkers = 8
	}
	return &litmusServer{
		bin:        cfg.Bin,
		dirs:       cfg.Dirs,
		maxRSSGB:   cfg.MaxRSSGB,
		maxWorkers: cfg.MaxWorkers,
		client: &http.Client{
			Timeout: 15 * time.Minute,
		},
	}
}

// Start launches the litmus server and waits for it to become healthy.
// It picks a random available port.
func (s *litmusServer) Start(ctx context.Context) error {
	s.mu.Lock()
	defer s.mu.Unlock()

	updateLitmus(ctx)

	port, err := freePort(ctx)
	if err != nil {
		return fmt.Errorf("find free port: %w", err)
	}
	s.port = port
	s.url = "http://127.0.0.1:" + port

	return s.startLocked(ctx)
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

func (s *litmusServer) startLocked(ctx context.Context) error {
	bind := "127.0.0.1:" + s.port

	args := []string{"serve", "--bind", bind}
	if len(s.dirs) > 0 {
		args = append(args, "--allowed-dirs", strings.Join(s.dirs, ","))
	}
	if s.maxRSSGB > 0 {
		args = append(args, "--max-rss-gb", strconv.Itoa(s.maxRSSGB))
	}

	cmd := exec.CommandContext(ctx, s.bin, args...) //nolint:gosec // bin path is from trusted CLI flag

	logFile, err := os.CreateTemp("", "litmus-*.log")
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
		return fmt.Errorf("litmus not healthy: %w", err)
	}

	slog.Info("litmus server ready", "url", s.url)
	return nil
}

// Stop kills the litmus server.
func (s *litmusServer) Stop() {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.cmd != nil && s.cmd.Process != nil {
		s.cmd.Process.Kill() //nolint:errcheck,gosec // best-effort kill
		s.cmd.Wait()         //nolint:errcheck,gosec // collecting zombie
		slog.Info("litmus server stopped")
	}
}

// Monitor watches the litmus process and restarts it on crash.
// Blocks until ctx is cancelled or restart limit (10) is exceeded.
func (s *litmusServer) Monitor(ctx context.Context) error {
	const maxRestarts = 10
	restarts := 0
	for {
		err := s.waitExit(ctx)
		if ctx.Err() != nil {
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

		s.mu.Lock()
		err = s.startLocked(ctx)
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

// analyzeResult holds the split litmus response for storage in hopper.
type analyzeResult struct {
	ML        json.RawMessage // ml section → litmus_result column
	Raw       json.RawMessage // raw section → cleave_result column
	Canonical string          // canonical SHA256 from raw.fs[]
}

// restartThreshold is the number of consecutive 503s across all workers
// before we kill and restart the server to clear orphaned tasks.
const restartThreshold = 50

// Analyze sends a file to the litmus server for analysis.
// Returns the split response (ml + raw sections) and extracted canonical SHA.
// Retries on 503 with exponential backoff+jitter. If the server is
// persistently stuck (orphaned tasks), triggers a restart.
func (s *litmusServer) Analyze(ctx context.Context, sha256, path string) (*analyzeResult, error) {
	body, err := json.Marshal(struct {
		Path string `json:"path"`
	}{Path: path})
	if err != nil {
		return nil, err
	}

	r, err := retry.DoWithData(
		func() (*analyzeResult, error) {
			result, err := s.doAnalyze(ctx, sha256, body)
			if err != nil {
				return nil, err
			}
			return result, nil
		},
		retry.Attempts(12),
		retry.Context(ctx),
		retry.Delay(2*time.Second),
		retry.MaxDelay(30*time.Second),
		retry.DelayType(retry.CombineDelay(retry.BackOffDelay, retry.RandomDelay)),
		retry.MaxJitter(3*time.Second),
		retry.RetryIf(func(err error) bool {
			return errors.Is(err, errRetryable)
		}),
		retry.OnRetry(func(attempt uint, err error) {
			if errors.Is(err, errRetryable) {
				n := s.consecutive503.Add(1)
				slog.Debug("litmus overloaded, retrying", "path", path, "attempt", attempt+1, "consecutive_503s", n)
				if n >= restartThreshold {
					s.triggerRestart()
				}
			}
		}),
		retry.LastErrorOnly(true),
	)
	if err != nil {
		return nil, fmt.Errorf("litmus: %s: %w", path, err)
	}

	s.consecutive503.Store(0)
	return r, nil
}

// triggerRestart kills the current litmus process to clear orphaned tasks.
// Monitor() will detect the exit and restart it automatically.
// Uses mu to ensure only one restart happens at a time.
func (s *litmusServer) triggerRestart() {
	s.mu.Lock()
	defer s.mu.Unlock()

	if s.cmd == nil || s.cmd.Process == nil {
		return
	}

	slog.Warn("litmus server stuck with orphaned tasks, killing to force restart",
		"consecutive_503s", s.consecutive503.Load())
	s.consecutive503.Store(0)
	s.cmd.Process.Kill() //nolint:errcheck,gosec // best-effort; Monitor will restart
}

var errRetryable = errors.New("service unavailable")

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
	s.consecutive503.Store(0) // server accepted work, clear overload counter
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

	return &analyzeResult{
		ML:        envelope.ML,
		Raw:       envelope.Raw,
		Canonical: canonical,
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

func freePort(ctx context.Context) (string, error) {
	var lc net.ListenConfig
	l, err := lc.Listen(ctx, "tcp", "127.0.0.1:0")
	if err != nil {
		return "", err
	}
	addr, ok := l.Addr().(*net.TCPAddr)
	if !ok {
		l.Close() //nolint:errcheck,gosec // cleanup
		return "", errors.New("unexpected listener address type")
	}
	l.Close() //nolint:errcheck,gosec // we just need the port number
	return strconv.Itoa(addr.Port), nil
}
