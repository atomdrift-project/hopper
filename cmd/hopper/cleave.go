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
	"time"
)

// cleaveServer manages a cleave API server subprocess.
type cleaveServer struct {
	client     *http.Client
	cmd        *exec.Cmd
	bin        string // path to cleave binary
	url        string // base URL (e.g. http://127.0.0.1:PORT)
	port       string
	dirs       []string
	mu         sync.Mutex
	maxRSSGB   int
	maxWorkers int
}

// cleaveConfig holds options for starting a cleave server.
type cleaveConfig struct {
	Bin        string   // path to cleave binary (default: "cleave")
	Dirs       []string // directories to allow for /analyze-path
	MaxRSSGB   int      // memory limit in GB (0 = let cleave decide, 25% of system RAM)
	MaxWorkers int      // max concurrent analysis requests to send
}

func newCleaveServer(cfg cleaveConfig) *cleaveServer {
	if cfg.Bin == "" {
		cfg.Bin = "cleave"
	}
	if cfg.MaxWorkers < 1 {
		cfg.MaxWorkers = 8
	}
	return &cleaveServer{
		bin:        cfg.Bin,
		dirs:       cfg.Dirs,
		maxRSSGB:   cfg.MaxRSSGB,
		maxWorkers: cfg.MaxWorkers,
		client: &http.Client{
			Timeout: 15 * time.Minute,
		},
	}
}

// Start launches the cleave server and waits for it to become healthy.
// It picks a random available port.
func (s *cleaveServer) Start(ctx context.Context) error {
	s.mu.Lock()
	defer s.mu.Unlock()

	port, err := freePort(ctx)
	if err != nil {
		return fmt.Errorf("find free port: %w", err)
	}
	s.port = port
	s.url = "http://127.0.0.1:" + port

	return s.startLocked(ctx)
}

func (s *cleaveServer) startLocked(ctx context.Context) error {
	bind := "127.0.0.1:" + s.port

	args := []string{"serve", "--bind", bind}
	if len(s.dirs) > 0 {
		args = append(args, "--dangerous-local-file-paths", strings.Join(s.dirs, ","))
	}
	if s.maxRSSGB > 0 {
		args = append(args, "--max-rss-gb", strconv.Itoa(s.maxRSSGB))
	}

	cmd := exec.CommandContext(ctx, s.bin, args...) //nolint:gosec // bin path is from trusted CLI flag
	cmd.Stdout = os.Stderr
	cmd.Stderr = os.Stderr
	if err := cmd.Start(); err != nil {
		return fmt.Errorf("start cleave: %w", err)
	}
	s.cmd = cmd

	slog.Info("starting cleave server", "bind", bind, "pid", cmd.Process.Pid)

	// Wait for health endpoint.
	if err := s.waitHealthy(ctx); err != nil {
		cmd.Process.Kill() //nolint:errcheck,gosec // best-effort kill
		return fmt.Errorf("cleave not healthy: %w", err)
	}

	slog.Info("cleave server ready", "url", s.url)
	return nil
}

// Stop kills the cleave server.
func (s *cleaveServer) Stop() {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.cmd != nil && s.cmd.Process != nil {
		s.cmd.Process.Kill() //nolint:errcheck,gosec // best-effort kill
		s.cmd.Wait()         //nolint:errcheck,gosec // collecting zombie
		slog.Info("cleave server stopped")
	}
}

// Monitor watches the cleave process and restarts it on crash.
// Blocks until ctx is cancelled or restart limit (10) is exceeded.
func (s *cleaveServer) Monitor(ctx context.Context) error {
	const maxRestarts = 10
	restarts := 0
	for {
		err := s.waitExit(ctx)
		if ctx.Err() != nil {
			return ctx.Err()
		}
		restarts++
		slog.Warn("cleave server crashed", "error", err, "restarts", restarts)
		if restarts > maxRestarts {
			return fmt.Errorf("cleave crashed %d times, giving up", restarts)
		}

		// Exponential backoff: 1s, 2s, 4s, 8s, capped at 30s.
		delay := time.Duration(1<<min(restarts-1, 4)) * time.Second
		slog.Info("restarting cleave server", "delay", delay)
		select {
		case <-time.After(delay):
		case <-ctx.Done():
			return ctx.Err()
		}

		s.mu.Lock()
		err = s.startLocked(ctx)
		s.mu.Unlock()
		if err != nil {
			slog.Error("failed to restart cleave", "error", err)
			continue
		}
		slog.Info("cleave server restarted", "restarts", restarts)
	}
}

func (s *cleaveServer) waitExit(ctx context.Context) error {
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

func (s *cleaveServer) waitHealthy(ctx context.Context) error {
	deadline := time.After(90 * time.Second) // cleave takes ~27s to load traits+yara
	ticker := time.NewTicker(500 * time.Millisecond)
	defer ticker.Stop()

	for {
		select {
		case <-deadline:
			return errors.New("timeout waiting for cleave to start")
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

// cleaveResult is the subset of the cleave response we extract for the DB.
type cleaveResult struct {
	CanonicalSHA256 string
}

// Analyze sends a file to the cleave server for analysis.
// Returns the raw JSON response and extracted metadata.
// Retries on 503 (memory pressure / overload) with backoff.
func (s *cleaveServer) Analyze(ctx context.Context, sha256, path string) (json.RawMessage, *cleaveResult, error) {
	body, err := json.Marshal(struct {
		Path string `json:"path"`
	}{Path: path})
	if err != nil {
		return nil, nil, err
	}

	const maxRetries = 5
	for attempt := range maxRetries {
		raw, result, err := s.doAnalyze(ctx, sha256, body)
		if err == nil {
			return raw, result, nil
		}
		if !errors.Is(err, errRetryable) {
			return nil, nil, err
		}
		delay := time.Duration(1<<min(attempt, 3)) * time.Second
		slog.Debug("cleave returned 503, backing off", "path", path, "delay", delay)
		select {
		case <-time.After(delay):
		case <-ctx.Done():
			return nil, nil, ctx.Err()
		}
	}
	return nil, nil, fmt.Errorf("cleave: max retries exceeded for %s", path)
}

var errRetryable = errors.New("service unavailable")

func (s *cleaveServer) doAnalyze(ctx context.Context, sha256 string, body []byte) (json.RawMessage, *cleaveResult, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, s.url+"/analyze-path", bytes.NewReader(body))
	if err != nil {
		return nil, nil, err
	}
	req.Header.Set("Content-Type", "application/json")

	resp, err := s.client.Do(req) //nolint:gosec // URL is constructed from localhost + port
	if err != nil {
		return nil, nil, err
	}
	defer resp.Body.Close() //nolint:errcheck // HTTP response

	if resp.StatusCode == http.StatusServiceUnavailable {
		return nil, nil, errRetryable
	}
	if resp.StatusCode != http.StatusOK {
		msg, _ := io.ReadAll(io.LimitReader(resp.Body, 512)) //nolint:errcheck // best-effort error body
		return nil, nil, fmt.Errorf("cleave: %d %s", resp.StatusCode, msg)
	}

	raw, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, nil, fmt.Errorf("cleave: read response: %w", err)
	}

	result, err := extractCleaveResult(sha256, raw)
	if err != nil {
		return raw, nil, fmt.Errorf("cleave: parse response: %w", err)
	}

	return raw, result, nil
}

// extractCleaveResult pulls risk and finding count from the cleave JSON.
// The response has summary.max_risk (string) and summary.counts (hostile/suspicious/notable).
func extractCleaveResult(sha256 string, raw []byte) (*cleaveResult, error) {
	var resp struct {
		Files []struct {
			SHA256 string `json:"sha"`
		} `json:"fs"`
	}
	if err := json.Unmarshal(raw, &resp); err != nil {
		return nil, err
	}

	// Compute canonical SHA from the parsed files array.
	canonical := sha256
	for _, f := range resp.Files {
		if len(f.SHA256) == 64 && f.SHA256 < canonical {
			canonical = f.SHA256
		}
	}
	return &cleaveResult{CanonicalSHA256: canonical}, nil
}

// Workers returns the max concurrent analysis workers.
func (s *cleaveServer) Workers() int { return s.maxWorkers }

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
