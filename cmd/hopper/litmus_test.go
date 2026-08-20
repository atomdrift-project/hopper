package main

import (
	"context"
	"os"
	"os/exec"
	"path/filepath"
	"slices"
	"testing"
	"time"
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

// cmdWithEnv builds a command whose environment and working directory are fully
// determined by the test, so the path resolvers never read the ambient process
// environment or the package directory.
func cmdWithEnv(dir string, env ...string) *exec.Cmd {
	cmd := exec.Command("cleave", "validate")
	cmd.Dir = dir
	cmd.Env = env
	return cmd
}

func TestResolvedTraitsDir(t *testing.T) {
	// A directory with no "traits" child, so the workspace-local probe misses
	// and resolution falls through to the data dir.
	bare := t.TempDir()

	workspace := t.TempDir()
	if err := os.Mkdir(filepath.Join(workspace, "traits"), 0o755); err != nil {
		t.Fatalf("mkdir traits: %v", err)
	}

	tests := []struct {
		name string
		cmd  *exec.Cmd
		want string
	}{{
		name: "explicit override wins",
		cmd:  cmdWithEnv(workspace, "CLEAVE_TRAITS_DIR=/opt/traits", "HOME=/home/svc"),
		want: "/opt/traits",
	}, {
		name: "workspace-local checkout beats the data dir",
		cmd:  cmdWithEnv(workspace, "HOME=/home/svc"),
		want: filepath.Join(workspace, "traits"),
	}, {
		// Regression guard: dropping "atomdrift" names a path cleave never
		// reads, which is what sent an operator after the wrong bundle.
		name: "data dir keeps the atomdrift segment",
		cmd:  cmdWithEnv(bare, "HOME=/home/svc"),
		want: "/home/svc/.local/share/atomdrift/cleave/traits",
	}, {
		name: "XDG_DATA_HOME overrides HOME",
		cmd:  cmdWithEnv(bare, "HOME=/home/svc", "XDG_DATA_HOME=/data/xdg"),
		want: "/data/xdg/atomdrift/cleave/traits",
	}, {
		name: "empty override falls through to the data dir",
		cmd:  cmdWithEnv(bare, "CLEAVE_TRAITS_DIR=", "HOME=/home/svc"),
		want: "/home/svc/.local/share/atomdrift/cleave/traits",
	}}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := resolvedTraitsDir(tt.cmd); got != tt.want {
				t.Errorf("resolvedTraitsDir() = %q, want %q", got, tt.want)
			}
		})
	}
}

func TestResolvedModelsDir(t *testing.T) {
	bare := t.TempDir()

	tests := []struct {
		name string
		cmd  *exec.Cmd
		want string
	}{{
		name: "explicit override wins",
		cmd:  cmdWithEnv(bare, "SCAN_MODELS_DIR=/opt/models", "HOME=/home/svc"),
		want: "/opt/models",
	}, {
		name: "data dir under HOME",
		cmd:  cmdWithEnv(bare, "HOME=/home/svc"),
		want: "/home/svc/.local/share/atomdrift/scan/models",
	}, {
		name: "XDG_DATA_HOME overrides HOME",
		cmd:  cmdWithEnv(bare, "HOME=/home/svc", "XDG_DATA_HOME=/data/xdg"),
		want: "/data/xdg/atomdrift/scan/models",
	}}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := resolvedModelsDir(tt.cmd); got != tt.want {
				t.Errorf("resolvedModelsDir() = %q, want %q", got, tt.want)
			}
		})
	}
}

// Both resolvers must agree on the data-dir base, since they describe two
// bundles the tools read from the same platform directory.
func TestResolvedDirsShareDataHome(t *testing.T) {
	bare := t.TempDir()
	cmd := cmdWithEnv(bare, "HOME=/home/svc")

	const base = "/home/svc/.local/share/atomdrift"
	if got := resolvedTraitsDir(cmd); filepath.Dir(filepath.Dir(got)) != base {
		t.Errorf("traits dir %q is not under %q", got, base)
	}
	if got := resolvedModelsDir(cmd); filepath.Dir(filepath.Dir(got)) != base {
		t.Errorf("models dir %q is not under %q", got, base)
	}
}

// An unconfigured binary must be skipped outright rather than exec'd as "",
// which would fail once per retry and bury the real reason in the log.
func TestRefreshToolRulesNoBinary(t *testing.T) {
	done := make(chan struct{})
	go func() {
		defer close(done)
		refreshToolRules(context.Background(), "cleave", "")
	}()

	select {
	case <-done:
	case <-time.After(10 * time.Second):
		t.Fatal("refreshToolRules with an empty binary did not return promptly")
	}
}

// A cancelled context must not leave the caller parked in the post-failure
// pause: superviseLocalWorker calls this on every failed attempt, and shutdown
// has to be observed there too.
func TestRefreshToolRulesCancelledContext(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	cancel()

	done := make(chan struct{})
	go func() {
		defer close(done)
		// A binary that does not exist fails immediately, driving the error path.
		refreshToolRules(ctx, "cleave", filepath.Join(t.TempDir(), "definitely-absent"))
	}()

	select {
	case <-done:
	case <-time.After(updateErrorDelay):
		t.Fatal("refreshToolRules ignored a cancelled context during its error pause")
	}
}

// A crash-looping worker opens a fresh litmus-*.log every spawn and nothing
// else reclaims them, so the sweep is the only bound on the state directory.
// It must drop aged-out logs, spare recent ones (an active worker's log is
// always recent), and leave unrelated files alone.
func TestSweepStaleLitmusLogs(t *testing.T) {
	t.Parallel()
	dir := t.TempDir()
	past := time.Now().Add(-2 * litmusLogMaxAge)

	write := func(name string, aged bool) string {
		path := filepath.Join(dir, name)
		if err := os.WriteFile(path, []byte("x"), 0o600); err != nil {
			t.Fatal(err)
		}
		if aged {
			if err := os.Chtimes(path, past, past); err != nil {
				t.Fatal(err)
			}
		}
		return path
	}

	stale := write("litmus-123.log", true)
	fresh := write("litmus-456.log", false)
	foreign := write("scan-789.log", true)
	wrongSuffix := write("litmus-789.txt", true)

	sweepStaleLitmusLogs(dir)

	if _, err := os.Stat(stale); !os.IsNotExist(err) {
		t.Errorf("stale litmus log was not removed: err=%v", err)
	}
	for _, keep := range []string{fresh, foreign, wrongSuffix} {
		if _, err := os.Stat(keep); err != nil {
			t.Errorf("%s was removed: err=%v", filepath.Base(keep), err)
		}
	}
}

// The spawn path creates the log directory first, so an unreadable one is
// abnormal — but it is still only worth a warning, never a failed spawn.
func TestSweepStaleLitmusLogsMissingDir(t *testing.T) {
	t.Parallel()
	sweepStaleLitmusLogs(filepath.Join(t.TempDir(), "absent"))
}

// TestWorkerArgsInterpret pins the LLM pass onto the local worker. It ran for
// months without --interpret while every remote fleet worker had it, so the
// worker claiming the largest share of the queue wrote no llm_result at all —
// invisible at runtime, because a scan with no interpretation succeeds exactly
// like one with it. The endpoint gate is the other half: bare --interpret aims
// at localhost:8000 and a missing endpoint costs a health-gate wait per sample.
func TestWorkerArgsInterpret(t *testing.T) {
	t.Parallel()

	has := slices.Contains[[]string, string]

	configured := newLitmusServer(litmusConfig{
		HopperURL: "http://127.0.0.1:8081",
		LLMURL:    "http://10.9.8.149:8000/v1",
	})
	args := configured.workerArgs()
	if !has(args, "--interpret") {
		t.Errorf("configured endpoint must pass --interpret, got %v", args)
	}

	off := newLitmusServer(litmusConfig{HopperURL: "http://127.0.0.1:8081"})
	if args := off.workerArgs(); has(args, "--interpret") {
		t.Errorf("no endpoint must leave --interpret off, got %v", args)
	}
}
