package main

import (
	"context"
	"log/slog"
	"net"
	"net/http"
	"os"
	"strconv"
	"strings"
	"time"
)

// sdwatchdog.go wires hopper to the systemd service watchdog (WatchdogSec=).
//
// The pings are self-attesting: hopper sends WATCHDOG=1 only after a GET
// /healthz against its own listener succeeds over a *fresh* TCP connection.
// That exercises the exact path that died in the 2026-07-09 incident — the
// accept loop starved under cgroup memory pressure while established
// keep-alive connections (worker polls, Prometheus scrapes) kept being
// served, so every in-band liveness signal stayed green for hours. A probe
// that dials anew cannot be fooled that way: accepts wedge → probe fails →
// pings stop → systemd delivers SIGABRT (the Go runtime dumps every goroutine
// stack to the journal, so the wedge is diagnosable post-mortem) and
// Restart= brings hopper back.

// runSDWatchdog feeds the systemd watchdog until ctx is cancelled. It returns
// immediately when not running under a watchdog-armed systemd unit, so it is
// safe to start unconditionally. dashAddr is the dashboard/API listen address
// to probe; when the dashboard is disabled the pings degrade to attesting
// bare process liveness.
func runSDWatchdog(ctx context.Context, dashAddr string) {
	interval, ok := sdWatchdogInterval()
	if !ok {
		return
	}
	probeURL := ""
	if dashAddr != "" {
		// A wildcard bind isn't dialable; probe it via loopback.
		if after, found := strings.CutPrefix(dashAddr, "0.0.0.0:"); found {
			dashAddr = "127.0.0.1:" + after
		}
		probeURL = "http://" + dashAddr + "/healthz"
	}
	client := &http.Client{
		// Well under the ping cadence so a hung probe can't make us skip
		// the next window by accident — only a genuinely dead listener does.
		Timeout: max(time.Second, min(interval/4, 10*time.Second)),
		// Fresh TCP connection per probe: the accept path is the thing
		// under test, and a pooled connection would attest nothing.
		Transport: &http.Transport{DisableKeepAlives: true},
	}
	slog.Info("systemd watchdog armed", "interval", interval, "probe", probeURL)
	// Ping at half the budget (systemd's recommendation): one failed or slow
	// probe still leaves a full probe cycle before the deadline.
	ticker := time.NewTicker(interval / 2)
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
		}
		if probeURL != "" {
			resp, err := client.Get(probeURL) //nolint:noctx // deadline comes from client.Timeout; ctx cancel just stops the loop
			if err != nil {
				slog.Warn("watchdog self-probe failed; withholding WATCHDOG=1", "error", err)
				continue
			}
			_ = resp.Body.Close() //nolint:errcheck // nothing useful to do with a close error on a drained probe
			if resp.StatusCode != http.StatusOK {
				slog.Warn("watchdog self-probe unhealthy; withholding WATCHDOG=1", "status", resp.StatusCode)
				continue
			}
		}
		sdNotify("WATCHDOG=1")
	}
}

// sdWatchdogInterval returns the watchdog budget systemd armed for this
// process, or ok=false when there is none (not under systemd, WatchdogSec
// unset, or the watchdog is aimed at a different pid).
func sdWatchdogInterval() (time.Duration, bool) {
	usecStr := os.Getenv("WATCHDOG_USEC")
	if usecStr == "" || os.Getenv("NOTIFY_SOCKET") == "" {
		return 0, false
	}
	if pidStr := os.Getenv("WATCHDOG_PID"); pidStr != "" {
		if pid, err := strconv.Atoi(pidStr); err != nil || pid != os.Getpid() {
			return 0, false
		}
	}
	usec, err := strconv.ParseInt(usecStr, 10, 64)
	if err != nil || usec <= 0 {
		slog.Warn("unparseable WATCHDOG_USEC; systemd watchdog disabled",
			"value", sanitizeLogString(usecStr))
		return 0, false
	}
	return time.Duration(usec) * time.Microsecond, true
}

// sdNotify sends one datagram to the systemd notify socket. Best-effort by
// design: a failed send is indistinguishable from a withheld ping, which is
// exactly the fail-safe direction (systemd restarts rather than trusts).
func sdNotify(state string) {
	sock := os.Getenv("NOTIFY_SOCKET")
	if sock == "" {
		return
	}
	if strings.HasPrefix(sock, "@") { // abstract socket namespace
		sock = "\x00" + sock[1:]
	}
	//nolint:noctx // dest is systemd's NOTIFY_SOCKET env (local unix dgram); connectionless, nothing for a ctx to cancel
	conn, err := net.Dial("unixgram", sock) //nolint:gosec // socket path is supplied by local systemd
	if err != nil {
		slog.Warn("dial systemd notify socket failed", "error", err)
		return
	}
	defer conn.Close() //nolint:errcheck // datagram socket, nothing buffered
	if _, err := conn.Write([]byte(state)); err != nil {
		slog.Warn("write to systemd notify socket failed", "error", err)
	}
}
