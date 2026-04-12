package main

import (
	"context"
	"fmt"
	"math"
	"net"
	"net/http"
	"strings"
	"time"
)

// webDashboard serves a self-contained HTML page with the same information as
// the TTY dashboard. Auto-refreshes every 5 seconds via <meta refresh>.
type webDashboard struct {
	progress      *loadProgress
	litmus        *litmusServer
	monitors      []*nodeMonitor
	start         time.Time
	startAnalyzed int64
	maxAnalyzed   int
	ndirs         int
}

func startWebDashboard(ctx context.Context, addr string, wd *webDashboard) error {
	mux := http.NewServeMux()
	mux.HandleFunc("/", wd.handler)

	ln, err := net.Listen("tcp", addr)
	if err != nil {
		return fmt.Errorf("web dashboard listen %s: %w", addr, err)
	}

	srv := &http.Server{Handler: mux, ReadHeaderTimeout: 5 * time.Second}
	go func() {
		<-ctx.Done()
		_ = srv.Close()
	}()
	go func() {
		if err := srv.Serve(ln); err != nil && err != http.ErrServerClosed {
			fmt.Printf("web dashboard error: %v\n", err) //nolint:forbidigo // startup diag
		}
	}()
	return nil
}

func (wd *webDashboard) handler(w http.ResponseWriter, _ *http.Request) {
	elapsed := time.Since(wd.start).Round(time.Second)

	analyzedAbs := wd.progress.analyzed.Load()
	sessionAnalyzed := max(analyzedAbs-wd.startAnalyzed, 0)
	walked := wd.progress.walked.Load()
	hashedN := wd.progress.hashed.Load()
	inserted := wd.progress.inserted.Load()
	skipped := wd.progress.skipped.Load()
	hashDone := hashedN + wd.progress.tooSmall.Load() + wd.progress.tooLarge.Load() + wd.progress.hashErrors.Load()

	analyzeTarget := max(wd.progress.queued.Load()-wd.startAnalyzed, 0)
	if wd.maxAnalyzed > 0 && int64(wd.maxAnalyzed) < analyzeTarget {
		analyzeTarget = int64(wd.maxAnalyzed)
	}

	var b strings.Builder
	b.WriteString(`<!DOCTYPE html>
<html><head>
<meta charset="utf-8">
<meta http-equiv="refresh" content="5">
<title>Hopper Dashboard</title>
<style>
  body { font-family: monospace; background: #1a1a2e; color: #e0e0e0; margin: 2em; }
  h1 { color: #ffffff; font-size: 1.3em; }
  .bar-outer { background: #2a2a3e; border-radius: 4px; height: 22px; position: relative; margin: 6px 0; }
  .bar-inner { border-radius: 4px; height: 100%; transition: width 0.4s; }
  .bar-label { position: absolute; top: 2px; left: 8px; font-size: 0.85em; }
  table { border-collapse: collapse; margin-top: 1em; }
  th, td { text-align: left; padding: 4px 12px; }
  th { color: #aaa; border-bottom: 1px solid #333; }
  .ok { color: #4caf50; } .saturated { color: #4caf50; }
  .starting, .building { color: #ff9800; }
  .degraded, .failed { color: #ff9800; }
  .down { color: #f44336; }
  .dim { color: #888; }
  .stats { margin-top: 1em; color: #aaa; }
</style>
</head><body>
`)
	fmt.Fprintf(&b, "<h1>Hopper Loading Dashboard (%s)</h1>\n", elapsed)

	writeBar(&b, "Hashing", hashDone, walked, "#5c6bc0")
	writeBar(&b, "Insertion", inserted+skipped, hashedN, "#43a047")
	writeBar(&b, "Analysis", sessionAnalyzed, analyzeTarget, "#ef6c00")

	// Last error
	if last, ok := wd.progress.lastErr.Load().(string); ok && last != "" {
		fmt.Fprintf(&b, "<p style=\"color:#f44336\">Recent Error: %s</p>\n", htmlEscape(last))
	}

	// Pool table
	if len(wd.monitors) > 0 {
		totalSlots := 0
		for _, m := range wd.monitors {
			totalSlots += m.Slots()
		}
		fmt.Fprintf(&b, "<h1>Litmus Pool: %d nodes, %d slots</h1>\n", len(wd.monitors), totalSlots)
		b.WriteString("<table><tr><th>Node</th><th>Status</th><th>Uptime</th><th>Load</th><th>RSS</th><th>Tasks</th><th>Version</th><th>Traits</th><th>Detail</th></tr>\n")
		for _, m := range wd.monitors {
			snap := m.Snapshot()
			name := htmlEscape(m.Name())
			slots := m.Slots()
			if snap == nil {
				fmt.Fprintf(&b, "<tr><td>%s</td><td class=\"dim\">pending</td><td colspan=\"7\"></td></tr>\n", name)
				continue
			}
			status := poolStatusLabel(snap)
			cssClass := status
			if !snap.Reachable {
				cssClass = "down"
			}

			detail := ""
			if snap.Health.Reason != "" && snap.Health.Status != "ok" {
				detail = htmlEscape(snap.Health.Reason)
			}
			if snap.Health.OrphanedTasks > 0 {
				detail += fmt.Sprintf(" orphaned:%d", snap.Health.OrphanedTasks)
			}
			if snap.Restarts > 0 {
				detail += fmt.Sprintf(" restarts:%d", snap.Restarts)
			}

			version := snap.Version
			traits := shortCommit(snap.TraitsCommit)

			if !snap.Reachable {
				fmt.Fprintf(&b, "<tr><td>%s</td><td class=\"%s\">%s</td><td colspan=\"6\"></td><td class=\"dim\">%s</td></tr>\n",
					name, cssClass, status, htmlEscape(snap.LastErr))
			} else {
				fmt.Fprintf(&b, "<tr><td>%s</td><td class=\"%s\">%s</td><td>%s</td><td>%.2f</td><td>%d MB</td><td>%d/%d</td><td>%s</td><td><code>%s</code></td><td class=\"dim\">%s</td></tr>\n",
					name, cssClass, status,
					formatUptime(snap.Health.UptimeSecs),
					snap.Health.Load,
					snap.Health.RSSMB,
					snap.Health.LiveTasks, slots,
					htmlEscape(version),
					htmlEscape(traits),
					detail,
				)
			}
		}
		b.WriteString("</table>\n")
	}

	// Local worker info
	if wd.litmus != nil {
		summary := wd.litmus.workerSummary()
		if summary.Busy > 0 && summary.OldestFile != "" {
			fmt.Fprintf(&b, "<p class=\"dim\">oldest local: %s (%s)</p>\n",
				htmlEscape(summary.OldestFile),
				(time.Duration(summary.OldestMS)*time.Millisecond).Round(time.Second))
		}
	}

	fmt.Fprintf(&b, "<p class=\"stats\">Errors: %d &middot; Walked: %d &middot; Cache Hits: %d</p>\n",
		wd.progress.errors.Load(), walked, wd.progress.cacheHits.Load())

	b.WriteString("</body></html>\n")

	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	_, _ = fmt.Fprint(w, b.String())
}

func writeBar(b *strings.Builder, label string, done, total int64, color string) {
	pct := 0.0
	if total > 0 {
		pct = math.Min(float64(done)/float64(total)*100, 100)
	}
	fmt.Fprintf(b, `<div class="bar-outer"><div class="bar-inner" style="width:%.1f%%;background:%s"></div>`+
		`<span class="bar-label">%s %d/%d (%.0f%%)</span></div>`+"\n",
		pct, color, label, done, total, pct)
}

func shortCommit(s string) string {
	if len(s) > 8 {
		return s[:8]
	}
	return s
}

func htmlEscape(s string) string {
	s = strings.ReplaceAll(s, "&", "&amp;")
	s = strings.ReplaceAll(s, "<", "&lt;")
	s = strings.ReplaceAll(s, ">", "&gt;")
	s = strings.ReplaceAll(s, "\"", "&quot;")
	return s
}
