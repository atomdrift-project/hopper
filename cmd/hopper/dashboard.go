package main

import (
	"context"
	"fmt"
	"html"
	"log/slog"
	"math"
	"net"
	"net/http"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/codeGROOVE-dev/fido"

	"codeberg.org/atomdrift/hopper"
	"codeberg.org/atomdrift/obs"
)

// dashQueryTimeout bounds each dashboard stat query. The counts/aggregations
// are index-only scans over millions of rows (rescan backlog, pending groups),
// which can take several seconds under concurrent walk load; 3s was too tight
// and left tiles perpetually stale. Results are cached (see dashCacheTTL), so a
// query this slow runs at most about once per cache window, not per refresh.
const dashQueryTimeout = 10 * time.Second

// dashCacheTTL is how long a computed dashboard stat is served before a refresh
// recomputes it. Kept below the page auto-refresh interval so tiles stay live
// without rerunning the heavy queries on every request.
const dashCacheTTL = 45 * time.Second

// analysisRateWindow is the look-back used to measure live top-level analysis
// and rescan throughput for the queue ETAs. Wide enough to smooth the bursty
// way rescans are serviced — they run only on capacity left over after
// first-time analysis, so a short window swings between zero and a spike.
const analysisRateWindow = 60 * time.Minute

// minRescanRate is the rescans/sec below which the backlog is treated as not
// draining: first-time analysis is consuming the whole fleet, so any ETA would
// be a meaningless multi-year figure. ~72/hr.
const minRescanRate = 0.02

// webDashboard serves a self-contained HTML page. Auto-refreshes every 60s;
// expensive stats are cached (dashCacheTTL) so most refreshes hit memory.
// Fields guarded by cfgMu are set once via configure() after the load session
// begins; the handler renders a startup-status page until then.
type webDashboard struct {
	start         time.Time
	db            *hopper.DB
	progress      *loadProgress
	tracker       *workerTracker
	api           *apiServer // for live traits-version reads (refreshed every 2h)
	rescanCache   *fido.Cache[string, int64]
	ratesCache    *fido.Cache[string, hopper.AnalysisRates]
	pendingCache  *fido.Cache[string, int64]
	healthCache   *fido.Cache[string, hopper.WorkflowHealth]
	backlogCache  *fido.Cache[string, []hopper.WorkflowBacklog]
	samplesCache  *fido.Cache[string, []hopper.WorkflowSample]
	seriesCache   *fido.Cache[string, []queuePoint]
	newestATCache *fido.Cache[string, time.Time]
	metrics       *metricsStore
	litmus        *litmusServer
	traitsVersion string
	samples       []throughputSample
	stages        []*startupStage
	maxAnalyzed   int
	ndirs         int
	rescanAge     time.Duration
	cfgMu         sync.RWMutex
	mu            sync.Mutex
	stagesMu      sync.Mutex
}

// startupStage represents one named init step rendered on the bootstrap page.
// finished.IsZero() means still running. err non-empty means failed.
type startupStage struct {
	started  time.Time
	finished time.Time
	name     string
	label    string
	err      string
	current  int64
	total    int64
}

// findStage returns the existing stage with the given name, or nil.
// Caller must hold stagesMu.
func (wd *webDashboard) findStage(name string) *startupStage {
	for _, s := range wd.stages {
		if s.name == name {
			return s
		}
	}
	return nil
}

// beginStage records a new init step. Idempotent — repeated calls with the
// same name reset start time and clear any prior error / progress.
// No-op on a nil receiver so callers don't need to nil-check when the
// dashboard is disabled.
func (wd *webDashboard) beginStage(name, label string) {
	if wd == nil {
		return
	}
	wd.stagesMu.Lock()
	defer wd.stagesMu.Unlock()
	if s := wd.findStage(name); s != nil {
		s.started = time.Now()
		s.finished = time.Time{}
		s.label = label
		s.err = ""
		s.current = 0
		s.total = 0
		return
	}
	wd.stages = append(wd.stages, &startupStage{name: name, label: label, started: time.Now()})
}

// endStage marks a stage finished. No-op if unknown or receiver is nil.
func (wd *webDashboard) endStage(name string) {
	if wd == nil {
		return
	}
	wd.stagesMu.Lock()
	defer wd.stagesMu.Unlock()
	if s := wd.findStage(name); s != nil && s.finished.IsZero() {
		s.finished = time.Now()
	}
}

// failStage marks a stage failed with the given error message. No-op on nil.
func (wd *webDashboard) failStage(name, msg string) {
	if wd == nil {
		return
	}
	wd.stagesMu.Lock()
	defer wd.stagesMu.Unlock()
	if s := wd.findStage(name); s != nil {
		s.err = msg
		if s.finished.IsZero() {
			s.finished = time.Now()
		}
	}
}

func (wd *webDashboard) snapshotStages() []startupStage {
	wd.stagesMu.Lock()
	defer wd.stagesMu.Unlock()
	out := make([]startupStage, len(wd.stages))
	for i, s := range wd.stages {
		out[i] = *s
	}
	return out
}

// configure is called once the load session is ready. It sets the fields the
// handler needs to render progress and is safe to call concurrently with the
// HTTP server already running.
func (wd *webDashboard) configure( //nolint:revive // argument-limit: dashboard needs all session state at once
	progress *loadProgress, litmus *litmusServer, tracker *workerTracker, api *apiServer,
	db *hopper.DB, start time.Time, maxAnalyzed, ndirs int, traitsVersion string, rescanAge time.Duration,
	metrics *metricsStore,
) {
	wd.cfgMu.Lock()
	defer wd.cfgMu.Unlock()
	wd.metrics = metrics
	wd.progress = progress
	wd.litmus = litmus
	wd.tracker = tracker
	wd.api = api
	wd.db = db
	wd.start = start
	wd.maxAnalyzed = maxAnalyzed
	wd.ndirs = ndirs
	wd.traitsVersion = traitsVersion
	wd.rescanAge = rescanAge
	wd.newestATCache = fido.New[string, time.Time](fido.Size(1), fido.TTL(dashCacheTTL))
	wd.rescanCache = fido.New[string, int64](fido.Size(1), fido.TTL(dashCacheTTL))
	wd.ratesCache = fido.New[string, hopper.AnalysisRates](fido.Size(1), fido.TTL(dashCacheTTL))
	wd.pendingCache = fido.New[string, int64](fido.Size(1), fido.TTL(dashCacheTTL))
	wd.seriesCache = fido.New[string, []queuePoint](fido.Size(1), fido.TTL(dashCacheTTL))
	wd.healthCache = fido.New[string, hopper.WorkflowHealth](fido.Size(1), fido.TTL(dashCacheTTL))
	wd.backlogCache = fido.New[string, []hopper.WorkflowBacklog](fido.Size(1), fido.TTL(dashCacheTTL))
	wd.samplesCache = fido.New[string, []hopper.WorkflowSample](fido.Size(3), fido.TTL(dashCacheTTL))
}

const maxThroughputSamples = 2880 // ~48h at the 60s page refresh (one sample recorded per request)

type throughputSample struct {
	byNode map[string]int64 // keyed by worker name
	t      time.Time
	total  int64
}

func (wd *webDashboard) recordSample(total int64) {
	wd.mu.Lock()
	defer wd.mu.Unlock()
	s := throughputSample{t: time.Now(), total: total}
	if wd.tracker != nil {
		workers := wd.tracker.all()
		if len(workers) > 0 {
			s.byNode = make(map[string]int64, len(workers))
			for i := range workers {
				s.byNode[workers[i].Name] = workers[i].Analyzed
			}
		}
	}
	wd.samples = append(wd.samples, s)
	if len(wd.samples) > maxThroughputSamples {
		wd.samples = wd.samples[len(wd.samples)-maxThroughputSamples:]
	}
}

// ratesOver returns the average files/sec over the most recent window,
// both combined and per-node. Per-node rates are keyed by worker name.
func (wd *webDashboard) ratesOver(window time.Duration) (combined float64, perNode map[string]float64) {
	wd.mu.Lock()
	n := len(wd.samples)
	if n < 2 {
		wd.mu.Unlock()
		return 0, nil
	}
	latest := wd.samples[n-1]
	cutoff := latest.t.Add(-window)
	oldest := wd.samples[0]
	for _, s := range wd.samples {
		if !s.t.Before(cutoff) {
			oldest = s
			break
		}
	}
	wd.mu.Unlock()
	dt := latest.t.Sub(oldest.t).Seconds()
	if dt < 5 {
		return 0, nil
	}
	combined = max(float64(latest.total-oldest.total)/dt, 0)
	if len(latest.byNode) > 0 {
		perNode = make(map[string]float64, len(latest.byNode))
		for name, latestCount := range latest.byNode {
			if oldCount, ok := oldest.byNode[name]; ok {
				perNode[name] = max(float64(latestCount-oldCount)/dt, 0)
			} // else: worker joined after the oldest sample; skip.
		}
	}
	return combined, perNode
}

func startWebDashboard(ctx context.Context, addr string, wd *webDashboard, mux *http.ServeMux) error {
	mux.HandleFunc("/", wd.handler)
	ln, err := (&net.ListenConfig{}).Listen(ctx, "tcp", addr)
	if err != nil {
		return fmt.Errorf("web dashboard listen %s: %w", addr, err)
	}
	srv := &http.Server{Handler: obs.Middleware(mux), ReadHeaderTimeout: 5 * time.Second, IdleTimeout: 60 * time.Second}
	go func() {
		<-ctx.Done()
		// Graceful shutdown — let in-flight /data/* downloads finish so workers
		// don't see "error decoding response body" mid-stream. Detach from the
		// cancelled parent (it's the trigger, not a deadline). Close as a
		// fallback if a slow client keeps the server alive past the deadline.
		shutdownCtx, cancel := context.WithTimeout(context.WithoutCancel(ctx), 30*time.Second)
		defer cancel()
		if err := srv.Shutdown(shutdownCtx); err != nil {
			slog.Warn("web dashboard graceful shutdown timed out; forcing close", "error", err)
			_ = srv.Close() //nolint:errcheck // last-resort close after Shutdown timeout
		}
	}()
	go func() {
		if err := srv.Serve(ln); err != nil && err != http.ErrServerClosed {
			fmt.Printf("web dashboard error: %v\n", err) //nolint:forbidigo // startup diag
		}
	}()
	return nil
}

// ---------------------------------------------------------------------------
// Web dashboard.
// ---------------------------------------------------------------------------.

const css = `
*,*::before,*::after{box-sizing:border-box;margin:0;padding:0}
:root{
  --bg:#0b0d13;--surface:#10131b;--border:#1a1f2e;
  --text:#c4cdde;--sub:#4e5a72;--dim:#2d3448;
  --mono:"SF Mono","Fira Code",ui-monospace,monospace;
  --sans:-apple-system,BlinkMacSystemFont,"Segoe UI",system-ui,sans-serif;
  --green:#34d399;--amber:#fbbf24;--red:#f87171;--blue:#818cf8;
}
body{font-family:var(--sans);background:var(--bg);color:var(--text);
  font-size:13px;line-height:1.6;padding:2.5rem 3rem;max-width:1180px}

/* header */
.hdr{padding-bottom:1.5rem;margin-bottom:2rem;border-bottom:1px solid var(--border)}
.hdr-top{display:flex;align-items:baseline;gap:1rem;margin-bottom:1.25rem}
.hdr-title{font-size:.7rem;font-weight:700;letter-spacing:.12em;
  text-transform:uppercase;color:var(--sub)}
.hdr-time{font-family:var(--mono);font-size:.82rem;color:var(--sub)}

/* progress */
.progress{margin-bottom:.75rem}
.progress-stats{display:flex;justify-content:space-between;
  align-items:baseline;margin-bottom:.5rem}
.progress-main{font-family:var(--mono);font-size:1.1rem;font-weight:600}
.progress-pct{color:var(--text)}
.progress-detail{font-family:var(--mono);font-size:.82rem;color:var(--sub)}
.progress-detail em{font-style:normal;color:var(--text)}
.track{height:4px;background:var(--border);border-radius:2px;overflow:hidden;display:flex}
.fill{height:100%;border-radius:2px;transition:width .5s ease;flex-shrink:0}
.queue-grid{display:grid;grid-template-columns:repeat(4,minmax(0,1fr));gap:.75rem;margin-top:1rem}
.queue-card{background:var(--surface);border:1px solid var(--border);border-radius:6px;padding:.8rem .9rem}
.queue-label{font-size:.62rem;font-weight:700;letter-spacing:.11em;text-transform:uppercase;color:var(--sub);margin-bottom:.35rem}
.queue-value{font-family:var(--mono);font-size:1.05rem;color:var(--text);font-weight:600;line-height:1.25}
.queue-meta{font-family:var(--mono);font-size:.76rem;color:var(--sub);margin-top:.35rem}
.queue-meta em{font-style:normal;color:var(--text)}
.queue-note{color:var(--amber)}
.health-grid{display:grid;grid-template-columns:repeat(4,minmax(0,1fr));gap:.75rem}
.metric-card{background:var(--surface);border:1px solid var(--border);border-radius:6px;padding:.75rem .85rem}
.metric-label{font-size:.62rem;font-weight:700;letter-spacing:.11em;text-transform:uppercase;color:var(--sub);margin-bottom:.3rem}
.metric-value{font-family:var(--mono);font-size:.95rem;color:var(--text);font-weight:600}
.metric-sub{font-family:var(--mono);font-size:.72rem;color:var(--sub);margin-top:.25rem}
.pill{display:inline-block;border:1px solid var(--border);border-radius:4px;padding:.05rem .35rem;font-size:.7rem;font-family:var(--mono)}
.pill.hostile{color:#fca5a5;border-color:#3d1515;background:#1a0d0d}
.pill.suspicious{color:#fde68a;border-color:#3b2a0a;background:#171202}
.pill.benign{color:#86efac;border-color:#12331f;background:#06150c}
.pill.pending{color:var(--sub)}

/* section */
section{margin-bottom:2rem}
.label{font-size:.65rem;font-weight:700;letter-spacing:.12em;
  text-transform:uppercase;color:var(--sub);margin-bottom:.75rem}

/* nodes */
table{width:100%;border-collapse:collapse}
thead th{font-size:.65rem;font-weight:600;letter-spacing:.1em;
  text-transform:uppercase;color:var(--sub);
  padding:.25rem .6rem .5rem;text-align:left;border-bottom:1px solid var(--border)}
tbody tr{border-bottom:1px solid var(--border)}
tbody tr:last-child{border-bottom:none}
tbody td{padding:.5rem .6rem;font-family:var(--mono);font-size:.8rem;color:var(--sub)}
td.nn{font-family:var(--sans);color:var(--text);font-weight:500;
  font-size:.82rem;white-space:nowrap}
td.hi{color:var(--text)}
td.rate{color:var(--text);white-space:nowrap}
th.col-rss,td.col-rss{width:7.2ch;min-width:7.2ch;white-space:nowrap}
td.warn{color:var(--amber)}

/* status dot */
.dot{font-size:.5rem;vertical-align:middle;margin-right:.35rem}
.dot-ok{color:var(--green)}
.dot-fresh{color:#f5f7fa}
.dot-warn{color:var(--amber)}
.dot-bad{color:var(--red)}
.dot-off{color:var(--sub)}

/* error */
.err{background:#1a0d0d;border:1px solid #3d1515;border-radius:4px;
  padding:.5rem .75rem;font-size:.78rem;color:#f87171;margin-top:1.5rem;
  word-break:break-all;font-family:var(--mono)}
.err-inline{color:var(--red);font-family:var(--mono)}
.banner-down{background:var(--red);color:#fff;font-weight:700;font-size:1rem;
  padding:.85rem 1.25rem;margin-bottom:1.5rem;border-radius:4px;letter-spacing:.02em}
.banner-since{font-weight:400;opacity:.85;font-family:var(--mono);font-size:.82rem;margin-left:.5rem}
.banner-detail{margin:.6rem 0 0;padding:.5rem .7rem;background:rgba(0,0,0,.25);border-radius:3px;
  font-family:var(--mono);font-size:.78rem;font-weight:400;line-height:1.4;
  white-space:pre-wrap;word-break:break-all;overflow-x:auto;max-height:8rem}
.err-stage{color:var(--red)}
.err-time{white-space:nowrap;color:var(--sub)}
.err-msg{word-break:break-word;color:#fca5a5}

/* graph */
.graph-box{background:var(--surface);border:1px solid var(--border);
  border-radius:6px;padding:.75rem 1rem 0}
.graph-row{display:flex;gap:1rem;flex-wrap:wrap}
.graph-row .graph-mini{flex:1 1 0;min-width:240px;padding-bottom:.5rem}
.graph-title{font-size:.72rem;color:var(--sub);font-family:var(--mono);
  padding-bottom:.4rem;display:flex;justify-content:space-between;gap:.5rem}
.graph-title em{color:var(--text);font-style:normal}
.graph-note{font-size:.72rem;color:var(--sub);font-family:var(--mono);
  padding:.5rem 0}
.graph-legend{display:flex;gap:1rem;padding:.5rem 0;flex-wrap:wrap}
.legend-item{display:flex;align-items:center;gap:.35rem;
  font-size:.72rem;color:var(--sub);font-family:var(--mono)}
.legend-swatch{width:12px;height:2px;border-radius:1px}

/* footer */
footer{padding-top:1rem;border-top:1px solid var(--border);
  font-family:var(--mono);font-size:.75rem;color:var(--sub)}
@media (max-width:900px){body{padding:1.25rem;max-width:none}.queue-grid,.health-grid{grid-template-columns:1fr}}
`

// renderStartup writes the bootstrap HTML page shown before the load session is
// armed. Lists each init stage (running, done, or failed) with elapsed time and
// progress where known.
func (wd *webDashboard) renderStartup(w http.ResponseWriter) {
	stages := wd.snapshotStages()
	w.Header().Set("Content-Type", "text/html; charset=utf-8")

	var buf strings.Builder
	buf.WriteString(`<!DOCTYPE html><html lang="en"><head>` +
		`<meta charset="utf-8"><meta http-equiv="refresh" content="2">` +
		`<title>hopper</title><style>` + css + `</style></head><body>`)
	buf.WriteString(`<div class="hdr"><div class="hdr-top">`)
	buf.WriteString(`<span class="hdr-title">Hopper</span>`)
	buf.WriteString(`<span class="hdr-time">starting&hellip;</span>`)
	buf.WriteString(`</div></div>`)

	if len(stages) == 0 {
		buf.WriteString(`</body></html>`)
		_, _ = w.Write([]byte(buf.String())) //nolint:errcheck // best-effort HTTP response
		return
	}

	buf.WriteString(`<section><div class="label">Initializing</div><table><tbody>`)
	now := time.Now()
	for i := range stages {
		s := &stages[i]
		end := s.finished
		if end.IsZero() {
			end = now
		}
		dur := end.Sub(s.started).Round(100 * time.Millisecond)
		dot := "dot-warn"
		switch {
		case s.err != "":
			dot = "dot-bad"
		case !s.finished.IsZero():
			dot = "dot-ok"
		default:
			// running — leave dot-warn
		}
		//nolint:gosec // dot is a literal CSS class; label is HTML-escaped.
		fmt.Fprintf(&buf, `<tr><td><span class="dot %s">&#9679;</span>%s</td>`, dot, html.EscapeString(s.label))
		buf.WriteString(`<td class="rate">`)
		switch {
		case s.err != "":
			//nolint:gosec // err is HTML-escaped before write.
			fmt.Fprintf(&buf, `<span class="err-inline">%s</span>`, html.EscapeString(s.err))
		case s.total > 0 && s.current <= s.total:
			pct := float64(s.current) / float64(s.total) * 100
			//nolint:gosec // fmtN emits only digits and commas; pct is a float.
			fmt.Fprintf(&buf, `%s / %s (%.0f%%)`, fmtN(s.current), fmtN(s.total), pct)
		case s.current > 0:
			// Either no upfront total, or current overshot it — show raw count
			// rather than a misleading > 100% ratio.
			//nolint:gosec // fmtN emits only digits and commas.
			fmt.Fprintf(&buf, `%s processed`, fmtN(s.current))
		default:
			// no progress signal — render the duration only
		}
		//nolint:gosec // dur formats as a Go duration literal (digits + units).
		fmt.Fprintf(&buf, `</td><td>%s</td></tr>`, dur)
	}
	buf.WriteString(`</tbody></table></section>`)
	buf.WriteString(`</body></html>`)
	_, _ = w.Write([]byte(buf.String())) //nolint:errcheck // best-effort HTTP response
}

func (wd *webDashboard) handler(w http.ResponseWriter, r *http.Request) { //nolint:maintidx,gocognit,revive // dashboard handler has many query parameters and is long but flat
	wd.cfgMu.RLock()
	progress := wd.progress
	tracker := wd.tracker
	db := wd.db
	start := wd.start
	_ = wd.maxAnalyzed // reserved for future use
	wd.cfgMu.RUnlock()

	if progress == nil {
		wd.renderStartup(w)
		return
	}

	var workers []namedWorkerStats
	if tracker != nil {
		workers = tracker.all()
	}

	// Oldest active claim per worker — read from the in-memory tracker.
	oldestClaims := map[string]hopper.WorkerClaim{}
	if tracker != nil {
		oldestClaims = tracker.oldestPerWorker(staleClaimAge)
	}
	var newestAnalyzedAt time.Time
	if db != nil {
		//nolint:contextcheck,errcheck // closure creates its own context; closure logs errors before returning
		newestAnalyzedAt, _ = wd.newestATCache.Fetch("newest", func() (time.Time, error) {
			qctx, cancel := context.WithTimeout(r.Context(), dashQueryTimeout)
			defer cancel()
			t, err := db.NewestAnalyzedAt(qctx)
			if err != nil {
				slog.Warn("dashboard: NewestAnalyzedAt failed", "error", err)
			}
			return t, err
		})
	}

	var rescanPending int64
	if db != nil && wd.traitsVersion != "" {
		tv := wd.traitsVersion
		ra := wd.rescanAge
		//nolint:contextcheck,errcheck // closure creates its own context; closure logs errors before returning
		rescanPending, _ = wd.rescanCache.Fetch("rescan", func() (int64, error) {
			qctx, cancel := context.WithTimeout(r.Context(), dashQueryTimeout)
			defer cancel()
			n, err := db.CountRescanPending(qctx, tv, ra)
			if err != nil {
				slog.Warn("dashboard: CountRescanPending failed", "error", err)
			}
			return n, err
		})
	}

	// Top-level analysis and rescan rates, measured at the DB so they count
	// items the queue backlog is denominated in (parent = ''), not the ~80x
	// larger files/sec the fleet reports once exploded archive members are
	// included. Dividing a top-level backlog by a files/sec rate is what made
	// the old ETAs wildly optimistic.
	var topLevelRate, rescanRate float64
	if db != nil {
		//nolint:contextcheck,errcheck // closure creates its own context; closure logs errors before returning
		rates, _ := wd.ratesCache.Fetch("rates", func() (hopper.AnalysisRates, error) {
			qctx, cancel := context.WithTimeout(r.Context(), dashQueryTimeout)
			defer cancel()
			v, err := db.AnalysisRatesSince(qctx, analysisRateWindow)
			if err != nil {
				slog.Warn("dashboard: AnalysisRatesSince failed", "error", err)
			}
			return v, err
		})
		topLevelRate = float64(rates.TopLevel) / analysisRateWindow.Seconds()
		rescanRate = float64(rates.Rescans) / analysisRateWindow.Seconds()
	}

	var workflow dashboardWorkflow
	if db != nil {
		workflow = wd.fetchWorkflow(r.Context(), db)
	}

	elapsed := time.Since(start).Round(time.Second)
	analyzedAbs := progress.analyzed.Load()
	sessionAnalyzed := max(analyzedAbs-progress.startAnalyzed.Load(), 0)
	walked := progress.walked.Load()
	inserted := progress.inserted.Load()
	skipped := progress.skipped.Load()

	insertDone := inserted + skipped + progress.tooSmall.Load() + progress.tooLarge.Load() + progress.hashErrors.Load()
	inPipeline := max(walked-insertDone, 0)

	// Pending is the live database count (cleave_result IS NULL, not skipped,
	// not a child), cached so it costs one indexed count per dashCacheTTL.
	// Deriving it from in-memory progress counters drifts permanently: samples
	// that leave the pool via skip / permanent failure are never subtracted, so
	// the old estimate only ever grew (and read ~30k high). The analyzed/total
	// denominator follows from the live count.
	var pending int64
	if db != nil {
		//nolint:contextcheck,errcheck // closure creates its own context; closure logs errors before returning
		pending, _ = wd.pendingCache.Fetch("pending", func() (int64, error) {
			qctx, cancel := context.WithTimeout(r.Context(), dashQueryTimeout)
			defer cancel()
			n, err := db.CountPending(qctx)
			if err != nil {
				slog.Warn("dashboard: CountPending failed", "error", err)
			}
			return n, err
		})
	}
	totalExpected := analyzedAbs + pending

	wd.recordSample(sessionAnalyzed)
	rate, nodeRateByName := wd.ratesOver(15 * time.Minute)

	var initialETA string
	if topLevelRate > 0.001 && pending > 0 {
		initialETA = formatETA(time.Duration(float64(pending)/topLevelRate) * time.Second)
	}
	// Rescan ETA divides the backlog by the *measured* rescan rate, not the
	// overall analysis rate: rescans are the lowest claim tier and only run on
	// capacity left after first-time analysis, so the total rate overstates
	// progress by orders of magnitude. A near-zero rate means ingestion is
	// consuming the whole fleet and the backlog isn't draining.
	var rescanETA string
	if rescanRate > minRescanRate && rescanPending > 0 {
		rescanETA = formatETA(time.Duration(float64(rescanPending)/rescanRate) * time.Second)
	}

	pct := 0.0
	if totalExpected > 0 {
		pct = math.Min(float64(analyzedAbs)/float64(totalExpected)*100, 100)
	}

	var buf strings.Builder
	buf.WriteString(`<!DOCTYPE html><html lang="en"><head>` +
		`<meta charset="utf-8"><meta http-equiv="refresh" content="60">` +
		`<title>hopper</title><style>` + css + `</style></head><body>`)

	// Big red banner when the local scan (ascan) worker is down — crashing or
	// not starting. Reason, onset timestamp, and the last few log/output lines
	// come straight from the worker's published health (see superviseLocalWorker
	// / litmusServer.setHealth) so the banner is enough to debug the failure.
	if wd.litmus != nil {
		if h := wd.litmus.healthSnapshot(); h != nil && !h.ok {
			buf.WriteString(`<div class="banner-down">`)
			fmt.Fprintf(&buf,
				`&#9888; LOCAL SCAN WORKER DOWN &mdash; %s<span class="banner-since">since %s</span>`,
				html.EscapeString(h.reason),
				html.EscapeString(h.since.Format("2006-01-02 15:04:05 MST")))
			if h.detail != "" {
				fmt.Fprintf(&buf, `<pre class="banner-detail">%s</pre>`, html.EscapeString(h.detail))
			}
			buf.WriteString(`</div>`)
		}
	}

	// Header + progress
	buf.WriteString(`<div class="hdr">`)
	buf.WriteString(`<div class="hdr-top">`)
	buf.WriteString(`<span class="hdr-title">Hopper</span>`)
	fmt.Fprintf(&buf, `<span class="hdr-time">%s</span>`, elapsed)
	buf.WriteString(`</div>`)

	// Initial-analysis progress — kept separate from rescan work, which is a
	// lower-priority queue in claimJobs.
	buf.WriteString(`<div class="progress">`)
	buf.WriteString(`<div class="progress-stats">`)
	fmt.Fprintf(&buf, `<span class="progress-main"><span class="progress-pct">%.0f%%</span> initial analysis</span>`, pct)

	buf.WriteString(`<span class="progress-detail">`)
	fmt.Fprintf(&buf, `<em>%s</em> / %s analyzed`, fmtN(analyzedAbs), fmtN(totalExpected))
	if pending > 0 {
		fmt.Fprintf(&buf, ` &middot; <em>%s</em> pending initial`, fmtN(pending))
	}
	// Rates live in the Throughput tile; the progress line stays about progress.
	if initialETA != "" {
		fmt.Fprintf(&buf, ` &middot; initial ETA <em>%s</em>`, initialETA)
	}
	buf.WriteString(`</span>`)
	buf.WriteString(`</div>`)

	// Bar — session progress only.
	fmt.Fprintf(&buf,
		`<div class="track">`+
			`<div class="fill" style="width:%.2f%%;background:#fbbf24"></div>`+
			`</div>`,
		pct)
	buf.WriteString(`</div>`) // .progress

	buf.WriteString(`<div class="queue-grid">`)
	writeQueueCard(&buf, "Initial queue", fmt.Sprintf("%s pending", fmtN(pending)), func() string {
		var parts []string
		parts = append(parts, fmt.Sprintf("<em>%s</em> total", fmtN(totalExpected)))
		if topLevelRate > 0.001 {
			parts = append(parts, fmt.Sprintf("<em>%.2f</em>/s", topLevelRate))
		}
		if initialETA != "" {
			parts = append(parts, "ETA <em>"+initialETA+"</em>")
		}
		return strings.Join(parts, " &middot; ")
	}())
	rescanMeta := "stale traits disabled"
	if wd.traitsVersion != "" {
		switch {
		case rescanPending == 0:
			rescanMeta = "caught up"
		case rescanETA != "":
			rescanMeta = "ETA <em>" + rescanETA + "</em>"
		default:
			// Below the floor for a meaningful ETA. Report the measured rate
			// (rescans/hr) rather than asserting a cause — a low rate can be
			// first-time analysis hogging the fleet OR workers starved waiting on
			// a slow candidate query, and the dashboard can't tell which.
			rescanMeta = fmt.Sprintf(`<span class="queue-note">barely draining &middot; %.0f/hr</span>`, rescanRate*3600)
		}
	}
	writeQueueCard(&buf, "Rescan queue", fmt.Sprintf("%s pending", fmtN(rescanPending)), rescanMeta)

	// Throughput tile: the rescan rate gets its own labeled home rather than
	// hiding on the rescan card's ETA line. The headline is top-level items/s
	// (what the queues drain in); the meta carries the much larger raw files/s
	// (archive members included) and, when enabled, the rescan slice of it.
	throughputMeta := fmt.Sprintf("<em>%.0f</em> files/s", rate)
	if wd.traitsVersion != "" {
		throughputMeta += fmt.Sprintf(" &middot; <em>%.2f</em> rescan/s", rescanRate)
	}
	writeQueueCard(&buf, "Throughput", fmt.Sprintf("%.2f items/s", topLevelRate), throughputMeta)

	ingestMeta := fmt.Sprintf("<em>%s</em> known &middot; <em>%s</em> inserted", fmtN(progress.cacheHits.Load()), fmtN(inserted))
	if !progress.walkDone.Load() || inPipeline > 0 {
		ingestMeta += ` &middot; <span class="queue-note">walking</span>`
	}
	writeQueueCard(&buf, "Walk / ingest", fmt.Sprintf("%s walked", fmtN(walked)), ingestMeta)
	buf.WriteString(`</div>`)
	buf.WriteString(`</div>`) // .hdr

	if workflow.hasHealth {
		writeWorkflowHealth(&buf, workflow.health)
	}
	writeWorkflowBacklogs(&buf, workflow.backlogs)
	writeWorkflowSamples(&buf, "Recent Samples", "Newest rows seen by Hopper", workflow.latestAdded, "created")
	writeWorkflowSamples(&buf, "Prism Ready", "Top-level rows by first analysis completion", workflow.latestReady, "first_analyzed")
	writeWorkflowSamples(&buf, "Oldest Pending Cleave", "Claimable top-level rows still missing cleave results", workflow.oldestPending, "updated")

	// Queue graphs: pending depth, rescan depth, and completion throughput
	// over the trailing window, all from the database's own counts (sampled
	// into the local metrics cache). They share one time axis but each scales
	// to its own maximum, since the three magnitudes differ by orders.
	var queuePoints []queuePoint
	if wd.metrics != nil {
		//nolint:contextcheck,errcheck // closure creates its own context; closure logs errors before returning
		queuePoints, _ = wd.seriesCache.Fetch("series", func() ([]queuePoint, error) {
			qctx, cancel := context.WithTimeout(r.Context(), dashQueryTimeout)
			defer cancel()
			pts, err := wd.metrics.series(qctx, time.Now().Add(-queueGraphWindow))
			if err != nil {
				slog.Warn("dashboard: queue metric series failed", "error", err)
			}
			return pts, err
		})
	}
	writeQueueGraphs(&buf, queuePoints, wd.metrics != nil)

	// Workers
	//nolint:nestif // flat per-worker cell formatting, consistent with this handler's documented long-but-flat style
	if len(workers) > 0 {
		// latestTraits is the canonical traits version we measure each
		// worker against. Read live from apiServer so the periodic
		// rules-rotation refresh is reflected immediately on the next
		// dashboard render.
		latestTraits := wd.traitsVersion
		if wd.api != nil {
			if v := wd.api.TraitsVersion(); v != "" {
				latestTraits = v
			}
		}

		buf.WriteString(`<section><div class="label">Workers</div>`)
		buf.WriteString(`<table><thead><tr>` +
			`<th>Worker</th><th>Litmus</th><th>Traits</th><th>Tools</th>` +
			`<th>Tasks</th><th>Seen</th><th>Rate</th>` +
			`<th class="col-rss">RSS</th><th>Load</th>` +
			`<th>Queue</th><th>Last Done</th><th>F/s</th><th>Err 15m</th>` +
			`<th>Analyzed</th><th>Errors</th><th>Oldest Job</th><th></th>` +
			`</tr></thead><tbody>`)

		sort.Slice(workers, func(i, j int) bool { return workers[i].Name < workers[j].Name })
		for i := range workers {
			w := &workers[i]
			idle := time.Since(w.LastSeen)
			status, _ := workerStatus(w.ActiveClaims, idle)
			// Color purely by recency: white within workerActiveWindow,
			// yellow up to workerInactiveWindow, red beyond.
			dotClass := "dot-fresh"
			switch {
			case idle >= workerInactiveWindow:
				dotClass = "dot-bad"
			case idle >= workerActiveWindow:
				dotClass = "dot-warn"
			default:
			}
			// Stale-traits also drops the worker to dot-warn (unless
			// it's already a worse status). Mismatch is only meaningful
			// if we have a known-good "latest" to compare against.
			traitsStale := latestTraits != "" && w.Traits != "" && w.Traits != latestTraits
			if traitsStale && dotClass == "dot-fresh" {
				dotClass = "dot-warn"
			}

			litmusCell := dashEm(w.Version)
			traitsCell := dashEm(w.Traits)
			if traitsStale {
				traitsCell = fmt.Sprintf(`<span class="warn">%s &rarr; %s</span>`,
					htmlEscape(w.Traits), htmlEscape(latestTraits))
			}

			nRate := nodeRateByName[w.Name]
			rateStr := "—"
			if nRate > 0.05 {
				rateStr = fmt.Sprintf("%.1f/s", nRate)
			}

			rssStr := "—"
			if w.RSSMB > 0 {
				if w.RSSMB >= 1024 {
					rssStr = fmt.Sprintf("%.1f GB", float64(w.RSSMB)/1024)
				} else {
					rssStr = fmt.Sprintf("%d MB", w.RSSMB)
				}
			}

			loadStr := "—"
			if w.Load1 > 0 {
				loadStr = fmt.Sprintf("%.2f", w.Load1)
			}

			oldestStr := "—"
			if claim, ok := oldestClaims[w.Name]; ok {
				age := time.Since(claim.ClaimedAt)
				oldestStr = fmt.Sprintf("%s (%s)", filepath.Base(claim.Path), shortDuration(age))
			}

			// Worker-reported local-queue telemetry (from /api/heartbeat).
			queueStr := "—"
			if w.Queue > 0 {
				if !w.OldestQueueSince.IsZero() {
					queueStr = fmt.Sprintf("%d · %s", w.Queue, shortDuration(time.Since(w.OldestQueueSince)))
				} else {
					queueStr = strconv.Itoa(w.Queue)
				}
			}

			lastDoneStr := "—"
			if !w.LastCompletion.IsZero() {
				lastDoneStr = shortDuration(time.Since(w.LastCompletion))
			}

			fpsStr := "—"
			if w.FilesPerSec > 0.005 {
				fpsStr = fmt.Sprintf("%.2f/s", w.FilesPerSec)
			}

			// Errors in the trailing 15 min, with the most recent message (and
			// how long ago) surfaced as a hover title.
			err15Cell := `<td>—</td>`
			if w.ErrorsRecent > 0 {
				title := w.LastError
				if !w.LastErrorAt.IsZero() {
					title = strings.TrimSpace(title + " · " + shortDuration(time.Since(w.LastErrorAt)) + " ago")
				}
				//nolint:gocritic // %q applies Go quoting; an HTML attribute needs htmlEscape with literal quotes
				err15Cell = fmt.Sprintf(`<td class="warn" title="%s">%d</td>`,
					htmlEscape(title), w.ErrorsRecent)
			}

			fmt.Fprintf(&buf,
				`<tr>`+
					`<td class="nn"><span class="dot %s">●</span>%s</td>`+
					`<td>%s</td>`+
					`<td>%s</td>`+
					`<td>%s</td>`+
					`<td class="hi">%d/%d</td>`+
					`<td class="hi">%s</td>`+
					`<td class="rate">%s</td>`+
					`<td class="col-rss">%s</td>`+
					`<td>%s</td>`+
					`<td>%s</td>`+
					`<td>%s</td>`+
					`<td class="rate">%s</td>`+
					`%s`+
					`<td class="hi">%s</td>`+
					`<td>%s</td>`+
					`<td>%s</td>`+
					`<td class="warn">%s</td>`+
					`</tr>`,
				dotClass, htmlEscape(w.Name),
				litmusCell,
				traitsCell,
				dashEm(w.Tools),
				w.ActiveClaims, w.Slots,
				shortDuration(idle),
				rateStr,
				rssStr,
				loadStr,
				htmlEscape(queueStr),
				htmlEscape(lastDoneStr),
				fpsStr,
				err15Cell,
				fmtN(w.Analyzed),
				fmtN(w.Errors),
				htmlEscape(oldestStr),
				htmlEscape(status),
			)
		}
		buf.WriteString(`</tbody></table></section>`)
	}

	writeRecentErrors(&buf, progress)
	writeFooter(&buf, progress, walked, inserted, skipped, newestAnalyzedAt)

	buf.WriteString(`</body></html>`)
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	_, _ = fmt.Fprint(w, buf.String()) //nolint:errcheck // best-effort HTTP response
}

type dashboardWorkflow struct {
	health        hopper.WorkflowHealth
	backlogs      []hopper.WorkflowBacklog
	latestAdded   []hopper.WorkflowSample
	latestReady   []hopper.WorkflowSample
	oldestPending []hopper.WorkflowSample
	hasHealth     bool
}

func (wd *webDashboard) fetchWorkflow(ctx context.Context, db *hopper.DB) dashboardWorkflow {
	var out dashboardWorkflow
	var outMu sync.Mutex
	var wg sync.WaitGroup

	run := func(label string, fn func(context.Context) error) {
		wg.Go(func() {
			qctx, cancel := context.WithTimeout(ctx, dashQueryTimeout)
			defer cancel()
			if err := fn(qctx); err != nil {
				slog.Warn("dashboard: workflow query failed", "query", label, "error", err)
			}
		})
	}

	if wd.healthCache != nil {
		run("health", func(qctx context.Context) error {
			h, err := wd.healthCache.Fetch("health", func() (hopper.WorkflowHealth, error) {
				return db.WorkflowHealth(qctx)
			})
			if err != nil {
				return err
			}
			outMu.Lock()
			out.health = h
			out.hasHealth = true
			outMu.Unlock()
			return nil
		})
	}
	if wd.backlogCache != nil {
		run("backlogs", func(qctx context.Context) error {
			rows, err := wd.backlogCache.Fetch("backlogs", func() ([]hopper.WorkflowBacklog, error) {
				return db.WorkflowBacklogs(qctx, 5)
			})
			if err != nil {
				return err
			}
			outMu.Lock()
			out.backlogs = rows
			outMu.Unlock()
			return nil
		})
	}
	if wd.samplesCache != nil {
		run("latest_added", func(qctx context.Context) error {
			rows, err := wd.samplesCache.Fetch("latest_added", func() ([]hopper.WorkflowSample, error) {
				return db.WorkflowLatestAdded(qctx, 5)
			})
			if err != nil {
				return err
			}
			outMu.Lock()
			out.latestAdded = rows
			outMu.Unlock()
			return nil
		})
		run("latest_ready", func(qctx context.Context) error {
			rows, err := wd.samplesCache.Fetch("latest_ready", func() ([]hopper.WorkflowSample, error) {
				return db.WorkflowLatestReady(qctx, 5)
			})
			if err != nil {
				return err
			}
			outMu.Lock()
			out.latestReady = rows
			outMu.Unlock()
			return nil
		})
		run("oldest_pending", func(qctx context.Context) error {
			rows, err := wd.samplesCache.Fetch("oldest_pending", func() ([]hopper.WorkflowSample, error) {
				return db.WorkflowOldestPending(qctx, 5)
			})
			if err != nil {
				return err
			}
			outMu.Lock()
			out.oldestPending = rows
			outMu.Unlock()
			return nil
		})
	}

	wg.Wait()
	return out
}

func writeQueueCard(buf *strings.Builder, label, value, meta string) {
	fmt.Fprintf(buf,
		`<div class="queue-card"><div class="queue-label">%s</div><div class="queue-value">%s</div><div class="queue-meta">%s</div></div>`,
		htmlEscape(label), htmlEscape(value), meta)
}

func writeWorkflowHealth(buf *strings.Builder, h hopper.WorkflowHealth) {
	buf.WriteString(`<section><div class="label">Workflow Health</div><div class="health-grid">`)
	writeMetricCard(buf, "Latest added", ageValue(h.LatestAdded), timeTitle(h.LatestAdded))
	writeMetricCard(buf, "Latest analyzed", ageValue(h.LatestAnalyzed), timeTitle(h.LatestAnalyzed))
	writeMetricCard(buf, "Prism ready", ageValue(h.LatestReady), readyLag(h.LatestAdded, h.LatestReady))
	writeMetricCard(buf, "Workflow queues",
		fmt.Sprintf("%s / %s", fmtN(h.PendingCleave), fmtN(h.PendingLitmus)),
		"cleave pending / litmus pending")
	buf.WriteString(`</div></section>`)
}

func writeMetricCard(buf *strings.Builder, label, value, sub string) {
	//nolint:gosec // G705 false positive: every interpolated value is htmlEscape'd (html.EscapeString) before formatting.
	fmt.Fprintf(buf,
		`<div class="metric-card"><div class="metric-label">%s</div><div class="metric-value">%s</div><div class="metric-sub">%s</div></div>`,
		htmlEscape(label), htmlEscape(value), htmlEscape(sub))
}

func writeWorkflowBacklogs(buf *strings.Builder, rows []hopper.WorkflowBacklog) {
	if len(rows) == 0 {
		return
	}
	buf.WriteString(`<section><div class="label">Top Backlogs</div>`)
	buf.WriteString(`<table><thead><tr><th>Source</th><th>Feed</th><th>Ecosystem</th>` +
		`<th>Cleave</th><th>Litmus</th><th>Oldest</th><th>Newest</th></tr></thead><tbody>`)
	for i := range rows {
		r := &rows[i]
		//nolint:gosec // G705 false positive: string values are htmlEscape'd and fmtN emits only digits/commas.
		fmt.Fprintf(buf,
			`<tr><td>%s</td><td>%s</td><td class="hi">%s</td><td class="hi">%s</td><td>%s</td><td>%s</td><td>%s</td></tr>`,
			htmlEscape(dashIfEmpty(r.Source)),
			htmlEscape(dashIfEmpty(r.Feed)),
			htmlEscape(dashIfEmpty(r.Ecosystem)),
			fmtN(r.PendingCleave),
			fmtN(r.PendingLitmus),
			htmlEscape(ageValue(r.OldestPending)),
			htmlEscape(ageValue(r.NewestPending)))
	}
	buf.WriteString(`</tbody></table></section>`)
}

func writeWorkflowSamples(buf *strings.Builder, label, note string, samples []hopper.WorkflowSample, timeKind string) {
	if len(samples) == 0 {
		return
	}
	fmt.Fprintf(buf, `<section><div class="label">%s</div><div class="metric-sub">%s</div>`,
		htmlEscape(label), htmlEscape(note))
	buf.WriteString(`<table><thead><tr><th>When</th><th>State</th><th>Sample</th><th>Source</th><th>Ecosystem</th><th>SHA</th></tr></thead><tbody>`)
	for i := range samples {
		s := &samples[i]
		t := s.CreatedAt
		if timeKind == "updated" {
			t = s.UpdatedAt
		} else if timeKind == "first_analyzed" && s.FirstAnalyzedAt != nil {
			t = *s.FirstAnalyzedAt
		}
		name := firstNonEmpty(s.Filename, filepath.Base(s.Path), s.SHA256)
		//nolint:gosec // G705 false positive: every interpolated value is htmlEscape'd or constant HTML from workflowStateHTML.
		fmt.Fprintf(buf,
			`<tr><td title="%s">%s</td><td>%s</td><td class="hi">%s</td><td>%s</td><td>%s</td><td>%s</td></tr>`,
			htmlEscape(t.Format(time.RFC3339)),
			htmlEscape(ageValue(t)),
			workflowStateHTML(*s),
			htmlEscape(name),
			htmlEscape(dashIfEmpty(sourceFeed(s.Source, s.Feed))),
			htmlEscape(dashIfEmpty(s.Ecosystem)),
			htmlEscape(shortSHA(s.SHA256)))
	}
	buf.WriteString(`</tbody></table></section>`)
}

func workflowStateHTML(s hopper.WorkflowSample) string {
	if !s.HasCleave {
		return `<span class="pill pending">no cleave</span>`
	}
	if !s.HasLitmus {
		return `<span class="pill pending">no litmus</span>`
	}
	label, class := criticalityLabel(s.Criticality)
	return fmt.Sprintf(`<span class="pill %s">%s</span>`, class, htmlEscape(label))
}

func criticalityLabel(class int) (label, cssClass string) {
	switch class {
	case 2:
		return "hostile", "hostile"
	case 1:
		return "suspicious", "suspicious"
	case 0:
		return "benign", "benign"
	default:
		return "class " + strconv.Itoa(class), "pending"
	}
}

func ageValue(t time.Time) string {
	if t.IsZero() {
		return "—"
	}
	d := max(time.Since(t), 0)
	return shortDuration(d) + " ago"
}

func timeTitle(t time.Time) string {
	if t.IsZero() {
		return "no data"
	}
	return t.Format("2006-01-02 15:04:05 MST")
}

func readyLag(added, ready time.Time) string {
	if added.IsZero() || ready.IsZero() {
		return "no data"
	}
	if !added.After(ready) {
		return "caught up"
	}
	return "ready lag " + shortDuration(added.Sub(ready))
}

func sourceFeed(source, feed string) string {
	if feed == "" {
		return source
	}
	return source + "/" + feed
}

func dashIfEmpty(s string) string {
	if s == "" {
		return "—"
	}
	return s
}

func firstNonEmpty(vals ...string) string {
	for _, v := range vals {
		if v != "" && v != "." {
			return v
		}
	}
	return ""
}

func shortSHA(sha string) string {
	if len(sha) <= 12 {
		return sha
	}
	return sha[:12]
}

func writeRecentErrors(buf *strings.Builder, progress *loadProgress) {
	errs := progress.recentErrors()
	if len(errs) == 0 {
		return
	}
	buf.WriteString(`<section><div class="label">Recent Errors</div>`)
	buf.WriteString(`<table><thead><tr><th>Time</th><th>Stage</th><th>Error</th></tr></thead><tbody>`)
	for i := len(errs) - 1; i >= 0; i-- {
		e := errs[i]
		fmt.Fprintf(buf,
			`<tr><td class="err-time">%s</td><td class="err-stage">%s</td><td class="err-msg">%s</td></tr>`,
			htmlEscape(e.At.Format("15:04:05")),
			htmlEscape(e.Stage),
			htmlEscape(e.Message))
	}
	buf.WriteString(`</tbody></table></section>`)
}

// writeFooter renders the pipeline summary footer.
func writeFooter(buf *strings.Builder, progress *loadProgress, walked, inserted, skipped int64, newestAnalyzedAt time.Time) {
	cacheHits := progress.cacheHits.Load()
	tooSmall := progress.tooSmall.Load()
	tooLarge := progress.tooLarge.Load()
	errs := progress.errors.Load()
	lastCompleted := ""
	if !newestAnalyzedAt.IsZero() {
		lastCompleted = fmt.Sprintf(` &middot; last completed %s ago`, shortDuration(time.Since(newestAnalyzedAt)))
	}
	var footerParts []string
	walkStatus := "&hellip;"
	if progress.walkDone.Load() {
		walkStatus = "done"
	}
	dupes := max(skipped-cacheHits, 0)
	footerParts = append(footerParts, fmt.Sprintf("%s walked (%s) &middot; %s known &middot; %s new &middot; %s inserted",
		fmtN(walked), walkStatus, fmtN(cacheHits), fmtN(walked-cacheHits-tooSmall-tooLarge), fmtN(inserted)))
	if dupes > 0 {
		footerParts = append(footerParts, fmt.Sprintf("%s dupes", fmtN(dupes)))
	}
	if tooSmall+tooLarge > 0 {
		footerParts = append(footerParts, fmt.Sprintf("%s filtered", fmtN(tooSmall+tooLarge)))
	}
	if errs > 0 {
		footerParts = append(footerParts, fmt.Sprintf("%s errors", fmtN(errs)))
	}
	footer := strings.Join(footerParts, " &middot; ")
	footer += lastCompleted
	fmt.Fprintf(buf, `<footer>%s</footer>`, footer)
}

// ---------------------------------------------------------------------------
// Helpers shared by both dashboards.
// ---------------------------------------------------------------------------.

// ---------------------------------------------------------------------------
// Queue graphs (SVG sparklines, sourced from the local metrics cache).
// ---------------------------------------------------------------------------.

// queueGraphWindow is the trailing span the queue graphs cover.
const queueGraphWindow = 72 * time.Hour

// writeQueueGraphs renders pending depth, rescan depth, and completion
// throughput side by side over the trailing window. All three come from the
// database's own counts (snapshotted into the metrics cache) and share one
// time axis, but each is scaled to its own maximum: pending (~10^5), rescan
// (~10^6) and per-interval completions (~10^3) differ by orders of magnitude,
// so a single shared y-axis would flatten two of the three into the baseline.
func writeQueueGraphs(buf *strings.Builder, points []queuePoint, cacheReady bool) {
	if len(points) < 2 {
		// Make the empty state visible rather than silently omitting the
		// section: distinguish a disabled cache (won't fix itself) from the
		// normal post-restart warm-up (fills within a couple of samples).
		buf.WriteString(`<section><div class="label">Queues &amp; throughput</div><div class="graph-note">`)
		if cacheReady {
			buf.WriteString(`collecting&hellip; first points appear within a few minutes`)
		} else {
			buf.WriteString(`metrics cache unavailable — set HOPPER_METRICS_DB to a writable path`)
		}
		buf.WriteString(`</div></section>`)
		return
	}
	pending := make([]float64, len(points))
	rescan := make([]float64, len(points))
	for i, p := range points {
		pending[i] = float64(p.Pending)
		rescan[i] = float64(p.Rescan)
	}
	// Completion throughput = the count the database recorded as analyzed
	// within each sampling interval (the difference of the cumulative analyzed
	// count). Clamp negatives so a restart gap or counter reset reads as zero
	// rather than a downward spike.
	completed := make([]float64, len(points)-1)
	for i := 1; i < len(points); i++ {
		completed[i-1] = max(float64(points[i].Completed-points[i-1].Completed), 0)
	}

	span := points[len(points)-1].T.Sub(points[0].T)
	step := span / time.Duration(len(points)-1)
	last := points[len(points)-1]

	buf.WriteString(`<section><div class="label">Queues &amp; throughput &middot; last `)
	buf.WriteString(htmlEscape(shortDuration(span)))
	buf.WriteString(`</div><div class="graph-row">`)
	writeMiniGraph(buf, "Pending", fmtN(last.Pending), pending, "#818cf8")
	writeMiniGraph(buf, "Rescan", fmtN(last.Rescan), rescan, "#fbbf24")
	writeMiniGraph(buf, "Completed / "+shortDuration(step), fmtN(int64(completed[len(completed)-1])), completed, "#34d399")
	buf.WriteString(`</div></section>`)
}

// writeMiniGraph renders one labelled area+line sparkline scaled to its own
// max. cur is the preformatted current value shown beside the title.
func writeMiniGraph(buf *strings.Builder, title, cur string, vals []float64, color string) {
	const w, h, px, py = 300, 80, 0, 6
	maxVal := 1.0
	for _, v := range vals {
		if v > maxVal {
			maxVal = v
		}
	}
	xOf := func(i, n int) float64 {
		if n <= 1 {
			return float64(px)
		}
		return float64(px) + float64(i)*float64(w-2*px)/float64(n-1)
	}
	yOf := func(v float64) float64 {
		return float64(h-py) - (v/maxVal)*float64(h-2*py)
	}
	var lineSB, areaSB strings.Builder
	fmt.Fprintf(&areaSB, "%.1f,%.1f", xOf(0, len(vals)), float64(h-py))
	for i, v := range vals {
		if i > 0 {
			lineSB.WriteByte(' ')
		}
		fmt.Fprintf(&lineSB, "%.1f,%.1f", xOf(i, len(vals)), yOf(v))
		fmt.Fprintf(&areaSB, " %.1f,%.1f", xOf(i, len(vals)), yOf(v))
	}
	fmt.Fprintf(&areaSB, " %.1f,%.1f", xOf(len(vals)-1, len(vals)), float64(h-py))

	buf.WriteString(`<div class="graph-box graph-mini">`)
	fmt.Fprintf(buf, `<div class="graph-title">%s <em>%s</em></div>`, htmlEscape(title), htmlEscape(cur))
	fmt.Fprintf(buf, `<svg viewBox="0 0 %d %d" preserveAspectRatio="none" style="display:block;width:100%%;height:80px;overflow:visible">`, w, h)
	y := yOf(maxVal)
	fmt.Fprintf(buf, `<line x1="%d" y1="%.1f" x2="%d" y2="%.1f" stroke="#1a1f2e" stroke-width="1"/>`, px, y, w-px, y)
	fmt.Fprintf(buf, `<text x="%d" y="%.1f" fill="#2d3448" font-size="9" font-family="monospace" dy="10">%s</text>`,
		px, y, htmlEscape(fmtN(int64(maxVal))))
	fmt.Fprintf(buf, `<polygon points="%s" fill="%s" fill-opacity="0.10"/>`, areaSB.String(), color)
	fmt.Fprintf(buf, `<polyline points="%s" fill="none" stroke="%s" stroke-width="2" stroke-linejoin="round"/>`, lineSB.String(), color)
	buf.WriteString(`</svg></div>`)
}

// ---------------------------------------------------------------------------
// Formatting helpers.
// ---------------------------------------------------------------------------.

func formatETA(d time.Duration) string {
	d = d.Round(time.Second)
	days := int(d / (24 * time.Hour))
	h := int(d / time.Hour)
	m := int((d % time.Hour) / time.Minute)
	s := int((d % time.Minute) / time.Second)
	switch {
	case days > 0:
		return fmt.Sprintf("%dd%02dh", days, h%24)
	case h > 0:
		return fmt.Sprintf("%dh%02dm", h, m)
	case m > 0:
		return fmt.Sprintf("%dm%02ds", m, s)
	default:
		return fmt.Sprintf("%ds", s)
	}
}

func fmtN(n int64) string {
	s := strconv.FormatInt(n, 10)
	if len(s) <= 3 {
		return s
	}
	var out []byte
	for i, c := range s {
		if i > 0 && (len(s)-i)%3 == 0 {
			out = append(out, ',')
		}
		out = append(out, byte(c)) //nolint:gosec // c is always an ASCII digit from FormatInt
	}
	return string(out)
}

func shortDuration(d time.Duration) string {
	d = d.Round(time.Second)
	h := int(d / time.Hour)
	m := int((d % time.Hour) / time.Minute)
	s := int((d % time.Minute) / time.Second)
	switch {
	case h > 0:
		return fmt.Sprintf("%dh%02dm", h, m)
	case m > 0:
		return fmt.Sprintf("%dm%02ds", m, s)
	default:
		return fmt.Sprintf("%ds", s)
	}
}

func htmlEscape(s string) string {
	return html.EscapeString(s)
}

// dashEm renders s as an html-escaped table cell, falling back to a long
// dash for empty values. Keeps the dashboard from showing blank cells
// for unreported fields like worker version / traits.
func dashEm(s string) string {
	if s == "" {
		return "—"
	}
	return htmlEscape(s)
}
