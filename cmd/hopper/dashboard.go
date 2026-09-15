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
	"slices"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/codeGROOVE-dev/fido"

	"github.com/atomdrift-project/hopper"
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

// etaWindow is the trailing span of sampled queue depths whose slope drives the
// queue ETAs, and etaMinSpan/etaMinPoints are the least history that slope is
// trusted on. Six hours smooths the bursty way rescans are serviced -- they run
// on capacity left over after first-time analysis -- while still tracking
// today's conditions rather than last week's.
const (
	etaWindow    = 6 * time.Hour
	etaMinSpan   = time.Hour
	etaMinPoints = 4
)

// etaMax caps a reported ETA, and exists to keep the arithmetic in range rather
// than to shape the display. depth/drain is unbounded as drain approaches zero:
// a 3.2M backlog draining at 1e-4/s is 3.2e10 seconds, and 3.2e10 * 1e9 ns
// overflows int64, so the conversion to a Duration wraps and formatETA prints a
// large NEGATIVE age. Clamping before the conversion is what makes that
// impossible; a queue this slow reads as "effectively never" either way.
const etaMax = 365 * 24 * time.Hour

// flowWindow is the span the gained/lost-ground chart covers.
const flowWindow = 6 * time.Hour

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
	rescanCache   *fido.Cache[string, hopper.RescanDepths]
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
	wd.rescanCache = fido.New[string, hopper.RescanDepths](fido.Size(1), fido.TTL(dashCacheTTL))
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

// startHTTPServer binds addr and serves handler until ctx is cancelled.
//
// Used for both listeners: the work API and the web dashboard. Each supplies
// its own middleware chain, which is what keeps their access policies separate
// — the API authenticates, the dashboard does not, and neither can leak a
// route to the other.
func startHTTPServer(ctx context.Context, addr string, handler http.Handler) error {
	ln, err := (&net.ListenConfig{}).Listen(ctx, "tcp", addr)
	if err != nil {
		return fmt.Errorf("listen %s: %w", addr, err)
	}
	srv := &http.Server{Handler: handler, ReadHeaderTimeout: 5 * time.Second, IdleTimeout: 60 * time.Second}
	go func() {
		<-ctx.Done()
		// Graceful shutdown — let in-flight /data/* downloads finish so workers
		// don't see "error decoding response body" mid-stream. Detach from the
		// cancelled parent (it's the trigger, not a deadline). Close as a
		// fallback if a slow client keeps the server alive past the deadline.
		shutdownCtx, cancel := context.WithTimeout(context.WithoutCancel(ctx), 30*time.Second)
		defer cancel()
		if err := srv.Shutdown(shutdownCtx); err != nil {
			slog.Warn("graceful shutdown timed out; forcing close", "addr", addr, "error", err)
			_ = srv.Close() //nolint:errcheck // last-resort close after Shutdown timeout
		}
	}()
	go func() {
		// srv.Addr is unset when serving a pre-bound listener; log the address
		// we actually bound.
		if err := srv.Serve(ln); err != nil && err != http.ErrServerClosed {
			slog.Error("HTTP server stopped", "error", err, "addr", addr)
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
.queue-grid{display:grid;grid-template-columns:repeat(auto-fit,minmax(190px,1fr));gap:.75rem;margin-top:.4rem}
.card-group-label{font-size:.62rem;font-weight:700;letter-spacing:.11em;text-transform:uppercase;
  color:var(--dim);margin-top:1.1rem}
.queue-card{background:var(--surface);border:1px solid var(--border);border-radius:6px;padding:.8rem .9rem}
.queue-label{font-size:.62rem;font-weight:700;letter-spacing:.11em;text-transform:uppercase;color:var(--sub);margin-bottom:.35rem}
.queue-value{font-family:var(--mono);font-size:1.05rem;color:var(--text);font-weight:600;line-height:1.25}
.queue-meta{font-family:var(--mono);font-size:.76rem;color:var(--sub);margin-top:.35rem}
.queue-meta em{font-style:normal;color:var(--text)}
.queue-note{color:var(--amber)}
.queue-bad{color:var(--red)}
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
.flow-head{display:flex;align-items:baseline;gap:.75rem;padding-bottom:.6rem;flex-wrap:wrap}
.flow-good{font-size:1.05rem;font-weight:600;color:var(--green)}
.flow-bad{font-size:1.05rem;font-weight:600;color:var(--red)}
.flow-warn{font-size:1.05rem;font-weight:600;color:var(--amber)}
.flow-detail{font-family:var(--mono);font-size:.78rem;color:var(--sub)}
.flow-detail em{font-style:normal;color:var(--text)}

/* status: the page's first and largest claim */
.status{margin-bottom:1.75rem}
.status-line{display:flex;align-items:center;gap:.6rem}
.status-dot{width:10px;height:10px;border-radius:50%;flex-shrink:0}
.status-ok{background:var(--green);box-shadow:0 0 10px rgba(52,211,153,.5)}
.status-warn{background:var(--amber);box-shadow:0 0 10px rgba(251,191,36,.5)}
.status-bad{background:var(--red);box-shadow:0 0 10px rgba(248,113,113,.5)}
.status-headline{font-size:1.45rem;font-weight:600;color:var(--text);letter-spacing:-.01em}
.status-facts{font-family:var(--mono);font-size:.78rem;color:var(--sub);
  margin-top:.4rem;padding-left:1.6rem}

/* claim ladder */
.ladder-cell{width:38%;min-width:120px}
.ladder-bar{display:inline-block;height:8px;border-radius:2px;background:var(--blue);
  min-width:2px;vertical-align:middle}
.spark{width:120px;height:20px;display:block}
.trend-up{color:var(--red)}
.trend-down{color:var(--green)}
.trend-flat{color:var(--sub)}
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

		fmt.Fprintf(&buf, `<tr><td><span class="dot %s">&#9679;</span>%s</td>`, dot, html.EscapeString(s.label))
		buf.WriteString(`<td class="rate">`)
		switch {
		case s.err != "":

			fmt.Fprintf(&buf, `<span class="err-inline">%s</span>`, html.EscapeString(s.err))
		case s.total > 0 && s.current <= s.total:
			pct := float64(s.current) / float64(s.total) * 100

			fmt.Fprintf(&buf, `%s / %s (%.0f%%)`, fmtN(s.current), fmtN(s.total), pct)
		case s.current > 0:
			// Either no upfront total, or current overshot it — show raw count
			// rather than a misleading > 100% ratio.

			fmt.Fprintf(&buf, `%s processed`, fmtN(s.current))
		default:
			// no progress signal — render the duration only
		}

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

	// Every rescan tier, not just stale-traits. The traits version is read live
	// from the API server rather than from wd.traitsVersion: the latter is a
	// startup snapshot, and the 10-minute refresh that can turn the tier on
	// later never reaches it. Gating the whole card on the snapshot is what let
	// this render "0 pending / stale traits disabled" over a 123,921-row repair
	// backlog that was in fact being handed out.
	// depthsOK is load-bearing, not decoration. A failed count leaves the struct
	// zero-valued, and a zero rescan queue renders as "caught up" -- the one
	// reading that would stop an operator investigating. An unavailable number
	// must look unavailable, not healthy.
	var depths hopper.RescanDepths
	depthsOK := db == nil
	if db != nil {
		ra := wd.rescanAge
		var err error
		//nolint:contextcheck // closure creates its own context; closure logs errors before returning
		depths, err = wd.rescanCache.Fetch("rescan", func() (hopper.RescanDepths, error) {
			qctx, cancel := context.WithTimeout(r.Context(), dashQueryTimeout)
			defer cancel()
			d, err := db.RescanDepths(qctx, ra)
			if err != nil {
				slog.Warn("dashboard: RescanDepths failed", "error", err)
			}
			return d, err
		})
		// Fetch serves the last good value on error; only a cache that has never
		// succeeded is genuinely unknown.
		depthsOK = err == nil || depths.Total() > 0
	}
	rescanPending := depths.Total()

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
	// The other half of "not fully analyzed": rows that got a cleave verdict but
	// no litmus (ml) envelope. Free — workflowHealth already counts it for the
	// Workflow queues card, off the same partial index, in the round trip it was
	// making anyway. Do NOT add a second query for this.
	//
	// Deliberately absent from totalExpected: these rows ARE analyzed as far as
	// analyzedAbs is concerned, so adding them would count them on both sides of
	// the progress fraction.
	pendingLitmus := workflow.health.PendingLitmus
	totalExpected := analyzedAbs + pending

	wd.recordSample(sessionAnalyzed)
	rate, nodeRateByName := wd.ratesOver(15 * time.Minute)

	// Both ETAs come from the OBSERVED slope of the backlog, not from a
	// throughput rate divided into a depth. See queueETA for why that model was
	// always optimistic.
	etaPts := wd.etaPoints(r.Context())
	initialETA, _, _ := queueETA(pending, etaPts, func(p queuePoint) int64 { return p.Pending })
	rescanETA, rescanDrain, rescanMeasured := queueETA(rescanPending, etaPts, func(p queuePoint) int64 { return p.Rescan })

	pct := 0.0
	if totalExpected > 0 {
		pct = math.Min(float64(analyzedAbs)/float64(totalExpected)*100, 100)
	}

	var buf strings.Builder
	buf.WriteString(`<!DOCTYPE html><html lang="en"><head>` +
		`<meta charset="utf-8"><meta http-equiv="refresh" content="60">` +
		`<title>hopper</title><style>` + css + `</style></head><body>`)

	// Big red banner when the local scan (atomscan) worker is down — crashing or
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

	walking := !progress.walkDone.Load() || inPipeline > 0
	writeSystemStatus(&buf, &statusInputs{
		walking:       walking,
		health:        workflow.health,
		flow:          flowRates(queuePoints),
		pendingLitmus: pendingLitmus,
		backlogs:      workflow.backlogs,
		rescan:        depths,
	})

	// Header + progress
	buf.WriteString(`<div class="hdr">`)
	buf.WriteString(`<div class="hdr-top">`)
	buf.WriteString(`<span class="hdr-title">Hopper</span>`)
	// Rendered-at alongside uptime: this page auto-refreshes, and a tab left
	// open on a dead process looks exactly like a live one. The clock is the
	// only thing that distinguishes them.
	fmt.Fprintf(&buf, `<span class="hdr-time">up %s &middot; rendered %s</span>`,
		htmlEscape(shortDuration(elapsed)), htmlEscape(time.Now().Format("15:04:05 MST")))
	buf.WriteString(`</div>`)

	// Initial-analysis progress — kept separate from rescan work, which is a
	// lower-priority queue in claimJobs.
	buf.WriteString(`<div class="progress">`)
	buf.WriteString(`<div class="progress-stats">`)
	fmt.Fprintf(&buf, `<span class="progress-main"><span class="progress-pct">%.1f%%</span> cleave analysis</span>`, pct)

	buf.WriteString(`<span class="progress-detail">`)
	fmt.Fprintf(&buf, `<em>%s</em> / %s analyzed`, fmtN(analyzedAbs), fmtN(totalExpected))
	if pending > 0 {
		fmt.Fprintf(&buf, ` &middot; <em>%s</em> awaiting cleave`, fmtN(pending))
	}
	// The ETA lives on the Cleave card, which is the thing it describes. It was
	// printed in both places, which reads as two independent estimates that
	// happen to agree.
	buf.WriteString(`</span>`)
	buf.WriteString(`</div>`)

	// Bar — session progress only.
	fmt.Fprintf(&buf,
		`<div class="track">`+
			`<div class="fill" style="width:%.2f%%;background:#fbbf24"></div>`+
			`</div>`,
		pct)
	buf.WriteString(`</div>`) // .progress

	buf.WriteString(`<div class="card-group-label">Backlogs</div><div class="queue-grid">`)
	// TWO cards, not one. They were summed under "Initial queue", which put
	// "169,458 pending" three inches below a bar reading "100% initial
	// analysis" -- 646x apart, both labelled initial, on the same screen. They
	// are different pipelines: no-cleave is served by tiers S/U/B/1 at the top
	// of the ladder, no-litmus only by the repair tier below the whole
	// unanalyzed backlog. One number cannot describe both.
	writeQueueCard(&buf, "Cleave queue", fmt.Sprintf("%s pending", fmtN(pending)), func() string {
		var parts []string
		if topLevelRate > 0.001 {
			parts = append(parts, fmt.Sprintf("<em>%s</em>/s", fmtRate(topLevelRate)))
		}
		if initialETA != "" {
			// Explicitly the cleave half's ETA: it is the slope of the no-cleave
			// depth alone. The no-litmus half drains through the repair tier on
			// leftover capacity and has its own, much flatter, slope.
			parts = append(parts, "ETA <em>"+initialETA+"</em>")
		}
		if len(parts) == 0 {
			parts = append(parts, "caught up")
		}
		return strings.Join(parts, " &middot; ")
	}())
	writeQueueCard(&buf, "Litmus queue", fmt.Sprintf("%s pending", fmtN(pendingLitmus)), litmusMeta(pendingLitmus, workflow.backlogs))
	rescanValue := fmt.Sprintf("%s pending", fmtN(rescanPending))
	if !depthsOK {
		rescanValue = "unknown"
	}
	writeQueueCard(&buf, "Rescan queue", rescanValue, rescanMeta(depths, rescanETA, rescanDrain, rescanMeasured, depthsOK))

	// Activity, not backlog. A rate and a walk's progress answer "what is
	// happening now"; the three cards above answer "what is waiting". Rendering
	// all five as one undifferentiated row invited reading a rate as a queue.
	buf.WriteString(`</div><div class="card-group-label">Activity</div><div class="queue-grid">`)

	// Throughput tile: the rescan rate gets its own labeled home rather than
	// hiding on the rescan card's ETA line. The headline is top-level items/s
	// (what the queues drain in); the meta carries the much larger raw files/s
	// (archive members included) and, when enabled, the rescan slice of it.
	// The rescan rate is measured from analyses whose first_analyzed_at predates
	// analyzed_at, which is true of every rescan tier — not just stale-traits.
	// Gating its display on a traits version hid the repair tier's throughput
	// for the same reason the card hid its depth.
	throughputMeta := fmt.Sprintf("<em>%s</em> files/s", fmtRate(rate))
	if rescanRate > 0 || depths.Total() > 0 {
		throughputMeta += fmt.Sprintf(" &middot; <em>%s</em> rescan/s", fmtRate(rescanRate))
	}
	writeQueueCard(&buf, "Throughput", fmtRate(topLevelRate)+" items/s", throughputMeta)

	ingestMeta := fmt.Sprintf("<em>%s</em> known &middot; <em>%s</em> inserted", fmtN(progress.cacheHits.Load()), fmtN(inserted))
	if !progress.walkDone.Load() || inPipeline > 0 {
		ingestMeta += ` &middot; <span class="queue-note">walking</span>`
	}
	writeQueueCard(&buf, "Walk / ingest", fmt.Sprintf("%s walked", fmtN(walked)), ingestMeta)
	buf.WriteString(`</div>`)
	buf.WriteString(`</div>`) // .hdr

	// Trend before detail: the graphs answer "which way is this going", which is
	// the question a reader has immediately after the queue counts. The sample
	// tables below are lookup tools -- useful when you already know what you are
	// chasing, noise when you do not.
	writeFlowGraph(&buf, queuePoints, wd.metrics != nil)

	// The claim ladder replaces the old generic Pending/Rescan/Completed
	// sparklines. Those showed three blended series with no way to tell which
	// tier any of them belonged to; per-tier rows carry the same trends attached
	// to the queue they describe, in the order the scheduler actually uses.
	if wd.api != nil {
		writeClaimLadder(&buf, wd.api.TierActivity(), map[string]int64{
			tierUnanalyzed:   pending,
			tierForcedRescan: depths.Forced,
			tierRepair:       depths.Repair,
			tierRescanAge:    depths.Age,
			tierMissingLLM:   depths.MissingLLM,
		}, queuePoints)
	}

	writeWorkflowBacklogs(&buf, workflow.backlogs)
	writeWorkflowSamples(&buf, "Recent Samples", "Newest rows seen by Hopper", workflow.latestAdded, "created")
	writeWorkflowSamples(&buf, "Prism Ready", "Top-level rows by first analysis completion", workflow.latestReady, "first_analyzed")
	writeWorkflowSamples(&buf, "Oldest Pending Cleave", "Claimable top-level rows still missing cleave results", workflow.oldestPending, "updated")

	// Queue graphs: pending depth, rescan depth, and completion throughput
	// over the trailing window, all from the database's own counts (sampled
	// into the local metrics cache). They share one time axis but each scales
	// to its own maximum, since the three magnitudes differ by orders.

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
			`<th>Queue</th><th>Intake</th><th>Last Done</th><th>F/s</th><th>Err 15m</th>` +
			`<th>Analyzed</th><th>Errors</th><th>Oldest Job</th><th></th>` +
			`</tr></thead><tbody>`)

		// Ghost registrations: a name that has reported no version, no tools and
		// no slots. Production carried ten of them against nine real hosts --
		// four sharing one IP -- so the table was majority noise and a reader
		// could not see the two hosts that were actually down. They are counted
		// below the table instead of occupying rows in it.
		live := workers[:0]
		ghosts := 0
		for i := range workers {
			if workers[i].Version == "" && workers[i].Traits == "" && workers[i].Slots == 0 {
				ghosts++
				continue
			}
			live = append(live, workers[i])
		}
		workers = live

		// Worst first. Alphabetical ordering put `scan-pdx` (down 2h) and
		// `steamdeck` (down 16h) in the middle of healthy hosts, which is the
		// one thing this table must never do: the rows that need action have to
		// be the rows you see first. Name breaks ties so the order is stable
		// between refreshes.
		severity := func(w *namedWorkerStats) int {
			switch idle := time.Since(w.LastSeen); {
			case idle >= workerInactiveWindow:
				return 0
			case idle >= workerActiveWindow:
				return 1
			default:
				return 2
			}
		}
		slices.SortFunc(workers, func(a, b namedWorkerStats) int {
			if d := severity(&a) - severity(&b); d != 0 {
				return d
			}
			return strings.Compare(a.Name, b.Name)
		})
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

			// Claim-side intake: free buffer room, then last poll want→got, then
			// memory reserved/ceiling. room 0 = saturated (not polling on purpose);
			// want>got with room = hopper had nothing; reserved≈ceiling = memory
			// throttle. "—" when the worker doesn't report the telemetry.
			intakeStr := "—"
			if !w.LastPollAt.IsZero() {
				intakeStr = fmt.Sprintf("%d · %d→%d", w.BufferRoom, w.LastWant, w.LastClaim)
				if w.MemCeilingMB > 0 {
					intakeStr += fmt.Sprintf(" · %dg/%dg", w.MemReservedMB/1024, w.MemCeilingMB/1024)
				}
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
				htmlEscape(intakeStr),
				htmlEscape(lastDoneStr),
				fpsStr,
				err15Cell,
				fmtN(w.Analyzed),
				fmtN(w.Errors),
				htmlEscape(oldestStr),
				htmlEscape(status),
			)
		}
		buf.WriteString(`</tbody></table>`)
		if ghosts > 0 {
			fmt.Fprintf(&buf,
				`<div class="graph-note">%d registration(s) hidden: reported no version, tools or slots</div>`,
				ghosts)
		}
		buf.WriteString(`</section>`)
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

// The cached stats below back the Prometheus collector (see obsmetrics.go).
// They deliberately reuse the same fido caches and keys the page handler fills,
// so a scrape and a page render within dashCacheTTL of each other run the
// underlying query once; when nothing is watching the page, a scrape recomputes
// at most one query per metric per cache window. They are kept separate from the
// handler's inline fetches so the handler's HTML rendering path is unchanged.
// ctx bounds the query; on error the cache's last (or zero) value is returned
// and the failure logged.

// pendingCount returns the live count of samples awaiting first analysis.
func (wd *webDashboard) pendingCount(ctx context.Context) int64 {
	if wd.db == nil || wd.pendingCache == nil {
		return 0
	}
	n, _ := wd.pendingCache.Fetch("pending", func() (int64, error) { //nolint:errcheck // cached value used on error
		qctx, cancel := context.WithTimeout(ctx, dashQueryTimeout)
		defer cancel()
		n, err := wd.db.CountPending(qctx)
		if err != nil {
			slog.Warn("metrics: CountPending failed", "error", err)
		}
		return n, err
	})
	return n
}

// rescanPending returns the total depth of every re-analysis tier, for the
// queue-depth metric series. Unlike the old stale-traits-only count it is not
// gated on a traits version: the priority tiers exist regardless.
func (wd *webDashboard) rescanPending(ctx context.Context) int64 {
	if wd.db == nil || wd.rescanCache == nil {
		return 0
	}
	ra := wd.rescanAge
	d, _ := wd.rescanCache.Fetch("rescan", func() (hopper.RescanDepths, error) { //nolint:errcheck // cached value used on error
		qctx, cancel := context.WithTimeout(ctx, dashQueryTimeout)
		defer cancel()
		d, err := wd.db.RescanDepths(qctx, ra)
		if err != nil {
			slog.Warn("metrics: RescanDepths failed", "error", err)
		}
		return d, err
	})
	return d.Total()
}

// analysisRates returns the top-level and rescan analysis counts over
// analysisRateWindow (divide by the window for per-second rates).
func (wd *webDashboard) analysisRates(ctx context.Context) hopper.AnalysisRates {
	if wd.db == nil || wd.ratesCache == nil {
		return hopper.AnalysisRates{}
	}
	rates, _ := wd.ratesCache.Fetch("rates", func() (hopper.AnalysisRates, error) { //nolint:errcheck // cached value used on error
		qctx, cancel := context.WithTimeout(ctx, dashQueryTimeout)
		defer cancel()
		v, err := wd.db.AnalysisRatesSince(qctx, analysisRateWindow)
		if err != nil {
			slog.Warn("metrics: AnalysisRatesSince failed", "error", err)
		}
		return v, err
	})
	return rates
}

// workflowHealth returns the workflow freshness/backlog snapshot. The bool is
// false when no value is available; it shares the "health" cache key with
// fetchWorkflow.
func (wd *webDashboard) workflowHealth(ctx context.Context) (hopper.WorkflowHealth, bool) {
	if wd.db == nil || wd.healthCache == nil {
		return hopper.WorkflowHealth{}, false
	}
	h, err := wd.healthCache.Fetch("health", func() (hopper.WorkflowHealth, error) {
		qctx, cancel := context.WithTimeout(ctx, dashQueryTimeout)
		defer cancel()
		return wd.db.WorkflowHealth(qctx)
	})
	if err != nil {
		slog.Warn("dashboard: workflow health query failed", "error", err)
		return hopper.WorkflowHealth{}, false
	}
	return h, true
}

// rescanMeta is the Rescan queue card's sub-line: the per-tier split, then how
// fast it is (or is not) draining.
//
// The tier breakdown is the point of the card. The three populations are
// drained at different ladder positions by different queries, so a single total
// with no split cannot answer the question an operator actually has, which is
// "is the tier I care about moving". It also has to distinguish a stale-traits
// tier that is EMPTY from one that is ABSENT: hopper drops that tier from the
// ladder entirely when it cannot read a traits version from its analyzer, and
// rendering that as "caught up" (or as a bare 0) is what hid a switched-off
// tier for the whole of a 24h uptime.
func rescanMeta(d hopper.RescanDepths, eta string, drain float64, measured, known bool) string {
	var parts []string
	if d.Forced > 0 {
		parts = append(parts, fmt.Sprintf("<em>%s</em> forced", fmtN(d.Forced)))
	}
	parts = append(parts, fmt.Sprintf("<em>%s</em> repair", fmtN(d.Repair)))
	// No "off" state to render any more: the age tier is always in the ladder,
	// so zero means caught up rather than unmeasured.
	if d.Age > 0 {
		parts = append(parts, fmt.Sprintf("<em>%s</em> past rescan age", fmtN(d.Age)))
	}
	if d.MissingLLM > 0 {
		parts = append(parts, fmt.Sprintf("<em>%s</em> undescribed", fmtN(d.MissingLLM)))
	}
	switch {
	case !known:
		// Never say "caught up" on a number we do not have.
		return `<span class="queue-bad">depth unavailable &mdash; the count is failing</span>`
	case d.Total() == 0:
		parts = append(parts, "caught up")
	case eta != "":
		parts = append(parts, "ETA <em>"+eta+"</em>")
	case !measured:
		// No slope yet -- a restart clears the sampled series. Saying "not
		// draining" here is a false statement about a queue that may be draining
		// fast, and it is what the live dashboard showed next to 21 rescans/sec.
		parts = append(parts, `<span class="queue-note">measuring&hellip;</span>`)
	case drain < 0:
		// Growing. Saying so is the whole point: this is the state every
		// previous version of this card rendered as a cheerful few hours.
		parts = append(parts, fmt.Sprintf(`<span class="queue-note">not draining &middot; +%.0f/hr</span>`, -drain*3600))
	default:
		// Flat, or not enough history yet to call it. No cause asserted: a flat
		// queue can be first-time analysis hogging the fleet OR workers starved
		// on a slow candidate query, and the dashboard cannot tell which.
		parts = append(parts, `<span class="queue-note">not draining</span>`)
	}
	return strings.Join(parts, " &middot; ")
}

// timeTitle renders an absolute timestamp for a hover title, so a relative age
// on the page can be checked against a log line.
func timeTitle(t time.Time) string {
	if t.IsZero() {
		return "no data"
	}
	return t.Format("2006-01-02 15:04:05 MST")
}

func writeQueueCard(buf *strings.Builder, label, value, meta string) {
	fmt.Fprintf(buf,
		`<div class="queue-card"><div class="queue-label">%s</div><div class="queue-value">%s</div><div class="queue-meta">%s</div></div>`,
		htmlEscape(label), htmlEscape(value), meta)
}

// statusInputs is everything the top-line verdict reads. Grouped into a struct
// so the call site stays one statement rather than a tail of positional
// arguments nobody can read.
type statusInputs struct {
	backlogs      []hopper.WorkflowBacklog
	health        hopper.WorkflowHealth
	flow          flowSeries
	rescan        hopper.RescanDepths
	pendingLitmus int64
	// walking marks a walk in progress, which inserts in bulk and legitimately
	// outruns processing for its duration. It downgrades the flow verdict from
	// critical to a warning and names the cause.
	walking bool
}

// oldestBacklog returns the age of the oldest pending row across the backlog
// rows, and whether there was one.
func oldestBacklog(rows []hopper.WorkflowBacklog) (time.Duration, bool) {
	var oldest time.Time
	for i := range rows {
		t := rows[i].OldestPending
		if t.IsZero() {
			continue
		}
		if oldest.IsZero() || t.Before(oldest) {
			oldest = t
		}
	}
	if oldest.IsZero() {
		return 0, false
	}
	return time.Since(oldest), true
}

// litmusMeta describes the litmus backlog by AGE. Its size has barely moved in
// months, so the size alone tells a reader nothing they can act on; "oldest
// 71d" does.
func litmusMeta(pending int64, rows []hopper.WorkflowBacklog) string {
	if pending == 0 {
		return "caught up"
	}
	if age, ok := oldestBacklog(rows); ok {
		return fmt.Sprintf(`oldest <em>%s</em> &middot; <span class="queue-note">served only by the repair tier</span>`,
			htmlEscape(shortDuration(age)))
	}
	return `<span class="queue-note">served only by the repair tier</span>`
}

// writeSystemStatus renders the one line the page exists for: is the pipeline
// healthy right now, and if not, what is wrong.
//
// It is first, largest, and alone. Everything below it is evidence. The page
// previously opened with eleven sections of equal weight and no answer to this
// question anywhere -- a reader had to assemble it from a progress bar, four
// cards, a health grid and a 21-column worker table, and those disagreed with
// each other.
//
// Problems are ranked by what would make someone act, and only the worst is
// promoted to the verdict; the rest trail as facts. A dashboard that reports
// five problems at equal weight has not triaged anything.
func writeSystemStatus(buf *strings.Builder, in *statusInputs) {
	type issue struct {
		text string
		bad  bool // red rather than amber
	}
	var issues []issue

	// Staleness first: a pipeline that has stopped moving outranks any backlog.
	if !in.health.LatestAdded.IsZero() && time.Since(in.health.LatestAdded) > time.Hour {
		issues = append(issues, issue{fmt.Sprintf("No sample ingested in %s",
			shortDuration(time.Since(in.health.LatestAdded))), true})
	}
	if !in.health.LatestAnalyzed.IsZero() && time.Since(in.health.LatestAnalyzed) > time.Hour {
		issues = append(issues, issue{fmt.Sprintf("Nothing analyzed in %s",
			shortDuration(time.Since(in.health.LatestAnalyzed))), true})
	}
	// Then direction: arriving faster than finishing is what turns every backlog
	// below into a permanent one.
	if losing, netRate := flowVerdict(in.flow); losing {
		text := fmt.Sprintf("Losing ground: backlog growing %s/s", fmtRate(-netRate))
		if in.walking {
			// A walk inserts in bulk, so say what is doing it rather than
			// leaving the reader to discover the cause themselves.
			text += " (walk in progress)"
		}
		issues = append(issues, issue{text, !in.walking})
	}
	// Then standing backlogs, described by age.
	if age, ok := oldestBacklog(in.backlogs); ok && age > 7*24*time.Hour {
		issues = append(issues, issue{fmt.Sprintf("%s files have no litmus score, oldest %s",
			fmtN(in.pendingLitmus), shortDuration(age)), false})
	}

	cls, headline := "status-ok", "Pipeline healthy"
	if len(issues) > 0 {
		cls, headline = "status-warn", issues[0].text
		if issues[0].bad {
			cls = "status-bad"
		}
	}

	buf.WriteString(`<div class="status">`)
	fmt.Fprintf(buf, `<div class="status-line"><span class="status-dot %s"></span>`+
		`<span class="status-headline">%s</span></div>`, cls, htmlEscape(headline))

	var facts []string
	if !in.health.LatestAdded.IsZero() {
		facts = append(facts, "ingest "+shortDuration(time.Since(in.health.LatestAdded))+" ago")
	}
	if !in.health.LatestAnalyzed.IsZero() {
		facts = append(facts, "analysis "+shortDuration(time.Since(in.health.LatestAnalyzed))+" ago")
	}
	if !in.health.LatestReady.IsZero() {
		// The one fact the Workflow Health grid carried that nothing else did:
		// how far prism's view trails ingestion.
		facts = append(facts, "prism "+shortDuration(time.Since(in.health.LatestReady))+" behind")
	}
	if in.rescan.Total() > 0 {
		facts = append(facts, fmtN(in.rescan.Total())+" queued for re-analysis")
	}
	// Everything the headline did not promote still gets said, just quietly.
	for _, is := range issues[min(1, len(issues)):] {
		facts = append(facts, is.text)
	}
	if len(facts) > 0 {
		fmt.Fprintf(buf, `<div class="status-facts">%s</div>`, htmlEscape(strings.Join(facts, " · ")))
	}
	buf.WriteString(`</div>`)
}

// tierLabel maps a claim tier's wire name to what it actually does. The wire
// names are load-bearing elsewhere (metrics, logs), so they are not renamed --
// but "rescan_age" is not a sentence, and the panel exists to be read.
func tierLabel(tier string) string {
	switch tier {
	case tierSighted:
		return "Cited by a threat feed"
	case tierUpload:
		return "Interactive uploads"
	case tierForcedRescan:
		return "Rescans you asked for"
	case tierBigArchive:
		return "Big archives"
	case tierUnanalyzed:
		return "Never analyzed"
	case tierRepair:
		return "Repair (missing members / litmus)"
	case tierPathRescan:
		return "Forced by path prefix"
	case tierMissingLLM:
		return "Fired, but no LLM rationale"
	case tierRescanAge:
		return "Analysis older than the rescan age"
	default:
		return tier
	}
}

// tierDepthSeries pulls one tier's depth history out of the sampled points.
// Tiers with no recorded depth (sighted, uploads, big archives, path rescans)
// return nil and render without a trend rather than with a flat fake one.
func tierDepthSeries(tier string, points []queuePoint) []float64 {
	var pick func(queuePoint) int64
	switch tier {
	case tierUnanalyzed:
		pick = func(p queuePoint) int64 { return p.Pending }
	case tierForcedRescan:
		pick = func(p queuePoint) int64 { return p.Forced }
	case tierRepair:
		pick = func(p queuePoint) int64 { return p.Repair }
	case tierRescanAge:
		pick = func(p queuePoint) int64 { return p.AgeTier }
	case tierMissingLLM:
		pick = func(p queuePoint) int64 { return p.MissingLLM }
	default:
		return nil
	}
	out := make([]float64, 0, len(points))
	for _, p := range points {
		out = append(out, float64(pick(p)))
	}
	return out
}

// sparkline renders a trend small enough to sit in a table cell.
//
// Scaled from zero rather than from the series minimum: these are queue depths,
// and a backlog that drifts between 3.40M and 3.41M is flat in every sense a
// reader cares about. Min-scaling would draw that as a dramatic slope and invite
// exactly the wrong conclusion.
func sparkline(vals []float64, color string) string {
	if len(vals) < 2 {
		return ""
	}
	const w, h = 120.0, 20.0
	maxVal := 1.0
	for _, v := range vals {
		if v > maxVal {
			maxVal = v
		}
	}
	var pts strings.Builder
	for i, v := range vals {
		if i > 0 {
			pts.WriteByte(' ')
		}
		x := float64(i) * w / float64(len(vals)-1)
		y := h - 1 - (v/maxVal)*(h-2)
		fmt.Fprintf(&pts, "%.1f,%.1f", x, y)
	}
	return fmt.Sprintf(
		`<svg viewBox="0 0 %.0f %.0f" preserveAspectRatio="none" class="spark">`+
			`<polyline points="%s" fill="none" stroke="%s" stroke-width="1.5" stroke-linejoin="round"/></svg>`,
		w, h, pts.String(), color)
}

// trendArrow says which way the series has moved over its span, in words the
// row can be read by without consulting the sparkline's shape.
func trendArrow(vals []float64) string {
	if len(vals) < 2 {
		return ""
	}
	first, last := vals[0], vals[len(vals)-1]
	if first == 0 && last == 0 {
		return ""
	}
	delta := last - first
	// A percent threshold, not an absolute one: these series span 130 to 3.4M.
	if scale := math.Max(first, 1); math.Abs(delta)/scale < 0.02 {
		return `<span class="trend-flat">flat</span>`
	}
	if delta < 0 {
		return `<span class="trend-down">&#9660; shrinking</span>`
	}
	return `<span class="trend-up">&#9650; growing</span>`
}

// writeClaimLadder renders every claim tier in the order workers are offered
// them, with what each has handed out recently.
//
// This replaces reading the rescan card and guessing. The ladder is the system's
// actual scheduling policy, and until now it was visible nowhere: a reader saw
// one "Rescan queue" number that silently blended three tiers, with no way to
// tell which of them was moving. Order is the point -- a tier starves because
// everything above it is busy, so the row above is the explanation for the row
// below.
//
// The bar is scaled to the busiest tier, so it reads as share of the fleet's
// attention rather than as an absolute rate. A tier with depth and no claims is
// called out: that is the starvation case, and it is the one worth seeing.
func writeClaimLadder(buf *strings.Builder, activity, depths map[string]int64, points []queuePoint) {
	order := claimTierOrder()
	var busiest int64
	for _, t := range order {
		if n := activity[t]; n > busiest {
			busiest = n
		}
	}

	buf.WriteString(`<section><div class="label">Claim ladder &middot; last ` +
		fmt.Sprintf("%dm", tierWindowMinutes) + `</div>`)
	buf.WriteString(`<table><thead><tr><th>#</th><th>Tier</th><th>Waiting</th>` +
		`<th>Claimed</th><th>Rate</th><th>Share of claims</th>` +
		`<th>Trend &middot; ` + htmlEscape(shortDuration(queueGraphWindow)) + `</th><th></th>` +
		`</tr></thead><tbody>`)
	for i, t := range order {
		claims := activity[t]
		rate := float64(claims) / (tierWindowMinutes * 60)

		depthCell := "&mdash;"
		if d, ok := depths[t]; ok {
			depthCell = fmtN(d)
		}
		claimsCell, rateCell := "&mdash;", "&mdash;"
		if claims > 0 {
			claimsCell = fmtN(claims)
			rateCell = fmtRate(rate) + "/s"
		}

		// Width and opacity both track share: a faint sliver and a solid bar are
		// distinguishable at a glance in a way two thin bars are not.
		var bar string
		switch {
		case busiest > 0 && claims > 0:
			share := float64(claims) / float64(busiest)
			bar = fmt.Sprintf(
				`<span class="ladder-bar" style="width:%.1f%%;opacity:%.2f"></span>`,
				share*100, 0.35+0.65*share)
		case depths[t] > 0:
			bar = `<span class="queue-note">idle with work waiting</span>`
		default:
			bar = ""
		}

		series := tierDepthSeries(t, points)
		fmt.Fprintf(buf,
			`<tr><td>%d</td><td>%s</td><td class="hi">%s</td><td class="hi">%s</td><td>%s</td>`+
				`<td class="ladder-cell">%s</td><td>%s</td><td>%s</td></tr>`,
			i+1, htmlEscape(tierLabel(t)), depthCell, claimsCell, rateCell, bar,
			sparkline(series, "#818cf8"), trendArrow(series))
	}
	buf.WriteString(`</tbody></table></section>`)
}

// writeWorkflowBacklogs renders the standing backlogs ordered by AGE.
//
// It used to render them by count with a Cleave and a Litmus column. On
// production every row's Cleave column was 0 -- a column of zeros -- and the
// counts barely move from week to week, so the same five rows rendered on every
// refresh and the section taught a reader nothing after the first look.
//
// Age is the signal that changes and the one that implies an action. "Oldest"
// says how long this feed has been stuck; "last arrival" says whether anything
// is still flowing into it, which separates a feed that is backed up from one
// that is abandoned. A row whose newest pending item is also ancient is a frozen
// set: nothing new is arriving and nothing is draining.
func writeWorkflowBacklogs(buf *strings.Builder, rows []hopper.WorkflowBacklog) {
	if len(rows) == 0 {
		return
	}
	ordered := make([]hopper.WorkflowBacklog, len(rows))
	copy(ordered, rows)
	slices.SortStableFunc(ordered, func(x, y hopper.WorkflowBacklog) int {
		a, b := x.OldestPending, y.OldestPending
		switch {
		case a.IsZero() && b.IsZero():
			return 0
		case a.IsZero():
			return 1
		case b.IsZero():
			return -1
		default:
			return a.Compare(b)
		}
	})

	buf.WriteString(`<section><div class="label">Backlogs by age</div>`)
	buf.WriteString(`<table><thead><tr><th>Feed</th><th>Ecosystem</th><th>Stage</th>` +
		`<th>Waiting</th><th>Oldest</th><th>Last arrival</th><th></th></tr></thead><tbody>`)
	for i := range ordered {
		r := &ordered[i]
		// One stage per row: whichever half actually holds work. Two columns
		// where one is always zero is a column that costs a reader attention
		// and returns nothing.
		stage, waiting := "litmus", r.PendingLitmus
		if r.PendingCleave > r.PendingLitmus {
			stage, waiting = "cleave", r.PendingCleave
		}
		// Frozen: nothing new has arrived in a week either, so this is not a
		// feed that is merely busy.
		note := ""
		if !r.NewestPending.IsZero() && time.Since(r.NewestPending) > 7*24*time.Hour {
			note = `<span class="queue-note">stalled</span>`
		}
		fmt.Fprintf(buf,
			`<tr><td>%s</td><td>%s</td><td>%s</td><td class="hi">%s</td>`+
				`<td class="hi" title="%s">%s</td><td title="%s">%s</td><td>%s</td></tr>`,
			htmlEscape(dashIfEmpty(r.Feed)),
			htmlEscape(dashIfEmpty(r.Ecosystem)),
			htmlEscape(stage),
			fmtN(waiting),
			htmlEscape(timeTitle(r.OldestPending)), htmlEscape(ageValue(r.OldestPending)),
			htmlEscape(timeTitle(r.NewestPending)), htmlEscape(ageValue(r.NewestPending)),
			note)
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

	// Rendered even when empty. A section that disappears on success looks
	// identical to one that was never reached, and "no errors" is a thing an
	// operator wants stated rather than inferred from absence.
	buf.WriteString(`<section><div class="label">Errors</div>`)
	if len(errs) == 0 {
		buf.WriteString(`<div class="graph-note">none recorded this run</div></section>`)
		return
	}

	// Age, not just wall-clock time. The live page listed errors from 08:23 under
	// the heading "Recent" on a render at 11:17; three hours is a different
	// situation from three minutes and the table was not saying which.
	newest := errs[len(errs)-1].At
	if age := time.Since(newest); age > time.Hour {
		fmt.Fprintf(buf, `<div class="graph-note">nothing in the last %s &middot; showing the last %d</div>`,
			htmlEscape(shortDuration(age.Round(time.Minute))), len(errs))
	}
	buf.WriteString(`<table><thead><tr><th>Age</th><th>Time</th><th>Stage</th><th>Error</th></tr></thead><tbody>`)
	for _, e := range slices.Backward(errs) {
		fmt.Fprintf(buf,
			`<tr><td class="err-time">%s</td><td class="err-time">%s</td>`+
				`<td class="err-stage">%s</td><td class="err-msg">%s</td></tr>`,
			htmlEscape(shortDuration(time.Since(e.At).Round(time.Second))),
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

// flowSeries is the net movement of the backlog, plus the arrival/completion
// decomposition when the sampler has recorded enough of it.
//
// net is the ground gained or lost per second: positive means the backlog
// shrank over that interval, negative means it grew.
type flowSeries struct {
	net      []float64
	in, out  []float64
	usable   bool
	hasRates bool
}

// flowRates derives the net backlog movement from the sampled queue DEPTHS, and
// the arrival/completion rates from the cumulative counters when they are there.
//
// Depth first, because depth is the honest answer and it is available
// immediately: the backlog level already nets off every arrival and every
// completion, whatever their source, so its slope IS "are we gaining ground".
// The in/out decomposition is an enrichment, and it is the half that has to wait
// -- the arrival watermark only starts accumulating when a build carrying it has
// been up for two sample intervals. Deriving the answer from depth means a fresh
// deploy shows the graph at once against months of existing history, instead of
// reporting "collecting..." for ten minutes over a cache that already holds the
// data.
//
// Two clamps on the rates, both because a counter going backwards is a restart
// rather than negative work: Added (max(samples.id)) never regresses, but
// Completed is an in-memory session counter that resets to its DB baseline on
// restart. Depth needs no such clamp -- it is a level, and it may legitimately
// move either way.
func flowRates(points []queuePoint) flowSeries {
	var f flowSeries
	for i := 1; i < len(points); i++ {
		prev, cur := points[i-1], points[i]
		dt := cur.T.Sub(prev.T).Seconds()
		if dt <= 0 {
			continue
		}
		depthPrev := prev.Pending + prev.Rescan
		depthCur := cur.Pending + cur.Rescan
		f.net = append(f.net, float64(depthPrev-depthCur)/dt)
		if prev.Added > 0 && cur.Added > 0 {
			f.in = append(f.in, max(float64(cur.Added-prev.Added), 0)/dt)
			f.out = append(f.out, max(float64(cur.Completed-prev.Completed), 0)/dt)
		}
	}
	f.usable = len(f.net) >= 2
	f.hasRates = len(f.in) >= 2
	return f
}

// mean returns the average of vals, or zero for an empty slice.
func mean(vals []float64) float64 {
	if len(vals) == 0 {
		return 0
	}
	var sum float64
	for _, v := range vals {
		sum += v
	}
	return sum / float64(len(vals))
}

// flowLosingShare is the fraction of sampled intervals that must show the
// backlog growing before the dashboard will call it "losing ground".
const flowLosingShare = 0.6

// medianOf returns the median of vals without disturbing the caller's slice.
func medianOf(vals []float64) float64 {
	if len(vals) == 0 {
		return 0
	}
	sorted := slices.Clone(vals)
	slices.Sort(sorted)
	mid := len(sorted) / 2
	if len(sorted)%2 == 1 {
		return sorted[mid]
	}
	return (sorted[mid-1] + sorted[mid]) / 2
}

// flowVerdict decides whether the backlog is genuinely losing ground, and by how
// much.
//
// Median rather than mean, with a persistence test on top. A walk re-inserting a
// million rows makes arrivals spike for as long as it runs, and on 2026-09-15
// the live dashboard read "Falling behind by 773.1/s" in red during exactly such
// a walk -- a routine, bounded, entirely expected operation. A verdict that goes
// critical during normal work teaches its reader to ignore it, which costs more
// than showing nothing would.
//
// The median discards the burst; requiring most intervals to agree stops one
// sample from deciding the headline. Both are needed: a long enough burst drags
// the median too, and a brief one can still sit at the midpoint of a short
// window.
func flowVerdict(f flowSeries) (losing bool, netRate float64) {
	if !f.usable {
		return false, 0
	}
	netRate = medianOf(f.net)
	growing := 0
	for _, v := range f.net {
		if v < 0 {
			growing++
		}
	}
	return netRate < 0 && float64(growing)/float64(len(f.net)) >= flowLosingShare, netRate
}

// writeFlowGraph answers the one question a queue dashboard exists to answer:
// are we gaining ground or losing it?
//
// It plots NET movement against a zero baseline rather than arrivals and
// completions as two lines. Two lines make the reader do the subtraction, and at
// these magnitudes -- arrivals and completions are usually within a few percent
// of each other -- the gap that decides the answer is thinner than the strokes.
// Against zero, the sign IS the answer.
//
// Windowed to flowWindow rather than the full graph window: a deploy that
// changes what a queue counts (the rescan tier gaining a whole population, say)
// puts one enormous step in the series, and over 72h that step sets the scale
// and flattens everything else into the axis. Six hours ages it out.
func writeFlowGraph(buf *strings.Builder, points []queuePoint, cacheReady bool) {
	cut := time.Now().Add(-flowWindow)
	recent := points
	for i, p := range points {
		if !p.T.Before(cut) {
			recent = points[i:]
			break
		}
	}
	f := flowRates(recent)

	buf.WriteString(`<section><div class="label">Ground gained or lost &middot; last ` +
		htmlEscape(shortDuration(flowWindow)) + `</div>`)
	if !f.usable {
		buf.WriteString(`<div class="graph-note">`)
		if cacheReady {
			buf.WriteString(`collecting&hellip; two queue samples are needed (about 10 minutes)`)
		} else {
			buf.WriteString(`metrics cache unavailable &mdash; set HOPPER_METRICS_DB to a writable path`)
		}
		buf.WriteString(`</div></section>`)
		return
	}

	losing, avgNet := flowVerdict(f)
	verdict, cls := "Gaining ground", "flow-good"
	switch {
	case losing:
		verdict, cls = "Losing ground", "flow-bad"
	case avgNet < 0:
		// Negative, but not persistently: a burst, not a trend. Named rather
		// than rounded away, so a reader sees the dashboard noticed.
		verdict, cls = "Holding, with bursts", "flow-warn"
	default:
	}
	// The in/out split when the arrival watermark has accumulated; otherwise the
	// net alone, which is the answer either way.
	detail := fmt.Sprintf("backlog <em>%s/s</em>", fmtSigned(avgNet))
	if f.hasRates {
		detail = fmt.Sprintf("in <em>%s/s</em> &middot; out <em>%s/s</em> &middot; net <em>%s/s</em>",
			fmtRate(mean(f.in)), fmtRate(mean(f.out)), fmtSigned(mean(f.out)-mean(f.in)))
	}
	fmt.Fprintf(buf, `<div class="flow-head"><span class="%s">%s</span>`+
		`<span class="flow-detail">%s</span></div>`, cls, htmlEscape(verdict), detail)

	const w, h = 1100, 150
	scale := 1.0
	for _, v := range f.net {
		if a := math.Abs(v); a > scale {
			scale = a
		}
	}
	zeroY := float64(h) / 2
	xOf := func(i int) float64 { return float64(i) * float64(w) / float64(len(f.net)-1) }
	yOf := func(v float64) float64 { return zeroY - (v/scale)*(zeroY-8) }

	var area, line strings.Builder
	fmt.Fprintf(&area, "%.1f,%.1f", xOf(0), zeroY)
	for i, v := range f.net {
		if i > 0 {
			line.WriteByte(' ')
		}
		fmt.Fprintf(&line, "%.1f,%.1f", xOf(i), yOf(v))
		fmt.Fprintf(&area, " %.1f,%.1f", xOf(i), yOf(v))
	}
	fmt.Fprintf(&area, " %.1f,%.1f", xOf(len(f.net)-1), zeroY)

	fmt.Fprintf(buf, `<svg viewBox="0 0 %d %d" preserveAspectRatio="none" `+
		`style="display:block;width:100%%;height:150px;overflow:visible">`, w, h)
	fmt.Fprintf(buf, `<defs><clipPath id="flowUp"><rect x="0" y="0" width="%d" height="%.1f"/></clipPath>`+
		`<clipPath id="flowDown"><rect x="0" y="%.1f" width="%d" height="%.1f"/></clipPath></defs>`,
		w, zeroY, zeroY, w, float64(h)-zeroY)
	fmt.Fprintf(buf, `<polygon points="%s" fill="#34d399" fill-opacity="0.16" clip-path="url(#flowUp)"/>`, area.String())
	fmt.Fprintf(buf, `<polygon points="%s" fill="#f87171" fill-opacity="0.16" clip-path="url(#flowDown)"/>`, area.String())
	fmt.Fprintf(buf, `<polyline points="%s" fill="none" stroke="#818cf8" stroke-width="1.5" stroke-linejoin="round"/>`, line.String())
	fmt.Fprintf(buf, `<line x1="0" y1="%.1f" x2="%d" y2="%.1f" stroke="#4e5a72" stroke-width="1"/>`, zeroY, w, zeroY)
	fmt.Fprintf(buf, `<text x="4" y="%.1f" fill="#4e5a72" font-size="10" font-family="monospace" dy="-4">backlog shrinking</text>`, zeroY)
	fmt.Fprintf(buf, `<text x="4" y="%.1f" fill="#4e5a72" font-size="10" font-family="monospace" dy="12">backlog growing</text>`, zeroY)
	buf.WriteString(`</svg>`)
	buf.WriteString(`<div class="graph-legend">` +
		`<span class="legend-item"><span class="legend-swatch" style="background:#34d399"></span>finishing faster than arriving</span>` +
		`<span class="legend-item"><span class="legend-swatch" style="background:#f87171"></span>arriving faster than finishing</span>` +
		`</div></section>`)
}

// ---------------------------------------------------------------------------
// Formatting helpers.
// ---------------------------------------------------------------------------.

// etaPoints fetches the trailing queue-depth samples the ETAs are measured from.
// Local SQLite over a handful of rows (one sample per 5 minutes), so it is not
// worth a cache. Returns nil when the metrics cache is unavailable, which the
// callers render as "measuring" rather than as a number.
func (wd *webDashboard) etaPoints(ctx context.Context) []queuePoint {
	if wd.metrics == nil {
		return nil
	}
	qctx, cancel := context.WithTimeout(ctx, dashQueryTimeout)
	defer cancel()
	pts, err := wd.metrics.series(qctx, time.Now().Add(-etaWindow))
	if err != nil {
		slog.Debug("dashboard: eta series unavailable", "error", err)
		return nil
	}
	return pts
}

// queueETA reports how long a queue will take to empty, measured as the slope
// of its own sampled depth. It returns the formatted ETA (empty when there
// isn't one) and the observed drain rate in items/sec, positive when draining.
//
// WHY A SLOPE AND NOT depth/rate. Every previous version of this divided a
// backlog by a throughput number, and every one of them read hours where the
// truth was days. Two compounding reasons, both optimistic:
//
//   - The divisor counted work that does not drain THIS queue. The initial-queue
//     ETA used the top-level analysis rate, which includes re-analyses; a rescan
//     completing does not remove a row from the no-cleave backlog. Measured
//     2026-09-14, rescans were 89,734 of 102,435 top-level analyses in an hour,
//     so that divisor was 8x too large -- it reported 24s for a backlog that,
//     against first-time analyses alone, needed 193s.
//   - Nothing subtracted arrivals. A queue draining at 12.7k/hr while being fed
//     at 19.6k/hr is not 40 minutes from empty, it is never empty, and no
//     depth/rate formula can say so because the arrival term is absent.
//
// The slope has neither problem: it is the net of every drain and every refill,
// whatever their source, and it needs no model of which tier serves what. A
// queue that is not shrinking has no ETA, and says so.
//
// Least squares rather than endpoint difference because rescan servicing is
// bursty -- two samples can straddle a spike and report a slope the hour does
// not support.
func queueETA(depth int64, points []queuePoint, at func(queuePoint) int64) (eta string, drain float64, measured bool) {
	if depth <= 0 {
		// Nothing queued: there is no slope to want, and no ETA to report.
		return "", 0, true
	}
	span := time.Duration(0)
	if len(points) >= 2 {
		span = points[len(points)-1].T.Sub(points[0].T)
	}
	if len(points) < etaMinPoints || span < etaMinSpan {
		// Not enough history to fit a line. This is NOT "not draining" -- the
		// caller must say so differently, or a freshly restarted hopper reports
		// a healthy queue as stalled.
		return "", 0, false
	}
	// Times as seconds relative to the first sample, to keep the sums small.
	base := points[0].T
	var sumT, sumD float64
	for _, p := range points {
		sumT += p.T.Sub(base).Seconds()
		sumD += float64(at(p))
	}
	n := float64(len(points))
	meanT, meanD := sumT/n, sumD/n
	var num, den float64
	for _, p := range points {
		dt := p.T.Sub(base).Seconds() - meanT
		num += dt * (float64(at(p)) - meanD)
		den += dt * dt
	}
	if den == 0 {
		return "", 0, false
	}
	drain = -(num / den) // depth falling => positive drain
	if drain <= 0 {
		return "", drain, true
	}
	// Clamp in seconds, BEFORE converting to a Duration: see etaMax.
	secs := float64(depth) / drain
	if secs >= etaMax.Seconds() {
		return coarsenETA(etaMax), drain, true
	}
	return coarsenETA(time.Duration(secs * float64(time.Second))), drain, true
}

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
		out = append(out, byte(c)) //nolint:gosec // c is restricted to ASCII digits
	}
	return string(out)
}

// fmtRate formats a per-second rate with precision proportional to its
// magnitude.
//
// The page was printing "27.61 items/s" for a number that swings by a fifth
// between refreshes. Two decimals on a quantity that unstable is not precision,
// it is a claim the data cannot support, and it invites a reader to compare
// digits that are noise. Small rates keep their decimals because there the
// digits are the signal.
// fmtSigned is fmtRate with an explicit sign, for values whose direction is the
// point.
func fmtSigned(v float64) string {
	if v >= 0 {
		return "+" + fmtRate(v)
	}
	return fmtRate(v)
}

func fmtRate(v float64) string {
	switch a := math.Abs(v); {
	case a >= 100:
		return fmt.Sprintf("%.0f", v)
	case a >= 1:
		return fmt.Sprintf("%.1f", v)
	default:
		return fmt.Sprintf("%.2f", v)
	}
}

// coarsenETA rounds an ETA to a granularity its own error bar can support.
//
// The ETA comes from a least-squares slope over a few hours of samples taken
// five minutes apart. "21h54m" spends four digits implying it knows the minute;
// it does not, and a reader who returns in an hour and sees "20h31m" learns
// nothing from the change. Anything measured in days or hours is rounded to the
// hour and prefixed to say so.
func coarsenETA(d time.Duration) string {
	if d >= time.Hour {
		return "~" + shortDuration(d.Round(time.Hour))
	}
	if d >= 10*time.Minute {
		return "~" + shortDuration(d.Round(time.Minute))
	}
	return shortDuration(d)
}

func shortDuration(d time.Duration) string {
	d = d.Round(time.Second)
	days := int(d / (24 * time.Hour))
	h := int(d / time.Hour)
	m := int((d % time.Hour) / time.Minute)
	s := int((d % time.Minute) / time.Second)
	switch {
	// Ages here reach months (a litmus backlog measured 3311h40m on the live
	// dashboard, which nobody reads as 138 days). Days first.
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
