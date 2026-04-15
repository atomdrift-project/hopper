package main

import (
	"context"
	"fmt"
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
)

const dashQueryTimeout = 3 * time.Second

// webDashboard serves a self-contained HTML page. Auto-refreshes every 5s.
// Fields guarded by cfgMu are set once via configure() after the load session
// begins; the handler renders a "starting" state until then.
type webDashboard struct { //nolint:govet // fields grouped logically.
	cfgMu         sync.RWMutex
	progress      *loadProgress
	litmus        *litmusServer
	tracker       *workerTracker
	db            *hopper.DB
	claimsCache   *fido.Cache[string, []hopper.WorkerClaim]
	newestATCache *fido.Cache[string, time.Time]
	samples       []throughputSample // capped at maxThroughputSamples
	start         time.Time
	startAnalyzed int64
	mu            sync.Mutex
	maxAnalyzed   int
	ndirs         int
}

// configure is called once the load session is ready. It sets the fields the
// handler needs to render progress and is safe to call concurrently with the
// HTTP server already running.
func (wd *webDashboard) configure(
	progress *loadProgress, litmus *litmusServer, tracker *workerTracker,
	db *hopper.DB, start time.Time, startAnalyzed int64, maxAnalyzed, ndirs int,
) {
	wd.cfgMu.Lock()
	defer wd.cfgMu.Unlock()
	wd.progress = progress
	wd.litmus = litmus
	wd.tracker = tracker
	wd.db = db
	wd.start = start
	wd.startAnalyzed = startAnalyzed
	wd.maxAnalyzed = maxAnalyzed
	wd.ndirs = ndirs
	wd.claimsCache = fido.New[string, []hopper.WorkerClaim](fido.Size(1), fido.TTL(10*time.Second))
	wd.newestATCache = fido.New[string, time.Time](fido.Size(1), fido.TTL(10*time.Second))
}

const maxThroughputSamples = 2880 // 4 hours at 5-second refresh

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

// throughputSeries derives per-interval files/sec from the sample history.
// Intervals wider than 30s are zeroed to avoid spikes after page inactivity.
// Returns combined rates and per-node rates keyed by worker name.
func (wd *webDashboard) throughputSeries() (combined []float64, perNode map[string][]float64) {
	wd.mu.Lock()
	n := len(wd.samples)
	samples := make([]throughputSample, n)
	copy(samples, wd.samples)
	wd.mu.Unlock()

	if n < 2 {
		return nil, nil
	}
	combined = make([]float64, n-1)

	// Collect all worker names seen across samples.
	nameSet := make(map[string]struct{})
	for _, s := range samples {
		for name := range s.byNode {
			nameSet[name] = struct{}{}
		}
	}
	if len(nameSet) > 0 {
		perNode = make(map[string][]float64, len(nameSet))
		for name := range nameSet {
			perNode[name] = make([]float64, n-1)
		}
	}

	for i := 1; i < n; i++ {
		dt := samples[i].t.Sub(samples[i-1].t).Seconds()
		if dt <= 0 || dt > 30 {
			continue
		}
		combined[i-1] = max(float64(samples[i].total-samples[i-1].total)/dt, 0)
		for name, series := range perNode {
			cur, okCur := samples[i].byNode[name]
			prev, okPrev := samples[i-1].byNode[name]
			if okCur && okPrev {
				series[i-1] = max(float64(cur-prev)/dt, 0)
			}
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
	srv := &http.Server{Handler: mux, ReadHeaderTimeout: 5 * time.Second}
	go func() {
		<-ctx.Done()
		_ = srv.Close() //nolint:errcheck // best-effort shutdown
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
  font-size:13px;line-height:1.6;padding:2.5rem 3rem;max-width:900px}

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
td.warn{color:var(--amber)}

/* status dot */
.dot{font-size:.5rem;vertical-align:middle;margin-right:.35rem}
.dot-ok{color:var(--green)}
.dot-warn{color:var(--amber)}
.dot-bad{color:var(--red)}
.dot-off{color:var(--sub)}

/* error */
.err{background:#1a0d0d;border:1px solid #3d1515;border-radius:4px;
  padding:.5rem .75rem;font-size:.78rem;color:#f87171;margin-top:1.5rem;
  word-break:break-all;font-family:var(--mono)}

/* graph */
.graph-box{background:var(--surface);border:1px solid var(--border);
  border-radius:6px;padding:.75rem 1rem 0}
.graph-legend{display:flex;gap:1rem;padding:.5rem 0;flex-wrap:wrap}
.legend-item{display:flex;align-items:center;gap:.35rem;
  font-size:.72rem;color:var(--sub);font-family:var(--mono)}
.legend-swatch{width:12px;height:2px;border-radius:1px}

/* footer */
footer{padding-top:1rem;border-top:1px solid var(--border);
  font-family:var(--mono);font-size:.75rem;color:var(--sub)}
`

func (wd *webDashboard) handler(w http.ResponseWriter, r *http.Request) { //nolint:maintidx // dashboard render is inherently complex.
	wd.cfgMu.RLock()
	progress := wd.progress
	tracker := wd.tracker
	db := wd.db
	start := wd.start
	startAnalyzed := wd.startAnalyzed
	maxAnalyzed := wd.maxAnalyzed
	wd.cfgMu.RUnlock()

	var workers []namedWorkerStats
	if tracker != nil {
		workers = tracker.all()
	}

	// Query oldest active claim per worker from the DB, with caching
	// and a timeout so a slow database never blocks page renders.
	oldestClaims := make(map[string]hopper.WorkerClaim)
	var newestAnalyzedAt time.Time
	if db != nil {
		//nolint:errcheck,contextcheck // Fetch returns cached/zero on error; closure creates its own context.
		claims, _ := wd.claimsCache.Fetch("claims", func() ([]hopper.WorkerClaim, error) {
			qctx, cancel := context.WithTimeout(r.Context(), dashQueryTimeout)
			defer cancel()
			return db.OldestClaims(qctx, staleClaimAge)
		})
		for _, c := range claims {
			oldestClaims[c.Worker] = c
		}
		//nolint:errcheck,contextcheck // Fetch returns zero time on error; closure creates its own context.
		newestAnalyzedAt, _ = wd.newestATCache.Fetch("newest", func() (time.Time, error) {
			qctx, cancel := context.WithTimeout(r.Context(), dashQueryTimeout)
			defer cancel()
			return db.NewestAnalyzedAt(qctx)
		})
	}

	if progress == nil {
		w.Header().Set("Content-Type", "text/html; charset=utf-8")
		_, _ = fmt.Fprint(w, //nolint:errcheck // best-effort HTTP response
			`<!DOCTYPE html><html lang="en"><head>`+
				`<meta charset="utf-8"><meta http-equiv="refresh" content="2">`+
				`<title>hopper</title><style>`+css+`</style></head><body>`+
				`<div class="hdr"><div class="hdr-top"><span class="hdr-title">Hopper</span>`+
				`<span class="hdr-time">starting&hellip;</span></div></div>`+
				`</body></html>`)
		return
	}

	elapsed := time.Since(start).Round(time.Second)
	analyzedAbs := progress.analyzed.Load()
	sessionAnalyzed := max(analyzedAbs-startAnalyzed, 0)
	walked := progress.walked.Load()

	analyzeTarget := max(progress.queued.Load()-startAnalyzed, 0)
	if maxAnalyzed > 0 && int64(maxAnalyzed) < analyzeTarget {
		analyzeTarget = int64(maxAnalyzed)
	}
	totalTarget := startAnalyzed + analyzeTarget
	totalDone := startAnalyzed + sessionAnalyzed

	wd.recordSample(sessionAnalyzed)
	rate, nodeRateByName := wd.ratesOver(15 * time.Minute)

	var etaStr string
	if rate > 0.1 && analyzeTarget > sessionAnalyzed {
		remaining := analyzeTarget - sessionAnalyzed
		etaDur := time.Duration(float64(remaining)/rate) * time.Second
		etaStr = formatETA(etaDur)
	}

	pct := 0.0
	if totalTarget > 0 {
		pct = math.Min(float64(totalDone)/float64(totalTarget)*100, 100)
	}

	var buf strings.Builder
	buf.WriteString(`<!DOCTYPE html><html lang="en"><head>` +
		`<meta charset="utf-8"><meta http-equiv="refresh" content="5">` +
		`<title>hopper</title><style>` + css + `</style></head><body>`)

	// Header + progress
	buf.WriteString(`<div class="hdr">`)
	buf.WriteString(`<div class="hdr-top">`)
	buf.WriteString(`<span class="hdr-title">Hopper</span>`)
	fmt.Fprintf(&buf, `<span class="hdr-time">%s</span>`, elapsed)
	buf.WriteString(`</div>`)

	// Big progress
	buf.WriteString(`<div class="progress">`)
	buf.WriteString(`<div class="progress-stats">`)
	fmt.Fprintf(&buf, `<span class="progress-main"><span class="progress-pct">%.0f%%</span> analyzed</span>`, pct)

	// Rate + ETA
	buf.WriteString(`<span class="progress-detail">`)
	fmt.Fprintf(&buf, `<em>%s</em> / %s`, fmtN(totalDone), fmtN(totalTarget))
	if rate > 0.1 {
		fmt.Fprintf(&buf, ` &middot; <em>%.1f</em>/s (15m avg)`, rate)
	}
	if etaStr != "" {
		fmt.Fprintf(&buf, ` &middot; ETA <em>%s</em>`, etaStr)
	}
	buf.WriteString(`</span>`)
	buf.WriteString(`</div>`)

	// Bar
	priorPct := 0.0
	sessionPct := 0.0
	if totalTarget > 0 {
		priorPct = math.Min(float64(startAnalyzed)/float64(totalTarget)*100, 100)
		sessionPct = math.Min(float64(sessionAnalyzed)/float64(totalTarget)*100, 100-priorPct)
	}
	fmt.Fprintf(&buf,
		`<div class="track">`+
			`<div class="fill" style="width:%.2f%%;background:#5a5230"></div>`+
			`<div class="fill" style="width:%.2f%%;background:#fbbf24"></div>`+
			`</div>`,
		priorPct, sessionPct)
	buf.WriteString(`</div>`) // .progress
	buf.WriteString(`</div>`) // .hdr

	// Throughput graph
	combinedSeries, perNodeSeries := wd.throughputSeries()
	if len(combinedSeries) >= 2 {
		// Build ordered name/series slices for the graph.
		var graphNodeNames []string
		var graphNodeSeries [][]float64
		for i := range workers {
			if series, ok := perNodeSeries[workers[i].Name]; ok {
				graphNodeNames = append(graphNodeNames, workers[i].Name)
				graphNodeSeries = append(graphNodeSeries, series)
			}
		}
		buf.WriteString(`<section><div class="label">Throughput</div>`)
		writeThroughputGraph(&buf, combinedSeries, graphNodeSeries, graphNodeNames)
		buf.WriteString(`</section>`)
	}

	// Workers
	if len(workers) > 0 {
		buf.WriteString(`<section><div class="label">Workers</div>`)
		buf.WriteString(`<table><thead><tr>` +
			`<th>Worker</th><th>Tasks</th><th>Claimed</th><th>Rate</th>` +
			`<th>Analyzed</th><th>Errors</th><th>Oldest Job</th><th></th>` +
			`</tr></thead><tbody>`)

		sort.Slice(workers, func(i, j int) bool { return workers[i].Name < workers[j].Name })
		for i := range workers {
			w := &workers[i]
			idle := time.Since(w.LastSeen)
			status, _ := workerStatus(w.ActiveClaims, idle)
			dotClass := "dot-ok"
			if w.ActiveClaims == 0 && idle >= 10*time.Minute {
				dotClass = "dot-warn"
			}
			if w.ActiveClaims == 0 && idle >= 30*time.Minute {
				dotClass = "dot-bad"
			}

			nRate := nodeRateByName[w.Name]
			rateStr := "—"
			if nRate > 0.05 {
				rateStr = fmt.Sprintf("%.1f/s", nRate)
			}

			oldestStr := "—"
			if claim, ok := oldestClaims[w.Name]; ok {
				age := time.Since(claim.ClaimedAt)
				oldestStr = fmt.Sprintf("%s (%s)", filepath.Base(claim.Path), shortDuration(age))
			}

			fmt.Fprintf(&buf,
				`<tr>`+
					`<td class="nn"><span class="dot %s">●</span>%s</td>`+
					`<td class="hi">%d/%d</td>`+
					`<td class="hi">%s</td>`+
					`<td class="rate">%s</td>`+
					`<td class="hi">%s</td>`+
					`<td>%s</td>`+
					`<td>%s</td>`+
					`<td class="warn">%s</td>`+
					`</tr>`,
				dotClass, htmlEscape(w.Name),
				w.ActiveClaims, w.Slots,
				fmtN(w.TotalClaimed),
				rateStr,
				fmtN(w.Analyzed),
				fmtN(w.Errors),
				htmlEscape(oldestStr),
				htmlEscape(status),
			)
		}
		buf.WriteString(`</tbody></table></section>`)
	}

	// Footer
	lastCompleted := ""
	if !newestAnalyzedAt.IsZero() {
		lastCompleted = fmt.Sprintf(` &middot; last completed %s ago`, shortDuration(time.Since(newestAnalyzedAt)))
	}
	fmt.Fprintf(&buf,
		`<footer>%s errors &middot; %s walked &middot; %s cache hits%s</footer>`,
		fmtN(progress.errors.Load()),
		fmtN(walked),
		fmtN(progress.cacheHits.Load()),
		lastCompleted,
	)

	// Last error at the bottom, untruncated
	if last, ok := progress.lastErr.Load().(string); ok && last != "" {
		fmt.Fprintf(&buf, `<div class="err">%s</div>`, htmlEscape(last))
	}

	buf.WriteString(`</body></html>`)
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	_, _ = fmt.Fprint(w, buf.String()) //nolint:errcheck // best-effort HTTP response
}

// ---------------------------------------------------------------------------
// Helpers shared by both dashboards.
// ---------------------------------------------------------------------------.

// shortNodeName trims the port suffix when it's the default litmus port.
func shortNodeName(name string) string {
	name = strings.TrimSuffix(name, ":49999")
	// Also trim ":NNNNN" from local:NNNNN for the local node.
	if strings.HasPrefix(name, "local:") {
		return "local"
	}
	return name
}

// ---------------------------------------------------------------------------
// Throughput graph (SVG sparkline).
// ---------------------------------------------------------------------------.

func writeThroughputGraph(buf *strings.Builder, combined []float64, perNode [][]float64, nodeNames []string) {
	const w, h, px, py = 900, 72, 0, 4

	maxVal := 0.1
	for _, v := range combined {
		if v > maxVal {
			maxVal = v
		}
	}
	for _, series := range perNode {
		for _, v := range series {
			if v > maxVal {
				maxVal = v
			}
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

	line := func(vals []float64) string {
		var sb strings.Builder
		for i, v := range vals {
			if i > 0 {
				sb.WriteByte(' ')
			}
			fmt.Fprintf(&sb, "%.1f,%.1f", xOf(i, len(vals)), yOf(v))
		}
		return sb.String()
	}

	areaPoints := func(vals []float64) string {
		if len(vals) == 0 {
			return ""
		}
		var sb strings.Builder
		fmt.Fprintf(&sb, "%.1f,%.1f", xOf(0, len(vals)), float64(h-py))
		for i, v := range vals {
			fmt.Fprintf(&sb, " %.1f,%.1f", xOf(i, len(vals)), yOf(v))
		}
		fmt.Fprintf(&sb, " %.1f,%.1f", xOf(len(vals)-1, len(vals)), float64(h-py))
		return sb.String()
	}

	nodeColors := []string{"#34d399", "#fbbf24", "#f87171", "#22d3ee", "#a78bfa", "#fb923c"}

	buf.WriteString(`<div class="graph-box">`)
	fmt.Fprintf(buf, `<svg width="%d" height="%d" viewBox="0 0 %d %d" style="display:block;width:100%%;overflow:visible">`,
		w, h, w, h)

	for _, frac := range []float64{0.5, 1.0} {
		y := yOf(maxVal * frac)
		fmt.Fprintf(buf, `<line x1="%d" y1="%.1f" x2="%d" y2="%.1f" stroke="#1a1f2e" stroke-width="1"/>`,
			px, y, w-px, y)
		fmt.Fprintf(buf, `<text x="%d" y="%.1f" fill="#2d3448" font-size="9" font-family="monospace" dy="-3">%.0f</text>`,
			px, y, maxVal*frac)
	}

	if pts := areaPoints(combined); pts != "" {
		fmt.Fprintf(buf, `<polygon points="%s" fill="#818cf8" fill-opacity="0.07"/>`, pts)
	}

	for i, series := range perNode {
		if pts := line(series); pts != "" {
			color := nodeColors[i%len(nodeColors)]
			fmt.Fprintf(buf,
				`<polyline points="%s" fill="none" stroke="%s" stroke-width="1" stroke-linejoin="round" stroke-opacity="0.7"/>`,
				pts, color)
		}
	}

	if pts := line(combined); pts != "" {
		fmt.Fprintf(buf, `<polyline points="%s" fill="none" stroke="#818cf8" stroke-width="2" stroke-linejoin="round"/>`, pts)
	}

	buf.WriteString(`</svg>`)

	buf.WriteString(`<div class="graph-legend">`)
	fmt.Fprint(buf, `<span class="legend-item"><span class="legend-swatch" style="background:#818cf8;height:2px"></span>combined</span>`)
	for i, name := range nodeNames {
		color := nodeColors[i%len(nodeColors)]
		fmt.Fprintf(buf, `<span class="legend-item"><span class="legend-swatch" style="background:%s"></span>%s</span>`,
			color, htmlEscape(shortNodeName(name)))
	}
	buf.WriteString(`</div></div>`)
}

// ---------------------------------------------------------------------------
// Formatting helpers.
// ---------------------------------------------------------------------------.

func formatETA(d time.Duration) string {
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
	s = strings.ReplaceAll(s, "&", "&amp;")
	s = strings.ReplaceAll(s, "<", "&lt;")
	s = strings.ReplaceAll(s, ">", "&gt;")
	s = strings.ReplaceAll(s, "\"", "&quot;")
	s = strings.ReplaceAll(s, "'", "&#39;")
	return s
}
