package main

import (
	"context"
	"fmt"
	"sync"
	"time"

	"go.opentelemetry.io/otel"
	"go.opentelemetry.io/otel/attribute"
	"go.opentelemetry.io/otel/metric"
)

// meterName scopes hopper's domain instruments. Per the atomdrift observability
// conventions, domain metrics use a service-scoped meter (not the obs package
// meter, which carries the shared HTTP/pool instrumentation).
const meterName = "github.com/atomdrift-project/hopper"

// metricsCollectTimeout bounds the database work a single scrape may trigger.
// The collector shares the dashboard's caches, so on a warm cache it does no
// I/O; on a cold scrape it recomputes the same handful of indexed counts the
// page would, capped here so a slow database cannot wedge a scrape past its
// timeout.
const metricsCollectTimeout = 8 * time.Second

// instruments holds the observable handles enableMetrics creates and observe
// records into. Grouping them lets the registration read as a flat manifest and
// keeps the callback's parameter list to one pointer.
type instruments struct {
	pending, rescan, cleavePending, litmusPending metric.Int64Observable
	analyzed                                      metric.Int64Observable
	analysisRate, filesRate                       metric.Float64Observable
	addedAge, analyzedAge, readyLag               metric.Float64Observable
	walked, inserted, cacheHits, filtered, errors metric.Int64Observable
	insertFails                                   metric.Int64Observable
	wLastSeen, wLoad, wFilesRate                  metric.Float64Observable
	wActive, wSlots, wQueue, wRSS                 metric.Int64Observable
	wAnalyzed, wErrors, wErrorsRecent             metric.Int64Observable
	localUp, localRestarts                        metric.Int64Observable
	localMem, localMemBudget                      metric.Int64Observable
	extractInUse, extractMax                      metric.Int64Observable
	resultInUse, resultMax                        metric.Int64Observable
}

// loadShedCount counts load-shedding events: requests turned away with a
// Retry-After because a slot pool (result ingestion or archive extraction) was
// saturated. This is the aggregate post-mortem signal for "we dropped work
// under pressure" — per-event logging would flood under sustained backpressure,
// but a counter labeled by pool aggregates cleanly and graphs over time.
var (
	loadShedOnce  sync.Once
	loadShedCount metric.Int64Counter
)

// recordLoadShed increments the load-shed counter for the named slot pool
// ("result" or "extract"). The counter is created lazily on first use — the
// meter provider is installed by obs.Init before any request is served — and a
// creation failure leaves it nil, degrading to a silent no-op. ctx carries the
// request's trace span so the metric links back to the shed request.
func recordLoadShed(ctx context.Context, pool string) {
	loadShedOnce.Do(func() {
		if c, err := otel.Meter(meterName).Int64Counter(
			"hopper.load_shed.total",
			metric.WithDescription("Requests shed with Retry-After because a slot pool was saturated."),
		); err == nil {
			loadShedCount = c
		}
	})
	if loadShedCount != nil {
		loadShedCount.Add(ctx, 1, metric.WithAttributes(attribute.String("pool", pool)))
	}
}

// enableMetrics registers the OpenTelemetry instruments that publish every
// numeric the web dashboard shows, so the trends are scrapeable at /_/metrik
// without screen-scraping the HTML. The instruments are observable: a single
// callback gathers one consistent snapshot per scrape and observes each gauge,
// so there is no hot-path cost and nothing to keep in sync by hand.
//
// Database-derived values reuse the dashboard's cached fetchers (see
// dashboard.go), so a scrape adds no load the page would not already cause and,
// when nothing is watching the page, costs at most one indexed count per metric
// per scrape window. Worker, progress, and local-worker-health values come from
// the in-memory trackers the dashboard already reads.
//
// Wire it after obs.Init has installed the global meter provider. Calling it
// before the load session is configured is harmless: the callback observes only
// what is wired (it no-ops until configure() populates progress/db/tracker).
func (wd *webDashboard) enableMetrics() error {
	return wd.registerMetrics(otel.Meter(meterName))
}

// registerMetrics creates the instruments on meter and wires the collection
// callback. Split from enableMetrics so a test can supply an isolated meter
// (its own provider and registry) instead of the process-global one.
func (wd *webDashboard) registerMetrics(meter metric.Meter) error {
	var firstErr error
	var all []metric.Observable
	track := func(name string, obs metric.Observable, err error) {
		if err != nil && firstErr == nil {
			firstErr = fmt.Errorf("%s: %w", name, err)
		}
		all = append(all, obs)
	}
	// Each closure omits the unit when empty: a "1" unit makes the Prometheus
	// exporter append a misleading _ratio suffix, so dimensionless instruments
	// (up, load average) pass "" and stay unsuffixed.
	gauge := func(name, desc, unit string) metric.Int64Observable {
		opts := []metric.Int64ObservableGaugeOption{metric.WithDescription(desc)}
		if unit != "" {
			opts = append(opts, metric.WithUnit(unit))
		}
		g, err := meter.Int64ObservableGauge(name, opts...)
		track(name, g, err)
		return g
	}
	counter := func(name, desc, unit string) metric.Int64Observable {
		opts := []metric.Int64ObservableCounterOption{metric.WithDescription(desc)}
		if unit != "" {
			opts = append(opts, metric.WithUnit(unit))
		}
		c, err := meter.Int64ObservableCounter(name, opts...)
		track(name, c, err)
		return c
	}
	fgauge := func(name, desc, unit string) metric.Float64Observable {
		opts := []metric.Float64ObservableGaugeOption{metric.WithDescription(desc)}
		if unit != "" {
			opts = append(opts, metric.WithUnit(unit))
		}
		g, err := meter.Float64ObservableGauge(name, opts...)
		track(name, g, err)
		return g
	}

	in := instruments{
		// Queue depth and pipeline backlog.
		pending:       gauge("hopper.queue.pending", "Samples awaiting first analysis.", "{sample}"),
		rescan:        gauge("hopper.queue.rescan", "Samples eligible for re-analysis under the live traits version.", "{sample}"),
		cleavePending: gauge("hopper.queue.cleave_pending", "Samples awaiting the cleave stage.", "{sample}"),
		litmusPending: gauge("hopper.queue.litmus_pending", "Samples awaiting the litmus stage.", "{sample}"),

		// Throughput. analyzed is a process-lifetime monotonic total.
		analyzed:     counter("hopper.analyzed", "Cumulative samples analyzed (database total at startup plus this session).", "{sample}"),
		analysisRate: fgauge("hopper.analysis.rate", "Top-level analyses per second over the rate window, by tier.", "{sample}/s"),
		filesRate:    fgauge("hopper.files.rate", "Files analyzed per second across the fleet over the trailing 15 minutes.", "{file}/s"),

		// Freshness / lag, in seconds. A rising value means that stage stalled.
		addedAge:    fgauge("hopper.workflow.added_age", "Seconds since the most recently added sample.", "s"),
		analyzedAge: fgauge("hopper.workflow.analyzed_age", "Seconds since the most recently analyzed sample.", "s"),
		readyLag:    fgauge("hopper.workflow.ready_lag", "Seconds between the newest added sample and the newest prism-ready sample.", "s"),

		// Walk / ingest. Process-lifetime counters; reset to zero on restart.
		walked:    counter("hopper.walk.files", "Files enumerated by the filesystem walk this process lifetime.", "{file}"),
		inserted:  counter("hopper.walk.inserted", "New samples inserted this process lifetime.", "{sample}"),
		cacheHits: counter("hopper.walk.cache_hits", "Walked files already known (hash cache hits) this process lifetime.", "{file}"),
		filtered:  counter("hopper.walk.filtered", "Walked files skipped for being too small or too large this process lifetime.", "{file}"),
		errors:    counter("hopper.errors", "Ingestion errors recorded this process lifetime.", "{error}"),
		// Insert failures broken out by cause, keyed by a bounded "cause"
		// attribute, so lock contention reads apart from malformed input.
		insertFails: counter("hopper.insert.failures", "Sample inserts that failed this process lifetime, by cause.", "{sample}"),

		// Per-worker, keyed by a bounded "worker" attribute.
		wLastSeen:     fgauge("hopper.worker.last_seen_age", "Seconds since the worker last polled or sent a heartbeat.", "s"),
		wLoad:         fgauge("hopper.worker.load1", "Worker host 1-minute load average.", ""),
		wFilesRate:    fgauge("hopper.worker.files_rate", "Files per second the worker reports.", "{file}/s"),
		wActive:       gauge("hopper.worker.active_claims", "Tasks the worker currently holds.", "{task}"),
		wSlots:        gauge("hopper.worker.slots", "Concurrent task slots the worker advertises.", "{task}"),
		wQueue:        gauge("hopper.worker.queue", "Items in the worker's local intake queue.", "{sample}"),
		wRSS:          gauge("hopper.worker.rss", "Worker resident set size.", "By"),
		wAnalyzed:     counter("hopper.worker.analyzed", "Cumulative samples analyzed by the worker.", "{sample}"),
		wErrors:       counter("hopper.worker.errors", "Cumulative errors reported by the worker.", "{error}"),
		wErrorsRecent: gauge("hopper.worker.errors_recent", "Errors the worker reported in the trailing 15 minutes.", "{error}"),

		// Local scan (litmus) worker liveness. up is the signal for the
		// "local worker down" alert; restarts trends supervisor churn.
		localUp:       gauge("hopper.local_worker.up", "1 when the in-process scan worker is healthy, 0 when down.", ""),
		localRestarts: counter("hopper.local_worker.restarts", "Cumulative supervisor restarts of the local scan worker.", "{restart}"),
		// Ground truth from /proc, not the worker's self-report: the
		// 2026-07-09 incident had a worker 33 GB past its self-reported
		// number, so the discrepancy between this gauge and the heartbeat's
		// rss_mb is itself a signal. The supervisor kills the worker when
		// this sustains above budget × the kill factor; alert at 1× budget
		// to see it coming.
		localMem:       gauge("hopper.local_worker.memory", "Kernel-reported memory (VmRSS+VmSwap) of the local scan worker.", "By"),
		localMemBudget: gauge("hopper.local_worker.memory_budget", "The local scan worker's configured memory budget (--max-memory-gb).", "By"),

		// Archive-member extraction concurrency. in_use approaching max means
		// /api/file member requests are queuing (or being shed with 503); the
		// ratio is the saturation signal for the extraction cap.
		extractInUse: gauge("hopper.extract.slots_in_use", "Archive-member extraction slots currently held.", "{slot}"),
		extractMax:   gauge("hopper.extract.slots_max", "Maximum concurrent archive-member extraction slots.", "{slot}"),
		// Result-ingestion concurrency. Same shape as extract; pair with
		// hopper.load_shed.total{pool="result"}.
		resultInUse: gauge("hopper.result.slots_in_use", "Result-ingestion slots currently held.", "{slot}"),
		resultMax:   gauge("hopper.result.slots_max", "Maximum concurrent result-ingestion slots.", "{slot}"),
	}
	if firstErr != nil {
		return firstErr
	}

	_, err := meter.RegisterCallback(func(ctx context.Context, o metric.Observer) error {
		wd.observe(ctx, o, &in)
		return nil
	}, all...)
	if err != nil {
		return fmt.Errorf("register hopper metrics callback: %w", err)
	}
	return nil
}

// observe gathers one snapshot and records it. It runs per scrape; until the
// load session is configured the trackers are nil and it observes nothing.
func (wd *webDashboard) observe(ctx context.Context, o metric.Observer, in *instruments) {
	wd.cfgMu.RLock()
	progress := wd.progress
	tracker := wd.tracker
	litmus := wd.litmus
	db := wd.db
	api := wd.api
	wd.cfgMu.RUnlock()

	now := time.Now()

	if db != nil {
		cctx, cancel := context.WithTimeout(ctx, metricsCollectTimeout)
		defer cancel()
		o.ObserveInt64(in.pending, wd.pendingCount(cctx))
		o.ObserveInt64(in.rescan, wd.rescanPending(cctx))

		rates := wd.analysisRates(cctx)
		o.ObserveFloat64(in.analysisRate, float64(rates.TopLevel)/analysisRateWindow.Seconds(),
			metric.WithAttributes(attribute.String("tier", "toplevel")))
		o.ObserveFloat64(in.analysisRate, float64(rates.Rescans)/analysisRateWindow.Seconds(),
			metric.WithAttributes(attribute.String("tier", "rescan")))

		if h, ok := wd.workflowHealth(cctx); ok {
			o.ObserveInt64(in.cleavePending, h.PendingCleave)
			o.ObserveInt64(in.litmusPending, h.PendingLitmus)
			observeAge(o, in.addedAge, now, h.LatestAdded)
			observeAge(o, in.analyzedAge, now, h.LatestAnalyzed)
			if !h.LatestAdded.IsZero() && !h.LatestReady.IsZero() {
				o.ObserveFloat64(in.readyLag, max(h.LatestAdded.Sub(h.LatestReady).Seconds(), 0))
			}
		}
	}

	if progress != nil {
		o.ObserveInt64(in.analyzed, progress.analyzed.Load())
		o.ObserveInt64(in.walked, progress.walked.Load())
		o.ObserveInt64(in.inserted, progress.inserted.Load())
		o.ObserveInt64(in.cacheHits, progress.cacheHits.Load())
		o.ObserveInt64(in.filtered, progress.tooSmall.Load()+progress.tooLarge.Load())
		o.ObserveInt64(in.errors, progress.errors.Load())
		for c := range numInsertFailCauses {
			o.ObserveInt64(in.insertFails, progress.insertFails[c].Load(),
				metric.WithAttributes(attribute.String("cause", c.String())))
		}
	}

	combined, _ := wd.ratesOver(15 * time.Minute)
	o.ObserveFloat64(in.filesRate, combined)

	if tracker != nil {
		workers := tracker.all()
		for i := range workers {
			ws := &workers[i]
			attr := metric.WithAttributes(attribute.String("worker", ws.Name))
			o.ObserveFloat64(in.wLastSeen, now.Sub(ws.LastSeen).Seconds(), attr)
			o.ObserveFloat64(in.wLoad, ws.Load1, attr)
			o.ObserveFloat64(in.wFilesRate, ws.FilesPerSec, attr)
			o.ObserveInt64(in.wActive, int64(ws.ActiveClaims), attr)
			o.ObserveInt64(in.wSlots, int64(ws.Slots), attr)
			o.ObserveInt64(in.wQueue, int64(ws.Queue), attr)
			o.ObserveInt64(in.wRSS, int64(ws.RSSMB)<<20, attr)
			o.ObserveInt64(in.wAnalyzed, ws.Analyzed, attr)
			o.ObserveInt64(in.wErrors, ws.Errors, attr)
			o.ObserveInt64(in.wErrorsRecent, int64(ws.ErrorsRecent), attr)
		}
	}

	if litmus != nil {
		var up int64
		if h := litmus.healthSnapshot(); h != nil && h.ok {
			up = 1
		}
		o.ObserveInt64(in.localUp, up)
		o.ObserveInt64(in.localRestarts, litmus.restarts.Load())
		if pid := litmus.currentPID(); pid > 0 {
			if mem, err := procMemoryBytes(pid); err == nil {
				o.ObserveInt64(in.localMem, int64(mem)) //nolint:gosec // /proc memory values are far below int64 range
			}
		}
		if litmus.maxRSSGB > 0 {
			o.ObserveInt64(in.localMemBudget, int64(litmus.maxRSSGB)<<30)
		}
	}

	// len/cap of the buffered semaphores: a non-blocking read of in-flight
	// work and the configured ceiling. nil when the cap is disabled.
	if api != nil && api.extractSem != nil {
		o.ObserveInt64(in.extractInUse, int64(len(api.extractSem)))
		o.ObserveInt64(in.extractMax, int64(cap(api.extractSem)))
	}
	if api != nil && api.resultSem != nil {
		o.ObserveInt64(in.resultInUse, int64(len(api.resultSem)))
		o.ObserveInt64(in.resultMax, int64(cap(api.resultSem)))
	}
}

// observeAge records the seconds elapsed since t, skipping a zero timestamp so
// "never happened" reads as an absent series rather than a misleading epoch age.
func observeAge(o metric.Observer, g metric.Float64Observable, now, t time.Time) {
	if t.IsZero() {
		return
	}
	o.ObserveFloat64(g, max(now.Sub(t).Seconds(), 0))
}
