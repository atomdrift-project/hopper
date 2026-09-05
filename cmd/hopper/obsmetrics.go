package main

import (
	"cmp"
	"context"
	"fmt"
	"math"
	"sync"
	"time"

	"github.com/atomdrift-project/hopper"
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
	wClaimed, wReleased                           metric.Int64Observable
	wInfo                                         metric.Int64Observable
	localUp, localRestarts                        metric.Int64Observable
	localMem, localMemBudget                      metric.Int64Observable
	extractInUse, extractMax                      metric.Int64Observable
	resultInUse, resultMax                        metric.Int64Observable
	lookupReqs                                    metric.Int64Observable
	lookupEntries, lookupCapacity                 metric.Int64Observable
	popularPackages                               metric.Int64Observable
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

// resultPhaseHist times what a result-ingestion slot is actually held on once
// acquired: "body" (streaming + decoding the envelope off the wire) versus
// "store" (the StoreResult transaction, retries and lock waits included). The
// HTTP route histogram measures the whole request — slot wait folded in — so
// it can say a request was slow but not which phase pinned the slot; this
// histogram is the difference between "raise the slot count" (bodies are slow;
// concurrency is cheap) and "fix the store path" (the DB holds the slot, and
// more slots only add contention — measured 2026-08-23 when 64 slots
// throughput-regressed against 32). Labeled by lane so renewals and worker
// results read separately.
var (
	resultPhaseOnce sync.Once
	resultPhaseHist metric.Float64Histogram
)

// recordResultPhase records one phase duration for a held result slot. Same
// lazy-create/no-op-on-failure contract as recordLoadShed.
func recordResultPhase(ctx context.Context, phase, lane string, d time.Duration) {
	resultPhaseOnce.Do(func() {
		if h, err := otel.Meter(meterName).Float64Histogram(
			"hopper.result_phase.seconds",
			metric.WithDescription("Time a held result-ingestion slot spent in each phase (body = read+decode, store = DB transaction)."),
			metric.WithExplicitBucketBoundaries(0.01, 0.05, 0.1, 0.25, 0.5, 1, 2, 4, 8, 16, 30, 60),
		); err == nil {
			resultPhaseHist = h
		}
	})
	if resultPhaseHist != nil {
		resultPhaseHist.Record(ctx, d.Seconds(), metric.WithAttributes(
			attribute.String("phase", phase), attribute.String("lane", lane)))
	}
}

// Sample-age histograms answer "how far behind is the queue" in the one unit
// that survives a change in throughput: how old the work itself is. Queue depth
// cannot answer it — a 500k backlog drained in SHA-pivot order and a 500k
// backlog nobody is touching look identical — and neither can throughput, which
// holds steady while the queue ages underneath it.
//
// Two measurements, both taken against samples.created_at (when the row entered
// the queue), because the gap between them is the informative part:
//
//   - claim age: how long work waited before a worker was handed it. This is
//     queue lag proper. Rising means we are reaching further back into the
//     backlog to find work.
//   - commit age: claim age plus however long the worker held the job. Rising
//     faster than claim age means the fleet, not the queue, is the constraint.
//
// Histograms rather than gauges: the average is what was asked for and
// rate(_sum)/rate(_count) gives it, but the distribution is what distinguishes
// "everything is a day old" from "most work is fresh and a tail is ancient",
// and those want different fixes. The buckets run from a minute to sixteen
// weeks — hopper's backlog is measured in weeks, so a second-scale ladder would
// pile every real observation into +Inf.
var sampleAgeBuckets = []float64{
	60, 300, 900, 3600, 4 * 3600, 12 * 3600, 24 * 3600,
	3 * 24 * 3600, 7 * 24 * 3600, 14 * 24 * 3600, 30 * 24 * 3600,
	60 * 24 * 3600, 120 * 24 * 3600,
}

// claimAgeHist and commitAgeHist follow the same lazy-create, nil-is-a-no-op
// contract as recordLoadShed: the meter provider is installed by obs.Init long
// before the first claim poll, and a creation failure degrades to silence
// rather than to a panic on a request path.
var (
	claimAgeOnce  sync.Once
	claimAgeHist  metric.Float64Histogram
	commitAgeOnce sync.Once
	commitAgeHist metric.Float64Histogram
)

// newSampleAgeHistogram builds one of the two age histograms on meter,
// returning nil if the instrument cannot be created (the recorder then degrades
// to a no-op). Split out for the same reason newDBRetryCounter is: a test can
// bind the instrument to its own provider and registry and still assert against
// the production definition, without installing a global meter provider —
// which would retroactively drag every other instrument the suite created into
// that registry.
func newSampleAgeHistogram(m metric.Meter, name, desc string) metric.Float64Histogram {
	h, err := m.Float64Histogram(name,
		metric.WithDescription(desc),
		metric.WithUnit("s"),
		metric.WithExplicitBucketBoundaries(sampleAgeBuckets...),
	)
	if err != nil {
		return nil
	}
	return h
}

const (
	claimAgeName = "hopper.claim.sample_age"
	claimAgeDesc = "Age of a sample (since its row was created) at the moment it was handed to a worker, by claim tier."

	commitAgeName = "hopper.commit.sample_age"
	commitAgeDesc = "Age of a sample (since its row was created) when its analysis was committed, " +
		"by whether this was a first analysis or a renewal."
)

// recordClaimAges reports the queue age of every job in one hand-out, all
// against a single clock read so a slow batch cannot make its later jobs look
// older than its earlier ones.
func recordClaimAges(ctx context.Context, jobs []hopper.ClaimJob) {
	now := time.Now()
	for _, j := range jobs {
		recordClaimAge(ctx, j.Tier, j.CreatedAt, now)
	}
}

// recordClaimAge records how old a sample was when it was handed to a worker,
// labeled by the tier it was drawn from. The tier label is not decoration: the
// rescan tiers deliberately re-serve rows that are months old, so a single
// unlabeled average would report a permanently ancient queue no matter how
// current the fresh-ingest path was. A zero createdAt (a row predating the
// column, or a SQLite string that would not parse) is skipped rather than
// reported as a 56-year lag.
func recordClaimAge(ctx context.Context, tier string, createdAt, now time.Time) {
	if createdAt.IsZero() {
		return
	}
	claimAgeOnce.Do(func() {
		claimAgeHist = newSampleAgeHistogram(otel.Meter(meterName), claimAgeName, claimAgeDesc)
	})
	if claimAgeHist != nil {
		claimAgeHist.Record(ctx, max(now.Sub(createdAt).Seconds(), 0),
			metric.WithAttributes(attribute.String("tier", tier)))
	}
}

// recordCommitAge records how old a sample was when its result was committed.
// Labeled "first" or "renewal" for the same reason claims are labeled by tier:
// a renewal is by construction a re-analysis of an old row, and averaging the
// two together hides the end-to-end latency of freshly ingested work, which is
// the number that says whether the pipeline is keeping up.
func recordCommitAge(ctx context.Context, renewal bool, createdAt, now time.Time) {
	if createdAt.IsZero() {
		return
	}
	commitAgeOnce.Do(func() {
		commitAgeHist = newSampleAgeHistogram(otel.Meter(meterName), commitAgeName, commitAgeDesc)
	})
	if commitAgeHist == nil {
		return
	}
	kind := "first"
	if renewal {
		kind = "renewal"
	}
	commitAgeHist.Record(ctx, max(now.Sub(createdAt).Seconds(), 0),
		metric.WithAttributes(attribute.String("kind", kind)))
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
		wLastSeen:  fgauge("hopper.worker.last_seen_age", "Seconds since the worker last polled or sent a heartbeat.", "s"),
		wLoad:      fgauge("hopper.worker.load1", "Worker host 1-minute load average.", ""),
		wFilesRate: fgauge("hopper.worker.files_rate", "Files per second the worker reports.", "{file}/s"),
		wActive:    gauge("hopper.worker.active_claims", "Tasks the worker currently holds.", "{task}"),
		wSlots:     gauge("hopper.worker.slots", "Concurrent task slots the worker advertises.", "{task}"),
		wQueue:     gauge("hopper.worker.queue", "Items in the worker's local intake queue.", "{sample}"),
		wRSS:       gauge("hopper.worker.rss", "Worker resident set size.", "By"),
		wAnalyzed:  counter("hopper.worker.analyzed", "Cumulative samples analyzed by the worker.", "{sample}"),
		// Claimed and released are a pair: released/claimed is the share of
		// handed-out work the worker gave back without a result. An embedded
		// idle worker sheds staged work whenever its host server takes an
		// interactive request, so a non-zero ratio is expected there — a
		// *rising* one says the host is spending its queue capacity on work it
		// never starts. Neither is meaningful without the other, so both are
		// exported even though claimed was previously dashboard-only.
		wClaimed:      counter("hopper.worker.claimed", "Cumulative samples handed out to the worker.", "{sample}"),
		wReleased:     counter("hopper.worker.released", "Cumulative claims the worker handed back without a result.", "{sample}"),
		wErrors:       counter("hopper.worker.errors", "Cumulative errors reported by the worker.", "{error}"),
		wErrorsRecent: gauge("hopper.worker.errors_recent", "Errors the worker reported in the trailing 15 minutes.", "{error}"),
		// Always 1. The value is the label: the scan version the worker
		// reports on every heartbeat, so a deploy is a visible edge on a
		// graph and a rule can ask "did latency move within an hour of a
		// version change on this worker". On 2026-09-04 a release tripled
		// every worker's slot count and /analyze latency rose thirtyfold; the
		// only record of when each box picked it up was a systemd journal.
		wInfo: gauge("hopper.worker.info", "1 for every known worker, carrying the scan version it last reported as a label.", ""),

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
		// Labeled by key kind and by whether the request reached the database,
		// so the served fraction — the whole point of the pool — is one query
		// away rather than something to infer from two unrelated counters.
		lookupReqs: counter("hopper.lookup.requests",
			"Sample lookups, by key and by whether the request reached the database.", "{request}"),
		lookupEntries: gauge("hopper.lookup.entries",
			"Sample lookup entries currently held in the in-process pool.", "{entry}"),
		lookupCapacity: gauge("hopper.lookup.capacity",
			"Maximum sample lookup entries the in-process pool will hold.", "{entry}"),
		// Whether a publisher's ranking actually landed is otherwise only
		// visible from the publisher's own side, which reports what it sent
		// rather than what was stored. Those are different claims, and after a
		// restart race they disagreed.
		popularPackages: gauge("hopper.popular.packages",
			"Package identities marked as popular, across all sources.", "{package}"),
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

// clampCount narrows a counter for the Int64 observer. Saturating rather than
// wrapping: a counter that overflowed would otherwise be reported as negative,
// and a monotonic instrument going backwards is read downstream as a process
// restart. Unreachable in practice at any plausible request rate.
func clampCount(v uint64) int64 {
	if v > math.MaxInt64 {
		return math.MaxInt64
	}
	return int64(v)
}

// observe gathers one snapshot and records it. It runs per scrape; until the
// load session is configured the trackers are nil and it observes nothing.
func (wd *webDashboard) observe(ctx context.Context, observer metric.Observer, in *instruments) {
	wd.cfgMu.RLock()
	progress := wd.progress
	tracker := wd.tracker
	litmus := wd.litmus
	db := wd.db
	api := wd.api
	wd.cfgMu.RUnlock()

	now := time.Now()

	if db != nil {
		// In-memory counters: no query, no timeout needed, and safe to observe
		// before the load session is configured.
		ls := db.LookupStats()
		lookup := func(key string, served, loaded uint64) {
			observer.ObserveInt64(in.lookupReqs, clampCount(served),
				metric.WithAttributes(attribute.String("key", key), attribute.String("source", "pool")))
			observer.ObserveInt64(in.lookupReqs, clampCount(loaded),
				metric.WithAttributes(attribute.String("key", key), attribute.String("source", "database")))
		}
		lookup("sha256", ls.SHAServed, ls.SHALoaded)
		lookup("purl", ls.PURLServed, ls.PURLLoaded)
		observer.ObserveInt64(in.lookupEntries, int64(ls.Entries))
		observer.ObserveInt64(in.lookupCapacity, int64(ls.Capacity))

		cctx, cancel := context.WithTimeout(ctx, metricsCollectTimeout)
		defer cancel()

		if n, err := db.PopularPackageCount(cctx); err == nil {
			observer.ObserveInt64(in.popularPackages, int64(n))
		}
		observer.ObserveInt64(in.pending, wd.pendingCount(cctx))
		observer.ObserveInt64(in.rescan, wd.rescanPending(cctx))

		rates := wd.analysisRates(cctx)
		observer.ObserveFloat64(in.analysisRate, float64(rates.TopLevel)/analysisRateWindow.Seconds(),
			metric.WithAttributes(attribute.String("tier", "toplevel")))
		observer.ObserveFloat64(in.analysisRate, float64(rates.Rescans)/analysisRateWindow.Seconds(),
			metric.WithAttributes(attribute.String("tier", "rescan")))

		if h, ok := wd.workflowHealth(cctx); ok {
			observer.ObserveInt64(in.cleavePending, h.PendingCleave)
			observer.ObserveInt64(in.litmusPending, h.PendingLitmus)
			observeAge(observer, in.addedAge, now, h.LatestAdded)
			observeAge(observer, in.analyzedAge, now, h.LatestAnalyzed)
			if !h.LatestAdded.IsZero() && !h.LatestReady.IsZero() {
				observer.ObserveFloat64(in.readyLag, max(h.LatestAdded.Sub(h.LatestReady).Seconds(), 0))
			}
		}
	}

	if progress != nil {
		observer.ObserveInt64(in.analyzed, progress.analyzed.Load())
		observer.ObserveInt64(in.walked, progress.walked.Load())
		observer.ObserveInt64(in.inserted, progress.inserted.Load())
		observer.ObserveInt64(in.cacheHits, progress.cacheHits.Load())
		observer.ObserveInt64(in.filtered, progress.tooSmall.Load()+progress.tooLarge.Load())
		observer.ObserveInt64(in.errors, progress.errors.Load())
		for c := range numInsertFailCauses {
			observer.ObserveInt64(in.insertFails, progress.insertFails[c].Load(),
				metric.WithAttributes(attribute.String("cause", c.String())))
		}
	}

	combined, _ := wd.ratesOver(15 * time.Minute)
	observer.ObserveFloat64(in.filesRate, combined)

	if tracker != nil {
		workers := tracker.all()
		for i := range workers {
			ws := &workers[i]
			attr := metric.WithAttributes(attribute.String("worker", ws.Name))
			observer.ObserveFloat64(in.wLastSeen, now.Sub(ws.LastSeen).Seconds(), attr)
			observer.ObserveFloat64(in.wLoad, ws.Load1, attr)
			observer.ObserveFloat64(in.wFilesRate, ws.FilesPerSec, attr)
			observer.ObserveInt64(in.wActive, int64(ws.ActiveClaims), attr)
			observer.ObserveInt64(in.wSlots, int64(ws.Slots), attr)
			observer.ObserveInt64(in.wQueue, int64(ws.Queue), attr)
			observer.ObserveInt64(in.wRSS, int64(ws.RSSMB)<<20, attr)
			observer.ObserveInt64(in.wAnalyzed, ws.Analyzed, attr)
			observer.ObserveInt64(in.wClaimed, ws.TotalClaimed, attr)
			observer.ObserveInt64(in.wReleased, ws.Released, attr)
			observer.ObserveInt64(in.wErrors, ws.Errors, attr)
			observer.ObserveInt64(in.wErrorsRecent, int64(ws.ErrorsRecent), attr)
			observer.ObserveInt64(in.wInfo, 1, metric.WithAttributes(
				attribute.String("worker", ws.Name),
				attribute.String("version", cmp.Or(ws.Version, "unknown"))))
		}
	}

	if litmus != nil {
		var up int64
		if h := litmus.healthSnapshot(); h != nil && h.ok {
			up = 1
		}
		observer.ObserveInt64(in.localUp, up)
		observer.ObserveInt64(in.localRestarts, litmus.restarts.Load())
		if pid := litmus.currentPID(); pid > 0 {
			if mem, err := procMemoryBytes(pid); err == nil {
				observer.ObserveInt64(in.localMem, int64(mem)) //nolint:gosec // /proc memory values are far below int64 range
			}
		}
		if litmus.maxRSSGB > 0 {
			observer.ObserveInt64(in.localMemBudget, int64(litmus.maxRSSGB)<<30)
		}
	}

	// len/cap of the buffered semaphores: a non-blocking read of in-flight
	// work and the configured ceiling. nil when the cap is disabled.
	if api != nil && api.extractSem != nil {
		observer.ObserveInt64(in.extractInUse, int64(len(api.extractSem)))
		observer.ObserveInt64(in.extractMax, int64(cap(api.extractSem)))
	}
	if api != nil && api.resultSem != nil {
		observer.ObserveInt64(in.resultInUse, int64(len(api.resultSem)))
		observer.ObserveInt64(in.resultMax, int64(cap(api.resultSem)))
	}
}

// observeAge records the seconds elapsed since t, skipping a zero timestamp so
// "never happened" reads as an absent series rather than a misleading epoch age.
func observeAge(observer metric.Observer, g metric.Float64Observable, now, t time.Time) {
	if t.IsZero() {
		return
	}
	observer.ObserveFloat64(g, max(now.Sub(t).Seconds(), 0))
}

// dbRetryCount counts retry attempts inside retryDBAccess, keyed by the
// operation and the classified cause. It exists because retried contention was
// invisible: retryDBAccess logs each attempt and then, having eventually
// succeeded, returns normally — so a result store that burned six lock_timeout
// retries and thirty seconds of a worker's throughput emitted no metric at all.
// hopper.insert.failures.total does not cover it either; that counter is fed
// only from the walk flush, so every lock timeout on the /api/result member
// upsert (the path that actually stalls the fleet) went unrecorded.
//
// The "cause" attribute reuses classifyInsertFailure's vocabulary rather than
// the raw SQLSTATE: the label set is already bounded and already understood on
// the insert-failure panel, so the two metrics read in the same terms and a
// lock_timeout means the same thing on both. "op" is one of a handful of string
// literals at the call sites, so the pair stays low-cardinality.
var (
	dbRetryOnce  sync.Once
	dbRetryCount metric.Int64Counter
)

// recordDBRetry increments the retry counter for one attempt. Created lazily on
// first use like recordLoadShed, and a creation failure leaves it nil for a
// silent no-op. ctx carries the calling span so the metric links back.
func recordDBRetry(ctx context.Context, op string, cause insertFailCause) {
	dbRetryOnce.Do(func() { dbRetryCount = newDBRetryCounter(otel.Meter(meterName)) })
	if dbRetryCount != nil {
		dbRetryCount.Add(ctx, 1, metric.WithAttributes(
			attribute.String("op", op),
			attribute.String("cause", cause.String()),
		))
	}
}

// newDBRetryCounter builds the retry counter on meter, returning nil if the
// instrument cannot be created (recordDBRetry then degrades to a no-op). Split
// out for the same reason registerMetrics takes a meter: a test can bind the
// counter to its own provider and registry, so pinning the exported name does
// not require installing a global meter provider — which would retroactively
// attach every other instrument the suite created to that registry.
func newDBRetryCounter(m metric.Meter) metric.Int64Counter {
	c, err := m.Int64Counter(
		"hopper.db.retries.total",
		metric.WithDescription("Database operations retried inside retryDBAccess, by operation and cause."),
	)
	if err != nil {
		return nil
	}
	return c
}
