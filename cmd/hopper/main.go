// Package main is the hopper CLI for managing the sample registry.
package main

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"log/slog"
	"math"
	"net/url"
	"os"
	"os/exec"
	"os/signal"
	"path/filepath"
	"runtime"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"codeberg.org/atomdrift/hopper"
)

const usageText = `usage: hopper <command>

commands:
  serve              start a local postgres server with hopper schema
  init               create/migrate a hopper database (sqlite or postgres)
  load               load sample files from directories
  reset              delete all samples and reports (preserves schema)
  import             transfer samples between hopper databases (sqlite↔postgres)
  false-positives    list known-good files that still score bad
  false-negatives    list known-bad files that still score benign
  benign-review      list marker-benign files cleave still flags as suspicious
  bad-review         list marker-bad files cleave still considers benign
  backfill           re-derive columns from cleave_result/litmus_result blobs
  purge-unsupported  delete analyzed rows cleave could not classify
  stats              show sample counts
`

func writeStderrf(format string, args ...any) {
	if _, err := fmt.Fprintf(os.Stderr, format, args...); err != nil {
		slog.Debug("stderr write failed", "error", err)
	}
}

func writeStdoutf(format string, args ...any) {
	if _, err := fmt.Printf(format, args...); err != nil {
		slog.Debug("stdout write failed", "error", err)
	}
}

func writeStdout(s string) {
	if _, err := fmt.Print(s); err != nil {
		slog.Debug("stdout write failed", "error", err)
	}
}

func writeStdoutLine(s string) {
	if _, err := fmt.Println(s); err != nil {
		slog.Debug("stdout write failed", "error", err)
	}
}

func parseFlags(f *flag.FlagSet, args []string) {
	if err := f.Parse(args); err != nil {
		panic(err)
	}
}

func closeFileBestEffort(name string, f *os.File) {
	if f == nil {
		return
	}
	if err := f.Close(); err != nil {
		slog.Warn("close file failed", "path", name, "error", err)
	}
}

func mkdirAllBestEffort(path string, perm os.FileMode) {
	if err := os.MkdirAll(path, perm); err != nil {
		slog.Warn("mkdir failed", "path", path, "error", err)
	}
}

func killProcessBestEffort(reason string, proc *os.Process) {
	if proc == nil {
		return
	}
	if err := proc.Kill(); err != nil {
		slog.Warn(reason, "error", err)
	}
}

func waitCmdBestEffort(reason string, cmd *exec.Cmd) {
	if cmd == nil {
		return
	}
	if err := cmd.Wait(); err != nil {
		slog.Debug(reason, "error", err)
	}
}

func main() {
	if len(os.Args) < 2 {
		writeStderrf("%s", usageText)
		os.Exit(1)
	}

	cleanup, err := setupLogging()
	if err != nil {
		writeStderrf("failed to setup logging: %v\n", err)
	}

	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt)
	err = run(ctx)
	stop()
	if cleanup != nil {
		cleanup()
	}
	if err != nil {
		slog.Error(err.Error())
		os.Exit(1)
	}
}

func run(ctx context.Context) error {
	switch os.Args[1] {
	case "serve":
		return cmdServe(ctx)
	case "init":
		return cmdInit(ctx)
	case "import":
		return cmdImport(ctx)
	case "load":
		return cmdLoad(ctx)
	case "reset":
		return cmdReset(ctx)
	case "false-positives":
		return cmdFalsePositives(ctx)
	case "false-negatives":
		return cmdFalseNegatives(ctx)
	case "benign-review":
		return cmdBenignReview(ctx)
	case "bad-review":
		return cmdBadReview(ctx)
	case "backfill":
		return cmdBackfill(ctx)
	case "purge-unsupported":
		return cmdPurgeUnsupported(ctx)
	case "stats":
		return cmdStats(ctx)
	default:
		writeStderrf("%s", usageText)
		return errors.New("unknown command: " + os.Args[1])
	}
}

func xdgLogDir() string {
	switch runtime.GOOS {
	case "darwin":
		if home, err := os.UserHomeDir(); err == nil {
			return filepath.Join(home, "Library", "Logs", "hopper")
		}
	case "windows":
		if appdata := os.Getenv("LOCALAPPDATA"); appdata != "" {
			return filepath.Join(appdata, "hopper", "Logs")
		}
	default:
	}
	// Default to XDG_STATE_HOME on Linux/Unix.
	if s := os.Getenv("XDG_STATE_HOME"); s != "" {
		return filepath.Join(s, "hopper")
	}
	if home, err := os.UserHomeDir(); err == nil {
		return filepath.Join(home, ".local", "state", "hopper")
	}
	return ".hopper" // Fallback
}

func setupLogging() (func(), error) {
	dir := xdgLogDir()
	if err := os.MkdirAll(dir, 0o750); err != nil {
		return nil, err
	}

	logPath := filepath.Join(dir, "hopper.log")
	f, err := os.OpenFile(logPath, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0o600)
	if err != nil {
		return nil, err
	}

	// Use a handler that writes to both stderr and the log file.
	opts := &slog.HandlerOptions{Level: slog.LevelInfo}
	h := &multiHandler{
		h1: slog.NewTextHandler(os.Stderr, opts),
		h2: slog.NewJSONHandler(f, opts),
	}
	slog.SetDefault(slog.New(h))

	return func() { closeFileBestEffort(logPath, f) }, nil
}

type multiHandler struct {
	h1, h2 slog.Handler
}

func (m *multiHandler) Enabled(ctx context.Context, l slog.Level) bool {
	return m.h1.Enabled(ctx, l) || m.h2.Enabled(ctx, l)
}

func (m *multiHandler) Handle(ctx context.Context, r slog.Record) error { //nolint:gocritic // matches slog.Handler interface
	err1 := m.h1.Handle(ctx, r)
	err2 := m.h2.Handle(ctx, r)
	if err1 != nil {
		return err1
	}
	return err2
}

func (m *multiHandler) WithAttrs(attrs []slog.Attr) slog.Handler {
	return &multiHandler{h1: m.h1.WithAttrs(attrs), h2: m.h2.WithAttrs(attrs)}
}

func (m *multiHandler) WithGroup(name string) slog.Handler {
	return &multiHandler{h1: m.h1.WithGroup(name), h2: m.h2.WithGroup(name)}
}

// redactDSN strips the password from a DSN for safe logging.
func redactDSN(dsn string) string {
	u, err := url.Parse(dsn)
	if err != nil {
		return dsn
	}
	return u.Redacted()
}

func openDB(ctx context.Context, dsn string) (*hopper.DB, error) {
	if dsn == "" {
		dsn = os.Getenv("DATABASE_URL")
	}
	if dsn == "" {
		dsn = "postgres://hopper@hopper:5432/hopper"
	}
	slog.Info("connecting to database", "dsn", redactDSN(dsn)) //nolint:gosec // dsn is redacted before logging
	return hopper.Open(ctx, dsn)
}

func cmdServe(ctx context.Context) error {
	home, err := os.UserHomeDir()
	if err != nil {
		home = "."
	}

	f := flag.NewFlagSet("serve", flag.ExitOnError)
	dir := f.String("dir", filepath.Join(home, ".hopper"), "data directory")
	port := f.Int("port", 5433, "listen port")
	parseFlags(f, os.Args[2:])

	pgdata := filepath.Join(*dir, "pgdata")
	p := strconv.Itoa(*port)

	// Initialize data directory if needed.
	if _, err := os.Stat(filepath.Join(pgdata, "PG_VERSION")); err != nil {
		slog.Info("initializing postgres")
		out, err := exec.CommandContext(ctx, "initdb",
			"-D", pgdata,
			"--auth=trust",
			"--no-locale",
			"-E", "UTF8",
		).CombinedOutput()
		if err != nil {
			return fmt.Errorf("initdb: %w\n%s", err, out)
		}
	}

	// Start postgres in foreground. Ctrl-c sends SIGINT to the process
	// group, which postgres handles as a graceful shutdown.
	pg := exec.CommandContext(ctx, "postgres", "-D", pgdata, "-p", p)
	pg.Stdout = os.Stdout
	pg.Stderr = os.Stderr
	if err := pg.Start(); err != nil {
		return fmt.Errorf("start postgres: %w", err)
	}

	// Wait for readiness.
	ready := false
	for range 30 {
		if exec.CommandContext(ctx, "pg_isready", "-p", p, "-h", "localhost", "-q").Run() == nil {
			ready = true
			break
		}
		time.Sleep(500 * time.Millisecond)
	}
	if !ready {
		killProcessBestEffort("failed to kill postgres after readiness timeout", pg.Process)
		return errors.New("postgres did not become ready within 15s")
	}

	// Create database (ignore "already exists" error).
	createdb := exec.CommandContext(ctx, "createdb", "-p", p, "-h", "localhost", "hopper")
	if err := createdb.Run(); err != nil {
		slog.Debug("createdb returned non-fatal error", "error", err)
	}

	// Run migrations.
	dsn := fmt.Sprintf("postgres://localhost:%s/hopper", p)
	db, err := hopper.Open(ctx, dsn)
	if err != nil {
		return fmt.Errorf("connect: %w", err)
	}
	if err := db.Migrate(ctx); err != nil {
		db.Close()
		return fmt.Errorf("migrate: %w", err)
	}
	db.Close()

	slog.Info("hopper ready", "dsn", dsn)

	waitCmdBestEffort("postgres exited", pg)
	return nil
}

func cmdInit(ctx context.Context) error {
	f := flag.NewFlagSet("init", flag.ExitOnError)
	dsn := f.String("db", "", "database (postgres:// DSN or sqlite file path)")
	parseFlags(f, os.Args[2:])

	db, err := openDB(ctx, *dsn)
	if err != nil {
		return err
	}
	defer db.Close()
	if err := db.Migrate(ctx); err != nil {
		return err
	}
	slog.Info("schema up to date")
	return nil
}

func cmdImport(ctx context.Context) error {
	f := flag.NewFlagSet("import", flag.ExitOnError)
	dstDSN := f.String("db", "", "destination database")
	srcDSN := f.String("from", "", "source database")
	afterSample := f.Int64("after", 0, "resume after this source sample ID (from progress logs)")
	afterReport := f.Int64("after-report", 0, "resume after this source report ID (from progress logs)")
	parseFlags(f, os.Args[2:])

	if *srcDSN == "" {
		return errors.New("pass --from (source database)")
	}

	dst, err := openDB(ctx, *dstDSN)
	if err != nil {
		return err
	}
	defer dst.Close()
	slog.Info("running schema migrations on destination")
	if err := dst.Migrate(ctx); err != nil {
		return err
	}

	slog.Info("opening source database", "dsn", *srcDSN)
	src, err := hopper.Open(ctx, *srcDSN)
	if err != nil {
		return fmt.Errorf("open source: %w", err)
	}
	defer src.Close()

	slog.Info("starting transfer", "resume_after_sample", *afterSample, "resume_after_report", *afterReport)
	samples, reports, err := hopper.TransferSamples(ctx, dst, src, *afterSample, *afterReport)
	if err != nil {
		return err
	}
	slog.Info("transfer complete", "samples", samples, "reports", reports)
	return nil
}

func cmdReset(ctx context.Context) error {
	f := flag.NewFlagSet("reset", flag.ExitOnError)
	dsn := f.String("db", "", "database (postgres:// DSN or sqlite file path)")
	parseFlags(f, os.Args[2:])

	db, err := openDB(ctx, *dsn)
	if err != nil {
		return err
	}
	defer db.Close()

	slog.Info("deleting all samples and reports")
	if err := db.DeleteAll(ctx); err != nil {
		return err
	}
	slog.Info("reset complete")
	return nil
}

func cmdLoad(ctx context.Context) error {
	f := flag.NewFlagSet("load", flag.ExitOnError)
	dsn := f.String("db", "", "database connection string")
	dataDir := f.String("data", "", "data directory containing bad/, good/, unknown/ subdirectories")
	source := f.String("source", "harvest", "sample source tag")
	workers := f.Int("workers", 8, "concurrent hash/insert workers")
	cleaveBinFlag := f.String("cleave", "cleave", "path to cleave binary (used for file enumeration)")
	litmusBin := f.String("litmus", "litmus", "path to litmus binary (pass empty to disable)")
	litmusWorkers := f.Int("litmus-workers", 0, "concurrent litmus analysis workers for the local node (0 = auto: max(1, NumCPU/2))")
	litmusNodes := f.String("litmus-nodes", "", "comma-separated host[:port] of additional remote litmus servers (default port "+defaultRemoteLitmusPort+")")
	noRulesUpdate := f.Bool("no-rules-update", false, "skip POST /_/update on each litmus node at startup")
	maxRSSGB := f.Int("max-memory-gb", 0, "litmus RSS limit in GB (0 = auto: min(50% RAM, 32 GiB))")
	analysisTimeout := f.Int("analysis-timeout", 1200, "per-file analysis timeout in seconds (passed to litmus)")
	rescan := f.Bool("rescan", false, "re-analyze samples that already have litmus results")
	noCache := f.Bool("no-cache", false, "disable hash cache (re-read every file)")
	maxAnalyzed := f.Int("max-analyzed", 0, "stop after N successful analyses (0 = unlimited)")
	experimentTag := f.String("experiment-tag", "", "label for experiment comparison")
	litmusVerbose := f.Bool("litmus-verbose", false, "enable debug logging in litmus server")
	dashAddr := f.String("dashboard-addr", "0.0.0.0:8081", "web dashboard listen address (empty to disable)")
	maxFileMB := f.Int64("max-file-size", defaultMaxFileSize/(1024*1024), "skip files larger than this many MiB")
	parseFlags(f, os.Args[2:])

	if *maxFileMB > 0 {
		maxFileSize = *maxFileMB * 1024 * 1024
	}

	if *dataDir == "" {
		return errors.New("pass --data <directory> (expects bad/, good/, unknown/ subdirectories)")
	}

	cleaveBinary = *cleaveBinFlag

	// Rebuild cleave from ../cleave (same policy as litmus) before we start
	// shelling out to `cleave iter-files`. Harmless if the source tree isn't
	// present; logs and proceeds with whatever is on $PATH.
	updateCleave(ctx)

	// Discover label directories under --data.
	// Convention: bad/ → label "bad", good/ → label "good", unknown/ → label "unknown".
	var loadDirs []struct{ dir, label string }
	for _, entry := range []struct{ name, label string }{
		{"bad", "bad"},
		{"good", "good"},
		{"unknown", "unknown"},
	} {
		dir := filepath.Join(*dataDir, entry.name)
		if info, err := os.Stat(dir); err == nil && info.IsDir() {
			loadDirs = append(loadDirs, struct{ dir, label string }{dir, entry.label})
		}
	}
	if len(loadDirs) == 0 {
		return fmt.Errorf("no bad/, good/, or unknown/ subdirectories found in %s", *dataDir)
	}

	// Open hash cache (default: ~/.hopper/hashcache.db).
	var cache *hashCache
	if !*noCache {
		home, err := os.UserHomeDir()
		if err != nil {
			home = "."
		}
		cacheDir := filepath.Join(home, ".hopper")
		mkdirAllBestEffort(cacheDir, 0o755)
		cache, err = openHashCache(ctx, filepath.Join(cacheDir, "hashcache.db"))
		if err != nil {
			slog.Warn("hash cache unavailable, continuing without cache", "error", err)
		} else {
			defer cache.close(ctx)
		}
	}

	var dirNames []string
	for _, d := range loadDirs {
		dirNames = append(dirNames, d.label)
	}
	slog.Info("load starting",
		"data", *dataDir,
		"labels", dirNames,
		"workers", *workers,
		"rescan", *rescan,
		"cache", cache != nil,
		"max_analyzed", *maxAnalyzed,
		"experiment", *experimentTag)
	db, err := openDB(ctx, *dsn)
	if err != nil {
		return err
	}
	defer db.Close()
	slog.Info("running schema migrations")
	if err := db.Migrate(ctx); err != nil {
		return err
	}

	// Collect directories for litmus's --allowed-dirs.
	var dirs []string
	for _, d := range loadDirs {
		if abs, err := filepath.Abs(d.dir); err == nil {
			dirs = append(dirs, abs)
		}
	}

	// Start litmus server if requested.
	var litmus *litmusServer
	if *litmusBin != "" {
		litmus = newLitmusServer(litmusConfig{
			Bin:         *litmusBin,
			Dirs:        dirs,
			MaxRSSGB:    *maxRSSGB,
			MaxWorkers:  *litmusWorkers,
			TimeoutSecs: *analysisTimeout,
			Verbose:     *litmusVerbose,
		})
		if err := litmus.Start(ctx); err != nil {
			return err
		}
		defer litmus.Stop()
		go func() {
			if err := litmus.Monitor(ctx); err != nil {
				slog.Error("litmus monitor failed", "error", err)
			}
		}()
		go litmus.WatchHealth(ctx)
	}

	// Build the analyzer pool: local litmus (if enabled) plus any remote
	// litmus servers passed via --litmus-nodes. Remote nodes that fail to
	// dial are logged and skipped, never fatal.
	var nodes []analyzer
	if litmus != nil {
		nodes = append(nodes, litmus)
	}
	if remoteAddrs := parseLitmusNodes(*litmusNodes); len(remoteAddrs) > 0 {
		for _, r := range dialAllRemoteLitmus(ctx, remoteAddrs) {
			nodes = append(nodes, r)
		}
	}
	if len(nodes) > 0 {
		totalSlots := 0
		nodeNames := make([]string, 0, len(nodes))
		for _, n := range nodes {
			totalSlots += n.Slots()
			nodeNames = append(nodeNames, fmt.Sprintf("%s(%d)", n.Name(), n.Slots()))
		}
		slog.Info("analysis pool ready",
			"nodes", len(nodes),
			"total_slots", totalSlots,
			"detail", strings.Join(nodeNames, ","))

		// Best-effort: ask every litmus node to refresh its models + traits
		// data files, then compare versions across the pool. Both phases
		// are non-fatal — a failed update or unreachable /_/info logs a
		// warning and the load proceeds. The version-mismatch check ALWAYS
		// runs (even with --no-rules-update) so the operator gets a loud
		// signal if a node is running stale code or stale rules.
		if !*noRulesUpdate {
			updateAllNodes(ctx, nodes)
		} else {
			slog.Info("skipping rules/model update (--no-rules-update)")
		}
		warnVersionMismatch(fetchAllNodeInfo(ctx, nodes))
	}

	var shared loadProgress
	shared.analyzeDurationMin.Store(math.MaxInt64)

	loadCtx, loadCancel := context.WithCancel(ctx)
	defer loadCancel()

	total := loadAll(loadCtx, loadCancel, db, litmus, nodes, cache, loadDirs, *source, *workers, *rescan, *maxAnalyzed, *experimentTag, *dashAddr, &shared)
	slog.Info("load complete", "samples", total)
	return nil
}

// loadJob is a file to be loaded and optionally analyzed.
type loadJob struct {
	path string
	sha  string // set after hashing
}

// loadProgress tracks counters across concurrent load workers.
type loadProgress struct { //nolint:govet // counters are grouped by pipeline stage for maintenance.
	walked     atomic.Int64
	hashed     atomic.Int64
	inserted   atomic.Int64
	skipped    atomic.Int64
	analyzed   atomic.Int64
	markers    atomic.Int64 // files skipped due to misclassification markers
	tooSmall   atomic.Int64 // files below minFileSize
	tooLarge   atomic.Int64 // files above maxFileSize
	errors     atomic.Int64
	hashErrors atomic.Int64 // hash failures (subset of errors, for % calc)
	cacheHits  atomic.Int64
	exploded   atomic.Int64 // archive members inserted
	queued     atomic.Int64 // items sent for analysis

	lastErr atomic.Value // string

	// Per-analysis timing (nanoseconds).
	analyzeDurationSum atomic.Int64
	analyzeDurationMax atomic.Int64
	analyzeDurationMin atomic.Int64 // initialized to math.MaxInt64
	scoreSum           atomic.Int64
}

const (
	loadBatchSize      = 500
	minFileSize        = 13                // skip trivially small files (markers, empty, etc.)
	defaultMaxFileSize = 100 * 1024 * 1024 // 100 MiB
)

// maxFileSize is the per-file byte cap applied during enumeration, hashing,
// and analysis. Overridable via the load command's --max-file-size flag.
var maxFileSize int64 = defaultMaxFileSize

var (
	errTooSmall = errors.New("too small")
	errTooLarge = errors.New("too large")
)

// loadAll orchestrates a load: analysis workers, a progress dashboard, and
// one per-directory pipeline goroutine that owns cleave→hash→batch→insert
// for its directory and queues analysis jobs directly. Everything waits on
// the directory pipelines; then the analysis queue is closed and drained;
// then the summary is logged. nworkers bounds how many directory pipelines
// may run concurrently (irrelevant for typical 3-dir loads).
//
//nolint:revive // signature matches the pipeline's top-level orchestration contract.
func loadAll(ctx context.Context, cancel context.CancelFunc, db *hopper.DB, litmus *litmusServer, nodes []analyzer, cache *hashCache, dirs []struct{ dir, label string }, source string, nworkers int, rescan bool, maxAnalyzed int, experimentTag, dashAddr string, shared *loadProgress) int {
	slog.Info("loading", "dirs", len(dirs))
	start := time.Now()
	var progress loadProgress
	progress.analyzeDurationMin.Store(math.MaxInt64)

	// Initialize already-analyzed count so the dashboard can subtract it
	// off to show session-relative numbers (a user running with
	// --max-analyzed=50 wants "N of 50 this session", not "39785 of 50").
	var startAnalyzed int64
	if n, err := db.CountAnalyzed(ctx); err == nil {
		progress.analyzed.Store(n)
		progress.queued.Store(n)
		startAnalyzed = n
	}

	// Analysis pool: a large buffered queue absorbs bursts from the
	// per-directory inserters so slow litmus analysis doesn't back up
	// into the DB insert path. One slot goroutine per node-slot is
	// spawned over this queue.
	var analyzeQueue chan loadJob
	var analyzeWG sync.WaitGroup
	var monitors []*nodeMonitor
	if len(nodes) > 0 {
		analyzeQueue = make(chan loadJob, 2_000_000)
		// Per-node /_/health pollers feed the dashboard's pool block.
		// Created before workers so monitors can be wired for per-node counters.
		monitors = startNodeMonitors(ctx, nodes)
		startAnalysisWorkers(ctx, cancel, db, nodes, analyzeQueue, &analyzeWG, &progress, shared, maxAnalyzed, monitors)
	}

	// Progress dashboard: reads counters, exits when dashCtx is cancelled.
	dashCtx, dashCancel := context.WithCancel(ctx)
	defer dashCancel()
	var dashWG sync.WaitGroup
	dashWG.Go(func() {
		runDashboard(dashCtx, &progress, litmus, monitors, start, startAnalyzed, maxAnalyzed, len(dirs))
	})

	if dashAddr != "" {
		wd := &webDashboard{
			progress:      &progress,
			litmus:        litmus,
			monitors:      monitors,
			start:         start,
			startAnalyzed: startAnalyzed,
			maxAnalyzed:   maxAnalyzed,
			ndirs:         len(dirs),
		}
		if err := startWebDashboard(dashCtx, dashAddr, wd); err != nil {
			slog.Warn("web dashboard disabled", "error", err)
		} else {
			slog.Info("web dashboard listening", "addr", dashAddr)
		}
	}

	// Per-directory pipelines: each goroutine runs cleave→hash→batch→
	// insert→queue end-to-end for its labeled directory. A semaphore
	// bounds concurrency to nworkers (usually larger than len(dirs), so
	// all dirs run simultaneously).
	sem := make(chan struct{}, max(1, nworkers))
	var pipeWG sync.WaitGroup
	for _, d := range dirs {
		pipeWG.Go(func() {
			select {
			case sem <- struct{}{}:
				defer func() { <-sem }()
			case <-ctx.Done():
				return
			}
			runDirPipeline(ctx, db, d, source, cache, &progress, analyzeQueue, rescan)
		})
	}
	pipeWG.Wait()

	// Ingest is done; drain analysis.
	if analyzeQueue != nil {
		close(analyzeQueue)
		analyzeWG.Wait()
	}

	dashCancel()
	dashWG.Wait()

	logLoadSummary(start, experimentTag, dirs, &progress)
	return int(progress.inserted.Load() + progress.skipped.Load())
}

// runDirPipeline is the entire load pipeline for one labeled directory:
// enumerate via cleave, hash each file (respecting the cache and marker
// conventions), batch into the samples table, and queue the rows that need
// analysis. Everything runs sequentially in this one goroutine so batches
// stay coherent without cross-goroutine plumbing; parallelism comes from
// running one instance per directory.
func runDirPipeline(
	ctx context.Context,
	db *hopper.DB,
	target struct{ dir, label string },
	source string,
	cache *hashCache,
	progress *loadProgress,
	analyzeQueue chan<- loadJob,
	rescan bool,
) {
	batch := make([]*hopper.Sample, 0, loadBatchSize)
	pathBySha := make(map[string]string, loadBatchSize)

	flush := func() {
		if len(batch) == 0 {
			return
		}
		n, needsAnalysis, err := db.InsertSampleBatch(ctx, batch)
		if err != nil {
			if ctx.Err() == nil {
				progress.errors.Add(int64(len(batch)))
				progress.lastErr.Store(fmt.Sprintf("insert: %v", err))
				slog.Error("batch insert failed", "error", err, "batch_size", len(batch), "dir", target.dir)
			}
			batch = batch[:0]
			clear(pathBySha)
			return
		}
		progress.inserted.Add(n)
		progress.skipped.Add(int64(len(batch)) - n)

		if analyzeQueue != nil {
			needs := make(map[string]struct{}, len(needsAnalysis))
			for _, sha := range needsAnalysis {
				needs[sha] = struct{}{}
			}
			for _, s := range batch {
				if !rescan {
					if _, ok := needs[s.SHA256]; !ok {
						continue
					}
				}
				select {
				case analyzeQueue <- loadJob{path: pathBySha[s.SHA256], sha: s.SHA256}:
					progress.queued.Add(1)
				case <-ctx.Done():
					return
				}
			}
		}
		batch = batch[:0]
		clear(pathBySha)
	}
	defer flush()

	slog.Info("listing files", "dir", target.dir, "label", target.label)
	err := pathLister(ctx, target.dir, func(lp labeledPath) bool {
		if ctx.Err() != nil {
			return false
		}
		if isMarkerFile(filepath.Base(lp.path)) {
			return true
		}
		lp.label = target.label
		progress.walked.Add(1)

		sample, err := hashFile(ctx, lp.path, lp.label, lp.fileType, source, cache, progress)
		if err != nil {
			switch {
			case errors.Is(err, errTooSmall):
				progress.tooSmall.Add(1)
			case errors.Is(err, errTooLarge):
				progress.tooLarge.Add(1)
			default:
				progress.errors.Add(1)
				progress.hashErrors.Add(1)
				progress.lastErr.Store(fmt.Sprintf("hash: %s: %v", filepath.Base(lp.path), err))
				slog.Warn("hash failed", "path", lp.path, "error", err)
			}
			return true
		}

		// Apply misclassification marker if it contradicts the label.
		if marker, markerMtime := markerInfo(lp.path); marker != "" {
			if (lp.label == "bad" && marker == "benign") || (lp.label == "good" && marker == "bad") {
				progress.markers.Add(1)
				if marker == "benign" {
					sample.Label = "good"
				} else {
					sample.Label = "bad"
				}
				sample.LabelSource = "marker"
				sample.Skip = "misclassified"
				sample.MarkerMtime = markerMtime
				slog.Info("misclassified file", "path", lp.path, "original_label", lp.label, "marker", marker)
			}
		}

		progress.hashed.Add(1)
		batch = append(batch, sample)
		pathBySha[sample.SHA256] = lp.path
		if len(batch) >= loadBatchSize {
			flush()
		}
		return true
	})
	if err != nil {
		slog.Warn("list files failed", "dir", target.dir, "error", err)
	}
}

// runDashboard renders the periodic progress view (TTY bars or slog lines)
// until ctx is cancelled. It reads progress counters directly; no
// coordination with workers is required beyond those atomic loads. The pool
// status block is fed by background nodeMonitors so this function never
// blocks on a slow remote.
func runDashboard(
	ctx context.Context,
	progress *loadProgress,
	litmus *litmusServer,
	monitors []*nodeMonitor,
	start time.Time,
	startAnalyzed int64,
	maxAnalyzed, ndirs int,
) {
	interval := 10 * time.Second
	if !isTTY() {
		interval = 30 * time.Second
	}
	ticker := time.NewTicker(interval)
	defer ticker.Stop()

	var prevAnalyzed int64
	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
		}

		analyzedAbs := progress.analyzed.Load()
		sessionAnalyzed := max(analyzedAbs-startAnalyzed, 0)
		recentRate := float64(analyzedAbs-prevAnalyzed) / interval.Seconds()
		prevAnalyzed = analyzedAbs

		walked := progress.walked.Load()
		hashedN := progress.hashed.Load()
		inserted := progress.inserted.Load()
		skipped := progress.skipped.Load()
		hashDone := hashedN + progress.tooSmall.Load() + progress.tooLarge.Load() + progress.hashErrors.Load()

		// Session target: how many new samples we queued for analysis
		// this run, capped at --max-analyzed if set.
		analyzeTarget := max(progress.queued.Load()-startAnalyzed, 0)
		if maxAnalyzed > 0 && int64(maxAnalyzed) < analyzeTarget {
			analyzeTarget = int64(maxAnalyzed)
		}

		if !isTTY() {
			attrs := []any{
				"dirs", ndirs,
				"walked", walked, "hashed", hashedN,
				"inserted", inserted, "skipped", skipped,
				"analyzed", sessionAnalyzed, "errors", progress.errors.Load(),
			}
			if walked > 0 {
				attrs = append(attrs, "hash_pct", fmt.Sprintf("%.0f%%", float64(hashDone)/float64(walked)*100))
			}
			if analyzeTarget > 0 {
				attrs = append(attrs, "analyze_pct", fmt.Sprintf("%.0f%%", float64(sessionAnalyzed)/float64(analyzeTarget)*100))
			}
			slog.Info("load progress", attrs...)
			logPoolStatus(monitors)
			continue
		}

		writeStdout("\033[H\033[2J")
		writeStdoutf("\033[1mHopper Loading Dashboard\033[0m (%s)\n", time.Since(start).Round(time.Second))
		writeStdoutLine(strings.Repeat("─", 60))
		drawBar("Hashing  ", hashDone, walked, "", "\033[34m")
		drawBar("Insertion", inserted+skipped, hashedN, "", "\033[32m")

		var analyzeInfo string
		if recentRate > 0 {
			if remaining := analyzeTarget - sessionAnalyzed; remaining > 0 {
				eta := (time.Duration(float64(remaining)/recentRate) * time.Second).Round(time.Second)
				analyzeInfo = fmt.Sprintf("%.1f/s ETA %s", recentRate, eta)
			}
		}
		drawBar("Analysis ", sessionAnalyzed, analyzeTarget, analyzeInfo, "\033[33m")
		writeStdoutLine(strings.Repeat("─", 60))

		if last, ok := progress.lastErr.Load().(string); ok && last != "" {
			writeStdoutf("\033[31mRecent Error:\033[0m %s\n", last)
			writeStdoutLine(strings.Repeat("─", 60))
		}
		renderPoolBlock(monitors)
		// Local-only diagnostic: which file the slowest local worker is on
		// right now. Remotes don't expose this (no /_/requests poll path).
		if litmus != nil {
			summary := litmus.workerSummary()
			if summary.Busy > 0 && summary.OldestFile != "" {
				writeStdoutf("oldest local: %s (%s)\n",
					summary.OldestFile,
					(time.Duration(summary.OldestMS) * time.Millisecond).Round(time.Second))
			}
		}
		writeStdoutf("Errors: %d | Walked: %d | Cache Hits: %d\n",
			progress.errors.Load(), walked, progress.cacheHits.Load())
	}
}

// renderPoolBlock writes a uniform per-node table for the TTY dashboard.
// Stays at zero allocation in the steady-state by reading each monitor's
// atomic snapshot pointer; never blocks on a slow node.
func renderPoolBlock(monitors []*nodeMonitor) {
	if len(monitors) == 0 {
		return
	}
	totalSlots := 0
	for _, m := range monitors {
		totalSlots += m.Slots()
	}

	// Right-pad node names so the columns line up regardless of address length.
	nameWidth := 4
	for _, m := range monitors {
		if w := len(m.Name()); w > nameWidth {
			nameWidth = w
		}
	}

	writeStdoutLine(strings.Repeat("─", 60))
	writeStdoutf("\033[1mLitmus Pool:\033[0m %d nodes, %d slots\n", len(monitors), totalSlots)
	for _, m := range monitors {
		snap := m.Snapshot()
		name := m.Name()
		slots := m.Slots()
		if snap == nil {
			writeStdoutf("  %-*s  \033[2mpending…\033[0m\n", nameWidth, name)
			continue
		}
		statusColor := poolStatusColor(snap)
		statusLabel := poolStatusLabel(snap)
		uptime := formatUptime(snap.Health.UptimeSecs)

		if !snap.Reachable {
			// Down: show last error inline; suppress stale numbers.
			writeStdoutf("  %-*s  %s%-9s\033[0m  %s\n",
				nameWidth, name, statusColor, statusLabel, truncate(snap.LastErr, 40))
			continue
		}
		// Append the litmus-supplied reason whenever the node isn't a
		// plain "ok" — that's how the operator finds out *why* something
		// is saturated/degraded/failed without having to curl /_/health.
		reason := ""
		if snap.Health.Reason != "" && snap.Health.Status != "ok" {
			reason = "  \033[2m" + snap.Health.Reason + "\033[0m"
		}
		// Surface orphan count and restart count when non-zero.
		extra := ""
		if snap.Health.OrphanedTasks > 0 {
			extra += fmt.Sprintf("  \033[33morphaned:%d\033[0m", snap.Health.OrphanedTasks)
		}
		if snap.Restarts > 0 {
			extra += fmt.Sprintf("  \033[33mrestarts:%d\033[0m", snap.Restarts)
		}
		if snap.TraitsCommit != "" {
			tc := snap.TraitsCommit
			if len(tc) > 8 {
				tc = tc[:8]
			}
			extra += fmt.Sprintf("  traits:%s", tc)
		}
		writeStdoutf("  %-*s  %s%-9s\033[0m  up %-9s  load %.2f  rss %4d MB  %2d/%-d%s%s\n",
			nameWidth, name,
			statusColor, statusLabel,
			uptime,
			snap.Health.Load,
			snap.Health.RSSMB,
			snap.Health.LiveTasks, slots,
			reason,
			extra,
		)
	}
}

// logPoolStatus emits one slog line per node for the non-TTY path. Each line
// is independently greppable; combined with the existing "load progress"
// line, the operator gets the same information as the TTY dashboard.
func logPoolStatus(monitors []*nodeMonitor) {
	for _, m := range monitors {
		snap := m.Snapshot()
		if snap == nil {
			slog.Info("litmus node", "node", m.Name(), "status", "pending")
			continue
		}
		if !snap.Reachable {
			slog.Warn("litmus node",
				"node", m.Name(),
				"status", "down",
				"error", snap.LastErr)
			continue
		}
		attrs := []any{
			"node", m.Name(),
			"status", snap.Health.Status,
			"uptime_secs", snap.Health.UptimeSecs,
			"load", fmt.Sprintf("%.2f", snap.Health.Load),
			"rss_mb", snap.Health.RSSMB,
			"live", snap.Health.LiveTasks,
			"slots", m.Slots(),
		}
		if snap.Health.Reason != "" {
			attrs = append(attrs, "reason", snap.Health.Reason)
		}
		if snap.Health.OrphanedTasks > 0 {
			attrs = append(attrs, "orphaned", snap.Health.OrphanedTasks)
		}
		if snap.Restarts > 0 {
			attrs = append(attrs, "restarts", snap.Restarts)
		}
		slog.Info("litmus node", attrs...)
	}
}

func poolStatusColor(snap *nodeStatusSnapshot) string {
	if !snap.Reachable {
		return "\033[31m" // red
	}
	switch snap.Health.Status {
	case "ok", "saturated":
		// Saturated = all worker slots busy. That's the target steady
		// state under load, not an unhealthy condition, so colour it the
		// same as ok.
		return "\033[32m" // green
	case "starting", "building":
		return "\033[33m" // yellow
	case "degraded", "failed":
		return "\033[33m" // yellow
	default:
		return "\033[37m" // gray for unknown
	}
}

func poolStatusLabel(snap *nodeStatusSnapshot) string {
	if !snap.Reachable {
		return "down"
	}
	if snap.Health.Status == "" {
		return "ok"
	}
	return snap.Health.Status
}

// formatUptime renders seconds as h:mm:ss (or m:ss for short uptimes). Used
// only by the TTY dashboard; the slog path emits raw seconds.
func formatUptime(secs int64) string {
	if secs <= 0 {
		return "—"
	}
	d := time.Duration(secs) * time.Second
	h := int(d / time.Hour)
	m := int((d % time.Hour) / time.Minute)
	s := int((d % time.Minute) / time.Second)
	if h > 0 {
		return fmt.Sprintf("%d:%02d:%02d", h, m, s)
	}
	return fmt.Sprintf("%d:%02d", m, s)
}

func truncate(s string, n int) string {
	if len(s) <= n {
		return s
	}
	if n <= 1 {
		return s[:n]
	}
	return s[:n-1] + "…"
}

// logLoadSummary emits the final "directory complete" line with the
// per-stage counters and analysis timing stats gathered during the load.
func logLoadSummary(start time.Time, experimentTag string, dirs []struct{ dir, label string }, progress *loadProgress) {
	analyzed := progress.analyzed.Load()
	elapsed := time.Since(start)
	attrs := []any{
		"dirs", len(dirs),
		"walked", progress.walked.Load(), "hashed", progress.hashed.Load(),
		"inserted", progress.inserted.Load(),
		"skipped", progress.skipped.Load(), "markers", progress.markers.Load(),
		"too_small", progress.tooSmall.Load(), "too_large", progress.tooLarge.Load(),
		"cache_hits", progress.cacheHits.Load(),
		"analyzed", analyzed,
		"exploded", progress.exploded.Load(),
		"errors", progress.errors.Load(),
		"elapsed", elapsed.Round(time.Millisecond),
	}
	if analyzed > 0 {
		throughput := float64(analyzed) / elapsed.Seconds()
		attrs = append(attrs,
			"avg_score", int(progress.scoreSum.Load()/analyzed),
			"throughput_per_sec", fmt.Sprintf("%.2f", throughput),
			"analyze_avg_ms", progress.analyzeDurationSum.Load()/analyzed/int64(time.Millisecond),
			"analyze_min_ms", progress.analyzeDurationMin.Load()/int64(time.Millisecond),
			"analyze_max_ms", progress.analyzeDurationMax.Load()/int64(time.Millisecond),
		)
	}
	if experimentTag != "" {
		attrs = append(attrs, "experiment", experimentTag)
	}
	slog.Info("directory complete", attrs...)
}

//nolint:revive // config is split across explicit parameters to keep call sites direct.
func startAnalysisWorkers(
	ctx context.Context,
	cancel context.CancelFunc,
	db *hopper.DB,
	nodes []analyzer,
	queue chan loadJob,
	wg *sync.WaitGroup,
	progress *loadProgress,
	shared *loadProgress,
	maxAnalyzed int,
	monitors []*nodeMonitor,
) {
	// Build a name→monitor map so each worker can increment its node's counter.
	monitorByName := make(map[string]*nodeMonitor, len(monitors))
	for _, m := range monitors {
		monitorByName[m.Name()] = m
	}

	// One goroutine per slot per node, all reading from the shared queue.
	// Work-stealing emerges naturally: when a slot finishes (fast or slow),
	// it grabs the next item, so heterogeneous nodes self-balance and the
	// 2-120s analysis-time variance is absorbed without a scheduler.
	workerID := 0
	for _, node := range nodes {
		// Only the local litmusServer wires into the dashboard's per-worker
		// in-flight tracking. Remote nodes have no equivalent today.
		local, _ := node.(*litmusServer)
		mon := monitorByName[node.Name()]
		for range node.Slots() {
			id := workerID
			workerID++
			n := node
			wg.Go(func() {
				for job := range queue {
					if ctx.Err() != nil {
						slog.Debug("analysis worker exiting", "reason", "context cancelled", "node", n.Name())
						return
					}

					file := filepath.Base(job.path)
					if local != nil {
						local.TrackWorker(id, file)
					}
					if mon != nil {
						mon.TrackSlot(id, file)
					}
					t0 := time.Now()
					result, err := analyzeWithRetry(ctx, n, job.sha, job.path)
					if local != nil {
						local.TrackWorker(id, "")
					}
					if mon != nil {
						mon.TrackSlot(id, "")
					}
					dur := time.Since(t0).Nanoseconds()

					if err != nil {
						progress.errors.Add(1)
						progress.lastErr.Store(fmt.Sprintf("analyze: %s: %v", filepath.Base(job.path), err))
						slog.Warn("analysis failed", "node", n.Name(), "path", job.path, "error", err)
						continue
					}

					// Track per-analysis duration.
					progress.analyzeDurationSum.Add(dur)
					shared.analyzeDurationSum.Add(dur)
					for {
						old := progress.analyzeDurationMax.Load()
						if dur <= old || progress.analyzeDurationMax.CompareAndSwap(old, dur) {
							break
						}
					}
					for {
						old := progress.analyzeDurationMin.Load()
						if dur >= old || progress.analyzeDurationMin.CompareAndSwap(old, dur) {
							break
						}
					}

					// Store raw litmus report and classification envelope separately.
					if err := db.UpdateCleaveResult(ctx, job.sha, result.Raw, result.Canonical); err != nil {
						progress.errors.Add(1)
						slog.Warn("storing cleave result failed", "path", job.path, "error", err)
						continue
					}
					if err := db.UpdateLitmusResult(ctx, job.sha, result.ML); err != nil {
						slog.Warn("storing litmus result failed", "path", job.path, "error", err)
					}
					progress.analyzed.Add(1)
					if mon != nil {
						mon.IncrAnalyzed()
					}

					// Check global analysis cap.
					if maxAnalyzed > 0 && shared.analyzed.Add(1) >= int64(maxAnalyzed) {
						slog.Info("max-analyzed reached", "limit", maxAnalyzed)
						cancel()
						return
					}

					// Explode archive members into individual sample rows.
					parent, err := db.SampleBySHA256(ctx, job.sha)
					if err != nil {
						slog.Warn("fetch for explosion failed", "sha256", job.sha, "error", err)
						continue
					}
					totalMembers, err := db.ExplodeArchiveMembers(ctx, parent)
					if err != nil {
						slog.Warn("archive explosion failed", "sha256", job.sha, "error", err)
					} else if totalMembers > 0 {
						slog.Debug("exploded archive members", "sha256", job.sha, "members", totalMembers)
						progress.exploded.Add(totalMembers)
					}
				}
			})
		}
	}
}

// Marker file conventions (shared with cyclotron):
//
//	._<filename>.BENIGN — file is actually benign (overrides --bad label)
//	._<filename>.BAD    — file is actually malicious (overrides --good label)
const (
	markerPrefix = "._"
	markerBenign = ".BENIGN"
	markerBad    = ".BAD"
)

// isMarkerFile returns true if the filename is itself a marker (e.g. ._foo.whl.BENIGN).
func isMarkerFile(name string) bool {
	return strings.HasPrefix(name, markerPrefix) &&
		(strings.HasSuffix(name, markerBenign) || strings.HasSuffix(name, markerBad))
}

// checkMarker looks for a sibling marker file that contradicts the given label.
// Returns "benign" or "bad" if a marker exists, "" otherwise.
func checkMarker(path string) string {
	kind, _ := markerInfo(path)
	return kind
}

func markerInfo(path string) (kind string, mtime *time.Time) {
	dir := filepath.Dir(path)
	base := filepath.Base(path)

	benign := filepath.Join(dir, markerPrefix+base+markerBenign)
	if info, err := os.Stat(benign); err == nil {
		t := info.ModTime()
		return "benign", &t
	}

	bad := filepath.Join(dir, markerPrefix+base+markerBad)
	if info, err := os.Stat(bad); err == nil {
		t := info.ModTime()
		return "bad", &t
	}

	return "", nil
}

// labeledPath is a file path with its classification label and the file type
// reported by cleave. The file type flows into the Sample row so DB queries
// can filter by type without waiting for analysis.
type labeledPath struct {
	path     string
	label    string
	fileType string
}

// pathLister enumerates recognized files under a directory and invokes emit
// for each one as cleave produces it. emit returns false when the caller
// wants to stop (typically because ctx.Done() fired on a blocked send), in
// which case the lister returns early with a nil error. Tests override this
// variable with a pure-Go walker that skips the real cleave binary.
var pathLister = streamCleaveIterFiles

// cleaveBinary is the path (or name, for $PATH lookup) of the cleave binary
// used for file enumeration. Set by the load command's --cleave flag.
var cleaveBinary = "cleave"

// streamCleaveIterFiles invokes `cleave iter-files` against dir and streams
// each decoded record to emit as cleave produces it. This lets the caller
// forward entries into the hash pipeline without buffering a whole
// directory's output first — the reason for the callback shape.
//
// Per-record decode errors stop the scan at the first bad record. A nonzero
// cleave exit caused by context cancellation is surfaced as an error so
// callers can unwind cleanly. A nonzero exit for any other reason degrades
// gracefully: whatever records were already emitted stay emitted, and a
// warn log captures the tail of cleave's stderr for diagnosis.
//
// Cleave's stderr is captured to a buffer and only shown on failure so the
// startup banner doesn't clutter every successful run.
func streamCleaveIterFiles(ctx context.Context, dir string, emit func(labeledPath) bool) error {
	// Hopper's max file size is in bytes; cleave's --max-file-size is in
	// megabytes and is a top-level flag that must precede the subcommand.
	args := make([]string, 0, 4)
	if mb := maxFileSize / (1024 * 1024); mb > 0 {
		args = append(args, "--max-file-size", strconv.FormatInt(mb, 10))
	}
	args = append(args, "iter-files", dir)

	start := time.Now()
	cmd := exec.CommandContext(ctx, cleaveBinary, args...)
	var stderrBuf bytes.Buffer
	cmd.Stderr = &stderrBuf
	stdout, err := cmd.StdoutPipe()
	if err != nil {
		return fmt.Errorf("cleave iter-files stdout pipe: %w", err)
	}
	if err := cmd.Start(); err != nil {
		return fmt.Errorf("cleave iter-files start: %w", err)
	}
	slog.Info("cleave iter-files started", "dir", dir, "pid", cmd.Process.Pid)

	var emitted int
	var stopped bool
	dec := json.NewDecoder(stdout)
	for dec.More() {
		var rec struct {
			Path     string `json:"path"`
			FileType string `json:"type"`
			Sz       int64  `json:"sz"`
		}
		if err := dec.Decode(&rec); err != nil {
			slog.Warn("cleave iter-files decode", "dir", dir, "error", err)
			break
		}
		if !emit(labeledPath{path: rec.Path, fileType: rec.FileType}) {
			stopped = true
			break
		}
		emitted++
	}
	// If the caller asked us to stop, drain stdout so cmd.Wait doesn't
	// block on a full pipe; the CommandContext will kill cleave when the
	// parent context fires, so any read error here is expected.
	if stopped {
		_, _ = io.Copy(io.Discard, stdout) //nolint:errcheck // drained for shutdown, error expected
	}

	if err := cmd.Wait(); err != nil {
		// Context cancellation is an orderly shutdown, not a cleave crash.
		if ctxErr := ctx.Err(); ctxErr != nil {
			return fmt.Errorf("cleave iter-files: %w", ctxErr)
		}
		stderrTail := tailBytes(stderrBuf.Bytes(), 2048)
		if emitted == 0 {
			return fmt.Errorf("cleave iter-files: %w (stderr: %s)", err, stderrTail)
		}
		slog.Warn("cleave iter-files exited with error",
			"dir", dir, "error", err, "emitted", emitted, "stderr", stderrTail)
	}
	slog.Info("cleave iter-files complete",
		"dir", dir, "files", emitted, "elapsed", time.Since(start).Round(time.Millisecond))
	return nil
}

// tailBytes returns the last n bytes of b as a string, or all of b if
// shorter. Used to truncate captured subprocess stderr for log lines.
func tailBytes(b []byte, n int) string {
	if len(b) <= n {
		return string(b)
	}
	return string(b[len(b)-n:])
}

// hashFile opens path, enforces size limits, consults the hash cache, and
// returns a Sample stamped with the cleave-classified file type. Pass "" for
// fileType in contexts that don't yet know it (tests, ad-hoc callers). Pass
// nil for progress when no cache-hit metric is being collected.
func hashFile(ctx context.Context, path, label, fileType, source string, cache *hashCache, progress *loadProgress) (*hopper.Sample, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer f.Close() //nolint:errcheck // read-only file

	info, err := f.Stat()
	if err != nil {
		return nil, err
	}

	if info.Size() < minFileSize {
		return nil, errTooSmall
	}
	if info.Size() >= maxFileSize {
		return nil, errTooLarge
	}

	dev, inode := fileStat(info)

	// Check hash cache before reading file contents.
	if cache != nil {
		if cached, ok := cache.lookup(dev, inode, info.Size(), info.ModTime()); ok {
			if progress != nil {
				progress.cacheHits.Add(1)
			}
			modTime := info.ModTime()
			return &hopper.Sample{
				SHA256:      cached,
				Source:      source,
				Filename:    filepath.Base(path),
				FileType:    fileType,
				Label:       label,
				LabelSource: source,
				SizeBytes:   info.Size(),
				Path:        path,
				Mtime:       &modTime,
			}, nil
		}
	}

	h := sha256.New()
	if _, err := io.Copy(h, f); err != nil {
		return nil, err
	}

	digest := hex.EncodeToString(h.Sum(nil))

	if cache != nil {
		cache.store(ctx, dev, inode, info.Size(), info.ModTime(), digest)
	}

	s := &hopper.Sample{
		SHA256:      digest,
		Source:      source,
		Filename:    filepath.Base(path),
		FileType:    fileType,
		Label:       label,
		LabelSource: source,
		SizeBytes:   info.Size(),
		Path:        path,
		Mtime:       ptrTime(info.ModTime()),
	}
	s.Feed, s.Ecosystem = extractFeedEcosystem(path, label)
	return s, nil
}

func ptrTime(t time.Time) *time.Time { return &t }

// extractFeedEcosystem parses feed and ecosystem from a file path when
// a "harvest" directory component is present.
//
// Known-bad:  .../harvest/<feed>/<ecosystem>/file → feed + ecosystem
//
//	.../harvest/<feed>/file             → feed only
//
// Known-good: .../harvest/<ecosystem>/file        → ecosystem only.
func extractFeedEcosystem(path, label string) (feed, ecosystem string) {
	parts := strings.Split(filepath.ToSlash(path), "/")
	idx := -1
	for i, p := range parts {
		if p == "harvest" {
			idx = i
			break
		}
	}
	if idx < 0 {
		return "", ""
	}
	// Directory components between "harvest" and the filename.
	after := parts[idx+1:]
	if len(after) < 2 {
		return "", "" // need at least one directory + filename
	}
	dirs := after[:len(after)-1]

	switch label {
	case "bad":
		switch len(dirs) {
		case 1:
			return dirs[0], ""
		default:
			return dirs[0], dirs[1]
		}
	default: // "good", "unknown"
		return "", dirs[0]
	}
}

func cmdStats(ctx context.Context) error {
	f := flag.NewFlagSet("stats", flag.ExitOnError)
	dsn := f.String("db", "", "postgres connection string")
	parseFlags(f, os.Args[2:])

	db, err := openDB(ctx, *dsn)
	if err != nil {
		return err
	}
	defer db.Close()

	counts, err := db.CountByLabel(ctx)
	if err != nil {
		return err
	}
	var total int
	for label, n := range counts {
		writeStdoutf("%-10s %d\n", label, n)
		total += n
	}
	writeStdoutf("%-10s %d\n", "total", total)
	return nil
}

func cmdBackfill(ctx context.Context) error {
	f := flag.NewFlagSet("backfill", flag.ExitOnError)
	dsn := f.String("db", "", "database connection string")
	parseFlags(f, os.Args[2:])

	db, err := openDB(ctx, *dsn)
	if err != nil {
		return err
	}
	defer db.Close()

	// Migrate runs the schema migrations (so newly added columns exist)
	// and performs an initial Backfill pass. We then re-invoke Backfill so
	// the CLI can surface fresh stats; the second pass is an idempotent
	// no-op if Migrate already did the work.
	if err := db.Migrate(ctx); err != nil {
		return err
	}
	slog.Info("backfilling derivable columns from cleave_result and litmus_result")
	stats, err := db.Backfill(ctx)
	if err != nil {
		return err
	}
	slog.Info("backfill complete", "scanned", stats.Scanned, "updated", stats.Updated, "markers_cleared", stats.MarkersCleared)
	return nil
}

// cmdPurgeUnsupported deletes samples that were analyzed but cleave could
// not classify — i.e. the file_type column came back empty. Dry-run by
// default: pass --apply to actually delete. Uses the idx_samples_file_type
// index so it's cheap even on multi-million-row tables.
func cmdPurgeUnsupported(ctx context.Context) error {
	f := flag.NewFlagSet("purge-unsupported", flag.ExitOnError)
	dsn := f.String("db", "", "database connection string")
	apply := f.Bool("apply", false, "actually delete rows (default is dry-run)")
	parseFlags(f, os.Args[2:])

	db, err := openDB(ctx, *dsn)
	if err != nil {
		return err
	}
	defer db.Close()

	if !*apply {
		n, err := db.PurgeUnsupported(ctx, true)
		if err != nil {
			return err
		}
		writeStdoutf("would delete %d unsupported row(s) (cleave_result set, file_type empty)\n", n)
		writeStdoutLine("re-run with --apply to actually delete")
		return nil
	}

	slog.Info("purging unsupported rows")
	n, err := db.PurgeUnsupported(ctx, false)
	if err != nil {
		return err
	}
	slog.Info("purge complete", "deleted", n)
	return nil
}

type sampleListFunc func(context.Context, *hopper.DB, int, int) ([]*hopper.Sample, error)

// reviewOpts bundles the flags shared by the review subcommands so their
// setup can return a single value instead of a 5-tuple.
type reviewOpts struct {
	fs    *flag.FlagSet
	dsn   *string
	score *int
	limit *int
	flush *bool
}

func reviewFlags(name string) reviewOpts {
	fs := flag.NewFlagSet(name, flag.ExitOnError)
	score := fs.Int("threshold", 85, "score threshold")
	fs.IntVar(score, "score", 85, "score threshold (deprecated: use --threshold)")
	return reviewOpts{
		fs:    fs,
		dsn:   fs.String("db", "", "database connection string"),
		score: score,
		limit: fs.Int("limit", 100, "maximum rows to print"),
		flush: fs.Bool("flush", false, "delete matching review markers and restore the underlying label"),
	}
}

func runReviewCommand(ctx context.Context, args []string, name string, list sampleListFunc) error {
	o := reviewFlags(name)
	parseFlags(o.fs, args)

	db, err := openDB(ctx, *o.dsn)
	if err != nil {
		return err
	}
	defer db.Close()

	samples, err := list(ctx, db, *o.score, *o.limit)
	if err != nil {
		return err
	}
	if *o.flush {
		return flushReviewSamples(ctx, db, name, samples)
	}
	for _, s := range samples {
		age := sampleAgeDays(s.Mtime)
		if name == "benign-review" || name == "bad-review" {
			age = sampleAgeDays(s.MarkerMtime)
		}
		writeStdoutf("%4d  %-64s  %-5d  %-4s  %-6s  %-8s  %s\n",
			s.ID, s.SHA256, s.Score, age, s.Label, s.LabelSource, s.Path)
	}
	return nil
}

func flushReviewSamples(ctx context.Context, db *hopper.DB, name string, samples []*hopper.Sample) error {
	if name != "benign-review" && name != "bad-review" {
		return fmt.Errorf("%s does not support --flush", name)
	}

	targetLabel := "bad"
	targetSource := "flush"
	if name == "bad-review" {
		targetLabel = "good"
	}

	for _, s := range samples {
		markerPath := reviewMarkerPath(name, s.Path)
		if err := os.Remove(markerPath); err != nil && !errors.Is(err, os.ErrNotExist) {
			return fmt.Errorf("remove marker for %s: %w", s.Path, err)
		}
		if err := db.Reclassify(ctx, s.SHA256, targetLabel, targetSource); err != nil {
			return err
		}
		if err := db.SetSkip(ctx, s.SHA256, ""); err != nil {
			return err
		}
		writeStdoutf("flushed  %-64s  %s\n", s.SHA256, s.Path)
	}
	return nil
}

func reviewMarkerPath(name, samplePath string) string {
	suffix := markerBenign
	if name == "bad-review" {
		suffix = markerBad
	}
	dir := filepath.Dir(samplePath)
	base := filepath.Base(samplePath)
	return filepath.Join(dir, markerPrefix+base+suffix)
}

func sampleAgeDays(ts *time.Time) string {
	if ts == nil {
		return ""
	}
	days := max(int(time.Since(*ts).Hours()/24), 0)
	return strconv.Itoa(days)
}

func cmdFalsePositives(ctx context.Context) error {
	return runReviewCommand(ctx, os.Args[2:], "false-positives",
		func(ctx context.Context, db *hopper.DB, score, limit int) ([]*hopper.Sample, error) {
			return db.FalsePositives(ctx, score, limit)
		})
}

func cmdFalseNegatives(ctx context.Context) error {
	return runReviewCommand(ctx, os.Args[2:], "false-negatives",
		func(ctx context.Context, db *hopper.DB, score, limit int) ([]*hopper.Sample, error) {
			return db.FalseNegatives(ctx, score, limit)
		})
}

func cmdBenignReview(ctx context.Context) error {
	return runReviewCommand(ctx, os.Args[2:], "benign-review",
		func(ctx context.Context, db *hopper.DB, score, limit int) ([]*hopper.Sample, error) {
			return db.BenignReview(ctx, score, limit)
		})
}

func cmdBadReview(ctx context.Context) error {
	return runReviewCommand(ctx, os.Args[2:], "bad-review",
		func(ctx context.Context, db *hopper.DB, score, limit int) ([]*hopper.Sample, error) {
			return db.BadReview(ctx, score, limit)
		})
}

func isTTY() bool {
	fileInfo, err := os.Stdout.Stat()
	if err != nil {
		return false
	}
	return (fileInfo.Mode() & os.ModeCharDevice) != 0
}

func drawBar(label string, current, total int64, info string, color string) {
	const width = 20
	var pct float64
	if total > 0 {
		pct = float64(current) / float64(total)
	}
	if pct > 1.0 {
		pct = 1.0
	}
	filled := max(int(float64(width)*pct), 0)
	bar := strings.Repeat("█", filled) + strings.Repeat("░", width-filled)
	writeStdoutf("%s%s\033[0m [%s] %3.0f%% (%d/%d) %s\n", color, label, bar, pct*100, current, total, info)
}
