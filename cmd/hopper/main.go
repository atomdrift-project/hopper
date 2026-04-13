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
	"net/http"
	"net/url"
	"os"
	"os/exec"
	"os/signal"
	"path/filepath"
	"runtime"
	"sort"
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
	hashWorkers := f.Int("hash-workers", 8, "concurrent hash/insert workers for file walking")
	cleaveBinFlag := f.String("cleave", "cleave", "path to cleave binary (used for file enumeration)")
	litmusBin := f.String("litmus", "litmus", "path to litmus binary (pass empty to disable)")
	litmusWorkers := f.Int("workers", 0, "concurrent analysis workers for the local litmus (0 = auto: max(2, cores/4))")
	// Remote litmus workers self-register via the pull API; no --litmus-nodes flag needed.
	maxRSSGB := f.Int("max-memory-gb", 0, "litmus RSS limit in GB (0 = auto)")
	analysisTimeout := f.Int("analysis-timeout", 1200, "per-file analysis timeout in seconds (passed to litmus)")
	rescan := f.Bool("rescan", false, "re-analyze samples that already have litmus results")
	noCache := f.Bool("no-cache", false, "disable hash cache (re-read every file)")
	maxAnalyzed := f.Int("max-analyzed", 0, "stop after N successful analyses (0 = unlimited)")
	experimentTag := f.String("experiment-tag", "", "label for experiment comparison")
	litmusVerbose := f.Bool("litmus-verbose", true, "enable debug logging in litmus server")
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

	// Start the web dashboard first so it's reachable while everything
	// else is still initializing. configure() is called inside loadAll
	// once the session state is ready.
	// Create shared HTTP mux for dashboard + work API.
	// API handlers are registered immediately so workers connecting during
	// startup get a clean 503 instead of the dashboard's HTML.
	httpMux := http.NewServeMux()
	tracker := newWorkerTracker()
	api := &apiServer{tracker: tracker} // db, progress, allowedDirs set after init
	api.registerAPI(httpMux)

	var wd *webDashboard
	if *dashAddr != "" {
		wd = &webDashboard{}
		if err := startWebDashboard(ctx, *dashAddr, wd, httpMux); err != nil {
			slog.Warn("web dashboard disabled", "error", err)
			wd = nil
		} else {
			slog.Info("web dashboard + API listening", "addr", *dashAddr)
		}
	}

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


	// Start litmus early — it takes several seconds to load its model and
	// YARA rules, and none of that depends on cleave, the hash cache, or
	// the database. Running it in parallel with those steps shaves ~5s off
	// every startup.
	var litmus *litmusServer
	type litmusResult struct{ err error }
	litmusCh := make(chan litmusResult, 1)
	if *litmusBin != "" {
		// Local worker always connects to loopback. Replace 0.0.0.0
		// with 127.0.0.1 since 0.0.0.0 is a bind address, not a destination.
		hopperURL := "http://127.0.0.1:8081"
		if *dashAddr != "" {
			addr := *dashAddr
			if strings.HasPrefix(addr, "0.0.0.0:") {
				addr = "127.0.0.1:" + strings.TrimPrefix(addr, "0.0.0.0:")
			}
			hopperURL = "http://" + addr
		}
		litmus = newLitmusServer(litmusConfig{
			Bin:         *litmusBin,
			HopperURL:   hopperURL,
			DataDir:     *dataDir,
			MaxRSSGB:    *maxRSSGB,
			MaxWorkers:  *litmusWorkers,
			TimeoutSecs: *analysisTimeout,
			Verbose:     *litmusVerbose,
		})
		go func() {
			litmusCh <- litmusResult{err: litmus.Start(ctx)}
		}()
	} else {
		litmusCh <- litmusResult{} // nothing to wait for
	}

	// Run all independent startup work in parallel: cleave rebuild, hash
	// cache load, DB connect+migrate, and remote litmus dial all happen
	// concurrently alongside the local litmus startup above.
	var dirNames []string
	for _, d := range loadDirs {
		dirNames = append(dirNames, d.label)
	}
	slog.Info("load starting",
		"data", *dataDir,
		"labels", dirNames,
		"workers", *hashWorkers,
		"rescan", *rescan,
		"cache", !*noCache,
		"max_analyzed", *maxAnalyzed,
		"experiment", *experimentTag)

	go updateCleave(ctx)

	type cacheResult struct {
		cache *hashCache
		err   error
	}
	cacheCh := make(chan cacheResult, 1)
	go func() {
		if *noCache {
			cacheCh <- cacheResult{}
			return
		}
		home, err := os.UserHomeDir()
		if err != nil {
			home = "."
		}
		cacheDir := filepath.Join(home, ".hopper")
		mkdirAllBestEffort(cacheDir, 0o755)
		c, err := openHashCache(ctx, filepath.Join(cacheDir, "hashcache.db"))
		cacheCh <- cacheResult{cache: c, err: err}
	}()

	type dbResult struct {
		db  *hopper.DB
		err error
	}
	dbCh := make(chan dbResult, 1)
	go func() {
		d, err := openDB(ctx, *dsn)
		if err != nil {
			dbCh <- dbResult{err: err}
			return
		}
		slog.Info("running schema migrations")
		if err := d.Migrate(ctx); err != nil {
			d.Close()
			dbCh <- dbResult{err: err}
			return
		}
		dbCh <- dbResult{db: d}
	}()

	// Remote litmus workers now self-register via the pull API.
	// No dialing needed — they poll /api/next when ready.

	// Collect results. Order doesn't matter — each blocks until ready.
	cr := <-cacheCh
	var cache *hashCache
	if cr.err != nil {
		slog.Warn("hash cache unavailable, continuing without cache", "error", cr.err)
	} else {
		cache = cr.cache
		if cache != nil {
			defer cache.close(ctx)
		}
	}

	dr := <-dbCh
	if dr.err != nil {
		return dr.err
	}
	db := dr.db
	defer db.Close()

	if res := <-litmusCh; res.err != nil {
		return res.err
	}
	if litmus != nil {
		defer litmus.Stop()
		go func() {
			if err := litmus.Monitor(ctx); err != nil {
				slog.Error("litmus monitor failed", "error", err)
			}
		}()
	}

	loadCtx, loadCancel := context.WithCancel(ctx)
	defer loadCancel()

	// Wire the API server now that the DB is ready.
	var allowedDirs []string
	for _, d := range loadDirs {
		if resolved, err := filepath.EvalSymlinks(d.dir); err == nil {
			allowedDirs = append(allowedDirs, resolved)
		} else if abs, err := filepath.Abs(d.dir); err == nil {
			allowedDirs = append(allowedDirs, abs)
		}
	}
	absDataDir, _ := filepath.EvalSymlinks(*dataDir)
	if absDataDir == "" {
		absDataDir, _ = filepath.Abs(*dataDir)
	}
	api.db = db
	api.dataRoot = absDataDir
	api.allowedDirs = allowedDirs

	total := loadAll(loadCtx, loadCancel, db, litmus, tracker, api, cache, loadDirs, *source, *hashWorkers, *rescan, *maxAnalyzed, *experimentTag, wd)
	slog.Info("file walk complete, serving API until interrupted", "samples", total)

	// Block until interrupted — workers are still draining the analysis queue.
	<-ctx.Done()
	slog.Info("shutting down")
	return nil
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
	walkedPaths sync.Map    // path → struct{}: all paths seen by iter-files

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
func loadAll(ctx context.Context, cancel context.CancelFunc, db *hopper.DB, litmus *litmusServer, tracker *workerTracker, api *apiServer, cache *hashCache, dirs []struct{ dir, label string }, source string, nworkers int, rescan bool, maxAnalyzed int, experimentTag string, wd *webDashboard) int {
	slog.Info("loading", "dirs", len(dirs))
	start := time.Now()
	var progress loadProgress
	progress.analyzeDurationMin.Store(math.MaxInt64)

	// Wire the API server's progress pointer so /api/result can update counters.
	if api != nil {
		api.progress = &progress
	}

	var startAnalyzed int64
	if n, err := db.CountAnalyzed(ctx); err == nil {
		progress.analyzed.Store(n)
		progress.queued.Store(n)
		startAnalyzed = n
	}

	// Progress dashboard — runs until ctx is cancelled (ctrl-C).
	var dashWG sync.WaitGroup
	dashWG.Go(func() {
		runDashboard(ctx, &progress, litmus, tracker, start, startAnalyzed, maxAnalyzed, len(dirs))
	})

	if wd != nil {
		wd.configure(&progress, litmus, tracker, start, startAnalyzed, maxAnalyzed, len(dirs))
	}

	// Per-directory pipelines: cleave→hash→batch→insert.
	// Analysis happens via the pull API — workers claim from the DB.
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
			runDirPipeline(ctx, db, d, source, cache, &progress, rescan)
		})
	}
	pipeWG.Wait()

	// Mark samples whose files are gone or filtered out by iter-files.
	walkedSet := make(map[string]struct{})
	progress.walkedPaths.Range(func(k, _ any) bool {
		walkedSet[k.(string)] = struct{}{}
		return true
	})
	if marked, err := db.MarkMissingSamples(ctx, walkedSet); err != nil {
		slog.Error("mark missing samples failed", "error", err)
	} else if marked > 0 {
		slog.Info("marked stale samples", "count", marked)
	}

	logLoadSummary(start, experimentTag, dirs, &progress)

	// Keep the dashboard running — workers are still analyzing.
	// The dashboard goroutine exits when ctx is cancelled (ctrl-C).
	dashWG.Wait()

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
		progress.queued.Add(int64(len(needsAnalysis)))
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
		progress.walkedPaths.Store(lp.path, struct{}{})

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
	_ *litmusServer,
	tracker *workerTracker,
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

	// Ring buffer for 15-minute rolling rate (one sample per tick).
	type sample struct {
		t      time.Time
		count  int64
		byNode []int64
	}
	const maxSamples = 120 // 10s * 120 = 20 minutes of history
	var samples []sample

	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
		}

		var workers []namedWorkerStats
		if tracker != nil {
			workers = tracker.all()
		}

		analyzedAbs := progress.analyzed.Load()
		sessionAnalyzed := max(analyzedAbs-startAnalyzed, 0)
		walked := progress.walked.Load()
		hashedN := progress.hashed.Load()
		inserted := progress.inserted.Load()
		skipped := progress.skipped.Load()
		hashDone := hashedN + progress.tooSmall.Load() + progress.tooLarge.Load() + progress.hashErrors.Load()

		analyzeTarget := max(progress.queued.Load()-startAnalyzed, 0)
		if maxAnalyzed > 0 && int64(maxAnalyzed) < analyzeTarget {
			analyzeTarget = int64(maxAnalyzed)
		}

		// Record sample (with per-worker counts) and compute 15-minute rolling rates.
		now := time.Now()
		s := sample{t: now, count: sessionAnalyzed}
		if len(workers) > 0 {
			s.byNode = make([]int64, len(workers))
			for i, w := range workers {
				s.byNode[i] = w.Analyzed
			}
		}
		samples = append(samples, s)
		if len(samples) > maxSamples {
			samples = samples[len(samples)-maxSamples:]
		}

		var rate15m float64
		var nodeRates map[string]float64
		if len(samples) >= 2 {
			cutoff := now.Add(-15 * time.Minute)
			oldest := samples[0]
			for _, ss := range samples {
				if !ss.t.Before(cutoff) {
					oldest = ss
					break
				}
			}
			if dt := now.Sub(oldest.t).Seconds(); dt > 5 {
				rate15m = float64(sessionAnalyzed-oldest.count) / dt
				latest := samples[len(samples)-1]
				// Per-node rates: compare matching indices up to the
				// shorter of the two slices. This handles monitor
				// count changes (nodes joining/leaving) gracefully.
				minLen := len(latest.byNode)
				if len(oldest.byNode) < minLen {
					minLen = len(oldest.byNode)
				}
				if minLen > 0 {
					nodeRates = make(map[string]float64, len(workers))
					for i, w := range workers {
						if i < minLen {
							nodeRates[w.Name] = float64(latest.byNode[i]-oldest.byNode[i]) / dt
						}
					}
				}
			}
		}

		totalTarget := startAnalyzed + analyzeTarget
		totalDone := startAnalyzed + sessionAnalyzed

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
			if rate15m > 0 {
				attrs = append(attrs, "rate_15m", fmt.Sprintf("%.1f/s", rate15m))
			}
			slog.Info("load progress", attrs...)
			logWorkerStatus(workers)
			continue
		}

		// TTY dashboard
		var etaStr string
		if rate15m > 0.1 && analyzeTarget > sessionAnalyzed {
			remaining := analyzeTarget - sessionAnalyzed
			etaDur := time.Duration(float64(remaining)/rate15m) * time.Second
			etaStr = formatETA(etaDur)
		}

		pct := 0.0
		if totalTarget > 0 {
			pct = float64(totalDone) / float64(totalTarget) * 100
			if pct > 100 {
				pct = 100
			}
		}

		writeStdout("\033[H\033[2J")

		// Header line: app name, elapsed, progress, rate, ETA
		header := fmt.Sprintf("\033[1mhopper\033[0m  %s", time.Since(start).Round(time.Second))
		right := fmt.Sprintf("%s / %s  %.0f%%", fmtN(totalDone), fmtN(totalTarget), pct)
		if rate15m > 0.1 {
			right += fmt.Sprintf("  %.1f/s", rate15m)
		}
		if etaStr != "" {
			right += "  ETA " + etaStr
		}
		// Pad to ~80 columns.
		pad := 78 - len(header) - len(right) + 8 // +8 for ANSI escape codes
		if pad < 2 {
			pad = 2
		}
		writeStdoutf("%s%s%s\n\n", header, strings.Repeat(" ", pad), right)

		// Workers
		if len(workers) > 0 {
			nameWidth := 6
			for _, w := range workers {
				if len(w.Name) > nameWidth {
					nameWidth = len(w.Name)
				}
			}
			writeStdoutf("\n  \033[2m  %-*s  tasks    rate  analyzed  errors\033[0m\n",
				nameWidth, "worker")

			sort.Slice(workers, func(i, j int) bool { return workers[i].Name < workers[j].Name })
			for _, w := range workers {
				idle := time.Since(w.LastSeen)
				status, dot := workerStatus(w.ActiveClaims, idle)

				rateStr := "    —"
				if r := nodeRates[w.Name]; r > 0.05 {
					rateStr = fmt.Sprintf("%4.1f/s", r)
				}

				line := fmt.Sprintf("  %s %-*s  %3d/%d  %s  %8s  %s",
					dot, nameWidth, w.Name,
					w.ActiveClaims, w.Slots, rateStr,
					fmtN(w.Analyzed), fmtN(w.Errors))
				if status != "" {
					line += fmt.Sprintf("  \033[33m%s\033[0m", status)
				}
				writeStdoutLine(line)
			}
		}

		// Footer
		writeStdoutf("\n  %s errors · %s walked · %s cache hits\n",
			fmtN(progress.errors.Load()), fmtN(walked), fmtN(progress.cacheHits.Load()))

		// Last error at the bottom, untruncated
		if last, ok := progress.lastErr.Load().(string); ok && last != "" {
			writeStdoutf("\n  \033[31m%s\033[0m\n", last)
		}
	}
}

// logWorkerStatus emits one slog line per worker for the non-TTY path.
// workerStatus returns a display status and ANSI dot color for a worker.
// Active claims > 0 means the worker is online (actively processing).
// Otherwise, fall back to time-based: inactive after 10min, down after 30min.
func workerStatus(activeClaims int, idle time.Duration) (status string, dot string) {
	green := "\033[32m●\033[0m"
	yellow := "\033[33m●\033[0m"
	red := "\033[31m●\033[0m"

	if activeClaims > 0 {
		return "", green
	}
	switch {
	case idle < 10*time.Minute:
		return "", green // recently active, just idle
	case idle < 30*time.Minute:
		return fmt.Sprintf("inactive %s", shortDuration(idle)), yellow
	default:
		return fmt.Sprintf("down %s", shortDuration(idle)), red
	}
}

func logWorkerStatus(workers []namedWorkerStats) {
	for _, w := range workers {
		online := time.Since(w.LastSeen) < 30*time.Second
		status := "online"
		if !online {
			status = "offline"
		}
		slog.Info("litmus worker",
			"worker", w.Name,
			"status", status,
			"slots", w.Slots,
			"analyzed", w.Analyzed,
			"errors", w.Errors)
	}
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

