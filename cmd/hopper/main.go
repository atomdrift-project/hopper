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

	logPath, cleanup, err := setupLogging()
	if err != nil {
		writeStderrf("failed to setup logging: %v\n", err)
	} else {
		fmt.Fprintf(os.Stderr, "log: %s\n", logPath) //nolint:forbidigo // startup info before slog is configured
	}

	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt)

	// Force-exit on a second interrupt so cleanup can't hang forever.
	go func() {
		sigCh := make(chan os.Signal, 1)
		signal.Notify(sigCh, os.Interrupt)
		<-sigCh // first is handled by NotifyContext
		<-sigCh // second means "exit now"
		slog.Warn("forced exit on second interrupt")
		os.Exit(1)
	}()

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

func setupLogging() (logPath string, cleanup func(), err error) {
	dir := xdgLogDir()
	if err := os.MkdirAll(dir, 0o750); err != nil {
		return "", nil, err
	}

	logPath = filepath.Join(dir, "hopper.log")
	f, err := os.OpenFile(logPath, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0o600)
	if err != nil {
		return "", nil, err
	}

	// Use a handler that writes to both stderr and the log file.
	// Console gets Warn+ only; Info/Debug go to the log file.
	stderrLevel := &slog.LevelVar{}
	stderrLevel.Set(slog.LevelWarn)
	fileLevel := &slog.LevelVar{}
	h := &multiHandler{
		h1: slog.NewTextHandler(os.Stderr, &slog.HandlerOptions{Level: stderrLevel}),
		h2: slog.NewJSONHandler(f, &slog.HandlerOptions{Level: fileLevel}),
	}
	slog.SetDefault(slog.New(h))

	return logPath, func() { closeFileBestEffort(logPath, f) }, nil
}

type multiHandler struct {
	h1, h2 slog.Handler
}

func (m *multiHandler) Enabled(ctx context.Context, l slog.Level) bool {
	return m.h1.Enabled(ctx, l) || m.h2.Enabled(ctx, l)
}

func (m *multiHandler) Handle(ctx context.Context, r slog.Record) error { //nolint:gocritic // matches slog.Handler interface
	var err1, err2 error
	if m.h1.Enabled(ctx, r.Level) {
		err1 = m.h1.Handle(ctx, r)
	}
	if m.h2.Enabled(ctx, r.Level) {
		err2 = m.h2.Handle(ctx, r)
	}
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

func cmdLoad(ctx context.Context) error { //nolint:nolintlint,revive,maintidx // complex command setup function.
	f := flag.NewFlagSet("load", flag.ExitOnError)
	dsn := f.String("db", "", "database connection string")
	dataDir := f.String("data", "", "data directory containing bad/, good/, unknown/ subdirectories")
	source := f.String("source", "harvest", "sample source tag")
	hashWorkers := f.Int("hash-workers", 8, "concurrent hash/insert workers for file walking")
	cleaveBinFlag := f.String("cleave", "cleave", "path to cleave binary (used for file enumeration)")
	litmusBin := f.String("litmus", "litmus", "path to litmus binary (pass empty to disable)")
	litmusWorkers := f.Int("workers", 0, "concurrent analysis workers for the local litmus (0 = auto: min(2, cores/2))")
	// Remote litmus workers self-register via the pull API; no --litmus-nodes flag needed.
	maxRSSGB := f.Int("max-memory-gb", 0, "litmus RSS limit in GB (0 = auto)")
	rescan := f.Bool("rescan", false, "re-analyze samples that already have litmus results")
	rescanAge := f.Duration("rescan-age", 7*24*time.Hour, "minimum age before a stale-traits sample is eligible for rescan")
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

	// Resolve symlinks and make absolute early so that all paths derived
	// from dataDir (loadDirs, DB rows, API prefix stripping) are consistent.
	if resolved, err := filepath.EvalSymlinks(*dataDir); err == nil {
		*dataDir = resolved
	}
	if abs, err := filepath.Abs(*dataDir); err == nil {
		*dataDir = abs
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

	// Rebuild tools first so we can bail early if litmus or cleave is broken.
	// Both builds run in parallel; once done we update litmus rules and check
	// the traits version — all before touching the database.
	type buildResult struct{ err error }
	litmusBuildCh := make(chan buildResult, 1)
	cleaveBuildCh := make(chan buildResult, 1)
	go func() {
		updateSiblingTool(ctx, "litmus", "../litmus")
		litmusBuildCh <- buildResult{}
	}()
	go func() {
		updateSiblingTool(ctx, "cleave", "../cleave")
		cleaveBuildCh <- buildResult{}
	}()
	<-litmusBuildCh
	<-cleaveBuildCh

	// With a freshly built binary, pull latest rules and check the version.
	var traitsVersion string
	if *litmusBin != "" {
		refreshLitmusRules(ctx, *litmusBin)
		traitsVersion = litmusTraitsVersion(ctx, *litmusBin)
		if traitsVersion != "" {
			slog.Info("traits version for rescan", "version", traitsVersion)
		}
	}

	// Now start litmus and the rest of the startup work.
	var litmus *litmusServer
	type litmusResult struct{ err error }
	litmusCh := make(chan litmusResult, 1)
	if *litmusBin != "" {
		// Local worker always connects to loopback. Replace 0.0.0.0
		// with 127.0.0.1 since 0.0.0.0 is a bind address, not a destination.
		hopperURL := "http://127.0.0.1:8081"
		if *dashAddr != "" {
			addr := *dashAddr
			if after, ok := strings.CutPrefix(addr, "0.0.0.0:"); ok {
				addr = "127.0.0.1:" + after
			}
			hopperURL = "http://" + addr
		}
		litmus = newLitmusServer(litmusConfig{
			Bin:        *litmusBin,
			HopperURL:  hopperURL,
			DataDir:    *dataDir,
			MaxRSSGB:   *maxRSSGB,
			MaxWorkers: *litmusWorkers,
			Verbose:    *litmusVerbose,
		})
		litmus.tracker = tracker
		litmus.workerName = "local"
		go func() {
			litmusCh <- litmusResult{err: litmus.Start(ctx)}
		}()
	} else {
		litmusCh <- litmusResult{} // nothing to wait for
	}

	// Run independent startup work in parallel: hash cache load, DB
	// connect+migrate, and file enumeration alongside litmus startup.
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

	// Start file enumeration early — cleave iter-files doesn't need the
	// hash cache or database, so overlap it with those slower init steps.
	fileChs := make([]<-chan labeledPath, len(loadDirs))
	for i, d := range loadDirs {
		fileChs[i] = startEnumeration(ctx, d.dir)
	}

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

	// Clear stale claims from previous runs so those samples get re-queued.
	if n, err := db.UnclaimAll(ctx); err != nil {
		slog.Warn("failed to clear stale claims", "error", err)
	} else if n > 0 {
		slog.Info("cleared stale claims from previous run", "count", n)
	}

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
	// dataDir was already resolved (symlinks + absolute) at startup.
	api.db = db
	api.dataRoot = *dataDir
	api.allowedDirs = allowedDirs

	api.traitsVersion = traitsVersion
	api.rescanAge = *rescanAge

	total := loadAll(loadCtx, loadCancel, db, litmus, tracker, api, cache,
		loadDirs, fileChs, *source, *hashWorkers, *rescan, *maxAnalyzed, *experimentTag, wd, traitsVersion, *rescanAge)
	slog.Info("file walk complete, serving API until interrupted", "samples", total)

	// Block until interrupted — workers are still draining the analysis queue.
	// Without litmus there's nothing left to wait for.
	if litmus != nil {
		<-ctx.Done()
		slog.Info("shutting down")
	}
	return nil
}

// loadProgress tracks counters across concurrent load workers.
type loadProgress struct { //nolint:govet // counters are grouped by pipeline stage for maintenance.
	walked      atomic.Int64
	hashed      atomic.Int64
	inserted    atomic.Int64
	skipped     atomic.Int64
	analyzed    atomic.Int64
	markers     atomic.Int64 // files skipped due to misclassification markers
	tooSmall    atomic.Int64 // files below minFileSize
	tooLarge    atomic.Int64 // files above maxFileSize
	errors      atomic.Int64
	hashErrors  atomic.Int64 // hash failures (subset of errors, for % calc)
	cacheHits   atomic.Int64
	exploded    atomic.Int64 // archive members inserted
	queued      atomic.Int64 // items sent for analysis
	walkedPaths sync.Map     // path → struct{}: all paths seen by iter-files

	walkDone atomic.Bool // true once all enumeration channels are drained

	lastErr atomic.Value // string

	// Per-analysis timing (nanoseconds).
	analyzeDurationSum atomic.Int64
	analyzeDurationMax atomic.Int64
	analyzeDurationMin atomic.Int64 // initialized to math.MaxInt64
	scoreSum           atomic.Int64
}

const (
	loadBatchSize      = 2000
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
func loadAll( //nolint:nolintlint,revive // many params reflect the many subsystems coordinated here.
	ctx context.Context,
	_ context.CancelFunc,
	db *hopper.DB,
	litmus *litmusServer,
	tracker *workerTracker,
	api *apiServer,
	cache *hashCache,
	dirs []struct{ dir, label string },
	fileChs []<-chan labeledPath,
	source string,
	nworkers int,
	_ bool,
	maxAnalyzed int,
	experimentTag string,
	wd *webDashboard,
	traitsVersion string,
	rescanAge time.Duration,
) int {
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
		startAnalyzed = n
	}
	// Initialize queued to analyzed + pending so the denominator reflects all
	// work from prior runs. Without this, pre-existing unanalyzed samples
	// cause analyzed to exceed queued, producing ">100%" progress.
	if pending, err := db.CountPending(ctx); err == nil {
		progress.queued.Store(startAnalyzed + pending)
	} else {
		progress.queued.Store(startAnalyzed)
	}

	// Progress dashboard — runs until ctx is cancelled (ctrl-C).
	var dashWG sync.WaitGroup
	dashWG.Go(func() {
		runDashboard(ctx, &progress, litmus, tracker, db, start, startAnalyzed, maxAnalyzed, len(dirs), traitsVersion, rescanAge)
	})

	if wd != nil {
		wd.configure(&progress, litmus, tracker, db, start, startAnalyzed, maxAnalyzed, len(dirs), traitsVersion, rescanAge)
	}

	// runWalk executes one full enumeration→hash→insert pass across all dirs.
	runWalk := func(chs []<-chan labeledPath) {
		// Reset walk-phase counters so they reflect the current pass, not a
		// cumulative total across re-walks. The walkedPaths map is kept to
		// accumulate the full set for MarkMissingSamples.
		progress.walked.Store(0)
		progress.hashed.Store(0)
		progress.inserted.Store(0)
		progress.skipped.Store(0)
		progress.cacheHits.Store(0)
		progress.tooSmall.Store(0)
		progress.tooLarge.Store(0)
		progress.hashErrors.Store(0)

		if chs == nil {
			chs = make([]<-chan labeledPath, len(dirs))
			for i, d := range dirs {
				chs[i] = startEnumeration(ctx, d.dir)
			}
		}

		sem := make(chan struct{}, max(1, nworkers))
		var pipeWG sync.WaitGroup
		for i, d := range dirs {
			ch := chs[i]
			pipeWG.Go(func() {
				select {
				case sem <- struct{}{}:
					defer func() { <-sem }()
				case <-ctx.Done():
					return
				}
				runDirPipeline(ctx, db, d, source, cache, &progress, ch)
			})
		}
		pipeWG.Wait()
		progress.walkDone.Store(true)

		// Mark samples whose files are gone or filtered out by iter-files.
		wasWalked := func(path string) bool {
			_, ok := progress.walkedPaths.Load(path)
			return ok
		}
		if marked, err := db.MarkMissingSamples(ctx, wasWalked); err != nil {
			slog.Error("mark missing samples failed", "error", err)
		} else if marked > 0 {
			slog.Info("marked stale samples", "count", marked)
		}

		logLoadSummary(start, experimentTag, dirs, &progress)
	}

	// Initial walk uses pre-started enumeration channels (if provided).
	runWalk(fileChs)

	// Re-walk periodically to pick up new files while workers analyze.
	if litmus != nil {
		go func() {
			ticker := time.NewTicker(10 * time.Minute)
			defer ticker.Stop()
			for {
				select {
				case <-ticker.C:
					progress.walkDone.Store(false)
					slog.Info("starting periodic re-walk")
					runWalk(nil)
				case <-ctx.Done():
					return
				}
			}
		}()
	}

	// If there's a litmus server, keep the dashboard running — analysis
	// is still in progress via the pull API. The dashboard goroutine exits
	// when ctx is cancelled (ctrl-C). Without litmus there's nothing to
	// wait for (remote workers also need the server to stay up).
	if litmus != nil {
		dashWG.Wait()
	}

	return int(progress.inserted.Load() + progress.skipped.Load())
}

// runDirPipeline is the hash→batch→insert pipeline for one labeled directory,
// fed by a pre-started enumeration channel. Everything runs sequentially in
// this one goroutine so batches stay coherent without cross-goroutine plumbing;
// parallelism comes from running one instance per directory.
func runDirPipeline(
	ctx context.Context,
	db *hopper.DB,
	target struct{ dir, label string },
	source string,
	cache *hashCache,
	progress *loadProgress,
	fileCh <-chan labeledPath,
) {
	batch := make([]*hopper.Sample, 0, loadBatchSize)
	batchKeys := make([]cacheKey, 0, loadBatchSize)
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
			batchKeys = batchKeys[:0]
			clear(pathBySha)
			return
		}
		progress.inserted.Add(n)
		progress.skipped.Add(int64(len(batch)) - n)
		progress.queued.Add(int64(len(needsAnalysis)))

		// Mark entries as inserted in the hash cache so future startups
		// can skip the DB round-trip entirely.
		if cache != nil && len(batchKeys) > 0 {
			cache.markInserted(ctx, batchKeys)
		}

		batch = batch[:0]
		batchKeys = batchKeys[:0]
		clear(pathBySha)
	}
	defer flush()

	for lp := range fileCh {
		if ctx.Err() != nil {
			break
		}
		if isMarkerFile(filepath.Base(lp.path)) {
			continue
		}
		lp.label = target.label
		progress.walked.Add(1)
		progress.walkedPaths.Store(lp.path, struct{}{})

		hr, err := hashFile(ctx, lp.path, lp.label, lp.fileType, source, cache, progress)
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
			continue
		}

		progress.hashed.Add(1)

		// Cache hit + already inserted into DB → skip the batch insert entirely.
		// Marker changes are picked up on the next full scan (--rescan or cache miss).
		if hr.inserted {
			progress.skipped.Add(1)
			continue
		}

		sample := hr.sample

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

		batch = append(batch, sample)
		batchKeys = append(batchKeys, hr.cacheKey)
		pathBySha[sample.SHA256] = lp.path
		if len(batch) >= loadBatchSize {
			flush()
		}
	}
}

// runDashboard renders the periodic progress view (TTY bars or slog lines)
// until ctx is cancelled. It reads progress counters directly; no
// coordination with workers is required beyond those atomic loads. The pool
// status block is fed by background nodeMonitors so this function never
// blocks on a slow remote.
func runDashboard( //nolint:nolintlint,gocognit,revive,maintidx // complex dashboard loop with many coordinated params.
	ctx context.Context,
	progress *loadProgress,
	_ *litmusServer,
	tracker *workerTracker,
	db *hopper.DB,
	start time.Time,
	startAnalyzed int64,
	maxAnalyzed, ndirs int,
	traitsVersion string,
	rescanAge time.Duration,
) {
	interval := 10 * time.Second
	if !isTTY() {
		interval = 30 * time.Second
	}
	ticker := time.NewTicker(interval)
	defer ticker.Stop()

	// Ring buffer for 15-minute rolling rate (one sample per tick).
	type sample struct {
		t        time.Time
		byNode   map[string]int64 // keyed by worker name
		count    int64            // session analyzed
		inserted int64            // session inserted (new DB rows)
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

		// Query oldest active claim per worker.
		oldestClaims := make(map[string]hopper.WorkerClaim)
		var newestAnalyzedAt time.Time
		var rescanPending int64
		if db != nil {
			if claims, err := db.OldestClaims(ctx, staleClaimAge); err == nil {
				for _, c := range claims {
					oldestClaims[c.Worker] = c
				}
			}
			newestAnalyzedAt, _ = db.NewestAnalyzedAt(ctx)   //nolint:errcheck // best-effort; zero time is acceptable fallback
			rescanPending, _ = db.CountRescanPending(ctx, traitsVersion, rescanAge) //nolint:errcheck // best-effort; zero is acceptable fallback
		}

		analyzedAbs := progress.analyzed.Load()
		sessionAnalyzed := max(analyzedAbs-startAnalyzed, 0)
		walked := progress.walked.Load()
		hashedN := progress.hashed.Load()
		inserted := progress.inserted.Load()
		skipped := progress.skipped.Load()
		hashDone := hashedN + progress.tooSmall.Load() + progress.tooLarge.Load() + progress.hashErrors.Load()

		// totalInDB = all samples in the database (analyzed + pending).
		totalInDB := progress.queued.Load()
		// totalExpected adds files still in the walk→hash→insert pipeline
		// that haven't reached the DB yet. This prevents premature 100%.
		insertDone := inserted + skipped + progress.tooSmall.Load() + progress.tooLarge.Load() + progress.hashErrors.Load()
		inPipeline := max(walked-insertDone, 0)
		totalExpected := totalInDB
		if !progress.walkDone.Load() || inPipeline > 0 {
			totalExpected += inPipeline
		}
		pending := max(totalExpected-analyzedAbs, 0)
		if maxAnalyzed > 0 && int64(maxAnalyzed) < pending {
			pending = int64(maxAnalyzed)
		}

		// Record sample (with per-worker counts) and compute 15-minute rolling rates.
		now := time.Now()
		s := sample{t: now, count: sessionAnalyzed, inserted: inserted}
		if len(workers) > 0 {
			s.byNode = make(map[string]int64, len(workers))
			for i := range workers {
				s.byNode[workers[i].Name] = workers[i].Analyzed
			}
		}
		samples = append(samples, s)
		if len(samples) > maxSamples {
			samples = samples[len(samples)-maxSamples:]
		}

		var rate15m float64
		var insertRate15m float64
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
				rate15m = max(float64(sessionAnalyzed-oldest.count)/dt, 0)
				insertRate15m = max(float64(inserted-oldest.inserted)/dt, 0)
				latest := samples[len(samples)-1]
				if len(latest.byNode) > 0 {
					nodeRates = make(map[string]float64, len(latest.byNode))
					for name, latestCount := range latest.byNode {
						if oldCount, ok := oldest.byNode[name]; ok {
							nodeRates[name] = max(float64(latestCount-oldCount)/dt, 0)
						}
					}
				}
			}
		}

		if !isTTY() {
			attrs := []any{
				"dirs", ndirs,
				"walked", walked, "hashed", hashedN,
				"inserted", inserted, "skipped", skipped,
				"analyzed", analyzedAbs, "pending", pending, "errors", progress.errors.Load(),
			}
			if walked > 0 {
				attrs = append(attrs, "hash_pct", fmt.Sprintf("%.0f%%", float64(hashDone)/float64(walked)*100))
			}
			if totalExpected > 0 {
				attrs = append(attrs, "analyze_pct", fmt.Sprintf("%.0f%%", float64(analyzedAbs)/float64(totalExpected)*100))
			}
			if rate15m > 0 {
				attrs = append(attrs, "rate_15m", fmt.Sprintf("%.1f/s", rate15m))
			}
			if elapsed := time.Since(start).Seconds(); elapsed > 5 && sessionAnalyzed > 0 {
				attrs = append(attrs, "rate_overall", fmt.Sprintf("%.1f/s", float64(sessionAnalyzed)/elapsed))
			}
			totalRemaining := pending + rescanPending
			if rescanPending > 0 {
				attrs = append(attrs, "rescan_pending", rescanPending)
			}
			if rate15m > 0.1 && totalRemaining > 0 {
				etaDur := time.Duration(float64(totalRemaining)/rate15m) * time.Second
				attrs = append(attrs, "eta", formatETA(etaDur))
			}
			slog.Info("load progress", attrs...)
			logWorkerStatus(workers, nodeRates, oldestClaims)
			continue
		}

		// TTY dashboard
		totalRemaining := pending + rescanPending

		var etaStr string
		if rate15m > 0.1 && totalRemaining > 0 {
			etaDur := time.Duration(float64(totalRemaining)/rate15m) * time.Second
			etaStr = formatETA(etaDur)
		}

		pct := 0.0
		if totalExpected > 0 {
			pct = float64(analyzedAbs) / float64(totalExpected) * 100
			if pct > 100 {
				pct = 100
			}
		}

		writeStdout("\033[H\033[2J")

		elapsed := time.Since(start)

		// Line 1: analysis progress
		analysisLine := fmt.Sprintf(
			"\033[1mhopper\033[0m  %s    %s / %s analyzed  %.0f%%",
			elapsed.Round(time.Second),
			fmtN(analyzedAbs), fmtN(totalExpected), pct)
		if rate15m > 0.1 {
			analysisLine += fmt.Sprintf("  %.1f/s", rate15m)
		}
		if etaStr != "" {
			analysisLine += "  ETA " + etaStr
		}
		writeStdoutf("%s\n", analysisLine)

		// Line 2: remaining work breakdown
		if totalRemaining > 0 || !progress.walkDone.Load() {
			remainLine := "  "
			if pending > 0 {
				remainLine += fmt.Sprintf("%s pending", fmtN(pending))
			}
			if rescanPending > 0 {
				if pending > 0 {
					remainLine += " + "
				}
				remainLine += fmt.Sprintf("%s rescan", fmtN(rescanPending))
			}
			if pending > 0 || rescanPending > 0 {
				remainLine += fmt.Sprintf(" = %s remaining", fmtN(totalRemaining))
			}
			if insertRate15m > 0.1 {
				remainLine += fmt.Sprintf("  %.1f/s new", insertRate15m)
			}
			if !progress.walkDone.Load() {
				remainLine += "  walking\u2026"
			}
			writeStdoutf("%s\n", remainLine)
		}

		// Workers
		if len(workers) > 0 {
			nameWidth := 6
			for i := range workers {
				if len(workers[i].Name) > nameWidth {
					nameWidth = len(workers[i].Name)
				}
			}
			writeStdoutf("\n  \033[2m  %-*s  tasks    seen    rate  analyzed  errors  oldest job\033[0m\n",
				nameWidth, "worker")

			sort.Slice(workers, func(i, j int) bool { return workers[i].Name < workers[j].Name })
			for i := range workers {
				idle := time.Since(workers[i].LastSeen)
				status, dot := workerStatus(workers[i].ActiveClaims, idle)

				rateStr := "    —"
				if r := nodeRates[workers[i].Name]; r > 0.05 {
					rateStr = fmt.Sprintf("%4.1f/s", r)
				}

				oldestStr := ""
				if claim, ok := oldestClaims[workers[i].Name]; ok {
					age := time.Since(claim.ClaimedAt)
					oldestStr = fmt.Sprintf("  %s (%s)", filepath.Base(claim.Path), shortDuration(age))
				}

				seenStr := fmt.Sprintf("%5s", shortDuration(idle))

				line := fmt.Sprintf("  %s %-*s  %3d/%d  %s  %s  %8s  %s",
					dot, nameWidth, workers[i].Name,
					workers[i].ActiveClaims, workers[i].Slots, seenStr, rateStr,
					fmtN(workers[i].Analyzed), fmtN(workers[i].Errors))
				if oldestStr != "" {
					line += oldestStr
				}
				if status != "" {
					line += fmt.Sprintf("  \033[33m%s\033[0m", status)
				}
				writeStdoutLine(line)
			}
		}

		// Footer: pipeline summary showing how walked files flow into analysis.
		cacheHits := progress.cacheHits.Load()
		tooSmall := progress.tooSmall.Load()
		tooLarge := progress.tooLarge.Load()
		errs := progress.errors.Load()
		lastCompleted := ""
		if !newestAnalyzedAt.IsZero() {
			lastCompleted = fmt.Sprintf(" · last completed %s ago", shortDuration(time.Since(newestAnalyzedAt)))
		}
		walkStatus := "…"
		if progress.walkDone.Load() {
			walkStatus = "done"
		}
		// skipped includes both cache-hit skips and batch-insert dupes;
		// subtract cache hits to show only the batch-insert dupes.
		dupes := max(skipped-cacheHits, 0)
		writeStdoutf("\n  %s walked (%s) · %s known · %s new · %s inserted",
			fmtN(walked), walkStatus, fmtN(cacheHits), fmtN(walked-cacheHits-tooSmall-tooLarge), fmtN(inserted))
		if dupes > 0 {
			writeStdoutf(" · %s dupes", fmtN(dupes))
		}
		if tooSmall+tooLarge > 0 {
			writeStdoutf(" · %s filtered", fmtN(tooSmall+tooLarge))
		}
		if errs > 0 {
			writeStdoutf(" · %s errors", fmtN(errs))
		}
		writeStdoutf("%s\n", lastCompleted)

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

func logWorkerStatus(workers []namedWorkerStats, nodeRates map[string]float64, oldestClaims map[string]hopper.WorkerClaim) {
	for i := range workers {
		online := time.Since(workers[i].LastSeen) < 30*time.Second
		status := "online"
		if !online {
			status = "offline"
		}
		attrs := []any{
			"worker", workers[i].Name,
			"status", status,
			"slots", workers[i].Slots,
			"claimed", workers[i].TotalClaimed,
			"analyzed", workers[i].Analyzed,
			"errors", workers[i].Errors,
		}
		if r := nodeRates[workers[i].Name]; r > 0.05 {
			attrs = append(attrs, "rate", fmt.Sprintf("%.1f/s", r))
		}
		if workers[i].RSSMB > 0 {
			attrs = append(attrs, "rss_mb", workers[i].RSSMB)
		}
		if workers[i].Load1 > 0 {
			attrs = append(attrs, "load1", fmt.Sprintf("%.2f", workers[i].Load1))
		}
		if claim, ok := oldestClaims[workers[i].Name]; ok {
			attrs = append(attrs,
				"oldest_job", filepath.Base(claim.Path),
				"oldest_age", shortDuration(time.Since(claim.ClaimedAt)))
		}
		slog.Info("litmus worker", attrs...)
	}
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

// startEnumeration kicks off pathLister in a goroutine and streams results
// into a channel so file enumeration can overlap with other startup work
// (hash cache loading, DB migrations, etc.).
func startEnumeration(ctx context.Context, dir string) <-chan labeledPath {
	ch := make(chan labeledPath, 4096)
	go func() {
		defer close(ch)
		slog.Info("listing files", "dir", dir)
		err := pathLister(ctx, dir, func(lp labeledPath) bool {
			select {
			case ch <- lp:
				return true
			case <-ctx.Done():
				return false
			}
		})
		if err != nil {
			slog.Warn("list files failed", "dir", dir, "error", err)
		}
	}()
	return ch
}

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

// hashResult bundles a sample with cache metadata so the pipeline can skip
// DB inserts for files that are both cache hits and already inserted.
type hashResult struct {
	sample   *hopper.Sample
	cacheKey cacheKey
	inserted bool // true if the hash cache says this SHA256 is already in the DB
}

// hashFile stats path, enforces size limits, consults the hash cache, and
// returns a Sample stamped with the cleave-classified file type. The file is
// only opened for reading on a cache miss. Pass "" for fileType in contexts
// that don't yet know it (tests, ad-hoc callers). Pass nil for progress when
// no cache-hit metric is being collected.
func hashFile(ctx context.Context, path, label, fileType, source string, cache *hashCache, progress *loadProgress) (hashResult, error) {
	info, err := os.Stat(path)
	if err != nil {
		return hashResult{}, err
	}

	if info.Size() < minFileSize {
		return hashResult{}, errTooSmall
	}
	if info.Size() >= maxFileSize {
		return hashResult{}, errTooLarge
	}

	dev, inode := fileStat(info)

	ck := cacheKey{dev: dev, inode: inode, size: info.Size(), mtime: info.ModTime().UnixNano()}

	// Check hash cache before reading file contents.
	if cache != nil {
		if cached, ins, ok := cache.lookup(ctx, dev, inode, info.Size(), info.ModTime()); ok {
			if progress != nil {
				progress.cacheHits.Add(1)
			}
			if ins {
				// Already in the DB — caller will skip the batch insert.
				return hashResult{cacheKey: ck, inserted: true}, nil
			}
			modTime := info.ModTime()
			return hashResult{
				cacheKey: ck,
				sample: &hopper.Sample{
					SHA256:      cached,
					Source:      source,
					Filename:    filepath.Base(path),
					FileType:    fileType,
					Label:       label,
					LabelSource: source,
					SizeBytes:   info.Size(),
					Path:        path,
					Mtime:       &modTime,
				},
			}, nil
		}
	}

	// Cache miss — open and read the file to compute SHA256.
	f, err := os.Open(path)
	if err != nil {
		return hashResult{}, err
	}
	defer f.Close() //nolint:errcheck // read-only file

	h := sha256.New()
	if _, err := io.Copy(h, f); err != nil {
		return hashResult{}, err
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
	return hashResult{cacheKey: ck, sample: s}, nil
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
		func(ctx context.Context, db *hopper.DB, _, limit int) ([]*hopper.Sample, error) {
			return db.FalsePositives(ctx, limit)
		})
}

func cmdFalseNegatives(ctx context.Context) error {
	return runReviewCommand(ctx, os.Args[2:], "false-negatives",
		func(ctx context.Context, db *hopper.DB, _, limit int) ([]*hopper.Sample, error) {
			return db.FalseNegatives(ctx, limit)
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
