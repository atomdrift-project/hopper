// Package main is the hopper CLI for managing the sample registry.
package main

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"flag"
	"fmt"
	"io"
	"io/fs"
	"log/slog"
	"math"
	"math/rand/v2"
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
  serve           start a local postgres server with hopper schema
  init            create/migrate a hopper database (sqlite or postgres)
  load            load sample files from directories
  reset           delete all samples and reports (preserves schema)
  import          transfer samples between hopper databases (sqlite↔postgres)
  false-positives list known-good files that still score bad
  false-negatives list known-bad files that still score benign
  benign-review   list marker-benign files whose score still looks bad
  bad-review      list marker-bad files whose score still looks benign
  stats           show sample counts
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
		dsn = "postgres://hopper@localhost:5432/hopper"
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
	litmusBin := f.String("litmus", "litmus", "path to litmus binary (pass empty to disable)")
	litmusWorkers := f.Int("litmus-workers", max(1, runtime.NumCPU()-1), "concurrent litmus analysis workers")
	maxRSSGB := f.Int("max-memory-gb", 32, "litmus RSS limit in GB")
	analysisTimeout := f.Int("analysis-timeout", 600, "per-file analysis timeout in seconds (passed to litmus)")
	rescan := f.Bool("rescan", false, "re-analyze samples that already have litmus results")
	noCache := f.Bool("no-cache", false, "disable hash cache (re-read every file)")
	maxAnalyzed := f.Int("max-analyzed", 0, "stop after N successful analyses (0 = unlimited)")
	experimentTag := f.String("experiment-tag", "", "label for experiment comparison")
	litmusVerbose := f.Bool("litmus-verbose", false, "enable debug logging in litmus server")
	parseFlags(f, os.Args[2:])

	if *dataDir == "" {
		return errors.New("pass --data <directory> (expects bad/, good/, unknown/ subdirectories)")
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

	var shared loadProgress
	shared.analyzeDurationMin.Store(math.MaxInt64)

	loadCtx, loadCancel := context.WithCancel(ctx)
	defer loadCancel()

	total := loadAll(loadCtx, loadCancel, db, litmus, cache, loadDirs, *source, *workers, *rescan, *maxAnalyzed, *experimentTag, &shared)
	slog.Info("load complete", "samples", total)
	return nil
}

// loadJob is a file to be loaded and optionally analyzed.
type loadJob struct {
	path string
	sha  string // set after hashing
}

// hashedFile is a file that has been read and hashed, ready for DB insert.
type hashedFile struct {
	sample *hopper.Sample
	path   string
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
	loadBatchSize = 500
	minFileSize   = 13      // skip trivially small files (markers, empty, etc.)
	maxFileSize   = 1 << 30 // 1 GiB
)

var (
	errTooSmall = errors.New("too small")
	errTooLarge = errors.New("too large")
)

//nolint:gocognit,revive,maintidx // coordinates the end-to-end load pipeline in one place.
func loadAll(ctx context.Context, cancel context.CancelFunc, db *hopper.DB, litmus *litmusServer, cache *hashCache, dirs []struct{ dir, label string }, source string, nworkers int, rescan bool, maxAnalyzed int, experimentTag string, shared *loadProgress) int {
	slog.Info("loading", "dirs", len(dirs), "workers", nworkers)
	start := time.Now()
	var progress loadProgress
	progress.analyzeDurationMin.Store(math.MaxInt64)

	// Initialize already-analyzed count for the dashboard.
	if n, err := db.CountAnalyzed(ctx); err == nil {
		progress.analyzed.Store(n)
		progress.queued.Store(n)
	}

	paths := make(chan labeledPath, nworkers*2)
	hashed := make(chan hashedFile, nworkers*2)
	var hashWG sync.WaitGroup

	// Analysis queue: nil if litmus is not configured.
	var analyzeQueue chan loadJob
	var analyzeWG sync.WaitGroup
	if litmus != nil {
		analyzeQueue = make(chan loadJob, litmus.Workers()*2)
		startAnalysisWorkers(ctx, cancel, db, litmus, analyzeQueue, &analyzeWG, &progress, shared, litmus.Workers(), maxAnalyzed)
	}

	// Periodic progress reporting.
	ticker := time.NewTicker(10 * time.Second)
	if !isTTY() {
		ticker.Reset(30 * time.Second)
	}

	done := make(chan struct{})
	var prevAnalyzed int64
	go func() {
		defer ticker.Stop()
		for {
			select {
			case <-ticker.C:
				analyzed := progress.analyzed.Load()
				recentRate := float64(analyzed-prevAnalyzed) / 10.0
				if !isTTY() {
					recentRate = float64(analyzed-prevAnalyzed) / 30.0
				}
				prevAnalyzed = analyzed
				walked := progress.walked.Load()
				hashedN := progress.hashed.Load()
				inserted := progress.inserted.Load()
				skipped := progress.skipped.Load()

				// Stage percentages.
				hashDone := hashedN + progress.tooSmall.Load() + progress.tooLarge.Load() + progress.hashErrors.Load()
				analyzeTarget := progress.queued.Load()
				if maxAnalyzed > 0 && int64(maxAnalyzed) < analyzeTarget {
					analyzeTarget = int64(maxAnalyzed)
				}

				if isTTY() {
					// Build progress bars
					writeStdout("\033[H\033[2J")
					writeStdoutf("\033[1mHopper Loading Dashboard\033[0m (%s)\n", time.Since(start).Round(time.Second))
					writeStdoutLine(strings.Repeat("─", 60))

					drawBar("Hashing  ", hashDone, walked, "", "\033[34m")          // Blue
					drawBar("Insertion", inserted+skipped, hashedN, "", "\033[32m") // Green

					var analyzeInfo string
					if recentRate > 0 {
						// Overall ETA based on everything walked
						targetTotal := walked
						if maxAnalyzed > 0 && int64(maxAnalyzed) < targetTotal {
							targetTotal = int64(maxAnalyzed)
						}
						remaining := targetTotal - analyzed
						if remaining > 0 {
							etaSec := float64(remaining) / recentRate
							eta := (time.Duration(etaSec) * time.Second).Round(time.Second)
							analyzeInfo = fmt.Sprintf("%.1f/s ETA %s", recentRate, eta)
						}
					}
					// Show analysis bar out of what's already inserted, but info shows overall ETA
					drawBar("Analysis ", analyzed, analyzeTarget, analyzeInfo, "\033[33m") // Yellow

					writeStdoutLine(strings.Repeat("─", 60))
					if last, ok := progress.lastErr.Load().(string); ok && last != "" {
						writeStdoutf("\033[31mRecent Error:\033[0m %s\n", last)
						writeStdoutLine(strings.Repeat("─", 60))
					}

					if litmus != nil {
						summary := litmus.workerSummary()
						writeStdoutf("Litmus: %d busy, %d idle | oldest: %s (%s)\n",
							summary.Busy, summary.Idle, summary.OldestFile,
							(time.Duration(summary.OldestMS) * time.Millisecond).Round(time.Second))

						health := litmus.pollHealth(ctx)
						if health != nil {
							writeStdoutf("Health: %.2f load, %d MB RSS, %d active tasks\n",
								health.Load, health.RSSMB, health.ActiveTasks)
						}
					}
					writeStdoutf("Errors: %d | Walked: %d | Cache Hits: %d\n",
						progress.errors.Load(), walked, progress.cacheHits.Load())
				} else {
					// Fallback to slog for non-TTY
					attrs := []any{
						"dirs", len(dirs),
						"walked", walked, "hashed", hashedN,
						"inserted", inserted, "skipped", skipped,
						"analyzed", analyzed, "errors", progress.errors.Load(),
					}
					if walked > 0 {
						attrs = append(attrs, "hash_pct", fmt.Sprintf("%.0f%%", float64(hashDone)/float64(walked)*100))
					}
					if analyzeTarget > 0 {
						attrs = append(attrs, "analyze_pct", fmt.Sprintf("%.0f%%", float64(analyzed)/float64(analyzeTarget)*100))
					}
					slog.Info("load progress", attrs...)
				}
			case <-done:
				return
			}
		}
	}()

	// Hash workers: read files, check markers, compute SHA256, send to batch inserter.
	for range nworkers {
		hashWG.Go(func() {
			for lp := range paths {
				if ctx.Err() != nil {
					return
				}

				sample, err := hashFile(ctx, lp.path, lp.label, source, cache, &progress)
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

				// Check for misclassification markers that contradict the label.
				if marker, markerMtime := markerInfo(lp.path); marker != "" {
					if (lp.label == "bad" && marker == "benign") || (lp.label == "good" && marker == "bad") {
						progress.markers.Add(1)
						sample.Label = marker
						if marker == "benign" {
							sample.Label = "good"
						}
						sample.LabelSource = "marker"
						sample.Skip = "misclassified"
						sample.MarkerMtime = markerMtime
						slog.Info("misclassified file", "path", lp.path, "original_label", lp.label, "marker", marker)
					}
				}

				progress.hashed.Add(1)
				select {
				case hashed <- hashedFile{sample: sample, path: lp.path}:
				case <-ctx.Done():
					return
				}
			}
		})
	}

	// Pending analysis: large buffer so hashing can proceed even if analysis is slow.
	pendingAnalysis := make(chan loadJob, 2_000_000)

	// Batch inserter: collects hashed files and flushes in batches.
	var insertWG sync.WaitGroup
	insertWG.Go(func() {
		defer close(pendingAnalysis)
		batch := make([]hashedFile, 0, loadBatchSize)

		flush := func() {
			if len(batch) == 0 {
				return
			}
			samples := make([]*hopper.Sample, len(batch))
			for i, h := range batch {
				samples[i] = h.sample
			}
			// Detect intra-batch SHA256 duplicates for diagnostics.
			seen := make(map[string]string, len(batch))
			intraDups := 0
			for _, h := range batch {
				if prev, ok := seen[h.sample.SHA256]; ok {
					intraDups++
					slog.Debug("intra-batch duplicate SHA256",
						"sha256", h.sample.SHA256,
						"path", h.path,
						"duplicate_of", prev)
				} else {
					seen[h.sample.SHA256] = h.path
				}
			}

			n, needsAnalysis, err := db.InsertSampleBatch(ctx, samples)
			if err != nil {
				if ctx.Err() != nil {
					slog.Debug("batch insert skipped (shutting down)", "batch_size", len(batch))
				} else {
					slog.Error("batch insert failed", "error", err, "batch_size", len(batch))
					progress.errors.Add(int64(len(batch)))
				}
				batch = batch[:0]
				return
			}
			progress.inserted.Add(n)
			skipped := int64(len(batch)) - n
			progress.skipped.Add(skipped)

			crossBatchDups := skipped - int64(intraDups)
			slog.Debug("batch flush",
				"batch_size", len(batch),
				"inserted", n,
				"skipped", skipped,
				"intra_batch_dups", intraDups,
				"cross_batch_dups", crossBatchDups,
				"unique_hashes", len(seen))

			// Send to analysis feeder without blocking the inserter.
			if analyzeQueue != nil {
				// Map SHA to path for the jobs.
				shaToPath := make(map[string]string, len(batch))
				for _, h := range batch {
					shaToPath[h.sample.SHA256] = h.path
				}

				toAnalyze := needsAnalysis
				if rescan {
					toAnalyze = make([]string, 0, len(batch))
					for _, h := range batch {
						toAnalyze = append(toAnalyze, h.sample.SHA256)
					}
				}

				for _, sha := range toAnalyze {
					path, ok := shaToPath[sha]
					if !ok {
						continue // should not happen
					}
					select {
					case pendingAnalysis <- loadJob{path: path, sha: sha}:
						progress.queued.Add(1)
					case <-ctx.Done():
						slog.Debug("inserter flush cancelled", "dirs", len(dirs), "pending_queue_len", len(pendingAnalysis))
						return
					}
				}
			}
			batch = batch[:0]
		}

		for h := range hashed {
			batch = append(batch, h)
			if len(batch) >= loadBatchSize {
				flush()
			}
		}
		flush()
	})

	// Analysis feeder: drains pendingAnalysis into the bounded analyzeQueue,
	// decoupling the inserter from slow analysis workers.
	var feederWG sync.WaitGroup
	if analyzeQueue != nil {
		feederWG.Go(func() {
			for job := range pendingAnalysis {
				select {
				case analyzeQueue <- job:
				case <-ctx.Done():
					slog.Debug("feeder cancelled", "dirs", len(dirs), "remaining_pending", len(pendingAnalysis))
					return
				}
			}
			slog.Debug("feeder drained")
		})
	}

	walkAndShuffle(ctx, dirs, paths, &progress)
	slog.Debug("shutdown", "step", "walk complete, closing paths")
	close(paths)
	hashWG.Wait()
	slog.Debug("shutdown", "dirs", len(dirs), "step", "hash workers done, closing hashed")
	close(hashed)
	insertWG.Wait() // also closes pendingAnalysis
	slog.Debug("shutdown", "dirs", len(dirs), "step", "inserter done")
	feederWG.Wait() // drains pendingAnalysis into analyzeQueue
	slog.Debug("shutdown", "dirs", len(dirs), "step", "feeder done")

	if analyzeQueue != nil {
		close(analyzeQueue)
		analyzeWG.Wait()
		slog.Debug("shutdown", "dirs", len(dirs), "step", "analysis workers done")
	}

	ticker.Stop()
	close(done)

	analyzed := progress.analyzed.Load()
	elapsed := time.Since(start)
	completeAttrs := []any{
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
		avgMs := progress.analyzeDurationSum.Load() / analyzed / int64(time.Millisecond)
		maxMs := progress.analyzeDurationMax.Load() / int64(time.Millisecond)
		minMs := progress.analyzeDurationMin.Load() / int64(time.Millisecond)
		throughput := float64(analyzed) / elapsed.Seconds()
		completeAttrs = append(completeAttrs,
			"avg_score", int(progress.scoreSum.Load()/analyzed),
			"throughput_per_sec", fmt.Sprintf("%.2f", throughput),
			"analyze_avg_ms", avgMs,
			"analyze_min_ms", minMs,
			"analyze_max_ms", maxMs,
		)
	}
	if experimentTag != "" {
		completeAttrs = append(completeAttrs, "experiment", experimentTag)
	}
	slog.Info("directory complete", completeAttrs...)

	return int(progress.inserted.Load() + progress.skipped.Load())
}

//nolint:revive // config is split across explicit parameters to keep call sites direct.
func startAnalysisWorkers(
	ctx context.Context,
	cancel context.CancelFunc,
	db *hopper.DB,
	litmus *litmusServer,
	queue chan loadJob,
	wg *sync.WaitGroup,
	progress *loadProgress,
	shared *loadProgress,
	nworkers int,
	maxAnalyzed int,
) {
	for workerID := range nworkers {
		wg.Go(func() {
			for job := range queue {
				if ctx.Err() != nil {
					slog.Debug("analysis worker exiting", "reason", "context cancelled")
					return
				}

				litmus.TrackWorker(workerID, filepath.Base(job.path))
				t0 := time.Now()
				result, err := litmus.Analyze(ctx, job.sha, job.path)
				litmus.TrackWorker(workerID, "")
				dur := time.Since(t0).Nanoseconds()

				if err != nil {
					progress.errors.Add(1)
					progress.lastErr.Store(fmt.Sprintf("analyze: %s: %v", filepath.Base(job.path), err))
					slog.Warn("analysis failed", "path", job.path, "error", err)
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

// labeledPath is a file path with its classification label.
type labeledPath struct {
	path  string
	label string
}

// walkAndShuffle walks all directories, collects file paths with labels,
// shuffles them randomly, and sends them to the channel. Shuffling ensures
// progress across all ecosystems rather than processing one directory at a time.
func walkAndShuffle(ctx context.Context, dirs []struct{ dir, label string }, paths chan<- labeledPath, progress *loadProgress) {
	var all []labeledPath
	for _, d := range dirs {
		slog.Info("walking directory", "dir", d.dir, "label", d.label)
		if err := filepath.WalkDir(d.dir, func(path string, entry fs.DirEntry, err error) error {
			if err != nil {
				return err
			}
			if !entry.Type().IsRegular() {
				if entry.IsDir() && entry.Name() == ".git" {
					return fs.SkipDir
				}
				return nil
			}
			if isMarkerFile(entry.Name()) {
				return nil
			}
			all = append(all, labeledPath{path: path, label: d.label})
			return nil
		}); err != nil {
			slog.Warn("walk directory failed", "dir", d.dir, "error", err)
		}
	}

	// Shuffle for even progress across directories and ecosystems.
	rng := rand.New(rand.NewPCG(rand.Uint64(), rand.Uint64())) //nolint:gosec // not crypto
	rng.Shuffle(len(all), func(i, j int) { all[i], all[j] = all[j], all[i] })

	slog.Info("walk complete", "files", len(all))
	progress.walked.Store(int64(len(all)))

	for _, lp := range all {
		select {
		case paths <- lp:
		case <-ctx.Done():
			return
		}
	}
}

func hashFile(ctx context.Context, path, label, source string, cache *hashCache, progress *loadProgress) (*hopper.Sample, error) {
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

type sampleListFunc func(context.Context, *hopper.DB, int, int) ([]*hopper.Sample, error)

func reviewFlags(name string) (*flag.FlagSet, *string, *int, *int, *bool) {
	f := flag.NewFlagSet(name, flag.ExitOnError)
	dsn := f.String("db", "", "database connection string")
	score := f.Int("threshold", 85, "score threshold")
	f.IntVar(score, "score", 85, "score threshold (deprecated: use --threshold)")
	limit := f.Int("limit", 100, "maximum rows to print")
	flush := f.Bool("flush", false, "delete matching review markers and restore the underlying label")
	return f, dsn, score, limit, flush
}

func runReviewCommand(ctx context.Context, args []string, name string, list sampleListFunc) error {
	f, dsn, score, limit, flush := reviewFlags(name)
	parseFlags(f, args)

	db, err := openDB(ctx, *dsn)
	if err != nil {
		return err
	}
	defer db.Close()

	samples, err := list(ctx, db, *score, *limit)
	if err != nil {
		return err
	}
	if *flush {
		if err := flushReviewSamples(ctx, db, name, samples); err != nil {
			return err
		}
		return nil
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
	days := int(time.Since(*ts).Hours() / 24)
	if days < 0 {
		days = 0
	}
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
