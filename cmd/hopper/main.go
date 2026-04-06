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
	"net/url"
	"os"
	"os/exec"
	"os/signal"
	"path/filepath"
	"strconv"
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
  import-legacy   import from a legacy cyclotron sqlite database
  import          transfer samples between hopper databases (sqlite↔postgres)
  stats           show sample counts
`

func main() {
	if len(os.Args) < 2 {
		fmt.Fprint(os.Stderr, usageText)
		os.Exit(1)
	}
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt)

	err := run(ctx)
	stop()
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
	case "import-legacy":
		return cmdImportLegacy(ctx)
	case "import":
		return cmdImport(ctx)
	case "load":
		return cmdLoad(ctx)
	case "stats":
		return cmdStats(ctx)
	default:
		fmt.Fprint(os.Stderr, usageText)
		return errors.New("unknown command: " + os.Args[1])
	}
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
	f.Parse(os.Args[2:]) //nolint:errcheck,gosec // ExitOnError handles parse errors

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
		pg.Process.Kill() //nolint:errcheck,gosec // best-effort kill before exit
		return errors.New("postgres did not become ready within 15s")
	}

	// Create database (ignore "already exists" error).
	exec.CommandContext(ctx, "createdb", "-p", p, "-h", "localhost", "hopper").Run() //nolint:errcheck,gosec // ignore "already exists"

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

	pg.Wait() //nolint:errcheck,gosec // exit status not relevant
	return nil
}

func cmdInit(ctx context.Context) error {
	f := flag.NewFlagSet("init", flag.ExitOnError)
	dsn := f.String("db", "", "database (postgres:// DSN or sqlite file path)")
	f.Parse(os.Args[2:]) //nolint:errcheck,gosec // ExitOnError handles parse errors

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

func cmdImportLegacy(ctx context.Context) error {
	f := flag.NewFlagSet("import-legacy", flag.ExitOnError)
	dsn := f.String("db", "", "destination database (postgres:// DSN or sqlite path)")
	legacy := f.String("from", "", "path to legacy cyclotron sqlite database")
	after := f.Int64("after", 0, "resume after this SQLite rowid (from progress logs)")
	f.Parse(os.Args[2:]) //nolint:errcheck,gosec // ExitOnError handles parse errors

	if *legacy == "" {
		return errors.New("pass --from /path/to/cyclotron.db")
	}

	slog.Info("opening legacy database", "path", *legacy, "resume_after", *after)
	db, err := openDB(ctx, *dsn)
	if err != nil {
		return err
	}
	defer db.Close()
	slog.Info("running schema migrations")
	if err := db.Migrate(ctx); err != nil {
		return err
	}
	slog.Info("schema up to date, starting legacy import")

	n, err := hopper.MigrateLegacy(ctx, db, *legacy, *after)
	if err != nil {
		return err
	}
	slog.Info("legacy import complete", "samples", n)
	return nil
}

func cmdImport(ctx context.Context) error {
	f := flag.NewFlagSet("import", flag.ExitOnError)
	dstDSN := f.String("db", "", "destination database")
	srcDSN := f.String("from", "", "source database")
	afterSample := f.Int64("after", 0, "resume after this source sample ID (from progress logs)")
	afterReport := f.Int64("after-report", 0, "resume after this source report ID (from progress logs)")
	f.Parse(os.Args[2:]) //nolint:errcheck,gosec // ExitOnError handles parse errors

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

func cmdLoad(ctx context.Context) error {
	f := flag.NewFlagSet("load", flag.ExitOnError)
	dsn := f.String("db", "", "database connection string")
	bad := f.String("bad", "", "directory of known-bad samples")
	good := f.String("good", "", "directory of known-good samples")
	source := f.String("source", "harvest", "sample source tag")
	workers := f.Int("workers", 8, "concurrent hash/insert workers")
	cleaveBin := f.String("cleave", "cleave", "path to cleave binary (pass empty to disable)")
	cleaveWorkers := f.Int("cleave-workers", 8, "concurrent cleave analysis workers")
	maxRSSGB := f.Int("max-memory-gb", 0, "cleave RSS limit in GB (default: 25% of system RAM)")
	rescan := f.Bool("rescan", false, "re-analyze samples that already have cleave results")
	f.Parse(os.Args[2:]) //nolint:errcheck,gosec // ExitOnError handles parse errors

	if *bad == "" && *good == "" {
		return errors.New("pass --bad and/or --good")
	}

	slog.Info("load starting", "bad", *bad, "good", *good, "workers", *workers, "rescan", *rescan)
	db, err := openDB(ctx, *dsn)
	if err != nil {
		return err
	}
	defer db.Close()
	slog.Info("running schema migrations")
	if err := db.Migrate(ctx); err != nil {
		return err
	}

	// Collect directories for cleave's --dangerous-local-file-paths.
	var dirs []string
	if *bad != "" {
		if abs, err := filepath.Abs(*bad); err == nil {
			dirs = append(dirs, abs)
		}
	}
	if *good != "" {
		if abs, err := filepath.Abs(*good); err == nil {
			dirs = append(dirs, abs)
		}
	}

	// Start cleave server if requested.
	var cleave *cleaveServer
	if *cleaveBin != "" {
		cleave = newCleaveServer(cleaveConfig{
			Bin:        *cleaveBin,
			Dirs:       dirs,
			MaxRSSGB:   *maxRSSGB,
			MaxWorkers: *cleaveWorkers,
		})
		if err := cleave.Start(ctx); err != nil {
			return err
		}
		defer cleave.Stop()
		go func() {
			if err := cleave.Monitor(ctx); err != nil {
				slog.Error("cleave monitor failed", "error", err)
			}
		}()
	}

	var total int64
	if *bad != "" {
		n := loadDir(ctx, db, cleave, *bad, "bad", *source, *workers, *rescan)
		total += int64(n)
	}
	if *good != "" {
		n := loadDir(ctx, db, cleave, *good, "good", *source, *workers, *rescan)
		total += int64(n)
	}
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
type loadProgress struct {
	walked   atomic.Int64
	hashed   atomic.Int64
	inserted atomic.Int64
	skipped  atomic.Int64
	analyzed atomic.Int64
	errors   atomic.Int64
}

const loadBatchSize = 500

func loadDir(ctx context.Context, db *hopper.DB, cleave *cleaveServer, dir, label, source string, nworkers int, rescan bool) int {
	slog.Info("loading directory", "dir", dir, "label", label, "workers", nworkers)
	start := time.Now()
	var progress loadProgress

	paths := make(chan string, nworkers*2)
	hashed := make(chan hashedFile, nworkers*2)
	var hashWG sync.WaitGroup

	// Analysis queue: nil if cleave is not configured.
	var analyzeQueue chan loadJob
	var analyzeWG sync.WaitGroup
	if cleave != nil {
		analyzeQueue = make(chan loadJob, cleave.Workers()*2)
		startAnalysisWorkers(ctx, db, cleave, analyzeQueue, &analyzeWG, &progress)
	}

	// Periodic progress reporting.
	ticker := time.NewTicker(5 * time.Second)
	done := make(chan struct{})
	go func() {
		for {
			select {
			case <-ticker.C:
				elapsed := time.Since(start).Seconds()
				slog.Info("load progress", "dir", dir,
					"walked", progress.walked.Load(), "hashed", progress.hashed.Load(),
					"inserted", progress.inserted.Load(),
					"skipped", progress.skipped.Load(), "analyzed", progress.analyzed.Load(),
					"errors", progress.errors.Load(),
					"files_per_sec", int(float64(progress.hashed.Load())/elapsed))
			case <-done:
				return
			}
		}
	}()

	// Hash workers: read files and compute SHA256, send to batch inserter.
	for range nworkers {
		hashWG.Go(func() {
			for path := range paths {
				if ctx.Err() != nil {
					return
				}
				sample, err := hashFile(path, label, source)
				if err != nil {
					progress.errors.Add(1)
					slog.Warn("skipping file", "path", path, "error", err)
					continue
				}
				progress.hashed.Add(1)
				select {
				case hashed <- hashedFile{sample: sample, path: path}:
				case <-ctx.Done():
					return
				}
			}
		})
	}

	// Batch inserter: collects hashed files and flushes in batches.
	var insertWG sync.WaitGroup
	insertWG.Go(func() {
		batch := make([]hashedFile, 0, loadBatchSize)

		flush := func() {
			if len(batch) == 0 {
				return
			}
			samples := make([]*hopper.Sample, len(batch))
			for i, h := range batch {
				samples[i] = h.sample
			}
			n, err := db.InsertSampleBatch(ctx, samples)
			if err != nil {
				slog.Error("batch insert failed", "error", err, "batch_size", len(batch))
				progress.errors.Add(int64(len(batch)))
				batch = batch[:0]
				return
			}
			progress.inserted.Add(n)
			progress.skipped.Add(int64(len(batch)) - n)

			// Enqueue for cleave analysis. With --rescan, enqueue everything.
			// Without, enqueue all samples from batches that had any new inserts —
			// analysis is idempotent so re-analyzing a few duplicates is fine,
			// and avoids per-row DB lookups to check which were new.
			hasNew := n > 0
			for _, h := range batch {
				enqueueAnalysis(ctx, analyzeQueue, h.path, h.sample.SHA256, hasNew, rescan)
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

	walkFiles(ctx, dir, paths, &progress)
	close(paths)
	hashWG.Wait()
	close(hashed)
	insertWG.Wait()

	if analyzeQueue != nil {
		close(analyzeQueue)
		analyzeWG.Wait()
	}

	ticker.Stop()
	close(done)

	slog.Info("directory complete", "dir", dir,
		"walked", progress.walked.Load(), "hashed", progress.hashed.Load(),
		"inserted", progress.inserted.Load(),
		"skipped", progress.skipped.Load(), "analyzed", progress.analyzed.Load(),
		"errors", progress.errors.Load(),
		"elapsed", time.Since(start).Round(time.Millisecond))

	return int(progress.inserted.Load() + progress.skipped.Load())
}

func startAnalysisWorkers(ctx context.Context, db *hopper.DB, cleave *cleaveServer, queue chan loadJob, wg *sync.WaitGroup, progress *loadProgress) {
	for range cleave.Workers() {
		wg.Go(func() {
			for job := range queue {
				if ctx.Err() != nil {
					return
				}
				raw, result, err := cleave.Analyze(ctx, job.sha, job.path)
				if err != nil {
					progress.errors.Add(1)
					slog.Warn("analysis failed", "path", job.path, "error", err)
					continue
				}
				if err := db.UpdateCleaveResult(ctx, job.sha, raw, result.CanonicalSHA256); err != nil {
					progress.errors.Add(1)
					slog.Warn("storing result failed", "path", job.path, "error", err)
					continue
				}
				progress.analyzed.Add(1)

				// Explode archive members into individual sample rows.
				parent, err := db.SampleBySHA256(ctx, job.sha)
				if err != nil {
					slog.Warn("fetch for explosion failed", "sha256", job.sha, "error", err)
					continue
				}
				if n, err := db.ExplodeArchiveMembers(ctx, parent); err != nil {
					slog.Warn("archive explosion failed", "sha256", job.sha, "error", err)
				} else if n > 0 {
					slog.Info("exploded archive members", "sha256", job.sha, "members", n)
				}
			}
		})
	}
}

func enqueueAnalysis(ctx context.Context, queue chan loadJob, path, sha string, enqueue, rescan bool) {
	if queue == nil {
		return
	}
	if !enqueue && !rescan {
		return
	}
	select {
	case queue <- loadJob{path: path, sha: sha}:
	case <-ctx.Done():
	}
}

func walkFiles(ctx context.Context, dir string, paths chan<- string, progress *loadProgress) {
	slog.Info("walking directory", "dir", dir)
	filepath.WalkDir(dir, func(path string, d fs.DirEntry, err error) error { //nolint:errcheck,gosec // errors logged per-file
		if err != nil || d.IsDir() {
			return err
		}
		progress.walked.Add(1)
		select {
		case paths <- path:
			return nil
		case <-ctx.Done():
			return ctx.Err()
		}
	})
	slog.Info("walk complete", "dir", dir, "files", progress.walked.Load())
}

func hashFile(path, label, source string) (*hopper.Sample, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer f.Close() //nolint:errcheck // read-only file

	info, err := f.Stat()
	if err != nil {
		return nil, err
	}

	h := sha256.New()
	if _, err := io.Copy(h, f); err != nil {
		return nil, err
	}

	return &hopper.Sample{
		SHA256:      hex.EncodeToString(h.Sum(nil)),
		Source:      source,
		Filename:    filepath.Base(path),
		Label:       label,
		LabelSource: source,
		SizeBytes:   info.Size(),
		Path:        path,
	}, nil
}

func cmdStats(ctx context.Context) error {
	f := flag.NewFlagSet("stats", flag.ExitOnError)
	dsn := f.String("db", "", "postgres connection string")
	f.Parse(os.Args[2:]) //nolint:errcheck,gosec // ExitOnError handles parse errors

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
		fmt.Printf("%-10s %d\n", label, n)
		total += n
	}
	fmt.Printf("%-10s %d\n", "total", total)
	return nil
}
