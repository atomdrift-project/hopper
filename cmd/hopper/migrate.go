package main

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"log/slog"
	"maps"
	"os"
	"runtime"
	"slices"
	"strconv"
	"strings"

	"github.com/atomdrift-project/hopper/internal/migrate"
	"github.com/jackc/pgx/v5/pgxpool"
)

// cmdMigrate builds the verdict schema from the legacy tables in the same
// database (MIGRATION_PLAN.md, part 2). Hopper must be stopped: nothing may
// write the legacy tables while it runs. It continues where an earlier run
// stopped. With --verify it only checks a finished migration against the
// legacy rows, writes nothing, and fails if any check finds a row.
//
// Its own connections commit without waiting for the WAL flush: a run cut
// short by a crash redoes the stage it was in, and redoing writes nothing,
// so durability per commit buys nothing here. Index builds get the memory
// and workers --maintenance-mem and --maintenance-workers name.
func cmdMigrate(ctx context.Context) error {
	f := flag.NewFlagSet("migrate", flag.ExitOnError)
	dsn := f.String("db", "", "database DSN (default: $DATABASE_URL)")
	from := f.String("from", "public", "schema holding the legacy tables")
	to := f.String("to", "verdict", "schema to build the verdict tables in")
	workers := f.Int("workers", runtime.NumCPU()/2, "parallel converters")
	batch := f.Int64("batch", 50_000, "legacy sample ids per range")
	production := f.Bool("production", false, "allow the production database (hopper-db)")
	verify := f.Bool("verify", false, "only check a finished migration; write nothing")
	maintMem := f.String("maintenance-mem", "4GB", "maintenance_work_mem for the index builds")
	maintWorkers := f.Int("maintenance-workers", 8, "max_parallel_maintenance_workers for the index builds")
	parseFlags(f, os.Args[2:])
	if *dsn == "" {
		*dsn = os.Getenv("DATABASE_URL")
	}
	if *dsn == "" {
		return errors.New("migrate: --db or $DATABASE_URL is required")
	}
	cfg, err := pgxpool.ParseConfig(*dsn)
	if err != nil {
		return fmt.Errorf("migrate: %w", err)
	}
	if strings.Contains(cfg.ConnConfig.Host, "hopper-db") && !*production {
		return errors.New("migrate: refusing hopper-db without --production")
	}
	cfg.ConnConfig.RuntimeParams["search_path"] = *to
	cfg.ConnConfig.RuntimeParams["application_name"] = "hopper-migrate"
	if !*verify {
		cfg.ConnConfig.RuntimeParams["synchronous_commit"] = "off"
		cfg.ConnConfig.RuntimeParams["maintenance_work_mem"] = *maintMem
		cfg.ConnConfig.RuntimeParams["max_parallel_maintenance_workers"] = strconv.Itoa(max(*maintWorkers, 0))
	}
	cfg.MaxConns = int32(min(max(*workers, 1), 1000) + 2)
	pool, err := pgxpool.NewWithConfig(ctx, cfg)
	if err != nil {
		return fmt.Errorf("migrate: %w", err)
	}
	defer pool.Close()
	opt := migrate.Options{From: *from, To: *to, Workers: *workers, Batch: *batch}
	if *verify {
		checks, err := migrate.Verify(ctx, pool, opt)
		failed := 0
		for _, c := range checks {
			mark := "ok  "
			if c.Count != 0 {
				mark, failed = "FAIL", failed+1
			}
			writeStdoutf("%s %10d  %s\n", mark, c.Count, c.Name)
		}
		if err == nil && failed > 0 {
			err = fmt.Errorf("migrate: %d of %d checks found rows", failed, len(checks))
		}
		return err
	}
	slog.Info("migrate", "dsn", redactDSN(*dsn), "from", *from, "to", *to, "workers", *workers)
	r, err := migrate.Run(ctx, pool, opt)
	if r != nil {
		writeStdoutf("names %d, samples %d, results %d (%d files, %d refused), locations %d\n",
			r.Names, r.Samples, r.Converted, r.Files, r.Failed, r.Locations)
		writeStdoutf("excerpts %d not converted, %d of their rows dropped\n", r.Excerpts, r.Dropped)
		writeStdoutf("sightings %d (%d respelled), reports %d, carried %d, cited %d, queued %d\n",
			r.Sightings, r.Respelled, r.Reports, r.Carried, r.Marked, r.Queued)
		for _, reason := range slices.Sorted(maps.Keys(r.Failures)) {
			writeStdoutf("refused %6d: %s\n", r.Failures[reason], reason)
		}
		for stage, took := range r.Took {
			writeStdoutf("stage %-10s %s\n", stage, took)
		}
	}
	return err
}
