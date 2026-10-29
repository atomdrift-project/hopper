package main

import (
	"context"
	"errors"
	"flag"
	"os"
)

func cmdMigratePurgatory(ctx context.Context) error {
	f := flag.NewFlagSet("migrate-purgatory", flag.ExitOnError)
	dsn := f.String("db", "", "database DSN (default: $DATABASE_URL)")
	dataRoot := f.String("data", "", "full corpus directory; ingestion and other movers must be paused")
	apply := f.Bool("apply", false, "move files and rename labels (default: dry-run)")
	dryRun := f.Bool("dry-run", false, "preview the migration without changing files or catalog rows")
	parseFlags(f, os.Args[2:])
	if *dataRoot == "" {
		return errors.New("migrate-purgatory: --data is required (run on the full corpus host)")
	}
	if *apply && *dryRun {
		return errors.New("migrate-purgatory: --apply and --dry-run are mutually exclusive")
	}
	db, err := openDB(ctx, *dsn)
	if err != nil {
		return err
	}
	defer db.Close()
	stats, err := db.MigratePurgatory(ctx, *dataRoot, *apply)
	verb := "planned"
	if *apply {
		verb = "completed"
	}
	writeStdoutf("%s: %d file moves, %d member paths, %d label renames; %d failed locations\n",
		verb, stats.Locations, stats.Members, stats.Labels, stats.Failed)
	return err
}
