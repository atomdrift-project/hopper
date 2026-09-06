package main

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"log/slog"
	"os"
	"path/filepath"

	"github.com/atomdrift-project/hopper"
)

// backfillDatasetPage is how many candidate rows one page of the backfill
// reads; each row costs a stat and a small file read on the data root.
const backfillDatasetPage = 500

// cmdBackfillDatasetMetadata repairs the rows a walk wrote from a dataset tree
// before it understood the tree's registry documents (see datasetmeta.go).
// For every top-level artifact under --path-prefix with no provenance it reads
// the document beside the file on --data and, with --apply, stores the
// synthesized sidecar and adopts its identity claims over the filename guesses
// the walk stored (package "forge" → "@servicetitan/forge", purl_base, feed,
// tarball URL). --purge additionally runs the dataset_metadata cleanup stage,
// deleting the documents (and their exploded members) that were ingested as
// samples. Dry-run by default; idempotent, so it is safe to re-run after a
// partial pass or when a new dataset lands.
func cmdBackfillDatasetMetadata(ctx context.Context) error {
	f := flag.NewFlagSet("backfill-dataset-metadata", flag.ExitOnError)
	dsn := f.String("db", "", "database connection string")
	dataDir := f.String("data", "", "fully mounted sample data root")
	prefix := f.String("path-prefix", "bad/datasets/", "only rows whose stored path starts with this")
	apply := f.Bool("apply", false, "write provenance (and delete with --purge); default is report only")
	purge := f.Bool("purge", false, "also delete the registry documents ingested as samples (dataset_metadata cleanup stage)")
	parseFlags(f, os.Args[2:])

	if *dataDir == "" {
		return errors.New("pass --data <directory> (the fully-mounted sample tree)")
	}
	if resolved, err := filepath.EvalSymlinks(*dataDir); err == nil {
		*dataDir = resolved
	}
	if abs, err := filepath.Abs(*dataDir); err == nil {
		*dataDir = abs
	}

	db, err := openDB(ctx, *dsn)
	if err != nil {
		return err
	}
	defer db.Close()
	if err := db.Migrate(ctx); err != nil {
		return err
	}

	stats, err := backfillDatasetProvenance(ctx, db, *dataDir, *prefix, *apply)
	if err != nil {
		return err
	}
	verb := "would attach"
	if *apply {
		verb = "attached"
	}
	writeStdoutf("%s provenance to %d artifact(s); %d without a usable document; %d not on disk\n",
		verb, stats.attached, stats.noDocument, stats.missing)

	if *purge {
		stage, ok := hopper.CleanupStageByName("dataset_metadata")
		if !ok {
			return errors.New("dataset_metadata cleanup stage is not defined")
		}
		n, err := db.CountCleanup(ctx, stage)
		if err != nil {
			return err
		}
		if !*apply {
			writeStdoutf("would delete %d row(s) — %s\n", n, stage.Description)
		} else if n > 0 {
			deleted, err := db.ApplyCleanup(ctx, stage)
			if err != nil {
				return err
			}
			writeStdoutf("deleted %d row(s) — %s\n", deleted, stage.Description)
		}
	}
	if !*apply {
		writeStdoutLine("re-run with --apply to write")
	}
	return nil
}

// backfillDatasetStats counts one pass of backfillDatasetProvenance.
type backfillDatasetStats struct {
	attached   int // rows paired with a document (written when applying)
	noDocument int // rows on disk with no document the reader accepts
	missing    int // rows whose path is not on the data root
}

// backfillDatasetProvenance pages the provenance-less artifacts under prefix
// and pairs each with the registry document beside it, writing when apply is
// set. The row's stored columns are the starting point, exactly as they would
// be for a walk's cache hit, so the document's claims replace only what the
// document actually knows.
func backfillDatasetProvenance(ctx context.Context, db *hopper.DB, dataDir, prefix string, apply bool) (backfillDatasetStats, error) {
	var stats backfillDatasetStats
	var afterID int64
	for page := 1; ; page++ {
		if page%20 == 0 {
			slog.Info("dataset backfill progress", "attached", stats.attached, "no_document", stats.noDocument, "missing", stats.missing)
		}
		rows, err := db.DatasetArtifactsWithoutProvenance(ctx, prefix, afterID, backfillDatasetPage)
		if err != nil {
			return stats, err
		}
		if len(rows) == 0 {
			return stats, nil
		}
		for _, s := range rows {
			afterID = s.ID
			abs := filepath.Join(dataDir, filepath.FromSlash(s.Path))
			if _, err := os.Stat(abs); err != nil {
				stats.missing++
				continue
			}
			c := *s
			c.Path = abs
			attachDatasetMetadata(&c, abs)
			if c.Provenance == nil {
				stats.noDocument++
				continue
			}
			stats.attached++
			if stats.attached <= 5 {
				slog.Info("dataset provenance", "path", s.Path, "package", c.Package, "version", c.Version,
					"purl_base", c.PURLBase, "was_package", s.Package, "apply", apply)
			}
			if !apply {
				continue
			}
			ok, err := db.AdoptProvenance(ctx, &c)
			if err != nil {
				return stats, fmt.Errorf("adopt provenance %s: %w", s.SHA256, err)
			}
			if !ok {
				slog.Warn("sample vanished during backfill", "sha256", s.SHA256)
			}
		}
	}
}
