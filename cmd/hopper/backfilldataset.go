package main

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"log/slog"
	"maps"
	"os"
	"path/filepath"
	"slices"
	"strings"

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
// samples.
//
// Dry-run by default, and the dry run is meant to be read: every row is logged
// with what would change or exactly why it was passed over, every row the
// purge would delete is logged by path, and stdout ends with a per-dataset
// table of the outcomes. Idempotent, so it is safe to re-run after a partial
// pass or when a new dataset lands.
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
	stats.report(*apply)

	if *purge {
		if err := purgeDatasetMetadata(ctx, db, *apply); err != nil {
			return err
		}
	}
	if !*apply {
		writeStdoutLine("re-run with --apply to write")
	}
	return nil
}

// Outcomes of one artifact row in backfillDatasetProvenance.
const (
	outcomeAttached   = "attached"    // paired with a document (written when applying)
	outcomeNoDocument = "no document" // on disk, but no document the reader accepts
	outcomeMissing    = "not on disk" // stored path absent from the data root
)

// backfillDatasetStats tallies a pass per dataset root and per skip reason, so
// the summary says which corpus the rows without a document belong to and
// what was wrong with them — not just how many there were.
type backfillDatasetStats struct {
	byRoot   map[string]map[string]int // dataset root → outcome → rows
	byReason map[string]int            // skip reason → rows
}

func newBackfillDatasetStats() *backfillDatasetStats {
	return &backfillDatasetStats{byRoot: map[string]map[string]int{}, byReason: map[string]int{}}
}

func (st *backfillDatasetStats) add(path, outcome string) {
	root := datasetRootOf(path)
	if st.byRoot[root] == nil {
		st.byRoot[root] = map[string]int{}
	}
	st.byRoot[root][outcome]++
}

func (st *backfillDatasetStats) total(outcome string) int {
	n := 0
	for _, m := range st.byRoot {
		n += m[outcome]
	}
	return n
}

// report prints the per-dataset table and the skip-reason breakdown.
func (st *backfillDatasetStats) report(apply bool) {
	verb := "would attach"
	if apply {
		verb = "attached"
	}
	writeStdoutf("%s provenance to %d artifact(s); %d without a usable document; %d not on disk\n",
		verb, st.total(outcomeAttached), st.total(outcomeNoDocument), st.total(outcomeMissing))
	if len(st.byRoot) > 0 {
		writeStdoutf("  %-9s %-12s %-12s dataset\n", outcomeAttached, "no-document", "not-on-disk")
		for _, root := range slices.Sorted(maps.Keys(st.byRoot)) {
			m := st.byRoot[root]
			writeStdoutf("  %-9d %-12d %-12d %s\n", m[outcomeAttached], m[outcomeNoDocument], m[outcomeMissing], root)
		}
	}
	if len(st.byReason) > 0 {
		writeStdoutLine("  skipped because:")
		for _, reason := range slices.Sorted(maps.Keys(st.byReason)) {
			writeStdoutf("  %8d  %s\n", st.byReason[reason], reason)
		}
	}
}

// datasetRootOf returns the stored path up to the dataset's samples/ directory
// — the unit the summary groups by — or the first two components for a path
// that does not fit the grammar.
func datasetRootOf(path string) string {
	if root, _, ok := strings.Cut(path, "/samples/"); ok {
		return root
	}
	parts := strings.SplitN(path, "/", 4)
	if len(parts) > 3 {
		return strings.Join(parts[:3], "/")
	}
	return filepath.Dir(path)
}

// skipReason collapses an error from datasetProvenance to a stable, countable
// phrase: the document rejections embed the package and release, which would
// make every row its own reason, so those count under their sentinel.
func skipReason(err error) string {
	for _, sentinel := range []error{errDocumentVersion, errDocumentPackage, errPackumentNoVersion, errNotRegistryDocument} {
		if errors.Is(err, sentinel) {
			return sentinel.Error()
		}
	}
	return err.Error()
}

// backfillDatasetProvenance pages the provenance-less artifacts under prefix
// and pairs each with the registry document beside it, writing when apply is
// set. The row's stored columns are the starting point, exactly as they would
// be for a walk's cache hit, so the document's claims replace only what the
// document actually knows. Every row is logged: what changes, or why not.
func backfillDatasetProvenance(ctx context.Context, db *hopper.DB, dataDir, prefix string, apply bool) (*backfillDatasetStats, error) {
	stats := newBackfillDatasetStats()
	var afterID int64
	for page := 1; ; page++ {
		rows, err := db.DatasetArtifactsWithoutProvenance(ctx, prefix, afterID, backfillDatasetPage)
		if err != nil {
			return stats, err
		}
		if len(rows) == 0 {
			return stats, nil
		}
		if page%20 == 0 {
			slog.Info("dataset backfill progress", "attached", stats.total(outcomeAttached),
				"no_document", stats.total(outcomeNoDocument), "missing", stats.total(outcomeMissing))
		}
		for _, s := range rows {
			afterID = s.ID
			abs := filepath.Join(dataDir, filepath.FromSlash(s.Path))
			if _, err := os.Stat(abs); err != nil {
				stats.add(s.Path, outcomeMissing)
				slog.Info("dataset artifact not on disk", "path", s.Path, "sha256", s.SHA256)
				continue
			}
			c := *s
			c.Path = abs
			if err := datasetProvenance(&c, abs); err != nil {
				stats.add(s.Path, outcomeNoDocument)
				stats.byReason[skipReason(err)]++
				slog.Info("dataset provenance skipped", "path", s.Path, "sha256", s.SHA256, "reason", err)
				continue
			}
			stats.add(s.Path, outcomeAttached)
			msg := "would attach dataset provenance"
			if apply {
				msg = "attached dataset provenance"
			}
			slog.Info(msg, "path", s.Path, "sha256", s.SHA256,
				"package", s.Package+" → "+c.Package, "version", s.Version+" → "+c.Version,
				"purl_base", s.PURLBase+" → "+c.PURLBase, "feed", s.Feed+" → "+c.Feed,
				"ecosystem", s.Ecosystem+" → "+c.Ecosystem, "url", c.URL)
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

// purgeDatasetPage is how many doomed rows one listing page reads.
const purgeDatasetPage = 5000

// purgeDatasetMetadata lists every row the dataset_metadata cleanup stage
// matches — logged by path, summarized per dataset root on stdout — and, when
// applying, deletes them. The listing runs in both modes: the apply log then
// records exactly what was removed.
func purgeDatasetMetadata(ctx context.Context, db *hopper.DB, apply bool) error {
	stage, ok := hopper.CleanupStageByName("dataset_metadata")
	if !ok {
		return errors.New("dataset_metadata cleanup stage is not defined")
	}
	msg := "would delete"
	if apply {
		msg = "deleting"
	}
	byRoot := map[string]int{}
	var afterID int64
	var total int
	for {
		rows, err := db.CleanupRows(ctx, stage, afterID, purgeDatasetPage)
		if err != nil {
			return err
		}
		if len(rows) == 0 {
			break
		}
		for _, r := range rows {
			afterID = r.ID
			total++
			byRoot[datasetRootOf(r.Path)]++
			slog.Info(msg, "path", r.Path, "sha256", r.SHA256)
		}
	}
	writeStdoutf("%s %d row(s) — %s\n", msg, total, stage.Description)
	for _, root := range slices.Sorted(maps.Keys(byRoot)) {
		writeStdoutf("  %8d  %s\n", byRoot[root], root)
	}
	if !apply || total == 0 {
		return nil
	}
	deleted, err := db.ApplyCleanup(ctx, stage)
	if err != nil {
		return err
	}
	writeStdoutf("deleted %d row(s)\n", deleted)
	return nil
}
