package main

import (
	"context"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"log/slog"
	"os"
	"path/filepath"
	"time"

	"github.com/atomdrift-project/hopper"
)

type locationPruneCheckpoint struct {
	Root            string
	Stats           hopper.LocationPruneStats
	MaxPaths        int
	GoodMaxPaths    int
	UnknownMaxPaths int
	PreviewRows     int64
	Version         int
	DryRun          bool
}

func writeLocationPruneCheckpoint(name string, checkpoint *locationPruneCheckpoint) error {
	data, err := json.MarshalIndent(checkpoint, "", "  ")
	if err != nil {
		return err
	}
	// Same-directory rename keeps a checkpoint intact across interruption.
	file, err := os.CreateTemp(filepath.Dir(name), ".prune-checkpoint-*")
	if err != nil {
		return err
	}
	temporary := file.Name()
	defer func() { _ = os.Remove(temporary) }() //nolint:errcheck // already renamed on success
	if err := file.Chmod(0o600); err != nil {
		_ = file.Close() //nolint:errcheck // Preserve the original write error.
		return err
	}
	if _, err := file.Write(append(data, '\n')); err != nil {
		_ = file.Close() //nolint:errcheck // Preserve the original write error.
		return err
	}
	if err := file.Sync(); err != nil {
		_ = file.Close() //nolint:errcheck // Preserve the original write error.
		return err
	}
	if err := file.Close(); err != nil {
		return err
	}
	return os.Rename(temporary, name)
}

func cmdPruneLocations(ctx context.Context) error {
	f := flag.NewFlagSet("prune-locations", flag.ExitOnError)
	dsn := f.String("db", "", "database connection string")
	root := f.String("data", "", "fully mounted sample data root")
	phase := f.String("phase", "all", "obsolete, cap, or all (sequential passes)")
	apply := f.Bool("apply", false, "delete catalog rows; default is a read-only preview")
	dry := f.Bool("dry-run", false, "explicitly select the default read-only preview")
	batch := f.Int("batch", 5000, "rows per database page and deletion transaction (max 10000)")
	maxPaths := f.Int("max-paths", 0, "optional override for both good/unknown caps; other labels and physical locations stay uncapped")
	goodMax := f.Int("good-max-paths", 256, "maximum contained locations per good SHA256")
	unknownMax := f.Int("unknown-max-paths", 512, "maximum contained locations per unknown SHA256")
	previewRows := f.Int64("limit-rows", 0, "cap-only dry run over this many location rows in ID order; caps are evaluated within that window")
	limit := f.Int64("limit", 0, "maximum rows inspected in the obsolete phase (0 = unlimited)")
	limitSHAs := f.Int("limit-shas", 0, "maximum overfull SHAs processed in the cap phase (0 = unlimited)")
	afterID := f.Int64("after-id", 0, "resume obsolete phase after this location ID")
	throughID := f.Int64("through-id", 0, "fixed upper ID boundary when resuming (0 captures maximum)")
	afterSHA := f.String("after-sha", "", "resume cap phase after this SHA256")
	checkpoint := f.String("checkpoint", "", "write an atomic JSON checkpoint after completed batches")
	resume := f.Bool("resume", false, "resume a matching --checkpoint (preview and apply checkpoints cannot be mixed)")
	var mounts stringListFlag
	f.Var(&mounts, "require-mount", "required pool mount, relative to --data (repeatable)")
	parseFlags(f, os.Args[2:])
	if *root == "" {
		return errors.New("pass --data <fully-mounted sample tree>")
	}
	if *apply && *dry {
		return errors.New("--apply and --dry-run are mutually exclusive")
	}
	if *phase != "all" && *phase != "obsolete" && *phase != "cap" {
		return errors.New("--phase must be all, obsolete, or cap")
	}
	resolved, err := filepath.EvalSymlinks(*root)
	if err != nil {
		return err
	}
	resolved, err = filepath.Abs(resolved)
	if err != nil {
		return err
	}
	*root = resolved
	if err := validateRequiredMounts(*root, mounts); err != nil {
		return err
	}
	opts := hopper.LocationPruneOptions{
		DataRoot: *root, Batch: *batch, MaxPaths: *maxPaths, GoodMaxPaths: *goodMax, UnknownMaxPaths: *unknownMax,
		PreviewRows: *previewRows, DryRun: !*apply,
		AfterID: *afterID, ThroughID: *throughID, AfterSHA: *afterSHA, Limit: *limit, LimitSHAs: *limitSHAs,
	}
	phases := []string{*phase}
	if *phase == "all" {
		phases = []string{"obsolete", "cap"}
	}
	if *previewRows > 0 && (*apply || *phase != "cap") {
		return errors.New("--limit-rows requires --phase cap and a dry run")
	}
	if *resume {
		if *checkpoint == "" {
			return errors.New("--resume requires --checkpoint")
		}
		data, err := os.ReadFile(*checkpoint)
		if err != nil {
			return err
		}
		var saved locationPruneCheckpoint
		if err := json.Unmarshal(data, &saved); err != nil {
			return err
		}
		phases, err = resumeLocationPrune(*phase, &saved, &opts)
		if err != nil {
			return err
		}
		if len(phases) == 0 {
			fmt.Println("checkpoint pass is already complete; omit --resume to start a new pass")
			return nil
		}
	}
	db, err := openDB(ctx, *dsn)
	if err != nil {
		return err
	}
	defer db.Close()
	// No Migrate: preview must work with read-only credentials and no schema writes.
	if *previewRows > 0 {
		fmt.Printf("Preview window: up to %d location rows in ID order; caps are evaluated only within this window.\n", *previewRows)
	}
	if opts.DryRun && *phase == "all" {
		fmt.Println("Preview phases are independent; cap estimates can include rows also found obsolete. Do not add the two estimates.")
	}
	for _, current := range phases {
		opts.Phase = current
		started := time.Now()
		opts.Progress = func(stats hopper.LocationPruneStats) error {
			fmt.Printf("prune: phase=%s scanned=%d obsolete=%d excess=%d deleted=%d protected=%d uncheckable=%d stat_calls=%d cache_hits=%d "+
				"capped_shas=%d busy_archives=%d physical_retained=%d archives_seen=%d archive_edges_removed=%d "+
				"after_id=%d through_id=%d after_sha=%s complete=%t elapsed=%s\n",
				stats.Phase, stats.Scanned, stats.Obsolete, stats.Excess, stats.Deleted, stats.Protected, stats.Uncheckable,
				stats.StatCalls, stats.CacheHits,
				stats.CappedSHAs, stats.BusyArchives, stats.PhysicalRetained, stats.ArchivesSeen, stats.ArchiveEdgesRemoved,
				stats.AfterID, stats.ThroughID, stats.AfterSHA, stats.Complete,
				time.Since(started).Round(time.Millisecond))
			slog.Info("location prune progress", "phase", stats.Phase, "scanned", stats.Scanned, "obsolete", stats.Obsolete, "excess", stats.Excess,
				"deleted", stats.Deleted, "dry_run", opts.DryRun, "after_id", stats.AfterID, "after_sha", stats.AfterSHA)
			reportLocationPruneLabels(stats.Labels)
			if *checkpoint != "" {
				return writeLocationPruneCheckpoint(*checkpoint, &locationPruneCheckpoint{
					Root: *root, MaxPaths: *maxPaths, GoodMaxPaths: *goodMax, UnknownMaxPaths: *unknownMax,
					PreviewRows: *previewRows, DryRun: opts.DryRun, Stats: stats, Version: 4,
				})
			}
			return nil
		}
		stats, err := db.PruneLocations(ctx, opts)
		if err != nil {
			return fmt.Errorf("prune %s failed (resume after ID %d or SHA %q, through ID %d): %w",
				current, stats.AfterID, stats.AfterSHA, stats.ThroughID, err)
		}
		if !stats.Complete {
			fmt.Printf("Pass stopped at its configured limit. Resume --phase %s --after-id %d --after-sha %q --through-id %d, "+
				"or use --resume --checkpoint.\n",
				current, stats.AfterID, stats.AfterSHA, stats.ThroughID)
			return nil
		}
		opts.ThroughID = stats.ThroughID
	}
	return nil
}

// A completed obsolete phase advances to cap when resuming the combined command.
// The SHA cursor advances only after an entire hash has been processed.
func resumeLocationPrune(phase string, saved *locationPruneCheckpoint, opts *hopper.LocationPruneOptions) ([]string, error) {
	if saved.Version != 4 {
		return nil, errors.New("checkpoint uses an earlier cap policy; start a new pass")
	}
	if saved.Root != opts.DataRoot || saved.MaxPaths != opts.MaxPaths || saved.GoodMaxPaths != opts.GoodMaxPaths ||
		saved.UnknownMaxPaths != opts.UnknownMaxPaths || saved.PreviewRows != opts.PreviewRows || saved.DryRun != opts.DryRun {
		return nil, errors.New("checkpoint root, retention limit, or preview/apply mode differs")
	}
	if saved.Stats.Phase != "obsolete" && saved.Stats.Phase != "cap" {
		return nil, errors.New("invalid checkpoint phase")
	}
	if phase != "all" && phase != saved.Stats.Phase {
		return nil, errors.New("checkpoint phase differs from --phase")
	}
	opts.AfterID = saved.Stats.AfterID
	opts.ThroughID = saved.Stats.ThroughID
	opts.AfterSHA = saved.Stats.AfterSHA
	if phase == "all" && saved.Stats.Phase == "obsolete" {
		if saved.Stats.Complete {
			return []string{"cap"}, nil
		}
		return []string{"obsolete", "cap"}, nil
	}
	if saved.Stats.Complete {
		return nil, nil
	}
	return []string{saved.Stats.Phase}, nil
}

func reportLocationPruneLabels(labels *hopper.LocationPruneLabels) {
	if labels == nil {
		return
	}
	for _, row := range []struct {
		detail *hopper.LocationPruneLabelStats
		label  string
	}{
		{&labels.Good, "good"}, {&labels.Unknown, "unknown"}, {&labels.Bad, "bad"}, {&labels.Other, "other"},
	} {
		detail := row.detail
		if detail.Rows == 0 {
			continue
		}
		fmt.Printf("prune label=%s rows=%d member_locations=%d eligible_locations=%d physical_retained=%d "+
			"would_remove=%d affected_shas=%d archive_edges_removed=%d\n",
			row.label, detail.Rows, detail.MemberLocations, detail.EligibleLocations, detail.PhysicalLocations,
			detail.Excess, detail.AffectedSHAs, detail.ArchiveEdgesRemoved)
	}
}
