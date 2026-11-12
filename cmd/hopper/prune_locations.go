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
	Root    string
	Stats   hopper.LocationPruneStats
	Version int
	DryRun  bool
}

// Version 7 removes cap pruning. Earlier policy cursors must start a fresh pass.
const locationPruneCheckpointVersion = 7

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
	phase := f.String("phase", "obsolete", "obsolete (cap pruning has been removed)")
	apply := f.Bool("apply", false, "remove obsolete catalog rows; default is a read-only preview")
	dry := f.Bool("dry-run", false, "explicitly select the default read-only preview")
	batch := f.Int("batch", 5000, "rows per database page and deletion transaction (max 10000)")
	limit := f.Int64("limit", 0, "maximum rows inspected (0 = unlimited)")
	afterID := f.Int64("after-id", 0, "resume after this location ID")
	throughID := f.Int64("through-id", 0, "fixed upper ID boundary when resuming (0 captures maximum)")
	checkpoint := f.String("checkpoint", "", "write an atomic JSON checkpoint after completed batches")
	resume := f.Bool("resume", false, "resume a matching --checkpoint (preview and apply checkpoints cannot be mixed)")
	maxObsolete := f.Float64("max-obsolete-fraction", hopper.DefaultMaxObsoleteFraction,
		"abort an apply when a batch or the pass would remove more than this share of rows")
	force := f.Bool("force", false, "disable the missing-file safety threshold (only after confirming every pool is mounted)")
	var mounts stringListFlag
	f.Var(&mounts, "require-mount", "required pool mount, relative to --data (repeatable)")
	parseFlags(f, os.Args[2:])
	if *phase != "obsolete" {
		return errors.New("--phase must be obsolete; cap pruning was removed because it discards valid observations")
	}
	if *root == "" {
		return errors.New("pass --data <fully-mounted sample tree>")
	}
	if *apply && *dry {
		return errors.New("--apply and --dry-run are mutually exclusive")
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
	if *maxObsolete <= 0 {
		return errors.New("--max-obsolete-fraction must be positive")
	}
	if *force {
		*maxObsolete = 1
	}
	opts := hopper.LocationPruneOptions{
		MaxObsoleteFraction: *maxObsolete,
		DataRoot:            *root, Batch: *batch, Phase: *phase, DryRun: !*apply,
		AfterID: *afterID, ThroughID: *throughID, Limit: *limit,
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
		complete, err := resumeLocationPrune(&saved, &opts)
		if err != nil {
			return err
		}
		if complete {
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
	started := time.Now()
	opts.Progress = func(stats hopper.LocationPruneStats) error {
		fmt.Printf("prune: phase=%s scanned=%d obsolete=%d deleted=%d protected=%d uncheckable=%d stat_calls=%d cache_hits=%d "+
			"safety_trips=%d pool_guarded=%d rebased=%d rebase_duplicates=%d rebase_conflicts=%d unmapped=%d "+
			"after_id=%d through_id=%d complete=%t elapsed=%s\n",
			stats.Phase, stats.Scanned, stats.Obsolete, stats.Deleted, stats.Protected, stats.Uncheckable,
			stats.StatCalls, stats.CacheHits, stats.SafetyTrips, stats.PoolGuarded, stats.Rebased,
			stats.RebaseDuplicates, stats.RebaseConflicts, stats.Unmapped,
			stats.AfterID, stats.ThroughID, stats.Complete, time.Since(started).Round(time.Millisecond))
		slog.Info("location prune progress", "scanned", stats.Scanned, "obsolete", stats.Obsolete,
			"deleted", stats.Deleted, "rebased", stats.Rebased, "dry_run", opts.DryRun, "after_id", stats.AfterID)
		if *checkpoint != "" {
			return writeLocationPruneCheckpoint(*checkpoint, &locationPruneCheckpoint{
				Root: *root, DryRun: opts.DryRun, Stats: stats, Version: locationPruneCheckpointVersion,
			})
		}
		return nil
	}
	stats, err := db.PruneLocations(ctx, opts)
	if errors.As(err, new(*hopper.PruneSafetyExceeded)) {
		return fmt.Errorf("prune safety threshold tripped after ID %d; nothing in the refused batch was deleted. "+
			"Confirm every pool is mounted, then raise --max-obsolete-fraction or pass --force: %w", stats.AfterID, err)
	}
	if err != nil {
		return fmt.Errorf("prune failed (resume after ID %d, through ID %d): %w", stats.AfterID, stats.ThroughID, err)
	}
	if stats.SafetyTrips > 0 {
		fmt.Printf("WARNING: %d batch(es) exceed the %.0f%% obsolete safety threshold; an apply would stop at the first\n",
			stats.SafetyTrips, opts.MaxObsoleteFraction*100)
	}
	if !stats.Complete {
		fmt.Printf("Pass stopped at its configured limit. Resume --after-id %d --through-id %d, or use --resume --checkpoint.\n",
			stats.AfterID, stats.ThroughID)
	}
	return nil
}

func resumeLocationPrune(saved *locationPruneCheckpoint, opts *hopper.LocationPruneOptions) (complete bool, err error) {
	if saved.Version != locationPruneCheckpointVersion {
		return false, errors.New("checkpoint uses an earlier pruning policy; start a new pass")
	}
	if saved.Root != opts.DataRoot || saved.DryRun != opts.DryRun {
		return false, errors.New("checkpoint root or preview/apply mode differs")
	}
	if saved.Stats.Phase != "obsolete" {
		return false, errors.New("invalid checkpoint phase; only obsolete pruning is supported")
	}
	opts.AfterID = saved.Stats.AfterID
	opts.ThroughID = saved.Stats.ThroughID
	return saved.Stats.Complete, nil
}
