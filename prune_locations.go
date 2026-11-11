package hopper

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"slices"
	"strconv"
	"strings"
	"time"
)

const locationCapPrefix = "location-member-cap/"

const pruneInFileSQL = `parent_sha256 <> '' AND rel IN ` + containmentRelsSQL + ` AND path LIKE '%!!%' AND path NOT LIKE '%://%'`

// LocationPruneOptions describes one resumable pass. DryRun performs only reads.
type LocationPruneOptions struct {
	Progress func(LocationPruneStats) error
	DataRoot string
	Phase    string // obsolete or cap
	AfterSHA string
	// CapLabels limits which labels the cap phase trims; empty means good and
	// unknown. Retention limits and admission markers are unaffected.
	CapLabels       []string
	AfterID         int64
	ThroughID       int64 // zero captures the current maximum ID
	Limit           int64 // obsolete rows inspected; zero is unlimited
	LimitSHAs       int   // overfull SHAs inspected; zero is unlimited
	Batch           int
	MaxPaths        int // optional override for both capped labels
	GoodMaxPaths    int
	UnknownMaxPaths int
	PreviewRows     int64 // cap preview over a bounded ID window; never applies
	// MaxObsoleteFraction aborts an obsolete apply before deleting a batch whose
	// absent share, or the pass's cumulative absent share, exceeds it. Zero
	// selects DefaultMaxObsoleteFraction; 1 or more disables the cap.
	MaxObsoleteFraction float64
	DryRun              bool
}

// DefaultMaxObsoleteFraction matches the legacy prune safety cap: a wrong data
// root or an unmounted pool makes most rows look absent, while ordinary churn
// removes a small share.
const DefaultMaxObsoleteFraction = 0.40

// pruneSafetyMinVictims keeps small clusters of genuinely removed files from
// tripping the fraction cap; a wrong root trips it within the first batch.
const pruneSafetyMinVictims = 50

// LocationPruneLabelStats describes the effects for one member label.
type LocationPruneLabelStats struct {
	Rows, MemberLocations, EligibleLocations, PhysicalLocations, Excess, ArchivesSeen, ArchiveEdgesRemoved, AffectedSHAs int64
}

// LocationPruneLabels separates eligible labels from protected labels.
type LocationPruneLabels struct {
	Good, Unknown, Bad, Other LocationPruneLabelStats
}

// LocationPruneStats describes completed batches; cursors advance after commit.
type LocationPruneStats struct {
	Labels                                                                           *LocationPruneLabels
	Phase                                                                            string
	AfterSHA                                                                         string
	AfterID, ThroughID                                                               int64
	Scanned, Obsolete, Excess, Deleted, Protected, Uncheckable, StatCalls, CacheHits int64
	OverfullSHAs, CappedSHAs, BusyArchives                                           int
	PhysicalRetained, ArchivesSeen, ArchiveEdgesRemoved                              int64
	// SafetyTrips counts obsolete batches that exceeded MaxObsoleteFraction. An
	// apply stops at the first; a dry run keeps counting so the preview is whole.
	SafetyTrips int64
	// PoolGuarded counts absent paths preserved because their top-level pool
	// directory was missing or empty, which is how an unmounted dataset looks.
	PoolGuarded int64
	// Rebased counts absent member rows moved onto their archive's live path;
	// Unmapped counts those kept because the old prefix could not be mapped.
	Rebased, Unmapped int64
	Complete          bool
}

type pruneLocation struct {
	Seen                   time.Time
	SHA, Path, Parent, Rel string
	ID                     int64
}

type prunePresence uint8

const (
	pruneUnknown prunePresence = iota
	prunePresent
	pruneAbsent
)

type pruneChecker struct {
	stats   *LocationPruneStats
	cache   map[string]prunePresence
	pools   map[string]bool
	parents map[string]*pruneParent
	root    string
}

// poolPresent reports whether the top-level directory holding resolved exists
// and is non-empty. An unmounted dataset leaves an empty mountpoint (or none),
// and every file under it would otherwise stat as absent. Files directly in
// the root have no pool and always pass.
func (c *pruneChecker) poolPresent(resolved string, fresh bool) bool {
	rel, err := filepath.Rel(c.root, resolved)
	if err != nil {
		return false
	}
	top, _, nested := strings.Cut(rel, string(filepath.Separator))
	if !nested {
		return true
	}
	if ok, cached := c.pools[top]; cached && !fresh {
		return ok
	}
	ok := false
	if dir, err := os.Open(filepath.Join(c.root, top)); err == nil {
		names, _ := dir.Readdirnames(1) //nolint:errcheck // an empty or unreadable pool is not present
		ok = len(names) > 0
		_ = dir.Close() //nolint:errcheck // read-only handle
	}
	if c.pools == nil {
		c.pools = map[string]bool{}
	}
	c.pools[top] = ok
	return ok
}

func (c *pruneChecker) check(path string, fresh bool) prunePresence {
	outer, _, _ := strings.Cut(path, "!!")
	if outer == "" || strings.Contains(outer, "://") {
		return pruneUnknown
	}
	resolved, ok := prunePathResolve(c.root, outer)
	if !ok || resolved == c.root {
		return pruneUnknown
	}
	if !fresh {
		if state, ok := c.cache[resolved]; ok {
			c.stats.CacheHits++
			return state
		}
	}
	c.stats.StatCalls++
	info, err := os.Stat(resolved)
	state := pruneUnknown
	if errors.Is(err, os.ErrNotExist) {
		state = pruneAbsent
		if !c.poolPresent(resolved, fresh) {
			c.stats.PoolGuarded++
			state = pruneUnknown
		}
	} else if err == nil && info.Mode().IsRegular() {
		state = prunePresent
	}
	if len(c.cache) >= 16384 {
		clear(c.cache)
	}
	c.cache[resolved] = state
	return state
}

// PruneLocations removes absent observations or caps contained locations globally
// per content hash. Physical locations never count toward the cap. It never
// removes files, reads archive members, changes labels, or copies discarded rows
// into history. New IDs after ThroughID are left for a subsequent pass.
func (db *DB) PruneLocations(ctx context.Context, opts LocationPruneOptions) (LocationPruneStats, error) {
	opts = normalizeLocationCaps(opts)
	stats := LocationPruneStats{
		Labels: &LocationPruneLabels{}, Phase: opts.Phase, AfterID: opts.AfterID, AfterSHA: opts.AfterSHA, ThroughID: opts.ThroughID,
	}
	if opts.DataRoot == "" {
		return stats, errors.New("hopper: prune-locations requires a data root")
	}
	if opts.Batch <= 0 || opts.Batch > 10000 || opts.MaxPaths < 0 || opts.MaxPaths > 4096 ||
		opts.GoodMaxPaths < 1 || opts.GoodMaxPaths > 4096 || opts.UnknownMaxPaths < 1 || opts.UnknownMaxPaths > 4096 || opts.PreviewRows < 0 ||
		opts.AfterID < 0 || opts.ThroughID < 0 || opts.Limit < 0 || opts.LimitSHAs < 0 {
		return stats, errors.New("hopper: invalid prune limits (batch 1..10000, max-paths 1..4096, nonnegative cursors and limits)")
	}
	if opts.PreviewRows > 0 && (!opts.DryRun || opts.Phase != "cap") {
		return stats, errors.New("hopper: --limit-rows requires a cap-only dry run")
	}
	if opts.Phase != "obsolete" && opts.Phase != "cap" {
		return stats, errors.New("hopper: prune phase must be obsolete or cap")
	}
	if opts.MaxObsoleteFraction < 0 {
		return stats, errors.New("hopper: max obsolete fraction must be nonnegative")
	}
	for _, label := range opts.CapLabels {
		if label != labelGood && label != labelUnknown {
			return stats, errors.New("hopper: cap labels must be good and/or unknown")
		}
	}
	if opts.MaxObsoleteFraction == 0 {
		opts.MaxObsoleteFraction = DefaultMaxObsoleteFraction
	}
	root, err := filepath.Abs(opts.DataRoot)
	if err != nil {
		return stats, err
	}
	root, err = filepath.EvalSymlinks(root)
	if err != nil {
		return stats, err
	}
	info, err := os.Stat(root)
	if err != nil {
		return stats, err
	}
	if !info.IsDir() {
		return stats, errors.New("hopper: data root is not a directory")
	}
	if stats.ThroughID == 0 {
		err = db.queryLocations(ctx, `SELECT COALESCE(max(id),0) FROM sample_locations`, nil, func(rows locationRows) error {
			if rows.Next() {
				return rows.Scan(&stats.ThroughID)
			}
			return rows.Err()
		})
		if err != nil {
			return stats, err
		}
	}
	checker := &pruneChecker{root: root, cache: make(map[string]prunePresence), stats: &stats}
	if !opts.DryRun && opts.Phase == "cap" {
		if err := db.prepareLocationCapPolicy(ctx, opts); err != nil {
			return stats, err
		}
	}
	switch {
	case opts.Phase == "obsolete":
		err = db.pruneObsoleteLocations(ctx, opts, &stats, checker)
	case opts.PreviewRows > 0:
		err = db.previewLocationWindow(ctx, opts, &stats)
	default:
		err = db.pruneCappedLocations(ctx, opts, &stats, checker)
	}
	return stats, err
}

func pruneSeen(value any) time.Time {
	if t, ok := value.(time.Time); ok {
		return t
	}
	if s, ok := value.(string); ok {
		for _, layout := range []string{time.RFC3339Nano, "2006-01-02T15:04:05.999999999", "2006-01-02 15:04:05.999999999"} {
			if t, err := time.Parse(layout, s); err == nil {
				return t
			}
		}
	}
	return time.Time{}
}

func scanPruneLocation(rows locationRows) (pruneLocation, error) {
	var l pruneLocation
	var seen any
	dest := []any{&l.ID, &l.SHA, &l.Path, &l.Parent, &l.Rel, &seen}
	err := rows.Scan(dest...)
	l.Seen = pruneSeen(seen)
	return l, err
}

const pruneLocationColumns = `id,sha256,path,parent_sha256,rel,first_seen_at`

func (db *DB) pruneObsoleteLocations(ctx context.Context, opts LocationPruneOptions, stats *LocationPruneStats, c *pruneChecker) error {
	for {
		size := int64(opts.Batch)
		if opts.Limit > 0 {
			size = min(size, opts.Limit-stats.Scanned)
			if size == 0 {
				return nil
			}
		}
		var batch []pruneLocation
		err := db.queryLocations(ctx, `SELECT `+pruneLocationColumns+` FROM sample_locations
   WHERE id > $1 AND id <= $2 ORDER BY id LIMIT $3`, []any{stats.AfterID, stats.ThroughID, size}, func(rows locationRows) error {
			for rows.Next() {
				l, err := scanPruneLocation(rows)
				if err != nil {
					return err
				}
				batch = append(batch, l)
			}
			return rows.Err()
		})
		if err != nil {
			return err
		}
		if len(batch) == 0 {
			stats.Complete = true
			return reportLocationPrune(opts, stats)
		}
		var victims []pruneLocation
		for _, l := range batch {
			switch c.check(l.Path, false) {
			case pruneAbsent:
				victims = append(victims, l)
			case pruneUnknown:
				stats.Uncheckable++
			default: // Keep observations whose outer file exists.
			}
		}
		if !opts.DryRun {
			victims = refreshPruneVictims(victims, c)
		}
		// Rebases are not losses: only rows with no live archive count toward the
		// safety cap and the obsolete total.
		plan, err := db.planObsoleteRebases(ctx, victims, c, !opts.DryRun)
		if err != nil {
			return err
		}
		stats.Unmapped += plan.unmapped
		safety := checkObsoleteSafety(opts, stats, len(plan.deletes), len(batch))
		if opts.DryRun {
			// Preview reports every batch an apply would refuse instead of stopping.
			if errors.As(safety, new(*PruneSafetyExceeded)) {
				stats.SafetyTrips++
			}
			stats.Rebased += int64(len(plan.rebases))
		} else {
			if safety != nil {
				return safety
			}
			moved, err := db.rebasePruneLocations(ctx, plan.rebases)
			if err != nil {
				return err
			}
			stats.Rebased += moved
			n, protected, err := db.deletePruneLocations(ctx, plan.deletes, false, nil, c, opts)
			if err != nil {
				return err
			}
			stats.Deleted += n
			stats.Protected += protected
		}
		stats.Obsolete += int64(len(plan.deletes))
		stats.Scanned += int64(len(batch))
		stats.AfterID = batch[len(batch)-1].ID
		if stats.AfterID >= stats.ThroughID {
			stats.Complete = true
		}
		if err := reportLocationPrune(opts, stats); err != nil {
			return err
		}
		if stats.Complete {
			return nil
		}
	}
}

// refreshPruneVictims rechecks each absent outer path before mutations.
func refreshPruneVictims(victims []pruneLocation, c *pruneChecker) []pruneLocation {
	fresh := map[string]prunePresence{}
	live := victims[:0]
	for _, l := range victims {
		outer, _, _ := strings.Cut(l.Path, "!!")
		state, ok := fresh[outer]
		if !ok {
			state = c.check(l.Path, true)
			fresh[outer] = state
		}
		if state == pruneAbsent {
			live = append(live, l)
		}
	}
	return live
}

// checkObsoleteSafety refuses a batch when its own absent share, or the pass's
// cumulative share including it, exceeds the cap. The batch check stops a wrong
// root before its first deletion; the cumulative check stops a slow drift. Both
// ignore fewer than pruneSafetyMinVictims absent rows so small clusters of
// genuinely removed files never trip it.
func checkObsoleteSafety(opts LocationPruneOptions, stats *LocationPruneStats, victims, batch int) error {
	limit := opts.MaxObsoleteFraction
	if limit >= 1 || batch == 0 {
		return nil
	}
	exceeds := func(v, total int64) bool {
		return v > pruneSafetyMinVictims && float64(v)/float64(total) > limit
	}
	if exceeds(int64(victims), int64(batch)) {
		return &PruneSafetyExceeded{Total: batch, Victims: victims, MaxFraction: limit}
	}
	v, total := stats.Obsolete+int64(victims), stats.Scanned+int64(batch)
	if exceeds(v, total) {
		return &PruneSafetyExceeded{Total: int(total), Victims: int(v), MaxFraction: limit}
	}
	return nil
}

// capLabelSelected reports whether the cap phase may trim this label.
func capLabelSelected(label string, opts LocationPruneOptions) bool {
	return len(opts.CapLabels) == 0 || slices.Contains(opts.CapLabels, label)
}

func reportLocationPrune(opts LocationPruneOptions, stats *LocationPruneStats) error {
	if opts.Progress != nil {
		return opts.Progress(*stats)
	}
	return nil
}

func pruneIDList(rows []pruneLocation) string {
	ids := make([]string, len(rows))
	for i, l := range rows {
		ids[i] = strconv.FormatInt(l.ID, 10)
	}
	return strings.Join(ids, ",")
}
