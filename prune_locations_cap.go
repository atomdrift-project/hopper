package hopper

import (
	"container/heap"
	"context"
	"errors"
	"os"
	"slices"
	"strings"
	"syscall"
)

var errPruneArchiveBusy = errors.New("hopper: archive move lock is busy")

type pruneArchiveGroup struct{ SHA, Parent, Outer string }

func locationCapKey(sha, path string) string {
	if !strings.Contains(path, "!!") {
		return ""
	}
	return locationCapPrefix + sha
}

func (g pruneArchiveGroup) key() string { return locationCapPrefix + g.SHA }

func (db *DB) pruneCappedLocations(ctx context.Context, opts LocationPruneOptions, stats *LocationPruneStats, c *pruneChecker) error {
	for {
		size := 100
		if opts.LimitSHAs > 0 {
			size = min(size, opts.LimitSHAs-stats.OverfullSHAs)
			if size == 0 {
				return nil
			}
		}
		// The partial parent index supplies SHA order without visiting physical paths.
		shas, err := db.pruneStringPage(ctx, `SELECT sha256 FROM sample_locations
 WHERE parent_sha256<>'' AND sha256>$1 GROUP BY sha256 HAVING count(*)>$2 ORDER BY sha256 LIMIT $3`,
			[]any{stats.AfterSHA, pruneCapFloor(opts), size})
		if err != nil {
			return err
		}
		if len(shas) == 0 {
			stats.Complete = true
			return reportLocationPrune(opts, stats)
		}
		for _, sha := range shas {
			sample, err := db.pruneCurrentLabel(ctx, sha)
			if err != nil {
				return err
			}
			limit := locationLabelCap(sample.Label, sample.Skip, sample.Source, opts)
			if !capLabelSelected(sample.Label, opts) {
				limit = 0 // excluded from this pass; its marker and rows are left alone
			}
			shaOpts := opts
			shaOpts.MaxPaths = limit
			if limit == 0 {
				stats.OverfullSHAs++
				stats.AfterSHA = sha
				if err := reportLocationPrune(opts, stats); err != nil {
					return err
				}
				continue
			}
			var plan memberCapPlan
			if opts.DryRun {
				plan, err = db.countMemberCap(ctx, sha, stats.ThroughID)
				stats.Scanned += plan.locations
			} else {
				plan, err = db.planMemberCap(ctx, sha, shaOpts, stats)
			}
			if err != nil {
				return err
			}
			if plan.locations > int64(limit) {
				physical, err := db.prunePhysicalCount(ctx, sha)
				if err != nil {
					return err
				}
				stats.PhysicalRetained += physical
				stats.ArchivesSeen += plan.archives
				stats.ArchiveEdgesRemoved += max(int64(0), plan.archives-int64(limit))
				stats.Excess += plan.locations - int64(limit)
				if !opts.DryRun {
					if err := db.applyAndMarkMemberCap(ctx, sha, plan.keep, shaOpts, opts, stats, c); err != nil {
						return err
					}
				}
				stats.CappedSHAs++
				recordCappedLocationStats(stats, sample.Label, plan, limit, physical)
			}
			stats.OverfullSHAs++
			stats.AfterSHA = sha
			if err := reportLocationPrune(opts, stats); err != nil {
				return err
			}
		}
	}
}

func (db *DB) applyAndMarkMemberCap(
	ctx context.Context, sha string, keep []pruneLocation, shaOpts, opts LocationPruneOptions, stats *LocationPruneStats, c *pruneChecker,
) error {
	if err := db.applyMemberCap(ctx, sha, keep, shaOpts, stats, c); err != nil {
		return err
	}
	return db.updateLocationCapMarker(ctx, pruneArchiveGroup{SHA: sha}, opts)
}

func recordCappedLocationStats(stats *LocationPruneStats, label string, plan memberCapPlan, limit int, physical int64) {
	detail := locationLabelStats(stats.Labels, label)
	detail.AffectedSHAs++
	detail.Rows += plan.locations
	detail.MemberLocations += plan.locations
	detail.EligibleLocations += plan.locations
	detail.PhysicalLocations += physical
	detail.Excess += plan.locations - int64(limit)
	detail.ArchivesSeen += plan.archives
	detail.ArchiveEdgesRemoved += max(int64(0), plan.archives-int64(limit))
}

// pruneCapFloor is the smallest allowance among the labels this pass trims;
// only SHAs above it can be overfull.
func pruneCapFloor(opts LocationPruneOptions) int {
	floor := 0
	for label, limit := range map[string]int{labelGood: opts.GoodMaxPaths, labelUnknown: opts.UnknownMaxPaths} {
		if capLabelSelected(label, opts) && (floor == 0 || limit < floor) {
			floor = limit
		}
	}
	return floor
}

func (db *DB) pruneStringPage(ctx context.Context, query string, args []any) ([]string, error) {
	var out []string
	err := db.queryLocations(ctx, query, args, func(rows locationRows) error {
		for rows.Next() {
			var s string
			if err := rows.Scan(&s); err != nil {
				return err
			}
			out = append(out, s)
		}
		return rows.Err()
	})
	return out, err
}

type memberCapPlan struct {
	keep                []pruneLocation
	locations, archives int64
}

func (db *DB) prunePhysicalCount(ctx context.Context, sha string) (int64, error) {
	var count int64
	err := db.queryLocations(ctx, `SELECT count(*) FROM sample_locations
 WHERE sha256=$1 AND parent_sha256=''`, []any{sha}, func(rows locationRows) error {
		if rows.Next() {
			return rows.Scan(&count)
		}
		return rows.Err()
	})
	return count, err
}

// A preview needs only counts: archive coverage is min(distinct parents, cap).
// Aggregate in the database instead of transferring and ranking every path.
func (db *DB) countMemberCap(ctx context.Context, sha string, through int64) (memberCapPlan, error) {
	plan := memberCapPlan{}
	err := db.queryLocations(ctx, `SELECT count(*),count(DISTINCT parent_sha256) FROM sample_locations
 WHERE sha256=$1 AND id<=$2 AND `+pruneInFileSQL, []any{sha, through}, func(rows locationRows) error {
		if rows.Next() {
			return rows.Scan(&plan.locations, &plan.archives)
		}
		return rows.Err()
	})
	return plan, err
}

// Favor one occurrence per archive before spending the remaining budget on
// repeated occurrences. Both heaps are bounded by MaxPaths, even for a SHA
// found in millions of archives. The existing parent index supplies the order.
func (db *DB) planMemberCap(ctx context.Context, sha string, opts LocationPruneOptions, stats *LocationPruneStats) (memberCapPlan, error) {
	plan := memberCapPlan{}
	var primary string
	err := db.queryLocations(ctx, `SELECT path FROM samples WHERE sha256=$1`, []any{sha}, func(rows locationRows) error {
		if rows.Next() {
			return rows.Scan(&primary)
		}
		return rows.Err()
	})
	if err != nil {
		return plan, err
	}
	all, parents := &pruneKeeperHeap{}, &pruneKeeperHeap{}
	var parentBest pruneKeeper
	lastParent := ""
	flush := func() {
		if lastParent != "" {
			pushPruneKeeper(parents, parentBest, opts.MaxPaths)
			plan.archives++
		}
	}
	err = db.queryLocations(ctx, `SELECT `+pruneLocationColumns+` FROM sample_locations
 WHERE sha256=$1 AND parent_sha256<>'' AND id<=$2 AND `+pruneInFileSQL+`
 ORDER BY parent_sha256,id DESC`, []any{sha, stats.ThroughID}, func(rows locationRows) error {
		for rows.Next() {
			l, err := scanPruneLocation(rows)
			if err != nil {
				return err
			}
			candidate := pruneKeeper{location: l, primary: l.Path == primary}
			if l.Parent != lastParent {
				flush()
				lastParent = l.Parent
				parentBest = candidate
			} else if betterPruneKeeper(candidate, parentBest) {
				parentBest = candidate
			}
			pushPruneKeeper(all, candidate, opts.MaxPaths)
			plan.locations++
			stats.Scanned++
			if stats.Scanned%int64(opts.Batch) == 0 {
				if err := reportLocationPrune(opts, stats); err != nil {
					return err
				}
			}
		}
		return rows.Err()
	})
	if err != nil {
		return plan, err
	}
	flush()
	ids := map[int64]bool{}
	for _, k := range *parents {
		plan.keep = append(plan.keep, k.location)
		ids[k.location.ID] = true
	}
	slices.SortFunc(*all, func(a, b pruneKeeper) int {
		if betterPruneKeeper(a, b) {
			return -1
		}
		if betterPruneKeeper(b, a) {
			return 1
		}
		return 0
	})
	for _, k := range *all {
		if len(plan.keep) == opts.MaxPaths {
			break
		}
		if !ids[k.location.ID] {
			plan.keep = append(plan.keep, k.location)
		}
	}
	return plan, nil
}

func pushPruneKeeper(h *pruneKeeperHeap, candidate pruneKeeper, limit int) {
	if h.Len() < limit {
		heap.Push(h, candidate)
	} else if betterPruneKeeper(candidate, (*h)[0]) {
		heap.Pop(h)
		heap.Push(h, candidate)
	}
}

func (db *DB) applyMemberCap(
	ctx context.Context, sha string, keep []pruneLocation, opts LocationPruneOptions, stats *LocationPruneStats, c *pruneChecker,
) error {
	quotas := map[string]int{}
	for _, l := range keep {
		quotas[l.Parent]++
	}
	after := ""
	for {
		parents, err := db.pruneStringPage(ctx, `SELECT parent_sha256 FROM sample_locations
 WHERE sha256=$1 AND parent_sha256<>'' AND parent_sha256>$2
 GROUP BY parent_sha256 ORDER BY parent_sha256 LIMIT 100`, []any{sha, after})
		if err != nil {
			return err
		}
		if len(parents) == 0 {
			return nil
		}
		for _, parent := range parents {
			if err := db.applyMemberParentCap(ctx, pruneArchiveGroup{SHA: sha, Parent: parent}, quotas[parent], opts, stats, c); err != nil {
				return err
			}
		}
		after = parents[len(parents)-1]
	}
}

func (db *DB) applyMemberParentCap(
	ctx context.Context, group pruneArchiveGroup, quota int, opts LocationPruneOptions, stats *LocationPruneStats, c *pruneChecker,
) error {
	lock, err := tryPruneArchiveLock(c.root, group.Parent)
	if errors.Is(err, errPruneArchiveBusy) {
		stats.BusyArchives++
		return nil
	}
	if err != nil {
		return err
	}
	defer lock.Close() //nolint:errcheck // releases the move lock
	// A consolidation may have rebased the selected row IDs before we acquired
	// its lock. Re-select this archive's allocated occurrences under the lock.
	keep, err := db.choosePruneKeepers(ctx, group, quota, stats.ThroughID)
	if err != nil {
		return err
	}
	return db.trimPruneArchive(ctx, group, keep, opts, stats, c)
}

func tryPruneArchiveLock(root, sha string) (*os.File, error) {
	if !isLowerHexSHA256(sha) {
		return nil, errors.New("hopper: invalid archive SHA for prune lock")
	}
	file, err := os.OpenFile(moveContentLockName(root, sha), os.O_CREATE|os.O_RDONLY, 0o660) //nolint:gosec // shared move lock permissions
	if err != nil {
		return nil, err
	}
	err = syscall.Flock(int(file.Fd()), syscall.LOCK_EX|syscall.LOCK_NB)
	if err == nil {
		return file, nil
	}
	_ = file.Close() //nolint:errcheck // preserve the flock error
	if errors.Is(err, syscall.EWOULDBLOCK) || errors.Is(err, syscall.EAGAIN) {
		return nil, errPruneArchiveBusy
	}
	return nil, err
}

type pruneKeeper struct {
	location pruneLocation
	primary  bool
}
type pruneKeeperHeap []pruneKeeper

func (h *pruneKeeperHeap) Len() int           { return len(*h) }
func (h *pruneKeeperHeap) Less(i, j int) bool { return betterPruneKeeper((*h)[j], (*h)[i]) }
func (h *pruneKeeperHeap) Swap(i, j int)      { (*h)[i], (*h)[j] = (*h)[j], (*h)[i] }
func (h *pruneKeeperHeap) Push(value any)     { *h = append(*h, value.(pruneKeeper)) } //nolint:errcheck // container/heap supplies pruneKeeper
func (h *pruneKeeperHeap) Pop() any {
	old := *h
	value := old[len(old)-1]
	*h = old[:len(old)-1]
	return value
}

func betterPruneKeeper(a, b pruneKeeper) bool {
	if a.primary != b.primary {
		return a.primary
	}
	if !a.location.Seen.Equal(b.location.Seen) {
		return a.location.Seen.Before(b.location.Seen)
	}
	return a.location.ID < b.location.ID
}

func (db *DB) choosePruneKeepers(ctx context.Context, group pruneArchiveGroup, quota int, through int64) ([]pruneLocation, error) {
	if quota == 0 {
		return nil, nil
	}
	var primary string
	err := db.queryLocations(ctx, `SELECT path FROM samples WHERE sha256=$1`, []any{group.SHA}, func(rows locationRows) error {
		if rows.Next() {
			return rows.Scan(&primary)
		}
		return rows.Err()
	})
	if err != nil {
		return nil, err
	}
	h := &pruneKeeperHeap{}
	err = db.queryLocations(ctx, `SELECT `+pruneLocationColumns+` FROM sample_locations
 WHERE sha256=$1 AND parent_sha256=$2 AND id<=$3 AND `+pruneInFileSQL, []any{group.SHA, group.Parent, through}, func(rows locationRows) error {
		for rows.Next() {
			l, err := scanPruneLocation(rows)
			if err != nil {
				return err
			}
			pushPruneKeeper(h, pruneKeeper{location: l, primary: l.Path == primary}, quota)
		}
		return rows.Err()
	})
	if err != nil {
		return nil, err
	}
	keep := make([]pruneLocation, 0, h.Len())
	for _, k := range *h {
		keep = append(keep, k.location)
	}
	return keep, nil
}

func (db *DB) trimPruneArchive(
	ctx context.Context, group pruneArchiveGroup, keep []pruneLocation, opts LocationPruneOptions, stats *LocationPruneStats, c *pruneChecker,
) error {
	ids := map[int64]bool{}
	for _, l := range keep {
		ids[l.ID] = true
	}
	// The existing (sha,parent,id DESC) index is a complete cursor; deleted
	// prefixes are never revisited. New IDs above the snapshot are deferred.
	before := stats.ThroughID
	for {
		var page []pruneLocation
		err := db.queryLocations(ctx, `SELECT `+pruneLocationColumns+` FROM sample_locations
 WHERE sha256=$1 AND parent_sha256=$2 AND id<=$3 AND `+pruneInFileSQL+`
 ORDER BY id DESC LIMIT $4`, []any{group.SHA, group.Parent, before, opts.Batch}, func(rows locationRows) error {
			for rows.Next() {
				l, err := scanPruneLocation(rows)
				if err != nil {
					return err
				}
				page = append(page, l)
			}
			return rows.Err()
		})
		if err != nil {
			return err
		}
		if len(page) == 0 {
			return nil
		}
		var victims []pruneLocation
		for _, l := range page {
			if !ids[l.ID] {
				victims = append(victims, l)
			}
		}
		if !opts.DryRun {
			n, p, err := db.deletePruneLocations(ctx, victims, true, keep, c, opts)
			if err != nil {
				return err
			}
			stats.Deleted += n
			stats.Protected += p
		}
		before = page[len(page)-1].ID - 1
		if err := reportLocationPrune(opts, stats); err != nil {
			return err
		}
	}
}

func (db *DB) updateLocationCapMarker(ctx context.Context, group pruneArchiveGroup, opts LocationPruneOptions) error {
	return db.locationTransaction(ctx, func(tx locationSQLTx) error {
		if err := lockLocationParent(tx, group.SHA); err != nil {
			return err
		}
		return refreshLocationCapMarker(tx, group, opts)
	})
}

func refreshLocationCapMarker(tx locationSQLTx, group pruneArchiveGroup, opts LocationPruneOptions) error {
	var label, skip, source string
	if err := tx.query(`SELECT label,skip,label_source FROM samples WHERE sha256=$1`, []any{group.SHA}, func(rows locationRows) error {
		if rows.Next() {
			return rows.Scan(&label, &skip, &source)
		}
		return rows.Err()
	}); err != nil {
		return err
	}
	limit := locationLabelCap(label, skip, source, opts)
	if limit == 0 {
		return tx.exec(`DELETE FROM hopper_kv WHERE key=$1`, group.key())
	}
	var full bool
	err := tx.query(`SELECT EXISTS(SELECT 1 FROM sample_locations
 WHERE sha256=$1 AND `+pruneInFileSQL+` LIMIT 1 OFFSET $2)`,
		[]any{group.SHA, limit - 1}, func(rows locationRows) error {
			if rows.Next() {
				return rows.Scan(&full)
			}
			return rows.Err()
		})
	if err != nil {
		return err
	}
	if !full {
		return tx.exec(`DELETE FROM hopper_kv WHERE key=$1`, group.key())
	}
	return tx.exec(`INSERT INTO hopper_kv(key,value) SELECT $2,CAST(id AS TEXT)||'/'||label FROM samples WHERE sha256=$1
 ON CONFLICT(key) DO UPDATE SET value=excluded.value`, group.SHA, group.key())
}
