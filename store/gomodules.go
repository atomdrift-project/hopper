package store

// Go module backfill: rescan the Go module zips scanned before scan learned
// the go_module file type.
//
// Until filefacts identified Go proxy distribution zips by content
// (2026-10-23), they were typed plain "zip". A rescan is the fix rather than a
// relabel: go_module changes how the archive is walked, so a renamed row would
// keep its zip-era verdict, and a result that names a new type retypes the
// sample on its own (writer.lock, store/write.go).

import (
	"context"
	"errors"
	"fmt"
	"time"
)

// GoModuleRollout is when the fleet's scan had come to recognize go_module, and
// the default cutoff for QueueGoModules. Measured on galadriel 2026-11-28 over
// Go-named top-level files, by week of last scan: go_module first appears the
// week of 2026-10-19 (bar one in July), and from the week of 2026-11-02 only a
// few hundred a week are still typed zip, against tens of thousands of
// go_module. Since 2026-11-16, engine 3.x typed 456k go_module and ~320 zip.
//
// A fixed date, not one derived per run: a zip that is not a module is
// rescanned once, and only a cutoff that stays put keeps its new scan from
// matching again. Nor the earliest go_module scan: bare go.mod files are typed
// go_module too, and one from July would put the cutoff before nearly every
// zip.
var GoModuleRollout = time.Date(2026, 11, 2, 0, 0, 0, 0, time.UTC)

// goZips selects the scanned samples published under a Go module name and
// typed zip.
//
// One samples_name probe per Go name (~314k of ~4.3M names, 2.6M samples).
// OFFSET 0 keeps the subquery from being flattened: flattened, the planner
// misjudges how many samples a name holds and merge-joins names against the
// whole of samples_name in name order, reading samples rows of every name
// in between. On galadriel that ran past three minutes; probing per name,
// a full count takes 40-95s.
const goZips = `FROM names n
	CROSS JOIN LATERAL (SELECT s.id FROM samples s
		WHERE s.name_id = n.id AND s.file_type = 'zip' OFFSET 0) s
	JOIN scans sc ON sc.sample_id = s.id
	WHERE starts_with(n.name, 'pkg:golang/')`

// QueueGoModules queues as QueueRequested up to limit Go-named files still
// typed "zip" whose last scan predates before, newest first, and returns how
// many it queued. With dryRun it queues nothing and returns how many files
// match in total, ignoring limit.
//
// QueueRequested, the priority of a rescan an operator asked for, because
// QueueRepair sits below first scans, which are never empty: queued there
// these would never be handed out. The limit is what keeps a request this
// high from crowding first scans out for long.
//
// A candidate is on disk (there is something to scan), not already queued,
// and has a scans row, which also makes it top level: members have none.
// Selection is by name, not by bytes, so a zip that is not a module costs
// one rescan, after which its scan is past the cutoff and it never matches
// again; and a module zip that arrived under no Go name is not found.
func (st *Store) QueueGoModules(ctx context.Context, before time.Time, limit int, dryRun bool) (int64, error) {
	if before.IsZero() {
		return 0, errors.New("store: queue go modules: no cutoff")
	}
	const candidates = goZips + `
		AND sc.scanned_at < $1
		AND EXISTS (SELECT 1 FROM locations l WHERE l.sample_id = s.id)
		AND NOT EXISTS (SELECT 1 FROM queue q WHERE q.sample_id = s.id)`
	if dryRun {
		var n int64
		if err := st.pool.QueryRow(ctx, `SELECT count(*) `+candidates, before).Scan(&n); err != nil {
			return 0, fmt.Errorf("store: queue go modules: count: %w", err)
		}
		return n, nil
	}
	if limit <= 0 {
		return 0, fmt.Errorf("store: queue go modules: limit must be positive, got %d", limit)
	}
	// Inserted in id order, as QueueSiblings does, so concurrent enqueues
	// take their key locks in one order.
	tag, err := st.pool.Exec(ctx, `INSERT INTO queue (sample_id, priority)
		SELECT x.id, $3 FROM (
			SELECT s.id `+candidates+`
			ORDER BY s.id DESC LIMIT $2) x
		ORDER BY x.id
		ON CONFLICT (sample_id) DO NOTHING`, before, limit, int16(QueueRequested))
	if err != nil {
		return 0, fmt.Errorf("store: queue go modules: %w", err)
	}
	return tag.RowsAffected(), nil
}
