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

// goNamed selects the samples published under a Go module name. names is a
// few million rows, so filtering it whole and joining samples_name from the
// survivors is cheaper than any walk of samples.
const goNamed = `FROM names n
	JOIN samples s ON s.name_id = n.id
	JOIN scans sc ON sc.sample_id = s.id
	WHERE starts_with(n.name, 'pkg:golang/')`

// GoModuleScanStart returns the earliest last scan of any Go-named file typed
// go_module: an estimate of when the fleet began recognizing the type. ok is
// false when there is none, meaning no worker's scan recognizes it yet.
//
// The estimate only errs late, since the earliest such file may have been
// scanned again since, and late is the safe side: a zip scanned between the
// true rollout and this time is rescanned once for nothing, and its new scan
// then puts it past the cutoff for good.
func (st *Store) GoModuleScanStart(ctx context.Context) (t time.Time, ok bool, err error) {
	var at *time.Time
	if err := st.pool.QueryRow(ctx, `SELECT min(sc.scanned_at) `+goNamed+`
		AND s.file_type = 'go_module'`).Scan(&at); err != nil {
		return time.Time{}, false, fmt.Errorf("store: go_module scan start: %w", err)
	}
	if at == nil {
		return time.Time{}, false, nil
	}
	return at.UTC(), true, nil
}

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
	const candidates = goNamed + `
		AND s.file_type = 'zip' AND sc.scanned_at < $1
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
