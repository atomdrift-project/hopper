package store

import (
	"context"
	"fmt"
	"time"

	"github.com/jackc/pgx/v5"
)

// Health is what hopper's metrics report of the corpus: whether files are
// arriving and being scanned, how much is queued, and how the acquirers are
// keeping up with the ledger.
type Health struct {
	// LatestArrived is when the newest file with a path of its own arrived;
	// LatestScanned when the newest scan was made. Zero when there are none.
	LatestArrived time.Time
	LatestScanned time.Time
	// OldestUnacquired is when the longest-waiting live claim no acquirer
	// has tried was made (see liveUnacquired); zero when there is none.
	OldestUnacquired time.Time
	// Depths counts queued files by priority; Stuck those handed out too
	// often without a result.
	Depths map[Priority]int64
	// SightedWait is how long the longest-waiting file sighted-pinned offers
	// has waited, counted from when its claim, the file and its first
	// analysis were all present. Zero when the queue is empty: files whose
	// retries ran out, or that no exact-version claim of the last day names,
	// are not work this queue can do.
	SightedWait time.Duration
	// Scanned counts scans made since the time asked for; Rescanned those of
	// files that arrived before it, which is as near as the store comes to
	// telling a rescan from a first scan (it keeps a file's latest scan).
	Scanned, Rescanned int64
	Stuck              int64
	// Unfinished counts acquisitions claimed before the time asked for that
	// never recorded how they ended.
	Unfinished int64
	Popular    int64 // packages ranked by popularity
}

// liveUnacquired selects the claims an acquirer still owes a try, made since
// they reached hopper rather than dated by a backfill (whose first_seen is
// the source's date or the epoch, exactly its published_at).
const liveUnacquired = `g.attempted_at IS NULL AND g.claim IN ('malicious', 'suspicious')
	AND g.first_seen <> 'epoch' AND g.first_seen IS DISTINCT FROM g.published_at`

// Health reads the corpus's health: scans counted since since, and
// acquisitions unfinished if claimed before unfinishedBefore.
func (st *Store) Health(ctx context.Context, since, unfinishedBefore time.Time) (*Health, error) {
	var h Health
	var arrived, scanned, unacquired *time.Time
	var sightedWait *float64
	// A digest claim counts only when hopper holds the bytes it names:
	// citing what nobody has is not work an acquirer can do.
	err := st.pool.QueryRow(ctx, `SELECT
			(SELECT s.created_at FROM samples s
			 WHERE EXISTS (SELECT 1 FROM locations l WHERE l.sample_id = s.id) ORDER BY s.id DESC LIMIT 1),
			(SELECT max(scanned_at) FROM scans),
			(SELECT count(*) FROM scans WHERE scanned_at >= $1),
			(SELECT count(*) FROM scans sc JOIN samples s ON s.id = sc.sample_id
			 WHERE sc.scanned_at >= $1 AND s.created_at < $1),
			(SELECT min(g.first_seen) FROM sightings g WHERE `+liveUnacquired+`
			   AND (starts_with(g.subject, 'pkg:') OR EXISTS (SELECT 1 FROM samples s
			     JOIN locations l ON l.sample_id = s.id
			     WHERE s.sha256 = CASE WHEN g.subject ~ '^[0-9a-f]{64}$' THEN decode(g.subject, 'hex') END))),
			(SELECT count(*) FROM sighting_acquisitions
			 WHERE finished_at IS NULL AND last_attempt IS NOT NULL AND last_attempt < $2),
			(SELECT count(*) FROM popular_packages)`,
		since, unfinishedBefore).Scan(&arrived, &scanned, &h.Scanned, &h.Rescanned,
		&unacquired, &h.Unfinished, &h.Popular)
	if err != nil {
		return nil, fmt.Errorf("store: health: %w", err)
	}
	// Its own query: the candidate clause binds $1 as the queue's report type.
	err = st.pool.QueryRow(ctx, sightedPinnedCandidates+`
		SELECT extract(epoch FROM now() - min(greatest(sighted, created_at, coalesce(scanned_at, created_at)))) FROM c`,
		"sighted-pinned", [][]byte{}).Scan(&sightedWait)
	if err != nil {
		return nil, fmt.Errorf("store: health: sighted wait: %w", err)
	}
	for _, t := range []struct {
		dst *time.Time
		src *time.Time
	}{{&h.LatestArrived, arrived}, {&h.LatestScanned, scanned}, {&h.OldestUnacquired, unacquired}} {
		if t.src != nil {
			*t.dst = t.src.UTC()
		}
	}
	if sightedWait != nil {
		h.SightedWait = time.Duration(*sightedWait * float64(time.Second))
	}
	if h.Depths, h.Stuck, err = st.Depths(ctx); err != nil {
		return nil, err
	}
	return &h, nil
}

// Watermark is the highest sample id issued: a count of every file hopper has
// ever recorded, members included, that never goes backwards. Differences
// between two readings are the arrival rate.
func (st *Store) Watermark(ctx context.Context) (int64, error) {
	var n int64
	if err := st.pool.QueryRow(ctx, `SELECT coalesce(max(id), 0) FROM samples`).Scan(&n); err != nil {
		return 0, fmt.Errorf("store: watermark: %w", err)
	}
	return n, nil
}

// Scanned counts the files scanned on their own.
func (st *Store) Scanned(ctx context.Context) (int64, error) {
	var n int64
	if err := st.pool.QueryRow(ctx, `SELECT count(*) FROM scans`).Scan(&n); err != nil {
		return 0, fmt.Errorf("store: scanned: %w", err)
	}
	return n, nil
}

// WorkFile is one file in a dashboard list: where it is and how atomscan
// judged it.
type WorkFile struct {
	Arrived   time.Time
	Scanned   *time.Time // nil until it is scanned on its own
	QueuedFor *time.Time // when it was queued, for a file waiting on a scan
	Source    string     // who put it where it is
	Feed      string
	Path      string
	Filename  string // the name it arrived under, when its sidecar says
	Type      string
	Class     string // atomscan's; empty before a verdict
	SHA256    []byte
}

// Backlog is the work queued for first scans from one source and feed.
type Backlog struct {
	Oldest, Newest time.Time
	Source, Feed   string
	Queued         int64
}

// Work is what the dashboard lists of the corpus.
type Work struct {
	Backlogs                  []Backlog
	Arrived, Scanned, Waiting []WorkFile // newest arrivals, newest scans, longest waiting
}

// firstScans are the priorities of files never scanned.
var firstScans = []int16{int16(QueueSighted), int16(QueueUpload), int16(QueueBigArchive), int16(QueueNew)}

// workFile selects a WorkFile for samples s, by its newest location.
const workFile = `SELECT s.created_at, sc.scanned_at, coalesce(l.source, ''), coalesce(l.feed, ''), coalesce(l.path, ''),
		coalesce(s.provenance->'artifact'->>'filename', ''), coalesce(s.file_type, ''), coalesce(v.class::text, ''), s.sha256, %s
	FROM %s
	LEFT JOIN scans sc ON sc.sample_id = s.id
	LEFT JOIN verdicts v ON v.sample_id = s.id AND v.scanner_id = 1
	LEFT JOIN LATERAL (SELECT source, feed, path FROM locations WHERE sample_id = s.id ORDER BY seen_at DESC LIMIT 1) l ON true`

// Work reads the dashboard's lists, limit rows each: the busiest first-scan
// backlogs by source and feed, the newest files with a path, the newest
// scans, and the files waiting longest for a first scan.
func (st *Store) Work(ctx context.Context, limit int) (*Work, error) {
	var w Work
	rows, err := st.pool.Query(ctx, `SELECT coalesce(l.source, ''), coalesce(l.feed, ''), count(*), min(q.queued_at), max(q.queued_at)
		FROM queue q
		LEFT JOIN LATERAL (SELECT source, feed FROM locations WHERE sample_id = q.sample_id ORDER BY seen_at DESC LIMIT 1) l ON true
		WHERE q.priority = ANY($1)
		GROUP BY 1, 2 ORDER BY 3 DESC LIMIT $2`, firstScans, limit)
	if err != nil {
		return nil, fmt.Errorf("store: work: backlogs: %w", err)
	}
	if w.Backlogs, err = pgx.CollectRows(rows, func(row pgx.CollectableRow) (Backlog, error) {
		var b Backlog
		return b, row.Scan(&b.Source, &b.Feed, &b.Queued, &b.Oldest, &b.Newest)
	}); err != nil {
		return nil, fmt.Errorf("store: work: backlogs: %w", err)
	}
	for _, list := range []struct {
		dst  *[]WorkFile
		name string
		from string
	}{
		{&w.Arrived, "arrived", fmt.Sprintf(workFile, "NULL::timestamptz", `(SELECT s.id, s.created_at, s.provenance, s.file_type, s.sha256
			FROM samples s WHERE EXISTS (SELECT 1 FROM locations l WHERE l.sample_id = s.id)
			ORDER BY s.id DESC LIMIT $1) s`) + ` ORDER BY s.id DESC`},
		{&w.Scanned, "scanned", fmt.Sprintf(workFile, "NULL::timestamptz", `(SELECT sample_id FROM scans ORDER BY scanned_at DESC LIMIT $1) n
			JOIN samples s ON s.id = n.sample_id`) + ` ORDER BY sc.scanned_at DESC`},
		{&w.Waiting, "waiting", fmt.Sprintf(workFile, "q.queued_at", `(SELECT sample_id, queued_at FROM queue
			WHERE priority = ANY($2) ORDER BY queued_at LIMIT $1) q JOIN samples s ON s.id = q.sample_id`) + ` ORDER BY q.queued_at`},
	} {
		args := []any{limit}
		if list.name == "waiting" {
			args = append(args, firstScans)
		}
		rows, err := st.pool.Query(ctx, list.from, args...)
		if err != nil {
			return nil, fmt.Errorf("store: work: %s: %w", list.name, err)
		}
		if *list.dst, err = pgx.CollectRows(rows, func(row pgx.CollectableRow) (WorkFile, error) {
			var f WorkFile
			return f, row.Scan(&f.Arrived, &f.Scanned, &f.Source, &f.Feed, &f.Path, &f.Filename, &f.Type, &f.Class, &f.SHA256, &f.QueuedFor)
		}); err != nil {
			return nil, fmt.Errorf("store: work: %s: %w", list.name, err)
		}
	}
	return &w, nil
}
