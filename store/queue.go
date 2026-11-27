package store

import (
	"context"
	"errors"
	"fmt"
	"slices"
	"time"

	"github.com/jackc/pgx/v5"
)

// Priority orders queued work: lower is handed out first. The order is the
// claim ladder hopper served from samples before the queue existed.
//
// The values are stored in queue rows and compared as numbers, by every
// writer that raises a row and by least() when a file is queued twice, so a
// level keeps its value for good. They are spaced so that a new level fits
// between two others without rewriting the rows; until 2026-11-27 they were
// 0 to 6, and [Store.Upgrade] remaps rows written then.
type Priority int16

const (
	// QueueSighted is a file a feed has cited. The registry may withdraw it
	// within hours, so it goes first, newest first.
	QueueSighted Priority = 0
	// QueueUpload is a file someone is waiting on a page for.
	QueueUpload Priority = 10
	// QueueCompromised is a first scan of a file whose package some source
	// has called malicious, in any release (see compromised): a project
	// taken over once is the likeliest to be taken over again, and the
	// release that proves it may be withdrawn as fast as a sighted one. It
	// is below an upload, which a person is waiting on, and above a rescan
	// an operator asked for, which re-checks a file that already has a
	// verdict, where this file has none.
	QueueCompromised Priority = 15
	// QueueRequested is a rescan an operator asked for.
	QueueRequested Priority = 20
	// QueueDescribe is a rescan of a file scanned in the last week that
	// scan's LLM gate admitted and no LLM has described (see
	// owedDescription): files scan would have sent to the LLM, missing the
	// line that says why. A rescan, so below the one an operator asked for; above the
	// first scans of QueueBigArchive and QueueNew all the same, because they
	// are never empty, and a level below them would never be reached. Its
	// share of a batch is capped instead, so first scans keep the rest.
	QueueDescribe Priority = 25
	// QueueBigArchive is a first scan of a file over bigFile, offered only to
	// workers large enough for it.
	QueueBigArchive Priority = 30
	// QueueNew is a first scan.
	QueueNew Priority = 40
	// QueueRepair is an archive holding a file that got worse since it was
	// scanned.
	QueueRepair Priority = 50
	// QueueStale is a file whose verdict predates the ruleset or the rescan
	// age.
	QueueStale Priority = 60
)

// IsRescan reports whether p queues a file to be scanned again: a scan an
// operator asked for, a description owed, a repair, or a verdict gone stale.
// Every other priority is a first scan, so a first-scan priority added later
// counts as one without being listed here; a rescan priority must be added.
func (p Priority) IsRescan() bool {
	return slices.Contains(rescans, int16(p))
}

// rescans are the priorities of files queued to be scanned again, as the
// queries take them: a first scan is any priority not among them.
var rescans = []int16{int16(QueueRequested), int16(QueueDescribe), int16(QueueRepair), int16(QueueStale)}

// compromised is true of the file s when some source has called its package
// malicious, in any release: a claim about the package's name (a package URL
// without its version, or a URL), not about these bytes, so a claim that
// names this release exactly makes the file sighted instead (named()). A
// suspicious claim does not count: capability feeds and policy blocks call
// popular packages suspicious wholesale. Two index probes.
const compromised = `EXISTS (SELECT 1 FROM names n JOIN sightings g ON g.subject = n.name
	WHERE n.id = s.name_id AND g.claim = 'malicious')`

// bigFile is the size above which a first scan is queued as BigArchive.
const bigFile = 1 << 30

// A row handed out 8 times without a result is stuck. The queries spell the
// number out, as schema.sql's queue_next predicate does, for the planner to
// match it.

// unqueueUnlocated drops the queued scans of the files among $1 that have no
// path left to be read from.
const unqueueUnlocated = `DELETE FROM queue q USING (
		SELECT sample_id FROM queue WHERE sample_id = ANY($1)
		  AND NOT EXISTS (SELECT 1 FROM locations l WHERE l.sample_id = queue.sample_id)
		ORDER BY sample_id FOR UPDATE) k
	WHERE q.sample_id = k.sample_id`

// maxRequeue bounds how many containing archives one result can queue for
// repair, however many archives hold the files that got worse.
const maxRequeue = 256

// errorBackoff is how long a row waits after a scan that failed for a reason
// that may pass.
const errorBackoff = 6 * time.Hour

// Job is one queued file a worker can be handed.
type Job struct {
	QueuedAt      time.Time
	SHA256        string // hex
	Path          string // where it was most recently seen
	FileType      string
	SizeBytes     int64
	Priority      Priority
	HasProvenance bool
	// HasLLMInput is set on a file to describe whose LLM input hopper holds
	// (llminput.go): the worker runs the LLM pass alone. It is read only for
	// QueueDescribe, and false at every other priority.
	HasLLMInput bool
}

// Rescan queues a scan a person asked for of the file with digest sha256, and
// reports whether it did. It does not when hopper has nowhere to read the
// file from, or when atomscan has judged the file since the time given and no
// scan of it is owed: asking again for a scan still owed is granted, and
// clears its attempts and back-off, but a file just scanned is not scanned
// again for the asking.
func (st *Store) Rescan(ctx context.Context, sha256 []byte, since time.Time) (bool, error) {
	tag, err := st.pool.Exec(ctx, `INSERT INTO queue (sample_id, priority)
		SELECT s.id, $2 FROM samples s
		WHERE s.sha256 = $1
		  AND EXISTS (SELECT 1 FROM locations l WHERE l.sample_id = s.id)
		  AND (EXISTS (SELECT 1 FROM queue q WHERE q.sample_id = s.id)
		    OR NOT EXISTS (SELECT 1 FROM scans sc WHERE sc.sample_id = s.id AND sc.scanned_at >= $3))
		ON CONFLICT (sample_id) DO UPDATE SET
			priority = least(queue.priority, EXCLUDED.priority), attempts = 0, retry_at = NULL`,
		sha256, int16(QueueRequested), since)
	if err != nil {
		return false, fmt.Errorf("store: rescan: %w", err)
	}
	return tag.RowsAffected() > 0, nil
}

// Candidates returns up to n files of one priority that may be handed out
// now, no larger than maxBytes when it is positive and none of skipTypes. It
// reads; [Store.Lease] claims. A file with nowhere on disk to read it from is
// not a candidate, nor, for a worker with a size limit, one whose size is not
// known. skipTypes are the file types the worker cannot run, excluded here so
// that files it can never take do not fill the n rows it is shown and hide the
// ones behind them. A file whose type is not yet known is never skipped.
//
// Files never handed out come first, in the order they were queued (the
// newest first when sighted), then those whose retry time has come. Files to
// describe whose LLM input hopper holds come before all others of their
// level: describing them costs an LLM call, not a scan. After them, those the
// LLM gate admitted as required, whose description can change the verdict,
// come before those it admitted as optional.
func (st *Store) Candidates(ctx context.Context, p Priority, n int, maxBytes int64, skipTypes []string) ([]Job, error) {
	order := "q.retry_at NULLS FIRST, q.queued_at"
	if p == QueueSighted {
		order = "q.retry_at NULLS FIRST, q.queued_at DESC" // small; sorted, not walked
	}
	return st.queued(ctx, order, p, n, maxBytes, skipTypes)
}

// NewestCandidates is [Store.Candidates] read from the other end: files
// never handed out, the one hopper first saw last first, then those whose
// retry time has come. Newest is by arrival, samples.id, which is handed out
// as hopper first records a file and stays with it. queued_at does not: a
// file queued again after it lost its last path and was shown once more is
// no newer for it, and a mount coming back would re-queue its whole backlog
// at the front. The queue_newest index serves the order.
func (st *Store) NewestCandidates(ctx context.Context, p Priority, n int, maxBytes int64, skipTypes []string) ([]Job, error) {
	return st.queued(ctx, "q.retry_at NULLS FIRST, q.sample_id DESC", p, n, maxBytes, skipTypes)
}

// queued is Candidates in the given order. A file to describe is read with
// whether its LLM input is held, and those that have one go first, then the
// required admissions: the level is small, a week of admitted scans left
// undescribed, so it is sorted, not walked. No other level pays for the
// probes.
func (st *Store) queued(ctx context.Context, order string, p Priority, n int, maxBytes int64, skipTypes []string) ([]Job, error) {
	if skipTypes == nil {
		skipTypes = []string{} // a NULL array would make the comparison below match nothing
	}
	input := "false"
	if p == QueueDescribe {
		input = "EXISTS (SELECT 1 FROM llm_inputs i WHERE i.sample_id = q.sample_id)"
		order = "has_input DESC, EXISTS (SELECT 1 FROM scans sc WHERE sc.sample_id = q.sample_id AND sc.llm_admission = 'required') DESC, " + order
	}
	rows, err := st.pool.Query(ctx, `SELECT encode(s.sha256, 'hex'), l.path,
			coalesce(s.size_bytes, 0), coalesce(s.file_type, ''), q.queued_at, s.provenance IS NOT NULL,
			`+input+` AS has_input
		FROM queue q
		JOIN samples s ON s.id = q.sample_id
		CROSS JOIN LATERAL (SELECT path FROM locations
		                    WHERE sample_id = q.sample_id ORDER BY seen_at DESC LIMIT 1) l
		WHERE q.priority = $1 AND q.attempts < 8
		  AND (q.retry_at IS NULL OR q.retry_at <= now())
		  AND ($2::bigint <= 0 OR s.size_bytes <= $2::bigint)
		  AND coalesce(s.file_type, '') <> ALL($4::text[])
		ORDER BY `+order+`
		LIMIT $3`, int16(p), maxBytes, n, skipTypes)
	if err != nil {
		return nil, fmt.Errorf("store: candidates: %w", err)
	}
	jobs, err := pgx.CollectRows(rows, func(row pgx.CollectableRow) (Job, error) {
		j := Job{Priority: p}
		err := row.Scan(&j.SHA256, &j.Path, &j.SizeBytes, &j.FileType, &j.QueuedAt, &j.HasProvenance, &j.HasLLMInput)
		return j, err
	})
	if err != nil {
		return nil, fmt.Errorf("store: candidates: %w", err)
	}
	return jobs, nil
}

// Lease claims files, named by hex digest, for one worker until each one's
// lease has passed, and returns the digests it got. A file another worker is
// leasing, or that a result has removed from the queue, is left out; rows
// locked by a concurrent Lease are skipped rather than waited for.
func (st *Store) Lease(ctx context.Context, sha256s []string, leases []time.Duration) ([]string, error) {
	if len(sha256s) != len(leases) {
		return nil, fmt.Errorf("store: lease: %d files, %d leases", len(sha256s), len(leases))
	}
	rows, err := st.pool.Query(ctx, `WITH want AS (
			SELECT decode(u.sha, 'hex') AS sha, u.lease FROM unnest($1::text[], $2::interval[]) AS u(sha, lease)
		), free AS (
			SELECT q.sample_id, w.lease, s.sha256 FROM want w
			JOIN samples s ON s.sha256 = w.sha
			JOIN queue q ON q.sample_id = s.id
			WHERE q.attempts < 8 AND (q.retry_at IS NULL OR q.retry_at <= now())
			ORDER BY q.sample_id
			FOR UPDATE OF q SKIP LOCKED
		)
		UPDATE queue q SET attempts = q.attempts + 1, retry_at = now() + f.lease
		FROM free f WHERE q.sample_id = f.sample_id
		RETURNING encode(f.sha256, 'hex')`, sha256s, leases)
	if err != nil {
		return nil, fmt.Errorf("store: lease: %w", err)
	}
	got, err := pgx.CollectRows(rows, pgx.RowTo[string])
	if err != nil {
		return nil, fmt.Errorf("store: lease: %w", err)
	}
	return got, nil
}

// Release ends leases early without counting them, for files handed out but
// never worked on.
func (st *Store) Release(ctx context.Context, sha256s []string) error {
	if _, err := st.pool.Exec(ctx, `UPDATE queue q SET attempts = greatest(q.attempts - 1, 0), retry_at = NULL
		FROM samples s
		WHERE s.sha256 = ANY(SELECT decode(x, 'hex') FROM unnest($1::text[]) AS x)
		  AND q.sample_id = s.id AND q.retry_at > now()`, sha256s); err != nil {
		return fmt.Errorf("store: release: %w", err)
	}
	return nil
}

// Unlocate forgets that the file with hex digest sha256 is at path: it was
// not there, or something else was. A file left with no path leaves the
// queue: nothing could be handed to a worker.
func (st *Store) Unlocate(ctx context.Context, sha256, path string) error {
	err := pgx.BeginFunc(ctx, st.pool, func(tx pgx.Tx) error {
		var id int64
		err := tx.QueryRow(ctx, `DELETE FROM locations
			WHERE path = $2 AND sample_id = (SELECT id FROM samples WHERE sha256 = decode($1, 'hex'))
			RETURNING sample_id`, sha256, path).Scan(&id)
		if errors.Is(err, pgx.ErrNoRows) {
			return nil
		}
		if err != nil {
			return err
		}
		_, err = tx.Exec(ctx, unqueueUnlocated, []int64{id})
		return err
	})
	if err != nil {
		return fmt.Errorf("store: unlocate: %w", err)
	}
	return nil
}

// Depths counts queued files by priority, and how many of them are stuck.
func (st *Store) Depths(ctx context.Context) (depths map[Priority]int64, stuck int64, err error) {
	rows, err := st.pool.Query(ctx, `SELECT priority, attempts >= 8, count(*) FROM queue GROUP BY 1, 2`)
	if err != nil {
		return nil, 0, fmt.Errorf("store: depths: %w", err)
	}
	depths = make(map[Priority]int64, 8)
	var (
		p       Priority
		isStuck bool
		n       int64
	)
	if _, err := pgx.ForEachRow(rows, []any{&p, &isStuck, &n}, func() error {
		if isStuck {
			stuck += n
		} else {
			depths[p] += n
		}
		return nil
	}); err != nil {
		return nil, 0, fmt.Errorf("store: depths: %w", err)
	}
	return depths, stuck, nil
}

// Cursor is where a sweep continues: after the file with id ID, last scanned
// at At. The zero Cursor starts from the oldest scan.
type Cursor struct {
	At time.Time
	ID int64
}

// SweepStale queues as QueueStale the files on disk among the next limit,
// oldest scan first after the cursor, that were last scanned before before.
// It returns where to continue, the zero Cursor once no scan older than
// before is left. A file not on disk is passed over, not deleted: it may come
// back, and its last scan is still what a lookup reports.
//
// Age is the only test. The ruleset changes at least daily, so "judged under
// another ruleset" is true of nearly every file and would rescan the corpus
// without end; and a test that needs to be told the current ruleset stops
// working the day nobody tells it.
func (st *Store) SweepStale(ctx context.Context, after Cursor, before time.Time, limit int) (next Cursor, queued int64, err error) {
	var (
		n    int
		last *time.Time
		id   *int64
	)
	err = st.pool.QueryRow(ctx, `WITH page AS (
			SELECT sample_id, scanned_at FROM scans
			WHERE (scanned_at, sample_id) > ($1, $2) AND scanned_at < $3
			ORDER BY scanned_at, sample_id LIMIT $4
		), queued AS (
			INSERT INTO queue (sample_id, priority)
			SELECT p.sample_id, $5::smallint FROM page p
			WHERE EXISTS (SELECT 1 FROM locations l WHERE l.sample_id = p.sample_id)
			ORDER BY p.sample_id
			ON CONFLICT DO NOTHING
			RETURNING 1
		), tail AS (
			SELECT scanned_at, sample_id FROM page ORDER BY scanned_at DESC, sample_id DESC LIMIT 1
		)
		SELECT (SELECT count(*) FROM page), (SELECT scanned_at FROM tail), (SELECT sample_id FROM tail),
		       (SELECT count(*) FROM queued)`,
		after.At, after.ID, before.UTC(), limit, int16(QueueStale)).Scan(&n, &last, &id, &queued)
	if err != nil {
		return Cursor{}, 0, fmt.Errorf("store: sweep stale: %w", err)
	}
	if n < limit || last == nil {
		return Cursor{}, queued, nil
	}
	return Cursor{At: *last, ID: *id}, queued, nil
}

// maxNesting bounds how far up through containers a repair looks for the
// archives on disk that hold a file.
const maxNesting = 16

// queue settles the queue for what this result concluded: a file judged ok,
// unsupported or timed out is no longer owed a scan; one whose scan failed for
// a reason that may pass waits errorBackoff; and the archives on disk that
// hold a file that got worse, directly or through containers inside them, are
// queued for repair. An archive is left alone when it already judges itself
// at least as bad, or was last scanned under this result's ruleset: a rescan
// would read the same rules.
func (w *writer) queue(ctx context.Context) error {
	var done, failed []int64
	var notes []string
	for i := range w.files {
		switch o := w.outcome[i]; o.outcome {
		case "":
			continue // only named
		case "error":
			failed, notes = append(failed, w.ids[i]), append(notes, o.err)
		default:
			done = append(done, w.ids[i])
		}
	}
	if len(done) > 0 {
		rows, err := w.tx.Query(ctx, `DELETE FROM queue q USING (
				SELECT sample_id FROM queue WHERE sample_id = ANY($1) ORDER BY sample_id FOR UPDATE) k
			WHERE q.sample_id = k.sample_id
			RETURNING q.queued_at, q.priority`, done)
		if err != nil {
			return fmt.Errorf("queue: %w", err)
		}
		if w.stats.Completed, err = pgx.AppendRows(w.stats.Completed, rows, pgx.RowToStructByPos[QueuedScan]); err != nil {
			return fmt.Errorf("queue: %w", err)
		}
	}
	if len(failed) > 0 {
		if _, err := w.tx.Exec(ctx, `UPDATE queue q SET retry_at = now() + $3::interval, note = left(u.note, 200)
			FROM (SELECT u.sample_id, u.note FROM unnest($1::bigint[], $2::text[]) AS u(sample_id, note) ORDER BY 1) u
			WHERE q.sample_id = u.sample_id`, failed, notes, errorBackoff); err != nil {
			return fmt.Errorf("queue: %w", err)
		}
	}
	if len(w.rose) == 0 {
		return nil
	}
	ids, classes := make([]int64, 0, len(w.rose)), make([]string, 0, len(w.rose))
	for id, class := range w.rose {
		ids, classes = append(ids, id), append(classes, class)
	}
	tag, err := w.tx.Exec(ctx, `WITH RECURSIVE up(id, class, depth) AS (
			SELECT r.sample_id, r.class, 0 FROM unnest($1::bigint[], $2::class[]) AS r(sample_id, class)
			UNION
			SELECT c.parent_id, up.class, up.depth + 1 FROM up
			CROSS JOIN LATERAL (SELECT parent_id FROM contents WHERE child_ids @> ARRAY[up.id] LIMIT $6) c
			WHERE up.depth < $8
		)
		INSERT INTO queue (sample_id, priority)
		SELECT h.id, $4::smallint
		FROM (SELECT id, max(class) AS class FROM up WHERE depth > 0 GROUP BY id) h
		LEFT JOIN verdicts pv ON pv.sample_id = h.id AND pv.scanner_id = $5
		LEFT JOIN scans sc ON sc.sample_id = h.id
		WHERE h.id <> ALL($3)
		  AND (pv.class IS NULL OR pv.class < h.class) AND sc.ruleset IS DISTINCT FROM $7
		  AND EXISTS (SELECT 1 FROM locations l WHERE l.sample_id = h.id)
		ORDER BY 1
		LIMIT $6
		ON CONFLICT (sample_id) DO UPDATE SET priority = EXCLUDED.priority
		WHERE queue.priority > EXCLUDED.priority`,
		ids, classes, w.ids, int16(QueueRepair), atomscan, maxRequeue, w.files[0].Scan.Ruleset, maxNesting)
	if err != nil {
		return fmt.Errorf("queue repair: %w", err)
	}
	w.stats.Requeued = tag.RowsAffected()
	return nil
}

// QueueUnscanned queues a first scan of every file on disk that atomscan has
// not judged and that is not already queued, as ingest would have: a file a
// feed has cited as QueueSighted, a file of a compromised package as
// QueueCompromised, a big file as QueueBigArchive, anything else as
// QueueNew. It reads every sample, so it is for a migration or a repair, not
// a hot path.
func (st *Store) QueueUnscanned(ctx context.Context) (int64, error) {
	tag, err := st.pool.Exec(ctx, `INSERT INTO queue (sample_id, priority)
		SELECT s.id, CASE WHEN s.label = 'sighted' OR named(s.sha256, s.name_id, s.version) THEN $6::smallint
			WHEN `+compromised+` THEN $5::smallint
			WHEN s.size_bytes > $1 THEN $2::smallint ELSE $3::smallint END
		FROM samples s
		WHERE EXISTS (SELECT 1 FROM locations l WHERE l.sample_id = s.id)
		  AND NOT EXISTS (SELECT 1 FROM verdicts v WHERE v.sample_id = s.id AND v.scanner_id = $4)
		ORDER BY s.id
		ON CONFLICT (sample_id) DO NOTHING`,
		int64(bigFile), int16(QueueBigArchive), int16(QueueNew), atomscan, int16(QueueCompromised), int16(QueueSighted))
	if err != nil {
		return 0, fmt.Errorf("store: queue unscanned: %w", err)
	}
	return tag.RowsAffected(), nil
}
