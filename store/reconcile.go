package store

import (
	"context"
	"fmt"
	"strings"
	"time"

	"github.com/jackc/pgx/v5"
)

// After a complete walk the catalog is made to agree with the disk: paths
// the walk saw that ingest did not record are learned, a file's label
// follows the pools its copies now sit in, and paths the walk did not see
// are retired. A member has no path of its own, so nothing cascades to
// members. This is the legacy ReconcilePools on the verdict schema.

// The breakers: a walk that saw too little must not rewrite the corpus. A
// reconcile that would relabel, or retire, more than maxChangePercent of the
// paths on disk (overall or in one pool) is refused as evidence of a bad
// walk (a missing mount, a renamed pool) rather than a changed corpus.
// Below minGuardedPopulation a corpus legitimately turns over wholesale.
const (
	maxChangePercent     = 15
	minGuardedPopulation = 100
)

// changeLimit is the most of n one reconcile step may change.
func changeLimit(n int64) int64 {
	if n < minGuardedPopulation {
		return n
	}
	return n * maxChangePercent / 100
}

// Reconciled counts what a reconcile changed.
type Reconciled struct {
	Learned   int64 // paths the walk saw that the catalog did not hold, or held for other bytes
	Relabeled int64 // files whose label or label source followed their pools
	Retired   int64 // paths the walk did not see and that are gone from disk
	Unlisted  int64 // paths the walk did not see that are still on disk: kept
}

// StartWalk empties the staging table for a new reconcile walk.
func (st *Store) StartWalk(ctx context.Context) error {
	if _, err := st.pool.Exec(ctx, `TRUNCATE walk_staging`); err != nil {
		return fmt.Errorf("store: start walk: %w", err)
	}
	return nil
}

// StageWalk records that the walk saw these files at these paths.
func (st *Store) StageWalk(ctx context.Context, shas [][]byte, paths []string) error {
	if len(shas) != len(paths) {
		return fmt.Errorf("store: stage walk: %d digests for %d paths", len(shas), len(paths))
	}
	_, err := st.pool.CopyFrom(ctx, pgx.Identifier{"walk_staging"}, []string{"path", "sha256"},
		pgx.CopyFromSlice(len(paths), func(i int) ([]any, error) { return []any{paths[i], shas[i]}, nil }))
	if err != nil {
		return fmt.Errorf("store: stage walk: %w", err)
	}
	return nil
}

// Reconcile makes the catalog agree with the walk just staged, which began at
// started. onDisk reports whether a path the walk did not see still exists,
// so a file the walker left out is kept rather than retired. With retire
// false (a data root that holds only part of the corpus, where absent means
// not on this host) nothing is retired; learning and relabelling still
// happen.
//
// A walk takes hours, and the catalog moves on meanwhile: what ingest, a move
// or a ruling recorded after the walk began is newer than what the walk saw,
// and stands.
func (st *Store) Reconcile(ctx context.Context, started time.Time, onDisk func(path string) bool, retire bool) (Reconciled, error) {
	var got Reconciled
	byPool, total, err := st.pathsByPool(ctx)
	if err != nil {
		return got, err
	}
	if got.Learned, err = st.learnStaged(ctx, started); err != nil {
		return got, err
	}
	if got.Relabeled, err = st.relabelFromPools(ctx, started, changeLimit(total)); err != nil {
		return got, err
	}
	if !retire {
		return got, nil
	}
	got.Retired, got.Unlisted, err = st.retireUnseen(ctx, onDisk, byPool, total)
	return got, err
}

// pathsByPool counts the paths on disk under each pool, the population the
// breakers take their share of.
func (st *Store) pathsByPool(ctx context.Context) (byPool map[string]int64, total int64, err error) {
	rows, err := st.pool.Query(ctx, `SELECT split_part(path, '/', 1), count(*) FROM locations GROUP BY 1`)
	if err != nil {
		return nil, 0, fmt.Errorf("store: reconcile counts: %w", err)
	}
	byPool = map[string]int64{}
	var (
		pool string
		n    int64
	)
	if _, err := pgx.ForEachRow(rows, []any{&pool, &n}, func() error {
		byPool[pool], total = n, total+n
		return nil
	}); err != nil {
		return nil, 0, fmt.Errorf("store: reconcile counts: %w", err)
	}
	return byPool, total, nil
}

// learnStaged records the staged paths the catalog lacks or holds for other
// bytes: a rename or a new hard link the hash cache recognised, which never
// reached ingest. What was recorded after the walk began is newer than what
// it saw: a path recorded for other bytes since keeps them, and a file given
// a path since (moved) does not get back the one it left. A file that loses
// its last path leaves the queue.
func (st *Store) learnStaged(ctx context.Context, started time.Time) (int64, error) {
	var learned int64
	err := pgx.BeginFunc(ctx, st.pool, func(tx pgx.Tx) error {
		rows, err := tx.Query(ctx, `INSERT INTO locations (path, sample_id)
			SELECT DISTINCT ON (w.path) w.path, s.id
			FROM walk_staging w JOIN samples s ON s.sha256 = w.sha256
			LEFT JOIN locations l ON l.path = w.path
			WHERE (l.path IS NULL AND NOT EXISTS (SELECT 1 FROM locations x WHERE x.sample_id = s.id AND x.seen_at >= $1))
			   OR (l.sample_id <> s.id AND l.seen_at < $1)
			ORDER BY w.path
			ON CONFLICT (path) DO UPDATE SET sample_id = EXCLUDED.sample_id, seen_at = now()
			WHERE locations.sample_id <> EXCLUDED.sample_id AND locations.seen_at < $1
			RETURNING old.sample_id`, started)
		if err != nil {
			return err
		}
		displaced, err := pgx.CollectRows(rows, func(row pgx.CollectableRow) (*int64, error) {
			var id *int64
			err := row.Scan(&id)
			return id, err
		})
		if err != nil {
			return err
		}
		learned = int64(len(displaced))
		var gone []int64
		for _, id := range displaced {
			if id != nil {
				gone = append(gone, *id)
			}
		}
		if len(gone) > 0 {
			_, err = tx.Exec(ctx, unqueueUnlocated, gone)
		}
		return err
	})
	if err != nil {
		return 0, fmt.Errorf("store: reconcile learn: %w", err)
	}
	return learned, nil
}

// relabelFromPools sets each staged file's label from the pools its copies
// sit in this walk, as legacy did: inconclusive/ (or purgatory/) and
// dual-use/ win, then bad/, then good/; sighted/ only lifts an unknown file;
// a file in both bad/ and good/ is bad, held as a conflict until one copy
// goes. A marker, and the reviewed labels, are never overridden, nor is a
// label changed since the walk began (a ruling, a move): the walk saw the
// file where it was before. A row is changed only if it still holds what
// was read. Refused, with nothing written, when more than limit files would
// change label.
func (st *Store) relabelFromPools(ctx context.Context, started time.Time, limit int64) (int64, error) {
	var changed, relabelled int64
	err := st.pool.QueryRow(ctx, `WITH pools AS (
				SELECT s.id, s.sha256, s.label, s.label_source,
				       bool_or(w.path LIKE 'bad/%') AS in_bad, bool_or(w.path LIKE 'good/%') AS in_good,
				       bool_or(w.path LIKE 'sighted/%') AS in_sighted,
				       bool_or(w.path LIKE 'inconclusive/%' OR w.path LIKE 'purgatory/%') AS in_inconclusive,
				       bool_or(w.path LIKE 'dual-use/%') AS in_dual_use
				FROM walk_staging w JOIN samples s ON s.sha256 = w.sha256
				WHERE s.label_source IS DISTINCT FROM 'marker' AND s.label NOT IN ('inconclusive', 'dual-use', 'purgatory')
				  AND NOT EXISTS (SELECT 1 FROM label_events e WHERE e.sha256 = encode(s.sha256, 'hex') AND e.observed_at >= $1)
				GROUP BY s.id
			), target AS (
				SELECT id, sha256, label AS old_label, label_source AS old_source,
				       CASE WHEN in_inconclusive THEN 'inconclusive' WHEN in_dual_use THEN 'dual-use'
				            WHEN in_bad THEN 'bad' WHEN in_good THEN 'good'
				            WHEN in_sighted AND label = 'unknown' THEN 'sighted'
				            ELSE label::text END::label AS new_label,
				       CASE WHEN in_inconclusive OR in_dual_use THEN label_source
				            WHEN in_bad AND in_good THEN 'conflict'
				            WHEN label_source = 'conflict' THEN NULL
				            ELSE label_source END AS new_source
				FROM pools
			), changed AS (
				SELECT id, sha256, old_label, old_source, new_label, new_source FROM target
				WHERE new_label <> old_label OR new_source IS DISTINCT FROM old_source
			), tally AS (
				SELECT count(*) AS n, count(*) FILTER (WHERE new_label <> old_label) AS moved FROM changed
			), allowed AS (
				SELECT c.* FROM changed c, tally WHERE tally.moved <= $2
			), relabel AS (
				UPDATE samples s SET label = c.new_label, label_source = c.new_source FROM allowed c
				WHERE s.id = c.id AND s.label = c.old_label AND s.label_source IS NOT DISTINCT FROM c.old_source
				RETURNING s.id, s.sha256, c.old_label, c.old_source, c.new_label, c.new_source
			), flag AS (
				UPDATE scans sc SET flagged = true FROM relabel c
				WHERE sc.sample_id = c.id AND c.new_label = 'bad' AND NOT sc.flagged
			), events AS (
				INSERT INTO label_events (sha256, from_label, to_label, from_skip, to_skip, reason)
				SELECT encode(sha256, 'hex'), old_label::text, new_label::text,
				       CASE WHEN old_source = 'conflict' THEN 'conflict' ELSE '' END,
				       CASE WHEN new_source = 'conflict' THEN 'conflict' ELSE '' END,
				       CASE WHEN new_source = 'conflict' THEN 'conflict' ELSE 'relabel' END
				FROM relabel
			)
			SELECT (SELECT count(*) FROM relabel), (SELECT moved FROM tally)`, started, limit).Scan(&changed, &relabelled)
	if err != nil {
		return 0, fmt.Errorf("store: reconcile relabel: %w", err)
	}
	if relabelled > limit {
		return 0, fmt.Errorf("store: reconcile: refusing to move %d files to another label (limit %d, %d%% of the paths on disk);"+
			" this likely means an incomplete walk or a missing mount", relabelled, limit, maxChangePercent)
	}
	return changed, nil
}

// retireUnseen retires the paths the walk did not see and that are gone
// from disk, after checking the breakers overall and per pool against what
// it would retire. A path the walk missed but that is still on disk is kept.
func (st *Store) retireUnseen(
	ctx context.Context, onDisk func(string) bool, byPool map[string]int64, total int64,
) (retired, unlisted int64, err error) {
	rows, err := st.pool.Query(ctx, `SELECT l.path FROM locations l
		WHERE NOT EXISTS (SELECT 1 FROM walk_staging w WHERE w.path = l.path)`)
	if err != nil {
		return 0, 0, fmt.Errorf("store: reconcile unseen: %w", err)
	}
	unseen, err := pgx.CollectRows(rows, pgx.RowTo[string])
	if err != nil {
		return 0, 0, fmt.Errorf("store: reconcile unseen: %w", err)
	}
	var gone []string
	goneByPool := map[string]int64{}
	for _, p := range unseen {
		if onDisk(p) {
			unlisted++
			continue
		}
		gone = append(gone, p)
		pool, _, _ := strings.Cut(p, "/")
		goneByPool[pool]++
	}
	if n := int64(len(gone)); n > changeLimit(total) {
		return 0, unlisted, fmt.Errorf("store: reconcile: refusing to retire %d of %d paths (>%d%%);"+
			" this likely means an incomplete walk or a storage failure", n, total, maxChangePercent)
	}
	for pool, n := range goneByPool {
		if n > changeLimit(byPool[pool]) {
			return 0, unlisted, fmt.Errorf("store: reconcile: refusing to retire %d of %d paths in %q (>%d%%);"+
				" this likely means an incomplete pool walk or a missing mount", n, byPool[pool], pool, maxChangePercent)
		}
	}
	if len(gone) == 0 {
		return 0, unlisted, nil
	}
	err = pgx.BeginFunc(ctx, st.pool, func(tx pgx.Tx) error {
		rows, err := tx.Query(ctx, `DELETE FROM locations WHERE path = ANY ($1) RETURNING sample_id`, gone)
		if err != nil {
			return err
		}
		ids, err := pgx.CollectRows(rows, pgx.RowTo[int64])
		if err != nil {
			return err
		}
		retired = int64(len(ids))
		_, err = tx.Exec(ctx, unqueueUnlocated, ids)
		return err
	})
	if err != nil {
		return 0, unlisted, fmt.Errorf("store: reconcile retire: %w", err)
	}
	return retired, unlisted, nil
}
