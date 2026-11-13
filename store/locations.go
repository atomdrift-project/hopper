package store

import (
	"context"
	"encoding/hex"
	"errors"
	"fmt"

	"github.com/jackc/pgx/v5"
)

// A move takes a file from one path on disk to another, and may change its
// label on the way (a triage ruling files a file under good/ or bad/). The
// filesystem half is hopper.MoveLocation; these are the catalog half, in the
// order it calls them. A member's path is relative to its container in
// contents, so moving an archive moves nothing else.

// Relabel is a label a move applies.
type Relabel struct {
	Label  string
	Source string
}

// ErrLabelChanged reports that a file's label is no longer the one a move
// expected, or is held by a good/bad conflict.
var ErrLabelChanged = errors.New("store: label changed or unresolved")

// Labelled is what a relabel needs to know about a file.
type Labelled struct {
	Label       string
	LabelSource string
	// Paths are where it is on disk, most recently seen first.
	Paths []string
}

// LabelOf returns a file's label and where it is.
func (st *Store) LabelOf(ctx context.Context, sha256 []byte) (*Labelled, error) {
	var l Labelled
	err := st.pool.QueryRow(ctx, `SELECT s.label::text, coalesce(s.label_source, ''),
			coalesce(array(SELECT l.path FROM locations l WHERE l.sample_id = s.id ORDER BY l.seen_at DESC, l.path), '{}')
		FROM samples s WHERE s.sha256 = $1`, sha256).Scan(&l.Label, &l.LabelSource, &l.Paths)
	if errors.Is(err, pgx.ErrNoRows) {
		return nil, ErrNotFound
	}
	if err != nil {
		return nil, fmt.Errorf("store: label: %w", err)
	}
	return &l, nil
}

// Source is where a file's bytes can be read: its own paths on disk, or, for
// a member with none, an archive on disk that holds it.
type Source struct {
	// Holder is set when the file has no path of its own but an archive on
	// disk lists it.
	Holder *Holder
	// Paths are the file's own, most recently seen first.
	Paths []string
}

// Holder is an archive on disk and where a member sits in it.
type Holder struct {
	SHA256   string // hex
	FileType string
	Member   string // the member's path inside the archive
	Paths    []string
}

// Source returns where the file with this digest can be read. A file known
// but nowhere to be read has neither paths nor a holder. ErrNotFound means
// the file is not known at all.
func (st *Store) Source(ctx context.Context, sha256 []byte) (*Source, error) {
	var src Source
	var id int64
	err := st.pool.QueryRow(ctx, `SELECT s.id,
			coalesce(array(SELECT l.path FROM locations l WHERE l.sample_id = s.id ORDER BY l.seen_at DESC, l.path), '{}')
		FROM samples s WHERE s.sha256 = $1`, sha256).Scan(&id, &src.Paths)
	if errors.Is(err, pgx.ErrNoRows) {
		return nil, ErrNotFound
	}
	if err != nil {
		return nil, fmt.Errorf("store: source: %w", err)
	}
	if len(src.Paths) > 0 {
		return &src, nil
	}
	var h Holder
	err = st.pool.QueryRow(ctx, `SELECT encode(p.sha256, 'hex'), coalesce(p.file_type, ''), m.path,
			array(SELECT l.path FROM locations l WHERE l.sample_id = p.id ORDER BY l.seen_at DESC, l.path)
		FROM contents c
		JOIN samples p ON p.id = c.parent_id
		CROSS JOIN LATERAL unnest(c.child_ids, c.paths) AS m(child_id, path)
		WHERE c.child_ids @> ARRAY[$1::bigint] AND m.child_id = $1
		  AND EXISTS (SELECT 1 FROM locations l WHERE l.sample_id = p.id)
		ORDER BY p.id LIMIT 1`, id).Scan(&h.SHA256, &h.FileType, &h.Member, &h.Paths)
	switch {
	case errors.Is(err, pgx.ErrNoRows):
	case err != nil:
		return nil, fmt.Errorf("store: source: holder: %w", err)
	default:
		src.Holder = &h
	}
	return &src, nil
}

// LocationsRecorded reports whether each of two paths is recorded as holding
// the file.
func (st *Store) LocationsRecorded(ctx context.Context, sha256 []byte, first, second string) (firstOK, secondOK bool, err error) {
	err = st.pool.QueryRow(ctx, `SELECT
			EXISTS (SELECT 1 FROM locations l JOIN samples s ON s.id = l.sample_id WHERE l.path = $2 AND s.sha256 = $1),
			EXISTS (SELECT 1 FROM locations l JOIN samples s ON s.id = l.sample_id WHERE l.path = $3 AND s.sha256 = $1)`,
		sha256, first, second).Scan(&firstOK, &secondOK)
	if err != nil {
		return false, false, fmt.Errorf("store: locations recorded: %w", err)
	}
	return firstOK, secondOK, nil
}

// PrepareMove records the destination of a move, and any label change, while
// the source is still recorded: whatever happens next, the catalog names a
// path that holds the bytes. It reports false when neither end is recorded
// for the file. A destination path recorded for other bytes is an error; so
// is a label other than expectedLabel, when one is given.
//
// A label change is appended to label_events, and a file labelled bad has
// its last scan flagged for triage.
func (st *Store) PrepareMove(ctx context.Context, sha256 []byte, oldRel, newRel string, relabel *Relabel, expectedLabel string) (bool, error) {
	var prepared bool
	err := pgx.BeginFunc(ctx, st.pool, func(tx pgx.Tx) error {
		var (
			id            int64
			label, source string
		)
		err := tx.QueryRow(ctx, `SELECT id, label::text, coalesce(label_source, '') FROM samples WHERE sha256 = $1 FOR NO KEY UPDATE`,
			sha256).Scan(&id, &label, &source)
		if errors.Is(err, pgx.ErrNoRows) {
			return nil
		}
		if err != nil {
			return err
		}
		if expectedLabel != "" && (label != expectedLabel || source == "conflict") {
			return ErrLabelChanged
		}
		var oldHeld, newHeld bool
		if err := tx.QueryRow(ctx, `SELECT
				EXISTS (SELECT 1 FROM locations WHERE path = $2 AND sample_id = $1 FOR NO KEY UPDATE),
				EXISTS (SELECT 1 FROM locations WHERE path = $3 AND sample_id = $1)`, id, oldRel, newRel).Scan(&oldHeld, &newHeld); err != nil {
			return err
		}
		if !oldHeld && !newHeld {
			return nil
		}
		if oldHeld && oldRel != newRel {
			tag, err := tx.Exec(ctx, `INSERT INTO locations (path, sample_id, source, feed, mtime)
				SELECT $2, sample_id, source, feed, mtime FROM locations WHERE path = $1
				ON CONFLICT (path) DO UPDATE SET seen_at = now() WHERE locations.sample_id = EXCLUDED.sample_id`, oldRel, newRel)
			if err != nil {
				return err
			}
			if tag.RowsAffected() == 0 {
				return fmt.Errorf("destination %s holds other bytes", newRel)
			}
		}
		if relabel != nil {
			if label != relabel.Label {
				if _, err := tx.Exec(ctx, `INSERT INTO label_events (sha256, from_label, to_label, reason)
					VALUES (encode($1, 'hex'), $2, $3, 'triage')`, sha256, label, relabel.Label); err != nil {
					return err
				}
			}
			if _, err := tx.Exec(ctx, `UPDATE samples SET label = $2::label, label_source = nullif($3, '') WHERE id = $1`,
				id, relabel.Label, relabel.Source); err != nil {
				return err
			}
			if relabel.Label == "bad" {
				if _, err := tx.Exec(ctx, `UPDATE scans SET flagged = true WHERE sample_id = $1 AND NOT flagged`, id); err != nil {
					return err
				}
			}
		}
		prepared = true
		return nil
	})
	if err != nil {
		if errors.Is(err, ErrLabelChanged) {
			return false, err
		}
		return false, fmt.Errorf("store: prepare move: %w", err)
	}
	return prepared, nil
}

// FinishMove retires the source of a move once its destination is recorded,
// and reports whether the destination is.
func (st *Store) FinishMove(ctx context.Context, sha256 []byte, oldRel, newRel string) (bool, error) {
	var recorded bool
	err := st.pool.QueryRow(ctx, `WITH s AS (SELECT id FROM samples WHERE sha256 = $1),
		n AS (SELECT 1 FROM locations l JOIN s ON s.id = l.sample_id WHERE l.path = $3),
		gone AS (DELETE FROM locations l USING s WHERE l.path = $2 AND l.sample_id = s.id AND $2 <> $3 AND EXISTS (SELECT 1 FROM n))
		SELECT EXISTS (SELECT 1 FROM n)`, sha256, oldRel, newRel).Scan(&recorded)
	if err != nil {
		return false, fmt.Errorf("store: finish move: %w", err)
	}
	return recorded, nil
}

// Donors returns up to limit other paths of the file under pool/, for a move
// into pool to publish by hard link instead of by copy.
func (st *Store) Donors(ctx context.Context, sha256 []byte, pool string, limit int) ([]string, error) {
	if pool == "" || limit <= 0 {
		return nil, nil
	}
	rows, err := st.pool.Query(ctx, `SELECT l.path FROM locations l JOIN samples s ON s.id = l.sample_id
		WHERE s.sha256 = $1 AND starts_with(l.path, $2 || '/') ORDER BY l.path LIMIT $3`, sha256, pool, limit)
	if err != nil {
		return nil, fmt.Errorf("store: donors: %w", err)
	}
	return pgx.CollectRows(rows, pgx.RowTo[string])
}

// maxSiblingRescan bounds what one conviction queues: a popular package
// holds every release and build, and a conviction must not become a bulk
// rescan of it.
const maxSiblingRescan = 64

// QueueSiblings queues for repair the other files of a convicted file's
// release name (other releases, and other files of the same release) that
// are still unknown and were judged under another ruleset than the
// conviction's evidence: their verdicts predate knowing the package is
// compromised. The newest first, at most maxSiblingRescan; a file already
// queued is left where it is. It returns how many were queued.
func (st *Store) QueueSiblings(ctx context.Context, sha256 []byte) (int64, error) {
	tag, err := st.pool.Exec(ctx, `WITH c AS (
			SELECT s.id, s.name_id, sc.scanned_at, sc.ruleset FROM samples s
			LEFT JOIN scans sc ON sc.sample_id = s.id
			WHERE s.sha256 = $1 AND s.name_id IS NOT NULL)
		INSERT INTO queue (sample_id, priority)
		SELECT x.id, $2 FROM (
			SELECT p.id FROM c
			JOIN samples p ON p.name_id = c.name_id AND p.id <> c.id AND p.label = 'unknown'
			LEFT JOIN scans ps ON ps.sample_id = p.id
			WHERE EXISTS (SELECT 1 FROM locations l WHERE l.sample_id = p.id)
			  AND (ps.sample_id IS NULL OR ((c.scanned_at IS NULL OR ps.scanned_at <= c.scanned_at)
			                                AND ps.ruleset IS DISTINCT FROM c.ruleset))
			ORDER BY p.id DESC LIMIT $3) x
		ORDER BY x.id
		ON CONFLICT DO NOTHING`, sha256, int16(QueueRepair), maxSiblingRescan)
	if err != nil {
		return 0, fmt.Errorf("store: queue siblings %s: %w", hex.EncodeToString(sha256), err)
	}
	return tag.RowsAffected(), nil
}
