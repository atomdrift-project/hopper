package store

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"time"

	"github.com/jackc/pgx/v5"
)

// intake.go answers what producers and the services beside hopper ask of the
// corpus between scans: which files hopper can hand back, their capture
// sidecars, the hot pool a drain empties, popularity rankings, and whether a
// file or anything holding it has been sighted.

// Held returns the digests among shas whose bytes hopper can produce: a file
// at a path of its own, or one an archive at a path lists. A producer skips
// sending those. A row alone is no evidence of bytes (a dependency named by a
// scan has one), and a false "held" loses a file for good where a false
// "not held" costs one upload, so only those two count.
func (st *Store) Held(ctx context.Context, shas [][]byte) ([][]byte, error) {
	if len(shas) == 0 {
		return nil, nil
	}
	rows, err := st.pool.Query(ctx, `SELECT s.sha256 FROM samples s
		WHERE s.sha256 = ANY($1)
		  AND (EXISTS (SELECT 1 FROM locations l WHERE l.sample_id = s.id)
		    OR EXISTS (SELECT 1 FROM contents c
		      WHERE c.child_ids @> ARRAY[s.id] AND EXISTS (SELECT 1 FROM locations l WHERE l.sample_id = c.parent_id)))`,
		shas)
	if err != nil {
		return nil, fmt.Errorf("store: held: %w", err)
	}
	held, err := pgx.CollectRows(rows, pgx.RowTo[[]byte])
	if err != nil {
		return nil, fmt.Errorf("store: held: %w", err)
	}
	return held, nil
}

// Provenance returns the capture sidecar of the file with digest sha256: nil
// when it arrived without one, ErrNotFound when hopper has no such file.
func (st *Store) Provenance(ctx context.Context, sha256 []byte) (json.RawMessage, error) {
	var sidecar []byte
	err := st.pool.QueryRow(ctx, `SELECT provenance FROM samples WHERE sha256 = $1`, sha256).Scan(&sidecar)
	if errors.Is(err, pgx.ErrNoRows) {
		return nil, ErrNotFound
	}
	if err != nil {
		return nil, fmt.Errorf("store: provenance: %w", err)
	}
	return sidecar, nil
}

// SetProvenance replaces the capture sidecar of the file with digest sha256,
// as a refreshed registry record does, and reports whether hopper has the
// file. The release it names (name, a package URL with or without its
// version, and version) is the file's when the file had no sidecar before or
// no release: the first sidecar supersedes a release guessed from a filename,
// as [Store.Ingest] has it, and a later one only fills what is missing.
func (st *Store) SetProvenance(ctx context.Context, sha256, sidecar []byte, name, version string) (bool, error) {
	name, version = NameOf(storable(name)), storable(version)
	var (
		found   bool
		renamed *int64
	)
	err := pgx.BeginFunc(ctx, st.pool, func(tx pgx.Tx) error {
		if name != "" {
			if err := intern(ctx, tx, []string{name}); err != nil {
				return err
			}
		}
		err := tx.QueryRow(ctx, `UPDATE samples s SET provenance = $2,
				name_id = CASE WHEN n.id IS NOT NULL AND (s.name_id IS NULL OR s.provenance IS NULL) THEN n.id ELSE s.name_id END,
				version = CASE WHEN $4 <> '' AND (s.version = '' OR s.provenance IS NULL) THEN $4 ELSE s.version END
			FROM (SELECT (SELECT id FROM names WHERE name = $3 AND $3 <> '') AS id) n
			WHERE s.sha256 = $1
			RETURNING CASE WHEN (old.name_id, old.version) IS DISTINCT FROM (s.name_id, s.version) THEN s.id END`,
			sha256, sidecar, name, version).Scan(&renamed)
		if errors.Is(err, pgx.ErrNoRows) {
			return nil
		}
		found = err == nil
		return err
	})
	if err != nil {
		return false, fmt.Errorf("store: set provenance: %w", err)
	}
	if renamed != nil {
		// Newly given a release: a sighting may name it.
		if err := st.cite(ctx, []int64{*renamed}); err != nil {
			return true, fmt.Errorf("store: set provenance: %w", err)
		}
	}
	return found, nil
}

// incomingRange is the hot pool's slice of locations. Paths compare as bytes
// (COLLATE "C"), so the pool is a range of the key.
const incomingRange = `l.path >= 'incoming/' AND l.path < 'incoming0'`

// IncomingQuery selects one page of the hot pool, oldest first.
type IncomingQuery struct {
	// Before leaves out paths seen since: a file the walk found a moment ago
	// may still be being written.
	Before time.Time
	// AfterSeen and AfterPath resume after the last row of a page, so rows a
	// drain could not move do not stay at the head.
	AfterSeen time.Time
	AfterPath string
	// Unknown selects files no one has labelled; otherwise the labelled ones,
	// which belong in another pool already and are cheapest to move.
	Unknown bool
	Limit   int
}

// Incoming is one file in the hot pool and the label that decides where it
// goes.
type Incoming struct {
	SeenAt time.Time
	Mtime  *time.Time
	Path   string
	Label  string
	SHA256 []byte
}

// Incoming returns a page of the hot pool, the paths hopper has known longest
// first.
func (st *Store) Incoming(ctx context.Context, q IncomingQuery) ([]Incoming, error) {
	if q.Limit <= 0 {
		return nil, nil
	}
	var after *time.Time
	if !q.AfterSeen.IsZero() {
		after = &q.AfterSeen
	}
	rows, err := st.pool.Query(ctx, `SELECT l.seen_at, l.mtime, l.path, s.label::text, s.sha256
		FROM locations l JOIN samples s ON s.id = l.sample_id
		WHERE `+incomingRange+` AND l.seen_at < $1
		  AND ((s.label = 'unknown') = $2)
		  AND ($3::timestamptz IS NULL OR (l.seen_at, l.path) > ($3, $4::text COLLATE "C"))
		ORDER BY l.seen_at, l.path LIMIT $5`,
		q.Before, q.Unknown, after, q.AfterPath, q.Limit)
	if err != nil {
		return nil, fmt.Errorf("store: incoming: %w", err)
	}
	page, err := pgx.CollectRows(rows, func(row pgx.CollectableRow) (Incoming, error) {
		var in Incoming
		err := row.Scan(&in.SeenAt, &in.Mtime, &in.Path, &in.Label, &in.SHA256)
		return in, err
	})
	if err != nil {
		return nil, fmt.Errorf("store: incoming: %w", err)
	}
	return page, nil
}

// Popular is how widely used a package is within its ecosystem, by one
// source's ranking: Name is a package URL without its version, and Rank 1 the
// most used.
type Popular struct {
	Name      string
	Ecosystem string
	Source    string
	Rank      int
}

// SetPopular records a ranking, replacing what was said of each package it
// names. A package it leaves out keeps its row: a ranking cut short must not
// erase yesterday's. Two spellings of one package (PURLs fold case, and pypi
// underscores) keep the better rank.
func (st *Store) SetPopular(ctx context.Context, ranks []Popular) error {
	if len(ranks) == 0 {
		return nil
	}
	names, ecosystems, sources := make([]string, len(ranks)), make([]string, len(ranks)), make([]string, len(ranks))
	order := make([]int32, len(ranks))
	for i, p := range ranks {
		names[i], ecosystems[i], sources[i], order[i] = NameOf(p.Name), p.Ecosystem, p.Source, int32(p.Rank) //nolint:gosec // ranks are small
	}
	_, err := st.pool.Exec(ctx, `INSERT INTO popular_packages (purl_base, ecosystem, rank, source, updated_at)
		SELECT DISTINCT ON (r.name) r.name, r.ecosystem, r.rank, r.source, now()
		FROM unnest($1::text[], $2::text[], $3::int[], $4::text[]) AS r(name, ecosystem, rank, source)
		WHERE r.name <> ''
		ORDER BY r.name, r.rank
		ON CONFLICT (purl_base) DO UPDATE SET
			ecosystem = EXCLUDED.ecosystem, rank = EXCLUDED.rank,
			source = EXCLUDED.source, updated_at = EXCLUDED.updated_at`,
		names, ecosystems, order, sources)
	if err != nil {
		return fmt.Errorf("store: set popular: %w", err)
	}
	return nil
}

// maxAncestors bounds [Store.Ancestry]. A file held by more containers than
// this, at every depth together, is an answer hopper will not give rather
// than one it gives incomplete.
const maxAncestors = 4096

// Ancestor is a file and its release: the one asked about, or an archive
// that holds it, directly or through others.
type Ancestor struct {
	Name    string // the release's package URL without its version; empty for none
	Version string
	SHA256  []byte
	Depth   int // 0 for the file asked about, 1 for what holds it, and so on
}

// Ancestry returns the file with digest sha256 and every archive that holds
// it, nearest first: ErrNotFound when hopper has no such file, and an error
// rather than a partial answer when there are more than maxAncestors.
func (st *Store) Ancestry(ctx context.Context, sha256 []byte) ([]Ancestor, error) {
	rows, err := st.pool.Query(ctx, `WITH RECURSIVE up(id, depth) AS (
			SELECT id, 0 FROM samples WHERE sha256 = $1
			UNION
			SELECT c.parent_id, up.depth + 1 FROM up JOIN contents c ON c.child_ids @> ARRAY[up.id]
			WHERE up.depth < $2
		), nearest AS (SELECT id, min(depth) AS depth FROM up GROUP BY id LIMIT $3 + 1)
		SELECT coalesce(n.name, ''), s.version, s.sha256, a.depth
		FROM nearest a JOIN samples s ON s.id = a.id LEFT JOIN names n ON n.id = s.name_id
		ORDER BY a.depth, s.id`, sha256, maxMemberDepth, maxAncestors)
	if err != nil {
		return nil, fmt.Errorf("store: ancestry: %w", err)
	}
	chain, err := pgx.CollectRows(rows, func(row pgx.CollectableRow) (Ancestor, error) {
		var a Ancestor
		err := row.Scan(&a.Name, &a.Version, &a.SHA256, &a.Depth)
		return a, err
	})
	switch {
	case err != nil:
		return nil, fmt.Errorf("store: ancestry: %w", err)
	case len(chain) == 0:
		return nil, ErrNotFound
	case len(chain) > maxAncestors:
		return nil, fmt.Errorf("store: ancestry: more than %d archives hold the file", maxAncestors)
	}
	return chain, nil
}
