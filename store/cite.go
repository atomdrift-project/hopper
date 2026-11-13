package store

import (
	"context"
	"fmt"

	"github.com/jackc/pgx/v5"
)

// A file is cited once some sighting names it (schema.sql, named()). The mark
// is set by the writers, never by a trigger, and after they commit: a claim
// and the file it names can commit at the same moment, and then neither
// transaction sees the other's row. Whichever commits second runs its
// marking after both commits, so it sees both, and the file is marked.
//
// The mark is only ever set. Claims are almost never withdrawn, and a file a
// withdrawn claim leaves marked costs the one queue that reads the mark
// (second, which checks the ledger again) a wasted row; [Store.Recite] puts
// the marks right whenever that matters, and after anything that wrote
// sightings without marking (psql, a crash between commit and mark).

// Claim is one row of the sightings ledger as far as citing is concerned:
// what it names (a lowercase sha256 or a package URL without its version,
// spelled as names spells it) and the releases it covers.
type Claim struct {
	Subject  string
	Affected string
}

// Cite marks the files the claims name, and moves those still waiting for
// their first scan to the front of the queue: a registry may withdraw a named
// package within hours. The sighting writer calls it once its claims have
// committed.
func (st *Store) Cite(ctx context.Context, claims []Claim) error {
	if len(claims) == 0 {
		return nil
	}
	subjects, affected := make([]string, len(claims)), make([]string, len(claims))
	for i, c := range claims {
		subjects[i], affected[i] = c.Subject, c.Affected
	}
	rows, err := st.pool.Query(ctx, `SELECT DISTINCT b.id
		FROM unnest($1::text[], $2::text[]) AS c(subject, affected), sighted_by(c.subject, c.affected) b`, subjects, affected)
	if err != nil {
		return fmt.Errorf("store: cite: %w", err)
	}
	ids, err := pgx.CollectRows(rows, pgx.RowTo[int64])
	if err != nil {
		return fmt.Errorf("store: cite: %w", err)
	}
	if err := st.cite(ctx, ids); err != nil {
		return fmt.Errorf("store: cite: %w", err)
	}
	return nil
}

// cite marks the files among ids that some sighting names, and raises those
// still waiting for their first scan to QueueSighted. Rows are taken in the
// order every writer takes them: samples by digest, queue by id.
func (st *Store) cite(ctx context.Context, ids []int64) error {
	if len(ids) == 0 {
		return nil
	}
	_, err := st.pool.Exec(ctx, `WITH n AS (
			SELECT s.id FROM samples s WHERE s.id = ANY($1) AND named(s.sha256, s.name_id, s.version)
		), marked AS (
			UPDATE samples s SET cited = true FROM (
				SELECT id FROM samples WHERE id IN (SELECT id FROM n) AND NOT cited ORDER BY sha256 FOR NO KEY UPDATE) k
			WHERE s.id = k.id
		)
		UPDATE queue q SET priority = $2 FROM (
			SELECT sample_id FROM queue WHERE sample_id IN (SELECT id FROM n) AND priority > $2
			  AND NOT EXISTS (SELECT 1 FROM verdicts v WHERE v.sample_id = queue.sample_id AND v.scanner_id = $3)
			ORDER BY sample_id FOR UPDATE) k
		WHERE q.sample_id = k.sample_id`, ids, int16(QueueSighted), atomscan)
	if err != nil {
		return fmt.Errorf("cite: %w", err)
	}
	return nil
}

// Recite recomputes every file's mark from the ledger: it marks what a
// sighting names and clears what none does. It reads every sighting and every
// marked file, so it is for a migration or a repair, not a hot path.
func (st *Store) Recite(ctx context.Context) (marked, cleared int64, err error) {
	tag, err := st.pool.Exec(ctx, `UPDATE samples s SET cited = true
		FROM (SELECT DISTINCT b.id FROM sightings g, sighted_by(g.subject, g.affected) b) k
		WHERE s.id = k.id AND NOT s.cited`)
	if err != nil {
		return 0, 0, fmt.Errorf("store: recite: %w", err)
	}
	marked = tag.RowsAffected()
	tag, err = st.pool.Exec(ctx, `UPDATE samples s SET cited = false
		WHERE s.cited AND NOT named(s.sha256, s.name_id, s.version)`)
	if err != nil {
		return marked, 0, fmt.Errorf("store: recite: %w", err)
	}
	return marked, tag.RowsAffected(), nil
}
