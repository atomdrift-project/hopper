package store

import (
	"context"
	"fmt"
	"strings"
	"time"

	"github.com/jackc/pgx/v5"
)

// Sighting is one row of the ledger: what a source claims about a subject.
// The rule that weighs them is the root package's (hopper.AssessRelease); the
// store only reads them.
type Sighting struct {
	FirstSeen   time.Time
	PublishedAt time.Time // zero when the source gave none
	Source      string
	Relayer     string
	Operator    string
	Subject     string
	Affected    string
	URL         string
	Note        string
	FileName    string
	Handle      string
	Claim       string
	Basis       string
}

// ledgerRows bounds the rows read for one lookup: the citations of the file,
// its release, and what it points at or holds.
const ledgerRows = 4096

// Sightings returns the ledger's rows about each subject, by subject.
// Subjects are spelled as the ledger spells them: a lowercase sha256, or a
// package URL without its version as NameOf spells it.
func (st *Store) Sightings(ctx context.Context, subjects []string) (map[string][]Sighting, error) {
	out := map[string][]Sighting{}
	if len(subjects) == 0 {
		return out, nil
	}
	rows, err := st.pool.Query(ctx, sightingColumns+` FROM sightings g WHERE g.subject = ANY ($1)
		ORDER BY g.subject, g.source, g.affected LIMIT $2`, subjects, ledgerRows)
	if err != nil {
		return nil, fmt.Errorf("store: sightings: %w", err)
	}
	all, err := pgx.CollectRows(rows, scanSighting)
	if err != nil {
		return nil, fmt.Errorf("store: sightings: %w", err)
	}
	for i := range all {
		out[all[i].Subject] = append(out[all[i].Subject], all[i])
	}
	return out, nil
}

const sightingColumns = `SELECT g.first_seen, coalesce(g.published_at, 'epoch'::timestamptz), g.source, g.relayer,
	g.operator, g.subject, g.affected, g.url, g.note, g.filename, g.handle, g.claim, g.basis`

func scanSighting(row pgx.CollectableRow) (Sighting, error) {
	var g Sighting
	err := row.Scan(g.fields()...)
	g.clean()
	return g, err
}

// fields are the scan targets for sightingColumns, in order.
func (g *Sighting) fields() []any {
	return []any{
		&g.FirstSeen, &g.PublishedAt, &g.Source, &g.Relayer, &g.Operator, &g.Subject,
		&g.Affected, &g.URL, &g.Note, &g.FileName, &g.Handle, &g.Claim, &g.Basis,
	}
}

// clean turns the epoch sightingColumns reads for a missing publication time
// back into the zero time.
func (g *Sighting) clean() {
	if g.PublishedAt.Equal(time.Unix(0, 0)) {
		g.PublishedAt = time.Time{}
	}
}

// AddSightings records what sources claim, by (source, subject, affected),
// and marks the files the claims name (Cite). The rows come prepared by the
// ledger's rules (hopper.PrepareSightings); here a package subject is only
// respelled as names are (NameOf). A row that would not change is not
// written. It returns how many rows were added or changed.
func (st *Store) AddSightings(ctx context.Context, rows []Sighting) (int, error) {
	if len(rows) == 0 {
		return 0, nil
	}
	n := len(rows)
	src, subj, url, note, op, aff, claim, file, handle, basis, relayer :=
		make([]string, n), make([]string, n), make([]string, n), make([]string, n), make([]string, n),
		make([]string, n), make([]string, n), make([]string, n), make([]string, n), make([]string, n), make([]string, n)
	published := make([]*time.Time, n)
	for i := range rows {
		g := &rows[i]
		subj[i], basis[i] = g.Subject, g.Basis
		if strings.HasPrefix(subj[i], "pkg:") {
			subj[i] = NameOf(subj[i])
		}
		if basis[i] == "" {
			basis[i] = "predicted"
		}
		src[i], url[i], note[i], op[i], aff[i] = g.Source, g.URL, g.Note, g.Operator, g.Affected
		claim[i], file[i], handle[i], relayer[i] = g.Claim, g.FileName, g.Handle, g.Relayer
		if !g.PublishedAt.IsZero() {
			t := g.PublishedAt.UTC()
			published[i] = &t
		}
	}
	// Taken in key order, so two writers of the same rows cannot deadlock.
	rowsOut, err := st.pool.Query(ctx, `INSERT INTO sightings
			(source, subject, url, note, operator, affected, claim, filename, handle, basis, relayer, published_at)
		SELECT src, subj, u, n, op, aff, cl, fn, h, bas, relay, pub
		FROM unnest($1::text[], $2::text[], $3::text[], $4::text[], $5::text[], $6::text[],
		            $7::text[], $8::text[], $9::text[], $10::text[], $11::text[], $12::timestamptz[])
			AS t(src, subj, u, n, op, aff, cl, fn, h, bas, relay, pub)
		ORDER BY src, subj, aff
		ON CONFLICT (source, subject, affected) DO UPDATE
			SET url = EXCLUDED.url, note = EXCLUDED.note, operator = EXCLUDED.operator, claim = EXCLUDED.claim,
			    filename = EXCLUDED.filename, handle = EXCLUDED.handle, basis = EXCLUDED.basis,
			    relayer = EXCLUDED.relayer, published_at = EXCLUDED.published_at
			WHERE (sightings.url, sightings.note, sightings.operator, sightings.claim, sightings.filename,
			       sightings.handle, sightings.basis, sightings.relayer, sightings.published_at)
			  IS DISTINCT FROM (EXCLUDED.url, EXCLUDED.note, EXCLUDED.operator, EXCLUDED.claim, EXCLUDED.filename,
			                    EXCLUDED.handle, EXCLUDED.basis, EXCLUDED.relayer, EXCLUDED.published_at)
		RETURNING subject, affected`, src, subj, url, note, op, aff, claim, file, handle, basis, relayer, published)
	if err != nil {
		return 0, fmt.Errorf("store: add sightings: %w", err)
	}
	claims, err := pgx.CollectRows(rowsOut, func(row pgx.CollectableRow) (Claim, error) {
		var c Claim
		return c, row.Scan(&c.Subject, &c.Affected)
	})
	if err != nil {
		return 0, fmt.Errorf("store: add sightings: %w", err)
	}
	if err := st.Cite(ctx, claims); err != nil {
		return len(claims), err
	}
	return len(claims), nil
}
