package store

import (
	"context"
	"fmt"
	"slices"
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
// respelled as names are (NameOf). A row's FirstSeen, when set, is when the
// claim was first made, for a source's backlog; otherwise it is now. A stored
// row only ever moves back in time. A row that would not change is not
// written. It returns how many rows were added or changed.
func (st *Store) AddSightings(ctx context.Context, rows []Sighting) (int, error) {
	if len(rows) == 0 {
		return 0, nil
	}
	n := len(rows)
	src, subj, url, note, op, aff, claim, file, handle, basis, relayer :=
		make([]string, n), make([]string, n), make([]string, n), make([]string, n), make([]string, n),
		make([]string, n), make([]string, n), make([]string, n), make([]string, n), make([]string, n), make([]string, n)
	published, seeded := make([]*time.Time, n), make([]*time.Time, n)
	for i := range rows {
		g := &rows[i]
		if !g.FirstSeen.IsZero() {
			t := g.FirstSeen.UTC()
			seeded[i] = &t
		}
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
			(source, subject, url, note, operator, affected, claim, filename, handle, basis, relayer, published_at, first_seen)
		SELECT src, subj, u, n, op, aff, cl, fn, h, bas, relay, pub, coalesce(seed, now())
		FROM unnest($1::text[], $2::text[], $3::text[], $4::text[], $5::text[], $6::text[],
		            $7::text[], $8::text[], $9::text[], $10::text[], $11::text[], $12::timestamptz[], $13::timestamptz[])
			AS t(src, subj, u, n, op, aff, cl, fn, h, bas, relay, pub, seed)
		ORDER BY src, subj, aff
		ON CONFLICT (source, subject, affected) DO UPDATE
			SET url = EXCLUDED.url, note = EXCLUDED.note, operator = EXCLUDED.operator, claim = EXCLUDED.claim,
			    filename = EXCLUDED.filename, handle = EXCLUDED.handle, basis = EXCLUDED.basis,
			    relayer = EXCLUDED.relayer, published_at = EXCLUDED.published_at,
			    first_seen = least(sightings.first_seen, EXCLUDED.first_seen)
			WHERE (sightings.url, sightings.note, sightings.operator, sightings.claim, sightings.filename,
			       sightings.handle, sightings.basis, sightings.relayer, sightings.published_at)
			  IS DISTINCT FROM (EXCLUDED.url, EXCLUDED.note, EXCLUDED.operator, EXCLUDED.claim, EXCLUDED.filename,
			                    EXCLUDED.handle, EXCLUDED.basis, EXCLUDED.relayer, EXCLUDED.published_at)
			   OR EXCLUDED.first_seen < sightings.first_seen
		RETURNING subject, affected`, src, subj, url, note, op, aff, claim, file, handle, basis, relayer, published, seeded)
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

// SightingKey names one row of the ledger.
type SightingKey struct {
	Source   string
	Subject  string // a lowercase sha256, or a package URL, respelled as names are
	Affected string
}

// keyColumns returns keys as three columns, package subjects respelled.
func keyColumns(keys []SightingKey) (sources, subjects, affected []string) {
	sources, subjects, affected = make([]string, len(keys)), make([]string, len(keys)), make([]string, len(keys))
	for i, k := range keys {
		sources[i], subjects[i], affected[i] = k.Source, k.Subject, k.Affected
		if strings.HasPrefix(k.Subject, "pkg:") {
			subjects[i] = NameOf(k.Subject)
		}
	}
	return sources, subjects, affected
}

// MarkAttempted records that something tried to acquire what each claim
// names, so no acquisition queue offers it again, and returns how many claims
// it marked. A claim marked already keeps its time.
func (st *Store) MarkAttempted(ctx context.Context, keys []SightingKey) (int64, error) {
	if len(keys) == 0 {
		return 0, nil
	}
	sources, subjects, affected := keyColumns(keys)
	tag, err := st.pool.Exec(ctx, `UPDATE sightings g SET attempted_at = now()
		FROM unnest($1::text[], $2::text[], $3::text[]) AS k(source, subject, affected)
		WHERE g.subject = k.subject AND g.source = k.source AND g.affected = k.affected AND g.attempted_at IS NULL`,
		sources, subjects, affected)
	if err != nil {
		return 0, fmt.Errorf("store: mark attempted: %w", err)
	}
	return tag.RowsAffected(), nil
}

// Retract removes claims their source no longer makes, and returns how many
// it removed. A file a retracted claim marked cited stays marked (see Cite).
func (st *Store) Retract(ctx context.Context, keys []SightingKey) (int64, error) {
	if len(keys) == 0 {
		return 0, nil
	}
	sources, subjects, affected := keyColumns(keys)
	tag, err := st.pool.Exec(ctx, `DELETE FROM sightings g
		USING unnest($1::text[], $2::text[], $3::text[]) AS k(source, subject, affected)
		WHERE g.subject = k.subject AND g.source = k.source AND g.affected = k.affected`,
		sources, subjects, affected)
	if err != nil {
		return 0, fmt.Errorf("store: retract: %w", err)
	}
	return tag.RowsAffected(), nil
}

// SourceKnown reports whether the ledger holds any claim from source.
func (st *Store) SourceKnown(ctx context.Context, source string) (bool, error) {
	var known bool
	if err := st.pool.QueryRow(ctx, `SELECT EXISTS (SELECT 1 FROM sightings WHERE source = $1)`, source).Scan(&known); err != nil {
		return false, fmt.Errorf("store: source known: %w", err)
	}
	return known, nil
}

// ClaimAcquisition claims target, a fetch an acquirer has in mind, for the
// caller, and reports whether it did. A target is claimed once ever: a
// second claim, whether the first finished or not, is refused, so a fetch
// that failed is not repeated by every pass. lease is when a person might
// reasonably open it again; nothing reopens it by itself. Only the claimant
// may give back a claim it could not finish (ReleaseAcquisition).
func (st *Store) ClaimAcquisition(ctx context.Context, target string, lease time.Duration) (bool, error) {
	tag, err := st.pool.Exec(ctx, `INSERT INTO sighting_acquisitions (target, attempts, last_attempt, next_attempt)
		VALUES ($1, 1, now(), now() + make_interval(secs => $2))
		ON CONFLICT (target) DO NOTHING`, target, lease.Seconds())
	if err != nil {
		return false, fmt.Errorf("store: claim acquisition: %w", err)
	}
	return tag.RowsAffected() == 1, nil
}

// FinishAcquisition records how the fetch of a claimed target ended:
// acquired, or not, with when a retry would be reasonable and why it failed.
// It reports false for a target nothing claimed.
func (st *Store) FinishAcquisition(ctx context.Context, target string, acquired bool, retryAfter time.Duration, reason string) (bool, error) {
	tag, err := st.pool.Exec(ctx, `UPDATE sighting_acquisitions
		SET acquired = $2, next_attempt = now() + make_interval(secs => $3), last_error = $4, finished_at = now()
		WHERE target = $1`, target, acquired, max(retryAfter, 0).Seconds(), reason)
	if err != nil {
		return false, fmt.Errorf("store: finish acquisition: %w", err)
	}
	return tag.RowsAffected() == 1, nil
}

// ReleaseAcquisition gives back a claim on target that its acquirer took but
// could not see through, because it was shutting down, so that target can be
// claimed again rather than reported as abandoned. Only a claim with no
// outcome is released: a finished or acquired row is another pass's completed
// work and is never erased. It reports whether a claim was released.
func (st *Store) ReleaseAcquisition(ctx context.Context, target string) (bool, error) {
	tag, err := st.pool.Exec(ctx, `DELETE FROM sighting_acquisitions
		WHERE target = $1 AND finished_at IS NULL AND NOT acquired`, target)
	if err != nil {
		return false, fmt.Errorf("store: release acquisition: %w", err)
	}
	return tag.RowsAffected() == 1, nil
}

// Reopened counts what ReopenAcquisitions changed, or would change.
type Reopened struct {
	// Targets is how many acquisition claims were deleted.
	Targets int64
	// Sightings is how many claims were offered to acquirers again.
	Sightings int64
	// Unmapped is how many of the targets name no ledger subject, so no
	// claim was offered again for them.
	Unmapped int64
}

// ReopenAcquisitions deletes the acquisition claims on targets, or on every
// target when none is named, so each can be claimed again, and offers the
// sightings they came from to acquirers again. Short of a claimant releasing
// a claim it never finished (ReleaseAcquisition), it is the only way a claimed
// target is retried, and it is an operator's to take (see ClaimAcquisition).
// An acquired target is never reopened: hopper holds its bytes.
// onlyUnfinished keeps to targets claimed without an outcome ever recorded,
// work lost with the pass that claimed it rather than work that failed.
//
// Deleting the claim is not enough. An acquirer reads only claims never
// attempted, and it stamps attempted the claims whose target another pass
// holds, so a target whose pass died has had its claims stamped by the next.
// Reopened alone, nothing would offer it again. So in the same transaction
// the malicious and suspicious claims about each target's subject lose their
// stamp. That is coarser than the target: a subject's other releases come
// back too, and cost an acquirer one read, since their targets are still
// claimed and it stamps them again.
//
// dryRun counts the same rows through the same predicates, writing nothing.
func (st *Store) ReopenAcquisitions(ctx context.Context, targets []string, onlyUnfinished, dryRun bool) (Reopened, error) {
	where := `NOT acquired AND ($1::text[] IS NULL OR target = ANY ($1))`
	if onlyUnfinished {
		where += ` AND finished_at IS NULL`
	}
	const stamped = `subject = ANY ($1) AND attempted_at IS NOT NULL AND claim IN ('malicious', 'suspicious')`
	reopen := `DELETE FROM sighting_acquisitions WHERE ` + where + ` RETURNING target`
	requeue := `WITH u AS (UPDATE sightings SET attempted_at = NULL WHERE ` + stamped + ` RETURNING 1)
		SELECT count(*) FROM u`
	if dryRun {
		reopen = `SELECT target FROM sighting_acquisitions WHERE ` + where
		requeue = `SELECT count(*) FROM sightings WHERE ` + stamped
	}
	// A nil array is "every target"; an empty one would be none.
	var named any
	if len(targets) > 0 {
		named = targets
	}

	var r Reopened
	err := pgx.BeginFunc(ctx, st.pool, func(tx pgx.Tx) error {
		rows, err := tx.Query(ctx, reopen, named)
		if err != nil {
			return err
		}
		reopened, err := pgx.CollectRows(rows, pgx.RowTo[string])
		if err != nil {
			return err
		}
		r.Targets = int64(len(reopened))
		subjects := make([]string, 0, len(reopened))
		for _, target := range reopened {
			if s := acquisitionSubject(target); s != "" {
				subjects = append(subjects, s)
			} else {
				r.Unmapped++
			}
		}
		if len(subjects) == 0 {
			return nil
		}
		slices.Sort(subjects)
		return tx.QueryRow(ctx, requeue, slices.Compact(subjects)).Scan(&r.Sightings)
	})
	if err != nil {
		return Reopened{}, fmt.Errorf("store: reopen acquisitions: %w", err)
	}
	return r, nil
}

// acquisitionSubject returns the ledger subject an acquisition target was
// made from, spelled as the ledger spells it, or "" for a target that names
// none. A target is the acquirer's spelling, and forager's are "sha256:" and
// a digest, or a package URL with a release ("@1.2.3", "@*" for every
// release, "@HEAD"), a tag qualifier, or a "#review-current" marker for a
// marketplace's current build. NameOf takes off all but the marker.
func acquisitionSubject(target string) string {
	if digest, ok := strings.CutPrefix(target, "sha256:"); ok {
		return strings.ToLower(digest)
	}
	if !strings.HasPrefix(target, "pkg:") {
		return ""
	}
	base, _ := strings.CutSuffix(target, "#review-current")
	return NameOf(base)
}
