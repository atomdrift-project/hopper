package store

import (
	"context"
	"errors"
	"fmt"

	"github.com/jackc/pgx/v5"
)

// GauntletRun is one published gauntlet run as the rows it is kept in.
// hopper.PrepareGauntletRun builds it, so the digest and the evidence keys
// follow the root package's rules; the store only writes them.
type GauntletRun struct {
	ID         string
	Producer   string
	ObservedAt string
	Source     string
	Digest     string // what an identical replay of the run hashes to
	Metadata   string // the run without its samples, as JSON
	Samples    []GauntletSample
	Withdrawn  []string
}

// GauntletSample is one member of a run.
type GauntletSample struct {
	SHA256   string
	Label    string
	Metadata string
	Results  []GauntletResult
	Eligible bool
}

// GauntletResult is one scanner's outcome for a member.
type GauntletResult struct {
	Scanner     string
	Status      string
	EvidenceKey string // what a gauntlet review of this outcome answers
	Payload     string
}

// ErrGauntletConflict reports a run whose identity is already stored with
// different content; the stored observations stand.
var ErrGauntletConflict = errors.New("store: gauntlet run identity has different content")

// AddGauntletRun records a run whole or not at all, and reports whether it
// was new. Replaying a stored run records nothing; replaying it with other
// content is ErrGauntletConflict.
//
// History is keyed by text sha256 and needs no sample row: a run outlives the
// corpus, and the gauntlet queue joins it to the files hopper holds.
func (st *Store) AddGauntletRun(ctx context.Context, r GauntletRun) (bool, error) {
	shas := make([]string, 0, len(r.Samples))
	labels := make([]string, 0, len(r.Samples))
	metas := make([]string, 0, len(r.Samples))
	eligible := make([]bool, 0, len(r.Samples))
	var resSHA, scanners, statuses, keys, payloads []string
	for _, s := range r.Samples {
		shas, labels, metas, eligible = append(shas, s.SHA256), append(labels, s.Label), append(metas, s.Metadata), append(eligible, s.Eligible)
		for _, v := range s.Results {
			resSHA, scanners, statuses = append(resSHA, s.SHA256), append(scanners, v.Scanner), append(statuses, v.Status)
			keys, payloads = append(keys, v.EvidenceKey), append(payloads, v.Payload)
		}
	}
	withdrawn := append([]string{}, r.Withdrawn...) // never NULL

	fresh := false
	err := pgx.BeginFunc(ctx, st.pool, func(tx pgx.Tx) error {
		// The run's key is taken first: a competing submission of the same run
		// waits on it, then finds it stored and compares digests.
		var id string
		err := tx.QueryRow(ctx, `INSERT INTO gauntlet_runs (id, producer, observed_at, source, digest, metadata)
			VALUES ($1, $2, $3, $4, $5, $6) ON CONFLICT (id) DO NOTHING RETURNING id`,
			r.ID, r.Producer, r.ObservedAt, r.Source, r.Digest, r.Metadata).Scan(&id)
		if errors.Is(err, pgx.ErrNoRows) {
			var stored string
			if err := tx.QueryRow(ctx, `SELECT digest FROM gauntlet_runs WHERE id = $1`, r.ID).Scan(&stored); err != nil {
				return err
			}
			if stored != r.Digest {
				return ErrGauntletConflict
			}
			return nil
		}
		if err != nil {
			return err
		}
		fresh = true
		if _, err := tx.Exec(ctx, `INSERT INTO gauntlet_samples (run_id, sha256, label, eligible, metadata)
			SELECT $1, sha, label, eligible, meta
			FROM unnest($2::text[], $3::text[], $4::boolean[], $5::text[]) AS t(sha, label, eligible, meta)`,
			r.ID, shas, labels, eligible, metas); err != nil {
			return err
		}
		if _, err := tx.Exec(ctx, `INSERT INTO gauntlet_results (run_id, sha256, scanner, status, evidence_key, payload)
			SELECT $1, sha, scanner, status, key, payload
			FROM unnest($2::text[], $3::text[], $4::text[], $5::text[], $6::text[]) AS t(sha, scanner, status, key, payload)`,
			r.ID, resSHA, scanners, statuses, keys, payloads); err != nil {
			return err
		}
		_, err = tx.Exec(ctx, `INSERT INTO gauntlet_withdrawals (run_id, sha256)
			SELECT $1, sha FROM unnest($2::text[]) AS t(sha) ON CONFLICT DO NOTHING`, r.ID, withdrawn)
		return err
	})
	switch {
	case errors.Is(err, ErrGauntletConflict):
		return false, err
	case err != nil:
		return false, fmt.Errorf("store: add gauntlet run %s: %w", r.ID, err)
	}
	return fresh, nil
}
