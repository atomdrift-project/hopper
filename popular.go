package hopper

import (
	"context"
	"fmt"
	"strconv"
	"strings"
	"time"
)

// PopularPackage is one package identity worth extra scrutiny, and how much.
//
// PURLBase is version-less on purpose — see the popular_packages migration.
// Rank is popularity order within Ecosystem, 1 being the most used.
type PopularPackage struct {
	PURLBase  string
	Ecosystem string
	Source    string
	Rank      int
}

// popularUpsertBatch bounds one statement's parameter count. Postgres caps a
// query at 65535 parameters and each row costs four, so this stays far enough
// under that a caller sending a whole ecosystem at once never has to know.
const popularUpsertBatch = 2000

// SetPopularPackages records a ranking, replacing what source previously said
// about each identity it names.
//
// Deliberately not a full replace of the source's rows: a ranking that arrives
// truncated — a feed half-read, a pass cut short — must not delete yesterday's
// good data for the packages it failed to mention. Identities that drop out of
// the top-1000 age out by updated_at instead, which a caller can prune on its
// own schedule.
func (db *DB) SetPopularPackages(ctx context.Context, pkgs []PopularPackage) error {
	if len(pkgs) == 0 {
		return nil
	}
	for start := 0; start < len(pkgs); start += popularUpsertBatch {
		end := min(start+popularUpsertBatch, len(pkgs))
		if err := db.upsertPopularBatch(ctx, pkgs[start:end]); err != nil {
			return err
		}
	}
	return nil
}

func (db *DB) upsertPopularBatch(ctx context.Context, pkgs []PopularPackage) error {
	now := time.Now().UTC()
	if db.pool == nil {
		return db.upsertPopularSQLite(ctx, pkgs, now)
	}
	var sb strings.Builder
	sb.WriteString(`INSERT INTO popular_packages (purl_base, ecosystem, rank, source, updated_at) VALUES `)
	args := make([]any, 0, len(pkgs)*5)
	for i, p := range pkgs {
		if i > 0 {
			sb.WriteByte(',')
		}
		n := i * 5
		sb.WriteString("($" + strconv.Itoa(n+1) + ",$" + strconv.Itoa(n+2) + ",$" +
			strconv.Itoa(n+3) + ",$" + strconv.Itoa(n+4) + ",$" + strconv.Itoa(n+5) + ")")
		args = append(args, p.PURLBase, p.Ecosystem, p.Rank, p.Source, now)
	}
	sb.WriteString(` ON CONFLICT (purl_base) DO UPDATE SET
		ecosystem = EXCLUDED.ecosystem, rank = EXCLUDED.rank,
		source = EXCLUDED.source, updated_at = EXCLUDED.updated_at`)
	if _, err := db.pool.Exec(ctx, sb.String(), args...); err != nil {
		return fmt.Errorf("hopper: set popular packages: %w", err)
	}
	return nil
}

func (db *DB) upsertPopularSQLite(ctx context.Context, pkgs []PopularPackage, now time.Time) error {
	tx, err := db.lite.BeginTx(ctx, nil)
	if err != nil {
		return fmt.Errorf("hopper: set popular packages: %w", err)
	}
	defer tx.Rollback() //nolint:errcheck // rolled back only if Commit did not run
	stmt, err := tx.PrepareContext(ctx, `
		INSERT INTO popular_packages (purl_base, ecosystem, rank, source, updated_at)
		VALUES (?,?,?,?,?)
		ON CONFLICT(purl_base) DO UPDATE SET
			ecosystem = excluded.ecosystem, rank = excluded.rank,
			source = excluded.source, updated_at = excluded.updated_at`)
	if err != nil {
		return fmt.Errorf("hopper: set popular packages: %w", err)
	}
	defer stmt.Close() //nolint:errcheck // statement closed with the tx
	for _, p := range pkgs {
		if _, err := stmt.ExecContext(ctx, p.PURLBase, p.Ecosystem, p.Rank, p.Source, now); err != nil {
			return fmt.Errorf("hopper: set popular packages: %w", err)
		}
	}
	if err := tx.Commit(); err != nil {
		return fmt.Errorf("hopper: set popular packages: %w", err)
	}
	return nil
}

// PopularPackageCount reports how many identities are marked, for the dashboard
// and for a caller checking that a publish landed.
func (db *DB) PopularPackageCount(ctx context.Context) (int, error) {
	var n int
	if db.pool != nil {
		if err := db.pool.QueryRow(ctx, `SELECT count(*) FROM popular_packages`).Scan(&n); err != nil {
			return 0, fmt.Errorf("hopper: popular count: %w", err)
		}
		return n, nil
	}
	if err := db.lite.QueryRowContext(ctx, `SELECT count(*) FROM popular_packages`).Scan(&n); err != nil {
		return 0, fmt.Errorf("hopper: popular count: %w", err)
	}
	return n, nil
}

// TriagePopular returns analyzed top-level samples belonging to a marked
// package that carry a detection, worst-ranked package first.
//
// Label-agnostic on purpose. Every other triage queue selects on what we
// believe about a sample; this one selects on what a mistake would cost. A
// false positive on a package a million people install is worth a human's time
// whether it is filed good, unknown, or bad — and it is worth far more than the
// same finding on a package nobody imports. Rank ordering is the point: a miss
// on rank 3 outranks a miss on rank 900.
//
// Like the -stale queues it does not self-drain — nothing about judging a
// sample removes it from the join — so callers pass ExcludeReportType to park
// what they have already ruled on until a re-analysis makes the question worth
// asking again.
func (db *DB) TriagePopular(ctx context.Context, limit int, f TriageFilter) ([]*Sample, error) {
	if db.pool != nil {
		return db.triagePopularPG(ctx, limit, f)
	}
	return db.triagePopularSQLite(ctx, limit, f)
}

func (db *DB) triagePopularPG(ctx context.Context, limit int, f TriageFilter) ([]*Sample, error) {
	extra, fargs := triageFilterClausePG(f, 1, "samples")
	args := append([]any{}, fargs...)
	args = append(args, limit)
	// EXISTS plus a correlated ORDER BY rather than a JOIN: the shared column
	// list is unqualified, and samples and popular_packages both have `source`,
	// so joining makes every one of those names ambiguous. popular_packages is
	// a few thousand rows keyed on the column being probed, so the subqueries
	// cost nothing worth restructuring the column list to avoid.
	rows, err := db.pool.Query(ctx,
		`SELECT `+pgSampleColsLight+` FROM samples
		 WHERE cleave_result IS NOT NULL AND parent = ''`+triageServablePathSQL+`
		   AND skip != 'conflict'
		   AND max_crit >= 3
		   AND purl_base != ''
		   AND EXISTS (SELECT 1 FROM popular_packages p WHERE p.purl_base = samples.purl_base)`+extra+`
		 ORDER BY (SELECT p.rank FROM popular_packages p WHERE p.purl_base = samples.purl_base) ASC,
		          analyzed_at DESC NULLS LAST, id DESC
		 LIMIT $`+strconv.Itoa(len(args)),
		args...)
	if err != nil {
		return nil, fmt.Errorf("hopper: triage popular: %w", err)
	}
	return scanPGSamplesLight(rows)
}

func (db *DB) triagePopularSQLite(ctx context.Context, limit int, f TriageFilter) ([]*Sample, error) {
	extra, fargs := triageFilterClauseSQLite(f, "samples")
	args := append([]any{}, fargs...)
	args = append(args, limit)
	//nolint:gosec // G202: predicates and column list are constant; filter values are parameterized via ? args
	rows, err := db.lite.QueryContext(ctx,
		`SELECT `+liteSampleColsLight+` FROM samples
		 WHERE cleave_result IS NOT NULL AND parent = ''`+triageServablePathSQL+`
		   AND skip != 'conflict'
		   AND max_crit >= 3
		   AND purl_base != ''
		   AND EXISTS (SELECT 1 FROM popular_packages p WHERE p.purl_base = samples.purl_base)`+extra+`
		 ORDER BY (SELECT p.rank FROM popular_packages p WHERE p.purl_base = samples.purl_base) ASC,
		          analyzed_at DESC, id DESC
		 LIMIT ?`,
		args...)
	if err != nil {
		return nil, fmt.Errorf("hopper: triage popular: %w", err)
	}
	return scanLiteSamplesLight(rows)
}

// PopularRanks returns the rank of every marked identity, keyed on purl_base.
//
// The whole set, not a per-sample probe: it is a few thousand rows totalling
// well under a megabyte, and the callers that want it — promoter deciding
// whether a package's standing earns it the benefit of the doubt — ask about
// one sample at a time, thousands of times. One query at startup beats one
// query per candidate against a table that changes once a day.
//
// A caller holding the result across a long run sees a snapshot; re-read it on
// whatever cadence its own freshness needs.
func (db *DB) PopularRanks(ctx context.Context) (map[string]int, error) {
	out := make(map[string]int)
	if db.pool != nil {
		rows, err := db.pool.Query(ctx, `SELECT purl_base, rank FROM popular_packages`)
		if err != nil {
			return nil, fmt.Errorf("hopper: popular ranks: %w", err)
		}
		defer rows.Close()
		for rows.Next() {
			var base string
			var rank int
			if err := rows.Scan(&base, &rank); err != nil {
				return nil, fmt.Errorf("hopper: popular ranks: %w", err)
			}
			out[base] = rank
		}
		if err := rows.Err(); err != nil {
			return nil, fmt.Errorf("hopper: popular ranks: %w", err)
		}
		return out, nil
	}
	rows, err := db.lite.QueryContext(ctx, `SELECT purl_base, rank FROM popular_packages`)
	if err != nil {
		return nil, fmt.Errorf("hopper: popular ranks: %w", err)
	}
	defer rows.Close() //nolint:errcheck // read-only
	for rows.Next() {
		var base string
		var rank int
		if err := rows.Scan(&base, &rank); err != nil {
			return nil, fmt.Errorf("hopper: popular ranks: %w", err)
		}
		out[base] = rank
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("hopper: popular ranks: %w", err)
	}
	return out, nil
}
