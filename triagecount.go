package hopper

// triagecount.go answers "how much work is in this queue right now" for the
// selectors whose population is a plain predicate over samples.
//
// The counts exist for an operator surface (cyclotron's dashboard and its
// queue-depth metric), not for the fleet's own decisions, and that shapes two
// choices:
//
//   - They are CAPPED. Nobody reading a backlog needs "254,197" rather than
//     "100000+", and an uncapped count over a hundred-million-row table is a
//     query whose cost is set by whichever queue happens to be largest.
//   - They share the selectors' predicates by construction (the triage*Where
//     constants below), because the failure mode of a hand-copied predicate is
//     a number that looks authoritative and quietly stops matching the queue it
//     claims to describe. TestTriageDepthMatchesSelection proves they agree.
//
// highest, lowest and stranded are counted differently, and the difference is
// worth knowing before reading their numbers. Those three select a bounded
// slice by construction — each route's top-K, or one archive's members — so
// counting what the selector RETURNS would just report the bound. What an
// operator actually wants is the population those queues are working through,
// so that is what they report, and it will not equal a selection. See
// TriageScoreDivider.

import (
	"context"
	"fmt"
	"strconv"
	"time"
)

// TriageDepthCap bounds every count here. A queue at the cap reports the cap;
// callers that care render it as "<cap>+".
const TriageDepthCap = 100000

// The shared population predicates. Each is the exact WHERE its Triage*
// selector uses, so the two cannot drift: the selector and the count read the
// same constant.
//
// Only triageNewWhere* is per-dialect, because SQLite has no LIKE-with-% path
// prefix idiom in use here — the selectors have always spelled it GLOB.
const (
	triageBadWhere = `label = 'bad' AND cleave_result IS NOT NULL AND parent = '' AND skip = ''` +
		triageServablePathSQL + `
		   AND max_crit < 5 AND suspicious_count < 2`

	triageGoodWhere = `label = 'good' AND cleave_result IS NOT NULL AND parent = '' AND skip = ''` +
		triageServablePathSQL + `
		   AND (max_crit >= 5 OR suspicious_count >= 2)`

	// The sighted queue is derived from the sightings ledger, not from the
	// legacy sighted label. A package claim applies either to the exact stored
	// version named by affected, or to every version when affected is empty.
	// Digest claims name bytes and therefore need no version arm. Malicious and
	// suspicious claims both need adjudication; vulnerability records describe a
	// legitimate package's security defect and do not belong in a malware queue.
	triageSightedWhere = `label != 'bad' AND cleave_result IS NOT NULL AND parent = '' AND skip = ''` +
		triageServablePathSQL + `
		   AND NOT EXISTS (SELECT 1 FROM reports r
		                   WHERE r.sha256 = samples.sha256 AND r.report_type = 'sighted')`

	triageNewWherePG = `label = 'unknown' AND cleave_result IS NOT NULL AND parent = '' AND skip = ''` +
		triageServablePathSQL + `
		   AND suspicious_count >= 1 AND path NOT LIKE 'review/%'`

	triageNewWhereSQLite = `label = 'unknown' AND cleave_result IS NOT NULL AND parent = '' AND skip = ''` +
		triageServablePathSQL + `
		   AND suspicious_count >= 1 AND path NOT GLOB 'review/*'`
)

// triageSightedMatchCTE deliberately starts from the comparatively small
// malware-relevant ledger slice and joins it into the indexed sample identities.
// Starting at samples would make every sighted poll probe the ledger once for
// each row in the full non-bad corpus. The UNION ALL keeps the digest and
// package index lookups independent; latest_sightings then collapses multiple
// sources and a possible digest+PURL double match to one candidate and its
// newest evidence.
const triageSightedMatchCTE = `WITH review_sightings AS (
		SELECT subject, affected, first_seen FROM sightings
		 WHERE claim IN ('malicious', 'suspicious')
	), matching_sightings AS (
		SELECT sm.sha256 AS matched_sha, s.first_seen AS sighted_at
		  FROM review_sightings s JOIN samples sm ON sm.sha256 = s.subject
		UNION ALL
		SELECT sm.sha256 AS matched_sha, s.first_seen AS sighted_at
		  FROM review_sightings s JOIN samples sm ON sm.purl_base = s.subject
		 WHERE sm.purl_base != ''
		   AND (s.affected = '' OR s.affected = sm.version)
	), latest_sightings AS (
		SELECT matched_sha, max(sighted_at) AS sighted_at
		  FROM matching_sightings GROUP BY matched_sha
	)
`

// triagePopularWhere is a var rather than a const because it embeds
// suspiciousCrit, and spelling that bound as a SQL literal here would put the
// number in two places — the one arrangement guaranteed to drift the day
// somebody retunes the floor.
var triagePopularWhere = `cleave_result IS NOT NULL AND parent = ''` + triageServablePathSQL + `
		   AND skip != 'conflict'
		   AND max_crit >= ` + strconv.Itoa(suspiciousCrit) + `
		   AND purl_base != ''
		   AND EXISTS (SELECT 1 FROM popular_packages p WHERE p.purl_base = samples.purl_base)`

// CountTriageBad reports how many samples TriageBad would draw from, capped at
// [TriageDepthCap]. Its siblings below mirror the other countable selectors.
func (db *DB) CountTriageBad(ctx context.Context, f TriageFilter) (int64, error) {
	return db.countTriage(ctx, "bad", triageBadWhere, triageBadWhere, f)
}

// CountTriageGood reports TriageGood's population, capped at [TriageDepthCap].
func (db *DB) CountTriageGood(ctx context.Context, f TriageFilter) (int64, error) {
	return db.countTriage(ctx, "good", triageGoodWhere, triageGoodWhere, f)
}

// CountTriageNew reports TriageNew's population, capped at [TriageDepthCap].
func (db *DB) CountTriageNew(ctx context.Context, f TriageFilter) (int64, error) {
	return db.countTriage(ctx, "new", triageNewWherePG, triageNewWhereSQLite, f)
}

// CountTriageSighted reports TriageSighted's population, capped at [TriageDepthCap].
func (db *DB) CountTriageSighted(ctx context.Context, f TriageFilter) (int64, error) {
	var n int64
	if db.pool != nil {
		extra, args := triageFilterClausePG(f, 1, "samples")
		args = append(args, TriageDepthCap)
		q := triageSightedMatchCTE + `SELECT count(*) FROM (
			SELECT 1 FROM samples
			JOIN latest_sightings ON latest_sightings.matched_sha = samples.sha256
			WHERE ` + triageSightedWhere + extra + `
			LIMIT $` + strconv.Itoa(len(args)) + `) q`
		if err := db.pool.QueryRow(ctx, q, args...).Scan(&n); err != nil {
			return 0, fmt.Errorf("hopper: count triage sighted: %w", err)
		}
		return n, nil
	}

	extra, args := triageFilterClauseSQLite(f, "samples")
	args = append(args, TriageDepthCap)
	q := triageSightedMatchCTE + `SELECT count(*) FROM (
		SELECT 1 FROM samples
		JOIN latest_sightings ON latest_sightings.matched_sha = samples.sha256
		WHERE ` + triageSightedWhere + extra + `
		LIMIT ?) q`
	if err := db.lite.QueryRowContext(ctx, q, args...).Scan(&n); err != nil {
		return 0, fmt.Errorf("hopper: count triage sighted: %w", err)
	}
	return n, nil
}

// CountTriagePopular reports TriagePopular's population, capped at
// [TriageDepthCap]. The most expensive of these by some margin — the EXISTS
// against popular_packages is a per-row probe — which is the reason the cap and
// the caller's refresh interval both exist.
func (db *DB) CountTriagePopular(ctx context.Context, f TriageFilter) (int64, error) {
	return db.countTriage(ctx, "popular", triagePopularWhere, triagePopularWhere, f)
}

// TriageScoreDivider splits the ensemble's opinion in half: at or above it the
// model calls a sample malicious, below it benign. It is what turns the
// score-ranked queues into a countable population, because their backlog is not
// "rows matching a predicate" but "rows the model and the label disagree
// about" — good samples scored hostile (highest) and bad samples scored clean
// (lowest).
//
// 0.5 is the neutral reading of a probability and nothing more. The queues
// themselves do NOT use it — they are rank-ordered and take each route's top-K
// wherever it falls — so moving this changes the reported backlog and no
// selection. That independence is the point: a depth that moved the work would
// be a worse instrument than no depth.
const TriageScoreDivider = 0.5

// CountTriageHighest reports how many good-labeled samples the model scores at
// or above divider — benign artifacts our own ensemble calls malicious, which
// is the population good:fp-peak grinds down. Not the selector's output: that
// is each route's top ten, whatever their scores.
func (db *DB) CountTriageHighest(ctx context.Context, divider float64, createdBefore, missingBefore time.Time, f TriageFilter) (int64, error) {
	return db.countScored(ctx, "highest", "good", ">=", divider, createdBefore, missingBefore, f)
}

// CountTriageLowest is the mirror: bad-labeled samples scored BELOW divider —
// known malware our ensemble calls clean, the population bad:ml-blind works.
func (db *DB) CountTriageLowest(ctx context.Context, divider float64, createdBefore, missingBefore time.Time, f TriageFilter) (int64, error) {
	return db.countScored(ctx, "lowest", "bad", "<", divider, createdBefore, missingBefore, f)
}

// countScored counts one side of the model/label disagreement, excluding rows
// already drained by a judgement report. cmp is ">=" or "<" and label is a
// literal from the two callers above — neither is caller-controlled.
func (db *DB) countScored(ctx context.Context, queue, label, cmp string, divider float64,
	createdBefore, missingBefore time.Time, f TriageFilter,
) (int64, error) {
	where := `label = '` + label + `' AND cleave_result IS NOT NULL AND skip = ''` +
		triageServablePathSQL + `
		   AND litmus_score IS NOT NULL AND litmus_score ` + cmp + ` %s
		   AND (parent = '' OR path LIKE '%%!!%%')
		   AND created_at < %s
		   AND NOT EXISTS (SELECT 1 FROM reports r
		                   WHERE r.sha256 = CASE WHEN samples.parent = '' THEN samples.sha256 ELSE samples.parent END
		                     AND (r.report_type = '` + queue + `'
		                          OR (r.report_type = '` + ReportTypeMissing + `' AND r.created_at > %s)))`
	return db.countTriageArgs(ctx, queue, where, []any{divider, createdBefore, missingBefore}, f)
}

// CountTriageStranded reports how many archive MEMBERS are still awaiting a
// verdict. Unlike highest/lowest this needs no divider: the queue's predicate is
// already a plain count, it is only the SELECTOR that collapses members to their
// parent archives. Members are what the work is measured in — one archive can
// hold dozens — so this is the more useful of the two numbers anyway.
func (db *DB) CountTriageStranded(ctx context.Context, createdBefore, missingBefore time.Time, f TriageFilter) (int64, error) {
	where := `label = 'good' AND cleave_result IS NOT NULL AND skip = ''
		   AND parent != '' AND path LIKE '%%!!%%'
		   AND score > 0 AND max_crit >= ` + strconv.Itoa(notableCrit) + `
		   AND label_source NOT LIKE 'cyclotron:%%'
		   AND created_at < %s
		   AND EXISTS (SELECT 1 FROM samples p WHERE p.sha256 = samples.parent AND p.label = 'bad')
		   AND NOT EXISTS (SELECT 1 FROM reports r
		                   WHERE r.sha256 = samples.sha256 AND r.report_type = 'stranded')
		   AND NOT EXISTS (SELECT 1 FROM reports r
		                   WHERE r.sha256 = samples.parent
		                     AND r.report_type = '` + ReportTypeMissing + `' AND r.created_at > %s)`
	return db.countTriageArgs(ctx, "stranded", where, []any{createdBefore, missingBefore}, f)
}

// countTriageArgs runs a capped count whose predicate carries its own bound
// parameters. where holds a %s per parameter, filled with the dialect's
// placeholder so one predicate string serves both.
func (db *DB) countTriageArgs(ctx context.Context, name, where string, pre []any, f TriageFilter) (int64, error) {
	var n int64
	if db.pool != nil {
		ph := make([]any, len(pre))
		for i := range pre {
			ph[i] = "$" + strconv.Itoa(i+1)
		}
		extra, fargs := triageFilterClausePG(f, len(pre)+1, "samples")
		args := append(append([]any{}, pre...), fargs...)
		args = append(args, TriageDepthCap)
		q := `SELECT count(*) FROM (SELECT 1 FROM samples WHERE ` +
			fmt.Sprintf(where, ph...) + extra + ` LIMIT $` + strconv.Itoa(len(args)) + `) q`
		if err := db.pool.QueryRow(ctx, q, args...).Scan(&n); err != nil {
			return 0, fmt.Errorf("hopper: count triage %s: %w", name, err)
		}
		return n, nil
	}
	ph := make([]any, len(pre))
	for i := range pre {
		ph[i] = "?"
	}
	extra, fargs := triageFilterClauseSQLite(f, "samples")
	// SQLite stores timestamps as RFC3339Nano text, so a bound time.Time
	// compares as a different type and silently matches nothing — the selectors
	// spell this out at each call site (createdBefore.UTC().Format(...)); this
	// helper takes any predicate's parameters, so it converts here instead.
	args := make([]any, 0, len(pre)+len(fargs)+1)
	for _, v := range pre {
		if t, ok := v.(time.Time); ok {
			v = t.UTC().Format(time.RFC3339Nano)
		}
		args = append(args, v)
	}
	args = append(args, fargs...)
	args = append(args, TriageDepthCap)

	q := `SELECT count(*) FROM (SELECT 1 FROM samples WHERE ` +
		fmt.Sprintf(where, ph...) + extra + ` LIMIT ?) q`
	if err := db.lite.QueryRowContext(ctx, q, args...).Scan(&n); err != nil {
		return 0, fmt.Errorf("hopper: count triage %s: %w", name, err)
	}
	return n, nil
}

// countTriage runs one capped count. The LIMIT lives inside a subquery rather
// than beside the count so it bounds the ROWS EXAMINED; a LIMIT on the outer
// aggregate would bound nothing, since count(*) always returns one row.
func (db *DB) countTriage(ctx context.Context, name, wherePG, whereLite string, f TriageFilter) (int64, error) {
	var n int64
	if db.pool != nil {
		extra, args := triageFilterClausePG(f, 1, "samples")
		args = append(args, TriageDepthCap)
		q := `SELECT count(*) FROM (SELECT 1 FROM samples WHERE ` + wherePG + extra +
			` LIMIT $` + strconv.Itoa(len(args)) + `) q`
		if err := db.pool.QueryRow(ctx, q, args...).Scan(&n); err != nil {
			return 0, fmt.Errorf("hopper: count triage %s: %w", name, err)
		}
		return n, nil
	}
	extra, args := triageFilterClauseSQLite(f, "samples")
	args = append(args, TriageDepthCap)

	q := `SELECT count(*) FROM (SELECT 1 FROM samples WHERE ` + whereLite + extra + ` LIMIT ?) q`
	if err := db.lite.QueryRowContext(ctx, q, args...).Scan(&n); err != nil {
		return 0, fmt.Errorf("hopper: count triage %s: %w", name, err)
	}
	return n, nil
}
