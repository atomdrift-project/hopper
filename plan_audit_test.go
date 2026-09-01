package hopper

import (
	"context"
	"fmt"
	"os"
	"strconv"
	"strings"
	"testing"
	"time"
)

// planAuditDSN is a Postgres DSN with production-like samples statistics.
// Without it, the EXPLAIN audit is skipped (SQLite / empty DBs can't show the
// seq-scan trap that only appears at tens of millions of rows).
//
//	HOPPER_PLAN_DSN='postgres://hopper@hopper-db/hopper?sslmode=disable' \
//	  go test ./... -run TestPlanAudit -count=1
func planAuditDSN(t *testing.T) string {
	t.Helper()
	for _, k := range []string{"HOPPER_PLAN_DSN", "DATABASE_URL"} {
		dsn := strings.TrimSpace(os.Getenv(k))
		if strings.HasPrefix(dsn, "postgres://") || strings.HasPrefix(dsn, "postgresql://") {
			return dsn
		}
	}
	t.Skip("set HOPPER_PLAN_DSN (or DATABASE_URL) to a postgres:// DSN with real samples stats to run plan audits")
	return ""
}

func openPlanDB(t *testing.T) *DB {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()
	db, err := Open(ctx, planAuditDSN(t), "hopper-test")
	if err != nil {
		t.Fatalf("Open plan DSN: %v", err)
	}
	t.Cleanup(func() { db.Close() })
	if db.Pool() == nil {
		t.Fatal("plan audit requires Postgres")
	}
	return db
}

// TestMarkCorroboratedSQLShape always runs: the mark-corroborated statements
// must stay single-column. Reintroducing `sha256 = ANY OR purl_base = ANY`
// is exactly the /api/sightings timeout we hit on 2026-08-17.
func TestMarkCorroboratedSQLShape(t *testing.T) {
	for _, tc := range []struct {
		name, sql string
		want      string
	}{
		{"by_sha", markCorroboratedBySHASQL, "sha256 = ANY"},
		{"by_purl", markCorroboratedByPURLSQL, "purl_base = ANY"},
		// The trigger body. Same rule, same reason: it is spliced into
		// sightings_corroborate() and would be untested SQL living in a
		// migration string otherwise.
		{"one_sha", markCorroboratedOneSHASQL, "sha256 = NEW.subject"},
		{"one_purl", markCorroboratedOnePURLSQL, "purl_base = NEW.subject"},
	} {
		sql := compactSQL(tc.sql)
		if !strings.Contains(sql, tc.want) {
			t.Errorf("%s: missing %q in %s", tc.name, tc.want, sql)
		}
		if strings.Contains(sql, "sha256") && strings.Contains(sql, "purl_base") {
			t.Errorf("%s: must not mention both sha256 and purl_base in one statement: %s", tc.name, sql)
		}
		if strings.Contains(sql, " OR ") {
			t.Errorf("%s: must not OR predicates (forces seq scan): %s", tc.name, sql)
		}
	}
	// Partial index idx_samples_purl_base is WHERE purl_base != ''; the query
	// must repeat that predicate or Postgres falls back to a seq scan.
	if !strings.Contains(compactSQL(markCorroboratedByPURLSQL), "purl_base <> ''") &&
		!strings.Contains(compactSQL(markCorroboratedByPURLSQL), "purl_base != ''") {
		t.Errorf("by_purl: missing purl_base <> '' (required to hit idx_samples_purl_base): %s",
			compactSQL(markCorroboratedByPURLSQL))
	}
}

// TestPlanAuditSamplesHotPaths EXPLAINs the hot samples-touching shapes against
// a real corpus and fails if Postgres plans a sequential scan of samples.
func TestPlanAuditSamplesHotPaths(t *testing.T) {
	db := openPlanDB(t)
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Minute)
	defer cancel()

	var reltuples float64
	if err := db.Pool().QueryRow(ctx,
		`SELECT reltuples FROM pg_class WHERE relname = 'samples'`).Scan(&reltuples); err != nil {
		t.Fatalf("samples reltuples: %v", err)
	}
	// Below ~100k the planner often seq-scans everything; the audit would be noise.
	const minRows = 100_000
	if reltuples < minRows {
		t.Skipf("samples reltuples=%.0f < %d; need production-like stats", reltuples, minRows)
	}
	t.Logf("samples reltuples=%.0f", reltuples)

	shas := planAuditSHAs(500)
	purls := planAuditPURLs(500)
	mixed := append(append([]string{}, shas...), purls...)

	// Calibration: the OR form that timed out /api/sightings must still seq-scan.
	// If the planner ever stops doing that, the positive checks below lose their
	// meaning and we should revisit rather than silently pass.
	badPlan := explainText(t, ctx, db,
		`EXPLAIN SELECT 1 FROM samples
		 WHERE NOT corroborated AND (sha256 = ANY($1) OR purl_base = ANY($1))`, mixed)
	if !planSeqScansSamples(badPlan) {
		t.Fatalf("calibration failed: OR form no longer seq-scans samples (planner changed?):\n%s", badPlan)
	}

	for _, tc := range []struct {
		name string
		sql  string
		args []string
	}{
		{
			name: "mark_corroborated_by_sha",
			// SET col = col keeps EXPLAIN UPDATE side-effect free.
			sql:  `EXPLAIN ` + strings.Replace(markCorroboratedBySHASQL, "SET corroborated = true", "SET corroborated = corroborated", 1),
			args: shas,
		},
		{
			name: "mark_corroborated_by_purl",
			sql:  `EXPLAIN ` + strings.Replace(markCorroboratedByPURLSQL, "SET corroborated = true", "SET corroborated = corroborated", 1),
			args: purls,
		},
		{
			name: "samples_by_shas",
			sql:  `EXPLAIN SELECT sha256 FROM samples WHERE sha256 = ANY($1)`,
			args: shas,
		},
		{
			// The trigger body, with NEW.subject standing in as a bind
			// parameter. A seq scan here would mean every inserted sighting
			// walks samples.
			name: "mark_corroborated_one_sha",
			sql: `EXPLAIN ` + strings.NewReplacer(
				"SET corroborated = true", "SET corroborated = corroborated",
				"NEW.subject", "$1").Replace(markCorroboratedOneSHASQL),
			args: shas[:1],
		},
		{
			name: "mark_corroborated_one_purl",
			sql: `EXPLAIN ` + strings.NewReplacer(
				"SET corroborated = true", "SET corroborated = corroborated",
				"NEW.subject", "$1").Replace(markCorroboratedOnePURLSQL),
			args: purls[:1],
		},
	} {
		plan := explainText(t, ctx, db, tc.sql, tc.args)
		if planSeqScansSamples(plan) {
			t.Errorf("%s: unexpected Seq Scan on samples:\n%s", tc.name, plan)
		} else {
			t.Logf("%s: ok\n%s", tc.name, firstPlanLines(plan))
		}
	}
}

// TestPlanAuditClaimQueues guards the two tiers that rank by corroboration.
//
// Both are polled by every worker on every claim, so a plan regression here is
// not a slow report — it is the whole fleet idling. The sighted tier must ride
// its partial index rather than filtering the 537k-row pending set, and the
// stale-traits tier must WALK idx_samples_stale_traits_pri2 in order: its
// failure mode is not a seq scan but a top-N sort over millions of rows, which
// is what cost 18s per poll before the expression index existed. A Sort node in
// that plan means the ORDER BY and the index definition have drifted apart.
func TestPlanAuditClaimQueues(t *testing.T) {
	db := openPlanDB(t)
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Minute)
	defer cancel()

	start := time.Now().Add(-time.Hour).UTC()

	sighted := explainText(t, ctx, db, `EXPLAIN `+sightedCandidatesSQL, start, maxClaimAttempts, 200)
	if planSeqScansSamples(sighted) {
		t.Errorf("sighted_candidates: unexpected Seq Scan on samples:\n%s", sighted)
	}
	if !strings.Contains(sighted, "idx_samples_pending_sighted") {
		t.Errorf("sighted_candidates: not using idx_samples_pending_sighted:\n%s", sighted)
	}
	t.Logf("sighted_candidates: ok\n%s", firstPlanLines(sighted))

	stale := explainText(t, ctx, db, `EXPLAIN `+staleTraitsCandidatesSQL,
		"plan-audit-traits", start, start, 200)
	if planSeqScansSamples(stale) {
		t.Errorf("stale_traits_candidates: unexpected Seq Scan on samples:\n%s", stale)
	}
	if !strings.Contains(stale, "idx_samples_stale_traits_pri2") {
		t.Errorf("stale_traits_candidates: not using idx_samples_stale_traits_pri2 "+
			"(ORDER BY drifted from the index?):\n%s", stale)
	}
	if strings.Contains(stale, "Sort") {
		t.Errorf("stale_traits_candidates: plan sorts instead of walking the index "+
			"in order; this is the 18s-per-poll regression:\n%s", stale)
	}
	t.Logf("stale_traits_candidates: ok\n%s", firstPlanLines(stale))
}

func explainText(t *testing.T, ctx context.Context, db *DB, sql string, args ...any) string {
	t.Helper()
	rows, err := db.Pool().Query(ctx, sql, args...)
	if err != nil {
		t.Fatalf("EXPLAIN: %v\nSQL: %s", err, compactSQL(sql))
	}
	defer rows.Close()
	var b strings.Builder
	for rows.Next() {
		var line string
		if err := rows.Scan(&line); err != nil {
			t.Fatalf("scan EXPLAIN: %v", err)
		}
		b.WriteString(line)
		b.WriteByte('\n')
	}
	if err := rows.Err(); err != nil {
		t.Fatalf("EXPLAIN rows: %v", err)
	}
	return b.String()
}

func planSeqScansSamples(plan string) bool {
	return planSeqScans(plan, "samples")
}

// planSeqScans reports whether the plan scans table sequentially. Matches both
// spellings the planner emits:
//
//	Parallel Seq Scan on <table>  → bad
//	Seq Scan on <table>           → bad
func planSeqScans(plan, table string) bool {
	for line := range strings.SplitSeq(plan, "\n") {
		if strings.Contains(line, "Seq Scan on "+table) {
			return true
		}
	}
	return false
}

// TestPlanAuditRepairStandaloneParents guards the shape repair-parents pages
// with. Paging on samples.id instead let the planner drive the semi-join from
// the ledger side: a full scan of sample_locations per batch with the cursor
// demoted to a post-scan filter, so every batch redid the same scan and the
// same sort to keep 20k rows of it — a repair that should cost minutes instead
// re-scanned the whole ledger once per page. The page must stay an ordered
// walk of sample_locations bounded by its own id.
func TestPlanAuditRepairStandaloneParents(t *testing.T) {
	db := openPlanDB(t)
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Minute)
	defer cancel()

	var reltuples float64
	if err := db.Pool().QueryRow(ctx,
		`SELECT reltuples FROM pg_class WHERE relname = 'sample_locations'`).Scan(&reltuples); err != nil {
		t.Fatalf("sample_locations reltuples: %v", err)
	}
	const minRows = 100_000
	if reltuples < minRows {
		t.Skipf("sample_locations reltuples=%.0f < %d; need production-like stats", reltuples, minRows)
	}
	t.Logf("sample_locations reltuples=%.0f", reltuples)

	rows, err := db.Pool().Query(ctx, `EXPLAIN `+repairStandaloneParentsPageSQL, int64(0), 20000)
	if err != nil {
		t.Fatalf("EXPLAIN: %v\nSQL: %s", err, compactSQL(repairStandaloneParentsPageSQL))
	}
	var b strings.Builder
	for rows.Next() {
		var line string
		if err := rows.Scan(&line); err != nil {
			rows.Close()
			t.Fatalf("scan EXPLAIN: %v", err)
		}
		b.WriteString(line)
		b.WriteByte('\n')
	}
	rows.Close()
	if err := rows.Err(); err != nil {
		t.Fatalf("EXPLAIN rows: %v", err)
	}
	plan := b.String()

	if planSeqScans(plan, "sample_locations") {
		t.Errorf("repair page seq-scans sample_locations:\n%s", plan)
	}
	// The cursor must bound the scan, not filter its result. Without this the
	// plan is still index-ish but every page walks the whole ledger again.
	if !strings.Contains(plan, "Index Cond: (id > ") {
		t.Errorf("repair page does not use id as an index bound:\n%s", plan)
	}
	t.Logf("repair_standalone_parents_page: ok\n%s", firstPlanLines(plan))
}

func planAuditSHAs(n int) []string {
	out := make([]string, n)
	for i := range n {
		out[i] = fmt.Sprintf("%064x", i+1)
	}
	return out
}

func planAuditPURLs(n int) []string {
	out := make([]string, n)
	for i := range n {
		out[i] = fmt.Sprintf("pkg:npm/plan-audit-%d", i)
	}
	return out
}

func compactSQL(s string) string {
	return strings.Join(strings.Fields(s), " ")
}

// firstPlanLines trims a plan to its top nodes for -v output. Depth is fixed:
// every caller wants the same look at the top of the tree, and the interesting
// node — the scan or the sort — is always in the first few lines.
func firstPlanLines(plan string) string {
	const depth = 8
	lines := strings.Split(strings.TrimSpace(plan), "\n")
	if len(lines) > depth {
		lines = lines[:depth]
	}
	for i, line := range lines {
		// Collapse huge ANY('{...}') literals so -v output stays readable.
		if j := strings.Index(line, "ANY ('{"); j >= 0 {
			if k := strings.Index(line[j:], "}')"); k >= 0 {
				lines[i] = line[:j] + "ANY ('{…}')" + line[j+k+3:]
			}
		}
	}
	return strings.Join(lines, "\n")
}

// TestPlanAuditUnconvictedQueues is the efficiency guard for the queues that
// replaced good/new. Each selector must WALK its partial index in order rather
// than scan-and-sort: at the table's real size the difference is the 8-99s
// measurements recorded beside the index list, and every one of those exceeds
// the API's apiQueryTimeout, which means the queue never runs at all.
//
// Two distinct failures are checked because they have different causes. A Seq
// Scan means the partial index predicate no longer matches the query's (the
// index is not slow, it is unused). A Sort means the ORDER BY drifted from the
// index's key list — the plan still finds the rows, then sorts the whole
// partition to order them.
func TestPlanAuditUnconvictedQueues(t *testing.T) {
	db := openPlanDB(t)
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Minute)
	defer cancel()

	for _, tc := range []struct {
		name  string
		where string
		order TriageFilter
		index string
	}{
		{
			name: "unconvicted-hostile", where: triageUnconvictedHostileWhere,
			order: TriageFilter{Order: TriageRepair}, index: "idx_samples_unconvicted_hostile_repair",
		},
		{
			name: "unconvicted-hostile-stale", where: triageUnconvictedHostileWhere,
			order: TriageFilter{Order: TriageStale}, index: "idx_samples_unconvicted_hostile_stale",
		},
		{
			name: "unconvicted-suspicious", where: triageUnconvictedSuspiciousWhere,
			order: TriageFilter{Order: TriageRepair}, index: "idx_samples_unconvicted_susp_repair",
		},
		{
			name: "unconvicted-suspicious-stale", where: triageUnconvictedSuspiciousWhere,
			order: TriageFilter{Order: TriageStale}, index: "idx_samples_unconvicted_susp_stale",
		},
		{
			name: "discord", where: triageDiscordWherePG,
			order: TriageFilter{}, index: "idx_samples_discord_newest",
		},
		{
			name: "fp-trait", where: triageFPTraitWhere,
			order: TriageFilter{}, index: "idx_samples_fp_trait_newest",
		},
		// version-drift's sibling test is a cross-row EXISTS and cannot live in
		// the partial, so this checks the half that can: the candidate walk must
		// still be an ordered index scan. What it CANNOT check is the filter
		// rate — if few candidates have a clean earlier sibling, the walk runs
		// long before LIMIT is satisfied. If that shows up in production the fix
		// is a bounded created_at window like fallout's, not a wider index.
		{
			// Includes the window: without it this EXPLAIN measures a query the
			// server no longer runs, which is how the unbounded version reached
			// production green.
			name:  "version-drift",
			where: triageVersionDriftWhere + ` AND created_at > now() - interval '7 days'`,
			order: TriageFilter{}, index: "idx_samples_version_drift_newest",
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			sql := `EXPLAIN SELECT ` + pgSampleColsLight + ` FROM samples WHERE ` + tc.where +
				` ` + triageOrderSQL(tc.order) + ` LIMIT 64`
			plan := explainText(t, ctx, db, sql)
			if planSeqScansSamples(plan) {
				t.Errorf("%s: Seq Scan on samples — the partial index predicate no longer "+
					"matches the selector's:\n%s", tc.name, plan)
			}
			if !strings.Contains(plan, tc.index) {
				t.Errorf("%s: not using %s:\n%s", tc.name, tc.index, plan)
			}
			if strings.Contains(plan, "Sort") {
				t.Errorf("%s: plan sorts instead of walking %s in order; the ORDER BY has "+
					"drifted from the index key list:\n%s", tc.name, tc.index, plan)
			}
			t.Logf("%s: ok\n%s", tc.name, firstPlanLines(plan))
		})
	}
}

// TestPlanAuditFPTraitWindow guards the bound that lets fp-trait exist without a
// precomputed aggregate table. The ranking is only affordable because the window
// is one ordered index walk of at most fpTraitWindow rows; if the plan seq-scans
// or sorts to build it, the queue is aggregating the whole good pool on every
// poll — which is the Postgres load it was designed to avoid.
func TestPlanAuditFPTraitWindow(t *testing.T) {
	db := openPlanDB(t)
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Minute)
	defer cancel()

	sql := `EXPLAIN SELECT ` + pgSampleColsLight + `, top_traits FROM samples
	         WHERE ` + triageFPTraitWhere + `
	         ORDER BY created_at DESC, id DESC LIMIT ` + strconv.Itoa(fpTraitWindow)
	plan := explainText(t, ctx, db, sql)
	if planSeqScansSamples(plan) {
		t.Errorf("fp-trait window: Seq Scan on samples:\n%s", plan)
	}
	if !strings.Contains(plan, "idx_samples_fp_trait_newest") {
		t.Errorf("fp-trait window: not using idx_samples_fp_trait_newest:\n%s", plan)
	}
	if strings.Contains(plan, "Sort") {
		t.Errorf("fp-trait window: sorts instead of walking the index in order:\n%s", plan)
	}
	t.Logf("fp-trait window: ok\n%s", firstPlanLines(plan))
}

// TestPlanAuditHighestRouteWalk guards the 2026-08-30 widening of TriageHighest
// to the unconvicted pool. The narrower idx_samples_good_route_score is a
// label='good' partial and stops covering the widened predicate, so the
// companion index is the only thing standing between the per-route LATERAL and
// a full scan of every scored sample.
func TestPlanAuditHighestRouteWalk(t *testing.T) {
	db := openPlanDB(t)
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Minute)
	defer cancel()

	sql := `EXPLAIN SELECT file_type, litmus_score FROM samples
	         WHERE ` + triageUnconvictedScoredWherePG + ` AND file_type = 'elf'
	         ORDER BY litmus_score DESC LIMIT ` + strconv.Itoa(triagePerRouteK)
	plan := explainText(t, ctx, db, sql)
	if planSeqScansSamples(plan) {
		t.Errorf("highest route walk: Seq Scan on samples:\n%s", plan)
	}
	if !strings.Contains(plan, "idx_samples_unconvicted_route_score") {
		t.Errorf("highest route walk: not using idx_samples_unconvicted_route_score "+
			"(the widened LATERAL cannot use the good-only partial):\n%s", plan)
	}
	if strings.Contains(plan, "Sort") {
		t.Errorf("highest route walk: sorts instead of walking the route's score tail:\n%s", plan)
	}
	t.Logf("highest route walk: ok\n%s", firstPlanLines(plan))
}

// TestPlanAuditNewSelectorsExecute runs each Postgres selector added with the
// unconvicted overhaul against a real database.
//
// It exists because the rest of the suite cannot: openTestDB is SQLite-backed,
// so every triage*PG function is checked by the compiler and nothing else. That
// gap is not theoretical — the fp-trait CTE shipped with an ambiguous `id`
// reference that SQLite caught only because its own mirror had the same shape.
// A PG-only mistake (a cast, a LATERAL, a jsonb operator, an ambiguous name)
// would otherwise reach production as a 500 on every poll, which the API turns
// into a queue that silently never runs.
//
// LIMIT 1 and no assertion on the rows: the point is that the server accepts and
// executes the statement, not what the corpus happens to contain.
func TestPlanAuditNewSelectorsExecute(t *testing.T) {
	db := openPlanDB(t)
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Minute)
	defer cancel()

	now := time.Now()
	for _, tc := range []struct {
		run  func() ([]*Sample, error)
		name string
	}{
		{name: "unconvicted-hostile", run: func() ([]*Sample, error) {
			return db.TriageUnconvictedHostile(ctx, 1, TriageFilter{Order: TriageRepair})
		}},
		{name: "unconvicted-hostile-stale", run: func() ([]*Sample, error) {
			return db.TriageUnconvictedHostile(ctx, 1, staleTriageFilter("unconvicted-hostile-stale"))
		}},
		{name: "unconvicted-suspicious", run: func() ([]*Sample, error) {
			return db.TriageUnconvictedSuspicious(ctx, 1, TriageFilter{Order: TriageRepair})
		}},
		{name: "discord", run: func() ([]*Sample, error) {
			return db.TriageDiscord(ctx, 1, TriageFilter{})
		}},
		{name: "fp-trait", run: func() ([]*Sample, error) {
			return db.TriageFPTrait(ctx, 1, TriageFilter{})
		}},
		{name: "version-drift", run: func() ([]*Sample, error) {
			return db.TriageVersionDrift(ctx, 1, now.Add(-VersionDriftWindow), TriageFilter{})
		}},
		{name: "highest (widened)", run: func() ([]*Sample, error) {
			return db.TriageHighest(ctx, 1, now.Add(-OutlierGrace), now.Add(-MissingRetry), TriageFilter{})
		}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if _, err := tc.run(); err != nil {
				t.Errorf("%s: %v", tc.name, err)
			}
		})
	}

	// The depth counts share the predicates but not the surrounding SQL, so a
	// count can be broken while its selector works.
	for _, tc := range []struct {
		count func() (int64, error)
		name  string
	}{
		{name: "unconvicted-hostile", count: func() (int64, error) {
			return db.CountTriageUnconvictedHostile(ctx, TriageFilter{})
		}},
		{name: "unconvicted-suspicious", count: func() (int64, error) {
			return db.CountTriageUnconvictedSuspicious(ctx, TriageFilter{})
		}},
		{name: "discord", count: func() (int64, error) { return db.CountTriageDiscord(ctx, TriageFilter{}) }},
		{name: "fp-trait", count: func() (int64, error) { return db.CountTriageFPTrait(ctx, TriageFilter{}) }},
		{name: "version-drift", count: func() (int64, error) {
			return db.CountTriageVersionDrift(ctx, now.Add(-VersionDriftWindow), TriageFilter{})
		}},
	} {
		t.Run("count/"+tc.name, func(t *testing.T) {
			if _, err := tc.count(); err != nil {
				t.Errorf("count %s: %v", tc.name, err)
			}
		})
	}
}

// TestPlanAuditFeedWindow guards the created_at window prism's fallout log
// asks its weeks for. The window's whole justification is that it becomes an
// index range condition on idx_samples_class_created — an ordered seek into
// one week of one class — rather than a filter applied to the class's entire
// newest-first walk. A Seq Scan or a Sort here means a week costs the same as
// the whole hostile history, and the log goes back to being as deep as its row
// cap rather than as deep as the week it names.
//
// The statement comes from feedSamplesQueryPG, not from a copy of it, so the
// audit cannot drift away from the query the server issues.
func TestPlanAuditFeedWindow(t *testing.T) {
	db := openPlanDB(t)
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Minute)
	defer cancel()

	week := time.Now().UTC().AddDate(0, 0, -7)
	q := &FeedQuery{
		OrderBy:       "created_at",
		TopLevelOnly:  true,
		LitmusClasses: []int{2},
		Limit:         1000,
		Since:         week,
		Until:         week.AddDate(0, 0, 7),
	}
	sql, args := feedSamplesQueryPG(q)
	plan := explainText(t, ctx, db, "EXPLAIN "+sql, args...)
	if planSeqScansSamples(plan) {
		t.Errorf("windowed feed: Seq Scan on samples:\n%s", plan)
	}
	if !strings.Contains(plan, "created_at") {
		t.Errorf("windowed feed: created_at is not in the index conditions, so the "+
			"window is being filtered rather than seeked:\n%s", plan)
	}
	if strings.Contains(plan, "Sort") {
		t.Errorf("windowed feed: sorts instead of walking the window in order:\n%s", plan)
	}
	t.Logf("windowed feed: ok\n%s", firstPlanLines(plan))

	// The unwindowed query must keep the plan it has always had: the window is
	// spelled into the SQL only when it is set, precisely so an unbounded
	// caller's statement — and its plan — is untouched by this feature.
	plain := *q
	plain.Since, plain.Until = time.Time{}, time.Time{}
	plainSQL, plainArgs := feedSamplesQueryPG(&plain)
	if strings.Contains(plainSQL, "created_at >=") {
		t.Errorf("unwindowed feed carries a window predicate:\n%s", compactSQL(plainSQL))
	}
	plainPlan := explainText(t, ctx, db, "EXPLAIN "+plainSQL, plainArgs...)
	if planSeqScansSamples(plainPlan) {
		t.Errorf("unwindowed feed: Seq Scan on samples:\n%s", plainPlan)
	}
	t.Logf("unwindowed feed: ok\n%s", firstPlanLines(plainPlan))
}
