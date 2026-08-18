package hopper

import (
	"context"
	"fmt"
	"os"
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
	db, err := Open(ctx, planAuditDSN(t))
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
	} {
		plan := explainText(t, ctx, db, tc.sql, tc.args)
		if planSeqScansSamples(plan) {
			t.Errorf("%s: unexpected Seq Scan on samples:\n%s", tc.name, plan)
		} else {
			t.Logf("%s: ok\n%s", tc.name, firstPlanLines(plan, 8))
		}
	}
}

func explainText(t *testing.T, ctx context.Context, db *DB, sql string, args []string) string {
	t.Helper()
	rows, err := db.Pool().Query(ctx, sql, args)
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
	for _, line := range strings.Split(plan, "\n") {
		if !strings.Contains(line, "Seq Scan on samples") {
			continue
		}
		// Parallel Seq Scan on samples  → bad
		// Seq Scan on samples           → bad
		return true
	}
	return false
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

func firstPlanLines(plan string, n int) string {
	lines := strings.Split(strings.TrimSpace(plan), "\n")
	if len(lines) > n {
		lines = lines[:n]
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
