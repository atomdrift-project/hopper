package hopper

import (
	"context"
	"encoding/json"
	"fmt"
	"slices"
	"strings"
	"sync"
	"testing"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
)

type analysisQueryTrace struct {
	mu               sync.Mutex
	selects, updates int
}

func (q *analysisQueryTrace) TraceQueryStart(ctx context.Context, _ *pgx.Conn, data pgx.TraceQueryStartData) context.Context {
	sql := strings.ToUpper(strings.TrimSpace(data.SQL))
	q.mu.Lock()
	defer q.mu.Unlock()
	if strings.HasPrefix(sql, "SELECT") {
		q.selects++
	}
	if strings.HasPrefix(sql, "UPDATE") {
		q.updates++
	}
	return ctx
}

func (*analysisQueryTrace) TraceQueryEnd(context.Context, *pgx.Conn, pgx.TraceQueryEndData) {}

func (q *analysisQueryTrace) reset() {
	if q == nil {
		return
	}
	q.mu.Lock()
	defer q.mu.Unlock()
	q.selects, q.updates = 0, 0
}

func (q *analysisQueryTrace) check(t *testing.T, selects, updates int) {
	t.Helper()
	if q == nil {
		return
	}
	q.mu.Lock()
	defer q.mu.Unlock()
	if q.selects != selects || q.updates != updates {
		t.Fatalf("analysis used %d SELECTs/%d UPDATEs, want %d/%d", q.selects, q.updates, selects, updates)
	}
}

func TestAnalysisWritesReturnPackageIdentity(t *testing.T) {
	for _, backend := range testBackends {
		t.Run(backend.name, func(t *testing.T) {
			db := backend.open(t)
			ctx := context.Background()
			var trace *analysisQueryTrace
			if db.pool != nil {
				config := db.pool.Config()
				trace = &analysisQueryTrace{}
				config.ConnConfig.Tracer = trace
				pool, err := pgxpool.NewWithConfig(ctx, config)
				if err != nil {
					t.Fatal(err)
				}
				db.pool.Close()
				db.pool = pool
			}
			const base = "pkg:pypi/returning-identity"
			const version = "1.0"
			first, second := fmt.Sprintf("%064x", 1), fmt.Sprintf("%064x", 2)
			for _, sha := range []string{first, second} {
				mustInsert(t, ctx, db, &Sample{SHA256: sha, Source: "test", PURLBase: base, Version: version})
				if err := db.UpdateCleaveResult(ctx, sha, critEnvelope(sha, 0), nil, "initial"); err != nil {
					t.Fatal(err)
				}
				if err := db.UpdateLitmusResult(ctx, sha, []byte(`{"lvl":25}`)); err != nil {
					t.Fatal(err)
				}
			}
			check := func(want string) {
				t.Helper()
				s, err := db.SampleByPURL(ctx, base, version)
				if err != nil {
					t.Fatal(err)
				}
				r, err := db.LookupRecord(ctx, "", base, version)
				if err != nil {
					t.Fatal(err)
				}
				if s.SHA256 != want || r.SHA256 == nil || *r.SHA256 != want {
					t.Fatalf("sample/record did not select %s: sample=%s record=%+v", want, s.SHA256, r)
				}
			}
			// Warm package caches under the newer of the equal-level payloads.
			check(second)
			trace.reset()
			raw := critEnvelope(first, 0)
			stats, err := db.StoreResult(ctx, first, raw, []byte(`{"lvl":0}`), nil, nil, "new", ResultAttribution{})
			if err != nil {
				t.Fatal(err)
			}
			trace.check(t, 1, 1) // The pre-existing metadata read and UPDATE; no identity SELECT.
			if stats.PURLBase != base || stats.PURLVersion != version {
				t.Fatalf("identity=%+v", stats)
			}
			check(first)

			trace.reset()
			stats, err = db.StoreResult(ctx, first, raw, []byte(`{"lvl":0}`), nil, nil, "new", ResultAttribution{})
			if err != nil || !stats.Unchanged {
				t.Fatalf("unchanged=%+v, %v", stats, err)
			}
			trace.check(t, 1, 0)
			check(first)

			trace.reset()
			if err := db.UpdateCleaveResult(ctx, first, raw, nil, "reset"); err != nil {
				t.Fatal(err)
			}
			trace.check(t, 0, 1)
			check(second) // Clearing the selected payload's level invalidates its package choice.

			trace.reset()
			if err := db.UpdateLitmusResult(ctx, first, []byte(`{"lvl":0}`)); err != nil {
				t.Fatal(err)
			}
			trace.check(t, 0, 1)
			check(first)

			absent := fmt.Sprintf("%064x", 99)
			trace.reset()
			if err := db.UpdateLitmusResult(ctx, absent, []byte(`{"lvl":0}`)); err != nil {
				t.Fatal(err)
			}
			trace.check(t, 0, 1) // Absent-row updates retain their successful no-op behavior.
		})
	}
}

func TestPURLCriticalIndexSQLitePlan(t *testing.T) {
	db := openTestDB(t)
	query := `EXPLAIN QUERY PLAN ` + sampleByPURLSQLite + ` AND version = ?` + purlLookupOrder("1.0", false)
	rows, err := db.lite.QueryContext(context.Background(), query, "pkg:pypi/plan", "1.0")
	if err != nil {
		t.Fatal(err)
	}
	defer func() {
		if err := rows.Close(); err != nil {
			t.Error(err)
		}
	}()
	var plan []string
	for rows.Next() {
		var id, parent, unused int
		var detail string
		if err := rows.Scan(&id, &parent, &unused, &detail); err != nil {
			t.Fatal(err)
		}
		plan = append(plan, detail)
	}
	if err := rows.Err(); err != nil {
		t.Fatal(err)
	}
	text := strings.Join(plan, "\n")
	t.Log(text)
	if !strings.Contains(text, "idx_samples_purl_critical") || strings.Contains(text, "TEMP B-TREE") {
		t.Fatalf("critical lookup must use its ordered index without sorting:\n%s", text)
	}
}

func TestPURLCriticalIndexPostgresPlan(t *testing.T) {
	db := openDisposablePG(t)
	ctx := context.Background()
	const base = "pkg:pypi/plan-load"
	// A synthetic high-fan-out release makes ranking cost and the ordered
	// LIMIT visible. Nothing in this test touches a shared/production schema.
	_, err := db.pool.Exec(ctx, `
        INSERT INTO samples (sha256, canonical_sha256, source, path, purl_base, version, cleave_result, litmus_result, analyzed_at)
        SELECT lpad(to_hex(n),64,'0'), lpad(to_hex(n),64,'0'), 'test', 'incoming/' || n,
            $1, '1.0', jsonb_build_object('fs',jsonb_build_array(jsonb_build_object(
                'sha',lpad(to_hex(n),64,'0'),'type','zip','dp',0))),
            jsonb_build_object('lvl', CASE WHEN n=5000 THEN 0 WHEN n%4=0 THEN -1 WHEN n%5=0 THEN NULL ELSE 100 END),
            now()-n*interval '1 second'
        FROM generate_series(1,10000) n`, base)
	if err != nil {
		t.Fatal(err)
	}
	if _, err = db.pool.Exec(ctx, `ANALYZE samples`); err != nil {
		t.Fatal(err)
	}
	query := `SELECT ` + recordSampleCols + ` FROM samples WHERE purl_base=$1 AND purl_base<>''
        AND litmus_result IS NOT NULL AND cleave_result IS NOT NULL AND file_type<>'registry' AND version=$2` + purlLookupOrder("1.0", true)
	explain := func() (string, float64) {
		t.Helper()
		var raw []byte
		if err := db.pool.QueryRow(ctx, `EXPLAIN (ANALYZE, BUFFERS, FORMAT JSON) `+query, base, "1.0").Scan(&raw); err != nil {
			t.Fatal(err)
		}
		var parsed []struct {
			ExecutionTime float64 `json:"Execution Time"`
		}
		if err := json.Unmarshal(raw, &parsed); err != nil {
			t.Fatal(err)
		}
		return string(raw), parsed[0].ExecutionTime
	}
	measure := func() (string, float64) {
		t.Helper()
		_, _ = explain() // Warm the same query on each side of the comparison.
		times := make([]float64, 7)
		var plan string
		for i := range times {
			plan, times[i] = explain()
		}
		slices.Sort(times)
		return plan, times[len(times)/2]
	}
	// Remove only this test schema's new index, then recreate the same DDL the
	// migration installs. This compares identical data and query semantics.
	if _, err = db.pool.Exec(ctx, `DROP INDEX idx_samples_purl_critical`); err != nil {
		t.Fatal(err)
	}
	before, beforeMS := measure()
	if _, err = db.pool.Exec(ctx, purlCriticalIndex(true)); err != nil {
		t.Fatal(err)
	}
	after, afterMS := measure()
	t.Logf("10,000 payloads: median database execution before %.3f ms; after %.3f ms", beforeMS, afterMS)
	t.Logf("indexed plan: %s", after)
	if !strings.Contains(before, `"Sort"`) {
		t.Fatalf("baseline did not exercise ranking:\n%s", before)
	}
	if !strings.Contains(after, "idx_samples_purl_critical") || strings.Contains(after, `"Sort"`) {
		t.Fatalf("critical lookup must use its ordered index without sorting:\n%s", after)
	}
	sample, err := db.recordSample(ctx, query, base, "1.0")
	if err != nil {
		t.Fatal(err)
	}
	if sample.SHA256 != fmt.Sprintf("%064x", 5000) {
		t.Fatalf("selected %s", sample.SHA256)
	}
}
