package hopper

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"slices"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/atomdrift-project/hopper/store"
	"github.com/atomdrift-project/hopper/v7result"
)

// writerUpload is one worker upload, rebuilt from exported production rows:
// the archive's stored report with every member's report joined back in, which
// is what the worker posted before hopper split it for storage.
type writerUpload struct {
	sample       Sample
	raw, ml, llm []byte
	restamped    []byte // raw under another ruleset: every report differs
}

// TestResultWriters stores the same uploads through hopper's current writer
// (DB.StoreResult, into the current schema with its indexes and triggers) and
// through the new one (v7result.Convert then store.Write, into the verdict schema),
// and reports time and WAL for a first scan and for two kinds of rescan.
//
// HOPPER_PROTO_DSN names the local prototype database holding legacy_samples;
// HOPPER_TEST_PG_DSN a disposable database on the same idle cluster, since WAL
// is measured cluster-wide. HOPPER_WRITER_RESULTS bounds the uploads (4000).
func TestResultWriters(t *testing.T) {
	protoDSN, testDSN := os.Getenv("HOPPER_PROTO_DSN"), os.Getenv("HOPPER_TEST_PG_DSN")
	if protoDSN == "" || testDSN == "" {
		t.Skip("HOPPER_PROTO_DSN and HOPPER_TEST_PG_DSN (disposable) are needed")
	}
	limit := 4000
	if v := os.Getenv("HOPPER_WRITER_RESULTS"); v != "" {
		n, err := strconv.Atoi(v)
		if err != nil || n < 1 {
			t.Fatal("HOPPER_WRITER_RESULTS must be a positive integer")
		}
		limit = n
	}
	ctx := t.Context()
	uploads := loadWriterUploads(ctx, t, protoDSN, limit)

	legacy := openDisposablePG(t) // refuses the production host
	// The current insert layer refuses files under MinSampleSize; neither
	// writer is given those.
	loaded := len(uploads)
	uploads = slices.DeleteFunc(uploads, func(u writerUpload) bool { return !validSample(&u.sample) })
	for i := range uploads {
		if err := legacy.InsertSample(ctx, &uploads[i].sample); err != nil {
			t.Fatalf("insert %s: %v", uploads[i].sample.SHA256, err)
		}
	}
	t.Logf("%d uploads, %d more refused by the current insert layer", len(uploads), loaded-len(uploads))
	verdicts, pool := freshVerdictStore(ctx, t, testDSN)

	passes := []struct {
		name, ruleset string
		restamp       bool
	}{
		{name: "first scan", ruleset: "bench-a"},
		{name: "rescan, new ruleset, same reports", ruleset: "bench-b"},
		{name: "rescan, new ruleset, every report differs", ruleset: "bench-c", restamp: true},
	}
	const level = 25
	for _, p := range passes {
		var files int
		var convert time.Duration
		var written store.Stats
		wal, elapsed := measureWriter(ctx, t, pool, func() time.Duration {
			var total time.Duration
			for i := range uploads {
				u := &uploads[i]
				raw := u.raw
				if p.restamp {
					raw = u.restamped
				}
				start := time.Now()
				c, err := v7result.Convert(&v7result.Result{
					At: start, SHA256: u.sample.SHA256, Worker: "bench", Ruleset: p.ruleset,
					ML: u.ml, LLM: u.llm, Raw: raw,
				}, level)
				if err != nil {
					t.Fatalf("%s: convert: %v", u.sample.SHA256, err)
				}
				convert += time.Since(start)
				// Version 8 carries the ruleset in the header, not in the report;
				// a version 7 report names its own, which Convert prefers.
				for j := range c.Files {
					c.Files[j].Scan.Ruleset = p.ruleset
				}
				st, err := verdicts.Write(ctx, c.Files)
				if err != nil {
					t.Fatalf("%s: write: %v", u.sample.SHA256, err)
				}
				total += time.Since(start)
				files += len(c.Files)
				written.Verdicts += st.Verdicts
				written.Reports += st.Reports
				written.ReportsUnchanged += st.ReportsUnchanged
			}
			return total
		})
		t.Logf("%-42s new:    %8.1f ms/result %7.0f µs/file %9.0f WAL B/result %7.0f WAL B/file (convert %v; %d verdict rows, %d reports stored, %d unchanged)",
			p.name, ms(elapsed)/float64(len(uploads)), us(elapsed)/float64(files),
			float64(wal)/float64(len(uploads)), float64(wal)/float64(files),
			convert.Round(time.Millisecond), written.Verdicts, written.Reports, written.ReportsUnchanged)

		var members int
		var stored int64
		wal, elapsed = measureWriter(ctx, t, pool, func() time.Duration {
			var total time.Duration
			for i := range uploads {
				u := &uploads[i]
				raw := u.raw
				if p.restamp {
					raw = u.restamped
				}
				start := time.Now()
				st, err := legacy.StoreResult(ctx, u.sample.SHA256, raw, u.ml, u.llm, nil, p.ruleset, ResultAttribution{Worker: "bench"})
				if err != nil {
					t.Fatalf("%s: StoreResult: %v", u.sample.SHA256, err)
				}
				total += time.Since(start)
				members += st.Members
				stored += st.MembersStored
			}
			return total
		})
		t.Logf("%-42s current: %8.1f ms/result %7.0f µs/file %9.0f WAL B/result %7.0f WAL B/file (%d members, %d member rows written)",
			p.name, ms(elapsed)/float64(len(uploads)), us(elapsed)/float64(files),
			float64(wal)/float64(len(uploads)), float64(wal)/float64(files), members, stored)
	}

	const size = `SELECT coalesce(sum(pg_total_relation_size(c.oid)), 0)::bigint
		FROM pg_class c WHERE c.relnamespace = current_schema()::regnamespace AND c.relkind = 'r'`
	var current, verdict int64
	if err := legacy.pool.QueryRow(ctx, size).Scan(&current); err != nil {
		t.Fatal(err)
	}
	if err := pool.QueryRow(ctx, size).Scan(&verdict); err != nil {
		t.Fatal(err)
	}
	t.Logf("%d uploads; on disk after all passes, before vacuum: current %d MB, new %d MB", len(uploads), current>>20, verdict>>20)
}

func ms(d time.Duration) float64 { return float64(d.Microseconds()) / 1e3 }
func us(d time.Duration) float64 { return float64(d.Microseconds()) }

// measureWriter checkpoints, so both writers start with the same full-page
// write debt, then returns the WAL the cluster produced while run executed and
// the time run reports having spent writing.
func measureWriter(ctx context.Context, t *testing.T, pool *pgxpool.Pool, run func() time.Duration) (wal int64, elapsed time.Duration) {
	t.Helper()
	const position = `SELECT pg_wal_lsn_diff(pg_current_wal_insert_lsn(), '0/0')::bigint`
	var before, after int64
	if _, err := pool.Exec(ctx, "CHECKPOINT"); err != nil {
		t.Fatal(err)
	}
	if err := pool.QueryRow(ctx, position).Scan(&before); err != nil {
		t.Fatal(err)
	}
	elapsed = run()
	if err := pool.QueryRow(ctx, position).Scan(&after); err != nil {
		t.Fatal(err)
	}
	return after - before, elapsed
}

// loadWriterUploads rebuilds up to limit uploads from legacy_samples, in digest
// order so the selection is arbitrary but repeatable.
func loadWriterUploads(ctx context.Context, t *testing.T, dsn string, limit int) []writerUpload {
	t.Helper()
	conn, err := pgx.Connect(ctx, dsn)
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close(context.WithoutCancel(ctx)) //nolint:errcheck // read-only fixture

	rows, err := conn.Query(ctx, `SELECT sha256, coalesce(source, ''), coalesce(feed, ''), coalesce(ecosystem, ''),
			coalesce(url, ''), coalesce(package, ''), coalesce(version, ''), coalesce(filename, ''),
			coalesce(file_type, ''), coalesce(size_bytes, 0), coalesce(label, ''), coalesce(label_source, ''),
			coalesce(nullif(path, ''), 'bench/' || sha256), cleave_result::text, litmus_result::text, llm_result::text
		FROM legacy_samples WHERE parent = '' AND cleave_result IS NOT NULL AND coalesce(file_type, '') <> ''
		ORDER BY sha256 LIMIT $1`, limit)
	if err != nil {
		t.Fatal(err)
	}
	parents, err := pgx.CollectRows(rows, func(row pgx.CollectableRow) (*Sample, error) {
		var s Sample
		return &s, row.Scan(&s.SHA256, &s.Source, &s.Feed, &s.Ecosystem, &s.URL, &s.Package, &s.Version, &s.Filename,
			&s.FileType, &s.SizeBytes, &s.Label, &s.LabelSource, &s.Path, &s.CleaveResult, &s.LitmusResult, &s.LLMResult)
	})
	if err != nil {
		t.Fatal(err)
	}

	uploads := make([]writerUpload, 0, len(parents))
	for _, parent := range parents {
		rows, err := conn.Query(ctx, `SELECT m.sha256, m.cleave_result::text, m.litmus_result::text
			FROM legacy_samples m WHERE m.cleave_result IS NOT NULL AND m.sha256 IN (
				SELECT f->>'sha' FROM legacy_samples p,
				       jsonb_array_elements(coalesce(p.cleave_result->'files', p.cleave_result->'fs')) AS f
				WHERE p.sha256 = $1)
			  AND m.sha256 <> $1`, parent.SHA256)
		if err != nil {
			t.Fatal(err)
		}
		members, err := pgx.CollectRows(rows, func(row pgx.CollectableRow) (*Sample, error) {
			var m Sample
			return &m, row.Scan(&m.SHA256, &m.CleaveResult, &m.LitmusResult)
		})
		if err != nil {
			t.Fatal(err)
		}
		envelope, err := Reassemble(parent, members)
		if err != nil {
			t.Fatalf("%s: reassemble: %v", parent.SHA256, err)
		}
		var sections struct{ Raw, ML, LLM json.RawMessage }
		if err := json.Unmarshal(envelope, &sections); err != nil {
			t.Fatal(err)
		}
		report, err := decodeObject(sections.Raw)
		if err != nil {
			t.Fatal(err)
		}
		// The exported reports were made under 35 rulesets, and a version 7
		// report names its ruleset, so a file shared by two archives would
		// carry a different report in each. A scan wave runs under one
		// ruleset: stamp every upload alike, and again for the restamped copy.
		var stamped [2][]byte
		for i, rev := range []string{`"bench-a"`, `"bench-c"`} {
			report["rev"] = json.RawMessage(rev)
			if stamped[i], err = json.Marshal(report); err != nil {
				t.Fatal(err)
			}
		}
		// A version 8 report is the file's own entry, without the report's
		// ruleset, so the restamped copy must differ inside every entry: one
		// more finding, at crit 1, which no verdict or juror reads.
		if stamped[1], err = withFinding(stamped[1]); err != nil {
			t.Fatal(err)
		}
		// The current writer wants the claimed, unanalyzed row a worker would
		// have been handed; the stored analysis is the upload, not the row.
		s := *parent
		s.CleaveResult, s.LitmusResult, s.LLMResult = nil, nil, nil
		uploads = append(uploads, writerUpload{sample: s, raw: stamped[0], ml: sections.ML, llm: sections.LLM, restamped: stamped[1]})
	}
	return uploads
}

// freshVerdictStore creates the verdict schema in a schema of its own, dropped
// when the test ends.
func freshVerdictStore(ctx context.Context, t *testing.T, dsn string) (*store.Store, *pgxpool.Pool) {
	t.Helper()
	if strings.Contains(dsn, "hopper-db") {
		t.Fatal("HOPPER_TEST_PG_DSN names the production host; this test writes data")
	}
	cfg, err := pgxpool.ParseConfig(dsn)
	if err != nil {
		t.Fatal(err)
	}
	schema := fmt.Sprintf("writer_%d", time.Now().UnixNano())
	cfg.ConnConfig.RuntimeParams["search_path"] = schema
	pool, err := pgxpool.NewWithConfig(ctx, cfg)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		if _, err := pool.Exec(context.WithoutCancel(ctx), "DROP SCHEMA "+schema+" CASCADE"); err != nil {
			t.Errorf("drop schema: %v", err)
		}
		pool.Close()
	})
	for _, ddl := range []string{"CREATE SCHEMA " + schema, store.Schema} {
		if _, err := pool.Exec(ctx, ddl); err != nil {
			t.Fatal(err)
		}
	}
	st, err := store.New(pool)
	if err != nil {
		t.Fatal(err)
	}
	return st, pool
}

// withFinding adds a crit 1 finding to every file entry of a version 7 report.
func withFinding(raw []byte) ([]byte, error) {
	var report map[string]any
	if err := json.Unmarshal(raw, &report); err != nil {
		return nil, err
	}
	files, ok := report["files"].([]any)
	if !ok {
		return raw, nil // the oldest shape has no entries to change
	}
	for _, f := range files {
		if entry, ok := f.(map[string]any); ok {
			traits, _ := entry["traits"].([]any) //nolint:errcheck // absent is an empty list
			entry["traits"] = append(traits, map[string]any{"id": "bench::restamp", "crit": 1})
		}
	}
	return json.Marshal(report)
}
