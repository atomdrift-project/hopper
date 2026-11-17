package migrate

import (
	"context"
	"crypto/sha256"
	"fmt"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/atomdrift-project/hopper/store"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/klauspost/compress/zstd"
)

// TestReportRange runs the reports stage on a handful of legacy rows against
// a disposable database (HOPPER_TEST_PG_DSN): it fills what convert left out
// of a version 4 scan and its member, and a member legacy cut to a stub whose
// excerpt names no parent; it leaves a full report, and a depth 0 stub, as
// they are; and a second run changes nothing.
func TestReportRange(t *testing.T) {
	dsn := strings.TrimSpace(os.Getenv("HOPPER_TEST_PG_DSN"))
	if dsn == "" {
		t.Skip("HOPPER_TEST_PG_DSN not set (a disposable Postgres database)")
	}
	if strings.Contains(dsn, "hopper-db") {
		t.Fatal("HOPPER_TEST_PG_DSN names the production host; these tests write data")
	}
	ctx := t.Context()
	cfg, err := pgxpool.ParseConfig(dsn)
	if err != nil {
		t.Fatal(err)
	}
	suffix := time.Now().UnixNano()
	schema, legacy := fmt.Sprintf("mig_%d", suffix), fmt.Sprintf("legacy_%d", suffix)
	cfg.ConnConfig.RuntimeParams["search_path"] = schema
	pool, err := pgxpool.NewWithConfig(ctx, cfg)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		if _, err := pool.Exec(context.WithoutCancel(ctx), "DROP SCHEMA "+schema+", "+legacy+" CASCADE"); err != nil {
			t.Errorf("drop schemas: %v", err)
		}
		pool.Close()
	})
	for _, q := range []string{
		"CREATE SCHEMA " + schema, "CREATE SCHEMA " + legacy,
	} {
		if _, err := pool.Exec(ctx, q); err != nil {
			t.Fatal(err)
		}
	}
	if _, err := pool.Exec(ctx, store.Schema); err != nil {
		t.Fatalf("schema: %v", err)
	}
	if _, err := pool.Exec(ctx, `CREATE TABLE `+legacy+`.samples (id bigint PRIMARY KEY, sha256 text, parent text NOT NULL DEFAULT '', cleave_result jsonb, litmus_result jsonb, traits_version text, analyzed_at timestamptz, last_error_at timestamptz, created_at timestamptz NOT NULL DEFAULT now())`); err != nil {
		t.Fatal(err)
	}
	st, err := store.New(pool)
	if err != nil {
		t.Fatal(err)
	}
	dig := func(name string) []byte { s := sha256.Sum256([]byte(name)); return s[:] }
	hexed := func(name string) string { return fmt.Sprintf("%x", dig(name)) }

	stub := `{"mol":"Os","risk":4}`
	full := `{"mol":"Os","risk":2,"traits":[{"crit":2,"id":"t::full"}]}`
	samples := map[int64]reportSample{
		1: {"gem", "", true, `{"v":"4","tv":"60d49","fs":[
			{"id":0,"sha":"` + hexed("gem") + `","path":"/d/x.gem","type":"gem","sz":900,"x":1,"f":"H2"},
			{"id":1,"dp":1,"sha":"` + hexed("rb") + `","path":"/d/x.gem!!lib/x.rb","type":"ruby","sz":94,"ts":[{"c":0.9,"d":"d","i":"t::dropper","l":5}]}]}`},
		2: {"rb", "", false, ""},
		3: {"member", stub, false, `{"v":"7","files":[{"id":7429,"depth":2,"path":"a.tgz!!b.zst!!c.ko","sha":"` + hexed("member") + `","size":10,"type":"elf","mol":"Os","risk":4,"traits":[{"id":"t::from-excerpt","crit":3}]}]}`},
		4: {"modern", full, true, `{"v":"7","files":[{"id":0,"sha":"` + hexed("modern") + `","size":10,"type":"php","mol":"Os","risk":9}]}`},
		5: {"alone", stub, false, `{"v":"7","files":[{"id":0,"sha":"` + hexed("alone") + `","size":10,"type":"elf","mol":"Os","risk":4,"traits":[{"id":"t::alone","crit":3}]}]}`},
		// Files with no verdict: a member only a legacy excerpt judged (a
		// version 7 entry at depth 2 with no pid, and a hostile finding), a
		// file whose legacy row is a scan, and a registry sidecar.
		6: {"excerpted", "", false, `{"v":"7","tv":"abc12","files":[{"id":4,"depth":2,"path":"a.tgz!!b.zst!!c.ko","sha":"` + hexed("excerpted") + `","size":10,"type":"elf","mol":"Os","risk":9,"traits":[{"id":"o::dropper","crit":5}]}]}`},
		7: {"scanned", "", false, `{"v":"7","files":[{"id":0,"sha":"` + hexed("scanned") + `","size":10,"type":"elf","mol":"Os","risk":9}]}`},
		8: {"sidecar", "", false, `{"v":"7","files":[{"id":2,"pid":0,"rel":"registry","type":"registry","sha":"` + hexed("sidecar") + `","traits":[{"id":"t","crit":2}]}]}`},
	}
	seedReportSamples(t, ctx, pool, legacy, samples, map[int64]bool{6: true, 7: true, 8: true})
	m := &migration{
		pool: pool, st: st, from: pgx.Identifier{legacy}.Sanitize(), opt: Options{From: legacy, To: schema, Workers: 1, Batch: 100},
		report: &Report{Took: map[string]time.Duration{}, Failures: map[string]int{}},
	}
	reports := func() map[int64]string {
		got, err := st.Reports(ctx, []int64{1, 2, 3, 4, 5, 6, 7, 8})
		if err != nil {
			t.Fatal(err)
		}
		out := map[int64]string{}
		for id, r := range got {
			out[id] = string(r)
		}
		return out
	}
	if err := m.reportRange(ctx, 0, 10); err != nil {
		t.Fatal(err)
	}
	want := map[int64]string{
		1: `{"f":"H2","x":1}`,
		2: `{"ts":[{"c":0.9,"d":"d","i":"t::dropper","l":5}]}`,
		3: `{"mol":"Os","risk":4,"traits":[{"crit":3,"id":"t::from-excerpt"}]}`,
		4: full,
		5: stub,
	}
	got := reports()
	for id, w := range want {
		if got[id] != w {
			t.Errorf("sample %d: report %s, want %s", id, got[id], w)
		}
	}
	if m.report.Filled != 3 {
		t.Errorf("filled %d, want the version 4 scan, its member and the nested member", m.report.Filled)
	}
	if err := m.reportRange(ctx, 0, 10); err != nil {
		t.Fatal(err)
	}
	if m.report.Filled != 3 {
		t.Errorf("a second run filled %d more", m.report.Filled-3)
	}

	// The files nothing judged: the excerpt's member takes a verdict judged on
	// its findings alone, formed when legacy analyzed it, and its report; a
	// scan's row, and a sidecar, take none; nothing else changes.
	if err := m.excerptVerdictRange(ctx, 0, 10); err != nil {
		t.Fatal(err)
	}
	if m.report.Recovered != 1 {
		t.Errorf("recovered %d verdicts, want the excerpted member alone", m.report.Recovered)
	}
	var class, rs string
	var fires *int
	var formed time.Time
	if err := pool.QueryRow(ctx, `SELECT class::text, fires_at, ruleset, formed_at FROM verdicts WHERE sample_id = 6 AND scanner_id = 1`).
		Scan(&class, &fires, &rs, &formed); err != nil {
		t.Fatal(err)
	}
	if class != "hostile" || fires != nil || rs != "abc12" || !formed.Equal(time.Date(2026, 5, 2, 3, 4, 5, 0, time.UTC)) {
		t.Errorf("excerpt verdict: %s, fires_at %v, ruleset %s, formed %v", class, fires, rs, formed)
	}
	got = reports()
	if got[6] != `{"mol":"Os","risk":9,"traits":[{"crit":5,"id":"o::dropper"}]}` {
		t.Errorf("excerpt report %s", got[6])
	}
	var n int
	if err := pool.QueryRow(ctx, `SELECT count(*) FROM verdicts WHERE sample_id IN (7, 8)`).Scan(&n); err != nil || n != 0 {
		t.Errorf("a scan's row or a sidecar took %d verdicts (%v)", n, err)
	}
	if err := pool.QueryRow(ctx, `SELECT count(*) FROM scans WHERE sample_id = 6`).Scan(&n); err != nil || n != 0 {
		t.Errorf("an excerpt took %d scans rows (%v)", n, err)
	}
	if err := m.excerptVerdictRange(ctx, 0, 10); err != nil || m.report.Recovered != 1 {
		t.Errorf("a second run: recovered %d, %v", m.report.Recovered, err)
	}
}

// reportSample is a legacy row, and the verdict already stored for it, that
// TestReportRange loads. An empty legacy is no legacy row; an empty report is
// a verdict with none.
type reportSample struct {
	name   string
	report string
	scan   bool
	legacy string
}

// seedReportSamples inserts samples and, where the row was judged, its verdict.
func seedReportSamples(t *testing.T, ctx context.Context, pool *pgxpool.Pool, legacy string, samples map[int64]reportSample, noVerdict map[int64]bool) {
	t.Helper()
	enc, err := zstd.NewWriter(nil)
	if err != nil {
		t.Fatal(err)
	}
	for id, s := range samples {
		sum := sha256.Sum256([]byte(s.name))
		hexed := fmt.Sprintf("%x", sum[:])
		if _, err := pool.Exec(ctx, `INSERT INTO samples (id, sha256, size_bytes, file_type, label) VALUES ($1, $2, 10, 'x', 'bad')`, id, sum[:]); err != nil {
			t.Fatal(err)
		}
		if noVerdict[id] {
			if _, err := pool.Exec(ctx, `INSERT INTO `+legacy+`.samples (id, sha256, cleave_result, traits_version, analyzed_at) VALUES ($1, $2, $3::jsonb, 'legacy1', '2026-05-02 03:04:05+00')`, id, hexed, s.legacy); err != nil {
				t.Fatal(err)
			}
			continue
		}
		var detail, digest []byte
		if s.report != "" {
			reportSum := sha256.Sum256([]byte(s.report))
			detail, digest = enc.EncodeAll([]byte(s.report), nil), reportSum[:]
		}
		if _, err := pool.Exec(ctx, `INSERT INTO verdicts (sample_id, formed_at, outcome, class, scanner_id, fires_at, ruleset, digest, detail)
			VALUES ($1, now(), 'ok', 'benign', 1, -1, 'r', $2, $3)`, id, digest, detail); err != nil {
			t.Fatal(err)
		}
		if s.scan {
			if _, err := pool.Exec(ctx, `INSERT INTO scans (sample_id, scanned_at, ruleset) VALUES ($1, now(), 'r')`, id); err != nil {
				t.Fatal(err)
			}
		}
		if s.legacy != "" {
			if _, err := pool.Exec(ctx, `INSERT INTO `+legacy+`.samples (id, sha256, cleave_result) VALUES ($1, $2, $3::jsonb)`, id, hexed, s.legacy); err != nil {
				t.Fatal(err)
			}
		}
	}
}
