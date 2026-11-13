package store

import (
	"os"
	"strconv"
	"strings"
	"testing"
	"time"
)

// TestTriageScale times every queue's selection and depth over a month of
// flagged scans at production's rate (PLAN.md, "Triage queues on the new
// tables": 17,041 flagged in 12 hours). Only flagged scans are generated:
// the queues with a window read nothing else. Labels, verdicts and package
// names are spread as production's are, roughly; the counts that matter are
// the window sizes, not the mix.
//
//	HOPPER_TRIAGE_SCALE=1000000 HOPPER_TEST_PG_DSN=... go test -run TriageScale -v ./store
func TestTriageScale(t *testing.T) {
	n, _ := strconv.Atoi(os.Getenv("HOPPER_TRIAGE_SCALE")) //nolint:errcheck // unset or bad means skip
	if n <= 0 {
		t.Skip("HOPPER_TRIAGE_SCALE not set (flagged scans to generate over 30 days)")
	}
	st := open(t)
	ctx := t.Context()
	start := time.Now()
	for _, step := range []string{
		`INSERT INTO names (name) SELECT 'pkg:npm/p' || g FROM generate_series(1, 20000) g`,
		`INSERT INTO popular_packages (purl_base, ecosystem, rank, source)
			SELECT 'pkg:npm/p' || g, 'npm', g, 'scale' FROM generate_series(1, 1000) g`,
		// One file per flagged scan, arriving up to a day before it.
		`INSERT INTO samples (id, sha256, size_bytes, file_type, label, name_id, version, created_at)
			SELECT g, sha256(g::text::bytea), 1000, (ARRAY['javascript', 'python', 'npm', 'pe', 'elf'])[1 + g % 5],
			       (ARRAY['bad', 'bad', 'bad', 'bad', 'unknown', 'unknown', 'unknown', 'unknown', 'good', 'sighted'])[1 + g % 10]::label,
			       CASE WHEN g % 3 = 0 THEN 1 + g % 20000 END, (g % 7)::text,
			       now() - (g::float8 / $1) * interval '30 days' - interval '6 hours'
			FROM generate_series(1, $1) g`,
		`INSERT INTO scans (sample_id, scanned_at, ruleset, flagged)
			SELECT id, created_at + interval '5 hours', 'r1', true FROM samples`,
		`INSERT INTO locations (path, sample_id) SELECT 'pool/' || id, id FROM samples`,
		`INSERT INTO verdicts (sample_id, scanner_id, outcome, class, ruleset, formed_at, summary)
			SELECT id, 1, 'ok', (ARRAY['hostile', 'suspicious', 'benign'])[1 + id % 3]::class, 'r1', created_at,
			       jsonb_build_object('top', jsonb_build_array(jsonb_build_object('id', 't' || id % 50, 'crit', 4)))
			FROM samples`,
		`INSERT INTO verdicts (sample_id, scanner_id, outcome, class, ruleset, formed_at, summary)
			SELECT id, 2, 'ok', CASE WHEN id % 4 = 0 THEN 'suspicious' ELSE 'hostile' END::class, 'r1', created_at,
			       jsonb_build_object('hostile', CASE WHEN id % 4 IN (1, 2) THEN 1 ELSE 0 END, 'suspicious', id % 3)
			FROM samples WHERE id % 5 < 3`,
		`INSERT INTO verdicts (sample_id, scanner_id, outcome, class, fires_at, ruleset, formed_at, summary)
			SELECT id, 3, 'ok', (ARRAY['benign', 'suspicious', 'hostile'])[1 + id % 3]::class, id % 3000, 'r1', created_at,
			       jsonb_build_object('prob', (id % 1000) / 1000.0)
			FROM samples WHERE id % 2 = 0`,
		`ANALYZE`,
	} {
		var args []any
		if strings.Contains(step, "$1") {
			args = []any{n}
		}
		if _, err := st.pool.Exec(ctx, step, args...); err != nil {
			t.Fatalf("%v: %.60s", err, step)
		}
	}
	t.Logf("generated %d flagged scans in %v", n, time.Since(start).Round(time.Second))
	for _, q := range TriageQueueNames() {
		start := time.Now()
		got, err := st.Triage(ctx, q, 64, nil)
		if err != nil {
			t.Fatalf("%s: %v", q, err)
		}
		selected := time.Since(start)
		start = time.Now()
		depth, capped, err := st.TriageDepth(ctx, q)
		if err != nil {
			t.Fatalf("%s depth: %v", q, err)
		}
		t.Logf("%-30s select 64: %4d in %8v   depth %5d (capped %-5v) in %8v",
			q, len(got), selected.Round(time.Millisecond/10), depth, capped, time.Since(start).Round(time.Millisecond/10))
	}
}
