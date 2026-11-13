package store

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"regexp"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/atomdrift-project/hopper/scanresult"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
)

// open returns a Store on a fresh schema of a disposable database.
//
//	HOPPER_TEST_PG_DSN='postgres://postgres@/hoppertest?host=/tmp&port=55432' go test ./store
func open(t *testing.T) *Store {
	t.Helper()
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
	schema := fmt.Sprintf("store_%d", time.Now().UnixNano())
	cfg.ConnConfig.RuntimeParams["search_path"] = schema
	pool, err := pgxpool.NewWithConfig(ctx, cfg)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		// t.Context is done by now; teardown needs its own.
		if _, err := pool.Exec(context.WithoutCancel(ctx), "DROP SCHEMA "+schema+" CASCADE"); err != nil {
			t.Errorf("drop schema: %v", err)
		}
		pool.Close()
	})
	if _, err := pool.Exec(ctx, "CREATE SCHEMA "+schema); err != nil {
		t.Fatal(err)
	}
	if _, err := pool.Exec(ctx, Schema); err != nil {
		t.Fatalf("schema: %v", err)
	}
	st, err := New(pool)
	if err != nil {
		t.Fatal(err)
	}
	return st
}

// result is a small archive result: a package that holds one script.
type result struct {
	header  string
	files   []map[string]any
	reports []string
}

func sum(s string) string {
	h := sha256.Sum256([]byte(s))
	return hex.EncodeToString(h[:])
}

func archive() *result {
	r := &result{
		header:  `{"v":8,"scan":{"engine":"3.0.0","ruleset":"r1","level":25,"worker":"w1","at":"2026-11-12T15:00:00Z","ms":40},"files":2}`,
		reports: []string{`{"traits":[{"id":"a::root","crit":2}]}`, `{"traits":[{"id":"b::fetch-exec","crit":5}]}`},
	}
	pkg, script := sum("package bytes"), sum("script bytes")
	r.files = []map[string]any{
		{
			"sha256": pkg, "size": 4000, "type": "npm", "report": sum(r.reports[0]),
			"verdict": map[string]any{
				"outcome": "ok", "class": "hostile", "fires_at": 12, "by": "floor", "in": script,
				"reason": "Install script fetches and runs a binary.",
				"top":    []map[string]any{{"id": "b::fetch-exec", "crit": 5}},
			},
			"ml":       map[string]any{"class": "benign", "fires_at": -1, "prob": 0.05},
			"floor":    map[string]any{"class": "hostile", "fires_at": 12, "hostile": 1},
			"contents": map[string]any{"children": []int{1}, "paths": []string{"package/install.js"}},
			"refs":     []map[string]any{{"kind": "dependency", "name": "pkg:npm/left-pad", "version": "1.3.0"}},
		},
		{
			"sha256": script, "size": 300, "type": "javascript", "report": sum(r.reports[1]),
			"verdict": map[string]any{"outcome": "ok", "class": "hostile", "fires_at": 12, "by": "floor"},
			"ml":      map[string]any{"class": "benign", "fires_at": -1, "prob": 0.04},
			"floor":   map[string]any{"class": "hostile", "fires_at": 12, "hostile": 1},
		},
	}
	return r
}

// body serializes the result as a version 8 body.
func (r *result) body(t *testing.T) *bytes.Buffer {
	t.Helper()
	var b bytes.Buffer
	b.WriteString(r.header + "\n")
	for _, f := range r.files {
		line, err := json.Marshal(f)
		if err != nil {
			t.Fatal(err)
		}
		b.Write(append(line, '\n'))
	}
	for _, report := range r.reports {
		b.WriteString(report + "\n")
	}
	return &b
}

// write decodes and stores the result, failing the test on any error.
func (r *result) write(ctx context.Context, t *testing.T, st *Store) Stats {
	t.Helper()
	files, err := scanresult.Decode(r.body(t).Bytes())
	if err != nil {
		t.Fatalf("decode: %v", err)
	}
	stats, err := st.Write(ctx, files)
	if err != nil {
		t.Fatalf("write: %v", err)
	}
	return stats
}

// Every juror and scanner a result may carry has a row to land in.
func TestScannerIDs(t *testing.T) {
	for _, name := range scanresult.Jurors {
		if _, ok := jurors[name]; !ok {
			t.Errorf("juror %s has no scanner id", name)
		}
	}
	for _, name := range scanresult.Scanners {
		if _, ok := outside[name]; !ok {
			t.Errorf("scanner %s has no scanner id", name)
		}
	}
	if len(jurors) != len(scanresult.Jurors) || len(outside) != len(scanresult.Scanners) {
		t.Errorf("ids for %d jurors and %d scanners, want %d and %d",
			len(jurors), len(outside), len(scanresult.Jurors), len(scanresult.Scanners))
	}
}

func TestWrite(t *testing.T) {
	st := open(t)
	ctx := t.Context()
	r := archive()
	pkgSum, scriptSum := sha256.Sum256([]byte("package bytes")), sha256.Sum256([]byte("script bytes"))
	pkg, script := pkgSum[:], scriptSum[:]

	t.Run("first scan stores everything", func(t *testing.T) {
		got := r.write(ctx, t, st)
		// Six opinions, five rows: the model's benign reading of the member,
		// which has no scan of its own, is not stored (writer.speaks).
		want := Stats{Files: 2, Judged: 2, NewSamples: 2, Verdicts: 5, Stamped: 1, Reports: 2, Contents: 1, Refs: 1}
		if got != want {
			t.Errorf("stats %+v, want %+v", got, want)
		}
		rec, err := st.BySHA256(ctx, pkg)
		if err != nil {
			t.Fatal(err)
		}
		if rec.Class != "hostile" || rec.FiresAt == nil || *rec.FiresAt != 12 || rec.Engine != "3.0.0" ||
			rec.Ruleset != "r1" || rec.Reason != "Install script fetches and runs a binary." ||
			len(rec.Findings) != 1 || rec.Findings[0].Crit != 5 || !rec.Analyzed ||
			!rec.ScannedAt.Equal(time.Date(2026, 11, 12, 15, 0, 0, 0, time.UTC)) {
			t.Errorf("record %+v", rec)
		}
		report, err := st.Report(ctx, script)
		if err != nil || string(report) != r.reports[1] {
			t.Errorf("report %q, %v; want %q", report, err, r.reports[1])
		}
	})

	// The rule scan uses before trusting a stored verdict: a reading from
	// another analyzer is confirmed afresh (upsert, refreshAge).
	t.Run("the same result under a new ruleset refreshes the verdicts it confirms", func(t *testing.T) {
		r.header = strings.NewReplacer(`"ruleset":"r1"`, `"ruleset":"r2"`, "T15:00:00Z", "T16:00:00Z").Replace(r.header)
		files, err := scanresult.Decode(r.body(t).Bytes())
		if err != nil {
			t.Fatal(err)
		}
		got, err := st.Write(ctx, files)
		if err != nil {
			t.Fatal(err)
		}
		// Five rows refreshed, no report rewritten: each digest is unchanged.
		want := Stats{Files: 2, Judged: 2, Verdicts: 5, Stamped: 1, ReportsUnchanged: 2}
		if got != want {
			t.Errorf("stats %+v, want %+v", got, want)
		}
		rec, err := st.BySHA256(ctx, pkg)
		if err != nil || rec.Ruleset != "r2" || rec.ScannedAt.Hour() != 16 {
			t.Errorf("record %+v, %v: not stamped", rec, err)
		}
		// A member has no scans row: its verdict's own time is when it was
		// last formed or confirmed.
		if rec, err := st.BySHA256(ctx, script); err != nil || rec.Ruleset != "r2" || rec.ScannedAt.Hour() != 16 {
			t.Errorf("member record %+v, %v: the confirmed member was not refreshed", rec, err)
		}
		var ruleset string
		if err := st.pool.QueryRow(ctx, `SELECT v.ruleset FROM verdicts v JOIN samples s ON s.id = v.sample_id
			WHERE s.sha256 = $1 AND v.scanner_id = $2`, pkg, jurors["ml"]).Scan(&ruleset); err != nil || ruleset != "r2" {
			t.Errorf("ml juror ruleset %q, %v; want r2, refreshed", ruleset, err)
		}
	})

	t.Run("a new engine is recorded with the scan, not on the verdict", func(t *testing.T) {
		r.header = strings.Replace(r.header, `"engine":"3.0.0"`, `"engine":"3.0.1"`, 1)
		// The member's row now holds this scan's time: settled, left alone.
		if got, want := r.write(ctx, t, st), (Stats{Files: 2, Judged: 1, Deferred: 1, Stamped: 1, ReportsUnchanged: 2}); got != want {
			t.Errorf("stats %+v, want %+v", got, want)
		}
		if rec, err := st.BySHA256(ctx, pkg); err != nil || rec.Engine != "3.0.1" {
			t.Errorf("record %+v, %v: want engine 3.0.1", rec, err)
		}
		if rec, err := st.BySHA256(ctx, script); err != nil || rec.Engine != "3.0.0" {
			t.Errorf("member record %+v, %v: want engine 3.0.0, untouched", rec, err)
		}
	})

	t.Run("the same upload again writes nothing", func(t *testing.T) {
		if got, want := r.write(ctx, t, st), (Stats{Files: 2, Judged: 1, Deferred: 1, ReportsUnchanged: 2}); got != want {
			t.Errorf("stats %+v, want %+v", got, want)
		}
	})

	// The rescan-by-age sweep reads the artifact's last scan, so a later scan
	// has to show there even when it found nothing new.
	t.Run("a later scan with the same result, from another worker, is recorded", func(t *testing.T) {
		r.header = strings.NewReplacer(`"worker":"w1"`, `"worker":"w2"`, "T16:00:00Z", "T17:00:00Z").Replace(r.header)
		if got, want := r.write(ctx, t, st), (Stats{Files: 2, Judged: 2, Stamped: 1, ReportsUnchanged: 2}); got != want {
			t.Errorf("stats %+v, want %+v", got, want)
		}
		if rec, err := st.BySHA256(ctx, pkg); err != nil || rec.ScannedAt.Hour() != 17 {
			t.Errorf("record %+v, %v: want the archive's last scan at 17:00", rec, err)
		}
		// The same ruleset an hour on: the member's row keeps 16:00.
		if rec, err := st.BySHA256(ctx, script); err != nil || rec.ScannedAt.Hour() != 16 {
			t.Errorf("member record %+v, %v: restamped under the same ruleset within refreshAge", rec, err)
		}
	})

	// A member's jurors are part of its opinion, so changing one restamps
	// the member's atomscan row too (TestWriteMemberJurorsFollowNewestScan).
	t.Run("a member's changed juror rewrites that juror and the member's opinion", func(t *testing.T) {
		r.files[1]["ml"] = map[string]any{"class": "suspicious", "fires_at": 900, "prob": 0.61}
		if got, want := r.write(ctx, t, st), (Stats{Files: 2, Judged: 2, Verdicts: 2, ReportsUnchanged: 2}); got != want {
			t.Errorf("stats %+v, want %+v", got, want)
		}
	})

	// Each rescan below is later than the last: a member's opinion changes
	// only for a scan newer than the one that formed it.
	t.Run("a juror that no longer fires loses its row", func(t *testing.T) {
		r.header = strings.Replace(r.header, "T17:00:00Z", "T18:00:00Z", 1)
		delete(r.files[1], "floor")
		if got, want := r.write(ctx, t, st), (Stats{Files: 2, Judged: 2, Verdicts: 1, Stamped: 1, JurorsRemoved: 1, ReportsUnchanged: 2}); got != want {
			t.Errorf("stats %+v, want %+v", got, want)
		}
	})

	t.Run("a changed report is stored, the other is skipped", func(t *testing.T) {
		r.header = strings.Replace(r.header, "T18:00:00Z", "T19:00:00Z", 1)
		r.reports[1] = `{"traits":[{"id":"b::fetch-exec","crit":5},{"id":"c::new","crit":3}]}`
		r.files[1]["report"] = sum(r.reports[1])
		if got, want := r.write(ctx, t, st), (Stats{Files: 2, Judged: 2, Verdicts: 1, Stamped: 1, Reports: 1, ReportsUnchanged: 1}); got != want {
			t.Errorf("stats %+v, want %+v", got, want)
		}
		report, err := st.Report(ctx, script)
		if err != nil || string(report) != r.reports[1] {
			t.Errorf("report %q, %v; want the new one", report, err)
		}
	})
}

// What a result states replaces what is stored; what it does not state, and
// what it cannot prove, changes nothing.
func TestWriteReplaces(t *testing.T) {
	st := open(t)
	ctx := t.Context()
	r := archive()
	r.write(ctx, t, st)
	pkgSum, scriptSum := sha256.Sum256([]byte("package bytes")), sha256.Sum256([]byte("script bytes"))
	pkg, script := pkgSum[:], scriptSum[:]

	t.Run("a report that does not match its hash stores nothing", func(t *testing.T) {
		bad := archive()
		bad.header = r.header
		bad.reports[0] = `{"traits":[]}`
		bad.files[0]["report"] = sum("something else")
		files, err := scanresult.Decode(bad.body(t).Bytes())
		if err != nil {
			t.Fatal(err)
		}
		if _, err := st.Write(ctx, files); !errors.Is(err, scanresult.ErrMalformed) || !strings.Contains(err.Error(), "hashes to") {
			t.Fatalf("got %v, want a malformed body: hash mismatch", err)
		}
		report, err := st.Report(ctx, pkg)
		if err != nil || string(report) != r.reports[0] {
			t.Errorf("report %q, %v; the failed write should have left it alone", report, err)
		}
	})

	t.Run("a file that is only named keeps its verdict", func(t *testing.T) {
		named := &result{
			header: r.header,
			files: []map[string]any{
				{"sha256": sum("another package"), "size": 9, "type": "npm", "contents": map[string]any{
					"children": []int{1}, "paths": []string{"vendor/install.js"},
				}},
				{"sha256": r.files[1]["sha256"], "size": 300, "type": "javascript"},
			},
		}
		if got, want := named.write(ctx, t, st), (Stats{Files: 2, NewSamples: 1, Contents: 1}); got != want {
			t.Errorf("stats %+v, want %+v", got, want)
		}
		rec, err := st.BySHA256(ctx, script)
		if err != nil || !rec.Analyzed || rec.Class != "hostile" {
			t.Errorf("record %+v, %v: naming a file must not clear its verdict", rec, err)
		}
	})

	t.Run("stated contents and references replace the stored ones", func(t *testing.T) {
		r.files[0]["contents"] = map[string]any{"children": []int{}, "paths": []string{}}
		r.files[0]["refs"] = []map[string]any{{"kind": "url_fetch", "name": "https://example.com/a.sh"}}
		got := r.write(ctx, t, st)
		if got.Contents != 1 || got.Refs != 1 || got.RefsRemoved != 1 {
			t.Errorf("stats %+v, want one contents row removed, one reference added and one removed", got)
		}
		// An emptied list keeps its row, empty, with the time it was emptied,
		// so that an older list arriving later cannot bring the members back.
		var n int
		if err := st.pool.QueryRow(ctx, `SELECT count(*) FROM contents WHERE cardinality(child_ids) > 0`).Scan(&n); err != nil || n != 1 {
			t.Errorf("%d contents rows, %v; want only the other package's", n, err)
		}
		// The other package still lists the script, so what is known of it stands.
		if rec, err := st.BySHA256(ctx, script); err != nil || !rec.Analyzed || got.Orphaned != 0 {
			t.Errorf("record %+v, %v, orphaned %d: a member another archive lists lost its verdict", rec, err, got.Orphaned)
		}
	})
}

// A scan that failed says nothing about the file, so it must not cost hopper
// what an earlier scan found.
func TestWriteFailedScan(t *testing.T) {
	st := open(t)
	ctx := t.Context()
	r := archive()
	r.write(ctx, t, st)
	scriptSum := sha256.Sum256([]byte("script bytes"))
	script := scriptSum[:]
	one := strings.NewReplacer(`"files":2`, `"files":1`, `"ruleset":"r1"`, `"ruleset":"r2"`).Replace(r.header)

	t.Run("a failed rescan keeps the verdict, its jurors and its report", func(t *testing.T) {
		failed := &result{header: one, files: []map[string]any{{
			"sha256": r.files[1]["sha256"], "size": 300, "type": "javascript",
			"verdict": map[string]any{"outcome": "timeout", "error": "analysis exceeded 60s"},
		}}}
		// The scan is recorded (the file stops looking overdue), but a
		// failed scan's time is bookkeeping, not a stamp of what is known.
		if got, want := failed.write(ctx, t, st), (Stats{Files: 1, Judged: 1}); got != want {
			t.Errorf("stats %+v, want %+v", got, want)
		}
		var recorded bool
		if err := st.pool.QueryRow(ctx, `SELECT EXISTS (SELECT 1 FROM scans sc JOIN samples s ON s.id = sc.sample_id
			WHERE s.sha256 = $1 AND sc.ruleset = 'r1')`, script).Scan(&recorded); err != nil || !recorded {
			t.Errorf("scan recorded %v, %v; want a row keeping the verdict's ruleset", recorded, err)
		}
		rec, err := st.BySHA256(ctx, script)
		if err != nil || rec.Class != "hostile" || rec.Ruleset != "r1" {
			t.Errorf("record %+v, %v: a failed rescan replaced the verdict", rec, err)
		}
		var n int
		if err := st.pool.QueryRow(ctx, `SELECT count(*) FROM verdicts v JOIN samples s ON s.id = v.sample_id
			WHERE s.sha256 = $1`, script).Scan(&n); err != nil || n != 2 {
			t.Errorf("%d verdict rows, %v; want atomscan's and the floor's (the model's benign reading is not stored)", n, err)
		}
		if report, err := st.Report(ctx, script); err != nil || string(report) != r.reports[1] {
			t.Errorf("report %q, %v; want it kept", report, err)
		}
	})

	t.Run("a failed first scan is recorded, and a later success replaces it", func(t *testing.T) {
		failed := &result{header: one, files: []map[string]any{{
			"sha256": sum("opaque bytes"), "size": 77,
			"verdict": map[string]any{"outcome": "unsupported", "error": "unknown file type"},
		}}}
		if got, want := failed.write(ctx, t, st), (Stats{Files: 1, Judged: 1, NewSamples: 1, Verdicts: 1}); got != want {
			t.Errorf("stats %+v, want %+v", got, want)
		}
		failed.files[0]["verdict"] = map[string]any{"outcome": "ok", "class": "benign", "fires_at": -1}
		if got, want := failed.write(ctx, t, st), (Stats{Files: 1, Judged: 1, Verdicts: 1}); got != want {
			t.Errorf("stats %+v, want %+v", got, want)
		}
	})
}

// A file the LLM judged in a scan of its own keeps that verdict when an archive
// holding it is rescanned: the member's line knows less, and replacing the
// verdict would only be undone by the file's next scan.
func TestWriteMemberWithOwnScan(t *testing.T) {
	st := open(t)
	ctx := t.Context()
	r := archive()
	r.write(ctx, t, st)
	scriptSum := sha256.Sum256([]byte("script bytes"))
	script := scriptSum[:]
	alone := &result{
		header: strings.Replace(r.header, `"files":2`, `"files":1`, 1),
		files: []map[string]any{{
			"sha256": r.files[1]["sha256"], "size": 300, "type": "javascript", "report": r.files[1]["report"],
			"verdict": map[string]any{"outcome": "ok", "class": "hostile", "fires_at": 5, "by": "llm"},
			"ml":      r.files[1]["ml"], "floor": r.files[1]["floor"],
			"llm":  map[string]any{"class": "hostile", "conf": 0.9, "reason": "Downloads and runs a binary."},
			"refs": []map[string]any{},
		}},
		reports: r.reports[1:],
	}
	// The model's benign reading, left unstored on the archive's line, is
	// kept now that the file is scanned on its own.
	if got, want := alone.write(ctx, t, st), (Stats{Files: 1, Judged: 1, Verdicts: 3, Stamped: 1, ReportsUnchanged: 1}); got != want {
		t.Errorf("scanned alone: stats %+v, want %+v (the verdict, the llm row and the ml row)", got, want)
	}

	// The archive is rescanned under a new ruleset. Its line for the script
	// disagrees with the stored verdict, has a new report, and carries no floor.
	r.header = strings.Replace(r.header, `"ruleset":"r1"`, `"ruleset":"r2"`, 1)
	r.files[0]["llm"] = map[string]any{"class": "suspicious", "conf": 0.6}
	r.files[1]["verdict"] = map[string]any{"outcome": "ok", "class": "suspicious", "fires_at": 900, "by": "ml"}
	delete(r.files[1], "floor")
	r.reports[1] = `{"traits":[]}`
	r.files[1]["report"] = sum(r.reports[1])
	// Written: the archive's scan and its llm row. Nothing of the script's.
	if got, want := r.write(ctx, t, st), (Stats{Files: 2, Judged: 1, Deferred: 1, Verdicts: 1, Stamped: 1, ReportsUnchanged: 2}); got != want {
		t.Errorf("archive rescan: stats %+v, want %+v", got, want)
	}
	rec, err := st.BySHA256(ctx, script)
	if err != nil || rec.Class != "hostile" || rec.FiresAt == nil || *rec.FiresAt != 5 || rec.Ruleset != "r1" {
		t.Errorf("record %+v, %v: the member's line replaced the file's own verdict", rec, err)
	}
	var n int
	if err := st.pool.QueryRow(ctx, `SELECT count(*) FROM verdicts v JOIN samples s ON s.id = v.sample_id
		WHERE s.sha256 = $1`, script).Scan(&n); err != nil || n != 4 {
		t.Errorf("%d verdict rows on the member, %v; want atomscan, ml, floor and llm, all kept", n, err)
	}
	if report, err := st.Report(ctx, script); err != nil || string(report) == r.reports[1] {
		t.Errorf("report %q, %v: the member's line replaced the file's own report", report, err)
	}

	// The archive's own llm row is the archive's to lose.
	delete(r.files[0], "llm")
	if got, want := r.write(ctx, t, st), (Stats{Files: 2, Judged: 1, Deferred: 1, JurorsRemoved: 1, ReportsUnchanged: 2}); got != want {
		t.Errorf("archive without llm: stats %+v, want %+v", got, want)
	}
}

// References are held by the artifact, under the name hopper gives the
// release, with the version they resolved to and the constraint they came from.
func TestWriteRefs(t *testing.T) {
	st := open(t)
	ctx := t.Context()
	r := archive()
	served := sum("served bytes")
	r.files[0]["refs"] = []map[string]any{
		{"kind": "dependency", "name": "pkg:PyPI/Django_Rest", "version": "3.1.0", "requested": ">=3"},
		{"kind": "dependency", "name": "pkg:pypi/django-rest", "version": "3.1.0", "requested": "~=3.1"},
		{"kind": "url_fetch", "name": "https://example.com/a.sh", "sha256": served},
	}
	if got := r.write(ctx, t, st); got.Refs != 2 || got.RefsRemoved != 0 {
		t.Errorf("stats %+v, want two references: one spelling of the package, and the URL", got)
	}
	type ref struct{ name, version, requested, fetched string }
	stored := func() []ref {
		rows, err := st.pool.Query(ctx, `SELECT n.name, r.version, r.requested, coalesce(encode(r.fetched, 'hex'), '')
			FROM refs r JOIN names n ON n.id = r.name_id ORDER BY n.name`)
		if err != nil {
			t.Fatal(err)
		}
		got, err := pgx.CollectRows(rows, func(row pgx.CollectableRow) (ref, error) {
			var x ref
			return x, row.Scan(&x.name, &x.version, &x.requested, &x.fetched)
		})
		if err != nil {
			t.Fatal(err)
		}
		return got
	}
	want := []ref{{"https://example.com/a.sh", "", "", served}, {"pkg:pypi/django-rest", "3.1.0", ">=3", ""}}
	if got := stored(); !slices.Equal(got, want) {
		t.Errorf("refs %+v, want %+v", got, want)
	}

	t.Run("a repeat writes nothing", func(t *testing.T) {
		if got := r.write(ctx, t, st); got.Refs != 0 || got.RefsRemoved != 0 {
			t.Errorf("stats %+v", got)
		}
	})

	t.Run("a new constraint for the same version updates the ref in place", func(t *testing.T) {
		r.files[0]["refs"] = []map[string]any{
			{"kind": "dependency", "name": "pkg:pypi/django-rest", "version": "3.1.0", "requested": "^3"},
			{"kind": "url_fetch", "name": "https://example.com/a.sh", "sha256": served},
		}
		if got := r.write(ctx, t, st); got.Refs != 1 || got.RefsRemoved != 0 {
			t.Errorf("stats %+v, want one reference changed", got)
		}
		want[1].requested = "^3"
		if got := stored(); !slices.Equal(got, want) {
			t.Errorf("refs %+v, want %+v", got, want)
		}
	})
}

// A member is uploaded only while scan has something to say about it. Once no
// archive lists it, what hopper believed about it goes: there are no bytes to
// scan it again, so nothing else would ever correct it.
func TestWriteOrphans(t *testing.T) {
	st := open(t)
	ctx := t.Context()
	benign := map[string]any{"outcome": "ok", "class": "benign", "fires_at": -1}
	hostile := map[string]any{"outcome": "ok", "class": "hostile", "fires_at": 12}
	type at struct {
		path  string
		child int // index of the member's own file line
	}
	file := func(name string, verdict map[string]any, members ...at) map[string]any {
		f := map[string]any{"sha256": sum(name), "size": 10, "type": "tar", "verdict": verdict}
		if len(members) > 0 {
			children, paths := []int{}, []string{}
			for _, m := range members {
				children, paths = append(children, m.child), append(paths, m.path)
			}
			f["contents"] = map[string]any{"children": children, "paths": paths}
		}
		return f
	}
	upload := func(files ...map[string]any) Stats {
		t.Helper()
		r := &result{files: files, header: fmt.Sprintf(
			`{"v":8,"scan":{"engine":"3.0.0","ruleset":"r1","level":25,"worker":"w1","at":"2026-11-12T15:00:00Z","ms":40},"files":%d}`, len(files))}
		return r.write(ctx, t, st)
	}
	analyzed := func(name string) bool {
		t.Helper()
		h := sha256.Sum256([]byte(name))
		rec, err := st.BySHA256(ctx, h[:])
		if err != nil {
			t.Fatalf("%s: %v", name, err)
		}
		return rec.Analyzed
	}

	// Two archives hold the same script; one also holds a nested archive
	// with a file of its own.
	upload(file("a", hostile, at{"x.js", 1}, at{"inner.tar", 2}), file("script", hostile),
		file("inner", hostile, at{"y.js", 3}), file("leaf", hostile))
	upload(file("b", hostile, at{"lib/x.js", 1}), file("script", hostile))

	// Under a later ruleset nothing in a is worth uploading.
	if got := upload(file("a", benign)); got.Orphaned != 0 {
		t.Fatalf("stats %+v: no member list was stated, so none was replaced", got)
	}
	a := file("a", benign)
	a["contents"] = map[string]any{"children": []int{}, "paths": []string{}}
	got := upload(a)
	if got.Orphaned != 2 || got.Contents != 1 {
		t.Errorf("stats %+v, want the nested archive and its file orphaned, and one list removed", got)
	}
	if analyzed("inner") || analyzed("leaf") {
		t.Error("a member no archive lists kept its verdict")
	}
	if !analyzed("script") {
		t.Error("a member another archive still lists lost its verdict")
	}
	var n int
	if err := st.pool.QueryRow(ctx, `SELECT count(*) FROM contents WHERE cardinality(child_ids) > 0`).Scan(&n); err != nil || n != 1 {
		t.Errorf("%d member lists, %v; want b's alone: an orphaned container gives up its own", n, err)
	}

	// A file in its own right is not a member to be forgotten.
	if _, err := st.pool.Exec(ctx, `INSERT INTO locations (path, sample_id)
		SELECT 'incoming/x.js', id FROM samples WHERE sha256 = $1`, digestOf("script")); err != nil {
		t.Fatal(err)
	}
	b := file("b", benign)
	b["contents"] = map[string]any{"children": []int{}, "paths": []string{}}
	if got := upload(b); got.Orphaned != 0 || !analyzed("script") {
		t.Errorf("stats %+v: a file with a location of its own lost its verdict", got)
	}
}

// Other scanners' opinions arrive on the artifact's line and are stored as
// rows of their own, as are isomer's two jurors.
func TestWriteScanners(t *testing.T) {
	st := open(t)
	ctx := t.Context()
	pkg := digestOf("package bytes")
	type row struct {
		outcome, class, ruleset, engine, signature string
		hasDB                                      bool
	}
	rowOf := func(scanner string) (got row, held bool) {
		t.Helper()
		err := st.pool.QueryRow(ctx, `SELECT v.outcome::text, coalesce(v.class::text, ''), v.ruleset,
				coalesce(v.summary->>'eng', ''), coalesce(v.summary->>'signature', ''), v.summary ?| ARRAY['db', 'ruleset', 'engine']
			FROM verdicts v JOIN samples s ON s.id = v.sample_id JOIN scanners n ON n.id = v.scanner_id
			WHERE s.sha256 = $1 AND n.name = $2`, pkg, scanner).
			Scan(&got.outcome, &got.class, &got.ruleset, &got.engine, &got.signature, &got.hasDB)
		if errors.Is(err, pgx.ErrNoRows) {
			return row{}, false
		}
		if err != nil {
			t.Fatal(err)
		}
		return got, true
	}
	clamav := func(db, signature string) map[string]any {
		return map[string]any{"clamav": map[string]any{
			"outcome": "ok", "class": "hostile", "engine": "1.4.1", "db": db, "signature": signature,
		}}
	}

	r := archive()
	base := r.write(ctx, t, st)
	r.files[0]["scanners"] = clamav("27450", "Js.Trojan.Agent-1")
	r.files[0]["drift_heuristic"] = map[string]any{"class": "suspicious", "fires_at": 400, "base": sum("the release before")}
	r.files[0]["drift_llm"] = map[string]any{"class": "hostile", "conf": 0.8, "base": sum("the release before")}
	if got := r.write(ctx, t, st); got.Verdicts != 3 {
		t.Fatalf("stats %+v (first write %+v), want clamav's row and isomer's two", got, base)
	}
	if got, _ := rowOf("clamav"); got != (row{"ok", "hostile", "27450", "1.4.1", "Js.Trojan.Agent-1", false}) {
		t.Errorf("clamav row %+v: want its database as the ruleset and its stamp out of the summary", got)
	}
	for _, juror := range []string{"drift_heuristic", "drift_llm"} {
		if _, held := rowOf(juror); !held {
			t.Errorf("no %s row", juror)
		}
	}

	t.Run("a new signature database that finds the same thing writes nothing", func(t *testing.T) {
		r.files[0]["scanners"] = clamav("27451", "Js.Trojan.Agent-1")
		if got := r.write(ctx, t, st); got.Verdicts != 0 {
			t.Errorf("stats %+v", got)
		}
		if got, _ := rowOf("clamav"); got.ruleset != "27450" {
			t.Errorf("ruleset %s, want the database it last changed its mind under", got.ruleset)
		}
	})

	t.Run("a different finding rewrites the scanner's row alone", func(t *testing.T) {
		r.files[0]["scanners"] = clamav("27452", "Js.Trojan.Agent-2")
		if got := r.write(ctx, t, st); got.Verdicts != 1 {
			t.Errorf("stats %+v", got)
		}
		if got, _ := rowOf("clamav"); got.ruleset != "27452" || got.signature != "Js.Trojan.Agent-2" {
			t.Errorf("clamav row %+v", got)
		}
	})

	t.Run("a scanner that fails does not erase what it found", func(t *testing.T) {
		r.files[0]["scanners"] = map[string]any{"clamav": map[string]any{"outcome": "error", "error": "clamd: connection refused"}}
		if got := r.write(ctx, t, st); got.Verdicts != 0 {
			t.Errorf("stats %+v", got)
		}
		if got, _ := rowOf("clamav"); got.class != "hostile" {
			t.Errorf("clamav row %+v", got)
		}
	})

	t.Run("a scanner left out of a result keeps its finding", func(t *testing.T) {
		// A host that runs only malcontent says nothing about ClamAV.
		r.files[0]["scanners"] = map[string]any{"malcontent": map[string]any{
			"class": "benign", "engine": "1.28.1", "ruleset": "1.28.1",
		}}
		if got := r.write(ctx, t, st); got.Verdicts != 1 || got.JurorsRemoved != 0 {
			t.Errorf("stats %+v, want malcontent's row written and nothing removed", got)
		}
		if got, _ := rowOf("clamav"); got.signature != "Js.Trojan.Agent-2" {
			t.Errorf("clamav row %+v, want its last finding", got)
		}
	})

	t.Run("a scan that names no scanner removes isomer's jurors and no scanner's row", func(t *testing.T) {
		// As atomscan --hopper uploads: atomdrift's own jurors and nothing else.
		delete(r.files[0], "scanners")
		delete(r.files[0], "drift_heuristic")
		delete(r.files[0], "drift_llm")
		if got := r.write(ctx, t, st); got.JurorsRemoved != 2 {
			t.Errorf("stats %+v, want isomer's two removed", got)
		}
		for _, name := range []string{"drift_heuristic", "drift_llm"} {
			if _, held := rowOf(name); held {
				t.Errorf("%s still holds a row", name)
			}
		}
		for _, name := range []string{"clamav", "malcontent"} {
			if _, held := rowOf(name); !held {
				t.Errorf("%s's row was removed by a result that did not name it", name)
			}
		}
	})
}

// What a file says it is rides on its line and is stored beside its verdicts.
func TestWriteClaims(t *testing.T) {
	st := open(t)
	ctx := t.Context()
	pkg, script := digestOf("package bytes"), digestOf("script bytes")
	type claim struct {
		name, version, signer, described string
	}
	claimOf := func(sha []byte) (c claim, held bool) {
		t.Helper()
		if err := st.pool.QueryRow(ctx, `SELECT count(*) > 0, coalesce(max(c.name), ''), coalesce(max(c.version), ''),
				coalesce(max(c.signer), ''), coalesce(max(c.ident->'description'->>'value'), '')
			FROM claims c JOIN samples s ON s.id = c.sample_id WHERE s.sha256 = $1`, sha).
			Scan(&held, &c.name, &c.version, &c.signer, &c.described); err != nil {
			t.Fatal(err)
		}
		return c, held
	}

	r := archive()
	// The description spells out an escape; it is text, not a NUL.
	r.files[0]["ident"] = map[string]any{
		"name": map[string]any{"value": "left-pad", "source": "npm.package_json"}, "version": map[string]any{"value": "1.3.0"},
		"description": map[string]any{"value": `pads with \u0000`}, "trust": "unsigned",
	}
	r.files[1]["ident"] = map[string]any{
		"name": map[string]any{"value": "Updater"}, "signer": map[string]any{"common_name": "Example Root CA"}, "trust": "signed",
	}
	if got := r.write(ctx, t, st); got.Claims != 2 || got.ClaimsRemoved != 0 {
		t.Fatalf("stats %+v, want two claims stored", got)
	}
	if got, _ := claimOf(pkg); got != (claim{"left-pad", "1.3.0", "", `pads with \u0000`}) {
		t.Errorf("package claims %+v", got)
	}
	if got, _ := claimOf(script); got != (claim{name: "Updater", signer: "Example Root CA"}) {
		t.Errorf("script claims %+v: with no organization the signer is the common name", got)
	}

	t.Run("the same claims again write nothing", func(t *testing.T) {
		if got := r.write(ctx, t, st); got.Claims != 0 || got.ClaimsRemoved != 0 {
			t.Errorf("stats %+v", got)
		}
	})

	// Each rescan below is later than the last, as a rescan is: a member's
	// opinion changes only for a scan newer than the one that formed it.
	later := func(h int) {
		r.header = regexp.MustCompile(`T\d\d:00:00Z`).ReplaceAllString(r.header, fmt.Sprintf("T%02d:00:00Z", h))
	}
	t.Run("a claim read differently replaces the stored one", func(t *testing.T) {
		later(16)
		r.files[1]["ident"] = map[string]any{
			"name":   map[string]any{"value": "Updater"},
			"signer": map[string]any{"common_name": "Example Root CA", "organization": "Example Corp"}, "trust": "signed",
		}
		if got := r.write(ctx, t, st); got.Claims != 1 {
			t.Errorf("stats %+v, want one claim replaced", got)
		}
		if got, _ := claimOf(script); got.signer != "Example Corp" {
			t.Errorf("signer %q, want the organization", got.signer)
		}
	})

	t.Run("a failed scan does not speak for what the file claims", func(t *testing.T) {
		failed := &result{header: strings.Replace(r.header, `"files":2`, `"files":1`, 1), files: []map[string]any{{
			"sha256": hexOf(pkg), "size": 4000, "type": "npm", "verdict": map[string]any{"outcome": "timeout", "error": "60s"},
		}}}
		if got := failed.write(ctx, t, st); got.ClaimsRemoved != 0 {
			t.Errorf("stats %+v", got)
		}
		if _, held := claimOf(pkg); !held {
			t.Error("a scan that timed out removed the file's claim")
		}
	})

	t.Run("a file read and found to claim nothing loses its claim", func(t *testing.T) {
		later(18)
		delete(r.files[1], "ident")
		if got := r.write(ctx, t, st); got.ClaimsRemoved != 1 || got.Claims != 0 {
			t.Errorf("stats %+v, want one claim removed", got)
		}
		if _, held := claimOf(script); held {
			t.Error("the script still holds a claim")
		}
	})

	t.Run("a member no archive lists any more gives up its claim", func(t *testing.T) {
		later(19)
		r.files[1]["ident"] = map[string]any{"name": map[string]any{"value": "Updater"}}
		r.write(ctx, t, st)
		alone := &result{header: strings.Replace(r.header, `"files":2`, `"files":1`, 1), files: []map[string]any{{
			"sha256": hexOf(pkg), "size": 4000, "type": "npm", "verdict": map[string]any{"outcome": "ok", "class": "benign", "fires_at": -1},
			"contents": map[string]any{"children": []int{}, "paths": []string{}}, "ident": r.files[0]["ident"],
		}}}
		if got := alone.write(ctx, t, st); got.Orphaned != 1 {
			t.Errorf("stats %+v, want the script orphaned", got)
		}
		if _, held := claimOf(script); held {
			t.Error("an orphaned member kept its claim")
		}
		if _, held := claimOf(pkg); !held {
			t.Error("the archive lost its own claim")
		}
	})
}

// Ingest creates a file's row before anything has scanned it, knowing its size
// and not its type. The scan's type is then the stored one.
func TestWriteSetsType(t *testing.T) {
	st := open(t)
	ctx := t.Context()
	r := archive()
	if _, err := st.pool.Exec(ctx, `INSERT INTO samples (sha256, size_bytes) VALUES ($1, 4000)`, digestOf("package bytes")); err != nil {
		t.Fatal(err)
	}
	if got := r.write(ctx, t, st); got.NewSamples != 1 || got.Retyped != 1 {
		t.Errorf("stats %+v, want the script new and the package typed", got)
	}
	var fileType string
	if err := st.pool.QueryRow(ctx, `SELECT coalesce(file_type, '') FROM samples WHERE sha256 = $1`,
		digestOf("package bytes")).Scan(&fileType); err != nil || fileType != "npm" {
		t.Errorf("file_type %q, %v; want npm", fileType, err)
	}
	if got := r.write(ctx, t, st); got.Retyped != 0 {
		t.Errorf("stats %+v: a repeat retyped a file", got)
	}
}

// verdicts.scanner_id is held to the scanners table by a CHECK, not a key:
// the two must name the same ids.
func TestScannerCheck(t *testing.T) {
	st := open(t)
	ctx := t.Context()
	var low, high int16
	if err := st.pool.QueryRow(ctx, `SELECT min(id), max(id) FROM scanners`).Scan(&low, &high); err != nil {
		t.Fatal(err)
	}
	var check string
	if err := st.pool.QueryRow(ctx, `SELECT pg_get_constraintdef(oid) FROM pg_constraint
		WHERE conrelid = 'verdicts'::regclass AND contype = 'c' AND conkey = ARRAY[
			(SELECT attnum FROM pg_attribute WHERE attrelid = 'verdicts'::regclass AND attname = 'scanner_id')]`).Scan(&check); err != nil {
		t.Fatal(err)
	}
	if want := fmt.Sprintf("CHECK (((scanner_id >= %d) AND (scanner_id <= %d)))", low, high); check != want {
		t.Errorf("verdicts check %s, want %s: widen it with the scanners table", check, want)
	}
	named := map[int16]bool{atomscan: true}
	for _, id := range jurors {
		named[id] = true
	}
	for _, id := range outside {
		named[id] = true
	}
	for id := low; id <= high; id++ {
		if !named[id] {
			t.Errorf("scanner id %d has no name in jurors or outside", id)
		}
	}
}
