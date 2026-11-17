package store

import (
	"bytes"
	"encoding/json"
	"testing"
	"time"
)

// A member whose stored report is its molecule alone takes a fuller one,
// keeping what the molecule said; a file with a fuller report keeps it.
func TestFillReports(t *testing.T) {
	st := open(t)
	ctx := t.Context()
	r := archive()
	r.reports[1] = `{"mol":"Os","risk":3}`
	r.files[1]["report"] = sum(r.reports[1])
	r.write(ctx, t, st)
	pkg, err := st.Sample(ctx, digestOf("package bytes"))
	if err != nil {
		t.Fatal(err)
	}
	script, err := st.Sample(ctx, digestOf("script bytes"))
	if err != nil {
		t.Fatal(err)
	}
	ingest(ctx, t, st, QueueNew, Arrival{SHA256: digestOf("unjudged"), Size: 10, Path: "incoming/unjudged"})
	unjudged, err := st.Sample(ctx, digestOf("unjudged"))
	if err != nil {
		t.Fatal(err)
	}
	full := `{"traits":[{"crit":4,"id":"x::from-the-excerpt"}]}`
	n, err := st.FillReports(ctx, map[int64][]byte{script.ID: []byte(full), pkg.ID: []byte(full), unjudged.ID: []byte(full)})
	if err != nil {
		t.Fatal(err)
	}
	if n != 1 {
		t.Errorf("filled %d, want the member alone", n)
	}
	reports, err := st.Reports(ctx, []int64{pkg.ID, script.ID, unjudged.ID})
	if err != nil {
		t.Fatal(err)
	}
	if want := `{"mol":"Os","risk":3,"traits":[{"crit":4,"id":"x::from-the-excerpt"}]}`; string(reports[script.ID]) != want {
		t.Errorf("member report %s, want %s", reports[script.ID], want)
	}
	if string(reports[pkg.ID]) != r.reports[0] {
		t.Errorf("package report %s, want its own kept", reports[pkg.ID])
	}
	if _, ok := reports[unjudged.ID]; ok {
		t.Error("a file atomscan never judged took a report")
	}
	if n, err := st.FillReports(ctx, map[int64][]byte{script.ID: []byte(`{"traits":[]}`)}); err != nil || n != 0 {
		t.Errorf("a second fill: %d, %v, want nothing: the member's report is full now", n, err)
	}
	var digest []byte
	if err := st.pool.QueryRow(ctx, `SELECT digest FROM verdicts WHERE sample_id = $1 AND scanner_id = 1`, script.ID).Scan(&digest); err != nil {
		t.Fatal(err)
	}
	if want := digestOf(`{"mol":"Os","risk":3,"traits":[{"crit":4,"id":"x::from-the-excerpt"}]}`); !bytes.Equal(digest, want) {
		t.Errorf("digest %x, want the stored report's", digest)
	}
}

// A file nothing has judged takes a verdict and its report; one with a
// verdict keeps it; a sample that is not there takes none; a second call
// stores nothing.
func TestFillVerdicts(t *testing.T) {
	st := open(t)
	ctx := t.Context()
	ingest(ctx, t, st, QueueNew,
		Arrival{SHA256: digestOf("unjudged one"), Size: 10, Path: "incoming/one"},
		Arrival{SHA256: digestOf("unjudged two"), Size: 10, Path: "incoming/two"})
	r := archive()
	r.write(ctx, t, st)
	one, err := st.Sample(ctx, digestOf("unjudged one"))
	if err != nil {
		t.Fatal(err)
	}
	two, err := st.Sample(ctx, digestOf("unjudged two"))
	if err != nil {
		t.Fatal(err)
	}
	pkg, err := st.Sample(ctx, digestOf("package bytes"))
	if err != nil {
		t.Fatal(err)
	}
	var before string
	if err := st.pool.QueryRow(ctx, `SELECT class::text || formed_at::text FROM verdicts WHERE sample_id = $1 AND scanner_id = 1`, pkg.ID).Scan(&before); err != nil {
		t.Fatal(err)
	}
	at := time.Date(2026, 5, 2, 3, 4, 5, 0, time.UTC)
	hostile := json.RawMessage(`{"outcome":"ok","class":"hostile","top":[{"id":"x::dropper","crit":5}]}`)
	report := []byte(`{"mol":"Os","risk":9}`)
	n, err := st.FillVerdicts(ctx, []Verdict{
		{ID: one.ID, At: at, Opinion: hostile, Ruleset: "60d49", Report: report},
		{ID: two.ID, At: at, Opinion: json.RawMessage(`{"outcome":"ok","class":"benign"}`), Ruleset: "60d49"},
		{ID: pkg.ID, At: at, Opinion: hostile, Ruleset: "60d49", Report: report},
		{ID: 1 << 40, At: at, Opinion: hostile, Ruleset: "60d49"},
	})
	if err != nil {
		t.Fatal(err)
	}
	if n != 2 {
		t.Errorf("stored %d, want the two unjudged files", n)
	}
	var class string
	var fires *int
	var formed time.Time
	var ruleset string
	if err := st.pool.QueryRow(ctx, `SELECT class::text, fires_at, formed_at, ruleset FROM verdicts WHERE sample_id = $1 AND scanner_id = 1`, one.ID).
		Scan(&class, &fires, &formed, &ruleset); err != nil {
		t.Fatal(err)
	}
	if class != "hostile" || fires != nil || !formed.Equal(at) || ruleset != "60d49" {
		t.Errorf("verdict %s, fires_at %v, formed %v, ruleset %s", class, fires, formed, ruleset)
	}
	reports, err := st.Reports(ctx, []int64{one.ID, two.ID, pkg.ID})
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(reports[one.ID], report) {
		t.Errorf("report %s, want %s", reports[one.ID], report)
	}
	if _, ok := reports[two.ID]; ok {
		t.Error("a verdict sent without a report gained one")
	}
	if string(reports[pkg.ID]) != r.reports[0] {
		t.Errorf("the judged package's report was replaced: %s", reports[pkg.ID])
	}
	var after string
	if err := st.pool.QueryRow(ctx, `SELECT class::text || formed_at::text FROM verdicts WHERE sample_id = $1 AND scanner_id = 1`, pkg.ID).Scan(&after); err != nil || after != before {
		t.Errorf("the judged package's verdict changed from %q to %q (%v)", before, after, err)
	}
	if n, err := st.FillVerdicts(ctx, []Verdict{{ID: one.ID, At: at, Opinion: hostile, Ruleset: "60d49", Report: report}}); err != nil || n != 0 {
		t.Errorf("a second call stored %d, %v", n, err)
	}
}

// A stored report too long for the decoder is a fuller report, not a reason to
// stop: it is left as it is, and the rest of the batch is filled.
func TestFillReportsLeavesOversizedReport(t *testing.T) {
	st := open(t)
	ctx := t.Context()
	r := archive()
	r.reports[1] = `{"mol":"Os","risk":3}`
	r.files[1]["report"] = sum(r.reports[1])
	r.write(ctx, t, st)
	pkg, err := st.Sample(ctx, digestOf("package bytes"))
	if err != nil {
		t.Fatal(err)
	}
	script, err := st.Sample(ctx, digestOf("script bytes"))
	if err != nil {
		t.Fatal(err)
	}
	huge := st.enc.EncodeAll(bytes.Repeat([]byte("a"), 65<<20), nil)
	if _, err := st.pool.Exec(ctx, `UPDATE verdicts SET detail = $2, digest = $3 WHERE sample_id = $1 AND scanner_id = 1`,
		pkg.ID, huge, digestOf("huge")); err != nil {
		t.Fatal(err)
	}
	full := `{"traits":[{"crit":4,"id":"x::from-the-excerpt"}]}`
	n, err := st.FillReports(ctx, map[int64][]byte{pkg.ID: []byte(full), script.ID: []byte(full)})
	if err != nil {
		t.Fatalf("an oversized stored report stopped the fill: %v", err)
	}
	if n != 1 {
		t.Errorf("filled %d, want the member alone", n)
	}
	var stored []byte
	if err := st.pool.QueryRow(ctx, `SELECT detail FROM verdicts WHERE sample_id = $1 AND scanner_id = 1`, pkg.ID).Scan(&stored); err != nil || !bytes.Equal(stored, huge) {
		t.Errorf("the oversized report changed (%v)", err)
	}
}
