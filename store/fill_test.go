package store

import (
	"bytes"
	"testing"
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
