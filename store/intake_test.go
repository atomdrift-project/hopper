package store

import (
	"bytes"
	"errors"
	"testing"
	"time"
)

// The routes producers and drains ask (held, provenance, the hot pool,
// popularity, ancestry) answer from the verdict tables.
func TestIntake(t *testing.T) {
	st := open(t)
	ctx := t.Context()
	archive().write(ctx, t, st) // package bytes holds script bytes
	pkg, script, nowhere := digestOf("package bytes"), digestOf("script bytes"), digestOf("nowhere")

	held, err := st.Held(ctx, [][]byte{pkg, script, nowhere})
	if err != nil || len(held) != 0 {
		t.Fatalf("held before any path: %x, %v; want none: a row alone is no bytes", held, err)
	}
	ingest(ctx, t, st, QueueNew,
		Arrival{SHA256: pkg, Size: 4000, Path: "incoming/pkg.tgz"},
		Arrival{SHA256: digestOf("good bytes"), Size: 10, Path: "incoming/good", Label: "good"})
	held, err = st.Held(ctx, [][]byte{pkg, script, nowhere})
	if err != nil {
		t.Fatal(err)
	}
	if len(held) != 2 || bytes.Equal(held[0], nowhere) || bytes.Equal(held[1], nowhere) {
		t.Errorf("held %x, want the package (its path) and the script (inside it)", held)
	}

	if prov, err := st.Provenance(ctx, pkg); err != nil || prov != nil {
		t.Errorf("provenance %s, %v; want none", prov, err)
	}
	if _, err := st.Provenance(ctx, nowhere); !errors.Is(err, ErrNotFound) {
		t.Errorf("provenance of an unknown file: %v, want ErrNotFound", err)
	}
	ok, err := st.SetProvenance(ctx, pkg, []byte(`{"registry":{"downloads":3}}`), "pkg:npm/left-pad@1.3.0", "1.3.0")
	if err != nil || !ok {
		t.Fatalf("set provenance: %v, %v", ok, err)
	}
	if prov, err := st.Provenance(ctx, pkg); err != nil || string(prov) != `{"registry": {"downloads": 3}}` {
		t.Errorf("provenance %s, %v", prov, err)
	}
	s, err := st.Sample(ctx, pkg)
	if err != nil {
		t.Fatal(err)
	}
	if s.Name != "pkg:npm/left-pad" || s.Version != "1.3.0" {
		t.Errorf("release %q %q, want the first sidecar's", s.Name, s.Version)
	}
	if ok, err := st.SetProvenance(ctx, pkg, []byte(`{}`), "pkg:npm/other", "9"); err != nil || !ok {
		t.Fatalf("refresh: %v, %v", ok, err)
	}
	if s, err = st.Sample(ctx, pkg); err != nil || s.Name != "pkg:npm/left-pad" || s.Version != "1.3.0" {
		t.Errorf("release after a refresh %q %q (%v), want the first sidecar's kept", s.Name, s.Version, err)
	}
	if ok, err := st.SetProvenance(ctx, nowhere, []byte(`{}`), "", ""); err != nil || ok {
		t.Errorf("set provenance of an unknown file: %v, %v; want false", ok, err)
	}

	later := time.Now().Add(time.Hour)
	unknown, err := st.Incoming(ctx, IncomingQuery{Before: later, Unknown: true, Limit: 10})
	if err != nil || len(unknown) != 1 || unknown[0].Path != "incoming/pkg.tgz" || unknown[0].Label != "unknown" {
		t.Errorf("unknown half %+v, %v", unknown, err)
	}
	classified, err := st.Incoming(ctx, IncomingQuery{Before: later, Limit: 10})
	if err != nil || len(classified) != 1 || classified[0].Path != "incoming/good" || classified[0].Label != "good" {
		t.Errorf("classified half %+v, %v", classified, err)
	}
	rest, err := st.Incoming(ctx, IncomingQuery{Before: later, Limit: 10, AfterSeen: classified[0].SeenAt, AfterPath: classified[0].Path})
	if err != nil || len(rest) != 0 {
		t.Errorf("after the last row: %+v, %v; want none", rest, err)
	}
	if early, err := st.Incoming(ctx, IncomingQuery{Before: time.Now().Add(-time.Hour), Unknown: true, Limit: 10}); err != nil || len(early) != 0 {
		t.Errorf("within the grace period: %+v, %v; want none", early, err)
	}

	if err := st.SetPopular(ctx, []Popular{
		{Name: "pkg:pypi/Foo_Bar", Ecosystem: "pypi", Source: "top", Rank: 3000},
		{Name: "pkg:pypi/foo-bar", Ecosystem: "pypi", Source: "top", Rank: 12},
	}); err != nil {
		t.Fatal(err)
	}
	var name string
	var rank int
	if err := st.pool.QueryRow(ctx, `SELECT purl_base, rank FROM popular_packages`).Scan(&name, &rank); err != nil {
		t.Fatal(err)
	}
	if name != "pkg:pypi/foo-bar" || rank != 12 {
		t.Errorf("popular %s rank %d, want one spelling at the better rank", name, rank)
	}

	chain, err := st.Ancestry(ctx, script)
	if err != nil {
		t.Fatal(err)
	}
	if len(chain) != 2 || !bytes.Equal(chain[0].SHA256, script) || chain[0].Depth != 0 ||
		!bytes.Equal(chain[1].SHA256, pkg) || chain[1].Depth != 1 || chain[1].Name != "pkg:npm/left-pad" {
		t.Errorf("ancestry %+v, want the script, then the package holding it", chain)
	}
	if _, err := st.Ancestry(ctx, nowhere); !errors.Is(err, ErrNotFound) {
		t.Errorf("ancestry of an unknown file: %v, want ErrNotFound", err)
	}
}
