package store

import (
	"maps"
	"testing"
	"time"
)

// TestQueueGoModules locks the go_module backfill's selection: Go-named zips on
// disk scanned before the cutoff are queued as an operator's rescan, the limit
// spends itself on the newest, and a re-run queues nothing twice.
func TestQueueGoModules(t *testing.T) {
	st := open(t)
	ctx := t.Context()
	goZip := func(bytes string, scanned time.Duration) *fixture {
		return with(base(bytes, "unknown"), func(f *fixture) {
			f.fileType, f.pkg, f.version, f.scanned = "zip", "pkg:golang/example.com/"+bytes, "v1.0.0", scanned
		})
	}
	// Stored in this order, so ids rise down the list: "newest" is last.
	world(ctx, t, st,
		with(goZip("typed", 30*hour), func(f *fixture) { f.fileType = "go_module" }), // the first go_module scan
		goZip("oldest", 48*hour),
		goZip("middle", 48*hour),
		goZip("rescanned", hour), // scanned since the cutoff
		with(goZip("npm zip", 48*hour), func(f *fixture) { f.pkg = "pkg:npm/zip" }),
		with(goZip("off disk", 48*hour), func(f *fixture) { f.created = -1 }), // world gives it no path
		with(goZip("unscanned", 0), func(f *fixture) { f.atomscan = "" }),     // no scans row, as a member
		goZip("already queued", 48*hour),
		goZip("newest", 48*hour),
	)
	enqueue(ctx, t, st, QueueNew, digestOf("already queued"))

	start, ok, err := st.GoModuleScanStart(ctx)
	if err != nil || !ok {
		t.Fatalf("GoModuleScanStart: %v, ok %t", err, ok)
	}
	if d := time.Since(start); d < 29*hour || d > 31*hour {
		t.Fatalf("scan start %v ago, want the go_module file's 30h", d.Round(time.Minute))
	}

	matched, err := st.QueueGoModules(ctx, start, 0, true)
	if err != nil || matched != 3 {
		t.Fatalf("dry run matched %d, %v; want oldest, middle and newest", matched, err)
	}

	n, err := st.QueueGoModules(ctx, start, 2, false)
	if err != nil {
		t.Fatal(err)
	}
	want := map[string]Priority{
		hexOf(digestOf("already queued")): QueueNew,
		hexOf(digestOf("newest")):         QueueRequested,
		hexOf(digestOf("middle")):         QueueRequested,
	}
	if got := priorities(ctx, t, st); n != 2 || !maps.Equal(got, want) {
		t.Fatalf("queued %d: %v, want the two newest at QueueRequested: %v", n, got, want)
	}

	if n, err = st.QueueGoModules(ctx, start, 10, false); err != nil || n != 1 {
		t.Fatalf("second run queued %d, %v; want only oldest", n, err)
	}
	if n, err = st.QueueGoModules(ctx, start, 10, false); err != nil || n != 0 {
		t.Errorf("rerun queued %d, %v; want 0", n, err)
	}
}

func TestGoModuleScanStartNone(t *testing.T) {
	st := open(t)
	ctx := t.Context()
	world(ctx, t, st, with(base("zip", "unknown"), func(f *fixture) { f.fileType, f.pkg = "zip", "pkg:golang/example.com/m" }))
	if _, ok, err := st.GoModuleScanStart(ctx); err != nil || ok {
		t.Fatalf("GoModuleScanStart with no go_module file: ok %t, %v; want ok false", ok, err)
	}
}

// The rescan is what retypes a file: a result naming go_module replaces the
// zip its earlier scan stored.
func TestWriteRetypesZipToGoModule(t *testing.T) {
	st := open(t)
	ctx := t.Context()
	r := archive()
	r.files[0]["type"] = "go_module"
	if _, err := st.pool.Exec(ctx, `INSERT INTO samples (sha256, size_bytes, file_type) VALUES ($1, 4000, 'zip')`,
		digestOf("package bytes")); err != nil {
		t.Fatal(err)
	}
	if got := r.write(ctx, t, st); got.Retyped != 1 {
		t.Errorf("stats %+v, want the package retyped", got)
	}
	var fileType string
	if err := st.pool.QueryRow(ctx, `SELECT file_type FROM samples WHERE sha256 = $1`,
		digestOf("package bytes")).Scan(&fileType); err != nil || fileType != "go_module" {
		t.Errorf("file_type %q, %v; want go_module", fileType, err)
	}
}
