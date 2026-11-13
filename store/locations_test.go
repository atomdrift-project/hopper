package store

import (
	"errors"
	"maps"
	"slices"
	"testing"
)

func TestMove(t *testing.T) {
	st := open(t)
	ctx := t.Context()
	sha := digestOf("sample")
	world(ctx, t, st, with(base("sample", "unknown"), func(f *fixture) { f.path = "pending/a/sample" }), base("other", "unknown"))
	paths := func() []string {
		t.Helper()
		l, err := st.LabelOf(ctx, sha)
		if err != nil {
			t.Fatal(err)
		}
		return l.Paths
	}

	t.Run("prepare records the destination beside the source; finish retires the source", func(t *testing.T) {
		ok, err := st.PrepareMove(ctx, sha, "pending/a/sample", "bad/a/sample", &Relabel{Label: "bad", Source: "cyclotron:bad"}, "")
		if err != nil || !ok {
			t.Fatalf("prepare: %v, %v", ok, err)
		}
		got := paths()
		slices.Sort(got)
		if want := []string{"bad/a/sample", "pending/a/sample"}; !slices.Equal(got, want) {
			t.Errorf("after prepare %q, want %q", got, want)
		}
		if ok, err := st.FinishMove(ctx, sha, "pending/a/sample", "bad/a/sample"); err != nil || !ok {
			t.Fatalf("finish: %v, %v", ok, err)
		}
		if got := paths(); !slices.Equal(got, []string{"bad/a/sample"}) {
			t.Errorf("after finish %q", got)
		}
		l, err := st.LabelOf(ctx, sha)
		if err != nil || l.Label != "bad" || l.LabelSource != "cyclotron:bad" {
			t.Errorf("label %+v, %v", l, err)
		}
		var flagged bool
		var events int
		if err := st.pool.QueryRow(ctx, `SELECT sc.flagged, (SELECT count(*) FROM label_events WHERE sha256 = encode(s.sha256, 'hex')
				AND from_label = 'unknown' AND to_label = 'bad' AND reason = 'triage')
			FROM samples s JOIN scans sc ON sc.sample_id = s.id WHERE s.sha256 = $1`, sha).Scan(&flagged, &events); err != nil {
			t.Fatal(err)
		}
		if !flagged || events != 1 {
			t.Errorf("flagged %v, %d label events; want the scan flagged and the change recorded once", flagged, events)
		}
	})

	t.Run("a move retried after it finished finds the destination recorded", func(t *testing.T) {
		if ok, err := st.PrepareMove(ctx, sha, "pending/a/sample", "bad/a/sample", nil, ""); err != nil || !ok {
			t.Errorf("prepare again: %v, %v", ok, err)
		}
		if ok, err := st.FinishMove(ctx, sha, "pending/a/sample", "bad/a/sample"); err != nil || !ok {
			t.Errorf("finish again: %v, %v", ok, err)
		}
	})

	t.Run("neither end recorded", func(t *testing.T) {
		if ok, err := st.PrepareMove(ctx, sha, "nowhere/x", "elsewhere/x", nil, ""); err != nil || ok {
			t.Errorf("%v, %v; want false", ok, err)
		}
	})

	t.Run("a label other than the one expected stops the move", func(t *testing.T) {
		if _, err := st.PrepareMove(ctx, sha, "bad/a/sample", "good/a/sample", nil, "good"); !errors.Is(err, ErrLabelChanged) {
			t.Errorf("%v, want ErrLabelChanged", err)
		}
	})

	t.Run("a destination holding other bytes is refused", func(t *testing.T) {
		if _, err := st.PrepareMove(ctx, sha, "bad/a/sample", "pool/other", nil, ""); err == nil {
			t.Error("the move took a path recorded for other bytes")
		}
		if got := paths(); !slices.Equal(got, []string{"bad/a/sample"}) {
			t.Errorf("paths %q after a refused move", got)
		}
	})

	t.Run("donors are the file's other paths in the destination's pool", func(t *testing.T) {
		place(ctx, t, st, sha, "bad/b/sample")
		place(ctx, t, st, sha, "good/c/sample")
		got, err := st.Donors(ctx, sha, "bad", 10)
		if err != nil || !slices.Equal(got, []string{"bad/a/sample", "bad/b/sample"}) {
			t.Errorf("donors %q, %v", got, err)
		}
	})
}

func TestQueueSiblings(t *testing.T) {
	st := open(t)
	ctx := t.Context()
	rel := func(bytes, label string) *fixture {
		return with(base(bytes, label), func(f *fixture) { f.pkg, f.version = "pkg:npm/evil", bytes })
	}
	world(ctx, t, st,
		rel("convicted", "bad"),
		with(rel("older sibling", "unknown"), func(f *fixture) { f.scanned = 2 * hour }),
		rel("good sibling", "good"),
		with(rel("same ruleset", "unknown"), func(f *fixture) { f.scanned = 2 * hour }),
		with(rel("never scanned", "unknown"), func(f *fixture) { f.scanned, f.atomscan = 0, "" }),
		base("unrelated", "unknown"),
	)
	if _, err := st.pool.Exec(ctx, `UPDATE scans SET ruleset = 'r2' WHERE sample_id = (SELECT id FROM samples WHERE sha256 = $1)`,
		digestOf("convicted")); err != nil {
		t.Fatal(err)
	}
	if _, err := st.pool.Exec(ctx, `UPDATE scans SET ruleset = 'r2' WHERE sample_id = (SELECT id FROM samples WHERE sha256 = $1)`,
		digestOf("same ruleset")); err != nil {
		t.Fatal(err)
	}
	n, err := st.QueueSiblings(ctx, digestOf("convicted"))
	if err != nil {
		t.Fatal(err)
	}
	want := map[string]Priority{hexOf(digestOf("older sibling")): QueueRepair, hexOf(digestOf("never scanned")): QueueRepair}
	if got := priorities(ctx, t, st); n != 2 || !maps.Equal(got, want) {
		t.Errorf("queued %d: %v, want %v", n, got, want)
	}
}
