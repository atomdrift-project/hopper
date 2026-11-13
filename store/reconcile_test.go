package store

import (
	"context"
	"fmt"
	"maps"
	"slices"
	"strings"
	"testing"
	"time"
)

// walk stages a walk that saw these path → bytes pairs, and returns when it
// began.
func walk(ctx context.Context, t *testing.T, st *Store, seen map[string]string) time.Time {
	t.Helper()
	started := time.Now()
	if err := st.StartWalk(ctx); err != nil {
		t.Fatal(err)
	}
	paths := slices.Sorted(maps.Keys(seen))
	shas := make([][]byte, len(paths))
	for i, p := range paths {
		shas[i] = digestOf(seen[p])
	}
	if err := st.StageWalk(ctx, shas, paths); err != nil {
		t.Fatal(err)
	}
	return started
}

func TestReconcile(t *testing.T) {
	st := open(t)
	ctx := t.Context()
	world(ctx, t, st,
		with(base("moved to good", "bad"), func(f *fixture) { f.path, f.labelSource = "bad/a", "pool" }),
		with(base("in both", "good"), func(f *fixture) { f.path, f.labelSource = "good/b", "pool" }),
		with(base("feed claim", "unknown"), func(f *fixture) { f.path = "sighted/c" }),
		with(base("marked", "good"), func(f *fixture) { f.path, f.labelSource = "good/d", "marker" }),
		with(base("reviewed", "purgatory"), func(f *fixture) { f.path, f.labelSource = "bad/e", "review" }),
		with(base("gone", "unknown"), func(f *fixture) { f.path = "pool/gone" }),
		with(base("unlisted", "unknown"), func(f *fixture) { f.path = "pool/unlisted" }),
		with(base("renamed", "unknown"), func(f *fixture) { f.path = "pool/old-name" }),
	)
	started := walk(ctx, t, st, map[string]string{
		"good/a":        "moved to good",
		"good/b":        "in both",
		"bad/b":         "in both",
		"sighted/c":     "feed claim",
		"bad/d":         "marked",
		"good/e":        "reviewed",
		"pool/new-name": "renamed",
	})
	onDisk := func(p string) bool { return p == "pool/unlisted" }
	got, err := st.Reconcile(ctx, started, onDisk, true)
	if err != nil {
		t.Fatal(err)
	}
	// Learned: good/a, bad/b, bad/d, good/e, pool/new-name. Retired: the
	// paths the walk no longer saw (bad/a, good/d, bad/e, pool/gone,
	// pool/old-name), but not pool/unlisted, which is still on disk.
	if want := (Reconciled{Learned: 5, Relabeled: 3, Retired: 5, Unlisted: 1}); got != want {
		t.Errorf("%+v, want %+v", got, want)
	}
	for bytes, want := range map[string]string{
		"moved to good": "good pool",
		"in both":       "bad conflict",
		"feed claim":    "sighted ",
		"marked":        "good marker",
		"reviewed":      "purgatory review",
	} {
		l, err := st.LabelOf(ctx, digestOf(bytes))
		if err != nil {
			t.Fatal(err)
		}
		if got := l.Label + " " + l.LabelSource; got != want {
			t.Errorf("%s: %q, want %q", bytes, got, want)
		}
	}
	for bytes, want := range map[string][]string{
		"moved to good": {"good/a"},
		"gone":          {},
		"unlisted":      {"pool/unlisted"},
		"renamed":       {"pool/new-name"},
	} {
		l, err := st.LabelOf(ctx, digestOf(bytes))
		if err != nil || !slices.Equal(l.Paths, want) {
			t.Errorf("%s paths %q, %v; want %q", bytes, l.Paths, err, want)
		}
	}
	var events int
	if err := st.pool.QueryRow(ctx, `SELECT count(*) FROM label_events WHERE reason IN ('relabel', 'conflict')`).Scan(&events); err != nil || events != 3 {
		t.Errorf("%d label events, %v; want each change recorded", events, err)
	}

	t.Run("a walk that saw nothing of a pool retires nothing", func(t *testing.T) {
		for i := range 200 {
			put(ctx, t, st, with(base(fmt.Sprintf("big %d", i), "unknown"), func(f *fixture) { f.path = fmt.Sprintf("big/%d", i) }))
		}
		// Enough paths elsewhere that the walk as a whole is within bounds.
		if _, err := st.pool.Exec(ctx, `INSERT INTO locations (path, sample_id)
			SELECT 'other/' || g, (SELECT id FROM samples WHERE sha256 = $1) FROM generate_series(1, 400) g`, digestOf("unlisted")); err != nil {
			t.Fatal(err)
		}
		seen := map[string]string{"pool/unlisted": "unlisted"}
		for i := range 150 {
			seen[fmt.Sprintf("big/%d", i)] = fmt.Sprintf("big %d", i)
		}
		for i := 1; i <= 400; i++ {
			seen[fmt.Sprintf("other/%d", i)] = "unlisted"
		}
		started := walk(ctx, t, st, seen)
		_, err := st.Reconcile(ctx, started, func(string) bool { return false }, true)
		if err == nil || !strings.Contains(err.Error(), `in "big"`) {
			t.Fatalf("%v, want the per-pool breaker", err)
		}
		if l, err := st.LabelOf(ctx, digestOf("big 199")); err != nil || len(l.Paths) != 1 {
			t.Errorf("paths %+v, %v: the refused reconcile retired something", l, err)
		}
	})

	t.Run("a walk that would relabel too much changes nothing", func(t *testing.T) {
		seen := map[string]string{}
		for i := range 200 {
			seen[fmt.Sprintf("bad/big%d", i)] = fmt.Sprintf("big %d", i)
		}
		started := walk(ctx, t, st, seen)
		_, err := st.Reconcile(ctx, started, func(string) bool { return true }, false)
		if err == nil || !strings.Contains(err.Error(), "another label") {
			t.Fatalf("%v, want the relabel breaker", err)
		}
		if l, err := st.LabelOf(ctx, digestOf("big 0")); err != nil || l.Label != "unknown" {
			t.Errorf("label %+v, %v: the refused relabel stuck", l, err)
		}
	})

	t.Run("what changed after the walk began stands", func(t *testing.T) {
		ruled := digestOf("ruled during the walk")
		world(ctx, t, st, with(base("ruled during the walk", "unknown"), func(f *fixture) { f.path = "good/r" }))
		started := walk(ctx, t, st, map[string]string{"good/r": "ruled during the walk"})
		// While the walk runs, a ruling files the file under bad/.
		if ok, err := st.PrepareMove(ctx, ruled, "good/r", "bad/r", &Relabel{Label: "bad", Source: "triage"}, ""); err != nil || !ok {
			t.Fatalf("prepare: %v, %v", ok, err)
		}
		if ok, err := st.FinishMove(ctx, ruled, "good/r", "bad/r"); err != nil || !ok {
			t.Fatalf("finish: %v, %v", ok, err)
		}
		if _, err := st.Reconcile(ctx, started, func(string) bool { return true }, false); err != nil {
			t.Fatal(err)
		}
		l, err := st.LabelOf(ctx, ruled)
		if err != nil || l.Label != "bad" || l.LabelSource != "triage" || !slices.Equal(l.Paths, []string{"bad/r"}) {
			t.Errorf("%+v, %v: the walk undid a ruling made while it ran", l, err)
		}
	})
}
