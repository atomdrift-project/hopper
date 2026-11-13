package store

import (
	"context"
	"errors"
	"fmt"
	"slices"
	"testing"

	"github.com/jackc/pgx/v5"
)

// judge uploads a scan of the named bytes alone, with the given class and
// level, holding the given contents (paths to bytes) and references.
func judge(ctx context.Context, t *testing.T, st *Store, bytes, class string, firesAt int, members []string, refs []map[string]any) {
	t.Helper()
	r := &result{}
	root := map[string]any{
		"sha256": sum(bytes), "size": 100, "type": "npm",
		"verdict": map[string]any{"outcome": "ok", "class": class, "fires_at": firesAt},
	}
	if refs != nil {
		root["refs"] = refs
	}
	r.files = append(r.files, root)
	if len(members) > 0 {
		children, paths := []int{}, []string{}
		for i, m := range members {
			children, paths = append(children, i+1), append(paths, "package/"+m)
			// A member's line repeats what is stored, so it changes nothing.
			line := map[string]any{"sha256": sum(m), "size": 100, "type": "javascript"}
			var stored string
			err := st.pool.QueryRow(ctx, `SELECT v.class::text FROM verdicts v JOIN samples s ON s.id = v.sample_id
				WHERE s.sha256 = $1 AND v.scanner_id = $2`, digestOf(m), atomscan).Scan(&stored)
			switch {
			case err == nil:
				line["verdict"] = map[string]any{"outcome": "ok", "class": stored}
			case !errors.Is(err, pgx.ErrNoRows):
				t.Fatal(err)
			}
			r.files = append(r.files, line)
		}
		root["contents"] = map[string]any{"children": children, "paths": paths}
	}
	r.header = fmt.Sprintf(`{"v":8,"scan":{"engine":"3.0.0","ruleset":"r1","level":25,"worker":"w1","at":"2026-11-12T15:00:00Z","ms":40},"files":%d}`, len(r.files))
	r.write(ctx, t, st)
}

// release files bytes under a package name and version, as the walker would.
func release(ctx context.Context, t *testing.T, st *Store, bytes, name, version, label string) {
	t.Helper()
	ingest(ctx, t, st, QueueNew, Arrival{
		SHA256: digestOf(bytes), Size: 100, Path: "pool/" + bytes, Name: name, Version: version,
		Label: label, LabelSource: map[bool]string{true: "pool"}[label != ""],
	})
}

func raise(ctx context.Context, t *testing.T, st *Store, bytes string) (*Record, *Raised) {
	t.Helper()
	rec, err := st.BySHA256(ctx, digestOf(bytes))
	if err != nil {
		t.Fatal(err)
	}
	raised, err := st.Raise(ctx, rec.ID)
	if err != nil {
		t.Fatal(err)
	}
	return rec, raised
}

// what lists the raisers as kind:name@version or kind:sha-prefix.
func what(raised *Raised) []string {
	var out []string
	for _, by := range raised.By {
		w := by.Kind + ":" + hexOf(by.SHA256)[:6]
		if by.Name != "" {
			w = by.Kind + ":" + by.Name + "@" + by.Version
		}
		out = append(out, w)
	}
	return out
}

func TestRaise(t *testing.T) {
	st := open(t)
	ctx := t.Context()
	release(ctx, t, st, "evil 1.0.0", "pkg:npm/evil", "1.0.0", "")
	judge(ctx, t, st, "evil 1.0.0", "hostile", 7, nil, nil)
	release(ctx, t, st, "evil 1.0.1", "pkg:npm/evil", "1.0.1", "")
	judge(ctx, t, st, "evil 1.0.1", "benign", -1, nil, nil)
	release(ctx, t, st, "popular 2.0.0", "pkg:npm/popular", "2.0.0", "good")
	judge(ctx, t, st, "popular 2.0.0", "hostile", 3, nil, nil) // a false positive
	release(ctx, t, st, "dropper v1", "https://example.com/x.sh", "", "")
	judge(ctx, t, st, "dropper v1", "hostile", 9, nil, nil)
	release(ctx, t, st, "dropper v2", "https://example.com/x.sh", "", "")
	judge(ctx, t, st, "dropper v2", "benign", -1, nil, nil)
	judge(ctx, t, st, "served bytes", "hostile", 11, nil, nil)
	judge(ctx, t, st, "bad script", "hostile", 2, nil, nil)
	judge(ctx, t, st, "nested", "benign", -1, []string{"bad script"}, nil)

	for _, tc := range []struct {
		name    string
		refs    []map[string]any
		members []string
		own     int
		want    []string
		level   int
	}{
		{
			name: "a declared release judged hostile raises, at its level",
			refs: []map[string]any{{"kind": "dependency", "name": "pkg:npm/evil", "version": "1.0.0", "requested": "^1.0.0"}},
			own:  -1, want: []string{"dependency:pkg:npm/evil@1.0.0"}, level: 7,
		},
		{
			name: "another version of the same name does not",
			refs: []map[string]any{{"kind": "dependency", "name": "pkg:npm/evil", "version": "1.0.1"}},
			own:  -1,
		},
		{
			name: "a release labelled good does not, though atomscan holds it hostile",
			refs: []map[string]any{{"kind": "dependency", "name": "pkg:npm/popular", "version": "2.0.0"}},
			own:  -1,
		},
		{
			name: "a command naming a hostile release raises",
			refs: []map[string]any{{"kind": "command", "name": "pkg:npm/evil", "version": "1.0.0"}},
			own:  -1, want: []string{"command:pkg:npm/evil@1.0.0"}, level: 7,
		},
		{
			name: "a URL whose newest file is clean does not, whatever it once served",
			refs: []map[string]any{{"kind": "url_fetch", "name": "https://example.com/x.sh"}},
			own:  -1,
		},
		{
			name: "a URL that served hostile bytes when scanned raises",
			refs: []map[string]any{{"kind": "url_fetch", "name": "https://example.com/x.sh", "sha256": sum("served bytes")}},
			own:  -1, want: []string{"url_fetch:https://example.com/x.sh@"}, level: 11,
		},
		{
			name:    "a hostile file inside a contained archive raises, and its own level is kept when tighter",
			members: []string{"nested"},
			own:     1, want: []string{"member:" + hexOf(digestOf("bad script"))[:6]}, level: 1,
		},
		{
			name: "nothing hostile, nothing raised",
			refs: []map[string]any{{"kind": "dependency", "name": "pkg:npm/unknown", "version": "1.0.0"}},
			own:  -1,
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			bytes := "declarer: " + tc.name
			class := "benign"
			if tc.own >= 0 {
				class = "suspicious"
			}
			judge(ctx, t, st, bytes, class, tc.own, tc.members, tc.refs)
			rec, raised := raise(ctx, t, st, bytes)
			if got := what(raised); !slices.Equal(got, tc.want) || raised.Truncated {
				t.Errorf("raised by %v (truncated %v), want %v", got, raised.Truncated, tc.want)
			}
			rec.RaiseBy(raised)
			switch {
			case len(tc.want) == 0 && rec.Class != class:
				t.Errorf("class %s, want %s unchanged", rec.Class, class)
			case len(tc.want) > 0 && (rec.Class != "hostile" || rec.FiresAt == nil || *rec.FiresAt != tc.level):
				t.Errorf("class %s at %v, want hostile at %d", rec.Class, rec.FiresAt, tc.level)
			}
		})
	}

	t.Run("a conviction shows on the next lookup, with nothing rewritten", func(t *testing.T) {
		judge(ctx, t, st, "declarer of 1.0.1", "benign", -1, nil,
			[]map[string]any{{"kind": "dependency", "name": "pkg:npm/evil", "version": "1.0.1"}})
		if _, raised := raise(ctx, t, st, "declarer of 1.0.1"); len(raised.By) != 0 {
			t.Fatalf("raised by %v before the conviction", what(raised))
		}
		judge(ctx, t, st, "evil 1.0.1", "hostile", 4, nil, nil)
		if _, raised := raise(ctx, t, st, "declarer of 1.0.1"); !slices.Equal(what(raised), []string{"dependency:pkg:npm/evil@1.0.1"}) {
			t.Errorf("raised by %v after it", what(raised))
		}
	})
}

func TestRaiseBounds(t *testing.T) {
	st := open(t)
	ctx := t.Context()
	judge(ctx, t, st, "bad", "hostile", 2, nil, nil)

	t.Run("too many references to examine", func(t *testing.T) {
		judge(ctx, t, st, "lockfile", "benign", -1, nil, nil)
		if _, err := st.pool.Exec(ctx, `INSERT INTO names (name) SELECT 'pkg:npm/n' || g FROM generate_series(1, $1) g`, raiseRefs+1); err != nil {
			t.Fatal(err)
		}
		if _, err := st.pool.Exec(ctx, `INSERT INTO refs (sample_id, name_id, version, kind)
			SELECT s.id, n.id, '1.0.0', 'dependency' FROM samples s, names n
			WHERE s.sha256 = $1 AND n.name LIKE 'pkg:npm/n%'`, digestOf("lockfile")); err != nil {
			t.Fatal(err)
		}
		if _, raised := raise(ctx, t, st, "lockfile"); !raised.Truncated || len(raised.By) != 0 {
			t.Errorf("%+v, want nothing raised and the search reported cut short", raised)
		}
	})

	t.Run("too many contained files", func(t *testing.T) {
		judge(ctx, t, st, "big", "benign", -1, nil, nil)
		if _, err := st.pool.Exec(ctx, `WITH m AS (
				INSERT INTO samples (sha256, size_bytes) SELECT sha256(('member ' || g)::bytea), 100
				FROM generate_series(1, $2) g RETURNING id)
			INSERT INTO contents (parent_id, listed_at, child_ids, paths)
			SELECT s.id, now(), array_agg(m.id ORDER BY m.id), array_agg('f' || m.id ORDER BY m.id)
			FROM samples s, m WHERE s.sha256 = $1 GROUP BY s.id`, digestOf("big"), raiseReach+1); err != nil {
			t.Fatal(err)
		}
		if _, raised := raise(ctx, t, st, "big"); !raised.Truncated {
			t.Errorf("%+v, want the walk reported cut short", raised)
		}
	})

	t.Run("a file inside itself ends the walk", func(t *testing.T) {
		judge(ctx, t, st, "quine", "benign", -1, nil, nil)
		if _, err := st.pool.Exec(ctx, `INSERT INTO contents (parent_id, listed_at, child_ids, paths)
			SELECT id, now(), ARRAY[id, (SELECT id FROM samples WHERE sha256 = $2)], ARRAY['self', 'bad'] FROM samples WHERE sha256 = $1`,
			digestOf("quine"), digestOf("bad")); err != nil {
			t.Fatal(err)
		}
		if _, raised := raise(ctx, t, st, "quine"); raised.Truncated || !slices.Equal(what(raised), []string{"member:" + hexOf(digestOf("bad"))[:6]}) {
			t.Errorf("raised by %v (truncated %v)", what(raised), raised.Truncated)
		}
	})
}

func TestRecordRaiseBy(t *testing.T) {
	level := func(n int) *int { return &n }
	for _, tc := range []struct {
		name  string
		own   *int
		by    []*int
		class string
		want  *int
	}{
		{"nothing raises", level(-1), nil, "benign", level(-1)},
		{"a tighter level wins", level(40), []*int{level(30), level(5)}, "hostile", level(5)},
		{"the record's own tighter level stays", level(2), []*int{level(30)}, "hostile", level(2)},
		{"a record that never fires takes the raiser's", level(-1), []*int{level(30)}, "hostile", level(30)},
		{"a raiser with no level raises the class only", nil, []*int{nil}, "hostile", nil},
	} {
		t.Run(tc.name, func(t *testing.T) {
			r := Record{Class: "benign", FiresAt: tc.own}
			raised := &Raised{}
			for _, l := range tc.by {
				raised.By = append(raised.By, Raiser{Kind: "dependency", FiresAt: l})
			}
			r.RaiseBy(raised)
			if r.Class != tc.class || (r.FiresAt == nil) != (tc.want == nil) || (r.FiresAt != nil && *r.FiresAt != *tc.want) {
				t.Errorf("class %s at %v, want %s at %v", r.Class, r.FiresAt, tc.class, tc.want)
			}
		})
	}
}
