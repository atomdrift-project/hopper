package store

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"slices"
	"testing"
	"time"
)

// fixture is one file as the triage queues see it. Times are how long ago.
type fixture struct {
	bytes       string
	label       string
	labelSource string
	fileType    string
	pkg         string // a PURL without a version, or ""
	version     string
	provenance  string
	path        string        // where it is on disk; "" for none
	created     time.Duration // how long ago it arrived
	scanned     time.Duration // how long ago it was last scanned; 0 for never
	atomscan    string        // atomscan's class; "" for no verdict
	top         string        // atomscan's top findings, JSON
	floor       []int         // hostile and suspicious counts; nil for no floor row
	ml          string        // the model's class; "" for no ml row
	mlFires     int
	mlProb      float64
	llmReason   string
}

// put stores f. A scan is flagged as the writer would
// flag it.
func put(ctx context.Context, t *testing.T, st *Store, f *fixture) {
	t.Helper()
	now := time.Now()
	label := f.label
	if label == "" {
		label = "unknown"
	}
	var id int64
	if err := st.pool.QueryRow(ctx, `WITH n AS (
			INSERT INTO names (name) SELECT $6 WHERE $6 <> ''
			ON CONFLICT (name) DO UPDATE SET name = EXCLUDED.name RETURNING id)
		INSERT INTO samples (sha256, size_bytes, file_type, label, label_source, name_id, version, created_at, provenance)
		VALUES ($1, 100, nullif($2, ''), $3::label, nullif($4, ''), (SELECT id FROM n), $7, $5, nullif($8, '')::jsonb)
		RETURNING id`, digestOf(f.bytes), f.fileType, label, f.labelSource, now.Add(-f.created), f.pkg, f.version, f.provenance).
		Scan(&id); err != nil {
		t.Fatal(err)
	}
	verdict := func(scanner int16, class string, summary map[string]any) {
		t.Helper()
		fires := summary["fires_at"] // a column of its own, as the writer stores it
		delete(summary, "fires_at")
		if _, err := st.pool.Exec(ctx, `INSERT INTO verdicts (sample_id, scanner_id, outcome, class, fires_at, ruleset, formed_at, summary)
			VALUES ($1, $2, 'ok', $3::class, $6, 'r1', $4, $5)`, id, scanner, class, now.Add(-f.scanned), summary, fires); err != nil {
			t.Fatal(err)
		}
	}
	flagged := label == "bad"
	if f.atomscan != "" {
		summary := map[string]any{}
		if f.top != "" {
			summary["top"] = jsonOf(t, f.top)
		}
		verdict(atomscan, f.atomscan, summary)
		flagged = flagged || f.atomscan != "benign"
	}
	if f.floor != nil {
		class := "suspicious"
		if f.floor[0] >= 1 || f.floor[1] >= 2 {
			class = "hostile"
		}
		verdict(jurors["floor"], class, map[string]any{"hostile": f.floor[0], "suspicious": f.floor[1]})
		flagged = true
	}
	if f.ml != "" {
		verdict(jurors["ml"], f.ml, map[string]any{"fires_at": f.mlFires, "prob": f.mlProb})
		flagged = flagged || f.ml != "benign"
	}
	if f.llmReason != "" {
		verdict(jurors["llm"], "hostile", map[string]any{"reason": f.llmReason})
	}
	if f.scanned > 0 {
		if _, err := st.pool.Exec(ctx, `INSERT INTO scans (sample_id, scanned_at, ruleset, flagged) VALUES ($1, $2, 'r1', $3)`,
			id, now.Add(-f.scanned), flagged); err != nil {
			t.Fatal(err)
		}
	}
	if f.path != "" {
		place(ctx, t, st, digestOf(f.bytes), f.path)
	}
}

func jsonOf(t *testing.T, s string) any {
	t.Helper()
	var v any
	if err := json.Unmarshal([]byte(s), &v); err != nil {
		t.Fatal(err)
	}
	return v
}

func report(ctx context.Context, t *testing.T, st *Store, bytes, kind string, ago time.Duration) {
	t.Helper()
	if _, err := st.pool.Exec(ctx, `INSERT INTO reports (sample_id, report_type, content, created_at)
		SELECT id, $2, 'judgement=x', $3 FROM samples WHERE sha256 = $1`, digestOf(bytes), kind, time.Now().Add(-ago)); err != nil {
		t.Fatal(err)
	}
}

// queued returns the bytes of the files the queue hands out, in order.
func queued(ctx context.Context, t *testing.T, st *Store, queue string, names ...string) []string {
	t.Helper()
	got, err := st.Triage(ctx, queue, 50, nil)
	if err != nil {
		t.Fatal(err)
	}
	byDigest := map[string]string{}
	for _, n := range names {
		byDigest[hexOf(digestOf(n))] = n
	}
	out := []string{}
	for i := range got {
		out = append(out, byDigest[hexOf(got[i].SHA256)])
	}
	return out
}

// world stores the fixtures and returns their names, for queued.
func world(ctx context.Context, t *testing.T, st *Store, fs ...*fixture) []string {
	t.Helper()
	names := make([]string, len(fs))
	for i, f := range fs {
		if f.path == "" && f.created >= 0 {
			f.path = "pool/" + f.bytes
		}
		put(ctx, t, st, f)
		names[i] = f.bytes
	}
	return names
}

const hour = time.Hour

// base is an ordinary scanned file on disk: judged benign an hour ago,
// arrived three days ago.
func base(bytes, label string) *fixture {
	return &fixture{bytes: bytes, label: label, created: 72 * hour, scanned: hour, atomscan: "benign"}
}

func with(f *fixture, change func(*fixture)) *fixture {
	change(f)
	return f
}

func TestTriageWindowed(t *testing.T) {
	for _, tc := range []struct {
		queue string
		files []*fixture
		after func(context.Context, *testing.T, *Store)
		want  []string
	}{
		{
			queue: "bad",
			files: []*fixture{
				with(base("miss", "bad"), func(f *fixture) { f.floor = []int{0, 1} }),
				with(base("no floor", "bad"), func(f *fixture) { f.created = 96 * hour }),
				with(base("convicted", "bad"), func(f *fixture) { f.floor = []int{1, 0} }),
				with(base("two crit 4", "bad"), func(f *fixture) { f.floor = []int{0, 2} }),
				with(base("scanned yesterday", "bad"), func(f *fixture) { f.scanned = 25 * hour }),
				with(base("under a marker", "bad"), func(f *fixture) { f.labelSource = "marker" }),
				with(base("reported", "bad"), func(f *fixture) {}),
				with(base("good", "good"), func(f *fixture) { f.atomscan = "suspicious" }),
			},
			after: func(ctx context.Context, t *testing.T, st *Store) {
				t.Helper()
				report(ctx, t, st, "reported", "bad", hour/2)
			},
			want: []string{"miss", "no floor"},
		},
		{
			queue: "unconvicted-hostile",
			files: []*fixture{
				with(base("good, crit 5", "good"), func(f *fixture) { f.floor = []int{1, 0}; f.created = 100 * hour }),
				with(base("unknown, crit 5", "unknown"), func(f *fixture) { f.floor = []int{1, 1} }),
				with(base("bad, crit 5", "bad"), func(f *fixture) { f.floor = []int{1, 0} }),
				with(base("two crit 4", "good"), func(f *fixture) { f.floor = []int{0, 2} }),
				with(base("scanned 13h ago", "good"), func(f *fixture) { f.floor = []int{1, 0}; f.scanned = 13 * hour }),
			},
			want: []string{"unknown, crit 5", "good, crit 5"},
		},
		{
			queue: "unconvicted-suspicious",
			files: []*fixture{
				with(base("two crit 4", "good"), func(f *fixture) { f.floor = []int{0, 2} }),
				with(base("crit 5", "good"), func(f *fixture) { f.floor = []int{1, 2} }),
				with(base("one crit 4", "good"), func(f *fixture) { f.floor = []int{0, 1} }),
			},
			want: []string{"two crit 4"},
		},
		{
			queue: "unconvicted-hostile-stale",
			files: []*fixture{
				with(base("newer scan", "good"), func(f *fixture) { f.floor = []int{1, 0}; f.scanned = 2 * hour }),
				with(base("older scan", "good"), func(f *fixture) { f.floor = []int{1, 0}; f.scanned = 11 * hour }),
			},
			want: []string{"older scan", "newer scan"},
		},
		{
			queue: "discord",
			files: []*fixture{
				with(base("rules hostile, model benign", "good"), func(f *fixture) { f.floor = []int{1, 0}; f.ml = "benign"; f.mlFires = -1 }),
				with(base("model hostile, rules silent", "bad"), func(f *fixture) { f.ml = "hostile"; f.created = 80 * hour }),
				with(base("both hostile", "bad"), func(f *fixture) { f.floor = []int{1, 0}; f.ml = "hostile" }),
				with(base("model hostile, one crit 4", "bad"), func(f *fixture) { f.floor = []int{0, 1}; f.ml = "hostile" }),
			},
			want: []string{"rules hostile, model benign", "model hostile, rules silent"},
		},
		{
			queue: "fallout",
			files: []*fixture{
				with(base("unexplained", "unknown"), func(f *fixture) { f.ml = "hostile"; f.created = 24 * hour }),
				with(base("explained but uncited", "unknown"), func(f *fixture) {
					f.ml = "hostile"
					f.created = 30 * hour
					f.llmReason = "Runs a dropper."
				}),
				with(base("created last week", "unknown"), func(f *fixture) { f.ml = "hostile"; f.created = 8 * 24 * hour }),
				with(base("retired", "unknown"), func(f *fixture) { f.ml = "hostile"; f.created = 24 * hour }),
				with(base("inside an archive", "unknown"), func(f *fixture) { f.ml = "hostile"; f.created = 24 * hour }),
				base("holder", "unknown"),
			},
			after: func(ctx context.Context, t *testing.T, st *Store) {
				t.Helper()
				report(ctx, t, st, "retired", "fallout", 100*hour)
				if _, err := st.pool.Exec(ctx, `INSERT INTO contents (parent_id, listed_at, child_ids, paths)
					SELECT h.id, now(), ARRAY[m.id], ARRAY['a'] FROM samples h, samples m WHERE h.sha256 = $1 AND m.sha256 = $2`,
					digestOf("holder"), digestOf("inside an archive")); err != nil {
					t.Fatal(err)
				}
			},
			want: []string{"unexplained", "explained but uncited"},
		},
	} {
		t.Run(tc.queue, func(t *testing.T) {
			st := open(t)
			ctx := t.Context()
			names := world(ctx, t, st, tc.files...)
			if tc.after != nil {
				tc.after(ctx, t, st)
			}
			if got := queued(ctx, t, st, tc.queue, names...); !slices.Equal(got, tc.want) {
				t.Errorf("%s handed out %q, want %q", tc.queue, got, tc.want)
			}
		})
	}
}

func TestTriagePopular(t *testing.T) {
	st := open(t)
	ctx := t.Context()
	pop := func(bytes, pkg string, scanned time.Duration) *fixture {
		return with(base(bytes, "unknown"), func(f *fixture) {
			f.pkg, f.version, f.floor, f.scanned = pkg, bytes, []int{1, 0}, scanned
		})
	}
	names := world(ctx, t, st,
		pop("second most used", "pkg:npm/b", hour),
		pop("most used", "pkg:npm/a", hour),
		pop("not popular", "pkg:npm/z", hour),
		pop("scanned last week", "pkg:npm/a", 7*24*hour),
	)
	if _, err := st.pool.Exec(ctx, `INSERT INTO popular_packages (purl_base, ecosystem, rank, source)
		VALUES ('pkg:npm/a', 'npm', 1, 'test'), ('pkg:npm/b', 'npm', 2, 'test')`); err != nil {
		t.Fatal(err)
	}
	if got, want := queued(ctx, t, st, "popular", names...), []string{"most used", "second most used"}; !slices.Equal(got, want) {
		t.Errorf("popular %q, want %q", got, want)
	}
	if got, want := queued(ctx, t, st, "popular-tail", names...), []string{"scanned last week"}; !slices.Equal(got, want) {
		t.Errorf("popular-tail %q, want %q", got, want)
	}
}

func TestTriageFPTrait(t *testing.T) {
	st := open(t)
	ctx := t.Context()
	fp := func(bytes, trait string) *fixture {
		return with(base(bytes, "good"), func(f *fixture) {
			f.floor = []int{0, 1}
			f.top = fmt.Sprintf(`[{"id":%q,"crit":4}]`, trait)
		})
	}
	names := world(ctx, t, st, fp("x1", "a::overfires"), fp("x2", "a::overfires"), fp("y", "b::rare"),
		with(fp("bad x", "a::overfires"), func(f *fixture) { f.label = "bad" }))
	got := queued(ctx, t, st, "fp-trait", names...)
	slices.Sort(got)
	if want := []string{"x1", "x2"}; !slices.Equal(got, want) {
		t.Errorf("fp-trait %q, want %q: the files sharing the trait most good files fire", got, want)
	}
}

func TestTriageVersionDrift(t *testing.T) {
	st := open(t)
	ctx := t.Context()
	release := func(bytes, pkg string, created time.Duration, floor []int) *fixture {
		return with(base(bytes, "good"), func(f *fixture) { f.pkg, f.version, f.created, f.floor = pkg, bytes, created, floor })
	}
	names := world(ctx, t, st,
		release("a 1.0", "pkg:npm/a", 5*24*hour, nil),
		release("a 1.1", "pkg:npm/a", 24*hour, []int{0, 1}),
		release("b 1.1", "pkg:npm/b", 24*hour, []int{1, 0}),
		release("c 1.0", "pkg:npm/c", 5*24*hour, []int{0, 1}),
		release("c 1.1", "pkg:npm/c", 24*hour, []int{1, 0}),
	)
	if got, want := queued(ctx, t, st, "version-drift", names...), []string{"a 1.1"}; !slices.Equal(got, want) {
		t.Errorf("version-drift %q, want %q: only a release with an earlier clean one", got, want)
	}
}

func TestTriageOutliers(t *testing.T) {
	st := open(t)
	ctx := t.Context()
	model := func(bytes, label, fileType string, fires int, prob float64) *fixture {
		return with(base(bytes, label), func(f *fixture) {
			f.fileType, f.ml, f.mlFires, f.mlProb = fileType, "suspicious", fires, prob
		})
	}
	names := world(ctx, t, st,
		model("js 50", "good", "javascript", 50, 0.6),
		model("js 5", "good", "javascript", 5, 0.9),
		model("py 7", "unknown", "python", 7, 0.8),
		with(model("too new", "good", "python", 1, 0.99), func(f *fixture) { f.created = hour }),
		model("reported", "good", "python", 2, 0.9),
		model("missing", "good", "python", 3, 0.9),
		model("bad sure", "bad", "javascript", 1, 0.95),
		model("bad unsure", "bad", "javascript", 2000, 0.2),
	)
	report(ctx, t, st, "reported", "highest", 200*24*hour)
	report(ctx, t, st, "missing", "missing", hour)
	if got, want := queued(ctx, t, st, "highest", names...), []string{"js 5", "py 7", "js 50"}; !slices.Equal(got, want) {
		t.Errorf("highest %q, want %q: the tightest per file type first, round by round", got, want)
	}
	if got, want := queued(ctx, t, st, "lowest", names...), []string{"bad unsure", "bad sure"}; !slices.Equal(got, want) {
		t.Errorf("lowest %q, want %q", got, want)
	}
}

func TestTriageAcquitSecondReview(t *testing.T) {
	st := open(t)
	ctx := t.Context()
	acq := func(bytes string) *fixture {
		return with(base(bytes, "bad"), func(f *fixture) {
			f.floor, f.provenance, f.atomscan = []int{1, 1}, `{"registry":{}}`, "hostile"
		})
	}
	sec := func(bytes string) *fixture {
		return with(base(bytes, "good"), func(f *fixture) { f.scanned = 48 * hour })
	}
	names := world(ctx, t, st,
		acq("fetched, convicted"),
		with(acq("reported by a feed"), func(f *fixture) { f.provenance = `{"feed":{"source_id":"x"}}` }),
		with(acq("too new"), func(f *fixture) { f.created = 24 * hour }),
		acq("cited"),
		sec("trusted cite"), sec("two operators"), sec("one operator"),
		with(sec("just scanned"), func(f *fixture) { f.scanned = hour }),
		sec("answered"), sec("asked again"),
		with(base("under review", "unknown"), func(f *fixture) { f.path = "review/x" }),
		with(base("good under review", "good"), func(f *fixture) { f.path = "review/y" }),
		base("elsewhere", "unknown"),
	)
	now := time.Now()
	for _, s := range []struct {
		source, operator, bytes string
		ago                     time.Duration
	}{
		{"feedx", "opx", "cited", hour},
		{"bazaar", "bazaar", "trusted cite", hour},
		{"bazaar", "bazaar", "just scanned", hour},
		{"feedx", "opx", "two operators", hour},
		{"feedy", "opy", "two operators", hour},
		{"feedx", "opx", "one operator", hour},
		{"bazaar", "bazaar", "answered", 200 * hour},
		{"bazaar", "bazaar", "asked again", hour},
	} {
		if _, err := st.pool.Exec(ctx, `INSERT INTO sightings (source, subject, operator, first_seen) VALUES ($1, $2, $3, $4)`,
			s.source, hexOf(digestOf(s.bytes)), s.operator, now.Add(-s.ago)); err != nil {
			t.Fatal(err)
		}
		// As the ledger's writer does once its claims commit.
		if err := st.Cite(ctx, []Claim{{Subject: hexOf(digestOf(s.bytes))}}); err != nil {
			t.Fatal(err)
		}
	}
	// Both reports are past the shared 72-hour cooldown; a trusted feed has
	// cited "asked again" since its report, and not "answered".
	report(ctx, t, st, "answered", "second", 100*hour)
	report(ctx, t, st, "asked again", "second", 100*hour)
	if got, want := queued(ctx, t, st, "acquit", names...), []string{"fetched, convicted"}; !slices.Equal(got, want) {
		t.Errorf("acquit %q, want %q", got, want)
	}
	got := queued(ctx, t, st, "second", names...)
	slices.Sort(got)
	if want := []string{"asked again", "trusted cite", "two operators"}; !slices.Equal(got, want) {
		t.Errorf("second %q, want %q", got, want)
	}
	if got, want := queued(ctx, t, st, "review", names...), []string{"under review"}; !slices.Equal(got, want) {
		t.Errorf("review %q, want %q", got, want)
	}
}

func TestTriageSighted(t *testing.T) {
	st := open(t)
	ctx := t.Context()
	rel := func(bytes, label, pkg, version string) *fixture {
		return with(base(bytes, label), func(f *fixture) { f.pkg, f.version = pkg, version })
	}
	names := world(ctx, t, st,
		base("named by digest", "good"),
		base("bad, named", "bad"),
		rel("pkg 1.0", "unknown", "pkg:npm/p", "1.0"),
		rel("q 1.0", "good", "pkg:npm/q", "1.0"),
		rel("r 1.0", "good", "pkg:npm/r", "1.0"),
		base("answered", "good"),
		rel("a 1", "good", "pkg:npm/a", "1"), rel("a 2", "good", "pkg:npm/a", "2"),
		rel("a 3", "good", "pkg:npm/a", "3"), rel("a 4", "good", "pkg:npm/a", "4"),
		rel("b 1", "good", "pkg:npm/b", "1"),
	)
	now := time.Now()
	for i, s := range []struct{ subject, affected string }{
		{hexOf(digestOf("named by digest")), ""},
		{hexOf(digestOf("bad, named")), ""},
		{"pkg:npm/p", ""},
		{"pkg:npm/q", "2.0"},
		{hexOf(digestOf("answered")), ""},
	} {
		if _, err := st.pool.Exec(ctx, `INSERT INTO sightings (source, subject, affected, first_seen) VALUES ('feed', $1, $2, $3)`,
			s.subject, s.affected, now.Add(-time.Duration(48+i)*hour)); err != nil {
			t.Fatal(err)
		}
	}
	// Pinned claims of the last day, oldest first: a's four releases, then b's.
	for i, s := range []struct{ subject, affected string }{
		{"pkg:npm/a", "1"}, {"pkg:npm/a", "2"}, {"pkg:npm/a", "3"}, {"pkg:npm/a", "4"}, {"pkg:npm/b", "1"}, {"pkg:npm/r", "1.0"},
	} {
		if _, err := st.pool.Exec(ctx, `INSERT INTO sightings (source, subject, affected, first_seen) VALUES ('feed', $1, $2, $3)`,
			s.subject, s.affected, now.Add(-time.Duration(10-i)*hour)); err != nil {
			t.Fatal(err)
		}
	}
	report(ctx, t, st, "answered", "sighted", 200*24*hour)
	if got, want := queued(ctx, t, st, "sighted", names...), []string{"named by digest", "pkg 1.0"}; !slices.Equal(got, want) {
		t.Errorf("sighted %q, want %q", got, want)
	}
	if got, want := queued(ctx, t, st, "sighted-pinned", names...), []string{"a 1", "a 2", "a 3", "b 1", "r 1.0", "a 4"}; !slices.Equal(got, want) {
		t.Errorf("sighted-pinned %q, want %q: three of a package per round", got, want)
	}
}

func TestTriageGauntlet(t *testing.T) {
	st := open(t)
	ctx := t.Context()
	names := world(ctx, t, st, base("good, detected", "good"), base("bad, passed", "bad"), base("fixed since", "good"),
		base("withdrawn", "good"), base("reviewed", "good"))
	runs := []struct {
		id, at string
		rows   [][3]string // sha bytes, expected label, status
	}{
		{"run1", "2026-11-01T00:00:00Z", [][3]string{
			{"good, detected", "good", "detected"},
			{"fixed since", "good", "detected"},
			{"withdrawn", "good", "detected"},
			{"reviewed", "good", "detected"},
		}},
		{"run2", "2026-11-02T00:00:00Z", [][3]string{{"bad, passed", "bad", "benign"}, {"fixed since", "good", "benign"}}},
	}
	for _, r := range runs {
		if _, err := st.pool.Exec(ctx, `INSERT INTO gauntlet_runs VALUES ($1, 'gauntlet', $2, 'test', 'd', '{"rules":{"ascan":{"version":"r9"}}}')`,
			r.id, r.at); err != nil {
			t.Fatal(err)
		}
		for _, row := range r.rows {
			sha := hexOf(digestOf(row[0]))
			if _, err := st.pool.Exec(ctx, `INSERT INTO gauntlet_samples VALUES ($1, $2, $3, true, '{}');
				`, r.id, sha, row[1]); err != nil {
				t.Fatal(err)
			}
			if _, err := st.pool.Exec(ctx, `INSERT INTO gauntlet_results VALUES ($1, $2, 'ascan', $3, $4, '{}')`,
				r.id, sha, row[2], r.id+"/"+sha); err != nil {
				t.Fatal(err)
			}
		}
	}
	if _, err := st.pool.Exec(ctx, `INSERT INTO gauntlet_withdrawals VALUES ('run1', $1)`, hexOf(digestOf("withdrawn"))); err != nil {
		t.Fatal(err)
	}
	if _, err := st.pool.Exec(ctx, `INSERT INTO reports (sample_id, report_type, content, evidence_key)
		SELECT id, 'gauntlet', 'x', 'run1/' || encode(sha256, 'hex') FROM samples WHERE sha256 = $1`, digestOf("reviewed")); err != nil {
		t.Fatal(err)
	}
	if got, want := queued(ctx, t, st, "gauntlet", names...), []string{"good, detected", "bad, passed"}; !slices.Equal(got, want) {
		t.Errorf("gauntlet %q, want %q", got, want)
	}
	got, err := st.Triage(ctx, "gauntlet", 1, nil)
	if err != nil || len(got) != 1 || got[0].Gauntlet == nil || got[0].Gauntlet.Key != "run1/"+hexOf(digestOf("good, detected")) ||
		got[0].Gauntlet.Expected != "good" || string(got[0].Gauntlet.Metadata) == "" {
		t.Errorf("first gauntlet candidate %+v, %v: want the run's evidence with it", got, err)
	}
}

func TestTriageCandidatesAndDepth(t *testing.T) {
	st := open(t)
	ctx := t.Context()
	f := with(base("miss", "bad"), func(f *fixture) {
		f.pkg, f.version, f.fileType, f.top = "pkg:npm/m", "1.0", "npm", `[{"id":"a::x","crit":4}]`
	})
	world(ctx, t, st, f)
	if _, err := st.pool.Exec(ctx, `UPDATE locations SET feed = 'bazaar'`); err != nil {
		t.Fatal(err)
	}
	got, err := st.Triage(ctx, "bad", 10, nil)
	if err != nil || len(got) != 1 {
		t.Fatalf("%+v, %v", got, err)
	}
	c := got[0]
	if c.Path != "pool/miss" || c.Feed != "bazaar" || c.Label != "bad" || c.Name != "pkg:npm/m" || c.Version != "1.0" ||
		c.FileType != "npm" || c.ScannedAt.IsZero() || len(c.Top) != 1 || c.Top[0].ID != "a::x" {
		t.Errorf("candidate %+v", c)
	}
	if got, err := st.Triage(ctx, "bad", 10, [][]byte{digestOf("miss")}); err != nil || len(got) != 0 {
		t.Errorf("%+v, %v: want the excluded file left out", got, err)
	}
	if depth, capped, err := st.TriageDepth(ctx, "bad"); err != nil || depth != 1 || capped {
		t.Errorf("depth %d (capped %v), %v; want 1", depth, capped, err)
	}
	if _, err := st.Triage(ctx, "no-such-queue", 1, nil); err == nil {
		t.Error("an unknown queue was accepted")
	}
	// The legacy registry's 21 queues, less bad-shared and stranded (PLAN.md).
	if n := len(TriageQueueNames()); n != 19 {
		t.Errorf("%d queues, want 19", n)
	}
}

// A citation is marked when either the claim or the file arrives, is kept
// when the claim goes, and is put right by Recite; a scan's flag follows its
// verdicts and its label.
func TestCitedAndFlagged(t *testing.T) {
	st := open(t)
	ctx := t.Context()
	cited := func(bytes string) bool {
		t.Helper()
		var c bool
		if err := st.pool.QueryRow(ctx, `SELECT cited FROM samples WHERE sha256 = $1`, digestOf(bytes)).Scan(&c); err != nil {
			t.Fatal(err)
		}
		return c
	}
	ingest(ctx, t, st, QueueNew, Arrival{SHA256: digestOf("lib 1.0"), Size: 100, Path: "pool/lib", Name: "pkg:npm/lib", Version: "1.0"})
	sight(ctx, t, st, "feed-a", "pkg:npm/lib", "")
	sight(ctx, t, st, "feed-b", hexOf(digestOf("lib 1.0")), "")
	if !cited("lib 1.0") {
		t.Fatal("a sighted release is not cited")
	}
	if _, err := st.pool.Exec(ctx, `DELETE FROM sightings WHERE source = 'feed-a'`); err != nil {
		t.Fatal(err)
	}
	if _, err := st.pool.Exec(ctx, `DELETE FROM sightings WHERE source = 'feed-b'`); err != nil {
		t.Fatal(err)
	}
	if !cited("lib 1.0") {
		t.Error("a withdrawn claim uncited a file: the mark is only set")
	}
	if marked, cleared, err := st.Recite(ctx); err != nil || marked != 0 || cleared != 1 {
		t.Errorf("recite: marked %d, cleared %d, %v; want the file nothing names cleared", marked, cleared, err)
	}
	if cited("lib 1.0") {
		t.Error("a file nothing names is still cited after Recite")
	}

	sight(ctx, t, st, "feed-c", hexOf(digestOf("late")), "")
	ingest(ctx, t, st, QueueNew, Arrival{SHA256: digestOf("late"), Size: 100, Path: "pool/late"})
	if !cited("late") {
		t.Error("a file that arrives already named is not cited")
	}

	flagged := func(bytes string) bool {
		t.Helper()
		var f bool
		if err := st.pool.QueryRow(ctx, `SELECT sc.flagged FROM scans sc JOIN samples s ON s.id = sc.sample_id WHERE s.sha256 = $1`,
			digestOf(bytes)).Scan(&f); err != nil {
			t.Fatal(err)
		}
		return f
	}
	r := archive()
	r.write(ctx, t, st)
	if !flagged("package bytes") {
		t.Error("a hostile scan is not flagged")
	}
	judge(ctx, t, st, "clean", "benign", -1, nil, nil)
	if flagged("clean") {
		t.Error("a benign scan is flagged")
	}
	ingest(ctx, t, st, QueueNew, Arrival{SHA256: digestOf("clean"), Size: 100, Path: "bad/clean", Label: "bad", LabelSource: "pool"})
	if !flagged("clean") {
		t.Error("a file labelled bad after its scan is not flagged for triage")
	}
}

func TestFileReport(t *testing.T) {
	st := open(t)
	ctx := t.Context()
	world(ctx, t, st, with(base("miss", "bad"), func(f *fixture) { f.floor = []int{0, 1} }))
	if err := st.FileReport(ctx, TriageReport{SHA256: digestOf("miss"), Type: "bad", Content: "judgement=wrote traits"}); err != nil {
		t.Fatal(err)
	}
	if got, err := st.Triage(ctx, "bad", 10, nil); err != nil || len(got) != 0 {
		t.Errorf("%+v, %v: a reported file is parked", got, err)
	}
	if err := st.FileReport(ctx, TriageReport{SHA256: digestOf("never seen"), Type: "bad"}); !errors.Is(err, ErrNotFound) {
		t.Errorf("report on an unknown file: %v, want ErrNotFound", err)
	}
	gauntlet := TriageReport{SHA256: digestOf("miss"), Type: "gauntlet", EvidenceKey: "run1/x"}
	if err := st.FileReport(ctx, gauntlet); !errors.Is(err, ErrGauntletEvidence) {
		t.Errorf("review of evidence no run holds: %v, want ErrGauntletEvidence", err)
	}
	sha := hexOf(digestOf("miss"))
	for _, q := range []string{
		`INSERT INTO gauntlet_runs VALUES ('run1', 'g', '2026-11-01T00:00:00Z', 's', 'd', '{}')`,
		`INSERT INTO gauntlet_samples VALUES ('run1', '` + sha + `', 'bad', true, '{}')`,
		`INSERT INTO gauntlet_results VALUES ('run1', '` + sha + `', 'ascan', 'benign', 'run1/x', '{}')`,
	} {
		if _, err := st.pool.Exec(ctx, q); err != nil {
			t.Fatal(err)
		}
	}
	for range 2 {
		if err := st.FileReport(ctx, gauntlet); err != nil {
			t.Fatal(err)
		}
	}
	var n int
	if err := st.pool.QueryRow(ctx, `SELECT count(*) FROM reports WHERE report_type = 'gauntlet'`).Scan(&n); err != nil || n != 1 {
		t.Errorf("%d gauntlet reviews, %v; want the repeat to record nothing", n, err)
	}
}
