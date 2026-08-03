package hopper

import (
	"context"
	"fmt"
	"testing"
	"time"
)

// setLitmus stamps a sample's litmus_result so the generated columns derive the
// given class and score: litmus_class comes from $.class (via litmusClassSQLite)
// and litmus_score from $.prob (a GENERATED column — it cannot be written
// directly).
func setLitmus(t *testing.T, ctx context.Context, db *DB, sha string, class int, score float64) {
	t.Helper()
	body := fmt.Sprintf(`{"class":%d,"prob":%g}`, class, score)
	if err := db.UpdateLitmusResult(ctx, sha, []byte(body)); err != nil {
		t.Fatalf("UpdateLitmusResult(%s): %v", sha, err)
	}
}

func shaSet(samples []*Sample) map[string]bool {
	m := make(map[string]bool, len(samples))
	for _, s := range samples {
		m[s.SHA256] = true
	}
	return m
}

// TestTriageHighestCollapsesToParent covers the parent-collapse contract: hot
// good members are returned as their archive (one row per root, ranked by the
// hottest member), top-level hot good files as themselves, bad-parent members
// excluded, unknown-parent members included.
func TestTriageHighestCollapsesToParent(t *testing.T) {
	ctx := context.Background()
	db := openTestDB(t)

	sha := func(c byte) string {
		s := make([]byte, 64)
		for i := range s {
			s[i] = c
		}
		return string(s)
	}
	pGood, pUnk, pBad := sha('a'), sha('b'), sha('c')
	m1, m2, mUnk, mBad := sha('1'), sha('2'), sha('3'), sha('4')
	top := sha('7')

	// Parents: containers, not themselves scored. Labels drive the join filter.
	mustInsert(t, ctx, db, &Sample{SHA256: pGood, Label: "good", Path: "good/pkg.tgz"})
	mustInsert(t, ctx, db, &Sample{SHA256: pUnk, Label: "unknown", Path: "unknown/u.tgz"})
	mustInsert(t, ctx, db, &Sample{SHA256: pBad, Label: "bad", Path: "bad/b.tgz"})

	// Hot good members under each parent, plus a top-level hot good file.
	for _, m := range []struct {
		sha, parent, path string
		score             float64
	}{
		{m1, pGood, "good/pkg.tgz!!a.dll", 0.99},
		{m2, pGood, "good/pkg.tgz!!b.dll", 0.90}, // sibling: must not appear separately
		{mUnk, pUnk, "unknown/u.tgz!!x.dll", 1.0},
		{mBad, pBad, "bad/b.tgz!!y.dll", 0.999}, // bad parent: excluded
		{top, "", "good/t.exe", 0.97},
	} {
		mustInsert(t, ctx, db, &Sample{SHA256: m.sha, Label: "good", Parent: m.parent, Path: m.path})
		mustAnalyze(t, ctx, db, m.sha, 5)
		setLitmus(t, ctx, db, m.sha, 2, m.score)
	}

	before := time.Now().Add(time.Hour)
	missing := time.Now().Add(-MissingRetry)
	got, err := db.TriageHighest(ctx, 20, before, missing, TriageFilter{})
	if err != nil {
		t.Fatalf("TriageHighest: %v", err)
	}
	set := shaSet(got)

	// pUnk (best 1.0), pGood (best 0.99), top (0.97) — collapsed, deduped.
	for _, want := range []string{pUnk, pGood, top} {
		if !set[want] {
			t.Errorf("TriageHighest missing expected root %q", want[:6])
		}
	}
	// Members and the bad parent must never surface.
	for _, bad := range []string{m1, m2, mUnk, mBad, pBad} {
		if set[bad] {
			t.Errorf("TriageHighest returned %q; expected it collapsed/excluded", bad[:6])
		}
	}
	if len(got) != 3 {
		t.Fatalf("TriageHighest returned %d rows, want 3 (%v)", len(got), keysOf(set))
	}
	// Ranked by hottest member: pUnk, pGood, top.
	if got[0].SHA256 != pUnk || got[1].SHA256 != pGood || got[2].SHA256 != top {
		t.Errorf("order = [%s %s %s], want [pUnk pGood top]",
			got[0].SHA256[:6], got[1].SHA256[:6], got[2].SHA256[:6])
	}

	// A highest report on the root drains the whole archive.
	if err := db.InsertReport(ctx, &Report{SHA256: pGood, Type: "highest", Content: "done"}); err != nil {
		t.Fatalf("InsertReport highest: %v", err)
	}
	got2, _ := db.TriageHighest(ctx, 20, before, missing, TriageFilter{})
	if shaSet(got2)[pGood] {
		t.Errorf("drained root pGood still returned")
	}

	// A fresh missing marker on a root suppresses it; an expired one does not.
	if err := db.InsertReport(ctx, &Report{SHA256: pUnk, Type: ReportTypeMissing, Content: "gone"}); err != nil {
		t.Fatalf("InsertReport missing: %v", err)
	}
	got3, _ := db.TriageHighest(ctx, 20, before, missing, TriageFilter{})
	if shaSet(got3)[pUnk] {
		t.Errorf("root pUnk with fresh missing marker still returned")
	}
	// missingBefore in the future => even a just-written marker counts as expired.
	got4, _ := db.TriageHighest(ctx, 20, before, time.Now().Add(time.Hour), TriageFilter{})
	if !shaSet(got4)[pUnk] {
		t.Errorf("root pUnk with expired missing marker not returned")
	}
}

// TestTriageLowestPerMember covers the mirror: bad members scored clean are
// returned individually (not collapsed), skip-marked members are excluded, and
// the drain is per member.
func TestTriageLowestPerMember(t *testing.T) {
	ctx := context.Background()
	db := openTestDB(t)

	sha := func(c byte) string {
		s := make([]byte, 64)
		for i := range s {
			s[i] = c
		}
		return string(s)
	}
	parent := sha('a')
	lm1, lm2, lmSkip := sha('1'), sha('2'), sha('3')

	mustInsert(t, ctx, db, &Sample{SHA256: parent, Label: "bad", Path: "bad/mal.tgz"})
	for _, m := range []struct {
		sha, path string
		score     float64
	}{
		{lm1, "bad/mal.tgz!!readme.md", 0.01},
		{lm2, "bad/mal.tgz!!logo.png", 0.02},
		{lmSkip, "bad/mal.tgz!!inert.txt", 0.0},
	} {
		mustInsert(t, ctx, db, &Sample{SHA256: m.sha, Label: "bad", Parent: parent, Path: m.path})
		mustAnalyze(t, ctx, db, m.sha, 0)
		setLitmus(t, ctx, db, m.sha, 0, m.score)
	}
	// The skip-benign-archive-item member is out of training, so out of queue.
	if err := db.SetSkip(ctx, lmSkip, "skip-benign-archive-item"); err != nil {
		t.Fatalf("SetSkip: %v", err)
	}

	before := time.Now().Add(time.Hour)
	missing := time.Now().Add(-MissingRetry)
	got, err := db.TriageLowest(ctx, 20, before, missing, TriageFilter{})
	if err != nil {
		t.Fatalf("TriageLowest: %v", err)
	}
	set := shaSet(got)
	// Per-member: lm1 and lm2 both returned as themselves, ordered by score asc.
	if len(got) != 2 || got[0].SHA256 != lm1 || got[1].SHA256 != lm2 {
		t.Fatalf("TriageLowest = %v, want [lm1 lm2] by ascending score", keysOf(set))
	}
	if set[lmSkip] {
		t.Errorf("skip-marked member returned")
	}
	if set[parent] {
		t.Errorf("lowest returned the parent archive; it should be per-member")
	}

	// Draining one member leaves its sibling: the drain is per member, not root.
	if err := db.InsertReport(ctx, &Report{SHA256: lm1, Type: "lowest", Content: "done"}); err != nil {
		t.Fatalf("InsertReport lowest: %v", err)
	}
	got2, _ := db.TriageLowest(ctx, 20, before, missing, TriageFilter{})
	set2 := shaSet(got2)
	if set2[lm1] {
		t.Errorf("drained member lm1 still returned")
	}
	if !set2[lm2] {
		t.Errorf("sibling lm2 was drained by a report on lm1 — drain is not per-member")
	}
}

func keysOf(m map[string]bool) []string {
	out := make([]string, 0, len(m))
	for k := range m {
		out = append(out, k[:6])
	}
	return out
}

// TestTriageStaleOrdering pins the TriageStale contract on the selectors that
// support it: rank least-recently-analyzed first, honour MinAnalyzedAt as a
// floor, and let ExcludeReportType park a row until it is re-analyzed. The
// default (TriageNewest) must keep ranking by created_at so existing callers
// are untouched.
func TestTriageStaleOrdering(t *testing.T) {
	ctx := context.Background()
	db := openTestDB(t)

	now := time.Now().UTC().Truncate(time.Second)
	setTimes := func(sha string, created, analyzed time.Time) {
		t.Helper()
		if _, err := db.lite.ExecContext(ctx,
			`UPDATE samples SET created_at = ?, analyzed_at = ? WHERE sha256 = ?`,
			created.Format(time.RFC3339Nano), analyzed.Format(time.RFC3339Nano), sha); err != nil {
			t.Fatalf("set times: %v", err)
		}
	}

	// created order is deliberately the reverse of analyzed order, so a test
	// that accidentally kept created_at ordering cannot pass.
	type row struct {
		sha               string
		created, analyzed time.Time
	}
	rows := []row{
		{sha: staleTestSHA(1), created: now.Add(-3 * time.Hour), analyzed: now.Add(-90 * 24 * time.Hour)},
		{sha: staleTestSHA(2), created: now.Add(-2 * time.Hour), analyzed: now.Add(-30 * 24 * time.Hour)},
		{sha: staleTestSHA(3), created: now.Add(-1 * time.Hour), analyzed: now.Add(-1 * 24 * time.Hour)},
	}
	for _, r := range rows {
		mustInsert(t, ctx, db, &Sample{
			SHA256: r.sha, Source: "test", Label: "bad", LabelSource: "test",
			Path: "bad/" + r.sha, FileType: "elf",
			CleaveResult:    []byte(`{"files":[]}`),
			MaxCrit:         0,
			SuspiciousCount: 0, // (max_crit<5 OR suspicious_count<2) => in queue
		})
		setTimes(r.sha, r.created, r.analyzed)
	}

	staleOrder := func(f TriageFilter) []string {
		t.Helper()
		got, err := db.TriageBad(ctx, 10, f)
		if err != nil {
			t.Fatalf("TriageBad(%+v): %v", f, err)
		}
		return shaList(got)
	}

	oldest, mid, newest := rows[0].sha[:8], rows[1].sha[:8], rows[2].sha[:8]

	if got, want := staleOrder(TriageFilter{Order: TriageStale}), []string{oldest, mid, newest}; !slicesEqual(got, want) {
		t.Errorf("stale order = %v, want %v (oldest analysis first)", got, want)
	}
	// Default ordering is unchanged — newest created first, the exact reverse.
	if got, want := staleOrder(TriageFilter{}), []string{newest, mid, oldest}; !slicesEqual(got, want) {
		t.Errorf("newest order = %v, want %v (newest created first)", got, want)
	}
	// MinAnalyzedAt drops the rows whose verdict predates the floor.
	if got, want := staleOrder(TriageFilter{Order: TriageStale, MinAnalyzedAt: now.Add(-7 * 24 * time.Hour)}), []string{newest}; !slicesEqual(got, want) {
		t.Errorf("min-analyzed = %v, want %v", got, want)
	}

	// A report filed after the sample's last analysis parks it...
	if err := db.InsertReport(ctx, &Report{SHA256: rows[0].sha, Type: "bad-stale", CreatedAt: now}); err != nil {
		t.Fatalf("insert report: %v", err)
	}
	if got, want := staleOrder(TriageFilter{Order: TriageStale, ExcludeReportType: "bad-stale"}), []string{mid, newest}; !slicesEqual(got, want) {
		t.Errorf("exclude-report = %v, want %v", got, want)
	}

	// ...until a re-analysis supersedes it, which makes the row eligible again
	// and sorts it last, since it now holds the freshest verdict.
	setTimes(rows[0].sha, rows[0].created, now.Add(time.Minute))
	if got, want := staleOrder(TriageFilter{Order: TriageStale, ExcludeReportType: "bad-stale"}), []string{mid, newest, oldest}; !slicesEqual(got, want) {
		t.Errorf("post-rescan = %v, want %v (re-analysis clears the report)", got, want)
	}
}

// staleTestSHA builds a valid 64-char hex sha256 that differs in its FIRST
// bytes, so shaList's 8-char prefix distinguishes rows. A "%064x" of a small
// int puts every distinguishing digit at the tail and renders them all as
// "00000000", which silently turns every ordering assertion into a tautology.
func staleTestSHA(n int) string { return fmt.Sprintf("%02x%062x", n, 0) }

func shaList(ss []*Sample) []string {
	out := make([]string, len(ss))
	for i, s := range ss {
		out[i] = s.SHA256[:8]
	}
	return out
}

func slicesEqual(a, b []string) bool {
	if len(a) != len(b) {
		return false
	}
	for i := range a {
		if a[i] != b[i] {
			return false
		}
	}
	return true
}

// TestTriageSelectorsExcludeSkipped pins the skip filter on the four
// label-partitioned selectors. A skipped sample cannot be worked -- 'missing'
// and 'corrupt' have no bytes, 'unsupported' is a type cleave cannot parse --
// so selecting one spends a batch slot to reach a dead end. Both orderings are
// covered, since they share the predicate.
//
// second and acquit are deliberately NOT included: acquit carries its own
// skip != 'conflict' rule, and neither was measured in the audit that motivated
// this filter.
func TestTriageSelectorsExcludeSkipped(t *testing.T) {
	ctx := context.Background()
	db := openTestDB(t)

	mk := func(n int, label, skip string, crit, susp int) string {
		t.Helper()
		sha := staleTestSHA(n)
		mustInsert(t, ctx, db, &Sample{
			SHA256: sha, Source: "test", Label: label, LabelSource: "test",
			Path: label + "/" + sha, FileType: "elf",
			CleaveResult: []byte(`{"files":[]}`),
			MaxCrit:      crit, SuspiciousCount: susp,
		})
		if skip != "" {
			if err := db.SetSkip(ctx, sha, skip); err != nil {
				t.Fatalf("SetSkip(%s): %v", sha, err)
			}
		}
		return sha
	}

	// One workable and one skipped row in each of the three detection-gap pools.
	badOK, badSkip := mk(1, "bad", "", 0, 0), mk(2, "bad", "missing", 0, 0)
	goodOK, goodSkip := mk(3, "good", "", 5, 2), mk(4, "good", "unsupported", 5, 2)
	newOK, newSkip := mk(5, "unknown", "", 0, 1), mk(6, "unknown", "corrupt", 0, 1)

	for _, tc := range []struct {
		name       string
		sel        func(TriageFilter) ([]*Sample, error)
		want, deny string
	}{
		{"bad", func(f TriageFilter) ([]*Sample, error) { return db.TriageBad(ctx, 10, f) }, badOK, badSkip},
		{"good", func(f TriageFilter) ([]*Sample, error) { return db.TriageGood(ctx, 10, f) }, goodOK, goodSkip},
		{"new", func(f TriageFilter) ([]*Sample, error) { return db.TriageNew(ctx, 10, f) }, newOK, newSkip},
	} {
		for _, order := range []TriageOrder{TriageNewest, TriageStale} {
			got, err := tc.sel(TriageFilter{Order: order})
			if err != nil {
				t.Fatalf("%s (order %v): %v", tc.name, order, err)
			}
			set := shaSet(got)
			if !set[tc.want] {
				t.Errorf("%s (order %v): workable sample missing from queue", tc.name, order)
			}
			if set[tc.deny] {
				t.Errorf("%s (order %v): skipped sample was selected; skip filter not applied",
					tc.name, order)
			}
		}
	}
}
