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
