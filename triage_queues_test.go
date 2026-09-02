package hopper

import (
	"context"
	"fmt"
	"testing"
	"time"
)

// setLitmus writes a litmus envelope. lvl is the level the sample fires at on
// azoth's grid, or -1 for one that fires nowhere; class is the derived
// criticality, which real envelopes carry redundantly.
//
// The level is not optional decoration: it is what litmus actually emits, what
// the derive trigger fills samples.lvl from, and what CriticalLevel /
// SuspiciousCeiling bucket into class. A fixture carrying only class describes
// an envelope litmus does not produce, and the score-ranked queues select on the
// level -- so callers must keep the two consistent: lvl <= CriticalLevel is
// class 2, lvl <= SuspiciousCeiling is class 1, and anything else is class 0.
func setLitmus(t *testing.T, ctx context.Context, db *DB, sha string, class, lvl int, score float64) {
	t.Helper()
	body := fmt.Sprintf(`{"class":%d,"lvl":%d,"prob":%g}`, class, lvl, score)
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

func TestTriageUnknownPoolsAreDisjoint(t *testing.T) {
	ctx := context.Background()
	db := openTestDB(t)

	sha := func(c byte) string {
		return fmt.Sprintf("%064x", c)
	}
	add := func(c byte, path string, crit int, skip string) string {
		t.Helper()
		s := sha(c)
		mustInsert(t, ctx, db, &Sample{SHA256: s, Label: "unknown", Path: path})
		traits := ""
		if crit > 0 {
			traits = fmt.Sprintf(`{"l":%d}`, crit)
		}
		mustAnalyzeWithTraits(t, ctx, db, s, 0, traits)
		if skip != "" {
			if err := db.SetSkip(ctx, s, skip); err != nil {
				t.Fatalf("SetSkip(%s): %v", s, err)
			}
		}
		return s
	}

	incoming := add(1, "incoming/forager/a.tgz", 4, "")
	pending := add(2, "pending/forager/b.tgz", 4, "")
	legacy := add(3, "unknown/forager/c.tgz", 4, "")
	reviewClean := add(4, "review/forager/d.tgz", 0, "")
	reviewFlagged := add(5, "review/forager/e.tgz", 4, "")
	reviewSkipped := add(6, "review/forager/f.tgz", 4, "unsupported")

	newRows, err := db.TriageNew(ctx, 20, TriageFilter{})
	if err != nil {
		t.Fatalf("TriageNew: %v", err)
	}
	newSet := shaSet(newRows)
	for _, want := range []string{incoming, pending, legacy} {
		if !newSet[want] {
			t.Errorf("TriageNew missing %s", want)
		}
	}
	for _, deny := range []string{reviewClean, reviewFlagged, reviewSkipped} {
		if newSet[deny] {
			t.Errorf("TriageNew included review sample %s", deny)
		}
	}

	reviewRows, err := db.TriageReview(ctx, 20, TriageFilter{})
	if err != nil {
		t.Fatalf("TriageReview: %v", err)
	}
	reviewSet := shaSet(reviewRows)
	for _, want := range []string{reviewClean, reviewFlagged} {
		if !reviewSet[want] {
			t.Errorf("TriageReview missing %s", want)
		}
	}
	for _, deny := range []string{incoming, pending, legacy, reviewSkipped} {
		if reviewSet[deny] {
			t.Errorf("TriageReview included ineligible sample %s", deny)
		}
	}
}

// TestTriageSightedUsesLedgerScope pins the queue's contract with the sightings
// ledger: exact releases match exactly, an unscoped package claim matches every
// release, suspicious claims are reviewed, vulnerability-only records are not,
// bad labels are already settled, and the old sighted label is not evidence.
// The newest applicable sighting leads regardless of sample insertion order.
func TestTriageSightedUsesLedgerScope(t *testing.T) {
	ctx := context.Background()
	db := openTestDB(t)

	add := func(n int, label, purl, version string) string {
		t.Helper()
		sha := fmt.Sprintf("%064x", 100+n)
		mustInsert(t, ctx, db, &Sample{
			SHA256: sha, Label: label, LabelSource: "test", Path: "test/" + sha,
			PURLBase: purl, Version: version,
		})
		mustAnalyzeWithTraits(t, ctx, db, sha, 0, "")
		return sha
	}

	exact := add(1, "good", "pkg:npm/exact", "1.2.3")
	wrongVersion := add(2, "good", "pkg:npm/exact", "2.0.0")
	broad := add(3, "unknown", "pkg:pypi/broad", "9.0")
	bad := add(4, "bad", "pkg:npm/settled", "1.0")
	vulnerable := add(5, "good", "pkg:npm/vulnerable", "1.0")
	suspicious := add(6, "good", "pkg:npm/suspicious", "3.0")
	labelOnly := add(7, "sighted", "pkg:npm/no-evidence", "1.0")
	digest := add(8, "unknown", "", "")

	if _, err := db.AddSightings(ctx, []Sighting{
		// Supplying the exact PURL directly must preserve 1.2.3 in Affected
		// before the subject is folded to its version-less ledger key.
		{Source: "exact", Subject: "pkg:npm/exact@1.2.3"},
		{Source: "broad", Subject: "pkg:pypi/broad"},
		{Source: "settled", Subject: "pkg:npm/settled", Affected: "1.0"},
		{Source: "advisory", Subject: "pkg:npm/vulnerable", Affected: "1.0", Claim: ClaimVulnerable},
		{Source: "scanner", Subject: "pkg:npm/suspicious", Affected: "3.0", Claim: ClaimSuspicious},
		{Source: "digest", Subject: digest},
	}); err != nil {
		t.Fatalf("AddSightings: %v", err)
	}

	// Make the evidence order unambiguous. SQLite stores these timestamps as
	// RFC3339 text, the same representation AddSightings uses.
	now := time.Now().UTC()
	for source, at := range map[string]time.Time{
		"exact": now, "scanner": now.Add(-time.Hour),
		"digest": now.Add(-2 * time.Hour), "broad": now.Add(-3 * time.Hour),
	} {
		if _, err := db.lite.ExecContext(ctx, `UPDATE sightings SET first_seen = ? WHERE source = ?`,
			at.Format(time.RFC3339Nano), source); err != nil {
			t.Fatalf("date %s: %v", source, err)
		}
	}

	got, err := db.TriageSighted(ctx, 20, TriageFilter{})
	if err != nil {
		t.Fatalf("TriageSighted: %v", err)
	}
	want := []string{exact, suspicious, digest, broad}
	if len(got) != len(want) {
		t.Fatalf("TriageSighted returned %d rows, want %d: %+v", len(got), len(want), got)
	}
	for i, sha := range want {
		if got[i].SHA256 != sha {
			t.Errorf("row %d = %s, want %s (newest applicable sighting first)", i, got[i].SHA256, sha)
		}
	}
	denied := map[string]string{
		wrongVersion: "wrong version", bad: "bad label", vulnerable: "vulnerability-only claim", labelOnly: "label without evidence",
	}
	for _, sample := range got {
		if why := denied[sample.SHA256]; why != "" {
			t.Errorf("TriageSighted included %s (%s)", sample.SHA256, why)
		}
	}

	stored, err := db.SightingsFor(ctx, []string{"pkg:npm/exact"})
	if err != nil || len(stored["pkg:npm/exact"]) != 1 || stored["pkg:npm/exact"][0].Affected != "1.2.3" {
		t.Fatalf("exact PURL scope was not preserved: rows=%+v err=%v", stored, err)
	}
	if err := db.InsertReport(ctx, &Report{SHA256: exact, Type: "sighted", Provider: "test"}); err != nil {
		t.Fatalf("InsertReport(sighted): %v", err)
	}
	after, err := db.TriageSighted(ctx, 20, TriageFilter{})
	if err != nil {
		t.Fatalf("TriageSighted after report: %v", err)
	}
	if shaSet(after)[exact] {
		t.Error("completed sighted report did not drain an upheld non-bad label")
	}
	depth, _, err := TriageQueues["sighted"].Count(ctx, db)
	if err != nil || depth != int64(len(after)) {
		t.Errorf("sighted depth = %d, %v; selection has %d", depth, err, len(after))
	}
}

func TestTriageQueuesReturnLightSamples(t *testing.T) {
	ctx := context.Background()
	db := openTestDB(t)
	sha := staleTestSHA(89)
	mustInsert(t, ctx, db, &Sample{SHA256: sha, Label: "unknown", Path: "review/" + sha})
	mustAnalyzeWithTraits(t, ctx, db, sha, 7, `{"l":4}`)
	setLitmus(t, ctx, db, sha, 2, 10, 0.95)
	if err := db.UpdateLLMResult(ctx, sha, []byte(`{"interpretation":"test"}`)); err != nil {
		t.Fatalf("UpdateLLMResult: %v", err)
	}

	got, err := db.TriageReview(ctx, 1, TriageFilter{})
	if err != nil {
		t.Fatalf("TriageReview: %v", err)
	}
	if len(got) != 1 {
		t.Fatalf("TriageReview returned %d samples, want 1", len(got))
	}
	s := got[0]
	if len(s.CleaveResult) != 0 || len(s.LitmusResult) != 0 || len(s.LLMResult) != 0 {
		t.Fatalf("triage result includes blobs: cleave=%d litmus=%d llm=%d",
			len(s.CleaveResult), len(s.LitmusResult), len(s.LLMResult))
	}
	if s.SHA256 != sha || s.Path != "review/"+sha || s.MaxCrit != 4 || s.LitmusScore != 0.95 {
		t.Fatalf("triage metadata incomplete: %+v", s)
	}
}

func TestTriageAttemptBudget(t *testing.T) {
	ctx := context.Background()
	db := openTestDB(t)
	sha := staleTestSHA(90)
	mustInsert(t, ctx, db, &Sample{SHA256: sha, Label: "bad", Path: "bad/x"})
	mustAnalyzeWithTraits(t, ctx, db, sha, 0, "")

	filter := TriageFilter{AttemptReportType: "cyclotron-attempt:bad", MaxAttempts: 2}
	selected := func() bool {
		t.Helper()
		got, err := db.TriageBad(ctx, 10, time.Time{}, filter)
		if err != nil {
			t.Fatalf("TriageBad: %v", err)
		}
		return shaSet(got)[sha]
	}
	if !selected() {
		t.Fatal("fresh sample missing from retry-budgeted queue")
	}
	for i := range 2 {
		if err := db.InsertReport(ctx, &Report{SHA256: sha, Type: "cyclotron-attempt:bad", Content: fmt.Sprintf("attempt=%d", i+1)}); err != nil {
			t.Fatalf("InsertReport: %v", err)
		}
		if got := selected(); got != (i == 0) {
			t.Fatalf("selected after %d attempts = %v, want %v", i+1, got, i == 0)
		}
	}
	// Another queue's attempts do not consume this queue's budget.
	if err := db.InsertReport(ctx, &Report{SHA256: sha, Type: "cyclotron-attempt:good"}); err != nil {
		t.Fatalf("InsertReport(other queue): %v", err)
	}
	if selected() {
		t.Fatal("other queue report changed an already-exhausted bad budget")
	}
}

func TestSampleClaimLease(t *testing.T) {
	ctx := context.Background()
	db := openTestDB(t)
	sha := staleTestSHA(95)
	mustInsert(t, ctx, db, &Sample{SHA256: sha, Label: "unknown", Path: "incoming/" + sha})

	claimed, err := db.TryClaimSample(ctx, sha, "worker-a", time.Hour)
	if err != nil || !claimed {
		t.Fatalf("first claim = %v, %v; want true, nil", claimed, err)
	}
	for _, owner := range []string{"worker-a", "worker-b"} {
		claimed, err = db.TryClaimSample(ctx, sha, owner, time.Hour)
		if err != nil || claimed {
			t.Fatalf("live claim by %q = %v, %v; want false, nil", owner, claimed, err)
		}
	}
	if err := db.ReleaseSampleClaim(ctx, sha, "worker-b"); err != nil {
		t.Fatalf("release by non-owner: %v", err)
	}
	claimed, err = db.TryClaimSample(ctx, sha, "worker-b", time.Hour)
	if err != nil || claimed {
		t.Fatalf("claim after non-owner release = %v, %v; want false, nil", claimed, err)
	}
	if err := db.ReleaseSampleClaim(ctx, sha, "worker-a"); err != nil {
		t.Fatalf("owner release: %v", err)
	}
	claimed, err = db.TryClaimSample(ctx, sha, "worker-b", time.Hour)
	if err != nil || !claimed {
		t.Fatalf("claim after owner release = %v, %v; want true, nil", claimed, err)
	}

	if _, err := db.lite.ExecContext(ctx, `UPDATE samples SET claimed_at = ? WHERE sha256 = ?`,
		time.Now().Add(-2*time.Hour).UTC().Format(time.RFC3339Nano), sha); err != nil {
		t.Fatalf("backdate claim: %v", err)
	}
	claimed, err = db.TryClaimSample(ctx, sha, "worker-c", time.Hour)
	if err != nil || !claimed {
		t.Fatalf("replace expired claim = %v, %v; want true, nil", claimed, err)
	}
}

func TestTriageInterestingOrder(t *testing.T) {
	ctx := context.Background()
	db := openTestDB(t)
	add := func(n, crit, suspicious int, score float64, corroborated bool) string {
		t.Helper()
		sha := staleTestSHA(n)
		mustInsert(t, ctx, db, &Sample{SHA256: sha, Label: "unknown", Path: "review/" + sha})
		traits := ""
		if crit > 0 {
			traits = fmt.Sprintf(`{"l":%d}`, crit)
		}
		mustAnalyzeWithTraits(t, ctx, db, sha, 0, traits)
		if suspicious > 1 {
			mustAnalyzeWithTraits(t, ctx, db, sha, 0, `{"l":4},{"l":4}`)
		}
		setLitmus(t, ctx, db, sha, 0, -1, score)
		if corroborated {
			if _, err := db.lite.ExecContext(ctx, `UPDATE samples SET corroborated = 1 WHERE sha256 = ?`, sha); err != nil {
				t.Fatalf("set corroborated: %v", err)
			}
		}
		return sha
	}

	corroborated := add(91, 0, 0, 0.1, true)
	hostile := add(92, 5, 1, 0.8, false)
	twoSuspicious := add(93, 4, 2, 0.9, false)
	weak := add(94, 0, 0, 0.99, false)
	got, err := db.TriageReview(ctx, 10, TriageFilter{Order: TriageInteresting})
	if err != nil {
		t.Fatalf("TriageReview: %v", err)
	}
	want := []string{corroborated[:8], hostile[:8], twoSuspicious[:8], weak[:8]}
	if list := shaList(got); !slicesEqual(list, want) {
		t.Fatalf("interesting order = %v, want %v", list, want)
	}
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
		{m1, pGood, "good/pkg.tgz!!a.dll", 0.9999},
		{m2, pGood, "good/pkg.tgz!!b.dll", 0.9995}, // sibling: must not appear separately
		{mUnk, pUnk, "unknown/u.tgz!!x.dll", 1.0},
		{mBad, pBad, "bad/b.tgz!!y.dll", 0.999}, // bad parent: excluded
		{top, "", "good/t.exe", 0.9997},
	} {
		mustInsert(t, ctx, db, &Sample{SHA256: m.sha, Label: "good", Parent: m.parent, Path: m.path})
		mustAnalyze(t, ctx, db, m.sha, 5)
		setLitmus(t, ctx, db, m.sha, 2, 10, m.score)
	}

	before := time.Now().Add(time.Hour)
	missing := time.Now().Add(-MissingRetry)
	got, err := db.TriageHighest(ctx, 20, triagePerRouteK, before, missing, time.Time{}, TriageFilter{})
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
	got2, err := db.TriageHighest(ctx, 20, triagePerRouteK, before, missing, time.Time{}, TriageFilter{})
	if err != nil {
		t.Fatalf("TriageHighest: %v", err)
	}
	if shaSet(got2)[pGood] {
		t.Errorf("drained root pGood still returned")
	}

	// A fresh missing marker on a root suppresses it; an expired one does not.
	if err := db.InsertReport(ctx, &Report{SHA256: pUnk, Type: ReportTypeMissing, Content: "gone"}); err != nil {
		t.Fatalf("InsertReport missing: %v", err)
	}
	got3, err := db.TriageHighest(ctx, 20, triagePerRouteK, before, missing, time.Time{}, TriageFilter{})
	if err != nil {
		t.Fatalf("TriageHighest: %v", err)
	}
	if shaSet(got3)[pUnk] {
		t.Errorf("root pUnk with fresh missing marker still returned")
	}
	// missingBefore in the future => even a just-written marker counts as expired.
	got4, err := db.TriageHighest(ctx, 20, triagePerRouteK, before, time.Now().Add(time.Hour), time.Time{}, TriageFilter{})
	if err != nil {
		t.Fatalf("TriageHighest: %v", err)
	}
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
		setLitmus(t, ctx, db, m.sha, 0, -1, m.score)
	}
	// The skip-benign-archive-item member is out of training, so out of queue.
	if err := db.SetSkip(ctx, lmSkip, "skip-benign-archive-item"); err != nil {
		t.Fatalf("SetSkip: %v", err)
	}

	before := time.Now().Add(time.Hour)
	missing := time.Now().Add(-MissingRetry)
	got, err := db.TriageLowest(ctx, 20, triagePerRouteK, before, missing, time.Time{}, TriageFilter{})
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
	got2, err := db.TriageLowest(ctx, 20, triagePerRouteK, before, missing, time.Time{}, TriageFilter{})
	if err != nil {
		t.Fatalf("TriageLowest: %v", err)
	}
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
			SuspiciousCount: 0, // max_crit<5 AND suspicious_count<2 => in queue
		})
		setTimes(r.sha, r.created, r.analyzed)
	}

	staleOrder := func(f TriageFilter) []string {
		t.Helper()
		got, err := db.TriageBad(ctx, 10, time.Time{}, f)
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

	// A report filed after the sample's last analysis parks it. Dated past
	// ReportCooldown so this exercises the re-analysis half of the re-entry rule;
	// a report younger than the cooldown parks regardless of rescans, which
	// TestReportCooldownRequiresRescanAndAge covers.
	reportAt := now.Add(-ReportCooldown - time.Hour)
	if err := db.InsertReport(ctx, &Report{SHA256: rows[0].sha, Type: "bad-stale", CreatedAt: reportAt}); err != nil {
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

	now := time.Now()
	mk := func(n int, label, skip string, crit, susp int) string {
		t.Helper()
		sha := staleTestSHA(n)
		mustInsert(t, ctx, db, &Sample{
			SHA256: sha, Source: "test", Label: label, LabelSource: "test",
			Path: label + "/" + sha, FileType: "elf",
			CleaveResult: []byte(`{"files":[]}`),
			MaxCrit:      crit, SuspiciousCount: susp,
		})
		// Stamped explicitly rather than through the Sample literal: InsertSample
		// does not persist AnalyzedAt, so the row would land with a NULL one.
		// A row carrying a cleave_result always carries the analyzed_at that
		// produced it in production -- UpdateCleaveResult writes both together --
		// and bad's freshness floor reads that column, so a NULL here is not a
		// state the queue can ever see.
		if _, err := db.lite.ExecContext(ctx,
			`UPDATE samples SET analyzed_at = ? WHERE sha256 = ?`, now, sha); err != nil {
			t.Fatalf("stamp analyzed_at(%s): %v", sha, err)
		}
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
		{"bad", func(f TriageFilter) ([]*Sample, error) { return db.TriageBad(ctx, 10, time.Time{}, f) }, badOK, badSkip},
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

// TestTriageHighestPerRouteReach covers the 2026-08-03 redesign: files that
// pin a small route's operating point must surface even when (a) they score
// below the hostile class band and (b) another route owns a deep tie band at
// the top of the global ordering — the two structural exclusions that kept
// threshold-pinning benigns invisible to the old class-gated global window.
// Ordering is rank-first across routes (every route's #1 before any #2).
func TestTriageHighestPerRouteReach(t *testing.T) {
	ctx := context.Background()
	db := openTestDB(t)

	analyzeAs := func(sha, ftype string, score int) {
		t.Helper()
		result := fmt.Appendf(nil, `{"fs":[{"sha":%q,"type":%q,"x":%d,"dp":0,"ts":[]}]}`, sha, ftype, score)
		if err := db.UpdateCleaveResult(ctx, sha, result, nil, ""); err != nil {
			t.Fatalf("UpdateCleaveResult(%s): %v", sha, err)
		}
	}
	sha := func(i int) string { return fmt.Sprintf("%064d", i) }

	// A "jar" tie band: more than triagePerRouteK good top-level files all at
	// score 1.0 — the shape that monopolized the old global score window.
	for i := range triagePerRouteK + 5 {
		s := sha(100 + i)
		mustInsert(t, ctx, db, &Sample{SHA256: s, Label: "good", Path: fmt.Sprintf("good/j%d.jar", i)})
		analyzeAs(s, "jar", 5)
		setLitmus(t, ctx, db, s, 2, 10, 1.0)
	}
	// The PE-shaped pinners: class 1 (below the hostile band) and scores below
	// the jar tie band — excluded by BOTH old mechanisms.
	// Scores well below the jar tie band, restored 2026-09-02. They had been
	// raised to 0.99995/0.9993 to clear HighestScoreFloor, which is exactly the
	// blindness that floor caused: a benign firing on a route calibrated below
	// 0.999 was unreachable at any rank. Membership is now the level, so a
	// sub-hostile pinner at 0.62 selects on its merits and this fixture can say
	// what it always meant to.
	pe1, pe2 := sha(1), sha(2)
	for _, p := range []struct {
		sha   string
		lvl   int
		score float64
	}{{pe1, 100, 0.62}, {pe2, 250, 0.58}} {
		mustInsert(t, ctx, db, &Sample{SHA256: p.sha, Label: "good", Path: "good/" + p.sha[:4] + ".exe"})
		analyzeAs(p.sha, "pe", 5)
		setLitmus(t, ctx, db, p.sha, 1, p.lvl, p.score)
	}

	before := time.Now().Add(time.Hour)
	missing := time.Now().Add(-MissingRetry)
	got, err := db.TriageHighest(ctx, 4, triagePerRouteK, before, missing, time.Time{}, TriageFilter{})
	if err != nil {
		t.Fatalf("TriageHighest: %v", err)
	}
	set := shaSet(got)
	if !set[pe1] {
		t.Errorf("pe route's #1 pinner (sub-hostile, sub-tie-band) not selected: %v", keysOf(set))
	}
	if !set[pe2] {
		t.Errorf("pe rank-2 displaced by deeper jar ranks: %v", keysOf(set))
	}
	// Rank-first: positions 0-1 are the two routes' #1 files (jar 1.0 by
	// score, then pe 0.997), positions 2-3 the rank-2 pair.
	if got[1].SHA256 != pe1 {
		t.Errorf("rank-first order violated: row 1 = %q, want pe #1", got[1].SHA256[:8])
	}
	if got[3].SHA256 != pe2 {
		t.Errorf("rank-first order violated: row 3 = %q, want pe #2", got[3].SHA256[:8])
	}
}

func TestTriageHighestAttemptBudgetUsesRoot(t *testing.T) {
	ctx := context.Background()
	db := openTestDB(t)
	root, member := staleTestSHA(201), staleTestSHA(202)
	mustInsert(t, ctx, db, &Sample{SHA256: root, Label: "good", Path: "good/archive.zip"})
	mustInsert(t, ctx, db, &Sample{
		SHA256: member, Label: "good", Parent: root, Path: "good/archive.zip!!payload.exe",
	})
	mustAnalyzeWithTraits(t, ctx, db, member, 90, `{"l":5}`)
	setLitmus(t, ctx, db, member, 2, 10, 0.9999) // fires in the hostile band

	filter := TriageFilter{AttemptReportType: "cyclotron-attempt:highest", MaxAttempts: 1}
	selectRoot := func() bool {
		t.Helper()
		got, err := db.TriageHighest(ctx, 10, triagePerRouteK, time.Now().Add(time.Hour), time.Now().Add(-MissingRetry), time.Time{}, filter)
		if err != nil {
			t.Fatalf("TriageHighest: %v", err)
		}
		return shaSet(got)[root]
	}
	if !selectRoot() {
		t.Fatal("archive root missing before attempt")
	}
	if err := db.InsertReport(ctx, &Report{SHA256: root, Type: "cyclotron-attempt:highest"}); err != nil {
		t.Fatalf("InsertReport(root attempt): %v", err)
	}
	if selectRoot() {
		t.Fatal("root remained eligible after exhausting highest attempt budget")
	}
}

// TestTriageStrandedPerMemberDrain covers the stranded queue (2026-08-03):
// good-labeled members with real findings inside bad-labeled archives are
// surfaced AS their parent archive (dedup), gated on score>0 + notable crit +
// never-individually-reviewed label_source, and drained PER MEMBER so the
// archive resurfaces until every qualifying member has a verdict.
func TestTriageStrandedPerMemberDrain(t *testing.T) {
	ctx := context.Background()
	db := openTestDB(t)

	sha := func(c byte) string {
		s := make([]byte, 64)
		for i := range s {
			s[i] = c
		}
		return string(s)
	}
	analyzeCrit := func(sa string, score int, crit int) {
		t.Helper()
		result := fmt.Appendf(nil,
			`{"fs":[{"sha":%q,"type":"pe","x":%d,"dp":0,"ts":[{"l":%d,"c":1.0}]}]}`,
			sa, score, crit)
		if err := db.UpdateCleaveResult(ctx, sa, result, nil, ""); err != nil {
			t.Fatalf("UpdateCleaveResult(%s): %v", sa, err)
		}
	}

	pBad, pGood := sha('a'), sha('b')
	m1, m2, mLow, mAcq, mUnderGood := sha('1'), sha('2'), sha('3'), sha('4'), sha('5')
	mustInsert(t, ctx, db, &Sample{SHA256: pBad, Label: "bad", Path: "bad/x.tgz"})
	mustInsert(t, ctx, db, &Sample{SHA256: pGood, Label: "good", Path: "good/y.tgz"})
	// Two qualifying stranded members under the bad parent.
	mustInsert(t, ctx, db, &Sample{SHA256: m1, Label: "good", Parent: pBad, Path: "bad/x.tgz!!a.exe"})
	analyzeCrit(m1, 90, 4)
	mustInsert(t, ctx, db, &Sample{SHA256: m2, Label: "good", Parent: pBad, Path: "bad/x.tgz!!b.exe"})
	analyzeCrit(m2, 40, 4)
	// Excluded: below the member gate. That gate is strandedMemberCrit, raised
	// from notable to suspicious on 2026-09-01 -- notable-only members were
	// 99.6% of the live population -- so crit 3 sits just under it now and crit
	// 1 further under.
	mustInsert(t, ctx, db, &Sample{SHA256: mLow, Label: "good", Parent: pBad, Path: "bad/x.tgz!!c.txt"})
	analyzeCrit(mLow, 5, 3)
	// Excluded: individually acquitted by the lowest queue.
	mustInsert(t, ctx, db, &Sample{SHA256: mAcq, Label: "good", Parent: pBad, Path: "bad/x.tgz!!d.dll", LabelSource: "cyclotron:lowest"})
	analyzeCrit(mAcq, 80, 4)
	// Excluded: parent is not bad.
	mustInsert(t, ctx, db, &Sample{SHA256: mUnderGood, Label: "good", Parent: pGood, Path: "good/y.tgz!!e.exe"})
	analyzeCrit(mUnderGood, 95, 5)

	before := time.Now().Add(time.Hour)
	missing := time.Now().Add(-MissingRetry)
	got, err := db.TriageStranded(ctx, 10, before, missing, TriageFilter{})
	if err != nil {
		t.Fatalf("TriageStranded: %v", err)
	}
	if len(got) != 1 || got[0].SHA256 != pBad {
		t.Fatalf("want exactly [pBad], got %v", keysOf(shaSet(got)))
	}

	members, err := db.StrandedMembers(ctx, pBad)
	if err != nil {
		t.Fatalf("StrandedMembers: %v", err)
	}
	if len(members) != 2 || members[0].SHA256 != m1 || members[1].SHA256 != m2 {
		t.Fatalf("StrandedMembers want [m1 m2] score-desc, got %d rows", len(members))
	}

	// Drain one member: archive must RESURFACE (m2 still unexamined).
	if err := db.InsertReport(ctx, &Report{SHA256: m1, Type: "stranded", Content: "benign"}); err != nil {
		t.Fatalf("InsertReport: %v", err)
	}
	got2, err := db.TriageStranded(ctx, 10, before, missing, TriageFilter{})
	if err != nil {
		t.Fatalf("TriageStranded: %v", err)
	}
	if len(got2) != 1 || got2[0].SHA256 != pBad {
		t.Fatalf("archive with an unexamined member must resurface, got %v", keysOf(shaSet(got2)))
	}
	// Drain the last member: archive leaves the queue.
	if err := db.InsertReport(ctx, &Report{SHA256: m2, Type: "stranded", Content: "malicious"}); err != nil {
		t.Fatalf("InsertReport: %v", err)
	}
	got3, err := db.TriageStranded(ctx, 10, before, missing, TriageFilter{})
	if err != nil {
		t.Fatalf("TriageStranded: %v", err)
	}
	if len(got3) != 0 {
		t.Fatalf("fully-examined archive must drain, got %v", keysOf(shaSet(got3)))
	}
}
