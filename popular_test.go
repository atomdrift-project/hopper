package hopper

import (
	"fmt"
	"strconv"
	"testing"
	"time"
)

func TestSetPopularPackagesUpsertsByIdentity(t *testing.T) {
	db := openTestDB(t)
	ctx := t.Context()

	if err := db.SetPopularPackages(ctx, []PopularPackage{
		{PURLBase: "pkg:npm/left-pad", Ecosystem: "npm", Rank: 7, Source: "poppy"},
		{PURLBase: "pkg:gem/rails", Ecosystem: "gem", Rank: 2, Source: "poppy"},
	}); err != nil {
		t.Fatalf("set: %v", err)
	}
	// A later pass moves left-pad up. One row per identity, not two.
	if err := db.SetPopularPackages(ctx, []PopularPackage{
		{PURLBase: "pkg:npm/left-pad", Ecosystem: "npm", Rank: 3, Source: "poppy"},
	}); err != nil {
		t.Fatalf("re-set: %v", err)
	}

	n, err := db.PopularPackageCount(ctx)
	if err != nil {
		t.Fatalf("count: %v", err)
	}
	if n != 2 {
		t.Errorf("count = %d, want 2 — the second publish should update, not insert", n)
	}
	var rank int
	if err := db.lite.QueryRowContext(ctx,
		`SELECT rank FROM popular_packages WHERE purl_base = ?`, "pkg:npm/left-pad").Scan(&rank); err != nil {
		t.Fatalf("read back: %v", err)
	}
	if rank != 3 {
		t.Errorf("rank = %d, want 3", rank)
	}
}

// A truncated ranking must not delete what it failed to mention: a half-read
// feed would otherwise wipe yesterday's good data for every package it missed.
func TestSetPopularPackagesDoesNotDeleteOmittedIdentities(t *testing.T) {
	db := openTestDB(t)
	ctx := t.Context()
	if err := db.SetPopularPackages(ctx, []PopularPackage{
		{PURLBase: "pkg:npm/a", Ecosystem: "npm", Rank: 1, Source: "poppy"},
		{PURLBase: "pkg:npm/b", Ecosystem: "npm", Rank: 2, Source: "poppy"},
	}); err != nil {
		t.Fatalf("set: %v", err)
	}
	if err := db.SetPopularPackages(ctx, []PopularPackage{
		{PURLBase: "pkg:npm/a", Ecosystem: "npm", Rank: 1, Source: "poppy"},
	}); err != nil {
		t.Fatalf("partial set: %v", err)
	}
	n, err := db.PopularPackageCount(ctx)
	if err != nil {
		t.Fatalf("count: %v", err)
	}
	if n != 2 {
		t.Errorf("count = %d, want 2 — an omitted identity must survive", n)
	}
}

func TestSetPopularPackagesEmptyIsNoOp(t *testing.T) {
	db := openTestDB(t)
	if err := db.SetPopularPackages(t.Context(), nil); err != nil {
		t.Errorf("empty publish: %v", err)
	}
}

// Batching is an implementation detail; crossing the boundary must not be.
func TestSetPopularPackagesSpansBatches(t *testing.T) {
	db := openTestDB(t)
	pkgs := make([]PopularPackage, popularUpsertBatch+50)
	for i := range pkgs {
		pkgs[i] = PopularPackage{
			PURLBase:  "pkg:npm/p" + strconv.Itoa(i),
			Ecosystem: "npm",
			Rank:      i + 1,
			Source:    "poppy",
		}
	}
	if err := db.SetPopularPackages(t.Context(), pkgs); err != nil {
		t.Fatalf("set: %v", err)
	}
	n, err := db.PopularPackageCount(t.Context())
	if err != nil {
		t.Fatalf("count: %v", err)
	}
	if n != len(pkgs) {
		t.Errorf("count = %d, want %d", n, len(pkgs))
	}
}

// TriagePopular ranks by how much a mistake costs, not by what we believe about
// the sample: a detection on the third most-used package outranks one on the
// nine-hundredth, whatever either is labeled.
func TestTriagePopularRanksByImportanceNotLabel(t *testing.T) {
	ctx := t.Context()
	db := openTestDB(t)

	var n int
	add := func(purlBase, label string, crit int) string {
		n++
		sha := fmt.Sprintf("%063x1", n)
		mustInsert(t, ctx, db, &Sample{
			SHA256: sha, Source: "test", Label: label, LabelSource: "test",
			PURLBase: purlBase, Version: "1.0.0",
		})
		result := fmt.Appendf(nil, `{"fs":[{"sha":%q,"type":"npm","x":0,"dp":0,"ts":[{"l":%d}]}]}`, sha, crit)
		if err := db.UpdateCleaveResult(ctx, sha, result, nil, ""); err != nil {
			t.Fatalf("UpdateCleaveResult: %v", err)
		}
		return sha
	}

	lowRank := add("pkg:npm/popular-3", "good", 5)   // rank 3, filed good
	highRank := add("pkg:npm/popular-900", "bad", 5) // rank 900, filed bad
	unmarked := add("pkg:npm/nobody-imports", "unknown", 5)
	benign := add("pkg:npm/popular-5", "unknown", 1) // marked, but no detection
	// The boundary the queue turns on, raised twice. "notable" is a finding worth
	// recording, not one worth the deep chain and a fleet-wide stand-down; at the
	// old notableCrit floor this row qualified and 92% of the live population
	// looked like it. Since 2026-09-01 the floor is HOSTILE, so the suspicious
	// row below is excluded too: what justifies standing the fleet down is a
	// widely-installed package our rules call hostile, which is either a live
	// supply-chain compromise or a false positive about to hit a great many
	// people. Merely suspicious was 13,798 of the 13,906 population.
	notable := add("pkg:npm/popular-7", "unknown", 3)
	suspicious := add("pkg:npm/popular-11", "unknown", 4)

	if err := db.SetPopularPackages(ctx, []PopularPackage{
		{PURLBase: "pkg:npm/popular-3", Ecosystem: "npm", Rank: 3, Source: "poppy"},
		{PURLBase: "pkg:npm/popular-900", Ecosystem: "npm", Rank: 900, Source: "poppy"},
		{PURLBase: "pkg:npm/popular-5", Ecosystem: "npm", Rank: 5, Source: "poppy"},
		{PURLBase: "pkg:npm/popular-7", Ecosystem: "npm", Rank: 7, Source: "poppy"},
		{PURLBase: "pkg:npm/popular-11", Ecosystem: "npm", Rank: 11, Source: "poppy"},
	}); err != nil {
		t.Fatalf("SetPopularPackages: %v", err)
	}

	got, err := db.TriagePopular(ctx, 100, time.Time{}, time.Time{}, TriageFilter{})
	if err != nil {
		t.Fatalf("TriagePopular: %v", err)
	}
	var order []string
	for _, s := range got {
		order = append(order, s.SHA256)
	}
	if len(order) != 2 {
		t.Fatalf("selected %d samples, want 2: %v", len(order), order)
	}
	if order[0] != lowRank {
		t.Errorf("rank 3 should come first; got order %v", order)
	}
	if order[1] != highRank {
		t.Errorf("rank 900 should come second; got order %v", order)
	}
	for _, excluded := range []struct {
		sha, why string
	}{
		{unmarked, "a package nobody marked as popular"},
		{benign, "a marked package with no detection"},
		{notable, "a marked package whose worst finding is only notable"},
		{suspicious, "a marked package whose worst finding is only suspicious"},
	} {
		for _, s := range got {
			if s.SHA256 == excluded.sha {
				t.Errorf("TriagePopular included %s", excluded.why)
			}
		}
	}
}

// Within one package the tie breaks on cleave risk score, worst first. It used
// to break on analyzed_at, which ordered a package's artifacts by when we last
// looked at them — no signal at all about which one is worth judging first, and
// one that a re-analysis silently reshuffles.
func TestTriagePopularBreaksTiesByRiskScore(t *testing.T) {
	ctx := t.Context()
	db := openTestDB(t)

	var n int
	add := func(risk int) string {
		n++
		sha := fmt.Sprintf("%063x1", n)
		mustInsert(t, ctx, db, &Sample{
			SHA256: sha, Source: "test", Label: "unknown", LabelSource: "test",
			PURLBase: "pkg:npm/one-package", Version: fmt.Sprintf("1.0.%d", n),
		})
		// Same package, same rank, same crit — risk is the only thing separating
		// them, so it is the only thing the ordering can be reading.
		// Hostile, not suspicious: popular's bar is max_crit >= 5 since
		// 2026-09-01, on the reasoning that a widely-installed package our rules
		// call hostile is what justifies standing the fleet down for it.
		result := fmt.Appendf(nil, `{"fs":[{"sha":%q,"type":"npm","x":%d,"dp":0,"ts":[{"l":5}]}]}`, sha, risk)
		if err := db.UpdateCleaveResult(ctx, sha, result, nil, ""); err != nil {
			t.Fatalf("UpdateCleaveResult: %v", err)
		}
		return sha
	}

	mild := add(10)
	worst := add(900)
	middling := add(400)

	if err := db.SetPopularPackages(ctx, []PopularPackage{
		{PURLBase: "pkg:npm/one-package", Ecosystem: "npm", Rank: 1, Source: "poppy"},
	}); err != nil {
		t.Fatalf("SetPopularPackages: %v", err)
	}

	got, err := db.TriagePopular(ctx, 100, time.Time{}, time.Time{}, TriageFilter{})
	if err != nil {
		t.Fatalf("TriagePopular: %v", err)
	}
	want := []string{worst, middling, mild}
	if len(got) != len(want) {
		t.Fatalf("selected %d samples, want %d", len(got), len(want))
	}
	for i, w := range want {
		if got[i].SHA256 != w {
			t.Errorf("position %d = %s, want %s (risk-descending)", i, got[i].SHA256, w)
		}
	}
}

func TestPopularRanksReturnsTheWholeSet(t *testing.T) {
	db := openTestDB(t)
	ctx := t.Context()
	if err := db.SetPopularPackages(ctx, []PopularPackage{
		{PURLBase: "pkg:npm/left-pad", Ecosystem: "npm", Rank: 7, Source: "poppy"},
		{PURLBase: "pkg:gem/rails", Ecosystem: "gem", Rank: 2, Source: "poppy"},
	}); err != nil {
		t.Fatalf("set: %v", err)
	}
	got, err := db.PopularRanks(ctx)
	if err != nil {
		t.Fatalf("PopularRanks: %v", err)
	}
	if len(got) != 2 || got["pkg:npm/left-pad"] != 7 || got["pkg:gem/rails"] != 2 {
		t.Errorf("PopularRanks = %v, want left-pad:7 rails:2", got)
	}
	if _, ok := got["pkg:npm/never-marked"]; ok {
		t.Error("PopularRanks invented an identity")
	}
}

// Two packages collapsing onto one identity is normal, not an input error: the
// PURL spec folds case for golang and case plus underscores for pypi. Postgres
// refuses a statement that touches one row twice, so a whole publish used to
// fail on it — which is exactly how pypi and golang failed in production.
func TestSetPopularPackagesSurvivesCollidingIdentities(t *testing.T) {
	db := openTestDB(t)
	ctx := t.Context()
	if err := db.SetPopularPackages(ctx, []PopularPackage{
		{PURLBase: "pkg:pypi/foo-bar", Ecosystem: "pypi", Rank: 12, Source: "poppy"},
		{PURLBase: "pkg:pypi/other", Ecosystem: "pypi", Rank: 50, Source: "poppy"},
		// `Foo_Bar` normalizes onto the same identity as `foo-bar`.
		{PURLBase: "pkg:pypi/foo-bar", Ecosystem: "pypi", Rank: 3000, Source: "poppy"},
	}); err != nil {
		t.Fatalf("a colliding ranking must still publish: %v", err)
	}

	n, err := db.PopularPackageCount(ctx)
	if err != nil {
		t.Fatalf("count: %v", err)
	}
	if n != 2 {
		t.Errorf("count = %d, want 2 distinct identities", n)
	}
	ranks, err := db.PopularRanks(ctx)
	if err != nil {
		t.Fatalf("PopularRanks: %v", err)
	}
	if got := ranks["pkg:pypi/foo-bar"]; got != 12 {
		t.Errorf("rank = %d, want 12 — the better rank must win the collision", got)
	}
}

// The collision may straddle a batch boundary, where it would not raise an
// error but would make the stored rank depend on batching order.
func TestDedupePopularSpansBatchBoundaries(t *testing.T) {
	pkgs := make([]PopularPackage, 0, popularUpsertBatch+2)
	pkgs = append(pkgs, PopularPackage{PURLBase: "pkg:pypi/edge", Ecosystem: "pypi", Rank: 9, Source: "poppy"})
	for i := range popularUpsertBatch {
		pkgs = append(pkgs, PopularPackage{
			PURLBase: "pkg:pypi/f" + strconv.Itoa(i), Ecosystem: "pypi", Rank: i + 100, Source: "poppy",
		})
	}
	pkgs = append(pkgs, PopularPackage{PURLBase: "pkg:pypi/edge", Ecosystem: "pypi", Rank: 8000, Source: "poppy"})

	got := dedupePopular(pkgs)
	if len(got) != popularUpsertBatch+1 {
		t.Errorf("len = %d, want %d", len(got), popularUpsertBatch+1)
	}
	if got[0].PURLBase != "pkg:pypi/edge" || got[0].Rank != 9 {
		t.Errorf("first entry = %+v, want the edge identity at rank 9", got[0])
	}
}

func TestDedupePopularKeepsOrderAndLeavesCleanInputAlone(t *testing.T) {
	in := []PopularPackage{
		{PURLBase: "pkg:npm/a", Rank: 1}, {PURLBase: "pkg:npm/b", Rank: 2}, {PURLBase: "pkg:npm/c", Rank: 3},
	}
	got := dedupePopular(in)
	if len(got) != 3 {
		t.Fatalf("len = %d, want 3", len(got))
	}
	for i, p := range got {
		if p != in[i] {
			t.Errorf("entry %d = %+v, want %+v — clean input must pass through in order", i, p, in[i])
		}
	}
}

// popular and popular-tail are one population divided by one timestamp: the
// freshest slice is what the fleet stands down for, the rest is reach. Before
// the split these were a single number, so reaching further back meant holding
// every other queue down for a three-week backlog.
func TestTriagePopularSplitsFreshFromTail(t *testing.T) {
	ctx := t.Context()
	db := openTestDB(t)

	add := func(n int, purlBase string, analyzedAt time.Time) string {
		sha := fmt.Sprintf("%063x2", n)
		mustInsert(t, ctx, db, &Sample{
			SHA256: sha, Source: "test", Label: "unknown", LabelSource: "test",
			PURLBase: purlBase, Version: "1.0.0",
		})
		result := fmt.Appendf(nil, `{"fs":[{"sha":%q,"type":"npm","x":0,"dp":0,"ts":[{"l":5}]}]}`, sha)
		if err := db.UpdateCleaveResult(ctx, sha, result, nil, ""); err != nil {
			t.Fatalf("UpdateCleaveResult: %v", err)
		}
		if _, err := db.lite.ExecContext(ctx, `UPDATE samples SET analyzed_at = ? WHERE sha256 = ?`,
			analyzedAt.UTC().Format(time.RFC3339Nano), sha); err != nil {
			t.Fatalf("backdate analyzed_at: %v", err)
		}
		return sha
	}

	now := time.Now()
	fresh := add(1, "pkg:npm/split-3", now.Add(-time.Hour))
	tail := add(2, "pkg:npm/split-9", now.Add(-72*time.Hour))
	ancient := add(3, "pkg:npm/split-11", now.Add(-40*24*time.Hour))

	if err := db.SetPopularPackages(ctx, []PopularPackage{
		{PURLBase: "pkg:npm/split-3", Ecosystem: "npm", Rank: 3, Source: "poppy"},
		{PURLBase: "pkg:npm/split-9", Ecosystem: "npm", Rank: 9, Source: "poppy"},
		{PURLBase: "pkg:npm/split-11", Ecosystem: "npm", Rank: 11, Source: "poppy"},
	}); err != nil {
		t.Fatalf("SetPopularPackages: %v", err)
	}

	priority, err := db.TriagePopular(ctx, 100, now.Add(-PopularPriorityWindow), time.Time{}, TriageFilter{})
	if err != nil {
		t.Fatalf("TriagePopular(priority): %v", err)
	}
	tailRows, err := db.TriagePopular(ctx, 100,
		now.Add(-PopularFreshness), now.Add(-PopularPriorityWindow), TriageFilter{})
	if err != nil {
		t.Fatalf("TriagePopular(tail): %v", err)
	}

	inPriority, inTail := shaSet(priority), shaSet(tailRows)
	if !inPriority[fresh] || len(priority) != 1 {
		t.Errorf("priority half = %d rows, want just the one analyzed inside the window", len(priority))
	}
	if !inTail[tail] || len(tailRows) != 1 {
		t.Errorf("tail half = %d rows, want just the one behind the window", len(tailRows))
	}
	// Disjoint, and neither reaches past the outer floor.
	for sha := range inPriority {
		if inTail[sha] {
			t.Errorf("%s is in both popular and popular-tail; the split must partition", sha)
		}
	}
	if inPriority[ancient] || inTail[ancient] {
		t.Error("a sample older than PopularFreshness was served by either half")
	}
}
