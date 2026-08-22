package hopper

import (
	"fmt"
	"strconv"
	"testing"
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

	lowRank := add("pkg:npm/popular-3", "good", 4)   // rank 3, filed good
	highRank := add("pkg:npm/popular-900", "bad", 4) // rank 900, filed bad
	unmarked := add("pkg:npm/nobody-imports", "unknown", 4)
	benign := add("pkg:npm/popular-5", "unknown", 1) // marked, but no detection

	if err := db.SetPopularPackages(ctx, []PopularPackage{
		{PURLBase: "pkg:npm/popular-3", Ecosystem: "npm", Rank: 3, Source: "poppy"},
		{PURLBase: "pkg:npm/popular-900", Ecosystem: "npm", Rank: 900, Source: "poppy"},
		{PURLBase: "pkg:npm/popular-5", Ecosystem: "npm", Rank: 5, Source: "poppy"},
	}); err != nil {
		t.Fatalf("SetPopularPackages: %v", err)
	}

	got, err := db.TriagePopular(ctx, 100, TriageFilter{})
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
	} {
		for _, s := range got {
			if s.SHA256 == excluded.sha {
				t.Errorf("TriagePopular included %s", excluded.why)
			}
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
