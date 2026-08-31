package hopper

import (
	"context"
	"fmt"
	"strings"
	"testing"
	"time"
)

// traitsAt builds the trait literal mustAnalyzeWithTraits wants, one finding per
// level. suspicious_count counts levels >= 4; max_crit is the highest of them.
//
// Named to stay clear of litmusClassSQLiteExpr's crit parameter, which a
// package-level crit would shadow in test builds.
func traitsAt(levels ...int) string {
	parts := make([]string, 0, len(levels))
	for _, l := range levels {
		parts = append(parts, fmt.Sprintf(`{"l":%d}`, l))
	}
	return strings.Join(parts, ",")
}

// seedUnconvicted inserts one analyzed top-level sample with the given label and
// findings, and returns its sha.
func seedUnconvicted(t *testing.T, ctx context.Context, db *DB, n byte, label string, levels ...int) string {
	t.Helper()
	sha := fmt.Sprintf("%064x", n)
	mustInsert(t, ctx, db, &Sample{SHA256: sha, Label: label, Path: fmt.Sprintf("incoming/%d.tgz", n)})
	mustAnalyzeWithTraits(t, ctx, db, sha, 10, traitsAt(levels...))
	return sha
}

// TestUnconvictedPairCoversTheRetiredPair is the assertion the whole retirement
// rests on. good and new were replaced on the claim that
// unconvicted-hostile ∪ unconvicted-suspicious is exactly good ∪ new — which is
// arithmetic about how suspicious_count is derived (it counts crit >= 4
// findings, so `unknown AND suspicious_count >= 1` is `unknown AND max_crit >= 4`),
// and arithmetic in a commit message is not evidence. This runs both sides.
//
// It is also what pins the label-conditional bar on the suspicious tier: drop
// the `OR label = 'unknown'` arm and every unknown sample with exactly one
// suspicious finding falls out of the union, which this test would catch.
func TestUnconvictedPairCoversTheRetiredPair(t *testing.T) {
	ctx := context.Background()
	db := openTestDB(t)

	// One sample per interesting cell of (label × findings).
	want := map[string]string{
		// good-labelled
		"good hostile":        seedUnconvicted(t, ctx, db, 1, "good", 5),
		"good two suspicious": seedUnconvicted(t, ctx, db, 2, "good", 4, 4),
		// unknown-labelled
		"unknown hostile":        seedUnconvicted(t, ctx, db, 4, "unknown", 5),
		"unknown two suspicious": seedUnconvicted(t, ctx, db, 5, "unknown", 4, 4),
		// The sliver the label-conditional bar exists for: one suspicious
		// finding is within policy on a benign-labelled file, and is the whole
		// reason to look on an unlabelled one.
		"unknown one suspicious": seedUnconvicted(t, ctx, db, 6, "unknown", 4),
	}
	// Neither pool selects these.
	excluded := map[string]string{
		"good one suspicious": seedUnconvicted(t, ctx, db, 3, "good", 4),
		"good notable only":   seedUnconvicted(t, ctx, db, 7, "good", 3),
		"bad hostile":         seedUnconvicted(t, ctx, db, 8, "bad", 5),
	}

	hostile, err := db.TriageUnconvictedHostile(ctx, 100, TriageFilter{})
	if err != nil {
		t.Fatalf("TriageUnconvictedHostile: %v", err)
	}
	susp, err := db.TriageUnconvictedSuspicious(ctx, 100, TriageFilter{})
	if err != nil {
		t.Fatalf("TriageUnconvictedSuspicious: %v", err)
	}

	// Disjoint: max_crit >= 5 and max_crit = 4 cannot both hold. Two workers
	// sharing a per-sha tmp dir depends on this.
	inHostile, inSusp := shaSet(hostile), shaSet(susp)
	for sha := range inHostile {
		if inSusp[sha] {
			t.Errorf("sample %s is in BOTH tiers; they must partition, not overlap", sha[:6])
		}
	}

	union := map[string]bool{}
	for sha := range inHostile {
		union[sha] = true
	}
	for sha := range inSusp {
		union[sha] = true
	}
	for name, sha := range want {
		if !union[sha] {
			t.Errorf("%s (%s) is in neither tier; the union lost coverage the old good+new pair had", name, sha[:6])
		}
	}
	for name, sha := range excluded {
		if union[sha] {
			t.Errorf("%s (%s) was selected; neither retired queue took it", name, sha[:6])
		}
	}

	// ...and the union really is the retired pair's union, read from the
	// retired selectors themselves rather than from a hand-written expectation.
	old, err := db.TriageGood(ctx, 100, TriageFilter{})
	if err != nil {
		t.Fatalf("TriageGood: %v", err)
	}
	oldNew, err := db.TriageNew(ctx, 100, TriageFilter{})
	if err != nil {
		t.Fatalf("TriageNew: %v", err)
	}
	oldUnion := shaSet(old)
	for sha := range shaSet(oldNew) {
		oldUnion[sha] = true
	}
	for sha := range oldUnion {
		if !union[sha] {
			t.Errorf("sample %s was in good∪new but is in neither replacement tier", sha[:6])
		}
	}
	for sha := range union {
		if !oldUnion[sha] {
			t.Errorf("sample %s is in the new union but was in neither good nor new", sha[:6])
		}
	}
}

// TestUnconvictedRepairOrderPutsUncorroboratedFirst pins TriageRepair's whole
// reason to exist. If we flag a file and nobody outside has ever cited it, the
// only party calling it bad is us, which is what an over-firing rule looks like;
// a corroborated row is far more likely a LABEL problem, which is the second
// queue's question rather than a repair.
func TestUnconvictedRepairOrderPutsUncorroboratedFirst(t *testing.T) {
	ctx := context.Background()
	db := openTestDB(t)

	// Insert corroborated FIRST and with the newer created_at, so plain
	// newest-first ordering would return it first. Only the corroboration key
	// can put the uncorroborated row ahead of it.
	cited := seedUnconvicted(t, ctx, db, 1, "good", 5)
	uncited := seedUnconvicted(t, ctx, db, 2, "good", 5)
	// corroborated is maintained by a trigger on sightings, not by a setter, so
	// the only honest way to corroborate a sample is to cite it.
	if _, err := db.AddSightings(ctx, []Sighting{
		{Source: "osv", Operator: "ossf-malpkgs", Subject: cited, Claim: ClaimMalicious, Basis: BasisReviewed},
	}); err != nil {
		t.Fatalf("AddSightings: %v", err)
	}

	got, err := db.TriageUnconvictedHostile(ctx, 10, TriageFilter{Order: TriageRepair})
	if err != nil {
		t.Fatalf("TriageUnconvictedHostile: %v", err)
	}
	if len(got) != 2 {
		t.Fatalf("returned %d rows, want 2", len(got))
	}
	if got[0].SHA256 != uncited {
		t.Errorf("head = %s, want the UNcorroborated row %s", got[0].SHA256[:6], uncited[:6])
	}
}

// TestTriageDiscordSelectsOnlyDisagreement covers both arms and, more
// importantly, the agreements: a queue that also returned rows where the two
// detectors agree would be a detection queue wearing a conflict's name.
func TestTriageDiscordSelectsOnlyDisagreement(t *testing.T) {
	ctx := context.Background()
	db := openTestDB(t)

	// class 0 = benign, 2 = hostile (litmus). max_crit is the rule engine.
	rulesOnly := seedUnconvicted(t, ctx, db, 1, "good", 5) // rules hostile, ML silent
	setLitmus(t, ctx, db, rulesOnly, 0, 0.1)
	mlOnly := seedUnconvicted(t, ctx, db, 2, "good", 3) // ML hostile, rules quiet
	setLitmus(t, ctx, db, mlOnly, 2, 0.99)
	bothAgreeHostile := seedUnconvicted(t, ctx, db, 3, "good", 5)
	setLitmus(t, ctx, db, bothAgreeHostile, 2, 0.99)
	bothAgreeQuiet := seedUnconvicted(t, ctx, db, 4, "good", 3)
	setLitmus(t, ctx, db, bothAgreeQuiet, 0, 0.1)
	// Label-agnostic: a convicted sample with a detector conflict belongs here
	// too, it just reads as a detection gap rather than a false positive.
	badConflict := seedUnconvicted(t, ctx, db, 5, "bad", 5)
	setLitmus(t, ctx, db, badConflict, 0, 0.1)
	// Never scored by the ensemble: silence from a detector that never ran is
	// not disagreement.
	neverScored := seedUnconvicted(t, ctx, db, 6, "good", 5)

	got, err := db.TriageDiscord(ctx, 100, TriageFilter{})
	if err != nil {
		t.Fatalf("TriageDiscord: %v", err)
	}
	in := shaSet(got)
	for name, sha := range map[string]string{"rules-only": rulesOnly, "ml-only": mlOnly, "bad conflict": badConflict} {
		if !in[sha] {
			t.Errorf("discord missed %s (%s)", name, sha[:6])
		}
	}
	for name, sha := range map[string]string{
		"both hostile": bothAgreeHostile, "both quiet": bothAgreeQuiet, "never scored": neverScored,
	} {
		if in[sha] {
			t.Errorf("discord returned %s (%s); the detectors do not conflict there", name, sha[:6])
		}
	}
}

// TestTriageHighestReachesUnknownMembers covers the 2026-08-30 widening. A route's
// threshold sits over its highest-scoring NON-BAD files, and an unknown label is
// not a conviction — so an unknown-labelled file at the top of its distribution
// pins the threshold exactly as a good-labelled one does. Before the widening the
// inner walk required label='good' and those files were invisible to every
// confidence-ranked queue.
func TestTriageHighestReachesUnknownMembers(t *testing.T) {
	ctx := context.Background()
	db := openTestDB(t)

	sha := func(c byte) string { return fmt.Sprintf("%064x", c) }
	unknownTop, badTop := sha(1), sha(2)
	mustInsert(t, ctx, db, &Sample{SHA256: unknownTop, Label: "unknown", Path: "unknown/hot.exe"})
	mustAnalyze(t, ctx, db, unknownTop, 5)
	setLitmus(t, ctx, db, unknownTop, 2, 0.98)
	// A convicted file is TriageLowest's domain and must stay out.
	mustInsert(t, ctx, db, &Sample{SHA256: badTop, Label: "bad", Path: "bad/hot.exe"})
	mustAnalyze(t, ctx, db, badTop, 5)
	setLitmus(t, ctx, db, badTop, 2, 0.999)

	before := time.Now().Add(time.Hour)
	missing := time.Now().Add(-MissingRetry)
	got, err := db.TriageHighest(ctx, 20, before, missing, TriageFilter{})
	if err != nil {
		t.Fatalf("TriageHighest: %v", err)
	}
	in := shaSet(got)
	if !in[unknownTop] {
		t.Errorf("unknown-labelled top scorer %s not selected; the widening did not take", unknownTop[:6])
	}
	if in[badTop] {
		t.Errorf("bad-labelled %s selected; convictions belong to lowest", badTop[:6])
	}
}

// seedWithTraits inserts an analyzed good-labelled sample whose findings carry
// the given trait ids, all at suspicious criticality, so top_traits is derived.
func seedWithTraits(t *testing.T, ctx context.Context, db *DB, n byte, ids ...string) string {
	t.Helper()
	sha := fmt.Sprintf("%064x", n)
	mustInsert(t, ctx, db, &Sample{SHA256: sha, Label: "good", Path: fmt.Sprintf("incoming/%d.tgz", n)})
	parts := make([]string, 0, len(ids))
	for _, id := range ids {
		parts = append(parts, fmt.Sprintf(`{"id":%q,"l":4}`, id))
	}
	mustAnalyzeWithTraits(t, ctx, db, sha, 10, strings.Join(parts, ","))
	return sha
}

// TestTriageFPTraitClustersOnOneTrait is the whole point of the queue. Any queue
// can return false positives; this one has to return false positives that share
// a CAUSE, because a batch of twenty files tripping one rule shows what the rule
// actually matches and a batch of twenty unrelated files does not.
//
// So the assertion is not "it returned rows" but "every row it returned fires
// the same trait, and that trait is the worst offender".
func TestTriageFPTraitClustersOnOneTrait(t *testing.T) {
	ctx := context.Background()
	db := openTestDB(t)

	// noisy/rule fires on three samples, quiet/rule on one. The batch must be
	// the three, not a mixture ranked by recency.
	var noisy []string
	for i := byte(1); i <= 3; i++ {
		noisy = append(noisy, seedWithTraits(t, ctx, db, i, "noisy/rule"))
	}
	// Seeded LAST, so plain newest-first ordering would put it at the head.
	lonely := seedWithTraits(t, ctx, db, 4, "quiet/rule")

	got, err := db.TriageFPTrait(ctx, 10, TriageFilter{})
	if err != nil {
		t.Fatalf("TriageFPTrait: %v", err)
	}
	if len(got) == 0 {
		t.Fatal("TriageFPTrait returned nothing")
	}
	in := shaSet(got)
	if in[lonely] {
		t.Errorf("batch includes %s, which fires a different trait; the queue ranked by "+
			"recency instead of by offender", lonely[:6])
	}
	for _, sha := range noisy {
		if !in[sha] {
			t.Errorf("batch is missing %s, which fires the worst trait", sha[:6])
		}
	}
	if len(got) != len(noisy) {
		t.Errorf("batch has %d rows, want exactly the %d firing the worst trait", len(got), len(noisy))
	}
}

// TestTriageFPTraitIsGoodOnly pins the deliberate difference from the
// unconvicted pair. This queue counts which of OUR RULES produces the most false
// positives; an unlabelled sample firing a trait is not evidence of one, and
// letting those into the ranking would let ordinary unclassified traffic
// nominate the trait a whole batch then gets spent on.
func TestTriageFPTraitIsGoodOnly(t *testing.T) {
	ctx := context.Background()
	db := openTestDB(t)

	// Four unlabelled samples on one trait against one benign sample on another:
	// if the pool were label-agnostic the unlabelled trait would win outright.
	for i := byte(1); i <= 4; i++ {
		sha := fmt.Sprintf("%064x", i)
		mustInsert(t, ctx, db, &Sample{SHA256: sha, Label: "unknown", Path: fmt.Sprintf("in/%d.tgz", i)})
		mustAnalyzeWithTraits(t, ctx, db, sha, 10, `{"id":"unlabelled/rule","l":4}`)
	}
	benign := seedWithTraits(t, ctx, db, 9, "benign/rule")

	got, err := db.TriageFPTrait(ctx, 10, TriageFilter{})
	if err != nil {
		t.Fatalf("TriageFPTrait: %v", err)
	}
	if len(got) != 1 || got[0].SHA256 != benign {
		t.Errorf("got %d rows (%v), want only the benign-labelled %s: unlabelled samples "+
			"must not nominate the trait", len(got), shaSet(got), benign[:6])
	}
}

// TestTriageVersionDriftNeedsACleanEarlierSibling pins both halves of the
// predicate. The queue's value is entirely in the sibling — a firing sample with
// no clean predecessor is just an ordinary unconvicted-pool row, and returning
// it would spend a premium batch slot on a file with no diff to reason against.
func TestTriageVersionDriftNeedsACleanEarlierSibling(t *testing.T) {
	ctx := context.Background()
	db := openTestDB(t)

	seed := func(n byte, purl, label string, levels ...int) string {
		sha := fmt.Sprintf("%064x", n)
		mustInsert(t, ctx, db, &Sample{
			SHA256: sha, Label: label, PURLBase: purl,
			Path: fmt.Sprintf("incoming/%d.tgz", n),
		})
		mustAnalyzeWithTraits(t, ctx, db, sha, 10, traitsAt(levels...))
		return sha
	}

	// drifted: v1 clean and good, v2 fires. The case the queue is for.
	seed(1, "pkg:npm/drifted", "good")
	drifted := seed(2, "pkg:npm/drifted", "good", 4, 4)

	// alwaysNoisy: no clean predecessor at all.
	seed(3, "pkg:npm/noisy", "good", 4, 4)
	alwaysNoisy := seed(4, "pkg:npm/noisy", "good", 4, 4)

	// backwards: the CLEAN release is the newer one, so nothing drifted.
	seed(5, "pkg:npm/backwards", "good", 4, 4)
	backwards := seed(6, "pkg:npm/backwards", "good")

	// convicted: the earlier sibling is labelled bad, so it vouches for nothing.
	seed(7, "pkg:npm/convicted", "bad")
	convicted := seed(8, "pkg:npm/convicted", "good", 4, 4)

	got, err := db.TriageVersionDrift(ctx, 50, time.Now().Add(-VersionDriftWindow), TriageFilter{})
	if err != nil {
		t.Fatalf("TriageVersionDrift: %v", err)
	}
	in := shaSet(got)
	if !in[drifted] {
		t.Errorf("missed %s: a clean earlier release plus a firing later one is the queue", drifted[:6])
	}
	for name, sha := range map[string]string{
		"no clean predecessor":  alwaysNoisy,
		"clean one is newer":    backwards,
		"predecessor convicted": convicted,
	} {
		if in[sha] {
			t.Errorf("returned %s (%s); there is no clean earlier sibling to diff against", name, sha[:6])
		}
	}
}
