package hopper

import (
	"slices"
	"strings"
	"testing"
)

// mal is a whole-subject malicious claim from one source, spelled as the ledger
// stores it. Operator defaults to the source, as a producer that speaks only
// for itself leaves it.
func mal(source, operator string, basis Basis) Sighting {
	return Sighting{Source: source, Operator: operator, Claim: ClaimMalicious, Basis: basis, Affected: AllVersions}
}

func TestAssessCountsOperatorsNotSources(t *testing.T) {
	// osv and ossf publish the same corpus and parallax gives them one
	// operator on purpose. Counting the rows would turn a single opinion into
	// "independently corroborated", which is the whole thing operator exists
	// to prevent.
	a := Assess([]Sighting{
		mal("osv", "ossf-malpkgs", BasisReviewed),
		mal("ossf", "ossf-malpkgs", BasisReviewed),
	})
	if got := len(a.Operators); got != 1 {
		t.Fatalf("two mirrors of one corpus counted as %d operators, want 1", got)
	}
	if a.Confidence != Strong {
		t.Errorf("Confidence = %v, want Strong (one operator, adjudicated reports)", a.Confidence)
	}
}

// The failure this guards is a feed that publishes the same subject under many
// source names, or simply many rows. Neither may climb the ladder.
func TestAssessVolumeFromOneOperatorCannotClimb(t *testing.T) {
	var many []Sighting
	for range 50 {
		many = append(many, mal("aikido", "aikido", BasisPredicted))
	}
	a := Assess(many)
	if a.Confidence != Weak {
		t.Fatalf("50 rows from one operator reached %v, want Weak", a.Confidence)
	}
	if len(a.Operators) != 1 {
		t.Errorf("Operators = %v, want exactly one", a.Operators)
	}
}

func TestAssessLadder(t *testing.T) {
	for _, tc := range []struct {
		name string
		in   []Sighting
		want Confidence
	}{
		{"nothing", nil, NoClaim},
		{"one prediction", []Sighting{
			mal("socket", "socket", BasisPredicted),
		}, Weak},
		{"one adjudicated report", []Sighting{
			mal("osv", "ossf-malpkgs", BasisReviewed),
		}, Strong},
		{"one corpus holding the bytes", []Sighting{
			mal("bazaar", "abuse.ch", BasisHosted),
		}, Weak},
		{"one operator that both hosts and reviews takes the stronger", []Sighting{
			mal("osm", "osm", BasisHosted),
			mal("osm", "osm", BasisReviewed),
		}, Strong},
		{"two independent predictions corroborate", []Sighting{
			mal("socket", "socket", BasisPredicted),
			mal("aikido", "aikido", BasisPredicted),
		}, Corroborated},
		{"prediction corroborated by reviewed report", []Sighting{
			mal("socket", "socket", BasisPredicted),
			mal("osv", "ossf-malpkgs", BasisReviewed),
		}, Corroborated},
		{"three independent", []Sighting{
			mal("socket", "socket", BasisPredicted),
			mal("aikido", "aikido", BasisPredicted),
			mal("osv", "ossf-malpkgs", BasisReviewed),
		}, Conclusive},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if got := Assess(tc.in).Confidence; got != tc.want {
				t.Errorf("Confidence = %v, want %v", got, tc.want)
			}
		})
	}
}

// Two independent voices outrank one careful voice regardless of basis.
func TestAssessIndependenceOutranksStanding(t *testing.T) {
	careful := Assess([]Sighting{mal("osv", "ossf-malpkgs", BasisReviewed)})
	independent := Assess([]Sighting{
		mal("socket", "socket", BasisPredicted),
		mal("aikido", "aikido", BasisPredicted),
	})
	if independent.Confidence <= careful.Confidence {
		t.Fatalf("two independent (%v) must outrank one firsthand (%v)",
			independent.Confidence, careful.Confidence)
	}
	carefulFloor, _ := Floor(careful.Confidence)
	independentFloor, _ := Floor(independent.Confidence)
	if independentFloor >= carefulFloor {
		t.Errorf("floors disagree with the ladder: %d vs %d", independentFloor, carefulFloor)
	}
}

// A vulnerability is the opposite kind of fact: the package is legitimate and
// some releases are not. One old advisory counted as malware is how every clean
// version of an advised package became externally disputed.
func TestAssessIgnoresNonMaliciousClaims(t *testing.T) {
	a := Assess([]Sighting{
		{Source: "ghsa", Operator: "github-advisories", Claim: ClaimVulnerable, Basis: BasisReviewed, Affected: AllVersions},
		{Source: "manifest", Operator: "manifest", Claim: ClaimSuspicious, Basis: BasisPredicted, Affected: AllVersions},
	})
	if a.Confidence != NoClaim {
		t.Fatalf("Confidence = %v, want NoClaim: neither claim asserts malware", a.Confidence)
	}
	if len(a.Operators) != 0 {
		t.Errorf("Operators = %v, want none", a.Operators)
	}
	if a.Suspicious != 1 {
		t.Errorf("Suspicious = %d, want 1 — recorded, never counted", a.Suspicious)
	}
}

// A feed naming versions has not named this artifact. Resolving the range needs
// a registry we may not have, and a caller blocking installs must not convict
// 2.0.0 because 1.4.4 was flagged.
func TestAssessReportsVersionScopedClaimsWithoutCountingThem(t *testing.T) {
	a := Assess([]Sighting{
		{Source: "ossf", Operator: "ossf-malpkgs", Claim: ClaimMalicious, Affected: ">=0.3.230 <0.3.302", Basis: BasisReviewed},
	})
	if a.Confidence != NoClaim {
		t.Fatalf("Confidence = %v, want NoClaim for a version-scoped claim", a.Confidence)
	}
	if a.Scoped != 1 {
		t.Errorf("Scoped = %d, want 1 — visible to a caller that wants the permissive reading", a.Scoped)
	}
}

// An unrecognized basis is a row written by a producer newer than this build.
// Believing a value we do not understand is the failure that costs something.
func TestAssessTreatsUnknownBasisAsAGuess(t *testing.T) {
	a := Assess([]Sighting{mal("newfeed", "newfeed", Basis("adjudicated-by-vibes"))})
	if a.Confidence != Weak {
		t.Fatalf("Confidence = %v, want Weak for an uninterpretable basis", a.Confidence)
	}
	if a.Firsthand != 0 {
		t.Errorf("Firsthand = %d, want 0", a.Firsthand)
	}
}

// An empty basis is what every row written before the column existed carries.
// It must read as the weakest claim, so adopting the column under-counts
// confidence until feeds re-push rather than over-counting it.
func TestAssessTreatsEmptyBasisAsAGuess(t *testing.T) {
	if Assess([]Sighting{mal("osv", "ossf-malpkgs", "")}).Confidence != Weak {
		t.Fatal("a pre-migration row must not read as firsthand")
	}
}

func TestAssessFallsBackToSourceWhenOperatorIsUnset(t *testing.T) {
	a := Assess([]Sighting{
		{Source: "socket", Claim: ClaimMalicious, Basis: BasisPredicted, Affected: AllVersions},
		{Source: "aikido", Claim: ClaimMalicious, Basis: BasisPredicted, Affected: AllVersions},
	})
	if !slices.Equal(a.Operators, []string{"aikido", "socket"}) {
		t.Fatalf("Operators = %v, want the two source names, sorted", a.Operators)
	}
}

func TestFloor(t *testing.T) {
	for _, tc := range []struct {
		c      Confidence
		want   int
		wantOK bool
	}{
		{NoClaim, 0, false},
		{Weak, 100, true},
		{Moderate, 50, true},
		{Strong, 25, true},
		{Corroborated, 10, true},
		{Conclusive, 1, true},
	} {
		lvl, ok := Floor(tc.c)
		if lvl != tc.want || ok != tc.wantOK {
			t.Errorf("Floor(%v) = (%d, %v), want (%d, %v)", tc.c, lvl, ok, tc.want, tc.wantOK)
		}
	}
}

// A derived level may convict without outranking measurement. Zero fires at
// every budget including zero, which would put a threat-feed citation above
// every verdict our own analyzer has ever produced.
func TestFloorNeverReachesZero(t *testing.T) {
	for _, c := range []Confidence{Weak, Moderate, Strong, Corroborated, Conclusive} {
		if lvl, _ := Floor(c); lvl < 1 {
			t.Errorf("Floor(%v) = %d, want at least 1", c, lvl)
		}
	}
}

// The ladder must be monotone: more agreement never produces a looser level.
func TestFloorIsMonotone(t *testing.T) {
	prev := 1 << 30
	for _, c := range []Confidence{Weak, Moderate, Strong, Corroborated, Conclusive} {
		lvl, ok := Floor(c)
		if !ok {
			t.Fatalf("Floor(%v) declined to answer", c)
		}
		if lvl > prev {
			t.Fatalf("Floor(%v) = %d loosens on the rung below (%d)", c, lvl, prev)
		}
		prev = lvl
	}
}

// A corpus listing is firsthand but light: it says somebody filed these bytes
// as malware, not that anybody confirmed it. It must land ABOVE the default
// budget, so one listing flags without convicting, while an adjudicated report
// lands at or below it.
func TestHostedFlagsAndReviewedConvicts(t *testing.T) {
	const defaultBudget = 25
	hosted, _ := Floor(Assess([]Sighting{mal("bazaar", "abuse.ch", BasisHosted)}).Confidence)
	reviewed, _ := Floor(Assess([]Sighting{mal("osv", "ossf-malpkgs", BasisReviewed)}).Confidence)

	if hosted <= defaultBudget {
		t.Errorf("a lone corpus listing reaches L%d and blocks by default; it should only flag", hosted)
	}
	if reviewed > defaultBudget {
		t.Errorf("a lone adjudicated report reaches L%d and does not block by default", reviewed)
	}
	if hosted <= reviewed {
		t.Errorf("hosted L%d must be looser than reviewed L%d", hosted, reviewed)
	}
}

// The bug this pins: rank(Predicted) equals rank(the zero value), so a `>`
// compare never inserted a predicted-only operator into the fold and the whole
// ladder scored NoClaim. Predictions remain visible and independent operators
// can corroborate one another.
func TestPredictedOnlyOperatorsAreStillCounted(t *testing.T) {
	one := Assess([]Sighting{mal("socket", "socket", BasisPredicted)})
	if len(one.Operators) != 1 || one.Confidence != Weak {
		t.Fatalf("one predicted operator: got %d operators, %v", len(one.Operators), one.Confidence)
	}
	three := Assess([]Sighting{
		mal("socket", "socket", BasisPredicted),
		mal("aikido", "aikido", BasisPredicted),
		mal("triage", "triage", BasisPredicted),
	})
	if three.Confidence != Conclusive {
		t.Fatalf("three predicted operators = %v, want Conclusive", three.Confidence)
	}
}

// Our own analysis, when it fired, is a second and independent line of evidence
// — unlike a verdict of ours in the ledger, which would only agree with itself.
func TestOurOwnFiringAnalysisBacksAnOutsideClaim(t *testing.T) {
	lvl := func(v int) *int { return &v }
	for _, tc := range []struct {
		name     string
		measured *int
		want     bool
	}{
		{"fired tight", lvl(5), true},
		{"fired loosely, still suspicious", lvl(2999), true},
		{"above the suspicious ceiling", lvl(5000), false},
		{"benign sentinel: looked, found nothing", lvl(-1), false},
		{"no level at all", nil, false},
	} {
		if got := fired(tc.measured); got != tc.want {
			t.Errorf("%s: fired = %v, want %v", tc.name, got, tc.want)
		}
	}

	if backed(Moderate) != Strong {
		t.Error("a corpus listing our analyzer also fired on should reach the adjudicated rung")
	}
	if backed(Conclusive) != Conclusive {
		t.Error("the top rung has nowhere to go")
	}
	if backed(NoClaim) != NoClaim {
		t.Error("our own signal must never manufacture an outside claim")
	}
}

// aikido publishes "*" for a package that exists only to be malware, and
// parallax carries it through unchanged. 91,796 ledger rows are spelled that
// way and every one of them counted for nothing: treated as a version scope,
// so never folded into an operator, so the subject read as uncited.
func TestWildcardAffectedIsAWholePackageClaim(t *testing.T) {
	a := Assess([]Sighting{
		{Source: "aikido", Operator: "aikido", Subject: "pkg:npm/evil", Affected: "*", Claim: ClaimMalicious},
	})
	if a.Confidence != Weak {
		t.Fatalf("Confidence = %v, want Weak: '*' is every release, not a version scope", a.Confidence)
	}
	if a.Scoped != 0 {
		t.Errorf("Scoped = %d, want 0", a.Scoped)
	}
	if len(a.Operators) != 1 {
		t.Errorf("Operators = %v, want the one that made the claim", a.Operators)
	}
}

// A real version scope must still be excluded — that is the num2words guard.
func TestExplicitVersionsAreStillScoped(t *testing.T) {
	a := Assess([]Sighting{
		{Source: "osv", Operator: "ossf-malpkgs", Subject: "pkg:pypi/num2words", Affected: "0.5.15, 0.5.16", Claim: ClaimMalicious},
	})
	if a.Confidence != NoClaim || a.Scoped != 1 {
		t.Fatalf("Confidence = %v, Scoped = %d; a versioned claim must not convict another release", a.Confidence, a.Scoped)
	}
}

// An empty Affected on a PACKAGE claim is unknown scope, not "every release".
// It must convict nothing: this is what num2words@0.5.14 turned on.
func TestUnknownScopeConvictsNothing(t *testing.T) {
	a := Assess([]Sighting{
		{Source: "osv", Operator: "ossf-malpkgs", Subject: "pkg:pypi/num2words", Claim: ClaimMalicious},
		{Source: "aikido", Operator: "aikido", Subject: "pkg:pypi/num2words", Claim: ClaimMalicious},
		{Source: "osm", Operator: "osm", Subject: "pkg:pypi/num2words", Claim: ClaimMalicious},
	})
	if a.Confidence != NoClaim {
		t.Fatalf("Confidence = %v, want NoClaim: three rows with no stated scope are three unknowns", a.Confidence)
	}
	if a.Scoped != 3 {
		t.Errorf("Scoped = %d, want 3 — visible, and counted toward nothing", a.Scoped)
	}
}

// A digest names exact bytes, which have no versions, so a digest claim covers
// its subject entirely however Affected is spelled. Feeds write it empty.
func TestDigestClaimsCoverTheirSubjectWithoutSayingSo(t *testing.T) {
	sha := strings.Repeat("a", 64)
	a := Assess([]Sighting{
		{Source: "bazaar", Operator: "abuse.ch", Subject: sha, Claim: ClaimMalicious, Basis: BasisHosted},
	})
	if a.Confidence != Weak {
		t.Fatalf("Confidence = %v, want Weak: exact hosted bytes still need corroboration", a.Confidence)
	}
	if a.Scoped != 0 {
		t.Errorf("Scoped = %d, want 0", a.Scoped)
	}
}
