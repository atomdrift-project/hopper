package hopper

import (
	"context"
	"errors"
	"testing"
)

// Covers answers the narrow question: is this claim evidence about ONE release?
//
// The two samples in the name are the ones that prompted it. Both are ordinary
// releases of real packages that a much later compromise of the same package
// caused to be shown as externally flagged: MAL-2025-6020 names is 3.3.1 and
// 5.0.0, MAL-2026-3475 names @tanstack/router-devtools-core 1.167.6 and
// 1.167.9, and neither says anything about the releases below.
func TestCoversNarrowsToTheReleasesNamed(t *testing.T) {
	const pkg = "pkg:npm/is"
	for _, tc := range []struct {
		name     string
		subject  string
		affected string
		version  string
		want     bool
	}{
		{"named release", pkg, "3.3.1, 5.0.0", "3.3.1", true},
		{"unnamed older release", pkg, "3.3.1, 5.0.0", "0.1.2", false},
		{"unnamed newer release", pkg, "3.3.1, 5.0.0", "6.0.0", false},
		{"tanstack unnamed", "pkg:npm/%40tanstack/router-devtools-core", "1.167.9, 1.167.6", "1.162.6", false},

		// Unnarrowable scopes speak for the package: dropping them would lose
		// real citations, which is the opposite failure.
		{"every release", pkg, AllVersions, "0.1.2", true},
		{"scope unknown", pkg, "", "0.1.2", true},
		{"ghsa all releases", pkg, ">= 0", "0.1.2", true},
		{"range", pkg, "<2.0.0", "0.1.2", true},
		{"mixed range", pkg, ">=1.0.0, <2.0.0", "0.1.2", true},

		// A release is not obliged to start with a digit.
		{"v-prefixed, named", pkg, "v1.2.3", "v1.2.3", true},
		{"v-prefixed, unnamed", pkg, "v1.2.3", "v1.2.4", false},

		// "= 1.2.3" still names one immutable release.
		{"equality, named", pkg, "= 1.2.3", "1.2.3", true},
		{"equality, unnamed", pkg, "= 1.2.3", "1.2.4", false},

		// A digest names bytes, which have no releases at all.
		{"digest subject", "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855", "3.3.1", "0.1.2", true},

		// Nothing to narrow with.
		{"caller holds no version", pkg, "3.3.1, 5.0.0", "", true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			s := &Sighting{Subject: tc.subject, Affected: tc.affected}
			if got := s.Covers(tc.version); got != tc.want {
				t.Errorf("Covers(%q) with affected %q = %v, want %v",
					tc.version, tc.affected, got, tc.want)
			}
		})
	}
}

// Covers and coversEveryRelease answer different questions, and an empty scope
// is where they must disagree: Assess holds no version and must not convict on
// a field nobody filled, while a caller holding the release cannot rule it out.
func TestCoversAndCoversEveryReleaseDisagreeOnUnknownScope(t *testing.T) {
	s := &Sighting{Subject: "pkg:npm/is", Affected: ""}
	if coversEveryRelease(s) {
		t.Error("an unknown scope must not convict every release")
	}
	if !s.Covers("0.1.2") {
		t.Error("an unknown scope must still be shown against a release it cannot exclude")
	}
}

// The database triggers must narrow the same way Covers does. A version that
// does not start with a digit read as unnarrowable under the old GLOB/regex
// test, so a claim naming exactly one release marked every release corroborated.
func TestVPrefixedExactVersionDoesNotCorroborateOtherVersions(t *testing.T) {
	ctx := context.Background()
	db := openTestDB(t)

	const purl = "pkg:golang/example.com/mod"
	cited := mustVersionedSample(t, ctx, db, "f6", purl, "v1.2.3")
	uncited := mustVersionedSample(t, ctx, db, "a7", purl, "v1.2.4")

	if _, err := db.AddSightings(ctx, []Sighting{{
		Source: "osv", Subject: purl, Affected: "v1.2.3", Claim: ClaimMalicious,
	}}); err != nil {
		t.Fatal(err)
	}
	if !corroborated(t, ctx, db, cited) {
		t.Error("the release the advisory names is not corroborated; the citation was lost")
	}
	if corroborated(t, ctx, db, uncited) {
		t.Error("v1.2.4 was corroborated by an advisory that names only v1.2.3")
	}
}

// A claim naming this exact release is evidence against it.
//
// The ledger keys package claims on the version-less purl_base, so without the
// release in hand "MAL-2025-6020 names is 3.3.1" and "this sample is is 3.3.1"
// are two facts that meet nowhere, and the claim can only be counted as Scoped.
// /v1/lookup held the version and dropped it, so the most precise evidence the
// ledger carries reached no consumer at all.
func TestAssessReleaseCountsAClaimNamingThisRelease(t *testing.T) {
	const purl = "pkg:npm/is"
	rows := []Sighting{{
		Source: "osv", Operator: "ossf-malpkgs", Subject: purl,
		Affected: "3.3.1, 5.0.0", Claim: ClaimMalicious, Basis: BasisReviewed,
	}}

	// The release the advisory names.
	named := AssessRelease(rows, "3.3.1")
	if named.Scoped != 0 || len(named.Operators) != 1 {
		t.Errorf("3.3.1 is named by the advisory: got scoped=%d operators=%v",
			named.Scoped, named.Operators)
	}
	if _, ok := Floor(named.Confidence); !ok {
		t.Errorf("a reviewed claim naming this release justifies a floor, got %v", named.Confidence)
	}

	// A release it does not name, and the version-less question, both unchanged.
	for _, tc := range []struct{ name, version string }{
		{"unnamed release", "0.1.2"},
		{"no release in hand", ""},
	} {
		t.Run(tc.name, func(t *testing.T) {
			a := AssessRelease(rows, tc.version)
			if a.Scoped != 1 || len(a.Operators) != 0 {
				t.Errorf("got scoped=%d operators=%v, want the claim counted as scoped only",
					a.Scoped, a.Operators)
			}
			if _, ok := Floor(a.Confidence); ok {
				t.Error("a claim that does not name this release must justify no floor")
			}
		})
	}
}

// convicts must not inherit Covers's permissiveness. Covers keeps a claim whose
// scope is unreadable so a reader still sees it; believing the same row is what
// graded num2words 0.5.14 hostile while every source that named versions named
// 0.5.15 and 0.5.16.
func TestAssessReleaseRefusesScopesItCannotRead(t *testing.T) {
	for _, affected := range []string{"", "<2.0.0", ">=1.0.0, <2.0.0"} {
		t.Run("affected="+affected, func(t *testing.T) {
			rows := []Sighting{{
				Source: "osv", Operator: "ossf-malpkgs", Subject: "pkg:pypi/num2words",
				Affected: affected, Claim: ClaimMalicious, Basis: BasisReviewed,
			}}
			a := AssessRelease(rows, "0.5.14")
			if len(a.Operators) != 0 {
				t.Errorf("affected %q must not convict 0.5.14, got operators=%v", affected, a.Operators)
			}
			// ...while the display rule still shows it.
			if !rows[0].Covers("0.5.14") {
				t.Errorf("affected %q should still be shown to a reader", affected)
			}
		})
	}
}

// Assess is AssessRelease with no release in hand; a claim covering every
// release convicts either way.
func TestAssessIsAssessReleaseWithoutAVersion(t *testing.T) {
	rows := []Sighting{{
		Source: "osv", Operator: "ossf-malpkgs", Subject: "pkg:npm/evil",
		Affected: AllVersions, Claim: ClaimMalicious, Basis: BasisReviewed,
	}}
	if a, b := Assess(rows), AssessRelease(rows, ""); a.Confidence != b.Confidence {
		t.Errorf("Assess = %v, AssessRelease(_, \"\") = %v", a.Confidence, b.Confidence)
	}
	if len(AssessRelease(rows, "1.0.0").Operators) != 1 {
		t.Error("an all-releases claim convicts whichever release is asked about")
	}
}

// The poppy case, end to end through the path /v1/lookup serves.
//
// poppy asks about pkg:npm/is@3.3.1 — a top-10000 package, so exactly the kind
// it promotes — and hopper splits that into a base and a version before calling
// LookupRecord. Until the version was threaded through corroborate, a sample our
// own analysis had not fired on came back with no fires_at while OSV named that
// exact release malware, and poppy promoted it to the good pool.
func TestLookupRecordUsesAClaimNamingTheRelease(t *testing.T) {
	ctx := context.Background()
	db := openTestDB(t)

	const purl = "pkg:npm/is"
	cited := mustVersionedSample(t, ctx, db, "b8", purl, "3.3.1")
	clean := mustVersionedSample(t, ctx, db, "c9", purl, "0.1.2")

	// Two operators, so the ladder reaches a floor on its own.
	if _, err := db.AddSightings(ctx, []Sighting{
		{
			Source:   "osv",
			Operator: "ossf-malpkgs",
			Subject:  purl,
			Affected: "3.3.1, 5.0.0",
			Claim:    ClaimMalicious,
			Basis:    BasisReviewed,
			Note:     "MAL-2025-6020",
		},
		{
			Source:   "socket",
			Operator: "socket",
			Subject:  purl,
			Affected: "3.3.1",
			Claim:    ClaimMalicious,
			Basis:    BasisPredicted,
		},
	}); err != nil {
		t.Fatal(err)
	}

	named, err := db.LookupRecord(ctx, cited, purl, "3.3.1")
	if err != nil {
		t.Fatalf("lookup 3.3.1: %v", err)
	}
	if named.FiresAt == nil {
		t.Error("two sources name 3.3.1 as malware; the lookup reported no level at all")
	}

	other, err := db.LookupRecord(ctx, clean, purl, "0.1.2")
	if err != nil {
		t.Fatalf("lookup 0.1.2: %v", err)
	}
	if other.FiresAt != nil {
		t.Errorf("0.1.2 is named by neither source, got fires_at=%d", *other.FiresAt)
	}
}

// An answer derived from the ledger must name the release it is about.
//
// Consumers file a lookup body under the coordinate it names — beamline caches
// one under its own row.purl — so a verdict about one release reported under
// the version-less base is handed to the next caller asking about the package.
// Harmless while the body did not depend on the release; AssessRelease is what
// changed that.
func TestFromLedgerNamesTheReleaseItAnswersAbout(t *testing.T) {
	ctx := context.Background()
	db := openTestDB(t)

	const purl = "pkg:npm/is"
	if _, err := db.AddSightings(ctx, []Sighting{
		{
			Source:   "osv",
			Operator: "ossf-malpkgs",
			Subject:  purl,
			Affected: "3.3.1",
			Claim:    ClaimMalicious,
			Basis:    BasisReviewed,
		},
		{
			Source:   "socket",
			Operator: "socket",
			Subject:  purl,
			Affected: "3.3.1",
			Claim:    ClaimMalicious,
			Basis:    BasisPredicted,
		},
	}); err != nil {
		t.Fatal(err)
	}

	// Nothing holds these bytes, so the answer comes from the ledger alone.
	rec, err := db.LookupRecord(ctx, "", purl, "3.3.1")
	if err != nil {
		t.Fatalf("lookup: %v", err)
	}
	if rec.PURL == nil || *rec.PURL != "pkg:npm/is@3.3.1" {
		t.Errorf("record names %v, want pkg:npm/is@3.3.1", rec.PURL)
	}

	// And the package-level question is not convicted by it.
	if _, err := db.LookupRecord(ctx, "", purl, ""); !errors.Is(err, ErrNotFound) {
		t.Errorf("a claim scoped to 3.3.1 must not answer for the package, got %v", err)
	}
}

func TestWithVersionKeepsQualifiers(t *testing.T) {
	for _, tc := range []struct{ base, version, want string }{
		{"pkg:npm/is", "3.3.1", "pkg:npm/is@3.3.1"},
		{"pkg:npm/%40scope/pkg", "1.0.0", "pkg:npm/%40scope/pkg@1.0.0"},
		{
			"pkg:golang/example.com/m?repository_url=proxy.example",
			"v1.2.3",
			"pkg:golang/example.com/m@v1.2.3?repository_url=proxy.example",
		},
	} {
		if got := withVersion(tc.base, tc.version); got != tc.want {
			t.Errorf("withVersion(%q, %q) = %q, want %q", tc.base, tc.version, got, tc.want)
		}
	}
}

// The repair tool must narrow the same way the marking does.
//
// TestReconcileClearsVersionMismatchedCorroboration covers this for a release
// spelled 0.3.298, which is why the leading-digit test survived in
// ReconcileCorroborated long after it was replaced everywhere else: every
// release in that test begins with a digit. aikido spells composer releases
// "v5.4.9", and for those the old rule read the claim as covering the whole
// package and left the flag exactly where it was meant to clear it.
func TestReconcileClearsVPrefixedVersionMismatch(t *testing.T) {
	ctx := context.Background()
	db := openTestDB(t)

	const purl = "pkg:composer/yrodevgit/ctrx"
	cited := mustVersionedSample(t, ctx, db, "d1", purl, "v5.4.9")
	wrong := mustVersionedSample(t, ctx, db, "e2", purl, "v3.1.4")
	if _, err := db.AddSightings(ctx, []Sighting{{
		Source: "aikido", Subject: purl, Affected: "v5.4.9", Claim: ClaimMalicious,
	}}); err != nil {
		t.Fatal(err)
	}
	// The state the old marking left behind.
	if err := setCorroborated(ctx, db, wrong, true); err != nil {
		t.Fatal(err)
	}

	if _, err := db.ReconcileCorroborated(ctx); err != nil {
		t.Fatal(err)
	}
	if corroborated(t, ctx, db, wrong) {
		t.Error("v3.1.4 is named by no claim; reconcile is the repair for exactly this")
	}
	if !corroborated(t, ctx, db, cited) {
		t.Error("reconcile cleared the release the claim names")
	}
}
