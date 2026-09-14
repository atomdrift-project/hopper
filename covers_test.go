package hopper

import (
	"context"
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
