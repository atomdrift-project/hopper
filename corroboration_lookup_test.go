package hopper

import (
	"context"
	"errors"
	"testing"
)

func findingIDs(r *LookupRecord) []string {
	out := make([]string, 0, len(r.Findings))
	for _, f := range r.Findings {
		out = append(out, f.ID)
	}
	return out
}

func hasFeedFinding(r *LookupRecord) bool {
	for _, f := range r.Findings {
		if f.ID == feedTraitID {
			return true
		}
	}
	return false
}

// The gap this feature exists for: a package nothing has analyzed, that several
// unrelated sources call malware. Answering "unknown" there is a worse answer
// than answering with what they say.
func TestLookupRecordDerivesALevelForAnArtifactNobodyHasAnalyzed(t *testing.T) {
	ctx := context.Background()
	db := openTestDB(t)

	if _, err := db.AddSightings(ctx, []Sighting{
		{Source: "osv", Operator: "ossf-malpkgs", Subject: "pkg:npm/ghost", Affected: AllVersions, Claim: ClaimMalicious, Basis: BasisReviewed},
		{Source: "aikido", Operator: "aikido", Subject: "pkg:npm/ghost", Affected: AllVersions, Claim: ClaimMalicious, Basis: BasisPredicted},
	}); err != nil {
		t.Fatalf("AddSightings: %v", err)
	}

	rec, err := db.LookupRecord(ctx, "", "pkg:npm/ghost", "1.0.0")
	if err != nil {
		t.Fatalf("LookupRecord: %v", err)
	}
	if rec.FiresAt == nil || *rec.FiresAt != 10 {
		t.Errorf("FiresAt = %v, want 10 (two independent operators)", rec.FiresAt)
	}
	// An engine is what separates a measurement from a citation. Every consumer
	// downstream — scan's is_verdict, beamline's cache rules — reads this.
	if rec.EngineVersion != nil {
		t.Errorf("EngineVersion = %v, want nil: nothing analyzed this", *rec.EngineVersion)
	}
	if rec.AnalyzedAt != nil {
		t.Errorf("AnalyzedAt = %v, want nil", *rec.AnalyzedAt)
	}
	if !hasFeedFinding(rec) {
		t.Errorf("findings = %v, want one naming the evidence", findingIDs(rec))
	}
	if rec.Reason == nil || *rec.Reason == "" {
		t.Error("a derived answer must say why in words a person reads")
	}
	// Counting sources rather than naming them: an API response that named a
	// vendor would republish its data under ours.
	for _, name := range []string{"osv", "aikido", "ossf"} {
		if rec.Reason != nil && contains(*rec.Reason, name) {
			t.Errorf("reason names a source (%q): %q", name, *rec.Reason)
		}
	}
	// Answerable now — there is no analysis coming for this key, so the 202
	// that means "come back" would be a lie.
	if !rec.Analyzed {
		t.Error("a derived record must answer rather than promise one")
	}
}

func contains(haystack, needle string) bool {
	for i := 0; i+len(needle) <= len(haystack); i++ {
		if haystack[i:i+len(needle)] == needle {
			return true
		}
	}
	return false
}

// Nothing stored and nothing said stays nothing. The derived path must not
// manufacture an answer out of an empty ledger.
func TestLookupRecordStillReportsAbsenceWhenNobodyHasSaidAnything(t *testing.T) {
	ctx := context.Background()
	db := openTestDB(t)
	if _, err := db.LookupRecord(ctx, "", "pkg:npm/quiet", "1.0.0"); !errors.Is(err, ErrNotFound) {
		t.Fatalf("LookupRecord err = %v, want ErrNotFound", err)
	}
}

// A claim naming versions has not named this artifact, so it cannot convict it.
func TestLookupRecordIgnoresVersionScopedClaimsWhenDeriving(t *testing.T) {
	ctx := context.Background()
	db := openTestDB(t)
	if _, err := db.AddSightings(ctx, []Sighting{
		{
			Source: "ghsa", Operator: "github-advisories", Subject: "pkg:npm/ranged",
			Affected: ">=0.3.1 <0.4.0", Claim: ClaimMalicious, Basis: BasisReviewed,
		},
	}); err != nil {
		t.Fatalf("AddSightings: %v", err)
	}
	if _, err := db.LookupRecord(ctx, "", "pkg:npm/ranged", "9.9.9"); !errors.Is(err, ErrNotFound) {
		t.Fatalf("a version-scoped claim convicted an unrelated release: err = %v", err)
	}
}

// The other half: a verdict we DID measure, that outside sources dispute. The
// citation may tighten it and must annotate it.
func TestLookupRecordTightensAMeasuredLevel(t *testing.T) {
	ctx := context.Background()
	db := openTestDB(t)

	const sha = "cccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc"
	mustInsertAnalyzed(t, ctx, db, sha, "loose", "1.0.0")
	// Re-analyse at a level far looser than the floor three operators justify.
	if err := db.UpdateLitmusResult(ctx, sha, []byte(`{"v":"7","lvl":900,"eng":"2.8.0"}`)); err != nil {
		t.Fatalf("UpdateLitmusResult: %v", err)
	}
	if _, err := db.AddSightings(ctx, []Sighting{
		{Source: "osv", Operator: "ossf-malpkgs", Subject: "pkg:npm/loose", Affected: AllVersions, Claim: ClaimMalicious, Basis: BasisReviewed},
		{Source: "aikido", Operator: "aikido", Subject: "pkg:npm/loose", Affected: AllVersions, Claim: ClaimMalicious, Basis: BasisPredicted},
		{Source: "socket", Operator: "socket", Subject: "pkg:npm/loose", Affected: AllVersions, Claim: ClaimMalicious, Basis: BasisPredicted},
	}); err != nil {
		t.Fatalf("AddSightings: %v", err)
	}

	rec, err := db.LookupRecord(ctx, sha, "", "")
	if err != nil {
		t.Fatalf("LookupRecord: %v", err)
	}
	if rec.FiresAt == nil || *rec.FiresAt != 1 {
		t.Errorf("FiresAt = %v, want 1 (three independent operators)", rec.FiresAt)
	}
	if !hasFeedFinding(rec) {
		t.Errorf("findings = %v, want the citation among them", findingIDs(rec))
	}
	// An engine DID produce this verdict, so it stays a verdict: the annotation
	// does not turn a measurement into a citation.
	if rec.EngineVersion == nil {
		t.Error("EngineVersion = nil on a record an engine produced")
	}
}

// Outside citations may only ever make an answer stricter. A measured level
// already tighter than the floor must survive untouched.
func TestLookupRecordNeverLoosensAMeasuredLevel(t *testing.T) {
	ctx := context.Background()
	db := openTestDB(t)

	const sha = "dddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddd"
	mustInsertAnalyzed(t, ctx, db, sha, "tight", "2.1.0") // lvl 3
	if _, err := db.AddSightings(ctx, []Sighting{
		{Source: "socket", Operator: "socket", Subject: "pkg:npm/tight", Affected: AllVersions, Claim: ClaimMalicious, Basis: BasisPredicted},
	}); err != nil {
		t.Fatalf("AddSightings: %v", err)
	}
	rec, err := db.LookupRecord(ctx, sha, "", "")
	if err != nil {
		t.Fatalf("LookupRecord: %v", err)
	}
	if rec.FiresAt == nil || *rec.FiresAt != 3 {
		t.Fatalf("FiresAt = %v, want the measured 3; a weak citation loosened it to 100", rec.FiresAt)
	}
}

// The sentinel trap: -1 means "fires at no budget", the ABSENCE of a level.
// Ordering it numerically against a floor would leave it as -1 — reported as
// benign — for an artifact three operators call malware.
func TestLookupRecordFloorsTheBenignSentinel(t *testing.T) {
	ctx := context.Background()
	db := openTestDB(t)

	const sha = "eeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeee"
	mustInsertAnalyzed(t, ctx, db, sha, "clean", "1.0.0")
	if err := db.UpdateLitmusResult(ctx, sha, []byte(`{"v":"7","lvl":-1,"eng":"2.8.0"}`)); err != nil {
		t.Fatalf("UpdateLitmusResult: %v", err)
	}
	if _, err := db.AddSightings(ctx, []Sighting{
		{Source: "osv", Operator: "ossf-malpkgs", Subject: "pkg:npm/clean", Affected: AllVersions, Claim: ClaimMalicious, Basis: BasisReviewed},
		{Source: "aikido", Operator: "aikido", Subject: "pkg:npm/clean", Affected: AllVersions, Claim: ClaimMalicious, Basis: BasisPredicted},
	}); err != nil {
		t.Fatalf("AddSightings: %v", err)
	}
	rec, err := db.LookupRecord(ctx, sha, "", "")
	if err != nil {
		t.Fatalf("LookupRecord: %v", err)
	}
	if rec.FiresAt == nil || *rec.FiresAt != 10 {
		t.Fatalf("FiresAt = %v, want 10: -1 is the absence of a level, not the tightest one", rec.FiresAt)
	}
	if db.CorroborationStats().Tightened == 0 {
		t.Error("overriding a measured verdict must be counted; it is the population this feature is riskiest in")
	}
}

// A record the ledger contributed to is only correct while the ledger has not
// moved, so it must carry an expiry. One without would be pinned for recordTTL
// — a week — and a retraction would never reach a caller.
func TestLedgerBackedRecordsAgeOut(t *testing.T) {
	if ledgerTTL <= 0 {
		t.Fatal("a ledger-backed record must be time-bound")
	}
	if ledgerTTL > recordTTL {
		t.Fatalf("ledgerTTL %v outlives the pool's own %v", ledgerTTL, recordTTL)
	}
}

// sha256 is the identity a caller compares to prove two spellings name one
// artifact. A record standing on citations for a package nothing has analyzed
// names no bytes, and "" is not "none" — every empty string compares equal to
// every other, so two unrelated derived records would read as the same file.
func TestDerivedRecordNamesNoBytesRatherThanEmptyOnes(t *testing.T) {
	ctx := context.Background()
	db := openTestDB(t)

	if _, err := db.AddSightings(ctx, []Sighting{
		{Source: "osv", Operator: "ossf-malpkgs", Subject: "pkg:npm/nobytes", Affected: AllVersions, Claim: ClaimMalicious, Basis: BasisReviewed},
		{Source: "aikido", Operator: "aikido", Subject: "pkg:npm/nobytes", Affected: AllVersions, Claim: ClaimMalicious, Basis: BasisPredicted},
	}); err != nil {
		t.Fatalf("AddSightings: %v", err)
	}
	rec, err := db.LookupRecord(ctx, "", "pkg:npm/nobytes", "1.0.0")
	if err != nil {
		t.Fatalf("LookupRecord: %v", err)
	}
	if rec.SHA256 != nil {
		t.Errorf("SHA256 = %q, want nil: this record describes a package, not an artifact", *rec.SHA256)
	}

	// A digest-subject citation does name bytes, and must still say so.
	const sha = "ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff"
	if _, err := db.AddSightings(ctx, []Sighting{
		{Source: "bazaar", Operator: "abuse.ch", Subject: sha, Affected: AllVersions, Claim: ClaimMalicious, Basis: BasisHosted},
	}); err != nil {
		t.Fatalf("AddSightings: %v", err)
	}
	byDigest, err := db.LookupRecord(ctx, sha, "", "")
	if err != nil {
		t.Fatalf("LookupRecord by digest: %v", err)
	}
	if byDigest.SHA256 == nil || *byDigest.SHA256 != sha {
		t.Errorf("SHA256 = %v, want the digest that was cited", byDigest.SHA256)
	}
}
