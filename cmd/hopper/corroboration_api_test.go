package main

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/atomdrift-project/hopper"
)

// The endpoint reads process counters, so it must answer without a database
// query — that is what makes it safe to poll and safe on a replica.
func TestCorroborationStatusReportsBothDirectionsSeparately(t *testing.T) {
	api := newV1API(t, context.Background())

	rec := httptest.NewRecorder()
	api.handleCorroborationStatus(rec, httptest.NewRequest(http.MethodGet, "/_/corroboration", http.NoBody))
	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200: %s", rec.Code, rec.Body.String())
	}
	if got := rec.Header().Get("Cache-Control"); got != "no-store" {
		t.Errorf("Cache-Control = %q, want no-store: counters are a moment, not a document", got)
	}

	var body struct {
		Ledger struct {
			CitedButNotFlagged *uint64 `json:"cited_but_not_flagged"`
			FlaggedButNotCited *uint64 `json:"flagged_but_not_cited"`
		} `json:"ledger"`
		Floor struct {
			Derived   *uint64 `json:"derived"`
			Tightened *uint64 `json:"tightened"`
		} `json:"floor"`
	}
	if err := json.Unmarshal(rec.Body.Bytes(), &body); err != nil {
		t.Fatalf("decode: %v", err)
	}
	// Present even at zero. An operator has to be able to tell "no
	// disagreement" from "this build does not report it".
	if body.Ledger.CitedButNotFlagged == nil || body.Ledger.FlaggedButNotCited == nil {
		t.Error("a missed mark and a missed clear must each be reported; a combined figure hides which moved")
	}
	if body.Floor.Derived == nil || body.Floor.Tightened == nil {
		t.Error("the floor's own effect must be visible, especially the count that overrides measurement")
	}
}

// End to end: a real lookup over the real route must move the counters. A
// status endpoint reporting a number nothing increments is worse than no
// endpoint, because it reads as evidence of health.
func TestCorroborationStatusTracksTheLookupPath(t *testing.T) {
	ctx := context.Background()
	api := newV1API(t, ctx)

	derived := func() float64 {
		t.Helper()
		rec := httptest.NewRecorder()
		api.handleCorroborationStatus(rec, httptest.NewRequest(http.MethodGet, "/_/corroboration", http.NoBody))
		var body struct {
			Floor struct {
				Derived float64 `json:"derived"`
			} `json:"floor"`
		}
		if err := json.Unmarshal(rec.Body.Bytes(), &body); err != nil {
			t.Fatalf("decode: %v", err)
		}
		return body.Floor.Derived
	}

	before := derived()
	if _, err := api.db.AddSightings(ctx, []hopper.Sighting{
		{Source: "osv", Operator: "ossf-malpkgs", Subject: "pkg:npm/tracked", Claim: hopper.ClaimMalicious, Basis: hopper.BasisReviewed},
		{Source: "aikido", Operator: "aikido", Subject: "pkg:npm/tracked", Claim: hopper.ClaimMalicious, Basis: hopper.BasisPredicted},
	}); err != nil {
		t.Fatalf("AddSightings: %v", err)
	}

	r := httptest.NewRequest(http.MethodGet, "/v1/lookup?purl=pkg:npm/tracked@1.0.0", http.NoBody)
	rec := httptest.NewRecorder()
	api.handleV1Lookup(rec, r)
	if rec.Code != http.StatusOK {
		t.Fatalf("lookup status = %d, want 200: %s", rec.Code, rec.Body.String())
	}
	var answer struct {
		FiresAt       *int    `json:"fires_at"`
		EngineVersion *string `json:"engine_version"`
	}
	if err := json.Unmarshal(rec.Body.Bytes(), &answer); err != nil {
		t.Fatalf("decode lookup: %v", err)
	}
	if answer.FiresAt == nil || *answer.FiresAt != 10 {
		t.Errorf("fires_at = %v, want 10 from two independent operators", answer.FiresAt)
	}
	if answer.EngineVersion != nil {
		t.Error("engine_version must stay null: no engine produced this")
	}
	if after := derived(); after <= before {
		t.Errorf("derived counter = %v, was %v: the endpoint does not observe the path it describes", after, before)
	}
}

// A producer too old to send a basis, or newer than this build and sending one
// it does not recognize, must land on the weakest value. Crediting a string we
// cannot interpret is what would let an unknown source climb the ladder.
func TestSightingBasisRefusesToInterpretTheUnknown(t *testing.T) {
	for _, tc := range []struct {
		in   string
		want hopper.Basis
	}{
		{"hosted", hopper.BasisHosted},
		{"reviewed", hopper.BasisReviewed},
		{" reviewed ", hopper.BasisReviewed},
		{"predicted", hopper.BasisPredicted},
		{"", hopper.BasisPredicted},
		{"adjudicated-by-vibes", hopper.BasisPredicted},
		{"HOSTED", hopper.BasisPredicted}, // the ledger's spelling is lowercase
	} {
		if got := sightingBasis(tc.in); got != tc.want {
			t.Errorf("sightingBasis(%q) = %q, want %q", tc.in, got, tc.want)
		}
	}
}
