package main

import (
	"encoding/json"
	"fmt"
	"net/http"
	"testing"

	"github.com/atomdrift-project/hopper"
)

// gauntletRunBody is one run as gauntlet posts it, with ascan's result set.
func gauntletRunBody(t *testing.T, status string) string {
	t.Helper()
	run := hopper.GauntletRun{
		Producer: "test", Source: "fixture", ObservedAt: "2026-11-20T00:00:00Z", Complete: true,
		Samples: []hopper.GauntletSample{{
			SHA256: fmt.Sprintf("%064x", 1), Label: "bad", Eligible: true, Metadata: json.RawMessage(`{}`),
			Results: []hopper.GauntletResult{{
				Scanner: "ascan", Status: status, Payload: json.RawMessage(`{"scanner":"ascan","status":"` + status + `"}`),
			}},
		}},
	}
	b, err := json.Marshal(run)
	if err != nil {
		t.Fatal(err)
	}
	return string(b)
}

// checkGauntletRunAPI posts a run twice, a conflicting one, and invalid ones.
func checkGauntletRunAPI(t *testing.T, api *apiServer) {
	t.Helper()
	body := gauntletRunBody(t, "benign")
	for i, want := range []bool{true, false} {
		rec := postJSON(t, api.handleGauntletRun, "/v1/gauntlet/runs", body)
		if rec.Code != http.StatusOK {
			t.Fatalf("post %d: %d %s", i, rec.Code, rec.Body.String())
		}
		var ack gauntletRunResponse
		if err := json.Unmarshal(rec.Body.Bytes(), &ack); err != nil {
			t.Fatal(err)
		}
		if ack.ID != hopper.GauntletRunID("test", "2026-11-20T00:00:00.000000000Z", "fixture") || ack.Inserted != want {
			t.Fatalf("post %d: %+v, want inserted=%v under the derived id", i, ack, want)
		}
	}
	if rec := postJSON(t, api.handleGauntletRun, "/v1/gauntlet/runs", gauntletRunBody(t, "detected")); rec.Code != http.StatusConflict {
		t.Fatalf("conflict: %d %s", rec.Code, rec.Body.String())
	}
	for _, bad := range []string{
		`{}`,
		`{"producer":"x","source":"y"} {}`,
		`{"producer":"x","source":"y","observed_at":"yesterday"}`,
		`{"producer":"x","source":"y","samples":[{"sha256":"nothex","label":"bad"}]}`,
	} {
		if rec := postJSON(t, api.handleGauntletRun, "/v1/gauntlet/runs", bad); rec.Code != http.StatusBadRequest {
			t.Fatalf("bad input %s: %d", bad, rec.Code)
		}
	}
}

func TestGauntletRunAPILegacy(t *testing.T) {
	checkGauntletRunAPI(t, newTriageAPI(t, t.Context()))
}

func TestGauntletRunAPIStore(t *testing.T) {
	api, _, _ := verdictAPI(t)
	checkGauntletRunAPI(t, api)
}
