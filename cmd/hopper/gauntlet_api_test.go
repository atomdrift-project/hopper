package main

import (
	"encoding/json"
	"net/http"
	"testing"

	"github.com/atomdrift-project/hopper"
)

func TestGauntletAPIReplayAndConflict(t *testing.T) {
	api := newTriageAPI(t, t.Context())
	run := hopper.GauntletRun{Producer: "test", Source: "fixture", ObservedAt: "2026-01-01T00:00:00Z", Complete: true}
	payload, _ := json.Marshal(run)
	for i := 0; i < 2; i++ {
		rec := postJSON(t, api.handleGauntletRun, "/api/gauntlet/runs", string(payload))
		if rec.Code != http.StatusOK {
			t.Fatalf("replay %d: %d %s", i, rec.Code, rec.Body.String())
		}
	}
	run.Complete = false
	payload, _ = json.Marshal(run)
	if rec := postJSON(t, api.handleGauntletRun, "/api/gauntlet/runs", string(payload)); rec.Code != http.StatusConflict {
		t.Fatalf("conflict: %d %s", rec.Code, rec.Body.String())
	}
	for _, bad := range []string{`{}`, `{"producer":"x","source":"y"} {}`, `{"producer":"x","source":"y","observed_at":"yesterday"}`} {
		if rec := postJSON(t, api.handleGauntletRun, "/api/gauntlet/runs", bad); rec.Code != http.StatusBadRequest {
			t.Fatalf("bad input %s: %d", bad, rec.Code)
		}
	}
}
