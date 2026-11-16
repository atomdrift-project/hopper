package main

import (
	"fmt"
	"net/http"
	"strings"
	"testing"
	"time"
)

// An acquirer's writes go through hopper: claims marked attempted and
// retracted by key, sightings backfilled with their source's dates, and a
// target claimed once and finished.
func TestLedgerRoutes(t *testing.T) {
	api, _, pool := verdictAPI(t)
	ctx := t.Context()
	mux := http.NewServeMux()
	api.registerAPI(mux)
	send := func(target, body string) (int, string) {
		t.Helper()
		return call(t, mux.ServeHTTP, http.MethodPost, target, body, nil)
	}

	if code, out := send("/v1/sightings", `[
		{"source":"osv","subject":"pkg:npm/evil@1.0.0","claim":"malicious","handle":"an-42"},
		{"source":"osv","subject":"pkg:npm/worse","affected":"=2.0.0","claim":"malicious"}]`); code != http.StatusOK {
		t.Fatalf("sightings: %d %s", code, out)
	}
	var handle string
	if err := pool.QueryRow(ctx, `SELECT handle FROM sightings WHERE subject = 'pkg:npm/evil'`).Scan(&handle); err != nil || handle != "an-42" {
		t.Errorf("handle %q, %v; want the source's id kept", handle, err)
	}
	code, out := send("/v1/sightings/attempted", `[{"source":"osv","subject":"pkg:npm/evil","affected":"1.0.0"}]`)
	if code != http.StatusOK || !strings.Contains(out, `"changed":1`) {
		t.Errorf("attempted: %d %s", code, out)
	}
	if _, out := send("/v1/sightings/attempted", `[{"source":"osv","subject":"pkg:npm/evil","affected":"1.0.0"}]`); !strings.Contains(out, `"changed":0`) {
		t.Errorf("attempted again: %s, want the first time kept", out)
	}
	var attempted int
	if err := pool.QueryRow(ctx, `SELECT count(*) FROM sightings WHERE attempted_at IS NOT NULL`).Scan(&attempted); err != nil || attempted != 1 {
		t.Errorf("attempted rows %d, %v", attempted, err)
	}
	if _, out := send("/v1/sightings/retract", `[{"source":"osv","subject":"pkg:npm/worse","affected":"=2.0.0"}]`); !strings.Contains(out, `"changed":1`) {
		t.Errorf("retract: %s", out)
	}
	if code, _ := send("/v1/sightings/retract", `[{"source":"","subject":"x"}]`); code != http.StatusBadRequest {
		t.Errorf("retract without a source: %d, want 400", code)
	}

	published := time.Date(2025, 3, 1, 0, 0, 0, 0, time.UTC)
	if code, out := send("/v1/sightings?backfill=1", fmt.Sprintf(`[
		{"source":"feed","subject":"pkg:npm/old","claim":"malicious","published_at":%q},
		{"source":"feed","subject":"pkg:npm/undated","claim":"malicious"}]`, published.Format(time.RFC3339))); code != http.StatusOK {
		t.Fatalf("backfill: %d %s", code, out)
	}
	dated := func(subject string) time.Time {
		t.Helper()
		var seen time.Time
		if err := pool.QueryRow(ctx, `SELECT first_seen FROM sightings WHERE subject = $1`, subject).Scan(&seen); err != nil {
			t.Fatal(err)
		}
		return seen.UTC()
	}
	if got := dated("pkg:npm/old"); !got.Equal(published) {
		t.Errorf("backfilled first_seen %v, want the source's date", got)
	}
	if got := dated("pkg:npm/undated"); !got.Equal(time.Unix(0, 0).UTC()) {
		t.Errorf("undated backfill first_seen %v, want the epoch", got)
	}
	if got := dated("pkg:npm/evil"); time.Since(got) > time.Minute {
		t.Errorf("live first_seen %v, want now", got)
	}

	claim := `{"target":"https://example.test/a.tgz","lease_seconds":1800}`
	if _, out := send("/v1/acquisitions/claim", claim); !strings.Contains(out, `"claimed":true`) {
		t.Errorf("claim: %s", out)
	}
	if _, out := send("/v1/acquisitions/claim", claim); !strings.Contains(out, `"claimed":false`) {
		t.Errorf("second claim: %s, want refused", out)
	}
	if code, _ := send("/v1/acquisitions/claim", `{"target":"x","lease_seconds":0}`); code != http.StatusBadRequest {
		t.Errorf("claim without a lease: %d, want 400", code)
	}
	if _, out := send("/v1/acquisitions/finish",
		`{"target":"https://example.test/a.tgz","acquired":false,"retry_after_seconds":3600,"error":"gone"}`); !strings.Contains(out, `"finished":true`) {
		t.Errorf("finish: %s", out)
	}
	var reason string
	var finished bool
	if err := pool.QueryRow(ctx, `SELECT last_error, finished_at IS NOT NULL FROM sighting_acquisitions`).Scan(&reason, &finished); err != nil ||
		reason != "gone" || !finished {
		t.Errorf("acquisition row %q finished=%v, %v", reason, finished, err)
	}
	if _, out := send("/v1/acquisitions/finish", `{"target":"never-claimed"}`); !strings.Contains(out, `"finished":false`) {
		t.Errorf("finish of an unclaimed target: %s", out)
	}
}
