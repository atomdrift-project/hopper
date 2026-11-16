package main

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/atomdrift-project/hopper"
	"github.com/atomdrift-project/hopper/store"
)

// call sends one request to h and returns the status and body.
func call(t *testing.T, h http.HandlerFunc, method, target, body string, path map[string]string) (code int, out string) {
	t.Helper()
	r := httptest.NewRequest(method, target, strings.NewReader(body))
	for k, v := range path {
		r.SetPathValue(k, v)
	}
	rec := httptest.NewRecorder()
	h(rec, r)
	return rec.Code, rec.Body.String()
}

// The producer-facing routes answer from the verdict store: what hopper
// holds, provenance read and refreshed, the hot pool, popularity, the
// ancestry check, and a cleave write-back queued as a whole scan.
func TestIntakeRoutesFromStore(t *testing.T) {
	api, st, pool := verdictAPI(t)
	ctx := t.Context()
	body, pkg, script := v8Body(t, "r1", `{"traits":[{"id":"b::fetch-exec","crit":5}]}`)
	if code, _ := post(t, api, body, true); code != http.StatusOK {
		t.Fatalf("result: %d", code)
	}
	walked := hexSum([]byte("walked"))
	if _, err := ingest(ctx, st, []*hopper.Sample{
		{SHA256: pkg, SizeBytes: 900, Path: "incoming/pkg.tgz", Source: "walk", Label: "unknown"},
		{SHA256: walked, SizeBytes: 900, Path: "incoming/walked", Source: "walk", Label: "good"},
	}, store.QueueNew); err != nil {
		t.Fatal(err)
	}
	nowhere := hexSum([]byte("nowhere"))

	code, out := call(t, api.handleKnown, http.MethodPost, "/v1/intake/held",
		`{"sha256":["`+pkg+`","`+script+`","`+nowhere+`"]}`, nil)
	var known struct {
		Known []string `json:"known"`
	}
	if err := json.Unmarshal([]byte(out), &known); err != nil || code != http.StatusOK {
		t.Fatalf("held: %d %s", code, out)
	}
	slices.Sort(known.Known)
	if want := []string{pkg, script}; !slices.Equal(known.Known, slices.Sorted(slices.Values(want))) {
		t.Errorf("held %v, want the package and the script inside it", known.Known)
	}

	if code, _ := call(t, api.handleProvenance, http.MethodGet, "/", "", map[string]string{"sha256": pkg}); code != http.StatusNotFound {
		t.Errorf("provenance of a file without one: %d, want 404", code)
	}
	prov := &hopper.Sidecar{}
	prov.Artifact.SHA256 = pkg
	prov.Artifact.Filename = "left-pad-1.3.0.tgz"
	prov.Package.PURL = "pkg:npm/left-pad@1.3.0"
	if ok, err := api.refreshProvenance(ctx, prov); err != nil || !ok {
		t.Fatalf("refresh provenance: %v, %v", ok, err)
	}
	code, out = call(t, api.handleProvenance, http.MethodGet, "/", "", map[string]string{"sha256": pkg})
	if code != http.StatusOK || !strings.Contains(out, "left-pad-1.3.0.tgz") {
		t.Errorf("provenance: %d %s", code, out)
	}
	var name string
	if err := pool.QueryRow(ctx, `SELECT n.name FROM samples s JOIN names n ON n.id = s.name_id WHERE s.sha256 = decode($1, 'hex')`,
		pkg).Scan(&name); err != nil || name != "pkg:npm/left-pad" {
		t.Errorf("release %q, %v; want the sidecar's", name, err)
	}
	prov.Artifact.SHA256 = nowhere
	if ok, err := api.refreshProvenance(ctx, prov); err != nil || ok {
		t.Errorf("refresh provenance of an unknown file: %v, %v; want false", ok, err)
	}

	before := time.Now().Add(time.Hour).UTC().Format(time.RFC3339Nano)
	code, out = call(t, api.handleIncomingLocations, http.MethodGet, "/v1/storage/incoming?class=classified&before="+before, "", nil)
	var page incomingLocationsResponse
	if err := json.Unmarshal([]byte(out), &page); err != nil || code != http.StatusOK ||
		len(page.Locations) != 1 || page.Locations[0].SHA256 != walked || page.Locations[0].Label != "good" {
		t.Errorf("incoming, classified: %d %s", code, out)
	}
	if code, _ := call(t, api.handleIncomingLocations, http.MethodGet, "/v1/storage/incoming?class=bogus", "", nil); code != http.StatusBadRequest {
		t.Errorf("incoming, unknown class: %d, want 400", code)
	}

	code, _ = call(t, api.handlePopular, http.MethodPost, "/v1/intake/popular",
		`{"source":"top","packages":[{"purl_base":"pkg:npm/left-pad","ecosystem":"npm","rank":7}]}`, nil)
	var rank int
	if err := pool.QueryRow(ctx, `SELECT rank FROM popular_packages WHERE purl_base = 'pkg:npm/left-pad'`).Scan(&rank); code != http.StatusOK || err != nil || rank != 7 {
		t.Errorf("popular: %d, rank %d, %v", code, rank, err)
	}

	ancestry := func() string {
		t.Helper()
		code, out := call(t, api.handleSightingsAncestry, http.MethodGet, "/v1/sightings/ancestry?sha256="+script, "", nil)
		if code != http.StatusOK {
			t.Fatalf("ancestry: %d %s", code, out)
		}
		return out
	}
	if out := ancestry(); strings.Contains(out, `"sighting"`) {
		t.Errorf("ancestry before any sighting: %s", out)
	}
	if _, err := hopper.AddSightingsToStore(ctx, st, []hopper.Sighting{{
		Source: "osv", Subject: "pkg:npm/left-pad", Affected: "=1.3.0", Claim: hopper.ClaimMalicious,
	}}, "test"); err != nil {
		t.Fatal(err)
	}
	if out := ancestry(); !strings.Contains(out, `"sha256":"`+pkg+`"`) || !strings.Contains(out, "osv") {
		t.Errorf("ancestry after a sighting of the package holding it: %s", out)
	}
	if code, _ := call(t, api.handleSightingsAncestry, http.MethodGet, "/v1/sightings/ancestry?sha256="+nowhere, "", nil); code != http.StatusNotFound {
		t.Errorf("ancestry of an unknown file: %d, want 404", code)
	}

	jurors := func() int {
		t.Helper()
		var n int
		if err := pool.QueryRow(ctx, `SELECT count(*) FROM verdicts WHERE scanner_id <> 1`).Scan(&n); err != nil {
			t.Fatal(err)
		}
		return n
	}
	had := jurors()
	code, out = call(t, api.handleCleaveResult, http.MethodPost, "/api/cleave-result",
		`{"sha256":"`+walked+`","result":{"fs":[]}}`, nil)
	if code != http.StatusOK || !strings.Contains(out, `"queued"`) {
		t.Errorf("cleave result: %d %s, want the file queued for a whole scan", code, out)
	}
	if jurors() != had {
		t.Error("a cleave write-back changed the jurors' opinions")
	}
}
