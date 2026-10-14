package main

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/atomdrift-project/hopper"
)

func TestSightingsAncestryAPIRequiresCompleteKnownLineage(t *testing.T) {
	db := mustOpenDB(t, t.Context(), t.TempDir()+"/hopper.db")
	defer db.Close()
	if err := db.Migrate(t.Context()); err != nil {
		t.Fatal(err)
	}
	sha := strings.Repeat("a", 64)
	api := &apiServer{db: db}
	request := func(query string) *httptest.ResponseRecorder {
		r := httptest.NewRequest(http.MethodGet, "/api/sightings/ancestry?"+query, http.NoBody)
		w := httptest.NewRecorder()
		api.handleSightingsAncestry(w, r)
		return w
	}
	if w := request("sha256=" + sha); w.Code != http.StatusNotFound {
		t.Fatalf("unknown sample = %d: %s", w.Code, w.Body.String())
	}
	if err := db.InsertSample(t.Context(), &hopper.Sample{SHA256: sha, Path: "good/sample", Label: "good"}); err != nil {
		t.Fatal(err)
	}
	w := request("sha256=" + sha)
	var body struct {
		Complete bool                                `json:"complete"`
		BySHA256 map[string]hopper.SightingsAncestry `json:"by_sha256"`
	}
	if err := json.Unmarshal(w.Body.Bytes(), &body); err != nil {
		t.Fatal(err)
	}
	if w.Code != http.StatusOK || !body.Complete || !body.BySHA256[sha].Checked {
		t.Fatalf("clear check = %d: %s", w.Code, w.Body.String())
	}
	if _, err := db.AddSightings(t.Context(), []hopper.Sighting{{Subject: sha, Source: "triage"}}); err != nil {
		t.Fatal(err)
	}
	w = request("sha256=" + sha)
	if err := json.Unmarshal(w.Body.Bytes(), &body); err != nil {
		t.Fatal(err)
	}
	if w.Code != http.StatusOK || len(body.BySHA256[sha].Sightings) != 1 {
		t.Fatalf("sighted check = %d: %s", w.Code, w.Body.String())
	}
	for _, query := range []string{"", "sha256=invalid"} {
		if w := request(query); w.Code != http.StatusBadRequest {
			t.Fatalf("invalid query %q = %d", query, w.Code)
		}
	}
}
