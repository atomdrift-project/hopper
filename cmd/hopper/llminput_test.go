package main

import (
	"encoding/hex"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/atomdrift-project/hopper/store"
)

// llmInputPath is the LLM input route of the file with hex digest sha.
func llmInputPath(sha string) string { return "/v1/files/" + sha + "/llm-input" }

// serve sends one request with body to mux and returns the recorder.
func serve(mux http.Handler, method, target string, body io.Reader) *httptest.ResponseRecorder {
	r := httptest.NewRequest(method, target, body)
	w := httptest.NewRecorder()
	mux.ServeHTTP(w, r)
	return w
}

// endless is a body that never ends, counting what was read of it.
type endless struct{ read int64 }

func (e *endless) Read(p []byte) (int, error) {
	e.read += int64(len(p))
	return len(p), nil
}

// An input is stored, read back, replaced, and refused for a file hopper
// does not know, a malformed digest, an empty body and one over the cap,
// which is not read past the cap.
func TestLLMInputRoutes(t *testing.T) {
	api, _, pool := verdictAPI(t)
	queueFiles(t, pool, store.QueueDescribe, "d", 1)
	sha := hexSum([]byte("d0"))
	mux := http.NewServeMux()
	api.registerAPI(mux)

	if w := serve(mux, http.MethodGet, llmInputPath(sha), http.NoBody); w.Code != http.StatusNotFound ||
		!strings.Contains(w.Body.String(), "no_llm_input") {
		t.Errorf("GET before any upload: %d %s, want 404 no_llm_input", w.Code, w.Body)
	}
	for _, input := range []string{"first\x00\xff", "second, longer"} {
		if w := serve(mux, http.MethodPut, llmInputPath(sha), strings.NewReader(input)); w.Code != http.StatusNoContent {
			t.Fatalf("PUT %q: %d %s, want 204", input, w.Code, w.Body)
		}
		w := serve(mux, http.MethodGet, llmInputPath(sha), http.NoBody)
		if w.Code != http.StatusOK || w.Body.String() != input || w.Header().Get("Content-Type") != "application/octet-stream" {
			t.Errorf("GET after PUT %q: %d %q %v", input, w.Code, w.Body, w.Header())
		}
	}

	for name, tc := range map[string]struct {
		target string
		body   io.Reader
		want   int
	}{
		"unknown file":     {llmInputPath(hexSum([]byte("nobody"))), strings.NewReader("x"), http.StatusNotFound},
		"malformed digest": {llmInputPath(strings.Repeat("Z", 64)), strings.NewReader("x"), http.StatusBadRequest},
		"empty body":       {llmInputPath(sha), http.NoBody, http.StatusBadRequest},
		"declared too big": {llmInputPath(sha), strings.NewReader(strings.Repeat("x", maxLLMInput+1)), http.StatusRequestEntityTooLarge},
	} {
		if w := serve(mux, http.MethodPut, tc.target, tc.body); w.Code != tc.want {
			t.Errorf("%s: %d %s, want %d", name, w.Code, w.Body, tc.want)
		}
	}

	// No Content-Length: the cap is enforced while reading.
	body := &endless{}
	r := httptest.NewRequest(http.MethodPut, llmInputPath(sha), body)
	r.ContentLength = -1
	w := httptest.NewRecorder()
	mux.ServeHTTP(w, r)
	if w.Code != http.StatusRequestEntityTooLarge {
		t.Errorf("endless body: %d %s, want 413", w.Code, w.Body)
	}
	if body.read > maxLLMInput+1 {
		t.Errorf("endless body: read %d bytes, want no more than the cap and one", body.read)
	}
	if w := serve(mux, http.MethodGet, llmInputPath(sha), http.NoBody); w.Body.String() != "second, longer" {
		t.Errorf("a refused upload replaced the stored input: %q", w.Body)
	}
}

// A file to describe whose input hopper holds is handed out saying so, on
// the wire too; a first scan never is.
func TestLLMInputClaim(t *testing.T) {
	api, st, pool := verdictAPI(t)
	queueFiles(t, pool, store.QueueDescribe, "d", 1)
	queueFiles(t, pool, store.QueueNew, "n", 9)
	sha := hexSum([]byte("d0"))
	sum, err := hex.DecodeString(sha)
	if err != nil {
		t.Fatal(err)
	}
	if _, _, err := st.SetLLMInput(t.Context(), sum, []byte("input")); err != nil {
		t.Fatal(err)
	}
	jobs := handOut(t, api, 10, true)
	described := 0
	for _, j := range jobs {
		if j.Tier != tierMissingLLM {
			if j.HasLLMInput {
				t.Errorf("%s job %s says it has an LLM input", j.Tier, j.SHA256)
			}
			continue
		}
		described++
		if j.SHA256 != sha || !j.HasLLMInput {
			t.Errorf("describe job %+v, want %s with its input", j, sha)
		}
		wire, err := json.Marshal(j)
		if err != nil || !strings.Contains(string(wire), `"has_llm_input":true`) {
			t.Errorf("describe job on the wire: %s, %v", wire, err)
		}
	}
	if described != 1 {
		t.Errorf("%d describe jobs in %+v, want 1", described, jobs)
	}
}

// Without the verdict store the routes answer 501.
func TestLLMInputNeedsVerdictStore(t *testing.T) {
	mux := http.NewServeMux()
	(&apiServer{tracker: newWorkerTracker()}).registerAPI(mux)
	sha := strings.Repeat("a", 64)
	for _, method := range []string{http.MethodPut, http.MethodGet} {
		if w := serve(mux, method, llmInputPath(sha), strings.NewReader("x")); w.Code != http.StatusNotImplemented {
			t.Errorf("%s without the verdict store: %d %s, want 501", method, w.Code, w.Body)
		}
	}
}

// A replica keeps no LLM inputs: it relays both routes to the primary, and
// without a relay refuses them.
func TestLLMInputOnReplica(t *testing.T) {
	path := llmInputPath(strings.Repeat("a", 64))
	refusing := newReplicaMux(t, "", "")
	for _, method := range []string{http.MethodPut, http.MethodGet} {
		if w := serve(refusing, method, path, strings.NewReader("input")); w.Code != http.StatusForbidden {
			t.Errorf("%s on a replica without a relay: %d, want 403", method, w.Code)
		}
	}
	primary, rec := newRelayPrimary(t, http.StatusNoContent, "")
	relaying := newReplicaMux(t, primary.URL, "")
	if w := serve(relaying, http.MethodPut, path, strings.NewReader("input")); w.Code != http.StatusNoContent {
		t.Errorf("PUT via relay: %d, want the primary's 204", w.Code)
	}
	if rec.method != http.MethodPut || rec.path != path || rec.body != "input" {
		t.Errorf("primary saw %s %s %q, want PUT %s \"input\"", rec.method, rec.path, rec.body, path)
	}
	serve(relaying, http.MethodGet, path, http.NoBody)
	if rec.method != http.MethodGet || rec.path != path {
		t.Errorf("primary saw %s %s, want GET %s", rec.method, rec.path, path)
	}
}
