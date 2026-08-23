package main

import (
	"net/http"
	"net/http/httptest"
	"strconv"
	"testing"

	"github.com/atomdrift-project/hopper"
)

// An artifact we hold but have not analyzed is "accepted, still working", not
// "success, nothing to send". A caller can act on the first and cannot on the
// second, which is the whole reason to distinguish them.
func TestUnanalyzedSampleAnswersAccepted(t *testing.T) {
	w := httptest.NewRecorder()
	writeSampleEnvelope(w, &hopper.Sample{SHA256: "abc"})

	if w.Code != http.StatusAccepted {
		t.Errorf("status = %d, want %d", w.Code, http.StatusAccepted)
	}
	if got := w.Header().Get("X-Sha256"); got != "abc" {
		t.Errorf("X-Sha256 = %q, want the digest even with no body", got)
	}
	after, err := strconv.Atoi(w.Header().Get("Retry-After"))
	if err != nil || after <= 0 {
		t.Errorf("Retry-After = %q, want a positive number of seconds", w.Header().Get("Retry-After"))
	}
	if w.Body.Len() != 0 {
		t.Errorf("a queued sample has no envelope to send, got %d bytes", w.Body.Len())
	}
}

func TestAnalyzedSampleAnswersOK(t *testing.T) {
	w := httptest.NewRecorder()
	writeSampleEnvelope(w, &hopper.Sample{SHA256: "abc", CleaveResult: []byte(`{"v":"8"}`)})

	if w.Code != http.StatusOK {
		t.Errorf("status = %d, want 200", w.Code)
	}
	if w.Header().Get("Retry-After") != "" {
		t.Error("a finished sample must not ask the caller to come back")
	}
	if w.Body.Len() == 0 {
		t.Error("an analyzed sample should carry its envelope")
	}
}
