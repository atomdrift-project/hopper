package main

import (
	"bytes"
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"unicode/utf8"

	"codeberg.org/atomdrift/hopper"
)

func TestTrimClientError(t *testing.T) {
	in := "cleave failed:\n\n   Failed to load traits\tfrom /usr/local/share/litmus/traits due to many validation errors while parsing the installed bundle"
	got := trimClientError(in)
	want := "cleave failed: Failed to load traits from /usr/local/share/litmus/traits due to many validation errors while parsing the"
	if got != want {
		t.Fatalf("trimClientError() = %q, want %q", got, want)
	}
	if utf8.RuneCountInString(got) > maxClientErrorRunes {
		t.Fatalf("trimClientError() returned %d runes, want <= %d", utf8.RuneCountInString(got), maxClientErrorRunes)
	}
}

func TestTrimClientErrorCountsRunes(t *testing.T) {
	in := strings.Repeat("•", maxClientErrorRunes+10)
	got := trimClientError(in)
	if utf8.RuneCountInString(got) != maxClientErrorRunes {
		t.Fatalf("trimClientError() returned %d runes, want %d", utf8.RuneCountInString(got), maxClientErrorRunes)
	}
	if !utf8.ValidString(got) {
		t.Fatal("trimClientError() returned invalid UTF-8")
	}
}

func TestHandleResultStoresAfterRequestContextCanceled(t *testing.T) {
	ctx := context.Background()
	db := mustOpenDB(t, ctx, t.TempDir()+"/hopper.db")
	defer db.Close()
	if err := db.Migrate(ctx); err != nil {
		t.Fatalf("Migrate: %v", err)
	}

	sha := "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
	if err := db.InsertSample(ctx, &hopper.Sample{
		SHA256:      sha,
		Source:      "test",
		Path:        "bad/sample.bin",
		Label:       "bad",
		LabelSource: "test",
	}); err != nil {
		t.Fatalf("InsertSample: %v", err)
	}

	raw := json.RawMessage(`{"fs":[{"sha":"` + sha + `","type":"elf","dp":0}]}`)
	body, err := json.Marshal(resultRequest{
		SHA256: sha,
		Worker: "worker1",
		Raw:    raw,
		ML:     json.RawMessage(`{}`),
	})
	if err != nil {
		t.Fatalf("Marshal: %v", err)
	}

	reqCtx, cancelReq := context.WithCancel(ctx)
	cancelReq()
	req := httptest.NewRequest(http.MethodPost, "/api/result", bytes.NewReader(body)).WithContext(reqCtx)
	rec := httptest.NewRecorder()
	api := &apiServer{db: db, tracker: newWorkerTracker(), progress: &loadProgress{}}

	api.handleResult(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, body = %s", rec.Code, rec.Body.String())
	}

	sample, err := db.SampleBySHA256(ctx, sha)
	if err != nil {
		t.Fatalf("SampleBySHA256: %v", err)
	}
	if len(sample.CleaveResult) == 0 {
		t.Fatal("cleave result was not stored")
	}
}
