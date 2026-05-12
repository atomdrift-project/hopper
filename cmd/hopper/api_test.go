package main

import (
	"bytes"
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"
	"unicode/utf8"

	"codeberg.org/atomdrift/hopper"
)

func TestWorkerTrackerClaimAndRelease(t *testing.T) {
	wt := newWorkerTracker()
	cands := []hopper.ClaimJob{
		{SHA256: "a", Path: "p/a"},
		{SHA256: "b", Path: "p/b"},
		{SHA256: "c", Path: "p/c"},
	}

	got := wt.tryClaimBatch(cands, "w1", time.Minute, 10)
	if len(got) != 3 {
		t.Fatalf("first claim: got %d, want 3", len(got))
	}

	// Re-claim while w1's hold is fresh: w2 should get nothing.
	got = wt.tryClaimBatch(cands, "w2", time.Minute, 10)
	if len(got) != 0 {
		t.Fatalf("w2 saw held claims as available: %+v", got)
	}

	// w1 finishes "a"; w2 can now take it.
	wt.release("a")
	got = wt.tryClaimBatch(cands, "w2", time.Minute, 10)
	if len(got) != 1 || got[0].SHA256 != "a" {
		t.Fatalf("after release: got %+v, want [{a ...}]", got)
	}
}

func TestWorkerTrackerClaimExpiry(t *testing.T) {
	wt := newWorkerTracker()
	cands := []hopper.ClaimJob{{SHA256: "exp1", Path: "p/x"}}

	if got := wt.tryClaimBatch(cands, "w1", time.Minute, 1); len(got) != 1 {
		t.Fatalf("first claim: got %d, want 1", len(got))
	}

	// Zero expiry treats every claim as already-expired and re-issues it.
	got := wt.tryClaimBatch(cands, "w2", 0, 1)
	if len(got) != 1 || got[0].SHA256 != "exp1" {
		t.Fatalf("zero-expiry steal: got %+v, want [{exp1 ...}]", got)
	}
	if wt.activeClaims("w1") != 0 || wt.activeClaims("w2") != 1 {
		t.Fatalf("active claims after steal: w1=%d w2=%d, want 0/1", wt.activeClaims("w1"), wt.activeClaims("w2"))
	}
}

func TestWorkerTrackerClaimLimitPrunesExpiredClaims(t *testing.T) {
	wt := newWorkerTracker()
	cands := make([]hopper.ClaimJob, maxClaimCount)
	for i := range cands {
		cands[i] = hopper.ClaimJob{SHA256: string(rune('a' + i)), Path: "p/x"}
	}
	if got := wt.tryClaimBatch(cands, "w1", time.Minute, maxClaimCount); len(got) != maxClaimCount {
		t.Fatalf("first claim: got %d, want %d", len(got), maxClaimCount)
	}
	if got := wt.claimLimit("w1"); got != 0 {
		t.Fatalf("fresh claimLimit = %d, want 0", got)
	}

	wt.mu.Lock()
	for sha, c := range wt.claims {
		c.at = time.Now().Add(-claimExpiry - time.Minute)
		wt.claims[sha] = c
	}
	wt.mu.Unlock()

	if got := wt.claimLimit("w1"); got != maxClaimCount {
		t.Fatalf("expired claimLimit = %d, want %d", got, maxClaimCount)
	}
	if got := wt.activeClaims("w1"); got != 0 {
		t.Fatalf("active claims after prune = %d, want 0", got)
	}
}

func TestWorkerTrackerOldestPerWorkerPrunesStale(t *testing.T) {
	wt := newWorkerTracker()
	wt.claims["fresh"] = claim{worker: "w1", path: "fresh.bin", at: time.Now()}
	wt.claims["stale"] = claim{worker: "w1", path: "stale.bin", at: time.Now().Add(-time.Hour)}
	wt.workers["w1"] = &workerStats{ActiveClaims: 2}

	out := wt.oldestPerWorker(time.Minute)
	if len(out) != 1 || out["w1"].Path != "fresh.bin" {
		t.Fatalf("oldestPerWorker = %+v, want only fresh.bin for w1", out)
	}
	if _, stillThere := wt.claims["stale"]; stillThere {
		t.Fatal("stale claim was not pruned during oldestPerWorker walk")
	}
	if got := wt.activeClaims("w1"); got != 1 {
		t.Fatalf("active claims after stale prune = %d, want 1", got)
	}
}

func TestWorkerToolParsingDistinguishesLegacyFromEmptyReport(t *testing.T) {
	if tools, caps := parseWorkerTools(nil); tools != "" || caps != nil {
		t.Fatalf("absent tools = %q/%v, want legacy nil capabilities", tools, caps)
	}
	tools, caps := parseWorkerTools([]string{""})
	if tools != "" || caps == nil {
		t.Fatalf("empty tools report = %q/%v, want present empty capability set", tools, caps)
	}
	if workerCanAnalyzeFileType("elf", caps) {
		t.Fatal("empty capability set should not accept elf")
	}
}

func TestWorkerCanAnalyzeFileTypeRequiresReportedTools(t *testing.T) {
	tools := workerToolSet{"rizin": true, "upx": true, "innoextract": true, "7z": true}
	for _, ft := range []string{"elf", "pe", "macho", "java_class", "python_bytecode", "msi", "cab", "sevenz"} {
		if !workerCanAnalyzeFileType(ft, &tools) {
			t.Fatalf("fully equipped worker rejected %s", ft)
		}
	}

	noUPX := workerToolSet{"rizin": true, "innoextract": true, "7z": true}
	if workerCanAnalyzeFileType("elf", &noUPX) || workerCanAnalyzeFileType("pe", &noUPX) {
		t.Fatal("missing upx should block elf and pe")
	}

	noInno := workerToolSet{"rizin": true, "upx": true, "7z": true}
	if workerCanAnalyzeFileType("msi", &noInno) || workerCanAnalyzeFileType("pe", &noInno) {
		t.Fatal("missing innoextract should block msi and pe")
	}

	noRizin := workerToolSet{"upx": true, "innoextract": true, "7z": true}
	if workerCanAnalyzeFileType("elf", &noRizin) || workerCanAnalyzeFileType("macho", &noRizin) {
		t.Fatal("missing rizin should block binary formats")
	}
	if !workerCanAnalyzeFileType("python", &noRizin) {
		t.Fatal("missing rizin should not block non-binary script formats")
	}

	no7z := workerToolSet{"rizin": true, "upx": true, "innoextract": true}
	if workerCanAnalyzeFileType("cab", &no7z) || workerCanAnalyzeFileType("seven_z", &no7z) {
		t.Fatal("missing 7z should block 7z/cab formats")
	}
}

func TestFilterCandidatesByWorkerToolsKeepsCompatibleJobsUnclaimed(t *testing.T) {
	tools := workerToolSet{"7z": true}
	cands := []hopper.ClaimJob{
		{SHA256: "elf", FileType: "elf"},
		{SHA256: "py", FileType: "python"},
		{SHA256: "cab", FileType: "cab"},
	}
	got := filterCandidatesByWorkerTools(cands, &tools)
	if len(got) != 2 || got[0].SHA256 != "py" || got[1].SHA256 != "cab" {
		t.Fatalf("filtered candidates = %+v, want python and cab only", got)
	}

	legacy := filterCandidatesByWorkerTools(cands, nil)
	if len(legacy) != 3 {
		t.Fatalf("legacy absent tool report filtered candidates: %+v", legacy)
	}
}

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
