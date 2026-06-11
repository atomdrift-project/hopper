package main

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
	"time"
	"unicode/utf8"

	"codeberg.org/atomdrift/hopper"
	"github.com/klauspost/compress/zstd"
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

func TestSizeClassBucketsByBounds(t *testing.T) {
	for _, tc := range []struct {
		bytes int64
		want  int
	}{
		{0, 0},
		{1<<20 - 1, 0},
		{1 << 20, 1},  // exactly 1 MiB → medium
		{32 << 20, 2}, // exactly 32 MiB → large
		{1 << 40, 2},
	} {
		if got := sizeClass(tc.bytes); got != tc.want {
			t.Errorf("sizeClass(%d) = %d, want %d", tc.bytes, got, tc.want)
		}
	}
}

func TestInterleaveBySizeClassSpreadsClassesEvenly(t *testing.T) {
	job := func(sha string, size int64) hopper.ClaimJob {
		return hopper.ClaimJob{SHA256: sha, Path: sha + ".bin", SizeBytes: size}
	}
	const big = 100 << 20

	// 4 smalls + 1 large: the large lands mid-stream (position 1/2 falls
	// between the smalls at 1/8, 3/8 and 5/8, 7/8), not at either end.
	got := interleaveBySizeClass([]hopper.ClaimJob{
		job("s1", 10), job("s2", 20), job("s3", 30), job("s4", 40), job("big", big),
	})
	want := []string{"s1", "s2", "big", "s3", "s4"}
	for i, w := range want {
		if got[i].SHA256 != w {
			t.Fatalf("position %d = %q, want %q (full: %v)", i, got[i].SHA256, w, shas(got))
		}
	}

	// An all-big run followed by all smalls must come back alternating-ish:
	// no batch prefix should be a solid block of one class.
	var cands []hopper.ClaimJob
	for i := range 4 {
		cands = append(cands, job("b"+strconv.Itoa(i), big))
	}
	for i := range 4 {
		cands = append(cands, job("t"+strconv.Itoa(i), 100))
	}
	mixed := interleaveBySizeClass(cands)
	for i := 0; i+1 < len(mixed); i += 2 {
		a, b := sizeClass(mixed[i].SizeBytes), sizeClass(mixed[i+1].SizeBytes)
		if a == b {
			t.Fatalf("positions %d,%d are both class %d (full: %v)", i, i+1, a, shas(mixed))
		}
	}

	// Stability: jobs within a class keep their input (tier) order.
	for i := 1; i < len(mixed); i++ {
		for j := range i {
			if sizeClass(mixed[j].SizeBytes) == sizeClass(mixed[i].SizeBytes) &&
				mixed[j].SHA256 > mixed[i].SHA256 {
				t.Fatalf("class-internal order not preserved: %q before %q", mixed[j].SHA256, mixed[i].SHA256)
			}
		}
	}

	// Short lists pass through untouched.
	two := []hopper.ClaimJob{job("x", big), job("y", 1)}
	if got := interleaveBySizeClass(two); got[0].SHA256 != "x" || got[1].SHA256 != "y" {
		t.Fatalf("short list reordered: %v", shas(got))
	}
}

func shas(jobs []hopper.ClaimJob) []string {
	out := make([]string, len(jobs))
	for i := range jobs {
		out[i] = jobs[i].SHA256
	}
	return out
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

func TestHandleHeartbeatRecordsTelemetryAndConvertsAges(t *testing.T) {
	api := &apiServer{tracker: newWorkerTracker()} // db nil: heartbeat must not touch it

	req := httptest.NewRequest(http.MethodGet,
		"/api/heartbeat?worker=nuc&slots=4&active=2&queue=3&rss_mb=512&load1=1.50"+
			"&fps=2.500&errs=1&oldest_s=30&done_age_s=10&err_age_s=5&err=boom&version=9.9&traits=abcde",
		http.NoBody)
	req.RemoteAddr = "127.0.0.1:1234" // loopback keeps the bare worker name
	rec := httptest.NewRecorder()

	before := time.Now()
	api.handleHeartbeat(rec, req)
	after := time.Now()

	if rec.Code != http.StatusNoContent {
		t.Fatalf("status = %d, want %d", rec.Code, http.StatusNoContent)
	}

	ws := api.tracker.workers["nuc"]
	if ws == nil {
		t.Fatal("worker not recorded in tracker")
	}
	if ws.Slots != 4 || ws.ReportedActive != 2 || ws.Queue != 3 {
		t.Errorf("slots/active/queue = %d/%d/%d, want 4/2/3", ws.Slots, ws.ReportedActive, ws.Queue)
	}
	if ws.RSSMB != 512 || ws.Load1 != 1.5 || ws.FilesPerSec != 2.5 {
		t.Errorf("rss/load/fps = %d/%.2f/%.3f, want 512/1.50/2.500", ws.RSSMB, ws.Load1, ws.FilesPerSec)
	}
	if ws.ErrorsRecent != 1 || ws.LastError != "boom" {
		t.Errorf("errors = %d/%q, want 1/\"boom\"", ws.ErrorsRecent, ws.LastError)
	}
	if ws.Version != "9.9" || ws.Traits != "abcde" {
		t.Errorf("version/traits = %q/%q, want \"9.9\"/\"abcde\"", ws.Version, ws.Traits)
	}

	// Ages are converted to absolute times anchored at receipt; each must land
	// within the handler's execution window offset by the reported age.
	assertAge := func(label string, got time.Time, ageSec int) {
		t.Helper()
		lo := before.Add(-time.Duration(ageSec) * time.Second)
		hi := after.Add(-time.Duration(ageSec) * time.Second)
		if got.Before(lo) || got.After(hi) {
			t.Errorf("%s = %v, want within [%v, %v]", label, got, lo, hi)
		}
	}
	assertAge("OldestQueueSince", ws.OldestQueueSince, 30)
	assertAge("LastCompletion", ws.LastCompletion, 10)
	assertAge("LastErrorAt", ws.LastErrorAt, 5)
}

func TestHandleHeartbeatRejectsInvalidWorker(t *testing.T) {
	api := &apiServer{tracker: newWorkerTracker()}
	req := httptest.NewRequest(http.MethodGet, "/api/heartbeat?worker=bad%20name", http.NoBody)
	rec := httptest.NewRecorder()
	api.handleHeartbeat(rec, req)
	if rec.Code != http.StatusBadRequest {
		t.Fatalf("status = %d, want %d", rec.Code, http.StatusBadRequest)
	}
	if len(api.tracker.workers) != 0 {
		t.Fatalf("invalid worker was recorded: %v", api.tracker.workers)
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
	if workerCanAnalyzeFile("ole_doc", "installers/setup.msi", &noInno) {
		t.Fatal("missing innoextract should block MSI paths even when file type is OLE")
	}

	noRizin := workerToolSet{"upx": true, "innoextract": true, "7z": true}
	if workerCanAnalyzeFileType("elf", &noRizin) || workerCanAnalyzeFileType("macho", &noRizin) {
		t.Fatal("missing rizin should block native binary formats")
	}
	if !workerCanAnalyzeFileType("java_class", &noRizin) || !workerCanAnalyzeFileType("python_bytecode", &noRizin) {
		t.Fatal("missing rizin should not block bytecode formats")
	}
	if !workerCanAnalyzeFileType("python", &noRizin) {
		t.Fatal("missing rizin should not block non-binary script formats")
	}

	no7z := workerToolSet{"rizin": true, "upx": true, "innoextract": true}
	if !workerCanAnalyzeFileType("cab", &no7z) || !workerCanAnalyzeFileType("seven_z", &no7z) {
		t.Fatal("missing 7z should not block library-backed 7z/cab archive formats")
	}
	if workerCanAnalyzeFileType("pe", &no7z) {
		t.Fatal("missing 7z should block PE SFX formats")
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

func TestResultBody(t *testing.T) {
	t.Parallel()

	want := []byte(`{"sha256":"abc","worker":"w","raw":{"fs":[]}}`)

	enc, err := zstd.NewWriter(nil)
	if err != nil {
		t.Fatalf("NewWriter: %v", err)
	}
	compressed := enc.EncodeAll(want, nil)
	if err := enc.Close(); err != nil {
		t.Fatalf("Close: %v", err)
	}

	cases := []struct {
		name     string
		encoding string
		body     []byte
		wantErr  bool
	}{
		{"identity_implicit", "", want, false},
		{"identity_explicit", "identity", want, false},
		{"zstd", "zstd", compressed, false},
		{"unsupported", "gzip", want, true},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			r := httptest.NewRequest(http.MethodPost, "/api/result", bytes.NewReader(tc.body))
			if tc.encoding != "" {
				r.Header.Set("Content-Encoding", tc.encoding)
			}
			rb, err := resultBody(r)
			if tc.wantErr {
				if err == nil {
					t.Fatal("resultBody: expected error for unsupported encoding, got nil")
				}
				return
			}
			if err != nil {
				t.Fatalf("resultBody: %v", err)
			}
			defer rb.cleanup()
			got, err := io.ReadAll(rb.body)
			if err != nil {
				t.Fatalf("ReadAll: %v", err)
			}
			if !bytes.Equal(got, want) {
				t.Fatalf("decoded body = %q, want %q", got, want)
			}
			if rb.overLimit() {
				t.Fatal("overLimit() = true for a body well under the limit")
			}
		})
	}
}

func TestSanitizeUploadFilename(t *testing.T) {
	t.Parallel()
	cases := []struct {
		in, want string
	}{
		// Happy paths.
		{"sample.exe", "sample.exe"},
		{"My Document.zip", "My Document.zip"},
		{".gitignore", ".gitignore"},
		{"unicode-名前.tar.gz", "unicode-名前.tar.gz"}, //nolint:gosmopolitan // multilingual filename coverage is the point

		// Path traversal — sanitization MUST refuse these and the caller
		// substitutes a placeholder.
		{"..", ""},
		{".", ""},
		{"...", ""},
		{"../../etc/passwd", "passwd"},
		{"..\\..\\windows\\system32", "....windowssystem32"},
		{"/etc/passwd", "passwd"},
		{"\\", ""},
		{"/", ""},

		// NUL and non-whitespace control chars stripped; whitespace-like
		// control chars (CR/LF/tab) collapse to a single space so we don't
		// silently glue words.
		{"foo\x00bar", "foobar"},
		{"foo\rbar\nbaz", "foo bar baz"},
		{"\x01\x02\x03", ""},

		// Trailing dots/spaces (Windows ignores them; "evil.exe." → "evil.exe").
		{"evil.exe.", "evil.exe"},
		{"evil.exe   ", "evil.exe"},
		{"evil.exe. . .", "evil.exe"},

		// Reserved Windows names with and without extensions.
		{"CON", ""},
		{"con.txt", ""},
		{"LPT1.bin", ""},
		{"NUL", ""},
		{"console.txt", "console.txt"}, // not reserved — stem differs

		// Whitespace collapse.
		{"a   b\t\tc", "a b c"},

		// Empty-after-sanitize → empty result.
		{"   ", ""},
	}
	for _, tc := range cases {
		got := sanitizeUploadFilename(tc.in)
		if got != tc.want {
			t.Errorf("sanitizeUploadFilename(%q) = %q, want %q", tc.in, got, tc.want)
		}
	}
}

func TestSanitizeUploadFilenameTruncationIsUTF8Safe(t *testing.T) {
	t.Parallel()
	// 100 four-byte runes (400 bytes) followed by an extension — exceeds
	// uploadFilenameMax. Result must be well-formed UTF-8 and end in .bin.
	long := strings.Repeat("𝔸", 100) + ".bin"
	got := sanitizeUploadFilename(long)
	if got == "" {
		t.Fatalf("unexpectedly empty result for %d-byte input", len(long))
	}
	if !utf8.ValidString(got) {
		t.Fatalf("truncated filename is not valid UTF-8: %q", got)
	}
	if !strings.HasSuffix(got, ".bin") {
		t.Fatalf("truncated filename lost extension: %q", got)
	}
	if len(got) > uploadFilenameMax {
		t.Fatalf("len(got)=%d exceeds uploadFilenameMax=%d", len(got), uploadFilenameMax)
	}
}

func TestCheckBrowserCSRF(t *testing.T) {
	t.Parallel()
	cases := []struct {
		name        string
		fetchSite   string
		contentType string
		wantOK      bool
	}{
		{"raw upload no headers", "", "", true},
		{"raw upload octet-stream", "same-origin", "application/octet-stream", true},
		{"cross-site blocked", "cross-site", "application/octet-stream", false},
		{"form-urlencoded blocked", "same-origin", "application/x-www-form-urlencoded", false},
		{"multipart blocked", "same-origin", "multipart/form-data; boundary=xyz", false},
		{"text/plain blocked (CORS simple)", "same-origin", "text/plain", false},
		{"json allowed", "same-origin", "application/json", true},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			r := httptest.NewRequest(http.MethodPost, "/api/upload", http.NoBody)
			if tc.fetchSite != "" {
				r.Header.Set("Sec-Fetch-Site", tc.fetchSite)
			}
			if tc.contentType != "" {
				r.Header.Set("Content-Type", tc.contentType)
			}
			gotOK := checkBrowserCSRF(r) == nil
			if gotOK != tc.wantOK {
				t.Errorf("checkBrowserCSRF ok = %v, want %v", gotOK, tc.wantOK)
			}
		})
	}
}

func TestHandleUploadAuth(t *testing.T) {
	t.Parallel()
	api := &apiServer{
		tracker:  newWorkerTracker(),
		dataRoot: t.TempDir(),
	}
	if err := api.setUploadToken("test-token-with-32-chars-or-more!!"); err != nil {
		t.Fatalf("setUploadToken rejected the test token: %v", err)
	}
	// Stub db to non-nil so we get past the "starting" guard. Auth runs
	// before any DB access, so a nil pool is fine here.
	api.db = &hopper.DB{}

	check := func(name, auth string, wantCode int) {
		t.Run(name, func(t *testing.T) {
			t.Parallel()
			r := httptest.NewRequest(http.MethodPost, "/api/upload", strings.NewReader("x"))
			if auth != "" {
				r.Header.Set("Authorization", auth)
			}
			r.Header.Set("Content-Type", "application/octet-stream")
			r.ContentLength = 1
			w := httptest.NewRecorder()
			api.handleUpload(w, r)
			if w.Code != wantCode {
				t.Errorf("code=%d body=%s want=%d", w.Code, w.Body.String(), wantCode)
			}
		})
	}

	// Every rejected request returns the same Unauthorized status and the
	// same body shape so an attacker cannot distinguish "wrong scheme"
	// from "wrong-length token" from "right-length but wrong bytes". The
	// reason-string is only logged, not echoed.
	check("missing header", "", http.StatusUnauthorized)
	check("wrong scheme", "Basic foo", http.StatusUnauthorized)
	check("wrong token correct length", "Bearer not-the-right-token-value-okay-but-32-plus", http.StatusUnauthorized)
	check("wrong token short", "Bearer short", http.StatusUnauthorized)
	check("empty bearer value", "Bearer ", http.StatusUnauthorized)

	t.Run("disabled when no token", func(t *testing.T) {
		t.Parallel()
		api2 := &apiServer{
			tracker:  newWorkerTracker(),
			dataRoot: t.TempDir(),
			db:       &hopper.DB{},
		}
		r := httptest.NewRequest(http.MethodPost, "/api/upload", strings.NewReader("x"))
		r.Header.Set("Authorization", "Bearer anything")
		r.ContentLength = 1
		w := httptest.NewRecorder()
		api2.handleUpload(w, r)
		if w.Code != http.StatusServiceUnavailable {
			t.Errorf("code=%d body=%s want=%d", w.Code, w.Body.String(), http.StatusServiceUnavailable)
		}
	})
}

func TestSetUploadTokenRejectsShortTokens(t *testing.T) {
	t.Parallel()
	api := &apiServer{}
	if err := api.setUploadToken(""); err == nil {
		t.Error("empty token accepted")
	}
	if err := api.setUploadToken(strings.Repeat("a", uploadTokenMinLen-1)); err == nil {
		t.Error("token one byte too short accepted")
	}
	if err := api.setUploadToken(strings.Repeat("a", uploadTokenMinLen)); err != nil {
		t.Errorf("minimum-length token rejected: %v", err)
	}
	if !api.uploadTokenSet {
		t.Error("uploadTokenSet false after successful setUploadToken")
	}
}

func TestCheckUploadAuthConstantShape(t *testing.T) {
	t.Parallel()
	api := &apiServer{}
	if err := api.setUploadToken("the-correct-token-with-32-or-more!"); err != nil {
		t.Fatalf("setUploadToken rejected the fixture: %v", err)
	}

	mkReq := func(authHeader string) *http.Request {
		r := httptest.NewRequest(http.MethodPost, "/api/upload", http.NoBody)
		if authHeader != "" {
			r.Header.Set("Authorization", authHeader)
		}
		return r
	}

	// Negative cases of varying lengths — all must return a non-nil error.
	bads := []string{
		"",
		"Basic xyz",
		"Bearer ",
		"Bearer a",
		"Bearer " + strings.Repeat("x", 1),
		"Bearer " + strings.Repeat("x", 32),
		"Bearer " + strings.Repeat("x", 1024),
		"Bearer the-correct-token-with-32-or-more!!", // one byte off
	}
	for _, h := range bads {
		if err := api.checkUploadAuth(mkReq(h)); err == nil {
			t.Errorf("bad auth header accepted: %q", h)
		}
	}

	// Positive: the literal correct token passes.
	if err := api.checkUploadAuth(mkReq("Bearer the-correct-token-with-32-or-more!")); err != nil {
		t.Errorf("correct token rejected: %v", err)
	}

	// Plaintext is not retained: the stored 32-byte field must not be the
	// raw bytes of the token (taking the first 32 chars of the plaintext).
	// Defence-in-depth: catches a regression where someone "optimizes"
	// setUploadToken to keep the plaintext.
	plain := "the-correct-token-with-32-or-more!"
	if string(api.uploadTokenHash[:]) == plain[:sha256.Size] {
		t.Error("uploadTokenHash appears to contain the plaintext token")
	}
}

func TestResolveDataPath(t *testing.T) {
	t.Parallel()
	root := t.TempDir()
	api := &apiServer{dataRoot: root}

	if abs, err := api.resolveDataPath("unknown/uploads/ab/cd/foo.bin"); err != nil {
		t.Errorf("normal path errored: %v (got %q)", err, abs)
	}
	for _, bad := range []string{
		"..",
		"../etc/passwd",
		"../../../../../../../etc/passwd",
	} {
		if _, err := api.resolveDataPath(bad); err == nil {
			t.Errorf("resolveDataPath(%q) should have failed", bad)
		}
	}
}

func TestSweepUploadTmp(t *testing.T) {
	t.Parallel()
	root := t.TempDir()
	tmp := filepath.Join(root, uploadDir, ".tmp")
	if err := os.MkdirAll(tmp, 0o750); err != nil {
		t.Fatal(err)
	}
	// Old orphan: should be removed.
	old := filepath.Join(tmp, "up-old")
	if err := os.WriteFile(old, []byte("x"), 0o600); err != nil {
		t.Fatal(err)
	}
	past := time.Now().Add(-2 * uploadTmpMaxAge)
	if err := os.Chtimes(old, past, past); err != nil {
		t.Fatal(err)
	}
	// Recent: should be kept.
	fresh := filepath.Join(tmp, "up-fresh")
	if err := os.WriteFile(fresh, []byte("x"), 0o600); err != nil {
		t.Fatal(err)
	}
	// Non-upload file: should be untouched even if old.
	other := filepath.Join(tmp, "junk")
	if err := os.WriteFile(other, []byte("x"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.Chtimes(other, past, past); err != nil {
		t.Fatal(err)
	}

	api := &apiServer{dataRoot: root}
	api.sweepUploadTmp()

	if _, err := os.Stat(old); !os.IsNotExist(err) {
		t.Errorf("old orphan was not removed: err=%v", err)
	}
	if _, err := os.Stat(fresh); err != nil {
		t.Errorf("fresh tmp file was removed: err=%v", err)
	}
	if _, err := os.Stat(other); err != nil {
		t.Errorf("non-upload file was removed: err=%v", err)
	}
}

func TestBootstrapUploadTokenFromEnv(t *testing.T) {
	t.Setenv("HOPPER_UPLOAD_TOKEN", "env-supplied-token-32-bytes-long!")
	ctx := t.Context()
	db := mustOpenDB(t, ctx, filepath.Join(t.TempDir(), "bs.db"))
	defer db.Close()
	if err := db.Migrate(ctx); err != nil {
		t.Fatal(err)
	}
	api := &apiServer{tracker: newWorkerTracker()}

	bootstrapUploadToken(ctx, api, db)

	if !api.uploadTokenSet {
		t.Fatal("uploadTokenSet false after env bootstrap")
	}
	// Env path must NOT touch the DB.
	if _, err := db.KVGet(ctx, uploadTokenKVKey); !errors.Is(err, hopper.ErrNotFound) {
		t.Errorf("env path wrote to DB: err=%v", err)
	}
}

func TestBootstrapUploadTokenGeneratesAndPersists(t *testing.T) {
	t.Setenv("HOPPER_UPLOAD_TOKEN", "")
	ctx := t.Context()
	db := mustOpenDB(t, ctx, filepath.Join(t.TempDir(), "bs.db"))
	defer db.Close()
	if err := db.Migrate(ctx); err != nil {
		t.Fatal(err)
	}
	api := &apiServer{tracker: newWorkerTracker()}

	bootstrapUploadToken(ctx, api, db)

	if !api.uploadTokenSet {
		t.Fatal("uploadTokenSet false after generate bootstrap")
	}
	stored, err := db.KVGet(ctx, uploadTokenKVKey)
	if err != nil {
		t.Fatalf("KVGet after generate: %v", err)
	}
	if len(stored) < uploadTokenMinLen {
		t.Errorf("persisted token too short: len=%d want>=%d", len(stored), uploadTokenMinLen)
	}
	// Hash in api must match the stored value — proves prism (reading the
	// same row) will speak the same token.
	if sum := sha256.Sum256([]byte(stored)); sum != api.uploadTokenHash {
		t.Error("api hash does not match stored token's sha256")
	}
}

func TestBootstrapUploadTokenReusesPersistedValue(t *testing.T) {
	t.Setenv("HOPPER_UPLOAD_TOKEN", "")
	ctx := t.Context()
	db := mustOpenDB(t, ctx, filepath.Join(t.TempDir(), "bs.db"))
	defer db.Close()
	if err := db.Migrate(ctx); err != nil {
		t.Fatal(err)
	}

	// Seed the DB as if a previous run had persisted a token.
	const seeded = "previously-persisted-token-32-or-more!"
	if err := db.KVSetIfAbsent(ctx, uploadTokenKVKey, seeded); err != nil {
		t.Fatal(err)
	}

	api := &apiServer{tracker: newWorkerTracker()}
	bootstrapUploadToken(ctx, api, db)

	if !api.uploadTokenSet {
		t.Fatal("uploadTokenSet false after db bootstrap")
	}
	if sum := sha256.Sum256([]byte(seeded)); sum != api.uploadTokenHash {
		t.Error("api hash does not match seeded token's sha256")
	}
	// And the persisted value is unchanged — second startup didn't rotate.
	if got, err := db.KVGet(ctx, uploadTokenKVKey); err != nil || got != seeded {
		t.Errorf("persisted token mutated: got=%q err=%v, want %q", got, err, seeded)
	}
}

// Silences "imported and not used" complaints if a previous test gets
// trimmed; harmless when other tests reference io/os/filepath.
var _ = io.EOF
