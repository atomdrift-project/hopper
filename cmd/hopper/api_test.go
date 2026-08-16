package main

import (
	"archive/zip"
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"mime/multipart"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
	"time"
	"unicode/utf8"

	"github.com/atomdrift-project/hopper"
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
	// A claim's lease is fixed at claim time, so a fresh hold can't be stolen.
	if got := wt.tryClaimBatch(cands, "w2", time.Minute, 1); len(got) != 0 {
		t.Fatalf("w2 stole a fresh claim: %+v", got)
	}

	// Age w1's hold past its lease; now w2 re-issues it and the active-claim
	// accounting moves across.
	wt.mu.Lock()
	c := wt.claims["exp1"]
	c.at = time.Now().Add(-2 * time.Minute)
	wt.claims["exp1"] = c
	wt.mu.Unlock()

	got := wt.tryClaimBatch(cands, "w2", time.Minute, 1)
	if len(got) != 1 || got[0].SHA256 != "exp1" {
		t.Fatalf("expired steal: got %+v, want [{exp1 ...}]", got)
	}
	if wt.activeClaims("w1") != 0 || wt.activeClaims("w2") != 1 {
		t.Fatalf("active claims after steal: w1=%d w2=%d, want 0/1", wt.activeClaims("w1"), wt.activeClaims("w2"))
	}
}

func TestClaimLease(t *testing.T) {
	if got := claimLease(claimExpiry, 4*(1<<20)); got != claimExpiry {
		t.Errorf("small (4 MiB) sample lease = %v, want base %v", got, claimExpiry)
	}
	iso := claimLease(claimExpiry, 13*(1<<30)) // 13 GiB
	if iso <= claimExpiry {
		t.Errorf("13 GiB ISO lease = %v, want > base %v", iso, claimExpiry)
	}
	if iso > maxClaimLease {
		t.Errorf("13 GiB ISO lease = %v, want <= cap %v", iso, maxClaimLease)
	}
	if got := claimLease(claimExpiry, 1<<50); got != maxClaimLease {
		t.Errorf("pathological sample lease = %v, want cap %v", got, maxClaimLease)
	}
}

// TestBigArchiveClaimSurvivesBaseExpiry is the regression guard for the fix: a
// multi-GB archive still being scanned must not be stealable just because the
// base 30-minute lease elapsed, while an ordinary sample still is.
func TestBigArchiveClaimSurvivesBaseExpiry(t *testing.T) {
	wt := newWorkerTracker()
	cands := []hopper.ClaimJob{{SHA256: "iso", Path: "p/iso", SizeBytes: 13 * (1 << 30)}}
	if got := wt.tryClaimBatch(cands, "w1", claimExpiry, 1); len(got) != 1 {
		t.Fatalf("claim: got %d, want 1", len(got))
	}
	// Age the claim past the base lease but within its size-scaled lease.
	wt.mu.Lock()
	for sha, c := range wt.claims {
		c.at = time.Now().Add(-(claimExpiry + 10*time.Minute))
		wt.claims[sha] = c
	}
	wt.mu.Unlock()
	if got := wt.tryClaimBatch(cands, "w2", claimExpiry, 1); len(got) != 0 {
		t.Fatalf("w2 stole a big archive still within its lease: %+v", got)
	}

	// A same-age ordinary sample (no size) is past its base lease and stealable.
	small := []hopper.ClaimJob{{SHA256: "small", Path: "p/s"}}
	wt.tryClaimBatch(small, "w1", claimExpiry, 1)
	wt.mu.Lock()
	c := wt.claims["small"]
	c.at = time.Now().Add(-(claimExpiry + time.Minute))
	wt.claims["small"] = c
	wt.mu.Unlock()
	if got := wt.tryClaimBatch(small, "w2", claimExpiry, 1); len(got) != 1 {
		t.Fatalf("w2 could not steal an expired small claim: %+v", got)
	}
}

// TestRenewClaimsExtendsLease covers the multi-hour-scan fix: a worker
// heartbeating about an in-progress sha keeps its claim indefinitely, while a
// non-owner's heartbeat can't extend (or steal) it.
func TestRenewClaimsExtendsLease(t *testing.T) {
	wt := newWorkerTracker()
	cands := []hopper.ClaimJob{{SHA256: "iso", Path: "p", SizeBytes: 13 << 30}}
	if got := wt.tryClaimBatch(cands, "w1", claimExpiry, 1); len(got) != 1 {
		t.Fatalf("setup claim: got %d, want 1", len(got))
	}
	age := func(d time.Duration) {
		wt.mu.Lock()
		c := wt.claims["iso"]
		c.at = time.Now().Add(d)
		wt.claims["iso"] = c
		wt.mu.Unlock()
	}

	// Past even the 2h lease cap, but the owner's heartbeat renews it → not stealable.
	age(-3 * time.Hour)
	wt.renewClaims("w1", []string{"iso"}, time.Now())
	if got := wt.tryClaimBatch(cands, "w2", claimExpiry, 1); len(got) != 0 {
		t.Fatalf("renewed claim was stolen: %+v", got)
	}

	// A non-owner's renewal is ignored; once truly stale, the claim is reclaimable.
	age(-3 * time.Hour)
	wt.renewClaims("w2", []string{"iso"}, time.Now())
	if got := wt.tryClaimBatch(cands, "w2", claimExpiry, 1); len(got) != 1 || got[0].SHA256 != "iso" {
		t.Fatalf("stale claim not reclaimable after non-owner renew: %+v", got)
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

func TestHandleHealthzNeedsNothing(t *testing.T) {
	// db and tracker deliberately nil: healthz is the probe that must answer
	// even when everything behind the HTTP layer is broken, so constructing
	// it with a gutted server is the point, not a shortcut.
	api := &apiServer{hopperStart: time.Now().Add(-90 * time.Second)}
	rec := httptest.NewRecorder()
	api.handleHealthz(rec, httptest.NewRequest(http.MethodGet, "/healthz", http.NoBody))
	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, want %d", rec.Code, http.StatusOK)
	}
	var body struct {
		Status string `json:"status"`
		Uptime string `json:"uptime"`
	}
	if err := json.Unmarshal(rec.Body.Bytes(), &body); err != nil {
		t.Fatalf("healthz body %q is not JSON: %v", rec.Body.String(), err)
	}
	if body.Status != "ok" || body.Uptime == "" {
		t.Fatalf("healthz body = %+v, want status ok with uptime", body)
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

func TestFilterCandidatesBySize(t *testing.T) {
	cands := []hopper.ClaimJob{
		{SHA256: "small", SizeBytes: 1 << 20},        // 1 MiB
		{SHA256: "atcap", SizeBytes: 32 << 20},       // exactly 32 MiB
		{SHA256: "big", SizeBytes: (32 << 20) + 1},   // just over 32 MiB
		{SHA256: "huge", SizeBytes: 300 * (1 << 20)}, // 300 MiB
	}
	got := filterCandidatesBySize(cands, 32<<20)
	if len(got) != 2 || got[0].SHA256 != "small" || got[1].SHA256 != "atcap" {
		t.Fatalf("filtered candidates = %+v, want small and atcap only (<= 32 MiB)", got)
	}

	// maxBytes <= 0 means the worker advertised no cap: every candidate stays.
	for _, limit := range []int64{0, -1} {
		if uncapped := filterCandidatesBySize(cands, limit); len(uncapped) != len(cands) {
			t.Fatalf("cap %d filtered candidates: %+v", limit, uncapped)
		}
	}
}

func TestFilterCandidatesBySlots(t *testing.T) {
	cands := []hopper.ClaimJob{
		{SHA256: "pkg", SizeBytes: 300 * (1 << 20)}, // 300 MiB — ordinary
		{SHA256: "atcap", SizeBytes: 1 << 30},       // exactly 1 GiB
		{SHA256: "iso", SizeBytes: (1 << 30) + 1},   // just over 1 GiB — big archive
		{SHA256: "dvd", SizeBytes: 13 * (1 << 30)},  // 13 GiB DVD
	}

	// A small worker (< bigArchiveMinSlots) is offered no big archives.
	got := filterCandidatesBySlots(cands, bigArchiveMinSlots-1)
	if len(got) != 2 || got[0].SHA256 != "pkg" || got[1].SHA256 != "atcap" {
		t.Fatalf("small-worker filter = %+v, want pkg and atcap only (<= 1 GiB)", got)
	}

	// A worker advertising slots=1 (older builds' default) counts as small.
	if got := filterCandidatesBySlots(cands, 1); len(got) != 2 {
		t.Fatalf("slots=1 worker got %d candidates, want 2", len(got))
	}

	// A big worker (>= bigArchiveMinSlots) keeps every candidate.
	if got := filterCandidatesBySlots(cands, bigArchiveMinSlots); len(got) != len(cands) {
		t.Fatalf("big-worker filter dropped candidates: %+v", got)
	}
}

// TestClaimJobsBigArchiveDistribution asserts efficient work distribution for
// rare multi-GB archives against two quirks the audit surfaced:
//  1. a small worker must never be handed a big archive (routing), and
//  2. a capable worker must claim a pending big archive even on a tiny
//     steady-state poll — not only on a large startup poll. Before Tier B, a
//     count=1 poll sampled too narrow a random-pivot window to surface the rare
//     ISO, so a busy worker would seldom claim it.
func TestClaimJobsBigArchiveDistribution(t *testing.T) {
	ctx := context.Background()
	db, err := hopper.Open(ctx, filepath.Join(t.TempDir(), "t.db"))
	if err != nil {
		t.Fatalf("open: %v", err)
	}
	if err := db.Migrate(ctx); err != nil {
		t.Fatalf("migrate: %v", err)
	}
	t.Cleanup(func() { db.Close() })

	// 200 ordinary small samples plus one rare 4 GiB ISO.
	for i := range 200 {
		sha := fmt.Sprintf("%064x", i)
		if err := db.InsertSample(ctx, &hopper.Sample{
			SHA256: sha, Source: "test", Label: "good", LabelSource: "test",
			Path: "good/small/" + sha, SizeBytes: 1 << 20,
		}); err != nil {
			t.Fatalf("insert small %d: %v", i, err)
		}
	}
	const isoSHA = "ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff"
	if err := db.InsertSample(ctx, &hopper.Sample{
		SHA256: isoSHA, Source: "test", Label: "good", LabelSource: "test",
		Path: "good/iso/big.iso", SizeBytes: 4 << 30,
	}); err != nil {
		t.Fatalf("insert iso: %v", err)
	}

	api := &apiServer{tracker: newWorkerTracker(), db: db}

	// (1) A sub-16-slot worker draining small work one job at a time is never
	// handed the ISO.
	for i := range 50 {
		jobs, err := api.claimJobs(ctx, "small", 1, nil, 0, 8)
		if err != nil {
			t.Fatalf("small claim %d: %v", i, err)
		}
		for _, j := range jobs {
			if j.SHA256 == isoSHA {
				t.Fatalf("small worker (8 slots) was handed the ISO")
			}
		}
	}

	// (2) A capable worker's first single-job poll claims the ISO up front,
	// despite the tiny poll window.
	jobs, err := api.claimJobs(ctx, "big", 1, nil, 0, 16)
	if err != nil {
		t.Fatalf("big claim: %v", err)
	}
	if len(jobs) != 1 || jobs[0].SHA256 != isoSHA {
		t.Fatalf("capable worker's count=1 poll = %+v, want the ISO up front", jobs)
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

func TestHandleResultAcknowledgesAbsentSample(t *testing.T) {
	sha := strings.Repeat("9", 64)
	raw := json.RawMessage(`{"fs":[{"sha":"` + sha + `","type":"elf","dp":0}]}`)
	body, err := json.Marshal(resultRequest{SHA256: sha, Worker: "worker1", Raw: raw, ML: json.RawMessage(`{}`)})
	if err != nil {
		t.Fatal(err)
	}
	ctx := context.Background()
	db := mustOpenDB(t, ctx, filepath.Join(t.TempDir(), "hopper.db"))
	defer db.Close()
	if err := db.Migrate(ctx); err != nil {
		t.Fatal(err)
	}
	api := &apiServer{db: db, tracker: newWorkerTracker(), progress: &loadProgress{}}
	req := httptest.NewRequest(http.MethodPost, "/api/result", bytes.NewReader(body))
	rec := httptest.NewRecorder()
	api.handleResult(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, body = %s", rec.Code, rec.Body.String())
	}
	var response struct {
		OK     bool `json:"ok"`
		Stored bool `json:"stored"`
	}
	if err := json.Unmarshal(rec.Body.Bytes(), &response); err != nil {
		t.Fatal(err)
	}
	if !response.OK || response.Stored {
		t.Fatalf("response = %+v, want ok=true stored=false", response)
	}
}

func TestHandleResultRejectsRootSHAMismatch(t *testing.T) {
	ctx := context.Background()
	db := mustOpenDB(t, ctx, filepath.Join(t.TempDir(), "hopper.db"))
	defer db.Close()
	if err := db.Migrate(ctx); err != nil {
		t.Fatal(err)
	}
	claimed := strings.Repeat("a", 64)
	reported := strings.Repeat("b", 64)
	if err := db.InsertSample(ctx, &hopper.Sample{SHA256: claimed, Path: "pending/sample.bin", Label: "unknown"}); err != nil {
		t.Fatal(err)
	}
	body, err := json.Marshal(resultRequest{
		SHA256: claimed,
		Worker: "worker1",
		Raw:    json.RawMessage(`{"fs":[{"sha":"` + reported + `","type":"elf","dp":0}]}`),
	})
	if err != nil {
		t.Fatal(err)
	}
	api := &apiServer{db: db, tracker: newWorkerTracker(), progress: &loadProgress{}}
	rec := httptest.NewRecorder()
	api.handleResult(rec, httptest.NewRequest(http.MethodPost, "/api/result", bytes.NewReader(body)))
	if rec.Code != http.StatusUnprocessableEntity {
		t.Fatalf("status = %d, body = %s", rec.Code, rec.Body.String())
	}
	row, err := db.SampleBySHA256(ctx, claimed)
	if err != nil {
		t.Fatal(err)
	}
	if len(row.CleaveResult) != 0 {
		t.Fatal("mismatched result was stored")
	}
}

// TestHandleResultShedsLoadWhenSaturated verifies that with no ingestion slot
// free the handler sheds load with 503 + Retry-After instead of reading and
// buffering the body. A pre-filled cap-1 resultSem plus a cancelled request
// context makes acquireResult take the ctx.Done path deterministically.
func TestHandleResultShedsLoadWhenSaturated(t *testing.T) {
	ctx := context.Background()
	db := mustOpenDB(t, ctx, t.TempDir()+"/hopper.db")
	defer db.Close()
	if err := db.Migrate(ctx); err != nil {
		t.Fatalf("Migrate: %v", err)
	}

	sha := "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
	if err := db.InsertSample(ctx, &hopper.Sample{
		SHA256: sha, Source: "test", Path: "bad/x.bin", Label: "bad", LabelSource: "test",
	}); err != nil {
		t.Fatalf("InsertSample: %v", err)
	}

	api := &apiServer{
		db: db, tracker: newWorkerTracker(), progress: &loadProgress{},
		resultSem: make(chan struct{}, 1),
	}
	api.resultSem <- struct{}{} // occupy the only slot

	body, err := json.Marshal(resultRequest{SHA256: sha, Worker: "w", Raw: json.RawMessage(`{"fs":[]}`)})
	if err != nil {
		t.Fatalf("Marshal: %v", err)
	}
	reqCtx, cancel := context.WithCancel(ctx)
	cancel()
	req := httptest.NewRequest(http.MethodPost, "/api/result", bytes.NewReader(body)).WithContext(reqCtx)
	rec := httptest.NewRecorder()

	api.handleResult(rec, req)

	if rec.Code != http.StatusServiceUnavailable {
		t.Fatalf("status = %d, want 503; body = %s", rec.Code, rec.Body.String())
	}
	if rec.Header().Get("Retry-After") == "" {
		t.Error("expected Retry-After header on shed response")
	}
	if s, err := db.SampleBySHA256(ctx, sha); err == nil && len(s.CleaveResult) != 0 {
		t.Error("result was stored despite load shedding")
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

func TestUploadSampleFilenameFallback(t *testing.T) {
	t.Parallel()
	const sha = "60d11b7004c80ae17a900094bbddd0a92273167af2b15f7597b9749d1b5edaa2"

	// Real case (live audit 2026-08-08): a dependency uploaded with a
	// version-less PURL claim — the release is only in the filename.
	prov := &hopper.Sidecar{
		Package: hopper.PackageRef{Ecosystem: "javascript", Name: "pg", PURL: "pkg:npm/pg"},
	}
	s := uploadSample(sha, "pg-8.23.0.tgz", "incoming/uploads/pg-8.23.0.tgz", 1, prov)
	if s.Package != "pg" || s.Version != "8.23.0" {
		t.Errorf("versionless-PURL upload = (%q, %q), want (\"pg\", \"8.23.0\")", s.Package, s.Version)
	}
	if s.PURLBase != "pkg:npm/pg" {
		t.Errorf("PURLBase = %q, want \"pkg:npm/pg\"", s.PURLBase)
	}

	// Producer claims win: the parse must not override an explicit version.
	prov = &hopper.Sidecar{
		Package: hopper.PackageRef{Name: "pg", Version: "9.0.0-claimed", PURL: "pkg:npm/pg@9.0.0-claimed"},
	}
	s = uploadSample(sha, "pg-8.23.0.tgz", "incoming/uploads/pg-8.23.0.tgz", 1, prov)
	if s.Package != "pg" || s.Version != "9.0.0-claimed" {
		t.Errorf("claimed-version upload = (%q, %q), want (\"pg\", \"9.0.0-claimed\")", s.Package, s.Version)
	}

	// No provenance at all: identity comes from the filename alone, and an
	// unparseable filename stays empty rather than guessing.
	s = uploadSample(sha, "lodash-4.17.21.tgz", "incoming/uploads/lodash-4.17.21.tgz", 1, nil)
	if s.Package != "lodash" || s.Version != "4.17.21" {
		t.Errorf("bare upload = (%q, %q), want (\"lodash\", \"4.17.21\")", s.Package, s.Version)
	}
	s = uploadSample(sha, "evil.exe", "incoming/uploads/evil.exe", 1, nil)
	if s.Package != "" || s.Version != "" {
		t.Errorf("unparseable upload = (%q, %q), want empty", s.Package, s.Version)
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
		// multipart carries the provenance envelope from Bearer-authed clients
		// (forager, prism backend); auth runs before this guard, so a browser
		// form cannot reach the store. Same-origin multipart is allowed; a
		// cross-site one is still blocked by the Sec-Fetch-Site check above.
		{"multipart allowed (provenance upload)", "same-origin", "multipart/form-data; boundary=xyz", true},
		{"multipart cross-site blocked", "cross-site", "multipart/form-data; boundary=xyz", false},
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

	t.Run("open when no token configured", func(t *testing.T) {
		t.Parallel()
		// With no token set the endpoint is open: auth passes regardless of (or
		// without) an Authorization header, so an internal client can push content
		// without shared-secret plumbing. The browser CSRF guard, checked later in
		// the handler, is the remaining gate.
		api2 := &apiServer{tracker: newWorkerTracker(), dataRoot: t.TempDir()}
		if err := api2.checkUploadAuth(httptest.NewRequest(http.MethodPost, "/api/upload", http.NoBody)); err != nil {
			t.Errorf("checkUploadAuth with no token configured = %v, want nil (open)", err)
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

	if abs, err := api.resolveDataPath("incoming/uploads/ab/cd/foo.bin"); err != nil {
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
	stored, err := db.KVGet(ctx, uploadTokenKVKey)
	if err != nil || stored != "env-supplied-token-32-bytes-long!" {
		t.Errorf("env token was not persisted: got=%q err=%v", stored, err)
	}
}

func TestBootstrapUploadTokenFromEnvRotatesPersistedValue(t *testing.T) {
	t.Setenv("HOPPER_UPLOAD_TOKEN", "replacement-token-at-least-32-bytes!")
	ctx := t.Context()
	db := mustOpenDB(t, ctx, filepath.Join(t.TempDir(), "bs.db"))
	defer db.Close()
	if err := db.Migrate(ctx); err != nil {
		t.Fatal(err)
	}
	if err := db.KVSetIfAbsent(ctx, uploadTokenKVKey, "old-persisted-token-at-least-32-bytes"); err != nil {
		t.Fatal(err)
	}
	api := &apiServer{tracker: newWorkerTracker()}

	bootstrapUploadToken(ctx, api, db)

	stored, err := db.KVGet(ctx, uploadTokenKVKey)
	if err != nil || stored != "replacement-token-at-least-32-bytes!" {
		t.Fatalf("persisted token = %q, %v", stored, err)
	}
	if sum := sha256.Sum256([]byte(stored)); !api.uploadTokenSet || sum != api.uploadTokenHash {
		t.Fatal("API token does not match rotated persisted token")
	}
}

func TestBootstrapUploadTokenOpenMode(t *testing.T) {
	t.Setenv("HOPPER_UPLOAD_OPEN", "1")
	// A token in the env must not override open mode — open is checked first.
	t.Setenv("HOPPER_UPLOAD_TOKEN", "would-be-token-32-bytes-or-more!!")
	ctx := t.Context()
	db := mustOpenDB(t, ctx, filepath.Join(t.TempDir(), "bs.db"))
	defer db.Close()
	if err := db.Migrate(ctx); err != nil {
		t.Fatal(err)
	}
	api := &apiServer{tracker: newWorkerTracker()}

	bootstrapUploadToken(ctx, api, db)

	// Open: the endpoint is not enforced, so a tokenless push is accepted.
	if api.uploadTokenSet {
		t.Fatal("uploadTokenSet true under HOPPER_UPLOAD_OPEN; /api/upload should be open")
	}
	// But a token is still provisioned in the KV, so prism (which reads it) keeps
	// working and dropping open mode later re-enforces this same token.
	stored, err := db.KVGet(ctx, uploadTokenKVKey)
	if err != nil {
		t.Fatalf("open mode did not provision a KV token: %v", err)
	}
	if stored == "" {
		t.Error("provisioned upload token is empty")
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

// uploadAPI builds an apiServer wired to a real sqlite DB and a fresh data
// root, with the upload token configured, for exercising the full store path.
func uploadAPI(t *testing.T) *apiServer {
	t.Helper()
	db, err := hopper.Open(context.Background(), filepath.Join(t.TempDir(), "test.db"))
	if err != nil {
		t.Fatalf("open db: %v", err)
	}
	if err := db.Migrate(context.Background()); err != nil {
		t.Fatalf("migrate: %v", err)
	}
	t.Cleanup(func() { db.Close() })
	api := &apiServer{tracker: newWorkerTracker(), dataRoot: t.TempDir(), db: db}
	if err := api.setUploadToken("test-token-with-32-chars-or-more!!"); err != nil {
		t.Fatalf("setUploadToken: %v", err)
	}
	return api
}

// multipartUpload encodes a provenance+file body. provFirst=false puts the file
// part before the provenance part to exercise the ordering guard.
func multipartUpload(t *testing.T, prov []byte, file []byte, provFirst bool) (body *bytes.Buffer, contentType string) {
	t.Helper()
	var buf bytes.Buffer
	mw := multipart.NewWriter(&buf)
	write := func(name string, data []byte) {
		p, err := mw.CreateFormField(name)
		if err != nil {
			t.Fatalf("create part %s: %v", name, err)
		}
		if _, err := p.Write(data); err != nil {
			t.Fatalf("write part %s: %v", name, err)
		}
	}
	if provFirst {
		write("provenance", prov)
		write("file", file)
	} else {
		write("file", file)
		write("provenance", prov)
	}
	if err := mw.Close(); err != nil {
		t.Fatalf("close writer: %v", err)
	}
	return &buf, mw.FormDataContentType()
}

func validProvenance(t *testing.T, file []byte, claimedSHA string) []byte {
	t.Helper()
	sc := hopper.Sidecar{
		SchemaVersion: hopper.SidecarSchemaVersion,
		Artifact:      hopper.Artifact{Filename: "evil-1.0.0.tgz", SHA256: claimedSHA, SizeBytes: int64(len(file))},
		Package:       hopper.PackageRef{Ecosystem: "npm", Name: "evil", Version: "1.0.0", Feed: "npm"},
		Fetch: hopper.Fetch{
			Collector: "forager+test", Category: "new", At: time.Now().UTC(),
			URL: "https://registry.npmjs.org/evil/-/evil-1.0.0.tgz",
		},
	}
	b, err := json.Marshal(&sc)
	if err != nil {
		t.Fatalf("marshal provenance: %v", err)
	}
	return b
}

func TestUploadRootFor(t *testing.T) {
	t.Parallel()
	prov := func(collector string) *hopper.Sidecar {
		return &hopper.Sidecar{Fetch: hopper.Fetch{Collector: collector}}
	}
	for _, tc := range []struct {
		name string
		prov *hopper.Sidecar
		want string
	}{
		// Worker dependency mirroring and `atomscan --hopper` both identify as
		// "scan+<host>"; these are registry artifacts a promoting daemon may
		// bless into the good pool.
		{"worker mirror", prov("scan+galadriel"), uploadDirScan},
		{"scan with no instance suffix", prov("scan"), uploadDirScan},
		// Prism uploads are arbitrary user submissions: own tree, never
		// auto-promoted.
		{"prism", prov("prism"), uploadDirPrism},
		{"forager", prov("forager+0a45da172e3f"), uploadDirForager},
		// Everything else keeps the fallback root, including the deprecated
		// raw-body path that carries no sidecar at all — unattributable bytes
		// must not land in a tree a promoting daemon watches.
		{"unknown collector", prov("somethingelse"), uploadDir},
		{"no provenance", nil, uploadDir},
		// A collector must not be able to steer itself into another tree by
		// prefixing its name.
		{"lookalike collector", prov("scanner+evil"), uploadDir},
		{"empty collector", prov(""), uploadDir},
	} {
		if got := uploadRootFor(tc.prov); got != tc.want {
			t.Errorf("%s: uploadRootFor = %q, want %q", tc.name, got, tc.want)
		}
	}
}

// A sha already stored in an upload tree must keep its directory when
// re-uploaded, even by a producer that routes elsewhere now: re-sending the
// same bytes is idempotent, not a second copy in a new tree that the row can
// only point at one of. Rows outside the upload trees keep the old behavior of
// landing in the producer's root.
func TestUploadRootKeepsExistingUploadPath(t *testing.T) {
	t.Parallel()
	for _, tc := range []struct {
		name     string
		existing string
		want     string // "" means: use the producer's root, not the existing dir
	}{
		{"current uploads row re-sent by scan", "incoming/uploads/ab/cd/pkg.tgz", "incoming/uploads/ab/cd"},
		{"already in the scan tree", "incoming/scan/ab/cd/pkg.tgz", "incoming/scan/ab/cd"},
		{"already in the prism tree", "incoming/prism/ab/cd/pkg.tgz", "incoming/prism/ab/cd"},
		{"already in the forager tree", "incoming/forager/ab/cd/pkg.tgz", "incoming/forager/ab/cd"},
		{"legacy uploads row", "unknown/uploads/ab/cd/pkg.tgz", "unknown/uploads/ab/cd"},
		{"legacy scan row", "unknown/scan/ab/cd/pkg.tgz", "unknown/scan/ab/cd"},
		{"legacy prism row", "unknown/prism/ab/cd/pkg.tgz", "unknown/prism/ab/cd"},
		{"legacy forager row", "unknown/forager/ab/cd/pkg.tgz", "unknown/forager/ab/cd"},
		{"promoted row", "good/foraged-promote/ab/cd/pkg.tgz", ""},
		{"foraged row", "unknown/foraged/ab/cd/pkg.tgz", ""},
		{"no path", "", ""},
	} {
		if got := existingUploadDir(tc.existing); got != tc.want {
			t.Errorf("%s: reused dir = %q, want %q", tc.name, got, tc.want)
		}
	}
}

func mustJSON(t *testing.T, v any) []byte {
	t.Helper()
	b, err := json.Marshal(v)
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	return b
}

func postUpload(t *testing.T, api *apiServer, body *bytes.Buffer, contentType string) *httptest.ResponseRecorder {
	t.Helper()
	r := httptest.NewRequest(http.MethodPost, "/api/upload", body)
	r.Header.Set("Authorization", "Bearer test-token-with-32-chars-or-more!!")
	r.Header.Set("Content-Type", contentType)
	w := httptest.NewRecorder()
	api.handleUpload(w, r)
	return w
}

func TestHandleUploadMultipartEnrichesRow(t *testing.T) {
	t.Parallel()
	api := uploadAPI(t)
	file := []byte("malicious package bytes")
	sum := sha256.Sum256(file)
	sha := hex.EncodeToString(sum[:])

	body, ct := multipartUpload(t, validProvenance(t, file, sha), file, true)
	w := postUpload(t, api, body, ct)
	if w.Code != http.StatusOK {
		t.Fatalf("code=%d body=%s want 200", w.Code, w.Body.String())
	}

	got, err := api.db.SampleBySHA256(context.Background(), sha)
	if err != nil {
		t.Fatalf("SampleBySHA256: %v", err)
	}
	// Trust boundary: the producer's claims fill descriptive columns, but
	// Source marks the upload boundary and Label is never taken from the claim.
	if got.Source != "upload" {
		t.Errorf("Source = %q, want upload", got.Source)
	}
	if got.Label != "unknown" {
		t.Errorf("Label = %q, want unknown (claim must not set label)", got.Label)
	}
	if got.Ecosystem != "npm" || got.Package != "evil" || got.Version != "1.0.0" || got.Feed != "npm" {
		t.Errorf("descriptive columns not populated from provenance: %+v", got)
	}
	if got.URL != "https://registry.npmjs.org/evil/-/evil-1.0.0.tgz" {
		t.Errorf("URL = %q, want the provenance fetch URL", got.URL)
	}
	// No PURL in this sidecar, so the bytes are keyed by digest under the
	// producer's tree, with the fetch host as the only legible handle.
	if want := "incoming/forager/sha/npmjs.org/" + sha[:2] + "/" + sha[2:4] + "/" + sha + "/evil-1.0.0.tgz"; got.Path != want {
		t.Errorf("Path = %q, want %q", got.Path, want)
	}
	if got.Domain != "npmjs.org" {
		t.Errorf("Domain = %q, want npmjs.org derived from the fetch URL", got.Domain)
	}
}

// provenanceFrom builds an upload sidecar with an explicit collector and PURL,
// so a test can steer which tree the bytes land in.
func provenanceFrom(t *testing.T, file []byte, sha, collector, purl string) []byte {
	t.Helper()
	sc := hopper.Sidecar{
		SchemaVersion: hopper.SidecarSchemaVersion,
		Artifact:      hopper.Artifact{Filename: "evil-1.0.0.tgz", SHA256: sha, SizeBytes: int64(len(file))},
		Package:       hopper.PackageRef{PURL: purl},
		Fetch:         hopper.Fetch{Collector: collector, Category: "submitted", At: time.Now().UTC()},
	}
	b, err := json.Marshal(&sc)
	if err != nil {
		t.Fatalf("marshal provenance: %v", err)
	}
	return b
}

// collidingPayloads returns two distinct payloads whose digests share the first
// four hex digits — the whole of the upload shard key. With 65536 shards a pair
// turns up within a few hundred probes.
func collidingPayloads(t *testing.T) (first, second []byte) {
	t.Helper()
	seen := make(map[string][]byte)
	for i := range 1 << 20 {
		payload := []byte("collision probe " + strconv.Itoa(i))
		key := hexSHA256(payload)[:4]
		if prev, ok := seen[key]; ok {
			return prev, payload
		}
		seen[key] = payload
	}
	t.Fatal("no shard collision found")
	return nil, nil
}

func hexSHA256(b []byte) string {
	sum := sha256.Sum256(b)
	return hex.EncodeToString(sum[:])
}

// TestHandleUploadShardCollision proves two distinct digests that share a shard
// prefix and a filename both survive with their own bytes. The legacy root is
// keyed on sha[:4] alone, so a corpus full of common basenames ("index.js",
// "setup.py") collides routinely; storing the second over the first would leave
// the first row pointing at bytes whose digest it no longer describes.
//
// An unlisted collector is what routes these there — that root still receives
// every producer hopper does not recognize.
func TestHandleUploadShardCollision(t *testing.T) {
	t.Parallel()
	api := uploadAPI(t)
	ctx := context.Background()

	first, second := collidingPayloads(t)
	upload := func(payload []byte) {
		t.Helper()
		prov := provenanceFrom(t, payload, hexSHA256(payload), "some-unlisted-tool", "")
		body, ct := multipartUpload(t, prov, payload, true)
		if w := postUpload(t, api, body, ct); w.Code != http.StatusOK {
			t.Fatalf("upload: code=%d body=%s want 200", w.Code, w.Body.String())
		}
	}
	upload(first)
	upload(second)
	if !strings.HasPrefix(mustUploadPath(t, api, hexSHA256(first)), "incoming/uploads/") {
		t.Fatal("test precondition: an unlisted collector must route to the fallback root")
	}

	rows := make([]*hopper.Sample, 0, 2)
	for _, payload := range [][]byte{first, second} {
		row, err := api.db.SampleBySHA256(ctx, hexSHA256(payload))
		if err != nil {
			t.Fatalf("SampleBySHA256: %v", err)
		}
		rows = append(rows, row)
	}
	if rows[0].Path == rows[1].Path {
		t.Fatalf("colliding digests share path %q; one sample's bytes were overwritten", rows[0].Path)
	}
	// The decisive check: the bytes on disk must hash to the digest their own
	// row records. An overwrite leaves the survivor's content under both paths.
	for _, row := range rows {
		stored, err := os.ReadFile(filepath.Join(api.dataRoot, row.Path))
		if err != nil {
			t.Fatalf("read stored sample %s: %v", row.Path, err)
		}
		if got := hexSHA256(stored); got != row.SHA256 {
			t.Errorf("file at %s hashes to %s, but its row records %s", row.Path, got, row.SHA256)
		}
	}

	// Re-uploading known bytes must land on the existing path, not spawn a
	// third qualified copy alongside it.
	upload(first)
	again, err := api.db.SampleBySHA256(ctx, hexSHA256(first))
	if err != nil {
		t.Fatalf("SampleBySHA256 after re-upload: %v", err)
	}
	if again.Path != rows[0].Path {
		t.Errorf("re-upload moved sample from %q to %q", rows[0].Path, again.Path)
	}
	shard := filepath.Dir(filepath.Join(api.dataRoot, rows[0].Path))
	entries, err := os.ReadDir(shard)
	if err != nil {
		t.Fatalf("read shard dir: %v", err)
	}
	if len(entries) != 2 {
		names := make([]string, 0, len(entries))
		for _, e := range entries {
			names = append(names, e.Name())
		}
		t.Errorf("shard holds %d files %v, want exactly the 2 colliding samples", len(entries), names)
	}
}

func TestHandleUploadRepairsExistingPathWithWrongBytes(t *testing.T) {
	t.Parallel()
	api := uploadAPI(t)
	payload := []byte("the verified payload")
	sha := hexSHA256(payload)
	prov := provenanceFrom(t, payload, sha, "some-unlisted-tool", "")
	upload := func() *httptest.ResponseRecorder {
		body, ct := multipartUpload(t, prov, payload, true)
		return postUpload(t, api, body, ct)
	}
	if rec := upload(); rec.Code != http.StatusOK {
		t.Fatalf("first upload: %d %s", rec.Code, rec.Body.String())
	}
	original := mustUploadPath(t, api, sha)
	if err := os.Chmod(filepath.Join(api.dataRoot, original), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(api.dataRoot, original), []byte("corrupt replacement"), 0o444); err != nil {
		t.Fatal(err)
	}
	if rec := upload(); rec.Code != http.StatusOK {
		t.Fatalf("repair upload: %d %s", rec.Code, rec.Body.String())
	}
	repaired := mustUploadPath(t, api, sha)
	if repaired == original {
		t.Fatalf("canonical path remained on corrupted bytes: %q", repaired)
	}
	stored, err := os.ReadFile(filepath.Join(api.dataRoot, repaired))
	if err != nil {
		t.Fatal(err)
	}
	if got := hexSHA256(stored); got != sha {
		t.Fatalf("repaired path hashes to %s, want %s", got, sha)
	}
}

func mustUploadPath(t *testing.T, api *apiServer, sha string) string {
	t.Helper()
	row, err := api.db.SampleBySHA256(context.Background(), sha)
	if err != nil {
		t.Fatalf("SampleBySHA256(%s): %v", sha, err)
	}
	return row.Path
}

// TestHandleUploadCoordinateCollision covers the one place the coordinate tier
// can collide: two artifacts claiming a single PURL. Qualifiers are deliberately
// kept out of the path, so an Open VSX build and a Microsoft marketplace build of
// one extension share a directory — and must still keep their own bytes.
func TestHandleUploadCoordinateCollision(t *testing.T) {
	t.Parallel()
	api := uploadAPI(t)
	const purl = "pkg:vscode-extension/ms-python/python@2024.1.0"
	const wantDir = "incoming/scan/pkg/vscode-extension/ms-python/python/2024.1.0"
	payloads := [][]byte{[]byte("open vsx build"), []byte("marketplace build")}

	for _, payload := range payloads {
		prov := provenanceFrom(t, payload, hexSHA256(payload), "scan+build07", purl)
		body, ct := multipartUpload(t, prov, payload, true)
		if w := postUpload(t, api, body, ct); w.Code != http.StatusOK {
			t.Fatalf("upload: code=%d body=%s want 200", w.Code, w.Body.String())
		}
	}
	for _, payload := range payloads {
		sha := hexSHA256(payload)
		rel := mustUploadPath(t, api, sha)
		if dir := filepath.ToSlash(filepath.Dir(rel)); dir != wantDir {
			t.Errorf("Path = %q, want a file under %q", rel, wantDir)
		}
		stored, err := os.ReadFile(filepath.Join(api.dataRoot, rel))
		if err != nil {
			t.Fatalf("read stored sample %s: %v", rel, err)
		}
		if got := hexSHA256(stored); got != sha {
			t.Errorf("file at %s hashes to %s, but its row records %s", rel, got, sha)
		}
	}
}

// TestHandleUploadKeepsKnownBytesInPlace proves an upload of a digest hopper
// already holds refreshes the row without laying down a second copy — even when
// the new sidecar would route those bytes into an entirely different tree. It is
// what keeps a layout change, or a producer that skips the /api/known probe,
// from duplicating the corpus.
func TestHandleUploadKeepsKnownBytesInPlace(t *testing.T) {
	t.Parallel()
	api := uploadAPI(t)
	payload := []byte("submitted by a human, later identified as a package")
	sha := hexSHA256(payload)

	send := func(collector, purl string) {
		t.Helper()
		prov := provenanceFrom(t, payload, sha, collector, purl)
		body, ct := multipartUpload(t, prov, payload, true)
		if w := postUpload(t, api, body, ct); w.Code != http.StatusOK {
			t.Fatalf("upload: code=%d body=%s want 200", w.Code, w.Body.String())
		}
	}
	send("prism", "")
	first := mustUploadPath(t, api, sha)
	if want := "incoming/prism/sha/_unknown/"; !strings.HasPrefix(first, want) {
		t.Fatalf("Path = %q, want a digest-keyed path under %q", first, want)
	}

	// Same bytes, now carrying a coordinate that routes elsewhere.
	send("scan+build07", "pkg:npm/lodash@4.17.21")
	if got := mustUploadPath(t, api, sha); got != first {
		t.Errorf("known bytes moved from %q to %q", first, got)
	}
	if _, err := os.Stat(filepath.Join(api.dataRoot, "incoming", "scan")); !os.IsNotExist(err) {
		t.Errorf("a second copy was written under incoming/scan (stat err = %v)", err)
	}
}

// provenanceOnlyUpload builds a multipart body with just a "provenance" part and
// no "file" part — the refresh shape scan sends for a dependency hopper already
// holds the bytes for.
func provenanceOnlyUpload(t *testing.T, prov []byte) (body *bytes.Buffer, contentType string) {
	t.Helper()
	var buf bytes.Buffer
	mw := multipart.NewWriter(&buf)
	p, err := mw.CreateFormField("provenance")
	if err != nil {
		t.Fatalf("create provenance part: %v", err)
	}
	if _, err := p.Write(prov); err != nil {
		t.Fatalf("write provenance: %v", err)
	}
	if err := mw.Close(); err != nil {
		t.Fatalf("close writer: %v", err)
	}
	return &buf, mw.FormDataContentType()
}

// postDepResult posts a dependency verdict to /api/result keyed by content sha,
// with a real cleave report (fileType keeps StoreResult from deleting the row on
// an empty FileType). Returns the stored cleave_result for difference checks.
func postDepResult(t *testing.T, api *apiServer, sha, fileType string, lvl int) []byte {
	t.Helper()
	raw := json.RawMessage(`{"fs":[{"sha":"` + sha + `","type":"` + fileType + `","dp":0}]}`)
	ml := json.RawMessage(`{"lvl":` + strconv.Itoa(lvl) + `}`)
	body, err := json.Marshal(resultRequest{SHA256: sha, Worker: "worker1", Raw: raw, ML: ml})
	if err != nil {
		t.Fatalf("marshal result: %v", err)
	}
	r := httptest.NewRequest(http.MethodPost, "/api/result", bytes.NewReader(body))
	w := httptest.NewRecorder()
	api.handleResult(w, r)
	if w.Code != http.StatusOK {
		t.Fatalf("post result: code=%d body=%s", w.Code, w.Body.String())
	}
	got, err := api.db.SampleBySHA256(context.Background(), sha)
	if err != nil {
		t.Fatalf("SampleBySHA256 after result: %v", err)
	}
	return got.CleaveResult
}

// TestDependencyMirrorAndRefresh drives hopper's real handlers through exactly
// what scan does when it mirrors a fetched dependency and later re-scans it:
//   - first discovery (forager-style sidecar with a Feed record + initial
//     Registry, uploaded with bytes) stores content + provenance + findings;
//   - a re-scan (provenance-only refresh carrying a new Registry and no Feed, then
//     an updated verdict) refreshes the registry snapshot and the findings while
//     preserving the original discovery feed — and never re-moves the bytes.
func TestDependencyMirrorAndRefresh(t *testing.T) {
	api := uploadAPI(t)
	api.progress = &loadProgress{} // handleResult records progress
	ctx := context.Background()

	file := []byte("dependency tarball bytes")
	sum := sha256.Sum256(file)
	sha := hex.EncodeToString(sum[:])

	feed := &hopper.MetadataRecord{
		SourceID: "npm-firehose", Format: "npm.event",
		URL: "https://npm/feed", Status: hopper.MetadataComplete,
	}
	base := hopper.Sidecar{
		SchemaVersion: hopper.SidecarSchemaVersion,
		Artifact:      hopper.Artifact{Filename: "foo-1.0.0.tgz", SHA256: sha, SizeBytes: int64(len(file))},
		Package:       hopper.PackageRef{Ecosystem: "npm", Name: "foo", Version: "1.0.0", PURL: "pkg:npm/foo@1.0.0", Feed: "npm"},
		Fetch:         hopper.Fetch{Collector: "forager+test", Category: "new", At: time.Now().UTC(), URL: "https://registry.npmjs.org/foo/-/foo-1.0.0.tgz"},
		Feed:          feed,
		Registry: &hopper.MetadataRecord{
			SourceID: "npm-old", Format: "npm.packument", URL: "https://registry.npmjs.org/foo",
			Status: hopper.MetadataComplete, Record: json.RawMessage(`{"downloads_recent":100}`),
		},
	}

	// --- First discovery: bytes + provenance. ---
	body, ct := multipartUpload(t, mustJSON(t, &base), file, true)
	if w := postUpload(t, api, body, ct); w.Code != http.StatusOK {
		t.Fatalf("initial upload: code=%d body=%s", w.Code, w.Body.String())
	}
	if got, err := api.db.ProvenanceBySHA256(ctx, sha); err != nil || len(got) == 0 {
		t.Fatalf("provenance not stored on discovery: err=%v len=%d", err, len(got))
	}
	if s0, err := api.db.SampleBySHA256(ctx, sha); err != nil || s0.PURLBase != "pkg:npm/foo" {
		t.Fatalf("purl_base not projected: err=%v purl_base=%q", err, s0.PURLBase)
	}

	// First verdict.
	firstResult := postDepResult(t, api, sha, "elf", -1)
	if len(firstResult) == 0 {
		t.Fatal("findings not stored on first pass")
	}

	// --- Re-scan: provenance-only refresh with a new registry and no feed. ---
	refresh := base
	refresh.Feed = nil // scan sends no discovery feed
	refresh.Fetch.Collector = "scan+host"
	refresh.Registry = &hopper.MetadataRecord{
		SourceID: "npm-new", Format: "npm.packument", URL: "https://registry.npmjs.org/foo",
		Status: hopper.MetadataComplete, Record: json.RawMessage(`{"downloads_recent":999,"deprecated":true}`),
	}
	body2, ct2 := provenanceOnlyUpload(t, mustJSON(t, &refresh))
	if w := postUpload(t, api, body2, ct2); w.Code != http.StatusOK {
		t.Fatalf("provenance refresh: code=%d body=%s", w.Code, w.Body.String())
	}

	// The discovery feed survives; the registry snapshot is refreshed.
	raw, err := api.db.ProvenanceBySHA256(ctx, sha)
	if err != nil {
		t.Fatalf("ProvenanceBySHA256 after refresh: %v", err)
	}
	var stored hopper.Sidecar
	if err := json.Unmarshal(raw, &stored); err != nil {
		t.Fatalf("unmarshal stored provenance: %v", err)
	}
	if stored.Feed == nil || stored.Feed.SourceID != "npm-firehose" {
		t.Errorf("discovery feed not preserved across refresh: %+v", stored.Feed)
	}
	if stored.Registry == nil || stored.Registry.SourceID != "npm-new" {
		t.Errorf("registry snapshot not refreshed: %+v", stored.Registry)
	}
	if !bytes.Contains(stored.Registry.Record, []byte("deprecated")) {
		t.Errorf("refreshed registry record missing new data: %s", stored.Registry.Record)
	}

	// --- Updated verdict on re-scan: a different report replaces the findings. ---
	secondResult := postDepResult(t, api, sha, "pe", 100)
	if bytes.Equal(firstResult, secondResult) {
		t.Error("re-scan did not update the stored findings")
	}
}

func TestHandleKnown(t *testing.T) {
	t.Parallel()
	api := uploadAPI(t)
	ctx := context.Background()

	have := []string{strings.Repeat("a", 64), strings.Repeat("b", 64)}
	for i, sha := range have {
		if err := api.db.InsertSample(ctx, &hopper.Sample{
			SHA256: sha, Source: "test", Path: "test/" + strconv.Itoa(i), Label: "unknown",
		}); err != nil {
			t.Fatalf("insert %s: %v", sha, err)
		}
	}
	missing := strings.Repeat("c", 64)

	reqBody := mustJSON(t, knownRequest{SHA256: append(append([]string{}, have...), missing, "NOT-HEX")})
	r := httptest.NewRequest(http.MethodPost, "/api/known", bytes.NewReader(reqBody))
	r.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()
	api.handleKnown(w, r)
	if w.Code != http.StatusOK {
		t.Fatalf("code=%d body=%s want 200", w.Code, w.Body.String())
	}

	var resp knownResponse
	if err := json.Unmarshal(w.Body.Bytes(), &resp); err != nil {
		t.Fatalf("decode: %v", err)
	}
	gotKnown := map[string]bool{}
	for _, s := range resp.Known {
		gotKnown[s] = true
	}
	if !gotKnown[have[0]] || !gotKnown[have[1]] {
		t.Errorf("known = %v, want both inserted digests", resp.Known)
	}
	if gotKnown[missing] {
		t.Errorf("known includes the absent digest %s", missing)
	}
	if len(resp.Known) != 2 {
		t.Errorf("known has %d entries, want 2 (malformed entry must be dropped)", len(resp.Known))
	}
}

func TestHandleKnownBatchCap(t *testing.T) {
	t.Parallel()
	api := uploadAPI(t)
	shas := make([]string, maxKnownBatch+1)
	for i := range shas {
		shas[i] = strings.Repeat("a", 64)
	}
	reqBody := mustJSON(t, knownRequest{SHA256: shas})
	r := httptest.NewRequest(http.MethodPost, "/api/known", bytes.NewReader(reqBody))
	w := httptest.NewRecorder()
	api.handleKnown(w, r)
	if w.Code != http.StatusRequestEntityTooLarge {
		t.Errorf("code=%d want 413 for oversized batch", w.Code)
	}
}

func TestHandleUploadMultipartRejections(t *testing.T) {
	t.Parallel()
	file := []byte("some bytes")
	sum := sha256.Sum256(file)
	sha := hex.EncodeToString(sum[:])

	t.Run("sha mismatch", func(t *testing.T) {
		t.Parallel()
		api := uploadAPI(t)
		wrong := strings.Repeat("0", 64)
		body, ct := multipartUpload(t, validProvenance(t, file, wrong), file, true)
		if w := postUpload(t, api, body, ct); w.Code != http.StatusBadRequest {
			t.Errorf("code=%d body=%s want 400", w.Code, w.Body.String())
		}
	})

	t.Run("file before provenance", func(t *testing.T) {
		t.Parallel()
		api := uploadAPI(t)
		body, ct := multipartUpload(t, validProvenance(t, file, sha), file, false)
		if w := postUpload(t, api, body, ct); w.Code != http.StatusBadRequest {
			t.Errorf("code=%d body=%s want 400", w.Code, w.Body.String())
		}
	})

	t.Run("invalid provenance json", func(t *testing.T) {
		t.Parallel()
		api := uploadAPI(t)
		body, ct := multipartUpload(t, []byte("{not json"), file, true)
		if w := postUpload(t, api, body, ct); w.Code != http.StatusBadRequest {
			t.Errorf("code=%d body=%s want 400", w.Code, w.Body.String())
		}
	})

	t.Run("provenance too large", func(t *testing.T) {
		t.Parallel()
		api := uploadAPI(t)
		// A provenance part past the transport cap must be rejected as oversized,
		// not truncated into unparseable JSON and misreported as invalid. Pad
		// well-formed JSON past uploadProvenanceMaxBytes; the read never parses it.
		oversized := append([]byte(`{"pad":"`), bytes.Repeat([]byte("a"), uploadProvenanceMaxBytes+1)...)
		oversized = append(oversized, []byte(`"}`)...)
		body, ct := multipartUpload(t, oversized, file, true)
		w := postUpload(t, api, body, ct)
		if w.Code != http.StatusRequestEntityTooLarge {
			t.Errorf("code=%d body=%s want 413", w.Code, w.Body.String())
		}
		if !strings.Contains(w.Body.String(), "provenance too large") {
			t.Errorf("body=%s want provenance too large", w.Body.String())
		}
	})

	t.Run("missing required field", func(t *testing.T) {
		t.Parallel()
		api := uploadAPI(t)
		// Valid JSON, valid sha, but no collector — Validate must reject.
		sc := hopper.Sidecar{
			SchemaVersion: hopper.SidecarSchemaVersion,
			Artifact:      hopper.Artifact{Filename: "x.tgz", SHA256: sha},
			Fetch:         hopper.Fetch{Category: "new", At: time.Now().UTC()},
		}
		prov := mustJSON(t, &sc)
		body, ct := multipartUpload(t, prov, file, true)
		if w := postUpload(t, api, body, ct); w.Code != http.StatusBadRequest {
			t.Errorf("code=%d body=%s want 400", w.Code, w.Body.String())
		}
	})
}

// TestClassifyResultError pins which worker-reported errors are permanent
// (marked skip, never re-queued) versus transient (re-queued). The deterministic
// analysis-guard trips must be permanent; the load-shedding errors must not be,
// since they succeed once the worker pool drains.
func TestClassifyResultError(t *testing.T) {
	tests := []struct {
		name     string
		errMsg   string
		wantSkip string
		wantPerm bool
	}{
		{"file count guard", "cleave analysis of x.zip: Exceeded maximum file count (100000)", "oversized", true},
		{"extraction size guard", "cleave analysis of x.zip: Exceeded maximum total extraction size", "oversized", true},
		{"archive depth guard", "cleave analysis of x.zip: Maximum archive depth (8) exceeded", "oversized", true},
		{"decode depth guard", "cleave analysis of x.gz: Maximum decode depth 8 exceeded", "oversized", true},
		{"file count limit", "file count limit exceeded", "oversized", true},
		{"zip bomb", "Archive has suspicious compression ratio (potential zip bomb)", "oversized", true},
		{"worker size cap", "file size 17179869185 exceeds per-job cap of 17179869184 bytes", "oversized", true},
		{"legacy prefetch cap", "file size 1359668904 exceeds per-job prefetch cap of 536870912 bytes", "oversized", true},
		{"corrupt gzip", "cleave analysis of x.tar.gz: Failed to read tar entry: invalid gzip header", "corrupt", true},
		{"missing", "Path does not exist", "missing", true},
		// Load-shedding must stay retryable: the same input succeeds once capacity frees up.
		{"too many active tasks", "Rejecting request: too many active analysis tasks", "", false},
		{"server overloaded", "Server overloaded (too many active analyses)", "", false},
		{"unknown transient", "connection reset by peer", "", false},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			skip, perm := classifyResultError(tc.errMsg)
			if perm != tc.wantPerm || skip != tc.wantSkip {
				t.Errorf("classifyResultError(%q) = (%q, %v), want (%q, %v)",
					tc.errMsg, skip, perm, tc.wantSkip, tc.wantPerm)
			}
		})
	}
}

// TestHandleResultMissingRespectsDatasetIncomplete pins the disconnected-dataset
// contract for the worker-error path: a "Path does not exist" report marks the
// sample skip='missing' by default, but in --dataset-incomplete mode it is
// demoted to a transient error (note recorded, skip left empty) so the record
// stays trainable and the missing-marking never replicates to the primary.
func TestHandleResultMissingRespectsDatasetIncomplete(t *testing.T) {
	for _, tc := range []struct {
		name              string
		datasetIncomplete bool
		wantSkip          string
	}{
		{"default marks missing", false, "missing"},
		{"dataset-incomplete leaves trainable", true, ""},
	} {
		t.Run(tc.name, func(t *testing.T) {
			ctx := context.Background()
			db := mustOpenDB(t, ctx, t.TempDir()+"/hopper.db")
			defer db.Close()
			if err := db.Migrate(ctx); err != nil {
				t.Fatalf("Migrate: %v", err)
			}

			sha := "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb"
			if err := db.InsertSample(ctx, &hopper.Sample{
				SHA256: sha, Source: "test", Path: "bad/gone.bin",
				Label: "bad", LabelSource: "test",
			}); err != nil {
				t.Fatalf("InsertSample: %v", err)
			}

			body, err := json.Marshal(resultRequest{
				SHA256: sha, Worker: "worker1", Error: "Path does not exist",
			})
			if err != nil {
				t.Fatalf("Marshal: %v", err)
			}
			req := httptest.NewRequest(http.MethodPost, "/api/result", bytes.NewReader(body))
			rec := httptest.NewRecorder()
			api := &apiServer{
				db: db, tracker: newWorkerTracker(), progress: &loadProgress{},
				datasetIncomplete: tc.datasetIncomplete,
			}

			api.handleResult(rec, req)
			if rec.Code != http.StatusOK {
				t.Fatalf("status = %d, body = %s", rec.Code, rec.Body.String())
			}

			sample, err := db.SampleBySHA256(ctx, sha)
			if err != nil {
				t.Fatalf("SampleBySHA256: %v", err)
			}
			if sample.Skip != tc.wantSkip {
				t.Errorf("skip = %q, want %q", sample.Skip, tc.wantSkip)
			}
		})
	}
}

// TestAcquireSlot pins the shed-fast contract: a free slot is taken instantly, a
// saturated pool sheds with errSaturated within the bound (not blocking until
// the client times out), and a cancelled context returns its own error so the
// caller can tell "client gave up" from "server saturated".
func TestAcquireSlot(t *testing.T) {
	t.Run("free slot acquires immediately", func(t *testing.T) {
		sem := make(chan struct{}, 1)
		if err := acquireSlotWithin(context.Background(), sem, time.Second); err != nil {
			t.Fatalf("acquire on free pool: %v", err)
		}
	})

	t.Run("nil pool is unlimited", func(t *testing.T) {
		if err := acquireSlotWithin(context.Background(), nil, time.Second); err != nil {
			t.Fatalf("acquire on nil pool: %v", err)
		}
	})

	t.Run("saturated pool sheds within the bound", func(t *testing.T) {
		sem := make(chan struct{}, 1)
		sem <- struct{}{} // pool full
		start := time.Now()
		err := acquireSlotWithin(context.Background(), sem, 20*time.Millisecond)
		elapsed := time.Since(start)
		if !errors.Is(err, errSaturated) {
			t.Fatalf("saturated acquire = %v, want errSaturated", err)
		}
		if elapsed > 500*time.Millisecond {
			t.Fatalf("shed took %v, expected to bail near the 20ms bound", elapsed)
		}
	})

	t.Run("freed slot is taken before the bound", func(t *testing.T) {
		sem := make(chan struct{}, 1)
		sem <- struct{}{}
		go func() {
			time.Sleep(10 * time.Millisecond)
			<-sem // free it
		}()
		if err := acquireSlotWithin(context.Background(), sem, time.Second); err != nil {
			t.Fatalf("acquire after slot freed: %v", err)
		}
	})

	t.Run("cancelled context returns ctx error, not errSaturated", func(t *testing.T) {
		sem := make(chan struct{}, 1)
		sem <- struct{}{} // pool full
		ctx, cancel := context.WithCancel(context.Background())
		cancel()
		err := acquireSlotWithin(ctx, sem, time.Second)
		if !errors.Is(err, context.Canceled) {
			t.Fatalf("cancelled acquire = %v, want context.Canceled", err)
		}
	})
}

// TestHandleRescan covers the re-queue endpoint prism's rescan button drives: an
// eligible top-level sample is queued (200 {"status":"queued"}), an unknown sha
// is refused as not-eligible (409), a malformed sha is rejected before any DB
// access (400), and a not-yet-ready server reports starting (503).
func TestHandleRescan(t *testing.T) {
	t.Parallel()
	api := uploadAPI(t)
	ctx := context.Background()

	sha := strings.Repeat("a", 64)
	if err := api.db.InsertSample(ctx, &hopper.Sample{
		SHA256: sha, Source: "test", Path: "test/a", Label: "unknown",
	}); err != nil {
		t.Fatalf("InsertSample: %v", err)
	}

	post := func(target string) *httptest.ResponseRecorder {
		r := httptest.NewRequest(http.MethodPost, "/api/rescan/"+target, http.NoBody)
		r.SetPathValue("sha256", target)
		rec := httptest.NewRecorder()
		api.handleRescan(rec, r)
		return rec
	}

	// Eligible: a freshly inserted, never-analyzed top-level sample re-queues.
	rec := post(sha)
	if rec.Code != http.StatusOK {
		t.Fatalf("eligible rescan: status = %d, want 200 (body %s)", rec.Code, rec.Body.String())
	}
	var got map[string]string
	if err := json.Unmarshal(rec.Body.Bytes(), &got); err != nil {
		t.Fatalf("decode body: %v", err)
	}
	if got["status"] != "queued" {
		t.Errorf("status field = %q, want %q", got["status"], "queued")
	}

	// Unknown sha: RequestRescan affects zero rows -> not eligible.
	if rec := post(strings.Repeat("b", 64)); rec.Code != http.StatusConflict {
		t.Errorf("unknown sha: status = %d, want 409", rec.Code)
	}

	// Malformed sha: rejected before any DB access.
	if rec := post("NOT-A-VALID-SHA"); rec.Code != http.StatusBadRequest {
		t.Errorf("bad sha: status = %d, want 400", rec.Code)
	}

	// DB still starting (db nil): 503.
	starting := &apiServer{}
	r := httptest.NewRequest(http.MethodPost, "/api/rescan/"+sha, http.NoBody)
	r.SetPathValue("sha256", sha)
	rec = httptest.NewRecorder()
	starting.handleRescan(rec, r)
	if rec.Code != http.StatusServiceUnavailable {
		t.Errorf("starting: status = %d, want 503", rec.Code)
	}
}

// TestHandleFileMarksMissing: a top-level row whose bytes vanished from disk
// must be marked skip='missing' on the first fetch (410), so the selection
// queries promoter/gauntlet run stop returning it. Files that are present, or
// servers in dataset-incomplete mode, must not mark.
func TestHandleFileMarksMissing(t *testing.T) {
	ctx := context.Background()
	root := t.TempDir()
	db := mustOpenDB(t, ctx, filepath.Join(root, "hopper.db"))
	defer db.Close()
	if err := db.Migrate(ctx); err != nil {
		t.Fatalf("Migrate: %v", err)
	}

	resolvedRoot, err := filepath.EvalSymlinks(root)
	if err != nil {
		t.Fatalf("EvalSymlinks: %v", err)
	}

	goneSHA := strings.Repeat("a", 64)
	hereSHA := strings.Repeat("b", 64)
	for _, s := range []*hopper.Sample{
		{SHA256: goneSHA, Source: "test", Path: "bad/gone.bin", Label: "bad", LabelSource: "test"},
		{SHA256: hereSHA, Source: "test", Path: "bad/here.bin", Label: "bad", LabelSource: "test"},
	} {
		if err := db.InsertSample(ctx, s); err != nil {
			t.Fatalf("InsertSample: %v", err)
		}
	}
	if err := os.MkdirAll(filepath.Join(root, "bad"), 0o750); err != nil {
		t.Fatalf("mkdir: %v", err)
	}
	if err := os.WriteFile(filepath.Join(root, "bad", "here.bin"), []byte("x"), 0o600); err != nil {
		t.Fatalf("write: %v", err)
	}

	api := &apiServer{db: db, dataRoot: root, allowedDirs: []string{resolvedRoot}, tracker: newWorkerTracker()}

	get := func(t *testing.T, srv *apiServer, sha string) int {
		t.Helper()
		r := httptest.NewRequest(http.MethodGet, "/api/file/"+sha, http.NoBody)
		r.SetPathValue("sha256", sha)
		rec := httptest.NewRecorder()
		srv.handleFile(rec, r)
		return rec.Code
	}
	skipOf := func(t *testing.T, sha string) string {
		t.Helper()
		samp, err := db.SampleBySHA256(ctx, sha)
		if err != nil {
			t.Fatalf("SampleBySHA256: %v", err)
		}
		return samp.Skip
	}

	// Vanished bytes: 410 and the row is marked missing.
	if code := get(t, api, goneSHA); code != http.StatusGone {
		t.Fatalf("gone file: status = %d, want 410", code)
	}
	if got := skipOf(t, goneSHA); got != "missing" {
		t.Errorf("gone file: skip = %q, want %q", got, "missing")
	}
	// A direct SHA fetch is also a recovery signal. If the original bytes come
	// back before the next walk, serving clears the stale missing mark.
	if err := os.WriteFile(filepath.Join(root, "bad", "gone.bin"), []byte("revived"), 0o600); err != nil {
		t.Fatal(err)
	}
	if code := get(t, api, goneSHA); code != http.StatusOK {
		t.Fatalf("revived file: status = %d, want 200", code)
	}
	if got := skipOf(t, goneSHA); got != "" {
		t.Errorf("revived file: skip = %q, want empty", got)
	}

	// Present bytes: 200 and no mark.
	if code := get(t, api, hereSHA); code != http.StatusOK {
		t.Fatalf("present file: status = %d, want 200", code)
	}
	if got := skipOf(t, hereSHA); got != "" {
		t.Errorf("present file: skip = %q, want empty", got)
	}

	// Dataset-incomplete: local disk is not authoritative, so a vanished file
	// still 410s this request but must not be marked.
	if err := os.Remove(filepath.Join(root, "bad", "gone.bin")); err != nil {
		t.Fatal(err)
	}
	incomplete := &apiServer{db: db, dataRoot: root, allowedDirs: []string{resolvedRoot}, tracker: newWorkerTracker(), datasetIncomplete: true}
	if code := get(t, incomplete, goneSHA); code != http.StatusGone {
		t.Fatalf("dataset-incomplete: status = %d, want 410", code)
	}
	if got := skipOf(t, goneSHA); got != "" {
		t.Errorf("dataset-incomplete: skip = %q, want empty", got)
	}
}

func TestHandleFileReactivatesPrunedPrimaryLocation(t *testing.T) {
	ctx := context.Background()
	root := t.TempDir()
	db := mustOpenDB(t, ctx, filepath.Join(root, "hopper.db"))
	defer db.Close()
	if err := db.Migrate(ctx); err != nil {
		t.Fatal(err)
	}
	resolvedRoot, err := filepath.EvalSymlinks(root)
	if err != nil {
		t.Fatal(err)
	}
	sha := strings.Repeat("2", 64)
	rel := "pending/feed/revived.bin"
	if err := db.InsertSample(ctx, &hopper.Sample{SHA256: sha, Source: "test", Path: rel, Label: "unknown"}); err != nil {
		t.Fatal(err)
	}
	if removed, err := db.PruneMissingLocations(ctx, root, 1); err != nil || removed != 1 {
		t.Fatalf("prune = %d, %v", removed, err)
	}
	locations, err := db.TopLevelLocationsForSHA(ctx, sha)
	if err != nil || len(locations) != 0 {
		t.Fatalf("locations after prune = %+v, %v", locations, err)
	}
	abs := filepath.Join(root, filepath.FromSlash(rel))
	if err := os.MkdirAll(filepath.Dir(abs), 0o750); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(abs, []byte("back again"), 0o600); err != nil {
		t.Fatal(err)
	}

	api := &apiServer{db: db, dataRoot: root, allowedDirs: []string{resolvedRoot}, tracker: newWorkerTracker()}
	r := httptest.NewRequest(http.MethodGet, "/api/file/"+sha, http.NoBody)
	r.SetPathValue("sha256", sha)
	rec := httptest.NewRecorder()
	api.handleFile(rec, r)
	if rec.Code != http.StatusOK || rec.Body.String() != "back again" {
		t.Fatalf("response = %d %q", rec.Code, rec.Body.String())
	}
	sample, err := db.SampleBySHA256(ctx, sha)
	if err != nil || sample.Skip != "" {
		t.Fatalf("reactivated sample = %+v, %v", sample, err)
	}
	locations, err = db.TopLevelLocationsForSHA(ctx, sha)
	if err != nil || len(locations) != 1 || locations[0].Path != rel {
		t.Fatalf("reactivated locations = %+v, %v", locations, err)
	}
	retired, err := db.RetiredLocationsForSHA(ctx, sha)
	if err != nil || len(retired) != 1 || retired[0].Path != rel {
		t.Fatalf("retired audit after reactivation = %+v, %v", retired, err)
	}
}

func TestHandleFileFallsBackAndHealsPrimaryPath(t *testing.T) {
	ctx := context.Background()
	root := t.TempDir()
	db := mustOpenDB(t, ctx, filepath.Join(root, "hopper.db"))
	defer db.Close()
	if err := db.Migrate(ctx); err != nil {
		t.Fatalf("Migrate: %v", err)
	}
	resolvedRoot, err := filepath.EvalSymlinks(root)
	if err != nil {
		t.Fatal(err)
	}

	sha := strings.Repeat("c", 64)
	validPath := "pending/feed/sample.bin"
	stalePath := "incoming/feed/sample.bin"
	validAbs := filepath.Join(root, filepath.FromSlash(validPath))
	if err := os.MkdirAll(filepath.Dir(validAbs), 0o750); err != nil {
		t.Fatal(err)
	}
	want := []byte("fallback bytes")
	if err := os.WriteFile(validAbs, want, 0o600); err != nil {
		t.Fatal(err)
	}
	// The later observation becomes samples.path, while both paths remain in
	// sample_locations. This models a stale canonical path after a manual move.
	for _, path := range []string{validPath, stalePath} {
		if err := db.InsertSample(ctx, &hopper.Sample{SHA256: sha, Source: "test", Path: path, Label: "unknown"}); err != nil {
			t.Fatal(err)
		}
	}
	if err := db.SetSkip(ctx, sha, "missing"); err != nil {
		t.Fatal(err)
	}

	var logs bytes.Buffer
	previousLogger := slog.Default()
	slog.SetDefault(slog.New(slog.NewJSONHandler(&logs, nil)))
	t.Cleanup(func() { slog.SetDefault(previousLogger) })

	api := &apiServer{db: db, dataRoot: root, allowedDirs: []string{resolvedRoot}, tracker: newWorkerTracker()}
	r := httptest.NewRequest(http.MethodGet, "/api/file/"+sha, http.NoBody)
	r.SetPathValue("sha256", sha)
	rec := httptest.NewRecorder()
	api.handleFile(rec, r)
	if rec.Code != http.StatusOK || !bytes.Equal(rec.Body.Bytes(), want) {
		t.Fatalf("fallback response = %d %q", rec.Code, rec.Body.Bytes())
	}
	sample, err := db.SampleBySHA256(ctx, sha)
	if err != nil {
		t.Fatal(err)
	}
	if sample.Path != validPath || sample.Skip != "" {
		t.Fatalf("healed sample = path %q skip %q", sample.Path, sample.Skip)
	}
	locations, err := db.TopLevelLocationsForSHA(ctx, sha)
	if err != nil || len(locations) != 2 {
		t.Fatalf("active locations = %+v, %v", locations, err)
	}
	logText := logs.String()
	for _, field := range []string{
		`"msg":"sample path fallback succeeded"`,
		`"old_path":"incoming/feed/sample.bin"`,
		`"selected_path":"pending/feed/sample.bin"`,
		`"candidate_count":2`,
		`"primary_healed":true`,
	} {
		if !strings.Contains(logText, field) {
			t.Errorf("fallback log missing %s: %s", field, logText)
		}
	}
}

func TestHandleFileFallbackMarksMissingOnlyAfterAllLocationsFail(t *testing.T) {
	ctx := context.Background()
	root := t.TempDir()
	db := mustOpenDB(t, ctx, filepath.Join(root, "hopper.db"))
	defer db.Close()
	if err := db.Migrate(ctx); err != nil {
		t.Fatal(err)
	}
	resolvedRoot, err := filepath.EvalSymlinks(root)
	if err != nil {
		t.Fatal(err)
	}
	sha := strings.Repeat("d", 64)
	for _, path := range []string{"pending/feed/gone.bin", "incoming/feed/gone.bin"} {
		if err := db.InsertSample(ctx, &hopper.Sample{SHA256: sha, Source: "test", Path: path, Label: "unknown"}); err != nil {
			t.Fatal(err)
		}
	}
	api := &apiServer{db: db, dataRoot: root, allowedDirs: []string{resolvedRoot}, tracker: newWorkerTracker()}
	r := httptest.NewRequest(http.MethodGet, "/api/file/"+sha, http.NoBody)
	r.SetPathValue("sha256", sha)
	rec := httptest.NewRecorder()
	api.handleFile(rec, r)
	if rec.Code != http.StatusGone {
		t.Fatalf("status = %d, want 410", rec.Code)
	}
	sample, err := db.SampleBySHA256(ctx, sha)
	if err != nil || sample.Skip != "missing" {
		t.Fatalf("sample after failed fallbacks = %+v, %v", sample, err)
	}
}

func TestHandleNextFallsBackBeforeMarkingClaimMissing(t *testing.T) {
	ctx := context.Background()
	root := t.TempDir()
	db := mustOpenDB(t, ctx, filepath.Join(root, "hopper.db"))
	defer db.Close()
	if err := db.Migrate(ctx); err != nil {
		t.Fatal(err)
	}
	resolvedRoot, err := filepath.EvalSymlinks(root)
	if err != nil {
		t.Fatal(err)
	}
	sha := strings.Repeat("1", 64)
	wantPath := "pending/feed/claim.bin"
	stalePath := "incoming/feed/claim.bin"
	wantAbs := filepath.Join(root, filepath.FromSlash(wantPath))
	if err := os.MkdirAll(filepath.Dir(wantAbs), 0o750); err != nil {
		t.Fatal(err)
	}
	content := []byte("claim fallback")
	if err := os.WriteFile(wantAbs, content, 0o600); err != nil {
		t.Fatal(err)
	}
	for _, path := range []string{wantPath, stalePath} {
		if err := db.InsertSample(ctx, &hopper.Sample{
			SHA256: sha, Source: "test", Path: path, Label: "unknown", SizeBytes: int64(len(content)),
		}); err != nil {
			t.Fatal(err)
		}
	}

	api := &apiServer{db: db, dataRoot: root, allowedDirs: []string{resolvedRoot}, tracker: newWorkerTracker()}
	r := httptest.NewRequest(http.MethodGet, "/api/next?worker=tester&count=1&slots=1", http.NoBody)
	rec := httptest.NewRecorder()
	api.handleNext(rec, r)
	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, body = %s", rec.Code, rec.Body.String())
	}
	var response struct {
		Jobs []hopper.ClaimJob `json:"jobs"`
	}
	if err := json.Unmarshal(rec.Body.Bytes(), &response); err != nil {
		t.Fatal(err)
	}
	if len(response.Jobs) != 1 || response.Jobs[0].SHA256 != sha || response.Jobs[0].Path != wantPath {
		t.Fatalf("jobs = %+v", response.Jobs)
	}
	sample, err := db.SampleBySHA256(ctx, sha)
	if err != nil || sample.Path != wantPath || sample.Skip != "" {
		t.Fatalf("sample after claim fallback = %+v, %v", sample, err)
	}
}

func TestHandleArchiveMemberFallsBackToKnownParentLocation(t *testing.T) {
	ctx := context.Background()
	root := t.TempDir()
	db := mustOpenDB(t, ctx, filepath.Join(root, "hopper.db"))
	defer db.Close()
	if err := db.Migrate(ctx); err != nil {
		t.Fatal(err)
	}
	resolvedRoot, err := filepath.EvalSymlinks(root)
	if err != nil {
		t.Fatal(err)
	}

	parentSHA := strings.Repeat("e", 64)
	childSHA := strings.Repeat("f", 64)
	validPath := "pending/feed/parent.zip"
	stalePath := "incoming/feed/parent.zip"
	validAbs := filepath.Join(root, filepath.FromSlash(validPath))
	if err := os.MkdirAll(filepath.Dir(validAbs), 0o750); err != nil {
		t.Fatal(err)
	}
	f, err := os.Create(validAbs)
	if err != nil {
		t.Fatal(err)
	}
	zw := zip.NewWriter(f)
	entry, err := zw.Create("pkg/member.txt")
	if err != nil {
		t.Fatal(err)
	}
	want := []byte("member bytes")
	if _, err := entry.Write(want); err != nil {
		t.Fatal(err)
	}
	if err := zw.Close(); err != nil {
		t.Fatal(err)
	}
	if err := f.Close(); err != nil {
		t.Fatal(err)
	}
	analysis := []byte(`{"files":[{"type":"zip"}]}`)
	for _, path := range []string{validPath, stalePath} {
		if err := db.InsertSample(ctx, &hopper.Sample{
			SHA256: parentSHA, Source: "test", Path: path, Label: "unknown", CleaveResult: analysis,
		}); err != nil {
			t.Fatal(err)
		}
	}
	if err := db.InsertSample(ctx, &hopper.Sample{
		SHA256: childSHA, Source: "test", Parent: parentSHA,
		Path: parentSHA + "!!pkg/member.txt", Label: "unknown",
	}); err != nil {
		t.Fatal(err)
	}

	api := &apiServer{db: db, dataRoot: root, allowedDirs: []string{resolvedRoot}, tracker: newWorkerTracker()}
	r := httptest.NewRequest(http.MethodGet, "/api/file/"+childSHA, http.NoBody)
	r.SetPathValue("sha256", childSHA)
	rec := httptest.NewRecorder()
	api.handleFile(rec, r)
	if rec.Code != http.StatusOK || !bytes.Equal(rec.Body.Bytes(), want) {
		t.Fatalf("archive fallback response = %d %q", rec.Code, rec.Body.Bytes())
	}
	parent, err := db.SampleBySHA256(ctx, parentSHA)
	if err != nil || parent.Path != validPath {
		t.Fatalf("healed parent = %+v, %v", parent, err)
	}
}
