package main

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"io/fs"
	"log/slog"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"time"

	"codeberg.org/atomdrift/hopper"
)

// post-triage closes the triage loop. After an operator (or an /xtriage-*
// run) sorts mislabeled samples into misplaced-good/ (actually benign) and
// misplaced-bad/ (actually hostile) and fixes the cleave rules, this:
//
//  1. (default) re-uploads fresh analysis for the triaged directories by
//     shelling out to `scan --hopper <url> <dir>` so the corrected verdicts
//     land before the labels flip;
//  2. hashes each misplaced file and POSTs {sha256, verdict} to the master's
//     /api/triage, which moves the on-disk artifact into its corrected pool
//     bucket (<verdict>/mislabeled-<old-label>/) and flips the DB label.
//
// The client is deliberately thin and stateless: it ships SHA-256s, never
// file bytes. The master already holds the artifact on /data/samples — this
// relocates it in place. That keeps the master the sole authority over the
// data pool and the writable database, which matters when post-triage runs
// on a remote dev box (where the cleave work happens) rather than on the
// master itself.

const (
	defaultMisplacedGood = "/tmp/triage/misplaced-good"
	defaultMisplacedBad  = "/tmp/triage/misplaced-bad"
	// maxTriageVerdicts caps a single /api/triage request. Triage runs move
	// dozens of files; this is a generous backstop against a malformed batch.
	maxTriageVerdicts = 10_000
)

// triageVerdict is one corrected classification: the sample identified by
// SHA256 is actually Verdict ("good" or "bad").
type triageVerdict struct {
	SHA256  string `json:"sha256"`
	Verdict string `json:"verdict"`
}

// triageRequest is the JSON body for POST /api/triage.
type triageRequest struct {
	Verdicts []triageVerdict `json:"verdicts"`
	DryRun   bool            `json:"dry_run"`
}

// triageResult reports the outcome for one verdict. Status is one of:
// "moved" (relocated + relabeled), "plan" (dry-run, would move),
// "noop" (already in the corrected pool), "not_found" (unknown sha or no
// on-disk pool copy), or "error".
type triageResult struct {
	SHA256  string `json:"sha256"`
	Status  string `json:"status"`
	OldPath string `json:"old_path,omitempty"`
	NewPath string `json:"new_path,omitempty"`
	Error   string `json:"error,omitempty"`
}

// triageResponse is the JSON body returned by POST /api/triage.
type triageResponse struct {
	Results []triageResult `json:"results"`
	Moved   int            `json:"moved"`
	Noop    int            `json:"noop"`
	Failed  int            `json:"failed"`
}

// handleTriage applies a batch of corrected verdicts. Auth mirrors
// /api/upload: a Bearer token (when configured) plus the cross-site CSRF
// guard. The heavy lifting — disk move + DB flip — is in relocateTriaged.
func (s *apiServer) handleTriage(w http.ResponseWriter, r *http.Request) {
	if err := s.checkUploadAuth(r); err != nil {
		writeJSONError(w, http.StatusUnauthorized, err.Error())
		return
	}
	if err := checkBrowserCSRF(r); err != nil {
		writeJSONError(w, http.StatusForbidden, err.Error())
		return
	}
	if s.dataRoot == "" {
		writeJSONError(w, http.StatusServiceUnavailable, "data root not configured")
		return
	}

	var req triageRequest
	dec := json.NewDecoder(io.LimitReader(r.Body, 4<<20)) // verdicts are tiny; 4 MiB is plenty
	dec.DisallowUnknownFields()
	if err := dec.Decode(&req); err != nil {
		writeJSONError(w, http.StatusBadRequest, "decode body: "+err.Error())
		return
	}
	if len(req.Verdicts) == 0 {
		writeJSONError(w, http.StatusBadRequest, "no verdicts")
		return
	}
	if len(req.Verdicts) > maxTriageVerdicts {
		writeJSONError(w, http.StatusRequestEntityTooLarge,
			fmt.Sprintf("too many verdicts: %d > %d", len(req.Verdicts), maxTriageVerdicts))
		return
	}

	resp := triageResponse{Results: make([]triageResult, 0, len(req.Verdicts))}
	for _, v := range req.Verdicts {
		res := s.relocateTriaged(r.Context(), v, req.DryRun)
		switch res.Status {
		case "moved", "plan":
			resp.Moved++
		case "noop":
			resp.Noop++
		default:
			resp.Failed++
		}
		resp.Results = append(resp.Results, res)
	}

	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(resp) //nolint:errcheck,errchkjson // best-effort response
}

// relocateTriaged moves one sample into its corrected pool bucket and flips
// its DB label. It is idempotent: a sample already carrying the verdict label
// returns "noop" so re-running a batch is safe.
func (s *apiServer) relocateTriaged(ctx context.Context, v triageVerdict, dryRun bool) triageResult {
	res := triageResult{SHA256: v.SHA256}
	sha := strings.ToLower(strings.TrimSpace(v.SHA256))
	if !validSHA256(sha) {
		res.Status, res.Error = "error", "invalid sha256"
		return res
	}
	res.SHA256 = sha
	switch v.Verdict {
	case "good", "bad":
	default:
		res.Status, res.Error = "error", "verdict must be \"good\" or \"bad\""
		return res
	}

	samp, err := s.db.SampleBySHA256(ctx, sha)
	if errors.Is(err, hopper.ErrNotFound) {
		res.Status = "not_found"
		return res
	}
	if err != nil {
		res.Status, res.Error = "error", err.Error()
		return res
	}
	if samp.Path == "" {
		res.Status, res.Error = "not_found", "sample has no on-disk path"
		return res
	}
	// Already corrected — nothing to move.
	if samp.Label == v.Verdict {
		res.Status, res.OldPath = "noop", samp.Path
		return res
	}

	oldRel := relativeSamplePath(s.dataRoot, samp.Path)
	oldAbs := sampleDiskPath(s.dataRoot, oldRel)
	res.OldPath = oldRel

	// Bucket records the wrong label the file is being rescued from, so a
	// good→bad correction lands in bad/mislabeled-good and bad→good in
	// good/mislabeled-bad. Fall back to "unknown" for the odd legacy row.
	wrong := samp.Label
	if wrong == "" {
		wrong = "unknown"
	}
	newRel := filepath.Join(v.Verdict, "mislabeled-"+wrong, filepath.Base(oldRel))
	newAbs, err := s.resolveDataPath(newRel)
	if err != nil {
		res.Status, res.Error = "error", err.Error()
		return res
	}
	// Disambiguate a basename collision in the shared bucket by prefixing the
	// sha; keeps the bucket flat and human-browsable while staying unique.
	if collides, err := pathExists(newAbs); err != nil {
		res.Status, res.Error = "error", err.Error()
		return res
	} else if collides {
		base := filepath.Base(oldRel)
		ext := filepath.Ext(base)
		stem := strings.TrimSuffix(base, ext)
		newRel = filepath.Join(v.Verdict, "mislabeled-"+wrong, stem+"."+sha[:12]+ext)
		if newAbs, err = s.resolveDataPath(newRel); err != nil {
			res.Status, res.Error = "error", err.Error()
			return res
		}
	}
	res.NewPath = newRel

	if dryRun {
		res.Status = "plan"
		return res
	}

	if err := mkdirSharedAll(filepath.Dir(newAbs)); err != nil {
		res.Status, res.Error = "error", "mkdir: "+err.Error()
		return res
	}
	if err := os.Rename(oldAbs, newAbs); err != nil {
		res.Status, res.Error = "error", "rename: "+err.Error()
		return res
	}
	// The DB verdict is now authoritative; drop any stale litmus markers left
	// beside the old location so a future walk can't resurrect the wrong label.
	removeMarkers(oldAbs)

	if err := s.db.RelocateSample(ctx, sha, oldRel, newRel, v.Verdict, "triage"); err != nil {
		// The bytes already moved; report the error but leave them in place —
		// the next load walk will reconcile the DB from the new pool location.
		res.Status, res.Error = "error", "db relocate: "+err.Error()
		return res
	}
	res.Status = "moved"
	return res
}

// pathExists reports whether path exists, distinguishing a real stat error
// (e.g. permission denied) from a clean "not there".
func pathExists(path string) (bool, error) {
	_, err := os.Stat(path)
	if err == nil {
		return true, nil
	}
	if errors.Is(err, os.ErrNotExist) {
		return false, nil
	}
	return false, err
}

// removeMarkers deletes the ._<base>.BENIGN / ._<base>.BAD sibling markers of
// a file, best effort. A triage verdict is recorded in the database, so any
// on-disk marker is now redundant and a stale one would contradict the move.
func removeMarkers(samplePath string) {
	dir := filepath.Dir(samplePath)
	base := filepath.Base(samplePath)
	for _, suffix := range []string{markerBenign, markerBad} {
		p := filepath.Join(dir, markerPrefix+base+suffix)
		if err := os.Remove(p); err != nil && !errors.Is(err, os.ErrNotExist) {
			slog.Warn("remove stale marker failed", "path", p, "error", err)
		}
	}
}

// ---------------------------------------------------------------------------
// Client: `hopper post-triage`
// ---------------------------------------------------------------------------

func cmdPostTriage(ctx context.Context) error {
	f := flag.NewFlagSet("post-triage", flag.ExitOnError)
	baseURL := f.String("url", "http://hopper-api:8081/", "hopper master API base URL")
	var misplacedGood, misplacedBad stringListFlag
	f.Var(&misplacedGood, "misplaced-good",
		"dir of files re-classified benign (was bad); repeatable or comma-separated")
	f.Var(&misplacedBad, "misplaced-bad",
		"dir of files re-classified hostile (was good); repeatable or comma-separated")
	noUpload := f.Bool("no-upload", false, "skip pushing fresh analysis (default: scan fs --hopper each misplaced dir first)")
	scanBin := f.String("scan", "scan", "path to the scan (ascan) binary used for --upload")
	token := f.String("token", os.Getenv("HOPPER_UPLOAD_TOKEN"), "upload bearer token (default: $HOPPER_UPLOAD_TOKEN)")
	dryRun := f.Bool("dry-run", false, "ask the master to report the planned moves without touching anything")
	parseFlags(f, os.Args[2:])

	// Default to the skill-produced dirs ONLY when the operator named neither
	// side AND gave no positional dirs. The moment they point at a specific
	// dir — misplaced (flip these) or positional (rescan-only these) — we act
	// on exactly what they listed: naming a good dir must not silently sweep a
	// bad dir, and a plain `post-triage <dir>` rescan must not flip anything.
	if len(misplacedGood) == 0 && len(misplacedBad) == 0 && len(f.Args()) == 0 {
		misplacedGood = stringListFlag{defaultMisplacedGood}
		misplacedBad = stringListFlag{defaultMisplacedBad}
	}

	// 1. Push corrected analysis up the existing /api/result path first, so the
	//    fresh verdicts are stored before the labels flip. Remote-native: scan
	//    already talks to the master over HTTP.
	//
	//    The misplaced dirs are scanned unconditionally: they hold exactly the
	//    samples whose label is about to flip, so their stored analysis is the
	//    stale data this whole step exists to refresh. /xtriage-* relocated them
	//    out of the triage dir, so scanning only the positional dirs would skip
	//    them. Positional args add any extra directories to re-scan.
	scanDirs := dedupExistingDirs(append(append(append([]string{}, misplacedGood...), misplacedBad...), f.Args()...))
	switch {
	case *noUpload:
		// operator opted out
	case *dryRun:
		// A dry run must not mutate the master; the scan upload renews stored
		// results, so skip it and only preview the moves below.
		slog.Info("dry-run: skipping scan upload", "dirs", scanDirs)
	default:
		if len(scanDirs) == 0 {
			slog.Warn("nothing to re-scan: no misplaced dirs and no positional dirs exist")
		}
		for _, dir := range scanDirs {
			if err := runScanUpload(ctx, *scanBin, *baseURL, dir); err != nil {
				return fmt.Errorf("scan upload %s: %w", dir, err)
			}
		}
	}

	// 2. Collect verdicts from the selected misplaced directories.
	var verdicts []triageVerdict
	for _, dir := range misplacedGood {
		v, err := collectVerdicts(dir, "good")
		if err != nil {
			return err
		}
		verdicts = append(verdicts, v...)
	}
	goodCount := len(verdicts)
	for _, dir := range misplacedBad {
		v, err := collectVerdicts(dir, "bad")
		if err != nil {
			return err
		}
		verdicts = append(verdicts, v...)
	}
	bad := verdicts[goodCount:]
	if len(verdicts) == 0 {
		if len(misplacedGood) == 0 && len(misplacedBad) == 0 {
			writeStdoutf("rescan-only: uploaded fresh analysis, no labels to flip\n")
		} else {
			writeStdoutf("no misplaced files found in %v or %v\n",
				[]string(misplacedGood), []string(misplacedBad))
		}
		return nil
	}
	writeStdoutf("collected %d verdict(s): %d good, %d bad\n",
		len(verdicts), len(verdicts)-len(bad), len(bad))

	// 3. POST to the master, which performs the move + label flip on its disk.
	resp, err := postTriage(ctx, *baseURL, *token, triageRequest{Verdicts: verdicts, DryRun: *dryRun})
	if err != nil {
		return err
	}

	for _, r := range resp.Results {
		if r.Status == "moved" || r.Status == "plan" {
			writeStdoutf("  %-9s %s  %s -> %s\n", r.Status, r.SHA256, r.OldPath, r.NewPath)
		} else {
			writeStdoutf("  %-9s %s  %s\n", r.Status, r.SHA256, r.Error)
		}
	}
	verb := "moved"
	if *dryRun {
		verb = "planned"
	}
	writeStdoutf("\nSummary: %d %s, %d noop, %d failed\n", resp.Moved, verb, resp.Noop, resp.Failed)
	if resp.Failed > 0 {
		return fmt.Errorf("post-triage: %d verdict(s) failed", resp.Failed)
	}
	return nil
}

// dedupExistingDirs returns the input dirs that exist and are directories,
// in order, with duplicates (by cleaned path) removed. Non-existent entries
// are dropped silently so an operator who only sorted one direction — or who
// passes no extra positional dirs — gets a clean run.
func dedupExistingDirs(dirs []string) []string {
	seen := make(map[string]struct{}, len(dirs))
	out := make([]string, 0, len(dirs))
	for _, d := range dirs {
		clean := filepath.Clean(d)
		if _, ok := seen[clean]; ok {
			continue
		}
		seen[clean] = struct{}{}
		if info, err := os.Stat(clean); err == nil && info.IsDir() {
			out = append(out, clean)
		}
	}
	return out
}

// runScanUpload shells out to `scan fs --hopper <url> <dir>`, streaming its
// output through. `fs` is the filesystem-scan subcommand; --hopper (alias
// --upload) renews each result on the master by POSTing to <url>/api/result.
// scan authenticates on its own (reading $HOPPER_UPLOAD_TOKEN when the master
// enforces a token), so the child inherits this process's environment.
func runScanUpload(ctx context.Context, scanBin, baseURL, dir string) error {
	if info, err := os.Stat(dir); err != nil || !info.IsDir() {
		return fmt.Errorf("not a directory: %s", dir)
	}
	writeStdoutf("scan fs --hopper %s %s\n", baseURL, dir)
	cmd := exec.CommandContext(ctx, scanBin, "fs", "--hopper", baseURL, dir)
	cmd.Stdout = os.Stdout
	cmd.Stderr = os.Stderr
	return cmd.Run()
}

// collectVerdicts hashes every regular, non-marker file directly under dir
// (recursively) and tags it with verdict. A missing dir is not an error — it
// just contributes nothing, so an operator who only sorted one direction can
// run post-triage unchanged.
func collectVerdicts(dir, verdict string) ([]triageVerdict, error) {
	if _, err := os.Stat(dir); errors.Is(err, os.ErrNotExist) {
		return nil, nil
	}
	var out []triageVerdict
	err := filepath.WalkDir(dir, func(path string, d fs.DirEntry, walkErr error) error {
		if walkErr != nil {
			return walkErr
		}
		if d.IsDir() {
			return nil
		}
		name := d.Name()
		if strings.HasPrefix(name, ".") || isMarkerFile(name) || isForagerSidecar(name) {
			return nil
		}
		sum, err := hashFileSHA256(path)
		if err != nil {
			return fmt.Errorf("hash %s: %w", path, err)
		}
		out = append(out, triageVerdict{SHA256: sum, Verdict: verdict})
		return nil
	})
	if err != nil {
		return nil, err
	}
	return out, nil
}

func hashFileSHA256(path string) (string, error) {
	f, err := os.Open(path) //nolint:gosec // path comes from a local triage dir the operator chose
	if err != nil {
		return "", err
	}
	defer closeFileBestEffort(path, f)
	h := sha256.New()
	if _, err := io.Copy(h, f); err != nil {
		return "", err
	}
	return hex.EncodeToString(h.Sum(nil)), nil
}

func postTriage(ctx context.Context, baseURL, token string, req triageRequest) (*triageResponse, error) {
	body, err := json.Marshal(req)
	if err != nil {
		return nil, err
	}
	url := strings.TrimRight(baseURL, "/") + "/api/triage"
	httpReq, err := http.NewRequestWithContext(ctx, http.MethodPost, url, bytes.NewReader(body))
	if err != nil {
		return nil, err
	}
	httpReq.Header.Set("Content-Type", "application/json")
	// Marks the request as a non-browser client for the CSRF guard.
	httpReq.Header.Set("Sec-Fetch-Site", "same-origin")
	if token != "" {
		httpReq.Header.Set("Authorization", "Bearer "+token)
	}
	client := &http.Client{Timeout: 5 * time.Minute}
	resp, err := client.Do(httpReq)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close() //nolint:errcheck // best-effort close
	if resp.StatusCode != http.StatusOK {
		msg, _ := io.ReadAll(io.LimitReader(resp.Body, 4<<10)) //nolint:errcheck // diagnostic only
		return nil, fmt.Errorf("/api/triage: %s: %s", resp.Status, strings.TrimSpace(string(msg)))
	}
	var out triageResponse
	if err := json.NewDecoder(resp.Body).Decode(&out); err != nil {
		return nil, fmt.Errorf("decode response: %w", err)
	}
	return &out, nil
}
