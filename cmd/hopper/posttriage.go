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
	"syscall"
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

// triageVerdict is one corrected classification for the sample identified by
// SHA256. Exactly one of Verdict or Ruling is set:
//
//   - Verdict ("good"|"bad") is the operator post-triage flow: the file moves
//     into a <verdict>/mislabeled-<old-label>/ bucket (basename only) and is
//     relabeled.
//   - Ruling ("good"|"bad"|"sighted") is the remote flow (promoter, or the
//     demote-sighted backfill): the file moves into the ruling's pool tree
//     with its source subpath preserved and is relabeled. See rulingPlan.
type triageVerdict struct {
	SHA256  string `json:"sha256"`
	Verdict string `json:"verdict,omitempty"`
	Ruling  string `json:"ruling,omitempty"`
	Source  string `json:"source,omitempty"` // overrides the recorded label_source (e.g. "cyclotron:bad")
}

// Promotion pool layout. hopper owns where a ruled sample lands; the client
// (promoter, or the demote-sighted backfill) sends only the abstract ruling.
// The subpath beneath the sample's source tree is preserved into the
// destination tree, so unknown/foraged/npm/foo.tgz promotes to
// good/foraged-promote/npm/foo.tgz and bad/foraged/npm/foo.tgz demotes to
// sighted/foraged/npm/foo.tgz.
const (
	promoteGoodTree = "good/foraged-promote"
	promoteBadTree  = "bad/foraged-quarantine"
	sightedTree     = "sighted/foraged"
)

// promoteSrcRoots are the foraged discovery trees a ruled sample may start
// from; the first matching prefix is stripped to preserve the subpath. The
// trailing slashes keep siblings like unknown/foraged-review/ excluded.
var promoteSrcRoots = []string{"unknown/foraged/", "sighted/foraged/", "bad/foraged/"}

// placement is a triage item's resolved destination: the new relative path and
// the label + label_source to record.
type placement struct {
	newRel string
	label  string
	source string
}

// rulingPlan resolves a promoter ruling to its placement: the destination path
// (subpath preserved beneath the ruling's tree) plus the label change to apply.
// "sighted" demotes a feed-claimed sample out of bad/ into the sighted pool,
// pending re-promotion by evidence. ok is false for an unrecognized ruling.
// (A "review" ruling once parked one-signal samples in unknown/foraged-review;
// promoter now leaves them in the discovery tree so their evidence keeps
// accumulating instead of freezing.)
func rulingPlan(_ *hopper.Sample, oldRel, ruling string) (placement, bool) {
	sub := filepath.Base(oldRel) // not under a source root: preserve only the basename
	for _, root := range promoteSrcRoots {
		if rest := strings.TrimPrefix(oldRel, root); rest != oldRel {
			sub = rest
			break
		}
	}
	switch ruling {
	case "good":
		return placement{filepath.Join(promoteGoodTree, sub), "good", "promoter"}, true
	case "bad":
		return placement{filepath.Join(promoteBadTree, sub), "bad", "promoter"}, true
	case "sighted":
		return placement{filepath.Join(sightedTree, sub), "sighted", "promoter"}, true
	}
	return placement{}, false
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

// relocateTriaged moves one sample into its corrected location and updates its
// DB label+path atomically. It is idempotent: a sample already at its
// destination returns "noop" so re-running a batch is safe. It serves both the
// operator verdict flow (mislabeled bucket) and promoter's ruling flow (pool
// tree with preserved subpath); triagePlan resolves which.
func (s *apiServer) relocateTriaged(ctx context.Context, v triageVerdict, dryRun bool) triageResult {
	res := triageResult{SHA256: v.SHA256}
	sha := strings.ToLower(strings.TrimSpace(v.SHA256))
	if !validSHA256(sha) {
		res.Status, res.Error = "error", "invalid sha256"
		return res
	}
	res.SHA256 = sha
	if (v.Verdict == "") == (v.Ruling == "") {
		res.Status, res.Error = "error", `exactly one of "verdict" or "ruling" must be set`
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

	oldRel := relativeSamplePath(s.dataRoot, samp.Path)
	oldAbs := sampleDiskPath(s.dataRoot, oldRel)
	res.OldPath = oldRel

	// Idempotency: a sample already at its destination is a no-op, so retries
	// and re-runs are safe. good/bad are recognized by their terminal label.
	// Keying on label/tree (not recomputed path equality) stays correct after
	// the move, when the subpath no longer starts at the source root.
	switch {
	case v.Verdict != "" && samp.Label == v.Verdict,
		v.Ruling == "good" && samp.Label == "good",
		v.Ruling == "bad" && samp.Label == "bad",
		// "sighted" is additionally tree-aware: a row can be labeled sighted
		// with its file still outside the sighted pool (forager's
		// version-matched purl re-flag relabels DB-only), and the ruling is
		// how the file catches up — so label alone must not short-circuit.
		v.Ruling == "sighted" && samp.Label == "sighted" && strings.HasPrefix(oldRel, sightedTree+"/"):
		res.Status = "noop"
		return res
	}

	plan, err := s.triagePlan(samp, oldRel, v)
	if err != nil {
		res.Status, res.Error = "error", err.Error()
		return res
	}
	res.NewPath = plan.newRel

	newAbs, err := s.resolveDataPath(plan.newRel)
	if err != nil {
		res.Status, res.Error = "error", err.Error()
		return res
	}

	if dryRun {
		res.Status = "plan"
		return res
	}

	if err := mkdirSharedAll(filepath.Dir(newAbs)); err != nil {
		res.Status, res.Error = "error", "mkdir: "+err.Error()
		return res
	}
	if err := moveSample(oldAbs, newAbs); err != nil {
		res.Status, res.Error = "error", "move: "+err.Error()
		return res
	}
	// The DB is now authoritative; drop any stale litmus markers left beside the
	// old location so a future walk can't resurrect the wrong label.
	removeMarkers(oldAbs)

	if err := s.db.RelocateSample(ctx, sha, oldRel, plan.newRel, plan.label, plan.source); err != nil {
		// The bytes already moved; report the error but leave them in place —
		// the next load walk will reconcile the DB from the new pool location.
		res.Status, res.Error = "error", "db relocate: "+err.Error()
		return res
	}
	res.Status = "moved"
	return res
}

// triagePlan resolves a triage item to its destination path, target label, and
// label_source. A Ruling uses promoter's pool-tree placement (subpath
// preserved); a Verdict uses the operator mislabeled-bucket placement.
func (s *apiServer) triagePlan(samp *hopper.Sample, oldRel string, v triageVerdict) (placement, error) {
	if v.Ruling != "" {
		plan, ok := rulingPlan(samp, oldRel, v.Ruling)
		if !ok {
			return placement{}, errors.New(`ruling must be "good", "bad", or "sighted"`)
		}
		// A client-supplied source attributes the relabel to its author (e.g.
		// "cyclotron:bad", "sighted-backfill") instead of the default "promoter".
		if v.Source != "" {
			plan.source = v.Source
		}
		return plan, nil
	}

	switch v.Verdict {
	case "good", "bad":
	default:
		return placement{}, errors.New(`verdict must be "good" or "bad"`)
	}
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
		return placement{}, err
	}
	// Disambiguate a basename collision in the flat bucket by prefixing the sha;
	// keeps the bucket human-browsable while staying unique.
	if collides, err := pathExists(newAbs); err != nil {
		return placement{}, err
	} else if collides {
		base := filepath.Base(oldRel)
		ext := filepath.Ext(base)
		stem := strings.TrimSuffix(base, ext)
		newRel = filepath.Join(v.Verdict, "mislabeled-"+wrong, stem+"."+samp.SHA256[:12]+ext)
	}
	return placement{newRel, v.Verdict, "triage"}, nil
}

// moveSample relocates a sample file between pool trees. It tries an atomic
// rename and falls back to copy-then-remove across filesystem boundaries: the
// good/, bad/, and unknown/ pools live on separate filesystems, so a cross-pool
// move yields EXDEV. The destination's parent directory must already exist.
//
//nolint:gosec // G703: oldAbs/newAbs are sample paths the caller resolved within dataRoot
func moveSample(oldAbs, newAbs string) error {
	if err := os.Rename(oldAbs, newAbs); err == nil {
		return nil
	} else if !errors.Is(err, syscall.EXDEV) {
		return fmt.Errorf("rename: %w", err)
	}
	if err := copySample(oldAbs, newAbs); err != nil {
		return err
	}
	if err := os.Remove(oldAbs); err != nil {
		return fmt.Errorf("remove source after copy: %w", err)
	}
	return nil
}

// copySample streams src to dst, truncating any existing destination and
// preserving src's permission bits.
func copySample(src, dst string) error {
	in, err := os.Open(src) //nolint:gosec // src is a sample path resolved within dataRoot
	if err != nil {
		return fmt.Errorf("open source: %w", err)
	}
	defer in.Close() //nolint:errcheck // read-only handle
	info, err := in.Stat()
	if err != nil {
		return fmt.Errorf("stat source: %w", err)
	}
	out, err := os.OpenFile(dst, os.O_WRONLY|os.O_CREATE|os.O_TRUNC, info.Mode()) //nolint:gosec // dst resolved within dataRoot
	if err != nil {
		return fmt.Errorf("create destination: %w", err)
	}
	if _, err := io.Copy(out, in); err != nil {
		_ = out.Close()    //nolint:errcheck // already failing
		_ = os.Remove(dst) //nolint:errcheck,gosec // best-effort cleanup; G703: dst resolved within dataRoot
		return fmt.Errorf("copy: %w", err)
	}
	if err := out.Close(); err != nil {
		return fmt.Errorf("close destination: %w", err)
	}
	return nil
}

// pathExists reports whether path exists, distinguishing a real stat error
// (e.g. permission denied) from a clean "not there".
func pathExists(path string) (bool, error) {
	_, err := os.Stat(path) //nolint:gosec // G703: path is a sample destination resolved within dataRoot
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
		//nolint:gosec // G703: p is a marker beside a sample path within dataRoot
		if err := os.Remove(p); err != nil && !errors.Is(err, os.ErrNotExist) {
			slog.Warn("remove stale marker failed", "path", p, "error", err) //nolint:gosec // G706: p is server-derived
		}
	}
}

// Client: `hopper post-triage`.
func cmdPostTriage(ctx context.Context) error {
	f := flag.NewFlagSet("post-triage", flag.ExitOnError)
	//nolint:revive // unsecure-url-scheme: the master API is a plain-http internal cluster endpoint
	baseURL := f.String("url", "http://hopper-api:8081/", "hopper master API base URL")
	var misplacedGood, misplacedBad stringListFlag
	f.Var(&misplacedGood, "misplaced-good",
		"dir of files re-classified benign (was bad); repeatable or comma-separated")
	f.Var(&misplacedBad, "misplaced-bad",
		"dir of files re-classified hostile (was good); repeatable or comma-separated")
	noUpload := f.Bool("no-upload", false, "skip pushing fresh analysis (default: scan fs --hopper each misplaced dir first)")
	scanBin := f.String("scan", "atomscan", "path to the scan (atomscan) binary used for --upload")
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
	f, err := os.Open(path)
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
	resp, err := client.Do(httpReq) //nolint:gosec // G704: baseURL is the operator-provided trusted master endpoint
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
