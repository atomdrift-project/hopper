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
	"strconv"
	"strings"
	"time"

	"github.com/atomdrift-project/hopper"
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
	maxTriageVerdicts    = 10_000
	maxIncomingLocations = 1_000
)

type incomingLocation struct {
	Mtime  time.Time `json:"mtime"`
	SHA256 string    `json:"sha256"`
	Path   string    `json:"path"`
}

type incomingLocationsResponse struct {
	Locations []incomingLocation `json:"locations"`
}

// handleIncomingLocations exposes a bounded, oldest-first work feed for the
// hot-pool controller. It returns exact catalog paths so a later move is a
// compare-and-swap against one physical observation, not samples.path.
func (s *apiServer) handleIncomingLocations(w http.ResponseWriter, r *http.Request) {
	before := time.Now().UTC()
	if raw := r.URL.Query().Get("before"); raw != "" {
		parsed, err := time.Parse(time.RFC3339Nano, raw)
		if err != nil {
			writeJSONError(w, http.StatusBadRequest, "invalid before timestamp")
			return
		}
		before = parsed
	}
	limit := 128
	if raw := r.URL.Query().Get("limit"); raw != "" {
		parsed, err := strconv.Atoi(raw)
		if err != nil || parsed <= 0 || parsed > maxIncomingLocations {
			writeJSONError(w, http.StatusBadRequest, "limit must be between 1 and 1000")
			return
		}
		limit = parsed
	}
	locations, err := s.db.OldestIncomingLocations(r.Context(), before, limit)
	if err != nil {
		slog.Error("list incoming locations failed", "error", err)
		writeJSONError(w, http.StatusInternalServerError, "server error")
		return
	}
	resp := incomingLocationsResponse{Locations: make([]incomingLocation, 0, len(locations))}
	for _, loc := range locations {
		if loc.Mtime == nil {
			continue
		}
		resp.Locations = append(resp.Locations, incomingLocation{
			Mtime:  loc.Mtime.UTC(),
			SHA256: loc.SHA256,
			Path:   loc.Path,
		})
	}
	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(resp) //nolint:errcheck,errchkjson // best-effort response
}

// triageVerdict is one corrected classification for the sample identified by
// SHA256. Exactly one of Verdict or Ruling is set:
//
//   - Verdict ("good"|"bad") is the operator post-triage flow: the file moves
//     into a <verdict>/mislabeled-<old-label>/ bucket (basename only) and is
//     relabeled.
//   - Ruling ("good"|"bad"|"sighted"|"purgatory") is the remote classification flow
//     (promoter, or the demote-sighted backfill): the file moves into the
//     ruling's pool tree with its source subpath preserved and is relabeled.
//   - Ruling ("pending"|"review") is a workflow move within the unknown-class
//     pools: the file moves to that pool and keeps its DB label/source/skip.
//     See rulingPlan.
type triageVerdict struct {
	SHA256  string `json:"sha256"`
	Verdict string `json:"verdict,omitempty"`
	Ruling  string `json:"ruling,omitempty"`
	Source  string `json:"source,omitempty"`   // overrides the recorded label_source (e.g. "cyclotron:bad")
	OldPath string `json:"old_path,omitempty"` // exact catalog location; required by storage lifecycle clients
}

// Promotion pool layout. hopper owns where a ruled sample lands; the client
// (promoter, or the demote-sighted backfill) sends only the abstract ruling.
// The subpath beneath the sample's source tree is preserved into the
// destination tree, so pending/foraged/npm/foo.tgz promotes to
// good/foraged-promote/npm/foo.tgz and bad/foraged/npm/foo.tgz demotes to
// sighted/foraged/npm/foo.tgz.
const (
	promoteGoodTree = "good/foraged-promote"
	promoteBadTree  = "bad/foraged-quarantine"
	sightedTree     = "sighted/foraged"
	// Greyware has no discovery tree beneath it the way sighted/foraged does:
	// a sample lands here by operator judgement from anywhere in the pool, so
	// the root is the whole destination and the subpath rule below applies
	// unchanged.
	purgatoryTree = purgatoryPool
)

// promoteSrcRoots are the trees a ruled sample may start from; the first
// matching prefix is stripped to preserve the subpath. The trailing slashes
// keep path components distinct, and keep bad/foraged/
// from shadowing bad/foraged-quarantine/.
//
// uploads/ is here because a scanner push is a discovery too — a fetched
// dependency is often the first time anyone has seen those bytes. Without it a
// ruled upload matched no root and fell back to the basename, collapsing the
// sha shard (uploads/ab/cd/x.tgz) into a flat good/foraged-promote/x.tgz where
// two packages sharing a filename would collide.
// The destination trees are roots too, because a ruling is not final: a sample
// promoted to good/foraged-promote/npm/foo.tgz and later demoted, or demoted to
// bad/foraged-quarantine and later acquitted, re-enters rulingPlan from its
// destination. Without them that round trip matched no root and flattened an
// already-preserved subpath. sightedTree needs no separate entry — it is also a
// discovery root, which is why round trips through the sighted pool never
// collapsed.
var promoteSrcRoots = []string{
	// All hot-pool layouts share one storage lifecycle root. Strip only that
	// root so an incoming/bad/foraged/... acquisition keeps its full suffix.
	uploadBucket + "/",
	pendingPool + "/foraged/",
	pendingPool + "/",
	reviewPool + "/",
	legacyUnknownPool + "/foraged/",
	sightedTree + "/",
	"bad/foraged/",
	legacyUnknownPool + "/scan/",
	legacyUnknownPool + "/prism/",
	legacyUnknownPool + "/forager/",
	legacyUnknownPool + "/uploads/", // legacy root: rows written before the per-producer trees
	uploadDirScan + "/",
	uploadDirPrism + "/",
	uploadDirForager + "/",
	promoteGoodTree + "/",
	promoteBadTree + "/",
	purgatoryTree + "/",
}

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
// pending re-promotion by evidence. "pending" and "review" are path-only
// workflow moves inside label="unknown" storage. ok is false for an
// unrecognized ruling.
func rulingPlan(_ *hopper.Sample, oldRel, ruling string) (placement, bool) {
	sub := filepath.Base(oldRel) // not under a source root: preserve only the basename
	for _, root := range promoteSrcRoots {
		if rest, ok := strings.CutPrefix(oldRel, root); ok {
			sub = rest
			break
		}
	}
	switch ruling {
	case "good":
		return placement{newRel: filepath.Join(promoteGoodTree, sub), label: "good", source: "promoter"}, true
	case "bad":
		return placement{newRel: filepath.Join(promoteBadTree, sub), label: "bad", source: "promoter"}, true
	case "sighted":
		return placement{newRel: filepath.Join(sightedTree, sub), label: "sighted", source: "promoter"}, true
	case "purgatory":
		return placement{newRel: filepath.Join(purgatoryTree, sub), label: "purgatory", source: "triage"}, true
	case "pending":
		return workflowPlan(oldRel, pendingPool)
	case "review":
		return workflowPlan(oldRel, reviewPool)
	}
	return placement{}, false
}

// workflowPlan moves an unknown-class sample between workflow pools while
// preserving the source suffix below the workflow root. It deliberately has no
// producer-specific cases: review/foraged is just review/<suffix>.
func workflowPlan(oldRel, dstRoot string) (placement, bool) {
	newRel, err := hopper.RebasePoolPath(filepath.ToSlash(oldRel), dstRoot)
	if err != nil {
		return placement{}, false
	}
	return placement{newRel: filepath.FromSlash(newRel)}, true
}

// triageRequest is the JSON body for POST /api/triage.
type triageRequest struct {
	Verdicts []triageVerdict `json:"verdicts"`
	DryRun   bool            `json:"dry_run"`
}

// triageResult reports the outcome for one verdict. Status is one of:
// "moved" (relocated + relabeled), "plan" (dry-run, would move),
// "noop" (already in the corrected pool), "not_found" (unknown sha or no
// on-disk pool copy), "absent" (the DB row is real but its bytes are not on
// this host — a partial mirror; the verdict is deferred, re-submit once the
// full corpus is attached), or "error".
type triageResult struct {
	SHA256        string `json:"sha256"`
	Status        string `json:"status"`
	OldPath       string `json:"old_path,omitempty"`
	NewPath       string `json:"new_path,omitempty"`
	Error         string `json:"error,omitempty"`
	BytesFreed    int64  `json:"bytes_freed,omitempty"`
	SourceRemoved bool   `json:"source_removed,omitempty"`
}

// triageResponse is the JSON body returned by POST /api/triage.
type triageResponse struct {
	Results []triageResult `json:"results"`
	Moved   int            `json:"moved"`
	Noop    int            `json:"noop"`
	Absent  int            `json:"absent"` // rows whose bytes are not on this host (deferred)
	Failed  int            `json:"failed"`
}

// handleTriage applies a batch of corrected verdicts. The cross-site CSRF
// guard rejects browser form posts. The heavy lifting — disk move + DB flip —
// is in relocateTriaged.
func (s *apiServer) handleTriage(w http.ResponseWriter, r *http.Request) {
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
		case "absent":
			resp.Absent++
		default:
			resp.Failed++
		}
		resp.Results = append(resp.Results, res)
	}

	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(resp) //nolint:errcheck,errchkjson // best-effort response
}

// relocateTriaged resolves one exact catalog location, then delegates the
// durable filesystem and catalog transition to hopper.DB.MoveLocation.
func (s *apiServer) relocateTriaged(ctx context.Context, verdict triageVerdict, dryRun bool) triageResult {
	res := triageResult{SHA256: verdict.SHA256}
	sha := strings.ToLower(strings.TrimSpace(verdict.SHA256))
	if !validSHA256(sha) {
		res.Status, res.Error = "error", "invalid sha256"
		return res
	}
	res.SHA256 = sha
	if (verdict.Verdict == "") == (verdict.Ruling == "") {
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
	if samp.Path == "" && verdict.OldPath == "" {
		res.Status, res.Error = "not_found", "sample has no on-disk path"
		return res
	}

	oldRel := verdict.OldPath
	if oldRel == "" {
		oldRel = relativeSamplePath(s.dataRoot, samp.Path)
	}
	res.OldPath = oldRel

	if verdict.OldPath == "" {
		// Stateless clients omit old_path and can use the terminal label/tree as
		// their idempotency key. Exact-location clients retain the old row until
		// source cleanup, so they must proceed through MoveLocation on retries.
		switch {
		case verdict.Verdict != "" && samp.Label == verdict.Verdict,
			verdict.Ruling == "good" && samp.Label == "good",
			verdict.Ruling == "bad" && samp.Label == "bad",
			verdict.Ruling == "sighted" && samp.Label == "sighted" && strings.HasPrefix(oldRel, sightedTree+"/"),
			verdict.Ruling == "purgatory" && samp.Label == "purgatory" && strings.HasPrefix(oldRel, purgatoryTree+"/"):
			res.Status = "noop"
			return res
		}
	}

	plan, err := s.triagePlan(samp, oldRel, verdict)
	if err != nil {
		res.Status, res.Error = "error", err.Error()
		return res
	}
	res.NewPath = plan.newRel
	if oldRel == plan.newRel {
		res.Status = "noop"
		return res
	}

	// Classification destinations may already contain a different package build
	// with the same human-readable path. Preserve both using a deterministic
	// SHA suffix. Workflow moves preserve the exact suffix and treat a conflict
	// as an invariant violation.
	if plan.label != "" {
		newAbs, err := s.resolveDataPath(plan.newRel)
		if err != nil {
			res.Status, res.Error = "error", err.Error()
			return res
		}
		if exists, statErr := pathExists(newAbs); statErr != nil {
			res.Status, res.Error = "error", "stat destination: "+statErr.Error()
			return res
		} else if exists {
			same, hashErr := fileMatchesSHA256(newAbs, sha)
			if hashErr != nil {
				res.Status, res.Error = "error", "hash destination: "+hashErr.Error()
				return res
			}
			if !same {
				plan.newRel = shaSuffixedRel(plan.newRel, sha)
				res.NewPath = plan.newRel
			}
		}
	}

	oldAbs, err := s.resolveDataPath(oldRel)
	if err != nil {
		res.Status, res.Error = "error", err.Error()
		return res
	}
	newAbs, err := s.resolveDataPath(plan.newRel)
	if err != nil {
		res.Status, res.Error = "error", err.Error()
		return res
	}

	if verdict.OldPath != "" {
		locations, err := s.db.LocationsForSHA(ctx, sha)
		if err != nil {
			res.Status, res.Error = "error", "lookup locations: "+err.Error()
			return res
		}
		var oldRecorded, newRecorded bool
		for _, loc := range locations {
			if loc.ParentSHA256 != "" {
				continue
			}
			oldRecorded = oldRecorded || loc.Path == oldRel
			newRecorded = newRecorded || loc.Path == plan.newRel
		}
		if !oldRecorded && !newRecorded {
			res.Status, res.Error = "not_found", "exact source location is not recorded"
			return res
		}
	}

	oldExists, err := pathExists(oldAbs)
	if err != nil {
		res.Status, res.Error = "error", "stat source: "+err.Error()
		return res
	}
	newExists, err := pathExists(newAbs)
	if err != nil {
		res.Status, res.Error = "error", "stat destination: "+err.Error()
		return res
	}
	if !oldExists && !newExists {
		res.Status, res.Error = "absent", "bytes not on this host; re-submit once the full corpus is attached"
		return res
	}

	if dryRun {
		if !oldExists && newExists {
			res.Status = "noop"
		} else {
			res.Status = "plan"
		}
		return res
	}

	// A decision supersedes any filesystem marker at the old location. Removing
	// it before prepare prevents a crash from leaving contradictory metadata
	// beside the retained source location.
	removeMarkers(oldAbs)
	var relabel *hopper.LocationRelabel
	if plan.label != "" {
		relabel = &hopper.LocationRelabel{Label: plan.label, Source: plan.source}
	}
	result, err := s.db.MoveLocation(ctx, hopper.MoveLocationOptions{
		DataRoot: s.dataRoot,
		SHA256:   sha,
		OldPath:  oldRel,
		NewPath:  plan.newRel,
		Relabel:  relabel,
	})
	if err != nil {
		res.Status, res.Error = "error", "move location: "+err.Error()
		return res
	}
	if !result.Relocated {
		res.Status, res.Error = "error", "move location did not record destination"
		return res
	}
	res.BytesFreed = result.BytesFreed
	res.SourceRemoved = result.SourceRemoved
	res.Status = "moved"
	return res
}

// triagePlan resolves a triage item to its destination path, target label, and
// label_source. A Ruling uses promoter's pool-tree placement (subpath
// preserved); a Verdict uses the operator mislabeled-bucket placement.
func (*apiServer) triagePlan(samp *hopper.Sample, oldRel string, v triageVerdict) (placement, error) {
	if v.Ruling != "" {
		plan, ok := rulingPlan(samp, oldRel, v.Ruling)
		if !ok {
			return placement{}, errors.New(`ruling must be "good", "bad", "sighted", "purgatory", "pending", or "review"`)
		}
		if (v.Ruling == "pending" || v.Ruling == "review") && samp.Label != "unknown" {
			return placement{}, errors.New(`workflow ruling requires label "unknown"`)
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
	return placement{newRel: newRel, label: v.Verdict, source: "triage"}, nil
}

// shaSuffixedRel disambiguates rel's basename with the sample's sha prefix:
// dir/foo.tgz → dir/foo.<sha12>.tgz. Lets same-named, different-content
// samples coexist while staying human-attributable.
func shaSuffixedRel(rel, sha string) string {
	dir, base := filepath.Split(rel)
	ext := filepath.Ext(base)
	return filepath.Join(dir, strings.TrimSuffix(base, ext)+"."+sha[:12]+ext)
}

// fileMatchesSHA256 reports whether path's content hashes to sha
// (lowercase hex).
func fileMatchesSHA256(path, sha string) (bool, error) {
	f, err := os.Open(path) //nolint:gosec // path resolved within dataRoot
	if err != nil {
		return false, err
	}
	defer f.Close() //nolint:errcheck // read-only handle
	h := sha256.New()
	if _, err := io.Copy(h, f); err != nil {
		return false, err
	}
	return hex.EncodeToString(h.Sum(nil)) == sha, nil
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
	baseURL := f.String("url", "http://hopper-api:8081/", "hopper master API base URL") //nolint:revive // unsecure-url-scheme: internal cluster HTTP
	var misplacedGood, misplacedBad stringListFlag
	f.Var(&misplacedGood, "misplaced-good",
		"dir of files re-classified benign (was bad); repeatable or comma-separated")
	f.Var(&misplacedBad, "misplaced-bad",
		"dir of files re-classified hostile (was good); repeatable or comma-separated")
	noUpload := f.Bool("no-upload", false, "skip pushing fresh analysis (default: scan fs --hopper each misplaced dir first)")
	scanBin := f.String("scan", "atomscan", "path to the scan (atomscan) binary used for --upload")
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
	resp, err := postTriage(ctx, *baseURL, triageRequest{Verdicts: verdicts, DryRun: *dryRun})
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

func postTriage(ctx context.Context, baseURL string, req triageRequest) (*triageResponse, error) {
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
	// /api/triage requires a bearer token on a master deployed with
	// --token-file, loopback callers included.
	authorizeRequest(httpReq)
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
