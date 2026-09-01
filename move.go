package hopper

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"os"
	"path"
	"path/filepath"
	"sort"
	"strings"
	"syscall"
	"time"
)

const movePartialPrefix = ".hopper-move-"

// LocationRelabel optionally applies a classification transition while moving
// a physical location. A nil relabel makes the operation path-only.
type LocationRelabel struct {
	Label  string
	Source string
}

// MoveLocationOptions identifies one exact physical observation and its
// deterministic destination. Paths are slash-separated and relative to
// DataRoot.
type MoveLocationOptions struct {
	Relabel  *LocationRelabel
	DataRoot string
	SHA256   string
	OldPath  string
	NewPath  string
}

// MoveLocationResult reports durable progress for one physical move.
type MoveLocationResult struct {
	Relocated     bool
	SourceRemoved bool
	BytesFreed    int64
}

// RebasePoolPath replaces the workflow root of rel with destination while
// preserving every path component below it.
func RebasePoolPath(rel, destination string) (string, error) {
	if !isWorkflowPool(destination, false) {
		return "", fmt.Errorf("hopper: invalid destination pool %q", destination)
	}
	if rel == "" || strings.Contains(rel, "\\") || path.IsAbs(rel) || path.Clean(rel) != rel {
		return "", fmt.Errorf("hopper: invalid pool path %q", rel)
	}
	root, suffix, ok := strings.Cut(rel, "/")
	if !ok || suffix == "" || !isWorkflowPool(root, true) {
		return "", fmt.Errorf("hopper: path is outside a workflow pool: %q", rel)
	}
	return destination + "/" + suffix, nil
}

func isWorkflowPool(root string, legacy bool) bool {
	switch root {
	case PoolIncoming, PoolPending, PoolReview:
		return true
	case PoolLegacyUnknown:
		return legacy
	default:
		return false
	}
}

// MoveLocation moves one exact top-level location and updates its catalog state.
// The destination is published and recorded before the source is removed. The
// old sample_locations row is retained until cleanup succeeds, making it the
// durable retry record for every crash window without a separate moves table.
func (db *DB) MoveLocation(ctx context.Context, opts MoveLocationOptions) (MoveLocationResult, error) {
	var result MoveLocationResult
	sha := strings.ToLower(strings.TrimSpace(opts.SHA256))
	if !isLowerHexSHA256(sha) {
		return result, fmt.Errorf("hopper: invalid sha256 %q", opts.SHA256)
	}
	if opts.OldPath == opts.NewPath {
		return result, errors.New("hopper: source and destination paths are identical")
	}
	root, oldAbs, err := resolveMovePath(opts.DataRoot, opts.OldPath)
	if err != nil {
		return result, fmt.Errorf("hopper: source path: %w", err)
	}
	_, newAbs, err := resolveMovePath(root, opts.NewPath)
	if err != nil {
		return result, fmt.Errorf("hopper: destination path: %w", err)
	}

	locked, err := lockMoveSource(ctx, oldAbs)
	if err != nil {
		if !errors.Is(err, os.ErrNotExist) {
			return result, fmt.Errorf("hopper: lock source: %w", err)
		}
		if err := verifyMoveFile(newAbs, sha); err != nil {
			return result, fmt.Errorf("hopper: source missing and destination unusable: %w", err)
		}
		prepared, err := db.prepareLocationMove(ctx, sha, opts.OldPath, opts.NewPath, opts.Relabel)
		if err != nil {
			return result, err
		}
		if !prepared {
			return result, errors.New("hopper: source and destination locations are absent from catalog")
		}
		finished, err := db.finishLocationMove(ctx, sha, opts.OldPath, opts.NewPath)
		if err != nil {
			return result, err
		}
		result.Relocated = finished
		pruneMoveParents(filepath.Dir(oldAbs), filepath.Join(root, filepath.FromSlash(moveRoot(opts.OldPath))))
		logLocationMove(ctx, opts, result, true)
		return result, nil
	}
	defer locked.Close() //nolint:errcheck // closing releases the advisory lock

	info, err := locked.Stat()
	if err != nil {
		return result, fmt.Errorf("hopper: stat locked source: %w", err)
	}
	if !info.Mode().IsRegular() {
		return result, fmt.Errorf("hopper: source is not a regular file: %s", oldAbs)
	}
	current, err := os.Stat(oldAbs)
	if err != nil {
		return result, fmt.Errorf("hopper: restat locked source: %w", err)
	}
	if !os.SameFile(info, current) {
		return result, fmt.Errorf("hopper: source changed while waiting for lock: %s", oldAbs)
	}

	// Bytes identical to these may already sit inside the destination's pool —
	// an OS image's members are ~88% shared with the previous release, and a
	// promoted sample often ships inside a package that was collected earlier.
	// Publishing by hard link instead of by copy is why moving 900 GB out of
	// the hot pool does not also write 900 GB into tank.
	donors := db.moveDonors(ctx, root, sha, opts.OldPath, opts.NewPath)
	artifactCreated, err := publishMoveFile(ctx, oldAbs, newAbs, sha, donors)
	if err != nil {
		return result, fmt.Errorf("hopper: publish sample: %w", err)
	}
	sidecarCreated, sidecarPresent, err := publishMoveSidecar(ctx, oldAbs, newAbs)
	if err != nil {
		if rbErr := rollbackMoveDestination(newAbs, artifactCreated, sidecarCreated); rbErr != nil {
			// The destination keeps whatever was published before the sidecar
			// failed; the catalog still points at the source, so the move is
			// safe to retry, but the leftover needs an operator's eye.
			slog.ErrorContext(ctx, "move rollback failed; destination may hold a partial copy",
				"dst", newAbs, "error", rbErr)
		}
		return result, fmt.Errorf("hopper: publish sidecar: %w", err)
	}

	prepared, err := db.prepareLocationMove(ctx, sha, opts.OldPath, opts.NewPath, opts.Relabel)
	if err != nil {
		return result, err
	}
	if !prepared {
		return result, rollbackMoveDestination(newAbs, artifactCreated, sidecarCreated)
	}
	current, err = os.Stat(oldAbs)
	if err != nil {
		return result, fmt.Errorf("hopper: restat source before cleanup: %w", err)
	}
	if !os.SameFile(info, current) {
		return result, fmt.Errorf("hopper: source changed during move: %s", oldAbs)
	}

	if sidecarPresent {
		if err := removeMoveFile(oldAbs + ProvenanceSidecarSuffix); err != nil {
			return result, fmt.Errorf("hopper: remove source sidecar: %w", err)
		}
	}
	if err := os.Remove(oldAbs); err != nil {
		if !errors.Is(err, os.ErrNotExist) {
			return result, fmt.Errorf("hopper: remove source: %w", err)
		}
	} else {
		result.SourceRemoved = true
		result.BytesFreed = info.Size()
	}
	if err := syncMoveDir(filepath.Dir(oldAbs)); err != nil {
		return result, fmt.Errorf("hopper: sync source directory: %w", err)
	}

	finished, err := db.finishLocationMove(ctx, sha, opts.OldPath, opts.NewPath)
	if err != nil {
		return result, err
	}
	result.Relocated = finished
	pruneMoveParents(filepath.Dir(oldAbs), filepath.Join(root, filepath.FromSlash(moveRoot(opts.OldPath))))
	logLocationMove(ctx, opts, result, false)
	return result, nil
}

func logLocationMove(ctx context.Context, opts MoveLocationOptions, result MoveLocationResult, recovered bool) {
	if !result.Relocated {
		return
	}
	slog.InfoContext(ctx, "sample location moved",
		"sha256", strings.ToLower(strings.TrimSpace(opts.SHA256)),
		"old_path", opts.OldPath,
		"new_path", opts.NewPath,
		"source_removed", result.SourceRemoved,
		"bytes_freed", result.BytesFreed,
		"recovered", recovered)
}

func moveRoot(rel string) string {
	root, _, _ := strings.Cut(rel, "/")
	return root
}

func resolveMovePath(dataRoot, rel string) (root, resolved string, err error) {
	if dataRoot == "" {
		return "", "", errors.New("empty data root")
	}
	if rel == "" || strings.Contains(rel, "\\") || path.IsAbs(rel) || path.Clean(rel) != rel {
		return "", "", fmt.Errorf("invalid relative path %q", rel)
	}
	root, err = filepath.Abs(dataRoot)
	if err != nil {
		return "", "", err
	}
	root = filepath.Clean(root)
	resolved = filepath.Join(root, filepath.FromSlash(rel))
	if resolved == root || !strings.HasPrefix(resolved, root+string(filepath.Separator)) {
		return "", "", fmt.Errorf("path escapes data root: %q", rel)
	}
	return root, resolved, nil
}

func lockMoveSource(ctx context.Context, name string) (*os.File, error) {
	f, err := os.Open(name)
	if err != nil {
		return nil, err
	}
	ticker := time.NewTicker(100 * time.Millisecond)
	defer ticker.Stop()
	for {
		err := syscall.Flock(int(f.Fd()), syscall.LOCK_EX|syscall.LOCK_NB)
		if err == nil {
			return f, nil
		}
		if !errors.Is(err, syscall.EWOULDBLOCK) && !errors.Is(err, syscall.EAGAIN) {
			f.Close() //nolint:errcheck,gosec // abandoning an unlocked file; the flock error is what matters
			return nil, err
		}
		select {
		case <-ctx.Done():
			f.Close() //nolint:errcheck,gosec // abandoning an unlocked file; the ctx error is what matters
			return nil, ctx.Err()
		case <-ticker.C:
		}
	}
}

func publishMoveSidecar(ctx context.Context, src, dst string) (created, present bool, err error) {
	src += ProvenanceSidecarSuffix
	dst += ProvenanceSidecarSuffix
	if _, err := os.Lstat(src); err != nil {
		if errors.Is(err, os.ErrNotExist) {
			return false, false, nil
		}
		return false, false, err
	}
	expected, err := hashMoveFile(src)
	if err != nil {
		return false, true, err
	}
	// No donors: a sidecar records how THIS location was acquired, so two
	// locations of the same sample legitimately hold different provenance.
	// Linking them together would make one acquisition's history overwrite the
	// other's. Only the artifact bytes are shareable.
	created, err = publishMoveFile(ctx, src, dst, expected, nil)
	return created, true, err
}

// publishMoveFile creates dst without clobbering an existing path. A same-device
// hard link is preferred; cross-device moves copy once through a verified,
// fsynced temporary file and publish it with an atomic hard link.
func publishMoveFile(ctx context.Context, src, dst, expected string, donors []string) (bool, error) {
	info, err := os.Lstat(src)
	if err != nil {
		return false, err
	}
	if !info.Mode().IsRegular() {
		return false, fmt.Errorf("not a regular file: %s", src)
	}
	if err := verifyMoveFile(dst, expected); err == nil {
		if err := verifyMoveFile(src, expected); err != nil {
			return false, fmt.Errorf("source no longer matches catalog: %w", err)
		}
		return false, nil
	} else if !errors.Is(err, os.ErrNotExist) {
		return false, err
	}

	dir := filepath.Dir(dst)
	// Group-writable on purpose: /data/samples is shared by forager, hopper,
	// and promoter through the samples group (see cmd/hopper's sharedDirMode).
	if err := os.MkdirAll(dir, 0o775); err != nil { //nolint:gosec // shared samples directory permissions are intentional
		return false, err
	}
	if err := os.Link(src, dst); err == nil {
		if err := verifyMoveFile(dst, expected); err != nil {
			if rmErr := os.Remove(dst); rmErr != nil {
				// The link is corrupt and now unremovable: leaving it would let
				// a later move take the ErrExist path and adopt bad bytes.
				slog.ErrorContext(ctx, "cannot remove unverifiable destination link",
					"dst", dst, "error", rmErr)
			} else if syncErr := syncMoveDir(dir); syncErr != nil {
				slog.WarnContext(ctx, "destination dir sync failed after removing bad link",
					"dir", dir, "error", syncErr)
			}
			return false, err
		}
		if err := syncMoveDir(dir); err != nil {
			return true, err
		}
		return true, nil
	} else if errors.Is(err, os.ErrExist) {
		return false, verifyMoveFile(dst, expected)
	} else if !moveCopyFallback(err) {
		return false, err
	}

	// src is on another filesystem, which is the ordinary case for a move off
	// the hot pool. Before spending a read plus a write on copying its bytes,
	// look for a copy that is already on this one.
	for _, donor := range donors {
		created, err := publishMoveLink(ctx, donor, dst, expected, dir)
		if created {
			return true, err
		}
		if errors.Is(err, errDestinationPoisoned) {
			return false, err
		}
		if err != nil {
			slog.DebugContext(ctx, "donor link not used", "donor", donor, "dst", dst, "error", err)
		}
	}

	tmp, err := os.CreateTemp(dir, movePartialPrefix+"*")
	if err != nil {
		return false, err
	}
	tmpName := tmp.Name()
	defer func() {
		if tmpName == "" {
			return
		}
		if err := os.Remove(tmpName); err != nil {
			slog.WarnContext(ctx, "partial copy left behind", "tmp", tmpName, "error", err)
			return
		}
		if err := syncMoveDir(dir); err != nil {
			slog.WarnContext(ctx, "destination dir sync failed after discarding partial copy",
				"dir", dir, "error", err)
		}
	}()
	if err := tmp.Chmod(info.Mode().Perm()); err != nil {
		tmp.Close() //nolint:errcheck,gosec // abandoning the partial copy, which the defer removes
		return false, err
	}

	in, err := os.Open(src)
	if err != nil {
		tmp.Close() //nolint:errcheck,gosec // abandoning the partial copy, which the defer removes
		return false, err
	}
	h := sha256.New()
	_, copyErr := copyMoveContext(ctx, io.MultiWriter(tmp, h), in)
	closeInErr := in.Close()
	if copyErr == nil {
		copyErr = closeInErr
	}
	if copyErr == nil && hex.EncodeToString(h.Sum(nil)) != expected {
		copyErr = fmt.Errorf("sha256 changed while copying %s", src)
	}
	if copyErr == nil {
		copyErr = os.Chtimes(tmpName, info.ModTime(), info.ModTime())
	}
	if copyErr == nil {
		copyErr = tmp.Sync()
	}
	closeErr := tmp.Close()
	if copyErr == nil {
		copyErr = closeErr
	}
	if copyErr != nil {
		return false, copyErr
	}
	if err := os.Link(tmpName, dst); err != nil {
		if errors.Is(err, os.ErrExist) {
			return false, verifyMoveFile(dst, expected)
		}
		return false, err
	}
	if err := os.Remove(tmpName); err != nil {
		return true, err
	}
	tmpName = ""
	if err := syncMoveDir(dir); err != nil {
		return true, err
	}
	return true, nil
}

// DedupeResult reports what one sample's dedupe pass did.
type DedupeResult struct {
	Linked     int   // redundant copies collapsed onto a survivor's inode
	Skipped    int   // copies left alone (missing, unverifiable, already shared)
	BytesSaved int64 // sum of the collapsed copies' sizes
}

// LinkDuplicateLocations collapses a sample's duplicate on-disk copies onto one
// inode per filesystem, so N recorded observations of the same bytes cost one
// copy of them instead of N.
//
// It touches only the filesystem. sample_locations is deliberately left alone:
// every path still resolves to the same bytes afterwards, so the catalog was
// never wrong and needs no update. That is what makes this safe to interrupt at
// any point and safe to run repeatedly — a second pass finds the inodes already
// shared and does nothing.
//
// Two rules keep it from destroying data:
//
//   - A victim is hashed before it is replaced. The catalog says it holds this
//     sha; if it does not, it holds something nobody has a record of, and
//     overwriting it would lose that silently. Such a copy is skipped, not
//     replaced.
//   - The survivor is hashed through an open descriptor, and every link made
//     from it is checked to be that same inode before it replaces anything.
//     Hashing a path and then linking the path would leave a window in which
//     the survivor is renamed away and an unverified inode takes its place.
//
// Replacement is link-to-temp then rename, never unlink-then-link: rename is
// atomic, so a victim's path resolves to a complete file at every instant, and
// a crash mid-sweep leaves a walker-ignored temp file rather than a hole.
//
// dryRun reports what would be collapsed without hashing anything, so it is
// cheap but proves only that the copies are distinct inodes on one filesystem.
func LinkDuplicateLocations(ctx context.Context, dataRoot, sha string, rels []string, dryRun bool) (DedupeResult, error) {
	var result DedupeResult
	if !isLowerHexSHA256(strings.ToLower(strings.TrimSpace(sha))) {
		return result, fmt.Errorf("hopper: invalid sha256 %q", sha)
	}
	byDevice := map[uint64][]dedupeCandidate{}
	for _, rel := range rels {
		_, abs, err := resolveMovePath(dataRoot, rel)
		if err != nil {
			result.Skipped++
			continue
		}
		var st syscall.Stat_t
		if err := syscall.Stat(abs, &st); err != nil {
			// Gone, or on a filesystem this host does not have attached. Either
			// way there is nothing here to collapse.
			result.Skipped++
			continue
		}
		if st.Mode&syscall.S_IFMT != syscall.S_IFREG {
			result.Skipped++
			continue
		}
		dev := uint64(st.Dev) //nolint:unconvert,nolintlint // Dev is int32 on some platforms
		byDevice[dev] = append(byDevice[dev], dedupeCandidate{abs: abs, ino: uint64(st.Ino), size: st.Size})
	}
	for _, group := range byDevice {
		if err := ctx.Err(); err != nil {
			return result, err
		}
		dedupeGroup(ctx, sha, group, dryRun, &result)
	}
	return result, nil
}

type dedupeCandidate struct {
	abs  string
	ino  uint64
	size int64
}

// dedupeGroup collapses one filesystem's worth of a sample's copies. Failures
// are recorded as skips rather than errors: a sweep over millions of samples
// must not stop because one file is unreadable.
func dedupeGroup(ctx context.Context, sha string, group []dedupeCandidate, dryRun bool, result *DedupeResult) {
	distinct := map[uint64]bool{}
	for _, c := range group {
		distinct[c.ino] = true
	}
	if len(distinct) < 2 {
		// One inode already backs every path here; nothing to do. This is the
		// steady state a second pass finds.
		return
	}
	// Prefer the inode that already backs the most paths: linking onto it makes
	// the fewest changes and keeps repeated sweeps stable.
	counts := map[uint64]int{}
	for _, c := range group {
		counts[c.ino]++
	}
	sort.SliceStable(group, func(i, j int) bool {
		if counts[group[i].ino] != counts[group[j].ino] {
			return counts[group[i].ino] > counts[group[j].ino]
		}
		return group[i].abs < group[j].abs
	})

	if dryRun {
		for _, c := range group[1:] {
			if c.ino == group[0].ino {
				continue
			}
			result.Linked++
			result.BytesSaved += c.size
		}
		return
	}

	survivor, err := os.Open(group[0].abs)
	if err != nil {
		result.Skipped += len(group)
		return
	}
	defer survivor.Close() //nolint:errcheck // read-only descriptor
	var survivorStat syscall.Stat_t
	if err := syscall.Fstat(int(survivor.Fd()), &survivorStat); err != nil {
		result.Skipped += len(group)
		return
	}
	if got, err := hashMoveReader(ctx, survivor); err != nil || got != sha {
		// The survivor is not what the catalog claims. Collapsing onto it would
		// publish these bytes over every other copy, so this group is left
		// entirely alone for a repair pass to look at.
		slog.WarnContext(ctx, "dedupe survivor does not match catalog; group skipped",
			"sha256", sha, "path", group[0].abs, "error", err)
		result.Skipped += len(group)
		return
	}

	for _, victim := range group[1:] {
		if err := ctx.Err(); err != nil {
			return
		}
		if victim.ino == survivorStat.Ino {
			continue // already the same inode
		}
		saved, err := replaceWithLink(ctx, group[0].abs, victim.abs, sha, &survivorStat)
		if err != nil {
			slog.DebugContext(ctx, "dedupe copy skipped",
				"sha256", sha, "path", victim.abs, "error", err)
			result.Skipped++
			continue
		}
		if saved {
			result.Linked++
			result.BytesSaved += victim.size
		}
	}
}

// replaceWithLink points victim at survivor's inode. See LinkDuplicateLocations
// for why the victim is hashed first and why the link's identity is rechecked.
func replaceWithLink(ctx context.Context, survivor, victim, sha string, survivorStat *syscall.Stat_t) (bool, error) {
	if err := verifyMoveFile(victim, sha); err != nil {
		return false, fmt.Errorf("victim does not match catalog: %w", err)
	}
	dir := filepath.Dir(victim)
	tmp, err := os.CreateTemp(dir, movePartialPrefix+"*")
	if err != nil {
		return false, err
	}
	tmpName := tmp.Name()
	if err := tmp.Close(); err != nil {
		return false, err
	}
	// CreateTemp made a real file; link cannot target an existing name, so drop
	// the placeholder and take the name for the link.
	if err := os.Remove(tmpName); err != nil {
		return false, err
	}
	if err := os.Link(survivor, tmpName); err != nil {
		return false, err
	}
	var linked syscall.Stat_t
	if err := syscall.Stat(tmpName, &linked); err != nil {
		removeMoveFileBestEffort(ctx, tmpName)
		return false, err
	}
	if linked.Ino != survivorStat.Ino || linked.Dev != survivorStat.Dev {
		// The survivor's path was replaced between the hash and the link, so
		// this link points at bytes nobody verified.
		removeMoveFileBestEffort(ctx, tmpName)
		return false, errors.New("survivor path changed during dedupe")
	}
	if err := os.Rename(tmpName, victim); err != nil {
		removeMoveFileBestEffort(ctx, tmpName)
		return false, err
	}
	if err := syncMoveDir(dir); err != nil {
		slog.WarnContext(ctx, "dedupe dir sync failed", "dir", dir, "error", err)
	}
	return true, nil
}

func removeMoveFileBestEffort(ctx context.Context, name string) {
	if err := os.Remove(name); err != nil && !errors.Is(err, os.ErrNotExist) {
		slog.WarnContext(ctx, "dedupe temp left behind", "tmp", name, "error", err)
	}
}

// hashMoveReader hashes from an already-open descriptor, so the bytes hashed
// are the inode held open rather than whatever a path resolves to later.
func hashMoveReader(ctx context.Context, f *os.File) (string, error) {
	if _, err := f.Seek(0, io.SeekStart); err != nil {
		return "", err
	}
	h := sha256.New()
	if _, err := copyMoveContext(ctx, h, f); err != nil {
		return "", err
	}
	return hex.EncodeToString(h.Sum(nil)), nil
}

// maxMoveDonors bounds how many candidate copies one move will try. A donor
// that links but fails verification costs a hash of the whole file, so this is
// the ceiling on wasted I/O when a sha's other locations are damaged. Hitting
// it just means the copy fallback runs, which is what would have happened
// anyway.
const maxMoveDonors = 4

// errDestinationPoisoned reports that dst holds bytes that failed verification
// and could not be removed. The move must abort: leaving them would let a later
// move take publishMoveFile's ErrExist path and adopt them as genuine.
var errDestinationPoisoned = errors.New("hopper: destination holds unverifiable bytes")

// publishMoveLink publishes dst as a hard link to donor, then verifies the bytes
// that appear there and removes the link if they do not match.
//
// The hash is taken AFTER the link, never before. Hashing a donor path and then
// linking that path leaves a window in which the donor is renamed away and some
// other inode inherits its name — the link would then publish bytes nobody
// checked. Hashing through the link instead hashes the exact inode this process
// now holds a reference to, and no other writer can substitute it. That
// ordering is the whole reason this is safe to do on a live tree.
//
// A donor that fails is simply not used: the caller still holds the source and
// can copy. Only an unremovable bad link is fatal.
func publishMoveLink(ctx context.Context, donor, dst, expected, dir string) (bool, error) {
	if err := os.Link(donor, dst); err != nil {
		return false, err
	}
	if err := verifyMoveFile(dst, expected); err != nil {
		if rmErr := os.Remove(dst); rmErr != nil {
			slog.ErrorContext(ctx, "cannot remove unverifiable donor link",
				"dst", dst, "donor", donor, "error", rmErr)
			return false, errDestinationPoisoned
		}
		if syncErr := syncMoveDir(dir); syncErr != nil {
			slog.WarnContext(ctx, "destination dir sync failed after removing bad donor link",
				"dir", dir, "error", syncErr)
		}
		return false, err
	}
	if err := syncMoveDir(dir); err != nil {
		return true, err
	}
	return true, nil
}

// moveDonors lists other live top-level locations of sha that could publish
// newRel by hard link. The source and the destination themselves are excluded;
// so is anything outside the destination's pool root, because that is where a
// link can actually succeed — each pool is its own dataset, and incoming/ is on
// a different vdev entirely.
//
// The pool-root test is an optimization, not a correctness requirement. A donor
// that turns out to be on another filesystem fails with EXDEV and the copy
// happens as before, so a future layout change degrades performance rather than
// producing a wrong result.
//
// A lookup failure returns no donors rather than an error: publishing by copy
// is always correct, and a move must not fail because an optimization could not
// find its inputs.
func (db *DB) moveDonors(ctx context.Context, root, sha, oldRel, newRel string) []string {
	pool, _, ok := strings.Cut(newRel, "/")
	if !ok {
		return nil
	}
	locs, err := db.TopLevelLocationsForSHA(ctx, sha)
	if err != nil {
		slog.DebugContext(ctx, "donor lookup failed; publishing by copy",
			"sha256", sha, "error", err)
		return nil
	}
	return selectMoveDonors(locs, root, pool, oldRel, newRel)
}

// selectMoveDonors is the pure half of moveDonors: which of a sample's known
// locations are worth trying as link sources for a destination in pool.
func selectMoveDonors(locs []*SampleLocation, root, pool, oldRel, newRel string) []string {
	donors := make([]string, 0, maxMoveDonors)
	for _, loc := range locs {
		if len(donors) >= maxMoveDonors {
			break
		}
		if loc.Path == oldRel || loc.Path == newRel {
			continue
		}
		if donorPool, _, ok := strings.Cut(loc.Path, "/"); !ok || donorPool != pool {
			continue
		}
		_, abs, err := resolveMovePath(root, loc.Path)
		if err != nil {
			continue
		}
		donors = append(donors, abs)
	}
	return donors
}

func moveCopyFallback(err error) bool {
	return errors.Is(err, syscall.EXDEV) || errors.Is(err, syscall.EPERM) ||
		errors.Is(err, syscall.EOPNOTSUPP) || errors.Is(err, syscall.EMLINK)
}

func copyMoveContext(ctx context.Context, dst io.Writer, src io.Reader) (int64, error) {
	buf := make([]byte, 1024*1024)
	var written int64
	for {
		if err := ctx.Err(); err != nil {
			return written, err
		}
		n, readErr := src.Read(buf)
		if n > 0 {
			m, writeErr := dst.Write(buf[:n])
			written += int64(m)
			if writeErr != nil {
				return written, writeErr
			}
			if m != n {
				return written, io.ErrShortWrite
			}
		}
		if readErr != nil {
			if errors.Is(readErr, io.EOF) {
				return written, nil
			}
			return written, readErr
		}
	}
}

func hashMoveFile(name string) (string, error) {
	f, err := os.Open(name)
	if err != nil {
		return "", err
	}
	defer f.Close() //nolint:errcheck // read-only handle
	h := sha256.New()
	if _, err := io.Copy(h, f); err != nil {
		return "", err
	}
	return hex.EncodeToString(h.Sum(nil)), nil
}

func verifyMoveFile(name, expected string) error {
	got, err := hashMoveFile(name)
	if err != nil {
		return err
	}
	if got != expected {
		return fmt.Errorf("sha256 %s, want %s: %s", got, expected, name)
	}
	return nil
}

func rollbackMoveDestination(dst string, artifact, sidecar bool) error {
	var errs []error
	if sidecar {
		if err := removeMoveFile(dst + ProvenanceSidecarSuffix); err != nil {
			errs = append(errs, err)
		}
	}
	if artifact {
		if err := removeMoveFile(dst); err != nil {
			errs = append(errs, err)
		}
	}
	if artifact || sidecar {
		if err := syncMoveDir(filepath.Dir(dst)); err != nil {
			errs = append(errs, err)
		}
	}
	if len(errs) == 0 {
		return errors.New("hopper: source location disappeared during move")
	}
	return errors.Join(errs...)
}

func removeMoveFile(name string) error {
	if err := os.Remove(name); err != nil && !errors.Is(err, os.ErrNotExist) {
		return err
	}
	return nil
}

func syncMoveDir(name string) error {
	dir, err := os.Open(name)
	if err != nil {
		return err
	}
	defer dir.Close() //nolint:errcheck // fsync result is authoritative
	return dir.Sync()
}

func pruneMoveParents(dir, stop string) {
	stop = filepath.Clean(stop)
	for dir = filepath.Clean(dir); dir != stop; dir = filepath.Dir(dir) {
		if dir == "." || dir == string(filepath.Separator) || !strings.HasPrefix(dir, stop+string(filepath.Separator)) {
			return
		}
		if err := os.Remove(dir); err != nil {
			return
		}
	}
}
