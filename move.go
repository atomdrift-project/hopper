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

	artifactCreated, err := publishMoveFile(ctx, oldAbs, newAbs, sha)
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
	created, err = publishMoveFile(ctx, src, dst, expected)
	return created, true, err
}

// publishMoveFile creates dst without clobbering an existing path. A same-device
// hard link is preferred; cross-device moves copy once through a verified,
// fsynced temporary file and publish it with an atomic hard link.
func publishMoveFile(ctx context.Context, src, dst, expected string) (bool, error) {
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
