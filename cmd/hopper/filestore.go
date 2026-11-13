package main

import (
	"context"
	"encoding/hex"
	"errors"
	"log/slog"
	"net/http"
	"os"

	"github.com/atomdrift-project/hopper"
	"github.com/atomdrift-project/hopper/store"
)

// serveFileFromStore serves a file's bytes where the verdict store places
// them: from its own paths, newest first; or, for a member with none, out of
// an archive on disk that holds it. GET /v1/files/{sha256}.
func (s *apiServer) serveFileFromStore(ctx context.Context, w http.ResponseWriter, r *http.Request, sha string) {
	digest, err := hex.DecodeString(sha)
	if err != nil {
		v1Error(w, http.StatusBadRequest, "invalid_sha256", "Invalid sha256.")
		return
	}
	src, err := s.results.Source(ctx, digest)
	switch {
	case errors.Is(err, store.ErrNotFound):
		v1Error(w, http.StatusNotFound, "unknown_artifact", "Nothing stored for that sha256.")
		return
	case err != nil:
		slog.ErrorContext(ctx, "file: source lookup failed", "sha256", sha, "error", err, "remote", r.RemoteAddr)
		v1Error(w, http.StatusInternalServerError, "internal", "Finding the file failed.")
		return
	}
	if len(src.Paths) > 0 {
		o, err := s.openStorePaths(ctx, sha, src.Paths)
		if err != nil {
			writeOpenFailure(w, err, "file_gone", "The file is no longer on disk.")
			return
		}
		defer o.f.Close() //nolint:errcheck // best-effort close
		w.Header().Set("Content-Type", "application/octet-stream")
		// Content-addressed by sha256: the bytes never change, so cache forever.
		w.Header().Set("Cache-Control", "public, max-age=31536000, immutable")
		http.ServeContent(w, r, o.stat.Name(), o.stat.ModTime(), o.f)
		return
	}
	if h := src.Holder; h != nil {
		o, err := s.openStorePaths(ctx, h.SHA256, h.Paths)
		if err != nil {
			writeOpenFailure(w, err, "parent_gone", "The archive holding the file is no longer on disk.")
			return
		}
		defer o.f.Close() //nolint:errcheck // best-effort close
		s.streamOpenedMember(ctx, w, r, o.f, o.stat, &hopper.Sample{SHA256: h.SHA256, FileType: h.FileType}, h.Member, sha)
		return
	}
	v1Error(w, http.StatusNotFound, "not_on_disk", "The file is known, but no copy of it is on disk.")
}

// openStorePaths opens the first of a file's paths that it is still at, and
// returns that path. It forgets each path the file is not at: the file was
// moved or deleted, and the next walk learns where it went. A mirror that
// holds rows for bytes it lacks (--dataset-incomplete) forgets nothing, nor
// does a server whose data root is unreachable, where every path would look
// gone.
func (s *apiServer) openStorePaths(ctx context.Context, sha string, paths []string) (*openedFile, error) {
	var last error
	for _, path := range paths {
		f, stat, err := s.openSamplePath(path)
		if err == nil {
			return &openedFile{f: f, stat: stat, path: path}, nil
		}
		last = err
		if !errors.Is(err, os.ErrNotExist) || s.datasetIncomplete {
			continue
		}
		if _, rerr := os.Stat(s.dataRoot); rerr != nil {
			slog.ErrorContext(ctx, "data root inaccessible; not forgetting a path",
				"data_root", s.dataRoot, "sha256", sha, "path", path, "error", rerr)
			continue
		}
		if uerr := s.results.Unlocate(ctx, sha, path); uerr != nil {
			slog.WarnContext(ctx, "forgetting a missing path failed", "sha256", sha, "path", path, "error", uerr)
		} else {
			slog.InfoContext(ctx, "file not at its recorded path; forgot it", "sha256", sha, "path", path)
		}
	}
	return nil, last
}

// openedFile is a file opened at one of its paths.
type openedFile struct {
	f    *os.File
	stat os.FileInfo
	path string
}

// openClaimedFromStore opens a claimed job's file: at the path it was handed
// out with, else at any other the store records for it.
func (s *apiServer) openClaimedFromStore(ctx context.Context, j *hopper.ClaimJob) (*os.File, os.FileInfo, error) {
	paths := []string{j.Path}
	if digest, err := hex.DecodeString(j.SHA256); err == nil {
		if src, err := s.results.Source(ctx, digest); err == nil {
			for _, p := range src.Paths {
				if p != j.Path {
					paths = append(paths, p)
				}
			}
		}
	}
	o, err := s.openStorePaths(ctx, j.SHA256, paths)
	if err != nil {
		return nil, nil, err
	}
	j.Path = o.path
	return o.f, o.stat, nil
}

// writeOpenFailure answers a file that could not be opened: 404 for a path
// outside the pools or not a regular file, 410 with code for one gone from
// disk, and a retryable 503 for anything else.
func writeOpenFailure(w http.ResponseWriter, err error, code, message string) {
	if errors.Is(err, errSamplePathRejected) || errors.Is(err, errSampleNotRegular) {
		v1Error(w, http.StatusNotFound, "not_found", "Not found.")
		return
	}
	writeMissingSampleFile(w, err, code, message)
}

// heldInStore is what the verdict store knows of an upload's digest: the
// file with its newest path, if it has one, and whether atomscan has judged
// it. hopper.ErrNotFound when the digest is not known.
func (s *apiServer) heldInStore(ctx context.Context, sha string) (*hopper.Sample, bool, error) {
	digest, err := hex.DecodeString(sha)
	if err != nil {
		return nil, false, err
	}
	src, err := s.results.Source(ctx, digest)
	if errors.Is(err, store.ErrNotFound) {
		return nil, false, hopper.ErrNotFound
	}
	if err != nil {
		return nil, false, err
	}
	held := &hopper.Sample{SHA256: sha}
	if len(src.Paths) > 0 {
		held.Path = src.Paths[0]
	}
	rec, err := s.results.BySHA256(ctx, digest)
	if err != nil {
		return held, false, err
	}
	return held, rec.Analyzed, nil
}
