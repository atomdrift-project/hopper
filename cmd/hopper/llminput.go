package main

import (
	"bytes"
	"context"
	"encoding/hex"
	"errors"
	"log/slog"
	"net/http"
	"strconv"
	"strings"
	"time"

	"github.com/atomdrift-project/hopper/store"
)

// A worker whose LLM pass did not run leaves behind what that pass needs, so
// that a worker with an LLM handed the file to describe (tier missing_llm,
// hopper.ClaimJob.HasLLMInput) runs the pass alone instead of the whole
// analysis. The input is opaque to hopper; store/llminput.go keeps it.

// maxLLMInput caps an LLM input. The body is read no further than this.
const maxLLMInput = 16 << 20

// llmInputBodyTimeout bounds how long an LLM input may take to arrive, as
// resultBodyTimeout does for a result: a slow-loris defense.
const llmInputBodyTimeout = 2 * time.Minute

// handleSetLLMInput stores the input a worker's LLM pass needs to describe a
// file, replacing any stored before. PUT /v1/files/{sha256}/llm-input with
// the input as the body. 204 when stored, and when an LLM has described the
// file already (there is nothing left for the input to do); 404 for a file
// hopper does not know; 413 for a body over maxLLMInput; 415 for a
// Content-Encoding, since the bytes are kept and served as they arrive; 501
// without the verdict store.
func (s *apiServer) handleSetLLMInput(w http.ResponseWriter, r *http.Request) {
	if s.results == nil {
		v1Error(w, http.StatusNotImplemented, "needs_verdict_store", "Needs the verdict store.")
		return
	}
	sha := r.PathValue("sha256")
	if !validSHA256(sha) {
		v1Error(w, http.StatusBadRequest, "invalid_sha256", "Invalid sha256.")
		return
	}
	if enc := strings.TrimSpace(r.Header.Get("Content-Encoding")); enc != "" && !strings.EqualFold(enc, "identity") {
		v1Error(w, http.StatusUnsupportedMediaType, "unsupported_content_encoding", "Unsupported content-encoding.")
		return
	}
	_ = http.NewResponseController(w).SetReadDeadline(time.Now().Add(llmInputBodyTimeout)) //nolint:errcheck // unsupported under httptest
	// Sized for the declared length, and the slack ReadFrom asks for before
	// it sees the end, so a body is read into one allocation. A declared
	// length over the cap is refused unread.
	over := r.ContentLength > maxLLMInput
	body := &bytes.Buffer{}
	if !over {
		body.Grow(int(max(r.ContentLength, 0)) + bytes.MinRead)
		_, err := body.ReadFrom(http.MaxBytesReader(w, r.Body, maxLLMInput))
		_, over = errors.AsType[*http.MaxBytesError](err)
		if err != nil && !over {
			slog.WarnContext(r.Context(), "llm input rejected: body read failed", "sha256", sha, "error", err,
				"agent", r.UserAgent(), "remote", r.RemoteAddr)
			v1Error(w, http.StatusBadRequest, "body_read_failed", "Body read failed.")
			return
		}
	}
	if over {
		slog.WarnContext(r.Context(), "llm input rejected: body exceeds size limit", "sha256", sha,
			"content_length", r.ContentLength, "limit_bytes", maxLLMInput, "agent", r.UserAgent(), "remote", r.RemoteAddr)
		v1Error(w, http.StatusRequestEntityTooLarge, "llm_input_too_large", "LLM input exceeds 16 MiB.")
		return
	}
	if body.Len() == 0 {
		v1Error(w, http.StatusBadRequest, "empty_body", "The LLM input is empty.")
		return
	}
	sum, _ := hex.DecodeString(sha) //nolint:errcheck // validSHA256 passed
	ctx, cancel := context.WithTimeout(r.Context(), apiQueryTimeout)
	defer cancel()
	known, stored, err := s.results.SetLLMInput(ctx, sum, body.Bytes())
	if err != nil {
		slog.ErrorContext(ctx, "llm input: store failed", "sha256", sha, "bytes", body.Len(), "error", err,
			"agent", r.UserAgent(), "remote", r.RemoteAddr)
		v1Error(w, http.StatusInternalServerError, "server_error", "Server error.")
		return
	}
	if !known {
		slog.InfoContext(ctx, "llm input refused: unknown file", "sha256", sha, "bytes", body.Len(),
			"agent", r.UserAgent(), "remote", r.RemoteAddr)
		v1Error(w, http.StatusNotFound, "unknown_artifact", "Nothing stored for that sha256.")
		return
	}
	slog.InfoContext(ctx, "llm input", "sha256", sha, "bytes", body.Len(), "stored", stored,
		"agent", r.UserAgent(), "remote", r.RemoteAddr)
	w.WriteHeader(http.StatusNoContent)
}

// handleLLMInput serves the input stored for a file's LLM pass
// (handleSetLLMInput). GET /v1/files/{sha256}/llm-input. 404 with code
// no_llm_input when none is stored.
func (s *apiServer) handleLLMInput(w http.ResponseWriter, r *http.Request) {
	if s.results == nil {
		v1Error(w, http.StatusNotImplemented, "needs_verdict_store", "Needs the verdict store.")
		return
	}
	sha := r.PathValue("sha256")
	if !validSHA256(sha) {
		v1Error(w, http.StatusBadRequest, "invalid_sha256", "Invalid sha256.")
		return
	}
	sum, _ := hex.DecodeString(sha) //nolint:errcheck // validSHA256 passed
	ctx, cancel := context.WithTimeout(r.Context(), apiQueryTimeout)
	defer cancel()
	input, err := s.results.LLMInput(ctx, sum)
	switch {
	case errors.Is(err, store.ErrNotFound):
		v1Error(w, http.StatusNotFound, "no_llm_input", "No LLM input stored for that sha256.")
		return
	case err != nil:
		slog.ErrorContext(ctx, "llm input: read failed", "sha256", sha, "error", err,
			"agent", r.UserAgent(), "remote", r.RemoteAddr)
		v1Error(w, http.StatusInternalServerError, "server_error", "Server error.")
		return
	}
	slog.InfoContext(ctx, "llm input served", "sha256", sha, "bytes", len(input),
		"agent", r.UserAgent(), "remote", r.RemoteAddr)
	h := w.Header()
	h.Set("Content-Type", "application/octet-stream")
	h.Set("Content-Length", strconv.Itoa(len(input)))
	h.Set("X-Content-Type-Options", "nosniff")
	// Replaced by the next upload and deleted once used: never cached.
	h.Set("Cache-Control", "no-store")
	if _, err := w.Write(input); err != nil {
		slog.WarnContext(ctx, "llm input: write failed", "sha256", sha, "error", err)
	}
}
