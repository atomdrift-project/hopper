package main

import (
	"context"
	"encoding/json"
	"errors"
	"log/slog"
	"net/http"
	"strconv"
	"strings"
	"time"

	"github.com/atomdrift-project/hopper"
	"github.com/atomdrift-project/hopper/pkgparse"
)

// v1LookupTimeout bounds one lookup. Shorter than apiQueryTimeout because this
// route reads no large column and sits on somebody's critical path: a scan
// worker asks here only after missing its own index, with a caller waiting on
// both.
const v1LookupTimeout = 5 * time.Second

// handleV1Lookup answers what the corpus knows about one artifact.
//
// GET /v1/lookup?sha256=…&purl=… — either key, or both. 200 with the record,
// 404 when nothing is stored, 202 when the bytes are held but nothing has
// analyzed them yet.
//
// No threshold parameter and no decision: turning a level into allow/block
// belongs to whoever holds the policy, and a second implementation of that one
// rule is a security bug rather than a duplication. Hopper reports what it
// stored; see [hopper.LookupRecord].
func (s *apiServer) handleV1Lookup(w http.ResponseWriter, r *http.Request) {
	if s.db == nil {
		writeRetryable(w, retryAfterStarting, `{"error":"starting"}`)
		return
	}
	sha := strings.TrimSpace(r.URL.Query().Get("sha256"))
	raw := strings.TrimSpace(r.URL.Query().Get("purl"))
	if sha == "" && raw == "" {
		v1Error(w, http.StatusBadRequest, "missing_package", "Name an artifact with ?sha256= or ?purl=.")
		return
	}
	if sha != "" && !validSHA256(sha) {
		v1Error(w, http.StatusBadRequest, "invalid_sha256", "sha256 must be 64 hexadecimal characters.")
		return
	}
	var canon, base, version string
	if raw != "" {
		// `pkg:` is optional here as it is on scan's /v1/lookup and beamline's:
		// one surface, one spelling, so a caller who copies a PURL out of a
		// lockfile is not told a package they can see is unknown.
		if !strings.EqualFold(firstFour(raw), "pkg:") {
			raw = "pkg:" + raw
		}
		canon = pkgparse.CanonicalizePURL(raw)
		if len(canon) < 4 || !strings.EqualFold(canon[:4], "pkg:") {
			v1Error(w, http.StatusBadRequest, "invalid_purl", "purl is not a package URL.")
			return
		}
		base = pkgparse.VersionlessPURL(canon)
		version = pkgparse.PURLVersion(canon)
	}

	ctx, cancel := context.WithTimeout(r.Context(), v1LookupTimeout)
	defer cancel()

	record, err := s.db.LookupRecord(ctx, strings.ToLower(sha), base, version)
	if err != nil {
		if errors.Is(err, hopper.ErrNotFound) {
			v1Error(w, http.StatusNotFound, "unknown_artifact", "Nothing stored for that artifact.")
			return
		}
		slog.ErrorContext(r.Context(), "v1 lookup failed",
			"sha256", sha, "purl", canon, "error", err, "remote", r.RemoteAddr)
		v1Error(w, http.StatusInternalServerError, "internal", "Lookup failed.")
		return
	}

	// Held, but nobody has looked at it. 202 rather than an empty 200: an
	// answer is coming for this key, which is worth waiting on rather than
	// reading as "we looked and there was nothing".
	if !record.Analyzed {
		if record.SHA256 != nil {
			w.Header().Set("X-Sha256", *record.SHA256)
		}
		w.Header().Set("Retry-After", strconv.Itoa(sampleQueuedRetryAfter))
		w.WriteHeader(http.StatusAccepted)
		return
	}

	// A caller who named a PURL gets their spelling back, canonicalized: it is
	// the identity they asked about, and the record's own composed PURL can
	// differ when a digest resolves to a release named another way.
	if canon != "" {
		record.PURL = &canon
	}
	v1WriteJSON(w, http.StatusOK, record)
}

// v1Error writes a v1 error. `code` is stable and machine-readable; `message`
// is for people and may be reworded freely.
func v1Error(w http.ResponseWriter, status int, code, message string) {
	v1WriteJSON(w, status, map[string]any{
		"error": map[string]string{"code": code, "message": message},
	})
}

func v1WriteJSON(w http.ResponseWriter, status int, body any) {
	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("X-Content-Type-Options", "nosniff")
	w.WriteHeader(status)
	if err := json.NewEncoder(w).Encode(body); err != nil {
		slog.Warn("v1: write failed", "error", err)
	}
}

// firstFour returns up to the first four bytes of s, for prefix tests that must
// not panic on a shorter string.
func firstFour(s string) string {
	if len(s) < 4 {
		return s
	}
	return s[:4]
}
