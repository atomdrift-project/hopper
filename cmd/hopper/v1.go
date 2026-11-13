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
// whose state is "pending" when the bytes are held but nothing has analyzed
// them yet; 404 when nothing is stored.
//
// No threshold parameter and no decision: turning a level into allow/block
// belongs to whoever holds the policy, and a second implementation of that one
// rule is a security bug rather than a duplication. Hopper reports what it
// stored; see [hopper.LookupRecord].
func (s *apiServer) handleV1Lookup(w http.ResponseWriter, r *http.Request) {
	if s.db == nil {
		writeRetryable(w, retryAfterStarting, "starting", "Starting.")
		return
	}
	sha := strings.TrimSpace(r.URL.Query().Get("sha256"))
	if purls := r.URL.Query()["purl"]; len(purls) > 1 && sha == "" {
		s.handleV1LookupBatch(w, r, purls)
		return
	}
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

	record, err := s.lookup(ctx, strings.ToLower(sha), base, version)
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

	// A caller who named a PURL gets their spelling back, canonicalized: it is
	// the identity they asked about, and the record's own composed PURL can
	// differ when a digest resolves to a release named another way.
	if canon != "" {
		record = withPURL(record, canon)
	}
	v1WriteJSON(w, http.StatusOK, record)
}

// v1LookupBatchMax is the most PURLs one request may name. It is scan's batch
// size for its pre-fetch PURL negotiation (corpus_precheck.rs chunks by 50), so
// a conforming caller never trips it.
const v1LookupBatchMax = 50

// handleV1LookupBatch answers GET /v1/lookup?purl=…&purl=… — several packages
// in one request, as scan's pre-fetch dependency negotiation asks.
//
// Always 200 with {"records": […]}, one record per PURL the corpus has an
// analyzed verdict for, in the order asked; unknown, held-but-unanalyzed and
// unparseable PURLs are simply absent. Each record's purl is the caller's
// bytes, unaltered, because a caller matches a list reply to its request by
// that field — canonicalizing it here would silently drop every hit whose
// spelling normalization changes.
//
// This route used to read only the first purl= and answer it as if it were the
// whole request, so a 50-PURL batch skipped at most one dependency (and none at
// all when the first was unknown, since that answered the whole batch 404).
// Workers then fetched, analyzed and re-posted the other 49 — measured
// 2026-09-24 as a 4.6% fleet skip rate and a renew lane that was 97% redundant.
func (s *apiServer) handleV1LookupBatch(w http.ResponseWriter, r *http.Request, purls []string) {
	if len(purls) > v1LookupBatchMax {
		v1Error(w, http.StatusBadRequest, "too_many_purls",
			"Name at most "+strconv.Itoa(v1LookupBatchMax)+" PURLs per lookup.")
		return
	}
	ctx, cancel := context.WithTimeout(r.Context(), v1LookupTimeout)
	defer cancel()

	out := make([]*hopper.LookupRecord, 0, len(purls))
	var found, unanalyzed, unknown, invalid int
	for _, asked := range purls {
		raw := strings.TrimSpace(asked)
		if raw == "" {
			invalid++
			continue
		}
		if !strings.EqualFold(firstFour(raw), "pkg:") {
			raw = "pkg:" + raw
		}
		canon := pkgparse.CanonicalizePURL(raw)
		if len(canon) < 4 || !strings.EqualFold(canon[:4], "pkg:") {
			invalid++
			continue
		}
		record, err := s.lookup(ctx, "", pkgparse.VersionlessPURL(canon), pkgparse.PURLVersion(canon))
		switch {
		case errors.Is(err, hopper.ErrNotFound):
			unknown++
			continue
		case err != nil:
			// One bad key must not cost the caller the rest of the batch: every
			// absent entry falls through to an ordinary fetch on its side.
			slog.WarnContext(r.Context(), "v1 batch lookup failed",
				"purl", canon, "error", err, "remote", r.RemoteAddr)
			unknown++
			continue
		case record.State != hopper.StateAnalyzed:
			unanalyzed++
			continue
		default:
		}
		found++
		out = append(out, withPURL(record, asked))
	}
	recordPURLLookups(r.Context(), found, unanalyzed, unknown, invalid)
	v1WriteJSON(w, http.StatusOK, map[string]any{"records": out})
}

// withPURL returns a copy of a record carrying purl. The record LookupRecord
// hands back is the one the pool holds and every concurrent caller reads, so
// writing the caller's spelling into it in place would be a data race and would
// answer the next caller in the previous caller's spelling.
func withPURL(record *hopper.LookupRecord, purl string) *hopper.LookupRecord {
	c := *record
	c.PURL = &purl
	return &c
}

// v1Error writes the API's one error object:
//
//	{"error": {"code": "…", "message": "…", …details}}
//
// code is stable and machine-readable; message is for people and may be
// reworded freely. details are key/value pairs added to the object, such as
// "max" for a batch limit or "use" for a retired path. An error is never
// cached.
func v1Error(w http.ResponseWriter, status int, code, message string, details ...any) {
	body := map[string]any{"code": code, "message": message}
	for i := 0; i+1 < len(details); i += 2 {
		if k, ok := details[i].(string); ok {
			body[k] = details[i+1]
		}
	}
	w.Header().Set("Cache-Control", "no-store")
	v1WriteJSON(w, status, map[string]any{"error": body})
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
