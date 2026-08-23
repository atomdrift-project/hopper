package main

// triagewrite.go serves the two authoritative writes a triage consumer makes
// that were not already an endpoint: the reports row that drains a queue, and
// the cleave verdict written back after a re-scan.
//
// They exist so a scan host needs no database credential at all. Everything
// else it does already went through this API — bytes via /api/file, rulings via
// /api/triage, corroboration via /api/sightings — and these two were the
// remainder, reached over a direct Postgres connection because there was
// nowhere else to send them.
//
// Both are writes, so both live behind the read-only refusal on a replica: a
// consumer reads its work from a serve-replica instance and sends these to the
// primary, which is the same split prism has used for /api/rescan.

import (
	"context"
	"encoding/json"
	"io"
	"log/slog"
	"net/http"
	"strings"

	"github.com/atomdrift-project/hopper"
)

// maxTriageWriteBody bounds a report body. A report is a short line of
// provenance ("judgement=confirmed verdict_before=good conf=70→70"), so this is
// three orders of magnitude of headroom rather than a real limit.
const maxTriageWriteBody = 64 << 10

// maxCleaveResultBody bounds a written-back cleave envelope. It is the archive
// member tree, which for a large package runs to megabytes; this matches the
// ceiling the ingestion path already accepts for the same document.
const maxCleaveResultBody = maxResultBodyBytes

type reportRequest struct {
	SHA256   string `json:"sha256"`
	Type     string `json:"type"`
	Provider string `json:"provider"`
	Content  string `json:"content"`
}

// handleReport records one reports row. POST /api/report.
//
// This is a queue's DRAIN, which is why the type matters more than it looks: a
// review or -stale selector anti-joins on a report whose type is the queue's
// own name, so a row filed under the wrong type drains nothing and the sample
// churns through every cooldown forever. The handler cannot reject an unknown
// type — "re", "gap" and "fpr" are other producers' and the set is open — but it
// warns on one it does not recognize, so a typo shows up in the logs on the
// first write rather than as an unexplained backlog weeks later.
func (s *apiServer) handleReport(w http.ResponseWriter, r *http.Request) {
	if s.db == nil {
		writeRetryable(w, retryAfterStarting, `{"error":"starting"}`)
		return
	}

	var req reportRequest
	if err := json.NewDecoder(io.LimitReader(r.Body, maxTriageWriteBody+1)).Decode(&req); err != nil {
		slog.WarnContext(r.Context(), "report rejected: invalid json", "remote", r.RemoteAddr, "error", err)
		writeJSONError(w, http.StatusBadRequest, `{"error":"invalid json"}`)
		return
	}

	sha := strings.ToLower(strings.TrimSpace(req.SHA256))
	if !validSHA256(sha) {
		writeJSONError(w, http.StatusBadRequest, `{"error":"invalid sha256"}`)
		return
	}
	reportType := strings.TrimSpace(req.Type)
	if reportType == "" {
		// An empty type is never a drain: it anti-joins nothing, so the write
		// would "succeed" and the sample would resurface indefinitely.
		writeJSONError(w, http.StatusBadRequest, `{"error":"type is required"}`)
		return
	}
	if _, known := hopper.TriageQueues[reportType]; !known && reportType != hopper.ReportTypeMissing {
		slog.WarnContext(r.Context(), "report type is not a registered queue or a known marker",
			"type", reportType, "sha256", sha, "remote", r.RemoteAddr)
	}

	// Detached from the request, like every other write here: a caller that
	// hangs up must not abort a drain half-written, or the sample silently
	// re-selects forever.
	ctx, cancel := context.WithTimeout(context.WithoutCancel(r.Context()), apiQueryTimeout)
	defer cancel()

	err := retryDBAccessNoValue(ctx, "insert report", sha, func(ctx context.Context) error {
		return s.db.InsertReport(ctx, &hopper.Report{
			SHA256:   sha,
			Type:     reportType,
			Provider: strings.TrimSpace(req.Provider),
			Content:  req.Content,
		})
	})
	if err != nil {
		// A reports row references its sample, so an integrity violation here
		// means the sha is not one we hold — a client bug, not a server fault,
		// and retrying it forever would never help. retryDBAccess already
		// declines to retry a class-23 error (permanentPGError), so this only
		// has to give it an honest status.
		if classifyInsertFailure(err) == causeConstraint {
			slog.WarnContext(r.Context(), "report rejected: no such sample",
				"sha256", sha, "type", reportType, "remote", r.RemoteAddr)
			writeJSONError(w, http.StatusNotFound, `{"error":"unknown sample"}`)
			return
		}
		slog.ErrorContext(r.Context(), "report: insert failed",
			"sha256", sha, "type", reportType, "error", err, "remote", r.RemoteAddr)
		writeJSONError(w, http.StatusInternalServerError, `{"error":"server error"}`)
		return
	}
	slog.InfoContext(r.Context(), "report recorded",
		"sha256", sha, "type", reportType, "remote", r.RemoteAddr)
	writeTriageJSON(w, map[string]string{"status": "recorded"})
}

type cleaveResultRequest struct {
	SHA256 string          `json:"sha256"`
	Result json.RawMessage `json:"result"`
}

// handleCleaveResult stores a re-scanned cleave verdict. POST /api/cleave-result.
//
// Deliberately narrow, and NOT a thin alias for /api/result. That endpoint takes
// a whole analysis envelope — raw, ml and llm together — because it serves a
// scan worker submitting everything it produced. A triage consumer has only
// re-run cleave; it has no ML and no interpretation to send, and routing it
// through the full store would write those absent sections over the ones
// already on the row. The narrow endpoint touches exactly the column the caller
// actually recomputed.
//
// The caller sends only the envelope: ParseCleaveResult derives the canonical
// sha, the file info and the traits version, so the server's parse is the
// authoritative one and there is no second copy for a client to get wrong.
//
// A parse yielding no file type DELETES the sample — that is UpdateCleaveResult's
// long-standing contract for an envelope describing nothing analyzable, not
// something introduced here. It is reported as "deleted" rather than "stored" so
// a caller is never told its write-back landed when the row is gone.
func (s *apiServer) handleCleaveResult(w http.ResponseWriter, r *http.Request) {
	if s.db == nil {
		writeRetryable(w, retryAfterStarting, `{"error":"starting"}`)
		return
	}

	body := io.LimitReader(r.Body, maxCleaveResultBody+1)
	var req cleaveResultRequest
	if err := json.NewDecoder(body).Decode(&req); err != nil {
		slog.WarnContext(r.Context(), "cleave result rejected: invalid json", "remote", r.RemoteAddr, "error", err)
		writeJSONError(w, http.StatusBadRequest, `{"error":"invalid json"}`)
		return
	}

	sha := strings.ToLower(strings.TrimSpace(req.SHA256))
	if !validSHA256(sha) {
		writeJSONError(w, http.StatusBadRequest, `{"error":"invalid sha256"}`)
		return
	}
	if len(req.Result) == 0 {
		// Refused rather than passed through: an empty envelope parses to no
		// file type, which UpdateCleaveResult treats as a delete. A caller that
		// forgot to attach its scan must not thereby remove the sample.
		writeJSONError(w, http.StatusBadRequest, `{"error":"result is required"}`)
		return
	}

	// resultStoreTimeout and a detached context, matching /api/result: this is
	// the same document written to the same column, and a disconnect must not
	// abort it partway.
	ctx, cancel := context.WithTimeout(context.WithoutCancel(r.Context()), resultStoreTimeout)
	defer cancel()

	parsed := hopper.ParseCleaveResult(sha, req.Result)
	deleted := parsed.FileInfo.FileType == ""
	err := retryDBAccessNoValue(ctx, "update cleave result", sha, func(ctx context.Context) error {
		return s.db.UpdateCleaveResult(ctx, sha, req.Result, &parsed, parsed.TraitsVersion)
	})
	if err != nil {
		slog.ErrorContext(r.Context(), "cleave result: store failed",
			"sha256", sha, "error", err, "remote", r.RemoteAddr)
		writeJSONError(w, http.StatusInternalServerError, `{"error":"server error"}`)
		return
	}

	status := "stored"
	if deleted {
		status = "deleted"
		slog.WarnContext(r.Context(), "cleave result described nothing analyzable; sample deleted",
			"sha256", sha, "remote", r.RemoteAddr)
	} else {
		slog.InfoContext(r.Context(), "cleave result stored",
			"sha256", sha, "traits_version", parsed.TraitsVersion, "remote", r.RemoteAddr)
	}
	writeTriageJSON(w, map[string]string{"status": status})
}
