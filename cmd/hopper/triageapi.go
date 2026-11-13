package main

// triageapi.go serves the triage queues: the work-selection half of what used
// to be a direct database connection from every scan host.
//
// Two routes, both reads: GET /v1/triage/{queue} (candidates) and
// GET /v1/triage/{queue}/depth (backlog).
// They are registered on the read-safe side of registerAPI, so a serve-replica
// instance answers them from the replica's idle disk while the primary keeps its
// I/O for ingestion.
//
// Selection claims nothing: a GET here is a read, and repeated reads return
// the same head. Deciding who works which sample belongs to the consumer, the
// only party that knows when a batch starts, ends or dies. A lease here could
// only guess at that, and did: every row a select returned was held for two
// hours whether or not the caller batched it, so one worker reading 64 rows to
// batch 3 locked its siblings out of a 25-row queue for the whole lease.

import (
	"context"
	"encoding/json"
	"log/slog"
	"net/http"
	"strconv"
	"strings"

	"github.com/atomdrift-project/hopper"
	"github.com/atomdrift-project/hopper/store"
)

// triageQuerySlots bounds expensive queue reads independently of ingestion.
// A process-local limit reserves most of the shared DB pool for other work.
const triageQuerySlots = 4

func (s *apiServer) admitTriage(w http.ResponseWriter, r *http.Request) bool {
	s.triageSemOnce.Do(func() { s.triageSem = make(chan struct{}, triageQuerySlots) })
	if err := acquireSlot(r.Context(), s.triageSem); err != nil {
		if r.Context().Err() == nil {
			recordLoadShed(r.Context(), "triage")
			writeRetryable(w, retryAfterBusy, "busy_triage_queries_saturated", "Busy: triage queries saturated.")
		}
		return false
	}
	return true
}

// triageMaxLimit caps a single select. The queues exist to feed batches of a
// few samples each; a caller asking for thousands is either misconfigured or
// trying to drain a queue into its own process, and both are better answered
// with a bounded page than with a query whose cost the server does not control.
const triageMaxLimit = 500

// triageDefaultLimit is what a select returns when the caller names no limit.
const triageDefaultLimit = 16

// triageQueue resolves the {queue} path value against the registry, answering
// the request and reporting false when it is unknown or the DB is not up.
func (s *apiServer) triageQueue(w http.ResponseWriter, r *http.Request) (hopper.Queue, bool) {
	if s.db == nil && s.results == nil {
		writeRetryable(w, retryAfterStarting, "starting", "Starting.")
		return hopper.Queue{}, false
	}
	name := strings.ToLower(strings.TrimSpace(r.PathValue("queue")))
	if s.results != nil {
		if !triageKnown(name) {
			v1Error(w, http.StatusNotFound, "unknown_queue", "No such triage queue.", "queues", store.TriageQueueNames())
			return hopper.Queue{}, false
		}
		return hopper.Queue{Name: name}, true
	}
	q, ok := hopper.TriageQueues[name]
	if !ok {
		// 404 naming the valid set: an operator typo here is otherwise
		// invisible, and the caller already needs the registry to know what to
		// ask for. A []string cannot fail to marshal.
		v1Error(w, http.StatusNotFound, "unknown_queue", "No such triage queue.", "queues", hopper.TriageQueueNames())
		return hopper.Queue{}, false
	}
	return q, true
}

// handleTriageSelect returns the head of one queue, up to limit rows.
// GET /v1/triage/{queue}?limit=N.
//
// The samples are hopper.Sample values marshalled as-is. That makes the wire
// format the struct's Go field names, which is safe precisely because this is an
// internal, worker-facing API: both ends are pinned to one hopper version by
// go.mod, so a field rename moves both sides together. The Triage* selectors use
// the light column projection, so the JSONB blob columns (cleave_result,
// litmus_result, llm_result, provenance) come back nil and cost nothing to
// serialize — do not route a fully-populated Sample through here.
func (s *apiServer) handleTriageSelect(w http.ResponseWriter, r *http.Request) {
	q, ok := s.triageQueue(w, r)
	if !ok {
		return
	}
	limit, ok := triageLimit(w, r)
	if !ok {
		return
	}

	var excluded []string
	if raw := r.URL.Query().Get("exclude"); raw != "" {
		excluded = strings.Split(raw, ",")
		for _, sha := range excluded {
			if !validSHA256(sha) {
				v1Error(w, http.StatusBadRequest, "invalid_exclude", "exclude must hold comma-separated SHA256 digests.")
				return
			}
		}
	}
	if !s.admitTriage(w, r) {
		return
	}
	defer func() { <-s.triageSem }()
	ctx, cancel := context.WithTimeout(r.Context(), apiQueryTimeout)
	defer cancel()

	var samples []*hopper.Sample
	var err error
	if s.results != nil {
		samples, err = s.triageSelectStore(ctx, q.Name, limit, excluded)
	} else {
		samples, err = q.Select(ctx, s.db, limit, excluded)
	}
	if err != nil {
		slog.ErrorContext(r.Context(), "triage: select failed",
			"queue", q.Name, "limit", limit, "error", err, "remote", r.RemoteAddr)
		v1Error(w, http.StatusInternalServerError, "server_error", "Server error.")
		return
	}
	slog.InfoContext(r.Context(), "triage select",
		"queue", q.Name, "limit", limit, "returned", len(samples), "remote", r.RemoteAddr)

	writeTriageJSON(w, map[string]any{
		"queue":              q.Name,
		"exclusions_applied": true,
		// Never null: a client ranging over the result should not have to
		// distinguish "no work" from "no field".
		"samples": append(make([]*hopper.Sample, 0, len(samples)), samples...),
	})
}

// handleTriageDepth reports one queue's backlog. GET /v1/triage/{queue}/depth.
// Every queue can answer: a depth is the queue's own selection run to
// hopper.TriageDepthCap and counted, so there is no longer a "no countable
// population" case to 404 on.
func (s *apiServer) handleTriageDepth(w http.ResponseWriter, r *http.Request) {
	q, ok := s.triageQueue(w, r)
	if !ok {
		return
	}

	if !s.admitTriage(w, r) {
		return
	}
	defer func() { <-s.triageSem }()
	ctx, cancel := context.WithTimeout(r.Context(), apiQueryTimeout)
	defer cancel()

	if s.results != nil {
		body, err := s.triageDepthStore(ctx, q.Name)
		if err != nil {
			slog.ErrorContext(r.Context(), "triage: depth failed", "queue", q.Name, "error", err, "remote", r.RemoteAddr)
			v1Error(w, http.StatusInternalServerError, "server_error", "Server error.")
			return
		}
		writeTriageJSON(w, body)
		return
	}
	if q.Name == "gauntlet" {
		counts, capped, err := s.db.GauntletDepth(ctx)
		if err != nil {
			slog.ErrorContext(r.Context(), "gauntlet depth failed", "error", err)
			v1Error(w, http.StatusInternalServerError, "server_error", "Server error.")
			return
		}
		writeTriageJSON(w, map[string]any{
			"queue": q.Name, "depth": counts["false_positive"] + counts["miss"], "capped": capped, "by_failure": counts,
		})
		return
	}

	depth, capped, err := q.Count(ctx, s.db)
	if err != nil {
		slog.ErrorContext(r.Context(), "triage: depth failed",
			"queue", q.Name, "error", err, "remote", r.RemoteAddr)
		v1Error(w, http.StatusInternalServerError, "server_error", "Server error.")
		return
	}
	writeTriageJSON(w, map[string]any{
		"queue": q.Name,
		"depth": depth,
		// A queue at the cap reports the cap. Clients render that as "<cap>+"
		// rather than as an exact backlog.
		"capped": capped,
	})
}

// triageLimit parses ?limit=, defaulting and bounding it. A limit that is not a
// positive integer is a client bug worth reporting rather than silently
// defaulting — the caller asked for something specific and would not find out.
func triageLimit(w http.ResponseWriter, r *http.Request) (int, bool) {
	raw := strings.TrimSpace(r.URL.Query().Get("limit"))
	if raw == "" {
		return triageDefaultLimit, true
	}
	n, err := strconv.Atoi(raw)
	if err != nil || n < 1 {
		v1Error(w, http.StatusBadRequest, "invalid_limit", "Limit must be a positive integer.")
		return 0, false
	}
	return min(n, triageMaxLimit), true
}

// writeTriageJSON encodes a response body, logging rather than failing on a
// write error: the status line is already sent by then, so there is nothing
// left to tell the client.
func writeTriageJSON(w http.ResponseWriter, body any) {
	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("X-Content-Type-Options", "nosniff")
	if err := json.NewEncoder(w).Encode(body); err != nil {
		slog.Warn("triage: write response failed", "error", err)
	}
}

// maxSightingSubjects bounds one lookup. Subjects arrive as repeated query
// parameters, and a consumer asks about one batch at a time — a sha256 plus an
// optional purl_base per sample — so this is far above any real batch while
// keeping the URL and the IN-list bounded.
const maxSightingSubjects = 256

// handleSightingsFor returns the corroboration ledger for a set of subjects,
// keyed by subject. GET /v1/sightings?subject=<sha256-or-purl>&subject=...
//
// A GET sharing a path with the POST that RECORDS sightings, which is the
// honest pairing: same resource, one method reads it and the other appends to
// it. It also has to be a GET rather than a POST-with-a-body, because this is a
// read a consumer makes against a replica, and every POST is refused there.
func (s *apiServer) handleSightingsFor(w http.ResponseWriter, r *http.Request) {
	if s.db == nil {
		writeRetryable(w, retryAfterStarting, "starting", "Starting.")
		return
	}
	subjects := r.URL.Query()["subject"]
	if len(subjects) == 0 {
		v1Error(w, http.StatusBadRequest, "missing_subject", "At least one subject is required.")
		return
	}
	if len(subjects) > maxSightingSubjects {
		v1Error(w, http.StatusRequestEntityTooLarge, "too_many_subjects",
			"At most "+strconv.Itoa(maxSightingSubjects)+" subjects per request.", "max", maxSightingSubjects)
		return
	}
	// Normalize a sha256 subject to lowercase to match stored digests; a PURL is
	// left verbatim. Mirrors what the recording path does, so a lookup finds
	// what a write stored.
	for i, subject := range subjects {
		if lower := strings.ToLower(subject); validSHA256(lower) {
			subjects[i] = lower
		}
	}

	ctx, cancel := context.WithTimeout(r.Context(), apiQueryTimeout)
	defer cancel()

	var bySubject map[string][]hopper.Sighting
	var err error
	if s.results != nil {
		bySubject, err = s.sightingsFromStore(ctx, subjects)
	} else {
		bySubject, err = s.db.SightingsFor(ctx, subjects)
	}
	if err != nil {
		slog.ErrorContext(r.Context(), "sightings lookup failed",
			"subjects", len(subjects), "error", err, "remote", r.RemoteAddr)
		v1Error(w, http.StatusInternalServerError, "server_error", "Server error.")
		return
	}
	// Never null, for the same reason the select envelope is not: a client
	// ranging over the map should not have to distinguish "none" from "absent".
	if bySubject == nil {
		bySubject = map[string][]hopper.Sighting{}
	}
	writeTriageJSON(w, map[string]any{"by_subject": bySubject})
}
