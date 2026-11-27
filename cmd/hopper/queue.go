package main

import (
	"context"
	"encoding/hex"
	"fmt"
	"log/slog"
	"time"

	"github.com/atomdrift-project/hopper"
	"github.com/atomdrift-project/hopper/store"
)

// queue.go hands out work from the verdict schema's queue (store)
// when apiServer.results is set. The ladder is claimLadder's, one tier per
// queue priority; what differs is that a hand-out is a lease on the queue row,
// so it holds across hopper restarts and is counted where the reaper used to
// look.

// ingest records samples the walker or an upload built in the verdict
// schema, and queues the ones nothing has scanned at priority p. Of a sample
// it keeps the digest, the path and what the producer claims; the rest of the
// row was the legacy schema's bookkeeping. The name is the sample's PURL: a
// package name guessed from a filename, with no PURL, is not an identity.
func ingest(ctx context.Context, st *store.Store, samples []*hopper.Sample, p store.Priority) (store.Ingested, error) {
	arrivals := make([]store.Arrival, len(samples))
	for i, s := range samples {
		sum, err := hex.DecodeString(s.SHA256)
		if err != nil {
			return store.Ingested{}, fmt.Errorf("ingest: sha256 %q: %w", s.SHA256, err)
		}
		arrivals[i] = store.Arrival{
			SHA256: sum, Size: s.SizeBytes, Path: s.Path, Source: s.Source, Feed: s.Feed, Mtime: s.Mtime,
			Label: hopper.CanonicalLabel(s.Label), LabelSource: s.LabelSource,
			Name: s.PURLBase, Version: s.Version, URL: s.URL, FetchedAt: s.FetchedAt, Provenance: s.Provenance,
		}
	}
	got, err := st.Ingest(ctx, arrivals, p)
	if err != nil {
		return store.Ingested{}, err
	}
	// A walk shows hopper files it already has, batch after batch.
	level := slog.LevelDebug
	if got != (store.Ingested{}) {
		level = slog.LevelInfo
	}
	slog.Log(ctx, level, "ingest", "arrivals", len(arrivals), "priority", int(p), "new", got.New,
		"updated", got.Updated, "located", got.Located, "displaced", got.Displaced,
		"queued", got.Queued, "refused", got.Refused)
	return got, nil
}

// requestRescan queues a rescan an operator asked for, in whichever schema
// holds the queue.
func (s *apiServer) requestRescan(ctx context.Context, sha string) error {
	if s.results == nil {
		return s.db.RequestRescan(ctx, sha, rescanRequestCooldown)
	}
	sum, err := hex.DecodeString(sha)
	if err != nil {
		return hopper.ErrRescanNotEligible
	}
	queued, err := s.results.Rescan(ctx, sum, time.Now().Add(-rescanRequestCooldown))
	if err == nil && !queued {
		return hopper.ErrRescanNotEligible
	}
	return err
}

// The rescan-by-age tier is the last in the ladder: files last scanned longer
// ago than --rescan-age, handed out when a worker has nothing newer to do.
// The queue holds only what is owed, so something has to keep finding the
// old files; refillStale does, a tick at a time.
const (
	staleTarget   = 10_000      // rescans by age kept queued; refilled below half
	sweepPage     = 5_000       // overdue scans read by one statement, oldest first
	sweepPages    = 200         // most statements in one tick, for a run of files no longer on disk
	sweepInterval = time.Minute // between ticks
)

// sweepRescans keeps the rescan tiers that are found by reading scans
// supplied until ctx is done: rescans by age, and files to describe
// (store.QueueDescribe). The places they have reached are not kept across a
// restart: a file rescanned since is not owed the rescan any more, so
// starting over costs reads and queues nothing twice.
func sweepRescans(ctx context.Context, st *store.Store, rescanAge time.Duration) {
	ticker := time.NewTicker(sweepInterval)
	defer ticker.Stop()
	var after, described store.Cursor
	for {
		next, queued, err := refillStale(ctx, st, after, time.Now().Add(-rescanAge))
		switch {
		case err != nil && ctx.Err() == nil:
			slog.WarnContext(ctx, "rescan-by-age sweep failed; trying again next tick", "after", after.At, "error", err)
		case queued > 0 || (next == store.Cursor{} && after != store.Cursor{}):
			slog.InfoContext(ctx, "rescan-by-age sweep", "queued", queued, "from", after.At, "to", next.At,
				"pass_complete", next == store.Cursor{}, "rescan_age", rescanAge)
		default:
		}
		after = next
		described = sweepDescribe(ctx, st, described)
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
		}
	}
}

// refillStale does one tick of the sweep: if fewer than half of staleTarget
// rescans by age are queued, it walks on from after, oldest scan first,
// queueing files last scanned before the cutoff, until the queue is back to
// staleTarget, the tick has read its share, or no overdue scan is left. It
// returns where the next tick continues, the zero Cursor to start over.
func refillStale(ctx context.Context, st *store.Store, after store.Cursor, before time.Time) (next store.Cursor, queued int64, err error) {
	depths, _, err := st.Depths(ctx)
	if err != nil {
		return after, 0, err
	}
	depth := depths[store.QueueStale]
	if depth >= staleTarget/2 {
		return after, 0, nil
	}
	for range sweepPages {
		var n int64
		if after, n, err = st.SweepStale(ctx, after, before, sweepPage); err != nil {
			return after, queued, err
		}
		queued += n
		if after == (store.Cursor{}) || depth+queued >= staleTarget {
			break
		}
	}
	return after, queued, nil
}

// sweepDescribe does one tick of the describe sweep: it drops the rows no
// longer owed a description and the LLM inputs older than a week
// (store.ExpireDescribe), then queues the files owed one from after, at most
// describePages statements (store.SweepDescribe), and returns where the next
// tick continues.
func sweepDescribe(ctx context.Context, st *store.Store, after store.Cursor) store.Cursor {
	dropped, inputs, err := st.ExpireDescribe(ctx)
	if err != nil && ctx.Err() == nil {
		slog.WarnContext(ctx, "describe expiry failed; trying again next tick", "error", err)
	}
	from := after
	var queued int64
	for range describePages {
		next, n, err := st.SweepDescribe(ctx, after, sweepPage)
		if err != nil {
			if ctx.Err() == nil {
				slog.WarnContext(ctx, "describe sweep failed; trying again next tick", "after", after.At, "error", err)
			}
			break
		}
		queued, after = queued+n, next
		if after == (store.Cursor{}) {
			break
		}
	}
	if queued > 0 || dropped > 0 || inputs > 0 {
		slog.InfoContext(ctx, "describe sweep", "queued", queued, "dropped", dropped, "llm_inputs_expired", inputs,
			"from", from.At, "to", after.At, "pass_complete", after == store.Cursor{})
	}
	return after
}

// describePages bounds the statements one tick of the describe sweep runs.
// A week of flagged scans was a few tens of thousands, a pass a tick or two;
// the describable scans (store/describe.go) add those the LLM gate admitted
// that the floor and the model call benign, so a pass may take a few more.
// The bound is for a burst.
const describePages = 20

// Shares of a batch, of what is left of it when the ladder reaches the tier
// (claimTier.restShare).
const (
	// compromisedShare caps the first scans of packages called malicious
	// before. A project taken over once may have thousands of releases on
	// disk, and every one of them is queued at this level; a quarter keeps
	// them moving without stopping every other first scan.
	compromisedShare = 0.25
	// describeShare caps the files to describe. Each is a whole scan again
	// for one line of text, so a tenth: enough for the week's flagged
	// scans that came back undescribed, far from enough to slow first scans.
	// A file whose LLM input hopper holds costs only the LLM call, and is
	// handed out first within the share (store.Candidates); the share is not
	// raised for them, since every describe still calls the LLM endpoint,
	// the scarcer resource, and a tenth already drains the level in a day
	// or two.
	describeShare = 0.1
	// newestShare is the part of the unanalyzed backlog's share served from
	// its newest end; the oldest end has the rest. The backlog drains over
	// weeks, so oldest first alone would have a package published today
	// wait behind all of it, and newest first alone would leave the oldest
	// files to wait forever.
	newestShare = 0.5
)

// queueLadder is claimLadder for the queue. maxBytes is the worker's per-file
// cap and skipTypes the file types its tools cannot run; both are applied in
// the query so files the worker can never take do not crowd out ones it can.
// A worker without an LLM (llm false) is handed no files to describe: it
// would scan them again and describe nothing.
//
// The unanalyzed backlog is served from both ends, newest first and then
// oldest first, each its own tier. The second reads the queue after the
// first has leased what it took, so no file is handed out twice; each
// interleaves its size classes.
func (s *apiServer) queueLadder(slots int, maxBytes int64, skipTypes []string, llm bool) []claimTier {
	type read func(context.Context, store.Priority, int, int64, []string) ([]store.Job, error)
	tier := func(name string, p store.Priority, from read) claimTier {
		return claimTier{name: name, candidates: func(ctx context.Context, n int) ([]hopper.ClaimJob, error) {
			jobs, err := from(ctx, p, n, maxBytes, skipTypes)
			out := make([]hopper.ClaimJob, len(jobs))
			for i, j := range jobs {
				out[i] = hopper.ClaimJob{
					CreatedAt: j.QueuedAt, SHA256: j.SHA256, Path: j.Path, FileType: j.FileType,
					SizeBytes: j.SizeBytes, HasProvenance: j.HasProvenance, HasLLMInput: j.HasLLMInput,
				}
			}
			return out, err
		}}
	}
	oldest, newest := s.results.Candidates, s.results.NewestCandidates
	sighted := tier(tierSighted, store.QueueSighted, oldest)
	sighted.maxShare = sightedMaxShare
	compromised := tier(tierCompromised, store.QueueCompromised, newest)
	compromised.restShare = compromisedShare
	describe := tier(tierMissingLLM, store.QueueDescribe, oldest)
	describe.restShare = describeShare
	big := tier(tierBigArchive, store.QueueBigArchive, oldest)
	big.minSlots = bigArchiveMinSlots
	freshest := tier(tierUnanalyzedNewest, store.QueueNew, newest)
	freshest.interleave, freshest.restShare = true, newestShare
	backlog := tier(tierUnanalyzed, store.QueueNew, oldest)
	backlog.interleave = true
	ladder := []claimTier{
		sighted,
		tier(tierUpload, store.QueueUpload, oldest),
		compromised,
		tier(tierForcedRescan, store.QueueRequested, oldest),
		describe,
		big,
		freshest,
		backlog,
		tier(tierRepair, store.QueueRepair, oldest),
		tier(tierRescanAge, store.QueueStale, oldest),
	}
	out := ladder[:0]
	for _, t := range ladder {
		if (t.minSlots == 0 || slots >= t.minSlots) && (llm || t.name != tierMissingLLM) {
			out = append(out, t)
		}
	}
	return out
}

// leaseClaimed takes the queue lease on jobs the tracker has just claimed
// for worker, and gives the tracker back the ones another hopper or a result
// got to first.
func (s *apiServer) leaseClaimed(ctx context.Context, jobs []hopper.ClaimJob, worker string) []hopper.ClaimJob {
	if len(jobs) == 0 {
		return jobs
	}
	shas, leases := make([]string, len(jobs)), make([]time.Duration, len(jobs))
	for i := range jobs {
		shas[i], leases[i] = jobs[i].SHA256, claimLease(claimExpiry, jobs[i].SizeBytes)
	}
	got, err := s.results.Lease(ctx, shas, leases)
	if err != nil {
		slog.Warn("queue lease failed; handing out nothing from this tier", "worker", worker, "jobs", len(jobs), "error", err)
		s.tracker.releaseMany(shas)
		return nil
	}
	leased := make(map[string]bool, len(got))
	for _, sha := range got {
		leased[sha] = true
	}
	var lost []string
	out := jobs[:0]
	for _, j := range jobs {
		if leased[j.SHA256] {
			out = append(out, j)
		} else {
			lost = append(lost, j.SHA256)
		}
	}
	s.tracker.releaseMany(lost)
	return out
}

// releaseClaims gives up claims on files that will not be worked on: the
// tracker's, and the queue lease too when there is one.
func (s *apiServer) releaseClaims(ctx context.Context, shas []string) {
	s.tracker.releaseMany(shas)
	if s.results == nil || len(shas) == 0 {
		return
	}
	if err := s.results.Release(ctx, shas); err != nil {
		slog.Warn("queue release failed; the leases will lapse instead", "jobs", len(shas), "error", err)
	}
}

// markUnavailable records that a claimed file could not be read at path.
// Without the queue that is a skip on the sample; with it, the location is
// forgotten, since the file itself may well be readable somewhere else.
func (s *apiServer) markUnavailable(ctx context.Context, sha, path, skip string) {
	var err error
	if s.results != nil {
		err = s.results.Unlocate(ctx, sha, path)
	} else {
		err = s.db.SetSkip(ctx, sha, skip)
	}
	if err != nil {
		slog.Error("mark unavailable sample failed", "sha256", sha, "path", path, "skip", skip, "error", err)
	}
}

// logQueueEmpty says why a worker was handed nothing: what is queued, at
// which priority, and how much of it is stuck. The queue holds only pending
// work, so counting it is cheap when it has nothing to hand out.
func (s *apiServer) logQueueEmpty(ctx context.Context, worker string) {
	depths, stuck, err := s.results.Depths(ctx)
	if err != nil {
		slog.Warn("no work available; queue depths unavailable", "worker", worker, "error", err)
		return
	}
	slog.Info("no work available", "worker", worker, "active_claims", s.tracker.activeClaims(worker),
		"sighted", depths[store.QueueSighted], "upload", depths[store.QueueUpload],
		"compromised", depths[store.QueueCompromised], "requested", depths[store.QueueRequested],
		"describe", depths[store.QueueDescribe], "big_archive", depths[store.QueueBigArchive],
		"new", depths[store.QueueNew], "repair", depths[store.QueueRepair], "stale", depths[store.QueueStale],
		"stuck", stuck)
}
