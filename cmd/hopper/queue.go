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

// sweepStale keeps the rescan-by-age tier supplied until ctx is done. The
// place it has reached is not kept across a restart: a file rescanned since
// is not old any more, so starting over costs reads and queues nothing twice.
func sweepStale(ctx context.Context, st *store.Store, rescanAge time.Duration) {
	ticker := time.NewTicker(sweepInterval)
	defer ticker.Stop()
	var after store.Cursor
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

// queueLadder is claimLadder for the queue. maxBytes is the worker's per-file
// cap, applied in the query so files over it never crowd out ones under it.
func (s *apiServer) queueLadder(slots int, maxBytes int64) []claimTier {
	tier := func(name string, p store.Priority) claimTier {
		return claimTier{name: name, candidates: func(ctx context.Context, n int) ([]hopper.ClaimJob, error) {
			jobs, err := s.results.Candidates(ctx, p, n, maxBytes)
			out := make([]hopper.ClaimJob, len(jobs))
			for i, j := range jobs {
				out[i] = hopper.ClaimJob{
					CreatedAt: j.QueuedAt, SHA256: j.SHA256, Path: j.Path, FileType: j.FileType,
					SizeBytes: j.SizeBytes, HasProvenance: j.HasProvenance,
				}
			}
			return out, err
		}}
	}
	sighted := tier(tierSighted, store.QueueSighted)
	sighted.maxShare = sightedMaxShare
	big := tier(tierBigArchive, store.QueueBigArchive)
	big.minSlots = bigArchiveMinSlots
	fresh := tier(tierUnanalyzed, store.QueueNew)
	fresh.interleave = true
	ladder := []claimTier{
		sighted,
		tier(tierUpload, store.QueueUpload),
		tier(tierForcedRescan, store.QueueRequested),
		big,
		fresh,
		tier(tierRepair, store.QueueRepair),
		tier(tierRescanAge, store.QueueStale),
	}
	out := ladder[:0]
	for _, t := range ladder {
		if t.minSlots == 0 || slots >= t.minSlots {
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
		"requested", depths[store.QueueRequested], "big_archive", depths[store.QueueBigArchive],
		"new", depths[store.QueueNew], "repair", depths[store.QueueRepair], "stale", depths[store.QueueStale],
		"stuck", stuck)
}
