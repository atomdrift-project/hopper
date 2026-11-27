package main

import (
	"context"
	"encoding/hex"
	"time"

	"github.com/atomdrift-project/hopper"
	"github.com/atomdrift-project/hopper/store"
)

// dashstore.go answers the dashboard's and the queue graphs' questions of the
// corpus from the verdict store when one is open, in the shapes the legacy
// tables answered them in, so the page and graphs render either way.

// queueDepths returns the files waiting for a first scan and the rescans
// queued by tier: requested (prism's button, an operator), repair, and by
// age.
func queueDepths(ctx context.Context, db *hopper.DB, st *store.Store, rescanAge time.Duration) (int64, hopper.RescanDepths, error) {
	if st == nil {
		pending, err := db.CountPending(ctx)
		if err != nil {
			return 0, hopper.RescanDepths{}, err
		}
		d, err := db.RescanDepths(ctx, rescanAge)
		return pending, d, err
	}
	depths, _, err := st.Depths(ctx)
	if err != nil {
		return 0, hopper.RescanDepths{}, err
	}
	return firstScansOf(depths), rescanDepthsOf(depths), nil
}

// rescanDepthsOf is the queue's rescans by tier.
func rescanDepthsOf(depths map[store.Priority]int64) hopper.RescanDepths {
	return hopper.RescanDepths{
		Forced: depths[store.QueueRequested], MissingLLM: depths[store.QueueDescribe],
		Repair: depths[store.QueueRepair], Age: depths[store.QueueStale],
	}
}

// storeHealth reads the store's health and the queue's flows, cached for
// dashCacheTTL and shared by the dashboard and the metrics scrape. The flows
// are measured in the same breath as the store counts the files queued since
// they start, so that both halves of an arrival rate cover one span.
func (wd *webDashboard) storeHealth(ctx context.Context, st *store.Store) (*corpusReading, error) {
	return wd.storeHealthCache.Fetch("health", func() (*corpusReading, error) {
		now := time.Now()
		since := completedScans.since(now)
		h, err := st.Health(ctx, since, now.Add(-retiredOutcomeGrace))
		if err != nil {
			return nil, err
		}
		return &corpusReading{Health: h, flows: completedScans.flows(h.Queued, since, time.Now())}, nil
	})
}

// storeWork reads the dashboard's lists from the store, cached for
// dashCacheTTL.
func (wd *webDashboard) storeWork(ctx context.Context, st *store.Store) (*store.Work, error) {
	return wd.storeWorkCache.Fetch("work", func() (*store.Work, error) {
		return st.Work(ctx, 5)
	})
}

// firstScansOf sums the queue's first scans: every priority that is not a
// rescan.
func firstScansOf(depths map[store.Priority]int64) int64 {
	var n int64
	for p, d := range depths {
		if !p.IsRescan() {
			n += d
		}
	}
	return n
}

// arrivalWatermark is the highest sample id issued, the arrivals half of the
// flow graph.
func arrivalWatermark(ctx context.Context, db *hopper.DB, st *store.Store) (int64, error) {
	if st == nil {
		return db.ArrivalWatermark(ctx)
	}
	return st.Watermark(ctx)
}

// countAnalyzed counts the files analyzed so far.
func countAnalyzed(ctx context.Context, db *hopper.DB, st *store.Store) (int64, error) {
	if st == nil {
		return db.CountAnalyzed(ctx)
	}
	return st.Scanned(ctx)
}

// storeWorkflow is the dashboard's workflow cards from the store: its health
// from h, its lists from w.
func storeWorkflow(h *store.Health, w *store.Work) dashboardWorkflow {
	out := dashboardWorkflow{hasHealth: h != nil}
	if h != nil {
		out.health = hopper.WorkflowHealth{
			LatestAdded: h.LatestArrived, LatestAnalyzed: h.LatestScanned, LatestReady: h.LatestScanned,
			PendingCleave: firstScansOf(h.Depths),
		}
	}
	if w == nil {
		return out
	}
	for _, b := range w.Backlogs {
		out.backlogs = append(out.backlogs, hopper.WorkflowBacklog{
			OldestPending: b.Oldest, NewestPending: b.Newest, Source: b.Source, Feed: b.Feed, PendingCleave: b.Queued,
		})
	}
	for _, l := range []struct {
		dst *[]hopper.WorkflowSample
		src []store.WorkFile
	}{{&out.latestAdded, w.Arrived}, {&out.latestReady, w.Scanned}, {&out.oldestPending, w.Waiting}} {
		for i := range l.src {
			f := &l.src[i]
			*l.dst = append(*l.dst, hopper.WorkflowSample{
				CreatedAt: f.Arrived, UpdatedAt: f.Arrived, AnalyzedAt: f.Scanned, FirstAnalyzedAt: f.Scanned,
				SHA256: hex.EncodeToString(f.SHA256), Source: f.Source, Feed: f.Feed,
				Ecosystem: store.EcosystemOf("", f.Type), Filename: f.Filename, Path: f.Path,
				HasCleave: f.Scanned != nil, HasLitmus: f.Scanned != nil, Criticality: classCriticality(f.Class),
			})
		}
	}
	return out
}

// classCriticality places atomscan's class on the legacy 0–5 criticality
// scale the dashboard colours by.
func classCriticality(class string) int {
	switch class {
	case "hostile":
		return 4
	case "suspicious":
		return 3
	default:
		return 0
	}
}
