package main

import (
	"encoding/json"
	"log/slog"
	"net/http"
	"slices"
	"strings"
	"time"
)

// workerRow is one worker in the /workers.json answer.
type workerRow struct {
	LastSeen time.Time `json:"last_seen"`
	Name     string    `json:"name"`
	Version  string    `json:"version"`
}

// workersJSON lists the workers hopper has heard from within the retention
// window, from the in-memory tracker the dashboard's Workers table reads, so
// the two cannot disagree about who is in the fleet.
//
// It is not read from the database: the workers table is only written when the
// verdict store is off, and a roster built from it silently stops at the day
// that changed. The listener has no token, like the page beside it, and the
// answer holds nothing the page does not already show.
func (wd *webDashboard) workersJSON(w http.ResponseWriter, _ *http.Request) {
	wd.cfgMu.RLock()
	tracker := wd.tracker
	wd.cfgMu.RUnlock()
	if tracker == nil {
		// Still loading: the tracker is attached once the session state is
		// ready, and an empty list would read as "the fleet is gone".
		w.Header().Set("Retry-After", "5")
		http.Error(w, "starting", http.StatusServiceUnavailable)
		return
	}
	all := tracker.all()
	rows := make([]workerRow, 0, len(all))
	for i := range all {
		rows = append(rows, workerRow{Name: all[i].Name, Version: all[i].Version, LastSeen: all[i].LastSeen.UTC()})
	}
	slices.SortFunc(rows, func(a, b workerRow) int { return strings.Compare(a.Name, b.Name) })
	w.Header().Set("Content-Type", "application/json")
	if err := json.NewEncoder(w).Encode(rows); err != nil {
		slog.Debug("workers.json: write failed", "error", err)
	}
}
