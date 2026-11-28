package hopper

import (
	"encoding/json"
	"errors"
	"fmt"
	"reflect"
	"slices"
	"sync"
	"testing"
	"time"
)

func historyRun(n int, label, status string) GauntletRun {
	r := GauntletRun{
		Producer: "test", ObservedAt: GauntletTime(time.Date(2026, 1, 1, 0, n, 0, 0, time.UTC)), Source: fmt.Sprint("test:", n), Complete: true,
		Rules: map[string]GauntletRules{"ascan": {Version: "1", Traits: "traits", Models: "models"}},
		Samples: []GauntletSample{{SHA256: fmt.Sprintf("%064x", 1), Label: label, Eligible: true, Metadata: json.RawMessage(`{"filename":"sample"}`), Results: []GauntletResult{
			{Scanner: "ascan", Status: status, Payload: json.RawMessage(fmt.Sprintf(`{"scanner":"ascan","status":%q,"detail":"evidence"}`, status))},
			{Scanner: "other", Status: "error", Payload: json.RawMessage(`{"scanner":"other","status":"error","detail":"timed out"}`)},
		}}},
	}
	r.ID = GauntletRunID(r.Producer, r.ObservedAt, r.Source)
	return r
}

func TestGauntletHistoryAndReview(t *testing.T) {
	for _, backend := range testBackends {
		t.Run(backend.name, func(t *testing.T) { gauntletHistoryAndReview(t, backend.open(t)) })
	}
}

// gauntletHistoryAndReview stores, selects and reviews gauntlet history on db.
func gauntletHistoryAndReview(t *testing.T, db *DB) {
	t.Helper()
	ctx := t.Context()
	r := historyRun(1, "good", "detected")
	// History is allowed before, and survives without, a live sample.
	fresh, err := db.StoreGauntletRun(ctx, r)
	if err != nil || !fresh {
		t.Fatalf("store: %v %v", fresh, err)
	}
	normalized, err := NormalizeGauntletRun(r)
	if err != nil {
		t.Fatal(err)
	}
	got, err := db.GauntletRun(ctx, r.ID)
	if err != nil || !reflect.DeepEqual(*got, normalized) {
		t.Fatalf("round trip: %+v %v", got, err)
	}
	fresh, err = db.StoreGauntletRun(ctx, r)
	if err != nil || fresh {
		t.Fatalf("replay: %v %v", fresh, err)
	}
	conflict := historyRun(1, "good", "benign")
	if _, err := db.StoreGauntletRun(ctx, conflict); !errors.Is(err, ErrGauntletConflict) {
		t.Fatalf("conflict: %v", err)
	}
	mustInsert(t, ctx, db, &Sample{SHA256: r.Samples[0].SHA256, Label: "good", Path: "good/sample"})
	selectN := func(want int) *Sample {
		t.Helper()
		rows, err := db.TriageGauntlet(ctx, 10, GauntletSpan{}, nil)
		if err != nil || len(rows) != want {
			t.Fatalf("select want %d: %d %v", want, len(rows), err)
		}
		if want > 0 {
			return rows[0]
		}
		return nil
	}
	counts, _, err := db.GauntletDepth(ctx, GauntletSpan{})
	if err != nil || counts["false_positive"] != 1 || counts["miss"] != 0 {
		t.Fatalf("depth: %v %v", counts, err)
	}
	first := selectN(1)
	if first.Gauntlet == nil || first.Gauntlet.Expected != "good" {
		t.Fatal("missing selection evidence")
	}
	if rows, err := db.TriageGauntlet(ctx, 10, GauntletSpan{}, []string{first.SHA256}); err != nil || len(rows) != 0 {
		t.Fatalf("exclusion: %v %v", rows, err)
	}
	review := &Report{SHA256: first.SHA256, Type: "gauntlet", EvidenceKey: first.Gauntlet.Key, Content: "confirmed", Provider: "test"}
	if err := db.CompleteGauntlet(ctx, review); err != nil {
		t.Fatal(err)
	}
	if err := db.CompleteGauntlet(ctx, review); err != nil {
		t.Fatal(err)
	}
	selectN(0)
	// An unchanged failure in another run stays reviewed.
	if _, err := db.StoreGauntletRun(ctx, historyRun(2, "good", "detected")); err != nil {
		t.Fatal(err)
	}
	selectN(0)
	newer := historyRun(3, "good", "detected")
	newer.Rules["ascan"] = GauntletRules{Version: "1", Traits: "new", Models: "models"}
	if _, err := db.StoreGauntletRun(ctx, newer); err != nil {
		t.Fatal(err)
	}
	selectN(1)
	// Re-acknowledging old evidence cannot clear the new failure.
	if err := db.CompleteGauntlet(ctx, review); err != nil {
		t.Fatal(err)
	}
	selectN(1)
	if _, err := db.StoreGauntletRun(ctx, historyRun(4, "good", "error")); err != nil {
		t.Fatal(err)
	}
	selectN(1)
	if _, err := db.StoreGauntletRun(ctx, historyRun(5, "good", "benign")); err != nil {
		t.Fatal(err)
	}
	selectN(0)
	// Importing an older failure after newer successful data cannot resurrect it.
	if _, err := db.StoreGauntletRun(ctx, historyRun(0, "good", "detected")); err != nil {
		t.Fatal(err)
	}
	selectN(0)
}

func TestGauntletWithdrawalAndUnknownTime(t *testing.T) {
	for _, backend := range testBackends {
		t.Run(backend.name, func(t *testing.T) {
			db := backend.open(t)
			ctx := t.Context()
			r := historyRun(1, "good", "detected")
			mustInsert(t, ctx, db, &Sample{SHA256: r.Samples[0].SHA256, Label: "good", Path: "good/sample"})

			withdrawal := historyRun(2, "withdrawn", "detected")
			withdrawal.Samples = nil
			withdrawal.Withdrawn = []string{r.Samples[0].SHA256}
			if _, err := db.StoreGauntletRun(ctx, withdrawal); err != nil {
				t.Fatal(err)
			}
			if _, err := db.StoreGauntletRun(ctx, r); err != nil {
				t.Fatal(err)
			}
			rows, err := db.TriageGauntlet(ctx, 10, GauntletSpan{}, nil)
			if err != nil || len(rows) != 0 {
				t.Fatalf("withdrawn: %v %v", rows, err)
			}
			// A later malicious-cohort miss is new work, even if this SHA once left
			// the benign cohort. Withdrawal only retracts the benign expectation.
			bad := historyRun(4, "bad", "benign")
			if _, err := db.StoreGauntletRun(ctx, bad); err != nil {
				t.Fatal(err)
			}
			rows, err = db.TriageGauntlet(ctx, 10, GauntletSpan{}, nil)
			if err != nil || len(rows) != 1 {
				t.Fatalf("new hostile miss was suppressed: %v %v", rows, err)
			}
			if err := db.CompleteGauntlet(ctx, &Report{SHA256: rows[0].SHA256, EvidenceKey: rows[0].Gauntlet.Key}); err != nil {
				t.Fatal(err)
			}

			original, err := db.GauntletRun(ctx, r.ID)
			if err != nil || original.Samples[0].Label != "good" {
				t.Fatalf("original label was rewritten: %v %v", original, err)
			}
			undated := historyRun(3, "bad", "benign")
			undated.ID = ""
			undated.ObservedAt = ""
			if _, err := db.StoreGauntletRun(ctx, undated); err != nil {
				t.Fatal(err)
			}
			rows, err = db.TriageGauntlet(ctx, 10, GauntletSpan{}, nil)
			if err != nil || len(rows) != 0 {
				t.Fatalf("undated: %v %v", rows, err)
			}
		})
	}
}

func TestGauntletRejectsWholeInvalidBatch(t *testing.T) {
	db := openTestDB(t)
	ctx := t.Context()
	r := historyRun(1, "bad", "benign")
	invalid := r.Samples[0]
	invalid.SHA256 = fmt.Sprintf("%064x", 2)
	invalid.Results = append([]GauntletResult(nil), invalid.Results...)
	invalid.Results[0].Status = "unknown"
	r.Samples = append(r.Samples, invalid)
	if _, err := db.StoreGauntletRun(ctx, r); err == nil {
		t.Fatal("accepted unknown status")
	}
	if _, err := db.GauntletRun(ctx, r.ID); err == nil {
		t.Fatal("stored part of invalid batch")
	}
	empty := historyRun(2, "good", "benign")
	empty.Samples = nil
	if fresh, err := db.StoreGauntletRun(ctx, empty); err != nil || !fresh {
		t.Fatalf("empty: %v %v", fresh, err)
	}
	if fresh, err := db.StoreGauntletRun(ctx, empty); err != nil || fresh {
		t.Fatalf("empty replay: %v %v", fresh, err)
	}
}

func TestGauntletHistoryTransferPreservesReviewCoverage(t *testing.T) {
	src, dst := openTestDB(t), openTestDB(t)
	ctx := t.Context()
	r := historyRun(1, "good", "detected")
	mustInsert(t, ctx, src, &Sample{SHA256: r.Samples[0].SHA256, Label: "good", Path: "good/sample"})
	if _, err := src.StoreGauntletRun(ctx, r); err != nil {
		t.Fatal(err)
	}
	rows, err := src.TriageGauntlet(ctx, 1, GauntletSpan{}, nil)
	if err != nil || len(rows) != 1 {
		t.Fatalf("select: %v", err)
	}
	if err := src.CompleteGauntlet(ctx, &Report{SHA256: rows[0].SHA256, EvidenceKey: rows[0].Gauntlet.Key}); err != nil {
		t.Fatal(err)
	}
	if _, _, err := TransferSamples(ctx, dst, src, 0, 0); err != nil {
		t.Fatal(err)
	}
	got, err := dst.GauntletRun(ctx, r.ID)
	if err != nil || len(got.Samples[0].Results) != 2 {
		t.Fatalf("history transfer: %v", err)
	}
	rows, err = dst.TriageGauntlet(ctx, 1, GauntletSpan{}, nil)
	if err != nil || len(rows) != 0 {
		t.Fatalf("review coverage was lost: %v", err)
	}
}

func TestGauntletConcurrentReplay(t *testing.T) {
	for _, backend := range testBackends {
		t.Run(backend.name, func(t *testing.T) {
			db := backend.open(t)
			ctx := t.Context()
			run := historyRun(1, "bad", "benign")
			type result struct {
				fresh bool
				err   error
			}
			results := make(chan result, 8)
			var wg sync.WaitGroup
			for range 8 {
				wg.Go(func() { fresh, err := db.StoreGauntletRun(ctx, run); results <- result{fresh, err} })
			}
			wg.Wait()
			close(results)
			inserted := 0
			for r := range results {
				if r.err != nil {
					t.Fatal(r.err)
				}
				if r.fresh {
					inserted++
				}
			}
			if inserted != 1 {
				t.Fatalf("concurrent submissions inserted %d runs", inserted)
			}
		})
	}
}

// gauntlet-72h and gauntlet split on the newest usable observation's time, so
// a file a recent run saw misjudged is in the head only, even when an older
// run saw the same miss, and each queue's depth counts only its own files.
func TestGauntletQueuesSplitOnObservation(t *testing.T) {
	for _, backend := range testBackends {
		t.Run(backend.name, func(t *testing.T) {
			db := backend.open(t)
			ctx := t.Context()
			now := time.Now()
			run := func(n int, sha string, at time.Time) {
				t.Helper()
				r := historyRun(n, "good", "detected")
				r.ObservedAt, r.Samples[0].SHA256 = GauntletTime(at), sha
				r.ID = GauntletRunID(r.Producer, r.ObservedAt, r.Source)
				if _, err := db.StoreGauntletRun(ctx, r); err != nil {
					t.Fatal(err)
				}
			}
			old, renewed, fresh := fmt.Sprintf("%064x", 0xa), fmt.Sprintf("%064x", 0xb), fmt.Sprintf("%064x", 0xc)
			run(1, old, now.Add(-10*24*time.Hour))
			run(2, renewed, now.Add(-11*24*time.Hour))
			run(3, renewed, now.Add(-time.Hour))
			run(4, fresh, now.Add(-2*time.Hour))
			for _, sha := range []string{old, renewed, fresh} {
				mustInsert(t, ctx, db, &Sample{SHA256: sha, Label: "good", Path: "good/" + sha[60:]})
			}
			for queue, want := range map[string][]string{"gauntlet-72h": {renewed, fresh}, "gauntlet": {old}} {
				rows, err := TriageQueues[queue].Select(ctx, db, 10)
				if err != nil {
					t.Fatalf("%s: %v", queue, err)
				}
				got := make([]string, len(rows))
				for i, s := range rows {
					got[i] = s.SHA256
				}
				if !slices.Equal(got, want) {
					t.Errorf("%s selected %v, want %v (newest observation first)", queue, got, want)
				}
				counts, _, err := db.GauntletDepth(ctx, GauntletBounds(queue, now))
				if err != nil || counts["false_positive"] != int64(len(want)) {
					t.Errorf("%s depth %v, %v; want %d", queue, counts, err, len(want))
				}
			}
		})
	}
}
