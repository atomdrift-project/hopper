package hopper

import (
	"fmt"
	"testing"
	"time"
)

func TestReviewedLabelsSurviveObservationsAndReconciliation(t *testing.T) {
	for _, backend := range testBackends {
		t.Run(backend.name, func(t *testing.T) {
			db := backend.open(t)
			ctx := t.Context()
			for i, reviewed := range []string{labelInconclusive, labelDualUse, labelPurgatory} {
				sha := hexSHA(910 + i)
				mustInsert(t, ctx, db, &Sample{SHA256: sha, Path: reviewed + "/sample", Label: reviewed, LabelSource: "human-review"})
				if reviewed == labelPurgatory {
					execBoth(t, ctx, db, `UPDATE samples SET label = 'purgatory' WHERE sha256 = $1`, sha)
					db.forgetSHA(sha)
				}
				for _, incoming := range []string{"bad", "good", "sighted", "unknown", "dual-use", "inconclusive"} {
					for _, source := range []string{SourceFilesystem, labelSourceMarker} {
						observation := &Sample{SHA256: sha, Path: incoming + "/sample", Label: incoming, LabelSource: source}
						if _, _, err := db.InsertSampleBatch(ctx, []*Sample{observation}); err != nil {
							t.Fatal(err)
						}
						sample, err := db.SampleBySHA256(ctx, sha)
						if err != nil || sample.Label != reviewed || sample.LabelSource != "human-review" || sample.Skip != "" {
							t.Fatalf("%s observed as %s from %s: %+v, %v", reviewed, incoming, source, sample, err)
						}
					}
				}
				if err := db.StartWalkStaging(ctx); err != nil {
					t.Fatal(err)
				}
				if err := db.StageLocations(ctx, []SampleLocationKey{
					{SHA256: sha, Path: "bad/stale-copy"},
					{SHA256: sha, Path: "good/stale-copy"},
					{SHA256: sha, Path: "dual-use/sample"},
					{SHA256: sha, Path: "inconclusive/sample"},
				}); err != nil {
					t.Fatal(err)
				}
				if _, err := db.relabelFromPools(ctx, 100); err != nil {
					t.Fatal(err)
				}
				sample, err := db.SampleBySHA256(ctx, sha)
				if err != nil || sample.Label != reviewed || sample.LabelSource != "human-review" || sample.Skip != "" {
					t.Fatalf("reconcile overwrote %s: %+v, %v", reviewed, sample, err)
				}
			}
		})
	}
}

func TestReconcileRecognizesReviewedPools(t *testing.T) {
	for _, backend := range testBackends {
		t.Run(backend.name, func(t *testing.T) {
			db := backend.open(t)
			for i, pool := range []string{"inconclusive", "dual-use", "purgatory"} {
				sha := hexSHA(920 + i)
				mustInsert(t, t.Context(), db, &Sample{SHA256: sha, Path: "good/old", Label: "good", LabelSource: "test"})
				if err := db.StartWalkStaging(t.Context()); err != nil {
					t.Fatal(err)
				}
				if err := db.StageLocations(t.Context(), []SampleLocationKey{{SHA256: sha, Path: pool + "/new"}}); err != nil {
					t.Fatal(err)
				}
				if n, err := db.relabelFromPools(t.Context(), 100); err != nil || n != 1 {
					t.Fatalf("reconcile %s: %d, %v", pool, n, err)
				}
				sample, err := db.SampleBySHA256(t.Context(), sha)
				if err != nil || sample.Label != CanonicalLabel(pool) {
					t.Fatalf("pool %s: %+v, %v", pool, sample, err)
				}
			}
		})
	}
}

func TestReviewedLabelsExcludedFromRoutineQueues(t *testing.T) {
	for _, backend := range testBackends {
		t.Run(backend.name, func(t *testing.T) {
			db := backend.open(t)
			ctx := t.Context()
			denied := make(map[string]bool)
			controls := make(map[string]bool)
			for i, label := range []string{"unknown", "inconclusive", "dual-use", "purgatory"} {
				for j, crit := range []int{0, 5} {
					sha := hexSHA(930 + i*2 + j)
					purl := fmt.Sprintf("pkg:npm/reviewed-%d-%d", i, j)
					mustInsert(t, ctx, db, &Sample{SHA256: sha, Path: label + "/" + sha, Label: label, PURLBase: purl, Version: "1.0"})
					mustAnalyzeWithTraits(t, ctx, db, sha, 6, fmt.Sprintf(`{"l":%d,"c":1.0}`, crit))
					class, lvl := 2, 0
					if crit == 5 {
						class, lvl = 0, -1
					}
					setLitmus(t, ctx, db, sha, class, lvl, 0.5)
					execBoth(t, ctx, db, `UPDATE samples SET created_at = $1 WHERE sha256 = $2`, time.Now().Add(-4*24*time.Hour), sha)
					if label == "purgatory" {
						execBoth(t, ctx, db, `UPDATE samples SET label = 'purgatory' WHERE sha256 = $1`, sha)
					}
					if _, err := db.AddSightings(ctx, []Sighting{{Source: "test", Subject: purl, Affected: "1.0", Claim: ClaimMalicious}, {Source: "digest-test", Subject: sha, Claim: ClaimMalicious}}); err != nil {
						t.Fatal(err)
					}
					if label == "unknown" {
						controls[sha] = true
					} else {
						denied[sha] = true
					}
				}
			}
			for name, queue := range TriageQueues {
				rows, err := queue.Select(ctx, db, 100)
				if err != nil {
					t.Fatalf("queue %s: %v", name, err)
				}
				var controlFound bool
				for _, row := range rows {
					if denied[row.SHA256] {
						t.Errorf("queue %s selected reviewed sample %s", name, row.SHA256)
					}
					controlFound = controlFound || controls[row.SHA256]
				}
				if (name == "discord" || name == "sighted-pinned" || name == "fallout") && !controlFound {
					t.Errorf("queue %s lost its unreviewed control sample", name)
				}
			}
		})
	}
}
