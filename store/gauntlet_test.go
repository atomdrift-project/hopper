package store

import (
	"errors"
	"testing"
)

func TestAddGauntletRun(t *testing.T) {
	st := open(t)
	ctx := t.Context()
	world(ctx, t, st, base("miss", "bad"), base("withdrawn", "good"))
	miss, withdrawn := hexOf(digestOf("miss")), hexOf(digestOf("withdrawn"))
	run := GauntletRun{
		ID: "run1", Producer: "gauntlet", ObservedAt: "2026-11-20T00:00:00.000000000Z", Source: "live", Digest: "d1", Metadata: `{}`,
		Samples: []GauntletSample{
			{SHA256: miss, Label: "bad", Eligible: true, Metadata: `{}`, Results: []GauntletResult{
				{Scanner: "ascan", Status: "benign", EvidenceKey: "k-miss", Payload: `{"scanner":"ascan","status":"benign"}`},
				{Scanner: "other", Status: "error", EvidenceKey: "k-other", Payload: `{"scanner":"other","status":"error"}`},
			}},
			{SHA256: withdrawn, Label: "good", Eligible: true, Metadata: `{}`, Results: []GauntletResult{
				{Scanner: "ascan", Status: "detected", EvidenceKey: "k-withdrawn", Payload: `{"scanner":"ascan","status":"detected"}`},
			}},
		},
		Withdrawn: []string{withdrawn},
	}
	if fresh, err := st.AddGauntletRun(ctx, run); err != nil || !fresh {
		t.Fatalf("add: fresh=%v, %v", fresh, err)
	}
	if fresh, err := st.AddGauntletRun(ctx, run); err != nil || fresh {
		t.Fatalf("replay: fresh=%v, %v; want a no-op", fresh, err)
	}
	changed := run
	changed.Digest = "d2"
	if _, err := st.AddGauntletRun(ctx, changed); !errors.Is(err, ErrGauntletConflict) {
		t.Fatalf("conflicting replay: %v, want ErrGauntletConflict", err)
	}

	// The queue sees the miss and answers its key; the withdrawn good file is out.
	got, err := st.Triage(ctx, "gauntlet", 10, nil)
	if err != nil || len(got) != 1 || got[0].Gauntlet == nil || got[0].Gauntlet.Key != "k-miss" {
		t.Fatalf("triage: %+v, %v; want the miss with key k-miss", got, err)
	}
	if err := st.FileReport(ctx, TriageReport{SHA256: digestOf("miss"), Type: "gauntlet", EvidenceKey: "k-miss"}); err != nil {
		t.Fatal(err)
	}
	if got, err := st.Triage(ctx, "gauntlet", 10, nil); err != nil || len(got) != 0 {
		t.Fatalf("after review: %+v, %v; want none", got, err)
	}

	empty := GauntletRun{ID: "run2", Producer: "gauntlet", Source: "s", Digest: "d", Metadata: `{}`}
	for range 2 {
		if _, err := st.AddGauntletRun(ctx, empty); err != nil {
			t.Fatalf("run with no samples: %v", err)
		}
	}
}
