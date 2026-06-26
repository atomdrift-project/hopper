package hopper

import (
	"context"
	"errors"
	"strings"
	"testing"
)

// TestProvenanceBySHA256 covers the three outcomes the provenance endpoint maps
// to 200 / 204 / 404: a sample with a sidecar, a sample without one, and an
// unknown sample.
func TestProvenanceBySHA256(t *testing.T) {
	ctx := context.Background()
	db := openTestDB(t)

	withProv := strings.Repeat("a", 64)
	noProv := strings.Repeat("b", 64)
	absent := strings.Repeat("c", 64)

	prov := []byte(`{"schema_version":"1.0","registry":{"record":{"ecosystem":"npm","name":"left-pad"}}}`)
	mustInsert(t, ctx, db, &Sample{SHA256: withProv, Provenance: prov})
	mustInsert(t, ctx, db, &Sample{SHA256: noProv})

	got, err := db.ProvenanceBySHA256(ctx, withProv)
	if err != nil {
		t.Fatalf("ProvenanceBySHA256(withProv): %v", err)
	}
	if len(got) == 0 {
		t.Fatal("expected provenance bytes for a sample that has a sidecar")
	}

	got, err = db.ProvenanceBySHA256(ctx, noProv)
	if err != nil {
		t.Fatalf("ProvenanceBySHA256(noProv): %v", err)
	}
	if got != nil {
		t.Fatalf("expected nil provenance for a sample with no sidecar, got %q", got)
	}

	if _, err := db.ProvenanceBySHA256(ctx, absent); !errors.Is(err, ErrNotFound) {
		t.Fatalf("expected ErrNotFound for an unknown sample, got %v", err)
	}
}

// TestShasWithProvenance covers the claim-time batch stamp: only samples that
// exist and carry a sidecar appear in the returned set.
func TestShasWithProvenance(t *testing.T) {
	ctx := context.Background()
	db := openTestDB(t)

	withProv := strings.Repeat("a", 64)
	noProv := strings.Repeat("b", 64)
	absent := strings.Repeat("c", 64)

	mustInsert(t, ctx, db, &Sample{SHA256: withProv, Provenance: []byte(`{"schema_version":"1.0"}`)})
	mustInsert(t, ctx, db, &Sample{SHA256: noProv})

	set, err := db.ShasWithProvenance(ctx, []string{withProv, noProv, absent})
	if err != nil {
		t.Fatalf("ShasWithProvenance: %v", err)
	}
	if !set[withProv] {
		t.Error("a sample with a sidecar should be in the set")
	}
	if set[noProv] {
		t.Error("a sample without a sidecar should not be in the set")
	}
	if set[absent] {
		t.Error("an unknown sample should not be in the set")
	}

	// An empty input is a no-op, not a query.
	if set, err := db.ShasWithProvenance(ctx, nil); err != nil || len(set) != 0 {
		t.Fatalf("ShasWithProvenance(nil) = (%v, %v), want (empty, nil)", set, err)
	}
}
