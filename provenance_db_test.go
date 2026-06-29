package hopper

import (
	"context"
	"errors"
	"strings"
	"testing"
)

// TestSetProvenance covers the provenance-only upload path: a sample with bytes
// gets (or refreshes) its sidecar and projected purl_base, an already-provenanced
// sample is overwritten (the merge that preserves the discovery wrapper happens
// in the handler, above this unconditional write), and an absent sample is a
// no-op rather than an error.
func TestSetProvenance(t *testing.T) {
	ctx := context.Background()
	db := openTestDB(t)

	noProv := strings.Repeat("d", 64)
	hasProv := strings.Repeat("e", 64)
	absent := strings.Repeat("f", 64)

	mustInsert(t, ctx, db, &Sample{SHA256: noProv}) // bytes present, no provenance
	mustInsert(t, ctx, db, &Sample{SHA256: hasProv, Provenance: []byte(`{"schema_version":"1.0"}`)})

	prov := []byte(`{"schema_version":"1.0","package":{"purl":"pkg:npm/is-number@7.0.0"}}`)
	sidecar := &Sample{
		SHA256: noProv, Provenance: prov,
		Ecosystem: "npm", Package: "is-number", Version: "7.0.0", PURLBase: "pkg:npm/is-number",
	}

	// Unprovenanced sample → write applies, provenance + purl_base land.
	applied, err := db.SetProvenance(ctx, sidecar)
	if err != nil {
		t.Fatalf("SetProvenance: %v", err)
	}
	if !applied {
		t.Fatal("expected the write to apply to an unprovenanced sample")
	}
	got, err := db.ProvenanceBySHA256(ctx, noProv)
	if err != nil || len(got) == 0 {
		t.Fatalf("provenance not stored: err=%v len=%d", err, len(got))
	}
	s2, err := db.SampleBySHA256(ctx, noProv)
	if err != nil {
		t.Fatalf("SampleBySHA256: %v", err)
	}
	if s2.PURLBase != "pkg:npm/is-number" {
		t.Errorf("purl_base = %q, want pkg:npm/is-number", s2.PURLBase)
	}

	// A sample that already has provenance is overwritten with the new sidecar.
	refreshed := []byte(`{"schema_version":"1.0","registry":{"record":{"ecosystem":"npm","name":"left-pad"}}}`)
	if applied, err := db.SetProvenance(ctx, &Sample{SHA256: hasProv, Provenance: refreshed}); err != nil || !applied {
		t.Errorf("set over existing provenance = (%v, %v), want (true, nil)", applied, err)
	}
	if got, err := db.ProvenanceBySHA256(ctx, hasProv); err != nil || !strings.Contains(string(got), "left-pad") {
		t.Errorf("provenance not overwritten: err=%v got=%q", err, got)
	}

	// An absent sample is a no-op, not an error.
	if applied, err := db.SetProvenance(ctx, &Sample{SHA256: absent, Provenance: prov}); err != nil || applied {
		t.Errorf("set on absent sample = (%v, %v), want (false, nil)", applied, err)
	}
}

// TestSidecarMergeRefresh covers the merge policy the provenance-only handler
// applies before the unconditional write: the registry snapshot refreshes from
// the incoming sidecar while the original discovery wrapper (Feed) is preserved,
// and a discovery channel the prior sidecar lacked is adopted from the newer one.
func TestSidecarMergeRefresh(t *testing.T) {
	feed := &MetadataRecord{SourceID: "npm-firehose", Format: "npm.event", Status: MetadataComplete}
	oldReg := &MetadataRecord{SourceID: "npm-old", Format: "npm.packument", Status: MetadataComplete}
	newReg := &MetadataRecord{SourceID: "npm-new", Format: "npm.packument", Status: MetadataComplete}

	// Prior sidecar discovered via a feed; a re-fetch refreshes only the registry.
	prior := Sidecar{Feed: feed, Registry: oldReg, Package: PackageRef{Feed: "npm"}}
	prior.MergeRefresh(&Sidecar{Registry: newReg}) // incoming carries no Feed
	if prior.Feed != feed {
		t.Error("discovery wrapper (Feed) must be preserved across a registry refresh")
	}
	if prior.Package.Feed != "npm" {
		t.Errorf("package.feed = %q, want preserved npm", prior.Package.Feed)
	}
	if prior.Registry != newReg {
		t.Error("registry snapshot must be refreshed from the newer sidecar")
	}

	// A prior sidecar without a feed adopts one observed later.
	noFeed := Sidecar{Registry: oldReg}
	noFeed.MergeRefresh(&Sidecar{Feed: feed, Package: PackageRef{Feed: "aikido"}})
	if noFeed.Feed != feed || noFeed.Package.Feed != "aikido" {
		t.Error("a feed observed later should be adopted when none existed")
	}
	if noFeed.Registry != oldReg {
		t.Error("a newer sidecar without a registry must not erase the existing one")
	}
}

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
