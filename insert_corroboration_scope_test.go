package hopper

import (
	"context"
	"fmt"
	"os"
	"testing"
)

// autotel-vitest 0.4.71 arrived after three feeds had cited only 0.4.26.
// Inserts seeded corroboration by package name, bypassing the version-aware
// sighting trigger. Exercise real writes in both arrival orders and re-walks.
func TestInsertCorroborationUsesReleaseScope(t *testing.T) {
	ctx := context.Background()
	t.Run("sqlite", func(t *testing.T) { checkInsertCorroborationScope(t, ctx, openTestDBContext(t, ctx)) })
	t.Run("postgres", func(t *testing.T) {
		dsn := os.Getenv("HOPPER_SCOPE_TEST_DSN")
		if dsn == "" {
			t.Skip("set HOPPER_SCOPE_TEST_DSN to an isolated PostgreSQL test database")
		}
		db, err := Open(ctx, dsn, "scope-test")
		if err != nil {
			t.Fatal(err)
		}
		t.Cleanup(func() { db.Close() })
		if err := db.Migrate(ctx); err != nil {
			t.Fatal(err)
		}
		checkInsertCorroborationScope(t, ctx, db)
	})
}

func checkInsertCorroborationScope(t *testing.T, ctx context.Context, db *DB) {
	t.Helper()
	writers := []struct {
		name  string
		write func(*Sample) error
	}{
		{"single", func(s *Sample) error { return db.InsertSample(ctx, s) }},
		{"new", func(s *Sample) error { _, err := db.InsertSampleNew(ctx, s); return err }},
		{"batch", func(s *Sample) error { _, _, err := db.InsertSampleBatch(ctx, []*Sample{s}); return err }},
	}
	index := 0
	for _, writer := range writers {
		for _, first := range []bool{true, false} {
			t.Run(fmt.Sprintf("%s/sighting-first=%t", writer.name, first), func(t *testing.T) {
				index++
				runInsertCorroborationCase(t, ctx, db, writer.write, first, index)
			})
		}
	}
}

func runInsertCorroborationCase(t *testing.T, ctx context.Context, db *DB, write func(*Sample) error, sightingFirst bool, index int) {
	t.Helper()
	purl := fmt.Sprintf("pkg:npm/autotel-vitest-scope-%d", index)
	samples := make([]*Sample, 0, 2)
	for i, version := range []string{"0.4.26", "0.4.71"} {
		sha := fmt.Sprintf("%064x", 1000+index*2+i)
		samples = append(samples, &Sample{SHA256: sha, Source: "forager", Label: "unknown", LabelSource: "forager", Path: "incoming/" + sha + ".tgz", PURLBase: purl, Version: version, SizeBytes: 8})
	}
	cite := func() {
		if _, err := db.AddSightings(ctx, []Sighting{{Source: "osv", Subject: purl, Affected: "0.4.26", Claim: ClaimMalicious}}); err != nil {
			t.Fatal(err)
		}
	}
	if sightingFirst {
		cite()
	}
	for _, s := range samples {
		if err := write(s); err != nil {
			t.Fatal(err)
		}
	}
	if !sightingFirst {
		cite()
	}
	checkInsertCorroborationSamples(t, ctx, db, samples)
	// Batch re-observation must not reintroduce a false flag cleared by repair.
	if _, _, err := db.InsertSampleBatch(ctx, samples); err != nil {
		t.Fatal(err)
	}
	checkInsertCorroborationSamples(t, ctx, db, samples)
}

func checkInsertCorroborationSamples(t *testing.T, ctx context.Context, db *DB, samples []*Sample) {
	t.Helper()
	for i, s := range samples {
		got, err := db.SampleBySHA256(ctx, s.SHA256)
		if err != nil {
			t.Fatal(err)
		}
		if got == nil {
			t.Fatal("sample missing")
		}
		if got.Corroborated != (i == 0) {
			t.Errorf("version %s corroborated=%t; sighting names only 0.4.26", s.Version, got.Corroborated)
		}
	}
}
