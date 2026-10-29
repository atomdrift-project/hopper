package main

import (
	"os"
	"path/filepath"
	"testing"
)

func TestCmdMigratePurgatoryDefaultsToPreview(t *testing.T) {
	ctx := t.Context()
	root := t.TempDir()
	dsn := filepath.Join(t.TempDir(), "migration.db")
	db := mustOpenDB(t, ctx, dsn)
	if err := db.Migrate(ctx); err != nil {
		db.Close()
		t.Fatal(err)
	}
	oldRel, newRel := "purgatory/npm/pkg.tgz", "inconclusive/npm/pkg.tgz"
	sha := writeMvSample(t, db, ctx, root, oldRel, "inconclusive", "legacy bytes already read by new loader")
	db.Close()
	args := []string{"hopper", "migrate-purgatory", "--db", dsn, "--data", root}
	withArgs(args, func() {
		if err := run(ctx); err != nil {
			t.Fatal(err)
		}
	})
	if _, err := os.Stat(filepath.Join(root, oldRel)); err != nil {
		t.Fatalf("default preview removed source: %v", err)
	}
	if _, err := os.Stat(filepath.Join(root, newRel)); !os.IsNotExist(err) {
		t.Fatalf("default preview created destination: %v", err)
	}
	withArgs(append(args, "--apply"), func() {
		if err := run(ctx); err != nil {
			t.Fatal(err)
		}
	})
	db = mustOpenDB(t, ctx, dsn)
	defer db.Close()
	sample, err := db.SampleBySHA256(ctx, sha)
	if err != nil || sample.Path != newRel || sample.Label != "inconclusive" {
		t.Fatalf("applied migration = %+v, %v", sample, err)
	}
	if _, err := os.Stat(filepath.Join(root, oldRel)); !os.IsNotExist(err) {
		t.Fatalf("applied migration left source: %v", err)
	}
}
