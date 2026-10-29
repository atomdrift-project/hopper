package hopper

import (
	"os"
	"path/filepath"
	"testing"
)

func writePurgatoryFixture(t *testing.T, db *DB, root, rel, content string) string {
	t.Helper()
	abs := filepath.Join(root, filepath.FromSlash(rel))
	if err := os.MkdirAll(filepath.Dir(abs), 0o750); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(abs, []byte(content), 0o640); err != nil {
		t.Fatal(err)
	}
	sha := moveTestSHA([]byte(content))
	mustInsert(t, t.Context(), db, &Sample{SHA256: sha, Path: rel, Label: labelInconclusive, LabelSource: "human-review"})
	// Bypass canonicalization to represent a database written by the old binary.
	execBoth(t, t.Context(), db, `UPDATE samples SET label = 'purgatory' WHERE sha256 = $1`, sha)
	db.forgetSHA(sha)
	return sha
}

func TestMigratePurgatory(t *testing.T) {
	for _, backend := range testBackends {
		t.Run(backend.name, func(t *testing.T) {
			db := backend.open(t)
			ctx := t.Context()
			root := t.TempDir()
			oldRel := "purgatory/datasets/npm/pkg.tgz"
			newRel := "inconclusive/datasets/npm/pkg.tgz"
			sha := writePurgatoryFixture(t, db, root, oldRel, "legacy archive bytes")
			if err := os.WriteFile(filepath.Join(root, oldRel)+ProvenanceSidecarSuffix, []byte(`{"review":"careful"}`), 0o640); err != nil {
				t.Fatal(err)
			}
			// A second observation must move too, not just samples.path.
			duplicate := "purgatory/other/pkg.tgz"
			if err := os.MkdirAll(filepath.Dir(filepath.Join(root, duplicate)), 0o750); err != nil {
				t.Fatal(err)
			}
			if err := os.Link(filepath.Join(root, oldRel), filepath.Join(root, duplicate)); err != nil {
				t.Fatal(err)
			}
			if err := db.UpsertLocation(ctx, &SampleLocation{SHA256: sha, Path: duplicate}); err != nil {
				t.Fatal(err)
			}
			member := hexSHA(811)
			memberPath := oldRel + "!!lib/member.js"
			mustInsert(t, ctx, db, &Sample{SHA256: member, Path: memberPath, Parent: sha, Label: labelInconclusive, LabelSource: "human-review", Skip: "unsupported"})
			execBoth(t, ctx, db, `UPDATE samples SET label = 'purgatory' WHERE sha256 = $1`, member)
			// An independently classified member keeps its label while its
			// observation and canonical path follow the containing archive.
			knownMember := hexSHA(812)
			mustInsert(t, ctx, db, &Sample{SHA256: knownMember, Path: oldRel + "!!known.exe", Parent: sha, Label: "bad", LabelSource: "independent"})
			outside := hexSHA(814)
			mustInsert(t, ctx, db, &Sample{SHA256: outside, Path: "incoming/elsewhere.bin", Label: "inconclusive", LabelSource: "human-review"})
			execBoth(t, ctx, db, `UPDATE samples SET label = 'purgatory' WHERE sha256 = $1`, outside)
			execBoth(t, ctx, db, `INSERT INTO label_events (sha256, from_label, to_label, reason) VALUES ($1, 'good', 'purgatory', 'original-review')`, sha)
			want := PurgatoryMigrationStats{Locations: 2, Members: 2, Labels: 3}
			preview, err := db.MigratePurgatory(ctx, root, false)
			if err != nil || preview != want {
				t.Fatalf("preview = %+v, %v; want %+v", preview, err, want)
			}
			before, err := db.SampleBySHA256(ctx, sha)
			if err != nil || before.Label != "purgatory" || before.Path != oldRel {
				t.Fatalf("preview changed sample: %+v, %v", before, err)
			}
			if _, err := os.Stat(filepath.Join(root, newRel)); !os.IsNotExist(err) {
				t.Fatalf("preview created destination: %v", err)
			}
			stats, err := db.MigratePurgatory(ctx, root, true)
			if err != nil || stats != want {
				t.Fatalf("migration = %+v, %v; want %+v", stats, err, want)
			}
			assertPurgatoryMigratedRows(t, db, []purgatoryMigrationExpectation{
				{sha, newRel, "inconclusive", "human-review", ""},
				{member, newRel + "!!lib/member.js", "inconclusive", "human-review", "unsupported"},
				{knownMember, newRel + "!!known.exe", "bad", "independent", ""},
			})
			outsideSample, err := db.SampleBySHA256(ctx, outside)
			if err != nil || outsideSample.Label != "inconclusive" || outsideSample.Path != "incoming/elsewhere.bin" {
				t.Fatalf("label-only rename = %+v, %v", outsideSample, err)
			}
			if got, err := os.ReadFile(filepath.Join(root, newRel) + ProvenanceSidecarSuffix); err != nil || string(got) != `{"review":"careful"}` {
				t.Fatalf("sidecar = %q, %v", got, err)
			}
			if _, err := os.Stat(filepath.Join(root, oldRel)); !os.IsNotExist(err) {
				t.Fatalf("source still present: %v", err)
			}
			var events int
			if err := db.queryPurgatoryMigration(ctx, `SELECT count(*) FROM label_events WHERE sha256 = $1 AND to_label = 'purgatory' AND reason = 'original-review'`, []any{sha}, func(rows purgatoryMigrationRows) error {
				if rows.Next() {
					return rows.Scan(&events)
				}
				return rows.Err()
			}); err != nil || events != 1 {
				t.Fatalf("original audit history changed: %d, %v", events, err)
			}
			if again, err := db.MigratePurgatory(ctx, root, true); err != nil || again != (PurgatoryMigrationStats{}) {
				t.Fatalf("retry = %+v, %v", again, err)
			}
		})
	}
}

type purgatoryMigrationExpectation struct{ sha, path, label, source, skip string }

func assertPurgatoryMigratedRows(t *testing.T, db *DB, expected []purgatoryMigrationExpectation) {
	t.Helper()
	for _, check := range expected {
		sample, err := db.SampleBySHA256(t.Context(), check.sha)
		if err != nil || sample.Path != check.path || sample.Label != check.label || sample.LabelSource != check.source || sample.Skip != check.skip {
			t.Fatalf("migrated row: %+v, %v; want %+v", sample, err, check)
		}
		locations, err := db.LocationsForSHA(t.Context(), check.sha)
		if err != nil {
			t.Fatal(err)
		}
		for _, location := range locations {
			if len(location.Path) < len("inconclusive/") || location.Path[:len("inconclusive/")] != "inconclusive/" {
				t.Fatalf("legacy observation remains: %+v", location)
			}
		}
	}
}

func TestMigratePurgatoryResumesAfterArchiveMove(t *testing.T) {
	for _, backend := range testBackends {
		t.Run(backend.name, func(t *testing.T) {
			db := backend.open(t)
			root := t.TempDir()
			oldRel, newRel := "purgatory/npm/pkg.tgz", "inconclusive/npm/pkg.tgz"
			sha := writePurgatoryFixture(t, db, root, oldRel, "already moved archive")
			member := hexSHA(813)
			mustInsert(t, t.Context(), db, &Sample{SHA256: member, Path: oldRel + "!!a.js", Parent: sha, Label: "good"})
			if _, err := db.MoveLocation(t.Context(), MoveLocationOptions{DataRoot: root, SHA256: sha, OldPath: oldRel, NewPath: newRel}); err != nil {
				t.Fatal(err)
			}
			// Represents an interruption after file cleanup and before members.
			stats, err := db.MigratePurgatory(t.Context(), root, true)
			if err != nil || stats != (PurgatoryMigrationStats{Members: 1, Labels: 1}) {
				t.Fatalf("resume = %+v, %v", stats, err)
			}
			sample, err := db.SampleBySHA256(t.Context(), member)
			if err != nil || sample.Path != newRel+"!!a.js" || sample.Label != "good" {
				t.Fatalf("member recovery = %+v, %v", sample, err)
			}
		})
	}
}

func TestMigratePurgatoryRefusesMissingOrConflictingBytes(t *testing.T) {
	for _, scenario := range []string{"missing", "collision", "new-ruling"} {
		t.Run(scenario, func(t *testing.T) {
			db := openTestDB(t)
			root := t.TempDir()
			oldRel := "purgatory/pkg.tgz"
			sha := writePurgatoryFixture(t, db, root, oldRel, "legacy sample")
			switch scenario {
			case "missing":
				if err := os.Remove(filepath.Join(root, oldRel)); err != nil {
					t.Fatal(err)
				}
			case "collision":
				if err := os.MkdirAll(filepath.Join(root, "inconclusive"), 0o750); err != nil {
					t.Fatal(err)
				}
				if err := os.WriteFile(filepath.Join(root, "inconclusive", "pkg.tgz"), []byte("other content"), 0o640); err != nil {
					t.Fatal(err)
				}
			case "new-ruling":
				if err := db.Reclassify(t.Context(), sha, "dual-use", "new-review"); err != nil {
					t.Fatal(err)
				}
			}
			for _, apply := range []bool{false, true} {
				stats, err := db.MigratePurgatory(t.Context(), root, apply)
				if err == nil || stats.Failed != 1 || stats.Labels != 0 {
					t.Fatalf("apply=%v: stats=%+v, err=%v", apply, stats, err)
				}
			}
			sample, err := db.SampleBySHA256(t.Context(), sha)
			want := "purgatory"
			if scenario == "new-ruling" {
				want = "dual-use"
			}
			if err != nil || sample.Label != want || sample.Path != oldRel {
				t.Fatalf("failed migration changed sample: %+v, %v", sample, err)
			}
		})
	}
}
