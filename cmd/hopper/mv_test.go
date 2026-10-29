package main

import (
	"context"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/atomdrift-project/hopper"
)

func TestCollectMvSHAs(t *testing.T) {
	a := strings.Repeat("a", 64)
	b := strings.Repeat("b", 64)

	tests := []struct {
		name    string
		args    []string
		stdin   string
		want    []string
		wantErr bool
	}{
		{name: "args", args: []string{a, b}, want: []string{a, b}},
		{
			// Hashes get pasted out of a report in whatever case it printed
			// them, and a list assembled by hand repeats entries.
			name: "normalizes case and drops repeats",
			args: []string{strings.ToUpper(a), a, "  " + b + "  "},
			want: []string{a, b},
		},
		{
			name:  "reads stdin on bare dash",
			args:  []string{"-"},
			stdin: a + "\n" + b + "\n",
			want:  []string{a, b},
		},
		{
			// `hopper mv -target=bad < shas.txt` with no positional args.
			name:  "reads stdin when no args",
			stdin: a + " " + b + "\n",
			want:  []string{a, b},
		},
		{
			// A truncated or mistyped identifier must stop the run rather than
			// silently relabel a shorter list than the operator asked for.
			name:    "rejects a non-sha argument",
			args:    []string{a, "deadbeef"},
			wantErr: true,
		},
		{name: "empty", args: []string{}, stdin: "", want: nil},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			got, err := collectMvSHAs(tc.args, strings.NewReader(tc.stdin))
			if tc.wantErr {
				if err == nil {
					t.Fatalf("expected error, got %v", got)
				}
				return
			}
			if err != nil {
				t.Fatalf("collectMvSHAs: %v", err)
			}
			if len(got) != len(tc.want) {
				t.Fatalf("got %v, want %v", got, tc.want)
			}
			for i := range got {
				if got[i] != tc.want[i] {
					t.Fatalf("got %v, want %v", got, tc.want)
				}
			}
		})
	}
}

// mvTestServer stands up the one route cmdMv talks to, backed by a real
// database and data root, and returns its base URL.
func mvTestServer(t *testing.T, ctx context.Context, root string) (db *hopper.DB, baseURL string) {
	t.Helper()
	db = mustOpenDB(t, ctx, filepath.Join(root, "hopper.db"))
	t.Cleanup(func() { db.Close() })
	if err := db.Migrate(ctx); err != nil {
		t.Fatalf("Migrate: %v", err)
	}
	api := &apiServer{db: db, dataRoot: root, tracker: newWorkerTracker()}
	mux := http.NewServeMux()
	mux.HandleFunc("POST /api/triage", api.handleTriage)
	srv := httptest.NewServer(mux)
	t.Cleanup(srv.Close)
	return db, srv.URL
}

func writeMvSample(t *testing.T, db *hopper.DB, ctx context.Context, root, rel, label, content string) string {
	t.Helper()
	abs := filepath.Join(root, rel)
	if err := os.MkdirAll(filepath.Dir(abs), 0o750); err != nil {
		t.Fatalf("mkdir: %v", err)
	}
	if err := os.WriteFile(abs, []byte(content), 0o600); err != nil {
		t.Fatalf("write sample: %v", err)
	}
	sha := testSHA256([]byte(content))
	if err := db.InsertSample(ctx, &hopper.Sample{
		SHA256: sha, Source: "test", Path: rel, Label: label, LabelSource: "test",
	}); err != nil {
		t.Fatalf("InsertSample: %v", err)
	}
	return sha
}

// The point of -target=good|bad is the operator-correction placement: the
// sample lands in a bucket that records the label it was rescued from, which
// is what makes a relabel auditable after the fact. A ruling with the same
// spelling would put it in the promoter tree instead, so this pins which of
// the two cmdMv sends.
func TestCmdMvVerdictMovesAndRelabels(t *testing.T) {
	ctx := t.Context()
	root := t.TempDir()
	db, url := mvTestServer(t, ctx, root)

	sha := writeMvSample(t, db, ctx, root, filepath.Join("good", "sample.js"), "good", "payload")

	withArgs([]string{"hopper", "mv", "-url", url, "-target", "bad", sha}, func() {
		if err := cmdMv(ctx); err != nil {
			t.Fatalf("cmdMv: %v", err)
		}
	})

	wantRel := filepath.Join("bad", "mislabeled-good", "sample.js")
	if _, err := os.Stat(filepath.Join(root, wantRel)); err != nil {
		t.Fatalf("expected moved file at %s: %v", wantRel, err)
	}
	if _, err := os.Stat(filepath.Join(root, "good", "sample.js")); !os.IsNotExist(err) {
		t.Fatalf("old path should be gone, stat err = %v", err)
	}
	samp, err := db.SampleBySHA256(ctx, sha)
	if err != nil {
		t.Fatalf("SampleBySHA256: %v", err)
	}
	if samp.Label != "bad" || samp.Path != wantRel {
		t.Fatalf("row not updated: label=%q path=%q", samp.Label, samp.Path)
	}
}

// sighted/pending/review are the other flow: they ride triageVerdict.Ruling
// and land in the pool tree with the source subpath preserved.
func TestCmdMvRulingUsesPoolTree(t *testing.T) {
	ctx := t.Context()
	root := t.TempDir()
	db, url := mvTestServer(t, ctx, root)

	sha := writeMvSample(t, db, ctx, root, filepath.Join("bad", "foraged", "npm", "pkg.tgz"), "bad", "sighted-bytes")

	withArgs([]string{"hopper", "mv", "-url", url, "-target", "sighted", sha}, func() {
		if err := cmdMv(ctx); err != nil {
			t.Fatalf("cmdMv: %v", err)
		}
	})

	wantRel := filepath.Join("sighted", "foraged", "npm", "pkg.tgz")
	if _, err := os.Stat(filepath.Join(root, wantRel)); err != nil {
		t.Fatalf("expected moved file at %s: %v", wantRel, err)
	}
	samp, err := db.SampleBySHA256(ctx, sha)
	if err != nil {
		t.Fatalf("SampleBySHA256: %v", err)
	}
	if samp.Label != "sighted" || samp.Path != wantRel {
		t.Fatalf("row not updated: label=%q path=%q", samp.Label, samp.Path)
	}
}

func TestCmdMvDryRunDoesNotMove(t *testing.T) {
	ctx := t.Context()
	root := t.TempDir()
	db, url := mvTestServer(t, ctx, root)

	oldRel := filepath.Join("good", "keep.bin")
	sha := writeMvSample(t, db, ctx, root, oldRel, "good", "dry-run-bytes")

	withArgs([]string{"hopper", "mv", "-url", url, "-target", "bad", "-dry-run", sha}, func() {
		if err := cmdMv(ctx); err != nil {
			t.Fatalf("cmdMv: %v", err)
		}
	})

	if _, err := os.Stat(filepath.Join(root, oldRel)); err != nil {
		t.Fatalf("dry run must not move the file: %v", err)
	}
	samp, err := db.SampleBySHA256(ctx, sha)
	if err != nil {
		t.Fatalf("SampleBySHA256: %v", err)
	}
	if samp.Label != "good" {
		t.Fatalf("dry run must not flip the label, got %q", samp.Label)
	}
}

// A sha the master has never catalogued reports not_found, which counts as a
// failure so a scripted run stops instead of reporting success over a typo.
func TestCmdMvUnknownSHAFails(t *testing.T) {
	ctx := t.Context()
	root := t.TempDir()
	_, url := mvTestServer(t, ctx, root)

	withArgs([]string{"hopper", "mv", "-url", url, "-target", "bad", strings.Repeat("c", 64)}, func() {
		if err := cmdMv(ctx); err == nil {
			t.Fatal("expected an error for an unknown sha256")
		}
	})
}

func TestCmdMvTargetValidation(t *testing.T) {
	ctx := t.Context()
	sha := strings.Repeat("a", 64)

	for _, tc := range []struct {
		name string
		args []string
	}{
		{name: "missing target", args: []string{"hopper", "mv", sha}},
		{name: "unknown target", args: []string{"hopper", "mv", "-target", "hostile", sha}},
		{name: "no shas", args: []string{"hopper", "mv", "-target", "bad"}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			withArgs(tc.args, func() {
				// "no shas" would otherwise block reading the real stdin.
				if tc.name == "no shas" {
					restore := os.Stdin
					r, w, err := os.Pipe()
					if err != nil {
						t.Fatal(err)
					}
					if err := w.Close(); err != nil {
						t.Fatal(err)
					}
					os.Stdin = r
					defer func() { os.Stdin = restore }()
				}
				if err := cmdMv(ctx); err == nil {
					t.Fatal("expected an error")
				}
			})
		})
	}
}

// Reviewed classifications preserve provenance and accept retries. The legacy
// CLI and API spelling writes inconclusive rather than a new purgatory row.
func TestCmdMvReviewedPools(t *testing.T) {
	for _, target := range []string{"inconclusive", "dual-use", "purgatory"} {
		t.Run(target, func(t *testing.T) { testCmdMvReviewedPool(t, target) })
	}
}

func testCmdMvReviewedPool(t *testing.T, target string) {
	t.Helper()
	ctx := t.Context()
	root := t.TempDir()
	db, url := mvTestServer(t, ctx, root)

	oldRel := filepath.Join("good", "datasets", "PE", "dual-use.exe")
	sha := writeMvSample(t, db, ctx, root, oldRel, "good", "greyware-bytes")

	withArgs([]string{"hopper", "mv", "-url", url, "-target", target, "-dry-run", sha}, func() {
		if err := cmdMv(ctx); err != nil {
			t.Fatalf("cmdMv preview: %v", err)
		}
	})
	before, err := db.SampleBySHA256(ctx, sha)
	if err != nil || before.Label != "good" || before.Path != oldRel {
		t.Fatalf("preview changed sample: %+v, %v", before, err)
	}
	if _, err := os.Stat(filepath.Join(root, oldRel)); err != nil {
		t.Fatalf("preview disturbed source: %v", err)
	}
	withArgs([]string{"hopper", "mv", "-url", url, "-target", target, sha}, func() {
		if err := cmdMv(ctx); err != nil {
			t.Fatalf("cmdMv: %v", err)
		}
	})

	wantLabel := hopper.CanonicalLabel(target)
	wantRel := filepath.Join(wantLabel, "datasets", "PE", "dual-use.exe")
	if _, err := os.Stat(filepath.Join(root, wantRel)); err != nil {
		t.Fatalf("expected moved file at %s: %v", wantRel, err)
	}
	if _, err := os.Stat(filepath.Join(root, oldRel)); !os.IsNotExist(err) {
		t.Fatalf("old path should be gone, stat err = %v", err)
	}
	samp, err := db.SampleBySHA256(ctx, sha)
	if err != nil {
		t.Fatalf("SampleBySHA256: %v", err)
	}
	if samp.Label != wantLabel || samp.Path != wantRel {
		t.Fatalf("row not updated: label=%q path=%q", samp.Label, samp.Path)
	}

	// Idempotent: a re-submitted ruling is a noop, not a second move.
	withArgs([]string{"hopper", "mv", "-url", url, "-target", target, sha}, func() {
		if err := cmdMv(ctx); err != nil {
			t.Fatalf("cmdMv re-run: %v", err)
		}
	})
	if _, err := os.Stat(filepath.Join(root, wantRel)); err != nil {
		t.Fatalf("re-run disturbed the parked file: %v", err)
	}
	// Older clients send the alias directly to the API, bypassing cmdMv.
	resp, err := postTriage(ctx, url, triageRequest{Verdicts: []triageVerdict{{SHA256: sha, Ruling: target}}})
	if err != nil || resp.Noop != 1 || resp.Failed != 0 {
		t.Fatalf("API retry: %+v, %v", resp, err)
	}
}

// Correcting a reviewed sample records the former label in its bucket.
func TestCmdMvPurgatoryRoundTrip(t *testing.T) {
	ctx := t.Context()
	root := t.TempDir()
	db, url := mvTestServer(t, ctx, root)

	sha := writeMvSample(t, db, ctx, root,
		filepath.Join("purgatory", "npm", "pkg.tgz"), "purgatory", "round-trip-bytes")

	withArgs([]string{"hopper", "mv", "-url", url, "-target", "bad", sha}, func() {
		if err := cmdMv(ctx); err != nil {
			t.Fatalf("cmdMv: %v", err)
		}
	})

	wantRel := filepath.Join("bad", "mislabeled-inconclusive", "pkg.tgz")
	if _, err := os.Stat(filepath.Join(root, wantRel)); err != nil {
		t.Fatalf("expected moved file at %s: %v", wantRel, err)
	}
	samp, err := db.SampleBySHA256(ctx, sha)
	if err != nil {
		t.Fatalf("SampleBySHA256: %v", err)
	}
	if samp.Label != "bad" {
		t.Fatalf("label = %q, want bad", samp.Label)
	}
}

func TestCmdMvBetweenReviewedPools(t *testing.T) {
	ctx := t.Context()
	root := t.TempDir()
	db, url := mvTestServer(t, ctx, root)
	sha := writeMvSample(t, db, ctx, root, "inconclusive/npm/pkg.tgz", "inconclusive", "reviewed-bytes")
	for _, target := range []string{"dual-use", "inconclusive", "sighted"} {
		withArgs([]string{"hopper", "mv", "-url", url, "-target", target, sha}, func() {
			if err := cmdMv(ctx); err != nil {
				t.Fatal(err)
			}
		})
		wantPath := target + "/npm/pkg.tgz"
		if target == "sighted" {
			wantPath = "sighted/foraged/npm/pkg.tgz"
		}
		sample, err := db.SampleBySHA256(ctx, sha)
		if err != nil || sample.Label != target || sample.Path != wantPath {
			t.Fatalf("move to %s: %+v, %v", target, sample, err)
		}
	}
}
