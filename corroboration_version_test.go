package hopper

import (
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/atomdrift-project/hopper/pkgparse"
)

// A claim naming exact releases is evidence about those releases and nothing
// else.
//
// Found 2026-09-08 by inspection of a real sample. OSV advisory MAL-2026-10722
// lists 49 exact versions of @whalent/agent-core, the highest 0.3.298. Version
// 0.3.410 — fetched by the npm firehose, named by no claim — was flagged as
// cited by it, because both marking paths matched on purl_base and ignored the
// version entirely. Corroborated is not decoration: it drives the sighted claim
// tier, promoter's evidence rules and prism's feeds filter, so those rows were
// false evidence about clean releases.
func TestExactVersionClaimDoesNotCorroborateOtherVersions(t *testing.T) {
	ctx := context.Background()
	db := openTestDB(t)

	const purl = "pkg:npm/%40whalent/agent-core"
	cited := mustVersionedSample(t, ctx, db, "a1", purl, "0.3.298")
	uncited := mustVersionedSample(t, ctx, db, "b2", purl, "0.3.410")

	if _, err := db.AddSightings(ctx, []Sighting{{
		Source: "osv", Subject: purl, Affected: "0.3.230, 0.3.298", Claim: ClaimMalicious,
	}}); err != nil {
		t.Fatal(err)
	}

	if !corroborated(t, ctx, db, cited) {
		t.Error("the version the advisory names is not corroborated; the citation was lost")
	}
	if corroborated(t, ctx, db, uncited) {
		t.Error("0.3.410 was corroborated by an advisory that does not list it")
	}
}

// A scope we cannot narrow still speaks for the whole package: ” means the
// source did not say, '*' means every release, and a range names versions SQL
// cannot enumerate. Narrowing those would lose real citations.
func TestUnnarrowableClaimsStillCorroborateThePackage(t *testing.T) {
	ctx := context.Background()
	for _, affected := range []string{"", "*", ">= 0", "<2.0.0"} {
		t.Run("affected="+affected, func(t *testing.T) {
			db := openTestDB(t)
			const purl = "pkg:npm/broad"
			s := mustVersionedSample(t, ctx, db, "c3", purl, "9.9.9")
			if _, err := db.AddSightings(ctx, []Sighting{{
				Source: "aikido", Subject: purl, Affected: affected, Claim: ClaimMalicious,
			}}); err != nil {
				t.Fatal(err)
			}
			if !corroborated(t, ctx, db, s) {
				t.Errorf("affected %q should corroborate every release of the package", affected)
			}
		})
	}
}

// The repair path. Rows flagged by the old version-blind marking are cleared by
// reconcile-corroborated once the narrowed rule is in place.
func TestReconcileClearsVersionMismatchedCorroboration(t *testing.T) {
	ctx := context.Background()
	db := openTestDB(t)

	const purl = "pkg:npm/%40whalent/agent-core"
	cited := mustVersionedSample(t, ctx, db, "d4", purl, "0.3.298")
	wrong := mustVersionedSample(t, ctx, db, "e5", purl, "0.3.410")
	if _, err := db.AddSightings(ctx, []Sighting{{
		Source: "osv", Subject: purl, Affected: "0.3.298", Claim: ClaimMalicious,
	}}); err != nil {
		t.Fatal(err)
	}
	// Simulate the pre-fix state: the old trigger flagged every version.
	if err := setCorroborated(ctx, db, wrong, true); err != nil {
		t.Fatal(err)
	}

	if _, err := db.ReconcileCorroborated(ctx); err != nil {
		t.Fatal(err)
	}
	if corroborated(t, ctx, db, wrong) {
		t.Error("reconcile left a version-mismatched flag in place; it is the repair for exactly this")
	}
	if !corroborated(t, ctx, db, cited) {
		t.Error("reconcile cleared a genuine citation")
	}
}

// mustVersionedSample inserts a sample carrying a concrete release, which is
// what makes version-scoped corroboration testable at all.
func mustVersionedSample(t *testing.T, ctx context.Context, db *DB, sha, purlBase, version string) string {
	t.Helper()
	full := (sha + strings.Repeat("0", 64))[:64]
	mustInsert(t, ctx, db, &Sample{
		SHA256:      full,
		Source:      "forager",
		Label:       "unknown",
		LabelSource: "forager",
		PURLBase:    purlBase,
		Version:     version,
		Path:        "incoming/" + full,
		SizeBytes:   8,
	})
	return full
}

func setCorroborated(ctx context.Context, db *DB, sha string, v bool) error {
	if db.pool != nil {
		_, err := db.pool.Exec(ctx, `UPDATE samples SET corroborated = $2 WHERE sha256 = $1`, sha, v)
		return err
	}
	_, err := db.lite.ExecContext(ctx, `UPDATE samples SET corroborated = ? WHERE sha256 = ?`, v, sha)
	return err
}

// TestLocationFilenameYieldsVersion covers the recovery backfill-version relies
// on. The npm firehose stored these rows with an empty samples.version, which is
// what let a version-narrowed advisory look like a mismatch instead of a match;
// the filename the registry served is the authority we recover it from.
func TestLocationFilenameYieldsVersion(t *testing.T) {
	for _, tc := range []struct{ path, want string }{
		{"incoming/forager/javascript/npmjs.org/_/@whalent/agent-core/@whalent-agent-core-0.3.410.tgz", "0.3.410"},
		{"incoming/forager/javascript/npmjs.org/_/lodash/lodash-4.17.21.tgz", "4.17.21"},
		{"incoming/forager/python/pypi.org/_/requests/requests-2.31.0.tar.gz", "2.31.0"},
	} {
		if _, got, _ := pkgparse.ParseFilename(filepath.Base(tc.path)); got != tc.want {
			t.Errorf("ParseFilename(%q) version = %q, want %q", filepath.Base(tc.path), got, tc.want)
		}
	}
}

// TestBackfillVersionNeverOverwrites is a shape guard: the recovery must fill a
// blank version and never rewrite one already recorded, or a re-run would move
// rows off the release the registry actually served.
func TestBackfillVersionNeverOverwrites(t *testing.T) {
	src, err := os.ReadFile("pg.go")
	if err != nil {
		t.Fatal(err)
	}
	body := string(src)
	start := strings.Index(body, "func (db *DB) backfillVersionPG(")
	if start < 0 {
		t.Fatal("backfillVersionPG not found in pg.go")
	}
	body = body[start:]
	if end := strings.Index(body, "\n}\n"); end > 0 {
		body = body[:end]
	}
	for _, want := range []string{
		"s.version = '' AND s.purl_base <> ''", // only rows missing a version
		"WHERE s.id = v.id AND s.version = ''", // and still missing it at write time
	} {
		if !strings.Contains(body, want) {
			t.Errorf("backfillVersionPG is missing its no-overwrite guard %q", want)
		}
	}
}
