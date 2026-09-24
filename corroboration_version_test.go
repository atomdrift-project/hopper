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
			db := openTestDBContext(t, ctx)
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

// TestBackfillVersionOverwriteGuards is a shape guard. The recovery may fill a
// blank version, may trim a wheel's PEP 427 tags off one it already has, and may
// fill an empty purl_base from a wheel's name. It may not rewrite a version it
// merely parses differently, nor replace an identity already recorded: either
// would move rows off the release the registry actually served.
func TestBackfillVersionOverwriteGuards(t *testing.T) {
	src, err := os.ReadFile("pg.go")
	if err != nil {
		t.Fatal(err)
	}
	fn := func(sig string) string {
		t.Helper()
		body := string(src)
		start := strings.Index(body, sig)
		if start < 0 {
			t.Fatalf("%s not found in pg.go", sig)
		}
		body = body[start:]
		if end := strings.Index(body, "\n}\n"); end > 0 {
			body = body[:end]
		}
		return body
	}
	decide := fn("func versionRepair(")
	for _, want := range []string{
		`fill := have == ""`,                // arm 1: only a blank version
		`strings.HasSuffix(base, ".whl")`,   // arm 2: wheels only
		`strings.HasPrefix(have, want+"-")`, // and only to trim a suffix off
		"if !fill && !trim {",               // everything else keeps what it has
		"pkgparse.WheelIdentity(base)",      // identity only from a wheel
		`if havePURL == "" {`,               // and only where there is none
	} {
		if !strings.Contains(decide, want) {
			t.Errorf("versionRepair is missing its overwrite guard %q", want)
		}
	}
	sweep := fn("func (db *DB) backfillVersionPG(")
	for _, want := range []string{
		"versionRepair(base, have, havePURL)",
		"WHEN s.purl_base = '' THEN v.purl ELSE s.purl_base END",                                // never replace an identity
		"WHERE s.id = v.id AND (s.version <> v.version OR (s.purl_base = '' AND v.purl <> ''))", // no-op writes never land
	} {
		if !strings.Contains(sweep, want) {
			t.Errorf("backfillVersionPG is missing its overwrite guard %q", want)
		}
	}
	if strings.Contains(sweep, "s.version = v.version\n\t\t\t\tFROM unnest") {
		t.Error("backfillVersionPG must not rewrite a version it merely parses differently")
	}
}

// TestVersionRepair drives the per-row decision behind backfill-version,
// including the sckit wheel (memoryos 2.0.34) as the entry-path bug stored it.
func TestVersionRepair(t *testing.T) {
	for _, tc := range []struct {
		name, base, have, havePURL string
		wantVer, wantPURL          string
		wantOK                     bool
	}{
		{"fill blank npm", "@whalent-agent-core-0.3.410.tgz", "", "pkg:npm/%40whalent/agent-core", "0.3.410", "", true},
		{"trim tagged wheel", "ranbval_sdk-0.5.0-cp312-cp312-macosx_26_0_arm64.whl", "0.5.0-cp312-cp312-macosx_26_0_arm64", "pkg:pypi/ranbval-sdk", "0.5.0", "", true},
		{"sckit wheel: tagged version, no identity", "memoryos-2.0.34-py3-none-any.whl", "2.0.34-py3-none-any", "", "2.0.34", "pkg:pypi/memoryos", true},
		{"build-tag wheel, no identity", "memoryos-2.0.34-1-py3-none-any.whl", "2.0.34-1-py3-none-any", "", "2.0.34", "pkg:pypi/memoryos", true},
		{"correct version, identity only", "memoryos-2.0.34-py3-none-any.whl", "2.0.34", "", "2.0.34", "pkg:pypi/memoryos", true},
		{"blank version, no identity", "memoryos-2.0.34-py3-none-any.whl", "", "", "2.0.34", "pkg:pypi/memoryos", true},
		// Left alone:
		{"version parsed differently", "lodash-4.17.21.tgz", "4.17.20", "pkg:npm/lodash", "", "", false},
		{"already current", "flask-3.1.3-py3-none-any.whl", "3.1.3", "pkg:pypi/flask", "", "", false},
		{"sdist without identity", "memoryos-2.0.34.tar.gz", "", "", "", "", false},
		{"wheel claiming another release", "memoryos-2.0.34-py3-none-any.whl", "1.0.0", "", "", "", false},
		{"unparseable", "evil.exe", "", "pkg:npm/x", "", "", false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			ver, purl, ok := versionRepair(tc.base, tc.have, tc.havePURL)
			if ok != tc.wantOK || (ok && (ver != tc.wantVer || purl != tc.wantPURL)) {
				t.Errorf("versionRepair(%q, %q, %q) = (%q, %q, %v), want (%q, %q, %v)",
					tc.base, tc.have, tc.havePURL, ver, purl, ok, tc.wantVer, tc.wantPURL, tc.wantOK)
			}
		})
	}
}

// TestEveryCorroborationPathNarrowsByVersion is the guard that the fix is
// complete. There are four places that set samples.corroborated from a package
// claim, and on 2026-09-08 three of them ignored the affected list entirely.
// Missing any one of them is not a partial fix: the walk path alone would
// re-flag every row reconcile-corroborated had just cleared.
func TestEveryCorroborationPathNarrowsByVersion(t *testing.T) {
	pg, err := os.ReadFile("pg.go")
	if err != nil {
		t.Fatal(err)
	}
	schema, err := os.ReadFile("schema.sql")
	if err != nil {
		t.Fatal(err)
	}
	lite, err := os.ReadFile("sqlite.go")
	if err != nil {
		t.Fatal(err)
	}
	hop, err := os.ReadFile("hopper.go")
	if err != nil {
		t.Fatal(err)
	}

	// Each entry: the statement that marks by package identity, and the
	// narrowing it must carry.
	for _, tc := range []struct{ name, src, marker, narrows string }{
		{"bulk mark (RemarkCorroborated)", string(pg), "markCorroboratedByPURLVersionSQL = `", "string_to_array(replace(s.affected"},
		{"trigger body", string(schema), "IF NEW.affected ~ '^[0-9]' THEN", "string_to_array(replace(NEW.affected"},
		{"walk / staged rows", string(pg), "corroborateStagedByPURLPG = `", "string_to_array(replace(g.affected"},
		{"reconcile clear pass", string(hop), "), stale AS (", "string_to_array(replace(s.affected"},
		{"sqlite trigger", string(lite), "sightings_corroborate_trg", "replace(NEW.affected, ' ', '')"},
	} {
		i := strings.Index(tc.src, tc.marker)
		if i < 0 {
			t.Errorf("%s: anchor %q not found; the path moved and this guard went blind", tc.name, tc.marker)
			continue
		}
		window := tc.src[i:min(i+1400, len(tc.src))]
		if !strings.Contains(window, tc.narrows) {
			t.Errorf("%s marks by purl_base without narrowing to the versions the claim names", tc.name)
		}
	}
}

// TestBackfillVersionRepairsWheelIdentity runs the sweep itself against
// Postgres (backfill-version is Postgres-only): the sckit wheel as the entry
// path stored it gains its release and identity, a build-tag wheel likewise, a
// row whose identity is already recorded keeps it, and a second run is a no-op.
func TestBackfillVersionRepairsWheelIdentity(t *testing.T) {
	ctx := context.Background()
	db := openDisposablePG(t)

	insert := func(sha, file, version, purl string) string {
		t.Helper()
		full := (sha + strings.Repeat("0", 64))[:64]
		mustInsert(t, ctx, db, &Sample{
			SHA256: full, Source: "upload", Label: "unknown", LabelSource: "upload",
			Filename: file, Package: "memoryos", Version: version, PURLBase: purl,
			Path: "incoming/uploads/_unknown/" + file, SizeBytes: 8,
		})
		return full
	}
	sckit := insert("a1", "memoryos-2.0.34-py3-none-any.whl", "2.0.34-py3-none-any", "")
	build := insert("b2", "memoryos-2.0.33-1-py3-none-any.whl", "2.0.33-1-py3-none-any", "")
	kept := insert("c3", "memoryos-2.0.32-py3-none-any.whl", "2.0.32", "pkg:pypi/memoryos-legacy")
	sdist := insert("d4", "memoryos-2.0.31.tar.gz", "2.0.31", "")

	n, err := db.BackfillVersion(ctx, false)
	if err != nil {
		t.Fatalf("BackfillVersion: %v", err)
	}
	if n != 2 {
		t.Errorf("BackfillVersion repaired %d rows, want 2", n)
	}
	for sha, want := range map[string][2]string{
		sckit: {"2.0.34", "pkg:pypi/memoryos"},
		build: {"2.0.33", "pkg:pypi/memoryos"},
		kept:  {"2.0.32", "pkg:pypi/memoryos-legacy"},
		sdist: {"2.0.31", ""},
	} {
		var ver, purl string
		if err := db.pool.QueryRow(ctx, `SELECT version, purl_base FROM samples WHERE sha256 = $1`, sha).Scan(&ver, &purl); err != nil {
			t.Fatal(err)
		}
		if ver != want[0] || purl != want[1] {
			t.Errorf("%s: (version, purl_base) = (%q, %q), want (%q, %q)", sha[:4], ver, purl, want[0], want[1])
		}
	}
	if again, err := db.BackfillVersion(ctx, false); err != nil || again != 0 {
		t.Errorf("second BackfillVersion = %d, %v; want 0 (idempotent)", again, err)
	}
}
