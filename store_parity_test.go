package hopper

import (
	"encoding/hex"
	"errors"
	"os"
	"reflect"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/atomdrift-project/hopper/store"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
)

// TestStoreLookupParity renders every exported legacy row with recordOf and
// asks the verdict schema for the same digest. The two must agree field by
// field: this is the evidence that /v1/lookup answers survive the migration.
//
// Three differences are deliberate, counted and logged rather than failed,
// because in each the legacy answer is the defective one:
//
//   - purl: recordOf recomposes a PURL from the ecosystem and package columns
//     instead of reading purl_base, the identity a PURL lookup matches on. It
//     invents one for rows that have none (pkg:npm/node_modules%2Flodash for
//     an archive member) and contradicts purl_base where the columns disagree
//     (pkg:cargo/ahash for pkg:openbsd/wstunnel). The store answers with the
//     stored identity, so the test holds it to purl_base and counts how often
//     the recomposition differed. The export has no domain column, so a few
//     of those are the test's own.
//   - fires_at: recordOf reads the level under "lvl"; version 6 results spell
//     it "l", so the legacy record reports no level for a file that has one.
//     The store takes the level from the lvl column, which reads both.
//   - findings: the top_traits column was never filled for rows analyzed
//     before it existed. The store derives findings from the report.
//
// It needs the prototype database (internal/verdictproto) loaded:
//
//	HOPPER_PROTO_DSN='host=/tmp/hopper-schema-prototype/v2 port=5499 user=proto dbname=proto' go test -run StoreLookupParity
func TestStoreLookupParity(t *testing.T) {
	dsn := strings.TrimSpace(os.Getenv("HOPPER_PROTO_DSN"))
	if dsn == "" {
		t.Skip("HOPPER_PROTO_DSN not set (the loaded verdict prototype database)")
	}
	ctx := t.Context()
	pool, err := pgxpool.New(ctx, dsn)
	if err != nil {
		t.Fatal(err)
	}
	defer pool.Close()
	st, err := store.New(pool)
	if err != nil {
		t.Fatal(err)
	}

	rows, err := pool.Query(ctx, legacySampleColumns+` FROM legacy_samples ORDER BY id`)
	if err != nil {
		t.Fatal(err)
	}
	defer rows.Close()

	differ, deliberate := map[string]int{}, map[string]int{}
	var n int
	for rows.Next() {
		s, reportRuleset, err := scanLegacySample(rows)
		if err != nil {
			t.Fatal(err)
		}
		sha, err := hex.DecodeString(s.SHA256)
		if err != nil {
			t.Fatalf("%s: %v", s.SHA256, err)
		}
		rec, err := st.BySHA256(ctx, sha)
		if err != nil {
			t.Fatalf("%s: %v", s.SHA256, err)
		}
		n++
		compareRecord(t, s, reportRuleset, RecordOfStore(rec), differ, deliberate)
	}
	if err := rows.Err(); err != nil {
		t.Fatal(err)
	}
	if n == 0 {
		t.Fatal("legacy_samples is empty")
	}
	t.Logf("compared %d records", n)
	for reason, count := range deliberate {
		t.Logf("deliberate difference on %d records: %s", count, reason)
	}
	for field, count := range differ {
		t.Errorf("%s differs on %d of %d records", field, count, n)
	}

	if _, err := st.BySHA256(ctx, make([]byte, 32)); !errors.Is(err, store.ErrNotFound) {
		t.Errorf("unknown digest: got %v, want ErrNotFound", err)
	}
}

// legacySampleColumns selects what recordOf reads from a legacy samples row,
// for scanLegacySample.
const legacySampleColumns = `SELECT sha256, coalesce(ecosystem, ''), coalesce(package, ''),
	coalesce(version, ''), coalesce(purl_base, ''), litmus_result::text, llm_result::text,
	coalesce(traits_version, ''), analyzed_at, coalesce(top_traits, ''), cleave_result IS NOT NULL,
	coalesce(cleave_result->>'rev', cleave_result->>'tv', '')`

// scanLegacySample reads a row of legacySampleColumns, and the ruleset the
// report itself records. The cleave result is only marked present: recordOf
// never reads it.
func scanLegacySample(rows pgx.Rows) (*Sample, string, error) {
	s := &Sample{}
	var litmus, llm *string
	var hasCleave bool
	var reportRuleset string
	if err := rows.Scan(&s.SHA256, &s.Ecosystem, &s.Package, &s.Version, &s.PURLBase,
		&litmus, &llm, &s.TraitsVersion, &s.AnalyzedAt, &s.TopTraits, &hasCleave, &reportRuleset); err != nil {
		return nil, "", err
	}
	if litmus != nil {
		s.LitmusResult = []byte(*litmus)
	}
	if llm != nil {
		s.LLMResult = []byte(*llm)
	}
	if hasCleave {
		s.CleaveResult = []byte{'1'}
	}
	return s, reportRuleset, nil
}

// TestRehearsalLookupParity compares, for every analyzed top-level file the
// migration rehearsal converted (HOPPER_REHEARSAL_DSN, after
// TestMigrationRehearsal built its verdict schema), the record legacy lookup
// builds from the legacy row with the one the store holds. Excerpts are left
// out: they are not converted (MIGRATION_PLAN.md, "Legacy excerpts").
func TestRehearsalLookupParity(t *testing.T) {
	dsn := strings.TrimSpace(os.Getenv("HOPPER_REHEARSAL_DSN"))
	if dsn == "" || strings.Contains(dsn, "hopper-db") {
		t.Skip("HOPPER_REHEARSAL_DSN (a migrated rehearsal database) is needed")
	}
	ctx := t.Context()
	cfg, err := pgxpool.ParseConfig(dsn)
	if err != nil {
		t.Fatal(err)
	}
	cfg.ConnConfig.RuntimeParams["search_path"] = "verdict"
	pool, err := pgxpool.NewWithConfig(ctx, cfg)
	if err != nil {
		t.Fatal(err)
	}
	defer pool.Close()
	var migrated bool
	if err := pool.QueryRow(ctx, `SELECT to_regclass('verdict.samples') IS NOT NULL`).Scan(&migrated); err != nil || !migrated {
		t.Skipf("no verdict schema (%v): run TestMigrationRehearsal first", err)
	}
	st, err := store.New(pool)
	if err != nil {
		t.Fatal(err)
	}
	rows, err := pool.Query(ctx, legacySampleColumns+` FROM public.samples l
		WHERE l.parent = '' AND l.cleave_result IS NOT NULL
		  AND NOT coalesce(coalesce(l.cleave_result->'files', l.cleave_result->'fs')->0 ? 'pid', false)
		ORDER BY l.id`)
	if err != nil {
		t.Fatal(err)
	}
	defer rows.Close()
	differ, deliberate := map[string]int{}, map[string]int{}
	var n int
	for rows.Next() {
		s, reportRuleset, err := scanLegacySample(rows)
		if err != nil {
			t.Fatal(err)
		}
		sha, err := hex.DecodeString(s.SHA256)
		if err != nil {
			t.Fatal(err)
		}
		rec, err := st.BySHA256(ctx, sha)
		if err != nil {
			t.Fatalf("%s: %v", s.SHA256, err)
		}
		n++
		compareRecord(t, s, reportRuleset, RecordOfStore(rec), differ, deliberate)
	}
	if err := rows.Err(); err != nil {
		t.Fatal(err)
	}
	t.Logf("compared %d records", n)
	for reason, count := range deliberate {
		t.Logf("deliberate difference on %d records: %s", count, reason)
	}
	for field, count := range differ {
		t.Errorf("%s differs on %d of %d records", field, count, n)
	}
}

// compareRecord compares the record legacy lookup builds from sample s with
// got, the store's, counting each field that differs, and each difference
// that is deliberate, which it forgives.
func compareRecord(t *testing.T, s *Sample, reportRuleset string, got *LookupRecord, differ, deliberate map[string]int) {
	t.Helper()
	want := recordOf(s)
	// The converter takes the ruleset the report records over the row's
	// column (v7result: "the report's wins").
	if reportRuleset != "" && deref(want.TraitsVersion) != reportRuleset && deref(got.TraitsVersion) == reportRuleset {
		deliberate["ruleset the report records over traits_version"]++
		want.TraitsVersion = got.TraitsVersion
	}
	// A trait about a fetched dependency is the dependency's verdict, which
	// the store links through refs and raises by, not a finding of the file.
	if slices.ContainsFunc(want.Findings, func(f LookupFinding) bool { return strings.HasPrefix(f.ID, "fetch/dependency") }) &&
		!reflect.DeepEqual(want.Findings, got.Findings) {
		deliberate["dependency traits left to refs"]++
		want.Findings = got.Findings
	}
	// The legacy record repeats the ML result's own timestamp string; the
	// store formats the instant. Compare instants.
	// The migration stamps the later of the row's analysis time and the ML
	// result's (internal/migrate, scanTime); legacy answers the ML result's.
	if !sameInstant(want.AnalyzedAt, got.AnalyzedAt) {
		if later := laterTime(want.AnalyzedAt, s.AnalyzedAt); sameInstant(later, got.AnalyzedAt) {
			deliberate["analyzed_at the later of the row's and the ML result's"]++
		} else {
			differ["analyzed_at"]++
			logFirst(t, differ, "analyzed_at", s.SHA256, deref(want.AnalyzedAt), deref(got.AnalyzedAt))
		}
	}
	identity := (*string)(nil)
	if strings.HasPrefix(s.PURLBase, "pkg:") {
		purl := s.PURLBase
		if s.Version != "" {
			purl = withVersion(s.PURLBase, s.Version)
		}
		identity = &purl
	}
	if deref(want.PURL) != deref(identity) {
		if want.PURL != nil && identity == nil {
			deliberate["purl composed for a row with no PURL identity"]++
		} else {
			deliberate["purl recomposed differently from purl_base"]++
		}
		want.PURL = identity
	}
	// A slash in a qualifier value is not a PURL separator, so ECMA-427 5.4
	// has it percent-encoded; legacy left it bare.
	if want.PURL != nil && got.PURL != nil && *want.PURL != *got.PURL && strings.ReplaceAll(*got.PURL, "%2F", "/") == *want.PURL {
		deliberate["qualifier slash percent-encoded (ECMA-427 5.4)"]++
		want.PURL = got.PURL
	}
	if want.FiresAt == nil && got.FiresAt != nil && strings.Contains(string(s.LitmusResult), `"l": `) {
		deliberate["fires_at under the v6 key"]++
		want.FiresAt = got.FiresAt
	}
	if s.TopTraits == "" && len(got.Findings) > 0 {
		deliberate["findings where top_traits was never filled"]++
		want.Findings = got.Findings
	}
	for _, f := range []struct {
		name      string
		want, got any
	}{
		{"sha256", deref(want.SHA256), deref(got.SHA256)},
		{"purl", deref(want.PURL), deref(got.PURL)},
		{"fires_at", want.FiresAt, got.FiresAt},
		{"engine_version", deref(want.EngineVersion), deref(got.EngineVersion)},
		{"traits_version", deref(want.TraitsVersion), deref(got.TraitsVersion)},
		{"reason", deref(want.Reason), deref(got.Reason)},
		{"findings", want.Findings, got.Findings},
		{"state", want.State, got.State},
	} {
		if !reflect.DeepEqual(f.want, f.got) {
			differ[f.name]++
			logFirst(t, differ, f.name, s.SHA256, f.want, f.got)
		}
	}
}

// logFirst logs the first three disagreements on a field, enough to diagnose
// without burying the totals.
func logFirst(t *testing.T, differ map[string]int, field, sha string, want, got any) {
	t.Helper()
	if differ[field] <= 3 {
		if w, ok := want.(*int); ok && w != nil {
			want = *w
		}
		if g, ok := got.(*int); ok && g != nil {
			got = *g
		}
		t.Logf("%s %s: legacy %v, store %v", sha[:12], field, want, got)
	}
}

func deref(s *string) string {
	if s == nil {
		return "<nil>"
	}
	return *s
}

// laterTime returns the later of an RFC 3339 time and t, as a string.
func laterTime(at *string, t *time.Time) *string {
	if t == nil {
		return at
	}
	if at != nil {
		if parsed, err := time.Parse(time.RFC3339, *at); err == nil && parsed.After(*t) {
			return at
		}
	}
	s := t.UTC().Format(time.RFC3339)
	return &s
}

func sameInstant(a, b *string) bool {
	if a == nil || b == nil {
		return a == b
	}
	ta, errA := time.Parse(time.RFC3339, *a)
	tb, errB := time.Parse(time.RFC3339, *b)
	return errA == nil && errB == nil && ta.Truncate(time.Second).Equal(tb.Truncate(time.Second))
}

// TestStoreReleaseParity asks both layouts which file a package release names.
// The legacy choice is recordSampleByPURL's query, run over the exported rows.
//
// Both rank a release's files by level first. Among files at the same level
// the legacy query prefers the newest samples.analyzed_at and the store the
// newest scan time, which the ML result carries; where those pick different
// files the level served is the same, and the test requires exactly that.
func TestStoreReleaseParity(t *testing.T) {
	dsn := strings.TrimSpace(os.Getenv("HOPPER_PROTO_DSN"))
	if dsn == "" {
		t.Skip("HOPPER_PROTO_DSN not set (the loaded verdict prototype database)")
	}
	ctx := t.Context()
	pool, err := pgxpool.New(ctx, dsn)
	if err != nil {
		t.Fatal(err)
	}
	defer pool.Close()
	st, err := store.New(pool)
	if err != nil {
		t.Fatal(err)
	}

	rows, err := pool.Query(ctx, `SELECT DISTINCT ON (purl_base, version) purl_base, version, sha256, lvl
		FROM legacy_samples
		WHERE purl_base <> '' AND litmus_result IS NOT NULL AND cleave_result IS NOT NULL
		  AND file_type <> 'registry' AND coalesce(version, '') <> ''
		ORDER BY purl_base, version, `+purlCriticalOrder(true))
	if err != nil {
		t.Fatal(err)
	}
	defer rows.Close()
	var n, ties int
	for rows.Next() {
		var name, version, want string
		var level *int
		if err := rows.Scan(&name, &version, &want, &level); err != nil {
			t.Fatal(err)
		}
		n++
		rec, err := st.ByRelease(ctx, name, version)
		if err != nil {
			t.Errorf("%s@%s: %v", name, version, err)
			continue
		}
		if got := hex.EncodeToString(rec.SHA256); got != want {
			if !reflect.DeepEqual(level, rec.FiresAt) {
				t.Errorf("%s@%s: legacy %s, store %s, at different levels", name, version, want[:12], got[:12])
			}
			ties++
		}
	}
	if err := rows.Err(); err != nil {
		t.Fatal(err)
	}
	if n == 0 {
		t.Fatal("no releases in legacy_samples")
	}
	t.Logf("compared %d releases; %d name a different file at the same level", n, ties)
	if _, err := st.ByRelease(ctx, "pkg:npm/no-such-package", "1.0.0"); !errors.Is(err, store.ErrNotFound) {
		t.Errorf("unknown release: got %v, want ErrNotFound", err)
	}
}
