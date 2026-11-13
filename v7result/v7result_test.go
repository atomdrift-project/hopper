package v7result

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"os"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/atomdrift-project/hopper/scanresult"
	"github.com/atomdrift-project/hopper/store"
	"github.com/jackc/pgx/v5/pgxpool"
)

// level is scan's shipped default, DEFAULT_SEVERITY_LEVEL.
const level = 25

func digest(s string) string {
	h := sha256.Sum256([]byte(s))
	return hex.EncodeToString(h[:])
}

// A package holding a script and a nested tarball, with a registry sidecar
// and a fetched dependency whose own contents sit under it.
func sampleResult() (r *Result, sha map[string]string) {
	sha = map[string]string{}
	for _, n := range []string{"pkg", "script", "tar", "inner", "registry", "dep", "depfile"} {
		sha[n] = digest(n)
	}
	raw := fmt.Sprintf(`{"v":"8","rev":"r7","files":[
		{"id":0,"depth":0,"sha":%q,"path":"pkg.tgz","type":"npm","size":900,"traits":[
			{"id":"a::low","crit":2,"conf":1.0,"desc":"<script> & co","from":[{"file":0,"off":3},{"file":1,"line":2},{"file":99}]},
			{"id":"fetch/dependency-verdict","crit":5,"dep":{"locator":"pkg:npm/left-pad@1.3.0"}}]},
		{"id":1,"pid":0,"depth":1,"sha":%q,"path":"pkg.tgz!!package/install.js","type":"javascript","size":40,
		 "traits":[{"id":"b::fetch","crit":5},{"id":"b::hide","crit":4}],"refs":[{"to":"https://evil.example/x.sh","kind":"url_fetch"},{"to":"pkg:npm/is-odd?vers=vers:npm/%%5E3.0.0","kind":"dependency"}]},
		{"id":2,"pid":0,"depth":1,"sha":%q,"path":"pkg.tgz!!package/vendor.tar","type":"tar","size":300,
			"ident":{"name":{"value":"vendor","source":"tar.header"},"trust":"unsigned"}},
		{"id":3,"pid":2,"depth":2,"sha":%q,"path":"pkg.tgz!!package/vendor.tar!!lib/a.py","type":"python","size":20},
		{"id":4,"pid":0,"depth":1,"sha":%q,"path":"pkg.tgz!!registry.json","type":"registry","rel":"registry","size":10},
		{"id":5,"pid":0,"depth":1,"sha":%q,"path":"pkg:npm/left-pad@1.3.0","type":"npm","rel":"fetched","size":70},
		{"id":6,"pid":5,"depth":2,"sha":%q,"path":"pkg:npm/left-pad@1.3.0!!package/index.js","type":"javascript","size":30}],
		"fetched":[{"kind":"dependency","locator":"pkg:npm/left-pad@1.3.0","source_sha256":%q}]}`,
		sha["pkg"], sha["script"], sha["tar"], sha["inner"], sha["registry"], sha["dep"], sha["depfile"], sha["pkg"])
	return &Result{
		At: time.Date(2026, 11, 12, 15, 0, 0, 0, time.UTC), SHA256: sha["pkg"], Worker: "w1",
		ML: json.RawMessage(`{"v":"7","prob":0.97,"lvl":12,"version":"m1","eng":"2.12.0","analyzed_at":"2026-11-12T14:00:00Z",
			"files":[{"id":0,"verdict":{"prob":0.97,"lvl":12}},{"id":1,"verdict":{"prob":0.99,"lvl":3}}]}`),
		LLM: json.RawMessage(`{"grade":"hostile","conf":0.9,"interpretation":"Fetches and runs a script.","model":"g1",
			"before":{"lvl":900,"prob":0.4}}`),
		Raw: json.RawMessage(raw),
	}, sha
}

func TestConvert(t *testing.T) {
	r, sha := sampleResult()
	got, err := Convert(r, level)
	if err != nil {
		t.Fatal(err)
	}
	idx := map[string]int{}
	for i, f := range got.Files {
		idx[hex.EncodeToString(f.SHA256)] = i
	}
	if _, ok := idx[sha["registry"]]; ok {
		t.Error("the registry sidecar became a file")
	}
	if len(got.Files) != 6 {
		t.Fatalf("%d files, want 6", len(got.Files))
	}
	if err := scanresult.Check(got.Files); err != nil {
		t.Fatalf("the converted result does not pass the version 8 checks: %v", err)
	}
	contents := func(name string) []string {
		f := got.Files[idx[sha[name]]]
		var out []string
		for i, c := range f.Children {
			out = append(out, f.Paths[i]+"="+hex.EncodeToString(got.Files[c].SHA256)[:6])
		}
		return out
	}
	for name, want := range map[string][]string{
		"pkg": {"package/install.js=" + sha["script"][:6], "package/vendor.tar=" + sha["tar"][:6]},
		"tar": {"lib/a.py=" + sha["inner"][:6]},
		"dep": {"package/index.js=" + sha["depfile"][:6]},
	} {
		if c := contents(name); !slices.Equal(c, want) {
			t.Errorf("%s contents %v, want %v", name, c, want)
		}
	}
	// Every reference is the artifact's, whichever file declared it.
	if refs := got.Files[idx[sha["pkg"]]].Refs; !slices.Equal(refs, []scanresult.Ref{
		{Kind: "dependency", Name: "pkg:npm/left-pad", Version: "1.3.0"},
		{Kind: "dependency", Name: "pkg:npm/is-odd", Requested: "vers:npm/^3.0.0"},
	}) {
		t.Errorf("pkg refs %+v", refs)
	}
	for i, f := range got.Files[1:] {
		if f.Refs != nil {
			t.Errorf("file %d refs %+v: a member's line states none", i+1, f.Refs)
		}
	}
	// What a file says it is goes with the file; one that says nothing is
	// left as it was, since an old report cannot tell that from not looking.
	if claim, err := scanresult.ClaimOf(got.Files[idx[sha["tar"]]].Ident); err != nil || claim.Name != "vendor" {
		t.Errorf("tar claims %+v, %v", claim, err)
	}
	if ident := got.Files[idx[sha["script"]]].Ident; ident != nil {
		t.Errorf("script ident %s, want none stated", ident)
	}

	root := got.Files[0]
	if root.Scan.Ruleset != "r7" || root.Scan.Engine != "2.12.0" || root.Scan.At.Hour() != 14 {
		t.Errorf("stamp %+v", root.Scan)
	}
	for name, want := range map[string]string{
		"verdict": `{"fires_at":12,"outcome":"ok","class":"hostile","reason":"Fetches and runs a script."}`,
		"ml":      `{"fires_at":900,"prob":0.4,"class":"suspicious","model":"m1"}`,
		"llm":     `{"conf":0.9,"class":"hostile","model":"g1","reason":"Fetches and runs a script."}`,
	} {
		obj := root.Verdict
		if name != "verdict" {
			obj = root.Jurors[name]
		}
		if string(obj) != want {
			t.Errorf("root %s %s, want %s", name, obj, want)
		}
	}
	if _, ok := root.Jurors["floor"]; ok {
		t.Error("root floor juror without a finding at crit 4 or 5")
	}
	script := got.Files[idx[sha["script"]]]
	if string(script.Jurors["floor"]) != `{"class":"hostile","hostile":1,"suspicious":1}` {
		t.Errorf("script floor %s", script.Jurors["floor"])
	}
	if !strings.Contains(string(script.Verdict), `"class":"hostile"`) || !strings.Contains(string(script.Jurors["ml"]), `"fires_at":3`) {
		t.Errorf("script verdict %s, ml %s", script.Verdict, script.Jurors["ml"])
	}
	if _, ok := got.Files[idx[sha["inner"]]].Jurors["ml"]; ok {
		t.Error("a member with no ML entry got an ml juror")
	}
	for i, f := range got.Files {
		if f.ReportLine == nil {
			t.Errorf("file %d has no report", i)
		}
	}
	// Every report is the version 8 one: the file's own entry, keys sorted,
	// with nothing that says where it sat or which run produced it, so the
	// same file in another archive gives the same report. A source in this
	// file cites nothing, one in another file its sha256, one naming no file
	// is dropped; a dependency's pinned verdict leaves; numbers and text are
	// written as they came.
	for name, want := range map[string]string{
		"pkg": `{"traits":[{"conf":1.0,"crit":2,"desc":"<script> & co","from":[{"off":3},{"line":2,"sha256":"` + sha["script"] + `"}],"id":"a::low"}]}`,
		"script": `{"refs":[{"kind":"url_fetch","to":"https://evil.example/x.sh"},{"kind":"dependency","to":"pkg:npm/is-odd?vers=vers:npm/%5E3.0.0"}],` +
			`"traits":[{"crit":5,"id":"b::fetch"},{"crit":4,"id":"b::hide"}]}`,
		"tar": `{}`, // its identity is on its file line
	} {
		if report := string(got.Files[idx[sha[name]]].ReportLine); report != want {
			t.Errorf("%s report %s, want %s", name, report, want)
		}
	}
}

// The oldest reports use another schema. Their verdict and jurors are
// converted; the report is left out rather than passed on in a shape no
// version 8 reader knows.
func TestConvertOldestReport(t *testing.T) {
	sha := digest("old")
	got, err := Convert(&Result{
		At: time.Date(2026, 1, 2, 3, 4, 5, 0, time.UTC), SHA256: sha, Worker: "w1",
		ML:  json.RawMessage(`{"prob":0.1,"lvl":-1}`),
		Raw: json.RawMessage(`{"v":"5","fs":[{"id":0,"sz":10,"sha":"` + sha + `","path":"x","type":"unknown"}],"tv":"60d49"}`),
	}, level)
	if err != nil {
		t.Fatal(err)
	}
	if len(got.Files) != 1 || got.Files[0].Report != nil || got.Files[0].ReportLine != nil || got.Omitted["report older than version 6"] != 1 {
		t.Fatalf("files %+v, omitted %v; want one file with no report", got.Files, got.Omitted)
	}
	if !strings.Contains(string(got.Files[0].Verdict), `"class":"benign"`) || got.Files[0].Jurors["ml"] == nil {
		t.Errorf("verdict %s, jurors %v", got.Files[0].Verdict, got.Files[0].Jurors)
	}
}

func TestClass(t *testing.T) {
	for _, tc := range []struct {
		level, fires int
		want         string
	}{
		{25, -1, "benign"},
		{25, 0, "hostile"},
		{25, 25, "hostile"},
		{25, 26, "suspicious"},
		{25, 2500, "suspicious"},
		{25, 2501, "benign"},
		{25, 25001, "suspicious"},
		{25, 25002, "suspicious"},
		{0, 500, "suspicious"},
		{0, 501, "benign"},
		{300, 25000, "suspicious"},
		{300, 25003, "benign"},
	} {
		c := &converter{level: tc.level}
		if got := c.class(&tc.fires); got != tc.want {
			t.Errorf("L%d firing at %d: %q, want %q", tc.level, tc.fires, got, tc.want)
		}
	}
	if got := (&converter{level: 25}).class(nil); got != "" {
		t.Errorf("no level: %q, want no class", got)
	}
}

func TestConvertUnsupported(t *testing.T) {
	sha := digest("blob")
	got, err := Convert(&Result{SHA256: sha, Raw: json.RawMessage(`{"files":[{"id":0,"depth":0,"sha":"` + sha + `","type":""}]}`)}, level)
	if err != nil {
		t.Fatal(err)
	}
	if len(got.Files) != 1 || string(got.Files[0].Verdict) != `{"outcome":"unsupported"}` || got.Files[0].Report != nil {
		t.Errorf("%+v", got.Files)
	}
}

func TestConvertRejectsWrongRoot(t *testing.T) {
	r, _ := sampleResult()
	r.SHA256 = digest("something else")
	if _, err := Convert(r, level); err == nil || !strings.Contains(err.Error(), "describes") {
		t.Errorf("got %v, want a root mismatch", err)
	}
}

// TestConvertLegacyRows converts every exported top-level row as if a worker
// had uploaded it, writes the result through the store into a fresh schema,
// and compares each archive's members with the prototype loader's.
//
//	HOPPER_PROTO_DSN='host=/tmp/hopper-schema-prototype/v2 port=5499 user=proto dbname=proto' \
//	HOPPER_TEST_PG_DSN='postgres://proto@/proto?host=/tmp/hopper-schema-prototype/v2&port=5499' go test ./v7result
func TestConvertLegacyRows(t *testing.T) {
	protoDSN, testDSN := os.Getenv("HOPPER_PROTO_DSN"), os.Getenv("HOPPER_TEST_PG_DSN")
	if protoDSN == "" || testDSN == "" || strings.Contains(testDSN, "hopper-db") {
		t.Skip("HOPPER_PROTO_DSN and HOPPER_TEST_PG_DSN (disposable) are needed")
	}
	ctx := t.Context()
	proto, err := pgxpool.New(ctx, protoDSN)
	if err != nil {
		t.Fatal(err)
	}
	defer proto.Close()
	st, pool := freshStore(t, testDSN)

	rows, err := proto.Query(ctx, `SELECT sha256, cleave_result::text, litmus_result::text, llm_result::text,
		coalesce(traits_version, ''), coalesce(analyzed_at, created_at)
		FROM legacy_samples WHERE parent = '' AND cleave_result IS NOT NULL ORDER BY id`)
	if err != nil {
		t.Fatal(err)
	}
	var (
		results, files, reports int
		omitted                 = map[string]int{}
		elapsed                 time.Duration
	)
	for rows.Next() {
		var r Result
		var raw string
		var litmus, interp *string
		if err := rows.Scan(&r.SHA256, &raw, &litmus, &interp, &r.Ruleset, &r.At); err != nil {
			t.Fatal(err)
		}
		r.Raw = json.RawMessage(raw)
		if litmus != nil {
			r.ML = json.RawMessage(*litmus)
		}
		if interp != nil {
			r.LLM = json.RawMessage(*interp)
		}
		c, err := Convert(&r, level)
		if err != nil {
			t.Fatalf("%s: %v", r.SHA256, err)
		}
		start := time.Now()
		if _, err := st.Write(ctx, c.Files); err != nil {
			t.Fatalf("%s: write: %v", r.SHA256, err)
		}
		elapsed += time.Since(start)
		results, files = results+1, files+len(c.Files)
		for i := range c.Files {
			if c.Files[i].ReportLine != nil {
				reports++
			}
		}
		for k, v := range c.Omitted {
			omitted[k] += v
		}
	}
	if err := rows.Err(); err != nil {
		t.Fatal(err)
	}
	rows.Close()
	t.Logf("%d results, %d files, %d reports written in %v (%.0f µs per file)",
		results, files, reports, elapsed.Round(time.Millisecond), float64(elapsed.Microseconds())/float64(max(files, 1)))
	for k, v := range omitted {
		t.Logf("omitted %d: %s", v, k)
	}

	// The prototype loader's members, by digest, for the archives written here.
	edges := func(p *pgxpool.Pool) map[string]bool {
		rows, err := p.Query(ctx, `SELECT encode(ps.sha256, 'hex'), m.path, encode(cs.sha256, 'hex')
			FROM contents c JOIN samples ps ON ps.id = c.parent_id,
			     unnest(c.child_ids, c.paths) AS m(child_id, path) JOIN samples cs ON cs.id = m.child_id`)
		if err != nil {
			t.Fatal(err)
		}
		out := map[string]bool{}
		var parent, path, child string
		for rows.Next() {
			if err := rows.Scan(&parent, &path, &child); err != nil {
				t.Fatal(err)
			}
			out[parent+" "+path+" "+child] = true
		}
		if err := rows.Err(); err != nil {
			t.Fatal(err)
		}
		return out
	}
	got, want := edges(pool), edges(proto)
	// The prototype filed fetched dependencies from reports that lack
	// rel=fetched as members; the converter makes them references.
	var deps int
	for e := range want {
		if _, path, _ := strings.Cut(e, " "); !strings.Contains(path, "!!") && (strings.HasPrefix(path, "pkg:") || strings.HasPrefix(path, "http://") || strings.HasPrefix(path, "https://")) {
			delete(want, e)
			deps++
		}
	}
	t.Logf("%d prototype members are fetched dependencies, now references", deps)
	var missing, extra int
	for e := range want {
		if !got[e] {
			missing++
			if missing <= 4 {
				t.Logf("missing %s", e)
			}
		}
	}
	for e := range got {
		if !want[e] {
			extra++
			if extra <= 4 {
				t.Logf("extra   %s", e)
			}
		}
	}
	// A container named by several results keeps the list of the last one
	// written, where the prototype took the union of every stored scan.
	t.Logf("members: %d written, %d in the prototype, %d missing, %d extra", len(got), len(want), missing, extra)
	if extra > 0 || float64(missing) > 0.01*float64(len(want)) {
		t.Errorf("member lists diverge from the prototype loader's")
	}
}

func freshStore(t *testing.T, dsn string) (*store.Store, *pgxpool.Pool) {
	t.Helper()
	ctx := t.Context()
	cfg, err := pgxpool.ParseConfig(dsn)
	if err != nil {
		t.Fatal(err)
	}
	schema := fmt.Sprintf("v7_%d", time.Now().UnixNano())
	cfg.ConnConfig.RuntimeParams["search_path"] = schema
	pool, err := pgxpool.NewWithConfig(ctx, cfg)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		if _, err := pool.Exec(context.WithoutCancel(ctx), "DROP SCHEMA "+schema+" CASCADE"); err != nil {
			t.Errorf("drop schema: %v", err)
		}
		pool.Close()
	})
	for _, ddl := range []string{"CREATE SCHEMA " + schema, store.Schema} {
		if _, err := pool.Exec(ctx, ddl); err != nil {
			t.Fatal(err)
		}
	}
	st, err := store.New(pool)
	if err != nil {
		t.Fatal(err)
	}
	return st, pool
}

func TestSplitLocator(t *testing.T) {
	for _, tc := range []struct{ loc, name, version, requested string }{
		{"pkg:npm/left-pad@1.3.0", "pkg:npm/left-pad", "1.3.0", ""},
		{"pkg:npm/%40scope/x@2.0.0#lib", "pkg:npm/%40scope/x", "2.0.0", ""},
		{"pkg:cargo/itoa?version_requirement=1.0", "pkg:cargo/itoa", "", "1.0"},
		{"pkg:cargo/windows-sys?version_requirement=%3E%3D0.52%2C%20%3C0.62", "pkg:cargo/windows-sys", "", ">=0.52, <0.62"},
		{"pkg:npm/semver?vers=vers:npm/%5E1.0.0%2Bbuild", "pkg:npm/semver", "", "vers:npm/^1.0.0+build"},
		{"pkg:cargo/libc@0.2.191?checksum=sha256:65cd", "pkg:cargo/libc", "0.2.191", ""},
		{"pkg:cargo/serde@1.0.228?version_requirement=1.0.228", "pkg:cargo/serde", "1.0.228", ""},
		{"https://example.com/x.sh?a=1", "https://example.com/x.sh?a=1", "", ""},
		{"./local", "", "", ""},
	} {
		name, version, requested := splitLocator(tc.loc)
		if name != tc.name || version != tc.version || requested != tc.requested {
			t.Errorf("splitLocator(%q) = %q, %q, %q; want %q, %q, %q",
				tc.loc, name, version, requested, tc.name, tc.version, tc.requested)
		}
	}
}

// The interpreter's text arrives at whatever length the worker sent; the
// converted verdict must still pass the version 8 checks, or the result would
// be refused on every retry.
func TestConvertClipsInterpretation(t *testing.T) {
	sha := digest("old")
	got, err := Convert(&Result{
		At: time.Date(2026, 1, 2, 3, 4, 5, 0, time.UTC), SHA256: sha, Worker: "w1", Ruleset: "r1",
		ML:  json.RawMessage(`{"prob":0.1,"lvl":-1}`),
		LLM: json.RawMessage(`{"grade":"hostile","interpretation":"` + strings.Repeat("é", 2000) + `\u0000"}`),
		Raw: json.RawMessage(`{"v":"5","fs":[{"id":0,"sz":10,"sha":"` + sha + `","path":"x","type":"unknown"}],"tv":"60d49"}`),
	}, level)
	if err != nil {
		t.Fatal(err)
	}
	if err := scanresult.Check(got.Files); err != nil {
		t.Fatalf("converted verdict refused: %v", err)
	}
	if !strings.Contains(string(got.Files[0].Verdict), `"reason":"éé`) {
		t.Errorf("verdict %s lost the reason", got.Files[0].Verdict)
	}
}
