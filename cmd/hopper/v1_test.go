package main

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"net/url"
	"path/filepath"
	"strings"
	"testing"

	"github.com/atomdrift-project/hopper"
)

func newV1API(t *testing.T, ctx context.Context) *apiServer {
	t.Helper()
	db := mustOpenDB(t, ctx, filepath.Join(t.TempDir(), "hopper.db"))
	t.Cleanup(func() { db.Close() })
	if err := db.Migrate(ctx); err != nil {
		t.Fatalf("Migrate: %v", err)
	}
	return &apiServer{db: db, tracker: newWorkerTracker()}
}

func TestHandleV1Lookup(t *testing.T) {
	ctx := context.Background()
	api := newV1API(t, ctx)
	db := api.db

	sha := strings.Repeat("a", 64)
	if err := db.InsertSample(ctx, &hopper.Sample{
		SHA256: sha, Path: "incoming/evil.tgz", Source: "forager",
		Ecosystem: "npm", Package: "evil", Version: "1.0.0",
		PURLBase: "pkg:npm/evil",
	}); err != nil {
		t.Fatalf("InsertSample: %v", err)
	}
	cleave := []byte(`{"fs":[{"sha":"` + sha + `","type":"js","dp":0,"finds":[{"id":"objectives/c2/backdoor","crit":5}]}]}`)
	if err := db.UpdateCleaveResult(ctx, sha, cleave, nil, ""); err != nil {
		t.Fatalf("UpdateCleaveResult: %v", err)
	}
	if err := db.UpdateLitmusResult(ctx, sha, []byte(`{"v":"7","prob":0.99,"lvl":3,"eng":"2.8.0","analyzed_at":"2026-08-01T00:00:00Z"}`)); err != nil {
		t.Fatalf("UpdateLitmusResult: %v", err)
	}

	get := func(query string) (*httptest.ResponseRecorder, map[string]any) {
		t.Helper()
		r := httptest.NewRequest(http.MethodGet, "/v1/lookup?"+query, http.NoBody)
		rec := httptest.NewRecorder()
		api.handleV1Lookup(rec, r)
		// Asserted rather than ignored: a route that answers with something
		// other than JSON is a bug this helper would otherwise hide behind an
		// empty map, and every assertion below would then read as a missing
		// field instead of a broken response.
		body := map[string]any{}
		if rec.Body.Len() > 0 {
			if err := json.Unmarshal(rec.Body.Bytes(), &body); err != nil {
				t.Fatalf("response is not JSON: %s", rec.Body.Bytes())
			}
		}
		return rec, body
	}

	t.Run("by digest", func(t *testing.T) {
		rec, body := get("sha256=" + sha)
		if rec.Code != http.StatusOK {
			t.Fatalf("status = %d body = %s", rec.Code, rec.Body.Bytes())
		}
		if body["fires_at"] != float64(3) {
			t.Errorf("fires_at = %v, want 3", body["fires_at"])
		}
		if body["engine_version"] != "2.8.0" {
			t.Errorf("engine_version = %v", body["engine_version"])
		}
		// Every key present, so a caller writes one code path.
		for _, k := range []string{"sha256", "purl", "fires_at", "engine_version", "analyzed_at", "reason", "findings"} {
			if _, ok := body[k]; !ok {
				t.Errorf("%s is absent rather than null", k)
			}
		}
	})

	t.Run("by purl", func(t *testing.T) {
		rec, body := get("purl=" + url.QueryEscape("pkg:npm/evil@1.0.0"))
		if rec.Code != http.StatusOK {
			t.Fatalf("status = %d body = %s", rec.Code, rec.Body.Bytes())
		}
		if body["sha256"] != sha {
			t.Errorf("sha256 = %v, want %s", body["sha256"], sha)
		}
	})

	// The pkg: prefix is optional everywhere else; a caller who omits it must
	// not be told a package they can see is unknown.
	t.Run("bare purl", func(t *testing.T) {
		rec, _ := get("purl=" + url.QueryEscape("npm/evil@1.0.0"))
		if rec.Code != http.StatusOK {
			t.Fatalf("status = %d", rec.Code)
		}
	})

	t.Run("nothing stored is a 404, not an error", func(t *testing.T) {
		rec, body := get("sha256=" + strings.Repeat("b", 64))
		if rec.Code != http.StatusNotFound {
			t.Fatalf("status = %d", rec.Code)
		}
		if code := errCode(body); code != "unknown_artifact" {
			t.Errorf("code = %q", code)
		}
	})

	t.Run("naming nothing is refused", func(t *testing.T) {
		rec, body := get("")
		if rec.Code != http.StatusBadRequest {
			t.Fatalf("status = %d", rec.Code)
		}
		if code := errCode(body); code != "missing_package" {
			t.Errorf("code = %q", code)
		}
	})

	t.Run("a bad digest is refused", func(t *testing.T) {
		rec, body := get("sha256=nothex")
		if rec.Code != http.StatusBadRequest {
			t.Fatalf("status = %d", rec.Code)
		}
		if code := errCode(body); code != "invalid_sha256" {
			t.Errorf("code = %q", code)
		}
	})

	// Both keys: the digest names exact bytes, so it is asked first. A PURL
	// that resolves elsewhere must not override it.
	t.Run("the digest wins when both are given", func(t *testing.T) {
		rec, body := get("sha256=" + sha + "&purl=" + url.QueryEscape("pkg:npm/somethingelse@9.9.9"))
		if rec.Code != http.StatusOK {
			t.Fatalf("status = %d body = %s", rec.Code, rec.Body.Bytes())
		}
		if body["sha256"] != sha {
			t.Errorf("sha256 = %v, want %s", body["sha256"], sha)
		}
	})
}

// A sample hopper holds but nothing has looked at is 202, not an empty 200:
// there is an answer coming for this key, and that is worth waiting on rather
// than reading as "we looked and found nothing".
func TestHandleV1LookupHeldButUnanalyzed(t *testing.T) {
	ctx := context.Background()
	api := newV1API(t, ctx)

	sha := strings.Repeat("c", 64)
	if err := api.db.InsertSample(ctx, &hopper.Sample{
		SHA256: sha, Path: "incoming/pending.tgz", Source: "forager",
	}); err != nil {
		t.Fatalf("InsertSample: %v", err)
	}

	r := httptest.NewRequest(http.MethodGet, "/v1/lookup?sha256="+sha, http.NoBody)
	rec := httptest.NewRecorder()
	api.handleV1Lookup(rec, r)

	if rec.Code != http.StatusAccepted {
		t.Fatalf("status = %d, want 202", rec.Code)
	}
	if rec.Header().Get("Retry-After") == "" {
		t.Error("202 must say when to come back")
	}
}

func errCode(body map[string]any) string {
	e, ok := body["error"].(map[string]any)
	if !ok {
		return ""
	}
	code, ok := e["code"].(string)
	if !ok {
		return ""
	}
	return code
}

// TestHandleV1LookupBatch pins the multi-purl form scan's pre-fetch dependency
// negotiation relies on. It used to answer only the first purl= as if it were
// the whole request, so a 50-PURL batch spared the fleet at most one download.
func TestHandleV1LookupBatch(t *testing.T) {
	ctx := context.Background()
	api := newV1API(t, ctx)
	db := api.db

	insert := func(sha, pkg, version string, analyze bool) {
		t.Helper()
		if err := db.InsertSample(ctx, &hopper.Sample{
			SHA256: sha, Path: "incoming/" + pkg + ".tgz", Source: "forager",
			Ecosystem: "npm", Package: pkg, Version: version,
			PURLBase: "pkg:npm/" + pkg,
		}); err != nil {
			t.Fatalf("InsertSample: %v", err)
		}
		if !analyze {
			return
		}
		cleave := []byte(`{"fs":[{"sha":"` + sha + `","type":"js","dp":0}]}`)
		if err := db.UpdateCleaveResult(ctx, sha, cleave, nil, ""); err != nil {
			t.Fatalf("UpdateCleaveResult: %v", err)
		}
		if err := db.UpdateLitmusResult(ctx, sha, []byte(`{"v":"7","prob":0.01,"lvl":-1,"eng":"2.8.0","analyzed_at":"2026-08-01T00:00:00Z"}`)); err != nil {
			t.Fatalf("UpdateLitmusResult: %v", err)
		}
	}
	insert(strings.Repeat("1", 64), "left", "1.0.0", true)
	insert(strings.Repeat("2", 64), "right", "2.0.0", true)
	insert(strings.Repeat("3", 64), "pending", "3.0.0", false)

	get := func(purls ...string) (*httptest.ResponseRecorder, []map[string]any) {
		t.Helper()
		q := url.Values{"purl": purls}
		r := httptest.NewRequest(http.MethodGet, "/v1/lookup?"+q.Encode(), http.NoBody)
		rec := httptest.NewRecorder()
		api.handleV1Lookup(rec, r)
		var body []map[string]any
		if rec.Code == http.StatusOK {
			if err := json.Unmarshal(rec.Body.Bytes(), &body); err != nil {
				t.Fatalf("batch reply is not a JSON list: %s", rec.Body.Bytes())
			}
		}
		return rec, body
	}

	// An unknown first purl used to 404 the whole batch; the caller's spelling
	// ("npm/right" without pkg:) must come back byte-for-byte, since that is
	// what a list reply is matched by.
	rec, body := get("pkg:npm/nobody@9.9.9", "pkg:npm/left@1.0.0", "pkg:npm/pending@3.0.0", "npm/right@2.0.0")
	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d body = %s", rec.Code, rec.Body.Bytes())
	}
	var got []string
	for _, item := range body {
		got = append(got, item["purl"].(string)+"="+item["sha256"].(string)[:1])
	}
	if want := []string{"pkg:npm/left@1.0.0=1", "npm/right@2.0.0=2"}; strings.Join(got, ",") != strings.Join(want, ",") {
		t.Errorf("batch answered %v, want %v (unknown and unanalyzed omitted, order kept)", got, want)
	}
	for _, item := range body {
		if item["fires_at"] != float64(-1) {
			t.Errorf("%v: fires_at = %v, want -1", item["purl"], item["fires_at"])
		}
	}

	// Nothing known is still a list, never a 404: a caller of the batch form
	// reads one shape.
	rec, body = get("pkg:npm/nobody@1.0.0", "pkg:npm/nobody@2.0.0")
	if rec.Code != http.StatusOK || len(body) != 0 {
		t.Errorf("all-unknown batch = %d %s, want 200 []", rec.Code, rec.Body.Bytes())
	}

	// The cached record must not carry the previous caller's spelling.
	rec1, one := get("pkg:npm/left@1.0.0", "npm/left@1.0.0")
	if rec1.Code != http.StatusOK || len(one) != 2 || one[0]["purl"] == one[1]["purl"] {
		t.Errorf("two spellings of one package answered %s", rec1.Body.Bytes())
	}

	many := make([]string, v1LookupBatchMax+1)
	for i := range many {
		many[i] = "pkg:npm/left@1.0.0"
	}
	if rec, _ := get(many...); rec.Code != http.StatusBadRequest {
		t.Errorf("%d purls answered %d, want 400", len(many), rec.Code)
	}
}
