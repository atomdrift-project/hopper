package main

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/atomdrift-project/hopper"
)

// /v1/lookup from the verdict store: the artifact's own record and the
// ledger's word on it, raised by what it holds or points at that atomscan
// holds hostile or the ledger convicts at a hostile rung.
func TestLookupFromStore(t *testing.T) {
	api, _, pool := verdictAPI(t)
	ctx := t.Context()
	exec := func(sql string, args ...any) {
		t.Helper()
		if _, err := pool.Exec(ctx, sql, args...); err != nil {
			t.Fatalf("%s: %v", sql, err)
		}
	}
	file := func(bytes string, class string, firesAt int) string {
		t.Helper()
		sha := hexSum([]byte(bytes))
		exec(`INSERT INTO samples (sha256) VALUES (decode($1, 'hex'))`, sha)
		if class != "" {
			exec(`INSERT INTO verdicts (sample_id, formed_at, outcome, class, scanner_id, fires_at, ruleset)
				SELECT id, now(), 'ok', $2, 1, $3, 'r1' FROM samples WHERE sha256 = decode($1, 'hex')`,
				sha, class, firesAt)
			exec(`INSERT INTO scans (sample_id, scanned_at, ruleset) SELECT id, now(), 'r1' FROM samples WHERE sha256 = decode($1, 'hex')`, sha)
		}
		return sha
	}
	// cite records operators' claims about subject. A package claim names the
	// releases it convicts in affected; a digest needs none.
	cite := func(subject, affected string, operators ...string) {
		t.Helper()
		for _, op := range operators {
			exec(`INSERT INTO sightings (source, subject, operator, affected, claim, basis)
				VALUES ($1, $2, $1, $3, 'malicious', 'hosted')`, op, subject, affected)
		}
	}
	declare := func(sha, name, version string) {
		t.Helper()
		exec(`INSERT INTO names (name) VALUES ($1) ON CONFLICT DO NOTHING`, name)
		exec(`INSERT INTO refs (sample_id, name_id, version, kind)
			SELECT s.id, n.id, $3, 'dependency' FROM samples s, names n WHERE s.sha256 = decode($1, 'hex') AND n.name = $2`,
			sha, name, version)
	}
	get := func(sha string) (int, hopper.LookupRecord) {
		t.Helper()
		rec := httptest.NewRecorder()
		api.handleV1Lookup(rec, httptest.NewRequest(http.MethodGet, "/v1/lookup?sha256="+sha, http.NoBody))
		var out hopper.LookupRecord
		if rec.Code == http.StatusOK {
			if err := json.Unmarshal(rec.Body.Bytes(), &out); err != nil {
				t.Fatal(err)
			}
		}
		return rec.Code, out
	}

	clean := file("a clean script", "benign", -1)
	if code, r := get(clean); code != http.StatusOK || r.State != hopper.StateAnalyzed || r.FiresAt == nil || *r.FiresAt != -1 || len(r.RaisedBy) != 0 {
		t.Errorf("clean file = %d %+v, want analyzed, fires at -1, raised by nothing", code, r)
	}

	pending := hexSum([]byte("held, not scanned"))
	exec(`INSERT INTO samples (sha256) VALUES (decode($1, 'hex'))`, pending)
	if code, r := get(pending); code != http.StatusOK || r.State != hopper.StatePending {
		t.Errorf("unscanned file = %d %+v, want pending", code, r)
	}

	// An archive holding a hostile member is raised to the member's level.
	member := file("a hostile member", "hostile", 12)
	archive := file("an archive", "benign", -1)
	exec(`INSERT INTO contents (parent_id, listed_at, child_ids, paths)
		SELECT a.id, now(), ARRAY[m.id], ARRAY['lib/evil.js'] FROM samples a, samples m
		WHERE a.sha256 = decode($1, 'hex') AND m.sha256 = decode($2, 'hex')`, archive, member)
	code, r := get(archive)
	if code != http.StatusOK || r.FiresAt == nil || *r.FiresAt != 12 || len(r.RaisedBy) != 1 ||
		r.RaisedBy[0].Kind != "member" || r.RaisedBy[0].Why != hopper.RaisedDetected || *r.RaisedBy[0].SHA256 != member {
		t.Errorf("archive = %d %+v, want raised to 12 by its member, detected", code, r)
	}

	// A package declaring a release three operators convict is raised by the
	// ledger; one declaring a release a single prediction names is not.
	convicted := file("a package with a convicted dependency", "benign", -1)
	declare(convicted, "pkg:npm/evil-dep", "1.0.0")
	cite("pkg:npm/evil-dep", "1.0.0", "aikido", "socket", "osv")
	code, r = get(convicted)
	if code != http.StatusOK || r.FiresAt == nil || *r.FiresAt != 1 || len(r.RaisedBy) != 1 ||
		r.RaisedBy[0].Why != hopper.RaisedCorroborated || r.RaisedBy[0].Name != "pkg:npm/evil-dep" {
		t.Errorf("package = %d %+v, want raised to 1 by its dependency, corroborated", code, r)
	}
	other := file("a package with another release of that dependency", "benign", -1)
	declare(other, "pkg:npm/evil-dep", "1.0.1")
	if code, r := get(other); code != http.StatusOK || len(r.RaisedBy) != 0 {
		t.Errorf("package = %d %+v, want nothing raised by a release the claims do not name", code, r)
	}
	weak := file("a package with a weakly cited dependency", "benign", -1)
	declare(weak, "pkg:npm/rumoured-dep", "2.0.0")
	cite("pkg:npm/rumoured-dep", "2.0.0", "aikido")
	exec(`UPDATE sightings SET basis = 'predicted' WHERE subject = 'pkg:npm/rumoured-dep'`)
	if code, r := get(weak); code != http.StatusOK || len(r.RaisedBy) != 0 || r.FiresAt == nil || *r.FiresAt != -1 {
		t.Errorf("package = %d %+v, want nothing raised by one prediction", code, r)
	}

	// The ledger's word on the file itself tightens its own level, and a
	// digest nothing stored stands on the ledger alone.
	cited := file("a file three operators convict", "benign", -1)
	cite(cited, "", "aikido", "socket", "osv")
	if code, r := get(cited); code != http.StatusOK || r.FiresAt == nil || *r.FiresAt != 1 || len(r.RaisedBy) != 0 {
		t.Errorf("cited file = %d %+v, want its own level tightened to 1", code, r)
	}
	unseen := hexSum([]byte("bytes hopper never held"))
	cite(unseen, "", "aikido", "socket", "osv")
	if code, r := get(unseen); code != http.StatusOK || r.FiresAt == nil || *r.FiresAt != 1 || r.EngineVersion != nil {
		t.Errorf("unheld but convicted = %d %+v, want a ledger-only record at 1", code, r)
	}
	if code, _ := get(hexSum([]byte("nothing at all"))); code != http.StatusNotFound {
		t.Errorf("unknown = %d, want 404", code)
	}
}
