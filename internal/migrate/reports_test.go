package migrate

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"strings"
	"testing"
)

func digestOf(s string) string {
	sum := sha256.Sum256([]byte(s))
	return hex.EncodeToString(sum[:])
}

// A scanned file's legacy result in the version 4 shape gives a report to the
// file and to each member, keyed by digest, with placement taken out.
func TestLegacyReportsVersion4(t *testing.T) {
	gem, script := digestOf("gem"), digestOf("script")
	raw := `{"v":"4","tv":"60d49","fs":[
		{"id":0,"sha":"` + gem + `","path":"/d/x.gem","type":"gem","sz":900,"x":1,"f":"H2"},
		{"id":1,"dp":1,"sha":"` + script + `","path":"/d/x.gem!!lib/x.rb","type":"ruby","sz":94,"ss":[[8,"spec"]],
		 "ts":[{"c":0.9,"d":"a dropper","i":"objectives::dropper","l":5}]}]}`
	lines, err := legacyReports(raw, gem)
	if err != nil {
		t.Fatal(err)
	}
	if len(lines) != 2 {
		t.Fatalf("%d reports, want one for the gem and one for its member: %v", len(lines), lines)
	}
	for digest, line := range lines {
		var obj map[string]json.RawMessage
		if err := json.Unmarshal(line, &obj); err != nil {
			t.Fatalf("%s: %v", line, err)
		}
		for _, k := range []string{"id", "dp", "sha", "path", "type", "sz"} {
			if _, has := obj[k]; has {
				t.Errorf("%s: report keeps placement key %q: %s", digest[:6], k, line)
			}
		}
	}
	if got := string(lines[gem]); got != `{"f":"H2","x":1}` {
		t.Errorf("gem report %s", got)
	}
	if got := string(lines[script]); !strings.Contains(got, `"ss":[[8,"spec"]]`) || !strings.Contains(got, `"ts":[`) {
		t.Errorf("member report %s lost its strings or findings", got)
	}
}

// A current scan reports as it always did; an excerpt is not a scan's result
// and gives nothing here (the unscanned member path takes it).
func TestLegacyReportsOthers(t *testing.T) {
	sha := digestOf("a")
	v7 := `{"v":"7","files":[{"id":0,"sha":"` + sha + `","path":"p","type":"php","size":5,"mol":"Os","risk":3}]}`
	lines, err := legacyReports(v7, sha)
	if err != nil || string(lines[sha]) != `{"mol":"Os","risk":3}` {
		t.Errorf("version 7 scan: %s, %v", lines[sha], err)
	}
	excerpt := `{"v":"7","files":[{"id":3,"pid":0,"dp":1,"sha":"` + sha + `","path":"a!!b","type":"php","size":5,"mol":"Os"}]}`
	if lines, err := legacyReports(excerpt, sha); err != nil || len(lines) != 0 {
		t.Errorf("excerpt: %v, %v; want no reports", lines, err)
	}
}
