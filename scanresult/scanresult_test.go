package scanresult

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"slices"
	"strings"
	"testing"
)

// result is a small archive result: a package that holds one script.
type result struct {
	header  string
	files   []map[string]any
	reports []string
}

func sum(s string) string {
	h := sha256.Sum256([]byte(s))
	return hex.EncodeToString(h[:])
}

func archive() *result {
	r := &result{
		header:  `{"v":8,"scan":{"engine":"3.0.0","ruleset":"r1","level":25,"worker":"w1","at":"2026-11-12T15:00:00Z","ms":40},"files":2}`,
		reports: []string{`{"traits":[{"id":"a::root","crit":2}]}`, `{"traits":[{"id":"b::fetch-exec","crit":5}]}`},
	}
	pkg, script := sum("package bytes"), sum("script bytes")
	r.files = []map[string]any{
		{
			"sha256": pkg, "size": 4000, "type": "npm", "report": sum(r.reports[0]),
			"verdict": map[string]any{
				"outcome": "ok", "class": "hostile", "fires_at": 12, "by": "floor", "in": script,
				"reason": "Install script fetches and runs a binary.",
				"top":    []map[string]any{{"id": "b::fetch-exec", "crit": 5}},
			},
			"ml":       map[string]any{"class": "benign", "fires_at": -1, "prob": 0.05},
			"floor":    map[string]any{"class": "hostile", "fires_at": 12, "hostile": 1},
			"contents": map[string]any{"children": []int{1}, "paths": []string{"package/install.js"}},
			"refs":     []map[string]any{{"kind": "dependency", "name": "pkg:npm/left-pad", "version": "1.3.0"}},
		},
		{
			"sha256": script, "size": 300, "type": "javascript", "report": sum(r.reports[1]),
			"verdict": map[string]any{"outcome": "ok", "class": "hostile", "fires_at": 12, "by": "floor"},
			"ml":      map[string]any{"class": "benign", "fires_at": -1, "prob": 0.04},
			"floor":   map[string]any{"class": "hostile", "fires_at": 12, "hostile": 1},
		},
	}
	return r
}

// body serializes the result as a version 8 body.
func (r *result) body(t *testing.T) *bytes.Buffer {
	t.Helper()
	var b bytes.Buffer
	b.WriteString(r.header + "\n")
	for _, f := range r.files {
		line, err := json.Marshal(f)
		if err != nil {
			t.Fatal(err)
		}
		b.Write(append(line, '\n'))
	}
	for _, report := range r.reports {
		b.WriteString(report + "\n")
	}
	return &b
}

// decodeAndCheck is what hopper does with a body: decode it, then check it.
func decodeAndCheck(body []byte) ([]File, error) {
	files, err := Decode(body)
	if err != nil {
		return nil, err
	}
	return files, Check(files)
}

func TestDecode(t *testing.T) {
	r := archive()
	files, err := decodeAndCheck(r.body(t).Bytes())
	if err != nil {
		t.Fatal(err)
	}
	if len(files) != 2 {
		t.Fatalf("%d files, want 2", len(files))
	}
	pkg, script := files[0], files[1]
	if string(pkg.ReportLine) != r.reports[0] || string(script.ReportLine) != r.reports[1] {
		t.Errorf("reports %q and %q, want them in file order", pkg.ReportLine, script.ReportLine)
	}
	if pkg.Scan.Ruleset != "r1" || !pkg.Scan.At.Equal(script.Scan.At) || pkg.Scan.At.Location().String() != "UTC" {
		t.Errorf("stamp %+v, want the header's, in UTC, on every file", pkg.Scan)
	}
	if len(pkg.Jurors) != 2 || pkg.Jurors["floor"] == nil || pkg.Jurors["ml"] == nil {
		t.Errorf("jurors %v, want floor and ml", pkg.Jurors)
	}
	if !slices.Equal(pkg.Children, []int{1}) || !slices.Equal(pkg.Paths, []string{"package/install.js"}) {
		t.Errorf("contents %v %v", pkg.Children, pkg.Paths)
	}
	if len(pkg.Refs) != 1 || pkg.Refs[0].Name != "pkg:npm/left-pad" || script.Refs != nil {
		t.Errorf("refs %v on the package, %v on the script", pkg.Refs, script.Refs)
	}
	if string(script.Ident) != "null" {
		t.Errorf("ident %s, want null: a scan that read the file and found no identity says it claims none", script.Ident)
	}
}

func TestCheckJSONB(t *testing.T) {
	for in, ok := range map[string]bool{
		`{"a":"\u00e9"}`:       true,
		`{"a":"\ud83d\ude00"}`: true,
		`{"a":"\\u0000"}`:      true, // an escaped backslash, then text
		`{"a":"\u0000"}`:       false,
		`{"a":"\ud83d"}`:       false,
		`{"a":"\ud83dx"}`:      false,
		`{"a":"\ud83d\n"}`:     false,
		`{"a":"\ude00"}`:       false,
		`{"a":"\ud83d\ud83d"}`: false,
	} {
		if err := CheckJSONB([]byte(in)); (err == nil) != ok {
			t.Errorf("CheckJSONB(%s) = %v, want ok %v", in, err, ok)
		}
	}
}

func TestDecodeRejects(t *testing.T) {
	for name, tc := range map[string]struct {
		change func(*result)
		want   string
	}{
		"wrong version":         {func(r *result) { r.header = strings.Replace(r.header, `"v":8`, `"v":7`, 1) }, "version 7"},
		"no ruleset":            {func(r *result) { r.header = strings.Replace(r.header, `"ruleset":"r1",`, "", 1) }, "scan.ruleset"},
		"unknown field":         {func(r *result) { r.files[0]["raw"] = 1 }, "unknown field"},
		"short digest":          {func(r *result) { r.files[1]["sha256"] = "abcd" }, "sha256"},
		"child out of range":    {func(r *result) { r.files[0]["contents"] = map[string]any{"children": []int{2}, "paths": []string{"a"}} }, "child 2"},
		"child is itself":       {func(r *result) { r.files[0]["contents"] = map[string]any{"children": []int{0}, "paths": []string{"a"}} }, "child 0"},
		"juror, no verdict":     {func(r *result) { delete(r.files[1], "verdict") }, "without a verdict"},
		"oversized opinion":     {func(r *result) { r.files[1]["ml"] = map[string]any{"pad": strings.Repeat("x", MaxSummary)} }, "limit"},
		"unknown outcome":       {func(r *result) { r.files[1]["verdict"] = map[string]any{"outcome": "skipped"} }, `outcome "skipped"`},
		"verdict, no class":     {func(r *result) { r.files[1]["verdict"] = map[string]any{"outcome": "ok"} }, `class ""`},
		"failed, with class":    {func(r *result) { r.files[1]["verdict"] = map[string]any{"outcome": "error", "class": "benign"} }, "on outcome"},
		"failed, with jurors":   {func(r *result) { r.files[1]["verdict"] = map[string]any{"outcome": "timeout", "error": "60s"} }, "did not succeed"},
		"reference to a path":   {func(r *result) { r.files[0]["refs"] = []map[string]any{{"kind": "dependency", "name": "../x"}} }, "neither a PURL"},
		"unknown ref kind":      {func(r *result) { r.files[0]["refs"] = []map[string]any{{"kind": "import", "name": "pkg:npm/x"}} }, "kind"},
		"refs on a member":      {func(r *result) { r.files[1]["refs"] = []map[string]any{} }, "member's line"},
		"llm on a member":       {func(r *result) { r.files[1]["llm"] = map[string]any{"class": "benign"} }, "member's line"},
		"drift_llm on a member": {func(r *result) { r.files[1]["drift_llm"] = map[string]any{"class": "benign"} }, "member's line"},
		"scanners on a member":  {func(r *result) { r.files[1]["scanners"] = map[string]any{} }, "member's line"},
		"the old drift juror":   {func(r *result) { r.files[0]["drift"] = map[string]any{"class": "benign"} }, "unknown field"},
		"unknown scanner": {func(r *result) {
			r.files[0]["scanners"] = map[string]any{"norton": map[string]any{"outcome": "ok", "class": "benign"}}
		}, "scanners: norton: not a scanner hopper knows"},
		"scanner without a class": {func(r *result) {
			r.files[0]["scanners"] = map[string]any{"clamav": map[string]any{"outcome": "ok"}}
		}, `scanners: clamav: class ""`},
		"scanner with a report": {func(r *result) {
			r.files[0]["scanners"] = map[string]any{"malcontent": map[string]any{"class": "benign", "report": sum("x")}}
		}, "report is not stored yet"},
		"digest on a package": {func(r *result) {
			r.files[0]["refs"] = []map[string]any{{"kind": "dependency", "name": "pkg:npm/x", "sha256": sum("x")}}
		}, "sha256 on a dependency"},
		"short URL digest": {func(r *result) {
			r.files[0]["refs"] = []map[string]any{{"kind": "url_fetch", "name": "https://x", "sha256": "ab"}}
		}, "not a sha256"},
		"too many members": {func(r *result) {
			r.files[0]["contents"] = map[string]any{"children": slices.Repeat([]int{1}, MaxMembers+1), "paths": slices.Repeat([]string{"a"}, MaxMembers+1)}
		}, fmt.Sprintf("limit %d", MaxMembers)},
		"ident is not an object": {func(r *result) { r.files[1]["ident"] = "tool" }, "ident: not a JSON object"},
		"oversized ident":        {func(r *result) { r.files[1]["ident"] = map[string]any{"pad": strings.Repeat("x", MaxIdent)} }, "ident: 8"},
		"NUL in an ident": {func(r *result) {
			r.files[1]["ident"] = map[string]any{"name": map[string]any{"value": "a\x00b"}}
		}, "ident: holds a NUL"},
		"NUL in a verdict": {func(r *result) {
			r.files[1]["verdict"] = map[string]any{"outcome": "ok", "class": "benign", "reason": "a\x00b"}
		}, "verdict: holds a NUL"},
		"fewer files": {func(r *result) { r.files = r.files[:1]; r.reports = nil }, ""},
		"repeated digest": {func(r *result) {
			r.files[1]["sha256"] = r.files[0]["sha256"]
			r.files[0]["contents"] = map[string]any{"children": []int{}, "paths": []string{}}
		}, "repeats"},
		"report does not match": {func(r *result) { r.reports[1] = `{"traits":[]}` }, "report hashes to"},
		"missing report":        {func(r *result) { r.reports = r.reports[:1] }, "report of file 1"},
		"trailing bytes":        {func(r *result) { r.reports = append(r.reports, "{}") }, "after the last report"},
		"half a surrogate": {func(r *result) {
			r.files[1]["verdict"] = json.RawMessage(`{"outcome":"ok","class":"benign","reason":"\ud800"}`)
		}, "surrogate"},
		"oversized engine": {func(r *result) {
			r.header = strings.Replace(r.header, `"engine":"3.0.0"`, `"engine":"`+strings.Repeat("x", MaxStamp+1)+`"`, 1)
		}, "engine"},
		"unbounded count": {func(r *result) { r.header = strings.Replace(r.header, `"files":2`, `"files":999999`, 1) }, "file 2"},
		// fires_at is a smallint column: what it cannot hold is refused here,
		// not by the database on every retry.
		"fractional level": {func(r *result) { r.files[1]["ml"] = json.RawMessage(`{"class":"benign","fires_at":12.5}`) }, "ml: fires_at 12.5"},
		"level below -1":   {func(r *result) { r.files[1]["floor"] = map[string]any{"class": "benign", "fires_at": -2} }, "floor: fires_at -2"},
		"level too large": {func(r *result) {
			r.files[1]["verdict"] = map[string]any{"outcome": "ok", "class": "benign", "fires_at": 40000}
		}, "verdict: fires_at 40000"},
		"level as text": {func(r *result) {
			r.files[0]["scanners"] = map[string]any{"clamav": map[string]any{"class": "benign", "fires_at": "3"}}
		}, `fires_at "3"`},
	} {
		t.Run(name, func(t *testing.T) {
			r := archive()
			tc.change(r)
			_, err := decodeAndCheck(r.body(t).Bytes())
			if err == nil || !strings.Contains(err.Error(), tc.want) || !errors.Is(err, ErrMalformed) {
				t.Errorf("got error %v, want ErrMalformed containing %q", err, tc.want)
			}
		})
	}
}
