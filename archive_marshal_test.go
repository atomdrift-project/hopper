package hopper

import (
	"encoding/json"
	"testing"
)

// nestedMarshalEnvelope is the three-pass spelling marshalEnvelope replaced. It
// exists only so the test can assert the two produce identical bytes.
func nestedMarshalEnvelope(top map[string]json.RawMessage, name string, sec fileSection) []byte {
	obj := make(map[string]json.RawMessage, len(sec.obj)+1)
	for k, v := range sec.obj {
		obj[k] = v
	}
	obj[sec.key] = mustMarshal(sec.files)
	t2 := make(map[string]json.RawMessage, len(top))
	for k, v := range top {
		t2[k] = v
	}
	t2[name] = mustMarshal(obj)
	return mustMarshal(t2)
}

// TestMarshalEnvelopeMatchesNestedMarshal is the guarantee the optimisation
// rests on: collapsing three encoder passes into one must not change a single
// byte, because these envelopes are stored and compared.
func TestMarshalEnvelopeMatchesNestedMarshal(t *testing.T) {
	cases := []struct {
		name string
		top  map[string]json.RawMessage
		sec  fileSection
	}{
		{
			name: "plain",
			top: map[string]json.RawMessage{
				"version": json.RawMessage(`2`),
				"sha256":  json.RawMessage(`"abc"`),
			},
			sec: fileSection{
				obj:   map[string]json.RawMessage{"tool": json.RawMessage(`"cleave"`)},
				key:   "files",
				files: []json.RawMessage{json.RawMessage(`{"id":1}`), json.RawMessage(`{"id":2}`)},
			},
		},
		{
			// Whitespace in the inputs is where a compaction difference would
			// show up if the two paths ever diverged.
			name: "uncompacted input",
			top: map[string]json.RawMessage{
				"meta": json.RawMessage("{\n  \"a\" : 1\n}"),
			},
			sec: fileSection{
				obj:   map[string]json.RawMessage{"note": json.RawMessage(`  "spaced"  `)},
				key:   "fs",
				files: []json.RawMessage{json.RawMessage("{\n \"id\" : 7 }")},
			},
		},
		{
			// HTML-escapable bytes: encoding/json escapes <, > and & in strings.
			name: "html escaping",
			top: map[string]json.RawMessage{
				"q": json.RawMessage(`"a<b>c&d"`),
			},
			sec: fileSection{
				obj:   map[string]json.RawMessage{"path": json.RawMessage(`"x<y"`)},
				key:   "files",
				files: []json.RawMessage{json.RawMessage(`{"n":"p&q"}`)},
			},
		},
		{
			name: "empty file list",
			top:  map[string]json.RawMessage{"version": json.RawMessage(`1`)},
			sec:  fileSection{obj: map[string]json.RawMessage{}, key: "files"},
		},
		{
			name: "many keys forces sort order",
			top: map[string]json.RawMessage{
				"zeta": json.RawMessage(`1`), "alpha": json.RawMessage(`2`),
				"mid": json.RawMessage(`3`), "Beta": json.RawMessage(`4`),
			},
			sec: fileSection{
				obj: map[string]json.RawMessage{
					"z": json.RawMessage(`1`), "a": json.RawMessage(`2`), "m": json.RawMessage(`3`),
				},
				key:   "files",
				files: []json.RawMessage{json.RawMessage(`{"k":"v"}`)},
			},
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			want := nestedMarshalEnvelope(tc.top, "raw", tc.sec)
			got, err := marshalEnvelope(tc.top, "raw", tc.sec)
			if err != nil {
				t.Fatalf("marshalEnvelope: %v", err)
			}
			if string(got) != string(want) {
				t.Errorf("single-pass output differs:\n got: %s\nwant: %s", got, want)
			}
		})
	}
}

// TestMarshalSectionMatchesNestedMarshal covers the file-list-untouched variant.
func TestMarshalSectionMatchesNestedMarshal(t *testing.T) {
	top := map[string]json.RawMessage{
		"version": json.RawMessage(`2`),
		"sha256":  json.RawMessage(`"deadbeef"`),
	}
	obj := map[string]json.RawMessage{
		"files":         json.RawMessage(`[{"id":1}]`),
		"omitted_files": json.RawMessage(`3`),
	}

	t2 := make(map[string]json.RawMessage, len(top))
	for k, v := range top {
		t2[k] = v
	}
	t2["raw"] = mustMarshal(obj)
	want := mustMarshal(t2)

	got, err := marshalSection(top, "raw", obj)
	if err != nil {
		t.Fatalf("marshalSection: %v", err)
	}
	if string(got) != string(want) {
		t.Errorf("differs:\n got: %s\nwant: %s", got, want)
	}
}

func benchSection(members int) (map[string]json.RawMessage, fileSection) {
	files := make([]json.RawMessage, members)
	for i := range files {
		files[i] = json.RawMessage(`{"id":"member","sha256":"0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef","depth":1,"path":"usr/lib/x.so","traits":["elf","stripped"]}`)
	}
	top := map[string]json.RawMessage{
		"version": json.RawMessage(`2`),
		"sha256":  json.RawMessage(`"deadbeef"`),
	}
	return top, fileSection{
		obj:   map[string]json.RawMessage{"tool": json.RawMessage(`"cleave"`)},
		key:   "files",
		files: files,
	}
}

func BenchmarkNestedMarshalEnvelope(b *testing.B) {
	top, sec := benchSection(2000)
	b.ReportAllocs()
	for b.Loop() {
		_ = nestedMarshalEnvelope(top, "raw", sec)
	}
}

func BenchmarkMarshalEnvelopeSinglePass(b *testing.B) {
	top, sec := benchSection(2000)
	b.ReportAllocs()
	for b.Loop() {
		if _, err := marshalEnvelope(top, "raw", sec); err != nil {
			b.Fatal(err)
		}
	}
}
