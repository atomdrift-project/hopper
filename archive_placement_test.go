package hopper

import (
	"encoding/json"
	"testing"
)

func TestSplitJoinDuplicateSHAKeepsOccurrencePlacement(t *testing.T) {
	// The same bytes occur under two parents with different participation metadata.
	// A lookup keyed by SHA returns one leaf for both occurrences.
	envelope := []byte(`{"raw":{"v":"8","files":[
  {"id":0,"path":"outer","sha":"root","type":"zip"},
  {"id":1,"path":"outer!!nested","sha":"container","type":"zip","depth":1,"pid":0},
  {"id":2,"path":"outer!!x","sha":"shared","type":"pe","depth":1,"pid":0,"traits":[{"id":"x","crit":3,"conf":1}]},
  {"id":3,"path":"outer!!nested!!x","sha":"shared","type":"pe","depth":2,"pid":1,"rel":"fetched","via":"https://example.invalid/x","role":"sidecar","traits":[{"id":"x","crit":3,"conf":1}]}
 ]}}`)
	joined, leaves := roundTrip(t, envelope)
	assertJSONEqual(t, envelope, joined)
	var shared [][]byte
	for _, leaf := range leaves {
		if leaf.SHA256 == "shared" {
			shared = append(shared, leaf.Envelope)
		}
	}
	if len(shared) != 2 {
		t.Fatalf("want two shared occurrences, got %d", len(shared))
	}
	if !jsonEqual(shared[0], shared[1]) {
		t.Fatal("occurrence placement leaked into canonical leaves")
	}
	parent, _, err := Split(envelope)
	if err != nil {
		t.Fatal(err)
	}
	compacted, count, err := splitParentOnly(envelope)
	if err != nil {
		t.Fatal(err)
	}
	if count != 3 || !jsonEqual(parent, compacted) {
		t.Fatal("storage parent plan disagrees with Split")
	}
}

func TestRestorePlacementOverwritesLegacyLeafFields(t *testing.T) {
	// Old leaves retained these fields. An explicit modern reference wins.
	ref := map[string]json.RawMessage{
		"id": json.RawMessage(`3`), "depth": json.RawMessage(`2`),
		"path": json.RawMessage(`"correct"`), "pid": json.RawMessage(`1`), "rel": json.RawMessage(`"unpacked"`),
		"via": json.RawMessage(`"correct-locator"`), "role": json.RawMessage(`"content"`),
	}
	leaf := []byte(`{"raw":{"files":[{"sha":"shared","pid":99,"rel":"fetched","via":"wrong","role":"sidecar"}]}}`)
	restored, err := restoreMember(ref, leaf)
	if err != nil {
		t.Fatal(err)
	}
	assertJSONEqual(t, []byte(`{"id":3,"depth":2,"path":"correct","sha":"shared","pid":1,"rel":"unpacked","via":"correct-locator","role":"content"}`), restored)
}

func TestRestoreOptionalPlacementAndLegacyReferences(t *testing.T) {
	leaf := []byte(`{"raw":{"files":[{"sha":"shared","pid":99,"rel":"fetched","via":"old","role":"sidecar"}]}}`)
	modern := map[string]json.RawMessage{
		"id": json.RawMessage(`3`), "depth": json.RawMessage(`2`),
		"path": json.RawMessage(`"correct"`), "pid": json.RawMessage(`1`),
	}
	restored, err := restoreMember(modern, leaf)
	if err != nil {
		t.Fatal(err)
	}
	assertJSONEqual(t, []byte(`{"id":3,"depth":2,"path":"correct","sha":"shared","pid":1}`), restored)
	// Old references omitted all four new placement fields. Keep the leaf's
	// values because those references cannot tell us their original placement.
	delete(modern, "pid")
	restored, err = restoreMember(modern, leaf)
	if err != nil {
		t.Fatal(err)
	}
	assertJSONEqual(t, []byte(`{"id":3,"depth":2,"path":"correct","sha":"shared","pid":99,"rel":"fetched","via":"old","role":"sidecar"}`), restored)
}
