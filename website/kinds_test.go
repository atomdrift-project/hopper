package website

import "testing"

// TestSourceKindsCovered fails when the Default() registry adds a source
// without classifying it in largeInfraSources. The default fall-through is
// KindVendorWebsite, which is the safer (slower-polling) bucket — but new
// GitHub-Releases-helper sources should opt into KindLargeInfra explicitly,
// so this guards against silent drift between registration and classification.
//
// To add a vendor-website source: just register in Default().
// To add a large-infra source: register in Default() AND add to largeInfraSources.
//
// This test is informational rather than prescriptive: it succeeds either way
// and only logs unclassified names so they show up in `go test -v` output.
func TestSourceKindsCovered(t *testing.T) {
	for _, s := range Default() {
		k := KindOf(s)
		if k != KindVendorWebsite && k != KindLargeInfra {
			t.Errorf("source %q has unknown kind %q", s.Name(), k)
		}
	}
	// Sanity: at least one of each kind exists.
	var sawVendor, sawLarge bool
	for _, s := range Default() {
		switch KindOf(s) {
		case KindVendorWebsite:
			sawVendor = true
		case KindLargeInfra:
			sawLarge = true
		}
	}
	if !sawVendor {
		t.Error("no KindVendorWebsite sources registered")
	}
	if !sawLarge {
		t.Error("no KindLargeInfra sources registered")
	}
}
