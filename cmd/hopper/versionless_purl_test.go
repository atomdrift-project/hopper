package main

import "testing"

func TestVersionlessPURL(t *testing.T) {
	cases := map[string]string{
		"pkg:npm/lodash@4.17.21":         "pkg:npm/lodash",
		"pkg:npm/@zynkit/jwtbytes@0.5.2": "pkg:npm/@zynkit/jwtbytes",
		"pkg:cargo/serde@1.0.0":          "pkg:cargo/serde",
		"pkg:npm/no-version":             "pkg:npm/no-version",
		"":                               "",
	}
	for in, want := range cases {
		if got := versionlessPURL(in); got != want {
			t.Errorf("versionlessPURL(%q) = %q, want %q", in, got, want)
		}
	}
}
