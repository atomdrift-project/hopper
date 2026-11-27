package store

import (
	"testing"
	"time"
)

func TestAcquisitionSubject(t *testing.T) {
	digest := sum("bytes")
	for _, tc := range []struct{ target, want string }{
		{"sha256:" + digest, digest},
		{"sha256:" + "ABCDEF" + digest[6:], "abcdef" + digest[6:]},
		{"pkg:npm/evil@1.0.0", "pkg:npm/evil"},
		{"pkg:npm/%40scope/evil@1.0.0", "pkg:npm/%40scope/evil"},
		{"pkg:npm/evil@*", "pkg:npm/evil"},
		{"pkg:github/owner/repo@HEAD", "pkg:github/owner/repo"},
		{"pkg:oci/app?repository_url=ghcr.io%2Fowner&tag=%2A", "pkg:oci/app?repository_url=ghcr.io%2Fowner"},
		{"pkg:oci/app@sha256:" + digest + "?repository_url=ghcr.io%2Fowner", "pkg:oci/app?repository_url=ghcr.io%2Fowner"},
		{"pkg:vscode-extension/pub.ext#review-current", "pkg:vscode-extension/pub.ext"},
		{"https://example.test/evil.tgz", ""},
		{"", ""},
	} {
		if got := acquisitionSubject(tc.target); got != tc.want {
			t.Errorf("acquisitionSubject(%q) = %q, want %q", tc.target, got, tc.want)
		}
	}
}

// A reopened target is offered to acquirers again even when the claims it
// came from were already stamped attempted, which is the usual case: a pass
// that died holding the claim leaves the next pass to stamp them as taken.
func TestReopenAcquisitionsRequeuesSightings(t *testing.T) {
	st := open(t)
	ctx := t.Context()
	digest := sum("acquired bytes")
	claims := []Sighting{
		{Source: "osv", Subject: "pkg:npm/evil", Affected: "1.0.0", Claim: "malicious"},
		{Source: "socket", Subject: "pkg:npm/evil", Affected: "1.0.0", Claim: "suspicious"},
		{Source: "ghsa", Subject: "pkg:npm/evil", Affected: "1.0.0", Claim: "vulnerable"},
		{Source: "osv", Subject: "pkg:npm/other", Affected: "2.0.0", Claim: "malicious"},
		{Source: "bazaar", Subject: digest, Claim: "malicious"},
	}
	if _, err := st.AddSightings(ctx, claims); err != nil {
		t.Fatal(err)
	}
	const (
		lost   = "pkg:npm/evil@1.0.0"  // claimed by a pass that died
		failed = "pkg:npm/other@2.0.0" // claimed, fetch failed
		held   = "sha256:"             // acquired; digest appended below
	)
	for _, target := range []string{lost, failed, held + digest, "https://example.test/evil.tgz"} {
		if ok, err := st.ClaimAcquisition(ctx, target, time.Hour); err != nil || !ok {
			t.Fatalf("ClaimAcquisition(%q) = %v, %v", target, ok, err)
		}
	}
	if _, err := st.FinishAcquisition(ctx, failed, false, time.Hour, "404"); err != nil {
		t.Fatal(err)
	}
	if _, err := st.FinishAcquisition(ctx, held+digest, true, 0, ""); err != nil {
		t.Fatal(err)
	}
	keys := make([]SightingKey, len(claims))
	for i, c := range claims {
		keys[i] = SightingKey{Source: c.Source, Subject: c.Subject, Affected: c.Affected}
	}
	if n, err := st.MarkAttempted(ctx, keys); err != nil || n != int64(len(claims)) {
		t.Fatalf("MarkAttempted = %d, %v; want %d", n, err, len(claims))
	}

	unattempted := func() map[string]bool {
		t.Helper()
		rows, err := st.pool.Query(ctx, `SELECT source || ' ' || subject FROM sightings WHERE attempted_at IS NULL`)
		if err != nil {
			t.Fatal(err)
		}
		defer rows.Close()
		out := map[string]bool{}
		for rows.Next() {
			var k string
			if err := rows.Scan(&k); err != nil {
				t.Fatal(err)
			}
			out[k] = true
		}
		if err := rows.Err(); err != nil {
			t.Fatal(err)
		}
		return out
	}

	want := Reopened{Targets: 2, Sightings: 2, Unmapped: 1} // lost and the URL; osv and socket's evil
	preview, err := st.ReopenAcquisitions(ctx, nil, true, true)
	if err != nil || preview != want {
		t.Fatalf("dry run = %+v, %v; want %+v", preview, err, want)
	}
	if got := unattempted(); len(got) != 0 {
		t.Fatalf("dry run unstamped %v", got)
	}

	got, err := st.ReopenAcquisitions(ctx, nil, true, false)
	if err != nil || got != want {
		t.Fatalf("ReopenAcquisitions(unfinished) = %+v, %v; want %+v", got, err, want)
	}
	if u := unattempted(); len(u) != 2 || !u["osv pkg:npm/evil"] || !u["socket pkg:npm/evil"] {
		t.Errorf("offered again: %v; want osv's and socket's pkg:npm/evil, not the vulnerability or other subjects", u)
	}
	if ok, err := st.ClaimAcquisition(ctx, lost, time.Hour); err != nil || !ok {
		t.Errorf("reclaim %s = %v, %v; want claimed", lost, ok, err)
	}
	if ok, err := st.ClaimAcquisition(ctx, failed, time.Hour); err != nil || ok {
		t.Errorf("claim %s = %v, %v; an unfinished-only reopen left it claimed", failed, ok, err)
	}

	// Naming a target reopens it alone, finished or not, but never one acquired.
	got, err = st.ReopenAcquisitions(ctx, []string{failed, held + digest}, false, false)
	if err != nil || got != (Reopened{Targets: 1, Sightings: 1}) {
		t.Fatalf("ReopenAcquisitions(named) = %+v, %v; want the failed target and its claim", got, err)
	}
	if u := unattempted(); !u["osv pkg:npm/other"] || u["bazaar "+digest] {
		t.Errorf("offered again: %v; want osv's pkg:npm/other and not the acquired digest", u)
	}
	if ok, err := st.ClaimAcquisition(ctx, held+digest, time.Hour); err != nil || ok {
		t.Errorf("claim acquired %s = %v, %v; want refused", held+digest, ok, err)
	}
}

// A claimant gives back only a claim it never finished. A finished or acquired
// target is another pass's completed work and stays claimed.
func TestReleaseAcquisition(t *testing.T) {
	st := open(t)
	ctx := t.Context()
	const (
		cut      = "pkg:npm/cut@1.0.0"    // claimed, pass shut down mid-fetch
		failed   = "pkg:npm/failed@1.0.0" // claimed, fetch failed
		acquired = "pkg:npm/held@1.0.0"   // claimed, fetched
		marked   = "pkg:npm/marked@1.0.0" // acquired with no finish time, as no writer leaves it
	)
	for _, target := range []string{cut, failed, acquired, marked} {
		if ok, err := st.ClaimAcquisition(ctx, target, time.Hour); err != nil || !ok {
			t.Fatalf("ClaimAcquisition(%q) = %v, %v", target, ok, err)
		}
	}
	if _, err := st.FinishAcquisition(ctx, failed, false, time.Hour, "404"); err != nil {
		t.Fatal(err)
	}
	if _, err := st.FinishAcquisition(ctx, acquired, true, 0, ""); err != nil {
		t.Fatal(err)
	}
	if _, err := st.pool.Exec(ctx, `UPDATE sighting_acquisitions SET acquired = true WHERE target = $1`, marked); err != nil {
		t.Fatal(err)
	}

	for _, tc := range []struct {
		target string
		want   bool
	}{
		{cut, true},
		{cut, false}, // released already
		{failed, false},
		{acquired, false},
		{marked, false},
		{"pkg:npm/never-claimed@1.0.0", false},
	} {
		if got, err := st.ReleaseAcquisition(ctx, tc.target); err != nil || got != tc.want {
			t.Errorf("ReleaseAcquisition(%q) = %v, %v; want %v", tc.target, got, err, tc.want)
		}
	}
	if ok, err := st.ClaimAcquisition(ctx, cut, time.Hour); err != nil || !ok {
		t.Errorf("reclaim released %s = %v, %v; want claimed", cut, ok, err)
	}
	for _, target := range []string{failed, acquired, marked} {
		if ok, err := st.ClaimAcquisition(ctx, target, time.Hour); err != nil || ok {
			t.Errorf("claim %s = %v, %v; want still held", target, ok, err)
		}
	}
}
