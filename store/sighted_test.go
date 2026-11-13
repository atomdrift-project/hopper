package store

import (
	"context"
	"maps"
	"testing"
	"time"
)

// sight records a sighting as the ledger's writer would: the claim
// commits, then the files it names are cited.
func sight(ctx context.Context, t *testing.T, st *Store, source, subject, affected string) {
	t.Helper()
	if _, err := st.pool.Exec(ctx, `INSERT INTO sightings (source, subject, affected, operator)
		VALUES ($1, $2, $3, $1)`, source, subject, affected); err != nil {
		t.Fatal(err)
	}
	if err := st.Cite(ctx, []Claim{{Subject: subject, Affected: affected}}); err != nil {
		t.Fatal(err)
	}
}

// A sighting moves a file waiting for its first scan to the front of the
// queue, whichever arrives first.
func TestSighted(t *testing.T) {
	st := open(t)
	ctx := t.Context()
	arrive := func(bytes, name, version string) {
		t.Helper()
		ingest(ctx, t, st, QueueNew, Arrival{SHA256: digestOf(bytes), Size: 100, Path: "pool/" + bytes, Name: name, Version: version})
	}
	arrive("loose", "", "")
	arrive("evil 1.0.0", "pkg:npm/evil", "1.0.0")
	arrive("evil 1.0.1", "pkg:npm/evil", "1.0.1")
	arrive("evil 1.0.2", "pkg:npm/evil", "1.0.2")
	arrive("other 1.0.0", "pkg:npm/other", "1.0.0")
	arrive("ranged 2.0.0", "pkg:npm/ranged", "2.0.0")
	judge(ctx, t, st, "scanned", "benign", -1, nil, nil)
	place(ctx, t, st, digestOf("scanned"), "pool/scanned")
	if _, err := st.Rescan(ctx, digestOf("scanned"), time.Date(2026, 11, 12, 16, 0, 0, 0, time.UTC)); err != nil {
		t.Fatal(err)
	}
	want := map[string]Priority{
		hexOf(digestOf("loose")): QueueNew, hexOf(digestOf("evil 1.0.0")): QueueNew, hexOf(digestOf("evil 1.0.1")): QueueNew,
		hexOf(digestOf("evil 1.0.2")): QueueNew, hexOf(digestOf("other 1.0.0")): QueueNew, hexOf(digestOf("ranged 2.0.0")): QueueNew,
		hexOf(digestOf("scanned")): QueueRequested,
	}
	if got := priorities(ctx, t, st); !maps.Equal(got, want) {
		t.Fatalf("priorities %v, want %v", got, want)
	}

	for _, tc := range []struct {
		name, subject, affected string
		raised                  []string
	}{
		{"a digest raises that file", hexOf(digestOf("loose")), "", []string{"loose"}},
		{"a claim naming exact versions raises only those", "pkg:npm/evil", "1.0.1, 1.0.2", []string{"evil 1.0.1", "evil 1.0.2"}},
		{"one version written with = is exact too", "pkg:npm/other", "= 9.9.9", nil},
		{"a range cannot be narrowed, so the package is raised", "pkg:npm/ranged", ">=2", []string{"ranged 2.0.0"}},
		{"a claim with no versions raises every release", "pkg:npm/evil", "", []string{"evil 1.0.0"}},
		{"a file already scanned is left where it is", hexOf(digestOf("scanned")), "", nil},
	} {
		t.Run(tc.name, func(t *testing.T) {
			sight(ctx, t, st, "feed-"+tc.name, tc.subject, tc.affected)
			for _, bytes := range tc.raised {
				want[hexOf(digestOf(bytes))] = QueueSighted
			}
			if got := priorities(ctx, t, st); !maps.Equal(got, want) {
				t.Errorf("priorities %v, want %v", got, want)
			}
		})
	}

	t.Run("a subject corrected by hand is cited once Recite runs", func(t *testing.T) {
		sight(ctx, t, st, "typo-feed", "pkg:npm/othr", "")
		if _, err := st.pool.Exec(ctx, `UPDATE sightings SET subject = 'pkg:npm/other' WHERE source = 'typo-feed'`); err != nil {
			t.Fatal(err)
		}
		var cited bool
		if err := st.pool.QueryRow(ctx, `SELECT cited FROM samples WHERE sha256 = $1`, digestOf("other 1.0.0")).Scan(&cited); err != nil || cited {
			t.Fatalf("cited %v, %v: nothing but a writer or Recite marks a file", cited, err)
		}
		if marked, cleared, err := st.Recite(ctx); err != nil || marked != 1 || cleared != 0 {
			t.Fatalf("recite: marked %d, cleared %d, %v; want the one file", marked, cleared, err)
		}
	})

	t.Run("a file that arrives already named goes first", func(t *testing.T) {
		sight(ctx, t, st, "late", hexOf(digestOf("late digest")), "")
		sight(ctx, t, st, "late", "pkg:pypi/late", "3.0.0")
		arrive("late digest", "", "")
		arrive("late 3.0.0", "pkg:pypi/late", "3.0.0")
		arrive("late 2.0.0", "pkg:pypi/late", "2.0.0")
		want[hexOf(digestOf("late digest"))] = QueueSighted
		want[hexOf(digestOf("late 3.0.0"))] = QueueSighted
		want[hexOf(digestOf("late 2.0.0"))] = QueueNew
		if got := priorities(ctx, t, st); !maps.Equal(got, want) {
			t.Errorf("priorities %v, want %v", got, want)
		}
	})
}

// Names are spelled as the ledger spells a package subject, so the two join.
func TestNameOf(t *testing.T) {
	for in, want := range map[string]string{
		"pkg:npm/left-pad":                     "pkg:npm/left-pad",
		"pkg:PyPI/Django_Rest":                 "pkg:pypi/django-rest",
		"pkg:npm/left-pad@1.3.0":               "pkg:npm/left-pad",
		"pkg:npm/%40scope/x@1.0.0?arch=x86_64": "pkg:npm/%40scope/x",
		"https://example.com/x.sh":             "https://example.com/x.sh",
	} {
		if got := NameOf(in); got != want {
			t.Errorf("NameOf(%q) = %q, want %q", in, got, want)
		}
	}
}
