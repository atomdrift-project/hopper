package store

import (
	"context"
	"maps"
	"testing"
	"time"
)

// stored reads back what ingest decided about one file.
type stored struct {
	label, source, name, version, url string
	provenance                        bool
}

func sampleOf(ctx context.Context, t *testing.T, st *Store, sha []byte) stored {
	t.Helper()
	var s stored
	if err := st.pool.QueryRow(ctx, `SELECT s.label::text, coalesce(s.label_source, ''), coalesce(n.name, ''),
			s.version, coalesce(s.url, ''), s.provenance IS NOT NULL
		FROM samples s LEFT JOIN names n ON n.id = s.name_id WHERE s.sha256 = $1`, sha).
		Scan(&s.label, &s.source, &s.name, &s.version, &s.url, &s.provenance); err != nil {
		t.Fatal(err)
	}
	return s
}

func ingest(ctx context.Context, t *testing.T, st *Store, p Priority, arrivals ...Arrival) Ingested {
	t.Helper()
	got, err := st.Ingest(ctx, arrivals, p)
	if err != nil {
		t.Fatal(err)
	}
	return got
}

func TestIngest(t *testing.T) {
	st := open(t)
	ctx := t.Context()
	pkg := digestOf("pkg")
	mtime := time.Date(2026, 11, 1, 8, 0, 0, 0, time.UTC)
	arrival := Arrival{
		SHA256: pkg, Size: 4000, Path: "good/npm/left-pad-1.3.0.tgz", Source: "walk", Feed: "npm-top",
		Label: "good", LabelSource: "pool", Name: "pkg:PyPI/Django_Rest", Version: "3.1.0",
		URL: "https://files.example/django_rest-3.1.0.tar.gz", Mtime: &mtime,
		Provenance: []byte(`{"registry":{"title":"Django REST"}}`),
	}

	if got, want := ingest(ctx, t, st, QueueNew, arrival), (Ingested{New: 1, Located: 1, Queued: 1}); got != want {
		t.Errorf("first arrival: %+v, want %+v", got, want)
	}
	want := stored{"good", "pool", "pkg:pypi/django-rest", "3.1.0", arrival.URL, true}
	if got := sampleOf(ctx, t, st, pkg); got != want {
		t.Errorf("sample %+v, want %+v: the name is spelled as hopper spells a release", got, want)
	}
	if p := priorities(ctx, t, st); p[hexOf(pkg)] != QueueNew {
		t.Errorf("priorities %v, want the file queued as new", p)
	}

	t.Run("shown again, nothing is written", func(t *testing.T) {
		if got := ingest(ctx, t, st, QueueNew, arrival); got != (Ingested{}) {
			t.Errorf("%+v, want nothing", got)
		}
	})

	t.Run("a second path is a second location, not a second file", func(t *testing.T) {
		again := arrival
		again.Path, again.Feed = "mirror/django_rest-3.1.0.tar.gz", ""
		if got, want := ingest(ctx, t, st, QueueNew, again), (Ingested{Located: 1}); got != want {
			t.Errorf("%+v, want %+v", got, want)
		}
	})

	t.Run("someone waiting raises it in the queue; a walk does not lower it", func(t *testing.T) {
		if got, want := ingest(ctx, t, st, QueueUpload, arrival), (Ingested{Queued: 1}); got != want {
			t.Errorf("%+v, want %+v", got, want)
		}
		if got := ingest(ctx, t, st, QueueNew, arrival); got != (Ingested{}) {
			t.Errorf("%+v, want nothing", got)
		}
		if p := priorities(ctx, t, st); p[hexOf(pkg)] != QueueUpload {
			t.Errorf("priorities %v, want upload", p)
		}
	})

	t.Run("a path that now holds other bytes moves, and the old file leaves the queue", func(t *testing.T) {
		only, replacement := digestOf("only here"), digestOf("replacement")
		ingest(ctx, t, st, QueueNew, Arrival{SHA256: only, Size: 50, Path: "incoming/a.bin"})
		got := ingest(ctx, t, st, QueueNew, Arrival{SHA256: replacement, Size: 60, Path: "incoming/a.bin"})
		if want := (Ingested{New: 1, Located: 1, Displaced: 1, Queued: 1}); got != want {
			t.Errorf("%+v, want %+v", got, want)
		}
		p := priorities(ctx, t, st)
		if _, queued := p[hexOf(only)]; queued || p[hexOf(replacement)] != QueueNew {
			t.Errorf("priorities %v: want the replacement queued and the file with nowhere to read it not", p)
		}
	})

	t.Run("what is not worth a row is refused", func(t *testing.T) {
		got := ingest(ctx, t, st, QueueNew,
			Arrival{SHA256: emptySHA256[:], Path: "incoming/empty"},
			Arrival{SHA256: digestOf("tiny"), Size: minSize - 1, Path: "incoming/tiny"})
		if want := (Ingested{Refused: 2}); got != want {
			t.Errorf("%+v, want %+v", got, want)
		}
	})

	t.Run("what the database would refuse does not fail the batch", func(t *testing.T) {
		odd := digestOf("odd")
		got := ingest(ctx, t, st, QueueNew,
			Arrival{SHA256: digestOf("no such path"), Size: 100, Path: "incoming/a\x00b"},
			Arrival{SHA256: digestOf("nor this"), Size: 100, Path: "incoming/\xff"},
			Arrival{
				SHA256: odd, Size: 100, Path: "incoming/odd.tgz", Name: "pkg:npm/odd\x00", Version: "1.0\xff",
				URL: "https://registry.example/odd\x00.tgz", Provenance: []byte(`{"registry":{"title":"a\u0000b"}}`),
			})
		if want := (Ingested{Refused: 2, New: 1, Located: 1, Queued: 1}); got != want {
			t.Errorf("%+v, want %+v", got, want)
		}
		want := stored{"unknown", "", "pkg:npm/odd", "1.0", "https://registry.example/odd.tgz", false}
		if got := sampleOf(ctx, t, st, odd); got != want {
			t.Errorf("sample %+v, want %+v", got, want)
		}
	})

	t.Run("shown twice in one batch, the first arrival speaks for the file", func(t *testing.T) {
		twice := digestOf("twice")
		got := ingest(ctx, t, st, QueueNew,
			Arrival{SHA256: twice, Size: 100, Path: "good/twice", Label: "good", LabelSource: "pool"},
			Arrival{SHA256: twice, Size: 100, Path: "bad/twice", Label: "bad", LabelSource: "pool"})
		if want := (Ingested{New: 1, Located: 2, Queued: 1}); got != want {
			t.Errorf("%+v, want %+v", got, want)
		}
		if s := sampleOf(ctx, t, st, twice); s.label != "good" {
			t.Errorf("label %s, want good until the bad pool is shown again", s.label)
		}
		ingest(ctx, t, st, QueueNew, Arrival{SHA256: twice, Size: 100, Path: "bad/twice", Label: "bad", LabelSource: "pool"})
		if s := sampleOf(ctx, t, st, twice); s.label != "bad" || s.source != "conflict" {
			t.Errorf("label %s (%s), want bad (conflict)", s.label, s.source)
		}
	})

	t.Run("a file already judged is not queued again", func(t *testing.T) {
		r := archive()
		r.write(ctx, t, st)
		got := ingest(ctx, t, st, QueueNew, Arrival{SHA256: digestOf("package bytes"), Size: 4000, Path: "good/pkg.tgz"})
		if want := (Ingested{Located: 1}); got != want {
			t.Errorf("%+v, want %+v", got, want)
		}
	})
}

func TestIngestPriority(t *testing.T) {
	st := open(t)
	ctx := t.Context()
	cited, huge, plain := digestOf("cited"), digestOf("huge"), digestOf("plain")
	ingest(ctx, t, st, QueueNew,
		Arrival{SHA256: cited, Size: 100, Path: "sighted/a", Label: "sighted", LabelSource: "feed"},
		Arrival{SHA256: huge, Size: bigFile + 1, Path: "pool/huge.iso"},
		Arrival{SHA256: plain, Size: 100, Path: "pool/plain"})
	want := map[string]Priority{hexOf(cited): QueueSighted, hexOf(huge): QueueBigArchive, hexOf(plain): QueueNew}
	if got := priorities(ctx, t, st); !maps.Equal(got, want) {
		t.Errorf("priorities %v, want %v: the cited file first, the huge one for big workers, the rest new", got, want)
	}
}

// What a known file's label becomes when it is shown again.
func TestIngestLabels(t *testing.T) {
	st := open(t)
	ctx := t.Context()
	for name, tc := range map[string]struct {
		had, hadSource   string
		got, gotSource   string
		want, wantSource string
		unchanged        bool
	}{
		"a pool label claims more than none":            {"unknown", "", "good", "pool", "good", "pool", false},
		"no claim does not unseat a pool label":         {"good", "pool", "unknown", "", "good", "pool", true},
		"a citation does not unseat a pool label":       {"good", "pool", "sighted", "feed", "good", "pool", true},
		"bad outranks a citation":                       {"sighted", "feed", "bad", "pool", "bad", "pool", false},
		"good and bad pools disagreeing is bad":         {"good", "pool", "bad", "pool", "bad", "conflict", false},
		"the disagreement is settled once":              {"bad", "conflict", "good", "pool", "bad", "conflict", true},
		"a marker overrides the pool":                   {"good", "pool", "bad", "marker", "bad", "marker", false},
		"the pool's label returns with the marker gone": {"bad", "marker", "good", "pool", "good", "pool", false},
		"a reviewed label is not replaced":              {"purgatory", "review", "bad", "pool", "purgatory", "review", true},
	} {
		t.Run(name, func(t *testing.T) {
			sha := digestOf(name)
			if _, err := st.pool.Exec(ctx, `INSERT INTO samples (sha256, size_bytes, label, label_source)
				VALUES ($1, 100, $2::label, nullif($3, ''))`, sha, tc.had, tc.hadSource); err != nil {
				t.Fatal(err)
			}
			place(ctx, t, st, sha, "pool/"+name)
			got := ingest(ctx, t, st, QueueNew, Arrival{SHA256: sha, Size: 100, Path: "pool/" + name, Label: tc.got, LabelSource: tc.gotSource})
			if (got.Updated == 0) != tc.unchanged {
				t.Errorf("%+v: unchanged should be %v", got, tc.unchanged)
			}
			if s := sampleOf(ctx, t, st, sha); s.label != tc.want || s.source != tc.wantSource {
				t.Errorf("label %s (%s), want %s (%s)", s.label, s.source, tc.want, tc.wantSource)
			}
		})
	}
}

// The first sidecar supersedes an identity guessed from a filename; after
// that an arrival only fills what is missing.
func TestIngestIdentity(t *testing.T) {
	st := open(t)
	ctx := t.Context()
	sha := digestOf("release")
	guess := Arrival{SHA256: sha, Size: 100, Path: "pool/left-pad-1.3.tgz", Name: "pkg:npm/left-pad-1", Version: "3"}
	ingest(ctx, t, st, QueueNew, guess)

	sidecar := guess
	sidecar.Name, sidecar.Version, sidecar.URL = "pkg:npm/left-pad", "1.3.0", "https://registry.example/left-pad-1.3.0.tgz"
	sidecar.Provenance = []byte(`{"registry":{}}`)
	if got := ingest(ctx, t, st, QueueNew, sidecar); got.Updated != 1 {
		t.Errorf("%+v, want the sidecar's identity taken", got)
	}
	want := stored{"unknown", "", "pkg:npm/left-pad", "1.3.0", sidecar.URL, true}
	if got := sampleOf(ctx, t, st, sha); got != want {
		t.Errorf("sample %+v, want %+v", got, want)
	}

	later := sidecar
	later.Name, later.Version, later.URL = "pkg:npm/other", "9.9.9", "https://elsewhere.example/x.tgz"
	later.Provenance = []byte(`{"registry":{"title":"later"}}`)
	if got := ingest(ctx, t, st, QueueNew, later); got.Updated != 0 {
		t.Errorf("%+v: a later arrival replaced an identity that had a sidecar", got)
	}
	if got := sampleOf(ctx, t, st, sha); got != want {
		t.Errorf("sample %+v, want %+v", got, want)
	}
}
