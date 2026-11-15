package hopper

import (
	"context"
	"encoding/hex"
	"errors"
	"fmt"
	"log/slog"
	"strings"

	"github.com/atomdrift-project/hopper/store"
)

// lookupRaisers bounds the raisers one answer lists, as store.Raise bounds
// its own.
const lookupRaisers = 32

// LookupStore answers /v1/lookup from the verdict store for an artifact named
// by a lowercase sha256, a version-less package URL and version, or both, by
// the rule in PLAN.md ("Raising a class at lookup"):
//
//   - the artifact's own record, and what the ledger says of it, which
//     tightens its level by the ladder (Corroborate);
//   - then what it points at or holds that is hostile: detected by atomscan,
//     or convicted by the ledger at a hostile rung (Convicts). The tightest
//     of their levels and its own is the answer's, and each is listed in
//     raised_by.
//
// An artifact nothing stored stands on the ledger alone (FromLedger);
// ErrNotFound when the ledger says nothing either. hopper's API and the
// services that read the store directly answer through it, so a lookup reads
// the same wherever it is asked.
func LookupStore(ctx context.Context, st *store.Store, sha, base, version string) (*LookupRecord, error) {
	var rec *store.Record
	err := store.ErrNotFound
	if sha != "" {
		digest, derr := hex.DecodeString(sha)
		if derr != nil {
			return nil, fmt.Errorf("lookup: %w", derr)
		}
		rec, err = st.BySHA256(ctx, digest)
	}
	if errors.Is(err, store.ErrNotFound) && base != "" {
		rec, err = st.ByRelease(ctx, store.NameOf(base), version)
	}
	if errors.Is(err, store.ErrNotFound) {
		if r := FromLedger(storeLedger(ctx, st, sha, base), sha, base, version); r != nil {
			return r, nil
		}
		return nil, ErrNotFound
	}
	if err != nil {
		return nil, err
	}

	out := RecordOfStore(rec)
	Corroborate(out, storeLedger(ctx, st, hex.EncodeToString(rec.SHA256), rec.Name), rec.Version)

	raised, err := st.Raise(ctx, rec.ID)
	if err != nil {
		// Not best-effort: an answer missing a raise reads as cleaner than the
		// artifact is, so the caller gets an error to fail closed on.
		return nil, err
	}
	why := make([]string, 0, len(raised.By)+len(raised.Cited))
	for range raised.By {
		why = append(why, RaisedDetected)
	}
	for _, c := range raised.Cited {
		if level, ok := Convicts(SightingsOfStore(c.Sightings), c.Version); ok {
			r := c.Raiser
			r.FiresAt = &level
			raised.By, why = append(raised.By, r), append(why, RaisedCorroborated)
		}
	}
	if len(raised.By) > lookupRaisers {
		raised.By, why, raised.Truncated = raised.By[:lookupRaisers], why[:lookupRaisers], true
	}
	// The raise starts from the corroborated level: the ledger's word on the
	// artifact itself is part of its own.
	rec.FiresAt = out.FiresAt
	rec.RaiseBy(raised)
	out.FiresAt = rec.FiresAt
	for i, r := range raised.By {
		lr := LookupRaiser{FiresAt: r.FiresAt, Kind: r.Kind, Name: r.Name, Version: r.Version, Why: why[i]}
		if len(r.SHA256) > 0 {
			d := hex.EncodeToString(r.SHA256)
			lr.SHA256 = &d
		}
		out.RaisedBy = append(out.RaisedBy, lr)
	}
	out.RaisedTruncated = raised.Truncated
	return out, nil
}

// storeLedger returns what the ledger says about a digest and a package,
// spelled as the ledger spells them. Best-effort, as the legacy path's is: an
// outage leaves an answer as the analysis made it, and cannot invent a
// conviction.
func storeLedger(ctx context.Context, st *store.Store, sha, name string) []Sighting {
	var subjects []string
	if sha != "" {
		subjects = append(subjects, sha)
	}
	if name != "" {
		subjects = append(subjects, store.NameOf(name))
	}
	found, err := st.Sightings(ctx, subjects)
	if err != nil {
		slog.WarnContext(ctx, "lookup: ledger read failed", "subjects", len(subjects), "error", err)
		return nil
	}
	var rows []store.Sighting
	for _, subject := range subjects {
		rows = append(rows, found[subject]...)
	}
	return SightingsOfStore(rows)
}

// SightingsFromStore reads the verdict store's ledger for each subject, asked
// in the ledger's spelling and answered under the caller's, as the legacy
// ledger answers: a scoped package's ordinary spelling must not be told
// nothing is known while its rows sit under the canonical one.
func SightingsFromStore(ctx context.Context, st *store.Store, subjects []string) (map[string][]Sighting, error) {
	spelled := make([]string, len(subjects))
	for i, subject := range subjects {
		spelled[i] = subject
		if strings.HasPrefix(subject, "pkg:") {
			spelled[i] = store.NameOf(subject)
		}
	}
	found, err := st.Sightings(ctx, spelled)
	if err != nil {
		return nil, err
	}
	out := make(map[string][]Sighting, len(subjects))
	for i, subject := range subjects {
		if rows := found[spelled[i]]; len(rows) > 0 {
			out[subject] = SightingsOfStore(rows)
		}
	}
	return out, nil
}

// AddSightingsToStore records sightings in the verdict store's ledger by the
// rules the legacy ledger applies (PrepareSightings), relayed by relayer:
// /v1/sightings's write.
func AddSightingsToStore(ctx context.Context, st *store.Store, sightings []Sighting, relayer string) (int, error) {
	prepared, err := PrepareSightings(sightings, relayer)
	if err != nil {
		return 0, err
	}
	rows := make([]store.Sighting, len(prepared))
	for i := range prepared {
		g := &prepared[i]
		rows[i] = store.Sighting{
			PublishedAt: g.PublishedAt, Source: g.Source, Relayer: g.Relayer, Operator: g.Operator,
			Subject: g.Subject, Affected: g.Affected, URL: g.URL, Note: g.Note, FileName: g.FileName,
			Handle: g.Handle, Claim: string(g.Claim), Basis: string(g.Basis),
		}
	}
	return st.AddSightings(ctx, rows)
}
