package store

import (
	"context"
	"fmt"
	"slices"

	"github.com/jackc/pgx/v5"
)

// The bounds on one raise, measured on the local export (PLAN.md, "Raising a
// class at lookup"). Together they hold the worst case near 7 ms and leave an
// ordinary package under 0.1 ms.
const (
	raiseRefs   = 4096 // references examined
	raiseReach  = 4096 // contained files examined
	raiseDepth  = 16   // nesting levels walked
	raiseRaised = 32   // things listed as raising the class
)

// Raiser is something a file points at or contains that is hostile.
type Raiser struct {
	// FiresAt is the raiser's own level, as in Record.
	FiresAt *int
	// Kind is dependency, command or url_fetch for a reference, member for a
	// contained file.
	Kind string
	// Name and Version are the reference as declared, or a member's release
	// name and version when it has one.
	Name    string
	Version string
	// SHA256 is the hostile file.
	SHA256 []byte
}

// Raised is what Raise found.
type Raised struct {
	By []Raiser
	// Cited are the references and contained files the ledger names that
	// atomscan does not hold hostile. Whether one raises is the ledger rule's
	// to say (hopper.Convicts); the caller weighs it, and adds those that do
	// to By.
	Cited []Cited
	// Truncated reports that a bound stopped the search: more references or
	// contained files existed than were examined, or more raisers than are
	// listed.
	Truncated bool
}

// Cited is a reference or contained file the ledger names, with its rows.
type Cited struct {
	Raiser

	Sightings []Sighting
}

// Raise finds what makes the file with id hostile beyond its own stored
// verdict: a release it declares, a URL it fetched or a file it contains that
// atomscan holds hostile. It is computed per lookup, on top of a cached
// Record, and never stored; a conviction or acquittal anywhere shows on the
// next lookup with no fan-out.
//
// A reference is resolved one hop, at the version scan pinned. A URL raises
// when the newest file held under it is hostile, or the bytes it served when
// scanned are. Files are walked through contents to raiseDepth levels. A file
// labelled good never raises: the label is the brake on a false positive in a
// popular package, which would otherwise make every declarer hostile.
func (st *Store) Raise(ctx context.Context, id int64) (*Raised, error) {
	var raised Raised
	var err error
	if raised.By, raised.Truncated, err = st.raisingRefs(ctx, id); err != nil {
		return nil, fmt.Errorf("store: raise %d: refs: %w", id, err)
	}
	reach, truncated, err := st.reach(ctx, id)
	if err != nil {
		return nil, err
	}
	raised.Truncated = raised.Truncated || truncated
	if len(reach) > 0 {
		rows, err := st.pool.Query(ctx, `SELECT coalesce(n.name, ''), s.version, s.sha256, v.fires_at
			FROM verdicts v
			JOIN samples s ON s.id = v.sample_id
			LEFT JOIN names n ON n.id = s.name_id
			WHERE v.scanner_id = $2 AND v.class = 'hostile' AND v.sample_id = ANY ($1) AND s.label <> 'good'
			ORDER BY s.sha256
			LIMIT $3`, reach, atomscan, raiseRaised+1)
		if err != nil {
			return nil, fmt.Errorf("store: raise %d: members: %w", id, err)
		}
		members, err := pgx.CollectRows(rows, func(row pgx.CollectableRow) (Raiser, error) {
			r := Raiser{Kind: "member"}
			err := row.Scan(&r.Name, &r.Version, &r.SHA256, &r.FiresAt)
			return r, err
		})
		if err != nil {
			return nil, fmt.Errorf("store: raise %d: members: %w", id, err)
		}
		raised.By = append(raised.By, members...)
	}
	if raised.Cited, err = st.cited(ctx, id, reach, raised.By); err != nil {
		return nil, err
	}
	if len(raised.By) > raiseRaised {
		raised.By, raised.Truncated = raised.By[:raiseRaised], true
	}
	return &raised, nil
}

// raisingRefs returns the references of file id that resolve to something
// hostile, and whether it holds more references than were examined.
func (st *Store) raisingRefs(ctx context.Context, id int64) (by []Raiser, truncated bool, err error) {
	b := &pgx.Batch{}
	b.Queue(`SELECT count(*) > $2 FROM (SELECT 1 FROM refs WHERE sample_id = $1 LIMIT $2 + 1) r`, id, raiseRefs)
	// Driven from the file's own references so the cost is one probe per
	// reference, whatever the size of the tables. As a plain join the planner
	// may scan every release instead.
	b.Queue(`SELECT hit.kind::text, n.name, hit.version, hit.sha256, hit.fires_at FROM (
			SELECT r.kind, r.name_id, r.version, h.sha256, h.fires_at
			FROM (SELECT name_id, version, kind, fetched FROM refs WHERE sample_id = $1
			      ORDER BY name_id, version, kind LIMIT $3) r
			CROSS JOIN LATERAL (
				SELECT x.sha256, x.fires_at FROM (
					SELECT s.sha256, v.fires_at
					FROM samples s
					JOIN verdicts v ON v.sample_id = s.id AND v.scanner_id = $2 AND v.class = 'hostile'
					WHERE r.kind <> 'url_fetch' AND s.name_id = r.name_id AND s.version = r.version AND s.label <> 'good'
					UNION ALL
					SELECT s.sha256, v.fires_at
					FROM (SELECT id, sha256, label FROM samples
					      WHERE r.kind = 'url_fetch' AND name_id = r.name_id AND version = r.version
					      ORDER BY id DESC LIMIT 1) s
					JOIN verdicts v ON v.sample_id = s.id AND v.scanner_id = $2 AND v.class = 'hostile'
					WHERE s.label <> 'good'
					UNION ALL
					SELECT s.sha256, v.fires_at
					FROM samples s
					JOIN verdicts v ON v.sample_id = s.id AND v.scanner_id = $2 AND v.class = 'hostile'
					WHERE r.kind = 'url_fetch' AND s.sha256 = r.fetched AND s.label <> 'good'
				) x LIMIT 1) h
			ORDER BY r.name_id, r.version, r.kind
			LIMIT $4) hit
		JOIN names n ON n.id = hit.name_id
		ORDER BY n.name, hit.version, hit.kind`, id, atomscan, raiseRefs, raiseRaised+1)
	results := st.pool.SendBatch(ctx, b)
	defer func() {
		if cerr := results.Close(); err == nil {
			err = cerr
		}
	}()
	if err := results.QueryRow().Scan(&truncated); err != nil {
		return nil, false, err
	}
	rows, err := results.Query()
	if err != nil {
		return nil, false, err
	}
	by, err = pgx.CollectRows(rows, func(row pgx.CollectableRow) (Raiser, error) {
		var r Raiser
		err := row.Scan(&r.Kind, &r.Name, &r.Version, &r.SHA256, &r.FiresAt)
		return r, err
	})
	return by, truncated, err
}

// reach returns the files contained in id at any depth, walking contents one
// level per statement: a recursive CTE is estimated at thousands of rows and
// planned as hash joins over whole tables. Content addressing makes a cycle a
// file that contains itself; the seen set ends it.
func (st *Store) reach(ctx context.Context, id int64) (reach []int64, truncated bool, err error) {
	seen := map[int64]bool{id: true}
	frontier := []int64{id}
	for depth := 0; ; depth++ {
		var level []int64
		if err := st.pool.QueryRow(ctx, `SELECT coalesce(array_agg(DISTINCT u ORDER BY u), '{}')
			FROM contents c, unnest(c.child_ids) u WHERE c.parent_id = ANY ($1)`, frontier).Scan(&level); err != nil {
			return nil, false, fmt.Errorf("store: raise %d: contents: %w", id, err)
		}
		level = slices.DeleteFunc(level, func(u int64) bool { return seen[u] })
		switch {
		case len(level) == 0:
			return reach, false, nil
		case depth == raiseDepth:
			return reach, true, nil
		case len(reach)+len(level) > raiseReach:
			return append(reach, level[:raiseReach-len(reach)]...), true, nil
		default:
		}
		for _, u := range level {
			seen[u] = true
		}
		reach = append(reach, level...)
		frontier = level
	}
}

// RaiseBy applies what Raise found to a record: anything hostile it points at
// or contains makes it hostile, at the tightest level among its own and
// theirs. Only hostile raises, so a record is never lowered. A raised record
// whose own level said it never fires (-1), with no measured level among
// what raised it, has no level: it is hostile, so "never fires" would lie.
func (r *Record) RaiseBy(raised *Raised) {
	if raised == nil || len(raised.By) == 0 {
		return
	}
	r.Class = "hostile"
	var level *int
	if r.FiresAt != nil && *r.FiresAt >= 0 {
		level = r.FiresAt
	}
	for _, by := range raised.By {
		if by.FiresAt != nil && *by.FiresAt >= 0 && (level == nil || *by.FiresAt < *level) {
			l := *by.FiresAt
			level = &l
		}
	}
	r.FiresAt = level
}

// cited returns the references of file id and the files in reach that the
// ledger names, with their rows, leaving out what by already holds: a file
// atomscan holds hostile raises as it is. A file labelled good is left out,
// as it is from By.
func (st *Store) cited(ctx context.Context, id int64, reach []int64, by []Raiser) ([]Cited, error) {
	raised := map[string]bool{}
	for _, r := range by {
		raised[citedKey(r)] = true
	}
	var out []Cited
	index := map[string]int{}
	add := func(r Raiser, g Sighting) {
		k := citedKey(r)
		if raised[k] {
			return
		}
		i, ok := index[k]
		if !ok {
			i = len(out)
			index[k] = i
			out = append(out, Cited{Raiser: r})
		}
		out[i].Sightings = append(out[i].Sightings, g)
	}
	rows, err := st.pool.Query(ctx, sightingColumns+`, r.kind::text, n.name, r.version, r.fetched
		FROM (SELECT name_id, version, kind, fetched FROM refs WHERE sample_id = $1
		      ORDER BY name_id, version, kind LIMIT $2) r
		JOIN names n ON n.id = r.name_id
		JOIN sightings g ON g.subject = n.name OR g.subject = encode(r.fetched, 'hex')
		ORDER BY n.name, r.version, r.kind
		LIMIT $3`, id, raiseRefs, ledgerRows)
	if err != nil {
		return nil, fmt.Errorf("store: raise %d: cited refs: %w", id, err)
	}
	if err := citedRows(rows, add); err != nil {
		return nil, fmt.Errorf("store: raise %d: cited refs: %w", id, err)
	}
	if len(reach) == 0 {
		return out, nil
	}
	rows, err = st.pool.Query(ctx, sightingColumns+`, 'member'::text, coalesce(n.name, ''), s.version, s.sha256
		FROM samples s
		LEFT JOIN names n ON n.id = s.name_id
		JOIN sightings g ON g.subject = encode(s.sha256, 'hex') OR g.subject = n.name
		WHERE s.id = ANY ($1) AND s.label <> 'good'
		ORDER BY s.sha256
		LIMIT $2`, reach, ledgerRows)
	if err != nil {
		return nil, fmt.Errorf("store: raise %d: cited members: %w", id, err)
	}
	if err := citedRows(rows, add); err != nil {
		return nil, fmt.Errorf("store: raise %d: cited members: %w", id, err)
	}
	return out, nil
}

// citedRows reads rows of a sighting followed by the raiser it names.
func citedRows(rows pgx.Rows, add func(Raiser, Sighting)) error {
	defer rows.Close()
	for rows.Next() {
		var g Sighting
		var r Raiser
		if err := rows.Scan(append(g.fields(), &r.Kind, &r.Name, &r.Version, &r.SHA256)...); err != nil {
			return err
		}
		g.clean()
		add(r, g)
	}
	return rows.Err()
}

// citedKey names a raiser: a file by its digest, a reference by what it
// declares.
func citedKey(r Raiser) string {
	if r.Kind == "member" || r.Kind == "url_fetch" && len(r.SHA256) > 0 {
		return string(r.SHA256)
	}
	return r.Kind + "\x00" + r.Name + "\x00" + r.Version
}
