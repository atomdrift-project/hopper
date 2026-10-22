package hopper

import (
	"context"
	"database/sql"
	"errors"
	"fmt"

	"github.com/jackc/pgx/v5"
)

// AncestrySighting identifies the file or ancestor a sighting actually names.
type AncestrySighting struct {
	SHA256   string   `json:"sha256"`
	Sighting Sighting `json:"sighting"`
}

// SightingsAncestry is a completed existence check, with witnesses when any
// applicable sightings exist. It is not an enumeration of every sighting.
type SightingsAncestry struct {
	Sightings []AncestrySighting `json:"sightings"`
	Checked   bool               `json:"checked"`
}

const maxSightingAncestryNodes = 4096

// SightingsInAncestry checks a file and every recorded parent, recursively.
// Both location edges (including alternate containers) and the legacy primary
// parent count. A package sighting must cover the recorded release. Unknown
// nodes, query failures and traversal limits never return a clear check.
func (db *DB) SightingsInAncestry(ctx context.Context, root string) (*SightingsAncestry, error) {
	pending := []string{root}
	seen := map[string]bool{root: true}
	for i := 0; i < len(pending); i++ {
		sha := pending[i]
		identity, err := db.sightingAncestryIdentity(ctx, sha)
		if err != nil {
			return nil, err
		}
		subjects := []string{sha}
		if identity.purl != "" {
			subjects = append(subjects, identity.purl)
		}
		ledger, err := db.SightingsFor(ctx, subjects)
		if err != nil {
			return nil, err
		}
		result := &SightingsAncestry{Checked: true, Sightings: []AncestrySighting{}}
		for _, subject := range subjects {
			for i := range ledger[subject] {
				sighting := &ledger[subject][i]
				if subject == sha || sighting.Covers(identity.version) {
					result.Sightings = append(result.Sightings, AncestrySighting{SHA256: sha, Sighting: *sighting})
				}
			}
		}
		if len(result.Sightings) > 0 {
			return result, nil // One witness suffices to refuse benign promotion.
		}
		parents, err := db.sightingAncestryParents(ctx, sha)
		if err != nil {
			return nil, err
		}
		if identity.parent != "" {
			parents = append(parents, identity.parent)
		}
		for _, parent := range parents {
			if seen[parent] {
				continue
			}
			if len(seen) >= maxSightingAncestryNodes {
				return nil, errors.New("hopper: sightings ancestry exceeds traversal limit")
			}
			seen[parent] = true
			pending = append(pending, parent)
		}
	}
	return &SightingsAncestry{Checked: true, Sightings: []AncestrySighting{}}, nil
}

type sightingAncestor struct {
	purl, version, parent string
}

func (db *DB) sightingAncestryIdentity(ctx context.Context, sha string) (sightingAncestor, error) {
	var identity sightingAncestor
	var err error
	const projection = `SELECT COALESCE(purl_base,''), COALESCE(version,''), COALESCE(parent,'') FROM samples WHERE sha256 = `
	if db.pool != nil {
		err = db.pool.QueryRow(ctx, projection+"$1", sha).Scan(&identity.purl, &identity.version, &identity.parent)
	} else {
		err = db.lite.QueryRowContext(ctx, projection+"?", sha).Scan(&identity.purl, &identity.version, &identity.parent)
	}
	if errors.Is(err, pgx.ErrNoRows) || errors.Is(err, sql.ErrNoRows) {
		err = fmt.Errorf("hopper: sightings ancestry has unknown node %s: %w", sha, ErrNotFound)
	}
	return identity, err
}

func (db *DB) sightingAncestryParents(ctx context.Context, sha string) ([]string, error) {
	const query = `SELECT DISTINCT parent_sha256 FROM sample_locations WHERE parent_sha256 <> '' AND sha256 = `
	var parents []string
	var err error
	if db.pool != nil {
		rows, queryErr := db.pool.Query(ctx, query+"$1 LIMIT 4097", sha)
		if queryErr != nil {
			return nil, queryErr
		}
		parents, err = scanPGStrings(rows)
	} else {
		rows, queryErr := db.lite.QueryContext(ctx, query+"? LIMIT 4097", sha)
		if queryErr != nil {
			return nil, queryErr
		}
		parents, err = scanLiteStrings(rows)
	}
	if err != nil {
		return nil, err
	}
	if len(parents) > maxSightingAncestryNodes {
		return nil, errors.New("hopper: sightings ancestry exceeds parent limit")
	}
	return parents, nil
}
