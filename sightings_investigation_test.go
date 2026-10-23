package hopper

import (
	"context"
	"testing"
	"time"
)

func TestSightedInvestigationLagTracksEligibleRecentSamples(t *testing.T) {
	for _, b := range testBackends {
		t.Run(b.name, func(t *testing.T) {
			db := b.open(t)
			ctx := context.Background()
			now := time.Now().UTC()
			sha := hexSHA(501)
			addClaim := func(subject, affected string, ago time.Duration) Sighting {
				t.Helper()
				c := Sighting{Source: "feed", Subject: subject, Affected: affected, Claim: ClaimMalicious}
				if _, err := db.AddSightings(ctx, []Sighting{c}); err != nil {
					t.Fatal(err)
				}
				execBoth(t, ctx, db, `UPDATE sightings SET first_seen = $1 WHERE subject = $2 AND affected = $3`, now.Add(-ago), subject, affected)
				return c
			}
			check := func(want time.Duration) {
				t.Helper()
				lag, err := db.SightedInvestigationLag(ctx)
				if err != nil || lag < want-time.Minute || lag > want+time.Minute {
					t.Fatalf("investigation lag = %v, %v; want approximately %v", lag, err, want)
				}
			}

			claim := addClaim(sha, "", 6*time.Hour)
			check(0) // No sample bytes.
			mustInsert(t, ctx, db, &Sample{SHA256: sha, Path: "pending/held.exe"})
			check(0) // Not yet analyzed and eligible for Cyclotron.
			mustAnalyze(t, ctx, db, sha, 0)
			execBoth(t, ctx, db, `UPDATE samples SET created_at = $1, first_analyzed_at = $2, analyzed_at = $3 WHERE sha256 = $4`,
				now.Add(-8*time.Hour), now.Add(-10*time.Minute), now.Add(-10*time.Minute), sha)
			check(10 * time.Minute) // The sample only became ready ten minutes ago.
			execBoth(t, ctx, db, `UPDATE samples SET first_analyzed_at = $1 WHERE sha256 = $2`, now.Add(-5*time.Hour), sha)
			check(5 * time.Hour)

			// Acquisition finished, but the sample still needs investigation.
			if err := db.MarkSightingsAttempted(ctx, []Sighting{claim}); err != nil {
				t.Fatal(err)
			}
			check(5 * time.Hour)
			execBoth(t, ctx, db, `INSERT INTO reports (sha256, report_type, content) VALUES ($1, 'sighted', 'reviewed')`, sha)
			check(0)

			// Package claims must match the stored release, just as the queues do.
			pkg := hexSHA(502)
			mustInsert(t, ctx, db, &Sample{SHA256: pkg, Path: "pending/pkg.tgz"})
			mustAnalyze(t, ctx, db, pkg, 0)
			execBoth(t, ctx, db, `UPDATE samples SET purl_base = 'pkg:npm/example', version = '1.0.0',
			 created_at = $1, first_analyzed_at = $2, analyzed_at = $3 WHERE sha256 = $4`,
				now.Add(-9*time.Hour), now.Add(-9*time.Hour), now.Add(-9*time.Hour), pkg)
			addClaim("pkg:npm/example", "2.0.0", 7*time.Hour)
			check(0)
			addClaim("pkg:npm/example", "1.0.0", 4*time.Hour)
			check(4 * time.Hour)
			execBoth(t, ctx, db, `UPDATE samples SET skip = 'stuck' WHERE sha256 = $1`, pkg)
			check(0)
			execBoth(t, ctx, db, `UPDATE samples SET skip = '', label = 'bad' WHERE sha256 = $1`, pkg)
			check(0)
			execBoth(t, ctx, db, `UPDATE samples SET label = 'unknown', path = '' WHERE sha256 = $1`, pkg)
			check(0)
			execBoth(t, ctx, db, `UPDATE samples SET path = 'pending/pkg.tgz' WHERE sha256 = $1`, pkg)
			check(4 * time.Hour)

			// Historical claims stay in sighted, without paging as recent work.
			execBoth(t, ctx, db, `UPDATE sightings SET first_seen = $1 WHERE subject = 'pkg:npm/example'`, now.Add(-48*time.Hour))
			check(0)
			older, err := db.TriageSighted(ctx, 10, now.Add(-SightedPinnedWindow), TriageFilter{})
			if err != nil || len(older) != 1 || older[0].SHA256 != pkg {
				t.Fatalf("historical sighted work = %+v, %v; want the older package retained", older, err)
			}
		})
	}
}
