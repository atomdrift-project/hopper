package main

// demote-sighted is the one-time (idempotent, resumable) backfill that moves
// every listing-feed claim out of the bad/ training pool into sighted/. It is
// the migration half of the "feeds are reporters, not judges" change: going
// forward forager labels listing-feed downloads sighted, and promoter
// promotes sighted→bad on evidence; this command applies the same standard
// retroactively.
//
// The tool deliberately applies NO keep-criteria of its own: promoter's
// sighted pass re-promotes qualifying rows (hostile scan class,
// 2-independent-family corroboration, suspicious_count >= 3) into
// bad/foraged-quarantine on its first loop after the migration. Duplicating
// those rules here would be a second implementation free to drift, and the
// end state is cleaner: bad/foraged/ holds only byte-corpus samples, every
// listing-feed claim lives in sighted/foraged/ (unconfirmed) or
// bad/foraged-quarantine/ (evidence-confirmed). Run promoter immediately
// after -apply so hostile rows return to the bad pool within one pass.
//
// Demotion goes through the master's /api/triage ruling "sighted"
// (EXDEV-safe file move bad/foraged/X -> sighted/foraged/X + DB relabel +
// label_events audit, per-row idempotent). Archive members of demoted parents
// are demoted in a DB-only pass (members have no standalone file), and each
// demoted parent's own feed claim is recorded in the sightings ledger so
// promoter's family counting sees it.
//
// Default is a dry-run report; nothing moves without -apply.

import (
	"context"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"os"
	"slices"
	"sort"

	"github.com/atomdrift-project/hopper"
)

// demoteSightedSource is the label_source stamped on rows this backfill
// demotes, so the migration is identifiable (and reversible) in label_events
// and samples alike.
const demoteSightedSource = "sighted-backfill"

// listingFeeds maps samples.feed values written by forager's metadata-only
// threat feeds — current names and their legacy pre-rename spellings — to the
// feed's sightings source ID (the ThreatFeed record name). Only rows whose
// feed appears here are candidates: these feeds assert claims without
// providing bytes. Byte-serving corpora (vxug, malwarebazaar/abuse.ch,
// virussign, malshare, datadog, backstabbers, objectivesee, localrepo) are
// deliberately absent — they hand us the malware itself, so their bad labels
// stand.
var listingFeeds = map[string]string{
	"aikido.dev":              "aikido",
	"aikido":                  "aikido",
	"socket.dev":              "socket",
	"osv.dev":                 "osv",
	"osv":                     "osv",
	"opensourcemalware.com":   "osm",
	"opensourcemalware":       "osm",
	"github-advisories":       "ghsa",
	"ossf-malicious-packages": "ossf",
	"supplychainattack.org":   "supplychain",
	"safedep":                 "safedep",
	"stepsecurity":            "stepsecurity",
	"koi.security":            "koi",
	"koi":                     "koi",
	"research.jfrog.com":      "jfrog",
	"jfrog":                   "jfrog",
	"kmsec.uk":                "kmsec",
	"kmsec":                   "kmsec",
	"extsentry.github.io":     "extsentry",
	"vsxsentry.github.io":     "vsxsentry",
	"vsxsentry":               "vsxsentry",
	"manifest":                "manifest",
	"clawhub.ai":              "manifest",
	"skills.sh":               "manifest",
}

// backfillLabelSources are the label_source values a candidate may carry:
// forager's direct inserts ("forager"), hopper's own load-walk gap-fills
// (SourceFilesystem), the pre-rename spelling ("harvest"), and the odd walker
// row with no recorded source. Rows relabeled by markers, conflict resolution,
// triage, or cyclotron are real evidence and never candidates.
var backfillLabelSources = []string{"forager", hopper.SourceFilesystem, "harvest", ""}

// demoteCandidate is one bad/foraged row to demote. litmusClass rides along
// only for the dry-run report (it predicts how many rows promoter will
// immediately re-promote as hostile).
type demoteCandidate struct {
	sha256      string
	path        string
	feed        string
	labelSource string
	purlBase    string
	url         string
	litmusClass int
}

func cmdDemoteSighted(ctx context.Context) error {
	f := flag.NewFlagSet("demote-sighted", flag.ExitOnError)
	dsn := f.String("db", "", "database DSN (default: $DATABASE_URL)")
	//nolint:revive // unsecure-url-scheme: the master API is a plain-http internal cluster endpoint
	baseURL := f.String("url", "http://hopper-api:8081/", "hopper master API base URL")
	apply := f.Bool("apply", false, "apply the demotions (default: dry-run report only)")
	batch := f.Int("batch", 1000, "verdicts per /api/triage request")
	manifest := f.String("manifest", "demote-sighted-manifest.jsonl", "append per-row move results here (the rollback record)")
	parseFlags(f, os.Args[2:])

	db, err := openDB(ctx, *dsn)
	if err != nil {
		return err
	}
	defer db.Close()
	if db.Pool() == nil {
		return errors.New("demote-sighted requires the postgres backend (sightings evidence lives there)")
	}

	cands, err := demoteCandidates(ctx, db)
	if err != nil {
		return err
	}

	printDemoteReport(cands)

	memberCount, err := demoteMemberPass(ctx, db, true)
	if err != nil {
		return err
	}

	if !*apply {
		writeStdoutf("\ndry-run: would demote %d parent(s) and %d archive member(s); re-run with -apply\n",
			len(cands), memberCount)
		return nil
	}

	// Record each candidate's own feed claim in the sightings ledger before
	// anything moves: rows downloaded before the ledger existed carry no
	// citation from their own feed, and promoter's family counting (and rule
	// (a) above on a re-run) needs it. Idempotent bulk upsert.
	if err := backfillSelfSightings(ctx, db, cands); err != nil {
		return err
	}

	if err := demoteParents(ctx, *baseURL, *manifest, cands, *batch); err != nil {
		return err
	}

	// Members have no top-level file of their own, so their demotion is
	// DB-only. Runs after the parents so the sighted-parent set is complete.
	members, err := demoteMemberPass(ctx, db, false)
	if err != nil {
		return err
	}
	writeStdoutf("demoted %d archive member(s)\n", members)
	writeStdoutf("run promoter now: its sighted pass re-promotes hostile/corroborated rows into bad/foraged-quarantine\n")
	return nil
}

// demoteCandidates selects every top-level bad/foraged row attributable to a
// listing feed.
func demoteCandidates(ctx context.Context, db *hopper.DB) ([]*demoteCandidate, error) {
	feeds := make([]string, 0, len(listingFeeds))
	for feed := range listingFeeds {
		feeds = append(feeds, feed)
	}
	slices.Sort(feeds)

	rows, err := db.Pool().Query(ctx, `
		SELECT sha256, path, feed, label_source, purl_base, url, COALESCE(litmus_class, 0)
		FROM samples
		WHERE parent = '' AND label = 'bad'
		  AND path LIKE 'bad/foraged/%'
		  AND feed = ANY($1)
		  AND label_source = ANY($2)
		ORDER BY sha256`, feeds, backfillLabelSources)
	if err != nil {
		return nil, fmt.Errorf("demote-sighted: candidates: %w", err)
	}
	defer rows.Close()

	var cands []*demoteCandidate
	for rows.Next() {
		c := &demoteCandidate{}
		if err := rows.Scan(&c.sha256, &c.path, &c.feed, &c.labelSource, &c.purlBase, &c.url,
			&c.litmusClass); err != nil {
			return nil, fmt.Errorf("demote-sighted: scan candidate: %w", err)
		}
		cands = append(cands, c)
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("demote-sighted: candidates: %w", err)
	}
	return cands, nil
}

// printDemoteReport prints the per-feed breakdown that makes the dry run
// reviewable before anything moves. The hostile column predicts how many rows
// promoter's first sighted pass will immediately return to the bad pool.
func printDemoteReport(cands []*demoteCandidate) {
	type tally struct{ total, hostile int }
	perFeed := map[string]*tally{}
	hostile := 0
	for _, c := range cands {
		t := perFeed[c.feed]
		if t == nil {
			t = &tally{}
			perFeed[c.feed] = t
		}
		t.total++
		if c.litmusClass == 2 {
			t.hostile++
			hostile++
		}
	}

	feeds := make([]string, 0, len(perFeed))
	for feed := range perFeed {
		feeds = append(feeds, feed)
	}
	sort.Slice(feeds, func(i, j int) bool { return perFeed[feeds[i]].total > perFeed[feeds[j]].total })

	writeStdoutf("%-26s %9s %9s\n", "feed", "demote", "hostile")
	for _, feed := range feeds {
		t := perFeed[feed]
		writeStdoutf("%-26s %9d %9d\n", feed, t.total, t.hostile)
	}
	writeStdoutf("%-26s %9d %9d\n", "TOTAL", len(cands), hostile)
	writeStdoutf("\nall rows demote to sighted/; the hostile column returns via promoter's first pass\n")
}

// backfillSelfSightings records each candidate's own feed claim (sha256 and
// purl_base subjects) in the sightings ledger. AddSightings is a delta-guarded
// idempotent upsert, so re-running is near-free.
func backfillSelfSightings(ctx context.Context, db *hopper.DB, cands []*demoteCandidate) error {
	sightings := make([]hopper.Sighting, 0, 2*len(cands))
	for _, c := range cands {
		source := listingFeeds[c.feed]
		sightings = append(sightings, hopper.Sighting{Source: source, Subject: c.sha256, URL: c.url})
		if c.purlBase != "" {
			sightings = append(sightings, hopper.Sighting{Source: source, Subject: c.purlBase, URL: c.url})
		}
	}
	n, err := db.AddSightings(ctx, sightings)
	if err != nil {
		return fmt.Errorf("demote-sighted: backfill sightings: %w", err)
	}
	writeStdoutf("recorded %d self-sighting(s) for %d candidate(s)\n", n, len(cands))
	return nil
}

// demoteParents streams "sighted" rulings to the master in batches, appending
// each per-row result to the manifest file (the rollback record). The master
// performs the move + relabel and is per-row idempotent, so a rerun after a
// crash converges.
func demoteParents(ctx context.Context, baseURL, manifestPath string, demote []*demoteCandidate, batch int) error {
	mf, err := os.OpenFile(manifestPath, os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0o644) //nolint:gosec // operator-chosen log path
	if err != nil {
		return fmt.Errorf("demote-sighted: open manifest: %w", err)
	}
	defer mf.Close() //nolint:errcheck // flushed per write; nothing buffered

	enc := json.NewEncoder(mf)
	var moved, noop, absent, failed int
	for start := 0; start < len(demote); start += batch {
		chunk := demote[start:min(start+batch, len(demote))]
		verdicts := make([]triageVerdict, 0, len(chunk))
		for _, c := range chunk {
			verdicts = append(verdicts, triageVerdict{SHA256: c.sha256, Ruling: "sighted", Source: demoteSightedSource})
		}
		resp, err := postTriage(ctx, baseURL, triageRequest{Verdicts: verdicts})
		if err != nil {
			return fmt.Errorf("demote-sighted: triage batch at %d/%d: %w", start, len(demote), err)
		}
		for _, r := range resp.Results {
			if err := enc.Encode(r); err != nil {
				return fmt.Errorf("demote-sighted: manifest write: %w", err)
			}
			if r.Status == "error" || r.Status == "not_found" {
				writeStdoutf("  %-9s %s  %s\n", r.Status, r.SHA256, r.Error)
			}
		}
		moved += resp.Moved
		noop += resp.Noop
		absent += resp.Absent
		failed += resp.Failed
		writeStdoutf("demoted %d/%d (noop %d, absent %d, failed %d)\n", moved, len(demote), noop, absent, failed)
	}
	writeStdoutf("\nSummary: %d demoted to sighted/, %d noop, %d absent, %d failed (manifest: %s)\n",
		moved, noop, absent, failed, manifestPath)
	if absent > 0 {
		writeStdoutf("%d row(s) deferred: their bytes are not on this host (partial mirror); their labels\n"+
			"are untouched — re-run demote-sighted after the full corpus is attached to converge.\n", absent)
	}
	if failed > 0 {
		return fmt.Errorf("demote-sighted: %d row(s) failed", failed)
	}
	return nil
}

// demoteMemberPass demotes archive members of sighted parents that carry only
// the inherited (or cascade-derived) bad label: no top-level bad-pool copy of
// their own, and no other parent still labeled bad. Members have no
// standalone file, so this is DB-only. dryRun returns the eligible count
// without writing. Idempotent: demoted members leave the candidate set.
func demoteMemberPass(ctx context.Context, db *hopper.DB, dryRun bool) (int, error) {
	const eligible = `
		WITH sighted_parents AS (
			SELECT sha256 FROM samples WHERE parent = '' AND label = 'sighted'
		),
		cand AS (
			SELECT DISTINCT m.sha256
			FROM sample_locations l
			JOIN sighted_parents d ON d.sha256 = l.parent_sha256
			JOIN samples m ON m.sha256 = l.sha256
			WHERE m.label = 'bad'
			  AND (m.label_source = ANY($1) OR m.label_source = 'cascade:' || l.parent_sha256)
		)
		SELECT c.sha256 FROM cand c
		WHERE NOT EXISTS (
			SELECT 1 FROM sample_locations tl
			WHERE tl.sha256 = c.sha256 AND tl.parent_sha256 = '' AND tl.path LIKE 'bad/%')
		  AND NOT EXISTS (
			SELECT 1 FROM sample_locations pl
			JOIN samples p ON p.sha256 = pl.parent_sha256
			WHERE pl.sha256 = c.sha256 AND pl.parent_sha256 <> '' AND p.label = 'bad')`

	if dryRun {
		var n int
		err := db.Pool().QueryRow(ctx, `SELECT count(*) FROM (`+eligible+`) e`, backfillLabelSources).Scan(&n)
		if err != nil {
			return 0, fmt.Errorf("demote-sighted: member count: %w", err)
		}
		return n, nil
	}

	tag, err := db.Pool().Exec(ctx, `
		WITH e AS (`+eligible+`),
		upd AS (
			UPDATE samples s SET label = 'sighted', label_source = $2, updated_at = now()
			FROM e WHERE s.sha256 = e.sha256 AND s.label = 'bad'
			RETURNING s.sha256
		)
		INSERT INTO label_events (sha256, from_label, to_label, from_skip, to_skip, reason, observed_at)
		SELECT sha256, 'bad', 'sighted', '', '', $2, now() FROM upd`,
		backfillLabelSources, demoteSightedSource)
	if err != nil {
		return 0, fmt.Errorf("demote-sighted: member demote: %w", err)
	}
	return int(tag.RowsAffected()), nil
}
