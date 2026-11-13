package store

import (
	"bytes"
	"cmp"
	"context"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"slices"
	"time"

	"github.com/atomdrift-project/hopper/scanresult"
	"github.com/jackc/pgx/v5"
	"github.com/klauspost/compress/zstd"
)

// Stats counts what one [Store.Write] changed.
type Stats struct {
	Files            int   // files named
	Judged           int   // files whose verdict this result spoke for
	Deferred         int   // members left to their own scan, or to another archive's as recent or more
	NewSamples       int64 // files never seen before
	Retyped          int64 // known files whose type or size the scan set or corrected
	Verdicts         int64 // verdict rows inserted, rewritten because the opinion changed, or refreshed (upsert)
	Stamped          int64 // the artifact's scans row written by a scan that reached a verdict
	JurorsRemoved    int64 // juror and scanner rows dropped because they no longer have an opinion
	Claims           int64 // identity blocks stored or replaced
	ClaimsRemoved    int64 // identity blocks dropped because the file no longer claims anything
	Reports          int64 // reports stored
	ReportsUnchanged int   // reports whose stored copy already matched
	Contents         int64 // containers whose member list was written or removed
	Orphaned         int64 // members no archive lists any more, whose verdicts were dropped
	Refs             int64 // references added or changed
	RefsRemoved      int64
	Requeued         int64 // containing archives queued for repair
	// Late is set when a later scan of the artifact is already recorded: the
	// result is stale, and nothing but unknown files' rows was written.
	Late bool
}

// Changed reports whether the write changed what is known: a row beyond the
// files it only named. A failed scan moving the artifact's last-scan time is
// bookkeeping, not knowledge, and does not count.
func (s *Stats) Changed() bool {
	return s.NewSamples+s.Retyped+s.Verdicts+s.Stamped+s.JurorsRemoved+s.Claims+s.ClaimsRemoved+s.Reports+
		s.Contents+s.Orphaned+s.Refs+s.RefsRemoved+s.Requeued > 0
}

// Write stores what a scan concluded about files, all of it or none. files[0]
// is the scanned artifact; the rest are what it contains. files must pass
// scanresult.Check, which Write runs first: an error wrapping
// scanresult.ErrMalformed is the result's fault and fails the same way on
// every retry.
//
// The work does not grow with what is already known: a row is written, or
// locked, only where it differs from the stored one, a report only where its
// digest does. What every scan writes is the artifact's one narrow scans
// row. A failed scan never replaces a successful verdict, and a result older
// than the artifact's last recorded scan changes nothing (Stats.Late).
func (st *Store) Write(ctx context.Context, files []scanresult.File) (Stats, error) {
	if err := scanresult.Check(files); err != nil {
		return Stats{}, fmt.Errorf("store: write: %w", err)
	}
	w := &writer{files: files, enc: st.enc, keepOrphans: st.KeepOrphans}
	w.stats.Files = len(files)
	err := pgx.BeginFunc(ctx, st.pool, func(tx pgx.Tx) error {
		w.tx = tx
		if err := w.samples(ctx); err != nil {
			return err
		}
		if late, err := w.late(ctx); err != nil || late {
			w.stats.Late = late
			return err
		}
		for _, step := range []func(context.Context) error{
			w.verdicts, w.stamp, w.claims, w.contents, w.refs, w.queue,
		} {
			if err := step(ctx); err != nil {
				return err
			}
		}
		return nil
	})
	if err != nil {
		return Stats{}, fmt.Errorf("store: write: %w", err)
	}
	return w.stats, nil
}

// writer carries one Write through its statements.
type writer struct {
	tx      pgx.Tx
	enc     *zstd.Encoder
	rose    map[int64]string // sample id to the class it rose to
	files   []scanresult.File
	ids     []int64 // sample id of files[i]
	own     []bool  // files[i] holds an opinion only a scan of the file itself gives
	scanned []bool  // files[i] has been scanned on its own: it has a scans row
	settled []bool  // member files[i] holds an opinion formed by this scan's time or later
	thinner []bool  // member files[i]'s line would replace a richer opinion with a looser one
	// reclaim is set when the scanned artifact's own opinion replaces a newer
	// one that came from an archive's line and would have been held back had
	// the two arrived in order (heldBack): its rows are written as formed at
	// that newer time, so the line, seen again, is settled.
	reclaim time.Time
	outcome []conclusion // what this scan concluded about files[i]
	stats   Stats
	// keepOrphans leaves members no list names any more as they are
	// (Store.KeepOrphans).
	keepOrphans bool
}

// conclusion is the outcome of a verdict, and its error text when it failed.
type conclusion struct {
	outcome string // "" when the file was only named
	err     string
}

// late takes the artifact's lock, which every Write of it holds to commit,
// and reports whether a later scan of it than this one is already recorded.
// Two results for one artifact are stored one after the other, so the older
// can never overwrite the newer, whichever arrives last. The read is its own
// statement so that it sees what a writer that held the lock committed.
func (w *writer) late(ctx context.Context) (bool, error) {
	if _, err := w.tx.Exec(ctx, `SELECT pg_advisory_xact_lock($1)`, w.ids[0]); err != nil {
		return false, fmt.Errorf("artifact lock: %w", err)
	}
	var late bool
	err := w.tx.QueryRow(ctx, `SELECT EXISTS (SELECT 1 FROM scans WHERE sample_id = $1 AND scanned_at > $2)`,
		w.ids[0], w.files[0].Scan.At).Scan(&late)
	if err != nil {
		return false, fmt.Errorf("artifact lock: %w", err)
	}
	return late, nil
}

// samples makes sure every file has a row with the type the scan gave it, and
// learns its id. Rows are inserted in digest order so two writers naming the
// same new files cannot deadlock.
func (w *writer) samples(ctx context.Context) error {
	shas, sizes, types := make([][]byte, len(w.files)), make([]int64, len(w.files)), make([]string, len(w.files))
	for i := range w.files {
		shas[i], sizes[i], types[i] = w.files[i].SHA256, w.files[i].Size, w.files[i].Type
	}
	tag, err := w.tx.Exec(ctx, `INSERT INTO samples (sha256, size_bytes, file_type)
		SELECT u.sha, nullif(u.size, 0), nullif(u.type, '')
		FROM unnest($1::bytea[], $2::bigint[], $3::text[]) AS u(sha, size, type)
		ORDER BY u.sha
		ON CONFLICT (sha256) DO NOTHING`, shas, sizes, types)
	if err != nil {
		return fmt.Errorf("samples: %w", err)
	}
	w.stats.NewSamples = tag.RowsAffected()

	rows, err := w.tx.Query(ctx, `SELECT u.ord, s.id,
			EXISTS (SELECT 1 FROM verdicts v WHERE v.sample_id = s.id AND v.scanner_id = ANY($2)),
			EXISTS (SELECT 1 FROM scans c WHERE c.sample_id = s.id),
			coalesce(a.formed_at >= $6, false),
			(u.type <> '' AND s.file_type IS DISTINCT FROM u.type) OR (s.size_bytes IS NULL AND u.size > 0),
			a.class::text, a.fires_at, coalesce(a.summary->>'reason', '') <> '', coalesce(a.summary ? 'top', false),
			a.formed_at
		FROM unnest($1::bytea[], $3::text[], $4::bigint[]) WITH ORDINALITY AS u(sha, type, size, ord)
		JOIN samples s ON s.sha256 = u.sha
		LEFT JOIN verdicts a ON a.sample_id = s.id AND a.scanner_id = $5`,
		shas, []int16{jurors["llm"], jurors["drift_heuristic"], jurors["drift_llm"]}, types, sizes,
		atomscan, w.files[0].Scan.At)
	if err != nil {
		return fmt.Errorf("sample ids: %w", err)
	}
	n := len(w.files)
	w.ids, w.own, w.scanned = make([]int64, n), make([]bool, n), make([]bool, n)
	w.settled, w.thinner = make([]bool, n), make([]bool, n)
	var (
		ord, id                       int64
		own, scanned, settled, retype bool
		stored                        storedOpinion
		stale                         []int64
		staleTypes                    []string
		staleSizes                    []int64
	)
	if _, err := pgx.ForEachRow(rows, []any{
		&ord, &id, &own, &scanned, &settled, &retype,
		&stored.class, &stored.firesAt, &stored.reason, &stored.top, &stored.formedAt,
	}, func() error {
		w.ids[ord-1], w.own[ord-1], w.scanned[ord-1], w.settled[ord-1] = id, own, scanned, settled && ord > 1
		old, hasOld := stored.facts()
		line, hasLine := factsOf(w.files[ord-1].Verdict)
		switch {
		case !hasOld || !hasLine:
		case ord > 1:
			w.thinner[ord-1] = heldBack(old, line)
		case stored.formedAt.After(w.files[0].Scan.At) && heldBack(line, old):
			w.reclaim = *stored.formedAt
		default:
		}
		if retype {
			stale, staleTypes, staleSizes = append(stale, id), append(staleTypes, types[ord-1]), append(staleSizes, sizes[ord-1])
		}
		return nil
	}); err != nil {
		return fmt.Errorf("sample ids: %w", err)
	}
	if len(stale) == 0 {
		return nil
	}
	// A file hopper learned of before it was scanned (ingest knows a path, and
	// perhaps a size, not a type) takes its type and size from the scan. Only
	// the rows that differ are touched, in digest order, as every writer of
	// samples takes them, so that two cannot deadlock.
	tag, err = w.tx.Exec(ctx, `WITH held AS (
			SELECT id FROM samples WHERE id = ANY($1) ORDER BY sha256 FOR NO KEY UPDATE)
		UPDATE samples s SET file_type = coalesce(nullif(u.type, ''), s.file_type),
			size_bytes = coalesce(s.size_bytes, nullif(u.size, 0))
		FROM unnest($1::bigint[], $2::text[], $3::bigint[]) AS u(id, type, size), held
		WHERE s.id = u.id AND s.id = held.id`, stale, staleTypes, staleSizes)
	if err != nil {
		return fmt.Errorf("sample types: %w", err)
	}
	w.stats.Retyped = tag.RowsAffected()
	return nil
}

// formed is the time file i's opinion rows are written as formed: the scan's,
// or, for the scanned artifact reclaiming its opinion (writer.reclaim), the
// time of the opinion it replaces.
func (w *writer) formed(i int) time.Time {
	if i == 0 && !w.reclaim.IsZero() {
		return w.reclaim
	}
	return w.files[i].Scan.At
}

// storedOpinion is a file's stored atomscan verdict, as read beside its row.
type storedOpinion struct {
	class    *string // nil when there is no stored verdict, or it reached no class
	formedAt *time.Time
	firesAt  *int
	reason   bool // it carries a reason: the interpretation a person reads
	top      bool // it carries findings
}

func (o *storedOpinion) facts() (opinionFacts, bool) {
	if o.class == nil || o.formedAt == nil {
		return opinionFacts{}, false
	}
	return opinionFacts{class: *o.class, firesAt: o.firesAt, reason: o.reason, top: o.top}, true
}

// opinionFacts is what deciding between two opinions of a file reads.
type opinionFacts struct {
	firesAt     *int
	class       string
	reason, top bool
}

// factsOf reads a verdict object; false for none, or for a failed scan,
// which has its own rule in verdicts.
func factsOf(verdict json.RawMessage) (opinionFacts, bool) {
	if verdict == nil {
		return opinionFacts{}, false
	}
	var v struct {
		Outcome string            `json:"outcome"`
		Class   string            `json:"class"`
		FiresAt *int              `json:"fires_at"`
		Reason  string            `json:"reason"`
		Top     []json.RawMessage `json:"top"`
	}
	if json.Unmarshal(verdict, &v) != nil || cmp.Or(v.Outcome, "ok") != "ok" || v.Class == "" {
		return opinionFacts{}, false
	}
	return opinionFacts{firesAt: v.FiresAt, class: v.Class, reason: v.Reason != "", top: len(v.Top) > 0}, true
}

// classRank orders classes by severity.
var classRank = map[string]int{"benign": 1, "suspicious": 2, "hostile": 3}

// heldBack reports whether the newer opinion of a file should not replace
// the older: it says less (no reason where the older has one, or no
// findings where it has them) and is no tighter (neither a more severe class
// nor, at the same class, a tighter level).
//
// A member's line comes from scanning the archive that holds the file, which
// often reads less of it than a scan of the file itself: a shallower walk, no
// interpretation, a coarser level. Seen in the migration rehearsal: a stealer
// judged hostile at L12 with an LLM reason and three crit-5 findings was
// replaced, minutes later, by an archive's line for it at L25 with neither
// (TestWriteMemberLineKeepsRicherVerdict). A line as rich as the stored
// verdict replaces it at any level, as a newer opinion should, and a tighter
// one replaces it however thin, so newer rules still convict.
//
// The writer asks it both ways, so arrival order does not decide: a member's
// line that is held back against the stored opinion is not written
// (writer.thinner), and the scanned artifact's own opinion replaces a newer
// one from an archive's line that would have been held back against it
// (writer.reclaim).
func heldBack(older, newer opinionFacts) bool {
	if (!older.reason || newer.reason) && (!older.top || newer.top) {
		return false // says as much
	}
	if n, o := classRank[newer.class], classRank[older.class]; n != o {
		return n < o
	}
	fires := func(l *int) bool { return l != nil && *l >= 0 }
	tighter := fires(newer.firesAt) && (!fires(older.firesAt) || *newer.firesAt < *older.firesAt)
	return !tighter
}

// stamp records that the artifact was scanned: when, and, for a scan that
// reached a verdict, under which ruleset and engine. A failed scan moves only
// the time, so the verdict from the last scan that worked keeps the ruleset
// it was confirmed under (on a first row too: a member scanned alone for the
// first time takes its verdict's) and the file stops looking overdue to the
// rescan-by-age sweep. An earlier upload than the one recorded, or the same
// one again, writes nothing.
//
// It also records whether the scan left something for triage (scans.flagged):
// atomscan, the floor or the model not benign, or a bad label. Runs after the
// verdicts step, so it reads what this scan concluded.
func (w *writer) stamp(ctx context.Context) error {
	scan, outcome := w.files[0].Scan, w.outcome[0].outcome
	if outcome == "" {
		return nil // the artifact's line carries no verdict: nothing was concluded
	}
	tag, err := w.tx.Exec(ctx, `INSERT INTO scans (sample_id, scanned_at, ruleset, engine, flagged)
		SELECT $1, $2, coalesce(v.ruleset, $3), coalesce(v.summary->>'eng', $4),
		       EXISTS (SELECT 1 FROM verdicts f WHERE f.sample_id = $1 AND f.scanner_id = ANY($7) AND f.class <> 'benign')
		       OR EXISTS (SELECT 1 FROM samples s WHERE s.id = $1 AND s.label = 'bad')
		FROM (VALUES (1)) AS one
		LEFT JOIN verdicts v ON NOT $5 AND v.sample_id = $1 AND v.scanner_id = $6 AND v.outcome = 'ok'
		ON CONFLICT (sample_id) DO UPDATE SET scanned_at = EXCLUDED.scanned_at, flagged = EXCLUDED.flagged,
			ruleset = CASE WHEN $5 THEN EXCLUDED.ruleset ELSE scans.ruleset END,
			engine  = CASE WHEN $5 THEN EXCLUDED.engine ELSE scans.engine END
		WHERE scans.scanned_at < EXCLUDED.scanned_at
		   OR (scans.scanned_at = EXCLUDED.scanned_at AND $5
		       AND (scans.ruleset, scans.engine) IS DISTINCT FROM (EXCLUDED.ruleset, EXCLUDED.engine))`,
		w.ids[0], scan.At, scan.Ruleset, scan.Engine, outcome == "ok", atomscan,
		[]int16{atomscan, jurors["floor"], jurors["ml"]})
	if err != nil {
		return fmt.Errorf("stamp: %w", err)
	}
	if outcome == "ok" {
		w.stats.Stamped = tag.RowsAffected()
	}
	return nil
}

// verdicts writes the verdict rows that differ from the stored ones, with
// their reports, and drops the rows of jurors that no longer have an opinion.
//
// A row is written when the opinion in it differs (outcome, class, level,
// report or summary), and refreshed when a newer scan agrees with it under
// another ruleset or after refreshAge (upsert). Any other rescan that finds
// the same thing writes no verdict; that it happened is the artifact's scans
// row (see stamp). So the ruleset and formed_at on a verdict say when its
// opinion was formed or last confirmed, and no scan replaces an opinion
// formed after it (another archive's newer reading of a shared member, say).
//
// A scan that failed never replaces atomscan's row from one that succeeded:
// an error on a rescan does not erase what is known. The same holds for
// another scanner's row: its failure does not replace what it found when it
// last worked.
//
// Another scanner's row carries that scanner's own stamp, and is written by
// the same rule as a juror's: a new signature database that finds the same
// thing refreshes it, the same database within refreshAge writes nothing.
// Unlike a juror's, it is never removed
// for being absent: whether a scanner runs depends on the uploading host, not
// on the file, so only the scanner's own report replaces its row.
func (w *writer) verdicts(ctx context.Context) error {
	var (
		lead, held   opinionRows // atomscan's and other scanners' rows; jurors' rows
		goneIDs      []int64
		goneScanners []int16
		goneTimes    []time.Time
	)
	file := make(map[int64]int, len(w.files)) // sample id to index in files
	w.outcome = make([]conclusion, len(w.files))
	for i := range w.files {
		f := &w.files[i]
		if f.Report != nil {
			// Until the write stores it: every report it does not is one
			// already stored, or one of a member it leaves alone.
			w.stats.ReportsUnchanged++
		}
		if f.Verdict == nil {
			continue
		}
		if i > 0 && (w.own[i] || w.settled[i] || w.thinner[i]) {
			// The LLM or isomer has judged this file in a scan of its own,
			// which read everything a member's line can say and more; or
			// another archive's scan, as recent as this one or more, formed
			// its opinion; or the stored opinion says more than this line
			// (heldBack). The file keeps it: replacing it here
			// would only be undone, and two archives scanned in the same second
			// would undo each other on every pass.
			w.stats.Deferred++
			continue
		}
		w.stats.Judged++
		file[w.ids[i]] = i
		var verdict struct {
			Outcome string `json:"outcome"`
			Error   string `json:"error"`
		}
		if err := json.Unmarshal(f.Verdict, &verdict); err != nil {
			return fmt.Errorf("file %d: verdict: %w", i, err)
		}
		w.outcome[i] = conclusion{cmp.Or(verdict.Outcome, "ok"), verdict.Error}
		if w.outcome[i].outcome == "ok" {
			// Only a scan that succeeded speaks for its jurors, and a
			// member's line only for the jurors a member's line can carry.
			for name, scanner := range jurors {
				if !w.speaks(i, name) && (i == 0 || name == "floor" || name == "ml") {
					goneIDs, goneScanners = append(goneIDs, w.ids[i]), append(goneScanners, scanner)
					goneTimes = append(goneTimes, w.formed(i))
				}
			}
		}
		if err := w.scannerRows(i, &lead); err != nil {
			return err
		}
		// What the scan says about itself rides on atomscan's row: the engine,
		// and the level it ran at when that is not the one implied. The worker
		// is logged with the result and not stored.
		level := f.Scan.Level
		if level == impliedLevel {
			level = 0
		}
		extra, err := json.Marshal(struct {
			Engine string `json:"eng,omitempty"`
			Level  int    `json:"level,omitempty"`
		}{f.Scan.Engine, level})
		if err != nil {
			return err
		}
		// Every report is compressed, though most are stored already: the
		// insert compares digests and keeps the stored copy when they match.
		var detail []byte
		if f.ReportLine != nil {
			detail = w.enc.EncodeAll(f.ReportLine, nil)
		}
		lead.add(w.ids[i], atomscan, string(f.Verdict), f.Scan.Ruleset, string(extra), w.formed(i), f.Report, detail)
		for name, opinion := range f.Jurors {
			if w.speaks(i, name) {
				held.add(w.ids[i], jurors[name], string(opinion), f.Scan.Ruleset, "{}", w.formed(i), nil, nil)
			}
		}
	}
	w.rose = map[int64]string{}
	if len(lead.ids) == 0 {
		return nil
	}
	at := w.files[0].Scan.At

	// A member's jurors are part of its opinion: when this scan changes them,
	// atomscan's row is rewritten too, so its formed_at says when the whole
	// opinion last changed, and a scan older than that (another archive's,
	// holding the same member) changes none of it. Without this, a newer
	// scan that dropped a member's juror and an older one that names it
	// would undo each other on every pass. The scanned artifact needs none
	// of this: its results are ordered by its lock (late).
	rows, err := w.tx.Query(ctx, `SELECT DISTINCT x.sample_id FROM (
			SELECT u.sample_id FROM unnest($1::bigint[], $2::smallint[], $3::jsonb[]) AS u(sample_id, scanner_id, opinion)
			LEFT JOIN verdicts v ON v.sample_id = u.sample_id AND v.scanner_id = u.scanner_id
			WHERE v.sample_id IS NULL OR (v.outcome, v.class, v.fires_at, v.summary) IS DISTINCT FROM
			      (coalesce((u.opinion->>'outcome')::outcome, 'ok'), (u.opinion->>'class')::class,
			       (u.opinion->>'fires_at')::smallint, u.opinion - 'outcome' - 'class' - 'fires_at')
			UNION ALL
			SELECT g.sample_id FROM unnest($4::bigint[], $5::smallint[]) AS g(sample_id, scanner_id)
			JOIN verdicts v ON v.sample_id = g.sample_id AND v.scanner_id = g.scanner_id) x
		WHERE x.sample_id <> $8
		  AND NOT EXISTS (SELECT 1 FROM verdicts a WHERE a.sample_id = x.sample_id AND a.scanner_id = $6 AND a.formed_at > $7)`,
		held.ids, held.scanners, held.opinions, goneIDs, goneScanners, atomscan, at, w.ids[0])
	if err != nil {
		return fmt.Errorf("jurors: %w", err)
	}
	reformed, err := pgx.CollectRows(rows, pgx.RowTo[int64])
	if err != nil {
		return fmt.Errorf("jurors: %w", err)
	}

	// The scanners whose last good row a failed scan leaves standing.
	lasting := []int16{atomscan}
	for _, scanner := range outside {
		lasting = append(lasting, scanner)
	}
	// atomscan's and the other scanners' rows first, then the jurors': every
	// writer takes them in that order, each part in key order, so two cannot
	// deadlock.
	n, err := w.upsert(ctx, &lead, lasting, reformed, func(id int64, old []byte, rose bool, class *string) {
		if report := w.files[file[id]].Report; report != nil && !bytes.Equal(old, report) {
			w.stats.Reports++
			w.stats.ReportsUnchanged--
		}
		// Worse than a verdict it already had: the archives holding it were
		// judged on a reading of it that is now too kind.
		if rose {
			w.rose[id] = *class
		}
	})
	if err != nil {
		return fmt.Errorf("verdicts: %w", err)
	}
	w.stats.Verdicts = n
	if n, err = w.upsert(ctx, &held, lasting, nil, nil); err != nil {
		return fmt.Errorf("jurors: %w", err)
	}
	w.stats.Verdicts += n
	if len(goneIDs) == 0 {
		return nil
	}
	tag, err := w.tx.Exec(ctx, `DELETE FROM verdicts d USING (
			SELECT v.sample_id, v.scanner_id FROM verdicts v
			JOIN unnest($1::bigint[], $2::smallint[], $3::timestamptz[]) AS g(sample_id, scanner_id, at)
			  ON v.sample_id = g.sample_id AND v.scanner_id = g.scanner_id
			WHERE v.formed_at <= g.at
			  AND NOT EXISTS (SELECT 1 FROM verdicts a WHERE a.sample_id = v.sample_id AND a.scanner_id = $4 AND a.formed_at > g.at)
			ORDER BY 1, 2 FOR UPDATE OF v) k
		WHERE d.sample_id = k.sample_id AND d.scanner_id = k.scanner_id`, goneIDs, goneScanners, goneTimes, atomscan)
	if err != nil {
		return fmt.Errorf("stale jurors: %w", err)
	}
	w.stats.JurorsRemoved = tag.RowsAffected()
	return nil
}

// scannerRows adds file i's rows from the scanners that are not atomdrift's.
// The engine rides beside the finding, as atomscan's does.
func (w *writer) scannerRows(i int, lead *opinionRows) error {
	for name, scanner := range outside {
		obj, has := w.files[i].Scanners[name]
		if !has {
			continue
		}
		found, err := scanresult.SplitScanner(name, obj)
		if err != nil {
			return fmt.Errorf("file %d: scanners: %s: %w", i, name, err) // Check passed it
		}
		extra, err := json.Marshal(struct {
			Engine string `json:"eng,omitempty"`
		}{found.Engine})
		if err != nil {
			return err
		}
		lead.add(w.ids[i], scanner, string(found.Opinion), found.Ruleset, string(extra), w.formed(i), nil, nil)
	}
	return nil
}

// impliedLevel is the level a scan ran at when atomscan's row does not say:
// L25, hopper.CriticalLevel when this was written. It is fixed, not the
// deployed default, so a row keeps its meaning when the default moves.
const impliedLevel = 25

// speaks reports whether file i's line has juror name state an opinion to
// store. A member's floor or ml juror that finds nothing (benign, firing at
// no level) is left unstored, as if the line had not named it: it says no
// more than atomscan's own benign row, and nearly every member says it. A
// file scanned on its own keeps it, since the triage queues read the model's
// score of the files they hand out (store/triage.go).
func (w *writer) speaks(i int, name string) bool {
	opinion, has := w.files[i].Jurors[name]
	if !has || i == 0 || w.scanned[i] || (name != "floor" && name != "ml") {
		return has
	}
	var o struct {
		FiresAt *int   `json:"fires_at"`
		Class   string `json:"class"`
	}
	quiet := json.Unmarshal(opinion, &o) == nil && o.Class == "benign" && (o.FiresAt == nil || *o.FiresAt < 0)
	return !quiet
}

// opinionRows are verdict rows to store, column by column.
type opinionRows struct {
	ids      []int64
	scanners []int16
	opinions []string // the scanner's object, outcome and class included
	rulesets []string
	extras   []string // what rides beside the opinion in summary (the engine)
	times    []time.Time
	digests  [][]byte // the report's, or nil
	details  [][]byte // the report, compressed, or nil
}

func (o *opinionRows) add(id int64, scanner int16, opinion, ruleset, extra string, at time.Time, digest, detail []byte) {
	o.ids, o.scanners, o.opinions = append(o.ids, id), append(o.scanners, scanner), append(o.opinions, opinion)
	o.rulesets, o.extras = append(o.rulesets, ruleset), append(o.extras, extra)
	o.times, o.digests, o.details = append(o.times, at), append(o.digests, digest), append(o.details, detail)
}

// refreshAge is how old a stored opinion may grow before a newer scan that
// agrees with it, under the same ruleset, writes its own time on the row:
// scan's DEFAULT_MAX_AGE_DAYS, the age past which it stops trusting a
// benign verdict from hopper in place of analyzing the bytes again.
const refreshAge = `interval '30 days'`

// upsert writes the rows of o that differ from the stored ones, and the
// atomscan rows of the files in reformed whatever they hold (their jurors
// change). A newer scan that agrees with a row refreshes it, writing its
// own time, ruleset and engine, when the row's ruleset differs or the row is
// older than refreshAge; within that, agreeing writes nothing. This is the
// rule scan applies before trusting hopper's verdict on a dependency (the
// same analyzer, or a verdict at most 30 days old), and it keeps formed_at
// the time of the newest scan that formed or confirmed the opinion, to that
// grain. Without it, a newer scan that agreed left no trace, and an older
// scan's different reading, arriving after it, replaced the newer one (seen
// in the migration rehearsal: a member read alike on Sep 29 and Nov 7 kept
// Oct 18's reading, from another engine; TestWriteAgreeingNewerScanRefreshes).
// A row is never replaced by a scan older than its file's
// opinion, and a failed scan never replaces a scanner in lasting's good
// row. Rows that would not change are left out before the insert, since a
// conflict clause whose WHERE is false still locks the row; the same test
// in the conflict clause covers a row another writer changed meanwhile.
// A row whose digest is unchanged keeps its stored report, so a large one in
// TOAST is not written again. written, if given, is told of each atomscan
// row written. upsert returns how many rows it wrote.
func (w *writer) upsert(ctx context.Context, o *opinionRows, lasting []int16, reformed []int64,
	written func(id int64, oldDigest []byte, rose bool, class *string),
) (int64, error) {
	if len(o.ids) == 0 {
		return 0, nil
	}
	rows, err := w.tx.Query(ctx, `INSERT INTO verdicts
			(sample_id, formed_at, outcome, class, scanner_id, fires_at, ruleset, digest, summary, detail)
		SELECT u.sample_id, u.at, u.outcome, u.class, u.scanner_id, u.fires_at, u.ruleset, u.digest, u.summary, u.detail
		FROM (SELECT u.sample_id, u.scanner_id, coalesce((u.opinion->>'outcome')::outcome, 'ok') AS outcome,
		             (u.opinion->>'class')::class AS class, (u.opinion->>'fires_at')::smallint AS fires_at,
		             u.ruleset, u.at, u.digest, u.detail,
		             (u.opinion - 'outcome' - 'class' - 'fires_at') || u.extra AS summary
		      FROM unnest($1::bigint[], $2::smallint[], $3::jsonb[], $4::text[], $5::timestamptz[], $6::bytea[], $7::jsonb[], $11::bytea[])
		          AS u(sample_id, scanner_id, opinion, ruleset, at, digest, extra, detail)) u
		LEFT JOIN verdicts v ON v.sample_id = u.sample_id AND v.scanner_id = u.scanner_id
		WHERE NOT EXISTS (SELECT 1 FROM verdicts a WHERE a.sample_id = u.sample_id AND a.scanner_id = $9 AND a.formed_at > u.at)
		  AND (v.sample_id IS NULL
		    OR ((v.scanner_id <> ALL($8) OR u.outcome = 'ok' OR v.outcome <> 'ok') AND v.formed_at <= u.at
		        AND ((v.outcome, v.class, v.fires_at, v.digest, v.summary - 'eng')
		             IS DISTINCT FROM (u.outcome, u.class, u.fires_at, u.digest, u.summary - 'eng')
		             OR (v.formed_at < u.at AND (v.ruleset <> u.ruleset OR v.formed_at < u.at - `+refreshAge+`))
		             OR (u.scanner_id = $9 AND u.sample_id = ANY($10)))))
		ORDER BY u.sample_id, u.scanner_id
		ON CONFLICT (sample_id, scanner_id) DO UPDATE SET
			formed_at = EXCLUDED.formed_at, outcome = EXCLUDED.outcome, class = EXCLUDED.class,
			fires_at = EXCLUDED.fires_at, ruleset = EXCLUDED.ruleset, digest = EXCLUDED.digest, summary = EXCLUDED.summary,
			detail = CASE WHEN verdicts.digest IS NOT DISTINCT FROM EXCLUDED.digest THEN verdicts.detail ELSE EXCLUDED.detail END
		WHERE (verdicts.scanner_id <> ALL($8) OR EXCLUDED.outcome = 'ok' OR verdicts.outcome <> 'ok')
		  AND verdicts.formed_at <= EXCLUDED.formed_at
		  AND ((verdicts.outcome, verdicts.class, verdicts.fires_at, verdicts.digest, verdicts.summary - 'eng')
		       IS DISTINCT FROM (EXCLUDED.outcome, EXCLUDED.class, EXCLUDED.fires_at, EXCLUDED.digest, EXCLUDED.summary - 'eng')
		       OR (verdicts.formed_at < EXCLUDED.formed_at
		           AND (verdicts.ruleset <> EXCLUDED.ruleset OR verdicts.formed_at < EXCLUDED.formed_at - `+refreshAge+`))
		       OR (EXCLUDED.scanner_id = $9 AND EXCLUDED.sample_id = ANY($10)))
		RETURNING sample_id, scanner_id, old.digest, coalesce(class > old.class, false), class::text`,
		o.ids, o.scanners, o.opinions, o.rulesets, o.times, o.digests, o.extras, lasting, atomscan, reformed, o.details)
	if err != nil {
		return 0, err
	}
	var (
		id      int64
		scanner int16
		old     []byte
		rose    bool
		class   *string
	)
	tag, err := pgx.ForEachRow(rows, []any{&id, &scanner, &old, &rose, &class}, func() error {
		if written != nil && scanner == atomscan {
			written(id, old, rose, class)
		}
		return nil
	})
	return tag.RowsAffected(), err
}

// claims stores what each file says it is where that differs from what is
// stored, and forgets the claim of a file a scan read and found to make none.
// A member that holds a verdict from a scan of its own is left alone here as
// it is in verdicts. Rows are taken in id order.
func (w *writer) claims(ctx context.Context) error {
	var (
		ids, gone                []int64
		names, versions, signers []string
		idents                   []string
	)
	for i := range w.files {
		f := &w.files[i]
		switch {
		case f.Ident == nil, i > 0 && (w.own[i] || w.settled[i] || w.thinner[i]):
		case string(f.Ident) == "null":
			gone = append(gone, w.ids[i])
		default:
			c, err := scanresult.ClaimOf(f.Ident)
			if err != nil {
				return fmt.Errorf("file %d: ident: %w", i, err) // Check passed it
			}
			ids, idents = append(ids, w.ids[i]), append(idents, string(f.Ident))
			names, versions, signers = append(names, c.Name), append(versions, c.Version), append(signers, c.Signer)
		}
	}
	if len(ids) > 0 {
		// Unchanged rows are left out before the insert: a conflict clause
		// whose WHERE is false still locks the row.
		tag, err := w.tx.Exec(ctx, `INSERT INTO claims (sample_id, name, version, signer, ident)
			SELECT u.id, u.name, u.version, u.signer, u.ident
			FROM unnest($1::bigint[], $2::text[], $3::text[], $4::text[], $5::jsonb[])
				AS u(id, name, version, signer, ident)
			LEFT JOIN claims c ON c.sample_id = u.id
			WHERE c.sample_id IS NULL OR c.ident <> u.ident
			ORDER BY u.id
			ON CONFLICT (sample_id) DO UPDATE SET
				name = EXCLUDED.name, version = EXCLUDED.version, signer = EXCLUDED.signer, ident = EXCLUDED.ident
			WHERE claims.ident <> EXCLUDED.ident`, ids, names, versions, signers, idents)
		if err != nil {
			return fmt.Errorf("claims: %w", err)
		}
		w.stats.Claims = tag.RowsAffected()
	}
	if len(gone) > 0 {
		tag, err := w.tx.Exec(ctx, `DELETE FROM claims d USING (
				SELECT sample_id FROM claims WHERE sample_id = ANY($1) ORDER BY sample_id FOR UPDATE) k
			WHERE d.sample_id = k.sample_id`, gone)
		if err != nil {
			return fmt.Errorf("stale claims: %w", err)
		}
		w.stats.ClaimsRemoved = tag.RowsAffected()
	}
	return nil
}

// contents writes the member list of each file that states one, then drops
// what hopper believed about members that no list names any more. A list is
// stored in path order, so the same members always compare equal.
//
// The scanned artifact's own list is replaced as its verdict is: late has
// already refused an older scan of it. A member's list is replaced only by a
// strictly newer scan's, the first of two from the same instant standing, as
// its opinion is. The list's own time decides, not its file's verdict: a scan
// can form a newer opinion of a file without listing what is inside it, and
// that says nothing about the members.
func (w *writer) contents(ctx context.Context) error {
	// Parents are taken in id order so two writers cannot deadlock.
	order := make([]int, 0, len(w.files))
	for i := range w.files {
		if w.files[i].Children != nil {
			order = append(order, i)
		}
	}
	slices.SortFunc(order, func(a, b int) int { return cmp.Compare(w.ids[a], w.ids[b]) })
	at := w.files[0].Scan.At
	batch := &pgx.Batch{}
	kept := make([]map[int64]bool, 0, len(order)) // the members each queued statement leaves listed
	for _, i := range order {
		f := &w.files[i]
		if len(f.Children) == 0 {
			batch.Queue(`UPDATE contents SET child_ids = '{}', paths = '{}', listed_at = $2
				WHERE parent_id = $1 AND (listed_at < $2 OR ($3 AND listed_at = $2)) AND cardinality(child_ids) > 0
				RETURNING old.child_ids`, w.ids[i], at, i == 0)
			kept = append(kept, nil)
			continue
		}
		type member struct {
			path string
			id   int64
		}
		list := make([]member, len(f.Children))
		for j, child := range f.Children {
			list[j] = member{f.Paths[j], w.ids[child]}
		}
		slices.SortFunc(list, func(a, b member) int { return cmp.Or(cmp.Compare(a.path, b.path), cmp.Compare(a.id, b.id)) })
		children, paths := make([]int64, len(list)), make([]string, len(list))
		listed := make(map[int64]bool, len(list))
		for j, m := range list {
			children[j], paths[j] = m.id, m.path
			listed[m.id] = true
		}
		// The list it replaces comes back with the write; it is NULL for a
		// container seen for the first time. An unchanged list, or a stored
		// one this scan does not replace, is left out before the insert, so it
		// is neither written nor locked.
		batch.Queue(`INSERT INTO contents (parent_id, listed_at, child_ids, paths)
			SELECT $1, $4, $2, $3 WHERE NOT EXISTS (SELECT 1 FROM contents WHERE parent_id = $1
				AND (listed_at > $4 OR (listed_at = $4 AND NOT $5) OR (child_ids = $2 AND paths = $3)))
			ON CONFLICT (parent_id) DO UPDATE
				SET listed_at = EXCLUDED.listed_at, child_ids = EXCLUDED.child_ids, paths = EXCLUDED.paths
			WHERE (contents.listed_at < EXCLUDED.listed_at OR ($5 AND contents.listed_at = EXCLUDED.listed_at))
			  AND (contents.child_ids, contents.paths) IS DISTINCT FROM (EXCLUDED.child_ids, EXCLUDED.paths)
			RETURNING old.child_ids`,
			w.ids[i], children, paths, at, i == 0)
		kept = append(kept, listed)
	}
	if batch.Len() == 0 {
		return nil
	}
	var left []int64 // members a list named before this write and does not now
	results := w.tx.SendBatch(ctx, batch)
	for _, listed := range kept {
		rows, err := results.Query()
		if err != nil {
			return errors.Join(fmt.Errorf("contents: %w", err), results.Close())
		}
		var old []int64
		tag, err := pgx.ForEachRow(rows, []any{&old}, func() error {
			for _, id := range old {
				if !listed[id] {
					left = append(left, id)
				}
			}
			return nil
		})
		if err != nil {
			return errors.Join(fmt.Errorf("contents: %w", err), results.Close())
		}
		w.stats.Contents += tag.RowsAffected()
	}
	if err := results.Close(); err != nil {
		return fmt.Errorf("contents: %w", err)
	}
	if w.keepOrphans {
		return nil
	}
	return w.orphans(ctx, left)
}

// orphans drops the verdicts and claims of files that have just left an
// archive's member list and that nothing else accounts for. Scan uploads a member only while
// it has something to say about it, so a member that drops out has been
// found unremarkable, or has fallen below the upload's cap; hopper holds no
// bytes to scan it again, and without this its last verdict would stand for
// good.
//
// A file is left alone if another archive still lists it, or if it is a file
// in its own right: one with a location, a name, a URL or provenance. An
// orphaned container gives up its own member list too, so its members are
// considered in turn. The sample row stays: its id may be in a list another
// writer is committing.
//
// The candidates' sample rows are locked first, in digest order as every
// writer of samples takes them: a writer giving one of them a verdict holds
// a key lock on the row until it commits, so this waits for it, and the test
// that follows, a statement of its own, sees the list that writer committed.
func (w *writer) orphans(ctx context.Context, left []int64) error {
	for len(left) > 0 {
		slices.Sort(left)
		left = slices.Compact(left)
		if _, err := w.tx.Exec(ctx, `SELECT 1 FROM samples WHERE id = ANY($1) ORDER BY sha256 FOR UPDATE`, left); err != nil {
			return fmt.Errorf("orphaned members: %w", err)
		}
		var n int64
		// Verdict rows are taken in key order, as every writer takes them.
		err := w.tx.QueryRow(ctx, `WITH orphan AS (
				SELECT s.id FROM samples s
				WHERE s.id = ANY($1) AND s.name_id IS NULL AND s.url IS NULL AND s.provenance IS NULL
				  AND NOT EXISTS (SELECT 1 FROM locations l WHERE l.sample_id = s.id)
				  AND NOT EXISTS (SELECT 1 FROM contents c WHERE c.child_ids @> ARRAY[s.id])
			), v AS (
				DELETE FROM verdicts d USING (
					SELECT sample_id, scanner_id FROM verdicts WHERE sample_id IN (SELECT id FROM orphan)
					ORDER BY sample_id, scanner_id FOR UPDATE) k
				WHERE d.sample_id = k.sample_id AND d.scanner_id = k.scanner_id
				RETURNING d.sample_id
			), i AS (
				DELETE FROM claims d USING (
					SELECT sample_id FROM claims WHERE sample_id IN (SELECT id FROM orphan)
					ORDER BY sample_id FOR UPDATE) k
				WHERE d.sample_id = k.sample_id
			), c AS (
				DELETE FROM contents WHERE parent_id IN (SELECT id FROM orphan) RETURNING child_ids
			)
			SELECT (SELECT count(DISTINCT sample_id) FROM v),
			       ARRAY(SELECT DISTINCT m FROM c, unnest(c.child_ids) AS m)`, left).Scan(&n, &left)
		if err != nil {
			return fmt.Errorf("orphaned members: %w", err)
		}
		w.stats.Orphaned += n
	}
	return nil
}

// refs replaces the references of each file that states them. Package names
// are spelled the way hopper spells a sample's name, so that a ref and the
// release it names meet on the same interned name.
func (w *writer) refs(ctx context.Context) error {
	var (
		holders, samples           []int64
		names, versions, requested []string
		kinds                      []string
		fetched                    [][]byte
	)
	for i := range w.files {
		if w.files[i].Refs == nil {
			continue
		}
		holders = append(holders, w.ids[i])
		for _, r := range w.files[i].Refs {
			r.Name = NameOf(r.Name)
			var sum []byte
			if r.SHA256 != "" {
				sum, _ = hex.DecodeString(r.SHA256) //nolint:errcheck // Check has seen that it is a sha256
			}
			samples, names, versions = append(samples, w.ids[i]), append(names, r.Name), append(versions, r.Version)
			kinds, requested, fetched = append(kinds, r.Kind), append(requested, r.Requested), append(fetched, sum)
		}
	}
	if len(holders) == 0 {
		return nil
	}
	if err := intern(ctx, w.tx, names); err != nil {
		return err
	}
	// incoming is the stated references with their names resolved to ids.
	const incoming = `(SELECT u.sample_id, n.id AS name_id, u.version, u.kind::ref_kind AS kind, u.requested, u.fetched
		FROM unnest($1::bigint[], $2::text[], $3::text[], $4::text[], $5::text[], $6::bytea[])
			AS u(sample_id, name, version, kind, requested, fetched)
		JOIN names n ON n.name = u.name)`
	args := []any{samples, names, versions, kinds, requested, fetched}
	tag, err := w.tx.Exec(ctx, `DELETE FROM refs r WHERE r.sample_id = ANY($7)
		AND NOT EXISTS (SELECT 1 FROM `+incoming+` k
		                WHERE (k.sample_id, k.name_id, k.version, k.kind) = (r.sample_id, r.name_id, r.version, r.kind))`,
		append(args, holders)...)
	if err != nil {
		return fmt.Errorf("stale refs: %w", err)
	}
	w.stats.RefsRemoved = tag.RowsAffected()
	// Two declarations bound to one version are one ref; which constraint it
	// keeps is fixed by the order, so a repeat of the same result writes
	// nothing.
	// An unchanged ref is left out before the insert, so it is neither
	// written nor locked.
	tag, err = w.tx.Exec(ctx, `INSERT INTO refs (sample_id, name_id, version, kind, requested, fetched)
		SELECT k.sample_id, k.name_id, k.version, k.kind, k.requested, k.fetched
		FROM (SELECT DISTINCT ON (k.sample_id, k.name_id, k.version, k.kind) k.*
		      FROM `+incoming+` k
		      ORDER BY k.sample_id, k.name_id, k.version, k.kind, k.requested, k.fetched NULLS LAST) k
		LEFT JOIN refs r ON (r.sample_id, r.name_id, r.version, r.kind) = (k.sample_id, k.name_id, k.version, k.kind)
		WHERE r.sample_id IS NULL OR (r.requested, r.fetched) IS DISTINCT FROM (k.requested, k.fetched)
		ORDER BY k.sample_id, k.name_id, k.version, k.kind
		ON CONFLICT (sample_id, name_id, version, kind) DO UPDATE SET
			requested = EXCLUDED.requested, fetched = EXCLUDED.fetched
		WHERE (refs.requested, refs.fetched) IS DISTINCT FROM (EXCLUDED.requested, EXCLUDED.fetched)`, args...)
	if err != nil {
		return fmt.Errorf("refs: %w", err)
	}
	w.stats.Refs = tag.RowsAffected()
	return nil
}

// intern makes sure every name has a row. Names already stored are left out
// before the insert, so a known name neither locks a row nor burns an id.
func intern(ctx context.Context, tx pgx.Tx, names []string) error {
	if _, err := tx.Exec(ctx, `INSERT INTO names (name)
		SELECT DISTINCT n FROM unnest($1::text[]) AS n
		WHERE n <> '' AND NOT EXISTS (SELECT 1 FROM names WHERE name = n)
		ORDER BY n
		ON CONFLICT (name) DO NOTHING`, names); err != nil {
		return fmt.Errorf("names: %w", err)
	}
	return nil
}
