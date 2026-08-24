package hopper

// triagequeues.go is the triage queue registry: the named selections cyclotron's
// workers pull from, and the depth counts an operator reads.
//
// A "queue" is nothing more than a parametrized SELECT over the samples table —
// for most, the newest top-level (parent='') misfiles whose stored label
// disagrees with cleave's verdict. Processing an item resolves the disagreement,
// so the same query naturally returns the next-newest work on the following
// pass: the queue drains itself. The exceptions are called out per queue below.
//
// The definitions live in hopper rather than in the consumer because everything
// they are made of already does: the Triage* selectors, the Count* depths, the
// TriageFilter shape, and the drain predicates that anti-join a reports row
// named for the queue. That last one is why the split was untenable — hopper's
// triage SQL matches 'second'/'acquit'/'highest'/'lowest' literally, so the wire
// name was already a contract between the two systems, just an undeclared one.
//
// What deliberately does NOT live here is everything a consumer decides ABOUT a
// queue: its display name, its provider chain and tier, how many workers it
// runs, which outcomes file a drain report. Those are policy, they change on the
// consumer's cadence, and hopper has no opinion on them.

import (
	"context"
	"sort"
	"time"
)

// Queue is one triage queue. Select returns up to n candidates in the queue's
// order; the caller decides how many it can actually work.
//
// Depth reports how much work is waiting, for an operator surface. It reads the
// Count* selectors rather than restating any predicate here, so a depth cannot
// drift from the queue it describes. It is nil for the three queues that have no
// countable population (see below) — callers must nil-check rather than assume.
//
// For most queues depth is exactly the selector's population. For the ones whose
// selection is bounded by construction it is the population they are working
// THROUGH, which is the number an operator wants but is not a selection count:
// highest and lowest take each route's top-K, so their depth is how many samples
// the model and the label disagree about (TriageScoreDivider); stranded returns
// parent archives, so its depth counts the MEMBERS still awaiting a verdict,
// which is what the work is actually measured in.
type Queue struct {
	Select func(ctx context.Context, db *DB, n int) ([]*Sample, error)
	Depth  func(ctx context.Context, db *DB) (int64, error)
	Name   string
}

// The grace windows the score- and evidence-ranked queues select against.
// Exported because they are operator-visible tuning, not internals: a consumer
// that renders "why is this queue empty" needs to say how long the wait is.
const (
	// SecondOpinionSettle is how long after a sample's most recent analysis the
	// second-opinion queue waits before re-judging it, so the first pass's
	// write-backs and relabels finish landing before a premium review spends
	// tokens on it.
	SecondOpinionSettle = 24 * time.Hour

	// AcquitGrace is how old a conviction must be before the acquit queue
	// questions it: long enough for threat feeds to corroborate a genuinely
	// malicious sample, so the queue only ever holds convictions the world has
	// had a fair chance to confirm.
	AcquitGrace = 72 * time.Hour

	// OutlierGrace holds the highest/lowest queues off anything newer than this.
	// Those two are score-ranked over the same rows good and bad walk
	// newest-first, so the age floor keeps the pairs working opposite ends of the
	// table instead of contending for the same per-sha tmp dirs. It also lets a
	// fresh sample's score settle — re-analysis and late sightings both move it —
	// before a premium review spends tokens on it.
	OutlierGrace = 48 * time.Hour

	// FalloutWindow bounds how far back the fallout queue reaches. Selection is
	// newest-first, so widening it only adds tail: the freshest gaps are always
	// worked ahead of older ones. Matches the 7 days the public fallout page
	// renders — the queue covers exactly what the page shows, and anything older
	// backfills through the ordinary queues.
	FalloutWindow = 7 * 24 * time.Hour
)

// staleTriageFilter builds the TriageFilter for a queue that walks
// least-recently-analyzed first and drains via a report row named for itself.
//
// MinAnalyzedAt is deliberately left zero. Bounding it would restrict the queue
// to rows whose verdict is recent enough to trust, but the only thing that
// refreshes a verdict is a re-scan, and the rescan tier reaches this population
// at roughly 1.4k/day against a 1.6M backlog — a floor would gate the queue's
// ~30/day on that, for no gain. The report drain covers the same ground from the
// other side: a stale row that current traits already catch is judged once,
// produces no edit, and is parked until something re-scans it.
func staleTriageFilter(queue string) TriageFilter {
	return TriageFilter{
		Order:             TriageStale,
		ExcludeReportType: queue,
	}
}

// TriageQueues is the registry. Keys are the wire names, which are load-bearing
// in ways a rename would silently break — they are the reports row type the
// review and stale queues drain through (the triage SQL matches them literally),
// and consumers derive relabel sources, metric job names and dashboard keys from
// them. Renaming one is a data migration, not a refactor.
var TriageQueues = map[string]Queue{
	// bad: bad-labeled samples cleave missed (false negatives) → write traits.
	"bad": {Name: "bad", Select: func(ctx context.Context, db *DB, n int) ([]*Sample, error) {
		return db.TriageBad(ctx, n, TriageFilter{})
	}, Depth: func(ctx context.Context, db *DB) (int64, error) {
		return db.CountTriageBad(ctx, TriageFilter{})
	}},

	// good: good-labeled samples that trip detection — a hostile trait, 2+
	// suspicious traits, or a suspicious+ litmus class (false positives) →
	// loosen traits.
	"good": {Name: "good", Select: func(ctx context.Context, db *DB, n int) ([]*Sample, error) {
		return db.TriageGood(ctx, n, TriageFilter{})
	}, Depth: func(ctx context.Context, db *DB) (int64, error) {
		return db.CountTriageGood(ctx, TriageFilter{})
	}},

	// new: unknown-labeled samples cleave flagged → classify, file, and train.
	"new": {Name: "new", Select: func(ctx context.Context, db *DB, n int) ([]*Sample, error) {
		return db.TriageNew(ctx, n, TriageFilter{})
	}, Depth: func(ctx context.Context, db *DB) (int64, error) {
		return db.CountTriageNew(ctx, TriageFilter{})
	}},

	// sighted: every non-bad sample covered by a malicious or suspicious ledger
	// sighting → verify the claim, writing traits when malicious. Exact version
	// claims only cover that release; a claim without a version covers the whole
	// package. Vulnerability claims stay out. The legacy sighted label is not
	// evidence and does not select work. A bad ruling drains via relabel and a
	// confirmed non-bad ruling via report. Depth is intentionally omitted: an
	// exact count expands every broad package claim across the corpus, while the
	// bounded selector only needs the head of that join.
	"sighted": {Name: "sighted", Select: func(ctx context.Context, db *DB, n int) ([]*Sample, error) {
		return db.TriageSighted(ctx, n, TriageFilter{})
	}},

	// second: good-labeled samples whose benign label an outside source disputes
	// (a trusted malware-hosting source, or 2+ independent sources) → re-judge
	// with a premium provider chain, write traits, and relabel when the model
	// overturns the label. Most reviews are expected to agree with the standing
	// label; SecondOpinionSettle keeps a just-analyzed sample from being
	// immediately second-guessed. Detection-tripping samples are excluded here,
	// not by the consumer: they are the good queue's set, and queue disjointness
	// is what lets workers share per-sha sample tmp dirs safely.
	//
	// No Depth: its population is evidence-ranked against the sightings ledger
	// rather than a plain predicate over samples, so there is no cheap count.
	"second": {Name: "second", Select: func(ctx context.Context, db *DB, n int) ([]*Sample, error) {
		return db.TriageSecondOpinion(ctx, n, TrustedBadSources,
			time.Now().Add(-SecondOpinionSettle), TriageFilter{})
	}},

	// highest: whole archives (good/unknown parents) containing a good-labeled
	// member the ensemble scores hostile, worst first → settle the label, then
	// loosen the traits driving the score. Those members pin each route's
	// operating point (a per-route threshold sits at the highest-scoring benign
	// in its slice), so the top of this queue is where reported recall is lost.
	// TriageHighest collapses hot members to their parent and returns the archive
	// itself, so the worker fetches and judges the whole package — provenance and
	// sibling files are what make the call cheap, and scoring a lone member out of
	// its archive throws both away. The whole-archive scan on upload also refreshes
	// every sibling's score for free.
	"highest": {Name: "highest", Select: func(ctx context.Context, db *DB, n int) ([]*Sample, error) {
		now := time.Now()
		return db.TriageHighest(ctx, n, now.Add(-OutlierGrace), now.Add(-MissingRetry), TriageFilter{})
	}, Depth: func(ctx context.Context, db *DB) (int64, error) {
		now := time.Now()
		return db.CountTriageHighest(ctx, TriageScoreDivider,
			now.Add(-OutlierGrace), now.Add(-MissingRetry), TriageFilter{})
	}},

	// lowest: the mirror — bad-labeled samples the ensemble scores clean,
	// best-hidden first → settle the label, then write the traits that would
	// catch them. Judged per file, not per archive: members inherit "bad" from
	// their parent at explode time, so a chunk of this queue is inert content
	// that was never malicious, and relabelling those is as valuable as any
	// trait. That per-file granularity is why its drain keys on the member's own
	// sha while highest's keys on the root archive.
	"lowest": {Name: "lowest", Select: func(ctx context.Context, db *DB, n int) ([]*Sample, error) {
		now := time.Now()
		return db.TriageLowest(ctx, n, now.Add(-OutlierGrace), now.Add(-MissingRetry), TriageFilter{})
	}, Depth: func(ctx context.Context, db *DB) (int64, error) {
		now := time.Now()
		return db.CountTriageLowest(ctx, TriageScoreDivider,
			now.Add(-OutlierGrace), now.Add(-MissingRetry), TriageFilter{})
	}},

	// stranded: good-labeled members with real findings inside CONVICTED
	// archives — benign labels inherited before the parent's conviction and
	// never individually reviewed. Unit of work is the archive (context);
	// verdicts and the drain are PER MEMBER, so an archive resurfaces until every
	// qualifying member has been judged.
	"stranded": {Name: "stranded", Select: func(ctx context.Context, db *DB, n int) ([]*Sample, error) {
		now := time.Now()
		return db.TriageStranded(ctx, n, now.Add(-OutlierGrace), now.Add(-MissingRetry), TriageFilter{})
	}, Depth: func(ctx context.Context, db *DB) (int64, error) {
		now := time.Now()
		return db.CountTriageStranded(ctx, now.Add(-OutlierGrace), now.Add(-MissingRetry), TriageFilter{})
	}},

	// popular: samples from a ranked package whose worst finding is suspicious
	// or hostile (the suspiciousCrit floor), worst-ranked package first.
	// Deliberately NOT every sample that trips detection: "notable" findings are
	// worth recording and not worth this queue, and on popular packages they are
	// 92% of the population — a backlog measured in months, spent on ordinary
	// behaviour, with every other queue stood down behind it.
	//
	// Label-agnostic on purpose — every other queue selects on what we believe
	// about a sample; this one selects on what a mistake would cost. A false
	// positive on a package a million people install is worth a slot whether it
	// is filed good, unknown, or bad, and it is worth far more than the same
	// finding on a package nobody imports. Rank ordering is the point: a miss on
	// rank 3 outranks a miss on rank 900.
	//
	// Populated by poppy, which publishes each ecosystem's ranking on every daily
	// catalog refresh. Like the -stale queues it does not self-drain — judging a
	// sample does not remove it from the marked set — so it takes the same
	// ExcludeReportType drain: a completed judgement parks the sample until a
	// re-analysis makes the question worth asking again.
	//
	// popular_packages must be present for this queue to return anything. On a
	// logical replica that means the table has to be in REPLICATED_TABLES —
	// migration creates it empty either way, so an unpublished table reads as a
	// permanently drained queue rather than as an error.
	"popular": {Name: "popular", Select: func(ctx context.Context, db *DB, n int) ([]*Sample, error) {
		return db.TriagePopular(ctx, n, staleTriageFilter("popular"))
	}, Depth: func(ctx context.Context, db *DB) (int64, error) {
		return db.CountTriagePopular(ctx, staleTriageFilter("popular"))
	}},

	// The -stale queues: the same populations as new/good, ranked
	// least-recently-analyzed first instead of newest-added first. Their reason
	// to exist is that the newest-first queues cannot reach the backlog — while
	// arrivals outpace triage the cursor never descends past the last few days,
	// which leaves ~99% of each population permanently unexamined. Ordering by
	// analyzed_at rather than created_at also targets the right thing: a row's
	// queue membership is whatever its last scan computed, so the least recently
	// analyzed rows are the ones whose verdict rests on the oldest trait set.
	//
	// Unlike their newest-first counterparts these do not self-drain. A
	// newest-first queue is pushed along by fresh arrivals, so a sample nothing
	// can be done about sinks on its own; a stale queue's head does not move,
	// and without a drain the same unfixable row would be re-selected forever.
	// Hence ExcludeReportType: a completed judgement files a "<queue>" report
	// that parks the sample until it is re-analyzed, at which point the verdict
	// is new and the question is worth asking again.
	//
	// There is deliberately no bad-stale. Its product would be traits that catch
	// OLD malware — a false-negative fix on samples that are no longer
	// circulating, which is not worth a batch slot. False POSITIVES in old
	// samples are, because a wrong detection keeps costing recall for as long as
	// it stands: an over-firing trait caps every route whose threshold sits at
	// its highest-scoring benign. The label-hygiene half of what bad-stale would
	// have done (bad-labeled files that are really inert) is already covered by
	// lowest, which is score-ranked and so reaches old samples natively.
	"new-stale": {Name: "new-stale", Select: func(ctx context.Context, db *DB, n int) ([]*Sample, error) {
		return db.TriageNew(ctx, n, staleTriageFilter("new-stale"))
	}, Depth: func(ctx context.Context, db *DB) (int64, error) {
		return db.CountTriageNew(ctx, staleTriageFilter("new-stale"))
	}},

	"good-stale": {Name: "good-stale", Select: func(ctx context.Context, db *DB, n int) ([]*Sample, error) {
		return db.TriageGood(ctx, n, staleTriageFilter("good-stale"))
	}, Depth: func(ctx context.Context, db *DB) (int64, error) {
		return db.CountTriageGood(ctx, staleTriageFilter("good-stale"))
	}},

	// acquit: the second queue's mirror — bad-labeled samples whose conviction
	// no outside evidence has ever supported (provenance shows a registry pull,
	// not a malware-feed download; no sighting from anyone) → re-judge the
	// conviction with a premium chain. Most convictions stand; a wrongful one is
	// relabeled good (it was poisoning trait training) and its over-tight traits
	// loosened. Detection-gap samples are excluded here — they are the bad
	// queue's set, same disjointness rule as second vs good.
	//
	// No Depth: like second, its population is defined by the ABSENCE of a
	// sighting, which is not a countable predicate over samples alone.
	"acquit": {Name: "acquit", Select: func(ctx context.Context, db *DB, n int) ([]*Sample, error) {
		return db.TriageAcquit(ctx, n, time.Now().Add(-AcquitGrace), TriageFilter{})
	}},

	// fallout: litmus-hostile samples (class 2 — the public fallout page's
	// population) that are UNDESCRIBED or UNCORROBORATED. Undescribed is the
	// original population: no LLM interpretation, because the reasoning pass
	// never ran (arrivals outpace the new queue, which ranks a litmus-hostile
	// sample no higher than any other suspicious unknown) or it failed and
	// stored only an error. Uncorroborated is the second: we call it hostile and
	// no outside source has ever cited it, which on this page is the more common
	// gap by an order of magnitude (229 of 337 over a week, against 11
	// undescribed — and every undescribed sample was also uncorroborated).
	//
	// One queue for both because they are one population worked by one pass. The
	// judgement it produces answers whichever gap applied: the write-back's
	// interpret pass stores the rationale a described-nothing sample lacks, and
	// the verdict itself settles whether a hostile call nobody else made still
	// stands.
	//
	// Uniquely, its population spans label pools (the page filters on
	// classification, not label), so it overlaps new/bad/good rather than
	// partitioning against them — a consumer's claim set is what keeps two queues
	// off the same sample.
	//
	// Two drains: llm_result landing removes an undescribed row from the
	// selector, and a completed judgement files a "fallout" report (permanent
	// anti-join) which is the only thing that drains an uncorroborated one —
	// corroboration is not ours to produce. The permanent park also covers a
	// sample whose interpret pass errors (large renders overflow the endpoint),
	// which would otherwise churn through the window.
	//
	// No Depth: the undescribed/uncorroborated disjunction spans the sightings
	// ledger, so there is no single predicate to count.
	"fallout": {Name: "fallout", Select: func(ctx context.Context, db *DB, n int) ([]*Sample, error) {
		return db.TriageFallout(ctx, n, time.Now().Add(-FalloutWindow), TriageFilter{})
	}},
}

// TriageQueueNames returns every registered queue name, sorted.
//
// Sorted because TriageQueues is a map and Go randomizes map iteration; without
// it, a consumer's worker start order and every log line listing queues would
// vary per process. It is also the one list a consumer should validate its own
// per-queue policy tables against, so that adding a queue here fails that
// consumer's completeness test rather than silently getting a default.
func TriageQueueNames() []string {
	names := make([]string, 0, len(TriageQueues))
	for name := range TriageQueues {
		names = append(names, name)
	}
	sort.Strings(names)
	return names
}
