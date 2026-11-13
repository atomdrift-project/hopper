# Deferred

Work that was decided on and put off. Each entry says what covers the gap
meanwhile, what the gap costs, and where the work would go. `PLAN.md` has the
design these belong to; `PLAN_TODO.md` has what is still to be done now.

Both entries lean on the same thing: every top-level file is rescanned
eventually. That is the rescan-by-age queue hopper has always had: a file
last scanned more than `--rescan-age` ago (90 days by default) is handed out
when workers have nothing newer to do (`PLAN.md`, "Rescan by age"). Age is
its only test. A new ruleset does not make a file due, because the ruleset
changes daily and everything would always be due.

So "eventually" below means up to `--rescan-age` after the file's last scan,
plus however long the queue takes to drain.

## Rescan the archives holding a member that is no longer hostile

Decided 2026-11-12: wanted, deferred.

**The gap.** Scan folds a member's verdict into the stored verdict of the
archive that holds it. When a later upload judges that member benign (a
ruleset fixed a false positive, say), the member's row changes and the
archive's does not. The archive keeps answering hostile for a reason that no
longer exists.

**What covers it meanwhile.** The archive's own next scan, when it comes due
by age, or sooner if someone asks for it (`/api/rescan`).

**What it costs.** A false positive on a widely shared file outlives its fix
by up to `--rescan-age` in every archive that holds it. The error is in the
safe direction: hostile for too long, never benign for too long. The opposite
case, a member that gets worse, is already handled.

**Where it goes.** `writer.queue` in `store/queue.go` queues the
holders of a member whose class rose, at `QueueRepair`, at most `maxRequeue`
(256) per upload. The verdicts step collects those members in `w.rose` from
the old and new class its upsert returns. A fall is the same shape:

- collect members whose class fell from hostile;
- queue holders whose own class is still at or above the member's old one,
  where the rise queues holders whose class is below the new one;
- same priority, same cap, same exclusions (the archives in this upload,
  holders already judged under this ruleset, holders with no location).

A holder is worth queueing only if that member could have been why it is
hostile. `verdicts.summary->>'in'` names the contained file that decided the
verdict, when one did, and is the cheap test.

## Rescan the packages with a floating reference to a name that turns hostile

Decided 2026-11-12: wanted, deferred.

**The gap.** A reference is stored at the exact version scan resolved, with
the constraint as written in `refs.requested`. A package that declares
`left-pad ^1.3.0` and was scanned when that meant 1.3.0 keeps pointing at
1.3.0. If 1.3.1 is published and convicted, lookup does not raise the
package: a fresh install would pull 1.3.1, and hopper says nothing.

**What covers it meanwhile.** The package's next scan, which resolves the
range again. Nothing about a new release makes the package due, so this
waits for the package to come due by age.

**What it costs.** This is the unsafe direction: benign for too long, for up
to `--rescan-age`, 90 days by default. It is the case the lookup raise exists for. It applies
only to ranges; an exact reference is matched as written and is not affected.

**Where it goes.** When a sample with a name gets a hostile atomscan verdict
(the same moment `w.rose` is filled), queue the packages that hold a
reference to that name with a non-empty `requested`:

```sql
SELECT r.sample_id FROM refs r
WHERE r.name_id = $1 AND r.requested <> ''
  AND EXISTS (SELECT 1 FROM locations l WHERE l.sample_id = r.sample_id)
LIMIT 256
```

`refs_referrers (name_id, version, sample_id)` serves it. Queue them below
`QueueRepair`, which needs a new priority or `QueueStale`; a popular name has
far more than 256 floating declarers, so the cap means most still wait for
the sweep, and which 256 are taken matters. Newest first is the obvious
choice and needs `samples.published_at`, which nothing fills yet
(`PLAN_TODO.md`).

Matching the constraint in hopper instead (does `^1.3.0` admit 1.3.1?) would
close the gap at lookup with no rescan. It needs a version-range evaluator
per ecosystem, which hopper does not have and scan does.
