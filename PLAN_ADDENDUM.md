# Verdict schema: review addendum

Status: review notes, 2026-11-12, written against `PLAN.md` and
`internal/store` as they stood that day. Nothing here is implemented, and
neither `PLAN.md` nor any code is changed. This file is for whoever owns the
plan to accept or reject item by item. Scan's side is in
`../scan/JSON_PLAN_ADDENDUM.md`.

The review was a read-through. Nothing was run or measured; every cost figure
quoted is `PLAN.md`'s own. `internal/store` was being edited during the
review, so code is cited by file and symbol, not by line.

Each item carries one of these marks:

- **Decided**: Thomas decided it during the review.
- **Proposed**: the reviewer's proposal; not yet confirmed.
- **Unverified**: rests on code the reviewer did not finish tracing.

## What changes, at a glance

| # | Change | Mark |
| --- | --- | --- |
| 1 | `refs` gains the requested constraint; `version` is the resolved one | Decided |
| 2 | `refs_referrers` includes `version` | Decided |
| 3 | Ref names are canonicalized by hopper at ingest | Decided |
| 4 | A ref's holder is the scanned artifact, not the declaring file | Proposed |
| 5 | `refs.version` and `samples.version` agree on "no version" | Proposed |
| 6 | Juror rows absent from an upload are removed (the writer already does this) | Decided |
| 7 | `contents` lists every evaluated member | Proposed |
| 8 | A hostile dependency, URL or member raises a sample's class at lookup | Decided |
| 9 | The raise uses the existing ladder in `corroboration.go` | Decided |
| 10 | Smaller points | Proposed |

## 1. Refs: resolved version and requested constraint

**Decided.**

Scan will send `version` as the exact version a ref is bound to (declared if
exact, else resolved by scan) and `requested` as the constraint as written.
The reason is in scan's addendum, item 1: a declared range has no version, so
it can never equal a release.

Schema:

```sql
CREATE TABLE refs (
    sample_id bigint   NOT NULL REFERENCES samples,
    name_id   bigint   NOT NULL REFERENCES names,
    version   text     NOT NULL DEFAULT '',
    kind      ref_kind NOT NULL,
    requested text     NOT NULL DEFAULT '',   -- '' when the request was exact
    PRIMARY KEY (sample_id, name_id, version, kind)
);
```

- `requested` is not part of the key. Two declarations of one name that
  resolve to the same version are one row.
- A non-empty `requested` marks a floating ref.
- `PLAN.md`'s table says refs are written at the "first scan of the declaring
  file". For a floating ref the resolved version can change between scans.
  The writer's `refs` step already replaces a holder's refs on every scan, so
  the text needs updating and the code does not.

**Proposed**, building on it: when a name gets a hostile release, find the
declarers whose ref to that name floats and put them in `queue` for a rescan.
Without that, a hostile release published after a package's last scan is not
seen until something else rescans the package.

**Proposed**, for URL refs: scan also sends the sha256 it fetched. A sample
row has one name, so bytes first seen at URL A stay filed under A, and a ref
to URL B that served the same bytes finds no sample by name. Store the digest
on the ref (a nullable `bytea`, URL refs only) and fall back to it when no
sample is filed under the URL. A `bigint` reference to `samples` is smaller
but needs the dependency's sample row to exist first.

## 2. The reverse index includes the version

**Decided.**

`refs_referrers` is `(name_id, sample_id)`. "Who declares this hostile
release" is a search by name and version; with the current index it scans
every referrer of every version of the name. Make it
`(name_id, version, sample_id)`.

## 3. Hopper canonicalizes ref names

**Decided.**

A ref's name is written by scan (fletch's canonical form). A sample's name is
written by hopper (`pkgparse`). `Ref.Check` in `internal/store/v8.go` tests
only the prefix, and names are interned by exact bytes (`text_key`). Any
difference in spelling is a silent miss on the join that the whole
dependency feature rests on. This is the same kind of drift as the
`SuspiciousCeiling` constant that version 8 removes for classes.

Change: run every ref name through `pkgparse.CanonicalizePURL` at ingest, so
one canonicalizer writes both sides.

The sightings ledger has the same requirement: its `subject` text must be
spelled the way ref names are, or corroboration of a ref (item 8) misses.

## 4. A ref's holder is the scanned artifact

**Proposed.**

Rule 2 files a ref under the declaring file, and `v7result` does the same
(`add(f.Source, …)`). The prototype's walk then probes `refs` for every file
it reached (`FROM refs f WHERE f.sample_id = ANY (reach || root)` in
`internal/verdictproto/bench.sql`). A lookup must walk an archive's members
before it can find one dependency, so the dependency path inherits the cost
and the caps of the member walk.

Change: scan puts the union of an artifact's refs on the artifact's own line
(scan's addendum, item 2), and hopper stores them under that sample.

- A lookup reads one sample's refs with a single range scan of the primary
  key. No walk.
- "Who declares this release" returns packages directly, with no walk up.
- Cost: a nested archive looked up by its own hash shows no dependencies
  unless it was scanned as an artifact itself.

## 5. One spelling for "no version"

**Proposed.**

`refs.version` is `NOT NULL DEFAULT ''`. `samples.version` is nullable. An
unversioned ref therefore never equals a sample's version under plain
equality. Use `''` in both, so `samples_release` serves the join as it
stands.

## 6. Juror rows

**Decided.**

- Each rescan reflects only the jurors it had. The writer's `DELETE FROM
  verdicts` for jurors missing from a successful scan is correct and stays.
- Scan is the only decider. A juror never arrives alone, so hopper never
  blends.
- Jurors cover the file and what it contains, as `../scan/JSON_PLAN.md` open
  question 1 proposed. Scan will do that fold at every nested level, so a
  nested archive's row is the same whether it arrived as a member or was
  scanned directly.
- Members carry `ml` and `floor` at most. `llm` and `drift` exist only on the
  scanned artifact.
- Juror rows have two readers: cyclotron's queues, to find discrepancies, and
  possibly prism for display.

Open, raised in review and not answered: a file scanned individually with the
LLM, which also sits inside an archive, loses its `llm` row and its
LLM-informed verdict each time that archive is rescanned. That is "most
recent scan wins", and it is close to today's behaviour, where a newer member
analysis supersedes an older standalone one (`RefreshStaleMemberAnalysis`).
If the individual scan should win, the writer needs one rule: a member line
does not replace a row that carries more jurors than it does.

## 7. `contents` lists every evaluated member

**Proposed.** Thomas asked for the risk in detail and has not confirmed.

`PLAN.md` treats `contents` as a function of the parent's bytes, written
once. That holds only if scan sends a file line for every member. Scan's
retention keeps a member in the report only when it has findings, and if file
lines are built from the retained report, the member set follows the ruleset.
The full scenario is in scan's addendum, item 8. For hopper it means:

- A member's hostile verdict can never clear. After a false-positive fix the
  member is no longer sent, the writer touches only files in the upload, and
  hopper holds no bytes to rescan a member alone. The row stays in
  `verdicts_flagged`.
- `contents_parents` answers "which archives hold this file" only for
  archives where the file had findings at their last scan.
- The `contents` row is rewritten whenever the retained set changes, each a
  non-HOT update that touches the GIN index.

`PLAN.md` already records the same family of defects in today's data: stored
archive reports that keep only the container entry, and nothing deleting a
parent's stale member rows.

Change: scan sends every evaluated member's line; retention governs only
whether a report is attached. By `PLAN.md`'s numbers that is 153 B of WAL per
unchanged member per rescan, about 3.4 MB for the 22,242-file archive.

## 8. Raising a sample's class at lookup

**Decided**, except where a bullet says otherwise. This extends rule 3 and
changes how rule 6 reads.

Today a dependency's verdict is folded into the declaring package at scan
time. From version 8 scan's uploaded verdict covers only the file and what it
contains. Hopper adds the rest when `/v1/lookup` runs, so a dependency, URL
or member convicted later is reflected without a rescan, and one acquitted
later clears at once.

What raises the class:

| Thing the sample points at or contains | Raises when |
| --- | --- |
| A dependency (by name and version) | a file of that release is detected hostile, or the release is corroborated |
| A URL reference | the newest sample hopper holds under that URL is detected hostile, or the URL is corroborated |
| A member, at any depth within the caps | the member is detected hostile, or corroborated |

- **Detected** means atomscan's current class for that sample is `hostile`.
- **Corroborated** means the sightings ledger justifies it; see item 9.
- **Suspicious does not count.** Only hostile raises.
- **The `bad` label is deferred.** It is not a reason for now.
- **Development-only dependencies raise** like any other ref. Refs carry no
  scope.
- **The response says why.** Each thing that raised the class is listed with
  its kind, name, version, sha256 where there is one, its reasons (detected,
  corroborated) and its level. Field names are not settled.

How it is computed (**Proposed**):

- The raise is never stored. The verdict row keeps the sample's own class.
  Cyclotron's queues keep comparing real juror opinions, and an acquittal
  needs no fan-out.
- `fires_at` in the response becomes the tightest of the sample's own level
  and its refs' and members' levels, using the existing `tighten`. The class
  is graded from that.
- One hop only. A lookup resolves the sample's own refs, not the refs of its
  dependencies. Lockfiles already list transitive dependencies flat.
- Dependencies: read the sample's refs (item 4), then per ref one probe of
  `samples_release` and one of `verdicts_flagged`. Corroboration is one query
  of the ledger for all the ref names, folded with `AssessRelease` at each
  ref's version. A dependency hopper has never fetched can still be
  corroborated, since the ledger needs only the name.
- Members: read the archive's `child_ids`, ask `verdicts_flagged` which of
  those ids are hostile, and descend only into children that have a
  `contents` row. Cap the depth and the total ids, and report truncation.
  `PLAN.md` measured the walk at 2.8 ms for 100–1,000 members and 263 ms at
  22,242, so the cap is not optional.
- Cap the refs resolved per lookup as well. A lockfile can declare thousands.

URL refs (**Decided**: most recent, and keep the old finding on 404 or 403):

- A failed fetch produces no bytes and no sample, so the previous sample
  stays the newest and the old finding is kept with no extra rule.
- "Newest under a name" needs `samples_release` to end in `id`:
  `(name_id, version, id)`.
- Not covered, **Proposed** for discussion:
  - A takedown or parking page served with status 200 becomes the newest
    sample and clears the finding. A window ("hostile if any sample from
    this URL in the last N days was") would close it.
  - The same bytes from two URLs; see the digest fallback in item 1.
  - A URL that serves hostile bytes, then clean, then the same hostile bytes
    again. The clean sample stays the newest. Accepted as rare.

Caches (**Proposed**; without this the feature does not show):

- `lookup_cache.go` holds a sample for up to 48 hours and invalidates only
  the sample that was written. Convicting a dependency does not invalidate
  the packages that declare it. Compute the raise per request, on top of the
  cached record.
- Scan's own verdict index keeps a digest's answer for the life of the
  ruleset. That is noted in scan's addendum.

Risks to accept knowingly:

- One false positive on a popular package makes every package that declares
  it hostile at lookup. It clears as soon as the conviction is fixed.
- A ref with no exact version cannot be matched. See scan's addendum, item 1.
- None of the lookup paths above are measured.

## 9. Levels come from the existing ladder

**Decided.**

Thomas considered a new rule (two corroborations suspicious, three hostile)
and chose instead to keep what `corroboration.go` already does for a sample's
own sightings (`Floor`):

| Evidence | Level | Class at level 25 |
| --- | --- | --- |
| Three or more independent operators | L1 | hostile |
| Two independent operators | L10 | hostile |
| One operator, human-reviewed | L25 | hostile |
| One unreviewed claim backed by our own firing analysis | L50 | suspicious |
| One operator, prediction only | L100 | suspicious |

- A ref or member that is **corroborated** contributes its ladder level.
- A ref or member that is **detected** contributes its own `fires_at`.
- **Refs use only L25 and tighter.** The two lower rungs reach only
  suspicious, which does not count for refs. The sample itself keeps the full
  ladder. (The reviewer proposed this and read Thomas's "that's OK" as
  agreement; worth confirming.)

Two things in `PLAN.md` and the code to reconcile with this:

- Rule 6 says a file is hostile when "three independent sources" say so. The
  ladder convicts at two operators, and at one reviewed claim. The ladder is
  what was chosen.
- `fired`, which decides "backed by our own analysis", tests against a flat
  L3000 (`suspiciousCeiling` in `corroboration.go`). That is the drifted
  constant `PLAN_TODO.md` already lists. With the class stored in version 8,
  `fired` can read the class.

## 10. Smaller points

All **Proposed**.

- **One long sentence rejects a whole upload.** `opinion` in
  `internal/store/v8.go` fails the upload when an object exceeds
  `maxSummary`. Scan will cap `reason` and `error`; the two numbers must
  agree, and hopper's limit should be stated in `../scan/JSON_PLAN.md`.
- **Per-row constants.** The writer merges `worker` and `level` into every
  atomscan summary. `level` is constant and `worker` is debugging detail;
  dropping `worker` from the row costs nothing a log does not already hold.
- **Drift.** It judges a pair, so its summary needs the baseline's sha256.
  The `(sample_id, scanner_id)` key allows one baseline per head.
- **The reason is stored twice**, in atomscan's summary and in the `llm`
  row, when the LLM decided. Keep one.

## Still open

1. Whether an individual scan's LLM verdict should survive a rescan of an
   archive that contains the file (item 6).
2. Whether item 7 is accepted.
3. Whether refs are held by the scanned artifact (item 4). The lookup design
   in item 8 assumes they are.
4. Confirmation that refs use only L25 and tighter (item 9).
5. The 200-status URL case (item 8).
6. Field names and shape of the lookup response's list of what raised the
   class.
