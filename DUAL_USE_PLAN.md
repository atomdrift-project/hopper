# Smaug rollout: inconclusive and dual-use pools

## Collection review update (2026-10-29)

The dataset rename has since been performed, and both `inconclusive` and
`dual-use` datasets exist. The latest read-only service check found Hopper,
Forager, Draino, and postdoc_worker stopped.

The review artifacts are in `out/pool-review-20261029/` (generated, ignored by
Git). `review.csv` has one row per SHA256 with current label/decider, paths,
detected level, hostile-trait count, a decided pool, and rationale. The scope
includes reviewed labels, legacy/current pool locations, and archive descendants:
119,014 hashes. Five decisions have individual static inspection; the remaining
decisions are explicitly marked best guesses. Unresolved cases default to
inconclusive. Other good/bad pool signals inform the decision as requested.

All live relocation and classification must use Hopper's built-in move API,
`POST /api/triage` (also used by `hopper mv`). No independent SQL relabeler or
filesystem deletion runner should apply this review. `export-pool-review-api.py`
creates exact-location dry-run request bodies; it performs no network requests.

Before applying the cleanup, address these current endpoint limitations within
Hopper's API:

- A SHA-only move can return noop when the label already agrees, despite other
  locations being in the wrong pool. Exact `old_path` requests bypass that noop.
- Individual moves currently derive their own destinations. Repeating them does
  not guarantee one canonical location per SHA256; consolidation needs API-side
  coordination using the existing verified `DB.MoveLocation` mechanism.
- Catalog aliases under the renamed purgatory root may be missing on disk, or
  may be ghosts from an earlier walk. Recovery must verify the surviving copy.
- Virtual archive-member aliases must follow their containing archive while
  preserving membership and independent labels. They are not standalone files.

No live changes from the collection review have been applied. The original
rollout instructions below describe the earlier inspected state.

### Reproduce the review export

The scripts require Python 3.9+ and `psql`. Use an output directory under `out/`
for generated evidence. The database commands run read-only transactions; use
the publisher with its location indexes for a full collection export.

```sh
mkdir -p out/pool-review
# Set HOPPER_DB to the database DSN, using .pgpass for authentication.
psql "$HOPPER_DB" -X -q -w -At -v ON_ERROR_STOP=1 \
  -f scripts/pool-review-seeds.sql > out/pool-review/seeds.jsonl
# Run this inventory on the corpus host, saving its stdout with the export.
python3 scripts/inventory-pool-review.py --root /data/samples \
  > out/pool-review/filesystem-inventory.jsonl
python3 scripts/expand-pool-review.py --dsn "$HOPPER_DB" \
  --seeds out/pool-review/seeds.jsonl --output out/pool-review/expanded-seeds.jsonl
python3 scripts/export-pool-review.py --seeds out/pool-review/expanded-seeds.jsonl \
  --inventory out/pool-review/filesystem-inventory.jsonl --output out/pool-review
python3 scripts/decide-pool-review.py --directory out/pool-review
python3 scripts/plan-pool-review.py --directory out/pool-review
python3 scripts/export-pool-review-api.py --directory out/pool-review
python3 -B scripts/tests/test_pool_review.py
```

Exporting can resume from `evidence.jsonl`; it retains each batch's capture
timestamp. `--render-only` rebuilds the CSV without querying the database and
preserves decision fields already present in that CSV. To refresh database
evidence, use a new output directory. `decide-pool-review.py` uses collection-
specific path and analysis heuristics, marks its decisions `best_guess`, and
preserves rows marked `reviewed`. It is not a replacement for individual
inspection. The preview and API export only write local files; they do not
send requests or apply classifications.

## Scope and inspected state

Replace the legacy `purgatory` label and pool with `inconclusive`, and add a
separate `dual-use` label and pool. Existing samples default to `inconclusive`;
assigning `dual-use` requires an explicit review and ruling.

Live inspection on 2026-10-29 found:

- Smaug runs native FreeBSD. Hopper was ready; Draino, Forager, and
  `postdoc_worker` were running.
- The Hopper checkout is `/home/t/hopper`; the installed binary is
  `/usr/local/bin/hopper`.
- `tank/samples/purgatory` mounts at `/data/samples/purgatory` and uses about
  17.4 GB. The `tank` pool has about 6.57 TB available.
- Neither `/data/samples/inconclusive` nor `/data/samples/dual-use` exists yet.
- Purgatory's mountpoint is inherited from `tank/samples`. Its root is owned by
  `hopper:samples` with mode `2775`.
- The parent dataset supplies `compression=zstd`, `recordsize=128K`, and
  `atime=off`. Its `canmount` property is `off`; the existing purgatory child
  has `canmount=on`.
- The installed Hopper rc.d script currently requires mounts for
  `bad,good,incoming,pending,review`.

The inspection was read-only. No live dataset, service, binary, or catalog
changes have been applied.

## 1. Prepare the FreeBSD binary and deployment configuration

Transfer or land the tested Hopper changes in `/home/t/hopper`, preserving any
host-local changes, then build on Smaug:

```sh
cd /home/t/hopper
gmake build
```

The executable built in the Linux development workspace cannot be installed on
FreeBSD. Prefer a Hopper-only installation for this rollout: the normal
FreeBSD deployment script also updates and rebuilds cleave and postdoc, and its
source-update step can reset those sibling checkouts.

Before a future full deployment, update `scripts/master/freebsd.sh` so its
`REQUIRED_MOUNTS` defaults and shared-group permission setup include
`inconclusive` and `dual-use`. Preserve the live database, token, listener, and
worker configuration. Create and mount the new dataset layout before running
a deployment that requires those mounts.

## 2. Open the migration window

Pause remote triage work and stop the local services:

```sh
doas service postdoc_worker stop
doas service forager stop
doas service draino stop
doas service hopper stop
```

Confirm other corpus movers and catalog writers are paused. Take a snapshot of
`tank/samples/purgatory` with a unique pre-migration name, and save the affected
catalog rows, including legacy labels and locations, for rollback. Retain the
previous Hopper binary and service configuration.

## 3. Change the ZFS dataset layout

Use the existing `tank` pool:

```sh
doas zfs rename tank/samples/purgatory tank/samples/inconclusive
doas zfs create tank/samples/dual-use
doas chown hopper:samples /data/samples/dual-use
doas chmod 2775 /data/samples/dual-use
```

Because purgatory's mountpoint is inherited, renaming the dataset changes its
mountpoint to `/data/samples/inconclusive`. Its existing ownership and
permissions survive. The new dual-use dataset inherits compression, record
size, and atime settings from the parent; verify it is mounted with
`canmount=on` and that both roots are writable by Hopper.

The dataset rename avoids copying the existing contents. The migration still
reads files to verify their hashes. A local rehearsal verified the sequence
of renaming the root first and repairing the catalog afterward, including
contained-member paths, labels, and provenance sidecars.

## 4. Extend Hopper's mount guards

Set the rc.conf override used by the installed rc.d script:

```sh
doas sysrc hopper_required_mounts="bad,good,incoming,pending,review,inconclusive,dual-use"
```

Check that both new paths are actual mounted datasets before restarting Hopper.

## 5. Install and run the migration

With Hopper still stopped, install the native binary built in step 1:

```sh
cd /home/t/hopper
doas install -m 0755 -o root -g wheel hopper /usr/local/bin/hopper
```

Run the following migration commands as the `hopper` account, with
`HOME=/home/hopper`, its existing `/home/hopper/.pgpass`, and `DATABASE_URL` set
to the same database DSN used by the live service:

```sh
hopper migrate-purgatory --db "$DATABASE_URL" --data /data/samples --dry-run
hopper migrate-purgatory --db "$DATABASE_URL" --data /data/samples --apply
```

Inspect the preview and migration logs. The migration reconciles old catalog
locations against the files already present under `inconclusive/`, repairs
contained-member paths, and renames remaining legacy labels. Attribution, skip
state, and historical audit records are preserved. Re-running resumes
unfinished work; resolve reported failures before reopening the service.

## 6. Verify and resume

Confirm:

- Both new datasets are mounted at the expected paths with the shared-writer
  permissions.
- The migration reports no failures, and a subsequent preview reports no
  remaining work.
- No active `purgatory` labels or locations remain. Historical audit entries
  retaining the old spelling are expected.

Start Hopper and check readiness before resuming its consumers and producers:

```sh
doas service hopper start
fetch -T 5 -qo - http://127.0.0.1:8081/_/ready
```

Once Hopper is ready, restart Draino, Forager, and `postdoc_worker`, then resume
remote triage work. Confirm new rulings reach the expected pools. Move confirmed
dual-use samples separately with `hopper mv -target=dual-use`; the migration
does not infer those assignments.

Any rollback must restore filesystem paths and catalog state together. A ZFS
snapshot alone does not undo catalog label and location changes.
