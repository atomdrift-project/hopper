# Hopper performance investigation — 2026-09-23

Observations collected around 13:59–14:20 EDT from smaug, Prometheus on otel,
and PostgreSQL 18.6 on minas-tirith (via hopper-db). Production inspection was
read-only. No restart, deployment, database DDL, or production data changes were
performed. Raw captures and runnable SQL are in `/tmp/hopper-audit-20260923/`.

## Immediate failure: cache corruption stranded ingestion

At **12:11:23.751 EDT**, a GET /v1/lookup panicked in Fido v1.11.0:

```
entry.freq -> s3fifo.evictFromSmall -> evictOne -> setWithHash
          -> Cache.Fetch -> DB.recordFor -> handleV1Lookup
```

`evictFromSmall` had a positive queue length and a nil queue head. The HTTP
middleware recovered the panic. `setWithHash` used manual Unlock calls, so the
panic left the writer mutex held permanently.

The first subsequent worker result shed was at **12:11:35.362**. Prometheus
shows completed stores collapsing to zero after this event. At 14:01:

- All **32/32 result slots** were held; all **32 database connections were idle**.
- Of 1,425 goroutines, 30 result handlers waited in
  `StoreResult -> forgetSHA -> forgetRecord -> fido.Delete` after the SQL store
  had returned successfully. Two more result handlers waited on singleflight.
- 708 lookup handlers waited to insert records, 276 triage handlers waited to
  invalidate records, and at least 196 upload handlers waited on invalidation.
- The last 20,000 log lines contained 19,976 result-slot saturation warnings.
- At 14:03, shedding was approximately **1.43 worker requests/s** and
  **0.32 renewal requests/s**, with zero completed stores.
- Host CPU was approximately 3% on smaug and 5% on minas-tirith. PostgreSQL had
  no application lock-wait pileup at the sampled times.

These observations establish the cause of this stall. Increasing result slots,
connection limits, or PostgreSQL write throughput cannot unblock the mutex.
The ten-minute store context cannot interrupt a Go mutex wait.

A reproducible defect in Fido's `Delete` explains the queue corruption:
pending-eviction entries remain in the map but have already left the FIFO and
live count. Delete unlinked them again, damaged queue head/tail state, decremented
the count twice, and left a stale pointer in the pending ring. A regression
using only Set/Get/Delete reproduces the invalid live count on v1.11.0.

The local Fido fix removes a pending entry from its ring without touching FIFO
links or live count, removes the map entry, and uses deferred Unlock in the two
insertion/resurrection paths. This fixes the reproduced cause; deferred Unlock
alone would not repair a cache whose structures were already corrupted.
Production needs the patched dependency and a restart. A restart alone is a
short-term recovery and can encounter the same defect again.

## PostgreSQL is still an important throughput opportunity

`pg_stat_statements` was already enabled. Its reset time was September 16 at
09:11 UTC, so these figures cover roughly seven days, multiple workloads, and
possibly multiple application builds. They are not measurements of the current
stalled interval.

| Statement | Calls | Mean execution | Cumulative execution | WAL |
|---|---:|---:|---:|---:|
| Member samples upsert (-3835926576491465047) | 1,271,639 | 194.57 ms | 247,423 s | 2,797.5 GB |
| Locations upsert (-8300666352929280574) | 1,438,316 | 142.37 ms | 204,768 s | 739.1 GB |
| COPY into staging | 1,438,327 | 55.02 ms | 79,137 s | negligible |
| Parent result UPDATE | 1,247,668 | 4.65 ms | 5,802 s | 99.1 GB |

The two upserts account for about **3.54 TB of WAL**. The member upsert affected
406.3 million rows, about 320 per call and **6.9 KB WAL per affected row**.
This strongly motivates reducing repeated member updates and index maintenance;
it does not by itself prove disk saturation before the cache fault.

Current source already batches members in groups of 1,000, sorts by SHA to
order locks, filters older/equal analysis timestamps before upserting, preserves
unchanged TOAST values, and delta-gates location updates. Preserve these changes.
Some older source comments still describe the old atomic whole-archive
transaction and historical 175-second stores; current PostgreSQL code commits
bounded member batches before updating the parent.

Table estimates and index inventory:

- samples: **157.3M live rows**, **1,526 GiB**, **70 indexes**.
- sample_locations: **1.580B live rows**, **2,089 GiB**, **11 indexes**.
- samples updates: 437.1M; HOT updates: 472,048 (**0.108%**).
- Three location indexes occupy approximately **1.33 TB decimal** combined:
  unique (sha256,path) 677 GB; child/parents 370 GB; parent/child 287 GB.
- Examples of zero-scan indexes in this statistics window:
  samples unconvicted_route_fresh 49.3 GB, feed_source 13.6 GB,
  litmus_done 7.8 GB. Zero scans are review candidates, not authorization to
  remove an index; verify periodic queries, replicas, and migration policy.
- Statistics were being maintained; samples had recent vacuum/analyze. This
  was not an observed autovacuum outage.

Configuration: 64 GiB shared_buffers, effective_cache_size=300 GiB on a 249 GiB
host, 64 MiB work_mem, 100 max_connections, synchronous_commit=on, fsync=on,
track_io_timing=off, track_wal_io_timing=off. The 300 GiB planner estimate exceeds
physical RAM; review it against actual ARC/PG cache residency. Do not increase
memory limits blindly. Forager still held 32 mostly idle connections, despite
source comments expecting a smaller budget.

ZFS data and WAL use a mirrored enterprise NVMe pool with an Optane log device;
sync=standard, data recordsize=8K, WAL recordsize=128K, compression=lz4. Pools
reported no errors. `full_page_writes=off` should remain an explicit,
filesystem-specific durability decision, not an additional throughput knob.
Replication was current (about 95 KiB retained WAL at the sampled instant), and
wal_buffers_full was zero. Current idle-period disk measurements cannot establish
the pre-stall disk ceiling.

## EXPLAIN and bounded timing measurements

`explain.sql` plans the actual member and location upsert bodies, with a
materialized CTE substituting for the session staging table and a bounded
1,000-row sample ordered by SHA. INSERTs were **not executed**. The member plan
uses the SHA unique index for point probes; the location plan uses the expected
conflict index and ordered deduplication. No full production-table scan appears
in these shapes.

Read-only EXPLAIN ANALYZE of the member SELECT side took **40.56 ms** on the first
pass (693 shared-buffer reads), then **3.07 ms** on the warm repeat (all hits).
The freshness join made 1,000 index searches. These results demonstrate cache
sensitivity, but omit actual writes, triggers, WAL, commit, and concurrency.
The ordered sample and CTE are not a representative write benchmark.

Next write experiment: an isolated restored database with production schema,
triggers, indexes, and representative archive envelopes. Measure the exact
CREATE TEMP/COPY/member upsert/location upsert/commit/drop sequence. Capture
`EXPLAIN (ANALYZE, BUFFERS, WAL, SETTINGS)` for both writes there; [ANALYZE executes
the statement](https://www.postgresql.org/docs/18/using-explain.html), and rolling
it back still incurs work and locks. Use batches
100/250/500/1000 and concurrency 1/2/4/8/16/32; include fresh members, repeated
shared dependencies, changed analysis, and large archives. Report committed
results/s, members/s, p50/p95/p99, WAL/result, retries, wait events, pool waits,
replica lag, and backlog age. Use deltas rather than resetting production stats.

## Prioritized throughput and ingestion work

1. Deploy the reproduced Fido fix and restart Hopper. Preserve producer retry
   state during recovery. Verify stores resume, full-slot time falls, all lanes
   make progress, uploads finish, and the goroutine population drains.
2. Preserve completed results through outages with a **durable producer outbox**
   (or a durable server inbox acknowledged only after persistence). Use stable
   idempotency identity including SHA and analyzer version, replay with jitter,
   acknowledge durable success, and track backlog bytes/age. RAM-only retries
   have a finite budget. Current scan worker source retries for 20 minutes;
   renewal/forwarding clients have different paths and require an explicit audit.
   Shed counts are requests, not unique permanently lost results.
3. Separate database commit timing from cache invalidation timing. Current
   `phase=store` includes both and records only completed operations, so a cache
   deadlock leaves apparently benign historical histograms. Add in-flight age,
   last durable commit, invalidation latency, successful result acknowledgments,
   and producer outbox depth. Alert on full result slots + no completions + idle
   DB, and on handler panics. Existing shedding alerts did fire; the generic
   analyzed-age alert was not firing in the captured alert list.
4. Reduce repeated member writes when the analysis identity and relevant content
   truly have not changed. The current member freshness timestamp is stamped at
   ingestion, so another archive can rewrite the same dependency. Separate
   observation freshness from verdict changes; preserve late LLM/model/claims
   updates and analyzer version correctness. Benchmark before changing semantics.
5. Audit and remove redundant/obsolete indexes only after query-plan review.
   Longer-term, use compact content IDs for the billion-row location relation
   and keep frequently changed queue/analysis state separate from wide metadata.
   Both need migration and benchmark plans; neither is an immediate hotfix.
6. Benchmark staging reuse per connection and fewer catalog operations. Current
   code creates and drops _staging per batch and commits samples and locations
   separately. Catalog churn is measurable, but much smaller than upsert cost;
   preserve pooled-session cleanup and crash/retry correctness.
7. Enable I/O and WAL timing after measuring its platform overhead; sample wait
   events during a healthy ingest burst. Measure host network RTT, COPY time,
   trigger execution, fsync, and index reads before changing pool/slot limits.

Other concrete concerns: 46 result-store errors on September 23 in the captured
window included repeated PostgreSQL 22021 rejection of NUL bytes in claims;
these can consume the entire retry budget. Fix the claims text boundary while
preserving source evidence. Workers also reported file-descriptor exhaustion,
Windows allocation failures, missing downloaded bytes, and claim/file size
mismatches. Prometheus showed crates publications-loss and PyPI undercoverage
alerts, plus a long-standing Go feed backlog. Increasing database throughput
alone will not resolve all upstream loss.

## Cache memory and instrumentation

At 14:07 the heap profile attributed 54.5 MiB to record-cache fetching and entry
storage, plus key/map/bloom allocations: roughly **60–80 MiB** for the record
cache, with in-flight attribution uncertainty. It is not an exact ownership
measurement. Sample-cache entries were **72/32,768**; record-cache capacity is
128,000. Large profile allocations were JSON payloads and pgx buffers. The
profile's sampled in-use total was 952 MiB; the later live heap metric was
2.30 GiB. These differ in sampling and GC timing and must not be equated.

Previously only sample entry count/capacity and served/load counters were in
Prometheus; record stats were available at /_/corroboration. The new local code
exports both caches through:

- hopper_cache_entries{cache="sample"|"record"}
- hopper_cache_capacity{cache=...}
- hopper_cache_requests_total{cache=...,source="cache"|"database"}
- hopper_cache_memory_estimated_bytes{cache=...}
- hopper_cache_memory_sampled_at_seconds{cache=...}

See README for the windowed served-rate PromQL. Coalesced misses count as served
without database work; this is not a strict resident-hit ratio. Memory accounting
includes payloads, FIFO entries, bloom storage, expired entries and pending
entries; it excludes allocator/xsync internals and in-flight loads and may double
count shared backing storage. The sample timestamp exposes staleness.

Fido adds no sampling goroutine or hot-path byte counters. Hopper samples at most
once a minute in a background task; scrapes read the last successful snapshot.
Fido briefly try-locks queue metadata, then traverses the concurrent map and
invokes sizing callbacks after releasing the writer lock. Local 128K-entry
sampling benchmark: **1.92 ms, zero allocations**. Small before/after benchmark
runs showed ~6.8 ns cache gets and ~172 vs ~176 ns eviction inserts (roughly 2%
median difference, limited local measurement, not production ARM64 results).

Hopper now pins published Fido commit `2fcd14cd89d4` as
`v1.11.1-0.20260923181850-2fcd14cd89d4`; no local replacement remains. Nothing
has been deployed. Fido's full short suite, the new focused race tests, Hopper's
cache/lookup tests, and its cache-metric race tests pass. Production still showed
all 32 result slots occupied in the final read-only snapshot.
