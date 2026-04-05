# hopper

Sample registry for the [atomdrift](https://codeberg.org/atomdrift) malware detection pipeline. Stores binary samples, cleave analysis results, and reverse engineering reports in PostgreSQL or SQLite.

Hopper is the canonical data store between **cyclotron** (LLM-driven reverse engineering and trait improvement) and **collimator** (ML training). Cyclotron reads work items from hopper and writes results back. Collimator reads labeled samples and cleave results for training.

## CLI

```
hopper serve             # start a local postgres with hopper schema
hopper init --db <dsn>   # create/migrate the database
hopper load --bad ./malware --good ./benign [--rescan]
hopper import --db <dst> --from <src>
hopper import-legacy --db <dst> --from /path/to/cyclotron.db
hopper stats --db <dsn>
```

The `load` command hashes files, inserts samples, and runs cleave analysis by default. Cleave is auto-started as a managed server with health monitoring, OOM-aware memory limits, and automatic restart on crash. Pass `--cleave=""` to disable analysis, or `--cleave /path/to/cleave` to use a specific binary. Pass `--rescan` to re-analyze samples that already have results.

Set `DATABASE_URL` to avoid passing `--db` every time.

## Library

```go
db, _ := hopper.Open(ctx, "postgres://localhost:5433/hopper")
defer db.Close()
db.Migrate(ctx)
db.InsertSample(ctx, &hopper.Sample{SHA256: "abc...", Label: "bad", StoragePath: "/data/s1"})
db.UpdateCleaveResult(ctx, "abc...", rawJSON, "hostile", 5)
```

Dual backend: `postgres://` or `postgresql://` DSNs use PostgreSQL; everything else is treated as a SQLite file path. Detected automatically.

## Schema

Two tables: **samples** (metadata, labels, cleave results, canonical SHA for train/test splits) and **reports** (analysis reports keyed by SHA256 and type). See `schema.sql` / `schema_sqlite.sql`.

The `canonical_sha256` column is the lexicographic minimum SHA256 across a sample and all its embedded archive files. Collimator uses this for deterministic train/test partitioning — archives sharing an inner file get the same canonical SHA and land in the same partition.

## Data flow

```
files on disk → hopper load [--cleave] → hopper DB ← cyclotron (RE/traits)
                                              ↓
                                         collimator (ML training)
```

## Requirements

- Go 1.25+, CGO enabled (for go-sqlite3)
- PostgreSQL 14+ (for `serve` command and production use)
- cleave binary (optional, for `--cleave` analysis during load)
