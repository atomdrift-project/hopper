# hopper

Hopper is a sample registry for malware research. You point it at directories of binaries — known-bad, known-good, or both — and it catalogs them, runs static analysis via [cleave](https://codeberg.org/atomdrift/cleave), and stores everything in a database that downstream tools can query.

It's the shared data layer for the [atomdrift](https://codeberg.org/atomdrift) pipeline: [cyclotron](https://github.com/atomdrift/cyclotron) reads samples from hopper to drive LLM-powered reverse engineering, and [collimator](https://codeberg.org/atomdrift/collimator) reads cleave results to train detection models. But hopper is useful on its own — if you have a pile of samples and want them analyzed and organized, this is where you start.

## Quick start

```bash
# Initialize a local SQLite database and load samples with cleave analysis:
hopper init --db samples.db
hopper load --db samples.db --bad ./malware --good ./benign

# Or use PostgreSQL for production scale:
hopper serve                          # starts a local postgres instance
hopper load --bad ./malware --good ./benign   # uses DATABASE_URL
```

When loading, hopper auto-starts a cleave server, manages its memory, restarts it if it crashes, and parallelizes analysis across your samples. Pass `--rescan` to re-analyze samples that already have results.

## As a Go library

```go
db, _ := hopper.Open(ctx, "postgres://localhost:5433/hopper")
defer db.Close()

db.InsertSample(ctx, &hopper.Sample{SHA256: sha, Label: "bad", StoragePath: path})
db.UpdateCleaveResult(ctx, sha, cleaveJSON, "hostile", 5)

samples, _ := db.SamplesByStatus(ctx, "bad-review", 100)
```

PostgreSQL or SQLite — detected automatically from the DSN.

## How it fits together

```
samples on disk ──→ hopper load ──→ hopper DB ←── cyclotron (RE + traits)
                        │                │
                     cleave              └──→ collimator (ML training)
                   (auto-managed)
```

## Building

Requires Go 1.25+ with CGO enabled (for SQLite). PostgreSQL 14+ for the `serve` command.

```bash
make build    # produces ./hopper
make test
make lint
```
