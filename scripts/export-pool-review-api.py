#!/usr/bin/env python3
"""Export exact-location Hopper API dry-run requests from the decided CSV.

Writes local request bodies only. Execution and all live changes belong to
Hopper's /api/triage move API. These are classification requests, not a claim
that the current endpoint consolidates all aliases into one destination.
"""
import argparse
import csv
import json
from pathlib import Path


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--directory", type=Path, required=True)
    args = parser.parse_args()
    root = args.directory
    csv.field_size_limit(100_000_000)
    with (root / "review.csv").open(newline="") as source:
        decisions = {r["sha256"]: r for r in csv.DictReader(source)}
    requests = 0
    deferred = 0
    with (root / "evidence.jsonl").open() as source, (root / "api-dry-run-requests.jsonl").open("w") as out, (root / "api-deferred.jsonl").open("w") as pending:
        for line in source:
            record = json.loads(line)
            row = decisions[record["sha256"]]
            if row["review_status"] not in {"reviewed", "best_guess"} or not row["review_rationale"].strip():
                raise ValueError("Unfinished review for " + row["sha256"])
            pool = row["decided_pool"]
            if pool not in {"good", "bad", "inconclusive", "dual-use"}:
                raise ValueError("Missing/invalid decision for " + row["sha256"])
            locations = [l for l in record["locations"] if not l["parent"]]
            if not locations:
                pending.write(json.dumps(dict(sha256=row["sha256"], decided_pool=pool,
                    reason="No standalone catalog location; archive membership must be preserved.")) + "\n")
                deferred += 1
                continue
            for location in locations:
                item = dict(sha256=row["sha256"], old_path=location["path"],
                            source="triage/pool-review-20261029/" + row["review_status"])
                item["verdict" if pool in {"good", "bad"} else "ruling"] = pool
                out.write(json.dumps(dict(verdicts=[item], dry_run=True)) + "\n")
                requests += 1
    print(json.dumps(dict(dry_run_request_count=requests, deferred_hashes=deferred,
                         endpoint="POST /api/triage", live_changes=False)))


if __name__ == "__main__":
    main()
