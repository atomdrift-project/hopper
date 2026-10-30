"""Offline checks for review CSV integrity; no production database access."""
import csv
import importlib.util
import json
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest

sys.dont_write_bytecode = True
SCRIPT = Path(__file__).resolve().parents[1] / "export-pool-review.py"
spec = importlib.util.spec_from_file_location("pool_review", SCRIPT)
review = importlib.util.module_from_spec(spec)
spec.loader.exec_module(review)


class PoolReviewTest(unittest.TestCase):
    def test_hostile_count_excludes_suspicious(self):
        for key, crit, ident in (("traits", "crit", "id"), ("find", "crit", "id"), ("ts", "l", "i")):
            with self.subTest(key=key):
                row = {"cleave_file": {key: [{crit: 4, ident: "suspicious"}, {crit: 5, ident: "hostile"}]}}
                self.assertEqual(review.trait_summary(row), ("hostile", 1, ["hostile"]))
        self.assertEqual(review.trait_summary({"stored_max_crit": 5}), ("unavailable", "", []))

    def test_query_preserves_unicode_line_separator(self):
        from unittest.mock import patch
        result = subprocess.CompletedProcess([], 0, '{"path":"a\u2028b"}\n', "")
        with patch.object(review.subprocess, "run", return_value=result):
            self.assertEqual(review.query("unused", "SELECT 1;"), [{"path": "a\u2028b"}])

    def test_render_roundtrip_and_preserve_decision(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            sha = "a" * 64
            unusual = 'purgatory/a, "quoted"\nline\u2028name'
            seeds = root / "seeds.jsonl"
            seeds.write_text(json.dumps({"sha256": sha, "path": unusual, "kind": "standalone"}) + "\n")
            evidence = dict(sha256=sha, label="purgatory", decider="triage", canonical_path=unusual,
                            locations=[dict(path="good/a", parent="", rel="")],
                            cleave_file={"traits": []})
            (root / "evidence.jsonl").write_text(json.dumps(evidence) + "\n")
            command = [sys.executable, str(SCRIPT), "--render-only", "--seeds", str(seeds), "--output", str(root)]
            subprocess.run(command, check=True, capture_output=True)
            with (root / "review.csv").open(newline="") as source:
                rows = list(csv.DictReader(source))
            self.assertEqual(len(rows), 1)
            self.assertIn(unusual, json.loads(rows[0]["paths"]))
            self.assertEqual(rows[0]["suggested_pool"], "good")
            self.assertEqual(rows[0]["decided_pool"], "")
            rows[0].update(decided_pool="dual-use", review_status="reviewed", review_rationale="Individual decision")
            with (root / "review.csv").open("w", newline="") as dest:
                writer = csv.DictWriter(dest, fieldnames=list(rows[0]))
                writer.writeheader()
                writer.writerows(rows)
            subprocess.run(command, check=True, capture_output=True)
            with (root / "review.csv").open(newline="") as source:
                updated = next(csv.DictReader(source))
            self.assertEqual(updated["decided_pool"], "dual-use")
            self.assertEqual(updated["review_rationale"], "Individual decision")

    def test_api_export_uses_exact_locations_and_defers_members(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            rows = [dict(sha256="a" * 64, decided_pool="good", review_status="best_guess", review_rationale="benign interpretation"),
                    dict(sha256="b" * 64, decided_pool="inconclusive", review_status="best_guess", review_rationale="insufficient evidence")]
            with (root / "review.csv").open("w", newline="") as out:
                writer = csv.DictWriter(out, fieldnames=list(rows[0]))
                writer.writeheader()
                writer.writerows(rows)
            records = [dict(sha256="a" * 64, locations=[dict(path="purgatory/a", parent=""), dict(path="purgatory/x.zip!!a", parent="c" * 64)]),
                       dict(sha256="b" * 64, locations=[dict(path="purgatory/x.zip!!b", parent="c" * 64)])]
            (root / "evidence.jsonl").write_text("".join(json.dumps(r) + "\n" for r in records))
            subprocess.run([sys.executable, str(SCRIPT.with_name("export-pool-review-api.py")), "--directory", str(root)], check=True, capture_output=True)
            requests = [json.loads(line) for line in (root / "api-dry-run-requests.jsonl").read_text().split("\n") if line]
            self.assertEqual(len(requests), 1)
            self.assertTrue(requests[0]["dry_run"])
            self.assertEqual(requests[0]["verdicts"][0]["old_path"], "purgatory/a")
            self.assertEqual(requests[0]["verdicts"][0]["verdict"], "good")
            deferred = json.loads((root / "api-deferred.jsonl").read_text())
            self.assertEqual(deferred["sha256"], "b" * 64)


if __name__ == "__main__":
    unittest.main()
