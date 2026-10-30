#!/usr/bin/env python3
"""Record transparent best guesses for this collection, with inconclusive fallback.

This is a batch review aid, not a malware detector. It does not mutate Hopper.
Directly inspected decisions in review.csv always take precedence.
"""
import argparse
import collections
import csv
import json
from pathlib import Path, PurePosixPath
import re

DUAL_USE = re.compile(
    r"metasploit|meterpreter|impacket|mimikatz|bloodhound|sharphound|"
    r"cobalt[-_. ]?strike|bishopfox[/.-]sliver|/projects/sliver/|\bsqlmap\b|lgandx[/.-]responder|"
    r"evil[-_.]?winrm|crackmapexec|netexec|powersploit|power[sS]hell[-_.]?empire|"
    r"rustredops|black-hat-rust|lazyown|slackor|memshellparty|yaklang|"
    r"/projects/exploits/|/exploit-db/|/exploitdb/|/pentest/|/red[-_]?team/",
    re.IGNORECASE,
)
MALWARE = re.compile(
    r"vega-stealer|ultimate-stealer-collection|malicious_intent/|"
    r"/datalake\.abuse\.ch/|/virusshare/|/vxheaven/|/vx\.netlux\.org/|"
    r"/malwarebazaar/|/bazaar/|/vxunderground-inthewild/|/malware-feed/|"
    r"trojan[.-]|backdoor[.-]|ransomware|ransom\.win|"
    r"/forager/bad/sha256/|/malcontent-samples/|"
    r"(?:^|[/_.-])(?:njrat|remcos|vidar|amadey|darkgate|rhadamanthys|icedid|medusalocker|revil|stealc|luca-stealer)(?:[/_.-]|$)",
    re.IGNORECASE,
)
BENIGN_ASSET_TYPES = {"png", "jpeg", "jpg", "gif", "bmp", "ico", "ttf", "woff", "woff2"}
BENIGN_TEXT_NAMES = {"license", "copying", "notice", "authors", "changelog", "readme", "copyright"}


def best_guess(row, record):
    file = record.get("cleave_file") or {}
    traits = file.get("traits") or file.get("find") or file.get("ts") or []
    suspicious = [t for t in traits if int(t.get("crit") or t.get("l") or 0) >= 4]
    hostile = [t for t in traits if int(t.get("crit") or t.get("l") or 0) >= 5]
    path = record.get("canonical_path", "")
    # Other physical aliases are evidence too, but a misleading ancestor name
    # never makes a generic passive asset offensive by itself.
    context = "\n".join([path] + json.loads(row["paths"]))
    name = PurePosixPath(path).name.lower()
    kind = (record.get("file_type") or file.get("type") or "").lower()
    label = record.get("label", "")
    signals = set(json.loads(row["other_pool_signals"]))
    llm = record.get("llm_result") or {}
    interpretation = llm.get("interpretation", "")
    if record.get("size_bytes") == 0:
        return "good", "medium", "Empty content has a reasonable benign interpretation regardless of its containing archive."
    if not suspicious and kind in BENIGN_ASSET_TYPES:
        return "good", "medium", f"Passive {kind} asset with no suspicious or hostile traits; reasonable benign interpretation."
    if not suspicious and name.split(".")[0] in BENIGN_TEXT_NAMES:
        return "good", "medium", "Documentation/license file with no suspicious or hostile findings; reasonable benign interpretation."
    malware = MALWARE.search(context)
    # A good signal is meaningful even for malware feeds: those contain benign
    # collateral too. Retain good unless a specific offensive role is evident.
    dual = DUAL_USE.search(context)
    if dual and not malware:
        return "dual-use", "medium", f"Offensive/security-tool context ({dual.group(0)}) supports legitimate testing and malicious reuse."
    if label == "good" or signals == {"good"}:
        return "good", "low", "Existing good label/location provides the requested benign signal; no stronger individual decision was available."
    if malware:
        return "bad", "medium", f"Malware-related collection/project context ({malware.group(0)}); follows the requested malware-related policy."
    if signals == {"bad"} or label == "bad" and "good" not in signals:
        return "bad", "low", "Existing bad label/location is the only alternative pool signal; lean toward it as requested."
    if dual:
        return "dual-use", "low", f"Security-tool context ({dual.group(0)}) supports dual-use despite mixed pool signals."
    if not llm.get("error") and interpretation and llm.get("grade") == "benign":
        return "good", "low", "Stored analysis supplies a benign interpretation: " + interpretation
    if not llm.get("error") and interpretation and llm.get("grade") == "hostile" and hostile:
        return "bad", "low", "Hostile findings corroborate the stored interpretation: " + interpretation
    specific = [t.get("id", t.get("i", "")) for t in hostile
                if re.match(r"well-known/(malware|ransomware)/", t.get("id", t.get("i", "")))]
    if specific:
        return "bad", "medium", "Specific malware-family trait: " + specific[0]
    if "good" in signals and not hostile:
        return "good", "low", "Mixed pool signals include good and no hostile finding supports the bad signal; prefer the reasonable benign interpretation."
    return "inconclusive", "low", "Available paths, labels, and stored analysis do not support a better guess; requested default is inconclusive."


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--directory", type=Path, required=True)
    args = parser.parse_args()
    root = args.directory
    csv.field_size_limit(100_000_000)
    with (root / "review.csv").open(newline="") as source:
        reader = csv.DictReader(source)
        fields = list(reader.fieldnames)
        rows = {r["sha256"]: r for r in reader}
    for field in ("decision_confidence", "review_decider"):
        if field not in fields:
            fields.append(field)
    with (root / "evidence.jsonl").open() as source:
        for line in source:
            record = json.loads(line)
            row = rows[record["sha256"]]
            if row["review_status"] == "reviewed" and row["decided_pool"]:
                row["review_decider"] = "Codex:individual-static-review"
                row["decision_confidence"] = "medium"
                continue
            pool, confidence, reason = best_guess(row, record)
            row.update(decided_pool=pool, decision_confidence=confidence, review_rationale=reason,
                       review_status="best_guess", review_decider="Codex:collection-policy-v1")
    if any(not r["decided_pool"] for r in rows.values()):
        raise ValueError("Some rows lack evidence/decisions")
    temporary = root / "decisions.csv.tmp"
    with temporary.open("w", newline="") as out:
        writer = csv.DictWriter(out, fieldnames=fields)
        writer.writeheader()
        writer.writerows(rows[sha] for sha in sorted(rows))
    temporary.replace(root / "review.csv")
    counts = collections.Counter(r["decided_pool"] for r in rows.values())
    (root / "decision-summary.json").write_text(json.dumps(dict(policy="collection-policy-v1", counts=counts,
        rows=len(rows), applied=False, default="inconclusive", individually_inspected=sum(r["review_status"] == "reviewed" for r in rows.values())), indent=2) + "\n")
    print(json.dumps(counts))


if __name__ == "__main__":
    main()
