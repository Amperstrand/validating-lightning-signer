#!/usr/bin/env python3
"""Summarize a derivation-auditor JSONL trail.

Usage: audit_summary.py <trail.jsonl> [trail2.jsonl ...]

Prints per-checkpoint verdict counts, on_chain_match status, and
cross-implementation field agreement for justice records.
"""

import json
import sys

FIELDS = [
    "funding_pubkey",
    "revocation_basepoint",
    "htlc_basepoint",
    "delayed_basepoint",
    "payment_basepoint",
    "to_self_delay",
    "per_commitment_point",
]


def summarize(path: str) -> None:
    records = []
    with open(path) as f:
        for line in f:
            try:
                records.append(json.loads(line))
            except json.JSONDecodeError:
                continue

    counts = {}
    for r in records:
        counts[(r.get("checkpoint"), r.get("verdict"))] = (
            counts.get((r.get("checkpoint"), r.get("verdict")), 0) + 1
        )
    print(f"== {path}: {len(records)} records")
    for (ckpt, verdict), n in sorted(counts.items(), key=str):
        print(f"   {ckpt:<20} {verdict:<18} {n}")

    justice = [r for r in records if r.get("checkpoint") == "justice"]
    if justice:
        matches = [r.get("context", {}).get("on_chain_match") for r in justice]
        true_n = sum(1 for m in matches if m is True)
        print(f"   on_chain_match: {true_n}/{len(justice)} true")

        agreements = {}
        for r in justice:
            e, v = r.get("electrum", {}), r.get("vls", {})
            agree = sum(1 for f in FIELDS if e.get(f) == v.get(f))
            agreements[agree] = agreements.get(agree, 0) + 1
        print(f"   input agreement (of {len(FIELDS)}): {agreements}")

        diverging = set()
        for r in justice:
            e, v = r.get("electrum", {}), r.get("vls", {})
            for f in FIELDS:
                if e.get(f) != v.get(f):
                    diverging.add(f)
        if diverging:
            print(f"   diverging fields: {sorted(diverging)}")

    gate = [r for r in records if "decision" in r]
    if gate:
        decisions = {}
        for r in gate:
            decisions[r["decision"]] = decisions.get(r["decision"], 0) + 1
        print(f"   gate decisions: {decisions}")


if __name__ == "__main__":
    if len(sys.argv) < 2:
        print(__doc__)
        sys.exit(1)
    for path in sys.argv[1:]:
        summarize(path)
