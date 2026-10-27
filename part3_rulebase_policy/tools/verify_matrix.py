#!/usr/bin/env python3
"""Run the verification-matrix probes through the production policy (simulator).

Prints one line per probe and a per-test summary. Exit code 1 if any probe
gets a different action or a different deciding rule than expected, so it
can gate a policy change the same way lint_policy.py does.

This proves the rule base is written correctly. It does not replace the lab
run: the matrix's `observed_in_lab` column is filled from Part IV evidence.
"""
from __future__ import annotations

import argparse
import sys
from collections import defaultdict
from pathlib import Path

import yaml

import _path  # noqa: F401
from sjvnet import POLICY_FILE
from sjvnet.model import ObjectModel
from sjvnet.policy import Packet, Policy

PROBES = Path(__file__).resolve().parent.parent / "verification" / "probes.yaml"


def resolve(name: str, addresses: dict, model: ObjectModel) -> str:
    if name in addresses:
        return str(addresses[name])
    return model.host_ip(name)


def run(policy: Policy, data: dict) -> list[tuple[dict, Packet, object, bool]]:
    model = policy.model
    out = []
    for p in data["probes"]:
        pkt = Packet(resolve(p["src"], data["addresses"], model), resolve(p["dst"], data["addresses"], model),
                     p.get("proto", "tcp"), p.get("dport"), url_path=p.get("url_path"), app=p.get("app"),
                     user_groups=tuple(p.get("groups", ())))
        d = policy.evaluate(pkt, ngfw=p.get("ngfw", True))
        ok = d.action == p["expect"] and (d.rule.id if d.rule else None) == p.get("rule")
        out.append((p, pkt, d, ok))
    return out


def main(argv=None) -> int:
    ap = argparse.ArgumentParser(description=__doc__.split("\n")[0])
    ap.add_argument("--policy", default=POLICY_FILE)
    ap.add_argument("--probes", default=PROBES)
    ap.add_argument("-q", "--quiet", action="store_true", help="only print failures and the summary")
    args = ap.parse_args(argv)

    policy = Policy.load(args.policy, ObjectModel.load())
    data = yaml.safe_load(open(args.probes, encoding="utf-8"))
    results = run(policy, data)

    per_test = defaultdict(lambda: [0, 0])
    for p, pkt, d, ok in results:
        per_test[p["test"]][0 if ok else 1] += 1
        if ok and args.quiet:
            continue
        mark = "PASS" if ok else "FAIL"
        exp = f"{p['expect']} by {p.get('rule')}"
        note = f"  ({p['note']})" if p.get("note") else ""
        print(f"[{mark}] T{p['test']:<2} {str(pkt):52} expected {exp:16} got {d}{note}")

    print("\nTest  probes  result")
    for t in sorted(per_test):
        good, bad = per_test[t]
        print(f"T{t:<4} {good + bad:>6}  {'PASS' if not bad else 'FAIL'}")
    fails = sum(b for _, b in per_test.values())
    print(f"\n{len(results)} probes, {fails} failure(s). Simulator result only; lab evidence is in Part IV.")
    return 1 if fails else 0


if __name__ == "__main__":
    sys.exit(main())
