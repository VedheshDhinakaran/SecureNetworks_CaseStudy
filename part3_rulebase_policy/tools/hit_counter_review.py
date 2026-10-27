#!/usr/bin/env python3
"""Rule-hit counter review (report Section 10.2, monthly hygiene review).

Input is the output of `pfctl -vvsr` saved from the firewall:

    ssh root@192.168.90.1 'pfctl -vvsr' > results/pfctl_$(date +%F).txt
    ssh root@192.168.90.1 'cat /tmp/rules.debug' > results/rules.debug

OPNsense labels each pf rule with a hash, not with our rule ID. The mapping
is taken from rules.debug (each rule line ends in `label "<hash>" # <descr>`)
or from a CSV with columns label,rule_id. Our descriptions start with the
rule ID ("DV-01 DNS"), so the ID is the first token of the description.

What it reports, per rule ID:
  * evaluations, packets, bytes and states in the snapshot
  * delta against an earlier snapshot (--baseline), if given
  * flags:  DEAD     permit with zero packets (candidate for removal)
            HOT      packets > 5x baseline (mis-scoped or abused rule)
            ALERT    a deny rule logged as 'alert' in policy.yaml was hit
            UNMAPPED pf rule whose label we could not map to an ID

Usage:
  python3 hit_counter_review.py current.txt --rules-debug rules.debug
  python3 hit_counter_review.py current.txt --baseline last_month.txt --label-map labels.csv
  python3 hit_counter_review.py current.txt --only DV-0     # E3 counters
"""
from __future__ import annotations

import argparse
import csv
import re
import sys
from collections import OrderedDict
from dataclasses import dataclass

import _path  # noqa: F401
from sjvnet.model import ObjectModel
from sjvnet.opnsense import RULE_ID_RE as ID_RE
from sjvnet.opnsense import label_map_from_debug
from sjvnet.policy import Policy

RULE_RE = re.compile(r"^@(?P<num>\d+)\s+(?P<action>pass|block|match)\b(?P<body>.*)$")
LABEL_RE = re.compile(r'label\s+"(?P<label>[^"]+)"')
COUNTER_RE = re.compile(r"(Evaluations|Packets|Bytes|States):\s*(\d+)")


@dataclass
class Counter:
    label: str
    action: str
    evaluations: int = 0
    packets: int = 0
    bytes: int = 0
    states: int = 0

    def add(self, other: "Counter") -> None:
        self.evaluations += other.evaluations
        self.packets += other.packets
        self.bytes += other.bytes
        self.states += other.states


def parse_pfctl(text: str) -> list[Counter]:
    """Parse `pfctl -vvsr` output into one Counter per pf rule."""
    out: list[Counter] = []
    current: Counter | None = None
    for line in text.splitlines():
        if line.lstrip().startswith("#"):
            continue
        m = RULE_RE.match(line.strip())
        if m:
            lab = LABEL_RE.search(m.group("body"))
            current = Counter(label=lab.group("label") if lab else "", action=m.group("action"))
            out.append(current)
            continue
        if current is not None and line.strip().startswith("["):
            for key, val in COUNTER_RE.findall(line):
                setattr(current, key.lower(), int(val))
    return out


def label_map_from_csv(path: str) -> dict[str, str]:
    with open(path, newline="", encoding="utf-8") as fh:
        return {row["label"]: row["rule_id"] for row in csv.DictReader(fh)}


def aggregate(counters: list[Counter], mapping: dict[str, str]) -> "OrderedDict[str, Counter]":
    """One rule ID can become several pf rules (e.g. TCP and UDP); sum them."""
    agg: "OrderedDict[str, Counter]" = OrderedDict()
    for c in counters:
        rid = mapping.get(c.label) or (c.label if ID_RE.fullmatch(c.label or "") else None)
        if rid is None:
            if not c.label:
                continue           # OPNsense housekeeping rules without labels
            rid = f"UNMAPPED:{c.label[:12]}"
        agg.setdefault(rid, Counter(rid, c.action)).add(c)
    return agg


def review(current, baseline, alert_ids: set, hot_factor: float = 5.0) -> list[dict]:
    rows = []
    for rid, c in current.items():
        b = baseline.get(rid) if baseline else None
        delta = c.packets - b.packets if b else None
        flags = []
        if rid.startswith("UNMAPPED"):
            flags.append("UNMAPPED")
        if c.action == "pass" and c.packets == 0:
            flags.append("DEAD")
        if b and b.packets > 0 and c.packets > hot_factor * b.packets:
            flags.append("HOT")
        if c.action == "block" and rid in alert_ids and c.packets > 0:
            flags.append("ALERT")
        rows.append({"rule": rid, "action": c.action, "evaluations": c.evaluations, "packets": c.packets,
                     "bytes": c.bytes, "states": c.states,
                     "delta_packets": "" if delta is None else delta, "flags": ",".join(flags)})
    return rows


def main(argv=None) -> int:
    ap = argparse.ArgumentParser(description=__doc__.split("\n")[0])
    ap.add_argument("current", help="saved `pfctl -vvsr` output")
    ap.add_argument("--baseline", help="earlier `pfctl -vvsr` output to compare against")
    ap.add_argument("--rules-debug", help="copy of /tmp/rules.debug from OPNsense")
    ap.add_argument("--label-map", help="CSV with columns label,rule_id")
    ap.add_argument("--only", help="only rule IDs starting with this prefix (e.g. DV-0)")
    ap.add_argument("--csv", action="store_true", help="CSV output for the review record")
    args = ap.parse_args(argv)

    mapping: dict[str, str] = {}
    if args.rules_debug:
        mapping.update(label_map_from_debug(open(args.rules_debug, encoding="utf-8").read()))
    if args.label_map:
        mapping.update(label_map_from_csv(args.label_map))

    current = aggregate(parse_pfctl(open(args.current, encoding="utf-8").read()), mapping)
    baseline = None
    if args.baseline:
        baseline = aggregate(parse_pfctl(open(args.baseline, encoding="utf-8").read()), mapping)

    policy = Policy.load(model=ObjectModel.load())
    alert_ids = {r.id for r in policy.rules if r.log == "alert"}
    rows = review(current, baseline, alert_ids)
    if args.only:
        rows = [r for r in rows if r["rule"].startswith(args.only)]

    if args.csv:
        w = csv.DictWriter(sys.stdout, fieldnames=list(rows[0]) if rows else ["rule"], lineterminator="\n")
        w.writeheader()
        w.writerows(rows)
        return 0

    print(f"{'rule':12} {'act':5} {'evals':>9} {'packets':>9} {'bytes':>11} {'states':>6} {'delta':>8}  flags")
    for r in rows:
        print(f"{r['rule']:12} {r['action']:5} {r['evaluations']:>9} {r['packets']:>9} {r['bytes']:>11} "
              f"{r['states']:>6} {str(r['delta_packets']):>8}  {r['flags']}")
    dead = [r["rule"] for r in rows if "DEAD" in r["flags"]]
    alerts = [r["rule"] for r in rows if "ALERT" in r["flags"]]
    print(f"\n{len(rows)} rule IDs; dead permits: {', '.join(dead) or 'none'}; "
          f"alert-level denies hit: {', '.join(alerts) or 'none'}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
