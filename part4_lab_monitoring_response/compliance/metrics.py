#!/usr/bin/env python3
"""Monthly rule-base metrics for management (report Section 14.3).

Computed from the rule base itself, so the numbers cannot drift from the
policy that is actually deployed (export it first if the firewall was
changed outside the repo). Metrics that need live data (hit counters,
time to contain, TLS failure rate) are read from optional inputs or shown
as "needs data".

  python3 metrics.py
  python3 metrics.py --hits review.csv      # CSV from hit_counter_review.py --csv
"""
from __future__ import annotations

import argparse
import csv
import sys

import _path  # noqa: F401
from sjvnet.model import ANY_NET, ObjectModel
from sjvnet.policy import Policy


def is_any(addrset) -> bool:
    return addrset.include == (ANY_NET,) and not addrset.exclude


def compute(policy: Policy, hits_csv: str | None = None) -> list[tuple[str, str, str, bool | None]]:
    rules = policy.rules
    no_meta = [r.id for r in rules if not (r.owner and r.req and r.review)]
    any_any = [r.id for r in rules if r.is_permit and r.enabled and is_any(r.src) and is_any(r.dst)]
    ticket_live = [r.id for r in rules if r.review == "T" and r.enabled and r.raw.get("schedule") != "per-ticket"]
    unlogged = [r.id for r in rules if r.is_permit and r.log not in ("yes", "alert")]
    out = [
        ("Rules without owner, requirement or review", "0", str(len(no_meta)) + (f" ({', '.join(no_meta)})" if no_meta else ""), not no_meta),
        ("Permit rules with any source and destination", "0", str(len(any_any)), not any_any),
        ("Ticket-bound exceptions active without a schedule", "0", str(len(ticket_live)), not ticket_live),
        ("Permit rules without logging", "0", str(len(unlogged)), not unlogged),
    ]
    if hits_csv:
        with open(hits_csv, newline="", encoding="utf-8") as fh:
            dead = [row["rule"] for row in csv.DictReader(fh) if "DEAD" in row.get("flags", "")]
        out.append(("Permit rules with no hits in the period", "reviewed in 30 days",
                    str(len(dead)) + (f" ({', '.join(dead)})" if dead else ""), None))
    else:
        out.append(("Permit rules with no hits for 90 days", "reviewed in 30 days", "needs data (--hits)", None))
    out += [
        ("Changes without a ticket", "0", "needs data (UC-06 count)", None),
        ("Time to contain a G-03 alert", "< 30 min", "needs data (case files)", None),
        ("TLS inspection failure rate", "< 2%", "needs data (NGFW)", None),
        ("Verification tests passing after a change", "100%", "run part3 tools/verify_matrix.py", None),
    ]
    return out


def main(argv=None) -> int:
    ap = argparse.ArgumentParser(description=__doc__.split("\n")[0])
    ap.add_argument("--hits", help="CSV written by hit_counter_review.py --csv")
    args = ap.parse_args(argv)
    policy = Policy.load(model=ObjectModel.load())
    rows = compute(policy, args.hits)
    print(f"{'Metric':52} {'Target':20} {'Value':28} Status")
    bad = 0
    for name, target, value, ok in rows:
        status = "-" if ok is None else ("OK" if ok else "MISS")
        bad += 1 if ok is False else 0
        print(f"{name:52} {target:20} {value:28} {status}")
    print(f"\nRule base: {len(policy.rules)} rules. {bad} metric(s) off target.")
    return 1 if bad else 0


if __name__ == "__main__":
    sys.exit(main())
