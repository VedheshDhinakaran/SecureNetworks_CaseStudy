#!/usr/bin/env python3
"""Rebuild an incident timeline from OPNsense filterlog (experiment E8, matrix test 15).

Reads the remote copy of the firewall log (rsyslog on the bastion), keeps the
lines for the sources of interest, maps each pf label to our rule ID and
prints one row per event:

    time | src (zone) | dst (zone) | proto/port | rule | action

With --marks it also checks the timeline against the attempt times the team
wrote down during the run (attempt_times.csv from experiments/common.sh):
every marked attempt should have at least one matching log line within
--window seconds. That check is what "complete" means in Table 11.2.

Usage:
  python3 timeline.py /var/log/opnsense.log --rules-debug rules.debug \\
      --src 192.168.40.100 --src 10.61.0.0/24 --action block --marks attempt_times.csv
  python3 timeline.py filterlog.log --csv > evidence/E8/timeline.csv
"""
from __future__ import annotations

import argparse
import csv
import ipaddress
import sys
from datetime import datetime, timedelta

import _path  # noqa: F401
from sjvnet.model import ObjectModel
from sjvnet.opnsense import FilterEvent, label_map_from_debug, parse_filterlog


def in_any(ip: str, nets: list) -> bool:
    try:
        addr = ipaddress.ip_address(ip)
    except ValueError:
        return False
    return any(addr in n for n in nets)


def load_marks(path: str) -> list[tuple[datetime, str, str]]:
    marks = []
    with open(path, encoding="utf-8") as fh:
        for row in csv.reader(fh):
            if not row or row[0].startswith("#"):
                continue
            marks.append((datetime.fromisoformat(row[0]), row[1], ",".join(row[2:])))
    return marks


def _naive(t: datetime) -> datetime:
    return t.replace(tzinfo=None) if t.tzinfo else t


def check_marks(events: list[FilterEvent], marks, window: int) -> list[tuple]:
    out = []
    for t, role, text in marks:
        hits = [e for e in events if e.time and abs(_naive(e.time) - _naive(t)) <= timedelta(seconds=window)]
        out.append((t, role, text, len(hits), sorted({e.rule_id or e.label[:8] for e in hits})))
    return out


def main(argv=None) -> int:
    ap = argparse.ArgumentParser(description=__doc__.split("\n")[0])
    ap.add_argument("logfile", nargs="+")
    ap.add_argument("--rules-debug", help="copy of /tmp/rules.debug (maps label hash to rule ID)")
    ap.add_argument("--src", action="append", default=[], help="source IP or CIDR (repeatable)")
    ap.add_argument("--dst", action="append", default=[], help="destination IP or CIDR (repeatable)")
    ap.add_argument("--action", choices=["pass", "block", "reject"])
    ap.add_argument("--rule", action="append", default=[], help="only these rule IDs")
    ap.add_argument("--year", type=int, help="year for BSD-style timestamps without one")
    ap.add_argument("--marks", help="attempt_times.csv written by experiments/common.sh")
    ap.add_argument("--window", type=int, default=30, help="seconds either side of a mark")
    ap.add_argument("--csv", action="store_true")
    args = ap.parse_args(argv)

    labels = label_map_from_debug(open(args.rules_debug, encoding="utf-8").read()) if args.rules_debug else {}
    src_nets = [ipaddress.ip_network(s, strict=False) for s in args.src]
    dst_nets = [ipaddress.ip_network(s, strict=False) for s in args.dst]
    model = ObjectModel.load()

    events: list[FilterEvent] = []
    for path in args.logfile:
        with open(path, encoding="utf-8", errors="replace") as fh:
            for ev in parse_filterlog(fh, labels, args.year):
                if src_nets and not in_any(ev.src, src_nets):
                    continue
                if dst_nets and not in_any(ev.dst, dst_nets):
                    continue
                if args.action and ev.action != args.action:
                    continue
                if args.rule and ev.rule_id not in args.rule:
                    continue
                events.append(ev)
    events.sort(key=lambda e: _naive(e.time) if e.time else datetime.min)

    if args.csv:
        w = csv.writer(sys.stdout, lineterminator="\n")
        w.writerow(["time", "src", "src_zone", "dst", "dst_zone", "proto", "dport", "rule", "action", "iface"])
        for e in events:
            w.writerow([e.time.isoformat() if e.time else "", e.src, model.zone_of(e.src), e.dst,
                        model.zone_of(e.dst), e.proto, e.dport or "", e.rule_id or e.label, e.action, e.interface])
    else:
        print(f"{'time':25} {'source':28} {'destination':28} {'svc':9} {'rule':7} action")
        for e in events:
            t = e.time.isoformat(timespec="seconds") if e.time else "?"
            src = f"{e.src} ({model.zone_of(e.src).replace('Z_', '')})"
            dst = f"{e.dst} ({model.zone_of(e.dst).replace('Z_', '')})"
            svc = f"{e.proto}/{e.dport}" if e.dport else e.proto
            print(f"{t:25} {src:28} {dst:28} {svc:9} {(e.rule_id or e.label[:7]):7} {e.action}")
        print(f"\n{len(events)} event(s)")

    if args.marks:
        print("\nAttempt marks vs log", file=sys.stderr)
        missing = 0
        for t, role, text, n, rules in check_marks(events, load_marks(args.marks), args.window):
            status = "FOUND" if n else "MISSING"
            missing += 0 if n else 1
            print(f"  {status:7} {t.isoformat(timespec='seconds')} {role:7} {text}  "
                  f"({n} line(s){', rules ' + ','.join(rules) if rules else ''})", file=sys.stderr)
        print(f"  {missing} marked attempt(s) without a log line", file=sys.stderr)
        return 1 if missing else 0
    return 0


if __name__ == "__main__":
    sys.exit(main())
