#!/usr/bin/env python3
"""Summarise Suricata EVE JSON (experiments E6 and E7).

OPNsense keeps it at /var/log/suricata/eve.json. Copy it to the bastion and run:

    python3 eve_summary.py eve.json                 # alerts by signature
    python3 eve_summary.py eve.json --src 192.168.40.100 --since 2026-01-01T10:00
    python3 eve_summary.py eve.json --apps          # app-layer protocols seen (E7)

For each signature it shows hits, how many were dropped (IPS) versus only
alerted (IDS), and the sources involved. A drop count of 0 in IPS mode is a
finding: either the rule is set to Alert, or the traffic did not cross an
IPS-enabled interface.
"""
from __future__ import annotations

import argparse
import json
import sys
from collections import Counter, defaultdict
from datetime import datetime


def load(path: str):
    with open(path, encoding="utf-8", errors="replace") as fh:
        for n, line in enumerate(fh, 1):
            line = line.strip()
            if not line or line.startswith("#"):
                continue
            try:
                yield json.loads(line)
            except json.JSONDecodeError:
                print(f"skipping malformed line {n}", file=sys.stderr)


def ts(ev) -> datetime | None:
    try:
        return datetime.strptime(ev["timestamp"][:19], "%Y-%m-%dT%H:%M:%S")
    except (KeyError, ValueError):
        return None


def main(argv=None) -> int:
    ap = argparse.ArgumentParser(description=__doc__.split("\n")[0])
    ap.add_argument("eve")
    ap.add_argument("--src", action="append", default=[])
    ap.add_argument("--since", help="ISO time, e.g. 2026-01-01T10:00")
    ap.add_argument("--apps", action="store_true", help="count app_proto per flow instead of alerts")
    args = ap.parse_args(argv)
    since = datetime.fromisoformat(args.since) if args.since else None

    sigs = defaultdict(lambda: {"hits": 0, "blocked": 0, "srcs": Counter(), "sid": None, "sev": None})
    apps = Counter()
    for ev in load(args.eve):
        if since and (ts(ev) or datetime.min) < since:
            continue
        if args.src and ev.get("src_ip") not in args.src:
            continue
        if args.apps and ev.get("app_proto"):
            apps[(ev.get("src_ip"), ev.get("dest_ip"), ev.get("dest_port"), ev["app_proto"])] += 1
        if ev.get("event_type") != "alert":
            continue
        a = ev.get("alert", {})
        s = sigs[a.get("signature", "?")]
        s["hits"] += 1
        s["blocked"] += 1 if a.get("action") == "blocked" else 0
        s["srcs"][ev.get("src_ip")] += 1
        s["sid"], s["sev"] = a.get("signature_id"), a.get("severity")

    if args.apps:
        print(f"{'src':16} {'dst':16} {'port':>5}  app_proto   events")
        for (s, d, p, app), n in apps.most_common():
            print(f"{s or '':16} {d or '':16} {p or '':>5}  {app:10} {n:>6}")
        return 0

    print(f"{'sid':>9} {'sev':>3} {'hits':>5} {'drop':>5}  signature  [sources]")
    for name, s in sorted(sigs.items(), key=lambda kv: -kv[1]["hits"]):
        srcs = ", ".join(f"{ip}x{n}" for ip, n in s["srcs"].most_common(3))
        print(f"{s['sid'] or '':>9} {s['sev'] or '':>3} {s['hits']:>5} {s['blocked']:>5}  {name}  [{srcs}]")
    total = sum(s["hits"] for s in sigs.values())
    dropped = sum(s["blocked"] for s in sigs.values())
    print(f"\n{total} alert(s), {dropped} dropped by IPS, {len(sigs)} distinct signature(s)")
    return 0


if __name__ == "__main__":
    sys.exit(main())
