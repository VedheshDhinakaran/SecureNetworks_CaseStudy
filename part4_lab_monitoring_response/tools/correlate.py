#!/usr/bin/env python3
"""Offline implementation of SIEM use cases UC-01 to UC-05 (report Section 12.2).

The production SIEM runs the Sigma rules in ../siem/sigma/. This script
applies the same logic to a saved filterlog file so the team can test the
thresholds on lab logs without a SIEM.

  UC-01  one source denied in >= 3 distinct zones within 60 s   HIGH
  UC-02  any hit on G-03 (EMR database from outside HIS)        CRITICAL
  UC-03  >= 5 DV-05 denies to the internet in 10 min, per src    HIGH
  UC-04  >= 20 VW-01 denies in 5 min, per src                    MEDIUM
  UC-05  any hit on X-99 (final deny = policy gap)               LOW (ticket)

UC-06 (unticketed change) needs the firewall audit log, not filterlog,
so it is only in Sigma form.

Thresholds can be lowered for a short lab run with --lab-thresholds.
"""
from __future__ import annotations

import argparse
import sys
from collections import defaultdict
from dataclasses import dataclass
from datetime import datetime, timedelta

import _path  # noqa: F401
from sjvnet.model import ObjectModel
from sjvnet.opnsense import FilterEvent, label_map_from_debug, parse_filterlog


@dataclass
class Alert:
    uc: str
    severity: str
    time: datetime
    src: str
    detail: str

    def __str__(self) -> str:
        return f"{self.time.isoformat(timespec='seconds')}  {self.uc}  {self.severity:8}  {self.src:15}  {self.detail}"


PROD = {"uc01_zones": 3, "uc01_window": 60, "uc03_count": 5, "uc03_window": 600,
        "uc04_count": 20, "uc04_window": 300}
LAB = {"uc01_zones": 3, "uc01_window": 60, "uc03_count": 2, "uc03_window": 600,
       "uc04_count": 2, "uc04_window": 300}


def _naive(t):
    return t.replace(tzinfo=None) if t and t.tzinfo else t


def sliding(events: list[FilterEvent], window: int, key, threshold: int, distinct=None):
    """Yield (src, first_event, events_in_window) the first time a threshold is crossed per src."""
    by_src = defaultdict(list)
    for e in events:
        by_src[key(e)].append(e)
    for src, evs in by_src.items():
        evs.sort(key=lambda e: _naive(e.time))
        start = 0
        for end, e in enumerate(evs):
            while _naive(e.time) - _naive(evs[start].time) > timedelta(seconds=window):
                start += 1
            win = evs[start:end + 1]
            size = len({distinct(x) for x in win}) if distinct else len(win)
            if size >= threshold:
                yield src, e, win
                break


def correlate(events: list[FilterEvent], model: ObjectModel, t: dict) -> list[Alert]:
    alerts: list[Alert] = []
    denies = [e for e in events if e.action in ("block", "reject") and e.time]

    for src, e, win in sliding(denies, t["uc01_window"], lambda e: e.src, t["uc01_zones"],
                               distinct=lambda x: model.zone_of(x.dst)):
        zones = sorted({model.zone_of(x.dst) for x in win})
        alerts.append(Alert("UC-01", "HIGH", e.time, src, f"denied in {len(zones)} zones: {', '.join(zones)}"))

    for e in denies:
        if e.rule_id == "G-03":
            alerts.append(Alert("UC-02", "CRITICAL", e.time, e.src, f"EMR DB {e.dst}:{e.dport} (G-03) - page on-call"))
        if e.rule_id == "X-99":
            alerts.append(Alert("UC-05", "LOW", e.time, e.src, f"final deny hit to {e.dst}:{e.dport} - ticket to network team"))

    dv05 = [e for e in denies if e.rule_id == "DV-05" and model.zone_of(e.dst) == "INTERNET"]
    for src, e, win in sliding(dv05, t["uc03_window"], lambda e: e.src, t["uc03_count"]):
        alerts.append(Alert("UC-03", "HIGH", e.time, src, f"{len(win)} device egress attempts - notify biomed"))

    vw01 = [e for e in denies if e.rule_id == "VW-01"]
    for src, e, win in sliding(vw01, t["uc04_window"], lambda e: e.src, t["uc04_count"]):
        alerts.append(Alert("UC-04", "MEDIUM", e.time, src, f"{len(win)} vendor Wi-Fi attempts on internal ranges"))

    return sorted(alerts, key=lambda a: _naive(a.time))


def main(argv=None) -> int:
    ap = argparse.ArgumentParser(description=__doc__.split("\n")[0])
    ap.add_argument("logfile", nargs="+")
    ap.add_argument("--rules-debug")
    ap.add_argument("--year", type=int)
    ap.add_argument("--lab-thresholds", action="store_true", help="lower counts for a short lab run")
    args = ap.parse_args(argv)

    labels = label_map_from_debug(open(args.rules_debug, encoding="utf-8").read()) if args.rules_debug else {}
    events = []
    for path in args.logfile:
        with open(path, encoding="utf-8", errors="replace") as fh:
            events += list(parse_filterlog(fh, labels, args.year))
    alerts = correlate(events, ObjectModel.load(), LAB if args.lab_thresholds else PROD)
    for a in alerts:
        print(a)
    print(f"\n{len(events)} filterlog events, {len(alerts)} alert(s)")
    return 0


if __name__ == "__main__":
    sys.exit(main())
