"""Parsers for OPNsense output: filterlog lines and rules.debug label maps.

filterlog is OPNsense's packet-filter log. Each entry is a CSV payload
inside a syslog line, e.g. (RFC 5424, as sent to a remote collector):

  <134>1 2026-01-01T10:00:00+05:30 fw.sjv.lab filterlog 4242 - [meta sequenceId="7"] 82,,,<label>,em4,match,block,in,4,0x0,,64,...

or (BSD syslog, older releases / local clog):

  Jan  1 10:00:00 fw filterlog[4242]: 82,,,<label>,em4,match,block,in,4,...

Field order follows the OPNsense filterlog format documentation:
common fields, then IPv4 or IPv6 fields, then protocol fields.
"""
from __future__ import annotations

import re
from dataclasses import dataclass
from datetime import datetime
from typing import Iterable, Iterator, Optional

# Locate the CSV payload: rulenr,subrulenr,anchor,label,iface,reason,action,dir,
PAYLOAD_RE = re.compile(r"(?P<csv>\d+,\d*,[^,]*,[^,]*,[\w.]+,[\w-]+,(?:pass|block|reject),(?:in|out),[46],.*)$")
ISO_TS_RE = re.compile(r"(\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(?:\.\d+)?(?:Z|[+-]\d{2}:\d{2})?)")
BSD_TS_RE = re.compile(r"^([A-Z][a-z]{2}\s+\d{1,2}\s+\d{2}:\d{2}:\d{2})")
DEBUG_RE = re.compile(r'label\s+"(?P<label>[^"]+)"\s*#\s*(?P<descr>.*)$')
RULE_ID_RE = re.compile(r"\b([A-Z]{1,2}-\d{2})\b")   # G-03, DV-01, VW-02, X-99 ...


@dataclass
class FilterEvent:
    time: Optional[datetime]
    rule_number: int
    label: str
    interface: str
    action: str
    direction: str
    proto: str
    src: str
    dst: str
    sport: Optional[int] = None
    dport: Optional[int] = None
    tcp_flags: str = ""
    rule_id: str = ""          # filled from the label map, e.g. "G-03"
    raw: str = ""


def _int(text: str) -> Optional[int]:
    try:
        return int(text)
    except (TypeError, ValueError):
        return None


def parse_time(line: str, year: Optional[int] = None) -> Optional[datetime]:
    m = ISO_TS_RE.search(line)
    if m:
        return datetime.fromisoformat(m.group(1).replace("Z", "+00:00"))
    m = BSD_TS_RE.search(line)
    if m:
        year = year or datetime.now().year
        return datetime.strptime(f"{year} {m.group(1)}", "%Y %b %d %H:%M:%S")
    return None


def parse_filterlog_line(line: str, year: Optional[int] = None) -> Optional[FilterEvent]:
    if "filterlog" not in line:
        return None
    m = PAYLOAD_RE.search(line.rstrip())
    if not m:
        return None
    f = m.group("csv").split(",")
    ev = FilterEvent(time=parse_time(line, year), rule_number=int(f[0]), label=f[3], interface=f[4],
                     action=f[6], direction=f[7], proto="", src="", dst="", raw=line.rstrip())
    if f[8] == "4" and len(f) >= 20:
        ev.proto, ev.src, ev.dst = f[16].lower(), f[18], f[19]
        rest = f[20:]
    elif f[8] == "6" and len(f) >= 17:
        ev.proto, ev.src, ev.dst = f[12].lower(), f[15], f[16]
        rest = f[17:]
    else:
        return ev
    if ev.proto in ("tcp", "udp") and len(rest) >= 2:
        ev.sport, ev.dport = _int(rest[0]), _int(rest[1])
        if ev.proto == "tcp" and len(rest) >= 4:
            ev.tcp_flags = rest[3]
    return ev


def parse_filterlog(lines: Iterable[str], labels: Optional[dict] = None,
                    year: Optional[int] = None) -> Iterator[FilterEvent]:
    labels = labels or {}
    for line in lines:
        if line.lstrip().startswith("#"):
            continue
        ev = parse_filterlog_line(line, year)
        if ev is None:
            continue
        ev.rule_id = labels.get(ev.label) or (ev.label if RULE_ID_RE.fullmatch(ev.label) else "")
        yield ev


def label_map_from_debug(text: str) -> dict:
    """Map pf label hash -> our rule ID, using /tmp/rules.debug from OPNsense.

    Our rule descriptions start with the rule ID ("[cs07] DV-01 DNS"), so the
    first rule-ID-shaped token in the trailing comment is the ID.
    """
    mapping = {}
    for line in text.splitlines():
        m = DEBUG_RE.search(line)
        if m:
            rid = RULE_ID_RE.search(m.group("descr"))
            if rid:
                mapping[m.group("label")] = rid.group(1)
    return mapping
