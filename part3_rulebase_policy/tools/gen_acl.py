#!/usr/bin/env python3
"""Render the rule base (policy.yaml) into reviewable and loadable forms.

Formats
  csv    one row per rule, same columns as report Table 8.2 (rulebase.csv)
  md     Markdown table for the wiki / change ticket
  pf     pf.conf-style tables and rules, so the reader can see what a
         pf-based firewall (OPNsense, pfSense, OpenBSD) actually enforces
  flat   every rule expanded to (src net, dst net, proto, port) tuples;
         useful to show how much one "simple" object-based rule expands to

NGFW-only fields (app, user, url_path, ips, profiles, tls_inspect) have no
pf equivalent. In pf output they are written as comments, because they are
enforced by Suricata / Zenarmor, not by the packet filter.

Usage:
  python3 gen_acl.py --format csv  > ../rulebase/rulebase.csv
  python3 gen_acl.py --format pf   > ../generated/sanjivani.pf
  python3 gen_acl.py --format md --section devices
"""
from __future__ import annotations

import argparse
import csv
import io
import sys

import yaml

import _path  # noqa: F401
from sjvnet import POLICY_FILE
from sjvnet.model import ObjectModel
from sjvnet.policy import Policy, Rule

NGFW_FIELDS = ("app", "app_block", "user", "url_path", "url_category", "ips", "profiles", "tls_inspect", "schedule", "shaper")
SECTION_TITLES = {
    "global": "Section 0 - Global protections",
    "mgmt": "Section 1 - MGMT",
    "his": "Section 2 - HIS",
    "dmz": "Section 3 - DMZ (outbound)",
    "inbound": "Section 3b - Inbound from internet",
    "devices": "Section 4 - DEVICES",
    "radiology": "Section 5 - RADIOLOGY",
    "clinical": "Section 6 - CLINICAL",
    "guest": "Section 7 - GUEST",
    "vendor_wifi": "Section 8 - VENDOR-WIFI",
    "research": "Section 9 - RESEARCH",
    "vendor_maint": "Section 10 - VENDOR-MAINT",
    "final": "Section 11 - Final deny",
}


# ------------------------------------------------------------- helpers
def addr_text(spec) -> str:
    """Human form of a src/dst field, as written in the report."""
    if isinstance(spec, dict) and "not" in spec:
        return "any except " + ", ".join(spec["not"])
    if isinstance(spec, dict) and "zone" in spec:
        exc = spec.get("except", [])
        return spec["zone"] + (" except " + ", ".join(exc) if exc else "")
    if isinstance(spec, list):
        return ", ".join(spec)
    return str(spec)


def svc_text(spec) -> str:
    if isinstance(spec, list):
        return ", ".join(spec)
    return str(spec or "any")


def ngfw_text(raw: dict) -> str:
    parts = []
    for key in NGFW_FIELDS:
        if key in raw:
            val = raw[key]
            val = ",".join(map(str, val)) if isinstance(val, list) else val
            parts.append(f"{key}={val}")
    return "; ".join(parts)


def load(path) -> tuple[Policy, dict]:
    with open(path, encoding="utf-8") as fh:
        data = yaml.safe_load(fh)
    model = ObjectModel.load()
    # simulate=False: FQDN and dynamic objects stay symbolic, as on a real box
    return Policy.from_dict(data, model, simulate=False, name=str(path)), data


# ---------------------------------------------------------------- csv/md
COLUMNS = ["section", "id", "source", "destination", "service", "action", "log",
           "owner", "requirement", "review", "ngfw_controls", "enabled"]


def rows(policy: Policy):
    for r in policy.rules:
        raw = r.raw
        src = addr_text(raw["src"])
        if raw.get("user"):
            src += f" (user group {raw['user']})"
        yield {
            "section": SECTION_TITLES.get(r.section, r.section),
            "id": r.id,
            "source": src,
            "destination": addr_text(raw["dst"]),
            "service": svc_text(raw.get("svc", "any")),
            "action": r.action,
            "log": {"yes": "Y", "alert": "A", "no": "N"}.get(r.log, r.log),
            "owner": r.owner,
            "requirement": r.req,
            "review": r.review,
            "ngfw_controls": ngfw_text(raw),
            "enabled": "yes" if r.enabled else "no (template)",
        }


def render_csv(policy: Policy) -> str:
    buf = io.StringIO()
    w = csv.DictWriter(buf, fieldnames=COLUMNS, lineterminator="\n")
    w.writeheader()
    for row in rows(policy):
        w.writerow(row)
    return buf.getvalue()


def render_md(policy: Policy) -> str:
    out, current = [], None
    for row in rows(policy):
        if row["section"] != current:
            current = row["section"]
            out += ["", f"### {current}", "",
                    "| ID | Source | Destination | Service | Action | Log | Owner | Requirement |",
                    "|---|---|---|---|---|---|---|---|"]
        cells = [row[k].replace("|", "\\|") for k in
                 ("id", "source", "destination", "service", "action", "log", "owner", "requirement")]
        out.append("| " + " | ".join(cells) + " |")
    return "\n".join(out).lstrip() + "\n"


# -------------------------------------------------------------------- pf
def _rel(path: str) -> str:
    """Path relative to the repository root, so generated files are portable."""
    from pathlib import Path
    root = Path(__file__).resolve().parents[2]
    try:
        return str(Path(path).resolve().relative_to(root))
    except ValueError:
        return str(path)


def _table_name(spec) -> str:
    if isinstance(spec, list):
        return "T_" + "_".join(s.replace("Z_", "").replace("H_", "") for s in spec)[:40]
    if isinstance(spec, dict) and "not" in spec:
        return "NOT_" + "_".join(s.replace("Z_", "").replace("H_", "") for s in spec["not"])[:40]
    if isinstance(spec, dict) and "zone" in spec:
        return spec["zone"] + "_EXCEPT"
    return str(spec)


def _pf_entries(addrset) -> list[str]:
    return [str(n) for n in addrset.include] + [f"!{n}" for n in addrset.exclude]


def _pf_ports(services) -> dict:
    """{proto: [ports]}; empty port list means 'all ports'. None means any proto."""
    if services is None:
        return {None: []}
    by_proto: dict = {}
    for s in sorted(services, key=lambda s: (s.proto, s.port or 0)):
        by_proto.setdefault(s.proto, [])
        if s.port is not None:
            by_proto[s.proto].append(s.port)
    return by_proto


def render_pf(policy: Policy) -> str:
    tables: dict[str, list[str]] = {}
    lines: list[str] = []

    def ref(spec, addrset) -> str:
        if spec == "any":
            return "any"
        name = _table_name(spec)
        entries = _pf_entries(addrset)
        if not entries:
            # FQDN / dynamic object: filled at run time by the firewall
            tables.setdefault(name, ["# resolved at run time (FQDN or dynamic alias)"])
        else:
            tables.setdefault(name, entries)
        return f"<{name}>"

    for r in policy.rules:
        raw = r.raw
        verb = "pass" if r.is_permit else "block"
        logk = " log" if r.log in ("yes", "alert") else ""
        src = ref(raw["src"], r.src)
        dst = ref(raw["dst"], r.dst)
        extra = ngfw_text(raw)
        lines.append(f"# {r.id}  {r.req}  [owner {r.owner}, review {r.review}]")
        if extra:
            lines.append(f"#   NGFW layer (Suricata/Zenarmor, not pf): {extra}")
        prefix = "# DISABLED (template) " if not r.enabled else ""
        if r.services is not None and not r.services:
            # service is a run-time object (e.g. TICKET_PORT): filled in per change ticket
            lines.append(f'{prefix}{verb} in quick{logk} from {src} to {dst} port <set per ticket> label "{r.id}"')
        for proto, ports in _pf_ports(r.services).items():
            ptxt = f" proto {proto}" if proto else ""
            port = ""
            if ports:
                port = f" port {ports[0]}" if len(ports) == 1 else " port { " + " ".join(map(str, ports)) + " }"
            state = " keep state" if r.is_permit else ""
            lines.append(f'{prefix}{verb} in quick{logk}{ptxt} from {src} to {dst}{port}{state} label "{r.id}"')
        lines.append("")

    head = [
        "# =================================================================",
        "#  Sanjivani NGFW rule base rendered as pf.conf (GENERATED - do not edit)",
        f"#  Source: {_rel(policy.name)}",
        "#  Regenerate with: python3 part3_rulebase_policy/tools/gen_acl.py --format pf",
        "#  This is a reading aid. OPNsense rules are loaded through its API",
        "#  (opnsense_load.py), not by pasting this file.",
        "# =================================================================",
        "",
    ]
    tdefs = []
    for name, entries in tables.items():
        if entries and entries[0].startswith("#"):
            tdefs.append(f"table <{name}> persist  {entries[0]}")
        else:
            tdefs.append(f"table <{name}> const {{ {' '.join(entries)} }}")
    return "\n".join(head + tdefs + [""] + lines)


# ------------------------------------------------------------------ flat
def render_flat(policy: Policy) -> str:
    out = ["id,action,src,dst,proto,port"]
    total = 0
    for r in policy.rules:
        for s_net in r.src.include or ["<runtime>"]:
            for d_net in r.dst.include or ["<runtime>"]:
                for proto, ports in _pf_ports(r.services).items():
                    for port in ports or ["any"]:
                        out.append(f"{r.id},{r.action},{s_net},{d_net},{proto or 'any'},{port}")
                        total += 1
    out.append(f"# {len(policy.rules)} rules expand to {total} address/port tuples "
               f"(exclusions not expanded)")
    return "\n".join(out) + "\n"


RENDERERS = {"csv": render_csv, "md": render_md, "pf": render_pf, "flat": render_flat}


def main(argv=None) -> int:
    ap = argparse.ArgumentParser(description=__doc__.split("\n")[0])
    ap.add_argument("policy", nargs="?", default=POLICY_FILE)
    ap.add_argument("--format", choices=sorted(RENDERERS), default="csv")
    ap.add_argument("--section", help="only rules from this section (e.g. devices)")
    ap.add_argument("-o", "--output", help="write to file instead of stdout")
    args = ap.parse_args(argv)

    policy, _ = load(args.policy)
    if args.section:
        policy.rules = [r for r in policy.rules if r.section == args.section]
        if not policy.rules:
            print(f"no rules in section '{args.section}'", file=sys.stderr)
            return 1
    text = RENDERERS[args.format](policy)
    if args.output:
        with open(args.output, "w", encoding="utf-8") as fh:
            fh.write(text)
    else:
        sys.stdout.write(text)
    return 0


if __name__ == "__main__":
    sys.exit(main())
