#!/usr/bin/env python3
"""Load the lab rule set (opnsense/lab_rules.yaml) into OPNsense via its REST API.

Why: typing 18 rules and 9 aliases into the GUI by hand is where mistakes
creep in (wrong order, a missing "log" tick). Loading from the same files
the report is built from keeps the lab identical to Table 11.1.

Safety
  * Dry run is the DEFAULT. Nothing is sent unless --apply is given.
  * Rules are applied with a savepoint. If the new rules cut off the API
    session, OPNsense rolls back automatically after 60 seconds unless
    this script confirms (cancelRollback) that it can still reach the box.
  * Lab only. Never point this at a production firewall.

API notes (OPNsense 24.x / 25.x)
  * Create an API key under System > Access > Users > (user) > API keys.
    Export OPN_KEY and OPN_SECRET, or pass --key-file with the downloaded
    apikey.txt.
  * Rules created through /api/firewall/filter appear under
    Firewall > Automation > Filter and are evaluated BEFORE the
    per-interface rules in the GUI. Keep the GUI interface tabs empty
    in the lab so there is one place to look.

Usage
  python3 opnsense_load.py                         # dry run: print payloads
  python3 opnsense_load.py --apply --host 192.168.90.1 --ca opnsense-ca.pem
  python3 opnsense_load.py --apply --setup-mode on  # temporary egress for apk
  python3 opnsense_load.py --apply --setup-mode off
  python3 opnsense_load.py --apply --purge          # delete rules this tool made
"""
from __future__ import annotations

import argparse
import json
import os
import sys
from pathlib import Path

import yaml

import _path  # noqa: F401
from sjvnet.model import ObjectModel

HERE = Path(__file__).resolve().parent
LAB_FILE = HERE.parent / "opnsense" / "lab_rules.yaml"
MARKER = "[cs07]"   # prefix on every description we create, so --purge is safe


# --------------------------------------------------------------- payloads
def alias_payloads(lab: dict, model: ObjectModel) -> list[dict]:
    out = []
    for name in lab["aliases"].get("hosts", []):
        out.append({"name": name, "type": "host", "content": str(model.hosts[name]["ip"]),
                    "description": f"{MARKER} {model.hosts[name]['role']}"})
    for name in lab["aliases"].get("networks", []):
        out.append({"name": name, "type": "network", "content": "\n".join(model.networks[name]),
                    "description": f"{MARKER} network object {name}"})
    for name in lab["aliases"].get("ports", []):
        ports = [s.split("/")[1] for s in model.services[name]]
        out.append({"name": name, "type": "port", "content": "\n".join(sorted(set(ports))),
                    "description": f"{MARKER} service {name}"})
    for a in out:
        a["enabled"] = "1"
    return out


def _addr(text: str, ifaces: dict) -> str:
    """Translate lab notation into what the OPNsense filter API expects."""
    text = str(text)
    if text.endswith(" net"):
        return ifaces[text[:-4]]["opnsense_id"]       # e.g. "opt3" means "RADIOLOGY net"
    if text == "(self)":
        return "(self)"
    return text                                       # alias name, address or "any"


def rule_payload(rule: dict, ifaces: dict, seq: int, descr: str) -> dict:
    proto = rule.get("proto", "any")
    p = {
        "enabled": "1",
        "sequence": str(seq),
        "action": rule["action"],
        "quick": "1",
        "interface": ifaces[rule["iface"]]["opnsense_id"],
        "direction": "in",
        "ipprotocol": "inet",
        "protocol": proto,
        "source_net": _addr(rule["src"], ifaces),
        "destination_net": _addr(rule["dst"], ifaces),
        "destination_not": "1" if rule.get("not") else "0",
        "log": "1",
        "description": descr,
    }
    if "port" in rule and proto != "any":
        p["destination_port"] = str(rule["port"])
    return p


def lab_rule_payloads(lab: dict) -> list[dict]:
    ifaces = lab["interfaces"]
    return [rule_payload(r, ifaces, 100 + 10 * i, f"{MARKER} {r['descr']}")
            for i, r in enumerate(lab["rules"])]


def setup_rule_payloads(lab: dict) -> list[dict]:
    ifaces, tag = lab["interfaces"], lab["setup_mode"]["tag"]
    return [rule_payload(r, ifaces, 10 + i, f"{MARKER} {tag} {r['iface']} temporary egress")
            for i, r in enumerate(lab["setup_mode"]["rules"])]


# ------------------------------------------------------------------ client
class OPNsense:
    def __init__(self, host: str, key: str, secret: str, verify):
        import requests  # imported here so dry runs need no extra package
        self.base = f"https://{host}/api"
        self.s = requests.Session()
        self.s.auth = (key, secret)
        self.s.verify = verify

    def get(self, path: str) -> dict:
        r = self.s.get(f"{self.base}/{path}", timeout=15)
        r.raise_for_status()
        return r.json()

    def post(self, path: str, body: dict | None = None) -> dict:
        r = self.s.post(f"{self.base}/{path}", json=body or {}, timeout=30)
        r.raise_for_status()
        data = r.json()
        if isinstance(data, dict) and data.get("result") == "failed":
            raise RuntimeError(f"{path}: {json.dumps(data.get('validations', data))}")
        return data

    # aliases ---------------------------------------------------------
    def upsert_alias(self, alias: dict) -> str:
        uuid = self.get(f"firewall/alias/getAliasUUID/{alias['name']}").get("uuid")
        if uuid:
            self.post(f"firewall/alias/setItem/{uuid}", {"alias": alias})
            return "updated"
        self.post("firewall/alias/addItem", {"alias": alias})
        return "added"

    # rules -----------------------------------------------------------
    def our_rules(self, contains: str = MARKER) -> list[dict]:
        rows = self.post("firewall/filter/searchRule", {"current": 1, "rowCount": -1,
                                                        "searchPhrase": contains}).get("rows", [])
        return [r for r in rows if contains in r.get("description", "")]

    def add_rule(self, rule: dict) -> None:
        self.post("firewall/filter/addRule", {"rule": rule})

    def del_rule(self, uuid: str) -> None:
        self.post(f"firewall/filter/delRule/{uuid}")

    def apply_with_rollback(self) -> None:
        rev = self.post("firewall/filter/savepoint")["revision"]
        self.post(f"firewall/filter/apply/{rev}")
        # If we can still talk to the API, the new rules did not lock us out.
        self.post(f"firewall/filter/cancelRollback/{rev}")
        print(f"[+] applied (savepoint {rev} confirmed)")


# -------------------------------------------------------------------- main
def credentials(args) -> tuple[str, str]:
    if args.key_file:
        vals = dict(line.strip().split("=", 1) for line in open(args.key_file) if "=" in line)
        return vals["key"], vals["secret"]
    key, secret = os.environ.get("OPN_KEY"), os.environ.get("OPN_SECRET")
    if not (key and secret):
        sys.exit("set OPN_KEY and OPN_SECRET, or pass --key-file apikey.txt")
    return key, secret


def main(argv=None) -> int:
    ap = argparse.ArgumentParser(description=__doc__.split("\n")[0])
    ap.add_argument("--lab-file", default=LAB_FILE)
    ap.add_argument("--host", default="192.168.90.1")
    ap.add_argument("--key-file")
    ap.add_argument("--ca", help="PEM of the OPNsense web GUI CA (System > Trust)")
    ap.add_argument("--insecure", action="store_true", help="skip TLS verification (isolated lab only)")
    ap.add_argument("--apply", action="store_true", help="actually talk to the firewall")
    group = ap.add_mutually_exclusive_group()
    group.add_argument("--setup-mode", choices=["on", "off"])
    group.add_argument("--purge", action="store_true", help="delete every rule created by this tool")
    args = ap.parse_args(argv)

    lab = yaml.safe_load(open(args.lab_file, encoding="utf-8"))
    model = ObjectModel.load()
    aliases = alias_payloads(lab, model)
    rules = setup_rule_payloads(lab) if args.setup_mode == "on" else lab_rule_payloads(lab)

    if not args.apply:
        print("# DRY RUN - nothing sent. Add --apply to load.\n")
        if args.setup_mode == "off" or args.purge:
            print("# would delete rules whose description contains",
                  lab["setup_mode"]["tag"] if args.setup_mode else MARKER)
            return 0
        if not args.setup_mode:
            print(json.dumps({"aliases": aliases}, indent=2))
        print(json.dumps({"rules": rules}, indent=2))
        print(f"\n# {len(aliases)} aliases, {len(rules)} rules")
        return 0

    verify = False if args.insecure else (args.ca or True)
    fw = OPNsense(args.host, *credentials(args), verify)

    if args.purge or args.setup_mode == "off":
        tag = MARKER if args.purge else lab["setup_mode"]["tag"]
        found = fw.our_rules(tag)
        for r in found:
            fw.del_rule(r["uuid"])
        print(f"[+] deleted {len(found)} rule(s) tagged '{tag}'")
        fw.apply_with_rollback()
        return 0

    if not args.setup_mode:
        for a in aliases:
            print(f"[+] alias {a['name']}: {fw.upsert_alias(a)}")
        fw.post("firewall/alias/reconfigure")
        existing = fw.our_rules()
        if existing:
            sys.exit(f"{len(existing)} rule(s) from an earlier load exist; run --purge first")

    for r in rules:
        fw.add_rule(r)
        print(f"[+] rule {r['interface']:5} {r['action']:5} {r['description']}")
    fw.apply_with_rollback()
    if args.setup_mode == "on":
        print("[!] setup mode is ON. Turn it off before running any experiment.")
    return 0


if __name__ == "__main__":
    sys.exit(main())
