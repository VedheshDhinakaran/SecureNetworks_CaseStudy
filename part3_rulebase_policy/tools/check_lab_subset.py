#!/usr/bin/env python3
"""Check that the lab rule set is a faithful subset of the production rule base.

For every lab rule (opnsense/lab_rules.yaml) we build one probe packet that
the lab rule is meant to match, run it through the production policy
(rulebase/policy.yaml) and compare the decisions:

  OK      same action as production
  BROAD   lab rule is knowingly wider than production (marked `broader:`)
  LAB     rule exists only for the lab (marked `lab_only:`), not compared
  FAIL    lab and production disagree -> the lab would prove the wrong thing

Exit code 1 if any FAIL.
"""
from __future__ import annotations

import ipaddress
import sys
from pathlib import Path

import yaml

import _path  # noqa: F401
from sjvnet.model import ObjectModel
from sjvnet.policy import Packet, Policy

LAB_FILE = Path(__file__).resolve().parent.parent / "opnsense" / "lab_rules.yaml"
INTERNET_PROBE = "8.8.8.8"
INTERNAL_PROBE = "192.168.10.21"   # EMR app: the most valuable internal target


def probe_ip(text: str, model: ObjectModel, ifaces: dict, negated: bool = False) -> str:
    text = str(text)
    if negated:
        return INTERNET_PROBE                       # "! N_RFC1918" -> somewhere on the internet
    if text.endswith(" net"):
        net = ipaddress.ip_network(ifaces[text[:-4]]["subnet"])
        return str(net.network_address + 100)      # a workstation-like address in the zone
    if text == "any":
        return INTERNET_PROBE
    if text in model.hosts:
        return str(model.hosts[text]["ip"])
    if text in model.networks:
        return INTERNAL_PROBE
    return text                                     # literal address


def probe_port(rule: dict, model: ObjectModel) -> tuple[str, int | None]:
    proto = rule.get("proto", "any")
    proto = "udp" if proto == "UDP" else "tcp"
    port = rule.get("port")
    if port is None:
        return proto, 445   # SMB: never permitted anywhere, so it exercises the deny
    port = str(port).split(",")[-1]
    if port in model.services:
        return model.services[port][0].split("/")[0], int(model.services[port][0].split("/")[1])
    return proto, int(port)


def main() -> int:
    lab = yaml.safe_load(open(LAB_FILE, encoding="utf-8"))
    model = ObjectModel.load()
    policy = Policy.load(model=model)
    ifaces = lab["interfaces"]
    fails = 0
    print(f"{'lab rule':28} {'probe':48} {'lab':6} {'prod':6} {'prod rule':9} result")
    for r in lab["rules"]:
        if r.get("lab_only"):
            print(f"{r['descr'][:28]:28} {'(not compared)':48} {r['action']:6} {'-':6} {'-':9} LAB")
            continue
        src = probe_ip(r["src"], model, ifaces)
        dst = probe_ip(r["dst"], model, ifaces, r.get("not", False))
        proto, port = probe_port(r, model)
        pkt = Packet(src, dst, proto, port)
        lab_action = "permit" if r["action"] == "pass" else "deny"
        d = policy.evaluate(pkt, ngfw=False)
        if d.action == lab_action:
            result = "OK"
        elif r.get("broader"):
            result = "BROAD (" + r["broader"] + ")"
        else:
            result = "FAIL"
            fails += 1
        rid = d.rule.id if d.rule else "-"
        print(f"{r['descr'][:28]:28} {str(pkt)[:48]:48} {lab_action:6} {d.action:6} {rid:9} {result}")
    print(f"\n{len(lab['rules'])} lab rules checked, {fails} failure(s)")
    return 1 if fails else 0


if __name__ == "__main__":
    sys.exit(main())
