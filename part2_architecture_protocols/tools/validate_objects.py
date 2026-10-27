#!/usr/bin/env python3
"""Sanity checks for the network object model (objects.yaml).

  - zone subnets do not overlap and VLAN IDs are unique
  - every gateway is inside its zone subnet
  - every host lies inside the zone it claims to be in
  - no two hosts share an IP address
  - group members and service entries resolve
  - every zone in the model is referenced by at least one rule

Exit code 1 if anything fails.
"""
import ipaddress
import sys

import _path  # noqa: F401
from sjvnet.model import ObjectModel, Service
from sjvnet.policy import Policy


def check(model: ObjectModel) -> list[str]:
    problems = []
    nets = {n: ipaddress.ip_network(z["subnet"]) for n, z in model.zones.items()}
    vlans = {}
    for name, z in model.zones.items():
        if z["vlan"] in vlans:
            problems.append(f"VLAN {z['vlan']} used by {vlans[z['vlan']]} and {name}")
        vlans[z["vlan"]] = name
        if ipaddress.ip_address(z["gateway"]) not in nets[name]:
            problems.append(f"{name}: gateway {z['gateway']} outside {nets[name]}")
    names = list(nets)
    for i, a in enumerate(names):
        for b in names[i + 1:]:
            if nets[a].overlaps(nets[b]):
                problems.append(f"zones {a} and {b} overlap")
    seen = {}
    for h, d in model.hosts.items():
        ip = ipaddress.ip_address(d["ip"])
        if str(ip) in seen:
            problems.append(f"{h} and {seen[str(ip)]} share {ip}")
        seen[str(ip)] = h
        z = d["zone"]
        if z in nets and ip not in nets[z]:
            problems.append(f"{h} ({ip}) is not inside its zone {z} ({nets[z]})")
        is_firewall = "firewall" in d.get("role", "").lower()   # the firewall IS the gateway
        if z in nets and ip == ipaddress.ip_address(model.zones[z]["gateway"]) and not is_firewall:
            problems.append(f"{h} uses the gateway address of {z}")
    for g, members in model.groups.items():
        for m in members:
            if m not in model.names():
                problems.append(f"group {g}: unknown member {m}")
    for s, entries in model.services.items():
        for e in entries:
            try:
                svc = Service.parse(e)
                if svc.proto not in ("tcp", "udp", "icmp") or (svc.port is not None and not 0 < svc.port < 65536):
                    problems.append(f"service {s}: bad entry {e}")
            except ValueError:
                problems.append(f"service {s}: bad entry {e}")
    policy = Policy.load(model=model)
    used = set()
    for r in policy.rules:
        for field in ("src", "dst"):
            spec = r.raw[field]
            if isinstance(spec, dict):
                spec = spec.get("not", []) + [spec.get("zone", "")] + spec.get("except", [])
            used |= set(spec if isinstance(spec, list) else [spec])
    for z in model.zones:
        if z not in used:
            problems.append(f"zone {z} is never referenced by the rule base")
    return problems


def main() -> int:
    model = ObjectModel.load()
    problems = check(model)
    print(f"{len(model.zones)} zones, {len(model.hosts)} hosts, {len(model.groups)} groups, {len(model.services)} services")
    for p in problems:
        print("  FAIL", p)
    print("object model OK" if not problems else f"{len(problems)} problem(s)")
    return 1 if problems else 0


if __name__ == "__main__":
    sys.exit(main())
