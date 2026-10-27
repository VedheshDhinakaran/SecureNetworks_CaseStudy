#!/usr/bin/env python3
"""Generate documentation from objects.yaml so the report tables never drift.

Writes into ../docs/:
  ip_plan.md        zone, VLAN, subnet and gateway table + named hosts
  architecture.dot  Graphviz diagram of zones and firewall tiers
                    (render with:  dot -Tpng architecture.dot -o architecture.png)
"""
from pathlib import Path

import _path  # noqa: F401
from sjvnet.model import ObjectModel

OUT = Path(__file__).resolve().parents[1] / "docs"

TIER = {"Z_DMZ": "edge", "Z_VENDOR_MAINT": "edge"}
COLOUR = {"high": "#E7F1FB", "highest": "#E5F4E4", "medium": "#E7F1FB", "low": "#F9ECE7",
          "restricted": "#F9ECE7", "untrusted": "#FBEBEB"}


def ip_plan(model: ObjectModel) -> str:
    lines = ["# VLAN and IP plan", "", "Generated from `network/objects.yaml`. `*` = address from the case brief.", "",
             "| Zone | VLAN | Subnet | Gateway | Trust | Owner |", "|---|---|---|---|---|---|"]
    for n, z in model.zones.items():
        star = "*" if z.get("brief") else ""
        lines.append(f"| {n} | {z['vlan']} | {z['subnet']}{star} | {z['gateway']} | {z['trust']} | {z['owner']} |")
    lines += ["| QUARANTINE | 999 | none | none | none | Network team |", "", "## Named hosts", "",
              "| Object | Address | Zone | Role |", "|---|---|---|---|"]
    for n, h in model.hosts.items():
        lines.append(f"| {n} | {h['ip']}{'*' if h.get('brief') else ''} | {h['zone']} | {h['role']} |")
    return "\n".join(lines) + "\n"


def dot(model: ObjectModel) -> str:
    out = ["digraph sjv {", '  rankdir=TB; node [shape=box, style="rounded,filled", fontname="Helvetica", fontsize=10];',
           '  internet [label="Internet", shape=ellipse, fillcolor="#F2F2F2"];',
           '  dr [label="DR site\\n10.200.0.0/24", shape=ellipse, fillcolor="#F2F2F2"];',
           '  edge [label="Edge NGFW HA pair\\nIPS, URL, TLS inspection, NAT, IPsec", fillcolor="#FFF4D6"];',
           '  isfw [label="Internal segmentation NGFW HA pair\\ngateway of every internal zone", fillcolor="#FFF4D6"];',
           "  internet -> edge; dr -> edge [style=dashed, label=IPsec]; edge -> isfw [label=transit];"]
    for n, z in model.zones.items():
        label = f"{n}\\nVLAN {z['vlan']}  {z['subnet']}"
        out.append(f'  {n} [label="{label}", fillcolor="{COLOUR.get(z["trust"], "#FFFFFF")}"];')
        parent = "edge" if TIER.get(n) == "edge" else "isfw"
        out.append(f"  {parent} -> {n};")
    out.append('  quarantine [label="QUARANTINE VLAN 999\\nno route", style="dashed,rounded"];')
    out.append("}")
    return "\n".join(out) + "\n"


def main():
    model = ObjectModel.load()
    OUT.mkdir(exist_ok=True)
    (OUT / "ip_plan.md").write_text(ip_plan(model), encoding="utf-8")
    (OUT / "architecture.dot").write_text(dot(model), encoding="utf-8")
    print(f"wrote {OUT / 'ip_plan.md'} and {OUT / 'architecture.dot'}")


if __name__ == "__main__":
    main()
