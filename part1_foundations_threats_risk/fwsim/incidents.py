"""Replay the case-study incidents through the OLD and the NEW design.

Old design: one stateless filter at the internet edge. Flows between two
internal hosts never reach it (flat network), so they are "not inspected".
New design: every inter-zone flow crosses the stateful NGFW with the
60-rule policy.

Run:  python3 -m fwsim incidents
"""
from __future__ import annotations

from dataclasses import dataclass

from sjvnet import LEGACY_POLICY_FILE
from sjvnet.model import ObjectModel
from sjvnet.policy import Packet, Policy

from .engines import StatefulFirewall, StatelessFilter


@dataclass
class Case:
    ref: str
    text: str
    pkt: Packet
    expect_new: str     # what the redesign must do
    expect_rule: str | None = None
    crosses_firewall: bool = True


CASES = [
    Case("F1", "Rogue laptop on device port -> pump web UI", Packet("192.168.30.200", "192.168.30.10", "tcp", 80), "deny", crosses_firewall=False),
    Case("F1", "Rogue laptop on device port -> EMR database", Packet("192.168.30.200", "192.168.10.20", "tcp", 1433), "deny", "G-03"),
    Case("F2", "Radiology workstation -> EMR SQL 1433", Packet("192.168.40.100", "192.168.10.20", "tcp", 1433), "deny", "G-03"),
    Case("F2", "PACS broker -> interface engine MLLP", Packet("192.168.40.12", "192.168.10.40", "tcp", 2575, app="hl7"), "permit", "R-02"),
    Case("F2", "Reading workstation -> interface engine MLLP", Packet("192.168.40.100", "192.168.10.40", "tcp", 2575), "deny", "R-06"),
    Case("F3", "Vendor laptop -> nurse PC SMB", Packet("10.61.0.50", "192.168.50.25", "tcp", 445), "deny", "VW-01"),
    Case("F3", "Vendor laptop -> EMR database", Packet("10.61.0.50", "192.168.10.20", "tcp", 1433), "deny", "G-03"),
    Case("F3", "Vendor laptop -> internet HTTPS", Packet("10.61.0.50", "93.184.216.34", "tcp", 443), "permit", "VW-02"),
    Case("R3", "Pump -> internet (botnet C2)", Packet("192.168.30.10", "198.18.0.66", "tcp", 443), "deny", "DV-05"),
    Case("R3", "Pump -> interface engine MLLP", Packet("192.168.30.10", "192.168.10.40", "tcp", 2575, app="hl7"), "permit", "DV-03"),
    Case("R3", "Pump -> DNS over TCP (large answer)", Packet("192.168.30.10", "192.168.10.53", "tcp", 53), "permit", "DV-01"),
    Case("R5", "Guest phone -> nurse PC", Packet("10.60.1.20", "192.168.50.25", "tcp", 3389), "deny", "GW-01"),
    Case("R6", "Research host -> EMR app", Packet("192.168.70.15", "192.168.10.21", "tcp", 443), "deny", "RS-03"),
    Case("R10", "Nurse PC -> EMR app (clinician)", Packet("192.168.50.25", "192.168.10.21", "tcp", 443, user_groups=("GRP_CLINICIANS",), app="emr-web"), "permit", "C-02"),
    Case("R10", "Nurse PC -> EMR server RDP (ransomware spread)", Packet("192.168.50.25", "192.168.10.21", "tcp", 3389), "deny", "C-08"),
    Case("R11", "Nurse PC -> firewall GUI", Packet("192.168.50.25", "192.168.90.1", "tcp", 443), "deny", "G-02"),
    Case("D-01", "Internet -> portal /admin/", Packet("198.18.0.66", "192.168.20.10", "tcp", 443, url_path="/admin/login"), "deny", "D-01"),
    Case("D-02", "Internet -> portal /portal/", Packet("198.18.0.66", "192.168.20.10", "tcp", 443, url_path="/portal/appointments"), "permit", "D-02"),
]


def legacy_verdict(model: ObjectModel, legacy: StatelessFilter, p: Packet) -> str:
    src_internal = model.zone_of(p.src) != "INTERNET"
    dst_internal = model.zone_of(p.dst) != "INTERNET"
    if src_internal and dst_internal:
        return "permit (flat network, never inspected)"
    d = legacy.process(p)
    return f"{d.action} ({d.rule.id if d.rule else 'implicit'})"


def run(verbose: bool = True) -> list[tuple]:
    model = ObjectModel.load()
    legacy = StatelessFilter(Policy.load(LEGACY_POLICY_FILE, model))
    new = Policy.load(model=model)
    rows = []
    if verbose:
        print(f"{'ref':5} {'scenario':48} {'OLD design':40} {'NEW design':26} check")
    for c in CASES:
        old = legacy_verdict(model, legacy, c.pkt)
        if c.crosses_firewall:
            fw = StatefulFirewall(new, ngfw=True)
            d = fw.process(c.pkt)
            action = d.action
            rid = d.rule.id if d.rule else "-"
            ok = action == c.expect_new and (c.expect_rule is None or rid == c.expect_rule)
        else:
            # Peers on the same VLAN switch directly. The firewall's DV-04
            # cannot enforce this case; access-port admission and PVLANs must.
            action, rid, ok = "not tested", "access layer", None
        rows.append((c.ref, c.text, old, action, rid, ok))
        if verbose:
            verdict = "N/A" if ok is None else ("OK" if ok else "MISMATCH")
            print(f"{c.ref:5} {c.text:48} {old:40} {action + ' ' + rid:26} {verdict}")
    if verbose:
        checked = [r for r in rows if r[-1] is not None]
        bad = [r for r in checked if not r[-1]]
        print(f"\n{len(checked) - len(bad)}/{len(checked)} firewall-path cases behave as the design intends; "
              f"{len(rows) - len(checked)} same-VLAN case requires access-layer verification.")
    return rows
