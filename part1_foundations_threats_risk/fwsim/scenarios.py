"""Scenarios for the five failures of stateless filtering, App-ID and rule order.

Each scenario returns a list of (step, stateless_result, stateful_result)
lines and prints them as a table. Run:  python3 -m fwsim scenarios
"""
from __future__ import annotations

from sjvnet.model import ObjectModel
from sjvnet.policy import Packet, Policy

from .engines import StatefulFirewall, StatelessFilter
from .nat import PatTable

NURSE_PC = "192.168.50.25"
EMR_APP = "192.168.10.21"
EMR_DB = "192.168.10.20"
RAD_WS = "192.168.40.100"
VENDOR_LAPTOP = "10.61.0.50"
ATTACKER = "198.18.0.66"   # RFC 2544 benchmark range used as "somewhere on the internet"


def _policy(rules: list, model: ObjectModel) -> Policy:
    return Policy.from_dict({"defaults": {"log": "yes", "review": "Q"}, "rules": rules}, model)


def _by(d) -> str:
    if d.rule:
        return d.rule.id
    return "(state table)" if d.action == "permit" else "(no state)"


def _run(title: str, steps: list, engines: list, ingress: dict | None = None) -> dict:
    print(f"\n=== {title} ===")
    print(f"{'step':52} " + " ".join(f"{e.name:>34}" for e in engines))
    results = {}
    for t, (label, pkt) in enumerate(steps):
        row = []
        for e in engines:
            d = e.process(pkt, now=float(t)) if not isinstance(pkt, tuple) else e.process(pkt[0], now=pkt[1])
            row.append(d)
        results[label] = [d.action for d in row]
        print(f"{label:52} " + " ".join(f"{d.action.upper() + ' ' + _by(d):>34}" for d in row))
    return results


def direction(model: ObjectModel) -> dict:
    """Failure 1: without a reverse rule the reply is dropped (silent outage)."""
    fwd = {"id": "CL-WEB", "src": "Z_CLINICAL", "dst": "H_EMR_APP", "svc": "S_HTTPS", "action": "permit",
           "owner": "NUR", "req": "nurse to EMR"}
    pol = _policy([fwd], model)
    syn = Packet(NURSE_PC, EMR_APP, "tcp", 443, 51514, "S")
    return _run("Failure 1 - direction (forward rule only)",
                [("nurse SYN to EMR :443", syn), ("EMR SYN-ACK back to nurse", syn.reply("SA")),
                 ("nurse ACK", Packet(NURSE_PC, EMR_APP, "tcp", 443, 51514, "A"))],
                [StatelessFilter(pol), StatefulFirewall(pol)])


def intent(model: ObjectModel) -> dict:
    """Failures 2 and 3: the hand-written reverse rule lets the server open new sessions."""
    fwd = {"id": "CL-WEB", "src": "Z_CLINICAL", "dst": "H_EMR_APP", "svc": "S_HTTPS", "action": "permit",
           "owner": "NUR", "req": "nurse to EMR"}
    rev = {"id": "CL-REV", "src": "H_EMR_APP", "dst": "Z_CLINICAL", "svc": "any", "action": "permit",
           "owner": "NUR", "req": "reply rule a stateless design needs (source port cannot be pinned per flow here)"}
    stateless = StatelessFilter(_policy([fwd, rev], model))
    stateful = StatefulFirewall(_policy([fwd], model))
    syn = Packet(NURSE_PC, EMR_APP, "tcp", 443, 51514, "S")
    return _run("Failures 2 and 3 - sequencing and intent (stateless needs a reverse rule)",
                [("nurse SYN to EMR :443", syn), ("EMR SYN-ACK", syn.reply("SA")),
                 ("compromised EMR host: new SYN to nurse :3389", Packet(EMR_APP, NURSE_PC, "tcp", 3389, 443, "S")),
                 ("ACK-scan probe from EMR host to nurse :445", Packet(EMR_APP, NURSE_PC, "tcp", 445, 443, "A"))],
                [stateless, stateful])


def spoofing(model: ObjectModel) -> dict:
    """Failure 4: a forged internal source arriving from the internet."""
    pol = Policy.load(model=model)
    pkt = Packet("192.168.10.99", EMR_DB, "tcp", 1433, 40000, "S")
    sl = StatelessFilter(Policy.from_dict({"rules": [
        {"id": "L-3", "src": "Z_HIS", "dst": "H_EMR_DB", "svc": "S_MSSQL", "action": "permit", "owner": "x", "req": "legacy",
         "review": "none"}]}, model))
    print("\n=== Failure 4 - spoofing (packet arrives on the INTERNET interface) ===")
    d1 = sl.process(pkt)
    actual_zone = "INTERNET"
    claimed = model.zone_of(pkt.src)
    anti_spoof = "deny" if claimed != actual_zone else pol.evaluate(pkt).action
    print(f"stateless filter, legacy rule L-3: {d1.action.upper()} (it only reads the forged header)")
    print(f"zone-based NGFW: source claims {claimed} but arrived from {actual_zone}: {anti_spoof.upper()} (reverse-path check)")
    return {"spoofed SYN": [d1.action, anti_spoof]}


def translation() -> dict:
    """Failure 5: no translation without a table."""
    print("\n=== Failure 5 - translation ===")
    pat = PatTable()
    pub = pat.outbound(NURSE_PC, 51514, "93.184.216.34", 443)
    back = pat.inbound(pub[1], "93.184.216.34", 443)
    unsolicited = pat.inbound(pub[1] + 7, ATTACKER, 443)
    print(f"stateless filter: {NURSE_PC}:51514 leaves unchanged (private source has no public return route)")
    print(f"stateful PAT: {NURSE_PC}:51514 -> {pub[0]}:{pub[1]}; reply maps back to {back}; "
          f"unsolicited packet to port {pub[1] + 7} maps to {unsolicited}")
    return {"reply": back, "unsolicited": unsolicited}


def udp_pseudo_state(model: ObjectModel) -> dict:
    pol = Policy.load(model=model)
    fw = StatefulFirewall(pol)
    q = Packet("192.168.30.10", "192.168.10.53", "udp", 53, 33000, "")
    return _run("UDP pseudo-state (pump DNS query, DV-01)",
                [("pump DNS query", (q, 0.0)), ("resolver reply after 0.2 s", (q.reply(""), 0.2)),
                 ("stray reply after 90 s (entry expired)", (q.reply(""), 90.0))],
                [fw])


def app_id(model: ObjectModel) -> dict:
    """Generation 4: SSH tunnelled to a permitted :443 (lab experiment E7)."""
    pol = Policy.load(model=model)
    syn = Packet(RAD_WS, EMR_APP, "tcp", 443, 52000, "S", user_groups=("GRP_RADIOLOGISTS",))
    ack = Packet(RAD_WS, EMR_APP, "tcp", 443, 52000, "A", user_groups=("GRP_RADIOLOGISTS",))
    payload = Packet(RAD_WS, EMR_APP, "tcp", 443, 52000, "PA", user_groups=("GRP_RADIOLOGISTS",), app="ssh")
    return _run("App-ID - SSH on port 443 from radiology (rule R-03 allows emr-web only)",
                [("TCP SYN to EMR app :443 (app unknown)", syn),
                 ("EMR SYN-ACK", syn.reply("SA")),
                 ("radiology ACK", ack),
                 ("payload classified as SSH", payload)],
                [StatelessFilter(pol), StatefulFirewall(pol), StatefulFirewall(pol, ngfw=True, name="ngfw")])


def rule_order(model: ObjectModel) -> dict:
    """Shadowing (lab experiment E5, self-check Q19)."""
    broad = {"id": "BAD-443", "src": "Z_VENDOR_WIFI", "dst": "any", "svc": "S_HTTPS", "action": "permit", "owner": "?", "req": "broad"}
    deny = {"id": "VW-01", "src": "Z_VENDOR_WIFI", "dst": "N_RFC1918", "svc": "any", "action": "deny", "owner": "SEC", "req": "no internal"}
    pkt = Packet(VENDOR_LAPTOP, EMR_APP, "tcp", 443, 50123, "S")
    wrong = StatefulFirewall(_policy([broad, deny], model), name="broad permit first")
    right = StatefulFirewall(_policy([deny, broad], model), name="deny first")
    return _run("Rule order - vendor laptop to EMR app :443", [("vendor SYN to EMR :443", pkt)], [wrong, right])


def run_all() -> None:
    model = ObjectModel.load()
    direction(model)
    intent(model)
    spoofing(model)
    translation()
    udp_pseudo_state(model)
    app_id(model)
    rule_order(model)
