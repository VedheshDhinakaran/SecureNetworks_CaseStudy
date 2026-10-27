"""Stateless and stateful filtering engines driven by one rule list."""
from __future__ import annotations

from dataclasses import dataclass, field

from sjvnet.policy import Decision, Packet, Policy

# Idle timeouts in seconds (typical defaults; report Section 2.5)
TCP_ESTABLISHED_TIMEOUT = 3600
TCP_HANDSHAKE_TIMEOUT = 30
UDP_TIMEOUT = 60
ICMP_TIMEOUT = 10


class StatelessFilter:
    """Generation 1: every packet is judged alone on its 5-tuple."""

    name = "stateless"

    def __init__(self, policy: Policy):
        self.policy = policy

    def process(self, p: Packet, now: float = 0.0) -> Decision:
        return self.policy.evaluate(p, ngfw=False)


@dataclass
class StateEntry:
    proto: str
    a: tuple            # (ip, port) of the side that opened the flow
    b: tuple            # (ip, port) of the responder
    state: str          # SYN_SENT, ESTABLISHED, CLOSING, UDP, ICMP
    expires: float
    rule_id: str
    packets: int = 0


@dataclass
class StatefulFirewall:
    """Generation 3: a packet filter plus a connection state table.

    Set `ngfw=True` to also apply App-ID (generation 4 behaviour on the
    application check only; IPS/URL/TLS are out of scope for this model).
    """

    policy: Policy
    ngfw: bool = False
    table: dict = field(default_factory=dict)
    name: str = "stateful"

    @staticmethod
    def _key(p: Packet) -> tuple:
        ends = sorted([(p.src, p.sport), (p.dst, p.dport)])
        return (p.proto, ends[0], ends[1])

    def _expire(self, now: float) -> None:
        for k in [k for k, e in self.table.items() if e.expires < now]:
            del self.table[k]

    def process(self, p: Packet, now: float = 0.0) -> Decision:
        self._expire(now)
        entry = self.table.get(self._key(p))
        if entry:
            return self._check_existing(entry, p, now)

        # No entry: only a packet that can START a conversation may be evaluated.
        if p.proto == "tcp" and p.flags != "S":
            return Decision("deny", None, f"no state entry for TCP [{p.flags}] (out of sequence / unsolicited)")

        decision = self.policy.evaluate(p, ngfw=self.ngfw)
        if decision.action == "permit":
            state = {"tcp": "SYN_SENT", "udp": "UDP", "icmp": "ICMP"}.get(p.proto, "OTHER")
            timeout = {"tcp": TCP_HANDSHAKE_TIMEOUT, "udp": UDP_TIMEOUT}.get(p.proto, ICMP_TIMEOUT)
            self.table[self._key(p)] = StateEntry(p.proto, (p.src, p.sport), (p.dst, p.dport), state,
                                                  now + timeout, decision.rule.id if decision.rule else "-", 1)
        return decision

    def _check_existing(self, e: StateEntry, p: Packet, now: float) -> Decision:
        from_initiator = (p.src, p.sport) == e.a
        e.packets += 1
        if p.proto == "tcp":
            if e.state == "SYN_SENT":
                if not from_initiator and p.flags == "SA":
                    e.state, e.expires = "SYN_RCVD", now + TCP_HANDSHAKE_TIMEOUT
                    return Decision("permit", None, f"reply matches state entry (rule {e.rule_id})")
                return Decision("deny", None, "invalid flags for SYN_SENT state")
            if e.state == "SYN_RCVD" and from_initiator and "A" in p.flags:
                e.state, e.expires = "ESTABLISHED", now + TCP_ESTABLISHED_TIMEOUT
                return Decision("permit", None, f"handshake complete (rule {e.rule_id})")
            if e.state == "ESTABLISHED":
                if "S" in p.flags:
                    return Decision("deny", None, "SYN inside an established session")
                if "F" in p.flags or "R" in p.flags:
                    e.state = "CLOSING"
                e.expires = now + TCP_ESTABLISHED_TIMEOUT
                return Decision("permit", None, f"established session (rule {e.rule_id})")
            if e.state == "CLOSING":
                return Decision("permit", None, "closing session")
            return Decision("deny", None, f"unexpected TCP [{p.flags}] in state {e.state}")
        # UDP / ICMP pseudo-state: only the responder's replies refresh it
        e.expires = now + (UDP_TIMEOUT if p.proto == "udp" else ICMP_TIMEOUT)
        return Decision("permit", None, f"pseudo-state entry (rule {e.rule_id})")

    def dump(self) -> list[str]:
        return [f"{e.proto:4} {e.a[0]}:{e.a[1]} -> {e.b[0]}:{e.b[1]}  {e.state:11} rule={e.rule_id} pkts={e.packets}"
                for e in self.table.values()]
