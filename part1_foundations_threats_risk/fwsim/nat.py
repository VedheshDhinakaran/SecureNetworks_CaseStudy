"""Port address translation, kept alongside the state table (report Section 2.5)."""
from __future__ import annotations

import itertools


class PatTable:
    def __init__(self, public_ip: str = "203.0.113.1", first_port: int = 61000):
        self.public_ip = public_ip
        self._ports = itertools.count(first_port)
        self.out_map: dict = {}   # (inside_ip, inside_port, dst_ip, dst_port) -> public_port
        self.in_map: dict = {}    # (public_port, dst_ip, dst_port) -> (inside_ip, inside_port)

    def outbound(self, src: str, sport: int, dst: str, dport: int) -> tuple[str, int]:
        key = (src, sport, dst, dport)
        if key not in self.out_map:
            port = next(self._ports)
            self.out_map[key] = port
            self.in_map[(port, dst, dport)] = (src, sport)
        return self.public_ip, self.out_map[key]

    def inbound(self, dst_port: int, src: str, sport: int):
        """Return the inside (ip, port) for a reply, or None if unsolicited."""
        return self.in_map.get((dst_port, src, sport))
