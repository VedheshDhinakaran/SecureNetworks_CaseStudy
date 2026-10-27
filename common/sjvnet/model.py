"""Network object model: zones, hosts, groups and services.

Addresses are resolved into `AddrSet` objects (a union of networks minus
an optional list of excluded networks), which is enough to express every
source and destination used in the rule base, including "internet"
(anything outside RFC1918) and negated sets such as "any not Z_HIS".
"""
from __future__ import annotations

import ipaddress
from dataclasses import dataclass, field
from typing import Iterable, Union

import yaml

from . import OBJECTS_FILE

Net = Union[ipaddress.IPv4Network]
ANY_NET = ipaddress.ip_network("0.0.0.0/0")
RFC1918 = [ipaddress.ip_network(n) for n in ("10.0.0.0/8", "172.16.0.0/12", "192.168.0.0/16")]


def _net(text: str) -> Net:
    return ipaddress.ip_network(str(text), strict=False)


@dataclass(frozen=True)
class AddrSet:
    """Union of `include` networks minus any address in `exclude`."""

    include: tuple = ()
    exclude: tuple = ()
    label: str = ""

    def contains(self, ip: str | ipaddress.IPv4Address) -> bool:
        addr = ipaddress.ip_address(ip)
        if not any(addr in n for n in self.include):
            return False
        return not any(addr in n for n in self.exclude)

    def is_empty(self) -> bool:
        return not self.include

    def covers(self, other: "AddrSet") -> bool:
        """Conservative superset test: True only when self surely contains other."""
        if other.is_empty():
            return True
        for b in other.include:
            if not any(b.subnet_of(a) for a in self.include):
                return False
            for x in self.exclude:
                if x.overlaps(b):
                    # The part of b removed by x must also be excluded by other.
                    if not any(x.subnet_of(y) for y in other.exclude):
                        return False
        return True

    def overlaps(self, other: "AddrSet") -> bool:
        """Approximate overlap test (ignores exclusions that only partly cut a network)."""
        for a in self.include:
            for b in other.include:
                if not a.overlaps(b):
                    continue
                inter = a if a.subnet_of(b) else b
                if any(inter.subnet_of(x) for x in self.exclude + other.exclude):
                    continue
                return True
        return False

    def __str__(self) -> str:
        return self.label or ",".join(map(str, self.include))


@dataclass(frozen=True)
class Service:
    proto: str  # tcp | udp | icmp
    port: int | None

    @classmethod
    def parse(cls, text: str) -> "Service":
        proto, _, port = text.partition("/")
        return cls(proto.lower(), int(port) if port else None)

    def __str__(self) -> str:
        return f"{self.proto}/{self.port}" if self.port is not None else self.proto


@dataclass
class ObjectModel:
    zones: dict = field(default_factory=dict)
    hosts: dict = field(default_factory=dict)
    networks: dict = field(default_factory=dict)
    groups: dict = field(default_factory=dict)
    fqdns: dict = field(default_factory=dict)
    services: dict = field(default_factory=dict)
    dynamic: dict = field(default_factory=dict)
    sim: dict = field(default_factory=dict)

    # ------------------------------------------------------------ loading
    @classmethod
    def load(cls, path=OBJECTS_FILE) -> "ObjectModel":
        with open(path, encoding="utf-8") as fh:
            data = yaml.safe_load(fh)
        return cls(
            zones=data.get("zones", {}),
            hosts=data.get("hosts", {}),
            networks=data.get("networks", {}),
            groups=data.get("groups", {}),
            fqdns=data.get("fqdns", {}),
            services=data.get("services", {}),
            dynamic=data.get("dynamic", {}),
            sim=data.get("simulation_addresses", {}),
        )

    def names(self) -> set:
        return (set(self.zones) | set(self.hosts) | set(self.networks) | set(self.groups)
                | set(self.fqdns) | set(self.dynamic) | {"any", "internet"})

    # ------------------------------------------------------- address sets
    def _nets_for(self, name: str, simulate: bool) -> tuple[list, list]:
        """Return (include, exclude) network lists for one object name."""
        if name == "any":
            return [ANY_NET], []
        if name == "internet":
            return [ANY_NET], list(RFC1918)
        if name in self.zones:
            return [_net(self.zones[name]["subnet"])], []
        if name in self.hosts:
            return [_net(self.hosts[name]["ip"])], []
        if name in self.networks:
            return [_net(n) for n in self.networks[name]], []
        if name in self.groups:
            inc, exc = [], []
            for member in self.groups[name]:
                i, e = self._nets_for(member, simulate)
                inc += i
                exc += e
            return inc, exc
        if name in self.fqdns or name in self.dynamic:
            # Resolved by the firewall at run time. The simulator uses the
            # RFC 5737 documentation addresses from `simulation_addresses`.
            if simulate and name in self.sim:
                return [_net(self.sim[name])], []
            return [], []
        raise KeyError(f"unknown object: {name}")

    def addrset(self, spec, simulate: bool = True) -> AddrSet:
        """Resolve a source/destination field from the policy file."""
        if isinstance(spec, dict) and "not" in spec:
            exc = []
            for name in spec["not"]:
                exc += self._nets_for(name, simulate)[0]
            return AddrSet((ANY_NET,), tuple(exc), label=f"any not {','.join(spec['not'])}")
        if isinstance(spec, dict) and "zone" in spec:
            inc, _ = self._nets_for(spec["zone"], simulate)
            exc = []
            for name in spec.get("except", []):
                exc += self._nets_for(name, simulate)[0]
            return AddrSet(tuple(inc), tuple(exc), label=f"{spec['zone']} except {','.join(spec.get('except', []))}")
        names = spec if isinstance(spec, list) else [spec]
        inc, exc = [], []
        for name in names:
            i, e = self._nets_for(name, simulate)
            inc += i
            exc += e
        return AddrSet(tuple(inc), tuple(exc), label=",".join(names))

    # ----------------------------------------------------------- services
    def service_set(self, spec) -> frozenset | None:
        """None means 'any service'."""
        if spec in (None, "any"):
            return None
        names = spec if isinstance(spec, list) else [spec]
        out = set()
        for name in names:
            if name in self.services:
                out |= {Service.parse(s) for s in self.services[name]}
            elif "/" in str(name):
                out.add(Service.parse(name))
            elif name in self.dynamic:
                continue  # ticket-bound port, unknown until the ticket exists
            else:
                raise KeyError(f"unknown service: {name}")
        return frozenset(out)

    # -------------------------------------------------------------- misc
    def zone_of(self, ip: str) -> str:
        addr = ipaddress.ip_address(ip)
        for name, z in self.zones.items():
            if addr in _net(z["subnet"]):
                return name
        if any(addr in n for n in RFC1918):
            return "INTERNAL_OTHER"
        return "INTERNET"

    def host_ip(self, name: str) -> str:
        if name in self.hosts:
            return str(self.hosts[name]["ip"])
        if name in self.sim:
            return str(self.sim[name]).split("/")[0]
        raise KeyError(name)


def iter_services(services: Iterable[Service] | None) -> list[str]:
    return ["any"] if services is None else sorted(str(s) for s in services)
