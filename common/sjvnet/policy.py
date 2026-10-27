"""Rule base loading and first-match evaluation."""
from __future__ import annotations

import fnmatch
from dataclasses import dataclass, field
from typing import Optional

import yaml

from . import POLICY_FILE
from .model import AddrSet, ObjectModel, Service


@dataclass
class Packet:
    """One packet (or the first packet of a flow) as the firewall sees it."""

    src: str
    dst: str
    proto: str = "tcp"
    dport: Optional[int] = None
    sport: int = 50000
    flags: str = "S"            # TCP flags: S, SA, A, PA, F, R ...
    user_groups: tuple = ()      # directory groups of the logged-in user, if known
    url_path: Optional[str] = None
    app: Optional[str] = None    # what App-ID would classify the payload as

    def reply(self, flags: str = "SA") -> "Packet":
        return Packet(self.dst, self.src, self.proto, self.sport, self.dport or 0, flags)

    def __str__(self) -> str:
        port = f":{self.dport}" if self.dport is not None else ""
        return f"{self.proto} {self.src}:{self.sport} -> {self.dst}{port} [{self.flags}]"


@dataclass
class Rule:
    id: str
    section: str
    src: AddrSet
    dst: AddrSet
    services: Optional[frozenset]
    action: str
    log: str
    owner: str
    req: str
    review: str
    enabled: bool = True
    user: Optional[str] = None
    url_path: Optional[str] = None
    app: tuple = ()
    app_block: tuple = ()
    raw: dict = field(default_factory=dict)

    @property
    def is_permit(self) -> bool:
        return self.action == "permit"

    def matches(self, p: Packet) -> bool:
        if not self.enabled:
            return False
        if not (self.src.contains(p.src) and self.dst.contains(p.dst)):
            return False
        if self.services is not None:
            if not any(s.proto == p.proto and (s.port is None or s.port == p.dport) for s in self.services):
                return False
        if self.user and self.user not in p.user_groups:
            return False
        if self.url_path and not (p.url_path and fnmatch.fnmatch(p.url_path, self.url_path)):
            return False
        return True

    def app_allows(self, p: Packet) -> bool:
        """NGFW App-ID check.

        A permit that names applications (`app`) rejects anything else; a permit
        with `app_block` (e.g. general web browsing) rejects only those apps.
        """
        if p.app is None:
            return True
        if p.app in self.app_block:
            return False
        return not self.app or p.app in self.app


@dataclass
class Decision:
    action: str            # permit | deny
    rule: Optional[Rule]
    reason: str

    def __str__(self) -> str:
        rid = self.rule.id if self.rule else "-"
        return f"{self.action.upper():6} by {rid:6} ({self.reason})"


class Policy:
    def __init__(self, rules: list[Rule], model: ObjectModel, name: str = "policy"):
        self.rules = rules
        self.model = model
        self.name = name

    @classmethod
    def load(cls, path=POLICY_FILE, model: Optional[ObjectModel] = None, simulate: bool = True) -> "Policy":
        with open(path, encoding="utf-8") as fh:
            data = yaml.safe_load(fh)
        return cls.from_dict(data, model, simulate, name=str(path))

    @classmethod
    def from_dict(cls, data: dict, model: Optional[ObjectModel] = None, simulate: bool = True,
                  name: str = "inline") -> "Policy":
        model = model or ObjectModel.load()
        defaults = data.get("defaults", {})
        rules = []
        for r in data["rules"]:
            log = r.get("log", defaults.get("log", "yes"))
            if log is False:
                log = "no"
            rules.append(Rule(
                id=r["id"],
                section=r.get("section", ""),
                src=model.addrset(r["src"], simulate),
                dst=model.addrset(r["dst"], simulate),
                services=model.service_set(r.get("svc", "any")),
                action=r["action"],
                log="yes" if log is True else str(log),
                owner=r.get("owner", ""),
                req=r.get("req", ""),
                review=r.get("review", defaults.get("review", "")),
                enabled=r.get("enabled", True),
                user=r.get("user"),
                url_path=r.get("url_path"),
                app=tuple(r.get("app", [])),
                app_block=tuple(r.get("app_block", [])),
                raw=r,
            ))
        return cls(rules, model, name=name)

    def evaluate(self, p: Packet, ngfw: bool = True) -> Decision:
        for rule in self.rules:
            if rule.matches(p):
                if rule.is_permit and ngfw and not rule.app_allows(p):
                    return Decision("deny", rule, f"App-ID saw '{p.app}', not allowed by {rule.id}")
                return Decision(rule.action, rule, rule.req)
        return Decision("deny", None, "implicit deny (no rule matched)")

    def get(self, rule_id: str) -> Rule:
        for r in self.rules:
            if r.id == rule_id:
                return r
        raise KeyError(rule_id)
