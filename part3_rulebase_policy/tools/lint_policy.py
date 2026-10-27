#!/usr/bin/env python3
"""Rule-base linter for the Sanjivani NGFW policy (report Ch. 8 and 10).

Checks the disciplines a regulator would look for:

  E1  every rule has an owner, a requirement and a review cycle
  E2  no permit with source AND destination 'any' (the old vendor rule)
  E3  every zone section ends in a logged default deny
  E4  the rule base ends in a global 'deny any any'
  E5  a rule is fully shadowed by an earlier rule (it can never match)
  W1  an earlier rule with the opposite action partly overlaps a rule
  W2  a permit has no logging
  W3  a permit uses 'any' as its service

Exit code is non-zero if any error (E*) is found, so this can run in CI
before a change is pushed to the firewall.

Usage:  python3 lint_policy.py [policy.yaml] [--verbose]
"""
from __future__ import annotations

import argparse
import sys

import _path  # noqa: F401
from sjvnet import POLICY_FILE
from sjvnet.model import ANY_NET
from sjvnet.policy import Policy, Rule

ZONE_SECTIONS = {
    "mgmt": "Z_MGMT", "his": "Z_HIS", "dmz": "Z_DMZ", "devices": "Z_DEVICES",
    "radiology": "Z_RADIOLOGY", "clinical": "Z_CLINICAL", "guest": "Z_GUEST",
    "vendor_wifi": "Z_VENDOR_WIFI", "research": "Z_RESEARCH", "vendor_maint": "Z_VENDOR_MAINT",
}


def _is_any(addrset) -> bool:
    return addrset.include == (ANY_NET,) and not addrset.exclude


def _svc_covers(a, b) -> bool:
    if a is None:
        return True
    if b is None:
        return False
    return b <= a


def _svc_overlap(a, b) -> bool:
    if a is None or b is None:
        return True
    return bool(a & b)


def covers(earlier: Rule, later: Rule) -> bool:
    """True if every packet matching `later` also matches `earlier`."""
    if not earlier.enabled:
        return False
    if earlier.user or earlier.url_path:
        # earlier is narrower in a dimension we cannot compare safely
        if earlier.user != later.user or earlier.url_path != later.url_path:
            return False
    return (earlier.src.covers(later.src) and earlier.dst.covers(later.dst)
            and _svc_covers(earlier.services, later.services))


def overlaps(a: Rule, b: Rule) -> bool:
    if a.url_path and b.url_path and a.url_path != b.url_path:
        return False
    return a.src.overlaps(b.src) and a.dst.overlaps(b.dst) and _svc_overlap(a.services, b.services)


def lint(policy: Policy, verbose: bool = False) -> tuple[list, list]:
    errors, warnings = [], []
    rules = policy.rules

    for r in rules:
        missing = [f for f in ("owner", "req", "review") if not getattr(r, f)]
        if missing:
            errors.append(f"E1 {r.id}: missing {', '.join(missing)}")
        if r.is_permit and _is_any(r.src) and _is_any(r.dst):
            errors.append(f"E2 {r.id}: permit with source and destination 'any'")
        if r.is_permit and r.log in ("no", "False", "false"):
            warnings.append(f"W2 {r.id}: permit without logging")
        if r.is_permit and r.services is None:
            warnings.append(f"W3 {r.id}: permit with service 'any'")

    # E3: each zone section must end with "<zone> -> any : deny"
    for section, zone in ZONE_SECTIONS.items():
        sec_rules = [r for r in rules if r.section == section]
        if not sec_rules:
            errors.append(f"E3 section '{section}': no rules")
            continue
        last = sec_rules[-1]
        zone_set = policy.model.addrset(zone)
        if not (last.action == "deny" and last.src.covers(zone_set) and _is_any(last.dst) and last.services is None):
            errors.append(f"E3 section '{section}': last rule {last.id} is not a '{zone} -> any' default deny")
        elif last.log in ("no", "False"):
            errors.append(f"E3 section '{section}': default deny {last.id} is not logged")

    # E4: final rule
    final = rules[-1]
    if not (final.action == "deny" and _is_any(final.src) and _is_any(final.dst) and final.services is None):
        errors.append(f"E4 final rule {final.id} is not 'deny any any'")

    # E5 / W1: shadowing and conflicts
    for j, later in enumerate(rules):
        if not later.enabled:
            continue
        for earlier in rules[:j]:
            if not earlier.enabled:
                continue
            if covers(earlier, later):
                kind = "redundant" if earlier.action == later.action else "conflicting"
                # A zone default after a broader default of the same action is expected
                if kind == "redundant" and later.action == "deny" and later.services is None:
                    if verbose:
                        warnings.append(f"I  {later.id}: covered by {earlier.id} (deny kept for its own counter)")
                    break
                errors.append(f"E5 {later.id}: fully shadowed by {earlier.id} ({kind}); it can never match")
                break
            if earlier.raw.get("global_block"):
                continue  # block lists are meant to override every permit
            if earlier.action != later.action and overlaps(earlier, later) and later.is_permit:
                verb = "denied" if earlier.action == "deny" else "permitted"
                warnings.append(f"W1 {later.id}: part of its traffic is already {verb} by {earlier.id}")
    return errors, warnings


def main(argv=None) -> int:
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("policy", nargs="?", default=str(POLICY_FILE))
    ap.add_argument("--verbose", "-v", action="store_true")
    args = ap.parse_args(argv)

    policy = Policy.load(args.policy)
    errors, warnings = lint(policy, args.verbose)
    print(f"Linted {len(policy.rules)} rules from {args.policy}")
    for line in errors + warnings:
        print("  " + line)
    print(f"{len(errors)} error(s), {len([w for w in warnings if not w.startswith('I')])} warning(s)")
    return 1 if errors else 0


if __name__ == "__main__":
    sys.exit(main())
