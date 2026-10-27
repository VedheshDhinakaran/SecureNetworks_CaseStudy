"""Shared library for the CS07 hospital NGFW project.

`model` loads the network object model (Part II) and `policy` loads and
evaluates the rule base (Part III). Part I's simulator and Part IV's
tools import from here so that every part works from the same data.
"""
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parents[2]
OBJECTS_FILE = REPO_ROOT / "part2_architecture_protocols" / "network" / "objects.yaml"
POLICY_FILE = REPO_ROOT / "part3_rulebase_policy" / "rulebase" / "policy.yaml"
LEGACY_POLICY_FILE = REPO_ROOT / "part1_foundations_threats_risk" / "fwsim" / "legacy_policy.yaml"
