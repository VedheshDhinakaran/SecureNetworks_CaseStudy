"""Make every part's code importable from the tests without installing anything."""
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
FIXTURES = Path(__file__).resolve().parent / "fixtures"

for sub in (
    "common",
    "part1_foundations_threats_risk",
    "part2_architecture_protocols/tools",
    "part2_architecture_protocols/lab/services",
    "part3_rulebase_policy/tools",
    "part4_lab_monitoring_response/tools",
    "part4_lab_monitoring_response/compliance",
):
    p = str(ROOT / sub)
    if p not in sys.path:
        sys.path.insert(0, p)
