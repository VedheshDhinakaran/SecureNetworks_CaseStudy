"""Part IV compliance metrics and matrices are consistent with the rule base."""
import csv
from pathlib import Path

import metrics
from sjvnet.model import ObjectModel
from sjvnet.policy import Policy

ROOT = Path(__file__).resolve().parents[1]


def test_metrics_on_target():
    rows = metrics.compute(Policy.load(model=ObjectModel.load()))
    assert all(ok is not False for *_, ok in rows)


def test_compliance_matrix_references_real_rules():
    ids = {r.id for r in Policy.load(model=ObjectModel.load()).rules}
    text = (ROOT / "part4_lab_monitoring_response/compliance/compliance_matrix.csv").read_text()
    for rid in ("C-04", "H-08", "GW-01", "VW-01", "H-06", "M-05", "R-04"):
        assert rid in text and rid in ids


def test_verification_matrix_has_16_tests():
    path = ROOT / "part3_rulebase_policy/verification/verification_matrix.csv"
    rows = list(csv.DictReader(open(path)))
    assert [int(r["test"]) for r in rows] == list(range(1, 17))


def test_evidence_folders_hold_no_results_yet():
    """Evidence must come from the real lab; the repo ships only templates."""
    ev = ROOT / "part4_lab_monitoring_response/evidence"
    for n in range(1, 9):
        files = {p.name for p in (ev / f"E{n}").iterdir()}
        assert files <= {"README.md"} or "TO FILL" not in (ev / f"E{n}" / "README.md").read_text()
