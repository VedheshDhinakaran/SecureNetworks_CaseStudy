"""Part III: the production rule base is clean and the linter catches real mistakes."""
from pathlib import Path

import pytest

import lint_policy
from sjvnet.model import ObjectModel
from sjvnet.policy import Packet, Policy

FIX = Path(__file__).parent / "fixtures"


@pytest.fixture(scope="module")
def policy():
    return Policy.load(model=ObjectModel.load())


def test_sixty_rules_ending_in_final_deny(policy):
    assert len(policy.rules) == 60
    assert policy.rules[-1].id == "X-99"
    assert len({r.id for r in policy.rules}) == 60


def test_production_policy_lints_clean(policy):
    errors, warnings = lint_policy.lint(policy)
    assert errors == [] and warnings == []


def test_linter_rejects_broken_policy():
    broken = Policy.load(FIX / "shadowed_policy.yaml", ObjectModel.load())
    errors, _ = lint_policy.lint(broken)
    text = "\n".join(errors)
    assert "E5 P-02" in text and "P-01" in text     # shadowed permit
    assert "E2 P-03" in text                         # any-any permit
    assert "E1 P-04" in text                         # no owner
    assert "E3 section 'radiology'" in text          # no zone default deny


def test_incident_f2_closed(policy):
    d = policy.evaluate(Packet("192.168.40.100", "192.168.10.20", "tcp", 1433))
    assert (d.action, d.rule.id) == ("deny", "G-03")


def test_bastion_can_still_manage_db_host(policy):
    """Regression for the G-03 shadowing bug the linter found."""
    d = policy.evaluate(Packet("192.168.90.5", "192.168.10.20", "tcp", 22))
    assert (d.action, d.rule.id) == ("permit", "M-02")


def test_his_backup_reaches_backup_server(policy):
    """Regression for the G-02 shadowing bug the linter found."""
    d = policy.evaluate(Packet("192.168.10.21", "192.168.90.20", "tcp", 8400))
    assert (d.action, d.rule.id) == ("permit", "H-01")


def test_vendor_maintenance_template_disabled(policy):
    assert policy.get("VM-02").enabled is False
