"""Part III generators, lab subset, verification matrix and OPNsense payloads."""
import csv
import io

import yaml

import check_lab_subset
import gen_acl
import opnsense_load
import verify_matrix
from sjvnet.model import ObjectModel
from sjvnet.policy import Policy


def test_csv_has_one_row_per_rule():
    policy, _ = gen_acl.load(gen_acl.POLICY_FILE)
    rows = list(csv.DictReader(io.StringIO(gen_acl.render_csv(policy))))
    assert len(rows) == 60
    g03 = next(r for r in rows if r["id"] == "G-03")
    assert g03["destination"] == "H_EMR_DB" and g03["log"] == "A"


def test_pf_output_labels_every_rule():
    policy, _ = gen_acl.load(gen_acl.POLICY_FILE)
    pf = gen_acl.render_pf(policy)
    for r in policy.rules:
        assert f'label "{r.id}"' in pf
    assert "table <internet> const { 0.0.0.0/0 !10.0.0.0/8 !172.16.0.0/12 !192.168.0.0/16 }" in pf
    assert '# DISABLED (template) pass in quick log from <H_JUMP> to <TICKET_DEVICE>' in pf


def test_committed_rulebase_csv_is_up_to_date():
    policy, _ = gen_acl.load(gen_acl.POLICY_FILE)
    committed = (gen_acl.POLICY_FILE.parent / "rulebase.csv").read_text(encoding="utf-8")
    assert committed == gen_acl.render_csv(policy), "run: make docs"


def test_verification_probes_all_pass():
    data = yaml.safe_load(open(verify_matrix.PROBES, encoding="utf-8"))
    results = verify_matrix.run(Policy.load(model=ObjectModel.load()), data)
    assert len(results) >= 30
    assert all(ok for *_, ok in results), [(p, str(d)) for p, _, d, ok in results if not ok]


def test_lab_subset_consistent():
    assert check_lab_subset.main() == 0


def test_opnsense_payloads():
    lab = yaml.safe_load(open(opnsense_load.LAB_FILE, encoding="utf-8"))
    model = ObjectModel.load()
    aliases = {a["name"]: a for a in opnsense_load.alias_payloads(lab, model)}
    assert aliases["H_EMR_DB"]["content"] == "192.168.10.20"
    assert aliases["S_MLLP"]["content"] == "2575"
    assert aliases["N_RFC1918"]["type"] == "network"
    rules = opnsense_load.lab_rule_payloads(lab)
    assert len(rules) == 18
    g03 = next(r for r in rules if "G-03" in r["description"])
    assert (g03["interface"], g03["action"], g03["source_net"]) == ("opt3", "block", "opt3")
    vw02 = next(r for r in rules if "VW-02 internet" in r["description"])
    assert vw02["destination_not"] == "1"
    assert all(r["log"] == "1" and r["description"].startswith(opnsense_load.MARKER) for r in rules)
    seqs = [int(r["sequence"]) for r in rules]
    assert seqs == sorted(seqs)


def test_opnsense_dry_run_sends_nothing(capsys):
    assert opnsense_load.main([]) == 0
    assert "DRY RUN" in capsys.readouterr().out
