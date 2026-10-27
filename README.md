# CS07: Segmentation and an NGFW for Sanjivani Hospital — software implementation

23CSE336 Secure Networks · Case study CS07 · Team of four (see [CONTRIBUTIONS.md](CONTRIBUTIONS.md))

This repository is the software side of our report *Replacing a Stateless
Packet Filter with Segmentation and an NGFW in a Hospital Network*. It
does three jobs:

1. **Makes the design executable.** The zone model and the 60-rule base
   from the report are data files (`objects.yaml`, `policy.yaml`). A
   simulator, a linter and a verification harness run against them, so
   every claim in Chapters 2, 8 and 10 can be checked by running code.
2. **Builds and drives the lab.** Scripts create the VirtualBox lab,
   configure each zone VM, load the OPNsense rules through its API and
   run experiments E1–E8 with full transcripts.
3. **Turns the monitoring and response chapters into tooling.** Suricata
   rules, Sigma use cases, a log-to-timeline tool, hit-counter review,
   incident playbooks and compliance metrics.

## Layout

```
cs07-ngfw-hospital/
├── common/sjvnet/                     shared library: object model, policy engine, OPNsense log parsers
├── part1_foundations_threats_risk/    Part I  - firewall simulator, threat model, risk register
├── part2_architecture_protocols/      Part II - zones/objects, protocols, access layer, lab build + services
├── part3_rulebase_policy/             Part III - rule base, linter, generators, OPNsense loader, verification
├── part4_lab_monitoring_response/     Part IV - experiments E1-E8, IDS, SIEM, IR, compliance, evidence
├── tests/                             pytest suite (42 tests) + synthetic fixtures
├── Makefile                           make check | test | sim | docs | risk
└── requirements.txt
```

Each part folder has its own README with the file-by-file detail.

## Quick start

```sh
python3 -m pip install -r requirements.txt
make test        # 42 tests
make check       # validate objects, lint the rule base, run 30 verification probes, lab-subset check, metrics
make sim         # stateless vs stateful vs NGFW demos and the F1-F3 incident replay
```

Trace a single packet through the production policy:

```sh
cd part1_foundations_threats_risk
PYTHONPATH=../common python3 -m fwsim trace 192.168.40.100 192.168.10.20 --dport 1433
#   tcp 192.168.40.100:50000 -> 192.168.10.20:1433 [S]
#     -> DENY   by G-03   (No zone outside HIS ever reaches the EMR database (incident F2))
```

## Where each report chapter lives

| Report | Topic | Code and data |
|---|---|---|
| Ch. 2 | Firewall generations, five stateless failures, state table | `part1…/fwsim/` |
| Ch. 3 | Assets, threats, STRIDE, attack paths | `part1…/threat_model/`, `part1…/risk/assets.csv`, `fwsim/incidents.py` |
| Ch. 4 | Risk register and heat maps | `part1…/risk/` |
| Ch. 5 | Zones, VLAN/IP plan, access layer, wireless | `part2…/network/objects.yaml`, `part2…/access_layer/`, `part2…/docs/` |
| Ch. 6 | Secure protocol register | `part2…/protocols/protocol_register.csv`, `part2…/lab/services/hl7.py` |
| Ch. 7 | CIA per zone | `objects.yaml` trust levels, `policy.yaml` |
| Ch. 8 | 60-rule base, return traffic, NGFW policy | `part3…/rulebase/`, `part3…/generated/`, `part3…/tools/lint_policy.py` |
| Ch. 9 | Critique of the reference design | `fwsim/legacy_policy.yaml`, `fwsim/incidents.py` (old vs new column) |
| Ch. 10 | Verification matrix, hit-counter review, change control | `part3…/verification/`, `hit_counter_review.py`, `part3…/change_control/` |
| Ch. 11 | Lab build and experiments E1–E8 | `part2…/lab/`, `part3…/opnsense/`, `part4…/experiments/`, `part4…/evidence/` |
| Ch. 12 | Telemetry, SIEM use cases, tools | `part4…/monitoring/`, `part4…/siem/sigma/`, `part4…/tools/` |
| Ch. 13 | Incident response | `part4…/ir/` |
| Ch. 14 | Continuous monitoring and compliance | `part4…/compliance/` |

## What is real and what the team must still produce

| Status | Items |
|---|---|
| **Runs and is tested here** | object validation, policy linter, verification probes, simulator, generators, OPNsense payload builder (dry run), log parsers, correlation, EVE summary, hit-counter review, metrics. Suricata rules pass `suricata -T` (Suricata 7.0) and Sigma rules parse with pySigma. |
| **Written for the lab, runs only there** | VirtualBox build scripts, zone VM setup, `opnsense_load.py --apply`, experiment scripts E1–E8, `collect_results.sh`, `snapshot_firewall.sh`, `collect_evidence.sh` |
| **Design reference, not lab-tested** | `access_switch_hardening.ios` (no 802.1X/PVLAN in VirtualBox), production TLS syslog block |
| **Must come from our own lab run** | everything under `part4_lab_monitoring_response/evidence/` and the `observed_in_lab` column of the verification matrix. These are empty templates marked `TO FILL`. |

Files in `tests/fixtures/` are hand-written **synthetic** inputs for the unit
tests (named `*_SYNTHETIC*`). They are not lab output and must not be used
as evidence.

## Safety notes

* `opnsense_load.py` does nothing unless `--apply` is given, applies with a
  savepoint and auto-rollback, and only touches rules it created (`[cs07]`
  prefix). It is for the isolated lab, never a production firewall.
* The experiment scripts run scans only inside the lab's internal networks.
  The report's rule for real hospitals stands: the device zone is tested
  passively, and active device testing happens only on spare units.
* `ir/collect_evidence.sh` copies `config.xml`, which contains secrets.
  Case folders are git-ignored.
