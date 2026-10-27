# Contributions

The work is split the same way as the report: each member owns one part,
its folder in this repository and the matching chapters. Ownership means
that member is responsible for the part's content, keeps it consistent
with the report, and presents it in the viva.

| Member | Roll no. | Part | Folder | Report chapters |
|---|---|---|---|---|
| Janhavi Harish Kulkarni | CSE23127 | I. Foundations, threats and risk | `part1_foundations_threats_risk/` | 2, 3, 4 |
| Debapriya Kundu | CSE23115 | II. Architecture, protocols, CIA and lab build | `part2_architecture_protocols/` | 5, 6, 7 (and 11.2–11.4) |
| Vedhesh Dhinakaran | CSE23257 | III. Rule base, NGFW policy and verification | `part3_rulebase_policy/` | 8, 9, 10 |
| Vundela Lasya | CSE23258 | IV. Lab experiments, monitoring, IR and compliance | `part4_lab_monitoring_response/` | 11, 12, 13, 14 |

## Part I: Janhavi Harish Kulkarni
* Firewall simulator: stateless filter, stateful engine with TCP state machine and UDP/ICMP pseudo-state, PAT table, App-ID check (`fwsim/engines.py`, `fwsim/nat.py`).
* The five stateless failures, App-ID and rule-order demonstrations (`fwsim/scenarios.py`).
* Incident replay of F1–F3 and the risk-register scenarios against the old and new design (`fwsim/incidents.py`, `fwsim/legacy_policy.yaml`).
* Asset register, STRIDE model, ATT&CK mapping, risk register R1–R14 and heat maps (`threat_model/`, `risk/`).

## Part II: Debapriya Kundu
* Network object model, the single source of truth for zones, hosts, groups and services (`network/objects.yaml`), its validator and the generated IP plan and diagram (`tools/`, `docs/`).
* Access-layer hardening reference and wireless SSID mapping (`access_layer/`).
* Secure protocol register (`protocols/`).
* VirtualBox lab build for Linux/macOS and Windows, zone VM setup scripts and the stand-in lab services: EMR web app, MSSQL listener, MLLP server/client and HL7 library (`lab/`).

## Part III: Vedhesh Dhinakaran
* The 60-rule base as data with full metadata (`rulebase/policy.yaml`) and the generated CSV, Markdown and pf renderings.
* Rule-base linter (`tools/lint_policy.py`). Its findings changed G-02, G-03 and G-04 in the final rule base (see the Part III README).
* Verification matrix and simulator probes (`verification/`, `tools/verify_matrix.py`), lab-subset checker.
* OPNsense API loader with dry run, savepoint/rollback and setup mode (`tools/opnsense_load.py`, `opnsense/lab_rules.yaml`).
* Hit-counter review and change-control templates (`tools/hit_counter_review.py`, `change_control/`).

## Part IV: Vundela Lasya
* Experiment scripts E1–E8 with transcript capture and the result collector (`experiments/`).
* Local Suricata rules, OPNsense ruleset metadata and offline replay (`ids/`).
* SIEM use cases UC-01–UC-06 in Sigma, offline correlation, filterlog timeline and EVE summary tools (`siem/`, `tools/`).
* Collector configuration, telemetry thresholds and firewall snapshots (`monitoring/`).
* Playbooks PB-1–PB-5, evidence collection and RACI (`ir/`).
* Compliance matrix, monitoring calendar and metrics (`compliance/`); evidence templates (`evidence/`).

## Shared
* `common/sjvnet/`: the object model (Part II) and the policy engine (Part III) that every part imports; the OPNsense log parsers (Part IV).
* `tests/`: each member keeps the tests for their part (`test_fwsim.py` I; `test_model.py`, `test_hl7.py` II; `test_policy.py`, `test_tools_part3.py` III; `test_logs.py`, `test_compliance.py` IV).
* The lab run itself (E1–E8) is done together; who ran which experiment is recorded in `part4_lab_monitoring_response/evidence/environment.md`.
