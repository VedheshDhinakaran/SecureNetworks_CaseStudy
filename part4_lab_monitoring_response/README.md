# Part IV: Lab experiments, monitoring, incident response and compliance

**Owner:** Vundela Lasya (CSE23258) · **Report:** Chapters 11, 12, 13 and 14

> **Evidence rule.** Nothing in `evidence/` is pre-filled. Every transcript,
> screenshot and "Observed" cell must come from our own lab run. Test
> fixtures used by the unit tests live in `/tests/fixtures/` and are marked
> SYNTHETIC; they are never evidence.

## Contents

| Path | What it is | Report |
|---|---|---|
| `experiments/e1_baseline.sh` … `e8_log_timeline.sh` | One script per experiment. Each detects which VM it is on, runs that VM's steps, pauses for GUI changes (`phase`) and writes a timestamped transcript with every command, its output and exit code | 11.5 |
| `experiments/common.sh` | Transcript helpers: `run`, `phase`, `mark_time` (attempt times for E8), `fw` (commands on OPNsense over SSH) | 11.5 |
| `experiments/collect_results.sh` | Run on the bastion: pulls every VM's transcripts into `evidence/raw/` and writes `SHA256SUMS` | 11.6 |
| `ids/suricata/sjv-custom.rules` | 13 local Suricata rules: SQLi / scanner to the EMR portal, SSH on 443, non-MLLP and malformed HL7 to the interface engine, EMR DB access from outside HIS, device DNS tunnelling and egress, Wi-Fi probing | 8.5.4, E6, E7 |
| `ids/suricata/sjv-custom.xml`, `run_suricata_offline.sh` | Ruleset metadata for OPNsense; offline replay of our own captures through Suricata | 11.4 |
| `siem/sigma/uc01 … uc06` | UC-01 to UC-06 as Sigma rules (correlation rules for UC-01, UC-03, UC-04) | 12.2 |
| `tools/correlate.py` | Same use cases run offline over a saved filterlog, with production or lab thresholds | 12.2 |
| `tools/timeline.py` | filterlog → incident timeline with zones and rule IDs; `--marks` checks each recorded attempt appears in the log (E8 "complete") | 11.5 E8 |
| `tools/eve_summary.py` | Suricata EVE summary: alerts per signature, dropped vs alerted, app-layer protocols seen (E6, E7) | 12.3 |
| `monitoring/` | rsyslog collector config (UDP 514 lab, TLS 6514 production), 180-day logrotate, `telemetry.yaml` thresholds, `snapshot_firewall.sh` | 12.1, 14 |
| `ir/playbooks/PB-1 … PB-5` | Step-by-step playbooks with triggers, commands, containment, verification and exit criteria | 13.2 |
| `ir/collect_evidence.sh`, `ir/raci.csv` | Evidence preservation with hashes and a custody note; responsibility matrix | 13 |
| `compliance/compliance_matrix.csv` | HIPAA, PCI DSS v4.0, DPDP Act, CERT-In, IEC 80001-1, NIST 800-41 mapped to design elements *and to the file in this repo* that evidences them | Table 14.2 |
| `compliance/monitoring_calendar.csv`, `metrics.py` | Review calendar; monthly metrics computed from the live rule base | 14.1, 14.3 |
| `evidence/` | Empty templates for E1–E8, lab config export and environment details | 11.6 |

## Running the experiments

1. Build the lab (Part II) and load the lab rules (Part III `opnsense_load.py`).
2. Copy this folder to each VM: `scp -r part4_lab_monitoring_response/experiments root@<vm>:/opt/sjv/`.
3. Run the experiment on every VM it names, in the order the script header gives. Each script tells you when to change something in the OPNsense GUI and waits for Enter.
4. On the bastion: `experiments/collect_results.sh`, then fill in `evidence/E<n>/README.md` with what you **observed**.
5. Copy the observed results into report Table 11.2 and the `observed_in_lab` column of the verification matrix.

| Exp. | Run on | GUI changes during the run |
|---|---|---|
| E1 | rad-vm, vendor-vm | allow-all rule at top of RADIOLOGY and VENDOR (remove afterwards) |
| E2 | rad-vm, vendor-vm, bastion | none (lab rules only) |
| E3 | pump-vm, bastion | none |
| E4 | rad-vm, his-vm, bastion | R-03 state none + floating rule; reverse rule; restore |
| E5 | vendor-vm, bastion | broad pass above, then below, VW-01 |
| E6 | rad-vm, vendor-vm | Suricata IPS off, then on |
| E7 | his-vm, rad-vm | Zenarmor off, then on |
| E8 | rad-vm, vendor-vm, bastion | none |
