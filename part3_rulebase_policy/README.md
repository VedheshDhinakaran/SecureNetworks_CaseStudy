# Part III: Rule base, NGFW policy and verification

**Owner:** Vedhesh Dhinakaran (CSE23257) · **Report:** Chapters 8, 9 and 10

The full 60-rule base from Table 8.2 lives in `rulebase/policy.yaml` as
data. Every other artefact here (CSV, Markdown, pf rendering, OPNsense
payloads, verification results) is generated from it or checked against it.

## Contents

| Path | What it is | Report |
|---|---|---|
| `rulebase/policy.yaml` | 60 rules, 12 sections, first match wins; owner, requirement, review cycle and NGFW fields per rule | Table 8.2 |
| `rulebase/rulebase.csv` | Generated, one row per rule (for the appendix / reviewers) | Table 8.2 |
| `generated/sanjivani.pf`, `generated/rulebase.md` | Generated pf.conf-style rendering and Markdown tables | 8.4 |
| `tools/lint_policy.py` | Rule-base linter: metadata (E1), any-any permits (E2), zone default denies (E3), final deny (E4), full shadowing (E5), partial conflicts (W1), logging (W2), `any` service (W3). Exit 1 on error | 8.1, 10 |
| `tools/gen_acl.py` | Renders the policy as `csv`, `md`, `pf` or `flat` | 8 |
| `verification/verification_matrix.csv` | Tests 1–16 with the command to run and an `observed_in_lab` column for the team | Table 10.1 |
| `verification/probes.yaml` + `tools/verify_matrix.py` | 30 packets that prove the policy *as written* meets the matrix (simulator, not lab) | 10.1 |
| `opnsense/lab_rules.yaml` | The 18-rule lab subset entered in OPNsense, linked to production rule IDs | Table 11.1 |
| `tools/check_lab_subset.py` | Confirms every lab rule makes the same decision as production (or is marked as deliberately broader / lab-only) | 11.4 |
| `tools/opnsense_load.py` | Loads aliases and lab rules through the OPNsense REST API. **Dry run by default**; savepoint and auto-rollback when applied; `--setup-mode on/off`; `--purge` | 11.4 |
| `tools/hit_counter_review.py` | Parses saved `pfctl -vvsr`, maps OPNsense label hashes to rule IDs via `rules.debug`, flags DEAD / HOT / ALERT rules against a baseline | 10.2 |
| `change_control/` | Change-request template and the rule-review record | 10.3 |

## What the linter found
Running `lint_policy.py` on the first draft of the rule base found two real
shadowing bugs and a few smaller problems. They were fixed in `policy.yaml`:

* **G-02** (management plane unreachable) also blocked the SIEM and backup
  collectors, so M-04 (central logging) and H-01 (HIS backups) could never
  match. G-02 now excepts H_SIEM and H_BACKUP.
* **G-03** (no zone outside HIS reaches the EMR DB) also blocked the bastion
  and NMS, so M-02 and M-03 could not manage the database host. G-03 now
  excepts H_BASTION and H_NMS.
* G-04 (DNS bypass) blocked guest and vendor Wi-Fi DNS; those zones are now
  excepted because they use public resolvers by design. D-08 moved to its own
  `inbound` section so the DMZ section ends in its own default deny, and
  G-01 (threat-feed block) is marked `global_block` so its intended
  overlap with every permit is not reported as a conflict.

`tests/test_policy.py` keeps regression tests for the first two.

## Run

```sh
cd part3_rulebase_policy/tools
python3 lint_policy.py                 # must print 0 error(s)
python3 verify_matrix.py -q            # 30 probes, 0 failures
python3 check_lab_subset.py
python3 gen_acl.py --format md --section devices
python3 opnsense_load.py               # dry run: prints the API payloads
export OPN_KEY=... OPN_SECRET=...
python3 opnsense_load.py --apply --ca opnsense-ca.pem
```
