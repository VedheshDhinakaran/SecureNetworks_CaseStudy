# Firewall change request — CHG______

Every change to the rule base follows this path (report Section 10.3). The
ticket number must appear in the rule description and in the firewall's
configuration-save note, or UC-06 fires.

| Field | Value |
|---|---|
| Requester (name, department) | |
| Business owner of the flow | |
| Rule ID(s) affected | new / existing: |
| Source (object names from `objects.yaml`) | |
| Destination | |
| Service (`S_*` objects or proto/port) | |
| Application / user group (if NGFW controls apply) | |
| Duration | permanent / until: |
| Clinical impact if delayed or wrong | |
| Rollback plan | |

## Security review (SEC)
- [ ] Narrowest possible source, destination and service (no `any` unless justified in writing)
- [ ] `python3 part3_rulebase_policy/tools/lint_policy.py` exits 0 (no shadowing, no any-any, metadata complete)
- [ ] `python3 part3_rulebase_policy/tools/verify_matrix.py -q` still passes
- [ ] Lab subset still consistent: `python3 part3_rulebase_policy/tools/check_lab_subset.py`
- [ ] Logging set (`yes` or `alert`)
- [ ] Review cycle set (Q / M / T)

## Implementation
- [ ] Log-only rehearsal done (where possible), dates: ______
- [ ] Approved window: ______
- [ ] Applied with savepoint / auto-rollback; confirmed within 10 minutes
- [ ] Relevant verification-matrix tests re-run from the affected zones
- [ ] Policy diff (`gen_acl.py --format csv` before/after), operator and ticket stored

Approved by (SEC): ____________  Date: ______
