# 7.5 Implementation and readiness validation

Implementation (11.2-11.4): VirtualBox 7.2.22, OPNsense 25.7, four Alpine 3.20.10 VMs; reboot verified.

**Table 7.2: Software and policy checks**

| Validation check | Observed |
|---|---|
| Unit tests: Part II / full suite | 9 / 42 PASS |
| Objects and policy lint | PASS |
| Simulator probes / lab rules | 30 / 18 PASS |
| Local service checks (loopback) | 6 / 6 PASS |
| Policy / temporary setup rules | 18 / 0 |
| Blocked flows matched in PF log | 7 / 7 PASS |

**Table 7.3: VM readiness checks**

| Lab role | Checks | Observed |
|---|---|---|
| MGMT bastion | 6 | PASS |
| HIS VM | 7 | PASS |
| Device VM | 8 | PASS |
| Radiology VM | 8 | PASS |
| Vendor VM | 6 | PASS |
| Total readiness | 35 | PASS |

The 7 block checks are included in the 35. E1-E8 remain separate. IPS/App-ID, NAC/PVLAN and HA are unverified. EMR uses plaintext HTTP on 443; the database is a TCP stand-in.

Evidence: part2_architecture_protocols/execution/results/ (offline, local_services and readiness records).
