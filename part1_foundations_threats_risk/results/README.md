# Part I run results (28 October 2026)

These are outputs from the repository's local Part I simulator and risk
register. They are **model results**, not observations from the VirtualBox
lab or a hospital network.

| File | Result |
|---|---|
| `scenarios.txt` | Five stateless-filter failures, UDP pseudo-state, App-ID and rule order demonstrated |
| `incidents.txt` | 17/17 firewall-path cases matched the expected rule and action; one same-VLAN F1 case is outside firewall coverage |
| `trace_radiology_to_emr_db.txt` | Radiology workstation to EMR SQL/1433 denied by G-03 |
| `heatmap_text.txt` | 14 risks: inherent 4 Critical and 10 High; residual 5 Medium and 9 Low |
| `heatmap_inherent.png`, `heatmap_residual.png` | Heat maps generated from `risk/risk_register.csv` |
| `part1_tests.txt` | 8 Part I tests passed |

Run from `part1_foundations_threats_risk/` with `PYTHONPATH=../common`:
`python -m fwsim scenarios`, `python -m fwsim incidents`,
`python -m fwsim trace 192.168.40.100 192.168.10.20 --dport 1433`,
and `python risk/heatmap.py --out-dir results`. The text heat map used
`python risk/heatmap.py --text`; tests used
`python -m pytest tests/test_fwsim.py -q` from the repository root.

The App-ID scenario now classifies SSH after the TCP handshake. The stateless
and stateful engines permit the classified payload packet on port 443; the
NGFW simulation denies it under R-03. The stateless example separately drops
the SYN-ACK because it has no reverse rule. The Part I data files parse as
14 risks, 11 assets, 7 STRIDE zones and 10 attack mappings.

The F1 laptop-to-pump packet would stay on the device VLAN. The simulator
cannot prove its denial: access-port admission and private VLAN isolation
need separate verification on suitable switch hardware. The residual risk
scores reflect the proposed controls and have not been validated by lab
evidence in this run.

The assignment's illustrative radiology-to-EMR-SQL permit conflicts with its
reported F2 incident. The project's final policy denies that flow; the
saved trace shows the corrected rule G-03.
