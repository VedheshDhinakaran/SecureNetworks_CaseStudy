# Part I: Firewall foundations, threats and risk

**Owner:** Janhavi Harish Kulkarni (CSE23127) · **Report:** Chapters 2, 3 and 4

This part turns the theory chapters into something that can be run. The
simulator shows *why* a stateless filter fails, on the same rule base the
rest of the project uses, and replays the three incidents against both the
old and the new design.

## Contents

| Path | What it is | Report |
|---|---|---|
| `fwsim/engines.py` | `StatelessFilter` and `StatefulFirewall` (TCP state machine, UDP/ICMP pseudo-state, timeouts). `ngfw=True` adds the App-ID check | 2.3, 2.5, 2.6 |
| `fwsim/nat.py` | Port address translation table kept next to the state table | 2.5 |
| `fwsim/scenarios.py` | The five stateless failures (direction, intent, spoofing, translation, UDP), App-ID and rule order, each run through stateless vs stateful vs NGFW | Table 2.1, Listing 2.1 |
| `fwsim/incidents.py` | 18 cases from F1–F3 and the risk register replayed through the old flat design and the new policy | Table 3.4 |
| `fwsim/legacy_policy.yaml` | The brief's original edge filter (L-1 … L-5) | 1, 9 |
| `threat_model/stride.yaml` | STRIDE per zone | Table 3.3 |
| `threat_model/attack_mapping.csv` | Threats mapped to MITRE ATT&CK techniques | Table 3.2 |
| `risk/assets.csv` | Asset register with CIA ratings | Table 3.1 |
| `risk/risk_register.csv` | R1–R14, inherent and residual likelihood × impact | Table 4.1 |
| `risk/heatmap.py` | Draws the inherent / residual heat maps (Figures 4.1, 4.2) | 4 |

## Run

From the repository root (`make sim` does the first two):

```sh
cd part1_foundations_threats_risk
PYTHONPATH=../common python3 -m fwsim scenarios      # five failures, App-ID, rule order
PYTHONPATH=../common python3 -m fwsim incidents      # F1-F3 old vs new
PYTHONPATH=../common python3 -m fwsim trace 192.168.40.100 192.168.10.20 --dport 1433
python3 risk/heatmap.py --text                       # or --out-dir figures for PNGs
```

`trace` takes `--proto`, `--flags`, `--group GRP_CLINICIANS`, `--path /portal/x`
and `--app ssh` so any single packet can be checked against the real policy.

## Limits
The simulator models the packet filter, the state table and the App-ID
decision. IPS, URL filtering and TLS inspection are shown only as rule
fields; their behaviour is tested in the lab (Part IV, E6 and E7).
