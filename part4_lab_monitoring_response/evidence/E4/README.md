# E4: Stateless versus stateful

Script: `experiments/e4_stateless_vs_stateful.sh`  ·  Run on: rad-vm, his-vm, bastion  ·  Report: Section 11.5

## Expected (from the report)

- Stateless, no reverse rule: silent timeout
- Stateless reverse rule abused (-g 443): 8080 open
- Stateful, same scan: filtered

## Observed (fill in from the real run)

| Test | Observed | Matches expected? | Transcript / screenshot |
|---|---|---|---|
| Stateless, no reverse rule | TO FILL | TO FILL | TO FILL |
| Stateless reverse rule abused (-g 443) | TO FILL | TO FILL | TO FILL |
| Stateful, same scan | TO FILL | TO FILL | TO FILL |

## Captures required

- [ ] tcpdump from step 1
- [ ] nmap from steps 3 and 4
- [ ] state-table entry for the curl session

## Notes and deviations

TO FILL: anything that went differently, and why.
