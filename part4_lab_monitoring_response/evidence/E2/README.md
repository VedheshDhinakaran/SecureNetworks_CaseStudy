# E2: Segmentation enforced

Script: `experiments/e2_segmentation.sh`  ·  Run on: rad-vm, vendor-vm, bastion  ·  Report: Section 11.5

## Expected (from the report)

- Radiology -> EMR DB 1433: filtered, G-03 in log
- Radiology -> EMR app 443: permitted (R-03)
- Broker / non-broker -> 2575: permitted / blocked
- Vendor -> 1433, 2575, 3389: filtered
- Vendor -> internet: permitted

## Observed (fill in from the real run)

| Test | Observed | Matches expected? | Transcript / screenshot |
|---|---|---|---|
| Radiology -> EMR DB 1433 | TO FILL | TO FILL | TO FILL |
| Radiology -> EMR app 443 | TO FILL | TO FILL | TO FILL |
| Broker / non-broker -> 2575 | TO FILL | TO FILL | TO FILL |
| Vendor -> 1433, 2575, 3389 | TO FILL | TO FILL | TO FILL |
| Vendor -> internet | TO FILL | TO FILL | TO FILL |

## Captures required

- [ ] nmap and curl outputs
- [ ] Live View filtered on 192.168.40.100 showing the G-03 blocks

## Notes and deviations

TO FILL: anything that went differently, and why.
