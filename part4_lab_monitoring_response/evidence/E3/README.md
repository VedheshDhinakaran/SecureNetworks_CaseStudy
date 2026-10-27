# E3: Device zone has three flows and nothing else

Script: `experiments/e3_device_zone.sh`  ·  Run on: pump-vm, bastion  ·  Report: Section 11.5

## Expected (from the report)

- Device DNS (UDP and TCP), NTP, MLLP: all succeed
- Device -> 1433, internet, radiology: all fail
- Counters DV-01..05: only DV-01..03 permit hits

## Observed (fill in from the real run)

| Test | Observed | Matches expected? | Transcript / screenshot |
|---|---|---|---|
| Device DNS (UDP and TCP), NTP, MLLP | TO FILL | TO FILL | TO FILL |
| Device -> 1433, internet, radiology | TO FILL | TO FILL | TO FILL |
| Counters DV-01..05 | TO FILL | TO FILL | TO FILL |

## Captures required

- [ ] pump-vm outputs
- [ ] pfctl -vvsr counters for DV-01 to DV-05 (run hit_counter_review.py --only DV-0 and save its output too)

## Notes and deviations

TO FILL: anything that went differently, and why.
