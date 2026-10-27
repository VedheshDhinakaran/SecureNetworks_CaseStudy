# PB-5 Bulk exfiltration over TLS

| | |
|---|---|
| **Triggers** | Upload > 2 GB per host per hour (telemetry), App-ID shows personal cloud storage, DLP match on D-05/C-07 |
| **Severity** | High; Critical if patient data is confirmed |
| **Owner** | SOC, CISO |
| **Related rules** | C-07, D-05, RS-02 |

## 1. Triage
1. Identify host, user and destination (SNI / App-ID name) from the NGFW session records.
2. Check the DLP match type and volume. Compare against the host's normal upload baseline.

## 2. Preserve
Export decrypted-session *metadata* (not content), proxy logs (H_PROXY) and flow records for the host for the last 7 days. Run `collect_evidence.sh`.

## 3. Isolate
Block the destination and the host's internet access (host deny above C-07 / RS-02). Keep EMR access (C-02) if clinical work must continue, so the response does not stop patient care.

## 4. Rebuild
Interview the user with HR present. Image the host if malware is suspected.

## 5. Notify (CISO)
* **CERT-In**: report within 6 hours of noticing, if the event is a reportable incident type under the April 2022 directions.
* **DPDP Act 2023**: if a personal-data breach occurred, intimate the Data Protection Board of India and affected data principals as the Act and its rules require.
* Record the decision and its timing in the case file.

## Exit criteria
Destination blocked, data volume and type established, notification decision recorded with timestamps.
