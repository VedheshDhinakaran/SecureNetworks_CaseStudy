# PB-1 Vendor laptop probing internal ranges (incident F3)

| | |
|---|---|
| **Triggers** | UC-04 (≥ 20 VW-01 denies in 5 min), UC-01 (denied in ≥ 3 zones in 60 s) |
| **Severity** | Medium, raised to High if UC-01 also fires |
| **Owner** | SOC (triage), Network (containment), SEC (vendor follow-up) |
| **Related rules** | VW-01, VW-02, VW-03, G-02, G-03 |

## 1. Triage (SOC, within 15 min)
1. Open the alert and note the source IP, first and last deny times and the zones targeted.
2. Pull the timeline:
   ```sh
   python3 part4_lab_monitoring_response/tools/timeline.py /var/log/opnsense.log \
       --rules-debug rules.debug --src <laptop-ip> --action block
   ```
3. Map IP to MAC and user from the DHCP lease and the wireless controller. Record the vendor name.
4. Decide: a mis-configured laptop (stale mapped drive, home proxy) or deliberate probing (ports 22/445/1433/3389, sequential sweeps). Probing continues to step 2.

## 2. Preserve (before any containment)
```sh
part4_lab_monitoring_response/ir/collect_evidence.sh PB1-<date>-<n> <laptop-ip>
```
Also export the wireless controller's client record and the DHCP lease history.

## 3. Isolate and verify (Network)
* Add a source deny for the IP and MAC at the top of the VENDOR-WIFI section, description `PB-1 <case-id> CHG<n>`.
* Deauthenticate and block the client on the wireless controller.
* Verify from a test laptop on vendor Wi-Fi: `nmap -sS -Pn -p 1433,2575,3389 192.168.10.20` shows *filtered* (verification test 1).

## 4. Rebuild and notify
* Tell the vendor's account manager in writing. The device is banned until the vendor confirms it has been cleaned.
* If anything other than VW-01 permitted traffic from this source (check VW-02 hits to unusual destinations), widen the case.

## 5. Close the gap
* Revoke any open VENDOR-MAINT tickets (VM-01/VM-02) for the same vendor.
* Review whether the vendor needs a different access path (VENDOR-MAINT via jump host) instead of Wi-Fi.

## Exit criteria
Source blocked, evidence hashed, vendor notified, no open VM tickets for the vendor, ticket closed with timeline attached.
