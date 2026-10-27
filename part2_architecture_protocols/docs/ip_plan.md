# VLAN and IP plan

Generated from `network/objects.yaml`. `*` = address from the case brief.

| Zone | VLAN | Subnet | Gateway | Trust | Owner |
|---|---|---|---|---|---|
| Z_HIS | 10 | 192.168.10.0/24* | 192.168.10.1 | high | Head of IT |
| Z_DMZ | 20 | 192.168.20.0/24* | 192.168.20.1 | low | Head of IT |
| Z_DEVICES | 30 | 192.168.30.0/24* | 192.168.30.1 | restricted | Biomedical engineering |
| Z_RADIOLOGY | 40 | 192.168.40.0/24* | 192.168.40.1 | medium | Head of radiology |
| Z_CLINICAL | 50 | 192.168.50.0/23 | 192.168.50.1 | medium | Nursing director |
| Z_GUEST | 60 | 10.60.0.0/22 | 10.60.0.1 | untrusted | Facilities |
| Z_VENDOR_WIFI | 61 | 10.61.0.0/24 | 10.61.0.1 | untrusted | Procurement |
| Z_RESEARCH | 70 | 192.168.70.0/24 | 192.168.70.1 | medium | Research director |
| Z_VENDOR_MAINT | 80 | 192.168.80.0/24 | 192.168.80.1 | low | Biomedical engineering |
| Z_MGMT | 90 | 192.168.90.0/24 | 192.168.90.1 | highest | Head of IT security |
| QUARANTINE | 999 | none | none | none | Network team |

## Named hosts

| Object | Address | Zone | Role |
|---|---|---|---|
| H_EMR_DB | 192.168.10.20* | Z_HIS | EMR database (MSSQL 1433) |
| H_EMR_APP | 192.168.10.21 | Z_HIS | EMR application (HTTPS 443) |
| H_PHARMACY | 192.168.10.30 | Z_HIS | Pharmacy application |
| H_BILLING | 192.168.10.35 | Z_HIS | Billing application (PCI DSS scope) |
| H_IFENGINE | 192.168.10.40* | Z_HIS | HL7 interface engine (MLLP 2575) |
| H_DNS | 192.168.10.53* | Z_HIS | Internal resolver |
| H_NTP | 192.168.10.57* | Z_HIS | Internal NTP (stratum 2) |
| H_AD | 192.168.10.60 | Z_HIS | Directory (LDAPS 636, Kerberos 88) |
| H_DEID | 192.168.10.70 | Z_HIS | De-identification server |
| H_PORTAL | 192.168.20.10* | Z_DMZ | Patient portal reverse proxy |
| H_MAILRELAY | 192.168.20.25 | Z_DMZ | Outbound SMTP relay |
| H_PROXY | 192.168.20.40 | Z_DMZ | Explicit web proxy for research |
| H_PACS | 192.168.40.10 | Z_RADIOLOGY | PACS server |
| H_PACS_ARCH | 192.168.40.11 | Z_RADIOLOGY | PACS archive |
| H_PACS_BROKER | 192.168.40.12 | Z_RADIOLOGY | RIS/PACS broker (HL7 to interface engine) |
| H_SFTP_DROP | 192.168.70.250 | Z_RESEARCH | Research SFTP drop |
| H_JUMP | 192.168.80.10 | Z_VENDOR_MAINT | Vendor jump host (recorded) |
| H_FW_MGMT | 192.168.90.1 | Z_MGMT | Firewall management interface |
| H_BASTION | 192.168.90.5 | Z_MGMT | Administrator bastion |
| H_SIEM | 192.168.90.10 | Z_MGMT | SIEM / syslog-TLS collector |
| H_BACKUP | 192.168.90.20 | Z_MGMT | Backup server |
| H_NMS | 192.168.90.30 | Z_MGMT | Network monitoring (SNMPv3) |
| H_DR_BACKUP | 10.200.0.10 | DR | Off-site backup target |
