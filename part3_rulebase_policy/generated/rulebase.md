### Section 0 - Global protections

| ID | Source | Destination | Service | Action | Log | Owner | Requirement |
|---|---|---|---|---|---|---|---|
| G-01 | G_THREAT_FEEDS | any | any | deny | A | SEC | Drop known-bad sources and destinations before any permit |
| G-02 | any except Z_MGMT | Z_MGMT except H_SIEM, H_BACKUP | any | deny | A | SEC | Management plane unreachable from user zones |
| G-03 | any except Z_HIS, H_BASTION, H_NMS | H_EMR_DB | any | deny | A | IT | No zone outside HIS ever reaches the EMR database (incident F2) |
| G-04 | any except H_DNS, H_PROXY, Z_GUEST, Z_VENDOR_WIFI | internet | S_DNS, S_DOT | deny | A | SEC | Stop DNS bypass and DNS tunnelling |

### Section 1 - MGMT

| ID | Source | Destination | Service | Action | Log | Owner | Requirement |
|---|---|---|---|---|---|---|---|
| M-01 | H_BASTION | G_MGMT_TARGETS | S_SSH, S_HTTPS | permit | Y | SEC | Administration only from the bastion |
| M-02 | H_BASTION | Z_HIS, Z_DMZ, Z_RESEARCH | S_SSH, S_RDP | permit | Y | IT | Server administration |
| M-03 | H_NMS | Z_HIS, Z_DMZ | S_SNMP | permit | Y | IT | Health monitoring with SNMPv3 |
| M-04 | Z_HIS, Z_DMZ, Z_RESEARCH, H_JUMP | H_SIEM | S_SYSLOG_TLS | permit | Y | SEC | Central logging |
| M-05 | H_BACKUP | H_DR_BACKUP | S_BACKUP | permit | Y | IT | Off-site backup copy over the DR IPsec tunnel |
| M-06 | H_BASTION, H_SIEM | internet | S_HTTPS | permit | Y | SEC | Patches and signature updates |
| M-07 | Z_MGMT | any | any | deny | A | SEC | MGMT default deny |

### Section 2 - HIS

| ID | Source | Destination | Service | Action | Log | Owner | Requirement |
|---|---|---|---|---|---|---|---|
| H-01 | G_HIS_SERVERS | H_BACKUP | S_BACKUP | permit | Y | IT | Backup out (brief) |
| H-02 | H_EMR_APP, H_IFENGINE | F_EPRESCRIBE, F_LABPARTNER | S_HTTPS | permit | Y | IT | E-prescribing and external lab results |
| H-03 | G_HIS_SERVERS | H_MAILRELAY | S_SMTP | permit | Y | IT | Application notifications |
| H-04 | H_DEID | H_SFTP_DROP | S_SSH | permit | Y | RES | De-identified extracts pushed to research |
| H-05 | H_IFENGINE | H_PACS_BROKER | S_MLLP | permit | Y | RAD | Orders sent to radiology |
| H-06 | H_NTP | F_NTP_UPSTREAM | S_NTP | permit | Y | IT | Upstream time traceable to IST (CERT-In) |
| H-07 | H_DNS | internet | S_DNS | permit | Y | IT | Recursive resolution |
| H-08 | Z_HIS | any | any | deny | A | IT | HIS default deny |

### Section 3 - DMZ (outbound)

| ID | Source | Destination | Service | Action | Log | Owner | Requirement |
|---|---|---|---|---|---|---|---|
| D-01 | internet | H_PORTAL | S_HTTPS | deny | A | IT | Admin path never public |
| D-02 | internet | H_PORTAL | S_HTTPS | permit | Y | IT | Patient portal |
| D-03 | H_PORTAL | H_EMR_APP | S_HTTPS | permit | Y | IT | Portal back end |
| D-04 | H_MAILRELAY | internet | S_SMTP | permit | Y | IT | Outbound mail |
| D-05 | H_PROXY | internet | S_WEB | permit | Y | RES | Research inspected egress |
| D-06 | internet | EDGE_IPSEC | S_IKE | permit | Y | SEC | Vendor and DR tunnels |
| D-07 | Z_DMZ | any | any | deny | A | IT | DMZ default deny |

### Section 3b - Inbound from internet

| ID | Source | Destination | Service | Action | Log | Owner | Requirement |
|---|---|---|---|---|---|---|---|
| D-08 | internet | any | any | deny | Y | SEC | Inbound default deny |

### Section 4 - DEVICES

| ID | Source | Destination | Service | Action | Log | Owner | Requirement |
|---|---|---|---|---|---|---|---|
| DV-01 | Z_DEVICES | H_DNS | S_DNS | permit | Y | BIO | Name resolution |
| DV-02 | Z_DEVICES | H_NTP | S_NTP | permit | Y | BIO | Time |
| DV-03 | Z_DEVICES | H_IFENGINE | S_MLLP | permit | Y | BIO | Device data to EMR |
| DV-04 | Z_DEVICES | Z_DEVICES | any | deny | A | BIO | No peer traffic (with PVLAN) |
| DV-05 | Z_DEVICES | any | any | deny | A | BIO | Strict egress default |

### Section 5 - RADIOLOGY

| ID | Source | Destination | Service | Action | Log | Owner | Requirement |
|---|---|---|---|---|---|---|---|
| R-01 | Z_RADIOLOGY | G_CORE | S_CORE | permit | Y | RAD | DNS, time, logon |
| R-02 | H_PACS_BROKER | H_IFENGINE | S_MLLP | permit | Y | RAD | Results and status to EMR |
| R-03 | Z_RADIOLOGY (user group GRP_RADIOLOGISTS) | H_EMR_APP | S_HTTPS | permit | Y | RAD | Clinical context while reporting |
| R-04 | H_PACS_ARCH | H_DR_BACKUP | S_DICOM_TLS | permit | Y | RAD | Off-site image copy |
| R-05 | H_PACS | F_TELERAD | S_DICOM_TLS, S_HTTPS | permit | Y | RAD | Teleradiology |
| R-06 | Z_RADIOLOGY | any | any | deny | A | RAD | Radiology default deny (incl. internet) |

### Section 6 - CLINICAL

| ID | Source | Destination | Service | Action | Log | Owner | Requirement |
|---|---|---|---|---|---|---|---|
| C-01 | Z_CLINICAL | G_CORE | S_CORE | permit | Y | NUR | DNS, time, logon |
| C-02 | Z_CLINICAL (user group GRP_CLINICIANS) | H_EMR_APP | S_HTTPS | permit | Y | NUR | EMR access |
| C-03 | Z_CLINICAL (user group GRP_PHARMACISTS) | H_PHARMACY | S_HTTPS | permit | Y | NUR | Pharmacy system |
| C-04 | Z_CLINICAL (user group GRP_BILLING) | H_BILLING | S_HTTPS | permit | Y | FIN | Billing (PCI scope) |
| C-05 | Z_CLINICAL (user group GRP_CLINICIANS) | H_PACS | S_HTTPS | permit | Y | RAD | Images at the bedside |
| C-06 | Z_CLINICAL (user group GRP_BIOMED) | H_JUMP | S_RDP | permit | Y | BIO | Device maintenance via jump host |
| C-07 | Z_CLINICAL | internet | S_WEB | permit | Y | NUR | Internet (brief) |
| C-08 | Z_CLINICAL | any | any | deny | A | NUR | Clinical default deny |

### Section 7 - GUEST

| ID | Source | Destination | Service | Action | Log | Owner | Requirement |
|---|---|---|---|---|---|---|---|
| GW-01 | Z_GUEST | N_RFC1918 | any | deny | Y | FAC | No internal reach |
| GW-02 | Z_GUEST | internet | S_WEB, S_DNS | permit | Y | FAC | Internet only (brief) |
| GW-03 | Z_GUEST | any | any | deny | Y | FAC | Guest default deny |

### Section 8 - VENDOR-WIFI

| ID | Source | Destination | Service | Action | Log | Owner | Requirement |
|---|---|---|---|---|---|---|---|
| VW-01 | Z_VENDOR_WIFI | N_RFC1918 | any | deny | A | SEC | Replaces the old any-any (incident F3) |
| VW-02 | Z_VENDOR_WIFI | internet | S_WEB, S_DNS, S_IKE | permit | Y | SEC | Internet only (brief) |
| VW-03 | Z_VENDOR_WIFI | any | any | deny | A | SEC | Vendor Wi-Fi default deny |

### Section 9 - RESEARCH

| ID | Source | Destination | Service | Action | Log | Owner | Requirement |
|---|---|---|---|---|---|---|---|
| RS-01 | Z_RESEARCH | H_DNS, H_NTP | S_CORE_MIN | permit | Y | RES | DNS and time |
| RS-02 | Z_RESEARCH | H_PROXY | S_PROXY | permit | Y | RES | Inspected egress via proxy (brief) |
| RS-03 | Z_RESEARCH | Z_HIS | any | deny | A | RES | Research never reaches clinical data |
| RS-04 | Z_RESEARCH | any | any | deny | A | RES | Research default deny |

### Section 10 - VENDOR-MAINT

| ID | Source | Destination | Service | Action | Log | Owner | Requirement |
|---|---|---|---|---|---|---|---|
| VM-01 | N_VPN_POOL | H_JUMP | S_RDP, S_SSH | permit | Y | BIO | Vendor reaches jump host only during ticket window |
| VM-02 | H_JUMP | TICKET_DEVICE | TICKET_PORT | permit | A | BIO | Template: created per ticket, disabled otherwise |
| VM-03 | Z_VENDOR_MAINT | any | any | deny | A | BIO | Vendor default deny |

### Section 11 - Final deny

| ID | Source | Destination | Service | Action | Log | Owner | Requirement |
|---|---|---|---|---|---|---|---|
| X-99 | any | any | any | deny | A | SEC | Global default deny; any hit means a zone section is incomplete |
