# MITRE ATT&CK Crosswalk

*Every technique covered in this repo, indexed by ATT&CK tactic and technique ID.*

## Coverage notes

This repo covers Defense Evasion, Persistence, Discovery, Credential Access, Lateral Movement,
Collection, Command and Control, and Exfiltration tactics in depth. Initial Access and Execution
are referenced where relevant but are not the primary focus. Reconnaissance and Resource
Development are covered in the foundations and C2 infrastructure sections respectively.

---

## Master table

| Tactic | ID | Technique name | Repo page(s) | Best telemetry source |
|---|---|---|---|---|
| **Reconnaissance** | T1592 | Gather Victim Host Information | [linux/01](../linux/01-host-triage-and-situational-awareness.md) | auditd execve, EDR process |
| **Resource Development** | T1583 | Acquire Infrastructure | [c2-infra/03](../c2-infrastructure/03-infrastructure-segregation-and-opsec.md) | Passive DNS, cert transparency |
| **Resource Development** | T1584 | Compromise Infrastructure | [c2-infra/01](../c2-infrastructure/01-redirectors-and-domain-fronting.md) | Threat intel feeds |
| **Execution** | T1059.004 | Unix Shell | [linux/05](../linux/05-living-off-the-land.md) | auditd execve, EDR |
| **Execution** | T1059.001 | PowerShell | [windows/05](../windows/05-edr-evasion-amsi-etw.md) | Sysmon EID 1, EID 4104 |
| **Execution** | T1059.003 | Windows Command Shell | [windows/01](../windows/01-process-stealth.md) | EID 4688, Sysmon EID 1 |
| **Execution** | T1218 | System Binary Proxy Execution | [windows/04](../windows/04-lolbas-and-execution.md), [linux/05](../linux/05-living-off-the-land.md) | Sysmon EID 1, cmdline |
| **Execution** | T1218.001 | Compiled HTML File (mshta) | [windows/04](../windows/04-lolbas-and-execution.md) | Sysmon EID 1 |
| **Execution** | T1218.011 | Rundll32 | [windows/04](../windows/04-lolbas-and-execution.md) | Sysmon EID 1, EID 7 |
| **Persistence** | T1053.003 | Scheduled Task/Job: Cron | [linux/03](../linux/03-persistence-stealth.md) | cron syslog, auditd |
| **Persistence** | T1053.005 | Scheduled Task/Job: Scheduled Task | [windows/02](../windows/02-persistence-stealth.md) | EID 4698, Task Scheduler log |
| **Persistence** | T1543.002 | Create or Modify System Process: Systemd | [linux/03](../linux/03-persistence-stealth.md) | journald, systemd unit events |
| **Persistence** | T1543.003 | Create or Modify System Process: Windows Service | [windows/02](../windows/02-persistence-stealth.md) | EID 7045, EID 4697 |
| **Persistence** | T1547.001 | Boot or Logon Autostart: Registry Run Keys | [windows/02](../windows/02-persistence-stealth.md) | Sysmon EID 13, EID 4657 |
| **Persistence** | T1546.003 | Event Triggered Execution: WMI Event Subscription | [windows/02](../windows/02-persistence-stealth.md) | Sysmon EID 19/20/21 |
| **Persistence** | T1098.004 | Account Manipulation: SSH Authorized Keys | [linux/03](../linux/03-persistence-stealth.md), [linux/08](../linux/08-credential-access-and-lateral-movement.md) | auditd file watch, auth.log |
| **Persistence** | T1574.006 | Hijack Execution Flow: LD_PRELOAD | [linux/03](../linux/03-persistence-stealth.md) | auditd, FIM on ld.so.preload |
| **Defense Evasion** | T1070.002 | Indicator Removal: Clear Linux or Mac System Logs | [linux/04](../linux/04-log-and-anti-forensics.md) | auditd config-change, SIEM gap |
| **Defense Evasion** | T1070.001 | Indicator Removal: Clear Windows Event Logs | [windows/03](../windows/03-log-and-anti-forensics.md) | EID 1102 / 104, WEF |
| **Defense Evasion** | T1070.006 | Indicator Removal: Timestomp | [linux/04](../linux/04-log-and-anti-forensics.md), [windows/03](../windows/03-log-and-anti-forensics.md) | FIM, MFT FN vs SI |
| **Defense Evasion** | T1036 | Masquerading | [linux/02](../linux/02-process-stealth-and-masquerading.md), [windows/01](../windows/01-process-stealth.md) | EDR comm/argv mismatch |
| **Defense Evasion** | T1036.004 | Masquerading: Masquerade Task or Service | [windows/01](../windows/01-process-stealth.md), [linux/02](../linux/02-process-stealth-and-masquerading.md) | Sysmon EID 1, path anomaly |
| **Defense Evasion** | T1055 | Process Injection (concept) | [linux/02](../linux/02-process-stealth-and-masquerading.md), [windows/01](../windows/01-process-stealth.md) | Sysmon EID 8/10, EDR |
| **Defense Evasion** | T1027 | Obfuscated Files or Information | [data-transfer/02](../data-transfer/02-encoding-compression-encryption.md) | auditd execve, EDR |
| **Defense Evasion** | T1027.003 | Steganography | [data-transfer/05](../data-transfer/05-covert-channels.md) | DLP, steg detection tools |
| **Defense Evasion** | T1132 | Data Encoding | [data-transfer/02](../data-transfer/02-encoding-compression-encryption.md), [detection-mapping/base64](../detection-mapping/base64-and-encoding-telemetry.md) | auditd, IDS, proxy DLP |
| **Defense Evasion** | T1132.001 | Standard Encoding (base64/base32) | [data-transfer/02](../data-transfer/02-encoding-compression-encryption.md), [detection-mapping/base64](../detection-mapping/base64-and-encoding-telemetry.md) | auditd execve, Suricata |
| **Defense Evasion** | T1562.001 | Impair Defenses: Disable or Modify Tools | [linux/07](../linux/07-edr-and-kernel-telemetry-evasion.md) | auditd daemon-stop, sensor gap |
| **Defense Evasion** | T1562.006 | Impair Defenses: Indicator Blocking | [linux/07](../linux/07-edr-and-kernel-telemetry-evasion.md), [windows/05](../windows/05-edr-evasion-amsi-etw.md) | ETW tamper, EDR alert |
| **Defense Evasion** | T1620 | Reflective Code Loading | [linux/02](../linux/02-process-stealth-and-masquerading.md) | memfd_create + execve, Falco |
| **Defense Evasion** | T1202 | Indirect Command Execution | [linux/05](../linux/05-living-off-the-land.md), [windows/04](../windows/04-lolbas-and-execution.md) | cmdline anomaly, parent-child |
| **Credential Access** | T1552.001 | Unsecured Credentials: Credentials In Files | [linux/08](../linux/08-credential-access-and-lateral-movement.md) | auditd file watch, EDR |
| **Credential Access** | T1552.004 | Private Keys | [linux/08](../linux/08-credential-access-and-lateral-movement.md) | auditd watch on ~/.ssh/ |
| **Credential Access** | T1550.001 | Use Alternate Authentication: Application Access Token | [linux/08](../linux/08-credential-access-and-lateral-movement.md) | auth.log, UEBA |
| **Discovery** | T1082 | System Information Discovery | [linux/01](../linux/01-host-triage-and-situational-awareness.md), [00-foundations](../00-foundations/threat-model-and-telemetry.md) | auditd execve burst |
| **Discovery** | T1049 | System Network Connections Discovery | [linux/01](../linux/01-host-triage-and-situational-awareness.md) | auditd execve (ss, netstat) |
| **Discovery** | T1069 | Permission Groups Discovery | [linux/01](../linux/01-host-triage-and-situational-awareness.md) | auditd execve (id, groups) |
| **Discovery** | T1083 | File and Directory Discovery | [linux/01](../linux/01-host-triage-and-situational-awareness.md) | auditd execve (find, ls) |
| **Lateral Movement** | T1021.004 | Remote Services: SSH | [linux/06](../linux/06-network-stealth-and-tunneling.md), [linux/08](../linux/08-credential-access-and-lateral-movement.md) | auth.log, netflow, UEBA |
| **Lateral Movement** | T1090.001 | Proxy: Internal Proxy | [linux/06](../linux/06-network-stealth-and-tunneling.md) | netflow, Zeek conn.log |
| **Collection** | T1005 | Data from Local System | [data-transfer/01](../data-transfer/01-exfil-principles-and-staging.md) | auditd file-read burst |
| **Collection** | T1074.001 | Data Staged: Local | [data-transfer/01](../data-transfer/01-exfil-principles-and-staging.md) | auditd O_CREAT, EDR file |
| **Collection** | T1560.001 | Archive Collected Data: Archive via Utility | [data-transfer/01](../data-transfer/01-exfil-principles-and-staging.md), [data-transfer/02](../data-transfer/02-encoding-compression-encryption.md) | auditd execve (tar), EDR |
| **Command and Control** | T1071.001 | Application Layer Protocol: Web Protocols | [c2-infra/01](../c2-infrastructure/01-redirectors-and-domain-fronting.md), [data-transfer/04](../data-transfer/04-https-and-cloud-exfil.md) | Zeek ssl.log, JA3/JA4, proxy |
| **Command and Control** | T1090.004 | Proxy: Domain Fronting | [c2-infra/01](../c2-infrastructure/01-redirectors-and-domain-fronting.md) | SNI/Host mismatch, cert CT |
| **Command and Control** | T1568 | Dynamic Resolution | [c2-infra/01](../c2-infrastructure/01-redirectors-and-domain-fronting.md) | DNS query log, passive DNS |
| **Command and Control** | T1571 | Non-Standard Port | [linux/06](../linux/06-network-stealth-and-tunneling.md) | NetFlow, firewall deny |
| **Command and Control** | T1572 | Protocol Tunneling | [linux/06](../linux/06-network-stealth-and-tunneling.md) | Zeek, NetFlow session metadata |
| **Command and Control** | T1573 | Encrypted Channel | [c2-infra/02](../c2-infrastructure/02-malleable-profiles-and-jitter.md), [data-transfer/04](../data-transfer/04-https-and-cloud-exfil.md) | JA3/JA4, cert, SNI |
| **Command and Control** | T1008 | Fallback Channels | [c2-infra/03](../c2-infrastructure/03-infrastructure-segregation-and-opsec.md) | Multiple infra destinations |
| **Exfiltration** | T1048 | Exfiltration Over Alternative Protocol | [data-transfer/03](../data-transfer/03-dns-tunneling.md), [data-transfer/04](../data-transfer/04-https-and-cloud-exfil.md) | NetFlow, DNS query log |
| **Exfiltration** | T1048.002 | Exfil: Asymmetric Encrypted Non-C2 Protocol | [data-transfer/04](../data-transfer/04-https-and-cloud-exfil.md) | NetFlow upload volume |
| **Exfiltration** | T1029 | Scheduled Transfer | [data-transfer/06](../data-transfer/06-out-of-band-and-throttling.md) | NetFlow periodicity |
| **Exfiltration** | T1030 | Data Transfer Size Limits | [data-transfer/06](../data-transfer/06-out-of-band-and-throttling.md) | DLP size thresholds |
| **Exfiltration** | T1041 | Exfiltration Over C2 Channel | [c2-infra/01](../c2-infrastructure/01-redirectors-and-domain-fronting.md) | JA3, beaconing |
| **Exfiltration** | T1052.001 | Exfil Over Physical Medium: USB | [data-transfer/06](../data-transfer/06-out-of-band-and-throttling.md) | EID 4663, udev, USBSTOR |
| **Exfiltration** | T1095 | Non-Application Layer Protocol | [data-transfer/05](../data-transfer/05-covert-channels.md) | ICMP anomaly, Suricata |
| **Exfiltration** | T1567.002 | Exfil to Cloud Storage | [data-transfer/04](../data-transfer/04-https-and-cloud-exfil.md) | CASB, proxy log, DLP |

---

## Detection priorities for SOC / threat hunters

Pages are ordered by detection ROI - highest signal first.

1. **Command-line auditing** - auditd `execve` (Linux) and EID 4688 + Sysmon EID 1 (Windows).
   Catches the overwhelming majority of techniques in this repo with a single data source.
2. **Process parent-child lineage** - anomalous spawning (web server -> shell, document -> mshta).
3. **NetFlow / IPFIX outbound volume anomalies** - upload asymmetry, off-baseline volume.
4. **New or rare outbound destinations** - UEBA, newly-seen-domain, low-reputation DNS.
5. **Persistence location FIM** - auditd watches on cron/systemd/Run-key paths; Sysmon EID 13.
6. **Sensitive file access** - id_rsa, credentials, shadow, SAM; auditd file watches; EDR.
7. **Log clearing events** - Linux auditd config-change + daemon stop; Windows EID 1102/104.
8. **TLS metadata** - JA3/JA4 fingerprints, certificate age, SNI reputation.
9. **DNS analytics** - query volume per domain, label entropy, rare RR types.
10. **Beaconing/periodicity** - autocorrelation on connection timestamps to external hosts.

## References

- MITRE ATT&CK Enterprise matrix: https://attack.mitre.org/matrices/enterprise/
- ATT&CK Navigator (visualization): https://mitre-attack.github.io/attack-navigator/
- ATT&CK Data Sources index: https://attack.mitre.org/datasources/
- Sigma rule repository: https://github.com/SigmaHQ/sigma
- Elastic Detection Rules: https://github.com/elastic/detection-rules
