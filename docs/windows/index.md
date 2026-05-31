---
title: "3. Windows"
nav_order: 4
has_children: true
---

# Windows

Five pages covering the Windows-specific stealth surface. Lighter than Linux because
ETW, Sysmon, and PowerShell logging are well-documented - but no less important for
engagements that touch Windows endpoints or AD environments.

| Page | Covers |
|---|---|
| [Process Stealth](01-process-stealth) | PPID spoofing, masquerading, cmdline logging awareness |
| [Persistence Stealth](02-persistence-stealth) | Run keys, tasks, services, WMI - with event trails |
| [Log & Anti-Forensics](03-log-and-anti-forensics) | Security/PowerShell/Sysmon logs, ETW, log-clear cost |
| [LOLBAS & Execution](04-lolbas-and-execution) | Signed-binary proxy execution and the telemetry it still emits |
| [EDR Evasion: AMSI & ETW](05-edr-evasion-amsi-etw) | AMSI, ETW, Script Block Logging, PowerShell 4104 |
