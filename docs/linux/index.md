---
title: "1. Linux"
nav_order: 2
has_children: true
---

# Linux

Eight pages, deepest coverage in the repo. Linux-first because most servers, containers,
and cloud workloads run it - and because the kernel telemetry (auditd, eBPF, Falco) is
more transparent and easier to reason about than Windows ETW.

| Page | Covers |
|---|---|
| [Host Triage & Awareness](01-host-triage-and-situational-awareness) | Reading the environment quietly before you touch it |
| [Process Stealth](02-process-stealth-and-masquerading) | argv/comm spoofing, memfd, fileless exec |
| [Persistence Stealth](03-persistence-stealth) | systemd, cron, udev, PAM, LD_PRELOAD |
| [Log & Anti-Forensics](04-log-and-anti-forensics) | auth.log, utmp/wtmp, journald, history, timestomping |
| [Living Off the Land](05-living-off-the-land) | GTFOBins, native interpreters, avoiding dropped binaries |
| [Network Stealth & Tunneling](06-network-stealth-and-tunneling) | Egress selection, SSH tunnels, traffic blending |
| [EDR & Kernel Evasion](07-edr-and-kernel-telemetry-evasion) | auditd, eBPF, ptrace, what is and is not hookable |
| [Credential Access & Lateral Movement](08-credential-access-and-lateral-movement) | SSH keys/agent, quiet pivoting, lockout avoidance |
