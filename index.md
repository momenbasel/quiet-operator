---
title: Home
nav_order: 0
description: "A purple-team field manual for staying stealthy on the host and on the wire."
permalink: /
---

# Quiet Operator

**A purple-team field manual for staying stealthy on the host and on the wire.**

Tradecraft for *authorized* red team operations, paired page-for-page with the
**detection telemetry** defenders use to catch it. Linux-first. Every offensive
page ends with the exact log source, event ID, and hunt query that catches it.

{: .warning }
**Authorized engagements only.** Read [DISCLAIMER](DISCLAIMER) before anything else.
Use this material only with written scope (ROE/SOW), in your own lab, or in a CTF.

---

## Who this is for

<div class="feature-grid">
<div class="feature-card">
<h3>Red Team Operator</h3>
<p>Start with <a href="docs/00-foundations/operator-opsec-model">Foundations</a> then your target OS. Use OPSEC notes to pick the quiet variant. Use the Detection section to know your blast radius.</p>
</div>
<div class="feature-card">
<h3>Blue Teamer / SOC</h3>
<p>Go straight to <a href="docs/detection-mapping/">Detection Mapping</a>. Every technique is indexed by log source, event ID, and hunt query. The <a href="docs/detection-mapping/base64-and-encoding-telemetry">base64 telemetry page</a> is written for you.</p>
</div>
<div class="feature-card">
<h3>Purple Team</h3>
<p>Start with <a href="docs/00-foundations/threat-model-and-telemetry">Threat Model & Telemetry</a> for a shared vocabulary of what each technique looks like to the SOC.</p>
</div>
</div>

---

## The thesis

<div class="stats-grid">
  <div class="stat-card"><div class="stat-number">27</div><div class="stat-label">Technique pages</div></div>
  <div class="stat-card"><div class="stat-number">8</div><div class="stat-label">Linux pages</div></div>
  <div class="stat-card"><div class="stat-number">6</div><div class="stat-label">Data transfer</div></div>
  <div class="stat-card"><div class="stat-number">50+</div><div class="stat-label">ATT&amp;CK IDs mapped</div></div>
</div>

Every action has a cost paid in artifacts: a disk write, a spawned process, an outbound
connection, an auth event, a log line. Good tradecraft is choosing the **cheapest path in
artifacts** that still gets the job done - and knowing exactly who is collecting each one.

Three rules the whole repo is built on:

1. **Avoid generating the artifact - do not try to delete it.** In a world of central SIEM
   and log forwarding, local deletion is near-useless and is itself a screaming IOC.
2. **Native and expected beats novel and dropped** - but command-line and behavioral telemetry
   still capture you. Living off the land defeats AV signatures, not EDR lineage.
3. **Regularity and volume are the meta-tells.** Fixed intervals and fixed sizes get you caught
   long after the payload was "undetectable."

---

## The base64 lesson

Operators reach for `base64` constantly. It is worth being direct about what it costs:

- **It is encoding, not encryption.** Any analyst decodes it in one command.
- **`... | base64 -d | sh` is one of the most-signatured patterns in existence.** auditd,
  Falco, Sigma, and commercial EDR all fire on it. Windows `certutil -decode` and PowerShell
  `-EncodedCommand` are the direct equivalents - and Script Block Log EID 4104 records the
  *decoded* content.
- **On the wire**, long base64 strings in HTTP bodies, URLs, and DNS labels are matched by
  Suricata content rules and proxy DLP by default.

Full treatment: [Encoding, Compression & Encryption](docs/data-transfer/02-encoding-compression-encryption) and the dedicated deep-dive [base64 & Encoding Telemetry](docs/detection-mapping/base64-and-encoding-telemetry).

---

## Want to practice on real boxes?

Apply these techniques against HackTheBox machines - a legal, controlled environment with
real operating systems and real defenses.

**[HTB Writeups - momenbasel.github.io/htb-writeups](https://momenbasel.github.io/htb-writeups/)**

---

## Quick start

```
1. Read DISCLAIMER - confirm you have written authorization in scope.
2. Read docs/00-foundations/ - OPSEC model, ROE, defender threat model.
3. Open the page for your task. Read it bottom-up:
   - "Detection & telemetry" first  -> know what you are about to generate.
   - "OPSEC notes"                  -> pick the quiet variant.
   - "Technique"                    -> the how.
4. Cross-check docs/detection-mapping/ to see how a SOC would catch you.
```
