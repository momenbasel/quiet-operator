# Authorization, Scope & Rules of Engagement

*The legal and operational guardrails that turn intrusion into an authorized engagement, and the agreed indicators that let the blue team tell you apart from a real adversary.*

## What & why

Every technique in this repo is a crime without prior written authorization. The goal of this page is to define the paperwork, scope boundaries, data-handling discipline, and deconfliction channel that convert offensive activity into a sanctioned exercise, and to give the blue team the agreed markers that distinguish red-team traffic from a genuine breach. The OPSEC rationale is two-sided: scope and authorization protect the operator legally and protect the client from collateral damage, while the deconfliction indicators (source-IP allowlists, canary tokens, header markers, a 24/7 contact) let defenders investigate realistically without burning real-incident resources or escalating to law enforcement against their own contractors. Skipping any of this is the fastest way to convert a paid engagement into a federal case and a destroyed business relationship.

## Technique

This is a pre-engagement discipline, not an attack. The "steps" are the documents, controls, and channels you stand up before the first packet leaves your box, and the operational hygiene you maintain throughout.

### Written authorization (the non-negotiable)

No activity begins until you hold a signed document from a person with authority to grant it. The signer must legally own or control the assets in scope. If the client merely rents infrastructure (cloud, SaaS, shared hosting, third-party SOC), their signature does not cover the provider; see [Third-party and cloud-provider notification](#third-party-and-cloud-provider-notification).

Minimum contents of the authorization:

- Legal entity names of both parties and the specific signer with title and authority statement.
- Explicit asset list: IP ranges (CIDR), FQDNs, application URLs, account identifiers, mobile app package names, API base URLs.
- Time window: start and end dates, allowed hours (for example business-hours-only versus 24/7), and any blackout periods.
- Authorized techniques and explicit exclusions (for example "no denial-of-service", "no social engineering of staff", "no exfiltration of production PII").
- A statement that the client confirms it owns or has authority over all listed assets.
- Signature, printed name, and date for both parties.

Store the signed PDF and keep a printed copy on the operator's person during any on-site work. This printed copy is the get-out-of-jail letter; carry it physically when badge-cloning, lockpicking, or doing any activity where building security or police may detain you.

### Signed ROE and SOW

The Statement of Work (SOW) defines deliverables, dates, and cost. The Rules of Engagement (ROE) is the operational contract and must be signed before testing. The ROE pins down, at minimum:

- Scope in and scope out, expressed as machine-readable lists where possible.
- Testing windows and timezone (always state the timezone explicitly; ambiguous "9-5" causes deconfliction failures across regions).
- Stop conditions and the escalation path (see below).
- Data-handling rules and retention/destruction timeline.
- Deconfliction channel and emergency contacts with names, phone numbers, and a secondary contact.
- Agreed red-team indicators (source IPs, canary header, token strings) that the blue team will allowlist or watch for.
- Evidence and reporting handling, including how findings are transmitted.

Cross-link: pair this page with the operator's pre-flight checklist in [pre-engagement checklist](./pre-engagement-checklist.md) and the C2 infrastructure design in [../03-c2/infrastructure-design.md](../03-c2/infrastructure-design.md) so your egress IPs are known before they appear in a SIEM.

### Scope boundaries

Translate the ROE scope into concrete, enforceable artifacts on the operator host so accidental out-of-scope traffic is hard:

```bash
# scope.txt: one in-scope CIDR or host per line, comments allowed.
# Validate a candidate target against the allowlist before any tooling runs.
target="203.0.113.45"
if grep -qxF "$target" <(prips 203.0.113.0/24) ; then
  echo "IN SCOPE: $target"
else
  echo "OUT OF SCOPE - ABORT: $target" >&2
  exit 1
fi
```

Bound your scanners explicitly rather than trusting yourself to remember. Example with nmap restricted to an allowlist file and excluding fragile hosts:

```bash
# Scan only the in-scope file; never expand with discovery into adjacent ranges.
# --excludefile carries known-fragile systems (SCADA, legacy printers, medical).
nmap -iL scope_hosts.txt --excludefile fragile_hosts.txt \
  -p 22,80,443,3389 -T3 -oA scans/inscope_$(date +%Y%m%d) \
  --max-rate 200
```

Notes:
- IP-range scope is a CIDR allowlist; treat any host not in the file as out of scope even if it answers.
- Domain scope must distinguish apex from wildcards. `*.example.com` may resolve to third-party CDNs or shared SaaS you are not authorized to touch; resolve and re-check each discovered host against the owner statement.
- Account scope: test only the credentials and identities the client provisioned for you. Do not pivot into real employee accounts unless the ROE authorizes it.
- Time-window scope: enforce it in cron or your task scheduler, and have C2 beacons jitter only within the agreed hours.

### Data-handling rules for collected loot

Treat everything you collect as the client's sensitive data, because it is. Minimize, encrypt at rest, and destroy on schedule.

- Minimize: collect only what proves the finding. A single screenshot or a hash count proves access; you do not need to dump the whole customer table. If the ROE forbids real PII exfiltration, prove the access with a benign canary record you seeded, or with row counts and column names rather than values.
- Encrypt at rest: keep all loot inside an encrypted container, not loose on disk.

```bash
# LUKS-backed loot vault on Linux (operator host or jump box).
truncate -s 5G /opt/loot.img
cryptsetup luksFormat /opt/loot.img
cryptsetup open /opt/loot.img loot
mkfs.ext4 /dev/mapper/loot
mount /dev/mapper/loot /mnt/loot
# work, then close so the key is not resident:
umount /mnt/loot && cryptsetup close loot
```

```bash
# Per-engagement encrypted archive when a full volume is overkill.
# age (or GPG) with a key held only by the engagement lead.
tar czf - findings/ | age -r age1exampleRecipientKey... > loot_$(date +%Y%m%d).tar.gz.age
```

- Destroy after report acceptance: the ROE retention clause sets the clock (commonly 30-90 days after report delivery and client sign-off, unless a regulator requires longer). Wipe deliberately:

```bash
# Destroy the encrypted container and shred the key material.
shred -u /opt/loot.img            # overwrite + remove on a non-CoW filesystem
# On SSD/CoW (btrfs, ZFS, APFS) shred is unreliable; destroy the encryption key
# and discard the volume instead - losing the key makes ciphertext unrecoverable.
```

Note: `shred` does not reliably destroy data on SSDs, journaled or copy-on-write filesystems, or RAID. On those, rely on full-disk or per-archive encryption and destroy the key, then issue a blkdiscard/TRIM if you control the disk.

### Deconfliction channel

Deconfliction is the live link that lets the blue team ask "is this you?" and get an answer in minutes. Define before the engagement:

- A primary channel reachable 24/7 during the window (dedicated phone bridge, signal/secure chat, or a shared incident channel).
- The exact information the blue team will provide when querying: timestamp, source IP, target, observed action.
- The maximum response SLA (for example 15 minutes during active hours).
- A shared, append-only activity log the red team keeps so deconfliction queries can be answered against recorded actions.

```bash
# Append-only operator activity log; one line per significant action.
# Timestamp in UTC, source IP, target, technique, ticket/finding ref.
printf '%s\t%s\t%s\t%s\t%s\n' \
  "$(date -u +%FT%TZ)" "198.51.100.10" "203.0.113.45" "kerberoast" "FND-014" \
  >> ~/engagement/oplog.tsv
chmod a-w ~/engagement/oplog.tsv 2>/dev/null || true
```

### Stop conditions and emergency contacts

The ROE must enumerate conditions that halt testing immediately. Common stop conditions:

- Evidence of a pre-existing, real compromise discovered during testing. Stop, preserve, and notify the client lead at once. This is now potentially an incident, not your test.
- A production outage or instability plausibly caused by testing.
- Discovery of data outside the authorized sensitivity (for example regulated health or payment data the ROE did not anticipate).
- A request to stop from any named emergency contact.

List names, roles, primary and secondary phone numbers, and timezone for each emergency contact. Confirm the numbers work before the window opens. Define who can authorize a resume after a stop.

### Get-out-of-jail letter

The authorization letter, carried physically for on-site work, that a building guard or law-enforcement officer can read to confirm you are sanctioned. It should state the client legal name, the operator's name, the dates and locations authorized, an authorizing signer with title, and a 24/7 phone number to verify in real time. It does not grant immunity, but it converts "intruder" into "contractor whose paperwork checks out" and gives the on-call client contact the chance to vouch for you.

### Evidence and chain-of-custody for findings

Findings must be reproducible and attributable to the engagement, both to support remediation and to defend the work if it is later questioned.

- Capture evidence with timestamps (UTC) and the source IP used. Screenshots should include the URL/host bar and a clock where possible.
- Hash artifacts at collection time and record the hash in the oplog:

```bash
# Record an immutable fingerprint of each evidence file at collection.
sha256sum findings/FND-014_*.png >> findings/EVIDENCE.sha256
```

- Keep evidence inside the encrypted vault; transmit the report and evidence over an agreed encrypted channel (client portal, PGP-encrypted email, or a shared encrypted drive), never plaintext email.
- Maintain a simple custody record: who collected, when, where stored, who accessed, when destroyed.

### Third-party and cloud-provider notification

Client authorization does not extend to infrastructure the client does not own. Check provider policy before testing assets you do not control:

- AWS: as of the current policy, customer-initiated penetration testing against a defined list of the customer's own services (for example EC2, RDS, CloudFront, API Gateway, Lambda, Lightsail) is permitted without prior approval, but simulated denial-of-service, DNS zone walking, and certain other activities still require an explicit request to AWS. Do not test other tenants or shared AWS-managed control planes. Confirm the live list and prohibited activities in AWS documentation before scoping.
- Azure: Microsoft permits testing of your own Azure resources under the unified online services penetration testing rules of engagement; some activities (notably DoS) are prohibited or require coordination. Read the current Microsoft rules of engagement and the cloud penetration testing notification guidance.
- GCP: Google generally does not require pre-notification to test your own projects but expects compliance with the acceptable use and terms; DoS and testing of other tenants are out of bounds.

In all cases, never test multi-tenant control planes, the provider's own management endpoints, or another customer's resources. SaaS vendors (Microsoft 365, Salesforce, Okta, and similar) have their own testing policies that frequently require advance permission; the client cannot waive these on the vendor's behalf.

### Avoiding collateral

- No denial-of-service unless explicitly authorized in writing. This includes accidental DoS from aggressive scanning of fragile devices; rate-limit and exclude known-fragile hosts.
- No real PII or regulated-data exfiltration unless the ROE authorizes it. Prefer seeded canary records and proof-of-access metadata.
- No destructive actions (deleting data, encrypting hosts, modifying production records) outside an explicitly authorized, isolated test environment.
- Watch for blast radius from shared infrastructure: a single shared database, identity provider, or load balancer can carry your action into out-of-scope systems.

## OPSEC notes

The loud version of "authorization" is treating it as a formality: a verbal yes, a scope copied loosely from a prior engagement, no deconfliction contact, loot left in cleartext on the operator laptop, and scanners pointed at a CIDR "close enough" to the agreed one. Each of these is a real-world failure mode that has produced wrongful-arrest situations, regulatory breaches, and lawsuits.

The quiet, correct variant is mechanical scope enforcement (allowlists checked in code, not memory), an append-only oplog that can answer any deconfliction query within the SLA, encrypted loot with a destruction date, and pre-shared red-team indicators that keep the blue team from spending a night chasing you as a real adversary. The discipline is invisible when it works and catastrophic when it is absent.

Failure modes and tells that you have drifted out of bounds:

- A host answers that is not in `scope.txt`. Stop; you may have hit a third party on a shared range.
- Your scanner finds a subdomain resolving to a CDN or SaaS IP you do not own. Re-check against the owner statement before touching it.
- A production alert or outage coincides with your activity. Treat it as your fault until proven otherwise; this can be a stop condition.
- You are about to collect real customer PII to "prove" a finding. Stop and use a seeded canary or metadata instead.
- The deconfliction contact does not answer a test call before the window. Do not start.

## Detection & telemetry

The defender's job here is the inverse of an investigation: confirm that anomalous activity is the authorized red team, fast, without standing down real detection. This works only if the indicators were agreed in the ROE. The signal sources below are where the blue team distinguishes sanctioned testing from a genuine intrusion.

### Source-IP allowlist

The single most reliable deconfliction control. The red team commits to a fixed set of egress IPs (jump boxes, C2 redirectors, scanner hosts) recorded in the ROE. The blue team loads these into a watchlist - not necessarily a block, since silently allowlisting can hide a real attacker who spoofs from the same range, but a tagging lookup so analysts see "known red team" on the relevant events.

Splunk: tag events whose source matches the agreed red-team IP set.

```spl
index=firewall OR index=proxy
| lookup redteam_ips.csv src_ip AS src OUTPUT engagement
| eval actor=if(isnotnull(engagement),"REDTEAM-".engagement,"unknown")
| stats count by actor, src, dest
```

KQL (Microsoft Sentinel / Defender), tagging sign-ins and network events from red-team egress:

```kusto
let RedTeamIPs = dynamic(["198.51.100.10","198.51.100.11","203.0.113.7"]);
SigninLogs
| where IPAddress in (RedTeamIPs)
| extend RedTeamTag = "purple-team-deconfliction"
| project TimeGenerated, UserPrincipalName, IPAddress, AppDisplayName, ResultType, RedTeamTag
```

Tell for defenders: an action from a red-team IP that the red team's oplog cannot account for is a real finding. Always cross-check the deconfliction log; matching source IP alone is not proof, since an attacker could be inside the same hosting provider.

### Canary tokens

Pre-placed tripwires that fire on access. The red team and blue team agree where canary tokens live so a red-team trigger is expected and a trigger from an unexpected actor is a real alert. Canarytokens (DNS/HTTP callback tokens, AWS key tokens, document tokens) and honey accounts are the common mechanisms. When a canary fires, the callback carries the source IP and a timestamp; correlate it against the red-team allowlist and oplog.

Hunt: a honey account login or canary callback whose source IP is not on the red-team allowlist is high-fidelity. On Windows, a logon to a designated honey account surfaces in Security.evtx as logon events (Event ID 4624 for a successful logon, 4625 for failed) and Kerberos service-ticket requests (4769); a service-ticket request for a honey SPN is a classic Kerberoast tell - see [../05-credential-access/kerberoasting.md](../05-credential-access/kerberoasting.md). Filter those events by the canary account name and compare the client IP to the allowlist.

```kusto
SecurityEvent
| where EventID in (4624,4625,4769)
| where TargetAccount has "svc-honey" or ServiceName has "honey"
| extend KnownRedTeam = iif(IpAddress in ("198.51.100.10","198.51.100.11"), "yes","no")
| where KnownRedTeam == "no"   // not us => investigate as real
| project TimeGenerated, EventID, Account, ServiceName, IpAddress, KnownRedTeam
```

### Agreed header marker

For web and API testing, the red team adds a unique HTTP header to all tool traffic (for example `X-RedTeam: <engagement-id>-<random>`). The blue team configures the WAF/proxy to log and tag it. This lets defenders separate authorized fuzzing from background noise without IP allowlisting, which is useful when the red team uses rotating cloud egress.

Sigma-style detection logic (proxy/WAF logs) to tag the marker:

```yaml
title: Authorized Red Team HTTP Marker
logsource:
  category: proxy
detection:
  selection:
    cs-header|contains: 'X-RedTeam: ENG-2026-014'
  condition: selection
level: informational
fields:
  - c-ip
  - cs-uri-stem
  - cs-header
```

Tell for defenders: identical attack patterns (same payloads, same paths) arriving without the agreed header, or from an IP off the allowlist, are the real-attacker hypothesis. The marker is for deconfliction only; never use it as an access-control bypass, and strip it from any payload meant to model a real adversary's traffic.

### Host and identity telemetry the engagement should still generate

Deconfliction does not mean the red team turns off detections. The point of a purple-team exercise is that these fire and the blue team practices on them, then deconflicts. Expected sources:

- Linux: auditd execve and file-access records, journald/auth.log authentication events, shell history. An auditd rule watching the loot vault or sensitive paths produces `type=PATH`/`type=SYSCALL` records the blue team can hunt. See [../09-detection/auditd-baseline.md](../09-detection/auditd-baseline.md).
- Windows: Sysmon (process creation Event ID 1, network connection 3, image load 7) and Security.evtx logon and Kerberos events. Map the red team's known hosts and accounts so analysts can confirm provenance.
- EDR: most platforms let you tag known-tester hosts or hashes; do this so EDR alerts carry a deconfliction label rather than paging the on-call as a P1.
- Cloud: CloudTrail (AWS), Azure Activity and sign-in logs, GCP Cloud Audit Logs. Tag the red-team principals and source IPs so audit events are attributable.

osquery example the blue team can run to confirm a process tree belongs to a known red-team operator account during a window:

```sql
SELECT p.pid, p.name, p.cmdline, p.cwd, u.username
FROM processes p
JOIN users u ON p.uid = u.uid
WHERE u.username = 'redteam-operator';
```

The governing rule: the red team is identifiable by agreed indicators (allowlisted source IPs, canary placement, header marker, named principals/hosts) plus a real-time deconfliction channel and an append-only oplog. Any high-fidelity event that those four cannot explain is treated as a genuine intrusion and escalated accordingly.

## MITRE ATT&CK

This page documents pre-engagement governance, not an attack technique, so it has no offensive technique ID. The closest ATT&CK mapping is the adversary-side Reconnaissance and Resource Development tactics that authorized scoping mirrors, and the defensive deconfliction controls that align with detection design rather than a single technique.

- PRE-engagement / Reconnaissance (TA0043) - the legitimate, authorized analogue of target scoping.
- Resource Development (TA0042) - standing up authorized infrastructure (redirectors, egress IPs) that must be pre-registered for deconfliction.
- Defensive alignment: this maps to detection engineering and the deconfliction process, not to an attacker technique. No T-number is claimed for the authorization process itself.

## References

- MITRE ATT&CK, Reconnaissance (TA0043) and Resource Development (TA0042). https://attack.mitre.org/tactics/TA0043/ and https://attack.mitre.org/tactics/TA0042/
- AWS, Penetration Testing policy and customer support for testing. https://aws.amazon.com/security/penetration-testing/
- Microsoft, Penetration Testing Rules of Engagement (unified online services). https://www.microsoft.com/en-us/msrc/pentest-rules-of-engagement
- Google Cloud, Acceptable Use Policy and security testing guidance. https://cloud.google.com/terms/aup
- PTES, Pre-engagement Interactions and Rules of Engagement. http://www.pentest-standard.org/index.php/Pre-engagement
- NIST SP 800-115, Technical Guide to Information Security Testing and Assessment. https://csrc.nist.gov/publications/detail/sp/800-115/final
- Thinkst Canarytokens documentation. https://docs.canarytokens.org/
- cryptsetup/LUKS man page. https://man7.org/linux/man-pages/man8/cryptsetup.8.html
- shred(1) man page (note limitations on SSD/journaled filesystems). https://man7.org/linux/man-pages/man1/shred.1.html
