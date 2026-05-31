---
title: "Infrastructure Segregation"
parent: "4. C2 Infrastructure"
nav_order: 3
---

# C2 Infrastructure Segregation & Operational OPSEC

_Tiered command-and-control infrastructure that limits blast radius and attribution, so the burn of one component does not collapse the engagement, paired with the threat-intelligence telemetry that correlates and deanonymizes sloppy infrastructure._

## What & why

The goal is to build C2 infrastructure where each function lives in its own segregated tier with its own domains, IPs, certificates, and personas, so that when blue team or an automated control burns one piece the rest of the operation survives and stays unattributed. The OPSEC rationale is twofold. First, blast radius: an interactive callback that triggers an EDR alert should never expose the phishing sender, the long-haul persistence channel, or the recon box, because each is a separate kill-chain stage with a different detection profile and a different acceptable burn rate. Second, attribution: defenders and CTI vendors pivot across infrastructure using passive DNS, certificate transparency, JARM/JA4 hashes, Shodan/Censys banners, and WHOIS/registration metadata. Reusing a TLS certificate, a default web page, a server header, a registrant email, or a payment trail across components - or worse, across clients - lets an analyst cluster your entire estate from a single observed indicator. Segregation plus disciplined metadata hygiene is what keeps a single observed indicator from unrolling the whole map. This page assumes an authorized engagement with a signed scope and a deconfliction process; none of it is for unauthorized use.

See also [redirector design](./01-redirectors-and-domain-fronting.md) and [malleable C2 profiles](./02-malleable-profiles.md) for the per-tier traffic-shaping that complements this segregation model, and [detection mapping](../detection-mapping/c2-infrastructure.md) for the defender pivot graph.

## Technique

### Tiering by kill-chain function

Treat infrastructure as discrete tiers, each provisioned, paid for, and rotated independently. A burn at one tier must not reveal the existence of another. The canonical tiers:

- **Recon** - subdomain enumeration, OSINT pulls, port/service scanning. High-volume, noisy, expendable. Lives on cloud VMs or VPS you expect to lose. Never share an IP or ASN with anything sensitive.
- **Phishing / delivery** - sender domains, landing pages, payload hosting. Aged domains with clean reputation, valid DKIM/SPF/DMARC, categorized in proxy/web filters. Burns fast once a user reports a mail.
- **Staging / payload** - hosts that serve stagers, beacons, second-stage tooling. Often behind a redirector. Short-lived per campaign.
- **Interactive** - the hands-on-keyboard tier where operators drive sessions. Lowest acceptable burn rate, highest care. Always behind redirectors; the team server IP is never exposed to the target.
- **Long-haul / persistence** - slow-beacon callback for survivability (sleep measured in hours, low-and-slow). Completely isolated DNS, domains, and certificates from the interactive tier so that loss of interactive infra does not cost you persistence, and vice versa.

The hard rule: **one team server, one target, one set of redirectors.** Do not multiplex two clients' callbacks through shared redirectors or a shared team server. Cross-client reuse is the single most common way CTI clusters "an actor" out of what is actually two unrelated authorized engagements.

### Redirector and team-server separation

The team server (Cobalt Strike, Mythic, Sliver, etc.) holds your loot, your operator credentials, and your full session state. It must never receive traffic directly from the target network. Place redirectors in front of every listener.

```bash
# Redirector host (Linux). Forward only the listener port to the team server
# over an authenticated, encrypted transport. Lock the team server's firewall
# so it ONLY accepts that redirector's source IP on the listener port.

# Example: socat HTTPS reverse-proxy redirector to team server (203.0.113.10).
# Bind 443 on the redirector, forward to the team server on the WireGuard /
# private link, never the public IP.
socat TCP4-LISTEN:443,reuseaddr,fork \
      TCP4:10.66.0.10:443
```

Prefer an application-aware redirector (Apache mod_rewrite, NGINX, or a purpose-built HTTP redirector) over a dumb TCP forward, because it lets you filter on URI, method, User-Agent, and the malleable profile's expected headers, and silently send everything that does not match the profile to a decoy site.

```apache
# /etc/apache2/sites-enabled/redirector.conf (Apache mod_rewrite)
# Only traffic that matches the malleable C2 URIs and UA reaches the team server.
# Everything else is redirected to a benign decoy (the cover site).
RewriteEngine On
RewriteCond %{REQUEST_URI}     ^/api/v2/(updates|telemetry)$  [NC]
RewriteCond %{HTTP_USER_AGENT} "Mozilla/5\.0 \(Windows NT 10\.0" [NC]
RewriteRule ^.*$  https://10.66.0.10%{REQUEST_URI}  [P,L]

# Default: anything that does not match goes to the cover site, not the C2.
RewriteRule ^.*$  https://www.example.com/  [R=302,L]
```

The team server's host firewall must enforce the separation - the redirector is the only thing allowed to talk to the listener:

```bash
# Team server (Linux). Default-deny inbound; allow ONLY the redirector
# over the private link, plus your management access over a separate path.
iptables -P INPUT DROP
iptables -A INPUT -i lo -j ACCEPT
iptables -A INPUT -m state --state ESTABLISHED,RELATED -j ACCEPT
# Redirector reaches the listener only over the private interface (wg0):
iptables -A INPUT -i wg0 -p tcp -s 10.66.0.11 --dport 443 -j ACCEPT
# Operator SSH only from the jump host, never wide open:
iptables -A INPUT -p tcp -s 198.51.100.5 --dport 22 -j ACCEPT
```

### Monitoring your own infrastructure for IR touches

You must know when blue team starts poking your redirectors, because an IR analyst scanning, curling, or sandbox-detonating your landing page is the earliest signal that a tier is about to burn. Instrument the redirectors (not the team server, which sees no untrusted traffic) and alert on anomalous source behavior.

Useful tells of an investigator, not a victim:
- Requests to the redirector's IP with no `Host` header or the wrong `Host`.
- Requests to the C2 URIs that lack the malleable profile's expected headers/UA - a curl, a Python `requests`, a sandbox UA.
- Hits from known security-vendor ASNs, cloud sandbox ranges, or scanner fingerprints.
- Repeated `HEAD`/`OPTIONS`, TLS scans, or requests to `/`, `/robots.txt`, `/favicon.ico` on a host that should only serve the profile URIs.

```bash
# Redirector: tail the access log and alert on requests that do NOT match the
# malleable profile (i.e. likely IR/scanner touches). Forward to an out-of-band
# notification channel - never back through the C2 path.
tail -F /var/log/apache2/access.log | \
  grep -vE '"GET /api/v2/(updates|telemetry) HTTP' | \
  while read -r line; do
    logger -t c2-watch "OFF-PROFILE: $line"
    # ship to your OOB webhook / signal here
  done
```

Ship redirector logs off-box in real time to a collector the target cannot reach, so that if the redirector is seized or torn down by the provider you retain the evidence of who touched it and when. Treat the redirector as untrusted and disposable; the collector is your source of truth.

### Burn procedures

Define burn triggers and the exact teardown before the engagement starts, so a 2 a.m. detection does not become an improvised scramble.

- **Trigger inventory:** an EDR alert tied to a callback, a user-reported phish, a redirector hit from a security ASN, a provider abuse notice, a domain categorization flip to "malicious", a certificate flagged in CT monitoring.
- **Rotate, do not patch.** When a domain or IP is burned, retire it and migrate live sessions to a pre-staged backup tier (have spare redirectors and a backup callback domain provisioned and warmed before you need them). Do not reuse a burned domain for a different tier later in the same op - the indicator is already in someone's blocklist and pivot graph.
- **Teardown order:** cut the target-facing redirector first (stops new exposure), migrate sessions to the backup channel, then decommission the burned redirector VM and revoke its certificate. The team server IP, if it was never exposed, survives and only needs a new front.
- **Evidence preservation:** snapshot logs and the malleable profile in use before destroying a host, for the engagement report and for deconfliction.

### Attribution hygiene

- **Registration via privacy.** Register domains with WHOIS privacy/redaction and a dedicated registrant identity per engagement. Do not reuse the same registrant email, the same recovery phone, or the same nameserver set across clients - these are all pivotable in WHOIS history (DomainTools, WhoisXML) even after privacy is enabled.
- **Payment trails.** Pay for each engagement's infrastructure through a separated method. Reusing one credit card or one cloud billing account across clients links the assets at the provider and, via leaks/legal process, downstream. Use the lab/engagement's funding controls per your rules of engagement; never personal accounts.
- **Consistent persona, scoped to one engagement.** Each persona (registrant, cloud account, email) is internally consistent but never crosses engagements. Cross-engagement persona reuse is exactly what lets CTI say "same actor."
- **Avoid operator-IP leaks via misconfig.** Classic leaks: SSHing to the team server from your real IP and leaving it in `last`/`auth.log` that later leaks; a redirector default page revealing the origin; an `X-Forwarded-For` or verbose error echoing the team server's private IP; a Cobalt Strike/Sliver default self-signed certificate; an exposed management port (e.g. the team server's web UI) indexed by Shodan. Always reach infra through a jump host and a VPN whose IP is itself disposable.
- **No infra reuse across clients.** Fresh domains, IPs, certs, JARM-affecting TLS configs, and default pages for every engagement. This is the master rule that defeats the majority of pivoting.

### Provider selection and acceptable-use realities

- Choose providers whose acceptable-use policy and abuse-handling speed match the tier. A phishing sender on a provider that suspends within an hour of one complaint is a liability; an interactive tier needs a provider that will not null-route you mid-session on a single automated report.
- Spread tiers across different ASNs and ideally different providers so a provider-level takedown of one tier does not catch the others. Shared ASN is itself a pivot pivotable by analysts.
- Domain fronting/CDN realities: most major CDNs have disabled or restricted domain fronting; verify current behavior rather than assuming a profile from years ago still works (see [redirectors and domain fronting](./01-redirectors-and-domain-fronting.md)).
- Mature category reputation in advance. A freshly registered domain with no category is itself suspicious to proxies; age and categorize delivery domains before the campaign.

### Deconfliction artifacts

Authorized red team must be distinguishable from a real adversary so blue team can deconflict during the engagement and so an incident is not escalated to law enforcement.

- Provide blue/IR leads, before go-live, with: your source IP ranges or ASNs, your domains, listener ports, beacon User-Agent/URIs, and a 24/7 contact.
- Embed a benign, agreed deconfliction marker where feasible (a specific header value, a known string in the cover page, a documented certificate fingerprint) so an analyst who pulls the artifact can match it to the engagement record.
- Maintain an engagement infrastructure ledger (domains, IPs, certs, registration dates, providers, burn status) shared with the trusted agent. This is also what you hand the defender in the readout so they can write durable detections.

## OPSEC notes

The loud version reuses things. One team server fronting two clients; one wildcard TLS cert across all redirectors; a Cobalt Strike default profile and default self-signed cert; the team server's web UI exposed on its public IP; SSH to infra from the operator's real residential IP; the same registrant email behind WHOIS privacy on every domain; a default Apache/NGINX welcome page on a redirector that should look like a real business. Each of these is a single observable that an analyst expands into your whole estate.

The quiet version is segregated and unique per tier and per engagement: distinct domains/IPs/ASNs/certs per tier, redirectors that only forward profile-matching traffic and decoy everything else, a team server reachable only over a private link from one redirector, custom TLS configuration that does not match a known C2 product's JARM/JA4, realistic cover pages, fresh personas and payment per engagement, and out-of-band monitoring of your own redirectors.

Failure modes and tells:
- **Certificate reuse / default certs.** Reusing one cert across redirectors, or shipping a C2 product's default self-signed cert, links hosts via CT logs and certificate-hash search (Censys/Shodan).
- **JARM/JA4 fingerprint.** Default TLS stacks of C2 frameworks produce recognizable JARM/JA4 server fingerprints; an unchanged stack is clusterable even without a cert match.
- **Default pages and headers.** A default welcome page, a revealing `Server` header, a stack-trace error, or a directory listing fingerprints the host and the framework.
- **SAN bleed.** A certificate whose SANs list multiple of your domains ties them together in CT logs instantly.
- **WHOIS history.** Privacy hides current data but not historical records; an early unredacted registration or a reused registrant artifact is permanent.
- **Open management ports.** The team server admin/web port reachable from the internet is both a compromise risk and a Shodan-indexable fingerprint.
- **Cross-tier shared IP/ASN.** Any two tiers on the same IP or same small ASN block collapse the segregation you paid for.

## Detection & telemetry

This section is written for the defender and the threat-intelligence analyst: how to pivot from one observed red-team (or real adversary) indicator across the rest of their estate, and what artifacts give them away. Red team should read it as the exact list of things to avoid producing.

### Certificate Transparency (CT) and TLS fingerprinting

- **CT log monitoring.** Every publicly trusted TLS cert is logged. Monitor `crt.sh`, Censys, or a CT firehose for your protected brands and for SANs that co-list suspicious domains. A cert whose SAN list bundles multiple lookalike domains is an immediate cluster.
  - Hunt: query `crt.sh` for a brand string or a suspicious registrant pattern; pull all certs and group by SHA-256 fingerprint and by overlapping SANs. Identical fingerprints across different IPs = same operator cert reuse.
- **JARM / JA4(S).** Scan or passively collect server-side TLS fingerprints. A JARM/JA4S value matching a known C2 framework's default stack, or one JARM value shared across many otherwise-unrelated IPs, is a high-fidelity pivot. Cross-reference observed JARM against public default-C2 JARM corpora.
- **Self-signed / default cert detection.** Flag certs with default subjects (the literal default CN that ships with the framework), unusual validity windows, or issuer reuse.

### Passive DNS and WHOIS pivoting

- **Passive DNS (pDNS).** Pivot from a known-bad IP to every domain that ever resolved to it, and from a known-bad domain to every IP it used. Co-hosting and shared-IP history collapses tiers an operator thought were separate.
- **WHOIS / registration.** Pivot on registrant email, registrant org, nameserver set, and registration timestamp clustering (many domains registered in the same window through the same registrar). WHOIS history services retain pre-privacy records.
- **Hosting reputation / ASN.** Score the hosting ASN; bulletproof or known-abuse ASNs, and multiple of an actor's hosts in one small block, raise confidence and enable block-at-ASN.

### Scanner/sandbox-visible artifacts

- **Shodan/Censys banners.** Index `Server` headers, default pages, favicon hashes (`http.favicon.hash`), exposed management ports, and product-default ports. A C2 team server's exposed admin port or a redirector's default welcome page is directly searchable.
  - Hunt: pivot on a favicon hash or a default-page body hash to find every host serving the same default artifact.
- **Default page / error fingerprints.** Hash the landing-page body and error pages; identical hashes across IPs cluster the operator's hosts.

### On the victim network (where the callback lands)

Once a beacon is on an endpoint, host and network telemetry exposes the infrastructure it talks to. Map these back to the tiers above.

- **DNS resolution telemetry.**
  - Windows: Sysmon **Event ID 22** (DnsQuery) records process, query name, and result - ties a process to the C2 domain. Microsoft-Windows-DNS-Client/Operational and DNS server query logs corroborate.
  - Linux: with auditd or a DNS resolver log, correlate the resolving process to the callback FQDN.
- **Process-to-network correlation.**
  - Windows: Sysmon **Event ID 3** (Network connection) gives source process, destination IP/port, and (with the right config) the destination hostname - links a suspicious process to the redirector IP.
  - Linux: auditd `connect`/`sendto` syscall records, or eBPF/EDR network telemetry, tie a PID and binary path to the destination IP.

```
# auditd: record outbound connect()/sendto() syscalls for later
# process-to-destination correlation. (Field of interest: a0/saddr in
# the SOCKADDR record; correlate exe= and pid= from the SYSCALL record.)
-a always,exit -F arch=b64 -S connect -S sendto -k net_outbound
```

- **TLS/JA3(S) on the wire.** Network sensors (Zeek `ssl.log`, Suricata TLS events) record SNI, the server cert (issuer/subject/validity/fingerprint), and JA3/JA3S/JA4 client and server fingerprints. A beacon's TLS client fingerprint plus the server's JA4S clusters the C2 endpoint.
  - Zeek: `ssl.log` (server_name, subject, issuer, cert chain), `x509.log` (cert fingerprint, SANs), `conn.log` (duration/bytes - low-and-slow beacon timing).
- **Beacon timing / jitter.** Long-haul tiers reveal themselves through regular, low-volume connections at fixed intervals plus jitter. Hunt `conn.log`/proxy logs for periodic, similar-sized requests to one destination over hours - classic beacon cadence.
- **Proxy/web-filter logs.** Newly registered or uncategorized destination domains, requests with off-profile User-Agents, and POSTs of unusual size to a single host.

### Example hunt queries

KQL (Microsoft Defender / Sentinel) - beacon-like periodic connections to a single remote destination:

```kql
DeviceNetworkEvents
| where Timestamp > ago(24h)
| where RemoteIPType == "Public"
| summarize conns = count(),
            distinctMinutes = dcount(bin(Timestamp, 1m)),
            bytesOut = sum(toint(coalesce(column_ifexists("SentBytes","0"),"0")))
        by DeviceId, InitiatingProcessFileName, RemoteIP, RemoteUrl
| where conns > 50 and distinctMinutes > 30   // steady cadence, not bursty
| order by conns desc
```

Sigma-style (concept) - Sysmon DNS query for newly seen, low-prevalence domain from an unusual process:

```yaml
title: Suspicious DNS query to low-prevalence domain
logsource:
  product: windows
  service: sysmon
detection:
  selection:
    EventID: 22          # DnsQuery
  filter_known:
    QueryName|endswith:
      - '.example.com'   # baseline of legitimate, allowlisted domains
  condition: selection and not filter_known
fields: [Image, QueryName, QueryResults]
```

osquery (via Fleet) - flag listening/exposed management-style ports on managed hosts (use on YOUR fleet to find accidentally exposed team-server-like services; verify column names with `get_osquery_schema` first):

```sql
SELECT p.pid, p.name, lp.address, lp.port, lp.protocol
FROM listening_ports lp
JOIN processes p ON lp.pid = p.pid
WHERE lp.address IN ('0.0.0.0', '::')   -- bound to all interfaces
  AND lp.port NOT IN (22, 80, 443);
```

Splunk - proxy/DNS pivot from one known-bad IP to all domains and clients that touched it:

```spl
index=proxy (dest_ip="203.0.113.10")
| stats values(url) AS urls dc(src_ip) AS client_count values(http_user_agent) AS uas
        earliest(_time) AS first_seen latest(_time) AS last_seen
        by dest_ip
| eval first_seen=strftime(first_seen,"%F %T"), last_seen=strftime(last_seen,"%F %T")
```

### Pivot graph the defender builds

1. Observe one indicator (callback IP, domain, cert fingerprint, JARM, favicon hash).
2. CT logs -> other domains sharing the cert / SANs.
3. pDNS -> other IPs the domain used and other domains on the IP.
4. WHOIS/registrant -> sibling domains by email/NS/registration window.
5. Shodan/Censys -> other hosts with the same default page / banner / JARM / exposed port.
6. Cluster -> attribute the whole tier set to one operator.

Every reuse you commit is an edge in that graph. Segregation and per-engagement uniqueness remove the edges.

## MITRE ATT&CK

- **T1583** - Acquire Infrastructure (and sub-techniques: .001 Domains, .003 Virtual Private Server, .004 Server, .006 Web Services)
- **T1584** - Compromise Infrastructure
- **T1587.003** - Develop Capabilities: Digital Certificates
- **T1588.004** - Obtain Capabilities: Digital Certificates
- **T1608** - Stage Capabilities (.001 Upload Malware, .003 Install Digital Certificate, .004 Drive-by Target, .005 Link Target)
- **T1090** - Proxy (.002 External Proxy, .004 Domain Fronting) - redirector and fronting layer
- **T1071.001** - Application Layer Protocol: Web Protocols - the beacon channel
- **T1568** - Dynamic Resolution - resilient callback / domain rotation
- **T1665** - Hide Infrastructure

## References

- MITRE ATT&CK, Acquire Infrastructure (T1583) and sub-techniques - https://attack.mitre.org/techniques/T1583/
- MITRE ATT&CK, Proxy (T1090) - https://attack.mitre.org/techniques/T1090/
- MITRE ATT&CK, Hide Infrastructure (T1665) - https://attack.mitre.org/techniques/T1665/
- Salesforce Engineering, JARM TLS server fingerprinting - https://github.com/salesforce/jarm
- FoxIO, JA4+ network fingerprinting suite - https://github.com/FoxIO-LLC/ja4
- Certificate Transparency search (crt.sh) - https://crt.sh/
- Microsoft Sysmon documentation (Event IDs 3, 22) - https://learn.microsoft.com/en-us/sysinternals/downloads/sysmon
- Zeek SSL and x509 log reference - https://docs.zeek.org/en/master/logs/ssl.html
- Linux auditd, auditctl(8) man page - https://man7.org/linux/man-pages/man8/auditctl.8.html
