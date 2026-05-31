# C2 Redirectors, Domains & Fronting

_Hiding the team server behind redirectors, aged and categorized domains, and valid TLS so victim traffic never touches your real C2 - and the telemetry that exposes every one of those tricks._

## What & why

The goal is to ensure no implant on a victim host ever holds a network path, a certificate, or a DNS record that resolves to the real team server. A redirector is a cheap, disposable host that sits in front of the team server, terminates beacon traffic, filters it (only well-formed beacons matching the malleable profile pass), and forwards the survivors over an authenticated tunnel to the long-haul listener. Everything else - vulnerability scanners, sandbox detonations, incident-response replays, curious analysts - gets a benign decoy page. The OPSEC rationale: redirectors are burned during the engagement (blocked, sinkholed, taken down) without losing the team server, the operator's session, or the implant catalog. They also break the single most reliable IR pivot - "follow the beacon IP to the adversary infrastructure" - because that IP is a throwaway VPS, not your control plane. This page pairs each offensive control with the exact defensive signal it leaves; see [malleable-profiles](../malleable-profiles.md) for the request shaping that redirectors filter on, and [data-transfer/https](../data-transfer/https.md) for payload-in-transit encoding.

## Technique

### The redirector pattern

Three tiers, strictly separated:

- Implant -> redirector (disposable VPS, cloud function, or CDN edge). Public, burnable, holds the categorized domain and the valid TLS cert.
- Redirector -> team server (over SSH tunnel, WireGuard, or a hardened reverse proxy). Never reachable directly from the internet.
- Team server (operator console, listener, payload host). Bound to localhost or a private interface only.

The redirector's job is admission control. A beacon that matches the profile (correct URI path, User-Agent, required headers, valid Host) is proxied to the team server. Everything else returns a 200/302 to a real-looking site or a 404, never the C2 listener.

### nginx redirector with strict filtering

nginx is the workhorse because `map`, `if`, and `proxy_pass` give precise admission logic. The pattern: validate URI, method, UA, and a custom header; only matching requests reach the upstream tunnel; all else serves a static decoy.

```nginx
# /etc/nginx/sites-available/redirector.conf
map $http_user_agent $valid_ua {
    default                                    0;
    "~*Mozilla/5\.0 \(Windows NT 10\.0.*Chrome" 1;  # must match profile UA exactly
}

map $request_uri $valid_uri {
    default              0;
    "~^/api/v2/updates"  1;   # beacon GET path from malleable profile
    "~^/submit\.php"     1;   # beacon POST path
}

server {
    listen 443 ssl http2;
    server_name cdn.example-lab.com;

    ssl_certificate     /etc/letsencrypt/live/cdn.example-lab.com/fullchain.pem;
    ssl_certificate_key /etc/letsencrypt/live/cdn.example-lab.com/privkey.pem;

    # Only forward beacons that pass every gate; one failure -> decoy.
    location / {
        if ($valid_ua = 0)  { return 302 https://www.example.com/; }
        if ($valid_uri = 0) { return 302 https://www.example.com/; }
        # Custom header keyed by profile (e.g. Cookie/X-Request-ID). Absent -> decoy.
        if ($http_x_request_id = "") { return 302 https://www.example.com/; }

        proxy_pass         https://127.0.0.1:8443;   # SSH-forwarded team server port
        proxy_ssl_verify   off;                       # internal pinned tunnel
        proxy_set_header   Host $host;
        proxy_set_header   X-Forwarded-For "";        # strip; do not leak chain
    }

    # Decoy root for scanners and IR replays.
    location = /index.html { root /var/www/decoy; }
}
```

Bring the upstream up with a reverse SSH tunnel from the team server so the redirector never stores team-server credentials or a route to it:

```bash
# Run on the TEAM SERVER. Exposes its listener (8443) on the redirector's loopback.
ssh -N -R 127.0.0.1:8443:127.0.0.1:8443 \
    -o ServerAliveInterval=30 -o ExitOnForwardFailure=yes \
    redirector-user@cdn.example-lab.com
```

If the redirector is seized, it contains an nginx config, a TLS cert, and an inbound SSH session it cannot reuse - no team-server IP, no payloads.

### Apache mod_rewrite redirector

Equivalent logic with `RewriteCond`/`RewriteRule`. The `[P]` flag proxies matching requests; `[R]` redirects the rest.

```apache
# Requires: a2enmod rewrite proxy proxy_http ssl headers
RewriteEngine On

# Pass only the profile UA and beacon URIs to the team server via the tunnel.
RewriteCond %{HTTP_USER_AGENT}  ^Mozilla/5\.0\ \(Windows\ NT\ 10\.0.*Chrome  [NC]
RewriteCond %{REQUEST_URI}      ^/(api/v2/updates|submit\.php)              [NC]
RewriteRule ^.*$  https://127.0.0.1:8443%{REQUEST_URI}  [P,L]

# Everything else: send to a benign external site (decoy).
RewriteRule ^.*$  https://www.example.com/  [R=302,L]
```

### socat as a dumb TCP redirector

For raw or non-HTTP listeners (or as a quick second hop), socat forwards bytes with no filtering. Use only behind an HTTP redirector that already did admission control, because socat itself inspects nothing.

```bash
# Forward 443 on the redirector to the team server reached over the SSH tunnel.
socat TCP4-LISTEN:443,reuseaddr,fork TCP4:127.0.0.1:8443
```

### Cloud-function / serverless redirectors

A small function (Cloudflare Worker, AWS Lambda + API Gateway, GCP Cloud Function) performs the same admission check and forwards to the long-haul. The win is reputation: traffic egresses from a major provider's IP space and rides a provider-owned TLS cert and SNI, which most netflow-based reputation scoring treats as benign. The function reads the request, applies the profile gate, and re-issues an outbound HTTPS request to the upstream redirector or team server, returning the response body. Conceptually identical to nginx, but the public-facing identity is the cloud provider, not a VPS you registered.

### DNS redirectors and staging vs long-haul split

DNS C2 (TXT/A/CNAME tunneling) needs its own redirector tier. Delegate an NS record for a subdomain (`ns.example-lab.com`) to the redirector host; the redirector runs an authoritative resolver that answers beacon queries and relays the encoded payload to the team server. DNS is slow and noisy - reserve it for a low-and-slow fallback channel, not primary tasking.

Separate infrastructure by lifecycle:

- Staging listener (delivers the payload, runs once per host) lives on its own domain and redirector. It is the loudest, most-sandboxed asset; isolate it so its burn does not cost you C2.
- Long-haul C2 listener (post-exploitation tasking) lives on a different domain, different redirector, often a different cloud account/ASN. Use a sacrificial categorized domain for staging and your best-aged domain for long-haul.

Never let a staged payload contain the long-haul domain in cleartext, and never reuse the staging redirector for tasking.

## OPSEC notes

### What makes the loud version loud

The classic burn signature, in one line: a newly-registered domain (or raw IP), a self-signed or default certificate, and an implant beaconing on a fixed interval with a default User-Agent. Any one of these is suspicious; together they are a high-confidence detection. Specific tells:

- Raw-IP C2 (`https://203.0.113.10/`) with no SNI and no domain - trivially blocked and instantly anomalous in proxy logs.
- Self-signed or framework-default TLS certificate (the well-known default Cobalt Strike cert serial/subject is fingerprinted by every major vendor and Suricata ruleset).
- Domain registered days before the engagement (low domain age), uncategorized or in a junk/new-gTLD bucket (`.zip`, `.mov`, `.xyz` churn) that proxies flag by policy.
- Default JA3/JA4 client fingerprint from the implant's TLS stack, mismatched against the User-Agent it claims (a "Chrome" UA with a non-Chrome TLS ClientHello).
- A redirector whose root path returns the listener's default page or a 404 to everything - no decoy content, so any analyst who browses the domain sees nothing legitimate.

### The quiet variant

- Aged, categorized domain. Acquire an expired domain with prior legitimate history, or let a fresh domain sit and build categorization before use. Verify its category at the major proxy vendors (the goal is a benign bucket like "Business" or "Technology", not "Newly Registered Domain" or "Uncategorized").
- Valid, free TLS via Let's Encrypt so the chain is publicly trusted and the cert is unremarkable. Match the cert's subject to the domain and host a real-looking site on the root.
- A genuine decoy on `/` - mirror a plausible corporate or SaaS landing page so scanners, IR, and casual visitors get a normal 200 with normal content.
- Profile-shaped traffic (correct UA, headers, URIs, and jitter) so the beacon blends with the categorized site's expected traffic. See [malleable-profiles](../malleable-profiles.md).
- Redirector reputation laundering via cloud edges/functions so the egress IP belongs to a trusted ASN.

### Failure modes and tells

- SNI/Host mismatch. If the implant sends SNI `cdn.example-lab.com` but an HTTP `Host:` header for a different domain, inline TLS-inspecting proxies log a mismatch - a strong signal.
- Cert transparency exposure. Every Let's Encrypt issuance is published to CT logs (crt.sh). Defenders and threat-intel feeds monitor CT for lookalike/typosquat domains; issuing a cert for `micros0ft-update.com` advertises your infrastructure the moment it is signed.
- Beacon regularity. Even over valid TLS, a fixed-interval callback to one destination is detectable by inter-arrival-time analysis regardless of payload encryption. Jitter helps; it does not eliminate the pattern.
- Decoy that does not match the category. A domain categorized as "Banking" serving a generic Apache default page is itself an anomaly.

## Detection & telemetry

This is the section that matters. Redirectors hide the team server, not the act of beaconing - so detection lives in DNS, TLS metadata, proxy logs, and timing, not in the C2 payload.

### Newly-registered and low-reputation domains (network/DNS)

- Source: DNS resolver logs, Zeek `dns.log` and `ssl.log`, secure web gateway / proxy logs (Zscaler, Palo Alto, Squid `access.log`), Sysmon Event ID 22 (DnsQuery) on endpoints.
- Hunt: correlate resolved domains against WHOIS registration age (flag age < 30 days) and against proxy category. A categorized domain defeats the category check but not the age check if it was freshly re-registered.

Splunk-style, Sysmon DNS on the endpoint:

```spl
index=sysmon EventCode=22
| lookup whois_age QueryName OUTPUT registration_days
| where registration_days < 30
| stats count dc(Computer) as hosts values(Image) as procs by QueryName
| where hosts < 5
```

### TLS fingerprint and certificate anomalies

- Source: Zeek `ssl.log` and `x509.log`, JA3/JA4 fingerprints (Zeek `ja3`/`ja4` fields, Suricata `tls.ja3.hash` / `ja3s`), Sysmon does not give JA3 - get it from network sensors.
- Hunt:
  - Self-signed certs: `x509.log` where issuer == subject, or short validity windows.
  - Known-bad JA3/JA4: match client hashes against threat-intel sets for C2 frameworks. Watch for a JA3 that does not match the advertised UA (TLS stack vs claimed browser).
  - CT-log monitoring: subscribe to certstream / crt.sh for lookalikes of your own brand - catches typosquat redirectors before traffic flows.

Zeek/Suricata Sigma-style logic:

```yaml
title: C2 redirector TLS anomaly - default cert or UA/JA3 mismatch
logsource:
  category: network_connection
  product: zeek
detection:
  selfsigned:
    x509.certificate.issuer|contains: x509.certificate.subject   # conceptual: issuer == subject
  default_c2_cert:
    ssl.cert_serial: '<known framework default serial>'          # populate from TI, do not guess
  condition: selfsigned or default_c2_cert
level: high
```

Note: populate `ssl.cert_serial` and JA3 sets from current threat intel; do not hardcode a serial you have not verified.

### Beaconing detection (timing)

- Source: proxy/firewall netflow, Zeek `conn.log` (aggregate by `id.resp_h` + `id.resp_p`), EDR network telemetry.
- Hunt: per destination, compute connection inter-arrival times; low variance (tight standard deviation around a mean interval) plus consistent bytes-out indicates beaconing. RITA, Zeek's heuristics, and most EDRs ship this. Jitter widens the variance but a clustered distribution still surfaces.

```spl
index=proxy sourcetype=zeek:conn
| streamstats current=f last(ts) as prev_ts by id.resp_h
| eval delta = ts - prev_ts
| stats count avg(delta) as mean_int stdev(delta) as jitter
        avg(orig_bytes) as avg_out by id.resp_h
| where count > 20 AND jitter < (mean_int * 0.25)
| sort - count
```

### Redirector decoy and HTTP-layer signals

- Source: proxy access logs, Zeek `http.log`.
- Hunt: a destination that returns 302-to-a-different-domain or identical decoy content to crawler UAs but full responses to one specific UA/URI combination is a redirector tell. Look for hosts where almost all observed requests share one exact User-Agent and one or two URIs - real sites have UA and path diversity; a redirector's beacon traffic does not.
- SNI/Host mismatch: where TLS inspection is available, alert on `ssl.server_name != http.host` for the same flow.

### Endpoint-side corroboration

- Sysmon Event ID 22 (DnsQuery): unusual process making DNS queries (e.g. `rundll32.exe`, `regsvr32.exe`, an Office child process resolving an external domain).
- Sysmon Event ID 3 (NetworkConnect): the same process opening outbound 443 to a low-reputation destination right after.
- Windows Security 5156 (Filtering Platform permitted connection) if WFP auditing is enabled - corroborates process-to-destination at the kernel filter layer.

osquery to surface non-browser processes holding outbound HTTPS sockets (endpoint corroboration):

```sql
SELECT p.name, p.path, pos.remote_address, pos.remote_port
FROM process_open_sockets pos
JOIN processes p ON pos.pid = p.pid
WHERE pos.remote_port = 443
  AND pos.protocol = 6                        -- TCP
  AND p.name NOT IN ('chrome.exe','msedge.exe','firefox.exe','svchost.exe');
```

### DNS C2 redirector signals

- Source: Zeek `dns.log`, resolver logs.
- Hunt: high count of TXT/NULL/long-label queries to one second-level domain, high entropy in subdomain labels, and query volume to a single authoritative NS that the org has never used. Aggregate distinct subdomains per parent domain per host; a tunnel produces hundreds of unique labels under one parent.

### Threat-intel on known C2 profiles

- Match served HTTP responses, header ordering, and URIs against published malleable-profile indicators (e.g. the default Cobalt Strike profile's checksum8 URIs and header patterns). Cross-reference JA3S (server-side fingerprint) and HTTP response fingerprints. See [malleable-profiles](../malleable-profiles.md) for how operators alter these to defeat exactly this matching.

## MITRE ATT&CK

- T1071.001 - Application Layer Protocol: Web Protocols (HTTP/S beaconing through redirectors)
- T1071.004 - Application Layer Protocol: DNS (DNS redirectors / tunneling)
- T1090.002 - Proxy: External Proxy (redirector hosts in front of the team server)
- T1090.004 - Proxy: Domain Fronting (legacy; largely defeated at major CDNs)
- T1568.002 - Dynamic Resolution: Domain Generation Algorithms (related infrastructure rotation)
- T1583.001 - Acquire Infrastructure: Domains (aged/categorized domain selection)
- T1583.003 - Acquire Infrastructure: Virtual Private Server (disposable redirector VPS)
- T1583.004 - Acquire Infrastructure: Server (team server)
- T1583.006 - Acquire Infrastructure: Web Services (cloud-function/CDN redirectors)
- T1608.003 - Stage Capabilities: Install Digital Certificate (Let's Encrypt cert on the redirector)
- T1573.002 - Encrypted Channel: Asymmetric Cryptography (TLS to hide payloads)

## A note on domain fronting (honest status)

Classic domain fronting - a benign domain in the TLS SNI and a different, attacker-controlled domain in the HTTP `Host:` header, both served by the same CDN - is largely dead at the major providers. Around 2018 Google and Amazon CloudFront disabled SNI/Host mismatch routing, and Cloudflare and Azure have since tightened or removed it. Do not plan an engagement around it at a tier-1 CDN. Conceptually adjacent techniques that operators discuss - "domain borrowing" (riding another tenant's already-categorized hostname on a shared CDN) and CDN edge/host-header tricks on misconfigured smaller providers - exist but are inconsistent, provider-specific, and brittle; treat them as opportunistic, not load-bearing. The durable, modern equivalent is reputation laundering through cloud functions and trusted web services (T1583.006/T1071.001): the egress is a major provider's IP and cert, which buys the same "blends with normal traffic" benefit without depending on a Host/SNI split. From the defender's side, the residual signal is the same one that killed fronting - watch for SNI/Host mismatch where TLS inspection exists, and treat high-volume beacon-shaped traffic to shared-CDN edges as worth a second look even when the SNI is reputable.

## References

- MITRE ATT&CK, T1090 Proxy and sub-techniques: https://attack.mitre.org/techniques/T1090/
- MITRE ATT&CK, T1071 Application Layer Protocol: https://attack.mitre.org/techniques/T1071/
- MITRE ATT&CK, T1583 Acquire Infrastructure: https://attack.mitre.org/techniques/T1583/
- Salesforce Engineering, JA3/JA3S TLS fingerprinting: https://github.com/salesforce/ja3
- FoxIO, JA4+ network fingerprinting suite: https://github.com/FoxIO-LLC/ja4
- Zeek documentation, ssl.log / x509.log / conn.log / dns.log: https://docs.zeek.org/en/master/logs/index.html
- Microsoft, Sysmon (Event ID 3 NetworkConnect, Event ID 22 DnsQuery): https://learn.microsoft.com/en-us/sysinternals/downloads/sysmon
- Google Security Blog, "A look at the latest changes to domain fronting" (CDN policy changes): https://security.googleblog.com/
- crt.sh Certificate Transparency search: https://crt.sh/
