# Malleable Profiles, Sleep & Jitter

*Shaping beacon traffic so it reads as a known-benign application, and accepting that the same transforms which fool a human analyst are exactly what a periodicity model and a JA3 hash catch. Profile choices are detection choices.*

This page is framework-agnostic. "Malleable profile" is Cobalt Strike's name for the idea, but the concept - a declarative description of what every C2 request and response looks like on the wire - applies to any modern HTTP/S beacon (Mythic C2 profiles, Sliver, Havoc, Brute Ratel, custom implants). Pair it with the redirector and infrastructure material in this directory, the egress profiling in [../linux/06-network-stealth-and-tunneling.md](../linux/06-network-stealth-and-tunneling.md), the encoding telemetry in [../data-transfer/02-encoding-compression-encryption.md](../data-transfer/02-encoding-compression-encryption.md), and the operator threat model in [../00-foundations/operator-opsec-model.md](../00-foundations/operator-opsec-model.md).

## What & why

The goal is to make periodic command-and-control traffic indistinguishable from routine application traffic that already exists in the target's baseline, so that a defender doing content inspection sees a plausible request to a plausible URI with a plausible header set, and a defender doing flow analysis cannot lock onto a fixed beacon interval. Two independent control surfaces do this: the malleable profile shapes the *content and structure* of each transaction (URIs, methods, headers, User-Agent, where the encrypted session metadata is hidden, and how the response is framed), while sleep and jitter shape the *timing* of transactions (how long the implant waits between check-ins and how much that interval randomly varies). The OPSEC rationale is that signature and reputation defenses are cheap and behavioral defenses are expensive; a good profile forces the defender off cheap signatures and onto periodicity analytics, JA3/JA4 correlation, and request-size statistics - and a bad profile (a default public profile, raw base64 in a default URI, a fixed 60-second sleep with zero jitter) hands all three back for free. Regularity is the enemy. Defaults are signatured. The whole exercise is buying time by raising the analyst cost per detection.

## Technique

### The profile concept: what a transaction declares

A malleable/traffic profile is a specification of one or more request/response templates. Conceptually, every C2 transaction has the following shaping points, and the profile sets each:

- HTTP method and verb shape - whether check-in is a `GET` (poll, small) or a `POST` (task delivery / output return, larger body). Real applications mix both; an implant that only ever `GET`s a static path is a tell.
- Request URI and path - the path the beacon requests. A telemetry-collecting SDK posts to `/v2/track`, an update client polls `/api/updates/check`, an analytics beacon hits `/collect`. The profile copies a real one.
- Headers and ordering - `Host`, `Accept`, `Accept-Language`, `Accept-Encoding`, `Connection`, `Referer`, and any application-specific headers (for example `X-Requested-With`, custom auth headers). Header *order* and casing are themselves a fingerprint.
- User-Agent - must match a real client that plausibly runs on the host (a browser UA on a server with no browser is anomalous; an SDK UA is better on a server).
- Where session metadata lives - the encrypted/encoded implant metadata (session ID, task ID) is carried somewhere innocuous: a cookie, a custom header, a query-string parameter, or framed inside the body. The profile says which, and what transform wraps it.
- Body transforms - the request and response bodies are run through a transform stack (see below) and optionally prepended/appended with static, benign-looking strings so the raw blob is not the entire body.
- Response shape - the server's reply is framed to look like the chosen application's real response (a JSON envelope, an HTML page, a 1x1 GIF, a JS file), with the tasking hidden inside.

The conceptual model: pick a real application that already talks to the internet from this class of host, capture several real transactions, and author the profile to reproduce them. The implant's data is the only thing that changes; everything around it is a copy of legitimate traffic.

### Data transform stacks and the base64-on-the-wire tell

Profiles describe how implant data is encoded for transit as an ordered transform stack. In Cobalt Strike malleable syntax these are the `base64`, `base64url`, `netbios`, `netbiosu`, `mask`, `prepend`, and `append` statements; other frameworks expose the same primitives under different names. A representative stack:

```text
# Conceptual transform stack (Cobalt-Strike-style malleable syntax)
http-get {
    set uri "/api/v2/metrics";
    client {
        header "Accept" "application/json";
        metadata {
            mask;                 # XOR with a random per-message key (breaks static content match)
            base64url;            # URL-safe base64 so it survives a query string / header
            prepend "session=";   # make it read like a real cookie value
            header "Cookie";      # carry it in the Cookie header
        }
    }
    server {
        header "Content-Type" "application/json";
        output {
            mask;
            base64;
            prepend "{\"status\":\"ok\",\"data\":\"";  # frame as a JSON envelope
            append "\"}";
            print;
        }
    }
}
```

The critical detection fact: `base64` and `base64url` are the *same* base64 that defenders hunt for on the wire. A 200-character base64 string sitting in a query parameter or a Cookie is a high-fidelity content signature regardless of how clean the rest of the profile is. This is why `mask` (a random XOR key prepended to the ciphertext) matters - it removes the constant base64 alphabet distribution and the fixed prefix bytes that survive into a plain base64 encode, so a static content rule no longer matches. A sloppy profile that puts raw `base64` in a default or guessable URI is itself an IOC, and the base64-specific detection mechanics (Shannon entropy thresholds, alphabet ratio, length-modulo-4, `==` padding) are covered in depth in [../data-transfer/02-encoding-compression-encryption.md](../data-transfer/02-encoding-compression-encryption.md). The transform stack does not make the data invisible; it changes *which* signature class fires. Order matters: `mask` before `base64` randomizes the input so the output alphabet looks uniform; `base64` before `mask` would XOR an already-recognizable base64 string and is pointless.

### Sleep and jitter: breaking fixed-interval beaconing

Two implant parameters control timing:

- Sleep - the base interval between check-ins (for example 60 seconds, or 3600 seconds for a low-and-slow beacon).
- Jitter - a percentage by which each individual sleep is randomly reduced. With sleep S and jitter J percent, the actual wait per cycle is drawn from the half-open interval `[S * (1 - J/100), S]`. So `sleep 60s, jitter 0` produces a check-in exactly every 60 seconds; `sleep 60s, jitter 50` produces a check-in every 30 to 60 seconds, drawn pseudo-randomly each cycle.

Operator commands (Cobalt-Strike-style Beacon console; other frameworks use equivalent syntax):

```text
# Beacon console
sleep 3600 37    # base 3600s (1h) check-in, 37% jitter -> 2268s..3600s actual wait
sleep 0          # interactive mode: check in continuously (LOUD - use only briefly)
```

```text
# Sliver-style equivalent on a session/beacon
reconfig --reconnect 3600s --jitter 37s
```

The detection this defeats: fixed-interval beaconing is the single most reliable C2 behavioral signal because it survives encryption. A defender does not need to read your TLS payload to notice that host 192.0.2.50 contacts 198.51.100.10 every 60.0 seconds with sub-second variance. Autocorrelation and FFT (next section) lock onto that period. High jitter on a long sleep smears the inter-arrival distribution so there is no single dominant period to lock onto. The trade is interactivity: a 1-hour sleep with 37% jitter means a tasking issued now may not execute for up to an hour, and an interactive shell is impossible. Operators run long-sleep/high-jitter as the default posture and only drop to short sleep (or `sleep 0`) for the few minutes of an interactive action, then return to the slow profile. Oversized jitter helps stealth and hurts ops; that tension is the whole point.

### host_stage, useragent, and certificate configuration

Three listener/profile settings produce some of the loudest tells if left at default:

- `set host_stage` - controls whether the team server will serve the second-stage payload over HTTP from the staging URI. Staging over cleartext HTTP means the full stage transits the wire unencrypted and is trivially YARA-matched (default stagers are heavily signatured). Set `host_stage "false"` and deliver the stage out-of-band (a stageless payload, or stage over the already-established encrypted channel). Stageless beacons remove the staging request entirely, which removes both the network tell and the in-memory unbacked-RWX allocation pattern that EDR flags during staging.
- `set useragent` - the global default User-Agent. Leaving it at a framework default UA, or setting a browser UA on a host that has no browser, is an anomaly. The UA must match a client that plausibly runs on this host class.
- Listener certificate / `https-certificate` and `code-signer` - a self-signed or default-keystore TLS certificate (default Subject/Issuer fields, default validity) is fingerprintable and feeds reputation scoring. Use a properly issued certificate (for example via an ACME CA) for the C2 hostname, and front the listener with a redirector so the certificate the client validates belongs to the redirector domain, not the team server. The TLS layer also produces a JA3/JA4 hash from the ClientHello - profile content shaping does nothing for that; see Detection.

### Profile hygiene: never ship a public or default profile

Public malleable profiles (the ones shipped in framework repos, in well-known profile collections on GitHub, in tutorials and blog posts) are fingerprinted by every serious EDR and many IDS rulesets. Shipping one is equivalent to shipping a known signature. Hygiene rules:

- Author per-engagement. Capture real traffic from the target's own application baseline and reproduce it; do not reuse a profile across engagements.
- Lint the profile before use. Cobalt Strike ships `c2lint`, which validates syntax and flags obvious tells; run it and read every warning.
- Strip default artifacts. Default pipe names, default named-process spoofing values, default `spawnto` paths, default GET/POST URIs (`/ca`, `/dpixel`, `/__utm.gif`, `/submit.php` and similar well-known defaults) are all signatured. Replace every one.
- Match the host class. A profile mimicking a browser SaaS app on a print server is more anomalous than a generic one. The profile must fit where the implant runs.
- Keep request sizes irregular. If every check-in body is the same length, that length is a signature by itself; pad with variable-length benign filler.

## OPSEC notes

What makes the loud version loud:

- Fixed interval. `sleep 60, jitter 0` is the textbook beacon and the first thing a periodicity hunt finds. Zero jitter is never acceptable outside a deliberate interactive burst.
- Default profile. Any public/default profile means a known content signature, a known URI set, a known UA, a known certificate shape. This is the most common single mistake.
- Raw base64 in a default URI. `GET /submit.php?id=<long-base64>` is a content match on two axes at once (the default path and the base64 body). `mask` plus a realistic URI fixes the content match; it does nothing for timing or TLS fingerprint.
- HTTP staging on. `host_stage true` puts a signatured stager on the wire in cleartext and creates the classic stage-then-RWX-allocate pattern in memory.
- UA/host mismatch. A browser UA on a headless server, or a framework-default UA anywhere, is an anomaly even if everything else is clean.
- Uniform request size. Identical body length every cycle is a signature independent of content.

The quiet variant: a per-engagement profile copied from the target's real baseline traffic, `mask` ahead of any base64 transform, a realistic non-default URI and UA matched to the host class, a properly issued certificate fronted by a redirector, stageless delivery (`host_stage false`), a long base sleep with substantial jitter (for example 30 to 60 minutes base, 30 to 50 percent jitter) as the resting posture, and variable-length padding so request sizes scatter. Drop to a short sleep only for the duration of an interactive action and restore the slow posture immediately.

Failure modes and tells that survive a good profile:

- JA3/JA4. The TLS ClientHello fingerprint is produced by the implant's TLS stack, not the profile. If the implant's TLS library yields a ClientHello that does not match any normal client on the host, content shaping is irrelevant. This is the most common residual tell.
- Destination reputation and newness. A first-seen domain/IP with no history scores badly regardless of how the request is shaped. Domain age, categorization, and prior-traffic baseline are independent of profile content.
- DNS resolution pattern. Resolving the C2 domain on a fixed cadence reintroduces periodicity at the DNS layer even if the HTTP layer is jittered. Cache TTL handling matters.
- Long-lived sessions vs. baseline. A multi-hour single TLS session, or many short sessions to the same destination, may itself deviate from the application being mimicked.
- Over-jitter operational cost. Too much jitter delays tasking past the point of usefulness and can cause an operator to drop the slow profile under pressure - which produces a sudden, visible cadence change that a baseline-deviation alert catches.

## Detection & telemetry

This is the section that matters. The defender's advantage is that timing and metadata survive encryption: you do not need to decrypt TLS to detect a beacon. Look in these places.

### Beaconing / periodicity analytics (the primary signal)

Compute the inter-arrival times between connections from each internal host to each external destination, then test the distribution for regularity.

- Source data: Zeek `conn.log` (`ts`, `id.orig_h`, `id.resp_h`, `id.resp_p`, `orig_bytes`, `resp_bytes`, `duration`), NetFlow/IPFIX from a router/firewall exporter, or proxy access logs. No payload decryption required.
- Method 1, autocorrelation: bin connection timestamps per (src, dst) pair and compute the autocorrelation of the inter-arrival series. A strong peak at a fixed lag is a fixed period; high jitter flattens the autocorrelation, so an unusually *low* variance is itself the alert.
- Method 2, FFT / spectral: take the FFT of the binned connection time series; a sharp spectral spike at one frequency is a dominant beacon period. Jitter spreads energy across frequencies, raising the noise floor and lowering the peak.
- Method 3, simple statistics: per (src, dst) pair, compute the coefficient of variation (stddev / mean) of inter-arrival times. A CV near zero is a near-perfect beacon. Many production hunts threshold on low CV plus a minimum connection count.
- Reference tooling: RITA (Real Intelligence Threat Analytics) consumes Zeek logs and scores beacons on exactly these features; AC-Hunter is its commercial successor. Splunk and Elastic ship beacon-hunting analytics built on the same inter-arrival math.

Example Splunk-style beacon hunt over proxy/Zeek connection events (interval regularity by source/destination):

```spl
index=zeek sourcetype=conn
| sort 0 id.orig_h id.resp_h _time
| streamstats current=f last(_time) as prev_time by id.orig_h id.resp_h
| eval interval = _time - prev_time
| where isnotnull(interval)
| stats count as conns, avg(interval) as avg_int, stdev(interval) as sd_int by id.orig_h id.resp_h id.resp_p
| eval cv = sd_int / avg_int
| where conns >= 20 AND cv < 0.10
| sort cv
```

Equivalent KQL over a connection table (for example a normalized network or proxy table):

```kql
NetworkConnLogs
| sort by SrcIp asc, DstIp asc, TimeGenerated asc
| serialize
| extend prev = prev(TimeGenerated, 1), prevSrc = prev(SrcIp, 1), prevDst = prev(DstIp, 1)
| where SrcIp == prevSrc and DstIp == prevDst
| extend interval = datetime_diff('second', TimeGenerated, prev)
| summarize conns = count(), avgInt = avg(interval), sdInt = stdev(interval) by SrcIp, DstIp, DstPort
| extend cv = sdInt / avgInt
| where conns >= 20 and cv < 0.10
| sort by cv asc
```

Note for defenders: high-jitter beacons defeat the low-CV threshold above. Pair it with a tolerance-banded interval test (cluster intervals and ask whether a large fraction fall within +/- the jitter window of a candidate base period) and with the request-size regularity check below, which jitter does not affect.

### TLS fingerprinting: JA3 / JA4

- Source data: Zeek `ssl.log` with the JA3 plugin, JA4 via the Zeek JA4 plugin or an EDR/NDR that computes it, or a TLS-aware proxy. JA3 hashes the ClientHello (version, cipher suites, extensions, elliptic curves, EC point formats); JA4 is the newer, more robust successor.
- Hunt: enumerate JA3/JA4 hashes seen on the network and flag hashes that are rare, that do not match the User-Agent claimed in any associated HTTP request, or that match published fingerprints for known offensive tooling TLS stacks. A mismatch between the JA3 (the real TLS library) and the User-Agent (what the profile claims) is high-fidelity: the profile lied about the client and the TLS stack told the truth.
- This fires regardless of malleable content shaping, because the profile does not control the ClientHello.

### Known-profile and URI/UA content signatures

- Source data: IDS (Suricata/Snort) alerts, proxy access logs, Zeek `http.log` (`host`, `uri`, `user_agent`, `request_body_len`, `response_body_len`, `method`, `status_code`).
- Default-profile signatures: Suricata/Emerging Threats and vendor rulesets ship signatures for default Cobalt Strike URIs and response bodies, default Meterpreter/Metasploit stagers, and other framework defaults. A default profile triggers these directly.
- URI / UA anomaly: hunt for User-Agent strings that are rare in the environment, that claim a browser on a host with no browser process, or that appear with a destination that has no web-browsing history. Hunt for URIs that match known default paths.
- base64-in-URI / body content match: a content rule for a long high-entropy base64 token in a query string, Cookie, or small request body. Example Suricata-style logic (illustrative): match an outbound HTTP request whose URI or Cookie header contains a base64 run above a length threshold with base64 alphabet characters and `==`/`=` padding. The `mask` transform defeats this; raw base64 does not. Full base64 detection mechanics (entropy, alphabet ratio, length modulo 4) are in [../data-transfer/02-encoding-compression-encryption.md](../data-transfer/02-encoding-compression-encryption.md).

Example Sigma-style rule sketch (HTTP proxy logs) for a suspicious UA/host-class mismatch plus regular small GETs - tune to environment:

```yaml
title: Possible HTTP Beacon - Rare User-Agent to First-Seen Destination
logsource:
    category: proxy
detection:
    selection:
        cs-method: 'GET'
    filter_known_ua:
        cs-user-agent:
            - '*Mozilla*'   # replace with your environment's allowlist of expected UAs
    condition: selection and not filter_known_ua
fields:
    - src_ip
    - cs-host
    - cs-uri-stem
    - cs-user-agent
    - sc-bytes
level: medium
```

### Request-size regularity (independent of timing jitter)

- Source data: Zeek `http.log` / `conn.log` byte counts (`request_body_len`, `response_body_len`, `orig_bytes`, `resp_bytes`), proxy `sc-bytes`/`cs-bytes`.
- Hunt: per (src, dst) pair, compute the distribution of request and response sizes. A beacon with no size padding produces a tight cluster of near-identical sizes even when timing is jittered. Low size variance plus a moderate-or-higher connection count is a strong supporting signal that timing jitter alone cannot hide. This is why size padding belongs in the profile.

### Host-side correlation

Network detection is strongest when joined to the endpoint. Pivot from a flagged (src, dst) pair to the host:

- Windows: Sysmon Event ID 3 (network connection) gives the `Image` (process) and `DestinationIp`/`DestinationPort` for the connecting process. A beacon destination tied to an unexpected `Image` (an Office app, a signed LOLBin, an unbacked memory region's host process) is the join that turns a network anomaly into an incident. Sysmon Event ID 22 (DNS query) ties the periodic DNS resolution to the same process.
- Linux: auditd `connect`/`sendto` syscall records (an audit rule on the `connect` syscall) and `execve` records correlate the process and command line to the flagged destination. See the host-side network tradecraft and its telemetry in [../linux/06-network-stealth-and-tunneling.md](../linux/06-network-stealth-and-tunneling.md).
- An osquery live check enumerating established sockets joined to process metadata (for example `process_open_sockets` joined to `processes`) lets a defender sweep fleet-wide for a flagged destination and attribute it to a process and binary path on demand.

The defender's playbook: start from periodicity analytics on flow/proxy/Zeek data to surface candidate beacons cheaply, confirm with JA3/JA4 mismatch and request-size regularity (both survive jitter), check for default-profile content signatures, then pivot to the host via Sysmon EID 3/22 or auditd to attribute the process. A good profile forces all of these in sequence instead of one cheap signature; it does not remove any of them.

## MITRE ATT&CK

- T1071.001 - Application Layer Protocol: Web Protocols (C2 over HTTP/S shaped to look like web traffic).
- T1071.004 - Application Layer Protocol: DNS (when the profile rides DNS).
- T1573.001 - Encrypted Channel: Symmetric Cryptography (the masked/encrypted payload transform).
- T1573.002 - Encrypted Channel: Asymmetric Cryptography (TLS-wrapped C2).
- T1001.002 - Data Obfuscation: Steganography (hiding implant metadata inside benign-looking fields).
- T1001.003 - Data Obfuscation: Protocol or Service Impersonation (mimicking a known-benign application's traffic).
- T1132.001 - Data Encoding: Standard Encoding (base64/base64url transforms on the wire).
- T1132.002 - Data Encoding: Non-Standard Encoding (netbios, mask, custom transforms).
- T1029 - Scheduled Transfer (long-sleep, jittered check-in cadence as a timing-control behavior).
- T1008 - Fallback Channels (alternate profiles/listeners for resilience).
- T1090.002 - Proxy: External Proxy (redirector fronting the team server and its certificate).

## References

- MITRE ATT&CK, T1071 Application Layer Protocol and sub-techniques. https://attack.mitre.org/techniques/T1071/
- MITRE ATT&CK, T1573 Encrypted Channel. https://attack.mitre.org/techniques/T1573/
- MITRE ATT&CK, T1001 Data Obfuscation. https://attack.mitre.org/techniques/T1001/
- Cobalt Strike Malleable C2 reference documentation (profile language, transform statements, host_stage, c2lint). https://hstechdocs.helpsystems.com/manuals/cobaltstrike/current/userguide/content/topics/malleable-c2_main.htm
- John Althouse et al., JA3/JA3S TLS fingerprinting (Salesforce Engineering). https://github.com/salesforce/ja3
- John Althouse, JA4+ network fingerprinting suite (FoxIO). https://github.com/FoxIO-LLC/ja4
- Active Countermeasures, RITA (Real Intelligence Threat Analytics) - beacon detection on Zeek logs. https://github.com/activecm/rita
- The Zeek Project documentation - conn.log, http.log, ssl.log field references. https://docs.zeek.org/en/master/logs/index.html
- Microsoft Sysinternals Sysmon documentation - Event ID 3 (network connection), Event ID 22 (DNS query). https://learn.microsoft.com/en-us/sysinternals/downloads/sysmon
