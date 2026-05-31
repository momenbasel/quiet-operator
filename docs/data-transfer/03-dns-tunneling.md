# DNS Tunneling & Exfiltration

*Low-and-slow data egress encoded into DNS queries that ride out through the recursive resolver to an authoritative name server you control.*

## What & why

DNS is the egress channel of last resort that almost always works. In hardened
environments outbound TCP/443 may be proxied, inspected, and TLS-intercepted, raw
egress is dropped, and only a handful of protocols leave the perimeter cleanly.
DNS is one of them: endpoints rarely resolve names directly, they hand queries to
an internal recursive resolver, which forwards them outward on UDP/53 (or TCP/53,
or DoT/DoH upstream) on the host's behalf. From the perimeter's point of view the
exfiltrating host never talks to the internet at all - the resolver does. That
indirection is the whole point.

Because resolution is mandatory for the network to function, blanket-blocking DNS
is not an option, and the protocol carries attacker-controlled strings (the QNAME)
that get delivered to an authoritative server of the attacker's choosing. Any
domain you register makes you the authority for its zone, so you receive every
label any resolver on earth asks about under that domain. Encode bytes into those
labels and you have a covert one-way (or, with downstream records, two-way)
channel that survives most egress controls.

The trade-off is throughput and noise. DNS was never built to move data, so the
channel is slow, and moving real volume produces a query pattern that looks
nothing like normal name resolution. This page covers the mechanics, the OPSEC
limits, and - because this is a purple-team repo - the exact telemetry that
catches it. See [exfil principles](01-exfil-principles-and-staging.md) for staging
and channel selection, and [out-of-band & throttling](06-out-of-band-and-throttling.md)
for rate-shaping that applies directly here.

## Technique

### Why the resolver path matters

A normal forward lookup walks a chain: stub resolver on the host -> configured
recursive resolver -> root -> TLD -> the authoritative NS for the zone. For
tunneling, the operator owns the last hop. Register `lab.example.com`, delegate it
to a name server you run (`ns1.lab.example.com` pointing at your VPS), and every
query for `<anything>.lab.example.com` that any recursive resolver fails to find
in cache eventually arrives at your server. The victim host only ever speaks to
its own internal resolver - it never needs a route to your VPS, never opens a
socket to an external IP. That is what defeats simple egress firewall rules.

### Encoding data into labels

The payload travels in the QNAME. DNS imposes hard structural limits that bound
how much you can pack per query:

- A single label (the text between two dots) is capped at 63 octets.
- The full domain name is capped at 255 octets on the wire, ~253 in presentation
  form, and that budget includes your base domain, the dots, and length prefixes.
- Labels are case-insensitive and traditionally treated as a restricted character
  set, so binary cannot go in raw.

So the operator subtracts the fixed suffix (`.lab.example.com`) and any per-query
header bytes from the 253-char budget, then fills the remainder with
data-bearing labels. Binary is made DNS-safe with an encoding that maps to the
allowed character set - base32 is the classic choice because it is
case-insensitive and stays within label rules, base64url is denser but case and
character sensitivity make it fragile across resolvers that normalize case. See
[encoding/base32 in labels](02-encoding-compression-encryption.md) for the
encoding mechanics and [base64 & encoding telemetry](../detection-mapping/base64-and-encoding-telemetry.md)
for how that same encoding gives the channel away.

A rough per-query budget: with a 253-char name and a ~20-char base domain you have
~230 chars for encoded data. base32 carries 5 bits per character, so ~230 chars is
~143 bytes of pre-encoding payload, minus framing (session id, sequence number).
Real tooling reserves part of every QNAME for those control fields, so usable
payload per query is well under 150 bytes and often far less.

### Downstream: getting data back

Upstream (victim -> operator) is easy: the data is in the question. The reverse
direction (operator -> victim) has to ride in the answer, so tooling abuses
record types whose RDATA can carry arbitrary-ish bytes:

- TXT - largest practical answer payload, free-form strings, the workhorse for
  downstream data and command delivery.
- NULL - historically used by tunnels (notably iodine) because RDATA is
  unstructured, though many resolvers and middleboxes mishandle it.
- CNAME / A / AAAA / MX - lower-capacity carriers, but A/AAAA blend in better
  because they are the common-case record types; an operator can encode a few
  bytes into synthetic addresses or alias labels.

The victim issues a query (often with a sequence/poll id in the QNAME), the
operator's authoritative server answers with the next chunk in the chosen RR type,
and the loop continues. This is request-response polling, not a push channel.

### Tooling concepts

These are described at the concept level - this repo does not ship weaponization
recipes.

- iodine - tunnels IPv4 over DNS, historically leaning on NULL/TXT records, aims
  for higher throughput by maximizing payload per query and negotiating the best
  record type and encoding the path allows. Produces a routable tunnel interface.
- dnscat2 - purpose-built C2-style channel over DNS with an encrypted session
  layer, designed for command-and-control rather than bulk transfer, supports
  running fully over the DNS hierarchy (through recursive resolvers) or direct to
  the operator's server.
- dns2tcp - relays a TCP stream over DNS, typically TXT-based, oriented toward
  tunneling a specific service (e.g. SSH) rather than a general IP tunnel.

All three share the same skeleton: an authoritative server the operator controls,
QNAME-encoded upstream, RR-encoded downstream, a session/sequencing layer, and a
chosen encoding to survive the character constraints.

### Throughput and why it is slow

DNS tunneling is bandwidth-starved by design:

- Tiny per-query payload (well under 150 bytes upstream, similar or less down).
- Request-response polling adds a full round trip per chunk - latency, not just
  bandwidth, throttles you.
- Resolvers, middleboxes, and the authoritative path add per-query overhead.
- Pushing rate up to compensate is exactly what makes the channel loud (see
  OPSEC).

Practical sustained throughput lands in the low kilobits-per-second range for a
"quiet" configuration, higher only if you abandon stealth. Exfiltrating anything
large is measured in minutes to hours, which is why this channel suits small,
high-value loot (keys, credentials, a config file) and beaconing, not database
dumps.

### Caching and recursion behavior

Recursive resolvers cache answers by name and honor TTL. This has two consequences
the operator must design around:

- Cache hits hide queries from your server. If two victims (or one victim twice)
  ask the same QNAME, the resolver may answer from cache and your authoritative
  server never sees the second query. Tunnels defeat this by making every QNAME
  unique - a sequence number or nonce in each label - which guarantees a cache
  miss and forces the query out to you. That uniqueness is itself a detection
  signal: a flood of never-repeating, high-entropy names under one domain is not
  what normal traffic looks like.
- Setting low/zero TTL on answers prevents downstream answers from being stale.

The very mechanism that makes the channel work (forcing cache misses with unique,
encoded labels) is the mechanism that makes it detectable.

## OPSEC notes

The hard truth: you can slow the channel down, but you cannot make high-volume DNS
to a novel domain look normal. The tells, in rough order of how reliably they burn
you:

- Query volume to a single registered domain. Normal hosts spread DNS across many
  domains and repeat popular ones (cached). A tunnel concentrates a large,
  sustained query count on one second-level domain. This is the single hardest
  signal to evade because the channel structurally requires it.
- Long, high-entropy labels. base32/base64 payload looks like random text, with
  near-maximal Shannon entropy and label lengths pushed toward the 63-char cap.
  Real hostnames are short, dictionary-ish, low-entropy.
- Unique, never-repeating QNAMEs. The cache-busting nonce defeats analyst
  intuition about repeat queries and shows up as an abnormal unique-name ratio.
- Unusual record types. Heavy TXT or NULL usage from an endpoint is anomalous -
  most client traffic is A/AAAA with some others. Sticking to A/AAAA reduces this
  tell but cuts downstream capacity.
- NXDOMAIN patterns. Some tunnel modes and misconfigurations generate bursts of
  NXDOMAIN responses, a strong signal on its own.
- Constant-rate beaconing. A fixed inter-query interval is trivially periodic and
  pops out of any time-series analysis.

Mitigations and their ceilings:

- Add jitter and cap the rate. Randomize inter-query timing and keep volume low to
  blunt periodicity and reduce the absolute count - see
  [out-of-band & throttling](06-out-of-band-and-throttling.md). This helps, but
  volume to a novel domain remains visible.
- Prefer common record types (A/AAAA) over TXT/NULL to reduce the rare-RR tell, at
  the cost of capacity.
- Use a domain with some history/reputation rather than one registered yesterday,
  to dodge newly-registered-domain scoring.
- Keep total bytes small. The less you move, the fewer queries, the less signal.
  This channel is for small loot only.

None of these defeat a defender who is counting queries-per-domain and scoring
label entropy. Treat DNS tunneling as detectable-by-design and reserve it for when
nothing else egresses.

## Detection & telemetry

DNS tunneling is one of the more detectable covert channels precisely because its
required behavior diverges sharply from normal resolution. Hunt across these
sources and fields.

### Sources and fields

- Zeek `dns.log` - per-query records. Key fields: `query` (the QNAME, for length
  and entropy), `qtype_name` (rare RR types like TXT/NULL), `rcode_name`
  (NXDOMAIN rate), `id.orig_h` (the client), plus answer fields for downstream
  sizing. This is the richest single source for hunting.
- Suricata - DNS application-layer events and DNS rule keywords let you alert on
  query content, record type, and response code. Build rules around abnormal QNAME
  length and anomalous RR types rather than fixed strings.
- Resolver query logging - BIND `querylog`, Unbound logs, Windows DNS Server
  analytical/audit logging, or cloud resolver query logs (e.g. provider DNS query
  logging). These capture the QNAME and client at the resolver, the natural
  aggregation point for per-domain volume.
- EDR DNS telemetry - endpoint sensors that record process-attributed DNS queries
  let you tie the traffic to a specific binary, which is decisive for triage.
- Passive DNS - to assess the destination domain's age, reputation, and whether it
  is newly registered or low-prevalence.

### What to compute

- Queries-per-second-level-domain over a window. Outliers concentrating volume on
  one domain are the primary signal.
- QNAME length distribution - flag names near the 253-char cap or labels near 63.
- Shannon entropy of the QNAME (or the leftmost labels). High entropy indicates
  encoded payload rather than human-readable hostnames.
- Unique-QNAME ratio per domain - a high count of never-repeating names under one
  domain indicates cache-busting.
- NXDOMAIN rate per client/domain.
- RR-type distribution per client - excess TXT/NULL is anomalous.
- Domain reputation/age enrichment on the destination.

### Example hunt - long-label / high-volume DNS (Splunk SPL)

Surfaces clients sending many long, distinct DNS names to a single domain. Tune
thresholds to your baseline.

```spl
index=dns sourcetype=zeek:dns
| eval qname_len=len(query)
| rex field=query "(?<sld>[a-z0-9-]+\.[a-z]+)$"
| where qname_len > 50
| stats count AS total_q
        dc(query) AS unique_q
        max(qname_len) AS max_len
        avg(qname_len) AS avg_len
        sum(eval(rcode_name="NXDOMAIN")) AS nxdomain
        values(qtype_name) AS rr_types
        BY id.orig_h sld
| where total_q > 200 AND unique_q > 100
| eval unique_ratio=round(unique_q/total_q,2)
| sort - total_q
```

### Example hunt - high-volume long-QNAME DNS (Microsoft KQL)

Equivalent logic over a DNS events table (adapt the table and column names to your
schema, e.g. Sentinel DNS or a custom resolver log table).

```kusto
DnsEvents
| where TimeGenerated > ago(1h)
| extend QnameLen = strlen(Name)
| extend Sld = strcat_array(array_slice(split(Name, "."), -2, -1), ".")
| where QnameLen > 50
| summarize TotalQ = count(),
            UniqueQ = dcount(Name),
            MaxLen = max(QnameLen),
            AvgLen = avg(QnameLen),
            NxDomain = countif(ResponseCode == "NXDOMAIN"),
            RrTypes = make_set(QueryType, 10)
          by ClientIP, Sld
| extend UniqueRatio = round(todouble(UniqueQ) / TotalQ, 2)
| where TotalQ > 200 and UniqueQ > 100
| sort by TotalQ desc
```

Both queries lean on the same invariants the tunnel cannot escape: many queries,
to one domain, with long and mostly-unique names. Layer entropy scoring and RR-type
anomaly on top, and enrich the destination domain through passive DNS to separate
a tunnel from a noisy-but-legitimate service.

## MITRE ATT&CK

- T1071.004 - Application Layer Protocol: DNS (C2 over the DNS protocol).
- T1048 - Exfiltration Over Alternative Protocol (exfil over a non-C2 channel).
- T1048.003 - Exfiltration Over Unencrypted Non-C2 Protocol.
- T1572 - Protocol Tunneling (encapsulating other traffic inside DNS).
- T1568 - Dynamic Resolution (operator-controlled resolution infrastructure).
- T1132.001 - Data Encoding: Standard Encoding (base32/base64 of payload labels).

## References

- MITRE ATT&CK T1071.004, Application Layer Protocol: DNS - https://attack.mitre.org/techniques/T1071/004/
- MITRE ATT&CK T1048, Exfiltration Over Alternative Protocol - https://attack.mitre.org/techniques/T1048/
- MITRE ATT&CK T1572, Protocol Tunneling - https://attack.mitre.org/techniques/T1572/
- RFC 1035, Domain Names - Implementation and Specification (label/name size limits, RR types) - https://www.rfc-editor.org/rfc/rfc1035
- Zeek dns.log documentation - https://docs.zeek.org/en/master/logs/dns.html
- Suricata DNS keywords and logging - https://docs.suricata.io/en/latest/rules/dns-keywords.html
- iodine project (concept reference) - https://github.com/yarrick/iodine
- dnscat2 project (concept reference) - https://github.com/iagox86/dnscat2
