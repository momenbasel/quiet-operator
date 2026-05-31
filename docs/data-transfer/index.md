---
title: "2. Data Transfer"
nav_order: 3
has_children: true
---

# Data Transfer & Exfiltration

Six pages covering every layer of getting data out - from the strategy (what to take,
how to stage) through encoding/encryption (and its telemetry cost), to the transport
channels and the rate/timing discipline that determines whether it gets caught.

The base64 encoding telemetry lesson runs throughout this section and has a dedicated
deep-dive in [Detection Mapping](../detection-mapping/base64-and-encoding-telemetry).

| Page | Covers |
|---|---|
| [Exfil Principles & Staging](01-exfil-principles-and-staging) | What to take, staging location, channel selection decision tree |
| [Encoding, Compression & Encryption](02-encoding-compression-encryption) | base64 telemetry deep-dive, compress-then-encrypt, splitting |
| [DNS Tunneling](03-dns-tunneling) | Low-and-slow DNS exfil, label encoding, query analytics |
| [HTTPS & Cloud Exfil](04-https-and-cloud-exfil) | TLS metadata, SaaS blending, JA3/JA4 |
| [Covert Channels](05-covert-channels) | ICMP, timing, steganography, protocol field abuse |
| [Out-of-Band & Throttling](06-out-of-band-and-throttling) | Rate shaping, jitter, off-hours, USB |
