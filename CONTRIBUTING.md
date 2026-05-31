# Contributing

Contributions are welcome from operators and defenders alike. To keep the
knowledge base coherent and dual-use-honest, every page follows the same shape.

## Page contract

Each technique page MUST contain, in order:

1. **What & why** — one paragraph: the goal and the OPSEC rationale.
2. **Technique** — concrete commands / steps in fenced code blocks, with inline notes.
3. **OPSEC notes** — what makes the loud version loud; the quiet variant; failure modes.
4. **Detection & telemetry** — the exact artifacts produced (log source, event ID,
   field, file path, syscall) and how a defender hunts it. This section is mandatory.
   A technique with no detection section will not be merged.
5. **MITRE ATT&CK** — technique IDs.
6. **References** — primary sources.

## Rules

- **No live targets, no real loot, no client data.** Examples use RFC-5737
  documentation IPs, `example.com`, and lab hostnames only.
- **Pair every offense with detection.** This repo is purple, not red-only.
- Prefer **native / built-in** tooling examples; call out when a dropped binary is required.
- Keep commands copy-pasteable and labelled with the platform/shell they assume.
- ASCII only in prose. `-` for dashes, never em-dashes.

## Scope of the project

Linux first and deepest, then data-transfer/exfil tradecraft, then Windows, then
shared C2 infrastructure OPSEC, then the defender's cross-mapping.
