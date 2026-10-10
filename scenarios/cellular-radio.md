# Scenario · Cellular radio — NB-IoT / LPWAN verticals

**Channel profile:** kb/s · seconds · bidirectional where coverage exists.

**Dual-pillar mode:** **live lease** — one datagram carries WHERE and WHETHER.

## How it works

Whitepaper verticals (fleet, energy, industrial, payment, swarm) assume exactly this channel. The single-datagram Q&A shape exists because round trips are the dearest resource on duty-cycle links: one RTTP question plus one IQA answer does what used to take a lookup, a session, and a certificate check.

## Honest limits

Coverage and subscription are the landlord (a carrier). Duty cycles bill bytes; the 128-byte envelope was sized for this. Coverage gaps degrade to lease residual.

## Cross-refs

Whitepaper Chapter 6 · D4 lease-residual decision vectors · [conformance challenge](https://iqa.org/challenge/) · [release attestations](https://iqa.org/attestations/)
