# Scenario · Satellite store-and-forward — LEO IoT constellations

**Channel profile:** B/s · hours between passes · one-way or relayed.

**Dual-pillar mode:** **lease residual** — per D4 decision vectors: answers inside vs outside the post-revocation cache are defined separately.

## How it works

The satellite is a courier, not a network. Envelopes are uploaded at pass time and verified at the destination offline. The 120 s window is not expected to hold; verification runs in archival mode and the answer honestly states its age.

## Honest limits

The guarantee degrades from "current lease" to "last known lease". This is stated by design, not hidden: an envelope from three passes ago is a different claim than one from sixty seconds ago, and the bytes say which is which.

## Cross-refs

Whitepaper Chapter 6 · D4 lease-residual decision vectors · [conformance challenge](https://iqa.org/challenge/) · [release attestations](https://iqa.org/attestations/)
