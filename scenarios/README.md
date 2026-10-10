# The Channel Spectrum — every medium the dual pillars can ride

> rttp:// and iqa:// are channel-agnostic by construction. The protocol never talks to the network: its entire work is **a set of bytes plus one local computation** (one SHA-256, one Ed25519 verification). Any medium that can move bytes — fiber, radio, sound, magnetism, paper, a pigeon — can carry the dual pillars. The Internet is simply the cheapest landlord available today; we are epibiotic on whoever transports bytes.

## The three operating modes

| mode | freshness guarantee | when it applies |
|---|---|---|
| **live lease** | 120 s window; reject on skew | any channel with minutes-level latency (fiber, cellular, ISM radio, Wi-Fi) |
| **lease residual** | "last known lease"; the answer is honest about its age | store-and-forward channels (satellite passes, delay-tolerant mesh, carried media) — per D4 lease-residual decision vectors |
| **archival** | no freshness check (`check_freshness=False`) | sealed records, printed envelopes, audit copies — the seal is still fully verifiable |

## The spectrum (fiber → paper)

| # | channel | bandwidth/latency | mode | file |
|---|---|---|---|---|
| 1 | fiber & cable | Gb/s · ms | live lease | [fiber-cable](fiber-cable.md) |
| 2 | cellular radio (NB-IoT/LPWAN) | kb/s · s | live lease | [cellular-radio](cellular-radio.md) |
| 3 | ISM free-band radio (LoRa etc.) | B/s–kb/s · s | live lease (broadcast standing) | [ism-radio-lora](ism-radio-lora.md) |
| 4 | satellite store-and-forward | B/s · hours | lease residual | [satellite-store-forward](satellite-store-forward.md) |
| 5 | underwater acoustics | B/s · s–min | lease residual | [acoustic-underwater](acoustic-underwater.md) |
| 6 | through-the-earth (mines) | B/min | archival + residual | [tte-mine](tte-mine.md) |
| 7 | visible light / LiFi / IR | kb/s–Mb/s · ms | live lease | [visible-light](visible-light.md) |
| 8 | NFC / RFID | kB · contact | live lease (contact moment) | [nfc-rfid](nfc-rfid.md) |
| 9 | paper: QR / barcode / plaintext | ~1–3 kB per print · hours | archival | [paper-qr-barcode](paper-qr-barcode.md) |
| 10 | postal / courier / carrier pigeon | days | archival | [postal-courier](postal-courier.md) |

## The doctrine

- "No lookup, no TTL, no registry, no DNS" has a fifth corollary: **the protocol never talks to the network**. It does not marry any transport; whoever moves bytes is a peer, not a foundation.
- The worse the channel, the **larger the dual pillars' relative advantage**: IP/DNS die at the mine entrance; a 128-byte envelope rides anything down to paper.
- A robot does not need to be online. It needs **the latest envelope and local computation**. Where bytes cannot go, the envelope itself travels.
- Naming: rttp = Resonant Time Transfer Protocol — time transfer by radio is a century-old discipline (BPM/BPL/WWV). The name always was a claim.

Cross-refs: [conformance challenge](https://iqa.org/challenge/) · [release attestations](https://iqa.org/attestations/) · [draft-li-rttp-iqa-addressing](https://datatracker.ietf.org/doc/draft-li-rttp-iqa-addressing/) · whitepaper Chapter 6 (working draft).
