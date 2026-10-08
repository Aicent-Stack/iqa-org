# iqa-org

**IQA for Rust: `iqa://` subject-attestation addressing, `IQA_ROUTE`
derivation, AICENT-009 sec. 11.3 action safety classes, the AE-128 fixed
attestation envelope -- and the published conformance vectors that prove an
implementation is right.**

[AICENT-009 sec. 10](https://iqa.org/AICENT-009/) - sec. 11 - spec v1.2.6 - zero dependencies (default build) - `#![forbid(unsafe_code)]`

---

## Verify it -- no trust required

```console
$ cargo test
...
test result: ok. 18 passed; 0 failed; 0 ignored

$ cargo test --features ed25519
...
test result: ok. 20 passed; 0 failed; 0 ignored
```

That is the point of this crate. A specification is worth exactly what an
independent implementation can reproduce from it -- so instead of asking you to
believe a table of numbers, this ships the vectors and replays them locally:
the conformance vector set (`8 positive URIs + 18 fail-closed rejections +
5 safety rows + the Ed25519 envelope vector`), plus the **AE-128 published
vector** -- reproduced byte for byte from the companion draft's documented
parameters -- behind a fail-closed structural matrix and a full-frame
authentication tamper matrix. Offline, no account, no network.

The three implementations -- Python (`pip install iqa-org`), JavaScript
(`npm install @aicent/iqa`), and this one -- **share no code** and agree byte
for byte on the same published vector set (`sha256 8529549e...`, shipped in all
of them) and on the AE-128 vector (`4bd14b6a...`).

---

## Install

```console
cargo add iqa-org
```

Zero dependencies in the default build: SHA-256 is implemented in-crate
(known-answer tested against NIST vectors), HMAC-SHA256 (RFC 2104) sits on top
of it, and the vector file is read through a minimal in-crate JSON reader. The
sovereign Ed25519 attestation envelope is available behind the optional
`ed25519` feature.

---

## Quickstart

```rust
use iqa_org::iqa_uri;

let parsed = iqa_uri::parse("iqa://3f9a1b2c.gateway.iqa").unwrap();

parsed.subject;        // "3f9a1b2c"   -- 8-hex routing short form of the AID
parsed.organ;          // "gateway"    -- closed set: forge | tss | gateway
parsed.action_omitted; // true         -- omitted = standing read (sec. 11.1)
parsed.action_safe;    // true         -- sec. 11.3
parsed.route_hex;      // "5c378581"   -- IQA_ROUTE, pure computation
```

### The two closed sets -- the deliberate difference from `rttp`

`rttp` accepts any well-formed action verb. **`iqa` does not.** AICENT-009 sec. 10.1
marks *both* segments "Closed set":

```rust
assert!(iqa_uri::parse("iqa://3f9a1b2c.gateway.iqa/pulse").is_err());   // 'pulse' is an rttp verb
assert!(iqa_uri::parse("iqa://3f9a1b2c.forgery.iqa").is_err());         // organ is forge|tss|gateway
```

Malformed input is rejected, not normalised: uppercase anywhere, `iqas://`,
userinfo, port, query and fragment all fail closed. Nothing is ever accepted
because a check could not be performed.

### One honest quirk of the grammar

The ABNF is an ordered choice (`hash-subject / name-subject`), so a lowercase
hex string of a **non-hash length** (9 digits, say) is a *name subject*, not an
error. The grammar is the grammar; vector #8 pins the behaviour so every
implementation agrees on it.

### Action safety classes (AICENT-009 sec. 11.3)

| `action` | Class | `action_safe` |
|:---|:---|:---|
| *(omitted)* | SAFE -- standing read | `true` |
| `verify` | SAFE -- read-only comparison | `true` |
| `audit` | NOT SAFE -- can trigger Authority Ischemia | `false` |
| `attest` | NOT SAFE -- state transition | `false` |
| `revoke` | NOT SAFE -- state transition | `false` |

Per sec. 11.2, dereferencing an `iqa` URI MUST NOT transition any subject's
standing. Tooling built on this crate MUST gate the three NOT-SAFE verbs
behind an explicit user action -- parsing one is not requesting one.

### AE-128 -- the fixed answer carrier (default build)

```rust
use iqa_org::envelope;

let shard = envelope::derive_intent_shard("f3b2a1c4.pillar.example")?;
let frame = envelope::encode(&envelope::EncodeParams {
    key: b"the organ key material",
    intent_shard: shard,
    organ: b"gateway",
    standing: envelope::STANDING_RADIANT,   // or a name via STANDING_NAMES
    lease_expiry: 1798761600,
    nonce: 1,
    flags: 0,
})?;
assert_eq!(frame.len(), envelope::SIZE);    // 128 -- one frame, one datagram

let r = envelope::verify(&frame, b"the organ key material", 1798761600 - 1, true);
assert!(r.ok);
assert_eq!(r.frame.unwrap().standing_name(), Some("radiant"));
```

Fixed offsets, HMAC-SHA256 over the whole frame with the attestation field
zeroed, the standing closed set at offset 80, constant-time compare, zero
dependencies. The published vector (`envelope::vector_1_frame()`) reproduces
byte for byte against the companion draft's parameters -- and against the
Python and JavaScript implementations.

### Attestation envelope (feature `ed25519`)

```toml
iqa-org = { version = "1.3.1", features = ["ed25519"] }
```

Ed25519, self-certifying (`AID = SHA-256(public key)`), domain prefix
`iqa-attest-v1`, `ts`/`nonce` inside the signature, 120-second freshness,
claim validation against both closed sets. The verifier needs only the
envelope -- no key directory, no issuer. The envelope **carries** a claim; it
does not **create** one (AICENT-009 sec. 10.4: parsing is not attestation).

---

## Scope -- what this crate is not

| | |
|:---|:---|
| OK **Validation / canonicalisation** | Real, and specified (AICENT-009 sec. 10.2 / sec. 10.3). |
| OK **Closed-set enforcement** | Real, and specified (sec. 10.1). |
| OK **IQA_ROUTE derivation** | Real (SPEC sec. 3, decision D1). |
| OK **Action safety classes** | Real, and specified (sec. 11.3). |
| OK **Attestation envelope** | Real, and specified (draft) -- feature `ed25519`. |
| OK **AE-128 fixed envelope** | Real, and specified (companion draft v0.3) -- default build, zero dependencies. |
| NO **Dereferencing / resolver service** | Not here. The codec computes; *answering* a standing read is an Organ's job (AICENT-009-C sec. 3). |
| NO **Staking, tiers, vitality** | Operator economics and telemetry -- AICENT-009 narrative, no cryptographic object here. |
| NO **Post-quantum Lattice Guard** | AICENT-009 sec. 12 #11 schedules it for v1.4.0; no implementation exists. |
| NO **Confidentiality** | Signing is not encryption. |

---

## Naming

| Ecosystem | Name | Status |
|:---|:---|:---|
| crates.io | `iqa-org` | **this crate** -- `1.3.1`, the first formal (non-pre-release) publication; the earlier `1.2.8-alpha` remains published and is not yanked |
| PyPI | **`iqa-org`** | **published** -- the Python reference implementation; `pip install iqa-org` (`import iqa`) |
| npm | **`@aicent/iqa`** | **published** -- the JavaScript independent implementation |

---

## Specification status

* **`iqa` URI scheme** -- submitted to IANA under RFC 7595, ticket **#1459963**:
  the scheme **name is approved**; the CRI number is in expert review. It is
  **not yet registered**. Please describe it that way. (The sibling `rttp`
  scheme **is** registered: Provisional, CRI 27.)
* **Internet-Draft (IETF)** -- under IETF review as the combined Individual
  Submission Internet-Draft `draft-li-rttp-iqa-addressing` (revision -00,
  16 pp., 2026-09-24, informational -- both schemes, one document):
  https://datatracker.ietf.org/doc/draft-li-rttp-iqa-addressing/ .
  An Internet-Draft is a working document -- it is not an IETF standard and
  carries no IETF endorsement.
* **URI grammar** -- AICENT-009 sec. 10.2 (frozen; this crate adds no syntax).
* **Dereference safety** -- AICENT-009 sec. 11 (closed sets and safety classes);
  the four-state standing vocabulary is normative since v1.2.9, sec. 11.1.1.
* **Attestation envelope** -- `SPEC/IQA-URI-ATTEST-v1.2.6.md` sec. 5, a **draft**.
* **AE-128** -- companion draft v0.3 (`ae128-draft-v0.3.md`): implemented here
  to the byte against the published vector. A roadmap artifact of the
  specification line; it creates no IANA/ISE obligations.

Where this crate and a specification disagree, **the specification wins and
the crate is wrong.** Please report it.

---

## License

Apache-2.0. See `LICENSE`.
