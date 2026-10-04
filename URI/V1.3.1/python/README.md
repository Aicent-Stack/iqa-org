# iqa-org

**Reference implementation of the IQA attestation layer: the `iqa://`
subject-attestation URI (AICENT-009 sec. 10), action safety classes (sec. 11), the
self-certifying Ed25519 attestation envelope, and AE-128 -- the fixed 128-byte
attestation envelope.**

[AICENT-009 sec. 10](https://iqa.org/AICENT-009/) - sec. 11 - stack v1.2.6

---

## Verify it in one command -- no trust required

```console
$ pip install iqa-org
$ python -m iqa.selftest
...
[PASS] all 108 checks passed (3 skipped)   # core install: the Ed25519 path needs the extra

$ pip install iqa-org[ed25519]
$ python -m iqa.selftest
...
[PASS] all 111 checks passed
```

That is the point of this package. A specification is worth exactly what an
independent implementation can reproduce from it -- so instead of asking you to
believe a table of numbers, this ships the vectors and replays them locally.
The 111 checks below are the full set, i.e. with the optional Ed25519 backend
installed; a default install runs 108 checks and skips 3.

* **34 conformance checks** -- `iqa://` parsing, the two **closed sets**
  (`organ` / `action` -- the deliberate difference from `rttp`, whose verb set
  is open), fail-closed rejections, sec. 11.3 action safety classes, and the
  `IQA_ROUTE` derivation.
* **2 RFC 8032 checks** -- the Ed25519 backend is shown to be *standard*
  Ed25519, not a lookalike, so a failure tells you which half broke.
* **39 envelope checks** -- 18 rule-layer checks that need no primitive (identity,
  freshness, claim validation and a tamper matrix), plus deterministic-vector
  reproduction, round-trip and self-certification through the optional backend.
* **33 AE-128 checks** -- the published vector reproduced byte for byte from
  the documented parameters, the standing closed set (11.1.1), eleven
  fail-closed structural rejects, a full-frame authentication matrix
  (organ, nonce, standing, lease and shard are all inside the HMAC coverage,
  and tampering with any of them is detected, not policy), and end-to-end
  replay of the shipped `ae128-vectors-v1.json` (positives, negatives and
  tampered frames, one sha256 across all three packages).
* **3 zero-dependency checks** -- a static scan plus a runtime guard proving the
  core imports nothing outside the standard library and opens no socket.

Offline. No account. No network. `[PASS]` or it is not. Every vector file shipped here is listed in `vectors.manifest.json` with its byte count and SHA-256, produced by a generator rather than typed by hand - recompute the hash yourself if you prefer.

---

## Install

```console
pip install iqa-org              # core: zero dependencies, standard library only
pip install iqa-org[ed25519]     # + sovereign attestation envelopes (Ed25519)
```

Python 3.9+. No compiled extensions in the core.

The core deliberately has **no dependencies**. A protocol reference that cannot
be read without resolving a dependency tree is not much of a reference -- and an
air-gapped reviewer should be able to check the claims.

---

## What is in the box

| Module | What it does | Authority |
|:---|:---|:---|
| `iqa.iqa_uri` | `iqa://` codec -- validate, canonicalise, classify (8/32/64 hex or name subject), enforce the `organ` and `action` **closed sets**, report `action_safe` | AICENT-009 sec. 10.1/sec. 10.2/sec. 10.3 |
| `iqa.iqa_uri.derive_route` | `IQA_ROUTE = SHA-256(ASCII(authority))[0:4]` -- pure computation, DNS-free | `SPEC/IQA-URI-ATTEST-v1.2.6.md` sec. 3 |
| `iqa.attest` | **Sovereign attestation envelope** -- Ed25519, self-certifying (`AID = SHA-256(pub)`), domain prefix `iqa-attest-v1`, `ts`/`nonce` inside the signature | `SPEC/IQA-URI-ATTEST-v1.2.6.md` sec. 5 (draft) |
| `iqa.envelope` | **AE-128** -- the fixed 128-byte answer carrier: magic `IQAE`, HMAC-SHA256 over the whole frame (attestation field zeroed), standing closed set at offset 80, zero-parser verification, `derive_intent_shard` (the same 16 octets the rttp pulse frame carries at 0x36) | companion draft v0.3 (`ae128-draft-v0.3.md` sec. 2-6) |

Plus `iqa.vectors` -- the published conformance vectors, shipped inside the
wheel so the self-test works from an installed package with no repository
checkout.

---

## Quickstart

### Address a standing claim

```python
from iqa import iqa_uri

parsed = iqa_uri.parse("iqa://3f9a1b2c.gateway.iqa")
parsed["subject"]        # '3f9a1b2c'   (8-hex routing short form)
parsed["organ"]          # 'gateway'    (closed set: forge | tss | gateway)
parsed["action"]         # None         (omitted = standing read, sec. 11.1)
parsed["action_safe"]    # True         (sec. 11.3)
parsed["route_hex"]      # '5c378581'   <- pure computation, vector-pinned
```

Addressing is **DNS-free** (AICENT-009 sec. 12 #9): the route fingerprint is derived
from the authority by SHA-256, so no registry, resolver or network is involved.
Malformed input is rejected rather than normalised -- a case variant is not a
spelling difference, it is a different string.

### The closed sets -- the deliberate difference from `rttp`

```python
iqa_uri.parse("iqa://3f9a1b2c.gateway.iqa/pulse")
# IqaUriError: action 'pulse' is outside the closed set -- 'pulse' is an rttp verb

iqa_uri.parse("iqa://3f9a1b2c.forgery.iqa")
# IqaUriError: organ is a closed set (forge | tss | gateway)
```

### Seal an attestation with your own identity

```python
from iqa import attest

keypair = attest.generate_keypair()          # nothing is issued to you
print(keypair["aid_hex"])                    # = SHA-256(public key): your identity

claim = attest.build_claim("iqa://3f9a1b2c.gateway.iqa", "gateway", "radiant")
envelope = attest.seal(claim, keypair)

ok, reason, aid = attest.verify_envelope(envelope)
# ok=True -- signer identity recovered from the packet itself
```

The verifier needs **only the envelope**. There is no key directory, no
credentials to obtain, and no operator who could refuse to issue them. The
envelope **carries a claim** that an Organ rendered a standing; it does not
**create** one -- verifying an attestation and trusting an attestation are
different acts (AICENT-009 sec. 10.4).

### Carry a verdict on the wire: AE-128

```python
from iqa import envelope

shard = envelope.derive_intent_shard("f3b2a1c4.pillar.example")
frame = envelope.encode(key=b"the organ's key material",
                        intent_shard=shard, organ="gateway",
                        standing="radiant",          # or 0x02
                        lease_expiry=1798761600, nonce=1)
len(frame)                                  # 128 -- one frame, one datagram

ok, reason, parsed = envelope.verify(frame, b"the organ's key material",
                                     now=1798761600 - 1)
# ok=True -- offline: no issuer contact, no key directory, no network call
parsed["standing_name"]                     # 'radiant'
```

Verification needs only SHA-256/HMAC-SHA256 and fixed offsets -- no CBOR
decoder, no TLV walker. The standing byte sits inside the HMAC coverage, so
flipping Ghost to Radiant on a captured frame is *detected*, not argued. The
full published vector reproduces byte for byte from the draft's parameters
alone (`envelope.vector_1_frame()`).

---

## Scope -- what this package is not

| | |
|:---|:---|
| OK **Validation / canonicalisation** | Real, and specified (AICENT-009 sec. 10.2 / sec. 10.3). |
| OK **Closed-set enforcement** | Real, and specified (sec. 10.1). |
| OK **IQA_ROUTE derivation** | Real (SPEC sec. 3, decision D1). |
| OK **Action safety classes** | Real, and specified (sec. 11.3). |
| OK **Attestation envelope** | Real, and specified (draft). |
| OK **AE-128 fixed envelope** | Real, and specified (companion draft v0.3, implemented to the byte). |
| NO **Dereferencing / resolver service** | Not here. The codec computes; *answering* a standing read is an Organ's job (AICENT-009-C sec. 3). |
| NO **Staking & tiers** | ZCMK collateral economics -- operator policy, no cryptographic object in this package. |
| NO **Vitality monitoring** | 1200 Hz heartbeats and Homeostasis Scores are telemetry, not codec. |
| NO **Post-quantum Lattice Guard** | AICENT-009 sec. 12 #11 schedules it for v1.4.0; no implementation exists. |
| NO **Revocation transport** | sec. 11.3 defines the verb; executing it is not the codec's job. |
| NO **Confidentiality** | Signing is not encryption. |

Unknown revisions, algorithms and malformed input **fail closed** everywhere.
Nothing in this package is ever accepted because a check could not be performed.

---

## Conformance vectors

`iqa/vectors/iqa-conformance-v1.2.6.json` is generated, not hand-edited. Each
vector is deterministic: fixed sequence values, fixed timestamp, fixed seed --
so two implementations either agree byte for byte or they do not. The same
file ships in the npm package `@aicent/iqa` (three mirrors, one sha256), and the
JavaScript side is an **independent** implementation that replays it without
sharing a line of code with this one.

The vector set is the intended deliverable for third-party certification: pass
it and you interoperate; fail it and you know exactly which case is wrong,
without needing to trust the authors.

---

## Naming

| Ecosystem | Name | Status |
|:---|:---|:---|
| crates.io | **`iqa-org`** | **published** -- `1.3.1`, the first formal (non-pre-release) publication of the crate; Cargo selects it from a plain `iqa-org` requirement. The earlier `1.2.8-alpha` remains published and is not yanked |
| PyPI | **`iqa-org`** | **this package** -- `pip install iqa-org`, `import iqa` (the import name is unchanged). The bare `iqa` is unregistered but **blocked by PyPI's typosquatting protection** (upload rejected with 400 "too similar to an existing project") -- the same class of guard that forced `@aicent/iqa` on npm |
| npm | **`@aicent/iqa`** | the bare `iqa` name is unregistered but blocked by npm's typosquatting protection (too similar to existing short names) -- so the JavaScript side is published under this project's own organization, as `@aicent/rttp` already is. The package name itself is still just `iqa` |

---

## Specification status

* **`iqa` URI scheme** -- submitted to IANA under RFC 7595, ticket **#1459963**:
  the scheme **name is approved**; the CRI number is in expert review. It is
  **not yet registered** -- as of 2026-10-04 the IANA "URI Schemes" registry
  contains no `iqa` entry. Please describe it that way. (The sibling `rttp`
  scheme **is** registered: Provisional, CRI 27.)
* **Internet-Draft (IETF)** -- under IETF review as the combined Individual
  Submission Internet-Draft `draft-li-rttp-iqa-addressing` (revision -00,
  16 pp., 2026-09-24, informational -- both schemes, one document):
  https://datatracker.ietf.org/doc/draft-li-rttp-iqa-addressing/ .
  An Internet-Draft is a working document -- it is not an IETF standard and
  carries no IETF endorsement.
* **URI grammar** -- AICENT-009 sec. 10.2 (frozen; this package adds no syntax).
* **Dereference safety** -- AICENT-009 sec. 11 (closed sets and safety classes);
  the four-state standing vocabulary is normative since v1.2.9, sec. 11.1.1.
* **Attestation envelope** -- `SPEC/IQA-URI-ATTEST-v1.2.6.md` sec. 5, a **draft**:
  the format is implemented and vector-tested, but it is not yet a numbered
  AICENT-009 section.
* **AE-128** -- companion draft v0.3 (`ae128-draft-v0.3.md`): implemented here
  to the byte against the published vector. It is a roadmap artifact of the
  specification line and creates no IANA/ISE obligations.

Where this package and a specification disagree, **the specification wins and
the package is wrong.** Please report it.

---

## License

Apache-2.0. See `LICENSE`.
