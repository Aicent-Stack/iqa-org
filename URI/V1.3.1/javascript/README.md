# @aicent/iqa

**IQA for JavaScript: `iqa://` subject-attestation addressing, `IQA_ROUTE`
derivation, action safety classes, the AE-128 fixed attestation envelope -- and
the published conformance vectors that prove an implementation is right.**

[AICENT-009 sec. 10](https://iqa.org/AICENT-009/) - sec. 11 - stack v1.2.6 - zero dependencies - no build step

---

## Verify it in one command -- no trust required

```console
$ npx @aicent/iqa
[PASS] all 32 checks passed

$ node --test
# 19 test blocks, 0 fail -- including the AE-128 published vector,
# replayed byte for byte from the draft's documented parameters
```

That is the point of this package. A specification is worth exactly what an
independent implementation can reproduce from it, so instead of asking you to
believe a table of numbers, the vectors ship inside the package and replay
locally -- offline, no account, no network. `[PASS]` or it is not. Every vector file shipped here is listed in `vectors.manifest.json` with its byte count and SHA-256, produced by a generator rather than typed by hand - recompute the hash yourself if you prefer.

The vectors cover the `iqa://` grammar (AICENT-009 sec. 10.2), the **closed sets**
(`organ` and `action` -- the deliberate difference from `rttp`, whose verb set
is open), the sec. 11.3 action safety classes, the `IQA_ROUTE` derivation, **and**
the deterministic Ed25519 attestation envelope -- replayed by both
implementations. The AE-128 envelope (companion draft v0.3) ships with its own
published vector and full fail-closed matrix under `@aicent/iqa/envelope`.

### The other half -- Python, on PyPI

```console
$ pip install iqa-org
$ python -m iqa.selftest
[PASS] all 108 checks passed (3 skipped)   # default install

$ pip install iqa-org[ed25519]
$ python -m iqa.selftest
[PASS] all 111 checks passed               # with the optional Ed25519 backend
```

Published as **`@aicent/iqa`** -- the bare `iqa` name is unregistered on npm but
blocked by its typosquatting protection, so the JavaScript side lives under
this project's organization, as `@aicent/rttp` already does. PyPI applies the
same class of guard: the Python package is therefore **`iqa-org`** (same name
as the Rust crate; the import stays `import iqa`). It ships a **byte-identical
copy** of this same vector set (three mirrors, one sha256) and replays it
offline, exactly as this one does: two registries, two languages, one
specification.

---

## Install

```console
npm install @aicent/iqa
```

Node 18+. No dependencies, no build step, no transitive tree to audit: the
published `src/` is exactly what runs.

---

## Quickstart

```js
import { parse } from '@aicent/iqa';

const r = parse('iqa://3f9a1b2c.gateway.iqa');

r.subject        // '3f9a1b2c'   -- 8-hex routing short form of the AID
r.organ          // 'gateway'    -- closed set: forge | tss | gateway
r.action         // null         -- omitted = standing read (sec. 11.1)
r.action_safe    // true         -- sec. 11.3: omitted and verify are SAFE
r.canonical_uri  // 'iqa://3f9a1b2c.gateway.iqa'
r.route_hex      // '5c378581'   <- pure computation, pinned by the vectors
```

The same lines ship as a runnable file:

```console
$ node examples/quickstart.mjs
5c378581
```

Its expected output is the route fingerprint the published conformance vectors
pin for that address, so the example can be **checked** rather than believed.

Addressing is **DNS-free** (AICENT-009 sec. 12 #9): the route fingerprint is derived
from the authority by SHA-256, so no registry, resolver or network is
involved. A URI either yields its fields or throws -- there is no fallback, no
`iqas`, and no rewriting to `https`.

---

## The two closed sets -- the deliberate difference from `rttp`

`rttp` accepts any well-formed action verb. **`iqa` does not.** AICENT-009 sec. 10.1
marks *both* segments "Closed set", and this package enforces exactly that:

```js
parse('iqa://3f9a1b2c.gateway.iqa/pulse')  // throws -- 'pulse' is an rttp verb
parse('iqa://3f9a1b2c.forgery.iqa')        // throws -- organ is forge|tss|gateway
```

### The one rule that surprises people

**Malformed input is rejected, not normalised.** `iqa://.../AUDIT`,
`iqa://3F9A1B2C....` and `IQA://...` all throw: the canonical form is lowercase
US-ASCII (AICENT-009 sec. 10.3), a case variant is not a spelling difference, and
nothing is ever accepted because a check could not be performed.

### One honest quirk of the grammar

The ABNF is an ordered choice (`hash-subject / name-subject`), so a lowercase
hex string of a **non-hash length** (9 digits, say) is a *name subject*, not
an error. The grammar is the grammar; vector #8 pins the behaviour so every
implementation agrees on it.

---

## Action safety classes (AICENT-009 sec. 11.3)

| `action` | Class | `action_safe` |
|:---|:---|:---|
| *(omitted)* | SAFE -- standing read | `true` |
| `verify` | SAFE -- read-only comparison | `true` |
| `audit` | NOT SAFE -- can trigger Authority Ischemia | `false` |
| `attest` | NOT SAFE -- state transition | `false` |
| `revoke` | NOT SAFE -- state transition | `false` |

Per sec. 11.2, dereferencing an `iqa` URI MUST NOT transition any subject's
standing. Tooling built on this package MUST gate the three NOT-SAFE verbs
behind an explicit user action -- parsing one is not requesting one.

---

## API -- main entry

| Export | What it does |
|:---|:---|
| `parse(uri)` | Validate, canonicalise, classify, derive. Throws `IqaUriError`. |
| `deriveRoute(authority)` | `Uint8Array(4)` = `SHA-256(ASCII(authority))[0:4]`. |
| `deriveRouteHex(authority)` | The same, as 8 lowercase hex characters. |
| `isValidAction(value)` | sec. 10.1 closed-set test. |
| `IqaUriError` | The only error type thrown. |
| `SCHEME`, `ORGANS`, `ACTIONS`, `STANDINGS`, `HASH_LENGTHS` | Constants. |

### AE-128 -- `@aicent/iqa/envelope`

```js
import { encode, verify, deriveIntentShard, vector1Frame, VECTOR_1_KEY } from '@aicent/iqa/envelope';

const frame = encode({
  key: Buffer.from('the organ key material'),
  intent_shard: deriveIntentShard('f3b2a1c4.pillar.example'),
  organ: 'gateway', standing: 'radiant',       // or 0x02
  lease_expiry: 1798761600, nonce: 1,
});
frame.length                                     // 128 -- one frame, one datagram

const { ok, reason, frame: parsed } = verify(frame, key, { now: 1798761600 - 1 });
// ok=true -- offline: no issuer contact, no key directory, no network call
parsed.standing_name                             // 'radiant'
```

Fixed offsets, HMAC-SHA256 over the whole frame with the attestation field
zeroed, standing closed set at offset 80, constant-time compare, zero-parser
verification. The published vector (`vector1Frame()`) reproduces byte for byte
against the draft's parameters -- and against the Python and Rust
implementations, field for field.

### The attestation envelope -- `@aicent/iqa/conformance`

The deterministic Ed25519 envelope (SPEC/IQA-URI-ATTEST-v1.2.6 sec. 5: domain
prefix `iqa-attest-v1`, `AID = SHA-256(pub)`, `ts`/`nonce` inside the
signature, 120-second freshness) is part of the shared vector set and is
replayed by this package's conformance run. `buildSigningInput` is exported
from `./conformance` for implementers of other languages.

---

## The conformance vectors

```js
import { loadVectors, runConformance } from '@aicent/iqa/conformance';

const { checked, failures, passed } = runConformance(loadVectors());
```

Or from the command line:

```console
npx @aicent/iqa                       # replay the shipped vectors
npx @aicent/iqa --vectors ./new.json  # replay a different vector set
npx @aicent/iqa --json                # machine-readable output
```

In CI:

```yaml
- run: npx @aicent/iqa
```

| Group | Count | What it proves |
|:---|---:|:---|
| `positive_uris` | 8 | Accept, classify and derive -- sec. 10.3's own examples, the 256-bit form, the all-zero boundary, the name-subject fall-through |
| `negative_uris` | 18 | Reject -- uppercase anywhere, `iqas://`, userinfo, port, query, fragment, wrong authority shape, closed-set violations on both segments |
| `action_safety` | 5 | sec. 11.3 classes as data |
| `attest_envelope_vector` | 1 | Deterministic Ed25519 envelope, verified through `node:crypto` |

`vectors.json` is plain JSON and ships inside the package, also reachable as
the subpath export `@aicent/iqa/vectors.json`. Any language can read it; that
is what it is for.

### Why the checker lives in this package, and why that is still honest

`src/conformance.mjs` is written from AICENT-009 sec. 10 alone and **must never
import `src/iqa-uri.mjs`**. A conformance suite that reuses the code under
test only proves the code equals itself. The two files share no code -- one is
a streaming charset scanner, the other a single full-match grammar check -- so
the rule is checkable by reading them.

The vectors are **generated, not written**. `generated_by` in the JSON names
the generator, and the file says so itself: change the cases in the generator,
not the JSON. Hand-editing a conformance vector is how a specification quietly
starts agreeing with its own bugs.

---

## Scope -- what this package is not

| | |
|:---|:---|
| OK **Validation / canonicalisation** | Real, and specified (AICENT-009 sec. 10.2 / sec. 10.3). |
| OK **Closed-set enforcement** | Real, and specified (sec. 10.1). |
| OK **IQA_ROUTE derivation** | Real (SPEC sec. 3, decision D1). |
| OK **Action safety classes** | Real, and specified (sec. 11.3). |
| OK **Conformance vectors + independent replay** | Published and generated. |
| OK **AE-128 fixed envelope** | Real, and specified (companion draft v0.3, implemented to the byte). |
| NO **Dereferencing / resolver service** | Not here. The codec computes; *answering* a standing read is an Organ's job (AICENT-009-C sec. 3). |
| NO **Staking, tiers, vitality** | Operator economics and telemetry -- AICENT-009 narrative, no cryptographic object in this package. |
| NO **Post-quantum Lattice Guard** | AICENT-009 sec. 12 #11 schedules it for v1.4.0; no implementation exists. |
| NO **Revocation transport** | sec. 11.3 defines the verb; executing it is not the codec's job. |
| NO **Confidentiality** | Signing is not encryption. |

---

## Naming

| Ecosystem | Name | Status |
|:---|:---|:---|
| crates.io | **`iqa-org`** | **published** -- `1.3.1`, the first formal (non-pre-release) publication of the crate; Cargo selects it from a plain `iqa-org` requirement. The earlier `1.2.8-alpha` remains published and is not yanked. |
| PyPI | **`iqa-org`** | **published** -- the Python reference implementation; `pip install iqa-org` (bare `iqa` blocked by PyPI's typosquatting protection, same class of guard as npm) |
| npm | **`@aicent/iqa`** | the bare `iqa` name is unregistered but **blocked by npm's typosquatting protection** (too similar to existing short names) -- so this package is published under the organization this project controls, as `@aicent/rttp` already is. The package name itself is still just `iqa`. |

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
  to the byte against the published vector. A roadmap artifact of the
  specification line; it creates no IANA/ISE obligations.

Where this package and the specification disagree, **the specification wins
and this package is wrong.** Please report it.

---

## License

Apache-2.0. See `LICENSE`.
