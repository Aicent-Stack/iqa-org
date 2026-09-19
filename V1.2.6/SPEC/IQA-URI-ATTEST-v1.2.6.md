# IQA URI Codec & Attestation Envelope — v1.2.6 (Draft)

**Status:** Draft — **not part of RFC-009.** Cite it as an implementation
addition. It has **no authority over the grammar**: the sole syntax authority
remains RFC-009 §10.2.
**Applies to:** RFC-009 §10 (`iqa://` URIs) · §11 (dereference safety) · RFC-001 (AID)
**Layout inheritance:** RTTP-SEAL-ENVELOPE-v1.2.6 §3 (envelope), RFC-002 §11 (derivation precedent)
**Reference implementations:** `PKG/iqa/src/iqa/` (Python) · `PKG/iqa-js/` (Node)
**Deterministic vectors:** `SPEC/iqa-conformance-vectors.json` — regenerate with
`python SPEC/tools/iqa_conformance.py --generate`; never hand-edit.

---

## 0. Scope and status

RFC-009 §10 already freezes the `iqa://` grammar and §11 the dereference
safety rules. What it does not provide is the **codec contract**: which
strings an implementation must accept, which it must reject, what fields it
returns, how the address derives a routing fingerprint, and how an
attestation travels as a verifiable object.

This document specifies exactly that, in two parts:

* **Part I — URI codec** (§1–§4): closed-set enforcement, rejection rules,
  returned fields, and the `IQA_ROUTE` derivation.
* **Part II — attestation envelope** (§5–§7): a signed, self-certifying
  object that cites an `iqa://` URI and carries a standing claim.

Nothing here extends the grammar. Where this document and RFC-009 disagree,
**RFC-009 wins and this document is wrong.**

---

## 1. Authority boundaries

| Concern | Authority |
|:---|:---|
| URI grammar (ABNF) | **RFC-009 §10.2** — verbatim, no additions |
| `organ` / `action` closed sets | **RFC-009 §10.1** ("Closed set" stated for both) |
| Case discipline | **RFC-009 §10.3** (lowercase US-ASCII only) + §12 #8 (fail closed) |
| Dereference safety classes | **RFC-009 §11.3** |
| Registration status | **RFC-009 §10.5** — Provisional, pending, IANA #1459963 |
| `IQA_ROUTE` derivation | **this document §3** (new decision, D1) |
| Envelope layout | **this document §5** (inherits RTTP-SEAL-ENVELOPE-v1.2.6 §3) |

---

## 2. Codec behaviour (normative)

### 2.1 Input model

`parse(uri)` is total: it either returns the full field set or raises
`IqaUriError`. It never returns a partial result, never repairs input, and
never "tries anyway".

### 2.2 Closed sets — the deliberate difference from `rttp`

`rttp` accepts any well-formed `action` verb (open set). **`iqa` does not.**
Both segments named "Closed set" in RFC-009 §10.1 are enforced exactly:

| Segment | Allowed | Everything else |
|:---|:---|:---|
| `organ` | `forge` · `tss` · `gateway` | **reject** — the spec's own example `iqa://3f9a1b2c.forgery.iqa` is INVALID |
| `action` | `verify` · `audit` · `attest` · `revoke` | **reject** — e.g. `pulse` (an `rttp` verb!) is not an `iqa` verb |

A codec ported from `rttp` that leaves the verb set open is **non-conformant**
for `iqa`.

### 2.3 Case: lowercase only, never normalised

RFC-009 §10.3: *"Lowercase US-ASCII only."* An uppercase character anywhere —
scheme, subject, organ or action — is a **rejection**, not a normalisation
candidate. The same section's phrase *"hex AID material is normalized to
lowercase on entry"* describes **authoring discipline** (how this document
writes an AID into a URI); it is not a licence for a parser to accept
uppercase. Two readings are possible; this codec takes the fail-closed one,
per §12 #8 (*"an unrecognized scheme MUST fail closed and MUST NOT be
silently rewritten"*). If a future revision wants parser-level hex tolerance,
it must say so and the vectors change with it.

### 2.4 Structural rejections

A valid `iqa` URI contains no `@`, `:`, `?`, `#`, `[`, `]`, whitespace, or any
byte outside `[a-z0-9-./]` (§10.3). Additional structural rules from §10.2:

* authority is exactly `<subject>.<organ>.<root>` — two or four segments reject
* path is at most `/<action>` — a second path segment rejects
* a trailing `/` with an empty action rejects (the closed set has no empty verb)
* any scheme other than exactly `iqa://` rejects — `iqas://` does not exist
  and there is no fallback (§12 #8)

### 2.5 Subject classification — the grammar is the grammar

`hash-subject` is **8, 32 or 64** lowercase hex digits (routing short form /
128-bit AID / 256-bit AID). The ABNF is an ordered choice
(`hash-subject / name-subject`), so a lowercase-hex string of some *other*
length — 9 digits, say — fails `hash-subject` and **matches `name-subject`**.
The codec reports exactly that (`subject_is_hash: false`) rather than
inventing a rejection the grammar does not contain. Vector `#8` pins this
behaviour so both implementations and any third party agree on it.

### 2.6 Returned fields

Field names are `snake_case` **on purpose**: the published conformance vectors
use those names, so the Python and JavaScript outputs compare directly —
field for field, byte for byte.

| Field | Meaning |
|:---|:---|
| `scheme` | always `"iqa"` |
| `subject` | first authority segment as written |
| `subject_is_hash` / `subject_hex` | whether it matched a hash length, and the hex (null for names) |
| `organ`, `root` | the other two authority segments |
| `authority` | `<subject>.<organ>.<root>`, canonical |
| `action` / `action_omitted` | the verb, and the same fact as a boolean |
| `action_safe` | §11.3 class: `true` for omitted and `verify` |
| `canonical_uri` | always begins `iqa://`; identical to input for canonical input |
| `route_hex` | `IQA_ROUTE`, 8 lowercase hex characters (§3) |

---

## 3. `IQA_ROUTE` derivation (decision D1)

```
IQA_ROUTE = SHA-256( ASCII( canonical_authority ) )[0:4]
```

* 4 bytes, rendered as **8 lowercase hex characters**.
* Pure computation — no registry, no resolver, no network (§12 #9: the scheme
  performs no DNS resolution).
* Mirrors the RTTP rule (`ROUTE_SHARD = SHA-256(authority)[0:16]`, RFC-002
  §11) so both schemes of the same addressing family derive the same way —
  the two IANA applications were written as one design (IANA dossier §2.3).

**What it is not.** The `subject` hash is a routing hint for the **AID** (an
identity); `IQA_ROUTE` is a fingerprint of the **address**. They are different
numbers about different things; an implementation MUST NOT conflate them, and
a conforming one never derives the subject from the authority.

Pinned examples (from the generated vector set):

```
iqa://3f9a1b2c.gateway.iqa                        ->  5c378581
iqa://0000004149434e531c5b21d80403358b.forge.iqa  ->  133a7fcd
iqa://3f9a1b2c.tss.iqa/audit                      ->  1d60651a
iqa://master-authority.gateway.iqa/verify         ->  510ef099
```

---

## 4. Action safety classes (restated from §11.3 for codecs)

| `action` | Class | Codec reports |
|:---|:---|:---|
| *(omitted)* | SAFE — standing read (§11.1) | `action_safe: true` |
| `verify` | SAFE — read-only comparison | `action_safe: true` |
| `audit` | NOT SAFE — can trigger Authority Ischemia (§11.4) | `action_safe: false` |
| `attest` | NOT SAFE — state transition | `action_safe: false` |
| `revoke` | NOT SAFE — state transition | `action_safe: false` |

Per §11.2, *dereferencing* an `iqa` URI MUST NOT transition any subject's
standing. Tooling built on this codec MUST therefore gate the three NOT-SAFE
verbs behind an explicit user action — parsing one is not requesting one.

---

## 5. Attestation envelope (Part II)

### 5.1 Layout

Identical to RTTP-SEAL-ENVELOPE-v1.2.6 §3 — same fields, same hex discipline,
same "no unsigned field" rule — with two changes:

1. **Domain separation.** The signing-input prefix is
   `b"iqa-attest-v1\n"` (not `rttp-seal-v1\n`), so a signature made for one
   scheme can never be replayed as the other, even with the same key.
2. **Payload semantics.** The payload carries a standing claim about a
   subject:

```json
{
  "v": 1, "alg": "ed25519",
  "aid": "3125ee20b2238281f70ca408192f82152647d365219184fa1fe22c08a42c035e",
  "pub": "9c097c66ab4f82136ceddaef56854f740bf87da3eec42a249ba40bbb066f1e6a",
  "ts": 1760000000, "nonce": "0011223344556677",
  "sig": "054b74c8dcd2b2128291ce433409983609d62c63a002138475d5e33bd21ea0b0c6243790db3d926ad6820cdf7e64f49cbd49a794a1b693cb60217a3382a5f007",
  "payload": {
    "subject_uri": "iqa://3f9a1b2c.gateway.iqa",
    "organ": "gateway",
    "standing": "radiant"
  }
}
```

`standing` is a **closed set** — `ghost` · `probation` · `radiant` · `genesis`
(RFC-009-C §3), lowercase, like everything else in this family.

### 5.2 Signing input

```
signing_input = b"iqa-attest-v1\n" || json_canonical({
    "alg", "aid", "nonce", "payload", "pub", "ts"
})
```

`json_canonical` = UTF-8, sorted keys, separators `,` and `:`, no insignificant
whitespace, `ensure_ascii=False`. `ts` and `nonce` are **inside** the
signature (a replay-window rewrite that leaves the seal intact is exactly the
attack §3.3 of the RTTP envelope spec exists to kill). Freshness window:
`|now - ts| <= 120 s` for any envelope arriving over a network; archival
validation only may disable it.

### 5.3 What the envelope does and does not claim

The envelope **carries a claim** that the named Organ rendered the named
standing for the named subject. It does not **create** standing: §10.4 of
RFC-009 (*"parsing is not attestation"*) applies with full force — a verified
signature proves who said it, not that it is true. Verifying an attestation
and trusting an attestation are different acts; this codec performs only the
first.

Identity is self-certifying: `AID = SHA-256(public key)`, recomputed by the
verifier from the in-band key. No registry, no issuer, no directory — the
same trade as the RTTP sovereign profile, with the same consequence: lose the
key, lose the identity.

### 5.4 Deterministic vector

Fixed seed, `ts` and `nonce` produce a byte-identical envelope under any
conforming implementation (Ed25519 is deterministic, RFC 8032):

```
seed (private)          e722fed924c7f76b157faab674ea97bb7c3075f55ad7d3c6319418e22b86d611
public                  9c097c66ab4f82136ceddaef56854f740bf87da3eec42a249ba40bbb066f1e6a
AID = SHA-256(public)   3125ee20b2238281f70ca408192f82152647d365219184fa1fe22c08a42c035e
ts                      1760000000
nonce                   0011223344556677
payload                 {"organ":"gateway","standing":"radiant","subject_uri":"iqa://3f9a1b2c.gateway.iqa"}

canonical signing input (hex)
  6971612d6174746573742d76310a7b22616964223a2233313235656532306232323338323831663730636134303831393266383231353236343764333635323139313834666131666532326330386134326330333565222c22616c67223a2265643235353139222c226e6f6e6365223a2230303131323233333434353536363737222c227061796c6f6164223a7b226f7267616e223a2267617465776179222c227374616e64696e67223a2272616469616e74222c227375626a6563745f757269223a226971613a2f2f33663961316232632e676174657761792e697161227d2c22707562223a2239633039376336366162346638323133366365646461656635363835346637343062663837646133656563343261323439626134306262623036366631653661222c227473223a313736303030303030307d

signature
  054b74c8dcd2b2128291ce433409983609d62c63a002138475d5e33bd21ea0b0c6243790db3d926ad6820cdf7e64f49cbd49a794a1b693cb60217a3382a5f007
```

The Python self-test additionally replays the **RFC 8032 §7.1** vectors
(TEST 1 and TEST 2), so a failure distinguishes *"our envelope logic is
wrong"* from *"the signature backend is not standard Ed25519"*.

---

## 6. Rejection rules (codec)

Conformance requires rejecting **all** of the following; the vector set
replays every case:

| # | Input shape | Rule |
|:---|:---|:---|
| R1 | uppercase anywhere (scheme / hex / organ / action) | §10.3 lowercase only |
| R2 | `iqas://` or any foreign scheme | §12 #8 — fail closed, no fallback |
| R3 | `@` (userinfo) | §10.3 — deliberately excluded |
| R4 | `:` / `?` / `#` (port / query / fragment) | §10.3 |
| R5 | second path segment | §10.2 |
| R6 | trailing `/` with empty action | §10.2 |
| R7 | authority ≠ three segments | §10.2 |
| R8 | `organ` outside `{forge,tss,gateway}` or case-variant | §10.1 closed set |
| R9 | `action` outside the four verbs | §10.1 closed set |
| R10 | whitespace | §10.3 |

## 7. Conformance vectors

`SPEC/iqa-conformance-vectors.json` is **generated, not hand-edited** —
`generated_by` names the generator, and the file says so itself. Groups:

| Group | Count | What it proves |
|:---|---:|:---|
| `positive_uris` | 8 | Accept, classify and derive — §10.3's own examples, the 256-bit form, the all-zero boundary, and the name-subject fall-through |
| `negative_uris` | 18 | Every rejection rule R1–R10 |
| `action_safety` | 5 | §11.3 classes as data |
| `attest_envelope_vector` | 1 | The deterministic §5.4 envelope, replayed by **both** implementations |

Each vector is deterministic. Two implementations either agree byte for byte
or they do not.

---

## 8. What this does NOT provide

Stated here rather than left for a reviewer to discover — RFC-009 narrates a
larger organism; **this is the codec, not the organism:**

| Not provided | Consequence / where it belongs |
|:---|:---|
| **Staking & tiers** (BASIC/ACTIVE/RADIANT collateral, ZCMK vaults) | Operator economics. RFC-009 §3.1 narrative; no cryptographic object in this codec. |
| **Vitality monitoring** (1200 Hz heartbeats, Homeostasis Score) | Telemetry, not codec. |
| **Post-quantum Lattice Guard** | RFC-009 §12 #11 itself schedules it for v1.4.0; no implementation exists. Claiming it here would be false. |
| **Revocation transport** | §11.3 defines the *verb*; the network that executes it is an Organ's job, not the codec's. |
| **Dereferencing / resolver service** | The codec computes fields and fingerprints; *answering* a standing read is an Organ (§3, RFC-009-C). |
| **Confidentiality** | Signing is not encryption. Envelope payloads are readable. |
| **Revocation of a compromised key** | Same gap as the RTTP envelope (§8 there): a compromised key stays valid to any verifier that has never met it. |

---

## 9. Open items

1. **Folding into RFC-009** — §2/§3 of this document should become a numbered
   RFC-009 section (or a companion RFC) rather than remaining a draft beside it.
2. **`nonce` cache** — same minimum-behaviour requirement as the RTTP envelope
   before high-value use.
3. **Rust parity** — the Shipyard `iqa-org` crate predates this document; the
   Python and Node packages are the conforming implementations so far.
4. **Registration status** — all artifacts describe `iqa` as *submitted under
   RFC 7595, Provisional, pending (IANA #1459963)*. Describing it as
   registered, assigned or standardised is incorrect (RFC-009 §10.5).
