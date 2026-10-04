# Changelog -- iqa (JavaScript)

All notable changes to this package are documented here.
Format: Keep a Changelog; versioning: SemVer.

---

## [1.3.1] -- 2026-10-04

**AE-128 lands: the answer side gets a wire form.** New subpath export
`@aicent/iqa/envelope`; the URI codec, the conformance vector file and its
replay are unchanged (same bytes, same sha256).

### Added

* **`src/envelope.mjs` -- AE-128**, the fixed 128-byte attestation envelope
  (companion draft v0.3): magic `IQAE`, HMAC-SHA256 over the ENTIRE frame with
  the attestation field zeroed (organ tag, nonce, lease and standing all
  authenticated), the standing closed set at offset 80 (`STANDING_CODES` /
  `STANDING_NAMES`, per AICENT-009 sec. 11.1.1), `deriveIntentShard` -- the
  same SHA-256[0:16] derivation the rttp pulse frame carries at 0x36.
  Constant-time compare via `timingSafeEqual`. `node:crypto` only, no build
  step; field names snake_case, byte-comparable with the Python `iqa.envelope`.
* **`test/envelope.test.mjs`** -- the published vector reproduced byte for
  byte from the documented parameters, the inclusive lease boundary
  ("valid until"), the standing closed set (names and wire codes accepted
  identically), eleven fail-closed structural rejects (wrong length, the
  pulse frame's "RTTP" magic included, unknown version/algorithm, nonzero
  flags, standing outside the closed set, nonzero reserved/extension,
  non-ASCII organ tag), and a full-frame authentication tamper matrix:
  flipping the standing byte, altering the organ tag, nonce, lease or shard
  all fail verification.

### Changed

* Package description and keywords mention the envelope.
* **Series designation: `RFC-009` is now `AICENT-009`** throughout the docs,
  source comments and error messages, aligning with the public specification
  line (`iqa.org/AICENT-009/`). Historical entries below keep the designation
  they were written with. The shipped vector file is byte-frozen (published
  sha256) and still carries the old designation inside its labels; renaming
  those labels is a coordinated vector-set regeneration, not an edit.
* README: specification-status section refreshed (combined I-D name
  `draft-li-rttp-iqa-addressing`, iqa IANA name approved / CRI in expert
  review, standing vocabulary normative since v1.2.9, AE-128 roadmap status).

## [1.2.8] -- 2026-09-21

**Version alignment -- no code change.** The code, the vector file and the
self-test result are identical to `1.2.7`; only the version string moves, so the
npm release carries the stack number alongside PyPI (`iqa-org 1.2.8`) and
crates.io (`1.2.8-alpha`).

### Changed

* The README's specification-status section now also records the IETF
  Internet-Draft (`draft-li-iqa-subject-attestation`, Individual Submission)
  alongside the IANA ticket.
## [1.2.7] -- 2026-09-19

**Metadata correction only -- no code change.** Every module, the conformance
vectors (same `sha256 8529549e...`) and all 32 checks are identical to 1.2.6.

### Fixed

* **The npm page showed the wrong Homepage link.** The manifest carried no
  `homepage` field, and npm derives one from `repository` when it is absent --
  so the package page linked to the umbrella repository rather than to this
  project's own site. An explicit `homepage` is now set, which takes
  precedence over the derived value.
* **`repository` now points at this project's own repository.** It named the
  umbrella repository, while the Rust crate of the same project names
  `Aicent-Stack/iqa-org`. npm derives the package page's Repository link from
  this field, and -- when `homepage` is absent -- its Homepage link too, so the
  wrong destination was visible on the page. Both fields are now explicit and
  consistent.
* Distribution table in the README: the crates.io row still said the name was
  "held by this project"; the crate has been published, so the row now states
  the published version and the pre-release caveat that applies to it.

> **Why a new version number.** Published npm metadata is immutable, and a
> version number that has been used can never be used again -- even after an
> unpublish. A link that ships in the manifest can therefore only be corrected
> by publishing the next version. PyPI and crates.io are unaffected and remain
> on their current versions.

## [1.2.6] -- 2026-09-19

**Version alignment -- no code change.** Identical to 0.1.1 in every module,
in the conformance vectors (same `sha256 8529549e...`) and in all 32 checks.

### Changed

* **The version number now mirrors the stack version.** npm and PyPI carry
  `1.2.6`; crates.io carries the same code as the pre-release `1.2.6-alpha`.

## [0.1.1] -- 2026-09-18

**Documentation only -- no code change.** Every module, the conformance
vectors (same `sha256 8529549e...`), and all 32 checks are identical to 0.1.0.

### Fixed

* **README distribution references now match the published Python package.**
  The 0.1.0 README pointed at `pip install iqa` -- the bare name that both
  registries' typosquatting protection ultimately rejected. The Python package
  is published as **`iqa-org`** (`import iqa` unchanged). The install commands
  and the naming table now say so.

### Distribution status at this release

| Registry | Name | State |
|:---|:---|:---|
| npm | **`@aicent/iqa`** | this package |
| PyPI | **`iqa-org`** | published 0.1.0 -- 2026-09-18 -- `pip install iqa-org` |
| crates.io | `iqa-org` | held by this project |

## [0.1.0] -- 2026-09-18

Initial public release.

### Added

* **`iqa://` URI codec** (RFC-009 sec. 10.2/sec. 10.3): validate, canonicalise and
  classify -- subject hash forms (8/32/64 lowercase hex) and name forms,
  **closed-set** enforcement for `organ` (`forge`/`tss`/`gateway`) and
  `action` (`verify`/`audit`/`attest`/`revoke`), fail-closed rejection of
  uppercase, userinfo, port, query, fragment, foreign schemes and every
  structural violation.
* **`IQA_ROUTE` derivation** (SPEC/IQA-URI-ATTEST-v1.2.6 sec. 3, decision D1):
  `SHA-256(ASCII(authority))[0:4]` -- pure computation, DNS-free, mirroring the
  RTTP `ROUTE_SHARD` rule.
* **Action safety classes** (RFC-009 sec. 11.3) exposed as `action_safe`.
* **Conformance vectors** -- 32 checks in four groups (8 positive / 18 negative
  / 5 safety / 1 deterministic Ed25519 envelope), generated by
  `SPEC/tools/iqa_conformance.py` and shipped inside the package; replayed
  offline by `npx iqa` and by the **independent** checker in
  `src/conformance.mjs` (which never imports `src/iqa-uri.mjs`).
* **CLI** (`bin/iqa.mjs`): `npx iqa [--vectors ./set.json] [--json]`.
* Zero dependencies, Node 18+, no build step.

### Distribution status at this release

| Registry | Name | State |
|:---|:---|:---|
| npm | **`@aicent/iqa`** | this package -- the bare `iqa` name is unregistered but **blocked by npm's typosquatting protection** (too similar to existing short names), so the JavaScript side is published under this project's organization, as `@aicent/rttp` already is |
| PyPI | **`iqa-org`** | the Python reference implementation -- bare `iqa` blocked by PyPI's typosquatting protection, so the distribution is `iqa-org` (`import iqa`) |
| crates.io | `iqa-org` | held by this project |

### Specification status

The `iqa` URI scheme is submitted to IANA under RFC 7595 (ticket **#1459963**,
Provisional) and is **under review -- not yet registered**. Every artifact in
this package describes it that way.

[0.1.0]: https://www.npmjs.com/package/iqa
