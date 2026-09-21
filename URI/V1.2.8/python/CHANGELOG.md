# Changelog -- iqa (Python)

All notable changes to this package are documented here.
Format: Keep a Changelog; versioning: SemVer.

---

## [1.2.8] -- 2026-09-21

**The envelope now runs without the optional primitive, and the vectors are pure
ASCII.** Counts move from 35/59 to **75 passed with 3 skipped** (core install) and
**78** (with `[ed25519]`). No grammar, closed-set or wire-format rule changed.

### Added

* **A backend abstraction for the attestation envelope** (`AttestBackend`,
  `CryptographyBackend`, `_resolve_backend`, `check_envelope`): the rule layer --
  identity, freshness, claim validation and a tamper matrix -- is now 18 checks
  that need no cryptographic primitive, and the self-test injects a clearly
  labelled test signer (`TestSignerBackend`) where the real backend is absent.
* **A runtime network guard** (`_NetworkGuard`) in the self-test: the run proves
  it opened no socket.

### Changed

* **The shipped vectors no longer contain the section character** (now `sec.`), so
  a byte-for-byte replay cannot depend on a non-ASCII character. The file is
  8,964 bytes, `sha256 8529549e...` -- the same bytes in the Python, Rust and
  JavaScript mirrors.
* **Message text was ASCII-ified** in `iqa_uri.py`, and so was the project
  description on the package index (`sec. 10/sec. 11` in place of a section sign).
  The parser logic is unchanged.
* Counts: 34 conformance, 18 envelope rules, 21 envelope flow, 2 RFC 8032,
  3 zero-dependency = 78.

### Fixed

* Carries forward the 1.2.7 fix: `verify_envelope` no longer raises `NameError`
  when the `[ed25519]` extra is missing -- it degrades through the backend
  abstraction instead.

## [1.2.7] -- 2026-09-19

**Bug fix -- the codec, the vectors and the wire format are unchanged.**

### Fixed

* **`verify_envelope` raised `NameError` when the `[ed25519]` extra was not
  installed.** `InvalidSignature` is imported inside a module-level
  `try/except ImportError`; without the extra the name was never bound, so
  evaluating the `except InvalidSignature:` clause itself raised
  `NameError: name 'InvalidSignature' is not defined` instead of returning the
  documented, fail-closed result. Environments that install the extra were
  never affected.
* **`python -m iqa.selftest` crashed in an install without the extra.** It now
  **skips** the one check that needs the backend and says so in the summary,
  matching the `rttp` package's behaviour: a green summary states what it did
  not verify. Exit status remains 0 when nothing failed.

### Notes

* The exception clauses in `verify_envelope` are now ordered `AttestError` ->
  `(ValueError, TypeError, KeyError)` -> `InvalidSignature`, so the placeholder
  used for the missing name can never swallow an unrelated error.
* Found by installing the published 1.2.6 into an empty virtual environment
  with `--no-index` and running the self-test there -- a check the published
  1.2.6 could not pass.

## [1.2.6] -- 2026-09-19

**Version alignment -- no code change.** Identical to 0.1.0 in every module,
byte layout and conformance vector; the self-test still reports the same 59
checks.

### Changed

* **The version number now mirrors the stack version.** PyPI and npm carry
  `1.2.6`; crates.io carries the same code as the pre-release `1.2.6-alpha`.
* Install command note: on crates.io every published version of this crate is
  a pre-release, so Cargo will not select it from a plain `iqa-org`
  requirement. Write `cargo add iqa-org@1.2.6-alpha`.

## [0.1.0] -- 2026-09-18

Initial public release.

### Added

* **`iqa://` URI codec** (RFC-009 sec. 10.2/sec. 10.3): validate, canonicalise and
  classify -- subject hash forms (8/32/64 lowercase hex) and name forms,
  **closed-set** enforcement for `organ` (`forge`/`tss`/`gateway`) and
  `action` (`verify`/`audit`/`attest`/`revoke`), fail-closed rejection of
  uppercase, userinfo, port, query, fragment, foreign schemes and every
  structural violation. Field names are snake_case so this output and the
  JavaScript package's output compare directly against the vectors.
* **`IQA_ROUTE` derivation** (SPEC/IQA-URI-ATTEST-v1.2.6 sec. 3, decision D1):
  `SHA-256(ASCII(authority))[0:4]` -- pure computation, DNS-free, mirroring the
  RTTP `ROUTE_SHARD` rule.
* **Action safety classes** (RFC-009 sec. 11.3) exposed as `action_safe` --
  omitted/verify SAFE, audit/attest/revoke NOT SAFE.
* **Sovereign attestation envelope** (`iqa.attest`, optional `[ed25519]`
  extra): Ed25519, self-certifying `AID = SHA-256(public key)`, domain prefix
  `iqa-attest-v1`, `ts`/`nonce` inside the signature, 120-second freshness
  window, claim validation against both closed sets, and a fail-closed
  verification order -- a check that cannot be performed is a failure, never a
  pass.
* **59-check self-test with the optional Ed25519 backend (35 by default)** (`python -m iqa.selftest`): 31 conformance + 2
  RFC 8032 + 22 envelope + 4 zero-dependency; replays the shipped vectors
  offline.
* **Conformance vectors** -- 32 published checks in four groups (8 positive /
  18 negative / 5 safety / 1 deterministic envelope), generated by
  `SPEC/tools/iqa_conformance.py`, shipped inside the wheel, and mirrored
  byte-identically in the npm package `iqa`.

### Distribution status at this release

| Registry | Name | State |
|:---|:---|:---|
| PyPI | **`iqa-org`** | this package -- `pip install iqa-org`, `import iqa`. The bare `iqa` is unregistered but blocked by PyPI's typosquatting protection (upload rejected 400, "too similar to an existing project") |
| npm | **`@aicent/iqa`** | the JavaScript independent implementation -- bare name blocked by npm's typosquatting protection, published under the project organization |
| crates.io | `iqa-org` | held by this project |

### Specification status

The `iqa` URI scheme is submitted to IANA under RFC 7595 (ticket **#1459963**,
Provisional) and is **under review -- not yet registered**. Every artifact in
this package describes it that way.

[0.1.0]: https://pypi.org/project/iqa/
