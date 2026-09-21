# IQA - Reference Implementation

Independent reference implementation of the IQA (Identity Quality Assurance)
`iqa://` subject-attestation scheme, frozen against **spec v1.2.6**. The same
conformance vectors ship in three independent languages, and all three must
agree on every vector.

## Layout

```
URI/V1.2.6/   released 1.2.6 snapshot (python / javascript / rust)
URI/V1.2.8/   current 1.2.8 sources   (python / javascript / rust)
```

## Versions

| language | package | version |
|----------|---------|---------|
| python     | PyPI `iqa-org`       | 1.2.8 |
| javascript | npm `@aicent/iqa`    | 1.2.8 |
| rust       | crates.io `iqa-org`  | 1.2.8-alpha |

## Self-test counts (asserted in CI)

| install | count |
|---------|-------|
| python default           | all 75 checks passed (3 skipped) |
| python `iqa-org[ed25519]` | all 78 checks passed |
| node (`npx @aicent/iqa`) | all 32 checks passed |
| rust default             | all 37 checks passed (1 skipped) |
| rust `--features ed25519` | all 38 checks passed |

Default installs are zero-dependency; the optional `ed25519` extra adds the
deterministic Ed25519 backend (RFC 8032) and un-skips the last checks.

## CI

`.github/workflows/ci.yml` runs three job families on every push: the Rust
sources under `URI/V1.2.8/rust` are built and tested from this repository,
while the Python and JavaScript jobs install the **published** packages by
name - they test what a reviewer gets today, on a fresh machine, with no
account. Every self-test count quoted above is asserted; drift fails the build.
