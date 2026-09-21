//! # iqa-org — Rust reference implementation of IQA (v1.2.6)
//!
//! `iqa://` subject-attestation addressing, `IQA_ROUTE` derivation, RFC-009
//! §11.3 action safety classes, and the published conformance vectors that
//! prove an implementation is right — replayed offline, `[PASS]` or it is not.
//!
//! **Zero dependencies by default.** SHA-256 is implemented in-crate
//! (known-answer tested), the vectors are read through a minimal in-crate JSON
//! reader, and the crate is `#![forbid(unsafe_code)]`. The sovereign
//! attestation envelope is available behind the optional `ed25519` feature —
//! the same split as the Python package's `[ed25519]` extra.
//!
//! ## Verify it
//!
//! ```console
//! $ cargo test                     # 33 published checks
//! $ cargo test --features ed25519  # 34 — adds the envelope signature
//! ```
//!
//! ## Quickstart
//!
//! ```
//! use iqa_org::iqa_uri;
//!
//! let parsed = iqa_uri::parse("iqa://3f9a1b2c.gateway.iqa").unwrap();
//! assert_eq!(parsed.organ, "gateway");          // closed set: forge|tss|gateway
//! assert!(parsed.action_omitted);               // standing read (§11.1)
//! assert!(parsed.action_safe);                  // §11.3
//! assert_eq!(parsed.route_hex, "5c378581");     // pure computation
//! ```
//!
//! ## The two closed sets — the deliberate difference from `rttp`
//!
//! `organ` and `action` are closed sets (RFC-009 §10.1). A codec ported from
//! `rttp`, whose verb set is open, is non-conformant for `iqa`:
//!
//! ```
//! use iqa_org::iqa_uri;
//! assert!(iqa_uri::parse("iqa://3f9a1b2c.gateway.iqa/pulse").is_err());   // an rttp verb
//! assert!(iqa_uri::parse("iqa://3f9a1b2c.forgery.iqa").is_err());         // not an organ
//! ```
//!
//! ## Authority
//!
//! Grammar: RFC-009 §10.2 ABNF. Dereference safety: RFC-009 §11.3. The `iqa`
//! URI scheme is submitted to IANA under RFC 7595 (ticket #1459963,
//! Provisional) and is **under review — not yet registered**. Where this crate
//! and the specification disagree, **the specification wins and this crate is
//! wrong.**

#![forbid(unsafe_code)]

pub mod conformance;
pub mod iqa_uri;
pub mod json;
pub mod sha256;

#[cfg(feature = "ed25519")]
pub mod attest;

pub use iqa_uri::{derive_route, derive_route_hex, is_valid_action, parse, ParsedUri, IqaUriError};
