//! # iqa-org -- Rust reference implementation of IQA (v1.3.1)
//!
//! `iqa://` subject-attestation addressing, `IQA_ROUTE` derivation, AICENT-009
//! sec. 11.3 action safety classes, AE-128 -- the fixed 128-byte attestation
//! envelope -- and the published conformance vectors that prove an
//! implementation is right -- replayed offline, `[PASS]` or it is not.
//!
//! **Zero dependencies by default.** SHA-256 is implemented in-crate
//! (known-answer tested), HMAC-SHA256 sits on top of it, the vectors are read
//! through a minimal in-crate JSON reader, and the crate is
//! `#![forbid(unsafe_code)]`. The sovereign Ed25519 attestation envelope is
//! available behind the optional `ed25519` feature -- the same split as the
//! Python package's `[ed25519]` extra.
//!
//! ## Verify it
//!
//! ```console
//! $ cargo test                     # 18 unit tests + 2 doc tests, all green
//!                                 # (includes the AE-128 published vector,
//!                                 # replayed byte for byte)
//! $ cargo test --features ed25519  # 20 unit tests -- adds the Ed25519
//!                                 # signature round-trip
//! ```
//!
//! ## Quickstart
//!
//! ```
//! use iqa_org::iqa_uri;
//!
//! let parsed = iqa_uri::parse("iqa://3f9a1b2c.gateway.iqa").unwrap();
//! assert_eq!(parsed.organ, "gateway");          // closed set: forge|tss|gateway
//! assert!(parsed.action_omitted);               // standing read (sec. 11.1)
//! assert!(parsed.action_safe);                  // sec. 11.3
//! assert_eq!(parsed.route_hex, "5c378581");     // pure computation
//! ```
//!
//! ## The two closed sets -- the deliberate difference from `rttp`
//!
//! `organ` and `action` are closed sets (AICENT-009 sec. 10.1). A codec ported from
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
//! Grammar: AICENT-009 sec. 10.2 ABNF. Dereference safety: AICENT-009 sec. 11.3. The `iqa`
//! URI scheme is submitted to IANA under RFC 7595 (ticket #1459963,
//! Provisional) and is **under review -- not yet registered**. Where this crate
//! and the specification disagree, **the specification wins and this crate is
//! wrong.**

#![forbid(unsafe_code)]

pub mod conformance;
pub mod envelope;
pub mod iqa_uri;
pub mod json;
pub mod sha256;

#[cfg(feature = "ed25519")]
pub mod attest;

pub use envelope::{
    derive_intent_shard, encode, intent_shard_hex, parse as parse_envelope,
    verify as verify_envelope, EnvelopeError, ParsedEnvelope, VerifyResult, SIZE as AE128_SIZE,
    MAGIC as AE128_MAGIC, VERSION as AE128_VERSION, STANDING_NAMES as AE128_STANDING_NAMES,
    VECTOR_1_FRAME_HEX as AE128_VECTOR_1_HEX,
};
pub use iqa_uri::{derive_route, derive_route_hex, is_valid_action, parse, ParsedUri, IqaUriError};
