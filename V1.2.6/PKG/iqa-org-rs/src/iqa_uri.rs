//! `iqa://` URI codec — validate, canonicalise, derive (RFC-009 §10/§11).
//!
//! Authority boundaries:
//!   Grammar ......... RFC-009 §10.2 ABNF (sole authority; no syntax added)
//!   Closed sets ..... §10.1 (`organ` and `action` are CLOSED sets — the
//!                     deliberate difference from `rttp`, whose verb set is open)
//!   Case discipline . §10.3 (lowercase US-ASCII only) + §12 #8 (fail closed)
//!   Deref safety .... §11.3 (action safety classes)
//!   Route derivation  SPEC/IQA-URI-ATTEST-v1.2.6 §3 (IQA_ROUTE)
//!
//! Malformed input is REJECTED, never normalised; a check that cannot be
//! performed is a failure, never a pass.

use crate::sha256::{bytes_to_hex, sha256};
use std::fmt;

pub const SCHEME: &str = "iqa";

/// RFC-009 §10.1 — organ is a CLOSED set (RFC-009-A/-B/-C).
pub const ORGANS: [&str; 3] = ["forge", "tss", "gateway"];

/// RFC-009 §10.1 — action is a CLOSED set (differs from `rttp`).
pub const ACTIONS: [&str; 4] = ["verify", "audit", "attest", "revoke"];

/// RFC-009-C §3 — standings an Organ may render (closed set, lowercase).
pub const STANDINGS: [&str; 4] = ["ghost", "probation", "radiant", "genesis"];

/// RFC-009 §10.2 — hash-subject lengths: routing short form / 128-bit / 256-bit.
pub const HASH_LENGTHS: [usize; 3] = [8, 32, 64];

/// IQA_ROUTE length in bytes (8 lowercase hex characters).
pub const ROUTE_BYTES: usize = 4;

/// The only error type raised by this module.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct IqaUriError(pub String);

impl fmt::Display for IqaUriError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.0)
    }
}
impl std::error::Error for IqaUriError {}

/// A parsed `iqa` URI.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ParsedUri {
    pub subject: String,
    pub subject_is_hash: bool,
    /// The subject hex, only for hash subjects.
    pub subject_hex: Option<String>,
    pub organ: String,
    pub root: String,
    pub authority: String,
    /// The verb; `None` = omitted (§11.1 standing read).
    pub action: Option<String>,
    pub action_omitted: bool,
    /// RFC-009 §11.3: omitted and `verify` are SAFE; audit/attest/revoke are NOT.
    pub action_safe: bool,
    pub canonical_uri: String,
    /// IQA_ROUTE = SHA-256(ASCII(authority))[0:4], 8 lowercase hex characters.
    pub route_hex: String,
}

fn fail(msg: impl Into<String>) -> IqaUriError {
    IqaUriError(msg.into())
}

/// §10.2 action test — true ONLY for the closed four-verb set.
pub fn is_valid_action(value: &str) -> bool {
    ACTIONS.contains(&value)
}

/// IQA_ROUTE = SHA-256( ASCII(canonical_authority) )[0:4].
///
/// Pure computation, DNS-free (§12 #9); mirrors the RTTP ROUTE_SHARD rule.
/// NOTE: this is the *address* fingerprint — NOT the subject hash, which is a
/// routing hint for the *AID*. Different numbers about different things.
pub fn derive_route(canonical_authority: &str) -> Result<[u8; ROUTE_BYTES], IqaUriError> {
    if canonical_authority.is_empty() {
        return Err(fail("derive_route: authority is empty"));
    }
    let digest = sha256(canonical_authority.as_bytes());
    let mut out = [0u8; ROUTE_BYTES];
    out.copy_from_slice(&digest[..ROUTE_BYTES]);
    Ok(out)
}

/// The same four bytes, as 8 lowercase hex characters.
pub fn derive_route_hex(canonical_authority: &str) -> Result<String, IqaUriError> {
    Ok(bytes_to_hex(&derive_route(canonical_authority)?))
}

fn allowed_char(c: u8) -> bool {
    c.is_ascii_lowercase() || c.is_ascii_digit() || c == b'-' || c == b'.' || c == b'/'
}

/// Validate, canonicalise and derive. Raises on any violation.
pub fn parse(uri: &str) -> Result<ParsedUri, IqaUriError> {
    let prefix = "iqa://";
    let rest = uri.strip_prefix(prefix).ok_or_else(|| {
        fail(format!(
            "scheme must be exactly {:?} - no other scheme, no case variant, \
             no fallback (RFC-009 §10.3, §12 #8)",
            prefix
        ))
    })?;

    // Charset gate: lowercase US-ASCII only (§10.3). This single scan rejects
    // uppercase anywhere, '@', ':', '?', '#', whitespace, '[', ']' and every
    // other foreign byte.
    for &b in rest.as_bytes() {
        if allowed_char(b) {
            continue;
        }
        let c = b as char;
        if "@:?#[]".contains(c) {
            return Err(fail(format!(
                "{:?} is not defined by the scheme (RFC-009 §10.3)",
                c
            )));
        }
        if c.is_ascii_whitespace() {
            return Err(fail(
                "whitespace is not allowed (RFC-009 §10.3 lowercase US-ASCII only)",
            ));
        }
        return Err(fail(format!(
            "character {:?} is outside the allowed set (lowercase US-ASCII, digits, '-', '.', '/')",
            c
        )));
    }

    // Path: at most one '/', and the action behind it must be non-empty.
    let (authority, action) = match rest.find('/') {
        Some(i) => {
            let a = &rest[..i];
            let act = &rest[i + 1..];
            if act.is_empty() {
                return Err(fail(
                    "trailing '/' with empty action - action is a closed-set verb, \
                     not omissible by empty string (§10.2)",
                ));
            }
            if act.contains('/') {
                return Err(fail("second path segment - path is a single '/<action>' (§10.2)"));
            }
            (a, Some(act))
        }
        None => (rest, None),
    };

    let segments: Vec<&str> = authority.split('.').collect();
    if segments.len() != 3 {
        return Err(fail(format!(
            "authority has {} segment(s), must be <subject>.<organ>.<root> (RFC-009 §10.2)",
            segments.len()
        )));
    }
    let (subject, organ, root) = (segments[0], segments[1], segments[2]);
    if subject.is_empty() || root.is_empty() {
        return Err(fail("authority segments must be non-empty (RFC-009 §10.2)"));
    }

    // Subject: hash form (8/32/64 lowercase hex) or name form. Ordered choice
    // per the ABNF: all-lowerhex input is tried as hash-subject first; a
    // lowercase-hex string of another length is a NAME subject, exactly as the
    // grammar says. Documented, not "fixed".
    let is_all_lowhex = subject.bytes().all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b));
    let subject_is_hash = is_all_lowhex && HASH_LENGTHS.contains(&subject.len());
    let subject_hex = if subject_is_hash { Some(subject.to_string()) } else { None };

    // Organ — CLOSED set, case-sensitive (§10.1). 'Forge', 'forgery' all fail.
    if !ORGANS.contains(&organ) {
        return Err(fail(format!(
            "organ {:?} is outside the closed set [forge, tss, gateway] (RFC-009 §10.1/§10.3)",
            organ
        )));
    }

    // Action — CLOSED set (§10.1). The deliberate difference from rttp.
    if let Some(a) = action {
        if !ACTIONS.contains(&a) {
            return Err(fail(format!(
                "action {:?} is outside the closed set [verify, audit, attest, revoke] (RFC-009 §10.1)",
                a
            )));
        }
    }

    let canonical_uri = match action {
        Some(a) => format!("{}{}/{}", prefix, authority, a),
        None => format!("{}{}", prefix, authority),
    };

    Ok(ParsedUri {
        subject: subject.to_string(),
        subject_is_hash,
        subject_hex,
        organ: organ.to_string(),
        root: root.to_string(),
        authority: authority.to_string(),
        action: action.map(str::to_string),
        action_omitted: action.is_none(),
        action_safe: matches!(action, None | Some("verify")), // §11.3
        canonical_uri,
        route_hex: derive_route_hex(authority)?,              // SPEC §3
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_the_pinned_examples() {
        let p = parse("iqa://3f9a1b2c.gateway.iqa").unwrap();
        assert_eq!(p.subject, "3f9a1b2c");
        assert!(p.subject_is_hash);
        assert!(p.action_omitted);
        assert!(p.action_safe);
        assert_eq!(p.route_hex, "5c378581");
        assert_eq!(p.canonical_uri, "iqa://3f9a1b2c.gateway.iqa");

        let q = parse("iqa://master-authority.gateway.iqa/verify").unwrap();
        assert!(!q.subject_is_hash);
        assert_eq!(q.route_hex, "510ef099");
        assert!(q.action_safe);
    }

    #[test]
    fn nine_hex_is_a_name_subject() {
        let p = parse("iqa://3f9a1b2cd.gateway.iqa/verify").unwrap();
        assert!(!p.subject_is_hash);
        assert_eq!(p.subject_hex, None);
    }

    #[test]
    fn closed_sets_reject() {
        assert!(parse("iqa://3f9a1b2c.forgery.iqa").is_err());
        assert!(parse("iqa://3f9a1b2c.gateway.iqa/pulse").is_err());
        assert!(parse("iqas://3f9a1b2c.gateway.iqa/audit").is_err());
        assert!(parse("iqa://3f9a1b2c.gateway.iqa/ATTEST").is_err());
        assert!(parse("iqa://subject@iqa.org").is_err());
        assert!(parse("iqa://iqa.org/RFC-009/").is_err());
    }

    #[test]
    fn safety_classes_match_section_11_3() {
        assert!(parse("iqa://3f9a1b2c.gateway.iqa/audit").unwrap().action_safe == false);
        assert!(parse("iqa://3f9a1b2c.gateway.iqa/attest").unwrap().action_safe == false);
        assert!(parse("iqa://3f9a1b2c.gateway.iqa/revoke").unwrap().action_safe == false);
        assert!(parse("iqa://3f9a1b2c.gateway.iqa/verify").unwrap().action_safe == true);
    }
}
