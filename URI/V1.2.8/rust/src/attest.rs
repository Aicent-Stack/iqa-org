//! Sovereign attestation envelope -- SPEC/IQA-URI-ATTEST-v1.2.6 sec. 5 (Ed25519,
//! self-certifying, domain prefix `iqa-attest-v1`). **Feature-gated**
//! (`ed25519`): the default build stays zero-dependency and still replays the
//! envelope's signing input and AID self-certification.
//!
//! The envelope **carries a claim** that an Organ rendered a standing; it does
//! not **create** one. Verifying is not trusting (RFC-009 sec. 10.4).

use crate::iqa_uri;
use crate::json::Json;
use crate::sha256::{bytes_to_hex, hex_to_bytes, sha256};
use ed25519_dalek::{Signer, SigningKey, Verifier, VerifyingKey};
use std::fmt;
use std::time::{SystemTime, UNIX_EPOCH};

pub const DOMAIN: &[u8] = b"iqa-attest-v1\n";
pub const MAX_SKEW: u64 = 120;
pub const NONCE_BYTES: usize = 8;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AttestError(pub String);

impl fmt::Display for AttestError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.0)
    }
}
impl std::error::Error for AttestError {}

pub struct Keypair {
    pub signing: SigningKey,
    pub pub_hex: String,
    pub aid_hex: String,
}

pub fn aid_from_public_key(public: &[u8; 32]) -> [u8; 32] {
    sha256(public)
}

pub fn generate_keypair() -> Result<Keypair, AttestError> {
    let mut seed = [0u8; 32];
    getrandom::getrandom(&mut seed).map_err(|e| AttestError(e.to_string()))?;
    Ok(keypair_from_seed(seed))
}

/// Deterministic keypair from a seed -- reproducible vectors only.
pub fn keypair_from_seed(seed: [u8; 32]) -> Keypair {
    let signing = SigningKey::from_bytes(&seed);
    let pub_bytes = signing.verifying_key().to_bytes();
    Keypair {
        signing,
        pub_hex: bytes_to_hex(&pub_bytes),
        aid_hex: bytes_to_hex(&aid_from_public_key(&pub_bytes)),
    }
}

/// Build and validate a claim payload (closed sets enforced). A claim that
/// violates the grammar is not built -- so an envelope can never carry a
/// subject URI the codec itself would reject.
pub fn build_claim(subject_uri: &str, organ: &str, standing: &str) -> Result<Json, AttestError> {
    let parsed = iqa_uri::parse(subject_uri).map_err(|e| AttestError(e.0))?;
    if !iqa_uri::ORGANS.contains(&organ) {
        return Err(AttestError(format!(
            "organ {:?} is outside the closed set [forge, tss, gateway]",
            organ
        )));
    }
    if !iqa_uri::STANDINGS.contains(&standing) {
        return Err(AttestError(format!("standing {:?} is outside the closed set", standing)));
    }
    if parsed.organ != organ {
        return Err(AttestError("organ does not match the subject URI's organ".into()));
    }
    Ok(Json::Obj(vec![
        ("subject_uri".into(), Json::Str(parsed.canonical_uri)),
        ("organ".into(), Json::Str(organ.to_string())),
        ("standing".into(), Json::Str(standing.to_string())),
    ]))
}

/// Canonical signing input: `iqa-attest-v1\n` + sorted-key JSON of every
/// envelope field except `sig`.
pub fn signing_input(env: &Json) -> Result<Vec<u8>, AttestError> {
    if !matches!(env, Json::Obj(_)) {
        return Err(AttestError("envelope must be an object".into()));
    }
    let inner = Json::Obj(vec![
        ("alg".into(), env.get("alg").cloned().unwrap_or(Json::Null)),
        ("aid".into(), env.get("aid").cloned().unwrap_or(Json::Null)),
        ("nonce".into(), env.get("nonce").cloned().unwrap_or(Json::Null)),
        ("payload".into(), env.get("payload").cloned().unwrap_or(Json::Null)),
        ("pub".into(), env.get("pub").cloned().unwrap_or(Json::Null)),
        ("ts".into(), env.get("ts").cloned().unwrap_or(Json::Null)),
    ]);
    let mut out = DOMAIN.to_vec();
    out.extend_from_slice(inner.canonical().as_bytes());
    Ok(out)
}

pub fn seal(
    payload: &Json,
    keypair: &Keypair,
    ts: Option<u64>,
    nonce_hex: Option<&str>,
) -> Result<Json, AttestError> {
    if !matches!(payload, Json::Obj(_)) {
        return Err(AttestError("payload must be an object".into()));
    }
    let ts = match ts {
        Some(t) => t,
        None => SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map_err(|e| AttestError(e.to_string()))?
            .as_secs(),
    };
    let nonce = match nonce_hex {
        Some(n) => {
            if n.len() != NONCE_BYTES * 2
                || !n.bytes().all(|b| b.is_ascii_hexdigit())
                || n.bytes().any(|b| b.is_ascii_uppercase())
            {
                return Err(AttestError("nonce must be 8 bytes of lowercase hex".into()));
            }
            n.to_string()
        }
        None => {
            let mut raw = [0u8; NONCE_BYTES];
            getrandom::getrandom(&mut raw).map_err(|e| AttestError(e.to_string()))?;
            bytes_to_hex(&raw)
        }
    };
    let env = Json::Obj(vec![
        ("v".into(), Json::Num("1".into())),
        ("alg".into(), Json::Str("ed25519".into())),
        ("aid".into(), Json::Str(keypair.aid_hex.clone())),
        ("pub".into(), Json::Str(keypair.pub_hex.clone())),
        ("ts".into(), Json::Num(ts.to_string())),
        ("nonce".into(), Json::Str(nonce)),
        ("payload".into(), payload.clone()),
    ]);
    let sig = keypair.signing.sign(&signing_input(&env)?).to_bytes();
    if let Json::Obj(pairs) = &env {
        let mut out = pairs.clone();
        out.push(("sig".into(), Json::Str(bytes_to_hex(&sig))));
        return Ok(Json::Obj(out));
    }
    unreachable!()
}

/// Verify an envelope (fail closed, in order -- SPEC sec. 5). On success returns
/// the signer AID.
pub fn verify_envelope(
    env: &Json,
    now: Option<u64>,
    check_freshness: bool,
) -> Result<String, AttestError> {
    if env.get("v").and_then(Json::as_u128) != Some(1) {
        return Err(AttestError(format!("unsupported envelope version: {:?}", env.get("v"))));
    }
    if env.get("alg").and_then(Json::as_str) != Some("ed25519") {
        return Err(AttestError(format!("unsupported algorithm: {:?}", env.get("alg"))));
    }
    for (key, bytes) in [("aid", 32usize), ("pub", 32), ("sig", 64), ("nonce", 8)] {
        let v = env.get(key).and_then(Json::as_str).unwrap_or("");
        if v.len() != bytes * 2
            || !v.bytes().all(|b| b.is_ascii_hexdigit())
            || v.bytes().any(|b| b.is_ascii_uppercase())
        {
            return Err(AttestError(format!(
                "{} must be {} bytes of lowercase hex -- a case variant is rejected, never normalised",
                key, bytes
            )));
        }
    }
    let ts = env
        .get("ts")
        .and_then(Json::as_u128)
        .ok_or_else(|| AttestError("ts must be an integer (unix seconds)".into()))?;
    let ts = u64::try_from(ts).map_err(|_| AttestError("ts out of range".into()))?;
    if !matches!(env.get("payload"), Some(Json::Obj(_))) {
        return Err(AttestError("payload must be an object".into()));
    }
    if check_freshness {
        let now = now.unwrap_or_else(|| {
            SystemTime::now().duration_since(UNIX_EPOCH).map(|d| d.as_secs()).unwrap_or(0)
        });
        let drift = now.abs_diff(ts);
        if drift > MAX_SKEW {
            return Err(AttestError(format!(
                "timestamp skew too large ({}s > {}s) - replay?",
                drift, MAX_SKEW
            )));
        }
    }
    let pub_hex = env.get("pub").and_then(Json::as_str).unwrap_or("");
    let pub_bytes = hex_to_bytes(pub_hex).ok_or_else(|| AttestError("bad pub hex".into()))?;
    let mut pub32 = [0u8; 32];
    pub32.copy_from_slice(&pub_bytes);
    let aid = bytes_to_hex(&aid_from_public_key(&pub32));
    if aid != env.get("aid").and_then(Json::as_str).unwrap_or("") {
        return Err(AttestError("AID does not match public key (self-certification failed)".into()));
    }
    let key = VerifyingKey::from_bytes(&pub32).map_err(|e| AttestError(e.to_string()))?;
    let sig_bytes = hex_to_bytes(env.get("sig").and_then(Json::as_str).unwrap_or(""))
        .ok_or_else(|| AttestError("bad sig hex".into()))?;
    let mut sig64 = [0u8; 64];
    sig64.copy_from_slice(&sig_bytes);
    let sig = ed25519_dalek::Signature::from_bytes(&sig64);
    key.verify(&signing_input(env)?, &sig)
        .map_err(|_| AttestError("bad seal (signature does not verify)".into()))?;
    Ok(aid)
}

/// Verify an envelope **and** its claim payload (closed sets, URI grammar).
/// The signature proves who said it; the claim checks make sure what they said
/// is well-formed. Neither proves the standing is true.
pub fn verify_attestation(
    env: &Json,
    expected_subject_uri: Option<&str>,
    now: Option<u64>,
    check_freshness: bool,
) -> Result<(), AttestError> {
    verify_envelope(env, now, check_freshness)?;
    let payload = env.get("payload").ok_or_else(|| AttestError("payload missing".into()))?;
    let subject = payload.get("subject_uri").and_then(Json::as_str).unwrap_or("");
    let organ = payload.get("organ").and_then(Json::as_str).unwrap_or("");
    let standing = payload.get("standing").and_then(Json::as_str).unwrap_or("");
    let claim = build_claim(subject, organ, standing)?;
    if let Some(expected) = expected_subject_uri {
        let want = iqa_uri::parse(expected).map_err(|e| AttestError(e.0))?;
        let got = claim.get("subject_uri").and_then(Json::as_str).unwrap_or("");
        if got != want.canonical_uri {
            return Err(AttestError("subject URI mismatch (cited a different subject?)".into()));
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn seal_verify_roundtrip() {
        let kp = keypair_from_seed([7u8; 32]);
        let claim = build_claim("iqa://3f9a1b2c.gateway.iqa", "gateway", "radiant").unwrap();
        let env = seal(&claim, &kp, Some(1_760_000_000), Some("0011223344556677")).unwrap();
        assert!(verify_envelope(&env, Some(1_760_000_000), true).is_ok());
        assert!(verify_attestation(&env, Some("iqa://3f9a1b2c.gateway.iqa"),
                                   Some(1_760_000_000), true).is_ok());
        // Tamper: alter the standing after signing.
        if let Json::Obj(pairs) = &env {
            let mut t = pairs.clone();
            for (k, v) in t.iter_mut() {
                if k == "payload" {
                    *v = build_claim("iqa://3f9a1b2c.gateway.iqa", "gateway", "genesis").unwrap();
                }
            }
            assert!(verify_envelope(&Json::Obj(t), Some(1_760_000_000), false).is_err());
        }
    }

    #[test]
    fn claim_closed_sets_reject() {
        assert!(build_claim("iqa://3f9a1b2c.gateway.iqa", "gateway", "ascendant").is_err());
        assert!(build_claim("iqa://3f9a1b2c.forge.iqa", "gateway", "radiant").is_err());
        assert!(build_claim("iqa://3f9a1b2c.forgery.iqa", "forge", "radiant").is_err());
    }
}
