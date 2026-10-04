//! AE-128 -- the fixed 128-byte attestation envelope (companion draft v0.3).
//!
//! Authority boundaries:
//!   Layout .......... ae128-draft-v0.3 sec. 2 (sole authority)
//!   Canonical rule .. draft sec. 3 (HMAC over the full frame, attestation zeroed)
//!   Verification .... draft sec. 4 (fail-closed)
//!   Standing codes .. AICENT-009 sec. 11.1.1 closed set (0x00..0x03)
//!
//! Relationship to the RTTP pulse frame: the pulse frame is the QUESTION
//! carrier (rttp side, magic "RTTP", shard at 0x36); AE-128 is the ANSWER
//! carrier (iqa side, magic "IQAE"). The two formats do not parse each other
//! and MUST NOT be conflated. The intent_shard at offset 16 is the same
//! SHA-256[0:16] derivation the pulse frame carries at 0x36 -- one subject,
//! one derived address, two carriers. By design, not a compatibility claim.
//!
//! Zero dependencies: HMAC-SHA256 is implemented in-crate on top of the
//! crate's own known-answer-tested [`crate::sha256`].

use crate::sha256::Sha256;

/// Frame size in octets -- fixed; a receiver MUST reject any other length.
pub const SIZE: usize = 128;
/// Magic at offset 0: 'IQAE' (IQA Envelope) -- scheme-anchored.
pub const MAGIC: [u8; 4] = [0x49, 0x51, 0x41, 0x45];
/// The only frame version this crate knows. Unknown versions fail closed.
pub const VERSION: u8 = 1;
/// The only algorithm byte defined in version 1.
pub const ALGORITHM_HMAC_SHA256: u8 = 0x01;

pub const OFF_MAGIC: usize = 0;
pub const OFF_VERSION: usize = 4;
pub const OFF_ALGORITHM: usize = 5;
pub const OFF_FLAGS: usize = 6; // 2, u16 BE, unassigned in version 1
pub const OFF_LEASE: usize = 8; // 8, u64 BE Unix seconds
pub const OFF_SHARD: usize = 16; // 16, ROUTE_SHARD of the subject
pub const OFF_ATTESTATION: usize = 32; // 32, HMAC over the whole frame, zeroed here
pub const OFF_ORGAN: usize = 64; // 8, US-ASCII organ tag, right-padded 0x00
pub const OFF_NONCE: usize = 72; // 8, u64 BE, unique per verdict
pub const OFF_STANDING: usize = 80; // 1, closed-set standing code (draft v0.3)
pub const OFF_RESERVED: usize = 81; // 15, MUST be all zeros
pub const OFF_EXTENSION: usize = 96; // 32, MUST be all zeros in version 1

/// Standing closed set per AICENT-009 sec. 11.1.1 -- wire codes.
pub const STANDING_GHOST: u8 = 0x00;
pub const STANDING_PROBATION: u8 = 0x01;
pub const STANDING_RADIANT: u8 = 0x02;
pub const STANDING_GENESIS: u8 = 0x03;

/// The reverse map: wire code -> lowercase name.
pub const STANDING_NAMES: [(u8, &str); 4] = [
    (STANDING_GHOST, "ghost"),
    (STANDING_PROBATION, "probation"),
    (STANDING_RADIANT, "radiant"),
    (STANDING_GENESIS, "genesis"),
];

/// The only error type raised by this module.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct EnvelopeError(pub String);

impl std::fmt::Display for EnvelopeError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "AE-128: {}", self.0)
    }
}
impl std::error::Error for EnvelopeError {}

fn fail(reason: &str) -> EnvelopeError {
    EnvelopeError(format!("AE-128: {reason}"))
}

/// ROUTE_SHARD = SHA-256(ASCII(canonical_authority))[0:16] (I-D sec. 4.4).
///
/// The same derivation the rttp side performs for its pulse frame (the 16
/// octets at offset 0x36). Pure computation. NOTE: this is NOT
/// [`crate::iqa_uri::derive_route`] -- that is the 4-octet IQA_ROUTE address
/// fingerprint. Different numbers about different things.
pub fn derive_intent_shard(canonical_authority: &str) -> Result<[u8; 16], EnvelopeError> {
    if canonical_authority.is_empty() {
        return Err(fail("derive_intent_shard: authority is empty"));
    }
    let mut h = Sha256::new();
    h.update(canonical_authority.as_bytes());
    let digest = h.finalize();
    let mut shard = [0u8; 16];
    shard.copy_from_slice(&digest[..16]);
    Ok(shard)
}

/// The same 16 octets, as 32 lowercase hex characters.
pub fn intent_shard_hex(canonical_authority: &str) -> Result<String, EnvelopeError> {
    Ok(hex(&derive_intent_shard(canonical_authority)?))
}

/// In-crate HMAC-SHA256 (RFC 2104) over the crate's own SHA-256.
fn hmac_sha256(key: &[u8], message: &[u8]) -> [u8; 32] {
    const BLOCK: usize = 64;
    let mut k = [0u8; BLOCK];
    if key.len() > BLOCK {
        let mut h = Sha256::new();
        h.update(key);
        k[..32].copy_from_slice(&h.finalize());
    } else {
        k[..key.len()].copy_from_slice(key);
    }
    let mut inner = Sha256::new();
    for b in k.iter() {
        inner.update(&[b ^ 0x36]);
    }
    inner.update(message);
    let inner_out = inner.finalize();
    let mut outer = Sha256::new();
    for b in k.iter() {
        outer.update(&[b ^ 0x5c]);
    }
    outer.update(&inner_out);
    outer.finalize()
}

fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{b:02x}")).collect()
}

fn resolve_shard(intent_shard: &[u8]) -> Result<[u8; 16], EnvelopeError> {
    if intent_shard.len() != 16 {
        return Err(fail(&format!(
            "intent_shard must be exactly 16 octets, got {}",
            intent_shard.len()
        )));
    }
    let mut shard = [0u8; 16];
    shard.copy_from_slice(intent_shard);
    Ok(shard)
}

fn resolve_organ_tag(organ: &[u8]) -> Result<[u8; 8], EnvelopeError> {
    if organ.is_empty() || organ.len() > 8 {
        return Err(fail(&format!(
            "organ tag must be 1..8 octets, got {}",
            organ.len()
        )));
    }
    if let Some(pos) = organ.iter().position(|b| *b < 0x20 || *b > 0x7e) {
        return Err(fail(&format!(
            "organ tag must be printable US-ASCII (byte {pos} is not)"
        )));
    }
    let mut tag = [0u8; 8];
    tag[..organ.len()].copy_from_slice(organ);
    Ok(tag)
}

fn standing_name(code: u8) -> Option<&'static str> {
    STANDING_NAMES.iter().find(|(c, _)| *c == code).map(|(_, n)| *n)
}

/// Parameters for [`encode`] -- one verdict, wire-ready.
pub struct EncodeParams<'a> {
    /// Organ key material (non-empty). HMAC-SHA256 secret.
    pub key: &'a [u8],
    /// The subject's ROUTE_SHARD (16 octets) -- see [`derive_intent_shard`].
    pub intent_shard: [u8; 16],
    /// US-ASCII organ tag, 1..8 bytes, right-padded with 0x00.
    pub organ: &'a [u8],
    /// Standing: a closed-set wire code (see [`STANDING_NAMES`]).
    pub standing: u8,
    /// u64 BE Unix seconds -- verdict valid until (inclusive).
    pub lease_expiry: u64,
    /// u64 BE -- unique per verdict issued.
    pub nonce: u64,
    /// Must be 0x0000 in version 1 (unassigned).
    pub flags: u16,
}

/// Build one AE-128 frame (draft sec. 2 + sec. 3) -- exactly 128 octets.
///
/// The attestation is HMAC-SHA256 over the ENTIRE frame with the attestation
/// field itself zeroed -- organ tag, nonce, lease and standing are all
/// authenticated: a rewrite of any of them cannot survive verification.
pub fn encode(p: &EncodeParams<'_>) -> Result<[u8; SIZE], EnvelopeError> {
    if p.key.is_empty() {
        return Err(fail("key must be non-empty bytes (organ key material)"));
    }
    if p.flags != 0 {
        return Err(fail(&format!(
            "flags must be 0x0000 in version 1 (unassigned), got 0x{:04x}",
            p.flags
        )));
    }
    if standing_name(p.standing).is_none() {
        return Err(fail(&format!(
            "standing 0x{:02x} is outside the closed set",
            p.standing
        )));
    }
    let shard = resolve_shard(&p.intent_shard)?;
    let tag = resolve_organ_tag(p.organ)?;

    let mut frame = [0u8; SIZE];
    frame[OFF_MAGIC..OFF_MAGIC + 4].copy_from_slice(&MAGIC);
    frame[OFF_VERSION] = VERSION;
    frame[OFF_ALGORITHM] = ALGORITHM_HMAC_SHA256;
    frame[OFF_FLAGS..OFF_FLAGS + 2].copy_from_slice(&p.flags.to_be_bytes());
    frame[OFF_LEASE..OFF_LEASE + 8].copy_from_slice(&p.lease_expiry.to_be_bytes());
    frame[OFF_SHARD..OFF_SHARD + 16].copy_from_slice(&shard);
    frame[OFF_ORGAN..OFF_ORGAN + 8].copy_from_slice(&tag);
    frame[OFF_NONCE..OFF_NONCE + 8].copy_from_slice(&p.nonce.to_be_bytes());
    frame[OFF_STANDING] = p.standing;
    // attestation (32..63), reserved (81..95) and extension (96..127) stay zero

    let mac = hmac_sha256(p.key, &frame);
    frame[OFF_ATTESTATION..OFF_ATTESTATION + 32].copy_from_slice(&mac);
    Ok(frame)
}

/// A structurally decoded AE-128 frame.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ParsedEnvelope {
    pub version: u8,
    pub algorithm: u8,
    pub flags: u16,
    pub lease_expiry: u64,
    pub intent_shard: [u8; 16],
    pub attestation: [u8; 32],
    pub organ: String,
    pub nonce: u64,
    pub standing: u8,
}

impl ParsedEnvelope {
    /// The lowercase standing name for the wire code, or None if impossible
    /// (parse already guarantees membership in the closed set).
    pub fn standing_name(&self) -> Option<&'static str> {
        standing_name(self.standing)
    }
}

/// Structural decode -- fail closed on every rule of draft sec. 2/sec. 4.
/// Malformed input is REJECTED, never normalised into a partial result.
pub fn parse(data: &[u8]) -> Result<ParsedEnvelope, EnvelopeError> {
    if data.len() != SIZE {
        return Err(fail(&format!(
            "frame must be exactly {SIZE} octets, got {}",
            data.len()
        )));
    }
    if data[OFF_MAGIC..OFF_MAGIC + 4] != MAGIC {
        return Err(fail(&format!(
            "bad magic {:?} (expected 'IQAE')",
            String::from_utf8_lossy(&data[OFF_MAGIC..OFF_MAGIC + 4])
        )));
    }
    if data[OFF_VERSION] != VERSION {
        return Err(fail(&format!("unknown version 0x{:02x}", data[OFF_VERSION])));
    }
    if data[OFF_ALGORITHM] != ALGORITHM_HMAC_SHA256 {
        return Err(fail(&format!(
            "unknown algorithm 0x{:02x}",
            data[OFF_ALGORITHM]
        )));
    }
    let flags = u16::from_be_bytes([data[OFF_FLAGS], data[OFF_FLAGS + 1]]);
    if flags != 0 {
        return Err(fail(&format!(
            "flags must be 0x0000 in version 1 (unassigned), got 0x{flags:04x}"
        )));
    }

    let tag = &data[OFF_ORGAN..OFF_ORGAN + 8];
    let end = tag.iter().rposition(|b| *b != 0).map_or(0, |p| p + 1);
    let stripped = &tag[..end];
    if stripped.is_empty() {
        return Err(fail("organ tag must be printable US-ASCII (right-padded with 0x00)"));
    }
    if let Some(pos) = stripped.iter().position(|b| *b < 0x20 || *b > 0x7e) {
        return Err(fail(&format!(
            "organ tag must be printable US-ASCII (byte {pos} is not)"
        )));
    }

    let code = data[OFF_STANDING];
    if standing_name(code).is_none() {
        return Err(fail(&format!(
            "standing 0x{code:02x} is outside the closed set"
        )));
    }

    if data[OFF_RESERVED..OFF_EXTENSION].iter().any(|b| *b != 0) {
        return Err(fail("reserved field (81..95) MUST be all zeros"));
    }
    if data[OFF_EXTENSION..SIZE].iter().any(|b| *b != 0) {
        return Err(fail("extension field (96..127) MUST be all zeros in version 1"));
    }

    Ok(ParsedEnvelope {
        version: data[OFF_VERSION],
        algorithm: data[OFF_ALGORITHM],
        flags,
        lease_expiry: u64::from_be_bytes(data[OFF_LEASE..OFF_LEASE + 8].try_into().unwrap()),
        intent_shard: data[OFF_SHARD..OFF_SHARD + 16].try_into().unwrap(),
        attestation: data[OFF_ATTESTATION..OFF_ATTESTATION + 32].try_into().unwrap(),
        organ: String::from_utf8_lossy(stripped).into_owned(),
        nonce: u64::from_be_bytes(data[OFF_NONCE..OFF_NONCE + 8].try_into().unwrap()),
        standing: code,
    })
}

/// Outcome of [`verify`] -- a failure is a RESULT, never a panic.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct VerifyResult {
    pub ok: bool,
    pub reason: String,
    pub frame: Option<ParsedEnvelope>,
}

/// Verify one AE-128 frame (draft sec. 4). Constant-time HMAC compare via
/// fold-xor (no early exit). `check_lease = false` is the archival mode.
pub fn verify(data: &[u8], key: &[u8], now: u64, check_lease: bool) -> VerifyResult {
    let frame = match parse(data) {
        Ok(f) => f,
        Err(e) => return VerifyResult { ok: false, reason: e.0, frame: None },
    };
    if check_lease && frame.lease_expiry < now {
        return VerifyResult {
            ok: false,
            reason: format!(
                "verdict expired (lease_expiry {} < now {now})",
                frame.lease_expiry
            ),
            frame: None,
        };
    }
    let mut scratch = [0u8; SIZE];
    scratch.copy_from_slice(data);
    scratch[OFF_ATTESTATION..OFF_ATTESTATION + 32].fill(0);
    let expected = hmac_sha256(key, &scratch);
    // constant-time compare
    let mut diff = 0u8;
    for (a, b) in expected.iter().zip(frame.attestation.iter()) {
        diff |= a ^ b;
    }
    if diff != 0 {
        return VerifyResult {
            ok: false,
            reason: "attestation does not verify (HMAC mismatch)".into(),
            frame: None,
        };
    }
    VerifyResult { ok: true, reason: "ok".into(), frame: Some(frame) }
}

// ---------------------------------------------------------------------------
// The published vector (companion draft v0.3 sec. 6) -- every parameter is
// documented there; any implementation MUST reproduce the frame byte for byte.

/// The merged I-D's own example authority (sec. 4.4).
pub const VECTOR_1_AUTHORITY: &str = "f3b2a1c4.pillar.example";
/// 32-byte US-ASCII test organ key (label retained from v0.1 for diff continuity).
pub const VECTOR_1_KEY: &[u8] = b"PLSF-TEST-ORG-KEY-00012345678901";
/// 2027-01-01T00:00:00Z.
pub const VECTOR_1_LEASE: u64 = 1798761600;
pub const VECTOR_1_STANDING: u8 = STANDING_RADIANT;
pub const VECTOR_1_ORGAN: &[u8] = b"ORG-TEST";
pub const VECTOR_1_NONCE: u64 = 1;
/// The full 128-octet published vector, as lowercase hex.
pub const VECTOR_1_FRAME_HEX: &str = concat!(
    "4951414501010000000000006b36ec80",
    "557c8154d3780cb78cc5fa1bd72b331c",
    "4bd14b6ae7b00904986294a326a0f0255847184ff2c9185539d4863efb84596a",
    "4f52472d544553540000000000000001",
    "02", "0000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000",
);

/// The published vector as bytes -- [`encode`] of the documented parameters.
pub fn vector_1_frame() -> Result<[u8; SIZE], EnvelopeError> {
    encode(&EncodeParams {
        key: VECTOR_1_KEY,
        intent_shard: derive_intent_shard(VECTOR_1_AUTHORITY)?,
        organ: VECTOR_1_ORGAN,
        standing: VECTOR_1_STANDING,
        lease_expiry: VECTOR_1_LEASE,
        nonce: VECTOR_1_NONCE,
        flags: 0,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn vector_1_reproduces_byte_for_byte() {
        let frame = vector_1_frame().unwrap();
        assert_eq!(hex(&frame), VECTOR_1_FRAME_HEX);
    }

    #[test]
    fn vector_1_verifies_before_expiry() {
        let frame = vector_1_frame().unwrap();
        let r = verify(&frame, VECTOR_1_KEY, VECTOR_1_LEASE - 1, true);
        assert!(r.ok, "{}", r.reason);
        assert_eq!(r.frame.unwrap().standing_name(), Some("radiant"));
    }

    #[test]
    fn lease_boundary_is_inclusive_and_expiry_rejects() {
        let frame = vector_1_frame().unwrap();
        assert!(verify(&frame, VECTOR_1_KEY, VECTOR_1_LEASE, true).ok);
        let r = verify(&frame, VECTOR_1_KEY, VECTOR_1_LEASE + 1, true);
        assert!(!r.ok);
        assert!(r.reason.contains("expired"));
        assert!(verify(&frame, VECTOR_1_KEY, VECTOR_1_LEASE + 100, false).ok);
    }

    #[test]
    fn shard_derivation_matches_i_d_4_4() {
        assert_eq!(
            intent_shard_hex(VECTOR_1_AUTHORITY).unwrap(),
            "557c8154d3780cb78cc5fa1bd72b331c"
        );
    }

    #[test]
    fn standing_outside_closed_set_is_rejected() {
        let p = EncodeParams {
            key: VECTOR_1_KEY,
            intent_shard: derive_intent_shard(VECTOR_1_AUTHORITY).unwrap(),
            organ: VECTOR_1_ORGAN,
            standing: 0x04,
            lease_expiry: VECTOR_1_LEASE,
            nonce: 1,
            flags: 0,
        };
        assert!(encode(&p).is_err());
    }

    #[test]
    fn structural_rejects_fail_closed() {
        let base = vector_1_frame().unwrap();
        let rejects: Vec<(&str, Box<dyn Fn(&mut [u8; SIZE])>)> = vec![
            ("version 2", Box::new(|f: &mut [u8; SIZE]| f[4] = 2)),
            ("algorithm 0x00", Box::new(|f: &mut [u8; SIZE]| f[5] = 0)),
            ("algorithm 0x02", Box::new(|f: &mut [u8; SIZE]| f[5] = 2)),
            ("flags nonzero", Box::new(|f: &mut [u8; SIZE]| f[6] = 1)),
            ("standing 0x04", Box::new(|f: &mut [u8; SIZE]| f[80] = 4)),
            ("reserved nonzero", Box::new(|f: &mut [u8; SIZE]| f[85] = 1)),
            ("extension nonzero", Box::new(|f: &mut [u8; SIZE]| f[100] = 1)),
            ("organ non-ascii", Box::new(|f: &mut [u8; SIZE]| f[64] = 0xFF)),
            (
                "pulse-frame magic",
                Box::new(|f: &mut [u8; SIZE]| f[..4].copy_from_slice(b"RTTP")),
            ),
        ];
        for (label, mutate) in rejects {
            let mut frame = base;
            mutate(&mut frame);
            assert!(parse(&frame).is_err(), "{label} was accepted");
        }
        assert!(parse(&base[..127]).is_err());
        assert!(parse(&base).is_ok());
    }

    #[test]
    fn tamper_matrix_full_frame_authentication() {
        let base = vector_1_frame().unwrap();
        let tampers: Vec<(&str, Box<dyn Fn(&mut [u8; SIZE])>)> = vec![
            ("attestation bit", Box::new(|f: &mut [u8; SIZE]| f[32] ^= 0x01)),
            ("organ tag", Box::new(|f: &mut [u8; SIZE]| f[71] = 0x55)),
            ("nonce", Box::new(|f: &mut [u8; SIZE]| f[79] = 2)),
            (
                "standing radiant->genesis",
                Box::new(|f: &mut [u8; SIZE]| f[80] = 3),
            ),
            ("lease", Box::new(|f: &mut [u8; SIZE]| f[15] = 0x81)),
            (
                "shard",
                Box::new(|f: &mut [u8; SIZE]| {
                    for (i, b) in f[16..32].iter_mut().enumerate() {
                        *b = i as u8;
                    }
                }),
            ),
        ];
        for (label, mutate) in tampers {
            let mut frame = base;
            mutate(&mut frame);
            let r = verify(&frame, VECTOR_1_KEY, VECTOR_1_LEASE - 1, true);
            assert!(!r.ok, "{label} was accepted");
        }
    }

    #[test]
    fn shipped_vector_file_replays_end_to_end() {
        let doc = crate::json::parse(include_str!(
            "../vectors/ae128-vectors-v1.json"
        ))
        .expect("vector file must parse");
        let unhex = |s: &str, into: &mut Vec<u8>| {
            (0..s.len() / 2).for_each(|i| {
                into.push(u8::from_str_radix(&s[i * 2..i * 2 + 2], 16).unwrap())
            });
        };

        let positive = doc.get("positive_frame_hex").and_then(|v| v.as_str()).unwrap();
        let frame = vector_1_frame().unwrap();
        assert_eq!(hex(&frame), positive);

        for (i, item) in doc
            .get("negative_frames")
            .and_then(|v| v.as_arr())
            .unwrap()
            .iter()
            .enumerate()
        {
            let hexstr = item.get("frame_hex").and_then(|v| v.as_str()).unwrap();
            let mut raw = Vec::new();
            unhex(hexstr, &mut raw);
            assert!(parse(&raw).is_err(), "negative frame #{i} was accepted");
        }
        for (i, item) in doc
            .get("tampered_frames")
            .and_then(|v| v.as_arr())
            .unwrap()
            .iter()
            .enumerate()
        {
            let hexstr = item.get("frame_hex").and_then(|v| v.as_str()).unwrap();
            let mut raw = Vec::new();
            unhex(hexstr, &mut raw);
            let r = verify(&raw, VECTOR_1_KEY, VECTOR_1_LEASE - 1, true);
            assert!(!r.ok, "tampered frame #{i} verified");
        }
    }
}
