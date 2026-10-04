// AE-128 -- the fixed 128-byte attestation envelope (companion draft v0.3).
//
// Authority boundaries:
//   Layout .......... ae128-draft-v0.3 sec. 2 (sole authority)
//   Canonical rule .. draft sec. 3 (HMAC over the full frame, attestation zeroed)
//   Verification .... draft sec. 4 (fail-closed, constant-time compare)
//   Standing codes .. AICENT-009 sec. 11.1.1 closed set (0x00..0x03)
//
// Relationship to the RTTP pulse frame: the pulse frame is the QUESTION
// carrier (rttp side, magic "RTTP", shard at 0x36); AE-128 is the ANSWER
// carrier (iqa side, magic "IQAE"). The two formats do not parse each other
// and MUST NOT be conflated. The intent_shard at offset 16 is the same
// SHA-256[0:16] derivation the pulse frame carries at 0x36 -- one subject,
// one derived address, two carriers. By design, not a compatibility claim.
//
// Zero dependencies. Node 18+. No build step -- the published src/ is what runs.

import { createHash, createHmac, timingSafeEqual } from 'node:crypto';

/** Frame size in octets -- fixed; a receiver MUST reject any other length. */
export const SIZE = 128;
/** Magic at offset 0: 'IQAE' (IQA Envelope) -- scheme-anchored, four printable ASCII bytes. */
export const MAGIC = 'IQAE';
/** The only frame version this module knows. Unknown versions fail closed. */
export const VERSION = 1;
/** The only algorithm byte defined in version 1. */
export const ALGORITHM_HMAC_SHA256 = 0x01;

// Fixed offsets (zero-based) -- the whole point of the format.
export const OFF_MAGIC = 0;
export const OFF_VERSION = 4;
export const OFF_ALGORITHM = 5;
export const OFF_FLAGS = 6;      // 2, u16 BE, unassigned in version 1
export const OFF_LEASE = 8;      // 8, u64 BE Unix seconds
export const OFF_SHARD = 16;     // 16, ROUTE_SHARD of the subject
export const OFF_ATTESTATION = 32; // 32, HMAC over the whole frame, zeroed here
export const OFF_ORGAN = 64;     // 8, US-ASCII organ tag, right-padded 0x00
export const OFF_NONCE = 72;     // 8, u64 BE, unique per verdict
export const OFF_STANDING = 80;  // 1, closed-set standing code (draft v0.3)
export const OFF_RESERVED = 81;  // 15, MUST be all zeros
export const OFF_EXTENSION = 96; // 32, MUST be all zeros in version 1

/** Standing closed set per AICENT-009 sec. 11.1.1 -- wire codes and names. */
export const STANDING_CODES = Object.freeze({ ghost: 0x00, probation: 0x01, radiant: 0x02, genesis: 0x03 });
/** The reverse map: wire code -> lowercase name. */
export const STANDING_NAMES = Object.freeze(Object.fromEntries(
  Object.entries(STANDING_CODES).map(([name, code]) => [code, name])));

const ORGAN_LEN = 8;
const SHARD_LEN = 16;
const ATTESTATION_LEN = 32;
const MAGIC_BYTES = Buffer.from(MAGIC, 'ascii');

export class EnvelopeError extends Error {
  constructor(message) {
    super(message);
    this.name = 'EnvelopeError';
  }
}

const fail = (reason) => new EnvelopeError('AE-128: ' + reason);

/**
 * ROUTE_SHARD = SHA-256(ASCII(canonical_authority))[0:16]  (I-D sec. 4.4).
 *
 * The same derivation the rttp side performs for its pulse frame (the 16
 * octets at offset 0x36). Pure computation: no registry, no resolver, no
 * network. NOTE: this is NOT deriveRoute() -- that is the 4-octet IQA_ROUTE
 * address fingerprint. Different numbers about different things.
 */
export function deriveIntentShard(canonicalAuthority) {
  if (!canonicalAuthority) throw fail('deriveIntentShard: authority is empty');
  try {
    return createHash('sha256').update(canonicalAuthority, 'ascii').digest().subarray(0, SHARD_LEN);
  } catch {
    throw fail('deriveIntentShard: authority must be US-ASCII');
  }
}

/** The same 16 octets, as 32 lowercase hex characters. */
export function intentShardHex(canonicalAuthority) {
  return deriveIntentShard(canonicalAuthority).toString('hex');
}

function resolveStanding(standing) {
  if (typeof standing === 'number' && Number.isInteger(standing)) {
    if (standing in STANDING_NAMES) return standing;
    throw fail(`standing 0x${standing.toString(16).padStart(2, '0')} is outside the closed set`);
  }
  if (typeof standing === 'string') {
    if (standing in STANDING_CODES) return STANDING_CODES[standing];
    throw fail(`standing ${JSON.stringify(standing)} is outside the closed set`);
  }
  throw fail(`standing must be a code or a name, got ${typeof standing}`);
}

function resolveShard(intentShard) {
  let shard;
  if (typeof intentShard === 'string') {
    if (!/^[0-9a-fA-F]+$/.test(intentShard) || intentShard.length % 2 !== 0) {
      throw fail('intent_shard hex is not valid hex');
    }
    shard = Buffer.from(intentShard, 'hex');
  } else if (intentShard instanceof Uint8Array) {
    shard = Buffer.from(intentShard);
  } else {
    throw fail(`intent_shard must be bytes or hex, got ${typeof intentShard}`);
  }
  if (shard.length !== SHARD_LEN) {
    throw fail(`intent_shard must be exactly ${SHARD_LEN} octets, got ${shard.length}`);
  }
  return shard;
}

function resolveOrganTag(organ) {
  let tag;
  if (typeof organ === 'string') {
    tag = Buffer.from(organ, 'ascii');
    if (tag.length !== organ.length) throw fail('organ tag must be US-ASCII');
  } else if (organ instanceof Uint8Array) {
    tag = Buffer.from(organ);
  } else {
    throw fail(`organ must be a string or bytes, got ${typeof organ}`);
  }
  if (tag.length < 1 || tag.length > ORGAN_LEN) {
    throw fail(`organ tag must be 1..${ORGAN_LEN} octets, got ${tag.length}`);
  }
  for (const b of tag) {
    if (b < 0x20 || b > 0x7e) throw fail('organ tag must be printable US-ASCII');
  }
  return Buffer.concat([tag, Buffer.alloc(ORGAN_LEN - tag.length)]);
}

function resolveU64(value, label) {
  if (typeof value !== 'number' || !Number.isInteger(value)) {
    throw fail(`${label} must be an integer`);
  }
  if (value < 0 || value > Number.MAX_SAFE_INTEGER) {
    throw fail(`${label} ${value} is outside the safe unsigned range`);
  }
  return value;
}

/**
 * Build one AE-128 frame (draft sec. 2 + sec. 3). Returns 128 bytes.
 *
 * The attestation is HMAC-SHA256 over the ENTIRE frame with the attestation
 * field itself zeroed -- organ tag, nonce, lease and standing are all
 * authenticated: a rewrite of any of them cannot survive verification.
 */
export function encode({ key, intent_shard, organ, standing, lease_expiry, nonce, flags = 0 }) {
  if (!(key instanceof Uint8Array) || key.length === 0) {
    throw fail('key must be non-empty bytes (organ key material)');
  }
  if (flags !== 0) {
    throw fail(`flags must be 0x0000 in version 1 (unassigned), got 0x${flags.toString(16).padStart(4, '0')}`);
  }
  const shard = resolveShard(intent_shard);
  const tag = resolveOrganTag(organ);
  const code = resolveStanding(standing);
  const lease = resolveU64(lease_expiry, 'lease_expiry');
  const nonce64 = resolveU64(nonce, 'nonce');

  const frame = Buffer.alloc(SIZE);
  Buffer.from(MAGIC_BYTES).copy(frame, OFF_MAGIC);
  frame[OFF_VERSION] = VERSION;
  frame[OFF_ALGORITHM] = ALGORITHM_HMAC_SHA256;
  frame.writeUInt16BE(flags, OFF_FLAGS);
  frame.writeBigUInt64BE(BigInt(lease), OFF_LEASE);
  shard.copy(frame, OFF_SHARD);
  tag.copy(frame, OFF_ORGAN);
  frame.writeBigUInt64BE(BigInt(nonce64), OFF_NONCE);
  frame[OFF_STANDING] = code;
  // attestation (32..63), reserved (81..95) and extension (96..127) stay zero

  const mac = createHmac('sha256', Buffer.from(key)).update(frame).digest();
  mac.copy(frame, OFF_ATTESTATION);
  return frame;
}

/**
 * Structural decode -- fail closed on every rule of draft sec. 2/sec. 4.
 * Returns a snake_case field dict (byte-comparable with the Python output).
 * Throws EnvelopeError on any violation; malformed input is never normalised.
 */
export function parse(data) {
  if (!(data instanceof Uint8Array)) {
    throw fail(`frame must be bytes, got ${typeof data}`);
  }
  const frame = Buffer.from(data);
  if (frame.length !== SIZE) {
    throw fail(`frame must be exactly ${SIZE} octets, got ${frame.length}`);
  }
  if (!frame.subarray(OFF_MAGIC, OFF_MAGIC + 4).equals(MAGIC_BYTES)) {
    throw fail(`bad magic ${JSON.stringify(frame.subarray(0, 4).toString('latin1'))} (expected 'IQAE')`);
  }
  if (frame[OFF_VERSION] !== VERSION) {
    throw fail(`unknown version 0x${frame[OFF_VERSION].toString(16).padStart(2, '0')}`);
  }
  if (frame[OFF_ALGORITHM] !== ALGORITHM_HMAC_SHA256) {
    throw fail(`unknown algorithm 0x${frame[OFF_ALGORITHM].toString(16).padStart(2, '0')}`);
  }
  const flags = frame.readUInt16BE(OFF_FLAGS);
  if (flags !== 0) {
    throw fail(`flags must be 0x0000 in version 1 (unassigned), got 0x${flags.toString(16).padStart(4, '0')}`);
  }

  const tag = frame.subarray(OFF_ORGAN, OFF_ORGAN + ORGAN_LEN);
  let end = ORGAN_LEN;
  while (end > 0 && tag[end - 1] === 0x00) end -= 1;
  const stripped = tag.subarray(0, end);
  if (stripped.length === 0) {
    throw fail('organ tag must be printable US-ASCII (right-padded with 0x00)');
  }
  for (const b of stripped) {
    if (b < 0x20 || b > 0x7e) throw fail('organ tag must be printable US-ASCII (right-padded with 0x00)');
  }

  const code = frame[OFF_STANDING];
  if (!(code in STANDING_NAMES)) {
    throw fail(`standing 0x${code.toString(16).padStart(2, '0')} is outside the closed set`);
  }

  if (!frame.subarray(OFF_RESERVED, OFF_EXTENSION).every((b) => b === 0)) {
    throw fail('reserved field (81..95) MUST be all zeros');
  }
  if (!frame.subarray(OFF_EXTENSION, SIZE).every((b) => b === 0)) {
    throw fail('extension field (96..127) MUST be all zeros in version 1');
  }

  return {
    version: frame[OFF_VERSION],
    algorithm: frame[OFF_ALGORITHM],
    flags,
    lease_expiry: Number(frame.readBigUInt64BE(OFF_LEASE)),
    intent_shard: frame.subarray(OFF_SHARD, OFF_SHARD + SHARD_LEN),
    attestation: frame.subarray(OFF_ATTESTATION, OFF_ATTESTATION + ATTESTATION_LEN),
    organ: stripped.toString('ascii'),
    nonce: Number(frame.readBigUInt64BE(OFF_NONCE)),
    standing: code,
    standing_name: STANDING_NAMES[code],
  };
}

/**
 * Verify one AE-128 frame (draft sec. 4). Constant-time HMAC compare.
 * Returns { ok, reason, frame }: on success frame is the parsed dict; on
 * failure frame is null and reason says which rule rejected it. A failure is
 * a RESULT, never an exception -- the caller decides.
 */
export function verify(data, key, { now = null, check_lease = true } = {}) {
  let parsed;
  try {
    parsed = parse(data);
  } catch (exc) {
    return { ok: false, reason: exc.message, frame: null };
  }
  if (check_lease) {
    const at = now === null ? Date.now() / 1000 : now;
    if (typeof at !== 'number') {
      return { ok: false, reason: `now must be a number, got ${typeof at}`, frame: null };
    }
    if (parsed.lease_expiry < at) {
      return { ok: false, reason: `verdict expired (lease_expiry ${parsed.lease_expiry} < now ${Math.floor(at)})`, frame: null };
    }
  }
  const scratch = Buffer.from(data);
  scratch.fill(0, OFF_ATTESTATION, OFF_ATTESTATION + ATTESTATION_LEN);
  const expected = createHmac('sha256', Buffer.from(key)).update(scratch).digest();
  const given = Buffer.from(parsed.attestation);
  if (!timingSafeEqual(expected, given)) {
    return { ok: false, reason: 'attestation does not verify (HMAC mismatch)', frame: null };
  }
  return { ok: true, reason: 'ok', frame: parsed };
}

// ---------------------------------------------------------------------------
// The published vector (companion draft v0.3 sec. 6) -- every parameter is
// documented there, so any implementation MUST reproduce the frame byte for
// byte from the parameters alone. Generated by ae128-vector-1.py, not typed.

/** The merged I-D's own example authority (sec. 4.4). */
export const VECTOR_1_AUTHORITY = 'f3b2a1c4.pillar.example';
/** 32-byte US-ASCII test organ key (label retained from v0.1 for diff continuity). */
export const VECTOR_1_KEY = Buffer.from('PLSF-TEST-ORG-KEY-00012345678901', 'ascii');
/** 2027-01-01T00:00:00Z. */
export const VECTOR_1_LEASE = 1798761600;
export const VECTOR_1_STANDING = 'radiant';
export const VECTOR_1_ORGAN = 'ORG-TEST';
export const VECTOR_1_NONCE = 1;
/** The full 128-octet frame, as lowercase hex. */
export const VECTOR_1_FRAME_HEX =
  '4951414501010000' + '000000006b36ec80' +
  '557c8154d3780cb78cc5fa1bd72b331c' +
  '4bd14b6ae7b00904986294a326a0f0255847184ff2c9185539d4863efb84596a' +
  '4f52472d544553540000000000000001' +
  '02' + '00'.repeat(47);

/** The published vector as bytes -- encode() of the documented parameters. */
export function vector1Frame() {
  return encode({
    key: VECTOR_1_KEY,
    intent_shard: deriveIntentShard(VECTOR_1_AUTHORITY),
    organ: VECTOR_1_ORGAN,
    standing: VECTOR_1_STANDING,
    lease_expiry: VECTOR_1_LEASE,
    nonce: VECTOR_1_NONCE,
  });
}
