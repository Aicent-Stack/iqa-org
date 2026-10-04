/**
 * AE-128 -- the fixed 128-byte attestation envelope (companion draft v0.3).
 * Zero dependencies. Field names are snake_case on purpose: they match the
 * Python implementation (iqa.envelope) and the published vector byte for byte.
 */

export declare const SIZE: 128;
export declare const MAGIC: 'IQAE';
export declare const VERSION: 1;
export declare const ALGORITHM_HMAC_SHA256: 0x01;

export declare const OFF_MAGIC: 0;
export declare const OFF_VERSION: 4;
export declare const OFF_ALGORITHM: 5;
export declare const OFF_FLAGS: 6;
export declare const OFF_LEASE: 8;
export declare const OFF_SHARD: 16;
export declare const OFF_ATTESTATION: 32;
export declare const OFF_ORGAN: 64;
export declare const OFF_NONCE: 72;
export declare const OFF_STANDING: 80;
export declare const OFF_RESERVED: 81;
export declare const OFF_EXTENSION: 96;

/** Standing closed set per AICENT-009 sec. 11.1.1. */
export declare const STANDING_CODES: Readonly<Record<'ghost' | 'probation' | 'radiant' | 'genesis', number>>;
export declare const STANDING_NAMES: Readonly<Record<number, string>>;

export declare class EnvelopeError extends Error {}

/**
 * ROUTE_SHARD = SHA-256(ASCII(canonical_authority))[0:16]  (I-D sec. 4.4).
 * The same derivation the rttp pulse frame carries at offset 0x36 -- NOT
 * deriveRoute() (the 4-octet IQA_ROUTE address fingerprint).
 */
export declare function deriveIntentShard(canonicalAuthority: string): Uint8Array;
export declare function intentShardHex(canonicalAuthority: string): string;

export interface EncodeParams {
  /** Organ key material (non-empty). HMAC-SHA256 secret. */
  key: Uint8Array;
  /** The subject's ROUTE_SHARD: 16 bytes or 32 hex characters. */
  intent_shard: Uint8Array | string;
  /** US-ASCII organ tag, 1..8 characters, right-padded with 0x00. */
  organ: string | Uint8Array;
  /** Standing: a closed-set wire code or its lowercase name. */
  standing: number | string;
  /** u64 BE Unix seconds -- verdict valid until (inclusive). */
  lease_expiry: number;
  /** u64 BE -- unique per verdict issued. */
  nonce: number;
  /** Must be 0x0000 in version 1 (unassigned). */
  flags?: number;
}

/** Build one AE-128 frame -- exactly 128 bytes (draft sec. 2 + sec. 3). */
export declare function encode(params: EncodeParams): Uint8Array;

export interface ParsedEnvelope {
  version: number;
  algorithm: number;
  flags: number;
  lease_expiry: number;
  intent_shard: Uint8Array;
  attestation: Uint8Array;
  organ: string;
  nonce: number;
  standing: number;
  standing_name: string;
}

/** Structural decode -- fail closed on every rule. Throws EnvelopeError. */
export declare function parse(data: Uint8Array): ParsedEnvelope;

export interface VerifyResult {
  ok: boolean;
  reason: string;
  /** The parsed frame on success, null on failure. */
  frame: ParsedEnvelope | null;
}

/**
 * Verify one AE-128 frame (draft sec. 4). Constant-time HMAC compare.
 * A failure is a RESULT, never an exception. now defaults to the wall clock;
 * check_lease=false is the archival mode.
 */
export declare function verify(
  data: Uint8Array,
  key: Uint8Array,
  opts?: { now?: number | null; check_lease?: boolean },
): VerifyResult;

export declare const VECTOR_1_AUTHORITY: string;
export declare const VECTOR_1_KEY: Uint8Array;
export declare const VECTOR_1_LEASE: 1798761600;
export declare const VECTOR_1_STANDING: 'radiant';
export declare const VECTOR_1_ORGAN: 'ORG-TEST';
export declare const VECTOR_1_NONCE: 1;
/** The full 128-octet published vector, as lowercase hex. */
export declare const VECTOR_1_FRAME_HEX: string;

/** The published vector as bytes -- encode() of the documented parameters. */
export declare function vector1Frame(): Uint8Array;
