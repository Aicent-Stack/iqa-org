/**
 * iqa -- RFC-009 sec. 10/sec. 11 codec for JavaScript.
 * Zero dependencies. Field names are snake_case on purpose: they match the
 * published conformance vectors (and the Python implementation) field for field.
 */

export declare const SCHEME: 'iqa';
export declare const ORGANS: readonly ['forge', 'tss', 'gateway'];
export declare const ACTIONS: readonly ['verify', 'audit', 'attest', 'revoke'];
export declare const STANDINGS: readonly ['ghost', 'probation', 'radiant', 'genesis'];
export declare const HASH_LENGTHS: readonly [8, 32, 64];

export declare class IqaUriError extends Error {}

/** True only for the closed four-verb set (RFC-009 sec. 10.1). */
export declare function isValidAction(value: string): boolean;

/**
 * IQA_ROUTE = SHA-256(ASCII(canonical_authority))[0:4]  (SPEC sec. 3).
 * The address fingerprint -- not the subject hash (which hints the AID).
 */
export declare function deriveRoute(authority: string): Uint8Array;
export declare function deriveRouteHex(authority: string): string;

export interface ParsedUri {
  scheme: 'iqa';
  subject: string;
  subject_is_hash: boolean;
  subject_hex: string | null;
  organ: string;
  root: string;
  authority: string;
  action: string | null;
  action_omitted: boolean;
  /** RFC-009 sec. 11.3 -- true for omitted and `verify`, false for audit/attest/revoke. */
  action_safe: boolean;
  canonical_uri: string;
  route_hex: string;
}

/** Validate, canonicalise and derive. Throws IqaUriError on any violation. */
export declare function parse(uri: string): ParsedUri;
