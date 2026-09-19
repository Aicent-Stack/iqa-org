// iqa:// URI codec — validate, canonicalise, derive (RFC-009 §10/§11).
//
// Authority boundaries:
//   Grammar ......... RFC-009 §10.2 ABNF (sole authority)
//   Closed sets ..... §10.1 (organ and action are CLOSED sets)
//   Case discipline . §10.3 (lowercase US-ASCII only) + §12 #8 (fail closed)
//   Deref safety .... §11.3 (action safety classes)
//   Route derivation  SPEC/IQA-URI-ATTEST-v1.2.6.md §3 (IQA_ROUTE)
//
// Zero dependencies. Node 18+. No build step — the published src/ is what runs.

import { createHash } from 'node:crypto';

export const SCHEME = 'iqa';

/** RFC-009 §10.1 — organ is a CLOSED set (RFC-009-A/-B/-C). */
export const ORGANS = Object.freeze(['forge', 'tss', 'gateway']);

/**
 * RFC-009 §10.1 — action is a CLOSED set. This is the deliberate difference
 * from `rttp`, whose verb set is open: here anything outside the four verbs
 * is rejected.
 */
export const ACTIONS = Object.freeze(['verify', 'audit', 'attest', 'revoke']);

/** RFC-009-C §3 — standings an Organ may render (closed set, lowercase). */
export const STANDINGS = Object.freeze(['ghost', 'probation', 'radiant', 'genesis']);

/** RFC-009 §10.2 — hash-subject lengths: routing short form / 128-bit / 256-bit. */
export const HASH_LENGTHS = Object.freeze([8, 32, 64]);

const SAFE = new Set([null, 'verify']); // §11.3: omitted = standing read; verify = read-only
const LOWHEX = new Set('0123456789abcdef');
const NAME_CHARS = new Set('abcdefghijklmnopqrstuvwxyz0123456789-');
const ALLOWED = new Set([...LOWHEX, ...NAME_CHARS, '.', '/']);
const FORBIDDEN = new Set(['@', ':', '?', '#', '[', ']']);

export class IqaUriError extends Error {
  constructor(message) {
    super(message);
    this.name = 'IqaUriError';
  }
}

const fail = (uri, reason) => new IqaUriError(`${JSON.stringify(uri)}: ${reason}`);

/** §10.2 action test — true only for the closed four-verb set. */
export function isValidAction(value) {
  return ACTIONS.includes(value);
}

/**
 * IQA_ROUTE = SHA-256(ASCII(canonical_authority))[0:4]  (SPEC §3, decision D1).
 *
 * Pure computation, DNS-free (RFC-009 §12 #9). Mirrors the RTTP ROUTE_SHARD
 * rule so both schemes of the same addressing family derive the same way.
 * NOTE: this is the *address* fingerprint — NOT the subject hash, which is a
 * routing hint for the *AID*. Different numbers about different things.
 */
export function deriveRoute(authority) {
  if (!authority) throw new IqaUriError('deriveRoute: authority is empty');
  return createHash('sha256').update(authority, 'ascii').digest().subarray(0, 4);
}

/** The same four bytes, as 8 lowercase hex characters. */
export function deriveRouteHex(authority) {
  return deriveRoute(authority).toString('hex');
}

/**
 * Validate, canonicalise and derive. Throws IqaUriError on any violation.
 *
 * Returned fields are snake_case ON PURPOSE so this output and the Python
 * package's output compare directly against the published vectors — field
 * for field, byte for byte.
 */
export function parse(uri) {
  if (typeof uri !== 'string') throw fail(uri, 'input must be a string');

  const prefix = SCHEME + '://';
  if (!uri.startsWith(prefix)) {
    throw fail(uri, `scheme must be exactly ${JSON.stringify(prefix)} - no other `
      + 'scheme, no case variant, no fallback (RFC-009 §10.3, §12 #8)');
  }
  const rest = uri.slice(prefix.length);

  // Charset gate: lowercase US-ASCII only (§10.3). One scan rejects uppercase
  // anywhere, userinfo '@', port ':', query '?', fragment '#', whitespace and
  // every other foreign byte.
  for (const ch of rest) {
    if (!ALLOWED.has(ch)) {
      if (FORBIDDEN.has(ch)) {
        throw fail(uri, `${JSON.stringify(ch)} is not defined by the scheme (RFC-009 §10.3)`);
      }
      if (/\s/.test(ch)) {
        throw fail(uri, 'whitespace is not allowed (RFC-009 §10.3 lowercase US-ASCII only)');
      }
      throw fail(uri, `character ${JSON.stringify(ch)} is outside the allowed set `
        + "(lowercase US-ASCII, digits, '-', '.', '/')");
    }
  }

  // Path: at most one '/', and the action behind it must be non-empty.
  let authority = rest;
  let action = null;
  const slash = rest.indexOf('/');
  if (slash !== -1) {
    authority = rest.slice(0, slash);
    action = rest.slice(slash + 1);
    if (action === '') {
      throw fail(uri, "trailing '/' with empty action - action is a closed-set "
        + 'verb, not omissible by empty string (§10.2)');
    }
    if (action.includes('/')) {
      throw fail(uri, "second path segment - path is a single '/<action>' (§10.2)");
    }
  }

  // Authority: exactly three segments.
  const segments = authority.split('.');
  if (segments.length !== 3) {
    throw fail(uri, `authority has ${segments.length} segment(s), must be `
      + '<subject>.<organ>.<root> (RFC-009 §10.2)');
  }
  const [subject, organ, root] = segments;
  if (subject === '' || root === '') {
    throw fail(uri, 'authority segments must be non-empty (RFC-009 §10.2)');
  }

  // Subject: hash form (8/32/64 lowercase hex) or name form. Ordered choice
  // per the ABNF: all-lowerhex input is tried as hash-subject first; a
  // lowercase-hex string of another length is therefore a NAME subject,
  // exactly as the grammar says. Documented, not "fixed".
  let subjectIsHash = false;
  let subjectHex = null;
  if ([...subject].every((c) => LOWHEX.has(c)) && HASH_LENGTHS.includes(subject.length)) {
    subjectIsHash = true;
    subjectHex = subject;
  }

  // Organ — CLOSED set, case-sensitive (§10.1). 'Forge', 'forgery', '' all fail.
  if (!ORGANS.includes(organ)) {
    throw fail(uri, `organ ${JSON.stringify(organ)} is outside the closed set `
      + `[${ORGANS.join(', ')}] (RFC-009 §10.1/§10.3)`);
  }

  // Action — CLOSED set (§10.1). The deliberate difference from rttp.
  if (action !== null && !ACTIONS.includes(action)) {
    throw fail(uri, `action ${JSON.stringify(action)} is outside the closed set `
      + `[${ACTIONS.join(', ')}] (RFC-009 §10.1)`);
  }

  const canonicalUri = SCHEME + '://' + authority + (action ? '/' + action : '');

  return {
    scheme: SCHEME,
    subject,
    subject_is_hash: subjectIsHash,
    subject_hex: subjectHex,
    organ,
    root,
    authority,
    action,
    action_omitted: action === null,
    action_safe: SAFE.has(action),           // §11.3
    canonical_uri: canonicalUri,
    route_hex: deriveRouteHex(authority),    // SPEC §3
  };
}
