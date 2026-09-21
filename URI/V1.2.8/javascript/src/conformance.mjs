// IQA conformance replay -- an INDEPENDENT implementation of RFC-009 sec. 10.
//
// This file is written from RFC-009 sec. 10/sec. 11 alone and MUST NEVER import
// ./iqa-uri.mjs. A conformance suite that reuses the code under test only
// proves the code equals itself. The two files share no code, so the rule is
// checkable by reading them.
//
// They ship together for the same reason the Python wheel ships its self-test:
// so a stranger can verify an installed package offline, with no repository
// checkout. Zero dependencies -- node:crypto and node:fs only.

import { createHash, createPublicKey, verify as cryptoVerify } from 'node:crypto';
import { readFileSync } from 'node:fs';
import { fileURLToPath } from 'node:url';
import { dirname, join } from 'node:path';

const DOMAIN = Buffer.from('iqa-attest-v1\n', 'utf8');

// ---------------------------------------------------------------------------
// Independent parse -- single full-match grammar check, deliberately different
// in structure from the streaming charset scanner in iqa-uri.mjs.
// ---------------------------------------------------------------------------

// authority = subject "." organ "." root ; subject/organ/root over [a-z0-9-]
// (the "." split is done by the regex groups, so empty segments fail);
// path = "/" action at most once; every matched char is lowercase US-ASCII,
// so uppercase, '@', ':', '?', '#', whitespace and all foreign bytes fail.
const GRAMMAR = /^iqa:\/\/([a-z0-9-]+)\.([a-z0-9-]+)\.([a-z0-9-]+)(?:\/([a-z0-9-]+))?$/;

const ORGANS = ['forge', 'tss', 'gateway'];         // sec. 10.1 closed set
const ACTIONS = ['verify', 'audit', 'attest', 'revoke']; // sec. 10.1 closed set
const HASH_LENGTHS = [8, 32, 64];                   // sec. 10.2 hash-subject

export function parseUri(uri) {
  const m = GRAMMAR.exec(uri);
  if (!m) {
    throw new Error(`REJECT (grammar/full-match): ${JSON.stringify(uri)}`);
  }
  const [, subject, organ, root, action = null] = m;

  if (!ORGANS.includes(organ)) {
    throw new Error(`REJECT (organ closed set): ${JSON.stringify(uri)}`);
  }
  if (action !== null && !ACTIONS.includes(action)) {
    throw new Error(`REJECT (action closed set): ${JSON.stringify(uri)}`);
  }

  const isAllLowerHex = /^[0-9a-f]+$/.test(subject);
  const subjectIsHash = isAllLowerHex && HASH_LENGTHS.includes(subject.length);

  return {
    scheme: 'iqa',
    subject,
    subject_is_hash: subjectIsHash,
    subject_hex: subjectIsHash ? subject : null,
    organ,
    root,
    authority: `${subject}.${organ}.${root}`,
    action,
    action_omitted: action === null,
    action_safe: action === null || action === 'verify', // sec. 11.3
    canonical_uri: 'iqa://' + `${subject}.${organ}.${root}` + (action ? '/' + action : ''),
    route_hex: createHash('sha256').update(`${subject}.${organ}.${root}`, 'ascii')
      .digest().subarray(0, 4).toString('hex'),
  };
}

// ---------------------------------------------------------------------------
// Envelope -- canonical JSON + Ed25519 over the domain-separated input.
// ---------------------------------------------------------------------------

function canonicalize(value) {
  if (value === null || typeof value !== 'object') return JSON.stringify(value);
  if (Array.isArray(value)) return '[' + value.map(canonicalize).join(',') + ']';
  const keys = Object.keys(value).sort();
  return '{' + keys.map((k) => JSON.stringify(k) + ':' + canonicalize(value[k])).join(',') + '}';
}

export function buildSigningInput(env) {
  const body = canonicalize({
    alg: 'ed25519',
    aid: env.aid,
    nonce: env.nonce,
    payload: env.payload,
    pub: env.pub,
    ts: env.ts,
  });
  return Buffer.concat([DOMAIN, Buffer.from(body, 'utf8')]);
}

function verifyEnvelope(env) {
  const input = buildSigningInput(env);
  if (input.toString('hex') !== env.signing_input_hex) {
    throw new Error('envelope :: signing input mismatch');
  }
  const aid = createHash('sha256').update(Buffer.from(env.pub, 'hex')).digest('hex');
  if (aid !== env.aid) {
    throw new Error('envelope :: aid != SHA-256(pub)');
  }
  // Wrap the raw 32-byte key in the fixed Ed25519 SPKI DER prefix.
  const spki = Buffer.concat([
    Buffer.from('302a300506032b6570032100', 'hex'),
    Buffer.from(env.pub, 'hex'),
  ]);
  const key = createPublicKey({ key: spki, format: 'der', type: 'spki' });
  const ok = cryptoVerify(null, input, key, Buffer.from(env.sig, 'hex'));
  if (!ok) throw new Error('envelope :: Ed25519 verification failed');
}

// ---------------------------------------------------------------------------
// Runner
// ---------------------------------------------------------------------------

const DEFAULT_VECTORS_PATH = join(dirname(fileURLToPath(import.meta.url)), 'vectors.json');

export { DEFAULT_VECTORS_PATH };

export function loadVectors(path = DEFAULT_VECTORS_PATH) {
  return JSON.parse(readFileSync(path, 'utf8'));
}

/**
 * Replay a vector set -> { checked, failures, passed }.
 * The checker accepts any object with the documented groups, so a different
 * vector set (e.g. a candidate next revision) can be replayed the same way.
 */
export function runConformance(vectors) {
  const failures = [];
  let checked = 0;

  for (const c of vectors.positive_uris ?? []) {
    checked += 1;
    try {
      const got = parseUri(c.uri);
      for (const key of ['canonical_uri', 'subject_is_hash', 'organ', 'root',
        'authority', 'action', 'action_omitted', 'action_safe', 'route_hex']) {
        if (got[key] !== c[key]) {
          failures.push(`${c.uri} :: ${key} ${JSON.stringify(c[key])} != ${JSON.stringify(got[key])}`);
        }
      }
    } catch (err) {
      failures.push(`${c.uri} :: expected ACCEPT but rejected (${err.message})`);
    }
  }

  for (const c of vectors.negative_uris ?? []) {
    checked += 1;
    try {
      parseUri(c.uri);
      failures.push(`${c.uri} :: expected REJECT but parsed`);
    } catch {
      // required behaviour
    }
  }

  for (const row of vectors.action_safety ?? []) {
    checked += 1;
    const uri = row.action === null
      ? 'iqa://3f9a1b2c.gateway.iqa'
      : `iqa://3f9a1b2c.gateway.iqa/${row.action}`;
    try {
      const got = parseUri(uri).action_safe;
      if (got !== row.safe) {
        failures.push(`action_safety ${row.action} :: expected ${row.safe} got ${got}`);
      }
    } catch (err) {
      failures.push(`action_safety ${row.action} :: expected ACCEPT but rejected (${err.message})`);
    }
  }

  if (vectors.attest_envelope_vector) {
    checked += 1;
    try {
      verifyEnvelope(vectors.attest_envelope_vector);
    } catch (err) {
      failures.push(err.message);
    }
  }

  return { checked, failures, passed: checked - failures.length };
}
