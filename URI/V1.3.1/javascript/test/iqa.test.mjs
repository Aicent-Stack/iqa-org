import test from 'node:test';
import assert from 'node:assert/strict';
import { parse, deriveRouteHex, isValidAction, IqaUriError } from '../src/iqa-uri.mjs';
import { runConformance, loadVectors } from '../src/conformance.mjs';

test('parses the sec. 10.3 examples with the pinned routes', () => {
  const r = parse('iqa://3f9a1b2c.gateway.iqa');
  assert.equal(r.subject, '3f9a1b2c');
  assert.equal(r.subject_is_hash, true);
  assert.equal(r.organ, 'gateway');
  assert.equal(r.action, null);
  assert.equal(r.action_omitted, true);
  assert.equal(r.action_safe, true);
  assert.equal(r.route_hex, '5c378581');
  assert.equal(r.canonical_uri, 'iqa://3f9a1b2c.gateway.iqa');
});

test('classifies the 256-bit AID form', () => {
  const r = parse('iqa://0000004149434e531c5b21d80403358ba794ef228ca5253994959ef6f3ff5678.tss.iqa/attest');
  assert.equal(r.subject_is_hash, true);
  assert.equal(r.subject_hex, '0000004149434e531c5b21d80403358ba794ef228ca5253994959ef6f3ff5678');
  assert.equal(r.action_safe, false); // attest is NOT SAFE (sec. 11.3)
});

test('9 hex digits is a name subject, not a hash (ABNF ordered choice)', () => {
  const r = parse('iqa://3f9a1b2cd.gateway.iqa/verify');
  assert.equal(r.subject_is_hash, false);
  assert.equal(r.subject_hex, null);
});

test('rejects the closed-set violations', () => {
  assert.throws(() => parse('iqa://3f9a1b2c.forgery.iqa'), IqaUriError);
  assert.throws(() => parse('iqa://3f9a1b2c.gateway.iqa/pulse'), IqaUriError);
  assert.throws(() => parse('iqas://3f9a1b2c.gateway.iqa/audit'), IqaUriError);
  assert.throws(() => parse('iqa://3f9a1b2c.gateway.iqa/AUDIT'), IqaUriError);
  assert.throws(() => parse('iqa://subject@iqa.org'), IqaUriError);
});

test('deriveRouteHex matches the vector-pinned values', () => {
  assert.equal(deriveRouteHex('3f9a1b2c.gateway.iqa'), '5c378581');
  assert.equal(deriveRouteHex('master-authority.gateway.iqa'), '510ef099');
});

test('isValidAction is the closed set', () => {
  for (const v of ['verify', 'audit', 'attest', 'revoke']) assert.equal(isValidAction(v), true);
  for (const v of ['pulse', 'AUDIT', '', 'get']) assert.equal(isValidAction(v), false);
});

test('replays the shipped conformance vectors end to end', () => {
  const r = runConformance(loadVectors());
  assert.equal(r.failures.length, 0, r.failures.join('\n'));
  assert.ok(r.checked >= 32);
  assert.equal(r.checked, r.passed);
});
