import test from 'node:test';
import assert from 'node:assert/strict';
import { readFileSync } from 'node:fs';
import {
  SIZE, MAGIC, STANDING_CODES, STANDING_NAMES, EnvelopeError,
  deriveIntentShard, encode, parse, verify,
  VECTOR_1_KEY, VECTOR_1_LEASE, VECTOR_1_FRAME_HEX, vector1Frame,
} from '../src/envelope.mjs';

const GOOD = {
  key: VECTOR_1_KEY,
  intent_shard: deriveIntentShard('f3b2a1c4.pillar.example'),
  organ: 'ORG-TEST',
  standing: 'radiant',
  lease_expiry: VECTOR_1_LEASE,
  nonce: 1,
};

test('AE128-VECTOR-1 reproduces byte for byte from the documented parameters', () => {
  assert.equal(Buffer.from(vector1Frame()).toString('hex'), VECTOR_1_FRAME_HEX);
  assert.equal(vector1Frame().length, SIZE);
});

test('AE128-VECTOR-1 verifies before lease expiry', () => {
  const r = verify(vector1Frame(), VECTOR_1_KEY, { now: VECTOR_1_LEASE - 1 });
  assert.equal(r.ok, true, r.reason);
  assert.equal(r.frame.standing_name, 'radiant');
});

test('lease boundary is inclusive (valid until)', () => {
  const r = verify(vector1Frame(), VECTOR_1_KEY, { now: VECTOR_1_LEASE });
  assert.equal(r.ok, true, r.reason);
});

test('AE128-VECTOR-1 rejects after lease expiry; archival mode accepts', () => {
  const bad = verify(vector1Frame(), VECTOR_1_KEY, { now: VECTOR_1_LEASE + 1 });
  assert.equal(bad.ok, false);
  assert.match(bad.reason, /expired/);
  const arch = verify(vector1Frame(), VECTOR_1_KEY,
    { now: VECTOR_1_LEASE + 100, check_lease: false });
  assert.equal(arch.ok, true, arch.reason);
});

test('parse reports the documented fields', () => {
  const p = parse(vector1Frame());
  assert.equal(p.organ, 'ORG-TEST');
  assert.equal(p.standing, 0x02);
  assert.equal(p.standing_name, 'radiant');
  assert.equal(p.nonce, 1);
  assert.equal(p.lease_expiry, VECTOR_1_LEASE);
  assert.equal(p.version, 1);
  assert.equal(p.algorithm, 1);
  assert.equal(p.flags, 0);
  assert.equal(Buffer.from(p.intent_shard).toString('hex'),
    '557c8154d3780cb78cc5fa1bd72b331c');
});

test('deriveIntentShard is the I-D sec. 4.4 derivation', () => {
  assert.equal(deriveIntentShard('f3b2a1c4.pillar.example').toString('hex'),
    '557c8154d3780cb78cc5fa1bd72b331c');
});

test('encode is deterministic', () => {
  assert.deepEqual(encode(GOOD), encode(GOOD));
  assert.deepEqual(vector1Frame(), encode(GOOD));
});

test('standing accepts the name and the wire code identically', () => {
  const byName = encode({ ...GOOD, standing: 'radiant' });
  const byCode = encode({ ...GOOD, standing: 0x02 });
  assert.deepEqual(byName, byCode);
  assert.deepEqual(byName, vector1Frame());
  assert.equal(STANDING_CODES.radiant, 0x02);
  assert.equal(STANDING_NAMES[0x03], 'genesis');
});

test('standing outside the closed set is rejected', () => {
  assert.throws(() => encode({ ...GOOD, standing: 0x04 }), EnvelopeError);
  assert.throws(() => encode({ ...GOOD, standing: 'ascendant' }), EnvelopeError);
});

test('structural rejects -- parse must raise, never normalise', () => {
  assert.throws(() => parse(Buffer.alloc(SIZE - 1)), EnvelopeError);           // length 127
  assert.throws(() => parse(Buffer.alloc(SIZE + 1)), EnvelopeError);           // length 129
  assert.throws(() => parse(Buffer.from('RTTP' + vector1Frame().toString('hex').slice(8), 'hex')), EnvelopeError); // pulse-frame magic
  const v2 = Buffer.from(vector1Frame()); v2[4] = 2;
  assert.throws(() => parse(v2), EnvelopeError);                               // version 2
  const a0 = Buffer.from(vector1Frame()); a0[5] = 0;
  assert.throws(() => parse(a0), EnvelopeError);                               // algorithm 0x00
  const a2 = Buffer.from(vector1Frame()); a2[5] = 2;
  assert.throws(() => parse(a2), EnvelopeError);                               // algorithm 0x02
  const fl = Buffer.from(vector1Frame()); fl[6] = 1;
  assert.throws(() => parse(fl), EnvelopeError);                               // flags 0x0001
  const st = Buffer.from(vector1Frame()); st[80] = 4;
  assert.throws(() => parse(st), EnvelopeError);                               // standing 0x04
  const rs = Buffer.from(vector1Frame()); rs[85] = 1;
  assert.throws(() => parse(rs), EnvelopeError);                               // reserved nonzero
  const ex = Buffer.from(vector1Frame()); ex[100] = 1;
  assert.throws(() => parse(ex), EnvelopeError);                               // extension nonzero
  const og = Buffer.from(vector1Frame()); og[64] = 0xFF;
  assert.throws(() => parse(og), EnvelopeError);                               // organ non-ASCII
});

test('tamper matrix -- the HMAC covers the WHOLE frame', () => {
  const fails = (label, mutate) => {
    const raw = Buffer.from(vector1Frame());
    mutate(raw);
    const r = verify(raw, VECTOR_1_KEY, { now: VECTOR_1_LEASE - 1 });
    assert.equal(r.ok, false, label + ' was accepted');
  };
  fails('one attestation bit flipped', (f) => { f[32] ^= 0x01; });
  fails('organ tag altered (ORG-TESU)', (f) => { f[71] = 0x55; });
  fails('nonce altered', (f) => { f[79] = 2; });
  fails('standing flipped radiant -> genesis', (f) => { f[80] = 3; });
  fails('lease_expiry altered', (f) => { f[15] = 0x81; });
  fails('intent_shard swapped for another subject', (f) => {
    Buffer.from(Array.from({ length: 16 }, (_, i) => i)).copy(f, 16);
  });
  fails('attestation from a different key', (f) => {
    const other = encode({
      key: Buffer.from('a different organ key material!!', 'ascii'),
      intent_shard: f.subarray(16, 32), organ: 'ORG-TEST', standing: 2,
      lease_expiry: VECTOR_1_LEASE, nonce: 1,
    });
    other.subarray(32, 64).copy(f, 32);
  });
});

test('the shipped AE-128 vector file replays end to end', () => {
  const ae = JSON.parse(
    readFileSync(new URL('../src/ae128-vectors-v1.json', import.meta.url), 'utf8'));
  assert.equal(ae.positive_frame_hex, VECTOR_1_FRAME_HEX);

  const accepted = ae.negative_frames
    .filter((n) => { try { parse(Buffer.from(n.frame_hex, 'hex')); return true; } catch { return false; } });
  assert.deepEqual(accepted, [],
    `negative frames accepted: ${accepted.map((n) => n.name).join(', ')}`);

  const verified = ae.tampered_frames
    .filter((n) => verify(Buffer.from(n.frame_hex, 'hex'), VECTOR_1_KEY,
      { now: VECTOR_1_LEASE - 1 }).ok);
  assert.deepEqual(verified, [],
    `tampered frames verified: ${verified.map((n) => n.name).join(', ')}`);
});
