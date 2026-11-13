import { test } from 'node:test';
import assert from 'node:assert/strict';
import { randomBytes } from 'node:crypto';
import { loadKeyring, encryptMedical, decryptMedical, rotateMedical } from '../server/medical-crypto.ts';

const k1 = randomBytes(32).toString('base64');
const k2 = randomBytes(32).toString('base64');
const info = { allergies: 'Penicillin', bloodType: 'O-', medication: 'Salbutamol inhaler' };
const bob = '0b0b0b0b-0000-0000-0000-000000000001';
const eve = '0e0e0e0e-0000-0000-0000-000000000002';

test('round-trips and never contains plaintext', () => {
  const ring = loadKeyring(`1:${k1}`);
  const { ciphertext, keyVersion } = encryptMedical(ring, bob, info);
  assert.equal(keyVersion, 1);
  assert.match(ciphertext, /^v1\./);
  assert.ok(!ciphertext.includes('Penicillin'));
  assert.deepEqual(decryptMedical(ring, bob, ciphertext), info);
});

test('same data encrypts differently each time (random IV)', () => {
  const ring = loadKeyring(`1:${k1}`);
  assert.notEqual(encryptMedical(ring, bob, info).ciphertext, encryptMedical(ring, bob, info).ciphertext);
});

test('ciphertext moved to another member fails to decrypt', () => {
  const ring = loadKeyring(`1:${k1}`);
  const { ciphertext } = encryptMedical(ring, bob, info);
  assert.throws(() => decryptMedical(ring, eve, ciphertext));
});

test('tampering is detected', () => {
  const ring = loadKeyring(`1:${k1}`);
  const { ciphertext } = encryptMedical(ring, bob, info);
  const parts = ciphertext.split('.');
  const data = Buffer.from(parts[3], 'base64url'); data[0] ^= 1;
  parts[3] = data.toString('base64url');
  assert.throws(() => decryptMedical(ring, bob, parts.join('.')));
});

test('key rotation re-encrypts under the newest key; old key still reads old data', () => {
  const old = encryptMedical(loadKeyring(`1:${k1}`), bob, info).ciphertext;
  const ring = loadKeyring(`1:${k1},2:${k2}`);
  const rotated = rotateMedical(ring, bob, old);
  assert.ok(rotated && rotated.keyVersion === 2 && rotated.ciphertext.startsWith('v2.'));
  assert.deepEqual(decryptMedical(ring, bob, rotated!.ciphertext), info);
  assert.equal(rotateMedical(ring, bob, rotated!.ciphertext), null);
  assert.throws(() => decryptMedical(loadKeyring(`2:${k2}`), bob, old), /key version 1/);
});

test('rejects weak keys', () => {
  assert.throws(() => loadKeyring(`1:${randomBytes(16).toString('base64')}`));
});
