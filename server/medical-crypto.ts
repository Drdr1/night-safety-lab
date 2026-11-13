// Field-level encryption for medical information.
//
// AES-256-GCM with a versioned keyring held outside the database
// (env var / secret manager). The member id is bound in as additional
// authenticated data, so a ciphertext copied onto another member's row
// fails to decrypt instead of showing the wrong person's medical data.
//
// Format: v<version>.<iv>.<tag>.<ciphertext>   (base64url parts)

import { createCipheriv, createDecipheriv, randomBytes } from 'node:crypto';

export interface MedicalInfo {
  allergies?: string;
  medication?: string;
  conditions?: string;
  bloodType?: string;
  insurance?: string;
}

export type Keyring = Map<number, Buffer>;

/** Parses MEDICAL_KEYS="1:<base64 32 bytes>,2:<base64 32 bytes>". Highest version encrypts. */
export function loadKeyring(spec: string): Keyring {
  const ring: Keyring = new Map();
  for (const part of spec.split(',').map((s) => s.trim()).filter(Boolean)) {
    const [v, b64] = part.split(':');
    const key = Buffer.from(b64 ?? '', 'base64');
    if (!/^\d+$/.test(v ?? '') || key.length !== 32) throw new Error(`invalid key entry for version "${v}"`);
    ring.set(Number(v), key);
  }
  if (ring.size === 0) throw new Error('MEDICAL_KEYS is empty');
  return ring;
}

export function currentVersion(ring: Keyring): number {
  return Math.max(...ring.keys());
}

export function encryptMedical(ring: Keyring, memberId: string, info: MedicalInfo): { ciphertext: string; keyVersion: number } {
  const version = currentVersion(ring);
  const iv = randomBytes(12);
  const cipher = createCipheriv('aes-256-gcm', ring.get(version)!, iv);
  cipher.setAAD(Buffer.from(memberId));
  const data = Buffer.concat([cipher.update(JSON.stringify(info), 'utf8'), cipher.final()]);
  const tag = cipher.getAuthTag();
  const b = (x: Buffer) => x.toString('base64url');
  return { ciphertext: `v${version}.${b(iv)}.${b(tag)}.${b(data)}`, keyVersion: version };
}

export function decryptMedical(ring: Keyring, memberId: string, ciphertext: string): MedicalInfo {
  const m = /^v(\d+)\.([\w-]+)\.([\w-]+)\.([\w-]*)$/.exec(ciphertext);
  if (!m) throw new Error('malformed ciphertext');
  const key = ring.get(Number(m[1]));
  if (!key) throw new Error(`key version ${m[1]} not available`);
  const decipher = createDecipheriv('aes-256-gcm', key, Buffer.from(m[2], 'base64url'));
  decipher.setAAD(Buffer.from(memberId));
  decipher.setAuthTag(Buffer.from(m[3], 'base64url'));
  const plain = Buffer.concat([decipher.update(Buffer.from(m[4], 'base64url')), decipher.final()]);
  return JSON.parse(plain.toString('utf8')) as MedicalInfo;
}

/** Key rotation: re-encrypt under the newest key. Returns null if already current. */
export function rotateMedical(ring: Keyring, memberId: string, ciphertext: string) {
  if (ciphertext.startsWith(`v${currentVersion(ring)}.`)) return null;
  return encryptMedical(ring, memberId, decryptMedical(ring, memberId, ciphertext));
}
