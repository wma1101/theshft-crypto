/**
 * Tests for the backup KDF + envelope upgrade — audit finding C-H2.
 *
 * Before this fix:
 *   - deriveBackupKey was sync, 10K iterated raw SHA-256, weak vs GPU brute force.
 *   - encryptBackup produced "backup_v1:" envelope.
 *
 * After this fix:
 *   - deriveBackupKey is async, PBKDF2-HMAC-SHA256 at OWASP 600K iterations.
 *   - encryptBackup produces "backup_v2:" envelope.
 *   - decryptBackup auto-detects v1 (legacy) vs v2, accepting `legacyOpts`
 *     so a user with a pre-fix backup can still restore.
 *
 * PBKDF2-600K is intentionally slow (~5s in JS / ~600ms native). Tests
 * derive each unique key ONCE in beforeAll and reuse to keep the suite
 * under a minute even with the slow JS fallback in jest-expo.
 */

const {
  deriveBackupKey,
  encryptBackup,
  decryptBackup,
} = require('../config/encryption');

const PASS_PRIMARY = 'correct-horse-battery-staple';
const PASS_OTHER = 'a different long backup passphrase';
const SALT_A = 'user_abc123';
const SALT_B = 'user_xyz';

describe('backup KDF (C-H2)', () => {
  let kPrimaryA;
  let kPrimaryA2;
  let kOtherA;
  let kPrimaryB;

  jest.setTimeout(180000);

  beforeAll(async () => {
    // Pre-derive every key the suite needs in parallel — one slow round
    // instead of N. PBKDF2 in the JS fallback is dominated by per-call
    // cost; Promise.all gives us the parallel-fanout speedup.
    [kPrimaryA, kPrimaryA2, kOtherA, kPrimaryB] = await Promise.all([
      deriveBackupKey(PASS_PRIMARY, SALT_A),
      deriveBackupKey(PASS_PRIMARY, SALT_A),
      deriveBackupKey(PASS_OTHER, SALT_A),
      deriveBackupKey(PASS_PRIMARY, SALT_B),
    ]);
  });

  test('returns a 32-byte Uint8Array', () => {
    expect(kPrimaryA).toBeInstanceOf(Uint8Array);
    expect(kPrimaryA.length).toBe(32);
  });

  test('is deterministic for the same (passphrase, salt)', () => {
    expect(Buffer.from(kPrimaryA).toString('hex')).toBe(
      Buffer.from(kPrimaryA2).toString('hex'),
    );
  });

  test('differs across salts (domain separation works)', () => {
    expect(Buffer.from(kPrimaryA).toString('hex')).not.toBe(
      Buffer.from(kPrimaryB).toString('hex'),
    );
  });

  test('differs across passphrases', () => {
    expect(Buffer.from(kPrimaryA).toString('hex')).not.toBe(
      Buffer.from(kOtherA).toString('hex'),
    );
  });

  test('rejects empty inputs (no derivation cost)', async () => {
    expect(await deriveBackupKey('', SALT_A)).toBeNull();
    expect(await deriveBackupKey(PASS_PRIMARY, '')).toBeNull();
    expect(await deriveBackupKey(null, SALT_A)).toBeNull();
    expect(await deriveBackupKey(PASS_PRIMARY, null)).toBeNull();
  });
});

describe('backup envelope v2 (C-H2)', () => {
  const payload = JSON.stringify({ sessions: { foo: 'bar' }, version: 1 });
  let key;
  let wrongKey;

  jest.setTimeout(180000);

  beforeAll(async () => {
    [key, wrongKey] = await Promise.all([
      deriveBackupKey(PASS_PRIMARY, SALT_A),
      deriveBackupKey(PASS_OTHER, SALT_A),
    ]);
  });

  test('encryptBackup produces a backup_v2: envelope (not v1)', () => {
    const encrypted = encryptBackup(payload, key);
    expect(encrypted).toMatch(/^backup_v2:/);
    expect(encrypted).not.toMatch(/^backup_v1:/);
  });

  test('v2 round-trips with the same key', async () => {
    const encrypted = encryptBackup(payload, key);
    const decrypted = await decryptBackup(encrypted, key);
    expect(decrypted).toBe(payload);
  });

  test('v2 decryption returns null with the wrong key', async () => {
    const encrypted = encryptBackup(payload, key);
    const result = await decryptBackup(encrypted, wrongKey);
    expect(result).toBeNull();
  });

  test('v2 ciphertexts differ across encrypt calls (random nonce)', () => {
    const e1 = encryptBackup(payload, key);
    const e2 = encryptBackup(payload, key);
    expect(e1).not.toBe(e2);
  });

  test('decryptBackup returns null for unknown envelope prefix', async () => {
    expect(await decryptBackup('garbage_data', key)).toBeNull();
    expect(await decryptBackup('backup_v9:abc:def', key)).toBeNull();
    expect(await decryptBackup(null, key)).toBeNull();
  });
});

describe('backup v1 legacy decrypt path (C-H2 restore compat)', () => {
  // Synthesize a v1 envelope using the same construction the pre-fix code
  // used, then assert decryptBackup can still read it when legacyOpts are
  // provided. Safety net for users with a pre-fix backup.
  const PASS_LEGACY = 'legacy backup passphrase';
  const SALT_LEGACY = 'user_legacy';
  const payload = JSON.stringify({ legacy: true });

  // Node's built-in sha256 for the test-only legacy envelope construction
  // (production code uses the in-module sha256 which isn't exported).
  const nodeCrypto = require('crypto');
  const sha256 = (s) => nodeCrypto.createHash('sha256').update(s).digest('hex');
  const nacl = require('tweetnacl');
  const { decodeUTF8, encodeBase64 } = require('tweetnacl-util');

  let v2KeyMatching;
  let v1Envelope;

  jest.setTimeout(180000);

  beforeAll(async () => {
    v2KeyMatching = await deriveBackupKey(PASS_LEGACY, SALT_LEGACY);
    // Build a v1 envelope the way pre-fix code did
    let derived = sha256(PASS_LEGACY + SALT_LEGACY + 'theshft_backup_v1');
    for (let i = 0; i < 10000; i++) {
      derived = sha256(derived + String(i));
    }
    const legacyKey = new Uint8Array(32);
    for (let i = 0; i < 32; i++) {
      legacyKey[i] = parseInt(derived.substring(i * 2, i * 2 + 2), 16);
    }
    const nonce = nacl.randomBytes(nacl.secretbox.nonceLength);
    const ciphertext = nacl.secretbox(decodeUTF8(payload), nonce, legacyKey);
    v1Envelope = 'backup_v1:' + encodeBase64(nonce) + ':' + encodeBase64(ciphertext);
  });

  test('v1 envelope decrypts when legacyOpts.{passphrase,salt} are provided', async () => {
    const decrypted = await decryptBackup(v1Envelope, v2KeyMatching, {
      passphrase: PASS_LEGACY,
      salt: SALT_LEGACY,
    });
    expect(decrypted).toBe(payload);
  });

  test('v1 envelope returns null when legacyOpts are missing', async () => {
    expect(await decryptBackup(v1Envelope, v2KeyMatching)).toBeNull();
    expect(await decryptBackup(v1Envelope, v2KeyMatching, {})).toBeNull();
    expect(await decryptBackup(v1Envelope, v2KeyMatching, { passphrase: PASS_LEGACY })).toBeNull();
  });

  test('v1 envelope returns null when the legacy passphrase is wrong', async () => {
    const result = await decryptBackup(v1Envelope, v2KeyMatching, {
      passphrase: 'wrong',
      salt: SALT_LEGACY,
    });
    expect(result).toBeNull();
  });
});
