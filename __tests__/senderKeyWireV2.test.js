/**
 * KAN-21 / C-D — epoch-aware Sender Key message wire codec (v1 `skey:` ↔ v2
 * `skey2:<epoch>:`).
 *
 * The safety guarantee (DECISION 1): with the v2 flag OFF, encodeSenderKeyMessage
 * is BYTE-IDENTICAL to legacy encryptWithSenderKey — an old in-field client reads
 * it exactly as today. The crypto is interchangeable: a body encrypted under key K
 * decodes the same whether framed v1 or v2; only the leading prefix differs and
 * the epoch is an unauthenticated advisory hint. Dual-read is ALWAYS on (never
 * flag-gated), so a v2 message from an early adopter is readable regardless.
 */

const nacl = require('tweetnacl');
const {
  generateSenderKey,
  encryptWithSenderKey,
  decryptWithSenderKey,
  decryptWithKeyChain,
  encodeSenderKeyMessage,
  decodeSenderKeyMessage,
  decodeSenderKeyMessageChain,
  parseSenderKeyEpoch,
} = require('../config/encryption');

describe('senderKeyWireV2 — parseSenderKeyEpoch', () => {
  test('returns the integer epoch for a v2 message', () => {
    const sk = generateSenderKey();
    const v2 = encodeSenderKeyMessage('hi', sk.key, sk.keyId, { epoch: 42, wireV2: true });
    expect(v2.startsWith('skey2:42:')).toBe(true);
    expect(parseSenderKeyEpoch(v2)).toBe(42);
  });

  test('epoch 0 is a valid v2 epoch (not confused with null)', () => {
    const sk = generateSenderKey();
    const v2 = encodeSenderKeyMessage('hi', sk.key, sk.keyId, { epoch: 0, wireV2: true });
    expect(parseSenderKeyEpoch(v2)).toBe(0);
  });

  test('returns null for legacy v1 (epoch unknown)', () => {
    const sk = generateSenderKey();
    const v1 = encryptWithSenderKey('hi', sk.key, sk.keyId);
    expect(parseSenderKeyEpoch(v1)).toBeNull();
  });

  test('returns null (never throws) for malformed / non-integer / non-sender-key input', () => {
    expect(parseSenderKeyEpoch(null)).toBeNull();
    expect(parseSenderKeyEpoch(undefined)).toBeNull();
    expect(parseSenderKeyEpoch('')).toBeNull();
    expect(parseSenderKeyEpoch('skey2:')).toBeNull();
    expect(parseSenderKeyEpoch('skey2:abc:id:n:c')).toBeNull(); // non-integer epoch
    expect(parseSenderKeyEpoch('skey2:-1:id:n:c')).toBeNull(); // negative
    expect(parseSenderKeyEpoch('skey2:1.5:id:n:c')).toBeNull(); // float
    expect(parseSenderKeyEpoch('skey2:5')).toBeNull(); // too few segments
    expect(parseSenderKeyEpoch('something-else')).toBeNull();
  });
});

describe('senderKeyWireV2 — encode write-gate (DECISION 1)', () => {
  test('flag OFF (no opts) ⇒ legacy skey: framing, decodable by the v1 reader', () => {
    const sk = generateSenderKey();
    const out = encodeSenderKeyMessage('payload', sk.key, sk.keyId);
    expect(out.startsWith('skey:')).toBe(true);
    expect(out.startsWith('skey2:')).toBe(false);
    // The legacy v1 reader decodes it.
    expect(decryptWithSenderKey(out, sk.key)).toBe('payload');
  });

  test('flag OFF byte-shape matches encryptWithSenderKey (same prefix/keyId/segment count)', () => {
    const sk = generateSenderKey();
    const fromNew = encodeSenderKeyMessage('payload', sk.key, sk.keyId, { wireV2: false, epoch: 9 });
    const fromLegacy = encryptWithSenderKey('payload', sk.key, sk.keyId);
    // Random nonce ⇒ ciphertext differs, but the FRAMING must be identical: same
    // prefix, same keyId field, same number of `:`-separated segments.
    const a = fromNew.split(':');
    const b = fromLegacy.split(':');
    expect(a[0]).toBe('skey');
    expect(b[0]).toBe('skey');
    expect(a.length).toBe(b.length); // 4 segments: skey,keyId,nonce,ct
    expect(a[1]).toBe(sk.keyId); // keyId preserved in field 1
    expect(b[1]).toBe(sk.keyId);
    // And it round-trips under the v1 reader (the in-field-old-client guarantee).
    expect(decryptWithSenderKey(fromNew, sk.key)).toBe('payload');
  });

  test('flag ON with a valid epoch ⇒ skey2:<epoch>: framing', () => {
    const sk = generateSenderKey();
    const out = encodeSenderKeyMessage('payload', sk.key, sk.keyId, { epoch: 5, wireV2: true });
    expect(out.startsWith('skey2:5:')).toBe(true);
    const parts = out.split(':');
    expect(parts[0]).toBe('skey2');
    expect(parts[1]).toBe('5');
    expect(parts[2]).toBe(sk.keyId);
    expect(parts.length).toBe(5);
  });

  test('flag ON but epoch missing/invalid ⇒ falls back to legacy v1 (no half-formed v2)', () => {
    const sk = generateSenderKey();
    expect(encodeSenderKeyMessage('p', sk.key, sk.keyId, { wireV2: true }).startsWith('skey:')).toBe(true);
    expect(encodeSenderKeyMessage('p', sk.key, sk.keyId, { wireV2: true, epoch: -1 }).startsWith('skey:')).toBe(true);
    expect(encodeSenderKeyMessage('p', sk.key, sk.keyId, { wireV2: true, epoch: 1.5 }).startsWith('skey:')).toBe(true);
    expect(encodeSenderKeyMessage('p', sk.key, sk.keyId, { wireV2: true, epoch: '3' }).startsWith('skey:')).toBe(true);
  });
});

describe('senderKeyWireV2 — decodeSenderKeyMessage dual-read', () => {
  test('round-trips a v1 message', () => {
    const sk = generateSenderKey();
    const v1 = encryptWithSenderKey('hello v1', sk.key, sk.keyId);
    expect(decodeSenderKeyMessage(v1, sk.key)).toBe('hello v1');
  });

  test('round-trips a v2 message', () => {
    const sk = generateSenderKey();
    const v2 = encodeSenderKeyMessage('hello v2', sk.key, sk.keyId, { epoch: 11, wireV2: true });
    expect(decodeSenderKeyMessage(v2, sk.key)).toBe('hello v2');
  });

  test('v1 and v2 decode IDENTICALLY under decodeSenderKeyMessage vs the legacy reader', () => {
    const sk = generateSenderKey();
    const v1 = encryptWithSenderKey('same body', sk.key, sk.keyId);
    expect(decodeSenderKeyMessage(v1, sk.key)).toBe(decryptWithSenderKey(v1, sk.key));
  });

  test('a body is INTERCHANGEABLE across framings: same key opens v1 and v2 of the same plaintext', () => {
    const sk = generateSenderKey();
    const v1 = encryptWithSenderKey('interchangeable', sk.key, sk.keyId);
    const v2 = encodeSenderKeyMessage('interchangeable', sk.key, sk.keyId, { epoch: 3, wireV2: true });
    expect(decodeSenderKeyMessage(v1, sk.key)).toBe('interchangeable');
    expect(decodeSenderKeyMessage(v2, sk.key)).toBe('interchangeable');
  });

  test('wrong key ⇒ null for both framings; other prefixes ⇒ null', () => {
    const sk = generateSenderKey();
    const other = generateSenderKey();
    const v1 = encryptWithSenderKey('x', sk.key, sk.keyId);
    const v2 = encodeSenderKeyMessage('x', sk.key, sk.keyId, { epoch: 1, wireV2: true });
    expect(decodeSenderKeyMessage(v1, other.key)).toBeNull();
    expect(decodeSenderKeyMessage(v2, other.key)).toBeNull();
    expect(decodeSenderKeyMessage('naclp:a:b', sk.key)).toBeNull();
    expect(decodeSenderKeyMessage('pqsk1:a:b:c', sk.key)).toBeNull();
  });

  test('malformed skey2 returns null, never throws', () => {
    const sk = generateSenderKey();
    expect(decodeSenderKeyMessage('skey2:1', sk.key)).toBeNull();
    expect(decodeSenderKeyMessage('skey2:1:id', sk.key)).toBeNull();
    expect(decodeSenderKeyMessage('skey2:1:id:not-base64-!!!:also', sk.key)).toBeNull();
    expect(decodeSenderKeyMessage('skey2:', sk.key)).toBeNull();
    expect(decodeSenderKeyMessage(null, sk.key)).toBeNull();
    expect(decodeSenderKeyMessage('skey2:1:id:n:c', null)).toBeNull();
  });
});

describe('senderKeyWireV2 — decodeSenderKeyMessageChain (archive ring, both versions)', () => {
  test('reads a v1 message via the archived key', () => {
    const sk = generateSenderKey();
    const archived = [{ key: sk.key, keyId: sk.keyId }];
    const v1 = encryptWithSenderKey('archived v1', sk.key, sk.keyId);
    expect(decodeSenderKeyMessageChain(v1, archived)).toBe('archived v1');
    // Equivalent to the legacy chain for v1.
    expect(decodeSenderKeyMessageChain(v1, archived)).toBe(decryptWithKeyChain(v1, archived));
  });

  test('reads a v2 message via the archived key (fast keyId match)', () => {
    const sk = generateSenderKey();
    const archived = [{ key: sk.key, keyId: sk.keyId }];
    const v2 = encodeSenderKeyMessage('archived v2', sk.key, sk.keyId, { epoch: 4, wireV2: true });
    expect(decodeSenderKeyMessageChain(v2, archived)).toBe('archived v2');
  });

  test('reads a v2 message by FALLBACK when the embedded keyId does not match the chain', () => {
    const sk = generateSenderKey();
    // Archive entry has the right KEY but a mismatched keyId label (e.g. collision /
    // relabel) — the fallback "try every key" must still recover the plaintext.
    const archived = [{ key: sk.key, keyId: 'unrelated-id' }];
    const v2 = encodeSenderKeyMessage('fallback v2', sk.key, sk.keyId, { epoch: 8, wireV2: true });
    expect(decodeSenderKeyMessageChain(v2, archived)).toBe('fallback v2');
  });

  test('pre-rotation history under EITHER version stays readable across a multi-key ring', () => {
    const old1 = generateSenderKey();
    const old2 = generateSenderKey();
    const current = generateSenderKey();
    const ring = [
      { key: current.key, keyId: current.keyId },
      { key: old2.key, keyId: old2.keyId },
      { key: old1.key, keyId: old1.keyId },
    ];
    const histV1 = encryptWithSenderKey('history under old1 (v1)', old1.key, old1.keyId);
    const histV2 = encodeSenderKeyMessage('history under old2 (v2)', old2.key, old2.keyId, { epoch: 2, wireV2: true });
    expect(decodeSenderKeyMessageChain(histV1, ring)).toBe('history under old1 (v1)');
    expect(decodeSenderKeyMessageChain(histV2, ring)).toBe('history under old2 (v2)');
  });

  test('returns null for an unknown key / bad prefix / bad input, never throws', () => {
    const sk = generateSenderKey();
    const ring = [{ key: generateSenderKey().key, keyId: 'x' }];
    const v2 = encodeSenderKeyMessage('secret', sk.key, sk.keyId, { epoch: 1, wireV2: true });
    expect(decodeSenderKeyMessageChain(v2, ring)).toBeNull(); // key not in ring
    expect(decodeSenderKeyMessageChain('naclp:a:b', ring)).toBeNull();
    expect(decodeSenderKeyMessageChain('skey2:1', ring)).toBeNull();
    expect(decodeSenderKeyMessageChain(null, ring)).toBeNull();
    expect(decodeSenderKeyMessageChain(v2, null)).toBeNull();
  });
});

describe('senderKeyWireV2 — padding / size normalization preserved across versions', () => {
  test('a >256B plaintext round-trips under both framings', () => {
    const sk = generateSenderKey();
    const big = 'A'.repeat(1000);
    const v1 = encryptWithSenderKey(big, sk.key, sk.keyId);
    const v2 = encodeSenderKeyMessage(big, sk.key, sk.keyId, { epoch: 6, wireV2: true });
    expect(decodeSenderKeyMessage(v1, sk.key)).toBe(big);
    expect(decodeSenderKeyMessage(v2, sk.key)).toBe(big);
  });

  test('unicode round-trips under v2', () => {
    const sk = generateSenderKey();
    const s = 'héllo 🌍 — café';
    const v2 = encodeSenderKeyMessage(s, sk.key, sk.keyId, { epoch: 1, wireV2: true });
    expect(decodeSenderKeyMessage(v2, sk.key)).toBe(s);
  });
});
