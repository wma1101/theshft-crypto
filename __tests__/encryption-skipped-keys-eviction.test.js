/**
 * Skipped-message-key eviction ordering (Double Ratchet).
 *
 * Skipped keys are stored under composite 'chainId:messageIndex' strings.
 * The old eviction sorted those LEXICOGRAPHICALLY, so 'eph:9' > 'eph:100'
 * and newly-cached keys (e.g. :201..:209) were evicted while genuinely old
 * keys (e.g. :99) were kept alive — weakening forward secrecy and letting a
 * crafted message-index pattern pin old keys in memory.
 *
 * These tests prove eviction is now NUMERIC per chain (oldest indices first,
 * legacy bare-numeric keys first of all) while MAX_SKIPPED_KEYS (256)
 * semantics are unchanged.
 */
/* global describe, test, expect, jest */

const nacl = require('tweetnacl');
const { encodeBase64 } = require('tweetnacl-util');

const {
  initRatchetSession,
  ratchetEncrypt,
  ratchetDecrypt,
  ratchetDecryptAsync,
} = require('../config/encryption');

const MAX_SKIPPED_KEYS = 256; // must mirror config/encryption.js

const b64Key = () => encodeBase64(nacl.box.keyPair().publicKey);

/**
 * Build a sender session plus a matching receive-only session.
 * The receiver's recvChainKey mirrors the sender's sendChainKey and
 * theirEphemeralKey matches the ephemeral embedded by ratchetEncrypt,
 * so decryption takes the pure symmetric-chain path (no DH ratchet) —
 * exactly the path that caches and evicts skipped keys.
 */
const makeSessionPair = () => {
  const alice = nacl.box.keyPair();
  const bob = nacl.box.keyPair();
  const sender = initRatchetSession(
    encodeBase64(bob.publicKey),
    encodeBase64(alice.secretKey),
    encodeBase64(alice.publicKey),
  );
  expect(sender).toBeTruthy();
  const receiver = {
    rootKey: sender.rootKey,
    sendChainKey: sender.recvChainKey,
    recvChainKey: sender.sendChainKey,
    sendMessageIndex: 0,
    recvMessageIndex: 0,
    previousChainLength: 0,
    myEphemeralKeyPair: {
      publicKey: encodeBase64(bob.publicKey),
      secretKey: encodeBase64(bob.secretKey),
    },
    theirEphemeralKey: sender.myEphemeralKeyPair.publicKey,
    skippedKeys: {},
    version: 2,
  };
  return { sender, receiver, chainId: sender.myEphemeralKeyPair.publicKey };
};

/** Encrypt `count` sequential messages, returning the ciphertexts. */
const encryptMany = (sender, count) => {
  const messages = [];
  let s = sender;
  for (let i = 0; i < count; i++) {
    const res = ratchetEncrypt(s, 'msg-' + i);
    expect(res).toBeTruthy();
    messages.push(res.encrypted);
    s = res.session;
  }
  return messages;
};

describe('skipped-key eviction is numeric per chain (not lexicographic)', () => {
  jest.setTimeout(120000);

  test('evicts the numerically-oldest keys and keeps the newest 256', () => {
    const { sender, receiver, chainId } = makeSessionPair();
    const messages = encryptMany(sender, 458);

    // Decrypt index 200 → caches skipped keys 0..199.
    let r = ratchetDecrypt(receiver, messages[200]);
    expect(r).toBeTruthy();
    expect(r.plaintext).toBe('msg-200');
    expect(Object.keys(r.session.skippedKeys)).toHaveLength(200);

    // Decrypt index 457 → caches 201..456 (256 more) → 456 total → evict 200.
    r = ratchetDecrypt(r.session, messages[457]);
    expect(r).toBeTruthy();
    expect(r.plaintext).toBe('msg-457');

    const remaining = Object.keys(r.session.skippedKeys);
    expect(remaining).toHaveLength(MAX_SKIPPED_KEYS);

    // ALL keys 0..199 (the numerically-oldest) must be gone; 201..456 kept.
    const indices = remaining.map((k) => parseInt(k.slice(k.lastIndexOf(':') + 1), 10));
    expect(Math.min(...indices)).toBe(201);
    expect(Math.max(...indices)).toBe(456);
    expect(r.session.skippedKeys[chainId + ':201']).toBeTruthy();
    expect(r.session.skippedKeys[chainId + ':456']).toBeTruthy();
    expect(r.session.skippedKeys[chainId + ':199']).toBeUndefined();

    // Lexicographic eviction would have dropped ':201'..':209' (they sort
    // before ':21', ':99', …) — a retained NEW key must still decrypt.
    const ok = ratchetDecrypt(r.session, messages[205]);
    expect(ok).toBeTruthy();
    expect(ok.plaintext).toBe('msg-205');

    // …and a genuinely old key must be unrecoverable (forward secrecy).
    expect(ratchetDecrypt(ok.session, messages[100])).toBeNull();
  });

  test('async decrypt path evicts identically', async () => {
    const { sender, receiver } = makeSessionPair();
    const messages = encryptMany(sender, 458);

    let r = await ratchetDecryptAsync(receiver, messages[200]);
    expect(r).toBeTruthy();
    r = await ratchetDecryptAsync(r.session, messages[457]);
    expect(r).toBeTruthy();

    const indices = Object.keys(r.session.skippedKeys)
      .map((k) => parseInt(k.slice(k.lastIndexOf(':') + 1), 10));
    expect(indices).toHaveLength(MAX_SKIPPED_KEYS);
    expect(Math.min(...indices)).toBe(201);
    expect(Math.max(...indices)).toBe(456);

    const ok = await ratchetDecryptAsync(r.session, messages[205]);
    expect(ok).toBeTruthy();
    expect(ok.plaintext).toBe('msg-205');
  });

  test('legacy bare-numeric keys are evicted before composite chain keys', () => {
    const { sender, receiver, chainId } = makeSessionPair();
    const messages = encryptMany(sender, 25);

    // Pre-seed 250 legacy-format keys (bare numeric, pre-chainId sessions).
    // Indices ≥1000 so they never collide with real lookups below.
    const seeded = { ...receiver, skippedKeys: {} };
    for (let i = 1000; i < 1250; i++) {
      seeded.skippedKeys[String(i)] = b64Key();
    }

    // Decrypt index 20 → caches chain keys 0..19 → 270 total → evict 14.
    const r = ratchetDecrypt(seeded, messages[20]);
    expect(r).toBeTruthy();
    expect(r.plaintext).toBe('msg-20');

    const remaining = Object.keys(r.session.skippedKeys);
    expect(remaining).toHaveLength(MAX_SKIPPED_KEYS);
    // The 14 numerically-oldest LEGACY keys go first…
    expect(r.session.skippedKeys['1000']).toBeUndefined();
    expect(r.session.skippedKeys['1013']).toBeUndefined();
    expect(r.session.skippedKeys['1014']).toBeTruthy();
    // …while every freshly-cached composite key survives.
    for (let i = 0; i < 20; i++) {
      expect(r.session.skippedKeys[chainId + ':' + i]).toBeTruthy();
    }
  });
});
