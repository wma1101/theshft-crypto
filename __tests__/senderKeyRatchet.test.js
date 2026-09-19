/**
 * skr1 — the group per-message ratchet (ADR 0001 §4.1 closure, phase A).
 *
 * The property being purchased: one message key per message, derived by a
 * one-way chain from the distributed root, so compromise of any single
 * message key exposes ONE message, and (once phase B deletes spent state)
 * compromise of current state exposes nothing already received. These tests
 * pin the codec half: derivation, wire, fail-closed decode, dual-read
 * routing, archive-ring fallback, and the epoch gate's coverage of the new
 * prefix.
 */
import {
  SENDER_KEY_RATCHET_PREFIX,
  skrDeriveMessageKey,
  encodeSenderKeyMessageRatchet,
  decodeSenderKeyMessage,
  decodeSenderKeyMessageChain,
  encodeSenderKeyMessage,
  parseSenderKeyEpoch,
  generateSenderKey,
} from '../config/encryption';

const root = generateSenderKey();
const KEY_ID = 'k1234567';

describe('skr1 derivation', () => {
  test('message keys are 32 bytes and differ per iteration', () => {
    const mk0 = skrDeriveMessageKey(root.key, 0, 0, KEY_ID);
    const mk1 = skrDeriveMessageKey(root.key, 1, 0, KEY_ID);
    const mk2 = skrDeriveMessageKey(root.key, 2, 0, KEY_ID);
    expect(mk0).toHaveLength(32);
    expect(Buffer.from(mk0).equals(Buffer.from(mk1))).toBe(false);
    expect(Buffer.from(mk1).equals(Buffer.from(mk2))).toBe(false);
  });

  test('derivation is deterministic', () => {
    const a = skrDeriveMessageKey(root.key, 57, 0, KEY_ID);
    const b = skrDeriveMessageKey(root.key, 57, 0, KEY_ID);
    expect(Buffer.from(a).equals(Buffer.from(b))).toBe(true);
  });

  test('bounds: negative, non-integer, and beyond-cap iters are rejected', () => {
    expect(skrDeriveMessageKey(root.key, -1, 0, KEY_ID)).toBeNull();
    expect(skrDeriveMessageKey(root.key, 1.5, 0, KEY_ID)).toBeNull();
    expect(skrDeriveMessageKey(root.key, 5000, 0, KEY_ID)).toBeNull();
    expect(skrDeriveMessageKey(null, 0, 0, KEY_ID)).toBeNull();
    expect(skrDeriveMessageKey('tooShort', 0, 0, KEY_ID)).toBeNull();
  });
});

describe('skr1 wire roundtrip', () => {
  test.each([0, 1, 57, 999])('roundtrips at iter %i', (iter) => {
    const wire = encodeSenderKeyMessageRatchet('hello ratchet 🔥', root.key, KEY_ID, 3, iter);
    expect(wire.startsWith(SENDER_KEY_RATCHET_PREFIX)).toBe(true);
    expect(wire.split(':')[3]).toBe(String(iter));
    expect(decodeSenderKeyMessage(wire, root.key)).toBe('hello ratchet 🔥');
  });

  test('epoch and keyId ride the wire; epoch gate parses the new prefix', () => {
    const wire = encodeSenderKeyMessageRatchet('x', root.key, KEY_ID, 7, 2);
    expect(wire.split(':')[1]).toBe('7');
    expect(wire.split(':')[2]).toBe(KEY_ID);
    expect(parseSenderKeyEpoch(wire)).toBe(7);
  });

  test('invalid encode inputs return null', () => {
    expect(encodeSenderKeyMessageRatchet('', root.key, KEY_ID, 0, 0)).toBeNull();
    expect(encodeSenderKeyMessageRatchet('x', null, KEY_ID, 0, 0)).toBeNull();
    expect(encodeSenderKeyMessageRatchet('x', root.key, KEY_ID, -1, 0)).toBeNull();
    expect(encodeSenderKeyMessageRatchet('x', root.key, KEY_ID, 0, 9999)).toBeNull();
  });
});

describe('skr1 decode fails closed', () => {
  const wire = encodeSenderKeyMessageRatchet('secret', root.key, KEY_ID, 1, 4);

  test('wrong root returns null', () => {
    const other = generateSenderKey();
    expect(decodeSenderKeyMessage(wire, other.key)).toBeNull();
  });

  test('tampered ciphertext is rejected by the MAC', () => {
    const parts = wire.split(':');
    const ct = Buffer.from(parts[5], 'base64');
    ct[0] ^= 0xff;
    parts[5] = ct.toString('base64');
    expect(decodeSenderKeyMessage(parts.join(':'), root.key)).toBeNull();
  });

  test('a rewritten iter cannot decrypt (mk is bound to the true iter)', () => {
    const parts = wire.split(':');
    parts[3] = '5';
    expect(decodeSenderKeyMessage(parts.join(':'), root.key)).toBeNull();
  });

  test('a rewritten EPOCH cannot decrypt (ADR §4.3 closed for skr1)', () => {
    const parts = wire.split(':');
    parts[1] = '9';
    expect(decodeSenderKeyMessage(parts.join(':'), root.key)).toBeNull();
  });

  test('a rewritten KEYID cannot decrypt (bound into the chain label)', () => {
    const parts = wire.split(':');
    parts[2] = 'evilkeyz';
    expect(decodeSenderKeyMessage(parts.join(':'), root.key)).toBeNull();
  });

  test('epoch and keyId derive DIFFERENT chains for the same root', () => {
    const a = skrDeriveMessageKey(root.key, 0, 1, KEY_ID);
    const b = skrDeriveMessageKey(root.key, 0, 2, KEY_ID);
    const c = skrDeriveMessageKey(root.key, 0, 1, 'otherkey');
    expect(Buffer.from(a).equals(Buffer.from(b))).toBe(false);
    expect(Buffer.from(a).equals(Buffer.from(c))).toBe(false);
  });

  test('malformed wires return null, never throw', () => {
    expect(decodeSenderKeyMessage('skr1:', root.key)).toBeNull();
    expect(decodeSenderKeyMessage('skr1:1:k:notanint:AA==:AA==', root.key)).toBeNull();
    expect(decodeSenderKeyMessage('skr1:1:k:-2:AA==:AA==', root.key)).toBeNull();
    expect(decodeSenderKeyMessage('skr1:1:k:2', root.key)).toBeNull();
  });
});

describe('dual-read routing and independence', () => {
  test('skey2 under the SAME root still decodes via its own path', () => {
    const v2 = encodeSenderKeyMessage('legacy v2', root.key, KEY_ID, { epoch: 1, wireV2: true });
    expect(decodeSenderKeyMessage(v2, root.key)).toBe('legacy v2');
  });

  test('domain separation: the root itself never decrypts an skr1 message', () => {
    // If ck0 were the raw root, an skey2 ciphertext re-labeled skr1 at iter 0
    // could cross-decrypt. Assert the derived mk differs from the root.
    const mk0 = skrDeriveMessageKey(root.key, 0, 0, KEY_ID);
    expect(Buffer.from(mk0).toString('base64')).not.toBe(root.key);
  });

  test('archive-ring fallback decodes an skr1 wire from an OLD keyId', () => {
    const oldKey = generateSenderKey();
    const wire = encodeSenderKeyMessageRatchet('from the past', oldKey.key, oldKey.keyId, 0, 3);
    const chain = [{ key: root.key, keyId: KEY_ID }, { key: oldKey.key, keyId: oldKey.keyId }];
    expect(decodeSenderKeyMessageChain(wire, chain)).toBe('from the past');
  });

  test('archive-ring returns null when no key opens the wire', () => {
    const stranger = generateSenderKey();
    const wire = encodeSenderKeyMessageRatchet('sealed', stranger.key, 'zz999999', 0, 0);
    const chain = [{ key: root.key, keyId: KEY_ID }];
    expect(decodeSenderKeyMessageChain(wire, chain)).toBeNull();
  });
});

// The vendored copy of this file drops the "chat.js dispatch census" suite
// that followed here: it reads app/chat.js by path, an app screen this
// repository does not carry (see README.md, "What this repository does
// not vendor"). The codec-level tests above are unaffected.
