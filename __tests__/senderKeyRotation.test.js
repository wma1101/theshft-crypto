/**
 * KAN-21 — epoch-based Sender Key rotation on group membership change.
 *
 * The security property under test: once a sender rotates their Sender Key for a
 * removal, the removed member CANNOT decrypt that sender's post-rotation
 * messages, while surviving members CAN — and pre-rotation history stays
 * readable to everyone who already held the old key.
 *
 * This exercises the real crypto primitives (NaCl box distribution + secretbox
 * message encryption) end to end across simulated members. It does NOT touch the
 * live chat.js path — it proves the rotation primitive the wiring will build on.
 */

const nacl = require('tweetnacl');
const { encodeBase64 } = require('tweetnacl-util');
const {
  generateSenderKey,
  encryptWithSenderKey,
  decryptWithSenderKey,
  distributeSenderKey,
  receiveSenderKey,
} = require('../config/encryption');
const {
  rotateForMembershipChange,
  recipientsForRotation,
  archiveKey,
  SENDER_KEY_ARCHIVE_MAX,
  rotateOwnKeyForEpoch,
  clearOwnKeyMemo,
  shouldRejectByJoinEpoch,
  shouldRotateForSecondaryTrigger,
  MAX_MESSAGES_PER_KEY,
  MAX_KEY_AGE_MS,
} = require('../config/senderKeyRotation');

// A group member = a NaCl box keypair + an id. publicKey is base64 like the
// real users/{uid}.publicKey field.
function makeMember(id) {
  const kp = nacl.box.keyPair();
  return { id, publicKey: encodeBase64(kp.publicKey), privateKey: encodeBase64(kp.secretKey) };
}

// What a recipient does on the wire: open the envelope addressed to them with
// the distributor's public key + their own private key.
function openEnvelope(distributedKeys, recipient, distributorPublicKey) {
  const env = distributedKeys[recipient.id];
  if (!env) return null;
  return receiveSenderKey(env, distributorPublicKey, recipient.privateKey);
}

describe('senderKeyRotation — recipientsForRotation (the exclusion guarantee)', () => {
  test('excludes the removed member even if a stale caller leaves them in the list', () => {
    const a = makeMember('a'); const b = makeMember('b'); const c = makeMember('c');
    const { recipients, excluded } = recipientsForRotation([a, b, c], ['b']);
    expect(recipients.map((m) => m.id).sort()).toEqual(['a', 'c']);
    expect(excluded).toEqual(['b']);
  });

  test('`excluded` is the true intersection — a ghost removedId is NOT reported excluded', () => {
    const a = makeMember('a');
    const { recipients, excluded } = recipientsForRotation([a], ['never-a-member']);
    expect(recipients.map((m) => m.id)).toEqual(['a']);
    expect(excluded).toEqual([]); // ghost id was never present → not "excluded"
  });

  test('a survivor without a publicKey is reported in `skipped`, not silently dropped', () => {
    const a = makeMember('a');
    const { recipients, skipped } = recipientsForRotation([a, { id: 'no-key' }], []);
    expect(recipients.map((m) => m.id)).toEqual(['a']);
    expect(skipped).toEqual(['no-key']);
  });

  test('de-dupes ids and tolerates empty input', () => {
    const a = makeMember('a');
    expect(recipientsForRotation([a, a], []).recipients.map((m) => m.id)).toEqual(['a']);
    expect(recipientsForRotation([], []).recipients).toEqual([]);
    expect(recipientsForRotation(null, null).recipients).toEqual([]);
  });

  test('never mutates its input', () => {
    const a = makeMember('a'); const b = makeMember('b');
    const input = [a, b];
    recipientsForRotation(input, ['b']);
    expect(input).toEqual([a, b]);
  });
});

describe('senderKeyRotation — rotateForMembershipChange', () => {
  test('throws without a private key', () => {
    expect(() => rotateForMembershipChange({ currentMembers: [], myPrivateKey: null }))
      .toThrow(/myPrivateKey required/);
  });

  test('increments the epoch and excludes the removed member from distribution', () => {
    const admin = makeMember('admin');
    const b = makeMember('b'); const c = makeMember('c');
    const r = rotateForMembershipChange({
      prevEpoch: 4,
      currentMembers: [b, c], // recipients (excluding self)
      removedIds: ['b'],
      myPrivateKey: admin.privateKey,
    });
    expect(r.epoch).toBe(5);
    expect(r.recipients).toEqual(['c']);
    expect(r.excluded).toEqual(['b']);
    expect(Object.keys(r.distributedKeys)).toEqual(['c']);
    expect(r.distributedKeys).not.toHaveProperty('b');
  });

  test('epoch defaulting/validation is pinned', () => {
    const admin = makeMember('admin'); const c = makeMember('c');
    const ok = (prevEpoch) => rotateForMembershipChange({ prevEpoch, currentMembers: [c], myPrivateKey: admin.privateKey }).epoch;
    expect(ok(undefined)).toBe(1);
    expect(ok(null)).toBe(1);
    expect(ok(0)).toBe(1);
    expect(ok(7)).toBe(8);
    // Garbage must THROW (no silent epoch regression).
    for (const bad of [-1, 2.5, '4', NaN, Infinity]) {
      expect(() => rotateForMembershipChange({ prevEpoch: bad, currentMembers: [c], myPrivateKey: admin.privateKey }))
        .toThrow(/non-negative integer/);
    }
  });

  test('throws if a recipient publicKey cannot be encrypted to (no silent partial rotation)', () => {
    const admin = makeMember('admin');
    const c = makeMember('c');
    const bad = { id: 'bad', publicKey: 'not-valid-base64-!!!' }; // distribute will drop it
    expect(() => rotateForMembershipChange({
      currentMembers: [c, bad], removedIds: [], myPrivateKey: admin.privateKey,
    })).toThrow(/failed to encrypt the new key/);
  });
});

describe('senderKeyRotation — end-to-end removal cutoff', () => {
  test('removed member cannot decrypt post-rotation messages; survivor can; history stays readable', () => {
    const admin = makeMember('admin'); // the sender/distributor
    const bob = makeMember('bob'); // to be removed
    const carol = makeMember('carol'); // survivor

    // ── Epoch 1: admin has a key and distributes to bob + carol ──
    const sk1 = generateSenderKey();
    const dist1 = distributeSenderKey(sk1.key, [bob, carol], admin.privateKey);
    const bobsKey1 = openEnvelope(dist1, bob, admin.publicKey);
    const carolsKey1 = openEnvelope(dist1, carol, admin.publicKey);
    expect(bobsKey1).toBe(sk1.key);
    expect(carolsKey1).toBe(sk1.key);

    const msg1 = encryptWithSenderKey('before removal', sk1.key, sk1.keyId);
    expect(decryptWithSenderKey(msg1, bobsKey1)).toBe('before removal');
    expect(decryptWithSenderKey(msg1, carolsKey1)).toBe('before removal');

    // ── Remove bob: admin rotates (epoch 2), distributing ONLY to carol ──
    const r = rotateForMembershipChange({
      prevEpoch: 1,
      currentMembers: [bob, carol], // realistic: stale list still contains bob
      removedIds: ['bob'],
      myPrivateKey: admin.privateKey,
    });
    const carolsKey2 = openEnvelope(r.distributedKeys, carol, admin.publicKey);
    expect(carolsKey2).toBe(r.key);
    expect(openEnvelope(r.distributedKeys, bob, admin.publicKey)).toBeNull(); // no envelope for bob

    // ── Admin sends under the new epoch ──
    const msg2 = encryptWithSenderKey('after removal', r.key, r.keyId);

    // SECURITY: carol reads it; bob (holding only sk1) cannot.
    expect(decryptWithSenderKey(msg2, carolsKey2)).toBe('after removal');
    expect(decryptWithSenderKey(msg2, bobsKey1)).toBeNull();

    // Backward-compat: bob can still read the pre-removal message he already had.
    expect(decryptWithSenderKey(msg1, bobsKey1)).toBe('before removal');
  });

  // The orchestration requirement, proven as a CONTRAST (not just documented):
  // each member owns their own key, so a removal only cuts bob off from a given
  // sender once THAT sender rotates. Same setup, two outcomes.
  test('cutoff depends on the sender rotating — non-rotating sender leaks, rotating sender does not', () => {
    const carol = makeMember('carol'); // a second sender
    const bob = makeMember('bob'); // removed
    const dave = makeMember('dave'); // survivor

    // carol distributed her key to bob + dave before bob was removed.
    const carolKey = generateSenderKey();
    const dist = distributeSenderKey(carolKey.key, [bob, dave], carol.privateKey);
    const bobsCarolKey = openEnvelope(dist, bob, carol.publicKey);
    const davesCarolKey = openEnvelope(dist, dave, carol.publicKey);

    // CASE A — carol does NOT rotate: her new message leaks to removed bob,
    // and dave (survivor) reads it too (so it's the same plaintext, not noise).
    const leaked = encryptWithSenderKey('carol did not rotate', carolKey.key, carolKey.keyId);
    expect(decryptWithSenderKey(leaked, davesCarolKey)).toBe('carol did not rotate'); // survivor
    expect(decryptWithSenderKey(leaked, bobsCarolKey)).toBe('carol did not rotate'); // LEAK

    // CASE B — carol DOES rotate (excluding bob): dave reads, bob is cut off.
    const r = rotateForMembershipChange({
      prevEpoch: 1, currentMembers: [bob, dave], removedIds: ['bob'], myPrivateKey: carol.privateKey,
    });
    const davesCarolKey2 = openEnvelope(r.distributedKeys, dave, carol.publicKey);
    const sealed = encryptWithSenderKey('carol rotated', r.key, r.keyId);
    expect(decryptWithSenderKey(sealed, davesCarolKey2)).toBe('carol rotated'); // survivor
    expect(decryptWithSenderKey(sealed, bobsCarolKey)).toBeNull(); // bob CUT OFF
  });
});

describe('senderKeyRotation — archiveKey ring', () => {
  test('prepends most-recent-first and caps at the max', () => {
    let ring = [];
    for (let i = 0; i < SENDER_KEY_ARCHIVE_MAX + 5; i++) {
      ring = archiveKey(ring, { key: 'k' + i, keyId: 'id' + i });
    }
    expect(ring.length).toBe(SENDER_KEY_ARCHIVE_MAX);
    expect(ring[0].keyId).toBe('id' + (SENDER_KEY_ARCHIVE_MAX + 4)); // newest first
  });

  test('de-dupes an exact repeat and drops malformed input entries', () => {
    let ring = archiveKey([{ keyId: 'x' /* no key */ }], { key: 'k1', keyId: 'id1' });
    ring = archiveKey(ring, { key: 'k1', keyId: 'id1' }); // exact dup
    ring = archiveKey(ring, null); // garbage
    expect(ring).toEqual([{ key: 'k1', keyId: 'id1' }]);
  });

  test('throws on a keyId collision with DIFFERENT key bytes (no silent loss)', () => {
    const ring = archiveKey([], { key: 'k1', keyId: 'dup' });
    expect(() => archiveKey(ring, { key: 'DIFFERENT', keyId: 'dup' }))
      .toThrow(/keyId collision/);
  });
});

describe('senderKeyRotation — shouldRejectByJoinEpoch (DECISION 3, fail-open)', () => {
  test('rejects ONLY when both are non-negative ints AND messageEpoch < myJoinedEpoch', () => {
    expect(shouldRejectByJoinEpoch(2, 5)).toBe(true); // pre-join history → reject
    expect(shouldRejectByJoinEpoch(5, 5)).toBe(false); // same epoch → allow
    expect(shouldRejectByJoinEpoch(6, 5)).toBe(false); // post-join → allow
    expect(shouldRejectByJoinEpoch(0, 1)).toBe(true);
  });

  test('FAIL-OPEN on null/absent (legacy v1 message or legacy member doc)', () => {
    expect(shouldRejectByJoinEpoch(null, 5)).toBe(false); // legacy v1 message
    expect(shouldRejectByJoinEpoch(2, null)).toBe(false); // legacy member doc
    expect(shouldRejectByJoinEpoch(null, null)).toBe(false);
    expect(shouldRejectByJoinEpoch(undefined, 5)).toBe(false);
    expect(shouldRejectByJoinEpoch(2, undefined)).toBe(false);
  });

  test('FAIL-OPEN on non-integer / negative garbage (never blackhole on bad data)', () => {
    expect(shouldRejectByJoinEpoch(2.5, 5)).toBe(false);
    expect(shouldRejectByJoinEpoch(2, 5.5)).toBe(false);
    expect(shouldRejectByJoinEpoch(-1, 5)).toBe(false);
    expect(shouldRejectByJoinEpoch(2, -1)).toBe(false);
    expect(shouldRejectByJoinEpoch('2', 5)).toBe(false);
    expect(shouldRejectByJoinEpoch(NaN, 5)).toBe(false);
  });
});

describe('senderKeyRotation — shouldRotateForSecondaryTrigger (DECISION 4)', () => {
  const T0 = 1_700_000_000_000;

  test('message-count boundary is strict > MAX_MESSAGES_PER_KEY', () => {
    const at = (n) => shouldRotateForSecondaryTrigger({ messagesSinceRotation: n, keyCreatedAtMs: T0, nowMs: T0 });
    expect(at(MAX_MESSAGES_PER_KEY - 1)).toBe(false);
    expect(at(MAX_MESSAGES_PER_KEY)).toBe(false); // exactly at threshold → still send under it
    expect(at(MAX_MESSAGES_PER_KEY + 1)).toBe(true);
  });

  test('age boundary is strict > MAX_KEY_AGE_MS', () => {
    const at = (ageMs) => shouldRotateForSecondaryTrigger({ messagesSinceRotation: 0, keyCreatedAtMs: T0, nowMs: T0 + ageMs });
    expect(at(MAX_KEY_AGE_MS - 1)).toBe(false);
    expect(at(MAX_KEY_AGE_MS)).toBe(false);
    expect(at(MAX_KEY_AGE_MS + 1)).toBe(true);
  });

  test('either trigger alone fires; missing/garbage telemetry never forces rotation', () => {
    expect(shouldRotateForSecondaryTrigger({ messagesSinceRotation: 5000, keyCreatedAtMs: T0, nowMs: T0 })).toBe(true);
    expect(shouldRotateForSecondaryTrigger({ messagesSinceRotation: 0, keyCreatedAtMs: 1, nowMs: T0 })).toBe(true); // very old key
    expect(shouldRotateForSecondaryTrigger({ messagesSinceRotation: NaN, keyCreatedAtMs: NaN, nowMs: T0 })).toBe(false);
    expect(shouldRotateForSecondaryTrigger({ messagesSinceRotation: undefined, keyCreatedAtMs: 0, nowMs: T0 })).toBe(false);
  });

  test('defaults nowMs to Date.now() when omitted', () => {
    // A key created "now" with zero messages must not rotate.
    expect(shouldRotateForSecondaryTrigger({ messagesSinceRotation: 0, keyCreatedAtMs: Date.now() })).toBe(false);
    // A key created ~8 days ago must rotate.
    expect(shouldRotateForSecondaryTrigger({ messagesSinceRotation: 0, keyCreatedAtMs: Date.now() - (MAX_KEY_AGE_MS + 60_000) })).toBe(true);
  });
});

describe('senderKeyRotation — rotateOwnKeyForEpoch (classical + idempotency)', () => {
  beforeEach(() => clearOwnKeyMemo());

  test('throws on missing private key / bad epoch', async () => {
    await expect(rotateOwnKeyForEpoch({ currentEpoch: 1, recipients: [], myPrivateKey: null }))
      .rejects.toThrow(/myPrivateKey required/);
    const a = makeMember('a');
    await expect(rotateOwnKeyForEpoch({ currentEpoch: -1, recipients: [], myPrivateKey: a.privateKey, conversationId: 'c' }))
      .rejects.toThrow(/non-negative integer/);
    await expect(rotateOwnKeyForEpoch({ currentEpoch: 2.5, recipients: [], myPrivateKey: a.privateKey, conversationId: 'c' }))
      .rejects.toThrow(/non-negative integer/);
  });

  test('classical path: mints a fresh key, distributes naclp envelopes only to recipients, archives the old key', async () => {
    const admin = makeMember('admin');
    const bob = makeMember('bob'); const carol = makeMember('carol');
    const old = generateSenderKey();

    const r = await rotateOwnKeyForEpoch({
      currentEpoch: 3,
      myCurrentKey: { key: old.key, keyId: old.keyId },
      recipients: [bob, carol], // survivors (post-membership-change list, no removed member)
      myPrivateKey: admin.privateKey,
      wireV2: false,
      conversationId: 'conv1',
    });

    expect(r.epoch).toBe(3);
    expect(r.newKey.key).not.toBe(old.key);
    expect(r.archivedOldKey).toEqual({ key: old.key, keyId: old.keyId });
    expect(r.failed).toEqual([]);
    expect(Object.keys(r.distributedKeys).sort()).toEqual(['bob', 'carol']);
    // Classical default ⇒ naclp envelopes that survivors can open to the new key.
    expect(r.distributedKeys.bob.startsWith('naclp:')).toBe(true);
    const bobsKey = receiveSenderKey(r.distributedKeys.bob, admin.publicKey, bob.privateKey);
    expect(bobsKey).toBe(r.newKey.key);
  });

  test('null myCurrentKey ⇒ archivedOldKey is null (first-ever key for the conv)', async () => {
    const admin = makeMember('admin'); const bob = makeMember('bob');
    const r = await rotateOwnKeyForEpoch({
      currentEpoch: 1, myCurrentKey: null, recipients: [bob], myPrivateKey: admin.privateKey, conversationId: 'c',
    });
    expect(r.archivedOldKey).toBeNull();
  });

  test('IDEMPOTENT per (conversation, epoch): repeat calls return the SAME key + distribution (no double-mint / no orphan)', async () => {
    const admin = makeMember('admin'); const bob = makeMember('bob');
    const args = { currentEpoch: 7, myCurrentKey: null, recipients: [bob], myPrivateKey: admin.privateKey, conversationId: 'convX' };
    const r1 = await rotateOwnKeyForEpoch({ ...args });
    const r2 = await rotateOwnKeyForEpoch({ ...args });
    expect(r2.newKey.key).toBe(r1.newKey.key);
    expect(r2.newKey.keyId).toBe(r1.newKey.keyId);
    // Same envelope bytes ⇒ no orphaned distribution.
    expect(r2.distributedKeys.bob).toBe(r1.distributedKeys.bob);
  });

  test('CONCURRENT calls (observe-then-send race) mint exactly ONE key for the epoch', async () => {
    const admin = makeMember('admin'); const bob = makeMember('bob');
    const args = { currentEpoch: 9, myCurrentKey: null, recipients: [bob], myPrivateKey: admin.privateKey, conversationId: 'race' };
    // Two callers fire before either persists a marker — the exact rotate-before-send race.
    const [a, b] = await Promise.all([
      rotateOwnKeyForEpoch({ ...args }),
      rotateOwnKeyForEpoch({ ...args }),
    ]);
    expect(a.newKey.key).toBe(b.newKey.key); // ONE key, no orphan
    // bob can open whichever envelope; both decode to the same key.
    expect(receiveSenderKey(a.distributedKeys.bob, admin.publicKey, bob.privateKey)).toBe(a.newKey.key);
  });

  test('different epochs mint different keys; clearOwnKeyMemo drops the cache', async () => {
    const admin = makeMember('admin'); const bob = makeMember('bob');
    const e5 = await rotateOwnKeyForEpoch({ currentEpoch: 5, recipients: [bob], myPrivateKey: admin.privateKey, conversationId: 'c' });
    const e6 = await rotateOwnKeyForEpoch({ currentEpoch: 6, recipients: [bob], myPrivateKey: admin.privateKey, conversationId: 'c' });
    expect(e6.newKey.key).not.toBe(e5.newKey.key);
    // After clearing, a re-rotation at epoch 5 mints a NEW key (memo gone).
    clearOwnKeyMemo('c');
    const e5b = await rotateOwnKeyForEpoch({ currentEpoch: 5, recipients: [bob], myPrivateKey: admin.privateKey, conversationId: 'c' });
    expect(e5b.newKey.key).not.toBe(e5.newKey.key);
  });

  test('surfaces failed[] for an undeliverable survivor without throwing (caller retries)', async () => {
    const admin = makeMember('admin'); const bob = makeMember('bob');
    const bad = { id: 'bad', publicKey: 'not-valid-base64-!!!' };
    const r = await rotateOwnKeyForEpoch({
      currentEpoch: 2, recipients: [bob, bad], myPrivateKey: admin.privateKey, conversationId: 'partial',
    });
    expect(r.failed).toEqual(['bad']);
    expect(Object.keys(r.distributedKeys)).toEqual(['bob']);
  });

  test('REMOVAL CUTOFF end-to-end: a removed member (absent from recipients) is cut off; survivor reads', async () => {
    const admin = makeMember('admin'); // sender
    const removed = makeMember('removed');
    const survivor = makeMember('survivor');

    // Before removal: admin had a key both held.
    const before = generateSenderKey();
    const distBefore = distributeSenderKey(before.key, [removed, survivor], admin.privateKey);
    const removedKeyBefore = receiveSenderKey(distBefore.removed, admin.publicKey, removed.privateKey);
    expect(removedKeyBefore).toBe(before.key);

    // Server bumped epoch on removal; admin rotates to the SURVIVOR-ONLY list.
    const r = await rotateOwnKeyForEpoch({
      currentEpoch: 4,
      myCurrentKey: { key: before.key, keyId: before.keyId },
      recipients: [survivor], // removed member simply absent
      myPrivateKey: admin.privateKey,
      conversationId: 'cutoff',
    });
    expect(r.distributedKeys).not.toHaveProperty('removed');

    const survivorKey = receiveSenderKey(r.distributedKeys.survivor, admin.publicKey, survivor.privateKey);
    const msg = encryptWithSenderKey('after removal', r.newKey.key, r.newKey.keyId);
    expect(decryptWithSenderKey(msg, survivorKey)).toBe('after removal'); // survivor reads
    expect(decryptWithSenderKey(msg, removedKeyBefore)).toBeNull(); // removed CUT OFF
  });
});
