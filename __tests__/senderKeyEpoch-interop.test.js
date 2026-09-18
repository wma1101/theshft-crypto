/**
 * KAN-21 / C-D — multi-client Sender Key EPOCH interop + removal-cutoff harness.
 *
 * The sibling __tests__/senderKeyRotation.test.js proves the rotation PRIMITIVE
 * in isolation (one distributor, the exclusion/idempotency/archive contracts).
 * THIS harness proves the end-to-end SYSTEM the wiring will rely on, across
 * multiple simulated clients and across epochs, using ONLY the pure primitives
 * (no RN, no Firebase, no native ML-KEM — the classical/`pqsk1`-classical path):
 *
 *   1. REMOVAL CUTOFF across all senders. Members A, B, C survive; E is removed.
 *      After the server bumps the epoch and A/B/C each rotate via
 *      rotateOwnKeyForEpoch, E CANNOT decrypt any of A/B/C's post-rotation
 *      messages, while A/B/C CAN read each other's. (This is the forward-secrecy
 *      property C-D exists to deliver — and the one with NO failing test if it
 *      silently breaks, so it is asserted directly.)
 *
 *   2. HISTORY STAYS READABLE. The pre-rotation messages everyone already held a
 *      key for remain decryptable via the archive ring (decodeSenderKeyMessageChain
 *      over archiveKey-built chains) — rotation must not destroy scrollback.
 *
 *   3. JOIN-EPOCH GATE (DECISION 3). A v2 message whose embedded epoch is < a
 *      reader's joinedEpoch is rejected (shouldRejectByJoinEpoch) — a member added
 *      at a later epoch cannot read pre-join history even if it possessed the key.
 *
 *   4. OLD-CLIENT INTEROP / WRITE-GATE (DECISION 1). A new client with the v2 flag
 *      OFF writes BYTE-IDENTICAL legacy `skey:` output, and an OLD client that only
 *      knows decryptWithSenderKey (v1-only decode) reads it. Flipping the flag ON
 *      emits `skey2:` that the new client's dual-read decode still reads. This is
 *      the in-field-interop guarantee that lets the flag flip safely.
 *
 *   5. SECONDARY ROTATION BOUND (DECISION 4). Under stable membership the
 *      message-count / age trigger fires at the documented bound.
 *
 * Style mirrors senderKeyRotation.test.js: real NaCl box distribution + secretbox
 * messages, members are real keypairs, "the wire" is the envelope/ciphertext
 * strings the app would actually persist.
 */

const nacl = require('tweetnacl');
const { encodeBase64 } = require('tweetnacl-util');
const {
  generateSenderKey,
  encryptWithSenderKey,
  decryptWithSenderKey,
  distributeSenderKey,
  receiveSenderKey,
  receiveSenderKeyAny,
  encodeSenderKeyMessage,
  decodeSenderKeyMessage,
  decodeSenderKeyMessageChain,
  parseSenderKeyEpoch,
} = require('../config/encryption');
const {
  rotateOwnKeyForEpoch,
  clearOwnKeyMemo,
  archiveKey,
  shouldRejectByJoinEpoch,
  shouldRotateForSecondaryTrigger,
  MAX_MESSAGES_PER_KEY,
  MAX_KEY_AGE_MS,
} = require('../config/senderKeyRotation');

// A client = a NaCl box keypair + an id. publicKey/privateKey are base64 like
// the real users/{uid}.publicKey field + the SecureStore-held private key.
function makeClient(id) {
  const kp = nacl.box.keyPair();
  return { id, publicKey: encodeBase64(kp.publicKey), privateKey: encodeBase64(kp.secretKey) };
}

// Open a distribution envelope addressed to `me` from `distributor` using the
// dual-read receive (handles both legacy `naclp:`-style boxes and `pqsk1:`).
async function openKey(distributedKeys, me, distributor) {
  const env = distributedKeys[me.id];
  if (!env) return null;
  // No PQ private key in jest (native ML-KEM unavailable) → classical path.
  return receiveSenderKeyAny(env, distributor.publicKey, me.privateKey, null);
}

describe('senderKeyEpoch-interop — removal cutoff across ALL senders (A,B,C survive, E removed)', () => {
  beforeEach(() => clearOwnKeyMemo());

  // Helper: one sender mints an epoch-1 key, distributes to the whole group
  // (incl. the soon-removed E), everyone records the key, sender posts a message.
  async function bootstrapSender(sender, allMembers) {
    const k1 = generateSenderKey();
    const dist1 = distributeSenderKey(k1.key, allMembers, sender.privateKey);
    const heldKeys = {};
    for (const m of allMembers) {
      heldKeys[m.id] = receiveSenderKey(dist1[m.id], sender.publicKey, m.privateKey);
    }
    const history = encryptWithSenderKey(`hi from ${sender.id} (epoch 1)`, k1.key, k1.keyId);
    return { k1, heldKeys, history };
  }

  test('after E removed + A/B/C rotate, E cannot read post-rotation msgs; A/B/C can; history survives', async () => {
    const A = makeClient('A');
    const B = makeClient('B');
    const C = makeClient('C');
    const E = makeClient('E'); // to be removed
    const survivors = [A, B, C];
    const everyone = [A, B, C, E];

    // ── Epoch 1: every sender distributes their own key to the WHOLE group ──
    // recipientsFor(sender) = everyone except the sender themself.
    const others = (self) => everyone.filter((m) => m.id !== self.id);
    const state = {};
    for (const s of [A, B, C]) {
      state[s.id] = await bootstrapSender(s, others(s));
    }

    // Sanity: in epoch 1, E held every sender's key and could read history.
    for (const s of [A, B, C]) {
      const eKey = state[s.id].heldKeys[E.id];
      expect(decryptWithSenderKey(state[s.id].history, eKey)).toBe(`hi from ${s.id} (epoch 1)`);
    }

    // ── Server bumps keyRotationEpoch to 2 on E's removal. Each surviving sender
    //    rotates its OWN key to epoch 2, distributing to SURVIVORS ONLY. ──
    const survivorRecipients = (self) => survivors.filter((m) => m.id !== self.id);
    const rotated = {};
    for (const s of [A, B, C]) {
      const r = await rotateOwnKeyForEpoch({
        currentEpoch: 2,
        myCurrentKey: { key: state[s.id].k1.key, keyId: state[s.id].k1.keyId },
        recipients: survivorRecipients(s), // E is simply ABSENT from the list
        myPrivateKey: s.privateKey,
        wireV2: false,
        // The own-key memo is keyed on (conversationId, epoch) and is
        // PROCESS-GLOBAL. In production each sender is a SEPARATE device/process,
        // so each owns its own memo for `group-1`. This single-process harness
        // models that device isolation by namespacing the scope per sender —
        // otherwise sender A's minted key would be handed back to B and C for the
        // same (group-1, epoch 2) pair (the idempotency guard doing its job).
        conversationId: `group-1::${s.id}`,
      });
      expect(r.epoch).toBe(2);
      expect(r.failed).toEqual([]);
      // The removed member never appears in any distribution map.
      expect(r.distributedKeys).not.toHaveProperty('E');
      rotated[s.id] = r;
    }

    // Each surviving sender posts a NEW message under its epoch-2 key.
    const newMsgs = {};
    for (const s of [A, B, C]) {
      newMsgs[s.id] = encryptWithSenderKey(`hi from ${s.id} (epoch 2)`, rotated[s.id].newKey.key, rotated[s.id].newKey.keyId);
    }

    // SURVIVORS read every other survivor's epoch-2 message.
    for (const sender of [A, B, C]) {
      for (const reader of survivors) {
        if (reader.id === sender.id) continue;
        const readerKey = await openKey(rotated[sender.id].distributedKeys, reader, sender);
        expect(readerKey).toBe(rotated[sender.id].newKey.key);
        expect(decryptWithSenderKey(newMsgs[sender.id], readerKey)).toBe(`hi from ${sender.id} (epoch 2)`);
      }
    }

    // SECURITY — the whole point: E (holding only the epoch-1 keys) is CUT OFF
    // from EVERY survivor's epoch-2 message. No envelope, and the old key fails.
    for (const sender of [A, B, C]) {
      expect(await openKey(rotated[sender.id].distributedKeys, E, sender)).toBeNull();
      const eOldKey = state[sender.id].heldKeys[E.id];
      expect(decryptWithSenderKey(newMsgs[sender.id], eOldKey)).toBeNull(); // CUT OFF
    }

    // HISTORY: pre-rotation messages stay readable to E (and survivors) via the
    // key E already held. Forward secrecy must not erase scrollback.
    for (const sender of [A, B, C]) {
      const eOldKey = state[sender.id].heldKeys[E.id];
      expect(decryptWithSenderKey(state[sender.id].history, eOldKey)).toBe(`hi from ${sender.id} (epoch 1)`);
    }
  });

  test('survivor archive ring keeps PRE-rotation history readable after rotating (decodeSenderKeyMessageChain)', async () => {
    const A = makeClient('A'); // sender
    const B = makeClient('B'); // survivor reader
    const E = makeClient('E'); // removed

    // Epoch 1: A distributes to B + E; A posts an epoch-1 message.
    const k1 = generateSenderKey();
    const dist1 = distributeSenderKey(k1.key, [B, E], A.privateKey);
    const bKey1 = receiveSenderKey(dist1[B.id], A.publicKey, B.privateKey);
    const hist = encryptWithSenderKey('old scrollback', k1.key, k1.keyId);

    // Epoch 2: E removed → A rotates to B only, archiving k1.
    const r = await rotateOwnKeyForEpoch({
      currentEpoch: 2,
      myCurrentKey: { key: k1.key, keyId: k1.keyId },
      recipients: [B],
      myPrivateKey: A.privateKey,
      conversationId: 'arch-1',
    });
    const bKey2 = await openKey(r.distributedKeys, B, A);

    // B builds an archive ring (newest current key conceptually held separately;
    // here we chain current + archived to read across the rotation boundary).
    const bChain = archiveKey([{ key: bKey2, keyId: r.newKey.keyId }], { key: bKey1, keyId: k1.keyId });

    // The NEW message reads under the current key; the OLD message reads under the
    // archived key — both via the single dual-read chain decode.
    const newMsg = encryptWithSenderKey('fresh', r.newKey.key, r.newKey.keyId);
    expect(decodeSenderKeyMessageChain(newMsg, bChain)).toBe('fresh');
    expect(decodeSenderKeyMessageChain(hist, bChain)).toBe('old scrollback');
  });
});

describe('senderKeyEpoch-interop — join-epoch gate (DECISION 3)', () => {
  test('a v2 message with epoch < the reader joinedEpoch is rejected even with the key', () => {
    const A = makeClient('A'); // sender
    const late = makeClient('late'); // joined at epoch 5

    // A holds an epoch-3 key and (hypothetically) shared it; the late joiner even
    // HAVING the key must not read epoch-3 history per the join gate.
    const k3 = generateSenderKey();
    const wire = encodeSenderKeyMessage('pre-join secret', k3.key, k3.keyId, { wireV2: true, epoch: 3 });
    expect(parseSenderKeyEpoch(wire)).toBe(3);

    const myJoinedEpoch = 5;
    const msgEpoch = parseSenderKeyEpoch(wire);

    // Decision gate fires → the receiver MUST drop it, never store plaintext.
    expect(shouldRejectByJoinEpoch(msgEpoch, myJoinedEpoch)).toBe(true);

    // Cryptographically the key WOULD open it — proving the gate is the thing
    // enforcing "no pre-join history", not key absence.
    expect(decodeSenderKeyMessage(wire, k3.key)).toBe('pre-join secret');

    // A message AT or AFTER the join epoch is allowed.
    const okWire = encodeSenderKeyMessage('post-join', k3.key, k3.keyId, { wireV2: true, epoch: 5 });
    expect(shouldRejectByJoinEpoch(parseSenderKeyEpoch(okWire), myJoinedEpoch)).toBe(false);
  });

  test('legacy v1 message (epoch unknown) is NEVER rejected by the join gate (fail-open)', () => {
    const k = generateSenderKey();
    const v1 = encryptWithSenderKey('legacy', k.key, k.keyId);
    expect(parseSenderKeyEpoch(v1)).toBeNull(); // v1 carries no epoch
    expect(shouldRejectByJoinEpoch(parseSenderKeyEpoch(v1), 9)).toBe(false);
  });
});

describe('senderKeyEpoch-interop — old-client interop / write-gate (DECISION 1)', () => {
  // The "OLD client" simulator: a build that predates v2 and ONLY knows
  // decryptWithSenderKey (it cannot parse `skey2:`). This is exactly the in-field
  // app version the write-gate must never break.
  const oldClientDecode = (wire, key) => decryptWithSenderKey(wire, key);

  test('flag OFF ⇒ new client writes BYTE-IDENTICAL legacy skey: an OLD client reads', () => {
    const k = generateSenderKey();

    // No opts and explicit flag-off must both produce a `skey:` an old client reads.
    const noOpts = encodeSenderKeyMessage('hello world', k.key, k.keyId);
    const flagOff = encodeSenderKeyMessage('hello world', k.key, k.keyId, { wireV2: false, epoch: 7 });
    expect(noOpts.startsWith('skey:')).toBe(true);
    expect(flagOff.startsWith('skey:')).toBe(true);
    expect(parseSenderKeyEpoch(noOpts)).toBeNull();
    expect(parseSenderKeyEpoch(flagOff)).toBeNull();

    // OLD client (v1-only decode) reads both.
    expect(oldClientDecode(noOpts, k.key)).toBe('hello world');
    expect(oldClientDecode(flagOff, k.key)).toBe('hello world');
  });

  test('OLD client CANNOT parse v2; NEW client dual-read can — proving why the gate stays off pre-rollout', () => {
    const k = generateSenderKey();
    const v2 = encodeSenderKeyMessage('v2 body', k.key, k.keyId, { wireV2: true, epoch: 4 });
    expect(v2.startsWith('skey2:')).toBe(true);

    // The OLD client's v1-only decode REFUSES the v2 prefix → would render
    // "Encrypted message". This is the interop break the flag prevents until all
    // clients ship v2-aware decode.
    expect(oldClientDecode(v2, k.key)).toBeNull();

    // A NEW client dual-reads it fine.
    expect(decodeSenderKeyMessage(v2, k.key)).toBe('v2 body');
    expect(parseSenderKeyEpoch(v2)).toBe(4);
  });

  test('a NEW client reads BOTH wire versions from a mixed-version conversation', () => {
    const k = generateSenderKey();
    const v1 = encryptWithSenderKey('from an old sender', k.key, k.keyId);
    const v2 = encodeSenderKeyMessage('from a new sender', k.key, k.keyId, { wireV2: true, epoch: 2 });
    // Same key (same epoch's distribution), two wire formats on one timeline.
    expect(decodeSenderKeyMessage(v1, k.key)).toBe('from an old sender');
    expect(decodeSenderKeyMessage(v2, k.key)).toBe('from a new sender');
  });

  test('end-to-end with the v2 flag ON, a removed member is still cut off (FS is independent of wire format)', async () => {
    clearOwnKeyMemo();
    const A = makeClient('A'); // sender
    const B = makeClient('B'); // survivor
    const E = makeClient('E'); // removed

    // Epoch 1: A → B + E.
    const k1 = generateSenderKey();
    const dist1 = distributeSenderKey(k1.key, [B, E], A.privateKey);
    const eKey1 = receiveSenderKey(dist1[E.id], A.publicKey, E.privateKey);

    // Epoch 2: E removed → A rotates to B only, and now sends v2 (flag flipped on).
    const r = await rotateOwnKeyForEpoch({
      currentEpoch: 2,
      myCurrentKey: { key: k1.key, keyId: k1.keyId },
      recipients: [B],
      myPrivateKey: A.privateKey,
      wireV2: false, // distribution channel stays classical in jest (no native PQ);
      conversationId: 'gate-on',
    });
    const bKey2 = await openKey(r.distributedKeys, B, A);

    // A sends a v2-framed message under the epoch-2 key.
    const v2msg = encodeSenderKeyMessage('after removal, v2', r.newKey.key, r.newKey.keyId, { wireV2: true, epoch: 2 });
    expect(parseSenderKeyEpoch(v2msg)).toBe(2);

    // B (survivor) reads it; E (only epoch-1 key) is CUT OFF regardless of wire ver.
    expect(decodeSenderKeyMessage(v2msg, bKey2)).toBe('after removal, v2');
    expect(decodeSenderKeyMessage(v2msg, eKey1)).toBeNull(); // CUT OFF
  });
});

describe('senderKeyEpoch-interop — secondary rotation bound (DECISION 4)', () => {
  const T0 = 1_700_000_000_000;

  test('fires at the documented message-count bound under stable membership', () => {
    expect(shouldRotateForSecondaryTrigger({ messagesSinceRotation: MAX_MESSAGES_PER_KEY, keyCreatedAtMs: T0, nowMs: T0 })).toBe(false);
    expect(shouldRotateForSecondaryTrigger({ messagesSinceRotation: MAX_MESSAGES_PER_KEY + 1, keyCreatedAtMs: T0, nowMs: T0 })).toBe(true);
  });

  test('fires at the documented age bound under stable membership', () => {
    expect(shouldRotateForSecondaryTrigger({ messagesSinceRotation: 0, keyCreatedAtMs: T0, nowMs: T0 + MAX_KEY_AGE_MS })).toBe(false);
    expect(shouldRotateForSecondaryTrigger({ messagesSinceRotation: 0, keyCreatedAtMs: T0, nowMs: T0 + MAX_KEY_AGE_MS + 1 })).toBe(true);
  });
});
