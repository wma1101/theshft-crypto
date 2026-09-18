/**
 * PQ-hybrid Sender Key distribution (group PQ gap — residual weakness #2).
 *
 * distributeSenderKeyHybrid / receiveSenderKeyHybrid wrap the group Sender Key
 * under HKDF(0xFF×32 ‖ X25519_shared ‖ [ML-KEM_shared]) — the same KEM-combiner
 * the 1:1 X3DH path uses. Breaking X25519 alone (e.g. a future quantum attacker)
 * is insufficient: the wrap key also needs the ML-KEM-768 shared secret.
 *
 * Native ML-KEM may be absent in a bare jest runner. Mirroring x3dh-pq.test.js,
 * we PROBE for it — but as of the 2026-07-25 audit an absent backend FAILS the
 * PQ tests instead of skipping them (see the PQ COVERAGE GATE note below).
 * The classical fallback + round-trip + tamper/negative tests always run; the
 * PQ branch + downgrade resistance need a runner with the native module
 * (device/simulator build). PQ_TESTS_OPTIONAL=1 restores skip behaviour and
 * records, explicitly, that the run covers no PQ code.
 */

const nacl = require('tweetnacl');
const { encodeBase64 } = require('tweetnacl-util');
const {
  generateSenderKey,
  distributeSenderKey,
  distributeSenderKeyHybrid,
  receiveSenderKeyHybrid,
  receiveSenderKeyAny,
  pqGenerateKeyPair,
} = require('../config/encryption');

function classicalMember(id) {
  const kp = nacl.box.keyPair();
  return { id, publicKey: encodeBase64(kp.publicKey), privateKey: encodeBase64(kp.secretKey) };
}

// ---------------------------------------------------------------------------
// PQ COVERAGE GATE (audit 2026-07-25) — kept in lockstep with x3dh-pq.test.js.
//
// WHY this exists: the group PQ-hybrid wrap is half of theSHFT's post-quantum
// claim, and every test that proves it lives behind `_pqTest`. Availability is
// probed by asking for a real keypair — config/encryption.js `pqGenerateKeyPair`
// loads modules/native-crypto, which calls requireNativeModule('NativeCrypto')
// and only resolves inside an actual iOS/Android build. Under bare jest the
// probe therefore ALWAYS fails, every PQ test was skipped, and the suite still
// reported green. A skip is not coverage. Missing ML-KEM now fails the suite.
//
// Two distinct defects are fixed here, not one:
//   1. `pqAvailable ? test(...) : test.skip(...)` was evaluated while jest was
//      REGISTERING the describe body, which happens before any beforeAll hook
//      runs. `pqAvailable` was still `undefined` at that moment, so the ternary
//      picked `test.skip` UNCONDITIONALLY — these tests could never execute,
//      not even on a runner that DOES have the native module. Registration now
//      keys off PQ_TESTS_OPTIONAL (readable synchronously at registration
//      time); the availability check moved inside the test body.
//   2. An unavailable PQ backend failed nothing. Now it fails loudly.
//
// Opt-out: PQ_TESTS_OPTIONAL=1 restores skip behaviour for a runner that
// genuinely cannot host the native module — a deliberate, greppable act.
const PQ_TESTS_OPTIONAL = process.env.PQ_TESTS_OPTIONAL === '1';

const PQ_UNAVAILABLE_MESSAGE = [
  'ML-KEM-768 is NOT available in this jest environment, so this test exercised nothing.',
  '',
  'pqGenerateKeyPair() returned null: config/encryption.js loads modules/native-crypto,',
  "which calls requireNativeModule('NativeCrypto') and only resolves inside a real",
  'iOS/Android build. Under bare jest there is no ML-KEM implementation at all.',
  '',
  'This failure is DELIBERATE. The post-quantum layer is the app\'s headline security',
  'claim; a green suite that silently skipped it was worse than a red one, because it',
  'was read as coverage.',
  '',
  'Resolve it one of two ways:',
  '  (a) run this file on a runner that has the native module (device/simulator build), or',
  '  (b) set PQ_TESTS_OPTIONAL=1 to record, explicitly, that this run proves nothing',
  '      about ML-KEM-768.',
].join('\n');

/**
 * Assert the native ML-KEM backend was reachable. Called from every PQ test
 * body and from the standalone gate test so that no PQ assertion can pass — or
 * quietly vanish — without a working backend behind it.
 */
const _assertPqAvailable = (pqAvailable) => {
  if (!pqAvailable) throw new Error(PQ_UNAVAILABLE_MESSAGE);
};

// Swap one base64 char in a chosen field of a pqsk1 envelope (tamper helper).
function tamperField(envelope, idx) {
  const parts = envelope.split(':');
  const f = parts[idx];
  const flipped = (f[0] === 'A' ? 'B' : 'A') + f.slice(1);
  parts[idx] = flipped;
  return parts.join(':');
}

describe('senderKeyHybrid — classical path (always runs)', () => {
  jest.setTimeout(60000);

  test('round-trips the Sender Key for a member without a PQ key (classical-only envelope)', async () => {
    const sk = generateSenderKey();
    const sender = classicalMember('sender');
    const bob = classicalMember('bob');

    const { distributed, failed } = await distributeSenderKeyHybrid(
      sk.key, [{ id: 'bob', publicKey: bob.publicKey }], sender.privateKey,
    );
    expect(failed).toEqual([]);
    expect(typeof distributed.bob).toBe('string');
    expect(distributed.bob.startsWith('pqsk1::')).toBe(true); // empty kemCt ⇒ classical-only

    const got = await receiveSenderKeyHybrid(distributed.bob, sender.publicKey, bob.privateKey, null);
    expect(got).toBe(sk.key);
  });

  test('a non-recipient (wrong private key) cannot open the envelope', async () => {
    const sk = generateSenderKey();
    const sender = classicalMember('sender');
    const bob = classicalMember('bob');
    const eve = classicalMember('eve');

    const { distributed } = await distributeSenderKeyHybrid(
      sk.key, [{ id: 'bob', publicKey: bob.publicKey }], sender.privateKey,
    );
    const got = await receiveSenderKeyHybrid(distributed.bob, sender.publicKey, eve.privateKey, null);
    expect(got).toBeNull();
  });

  test('tampered ciphertext / nonce is rejected (Poly1305)', async () => {
    const sk = generateSenderKey();
    const sender = classicalMember('sender');
    const bob = classicalMember('bob');
    const { distributed } = await distributeSenderKeyHybrid(
      sk.key, [{ id: 'bob', publicKey: bob.publicKey }], sender.privateKey,
    );
    // parts: [pqsk1, kemCt='', nonce, ct]
    expect(await receiveSenderKeyHybrid(tamperField(distributed.bob, 3), sender.publicKey, bob.privateKey, null)).toBeNull();
    expect(await receiveSenderKeyHybrid(tamperField(distributed.bob, 2), sender.publicKey, bob.privateKey, null)).toBeNull();
  });

  test('malformed / wrong-magic / wrong-arity envelopes return null, never throw', async () => {
    const m = classicalMember('m');
    expect(await receiveSenderKeyHybrid('not-an-envelope', m.publicKey, m.privateKey, null)).toBeNull();
    expect(await receiveSenderKeyHybrid('pqsk2:a:b:c', m.publicKey, m.privateKey, null)).toBeNull(); // wrong magic
    expect(await receiveSenderKeyHybrid('pqsk1:onlyonepart', m.publicKey, m.privateKey, null)).toBeNull();
    expect(await receiveSenderKeyHybrid('pqsk1::n:c:extra', m.publicKey, m.privateKey, null)).toBeNull(); // 5 parts
    expect(await receiveSenderKeyHybrid(null, m.publicKey, m.privateKey, null)).toBeNull();
  });

  test('empty members ⇒ empty result; a member missing publicKey ⇒ reported failed', async () => {
    const sender = classicalMember('sender');
    const sk = generateSenderKey();
    // The return carries coverage as of 2026-08-29: callers must be able to
    // SEE that a member got no PQ rather than infer it from the `pqsk1:`
    // prefix, which is emitted either way.
    const empty = await distributeSenderKeyHybrid(sk.key, [], sender.privateKey);
    expect(empty.distributed).toEqual({});
    expect(empty.failed).toEqual([]);
    // No members is not coverage. It must not read as "everyone is protected".
    expect(empty.pqCovered).toBe(false);
    const r = await distributeSenderKeyHybrid(sk.key, [{ id: 'no-key' }], sender.privateKey);
    expect(r.distributed).toEqual({});
    expect(r.failed).toEqual(['no-key']);
    // A member rejected for a missing publicKey never reaches the PQ branch,
    // so they are `failed`, not `classicalOnly`.
    expect(r.classicalOnly).toEqual([]);
  });

  test('an all-zero / low-order member publicKey is rejected (not silently keyed to a constant)', async () => {
    const sender = classicalMember('sender');
    const sk = generateSenderKey();
    const zeroPub = encodeBase64(new Uint8Array(32)); // low-order point → zero shared secret
    const r = await distributeSenderKeyHybrid(sk.key, [{ id: 'z', publicKey: zeroPub }], sender.privateKey);
    expect(r.failed).toEqual(['z']);
    expect(r.distributed).toEqual({});
  });
});

describe('receiveSenderKeyAny — dual-read (KAN-21 #2 rollout)', () => {
  test('reads a legacy classical (naclp) envelope', async () => {
    const sk = generateSenderKey();
    const sender = classicalMember('sender');
    const bob = classicalMember('bob');
    const naclpEnv = distributeSenderKey(sk.key, [{ id: 'bob', publicKey: bob.publicKey }], sender.privateKey).bob;
    expect(naclpEnv.startsWith('naclp:')).toBe(true);
    expect(await receiveSenderKeyAny(naclpEnv, sender.publicKey, bob.privateKey, null)).toBe(sk.key);
  });

  test('reads a hybrid (pqsk1) envelope', async () => {
    const sk = generateSenderKey();
    const sender = classicalMember('sender');
    const bob = classicalMember('bob');
    const { distributed } = await distributeSenderKeyHybrid(
      sk.key, [{ id: 'bob', publicKey: bob.publicKey }], sender.privateKey,
    );
    expect(distributed.bob.startsWith('pqsk1:')).toBe(true);
    expect(await receiveSenderKeyAny(distributed.bob, sender.publicKey, bob.privateKey, null)).toBe(sk.key);
  });

  test('returns null for a malformed pqsk1 envelope (hybrid path)', async () => {
    const m = classicalMember('m');
    expect(await receiveSenderKeyAny('pqsk1:bad', m.publicKey, m.privateKey, null)).toBeNull();
  });
});

describe('senderKeyHybrid — PQ path (native ML-KEM only)', () => {
  jest.setTimeout(60000);

  // Set by the probe in beforeAll. Read only from INSIDE test bodies — it is
  // still `undefined` while jest registers this describe block (see the PQ
  // COVERAGE GATE note above; that timing bug is what made every PQ test skip
  // unconditionally).
  let pqAvailable;

  // Registration-time decision: with the opt-out set, PQ tests are reported as
  // skipped; otherwise they are REAL tests whose bodies fail with
  // PQ_UNAVAILABLE_MESSAGE when no native ML-KEM backend answered the probe.
  const _pqTest = (name, fn) => (
    PQ_TESTS_OPTIONAL
      ? test.skip(name, fn)
      : test(name, async () => {
        _assertPqAvailable(pqAvailable);
        return fn();
      })
  );

  beforeAll(async () => {
    const probe = await pqGenerateKeyPair().catch(() => null);
    pqAvailable = !!(probe && probe.publicKey && probe.privateKey);
  });

  // Always-registered gate. Gives ONE crisp, self-explaining failure when the
  // runner has no ML-KEM backend, instead of a wall of skipped test names that
  // reads like success — and guarantees this describe always has a non-skipped
  // test, so `beforeAll` (and the probe) runs even under PQ_TESTS_OPTIONAL.
  test('ML-KEM-768 native backend is reachable from this test runner', () => {
    if (PQ_TESTS_OPTIONAL) {
      console.warn(
        'PQ_TESTS_OPTIONAL=1 — ML-KEM-768 tests were SKIPPED. This run proves nothing about the post-quantum layer.',
      );
      // Assert only that the probe actually ran; the opt-out must not fail a
      // runner that DOES have the backend, it just stops demanding one.
      expect(typeof pqAvailable).toBe('boolean');
      return;
    }
    _assertPqAvailable(pqAvailable);
    expect(pqAvailable).toBe(true);
  });

  _pqTest('hybrid round-trip carries a ML-KEM ciphertext and recovers the key', async () => {
    const sk = generateSenderKey();
    const sender = classicalMember('sender');
    const carol = classicalMember('carol');
    const carolPq = await pqGenerateKeyPair();

    const { distributed } = await distributeSenderKeyHybrid(
      sk.key, [{ id: 'carol', publicKey: carol.publicKey, pqPublicKey: carolPq.publicKey }], sender.privateKey,
    );
    expect(distributed.carol.split(':')[1].length).toBeGreaterThan(0); // kemCt present ⇒ PQ branch ran

    const got = await receiveSenderKeyHybrid(distributed.carol, sender.publicKey, carol.privateKey, carolPq.privateKey);
    expect(got).toBe(sk.key);
  });

  _pqTest('downgrade resistance: a PQ envelope cannot be opened without the PQ private key', async () => {
    const sk = generateSenderKey();
    const sender = classicalMember('sender');
    const carol = classicalMember('carol');
    const carolPq = await pqGenerateKeyPair();

    const { distributed } = await distributeSenderKeyHybrid(
      sk.key, [{ id: 'carol', publicKey: carol.publicKey, pqPublicKey: carolPq.publicKey }], sender.privateKey,
    );
    expect(await receiveSenderKeyHybrid(distributed.carol, sender.publicKey, carol.privateKey, null)).toBeNull();
  });

  _pqTest('the ML-KEM secret is load-bearing: wrong PQ key → cannot recover even with the right X25519 key', async () => {
    const sk = generateSenderKey();
    const sender = classicalMember('sender');
    const carol = classicalMember('carol');
    const carolPq = await pqGenerateKeyPair();
    const wrongPq = await pqGenerateKeyPair();

    const { distributed } = await distributeSenderKeyHybrid(
      sk.key, [{ id: 'carol', publicKey: carol.publicKey, pqPublicKey: carolPq.publicKey }], sender.privateKey,
    );
    const got = await receiveSenderKeyHybrid(distributed.carol, sender.publicKey, carol.privateKey, wrongPq.privateKey);
    expect(got).toBeNull();
  });
});

// ---------------------------------------------------------------------------
// AUDIT 2026-08-29 — coverage is an AND, not an average.
//
// Every member of a group receives the SAME sender key. So an attacker who
// breaks one classical envelope holds the key to every message in that group,
// no matter how many other envelopes carried a real ML-KEM encapsulation.
// pqCovered has to mean "all of them", and mixed groups must report false or
// the caller will emit `pqsk1:` and believe the group is post-quantum.
// ---------------------------------------------------------------------------
describe('pqCovered is an AND over every recipient', () => {
  // These need no native ML-KEM: the no-PQ-key branch is pure JS, and it is
  // the branch that decides whether a group may claim to be post-quantum.
  test('a member with NO pqPublicKey is named, and coverage is false', async () => {
    const sender = classicalMember('sender');
    const sk = generateSenderKey();
    const r = await distributeSenderKeyHybrid(
      sk.key, [classicalMember('nopq')], sender.privateKey);
    expect(r.classicalOnly).toEqual(['nopq']);
    expect(r.pqCovered).toBe(false);
    // They still get an envelope: nobody is locked out of the group over this.
    expect(Object.keys(r.distributed)).toEqual(['nopq']);
  });

  test('ONE uncovered member makes the whole group uncovered', async () => {
    // The property that matters. Every member shares the SAME sender key, so
    // breaking one classical envelope yields every message in the group. A
    // ratio would be the wrong summary; this has to be an AND.
    const sender = classicalMember('sender');
    const sk = generateSenderKey();
    const members = ['a', 'b', 'c'].map(classicalMember);
    const r = await distributeSenderKeyHybrid(sk.key, members, sender.privateKey);
    expect(r.classicalOnly.sort()).toEqual(['a', 'b', 'c']);
    expect(r.pqCovered).toBe(false);
  });

  test('the uncovered envelope is still PQ-SHAPED, which is why the flag exists', async () => {
    const sender = classicalMember('sender');
    const sk = generateSenderKey();
    const r = await distributeSenderKeyHybrid(
      sk.key, [classicalMember('nopq')], sender.privateKey);
    // `pqsk1:` with an EMPTY KEM segment. Anything that reads the wire format
    // to decide "is this group post-quantum" gets the wrong answer, which is
    // exactly why callers must read pqCovered instead of the prefix.
    expect(r.distributed.nopq.startsWith('pqsk1::')).toBe(true);
  });

  test('no members at all is not coverage', async () => {
    const sender = classicalMember('sender');
    const sk = generateSenderKey();
    const r = await distributeSenderKeyHybrid(sk.key, [], sender.privateKey);
    // Must not read as "everyone is protected" when there is nobody.
    expect(r.pqCovered).toBe(false);
  });
});
