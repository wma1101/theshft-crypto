/**
 * Epoch-based Sender Key rotation for group membership changes — KAN-21.
 *
 * WHY THIS EXISTS
 * ---------------
 * Every group member holds their OWN Sender Key (a random 256-bit secretbox key
 * + an 8-byte `keyId`). Today the only membership change that rotates anything is
 * an admin REMOVE, and it rotates only the removing admin's own key
 * (config/database.js:5577). Every other member keeps their existing key until
 * they opportunistically notice the `keyRotationEpoch` bump at chat-open and
 * rotate on their next send. During that window a removed member still holds the
 * old keys and can decrypt any message sent by a not-yet-rotated sender — the
 * confidentiality gap KAN-21 closes.
 *
 * WHAT THIS MODULE IS
 * -------------------
 * The security-critical rotation PRIMITIVE: given a membership change it mints a
 * fresh Sender Key bound to the NEXT epoch and a per-member distribution map that
 * PROVABLY EXCLUDES the removed member(s). It reuses the existing crypto
 * primitives only (no new crypto — per CLAUDE.md "no custom crypto"), and is a
 * pure, side-effect-free unit so it can be unit-tested and crypto-audited in
 * isolation.
 *
 * WHAT THIS MODULE IS NOT (yet)
 * -----------------------------
 * It deliberately does NOT touch the live send/receive path in app/chat.js. The
 * orchestration that makes EVERY remaining member rotate promptly (server-side
 * `keyRotationEpoch` bump on add/leave/kick, a reactive listener instead of the
 * chat-open-only pull, and the ML-KEM-768 wrap of the group distribution) is the
 * device-verified, multi-client rollout that gates merge — tracked in
 * docs/security/crypto-remediation-plan.md. Wiring it in blind would risk
 * breaking group messaging for everyone, so that step is intentionally separate.
 */

import { generateSenderKey, distributeSenderKey, distributeSenderKeyHybrid } from './encryption';

// Secondary in-epoch rotation thresholds (DECISION 4). Bound the exposure window
// of a single Sender Key under STABLE membership (no membership change ⇒ no epoch
// bump, but a long-lived key still wants rotating). These replace the legacy
// shouldRotateSenderKey(>=100) posture: the message threshold rises to the
// documented v1 value and an age dimension is added.
export const MAX_MESSAGES_PER_KEY = 1000; // rotate after >1000 messages on one key
export const MAX_KEY_AGE_MS = 7 * 24 * 60 * 60 * 1000; // ...or after >7 days

// Max archived keys retained locally for decrypting PRE-rotation history. The
// legacy 100-message rotation kept 5; membership-driven rotation can fire far
// more often (every remove/leave/kick), so the ring is widened and made
// explicit. Archived keys are NEVER redistributed — they only open old
// messages — so a deeper ring just trades a little local storage for not
// losing scrollback during membership churn.
export const SENDER_KEY_ARCHIVE_MAX = 20;

// Local helper — normalized, de-duplicated list of removed ids.
const dedupeRemoved = (removedIds) => [...new Set((removedIds || []).filter(Boolean))];

/**
 * THE security-critical guarantee, in one pass. Classifies the CURRENT
 * membership into:
 *   - `recipients`: members who get the new key (not removed, has a publicKey),
 *   - `excluded`:   members that were actually present AND removed (the truthful
 *                   intersection — NOT the caller's requested list, so a ghost
 *                   uid in removedIds can't fake an exclusion),
 *   - `skipped`:    non-removed members we can't address because they have no
 *                   publicKey (a survivor we failed to deliver to — the caller
 *                   must surface/retry, else they silently look "removed").
 * Removed ids are stripped even if a stale/buggy caller leaves them in
 * `currentMembers`; duplicates collapse. Pure — never mutates the input.
 *
 * @param {Array<{id: string, publicKey: string}>} currentMembers
 * @param {string[]} removedIds
 * @returns {{ recipients: Array<{id,publicKey}>, excluded: string[], skipped: string[] }}
 */
export const recipientsForRotation = (currentMembers, removedIds) => {
  const removed = new Set((removedIds || []).filter(Boolean));
  const seen = new Set();
  const recipients = [];
  const excluded = [];
  const skipped = [];
  for (const m of currentMembers || []) {
    if (!m || !m.id) continue;
    if (seen.has(m.id)) continue; // de-dupe
    seen.add(m.id);
    if (removed.has(m.id)) { excluded.push(m.id); continue; } // HARD exclude — the whole point
    if (!m.publicKey) { skipped.push(m.id); continue; } // can't receive an envelope
    recipients.push({ id: m.id, publicKey: m.publicKey });
  }
  return { recipients, excluded, skipped };
};

/**
 * Produce a rotated Sender Key for a membership change. The new key is bound to
 * `prevEpoch + 1` and distributed ONLY to the surviving members.
 *
 * DISPOSAL CONTRACT: the returned `key` is the CLEARTEXT root key (base64). The
 * caller owns its lifetime — persist it (encrypted at rest), distribute it, then
 * overwrite/drop the reference. The duress/panic-wipe path must be able to clear
 * it and `@sender_key_<groupId>` before the next event loop turn. `distributedKeys`
 * values are ciphertext (safe to log/store).
 *
 * @param {Object}   p
 * @param {number}   [p.prevEpoch]     Last known epoch (null/undefined ⇒ 0). MUST
 *                                     be a non-negative integer otherwise — a
 *                                     garbage value throws rather than risk an
 *                                     epoch regression.
 * @param {Array<{id,publicKey}>} p.currentMembers  Recipients (excluding self).
 * @param {string[]} [p.removedIds]    uid(s) being removed (excluded from dist).
 * @param {string}   p.myPrivateKey    Caller's NaCl box private key (base64).
 * @returns {{ epoch:number, keyId:string, key:string, distributedKeys:Object,
 *             recipients:string[], excluded:string[], skipped:string[] }}
 */
export const rotateForMembershipChange = ({
  prevEpoch = 0,
  currentMembers,
  removedIds = [],
  myPrivateKey,
}) => {
  if (!myPrivateKey) {
    throw new Error('rotateForMembershipChange: myPrivateKey required');
  }
  // Epoch must be monotonic. Accept null/undefined as "no prior epoch" (⇒ 0),
  // accept a non-negative integer, but THROW on anything else (negative, float,
  // string, NaN) so a stale/garbage read can't silently regress the epoch.
  let base;
  if (prevEpoch === undefined || prevEpoch === null) {
    base = 0;
  } else if (Number.isInteger(prevEpoch) && prevEpoch >= 0) {
    base = prevEpoch;
  } else {
    throw new Error('rotateForMembershipChange: prevEpoch must be a non-negative integer');
  }
  const epoch = base + 1;

  const { recipients, excluded, skipped } = recipientsForRotation(currentMembers, removedIds);
  const sk = generateSenderKey(); // fresh 256-bit key + random keyId
  const distributedKeys = distributeSenderKey(sk.key, recipients, myPrivateKey);

  // Fail-closed #1: a removed uid must never appear in the envelope map. If it
  // somehow did, abort rather than ship a key the removed member can open.
  for (const rid of dedupeRemoved(removedIds)) {
    if (Object.prototype.hasOwnProperty.call(distributedKeys, rid)) {
      throw new Error(
        'rotateForMembershipChange: removed member present in distribution — aborting',
      );
    }
  }
  // Fail-closed #2: every intended recipient must have actually received an
  // envelope. distributeSenderKey silently drops a member whose publicKey fails
  // to encrypt (malformed key) — a survivor missing the new key would look
  // "removed" to them at next chat-open. Surface it as an error, not a silent
  // partial rotation.
  const missing = recipients
    .map((r) => r.id)
    .filter((id) => !Object.prototype.hasOwnProperty.call(distributedKeys, id));
  if (missing.length) {
    throw new Error(
      `rotateForMembershipChange: failed to encrypt the new key for ${missing.length} recipient(s)`,
    );
  }

  return {
    epoch,
    keyId: sk.keyId,
    key: sk.key,
    distributedKeys,
    recipients: recipients.map((r) => r.id),
    excluded, // members that ACTUALLY existed and were dropped (∩, not requested)
    skipped, // survivors we couldn't address (no publicKey) — caller must retry
  };
};

/**
 * Append a just-rotated-away key to an archive ring (most-recent-first), capped
 * at SENDER_KEY_ARCHIVE_MAX, de-duplicated by keyId. Feed the result to
 * encryption.decryptWithKeyChain so PRE-rotation messages stay readable.
 *
 * @param {Array<{key,keyId}>} archive
 * @param {{key:string, keyId:string}|null} oldKey
 * @returns {Array<{key:string, keyId:string}>}
 */
export const archiveKey = (archive, oldKey) => {
  // Drop malformed entries up front so they can't pollute decryptWithKeyChain.
  const ring = Array.isArray(archive) ? archive.filter((k) => k && k.key && k.keyId) : [];
  if (oldKey && oldKey.key && oldKey.keyId) {
    const existing = ring.find((k) => k.keyId === oldKey.keyId);
    if (existing) {
      // Same keyId, DIFFERENT key bytes = a (vanishingly rare) 64-bit keyId
      // collision. Fail LOUD rather than silently keep one and lose every
      // message encrypted under the other.
      if (existing.key !== oldKey.key) {
        throw new Error('archiveKey: keyId collision with differing key bytes');
      }
      // exact duplicate → no-op
    } else {
      ring.unshift({ key: oldKey.key, keyId: oldKey.keyId });
    }
  }
  return ring.slice(0, SENDER_KEY_ARCHIVE_MAX);
};

/**
 * Join-epoch gate (DECISION 3). Returns true ONLY when BOTH arguments are
 * non-negative integers AND `messageEpoch < myJoinedEpoch` — i.e. the message was
 * sent under an epoch the reader joined AFTER, so it is pre-join history the
 * reader is not entitled to.
 *
 * FAIL-OPEN by construction (never blackhole a legitimate message during rollout):
 *   - messageEpoch === null  ⇒ legacy v1 message, epoch unknown ⇒ return false.
 *   - myJoinedEpoch null/absent ⇒ legacy member doc (no joinedEpoch stamped) ⇒
 *     return false.
 *   - either value not a non-negative integer ⇒ return false.
 * Active only on the v2 read path; never throws.
 *
 * @param {number|null} messageEpoch    parseSenderKeyEpoch(text) output
 * @param {number|null} myJoinedEpoch   cached members[myUid].joinedEpoch
 * @returns {boolean}  true ⇒ REJECT (render as 'Encrypted message', store no plaintext)
 */
export const shouldRejectByJoinEpoch = (messageEpoch, myJoinedEpoch) => {
  if (!Number.isInteger(messageEpoch) || messageEpoch < 0) return false; // unknown ⇒ never reject
  if (!Number.isInteger(myJoinedEpoch) || myJoinedEpoch < 0) return false; // legacy doc ⇒ never reject
  return messageEpoch < myJoinedEpoch;
};

/**
 * Secondary in-epoch rotation predicate (DECISION 4). Returns true when the
 * current Sender Key has been used for MORE THAN MAX_MESSAGES_PER_KEY messages OR
 * is OLDER THAN MAX_KEY_AGE_MS. Bounds in-epoch exposure under stable membership.
 *
 * Strict `>` (not `>=`) so the Nth message under a key (N === threshold) still
 * sends under it and the (N+1)th triggers the rotation — symmetric with how the
 * counter is read just before a send. Missing/garbage inputs ⇒ false (never force
 * a rotation on bad telemetry).
 *
 * @param {Object} p
 * @param {number} p.messagesSinceRotation  count of messages sent under the live key
 * @param {number} p.keyCreatedAtMs         epoch-ms the live key was minted (@sk_key_created)
 * @param {number} [p.nowMs]                injectable clock (defaults to Date.now())
 * @returns {boolean}
 */
export const shouldRotateForSecondaryTrigger = ({ messagesSinceRotation, keyCreatedAtMs, nowMs }) => {
  const now = Number.isFinite(nowMs) ? nowMs : Date.now();
  if (Number.isFinite(messagesSinceRotation) && messagesSinceRotation > MAX_MESSAGES_PER_KEY) {
    return true;
  }
  if (Number.isFinite(keyCreatedAtMs) && keyCreatedAtMs > 0 && (now - keyCreatedAtMs) > MAX_KEY_AGE_MS) {
    return true;
  }
  return false;
};

// ──────────────────────────────────────────────────────────────────────────
// rotateOwnKeyForEpoch — per-sender "rotate MY own key to the current epoch"
// ──────────────────────────────────────────────────────────────────────────
//
// IDEMPOTENCY (design-review must-fix: PERSISTENCE SPLIT + ROTATE-BEFORE-SEND RACE).
// The CALLER persists @sk_rotated_epoch_<conv> and skips when currentEpoch<=that.
// But two concurrent callers (a reactive-listener tick + a send) can BOTH observe
// serverEpoch>rotatedEpoch before either persists the marker — and a naive pure
// function would mint TWO DIFFERENT keys for the same epoch, orphaning whichever
// envelope loses the race (the removed member could then keep decrypting under the
// orphaned old key). We close this with an IN-MEMORY per-(conversation,epoch) memo:
// the FIRST call for a given (conversationId, currentEpoch) mints the key and caches
// the full result; every concurrent/subsequent re-entry for the SAME pair returns
// the SAME minted key + the SAME distributedKeys map. A given epoch's own-key is
// minted EXACTLY ONCE per process, so re-entry is a true no-op and there is never an
// orphaned envelope. (The caller's @sk_rotated_epoch marker remains the cross-process
// / persisted guard; this memo is the within-process concurrency guard the marker
// cannot provide because it is only set AFTER a rotation completes.)
//
// Retry-after-partial-failure stays SAFE: on re-entry we re-run distribution to any
// recipients still missing from the cached distributedKeys (e.g. a survivor who was
// in failed[] last time) USING THE SAME cached key, merge the new envelopes in, and
// recompute failed[]. The key never changes, so a late-delivered envelope opens the
// same messages as the originals — no orphaning.

const _ownKeyMemo = new Map(); // key: `${conversationId} ${epoch}` → cached result

const _memoKey = (conversationId, epoch) => `${conversationId || ''} ${epoch}`;

/**
 * Clear the in-memory own-key memo for a conversation (or all of it). The caller
 * should drop the memo for a conversation when it leaves the chat / signs out /
 * panic-wipes, so a stale minted key can't linger in memory. Pure bookkeeping.
 *
 * @param {string} [conversationId]  omit ⇒ clear the entire memo
 */
export const clearOwnKeyMemo = (conversationId) => {
  if (conversationId === undefined) { _ownKeyMemo.clear(); return; }
  const prefix = `${conversationId} `;
  for (const k of _ownKeyMemo.keys()) {
    if (k.startsWith(prefix)) _ownKeyMemo.delete(k);
  }
};

// Distribute the (already-minted) key to recipients, classical vs hybrid by flag.
// Returns { distributed, failed }. distributeSenderKey is sync and never reports
// per-recipient failures, so for the classical path we derive failed[] from the
// recipients that did not land an envelope (mirrors distributeSenderKeyHybrid).
const _distributeOwnKey = async (keyB64, recipients, myPrivateKey, wireV2) => {
  if (wireV2) {
    // PQ-hybrid `pqsk1:` envelopes (already returns {distributed, failed}).
    return distributeSenderKeyHybrid(keyB64, recipients, myPrivateKey);
  }
  // Legacy classical `naclp:` envelopes.
  const distributed = distributeSenderKey(keyB64, recipients, myPrivateKey) || {};
  const failed = recipients
    .filter((r) => r && r.id)
    .map((r) => r.id)
    .filter((id) => !Object.prototype.hasOwnProperty.call(distributed, id));
  return { distributed, failed };
};

/**
 * The "rotate MY own key for the current epoch" orchestrator the chat path calls:
 *   - REACTIVELY when it observes a higher server `keyRotationEpoch`, and
 *   - as ROTATE-BEFORE-SEND (idempotent re-check) right before encrypting.
 *
 * Mints a fresh Sender Key bound to `currentEpoch`, archives `myCurrentKey` (via
 * archiveKey, returned as `archivedOldKey` for the caller to persist into
 * @sk_archive_<conv>), and distributes ONLY to `recipients` — hybrid `pqsk1:`
 * envelopes when `wireV2===true`, else classical `naclp:`. Idempotent per
 * (conversationId, currentEpoch) via an in-memory memo (see block comment above):
 * concurrent/repeat calls return the SAME key and the SAME distribution, so a
 * given epoch's own-key is minted exactly once and no envelope is ever orphaned.
 *
 * This fn does NOT exclude removed members and does NOT bump the epoch — the
 * SERVER bumps `keyRotationEpoch`, and `recipients` is ALREADY the post-membership
 * -change survivor list the caller fetched from the freshly-read participants
 * (the removed member is simply absent from it). It does NOT persist anything;
 * the caller owns @sender_key/@sk_archive/@sk_rotated_epoch/the senderKeys doc.
 *
 * DISPOSAL: `newKey.key` is the CLEARTEXT root key (base64). The caller owns its
 * lifetime (persist encrypted-at-rest, distribute, then drop). `distributedKeys`
 * values are ciphertext (safe to log/store).
 *
 * @param {Object} p
 * @param {number} p.currentEpoch   server keyRotationEpoch (non-negative integer)
 * @param {{key:string,keyId:string}|null} p.myCurrentKey  key to archive (or null)
 * @param {Array<{id:string,publicKey:string,pqPublicKey?:string}>} p.recipients  survivors (excluding self)
 * @param {string} p.myPrivateKey   caller's Curve25519 private key (base64)
 * @param {boolean} p.wireV2        true ⇒ hybrid distribution, false ⇒ classical
 * @param {string} [p.conversationId]  memo scope (STRONGLY recommended — without it
 *                                     the memo cannot distinguish conversations)
 * @returns {Promise<{ epoch:number, newKey:{key:string,keyId:string},
 *   distributedKeys:Object, archivedOldKey:{key:string,keyId:string}|null,
 *   failed:string[] }>}
 */
export const rotateOwnKeyForEpoch = async ({
  currentEpoch,
  myCurrentKey,
  recipients,
  myPrivateKey,
  wireV2 = false,
  conversationId,
}) => {
  if (!myPrivateKey) {
    throw new Error('rotateOwnKeyForEpoch: myPrivateKey required');
  }
  if (!Number.isInteger(currentEpoch) || currentEpoch < 0) {
    throw new Error('rotateOwnKeyForEpoch: currentEpoch must be a non-negative integer');
  }
  const recips = Array.isArray(recipients) ? recipients.filter((r) => r && r.id && r.publicKey) : [];

  const memoId = _memoKey(conversationId, currentEpoch);
  const cached = _ownKeyMemo.get(memoId);

  if (cached) {
    // Re-entry for the SAME (conversation, epoch): reuse the SAME minted key so no
    // envelope is ever orphaned. Opportunistically retry distribution to any
    // recipient still missing an envelope (e.g. a survivor that previously failed),
    // merging new envelopes into the cached map under the unchanged key.
    const missing = recips.filter(
      (r) => !Object.prototype.hasOwnProperty.call(cached.distributedKeys, r.id),
    );
    if (missing.length) {
      const { distributed: extra } = await _distributeOwnKey(
        cached.newKey.key, missing, myPrivateKey, wireV2,
      );
      for (const id of Object.keys(extra)) cached.distributedKeys[id] = extra[id];
    }
    // Recompute failed[] against the CURRENT recipient set (a recipient now
    // delivered drops off; a still-missing one stays).
    cached.failed = recips
      .map((r) => r.id)
      .filter((id) => !Object.prototype.hasOwnProperty.call(cached.distributedKeys, id));
    return {
      epoch: cached.epoch,
      newKey: cached.newKey,
      distributedKeys: cached.distributedKeys,
      archivedOldKey: cached.archivedOldKey,
      failed: cached.failed.slice(),
    };
  }

  // FIRST mint for this (conversation, epoch). Mint the key and RESERVE the memo
  // slot SYNCHRONOUSLY — before the first `await` (distribution) yields — so a
  // concurrent caller that runs between this point and the distribution await
  // sees `cached` and converges on THIS key instead of minting a second one. This
  // is what makes "exactly one key per epoch" hold under JS's run-to-completion
  // model: nothing else executes between the `cached` check above and this set.
  const sk = generateSenderKey(); // fresh 256-bit key + random keyId
  const newKey = { key: sk.key, keyId: sk.keyId };
  const archivedOldKey = (myCurrentKey && myCurrentKey.key && myCurrentKey.keyId)
    ? { key: myCurrentKey.key, keyId: myCurrentKey.keyId }
    : null;
  const entry = {
    epoch: currentEpoch,
    newKey,
    distributedKeys: {},
    archivedOldKey,
    failed: recips.map((r) => r.id), // until distribution lands, all are undelivered
  };
  _ownKeyMemo.set(memoId, entry); // reserve synchronously — concurrency guard

  // Distribute (async). Mutate the SAME cached entry so a concurrent re-entry that
  // already grabbed `entry` observes the envelopes as they land.
  const { distributed, failed } = await _distributeOwnKey(newKey.key, recips, myPrivateKey, wireV2);
  for (const id of Object.keys(distributed)) entry.distributedKeys[id] = distributed[id];
  entry.failed = failed;

  return {
    epoch: entry.epoch,
    newKey: entry.newKey,
    distributedKeys: entry.distributedKeys,
    archivedOldKey: entry.archivedOldKey,
    failed: entry.failed.slice(),
  };
};
