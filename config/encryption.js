/**
 * theSHFT E2E Encryption Module
 *
 * Uses TweetNaCl (Curve25519-XSalsa20-Poly1305) for real end-to-end encryption.
 * - Key exchange: Curve25519 Diffie-Hellman
 * - Encryption: XSalsa20 stream cipher
 * - Authentication: Poly1305 MAC (tamper-proof)
 * - Each message gets a unique random nonce (24 bytes)
 *
 * Messages are encrypted on the sender's device and can ONLY be decrypted
 * by the intended recipient. Firebase never sees plaintext.
 */
import AsyncStorage from '@react-native-async-storage/async-storage';
import nacl from 'tweetnacl';
import {
  encodeUTF8, decodeUTF8,
  encodeBase64, decodeBase64,
} from 'tweetnacl-util';
// Platform is read only to pick the PBKDF2 backend (WebCrypto on web, native
// quick-crypto elsewhere). babel-preset-expo inlines Platform.OS on web, so the
// native branch is pruned from the browser bundle. Added 2026-09-16 (P2-C).
import { Platform } from 'react-native';
import { traces, endTrace } from './perfTracing';
import { WEB_DEV_PHRASE_RESTORE } from './environment';

// ============================================
// WEB IDENTITY GUARD (2026-09-16, P2-E)
// ============================================
// A web build never derives, stores or restores a recovery phrase. The
// browser is a linked device in the product and the phone is the identity
// root (docs/multi-device-linking-design.md section 2): the phrase, the
// identity private key and the duress PIN live on the phone only. This is
// enforced HERE, at the functions that would derive or hold the phrase, and
// not only on the screens, because every public route is reachable by URL and
// a screen guard alone would leave the derivation one pasted path away.
//
// The one exception is the staging dev bring-up flag (config/environment.js
// WEB_DEV_PHRASE_RESTORE): inlined at bundle time, never true in production,
// it lets a developer restore a throwaway staging account in a browser before
// the link flow exists. With it set, every function below behaves exactly as
// on a phone. babel-preset-expo inlines Platform.OS on web, so on native the
// predicate is a constant false and the guard costs nothing.
//
// PIN hashing and verification are deliberately NOT guarded: a linked browser
// keeps its own local PIN (hashPin/verifyUnlockPin through the WebCrypto
// PBKDF2 branch and config/secureStoreWeb.js).
const WEB_PHRASE_BLOCKED = Platform.OS === 'web' && !WEB_DEV_PHRASE_RESTORE;
export const WEB_PHRASE_GUARD_MESSAGE =
  'A web build never derives, stores or restores a recovery phrase. Link this browser from your phone instead.';
/** True when this bundle is a web build without the staging dev flag. */
export const isWebPhraseBlocked = () => WEB_PHRASE_BLOCKED;
const refuseWebPhrase = (op) => {
  console.log(`[web identity guard] ${op} refused. ${WEB_PHRASE_GUARD_MESSAGE}`);
};

// Secure storage keys (prefixed to avoid conflicts)
// Keychain labels use generic names to avoid revealing the app's purpose
// during forensic analysis. A Keychain dump showing "_cp_1" is meaningless;
// "_secure_shift_encryption_key" immediately reveals an encryption app.
// Legacy keys are checked as fallback for migration from older versions.
const SECURE_KEYS = {
  ENCRYPTION_KEY: '_cp_1',
  USER_PIN: '_cp_2',
  USER_PIN_SALT: '_cp_3',
  RECOVERY_PHRASE: '_cp_4',
  DURESS_PIN: '_cp_5',
  DURESS_PIN_SALT: '_cp_6',
  PRIVATE_KEY: '_cp_7',
  PUBLIC_KEY: '_cp_8',
  PQ_PUBLIC_KEY: '_cp_9',
  PQ_PRIVATE_KEY: '_cp_10',
  RATCHET_STORAGE_KEY: '_cp_11',
  // PIN KDF version markers. These used to be stored under the literal
  // names 'PIN_VERSION' / 'DURESS_PIN_VERSION', which violated the
  // generic-naming rule stated at the top of this file AND — worse — a
  // surviving 'DURESS_PIN_VERSION' item proved to anyone dumping the
  // Keychain that a duress PIN had been configured, i.e. that the wipe a
  // coercer just watched was deliberate rather than an empty phone. They
  // are now generic and, because they live in SECURE_KEYS, they are
  // removed by clearSecureStorage like every other secret.
  // Migration: the old literal names are listed in LEGACY_SECURE_KEYS, so
  // safeSecureStoreGet transparently reads the legacy item, rewrites it
  // under the generic name and DELETES the revealing one on first read.
  PIN_VERSION: '_cp_12',
  DURESS_PIN_VERSION: '_cp_13',
  // Index of identity ids (uids) that have per-identity Keychain items
  // ('_identity_phrase_<uid>' / '_identity_pin_<uid>', written by
  // config/storage.js saveIdentityPhrase). expo-secure-store cannot
  // enumerate the Keychain, and every wipe path clears AsyncStorage BEFORE
  // clearing the Keychain — so without this index clearSecureStorage has no
  // way to learn which per-identity items exist and the plaintext recovery
  // phrase survives panic/duress/remote wipe. Contains no secret material
  // (the uid is already visible in the item names it points at) and is
  // itself wiped by clearSecureStorage.
  IDENTITY_INDEX: '_cp_14',
};

// Legacy key names for migration from older versions
const LEGACY_SECURE_KEYS = {
  ENCRYPTION_KEY: '@secure_shift_encryption_key',
  USER_PIN: '@secure_shift_user_pin',
  USER_PIN_SALT: '@secure_shift_user_pin_salt',
  RECOVERY_PHRASE: '@secure_shift_recovery_phrase',
  DURESS_PIN: '@secure_shift_duress_pin',
  DURESS_PIN_SALT: '@secure_shift_duress_pin_salt',
  PRIVATE_KEY: '@secure_shift_private_key',
  PUBLIC_KEY: '@secure_shift_public_key',
  PQ_PUBLIC_KEY: '@pq_public_key',
  PQ_PRIVATE_KEY: '@pq_private_key',
  RATCHET_STORAGE_KEY: '@secure_shift_ratchet_storage_key',
  // Pre-_cp_ names for the PIN KDF version markers (see SECURE_KEYS above).
  // Reading through safeSecureStoreGet migrates + deletes these.
  PIN_VERSION: 'PIN_VERSION',
  DURESS_PIN_VERSION: 'DURESS_PIN_VERSION',
};

// ============================================
// SECURE STORAGE (expo-secure-store with AsyncStorage fallback)
// ============================================

// Try to load expo-secure-store; null if unavailable
let SecureStore = null;
try {
  SecureStore = require('./secureStore');
} catch (e) {
  // expo-secure-store not installed — will fall back to AsyncStorage
}

// expo-secure-store keys cannot contain '@' or other special chars,
// so we sanitize the key for SecureStore usage.
const sanitizeKeyForSecureStore = (key) => key.replace(/[^a-zA-Z0-9._-]/g, '_');

// iOS Keychain accessibility for ALL of our secure data.
//
// We use `AFTER_FIRST_UNLOCK_THIS_DEVICE_ONLY`:
//   - "after first unlock" → readable any time once the user has
//     unlocked since boot, even while the device is currently locked.
//     This is REQUIRED for VoIP push wake: PushKit can launch the app
//     while the device is locked, and the call setup reads the user's
//     PIN, encryption keys, and contact public keys from the keychain.
//     The default `whenUnlocked` would reject those reads with
//     `errSecInteractionNotAllowed` and break call setup, sign-in
//     restoration, and the "logs me out after signup" bug we see on
//     cold-start.
//   - "this device only" → items are not migrated to other devices via
//     iCloud Keychain. Required for our security model — recovery
//     phrase + PIN must not leak across devices automatically.
const KEYCHAIN_OPTIONS = SecureStore ? { keychainAccessible: SecureStore.AFTER_FIRST_UNLOCK_THIS_DEVICE_ONLY } : undefined;

// ─── Large-secret wrapping ────────────────────────────────────────────
// iOS Keychain has a documented 2KB-per-entry soft limit and
// expo-secure-store warns ("may not be stored successfully") above
// that. ML-KEM-768 private keys (~2400 raw / ~3200 base64) hit the
// limit. Strategy: keep a small (32-byte) AES wrapping key in
// SecureStore; encrypt the large value with it; persist the
// ciphertext to AsyncStorage. The wrapping key alone is meaningless
// — the ciphertext alone is useless. iOS still protects the
// keychain entry; the wrapped value rides on top.
const WRAP_KEY_SS_NAME = '_lwk_1';
const WRAPPED_VALUE_PREFIX = '@wrapped_';

// HMR-safe singleton state. Without this, Fast Refresh re-evaluating
// this file would reset locks + lazy-loaded module refs to null while
// real callers are mid-flight. Same pattern as config/socket.js and
// config/database.js.
const _e = globalThis.__shftCryptoState = globalThis.__shftCryptoState || {};
if (_e.wrappingKeyLock === undefined) _e.wrappingKeyLock = null;

const _getOrCreateWrappingKey = async () => {
  // Serialize concurrent first-run callers: two parallel get-or-create races
  // could each persist a DIFFERENT fresh key, making whatever was wrapped
  // under the losing key permanently undecryptable. Same in-flight-promise
  // pattern as getOrCreateKeyPair's keyPairLock.
  if (_e.wrappingKeyLock) return _e.wrappingKeyLock;
  _e.wrappingKeyLock = (async () => {
    try {
      const existing = await SecureStore.getItemAsync(WRAP_KEY_SS_NAME, KEYCHAIN_OPTIONS);
      if (existing) return decodeBase64(existing);
      const fresh = nacl.randomBytes(nacl.secretbox.keyLength); // 32 bytes
      await SecureStore.setItemAsync(WRAP_KEY_SS_NAME, encodeBase64(fresh), KEYCHAIN_OPTIONS);
      return fresh;
    } catch (e) {
      console.log('[wrap] getOrCreateWrappingKey failed:', e?.message);
      return null;
    } finally {
      _e.wrappingKeyLock = null;
    }
  })();
  return _e.wrappingKeyLock;
};

export const safeSecureStoreSetLarge = async (key, value) => {
  if (!key || value == null) return false;
  try {
    const wk = await _getOrCreateWrappingKey();
    if (!wk) return false;
    const nonce = nacl.randomBytes(nacl.secretbox.nonceLength);
    const plaintext = typeof value === 'string'
      ? new TextEncoder().encode(value)
      : value;
    const ciphertext = nacl.secretbox(plaintext, nonce, wk);
    const combined = new Uint8Array(nonce.length + ciphertext.length);
    combined.set(nonce, 0);
    combined.set(ciphertext, nonce.length);
    const sanitizedKey = sanitizeKeyForSecureStore(key);
    await AsyncStorage.setItem(WRAPPED_VALUE_PREFIX + sanitizedKey, encodeBase64(combined));
    return true;
  } catch (e) {
    console.log('[wrap] safeSecureStoreSetLarge failed:', e?.message);
    return false;
  }
};

/**
 * Strict read of a wrapped (large) secret: distinguish DEFINITELY ABSENT from
 * COULD NOT READ.
 *
 * AUDIT 2026-08-08 (round 50). safeSecureStoreGetLarge below collapses both
 * outcomes to null — it even detects the dangerous one ("wrapping key
 * unavailable but a wrapped value exists ... large secret undecryptable") and
 * still returns null. That is the same shape readSecureValueStrict exists to
 * prevent for small values, and its comment states the rule: "a read failure is
 * not proof of absence. NEVER mint a replacement secret on this."
 *
 * getOrCreatePqKeyPair was minting on exactly that signal. See there.
 *
 *   { ok:true,  value:<string> } → present
 *   { ok:true,  value:null }     → definitively absent
 *   { ok:false, value:null }     → unknown; the caller must NOT replace it
 */
export const readLargeSecureValueStrict = async (key) => {
  if (!key) return { ok: false, value: null };
  try {
    const sanitizedKey = sanitizeKeyForSecureStore(key);
    const stored = await AsyncStorage.getItem(WRAPPED_VALUE_PREFIX + sanitizedKey);
    if (!stored) return { ok: true, value: null };      // nothing stored: truly absent
    const wk = await _getOrCreateWrappingKey();
    // Ciphertext exists but the wrapping key is unavailable. Existence is
    // certain and readability is not — the one case that must never be read as
    // "absent", because minting over it destroys a live secret.
    if (!wk) return { ok: false, value: null };
    const combined = decodeBase64(stored);
    const nonce = combined.slice(0, nacl.secretbox.nonceLength);
    const ciphertext = combined.slice(nacl.secretbox.nonceLength);
    const plaintext = nacl.secretbox.open(ciphertext, nonce, wk);
    if (!plaintext) return { ok: false, value: null };  // present but undecryptable
    return { ok: true, value: new TextDecoder().decode(plaintext) };
  } catch (e) {
    console.log('[wrap] readLargeSecureValueStrict failed:', e?.message);
    return { ok: false, value: null };
  }
};

export const safeSecureStoreGetLarge = async (key) => {
  if (!key) return null;
  try {
    const sanitizedKey = sanitizeKeyForSecureStore(key);
    const stored = await AsyncStorage.getItem(WRAPPED_VALUE_PREFIX + sanitizedKey);
    if (!stored) return null;
    const wk = await _getOrCreateWrappingKey();
    if (!wk) {
      // We HAVE wrapped ciphertext but the SecureStore wrapping key is gone.
      // This is NOT a transient cache miss — the large secret (e.g. an ML-KEM
      // private key) is now undecryptable. Surface loudly so it's detectable
      // and the key can be regenerated, instead of silently returning null.
      console.warn('[wrap] wrapping key unavailable but a wrapped value exists for', sanitizedKey, '— large secret undecryptable');
      try { require('./telemetry').captureMessage('wrap_key_missing_with_value', 'warning', { key: sanitizedKey }); } catch (_) {}
      return null;
    }
    const combined = decodeBase64(stored);
    const nonce = combined.slice(0, nacl.secretbox.nonceLength);
    const ciphertext = combined.slice(nacl.secretbox.nonceLength);
    const plaintext = nacl.secretbox.open(ciphertext, nonce, wk);
    if (!plaintext) return null;
    return new TextDecoder().decode(plaintext);
  } catch (e) {
    console.log('[wrap] safeSecureStoreGetLarge failed:', e?.message);
    return null;
  }
};

// Wrap/unwrap for the keychain-accessibility migration's `_kcRecover_` backups.
// SECURITY (leak-audit H2): the backup must NEVER be plaintext — it can hold the
// master ENCRYPTION_KEY + identity private keys, and AsyncStorage is unencrypted.
// Wrapped with the SecureStore-held wrapping key (`_lwk_1`, which is NOT in
// SECURE_KEYS, so the migration never disturbs it). The 'kcw1:' prefix marks the
// wrapped format so a LEGACY plaintext orphan (from a pre-wrapping build) is still
// readable — and gets purged by the recovery sweep.
const _KC_BACKUP_WRAP_PREFIX = 'kcw1:';
const _wrapKcBackup = async (value) => {
  try {
    const wk = await _getOrCreateWrappingKey();
    if (!wk) return null;
    const nonce = nacl.randomBytes(nacl.secretbox.nonceLength);
    const ct = nacl.secretbox(new TextEncoder().encode(value), nonce, wk);
    const combined = new Uint8Array(nonce.length + ct.length);
    combined.set(nonce, 0);
    combined.set(ct, nonce.length);
    return _KC_BACKUP_WRAP_PREFIX + encodeBase64(combined);
  } catch (_) { return null; }
};
const _unwrapKcBackup = async (stored) => {
  if (typeof stored !== 'string') return null;
  if (!stored.startsWith(_KC_BACKUP_WRAP_PREFIX)) return stored; // legacy plaintext orphan
  try {
    const wk = await _getOrCreateWrappingKey();
    if (!wk) return null;
    const combined = decodeBase64(stored.slice(_KC_BACKUP_WRAP_PREFIX.length));
    const nonce = combined.slice(0, nacl.secretbox.nonceLength);
    const ct = combined.slice(nacl.secretbox.nonceLength);
    const pt = nacl.secretbox.open(ct, nonce, wk);
    return pt ? new TextDecoder().decode(pt) : null;
  } catch (_) { return null; }
};

export const safeSecureStoreSet = async (key, value) => {
  if (!key || typeof key !== 'string' || value === null || value === undefined) {
    console.warn('safeSecureStoreSet: Invalid params', { key, hasValue: !!value });
    return false;
  }
  try {
    if (SecureStore) {
      const sanitizedKey = sanitizeKeyForSecureStore(key);
      await SecureStore.setItemAsync(sanitizedKey, String(value), KEYCHAIN_OPTIONS);
      return true;
    }
    // SecureStore unavailable
    if (__DEV__) {
      console.warn('SecureStore unavailable — using AsyncStorage (not secure for production)');
      await AsyncStorage.setItem(key, String(value));
      return true;
    } else {
      console.log('SecureStore unavailable in production — refusing to store sensitive data in AsyncStorage');
      return false;
    }
  } catch (error) {
    console.log('Storage set error');
    return false;
  }
};

// Internal read that DISTINGUISHES "the item is not there" from "the read
// failed". Returns { ok: true, value } where `value === null` means the item
// is definitively absent, or { ok: false, value: null } when the Keychain
// threw and we therefore know NOTHING about whether the item exists.
//
// WHY this exists (audit 2026-07-25, HIGH): safeSecureStoreGet collapses both
// cases to `null`. Callers that treat null as "no key yet, mint a new one" —
// getOrCreateEncryptionKey and getRatchetStorageKey — would then generate and
// PERSIST a replacement master key on any transient Keychain error, e.g. a
// PushKit cold-wake before the device's first unlock since boot (our items are
// AFTER_FIRST_UNLOCK_THIS_DEVICE_ONLY, so they're genuinely unreadable then) or
// an intermittent errSecMissingEntitlement (-34018) after an app update. That
// silently destroys the wrapped recovery phrase (_cp_4) and every 'enc:' value
// in AsyncStorage (signed prekey privates, sender keys, X3DH material, PQ
// private key, cross-signing privates) — unrecoverable, on a live device.
// A read error must degrade (retry later), never mint.
const _secureStoreRead = async (key) => {
  if (!key || typeof key !== 'string') {
    console.warn('secureStoreRead: Invalid key');
    return { ok: false, value: null };
  }
  try {
    // Try SecureStore first with current (generic) key name
    if (SecureStore) {
      const sanitizedKey = sanitizeKeyForSecureStore(key);
      const secureValue = await SecureStore.getItemAsync(sanitizedKey, KEYCHAIN_OPTIONS);
      if (secureValue !== null) {
        // Lazy migration: an item stored under the old default
        // accessibility (`whenUnlocked`) stays under that accessibility
        // until it's rewritten. Existing accounts saved their secrets
        // before this code shipped, so the items will fail to read
        // on a locked device. Re-save with the relaxed accessibility
        // so the NEXT read from a locked state succeeds. Fire-and-forget
        // because we've already got the value for THIS call.
        SecureStore.setItemAsync(sanitizedKey, secureValue, KEYCHAIN_OPTIONS).catch(() => {});
        return { ok: true, value: secureValue };
      }

      // Check legacy key names (migration from older versions with revealing names)
      const legacyKey = Object.entries(LEGACY_SECURE_KEYS).find(([k, v]) => SECURE_KEYS[k] === key)?.[1];
      if (legacyKey) {
        const legacySanitized = sanitizeKeyForSecureStore(legacyKey);
        const legacyValue = await SecureStore.getItemAsync(legacySanitized, KEYCHAIN_OPTIONS);
        if (legacyValue !== null) {
          // Migrate to new generic key name and delete the revealing legacy key
          await SecureStore.setItemAsync(sanitizedKey, legacyValue, KEYCHAIN_OPTIONS);
          try { await SecureStore.deleteItemAsync(legacySanitized); } catch (_) {}
          return { ok: true, value: legacyValue };
        }
      }
    }
    // Check AsyncStorage for legacy migration data
    if (SecureStore || __DEV__) {
      const asyncValue = await AsyncStorage.getItem(key);
      return { ok: true, value: asyncValue };
    }
    return { ok: true, value: null };
  } catch (error) {
    console.log('Storage get error');
    return { ok: false, value: null, error };
  }
};

export const safeSecureStoreGet = async (key) => {
  if (!key || typeof key !== 'string') return null;
  const r = await _secureStoreRead(key);
  if (r.ok) return r.value;
  // Error path — preserved exactly as before: DEV falls back to AsyncStorage,
  // production returns null. Callers that must NOT treat this null as "absent"
  // use readSecureValueStrict below instead.
  if (__DEV__) {
    try {
      return await AsyncStorage.getItem(key);
    } catch (fallbackError) {
      console.log('AsyncStorage fallback get error:', fallbackError?.message || String(fallbackError));
    }
  }
  return null;
};

/**
 * Read a Keychain item, retrying on THROWN errors, and report whether the
 * absence is definitive. Mirrors getSecurePin's retry policy (iOS can
 * temporarily reject reads after rapid background/foreground cycles) but
 * unlike getSecurePin it surfaces the difference to the caller.
 *
 * @returns {Promise<{ ok: boolean, value: string|null }>}
 *   ok:true  + value:string → the item exists
 *   ok:true  + value:null   → the item definitively does not exist
 *   ok:false                → the Keychain failed; existence is UNKNOWN.
 *                             NEVER mint a replacement secret on this.
 */
export const readSecureValueStrict = async (key, attempts = 3) => {
  let last = { ok: false, value: null };
  for (let i = 0; i < attempts; i++) {
    last = await _secureStoreRead(key);
    if (last.ok) return last;
    if (i < attempts - 1) await new Promise(r => setTimeout(r, 300));
  }
  return last;
};

/**
 * Write a public/private key pair to the Keychain, or leave BOTH slots as they
 * were. Returns true only when both landed.
 *
 * AUDIT 2026-08-08 (round 40). safeSecureStoreSet returns false and never
 * throws. Every identity-pair writer in this file wrote the two halves as two
 * independent statements, so a refused write — errSecInteractionNotAllowed on a
 * not-yet-unlocked device, or the -34018 entitlement error this codebase
 * documents — left the NEW private key beside the STALE public key (or the
 * reverse). getOrCreateKeyPair then finds both items present, treats them as
 * `existing`, returns that MISMATCHED pair forever and never re-derives.
 *
 * The consequence is total and silent: everything we seal is unopenable by the
 * peers who fetched our published public key, everything they send is
 * unopenable by us, and the safety number mismatches — which reads to the user
 * as a MITM warning rather than a storage fault. deriveKeysFromPhrase's own
 * round-24 comment already states the rule this enforces: "Leaving the slot
 * EMPTY on that failure is recoverable; filling it with the wrong key is not."
 */
const persistKeyPairAtomically = async (privKeyName, pubKeyName, privB64, pubB64) => {
  const privSaved = await safeSecureStoreSet(privKeyName, privB64);
  const pubSaved = privSaved ? await safeSecureStoreSet(pubKeyName, pubB64) : false;
  if (privSaved && pubSaved) return true;
  // Partial write — undo it. An empty slot re-derives on the next call; a
  // mismatched one never does.
  console.log('[keys] key pair persist failed (priv:', privSaved, 'pub:', pubSaved, ') — clearing both slots');
  try { await safeSecureStoreDelete(privKeyName); } catch (_) {}
  try { await safeSecureStoreDelete(pubKeyName); } catch (_) {}
  return false;
};

const safeSecureStoreDelete = async (key) => {
  if (!key || typeof key !== 'string') return false;
  // AUDIT 2026-08-03 (round 20) — report the KEYCHAIN outcome, not just the
  // AsyncStorage one.
  //
  // The inner catch swallowed a Keychain delete failure and this returned true
  // regardless, so "Remove Duress PIN" could report success while the duress
  // hash was still on the device — and entering that PIN would still silently
  // wipe everything, which is the exact opposite of what the confirmation
  // dialog promised. A caller checking the return value would have been lied
  // to just as effectively as one that ignored it.
  let keychainOk = true;
  try {
    // Delete from SecureStore (keychain) first
    if (SecureStore) {
      try {
        const sanitizedKey = sanitizeKeyForSecureStore(key);
        await SecureStore.deleteItemAsync(sanitizedKey);
      } catch (secureError) {
        keychainOk = false;
        console.log('SecureStore delete error:', secureError?.message || String(secureError));
      }
    }
    // Also delete from AsyncStorage fallback
    await AsyncStorage.removeItem(key);
    return keychainOk;
  } catch (error) {
    console.log('Storage delete error:', error?.message || String(error));
    return false;
  }
};

// ============================================
// Constant-time string comparison to prevent timing attacks on PIN/hash checks
const constantTimeEqual = (a, b) => {
  if (typeof a !== 'string' || typeof b !== 'string') return false;
  if (a.length !== b.length) return false;
  let result = 0;
  for (let i = 0; i < a.length; i++) {
    result |= a.charCodeAt(i) ^ b.charCodeAt(i);
  }
  return result === 0;
};

// MESSAGE PADDING (prevents traffic analysis by normalizing message sizes)
// ============================================

const PADDING_BLOCK_SIZE = 256;

const padMessage = (messageBytes) => {
  const length = messageBytes.length;
  const totalLength = 4 + length;
  const paddedLength = Math.max(PADDING_BLOCK_SIZE, Math.ceil(totalLength / PADDING_BLOCK_SIZE) * PADDING_BLOCK_SIZE);
  const padded = new Uint8Array(paddedLength);
  padded[0] = (length >>> 24) & 0xff;
  padded[1] = (length >>> 16) & 0xff;
  padded[2] = (length >>> 8) & 0xff;
  padded[3] = length & 0xff;
  padded.set(messageBytes, 4);
  const randomPad = nacl.randomBytes(paddedLength - 4 - length);
  padded.set(randomPad, 4 + length);
  return padded;
};

const unpadMessage = (paddedBytes) => {
  if (!paddedBytes || paddedBytes.length < 4) return null;
  const length = ((paddedBytes[0] << 24) | (paddedBytes[1] << 16) | (paddedBytes[2] << 8) | paddedBytes[3]) >>> 0;
  if (length === 0 || 4 + length > paddedBytes.length) return null;
  return paddedBytes.slice(4, 4 + length);
};

// SHA-256 (pure JS — used for PIN hashing and key derivation from phrase)
// ============================================

const sha256 = (str) => {
  const K = [
    0x428a2f98, 0x71374491, 0xb5c0fbcf, 0xe9b5dba5, 0x3956c25b, 0x59f111f1, 0x923f82a4, 0xab1c5ed5,
    0xd807aa98, 0x12835b01, 0x243185be, 0x550c7dc3, 0x72be5d74, 0x80deb1fe, 0x9bdc06a7, 0xc19bf174,
    0xe49b69c1, 0xefbe4786, 0x0fc19dc6, 0x240ca1cc, 0x2de92c6f, 0x4a7484aa, 0x5cb0a9dc, 0x76f988da,
    0x983e5152, 0xa831c66d, 0xb00327c8, 0xbf597fc7, 0xc6e00bf3, 0xd5a79147, 0x06ca6351, 0x14292967,
    0x27b70a85, 0x2e1b2138, 0x4d2c6dfc, 0x53380d13, 0x650a7354, 0x766a0abb, 0x81c2c92e, 0x92722c85,
    0xa2bfe8a1, 0xa81a664b, 0xc24b8b70, 0xc76c51a3, 0xd192e819, 0xd6990624, 0xf40e3585, 0x106aa070,
    0x19a4c116, 0x1e376c08, 0x2748774c, 0x34b0bcb5, 0x391c0cb3, 0x4ed8aa4a, 0x5b9cca4f, 0x682e6ff3,
    0x748f82ee, 0x78a5636f, 0x84c87814, 0x8cc70208, 0x90befffa, 0xa4506ceb, 0xbef9a3f7, 0xc67178f2
  ];
  const rotr = (n, x) => (x >>> n) | (x << (32 - n));
  const ch = (x, y, z) => (x & y) ^ (~x & z);
  const maj = (x, y, z) => (x & y) ^ (x & z) ^ (y & z);
  const sigma0 = (x) => rotr(2, x) ^ rotr(13, x) ^ rotr(22, x);
  const sigma1 = (x) => rotr(6, x) ^ rotr(11, x) ^ rotr(25, x);
  const gamma0 = (x) => rotr(7, x) ^ rotr(18, x) ^ (x >>> 3);
  const gamma1 = (x) => rotr(17, x) ^ rotr(19, x) ^ (x >>> 10);

  const bytes = [];
  for (let i = 0; i < str.length; i++) {
    let code = str.charCodeAt(i);
    if (code >= 0xD800 && code <= 0xDBFF && i + 1 < str.length) {
      const low = str.charCodeAt(i + 1);
      if (low >= 0xDC00 && low <= 0xDFFF) {
        code = ((code - 0xD800) << 10) + (low - 0xDC00) + 0x10000;
        i++;
      }
    }
    if (code < 0x80) bytes.push(code);
    else if (code < 0x800) bytes.push(0xc0 | (code >> 6), 0x80 | (code & 0x3f));
    else if (code < 0x10000) bytes.push(0xe0 | (code >> 12), 0x80 | ((code >> 6) & 0x3f), 0x80 | (code & 0x3f));
    else bytes.push(0xf0 | (code >> 18), 0x80 | ((code >> 12) & 0x3f), 0x80 | ((code >> 6) & 0x3f), 0x80 | (code & 0x3f));
  }
  const bitLen = bytes.length * 8;
  bytes.push(0x80);
  while ((bytes.length % 64) !== 56) bytes.push(0);
  for (let i = 7; i >= 0; i--) bytes.push((bitLen / Math.pow(2, 8 * i)) & 0xff);

  let H = [0x6a09e667, 0xbb67ae85, 0x3c6ef372, 0xa54ff53a, 0x510e527f, 0x9b05688c, 0x1f83d9ab, 0x5be0cd19];
  for (let i = 0; i < bytes.length; i += 64) {
    const W = [];
    for (let t = 0; t < 16; t++) W[t] = (bytes[i + t * 4] << 24) | (bytes[i + t * 4 + 1] << 16) | (bytes[i + t * 4 + 2] << 8) | bytes[i + t * 4 + 3];
    for (let t = 16; t < 64; t++) W[t] = (gamma1(W[t - 2]) + W[t - 7] + gamma0(W[t - 15]) + W[t - 16]) | 0;
    let [a, b, c, d, e, f, g, h] = H;
    for (let t = 0; t < 64; t++) {
      const T1 = (h + sigma1(e) + ch(e, f, g) + K[t] + W[t]) | 0;
      const T2 = (sigma0(a) + maj(a, b, c)) | 0;
      h = g; g = f; f = e; e = (d + T1) | 0; d = c; c = b; b = a; a = (T1 + T2) | 0;
    }
    H = [(H[0] + a) | 0, (H[1] + b) | 0, (H[2] + c) | 0, (H[3] + d) | 0, (H[4] + e) | 0, (H[5] + f) | 0, (H[6] + g) | 0, (H[7] + h) | 0];
  }
  return H.map(h => (h >>> 0).toString(16).padStart(8, '0')).join('');
};

/**
 * SHA-256 operating on Uint8Array input, returning Uint8Array(32) output.
 * Used internally by HMAC-SHA-256 and PBKDF2.
 */
const sha256Bytes = (inputBytes) => {
  const bytes = Array.from(inputBytes);
  const bitLen = bytes.length * 8;
  bytes.push(0x80);
  while ((bytes.length % 64) !== 56) bytes.push(0);
  for (let i = 7; i >= 0; i--) bytes.push((bitLen / Math.pow(2, 8 * i)) & 0xff);

  const K = [
    0x428a2f98, 0x71374491, 0xb5c0fbcf, 0xe9b5dba5, 0x3956c25b, 0x59f111f1, 0x923f82a4, 0xab1c5ed5,
    0xd807aa98, 0x12835b01, 0x243185be, 0x550c7dc3, 0x72be5d74, 0x80deb1fe, 0x9bdc06a7, 0xc19bf174,
    0xe49b69c1, 0xefbe4786, 0x0fc19dc6, 0x240ca1cc, 0x2de92c6f, 0x4a7484aa, 0x5cb0a9dc, 0x76f988da,
    0x983e5152, 0xa831c66d, 0xb00327c8, 0xbf597fc7, 0xc6e00bf3, 0xd5a79147, 0x06ca6351, 0x14292967,
    0x27b70a85, 0x2e1b2138, 0x4d2c6dfc, 0x53380d13, 0x650a7354, 0x766a0abb, 0x81c2c92e, 0x92722c85,
    0xa2bfe8a1, 0xa81a664b, 0xc24b8b70, 0xc76c51a3, 0xd192e819, 0xd6990624, 0xf40e3585, 0x106aa070,
    0x19a4c116, 0x1e376c08, 0x2748774c, 0x34b0bcb5, 0x391c0cb3, 0x4ed8aa4a, 0x5b9cca4f, 0x682e6ff3,
    0x748f82ee, 0x78a5636f, 0x84c87814, 0x8cc70208, 0x90befffa, 0xa4506ceb, 0xbef9a3f7, 0xc67178f2
  ];
  const rotr = (n, x) => (x >>> n) | (x << (32 - n));
  const ch = (x, y, z) => (x & y) ^ (~x & z);
  const maj = (x, y, z) => (x & y) ^ (x & z) ^ (y & z);
  const sigma0 = (x) => rotr(2, x) ^ rotr(13, x) ^ rotr(22, x);
  const sigma1 = (x) => rotr(6, x) ^ rotr(11, x) ^ rotr(25, x);
  const gamma0 = (x) => rotr(7, x) ^ rotr(18, x) ^ (x >>> 3);
  const gamma1 = (x) => rotr(17, x) ^ rotr(19, x) ^ (x >>> 10);

  let H = [0x6a09e667, 0xbb67ae85, 0x3c6ef372, 0xa54ff53a, 0x510e527f, 0x9b05688c, 0x1f83d9ab, 0x5be0cd19];
  for (let i = 0; i < bytes.length; i += 64) {
    const W = [];
    for (let t = 0; t < 16; t++) W[t] = (bytes[i + t * 4] << 24) | (bytes[i + t * 4 + 1] << 16) | (bytes[i + t * 4 + 2] << 8) | bytes[i + t * 4 + 3];
    for (let t = 16; t < 64; t++) W[t] = (gamma1(W[t - 2]) + W[t - 7] + gamma0(W[t - 15]) + W[t - 16]) | 0;
    let [a, b, c, d, e, f, g, h] = H;
    for (let t = 0; t < 64; t++) {
      const T1 = (h + sigma1(e) + ch(e, f, g) + K[t] + W[t]) | 0;
      const T2 = (sigma0(a) + maj(a, b, c)) | 0;
      h = g; g = f; f = e; e = (d + T1) | 0; d = c; c = b; b = a; a = (T1 + T2) | 0;
    }
    H = [(H[0] + a) | 0, (H[1] + b) | 0, (H[2] + c) | 0, (H[3] + d) | 0, (H[4] + e) | 0, (H[5] + f) | 0, (H[6] + g) | 0, (H[7] + h) | 0];
  }
  const result = new Uint8Array(32);
  for (let i = 0; i < 8; i++) {
    result[i * 4] = (H[i] >>> 24) & 0xff;
    result[i * 4 + 1] = (H[i] >>> 16) & 0xff;
    result[i * 4 + 2] = (H[i] >>> 8) & 0xff;
    result[i * 4 + 3] = H[i] & 0xff;
  }
  return result;
};

/**
 * Native fast paths for SHA-256 / HMAC-SHA256.
 * Lazily loaded so this file still parses in test environments where the
 * native module isn't bundled. Callers that are already async (decryption
 * queue, KDF chains in onMessageRead, etc.) can `await sha256Async(...)`
 * and run the hash on a background dispatch queue (iOS) or
 * Dispatchers.Default (Android), keeping the JS thread free for input.
 *
 * The sync `sha256` / `hmacSha256` below remain authoritative for code
 * paths that aren't async — switching them all to async is a separate
 * refactor.
 */
let _nativeCryptoFast = null;
let _nativeShaAvailable = false;
try {
  const mod = require('../modules/native-crypto');
  if (mod && mod.isNativeShaAvailable && typeof mod.sha256 === 'function') {
    _nativeCryptoFast = mod;
    _nativeShaAvailable = true;
  }
} catch (_) {}

/** Async SHA-256. Falls back to sync JS when native is unavailable. */
export const sha256Async = async (input) => {
  // Accept string or Uint8Array. Native path needs base64.
  if (_nativeShaAvailable && _nativeCryptoFast) {
    try {
      let inputBytes;
      if (typeof input === 'string') inputBytes = decodeUTF8(input);
      else inputBytes = input;
      const inputB64 = encodeBase64(inputBytes);
      const hashB64 = await _nativeCryptoFast.sha256(inputB64);
      return decodeBase64(hashB64);
    } catch (_) { /* fall through to sync */ }
  }
  if (typeof input === 'string') {
    // Convert string → bytes → call sha256Bytes (defined below).
    return sha256Bytes(decodeUTF8(input));
  }
  return sha256Bytes(input);
};

/** Async HMAC-SHA256. Falls back to sync JS when native is unavailable. */
export const hmacSha256Async = async (key, message) => {
  if (_nativeShaAvailable && _nativeCryptoFast) {
    try {
      const macB64 = await _nativeCryptoFast.hmacSha256(
        encodeBase64(key),
        encodeBase64(message),
      );
      return decodeBase64(macB64);
    } catch (_) { /* fall through to sync */ }
  }
  return hmacSha256(key, message);
};

/**
 * HMAC-SHA-256: RFC 2104 keyed-hash message authentication code.
 * @param {Uint8Array} key - HMAC key
 * @param {Uint8Array} message - Data to authenticate
 * @returns {Uint8Array} - 32-byte MAC
 */
const hmacSha256 = (key, message) => {
  const BLOCK_SIZE = 64;
  let k = key;
  if (k.length > BLOCK_SIZE) k = sha256Bytes(k);
  if (k.length < BLOCK_SIZE) {
    const padded = new Uint8Array(BLOCK_SIZE);
    padded.set(k);
    k = padded;
  }
  const ipad = new Uint8Array(BLOCK_SIZE);
  const opad = new Uint8Array(BLOCK_SIZE);
  for (let i = 0; i < BLOCK_SIZE; i++) {
    ipad[i] = k[i] ^ 0x36;
    opad[i] = k[i] ^ 0x5c;
  }
  const inner = new Uint8Array(BLOCK_SIZE + message.length);
  inner.set(ipad);
  inner.set(message, BLOCK_SIZE);
  const innerHash = sha256Bytes(inner);
  const outer = new Uint8Array(BLOCK_SIZE + 32);
  outer.set(opad);
  outer.set(innerHash, BLOCK_SIZE);
  return sha256Bytes(outer);
};

/**
 * PBKDF2-HMAC-SHA256: RFC 2898 password-based key derivation.
 * Derives a 32-byte key from password + salt using iterative HMAC.
 * @param {string} password - User password/PIN
 * @param {string} saltHex - Hex-encoded salt
 * @param {number} iterations - Number of PBKDF2 iterations
 * @returns {string} - 64-char hex string (32 bytes)
 */
// Native PBKDF2 via react-native-quick-crypto — 10-50x faster than JS
let _quickCrypto = null;
// 2026-09-16 (P2-C): never require quick-crypto on web. Metro maps the package
// to a stub there (metro.config.js WEB_STUBBED_MODULES) and the real module
// cannot load in a browser anyway, so the require only produced a
// "quick-crypto failed to load" line on every page load. Web PBKDF2 runs
// through WebCrypto inside pbkdf2HmacSha256 below.
if (Platform.OS !== 'web') {
  try {
    _quickCrypto = require('react-native-quick-crypto');
    if (_quickCrypto && typeof _quickCrypto.pbkdf2 === 'function') {
      console.log('[Crypto] Native PBKDF2 loaded (react-native-quick-crypto)');
    } else {
      console.log('[Crypto] quick-crypto loaded but pbkdf2 not found, keys:', Object.keys(_quickCrypto || {}).join(', '));
      _quickCrypto = null;
    }
  } catch (e) {
    console.log('[Crypto] quick-crypto failed to load:', e?.message);
  }
}

// Hex salt to bytes for the WebCrypto branch: the same loop the quick-crypto
// and JS branches below run inline, kept identical so no backend can see
// different salt bytes for the same saltHex (a non-hex pair decodes to 0 on
// every path, which is why the hex equality below holds even for legacy salts).
const pbkdf2SaltBytes = (saltHex) => {
  const saltBytes = new Uint8Array(saltHex.length / 2);
  for (let i = 0; i < saltBytes.length; i++) {
    saltBytes[i] = parseInt(saltHex.substring(i * 2, i * 2 + 2), 16);
  }
  return saltBytes;
};

/**
 * PBKDF2-HMAC-SHA256 over WebCrypto (browser only). Added 2026-09-16 (P2-C).
 *
 * WHY: with quick-crypto stubbed on web, every KDF fell to the synchronous JS
 * loop, and 600K iterations of the array-based sha256Bytes freeze the tab for
 * seconds (twice per unlock, verifyUnlockPin hashes main and duress). The
 * browser's crypto.subtle runs the same PBKDF2-HMAC-SHA256 off the main
 * thread. Same password bytes (decodeUTF8), same salt decode, same iteration
 * count and a 32-byte output, so the hex it returns is byte-identical to the
 * quick-crypto and JS paths; __tests__/pbkdf2Web.test.js proves that against
 * the JS implementation and the RFC 6070 / RFC 7914 vectors.
 */
const pbkdf2HmacSha256WebCrypto = async (password, saltHex, iterations) => {
  const subtle = globalThis.crypto.subtle;
  const key = await subtle.importKey('raw', decodeUTF8(password), { name: 'PBKDF2' }, false, ['deriveBits']);
  const bits = await subtle.deriveBits(
    { name: 'PBKDF2', hash: 'SHA-256', salt: pbkdf2SaltBytes(saltHex), iterations },
    key,
    256,
  );
  return bytesToHex(new Uint8Array(bits));
};

const hasWebCryptoPbkdf2 = () => typeof globalThis !== 'undefined'
  && typeof globalThis.crypto?.subtle?.deriveBits === 'function';

/**
 * PBKDF2-HMAC-SHA256 with native acceleration.
 * Falls back to JS implementation if native module unavailable.
 * Input: password (string), saltHex (hex string), iterations (number)
 * Output: hex string (32 bytes = 64 hex chars)
 */
const pbkdf2HmacSha256 = (password, saltHex, iterations) => {
  const traceId = traces.pbkdf2();

  // Web: WebCrypto first, iterations passed through unchanged. On any throw
  // resolve to the JS implementation, mirroring the native error path below.
  // Every caller already awaits (hashPin, deriveKeysFromPhrase,
  // deriveBackupKey, verifyUnlockPin), so returning a Promise here is the
  // same contract the quick-crypto branch has always had.
  if (Platform.OS === 'web' && hasWebCryptoPbkdf2()) {
    return pbkdf2HmacSha256WebCrypto(password, saltHex, iterations)
      .then((hex) => {
        endTrace(traceId);
        return hex;
      })
      .catch((e) => {
        console.warn('[Crypto] WebCrypto PBKDF2 failed, falling back to JS:', e?.message);
        endTrace(traceId);
        return pbkdf2HmacSha256JS(password, saltHex, iterations);
      });
  }

  // Try native PBKDF2 first (async but dramatically faster — runs on native thread)
  if (_quickCrypto) {
    const saltBytes = new Uint8Array(saltHex.length / 2);
    for (let i = 0; i < saltBytes.length; i++) {
      saltBytes[i] = parseInt(saltHex.substring(i * 2, i * 2 + 2), 16);
    }

    return new Promise((resolve, reject) => {
      try {
        _quickCrypto.pbkdf2(password, Buffer.from(saltBytes), iterations, 32, 'sha256', (err, derivedKey) => {
          if (err) {
            console.warn('[Crypto] Native PBKDF2 failed, falling back to JS:', err?.message);
            endTrace(traceId);
            resolve(pbkdf2HmacSha256JS(password, saltHex, iterations));
          } else {
            endTrace(traceId);
            resolve(bytesToHex(new Uint8Array(derivedKey)));
          }
        });
      } catch (e) {
        console.warn('[Crypto] Native PBKDF2 error, falling back to JS:', e?.message);
        endTrace(traceId);
        resolve(pbkdf2HmacSha256JS(password, saltHex, iterations));
      }
    });
  }

  // JS fallback (synchronous, slow)
  const result = pbkdf2HmacSha256JS(password, saltHex, iterations);
  endTrace(traceId);
  return result;
};

// Original JS implementation as fallback
const pbkdf2HmacSha256JS = (password, saltHex, iterations) => {
  const pwBytes = new Uint8Array(decodeUTF8(password));
  const saltBytes = new Uint8Array(saltHex.length / 2);
  for (let i = 0; i < saltBytes.length; i++) {
    saltBytes[i] = parseInt(saltHex.substring(i * 2, i * 2 + 2), 16);
  }
  const saltBlock = new Uint8Array(saltBytes.length + 4);
  saltBlock.set(saltBytes);
  saltBlock[saltBytes.length] = 0;
  saltBlock[saltBytes.length + 1] = 0;
  saltBlock[saltBytes.length + 2] = 0;
  saltBlock[saltBytes.length + 3] = 1;

  let u = hmacSha256(pwBytes, saltBlock);
  const dk = new Uint8Array(u);
  for (let i = 1; i < iterations; i++) {
    u = hmacSha256(pwBytes, u);
    for (let j = 0; j < 32; j++) dk[j] ^= u[j];
  }
  return bytesToHex(dk);
};

// ============================================
// NaCl KEY PAIR MANAGEMENT
// ============================================

/**
 * Generate a NaCl box key pair (Curve25519).
 * Private key stays on device, public key is shared via Firestore.
 */
export const generateKeyPair = async () => {
  try {
    const keyPair = nacl.box.keyPair();
    if (!keyPair || !keyPair.secretKey || !keyPair.publicKey ||
        keyPair.secretKey.length !== nacl.box.secretKeyLength ||
        keyPair.publicKey.length !== nacl.box.publicKeyLength) {
      console.log('Key pair generation produced invalid keys');
      return null;
    }

    const privateKeyB64 = encodeBase64(keyPair.secretKey);
    const publicKeyB64 = encodeBase64(keyPair.publicKey);

    // Round 40 — this reported the failure but left the half-write in place, so
    // the slots could still end up mismatched and getOrCreateKeyPair would
    // adopt them as `existing`. Roll back on a partial write.
    if (!(await persistKeyPairAtomically(
      SECURE_KEYS.PRIVATE_KEY, SECURE_KEYS.PUBLIC_KEY, privateKeyB64, publicKeyB64))) {
      console.log('Failed to persist generated key pair to secure storage');
      return null;
    }

    return { privateKey: privateKeyB64, publicKey: publicKeyB64 };
  } catch (e) {
    console.log('Failed to generate key pair:', e?.message || String(e));
    return null;
  }
};

/** Get stored NaCl key pair */
export const getKeyPair = async () => {
  try {
    const privateKey = await safeSecureStoreGet(SECURE_KEYS.PRIVATE_KEY);
    const publicKey = await safeSecureStoreGet(SECURE_KEYS.PUBLIC_KEY);
    if (privateKey && publicKey) return { privateKey, publicKey };
    return null;
  } catch (e) {
    console.log('Failed to get key pair:', e?.message || String(e));
    return null;
  }
};

/** Get existing key pair or re-derive from recovery phrase (mutex-protected) */
// Lock lives on the HMR-safe `_e` singleton declared above _getOrCreateWrappingKey.
if (_e.keyPairLock === undefined) _e.keyPairLock = null;
export const getOrCreateKeyPair = async () => {
  // Prevent concurrent calls from generating duplicate key pairs
  if (_e.keyPairLock) return _e.keyPairLock;
  _e.keyPairLock = (async () => {
    try {
      // Read the keys DIRECTLY rather than through getKeyPair(), which catches
      // every error and returns null — making a transient Keychain failure
      // indistinguishable from "this device has no identity yet".
      //
      // AUDIT 2026-07-26 (round 3). That conflation was catastrophic here: a
      // failed read fell through to the generate-random branch at the bottom,
      // which MINTS AND PERSISTS a new identity keypair. The device's real
      // private key — the one every existing Double Ratchet session and every
      // published prekey is bound to — is replaced by one that matches nothing
      // in Firestore. Every conversation breaks, and the user appears to all
      // their contacts as a key change, i.e. indistinguishable from an
      // impersonation attempt. The Keychain is routinely unavailable for a
      // moment after a reboot before first unlock, which is exactly when a
      // background wake would call this.
      //
      // Same class as the recovery-phrase minting and the at-rest DB key
      // minting fixed earlier in this audit: a read failure is not proof of
      // absence.
      //
      // AUDIT 2026-08-03 (round 16) — CRITICAL. This guard was DEAD CODE.
      //
      // The intent above is right, but safeSecureStoreGet never throws: it
      // swallows the Keychain error and returns null, which is exactly the same
      // value it returns when the item legitimately does not exist. So
      // `readFailed` was never true, the guard below never fired, and a
      // transient Keychain rejection — the very "moment after a reboot before
      // first unlock" the comment names — minted and PERSISTED a replacement
      // IDENTITY KEYPAIR. That silently changes the user's E2EE identity: every
      // peer sees a key change, and material encrypted to the old key is lost.
      //
      // readSecureValueStrict is the API that can tell the two apart, and it
      // carries the retry policy getSecurePin only pretends to have.
      let existing = null;
      let readFailed = false;
      try {
        const [priv, pub] = await Promise.all([
          readSecureValueStrict(SECURE_KEYS.PRIVATE_KEY),
          readSecureValueStrict(SECURE_KEYS.PUBLIC_KEY),
        ]);
        if (!priv.ok || !pub.ok) {
          readFailed = true;
          console.log('getOrCreateKeyPair: key read FAILED (not absent) — refusing to mint');
        } else if (priv.value && pub.value) {
          existing = { privateKey: priv.value, publicKey: pub.value };
        }
      } catch (e) {
        readFailed = true;
        console.log('getOrCreateKeyPair: key read FAILED (not absent):', e?.message || String(e));
      }
      if (existing) {
        return existing;
      }
      if (readFailed) {
        // Fail closed. Callers already handle a null keypair (they surface
        // "Encryption not ready. Try again in a moment." and refuse to send in
        // the clear); the next call retries once the Keychain is readable.
        return null;
      }

      // SecureStore empty — try to re-derive from stored recovery phrase
      // This ensures keys always match what's in Firestore (phrase-derived)
      //
      // Web identity guard (2026-09-16, P2-E): skipped outright on a web build
      // without the dev flag. getIdentityPhrase and deriveKeysFromPhrase each
      // refuse on their own there, but the branch is skipped explicitly so the
      // rule is visible at the one place the identity is chosen, not implied
      // by two nulls. A linked browser (P1) gets its identity from device
      // keys, never from a phrase, so it falls through to the branches below.
      if (WEB_PHRASE_BLOCKED) {
        refuseWebPhrase('getOrCreateKeyPair phrase re-derive');
      } else {
        try {
          const { getIdentityPhrase } = require('./storage');
          const { getLocal, KEYS } = require('./storage');
          const activeIdentity = await getLocal(KEYS.ACTIVE_IDENTITY);
          if (activeIdentity) {
            const phrase = await getIdentityPhrase(activeIdentity);
            if (phrase) {
              console.log('Re-deriving keys from stored recovery phrase');
              // Look up derivationVersion from Firestore to use correct KDF
              let version = 'v3'; // Default to v3 for existing accounts
              try {
                const { getDb } = require('./database');
                const { doc, getDoc } = require('firebase/firestore');
                const userDocSnap = await getDoc(doc(getDb(), 'users', activeIdentity));
                if (userDocSnap.exists()) {
                  version = userDocSnap.data().derivationVersion || 'v3';
                }
              } catch (fbErr) {
              }
              const derived = await deriveKeysFromPhrase(phrase, { version });
              if (derived?.privateKey && derived?.publicKey) return derived;
            }
          }
        } catch (e) {
          console.log('Could not re-derive keys from phrase:', e.message);
        }
      }

      // Last resort: generate random keys — ONLY for a brand-new account that
      // has no phrase yet, which is what this branch has always claimed to be
      // for.
      //
      // AUDIT 2026-07-26 (round 3): the claim was not enforced. If an account
      // already exists, its identity is phrase-derived and PUBLISHED, so a
      // random keypair here matches nothing in Firestore and silently destroys
      // every session — and it was reachable whenever the phrase re-derivation
      // above failed for any reason (locked Keychain, transient Firestore read
      // for derivationVersion, a phrase that had not synced yet). Refuse
      // instead: returning null makes callers show "Encryption not ready" and
      // retry, which is recoverable. Minting is not.
      let setupComplete = true;
      try {
        const { getLocal, KEYS } = require('./storage');
        setupComplete = (await getLocal(KEYS.HAS_COMPLETED_SETUP)) === true;
      } catch (_) {
        setupComplete = true; // fail closed — never mint when we cannot tell
      }
      if (setupComplete) {
        console.log('getOrCreateKeyPair: refusing to mint a new identity for an existing account');
        return null;
      }

      const generated = await generateKeyPair();
      return generated;
    } finally {
      _e.keyPairLock = null;
    }
  })();
  return _e.keyPairLock;
};

// ============================================
// E2E MESSAGE ENCRYPTION (NaCl box)
// ============================================

/**
 * Encrypt a message for a specific recipient using NaCl box.
 * Uses Curve25519 key exchange + XSalsa20-Poly1305 AEAD.
 *
 * @param {string} message - Plaintext message
 * @param {string} theirPublicKeyB64 - Recipient's public key (base64)
 * @param {string} myPrivateKeyB64 - Sender's private key (base64)
 * @returns {string|null} - "naclp:<nonce_b64>:<ciphertext_b64>" or null on failure (callers should check for null)
 */
export const encryptMessage = (message, theirPublicKeyB64, myPrivateKeyB64) => {
  if (!message || !theirPublicKeyB64 || !myPrivateKeyB64) return null;
  const traceId = traces.naclEncrypt();

  try {
    const messageBytes = decodeUTF8(message);
    const paddedBytes = padMessage(messageBytes);
    const nonce = nacl.randomBytes(nacl.box.nonceLength);
    const theirPublicKey = decodeBase64(theirPublicKeyB64);
    const myPrivateKey = decodeBase64(myPrivateKeyB64);

    // Validate key sizes before encryption
    if (!theirPublicKey || theirPublicKey.length !== nacl.box.publicKeyLength) {
      console.log('Encrypt: invalid public key length', theirPublicKey?.length, 'expected', nacl.box.publicKeyLength);
      return null;
    }
    if (!myPrivateKey || myPrivateKey.length !== nacl.box.secretKeyLength) {
      console.log('Encrypt: invalid private key length', myPrivateKey?.length, 'expected', nacl.box.secretKeyLength);
      return null;
    }

    const encrypted = nacl.box(paddedBytes, nonce, theirPublicKey, myPrivateKey);
    if (!encrypted) { endTrace(traceId); return null; }

    endTrace(traceId);
    return 'naclp:' + encodeBase64(nonce) + ':' + encodeBase64(encrypted);
  } catch (e) {
    console.log('Encrypt error:', e?.message || String(e));
    endTrace(traceId);
    return null;
  }
};

/**
 * Decrypt a message from a specific sender using NaCl box.open.
 *
 * @param {string} encrypted - "naclp:<nonce_b64>:<ciphertext_b64>" or legacy "nacl:<nonce_b64>:<ciphertext_b64>" format
 * @param {string} theirPublicKeyB64 - Sender's public key (base64)
 * @param {string} myPrivateKeyB64 - Recipient's private key (base64)
 * @returns {string} - Decrypted plaintext or the encrypted string on failure
 */
export const decryptMessage = (encrypted, theirPublicKeyB64, myPrivateKeyB64) => {
  if (!encrypted) return encrypted;
  if (!theirPublicKeyB64 || !myPrivateKeyB64) return null;

  // Handle NaCl-encrypted messages (padded 'naclp:' and legacy unpadded 'nacl:')
  const isPadded = encrypted.startsWith('naclp:');
  const isLegacyNacl = !isPadded && encrypted.startsWith('nacl:');

  if (isPadded || isLegacyNacl) {
    const traceId = traces.naclDecrypt();
    try {
      const parts = encrypted.split(':');
      if (parts.length < 3) return encrypted;
      const nonce = decodeBase64(parts[1]);
      const ciphertext = decodeBase64(parts[2]);

      // Validate nonce and ciphertext sizes
      if (!nonce || nonce.length !== nacl.box.nonceLength) {
        console.warn('Decrypt: invalid nonce length');
        return 'This message couldn\'t be read';
      }
      if (!ciphertext || ciphertext.length === 0) {
        console.warn('Decrypt: empty ciphertext');
        return 'This message couldn\'t be read';
      }

      const theirPublicKey = decodeBase64(theirPublicKeyB64);
      const myPrivateKey = decodeBase64(myPrivateKeyB64);

      if (!theirPublicKey || theirPublicKey.length !== nacl.box.publicKeyLength) {
        console.warn('Decrypt: invalid public key (len:', theirPublicKey?.length, ')');
        return 'This message couldn\'t be read';
      }
      if (!myPrivateKey || myPrivateKey.length !== nacl.box.secretKeyLength) {
        console.warn('Decrypt: invalid private key');
        return 'This message couldn\'t be read';
      }

      const decrypted = nacl.box.open(ciphertext, nonce, theirPublicKey, myPrivateKey);
      if (!decrypted) {
        console.warn('Decrypt: NaCl box.open failed (wrong key or tampered)');
        return 'This message couldn\'t be read';
      }

      if (isPadded) {
        // SECURITY: if the payload claimed the padded format (ENCNP)
        // but unpad fails, treat as decryption failure rather than
        // falling back to raw bytes. The raw bytes include the
        // padding header + random pad and decode to UTF-8 noise that
        // looks decrypted.
        const unpadded = unpadMessage(decrypted);
        endTrace(traceId);
        if (!unpadded) return 'This message couldn\'t be read';
        return encodeUTF8(unpadded);
      }
      // Legacy unpadded format — return raw decrypted bytes
      endTrace(traceId);
      return encodeUTF8(decrypted);
    } catch (e) {
      console.log('Decrypt error:', e?.message || String(e));
      endTrace(traceId);
      return 'This message couldn\'t be read';
    }
  }

  // Explicitly catch known encrypted prefixes that should not be passed to this function
  if (encrypted.startsWith('ratchet:') || encrypted.startsWith('hybrid:') ||
      encrypted.startsWith('ENCN:') || encrypted.startsWith('ENCNP:')) {
    return 'This message couldn\'t be read';
  }

  // SECURITY (crypto-auditor invariant): when encryption keys are
  // available, NEVER pass plaintext through as if it were decrypted.
  // A malicious or buggy sender that wrote text:"stay home" with no
  // encryption prefix would otherwise render to the receiver as a
  // normal message — bypassing the E2E guarantee. Refuse the message
  // regardless of length / whitespace heuristics.
  if (theirPublicKeyB64 && myPrivateKeyB64) {
    return 'This message couldn\'t be read';
  }

  // No keys available — decryption setup is incomplete. The caller is
  // responsible for showing the appropriate placeholder. Returning the
  // input lets the legacy `decryptMessage(text)` (no-key) call sites
  // keep working for non-text content (e.g. system messages that pass
  // through this function with a missing key argument).
  return encrypted;
};

// ============================================
// SYMMETRIC ENCRYPTION (NaCl secretbox — for local data / media)
// ============================================

/**
 * Generate a shared secret for a conversation using NaCl box.before().
 * This precomputes the Curve25519-XSalsa20-Poly1305 shared key.
 *
 * ⚠️ KNOWN LIMITATION — NO FORWARD SECRECY FOR MEDIA (audit 2026-07-25).
 * The value returned here is X25519(myIdentityPriv, theirIdentityPub): one
 * static secret for the entire life of the two identities. It is never
 * ratcheted and never rotated. app/chat.js encrypts photos / video / files /
 * voice notes with it (encryptMedia(mediaForEncrypt, convKey)) while the TEXT
 * of the very same message goes through the Double Ratchet
 * (encryptionVersion: 'ratchet_v1'). Consequence: recovering either party's
 * identity private key — which deriveKeysFromPhrase regenerates from the
 * printed recovery phrase — retroactively decrypts every media blob still in
 * the bucket, including blobs whose ratcheted text is immune. There is no
 * post-compromise security either: the key is identical before and after.
 *
 * NOT FIXED HERE, DELIBERATELY. The correct design is Signal's: derive a
 * per-message media key from the ratchet message key (HKDF) and carry it
 * inside the already-ratcheted text envelope. That changes the wire format
 * and needs BOTH sides to understand it, so it requires a versioned envelope
 * plus a read-both/write-new rollout — a client-only change would make media
 * sent by the new build unreadable to every currently-shipped build on the
 * App Store. Tracked for the crypto-auditor review; do not "fix" it by
 * swapping the key here.
 */
export const generateConversationKey = async (_userId1, _userId2, theirPublicKeyB64) => {
  try {
    const keyPair = await getOrCreateKeyPair();
    if (!keyPair?.privateKey || !theirPublicKeyB64) {
      console.log('generateConversationKey: missing keys', { hasPrivate: !!keyPair?.privateKey, hasTheirPublic: !!theirPublicKeyB64 });
      return null;
    }

    const myPrivateKey = decodeBase64(keyPair.privateKey);
    const theirPublicKey = decodeBase64(theirPublicKeyB64);

    // Precompute shared secret
    const sharedKey = nacl.box.before(theirPublicKey, myPrivateKey);
    return encodeBase64(sharedKey);
  } catch (e) {
    console.log('Failed to generate conversation key:', e?.message || String(e));
    return null;
  }
};

// AUDIT 2026-08-03 (round 24) — every conversation key this device has EVER
// had for a peer, newest first.
//
// 1:1 media is sealed with generateConversationKey = box.before(theirPub,
// myPriv) — a static DH over the two IDENTITY keys, not the ratchet. A phrase
// restore deliberately rotates the identity key for single-device enforcement,
// which silently breaks every historical photo, video, voice note and file: the
// restoring user cannot open them, and the peer, re-deriving against the newly
// published key, loses them too. The bubbles just render empty.
//
// loginWithPhrase now preserves the pre-rotation key AND the phrase-derived
// original, so a decrypt can fall back through them. This is the same shape
// group media already has in decryptGroupMediaWithArchive.
//
// Returns [currentKey, ...previousKeys] with nulls dropped and duplicates
// removed, so a caller can try each in order and stop at the first that opens.
//
// AUDIT 2026-08-03 (round 25) — round 24 fixed only the RESTORING side.
// The key is box.before(theirPub, myPriv), so a restore breaks it from BOTH
// ends, and only one end was walking alternatives:
//
//   A restores. A's identity key rotates and the new public key is published.
//   A recovers, because A kept its own pre-rotation private key.
//   B did nothing at all — B's private key is unchanged — but B now re-derives
//   against A's NEW public key, so box.before differs and every historical
//   photo, video, voice note and file in that conversation stops opening for
//   B. Both directions: the ones A sent AND the ones B sent, because B sealed
//   its own outgoing media to A's old public key too. Silently — empty bubbles.
//
// So the candidate set is the cross product of the private keys this device has
// held with the public keys it has seen for that peer, current × current first.
// A wrong key fails secretbox.open in microseconds, and the current pair still
// wins on the first try in the overwhelmingly common case, so the hot path is
// unchanged. Bounded at 3 × 4 by construction.
export const getConversationKeyCandidates = async (userId, contactId, theirPublicKeyB64) => {
  const out = [];
  const push = (k) => { if (k && !out.includes(k)) out.push(k); };
  try { push(await generateConversationKey(userId, contactId, theirPublicKeyB64)); } catch (_) {}
  try {
    const { getLocal } = require('./storage');

    // MY private keys, newest first. The current one comes from the keypair
    // itself so the cross product below covers current-priv × old-peer-pub —
    // which is exactly B's case, and the one round 24 missed.
    const myPrivs = [];
    try {
      const kp = await getOrCreateKeyPair();
      if (kp?.privateKey) myPrivs.push(kp.privateKey);
    } catch (_) {}
    for (const k of ['@prev_private_key', '@phrase_identity_private_key']) {
      try {
        const priv = await getLocal(k);
        if (priv && typeof priv === 'string' && !myPrivs.includes(priv)) myPrivs.push(priv);
      } catch (_) {}
    }

    // THEIR public keys, newest first. `@known_pubkey_` is the last key this
    // device acknowledged, so while a key change is pending it still holds the
    // OLD one; the archive holds the ones acknowledged away from.
    const theirPubs = [];
    if (theirPublicKeyB64) theirPubs.push(theirPublicKeyB64);
    if (contactId) {
      try {
        const known = await getLocal('@known_pubkey_' + contactId);
        if (known && typeof known === 'string' && !theirPubs.includes(known)) theirPubs.push(known);
      } catch (_) {}
      try {
        const archive = await getLocal(PEER_PUBKEY_ARCHIVE_PREFIX + contactId);
        if (Array.isArray(archive)) {
          for (const p of archive) {
            if (p && typeof p === 'string' && !theirPubs.includes(p)) theirPubs.push(p);
          }
        }
      } catch (_) {}
    }

    for (const pub of theirPubs) {
      for (const priv of myPrivs) {
        // a malformed stored key must not break the ones that follow it
        try { push(encodeBase64(nacl.box.before(decodeBase64(pub), decodeBase64(priv)))); } catch (_) {}
      }
    }
  } catch (_) {}
  return out;
};

// Bounded ring of a peer's PREVIOUS identity public keys (newest first).
// Four is two more restores than anyone does, and the whole point is that these
// are public values — there is nothing here an attacker could not already read
// off the peer's user document.
const PEER_PUBKEY_ARCHIVE_PREFIX = '@peer_pubkey_archive_';
const PEER_PUBKEY_ARCHIVE_MAX = 4;

export const archivePeerPublicKey = async (contactId, oldPublicKeyB64) => {
  if (!contactId || !oldPublicKeyB64 || typeof oldPublicKeyB64 !== 'string') return false;
  try {
    const { getLocal, saveLocal } = require('./storage');
    const key = PEER_PUBKEY_ARCHIVE_PREFIX + contactId;
    const prior = await getLocal(key);
    const list = Array.isArray(prior) ? prior.filter((p) => p && typeof p === 'string') : [];
    if (list[0] === oldPublicKeyB64) return true;
    const next = [oldPublicKeyB64, ...list.filter((p) => p !== oldPublicKeyB64)]
      .slice(0, PEER_PUBKEY_ARCHIVE_MAX);
    await saveLocal(key, next);
    return true;
  } catch (err) {
    console.log('archivePeerPublicKey error:', err?.message || String(err));
    return false;
  }
};

// Try each candidate key in turn. Returns the first successful decrypt, or null.
// Deliberately mirrors decryptMedia's contract so call sites can swap directly.
export const decryptMediaWithCandidates = async (encryptedData, keyCandidates) => {
  if (!Array.isArray(keyCandidates)) return null;
  for (const k of keyCandidates) {
    if (!k) continue;
    try {
      const out = await decryptMedia(encryptedData, k);
      if (out) return out;
    } catch (_) { /* wrong key — try the next */ }
  }
  return null;
};

/**
 * Encrypt media data using NaCl secretbox (symmetric).
 * Full encryption, not partial — every byte is encrypted.
 */
export const encryptMedia = async (base64Data, conversationKeyB64) => {
  if (!base64Data || !conversationKeyB64) return null;

  try {
    const key = decodeBase64(conversationKeyB64);
    const nonce = nacl.randomBytes(nacl.secretbox.nonceLength);
    const commaIdx = base64Data.indexOf(',');
    const dataBytes = decodeBase64(commaIdx !== -1 ? base64Data.substring(commaIdx + 1) : base64Data);
    const paddedData = padMessage(dataBytes);

    const encrypted = nacl.secretbox(paddedData, nonce, key);
    if (!encrypted) return null;

    const header = commaIdx !== -1 ? base64Data.substring(0, commaIdx + 1) : '';
    return 'ENCNP:' + header + encodeBase64(nonce) + ':' + encodeBase64(encrypted);
  } catch (e) {
    console.log('Media encryption error:', e?.message || String(e));
    return null;
  }
};

/**
 * Decrypt media data using NaCl secretbox.
 */
export const decryptMedia = async (encryptedData, conversationKeyB64) => {
  if (!encryptedData || !conversationKeyB64) return null;
  const isPaddedMedia = encryptedData.startsWith('ENCNP:');
  const isLegacyNaclMedia = !isPaddedMedia && encryptedData.startsWith('ENCN:');

  if (!isPaddedMedia && !isLegacyNaclMedia) {
    // Legacy unencrypted or old format — return as-is
    if (encryptedData.startsWith('ENC1:')) return encryptedData; // old XOR format, can't decrypt
    return encryptedData;
  }

  try {
    const key = decodeBase64(conversationKeyB64);
    const prefixLen = isPaddedMedia ? 6 : 5; // 'ENCNP:' = 6, 'ENCN:' = 5
    const withoutPrefix = encryptedData.substring(prefixLen);

    // Extract header if present (e.g., "data:image/jpeg;base64,")
    let header = '';
    let remainder = withoutPrefix;
    const commaIndex = withoutPrefix.indexOf(',');
    if (commaIndex !== -1 && commaIndex < 50) {
      header = withoutPrefix.substring(0, commaIndex + 1);
      remainder = withoutPrefix.substring(commaIndex + 1);
    }

    const colonIndex = remainder.indexOf(':');
    if (colonIndex === -1) return encryptedData;

    const nonce = decodeBase64(remainder.substring(0, colonIndex));
    const ciphertext = decodeBase64(remainder.substring(colonIndex + 1));

    const decrypted = nacl.secretbox.open(ciphertext, nonce, key);
    if (!decrypted) return null; // Return null so UI can show error state

    if (isPaddedMedia) {
      // SECURITY: refuse on unpad failure rather than returning the raw
      // decrypted bytes (header + random padding) as if they were the
      // image — the UI would try to display garbage.
      const unpadded = unpadMessage(decrypted);
      if (!unpadded) return null;
      return header + encodeBase64(unpadded);
    }
    // Legacy unpadded format — return raw decrypted bytes
    return header + encodeBase64(decrypted);
  } catch (e) {
    console.log('Media decryption error:', e?.message || String(e));
    return null; // Return null so UI can show error state
  }
};

/**
 * Decrypt media to raw bytes (Uint8Array) WITHOUT re-encoding to base64.
 *
 * Same crypto as decryptMedia, but returns the decrypted binary directly.
 * Callers that write media to disk (video / file / story playback) must use
 * this instead of decryptMedia: decryptMedia base64-encodes the plaintext
 * into a data URI, then those callers immediately base64-DECODE it again to
 * write the file. That gratuitous encode->decode round-trip — together with
 * the many full-size JS-heap copies it forces — is what OOM-kills large-video
 * decrypts on device (Hermes heap), even though the crypto itself is fine.
 * decryptMedia (the data-URI variant) is still correct for <Image>, which
 * needs a data: URI.
 *
 * @param {string} encryptedData - 'ENCNP:' (padded) or legacy 'ENCN:' payload
 * @param {string} conversationKeyB64 - base64 conversation key
 * @returns {Promise<{ bytes: Uint8Array, mime: string|null }|null>} null on failure
 */
export const decryptMediaToBytes = async (encryptedData, conversationKeyB64) => {
  if (!encryptedData || !conversationKeyB64) return null;
  const isPaddedMedia = encryptedData.startsWith('ENCNP:');
  const isLegacyNaclMedia = !isPaddedMedia && encryptedData.startsWith('ENCN:');
  if (!isPaddedMedia && !isLegacyNaclMedia) return null;

  try {
    const key = decodeBase64(conversationKeyB64);
    const prefixLen = isPaddedMedia ? 6 : 5; // 'ENCNP:' = 6, 'ENCN:' = 5
    const withoutPrefix = encryptedData.substring(prefixLen);

    // Extract the mime from the header (e.g. "data:video/mp4;base64,") if present.
    let mime = null;
    let remainder = withoutPrefix;
    const commaIndex = withoutPrefix.indexOf(',');
    if (commaIndex !== -1 && commaIndex < 50) {
      const header = withoutPrefix.substring(0, commaIndex);
      remainder = withoutPrefix.substring(commaIndex + 1);
      const m = header.match(/^data:([^;]+)/);
      if (m) mime = m[1];
    }

    const colonIndex = remainder.indexOf(':');
    if (colonIndex === -1) return null;

    const nonce = decodeBase64(remainder.substring(0, colonIndex));
    const ciphertext = decodeBase64(remainder.substring(colonIndex + 1));

    const decrypted = nacl.secretbox.open(ciphertext, nonce, key);
    if (!decrypted) return null; // wrong key / tampered — fail closed

    if (isPaddedMedia) {
      // SECURITY: refuse on unpad failure rather than returning header+pad
      // bytes as if they were the media (matches decryptMedia).
      const unpadded = unpadMessage(decrypted);
      if (!unpadded) return null;
      return { bytes: unpadded, mime };
    }
    // Legacy unpadded format — raw decrypted bytes.
    return { bytes: decrypted, mime };
  } catch (e) {
    console.log('Media decryption (bytes) error:', e?.message || String(e));
    return null;
  }
};

// ============================================
// AT-REST MEDIA ENCRYPTION (Stories, Profile Pictures)
// ============================================
//
// Random per-asset NaCl secretbox key. Encrypts the binary blob; the key is
// stored alongside the metadata in Firestore (e.g. status doc, user doc).
// Threat model: protects against Storage-URL leaks and scrapers — anyone who
// gets the bucket URL alone gets gibberish. Server (Firebase) can still
// decrypt by combining the Firestore key with the Storage blob; this is not
// strict E2E because the viewer set is dynamic and unbounded (matches the
// industry-standard Stories model).
//
// Binary frame: SCK1\0 (5 bytes magic) | nonce (24 bytes) | ciphertext (rest)

const MAGIC = new Uint8Array([0x53, 0x43, 0x4B, 0x31, 0x00]); // "SCK1\0"

/**
 * Generate a new random 32-byte secret-box key (base64).
 */
export const generateMediaKey = () => encodeBase64(nacl.randomBytes(nacl.secretbox.keyLength));

/**
 * Encrypt a Blob with NaCl secretbox and a random key. Returns
 * { encryptedBlob, keyB64 }. Caller uploads `encryptedBlob` to Storage and
 * stores `keyB64` next to the metadata in Firestore. Returns null on failure.
 */
export const encryptMediaBlob = async (blob) => {
  if (!blob) return null;
  try {
    // React Native's polyfilled Blob (from XHR responseType:'blob') does not
    // expose arrayBuffer(); fall back to FileReader → base64 → bytes.
    const ab = typeof blob.arrayBuffer === 'function'
      ? await blob.arrayBuffer()
      : await new Promise((resolve, reject) => {
          const fr = new FileReader();
          fr.onload = () => {
            try {
              const dataUrl = String(fr.result);
              const b64 = dataUrl.includes(',') ? dataUrl.split(',')[1] : dataUrl;
              const bin = (typeof atob === 'function')
                ? atob(b64)
                : Buffer.from(b64, 'base64').toString('binary');
              const buf = new ArrayBuffer(bin.length);
              const view = new Uint8Array(buf);
              for (let i = 0; i < bin.length; i++) view[i] = bin.charCodeAt(i);
              resolve(buf);
            } catch (err) { reject(err); }
          };
          fr.onerror = () => reject(fr.error || new Error('FileReader failed'));
          fr.readAsDataURL(blob);
        });
    const data = new Uint8Array(ab);
    const key = nacl.randomBytes(nacl.secretbox.keyLength);
    const nonce = nacl.randomBytes(nacl.secretbox.nonceLength);
    const ciphertext = nacl.secretbox(data, nonce, key);
    if (!ciphertext) return null;
    const out = new Uint8Array(MAGIC.length + nonce.length + ciphertext.length);
    out.set(MAGIC, 0);
    out.set(nonce, MAGIC.length);
    out.set(ciphertext, MAGIC.length + nonce.length);
    // RN's Blob polyfill cannot be constructed from a Uint8Array
    // ("Creating blobs from 'ArrayBuffer'/'ArrayBufferView' are not
    // supported"), and Firebase Storage's RN path needs a real Blob
    // (it pulls bytes through the native bridge via _data.blobId).
    // Build the Blob by round-tripping through a data URI via XHR —
    // the polyfilled XHR yields a properly-backed Blob.
    const b64 = encodeBase64(out);
    const encryptedBlob = await new Promise((resolve, reject) => {
      const xhr = new XMLHttpRequest();
      xhr.onload = () => resolve(xhr.response);
      xhr.onerror = () => reject(new Error('Failed to construct encrypted blob'));
      xhr.responseType = 'blob';
      xhr.open('GET', `data:application/octet-stream;base64,${b64}`, true);
      xhr.send(null);
    });
    return { encryptedBlob, keyB64: encodeBase64(key) };
  } catch (e) {
    console.log('encryptMediaBlob error:', e?.message);
    return null;
  }
};

/**
 * Fetch an encrypted media URL, decrypt with the given key, and return a
 * base64 data URI suitable for <Image source={{ uri }}> or expo-video.
 *
 * If the blob has no magic prefix (legacy plaintext upload from before this
 * encryption was wired), returns the original URL unchanged so older content
 * keeps working without a migration.
 *
 * For very large videos a temp-file path would be more memory-efficient than
 * a data URI — see expo-file-system writeAsync. Current Story sizes (<50MB
 * compressed) are fine on a base64 path.
 */
// AUDIT 2026-07-26 — every decrypt-from-URL helper below fetches a URL that
// came out of ANOTHER user's Firestore document. `avatarUrl` on /users/{uid} is
// self-writable (the update rule is a deny-list and avatarUrl is not on it), so
// a user could point it at a host they control, attach any `avatarKey`, and
// have every device that merely RENDERS them — contact list, search results,
// activity feed, an incoming friend request — issue an HTTP request to that
// host. No interaction required. For an app whose entire premise is not
// disclosing who is talking to whom, handing an attacker the viewer's IP and a
// timestamp is a serious leak.
//
// It was worse than a beacon: when the fetched bytes carry no MAGIC header
// these helpers RETURN THE URL as a legacy-plaintext passthrough, so the
// attacker's URL was then handed to <Image>, fetched a second time and rendered
// as that user's avatar — arbitrary attacker-chosen imagery under someone
// else's identity.
//
// Storage download URLs are always https on Google's storage hosts. Parse the
// authority with a regex rather than `new URL()` — RN's URL implementation is a
// partial polyfill and this must not depend on its edge-case behavior.
// Rejecting any authority containing '@' kills the
// `https://firebasestorage.googleapis.com@evil.com/` credential trick, and
// exact host matching kills `firebasestorage.googleapis.com.evil.com`.
// AUDIT 2026-07-26 (round 2) — the first version of this allowlisted the HOST
// only, which stopped nothing: firebasestorage.googleapis.com and
// storage.googleapis.com are shared, multi-tenant Google endpoints serving
// every Firebase project on earth. The attacker spins up a free project, makes
// one object public, points avatarUrl at it, and reads the viewer IPs out of
// their own bucket's access logs. The BUCKET is the part that identifies us, so
// the bucket is what gets pinned. Both project buckets are listed because the
// same binary ships against prod and staging (config/cdn.js hardcodes the same
// pair).
const ALLOWED_MEDIA_BUCKETS = Object.freeze([
  'shift-aa75a.firebasestorage.app',
  'shift-aa75a.appspot.com',
  'shift-staging-11700.firebasestorage.app',
  'shift-staging-11700.appspot.com',
]);
export const isAllowedMediaUrl = (url) => {
  if (typeof url !== 'string' || !url) return false;
  // Already-local content — nothing leaves the device.
  if (url.startsWith('file://') || url.startsWith('data:')) return true;
  // The Storage EMULATOR serves over http on loopback, so dev builds and the
  // integration suite would otherwise be unable to fetch any media at all.
  // 10.0.2.2 is how the Android emulator reaches the host machine — without it
  // Android-emulator dev builds get no media at all. Gated on __DEV__ so a
  // shipped build never accepts http or a non-project bucket; production keeps
  // the check absolute, and loopback cannot reach an attacker in any case since
  // it is this machine. Same shape as the __DEV__-only SecureStore fallback in
  // config/storage.js.
  if (typeof __DEV__ !== 'undefined' && __DEV__
      && /^https?:\/\/(127\.0\.0\.1|localhost|10\.0\.2\.2)(:\d+)?\//i.test(url)) {
    return true;
  }
  const m = /^https:\/\/([^/?#]+)(\/[^?#]*)?/i.exec(url);
  if (!m) return false;
  const authority = m[1].toLowerCase();
  // Rejecting '@' kills https://firebasestorage.googleapis.com@evil.example/,
  // where everything before the @ is credentials and the real host is evil.
  if (authority.includes('@')) return false;
  const host = authority.replace(/:\d+$/, '');
  // AUDIT 2026-07-26 (round 3) — the CDN escape is an exact ORIGIN match, and
  // it lives HERE, after the '@' rejection above. Round 2 wrote it as
  // `url.startsWith(cdnBase)` placed before that rejection, which with
  // EXPO_PUBLIC_CDN_URL=https://cdn.theshft.app accepted
  // https://cdn.theshft.app.evil.example/… (the suffix-domain trick this very
  // function's comment claims to kill), https://cdn.theshft.app@evil.example/…
  // (the credential trick, since the escape short-circuited before the '@'
  // check), and https://cdn.theshft.appXYZ/…. A whitespace-only or bare-scheme
  // value matched nearly everything. Dormant today — the var is unset — but it
  // activates with a single env change at build time.
  const cdnHost = _cdnOriginHost();
  if (cdnHost && host === cdnHost) return true;
  if (host !== 'firebasestorage.googleapis.com') return false;
  // Download URLs are /v0/b/<bucket>/o/<encodedPath>. Require our bucket.
  const path = m[2] || '';
  return ALLOWED_MEDIA_BUCKETS.some((b) => path.startsWith(`/v0/b/${b}/o/`));
};

// Host of the configured CDN origin, or null. Parsed with the same
// authority regex rather than string prefixes, so a malformed or partial
// value ('https:', ' ', 'cdn.example') yields null and trusts nothing.
function _cdnOriginHost() {
  const raw = (process.env.EXPO_PUBLIC_CDN_URL || '').trim();
  if (!raw) return null;
  const cm = /^https:\/\/([^/?#]+)/i.exec(raw);
  if (!cm) return null;
  const a = cm[1].toLowerCase();
  if (a.includes('@')) return null;
  return a.replace(/:\d+$/, '') || null;
}

export const decryptMediaUrlToDataUri = async (url, keyB64, mimeHint) => {
  if (!url) return url;
  // AUDIT 2026-07-26 (round 2) — this MUST precede the keyless passthrough
  // below. It used to sit after `if (!url || !keyB64) return url`, which made
  // the entire allowlist opt-out: point the URL at a host you control and
  // simply OMIT the key, and the function handed the hostile URL straight back
  // to the caller, which passed it to <Image>. The guard only ever ran for
  // payloads that were already ours.
  if (!isAllowedMediaUrl(url)) {
    console.warn('[media] refusing off-host URL');
    return null;
  }
  if (!keyB64) return url;
  try {
    const resp = await fetch(url);
    // A 403/404 error body has no SCK1 magic and used to fall into the
    // legacy passthrough below — handing the RAW storage URL to Image
    // consumers (call-audit 2026-09-01). Non-2xx is a failure, full stop.
    if (!resp.ok) {
      if (__DEV__) console.log('[media] fetch failed:', resp.status);
      return null;
    }
    const ab = await resp.arrayBuffer();
    const framed = new Uint8Array(ab);
    if (framed.length < MAGIC.length + nacl.secretbox.nonceLength + nacl.secretbox.overheadLength
        || framed[0] !== MAGIC[0] || framed[1] !== MAGIC[1]
        || framed[2] !== MAGIC[2] || framed[3] !== MAGIC[3]) {
      // No magic — pre-encryption legacy upload. Use the URL directly.
      return url;
    }
    const nonce = framed.subarray(MAGIC.length, MAGIC.length + nacl.secretbox.nonceLength);
    const ciphertext = framed.subarray(MAGIC.length + nacl.secretbox.nonceLength);
    const key = decodeBase64(keyB64);
    const plain = nacl.secretbox.open(ciphertext, nonce, key);
    if (!plain) {
      if (__DEV__) console.log('[avatar] decrypt failed (secretbox open)');
      return null;
    }
    const mime = mimeHint || resp.headers.get('content-type') || 'application/octet-stream';
    return `data:${mime};base64,${encodeBase64(plain)}`;
  } catch (e) {
    console.log('decryptMediaUrlToDataUri error:', e?.message);
    return null;
  }
};

/**
 * Same as decryptMediaUrlToDataUri but writes the decrypted bytes to a
 * file in the app cache directory and returns a `file://` URI.
 *
 * Use this for video playback: expo-video's VideoView does not accept
 * data: URIs, so we have to round-trip through the filesystem. Image
 * rendering with <Image source={{ uri: data:... }}> still works fine,
 * so prefer the data-URI variant for stills.
 *
 * Returns the original URL on legacy (unencrypted) blobs, or null on
 * decryption failure.
 */
export const decryptMediaUrlToFile = async (url, keyB64, mimeHint) => {
  if (!url) return url;
  // Guard BEFORE the keyless passthrough — see decryptMediaUrlToDataUri.
  if (!isAllowedMediaUrl(url)) {
    console.warn('[media] refusing off-host URL');
    return null;
  }
  if (!keyB64) return url;
  try {
    const resp = await fetch(url);
    // Same guard as the avatar/data-URI paths: a non-2xx error body has no
    // magic and must not fall into the legacy raw-URL passthrough.
    if (!resp.ok) return null;
    const ab = await resp.arrayBuffer();
    const framed = new Uint8Array(ab);
    if (framed.length < MAGIC.length + nacl.secretbox.nonceLength + nacl.secretbox.overheadLength
        || framed[0] !== MAGIC[0] || framed[1] !== MAGIC[1]
        || framed[2] !== MAGIC[2] || framed[3] !== MAGIC[3]) {
      return url;
    }
    const nonce = framed.subarray(MAGIC.length, MAGIC.length + nacl.secretbox.nonceLength);
    const ciphertext = framed.subarray(MAGIC.length + nacl.secretbox.nonceLength);
    const key = decodeBase64(keyB64);
    // Yield to the event loop on either side of the two synchronous slabs
    // (secretbox.open over multi-MB media, then the sync file write) so
    // queued touches and state updates get a turn between stages. The
    // crypto call itself is atomic — poly1305-then-stream cannot be
    // chunked without reimplementing the cipher — so the slab stays, but
    // a spinner scheduled before this call now paints, and a tap queued
    // during the fetch runs before the CPU pin instead of after both.
    await new Promise(r => setTimeout(r, 0));
    const plain = nacl.secretbox.open(ciphertext, nonce, key);
    if (!plain) return null;
    await new Promise(r => setTimeout(r, 0));
    const mime = mimeHint || resp.headers.get('content-type') || 'video/mp4';
    // Web (2026-09-16, P2-F2): a browser has no cache directory. expo-file-
    // system's web File only console.warns and Paths.cache warns on every
    // read, so the write below threw and this returned null after two
    // warnings per story. The plaintext stays in this tab's memory behind a
    // blob: URL, which expo-image and expo-video accept, and app/status.js
    // revokes it in the same sweep that deletes the story_* files on a
    // phone. Nothing about the decryption above changes.
    if (Platform.OS === 'web') {
      if (typeof Blob !== 'function' || typeof URL === 'undefined' || typeof URL.createObjectURL !== 'function') return null;
      return URL.createObjectURL(new Blob([plain], { type: mime }));
    }
    const ext = mime.split('/')[1]?.split(';')[0] || 'bin';
    // Write the decrypted bytes straight to disk via the new FileSystem File
    // API. Avoids encodeBase64(plain) (a full-size base64 string the legacy
    // writeAsStringAsync path then re-decodes) — that round-trip is the
    // large-video memory blowup on device.
    const { File, Paths } = require('expo-file-system');
    const f = new File(Paths.cache, `story_${Date.now()}_${Math.random().toString(36).slice(2, 8)}.${ext}`);
    try { if (f.exists) f.delete(); } catch (_) {}
    f.write(plain);
    return f.uri;
  } catch (e) {
    console.log('decryptMediaUrlToFile error:', e?.message);
    return null;
  }
};

/**
 * Avatar-specific variant of the decrypt path that materializes the
 * decrypted image to a STABLE `file://` cache path instead of a big
 * base64 `data:` URI.
 *
 * Why: <Image source={{ uri: data:... }}> works, but a data URI is a
 * full-size base64 string that has to be re-decoded on every render and
 * is never persisted across app backgrounding. A file:// URI is handled
 * natively by expo-image, disk-cached for free, and reusable on the next
 * call — so a list of avatars paints from disk instead of re-decrypting.
 *
 * The cache file name is a stable hash of `cacheKeyHint` (caller passes
 * userId + the avatar's storage URL + key, so the name changes only when
 * the avatar itself changes — a new upload yields a new URL/token). If the
 * file already exists we skip fetch+decrypt entirely and return its URI.
 *
 * Crypto is unchanged — same SCK1 frame, same nacl.secretbox.open. Only
 * where the plaintext is written differs. Falls back to a data: URI if the
 * filesystem write fails, and returns null on decrypt failure / the
 * original URL on legacy (unencrypted) blobs — same contract as
 * decryptMediaUrlToDataUri.
 *
 * @param {string} url - encrypted avatar storage URL
 * @param {string} keyB64 - base64 per-asset secretbox key
 * @param {string} cacheKeyHint - stable per-avatar-version identifier
 * @param {string} [mimeHint] - defaults to image/jpeg
 */
export const decryptAvatarUrlToFile = async (url, keyB64, cacheKeyHint, mimeHint) => {
  if (!url) return url;
  // The avatar path is the one an attacker can actually reach — see
  // isAllowedMediaUrl. Refuse before the cache probe so a poisoned URL can
  // never even establish a cache entry, and before the keyless passthrough so
  // omitting avatarKey cannot opt out of the check (round-2 audit).
  if (!isAllowedMediaUrl(url)) {
    console.warn('[avatar] refusing off-host URL');
    return null;
  }
  if (!keyB64) return url;
  let cacheFile = null;
  try {
    const { File, Paths } = require('expo-file-system');
    const mime = mimeHint || 'image/jpeg';
    const ext = mime.split('/')[1]?.split(';')[0] || 'jpg';
    // Stable name from the caller-supplied hint (userId + url + key). sha256
    // here returns a hex string; slice keeps the filename short.
    const nameHash = sha256(String(cacheKeyHint || url)).slice(0, 32);
    cacheFile = new File(Paths.cache, `avatar_${nameHash}.${ext}`);
    // Reuse a previously-decrypted avatar without touching the network or
    // crypto. Size-check, not bare existence: a 0-byte file from a past
    // interrupted write would otherwise be served forever (call-audit
    // 2026-09-01) — delete it so this pass re-decrypts.
    try {
      if (cacheFile.exists) {
        if (cacheFile.size > 0) return cacheFile.uri;
        try { cacheFile.delete(); } catch (_) {}
      }
    } catch (_) {}
  } catch (_) {
    // expo-file-system unavailable — fall through to the data: URI path below.
    cacheFile = null;
  }

  try {
    const resp = await fetch(url);
    // A 403/404 error body has no SCK1 magic and used to fall into the
    // legacy passthrough below — handing the RAW storage URL to Image
    // consumers (call-audit 2026-09-01). Non-2xx is a failure, full stop.
    if (!resp.ok) {
      if (__DEV__) console.log('[avatar] fetch failed:', resp.status);
      return null;
    }
    const ab = await resp.arrayBuffer();
    const framed = new Uint8Array(ab);
    if (framed.length < MAGIC.length + nacl.secretbox.nonceLength + nacl.secretbox.overheadLength
        || framed[0] !== MAGIC[0] || framed[1] !== MAGIC[1]
        || framed[2] !== MAGIC[2] || framed[3] !== MAGIC[3]) {
      // No magic — pre-encryption legacy upload. Use the URL directly.
      return url;
    }
    const nonce = framed.subarray(MAGIC.length, MAGIC.length + nacl.secretbox.nonceLength);
    const ciphertext = framed.subarray(MAGIC.length + nacl.secretbox.nonceLength);
    const key = decodeBase64(keyB64);
    const plain = nacl.secretbox.open(ciphertext, nonce, key);
    if (!plain) {
      if (__DEV__) console.log('[avatar] decrypt failed (secretbox open)');
      return null;
    }
    const mime = mimeHint || resp.headers.get('content-type') || 'image/jpeg';
    // Write the decrypted bytes to the stable cache file and hand back its
    // file:// URI. Fall back to a data: URI if the write fails for any reason.
    if (cacheFile) {
      try {
        try { if (cacheFile.exists) cacheFile.delete(); } catch (_) {}
        cacheFile.write(plain);
        return cacheFile.uri;
      } catch (writeErr) {
        console.log('[best-effort] avatar file cache write failed, using data URI:', writeErr?.message);
      }
    }
    return `data:${mime};base64,${encodeBase64(plain)}`;
  } catch (e) {
    console.log('decryptAvatarUrlToFile error:', e?.message);
    return null;
  }
};

// ============================================
// KEY DERIVATION FROM RECOVERY PHRASE
// ============================================

/**
 * Derive a NaCl key pair deterministically from a recovery phrase.
 *
 * v6 (current): PBKDF2-HMAC-SHA256 with 600,000 iterations (OWASP 2023). Runs on
 *               the native quick-crypto path, so the high count is fast on-device
 *               (the same helper already hashes PINs at 600K).
 * v5 (legacy):  PBKDF2-HMAC-SHA256 with 10,000 iterations — retained so accounts
 *               created under v5 still derive the SAME identity keypair.
 * v3 (legacy):  Single SHA-256 hash — kept only for backward compatibility.
 *
 * IMPORTANT: the phrase derives the identity keypair ITSELF, so the iteration
 * count is part of the identity. An account's derivationVersion is stored in
 * Firestore and pinned on restore — we must NEVER re-derive an existing account
 * at a different count, or its public key changes and the user is locked out.
 * Only NEW accounts (no version passed) get v6. Migrating existing users to v6
 * requires a full re-key flow (tracked separately, not done here).
 *
 * @param {string} phrase - Recovery phrase
 * @param {object} [options] - Optional settings
 * @param {string} [options.version] - 'v3'/'v5' for legacy accounts; default 'v6'
 * @returns {{ privateKey: string, publicKey: string, derivationVersion: string }|null}
 */
const PHRASE_KDF_SALT_V3 = 'theshft_key_derivation_v3';
// v5: legacy 10K. Pinned for accounts created before v6 — changing this would
// change their derived identity key, so do NOT "upgrade" it in place.
const PHRASE_KDF_ITERATIONS_V5 = 10000;
// v6: 600K (OWASP 2023). Native PBKDF2 (react-native-quick-crypto) keeps this
// fast; the same helper already runs PIN hashing at 600K. New accounts only.
const PHRASE_KDF_ITERATIONS_V6 = 600000;

export const deriveKeysFromPhrase = async (phrase, options = {}) => {
  try {
    // Web identity guard (2026-09-16, P2-E): refused before the KDF runs, so a
    // web build without the dev flag derives nothing, not even in memory.
    if (WEB_PHRASE_BLOCKED) { refuseWebPhrase('deriveKeysFromPhrase'); return null; }
    if (!phrase || typeof phrase !== 'string') return null;
    // Normalize: lowercase, collapse all whitespace (tabs, newlines, double spaces) to single space
    const words = phrase.toLowerCase().trim().replace(/\s+/g, ' ');

    const version = options.version || 'v6';

    let seedHex;

    if (version === 'v3') {
      // Legacy path: single SHA-256 hash with static salt
      seedHex = sha256(words + PHRASE_KDF_SALT_V3);
    } else if (version === 'v5') {
      // Legacy PBKDF2 path: 10K iterations. PINNED for v5-era accounts so the
      // derived identity keypair stays byte-identical — never raise this.
      // Salt is SHA-256(phrase) + version marker: deterministic but unique
      // per-phrase (not a single static salt for all users).
      const phraseHash = sha256(words);
      const salt = sha256(phraseHash + 'theshft_kdf_v5');
      seedHex = await pbkdf2HmacSha256(words, salt, PHRASE_KDF_ITERATIONS_V5);
    } else {
      // v6 (current, NEW accounts and the default): PBKDF2 at 600K iterations.
      // Distinct salt marker so the derivation is unambiguously v6.
      const phraseHash = sha256(words);
      const salt = sha256(phraseHash + 'theshft_kdf_v6');
      seedHex = await pbkdf2HmacSha256(words, salt, PHRASE_KDF_ITERATIONS_V6);
    }

    if (!seedHex || seedHex.length !== 64 || !/^[0-9a-f]{64}$/.test(seedHex)) return null;

    const seed = new Uint8Array(32);
    for (let i = 0; i < 32; i++) seed[i] = parseInt(seedHex.substring(i * 2, i * 2 + 2), 16);

    if (!seed) return null;

    const keyPair = nacl.box.keyPair.fromSecretKey(seed);
    const privateKeyB64 = encodeBase64(keyPair.secretKey);
    const publicKeyB64 = encodeBase64(keyPair.publicKey);

    // AUDIT 2026-08-03 (round 25) — `persist: false` makes this a PURE
    // derivation. This function is not side-effect free: it INSTALLS what it
    // derives as the device's identity. Round 24 called it merely to recover a
    // historical key for the media fallback and thereby stamped that key into
    // the Keychain identity slot immediately before the restore's deliberate
    // rotation — so if generateKeyPair() then failed (a Keychain write refused
    // on a not-yet-unlocked device returns null), the device was left holding
    // an identity matching nothing in Firestore, which getOrCreateKeyPair
    // returns as `existing` forever and never re-derives. Leaving the slot
    // EMPTY on that failure is recoverable; filling it with the wrong key is
    // not. Callers that want the bytes without the installation pass false.
    if (options.persist !== false) {
      // Round 40 — both results were discarded, so a half-written pair was
      // installed and returned as though the whole installation succeeded. The
      // comment above spells out why that specific outcome is unrecoverable.
      // switchIdentity and restoreAccount both discard this return and report
      // success, so nothing downstream would have caught it either.
      if (!(await persistKeyPairAtomically(
        SECURE_KEYS.PRIVATE_KEY, SECURE_KEYS.PUBLIC_KEY, privateKeyB64, publicKeyB64))) {
        console.log('Key derivation: could not install the derived identity — leaving the slot empty');
        return null;
      }
    }

    return { privateKey: privateKeyB64, publicKey: publicKeyB64, derivationVersion: version };
  } catch (e) {
    console.log('Key derivation failed');
    return null;
  }
};

// ============================================
// ENCRYPTION KEY (symmetric, for local data)
// ============================================

export const generateEncryptionKey = async () => {
  const randomBytes = nacl.randomBytes(32);
  return encodeBase64(randomBytes);
};

// In-process memo of the at-rest master key. Once we have successfully READ the
// real key, a later transient Keychain failure can no longer influence anything
// — no re-read, no chance of minting. Cleared by clearSecureStorage (a wipe must
// not leave the old key live in memory, or the next account would encrypt its
// data under a key that no longer exists in the Keychain).
if (_e.encryptionKeyCache === undefined) _e.encryptionKeyCache = null;
if (_e.encryptionKeyLock === undefined) _e.encryptionKeyLock = null;

/**
 * The master symmetric key for local at-rest data (config/storage.js 'enc:'
 * values + the wrapped recovery phrase).
 *
 * SAFETY CONTRACT (audit 2026-07-25, HIGH — do not weaken):
 *  1. A fresh key is minted ONLY when the Keychain definitively reports the
 *     item as absent. A read that THREW returns null instead: callers degrade
 *     (config/storage.js leaves encryption off for now and retries on the next
 *     call; getLocal returns null for 'enc:' values, exactly as it already does
 *     on a locked cold-wake). Temporary unavailability is recoverable —
 *     overwriting the key is not.
 *  2. A newly minted key is adopted ONLY if it was successfully persisted.
 *     Returning an unpersisted key would encrypt this session's writes under a
 *     key that vanishes at app exit.
 *  3. Concurrent first-run callers share one in-flight promise, so two racing
 *     callers can't each persist a DIFFERENT fresh key (same pattern as
 *     _getOrCreateWrappingKey / getOrCreateKeyPair).
 */
export const getOrCreateEncryptionKey = async () => {
  if (_e.encryptionKeyCache) return _e.encryptionKeyCache;
  if (_e.encryptionKeyLock) return _e.encryptionKeyLock;
  _e.encryptionKeyLock = (async () => {
    try {
      const read = await readSecureValueStrict(SECURE_KEYS.ENCRYPTION_KEY);
      if (!read.ok) {
        // Keychain unavailable — existence UNKNOWN. Minting here would destroy
        // the recovery phrase and all stored key material. Degrade instead.
        console.log('[enc] master key read failed — refusing to mint a replacement');
        try {
          require('./telemetry').captureMessage('encryption_key_read_failed', 'warning');
        } catch (_) {}
        return null;
      }
      if (read.value) {
        _e.encryptionKeyCache = read.value;
        return read.value;
      }
      // Definitively absent → first run on this install. Mint and persist.
      const fresh = await generateEncryptionKey();
      const saved = await safeSecureStoreSet(SECURE_KEYS.ENCRYPTION_KEY, fresh);
      if (!saved) {
        console.log('[enc] master key generated but NOT persisted — not adopting it');
        return null;
      }
      _e.encryptionKeyCache = fresh;
      return fresh;
    } catch (e) {
      console.log('Failed to get/create encryption key:', e?.message || String(e));
      return null;
    } finally {
      _e.encryptionKeyLock = null;
    }
  })();
  const key = await _e.encryptionKeyLock;
  // Fire-and-forget (NOT awaited): records which identities have per-identity
  // Keychain items so a later wipe can delete them. Deliberately runs AFTER the
  // key is cached and the lock is released — it reads AsyncStorage through
  // config/storage.js getLocal, which calls back into this function via the
  // storage key provider. Awaiting it here would deadlock on our own lock.
  if (key) { try { _warmIdentityIndex(); } catch (_) {} }
  return key;
};

// ============================================
// PIN MANAGEMENT
// ============================================

// Legacy static salt for backward compatibility with old PIN hashes
const LEGACY_PIN_SALT = 'shift_pin_salt_v1';

/**
 * Convert a Uint8Array to a hex string.
 */
const bytesToHex = (bytes) => Array.from(bytes, b => b.toString(16).padStart(2, '0')).join('');

/**
 * Convert hex string to Uint8Array(32)
 */
const hexToBytes32 = (hex) => {
  // Strict validation: the first 64 chars must be hex. A wrong length OR non-hex
  // characters (e.g. a corrupt native ML-KEM return) would parse to NaN bytes and
  // silently corrupt derived key material. Fail safe + warn so it's detectable
  // rather than producing a quietly-broken key.
  if (!hex || typeof hex !== 'string' || !/^[0-9a-fA-F]{64}/.test(hex)) {
    console.warn('[Crypto] hexToBytes32: invalid hex input (len=' + (hex?.length ?? 'n/a') + '); returning zeroed bytes');
    return new Uint8Array(32); // Return zeroed bytes rather than crashing
  }
  const bytes = new Uint8Array(32);
  for (let i = 0; i < 32; i++) {
    bytes[i] = parseInt(hex.substring(i * 2, i * 2 + 2), 16);
  }
  return bytes;
};

/** Generate a cryptographically secure random hex string */
export const secureRandomHex = (byteCount = 8) => bytesToHex(nacl.randomBytes(byteCount));

/**
 * Hash a PIN with a salt using PBKDF2-HMAC-SHA256 (600K iterations) + server-side
 * rate limiting (5 attempts/15 min).
 *
 * @param {string} pin - The PIN to hash
 * @param {string} [existingSalt] - Hex salt for verification mode; omit to generate a new random salt (creation mode)
 * @param {number} [iterations] - Number of iterations (default: PIN_HASH_ITERATIONS)
 * @returns {{ hash: string, salt: string }|null} - The hash and salt, or null on failure
 */
// OWASP 2023 recommends >=600K iterations for PBKDF2-HMAC-SHA256. With native
// quick-crypto, 600K is ~12-20ms on iPhone 15 Pro — inside the tap-to-unlock
// budget. The JS fallback ALSO uses 600K (~2s, slow but correct — see C-B); it
// is never silently lowered. Existing 10K/100K hashes migrate up to 600K on the
// next successful unlock via the verify write-back path below. (KAN-11 / C-B)
const PIN_HASH_ITERATIONS_V2 = 600000;
// C-B: NEVER silently downgrade the PIN KDF. New PIN hashes are ALWAYS created
// at the v2 iteration count (600K). This previously dropped to 10K whenever
// native quick-crypto wasn't loaded (misconfigured/older runtime) — far weaker,
// and the 'pbkdf2' version tag masked the difference. On the rare JS-fallback
// path the 600K PBKDF2 is slow (~2s) but CORRECT; production uses native OpenSSL
// (~20ms). The verify path below still tries legacy counts (10K/100K) so PINs
// created under the old behaviour aren't locked out — they re-save at 600K on
// the next unlock. CLAUDE.md: iteration counts only go up.
const PIN_HASH_ITERATIONS = PIN_HASH_ITERATIONS_V2;
const LEGACY_PIN_HASH_ITERATIONS_10K = 10000;
const LEGACY_PIN_HASH_ITERATIONS_100K = 100000;
const LEGACY_PIN_HASH_ITERATIONS_1K = 1000;
// Backup KDF iteration count. OWASP 2023 recommends ≥600K for PBKDF2-
// HMAC-SHA256. With native quick-crypto this is ~600ms on iPhone 15,
// ~1.2s on iPhone SE — acceptable for the once-per-backup creation
// path. JS fallback would be unusable, so the JS path is implicitly
// gated by the pbkdf2HmacSha256 helper falling back to slower iters.
const BACKUP_KDF_ITERATIONS_V2 = 600000;

/**
 * Legacy iterated SHA-256 hash (kept for verifyPin backward compat only).
 */
const legacyHashPin = (pin, salt, iterations) => {
  let hash = sha256(salt + pin);
  for (let i = 1; i < iterations; i++) {
    hash = sha256(hash + salt);
  }
  return hash;
};

export const hashPin = async (pin, existingSalt, iterations = PIN_HASH_ITERATIONS) => {
  if (!pin) return null;
  try {
    const salt = existingSalt || bytesToHex(nacl.randomBytes(16));
    const hash = await pbkdf2HmacSha256(pin, salt, iterations);
    return { hash, salt, version: 'pbkdf2' };
  } catch (e) {
    console.log('Failed to hash PIN:', e?.message || String(e));
    return null;
  }
};

export const saveSecurePin = async (pin, type = 'main', options = {}) => {
  try {
    // Defense-in-depth: reject trivially-guessable PINs at the storage chokepoint,
    // not just in the create-pin/change-pin/duress UI. A modified client or any
    // non-UI path reaching here with a weak PIN (0000, 1234, repeats) is refused.
    // options.allowWeak is set ONLY by internal re-save/migration paths that are
    // persisting an ALREADY-CHOSEN PIN (legacy hash upgrade, account restore) —
    // those must not be blocked or a user with a pre-existing weak PIN would be
    // unable to migrate or restore.
    if (!options.allowWeak) {
      const { isWeakPin } = require('./pinValidation');
      const weak = isWeakPin(pin);
      if (weak.weak) {
        console.warn('[PIN] saveSecurePin refused weak PIN:', weak.reason);
        return false;
      }
    }
    const result = await hashPin(pin);
    if (!result) return false;

    let hashKey, saltKey;
    if (type === 'duress') {
      hashKey = SECURE_KEYS.DURESS_PIN;
      saltKey = SECURE_KEYS.DURESS_PIN_SALT;
    } else {
      hashKey = SECURE_KEYS.USER_PIN;
      saltKey = SECURE_KEYS.USER_PIN_SALT;
    }

    const hashSaved = await safeSecureStoreSet(hashKey, result.hash);
    const saltSaved = await safeSecureStoreSet(saltKey, result.salt);
    // Store version marker so verifyPin can skip legacy fallbacks.
    // Written under the generic _cp_N name (see SECURE_KEYS) — the old literal
    // 'DURESS_PIN_VERSION' item was a Keychain-visible proof that a duress PIN
    // existed, which defeats the decoy the feature exists to provide.
    const versionKey = type === 'duress' ? SECURE_KEYS.DURESS_PIN_VERSION : SECURE_KEYS.PIN_VERSION;
    await safeSecureStoreSet(versionKey, 'pbkdf2').catch((e) => console.warn("[best-effort]", e?.message || e));
    // Record the MAIN PIN's digit count so the unlock screen knows when an entry
    // is complete. Without it the screen has to guess, and guessing at a fixed 4
    // digits is what previously made 5-8 digit PINs impossible to enter. Not
    // secret (a length, not the PIN) and best-effort: a failure here only costs
    // the probe-and-backfill path on next unlock. Duress PINs are deliberately
    // excluded — storing their length would leak that a duress PIN exists.
    if (type !== 'duress' && hashSaved && saltSaved) {
      try {
        const { saveLocal, KEYS } = require('./storage');
        await saveLocal(KEYS.PIN_LENGTH, String(pin).length);
      } catch (e) { console.warn('[best-effort] pin length', e?.message || e); }
    }
    return hashSaved && saltSaved;
  } catch (e) {
    console.log('Failed to save PIN:', e?.message || String(e));
    return false;
  }
};

export const getSecurePin = async (type = 'main') => {
  let hashKey;
  if (type === 'duress') hashKey = SECURE_KEYS.DURESS_PIN;
  else hashKey = SECURE_KEYS.USER_PIN;
  // Retry only on thrown errors (iOS Keychain can temporarily reject reads
  // after rapid app background/foreground cycles). A clean `null` means
  // no PIN is set for this type — a valid state for biometric-only users
  // — so we return early without burning retry attempts or warning.
  let lastError = null;
  for (let i = 0; i < 3; i++) {
    try {
      return await safeSecureStoreGet(hashKey); // null is a legitimate answer
    } catch (e) {
      lastError = e;
      if (__DEV__) console.warn('getSecurePin attempt', i + 1, 'failed:', e.message);
      if (i < 2) await new Promise(r => setTimeout(r, 300));
    }
  }
  if (__DEV__ && lastError) console.warn('PIN keychain read failed after 3 retries:', lastError.message);
  return null;
};

// In-memory cache for PIN hash/salt to avoid repeated SecureStore reads
const _pinCache = {};

// Session verification: after first successful login, store a session token
// so subsequent logins use a single SHA-256 (~0.05ms) instead of PBKDF2 (~200-500ms)
const SESSION_TOKEN_KEY = 'session_verify_token';
const SESSION_DIGEST_KEY = 'session_verify_digest';

// Session timeout: require full PBKDF2 re-verification after inactivity
const SESSION_TIMEOUT_MS = 24 * 60 * 60 * 1000; // 24 hours — persisted to SecureStore for fast cold starts

// Lock to prevent concurrent PIN migrations from corrupting data
// Per-type migration lock to prevent concurrent migrations across main/duress
const _pinMigrationInProgress = new Map();

// AUDIT 2026-08-02 (round 14) — the app's single authoritative "is the lock
// open" flag.
//
// Round 13's deep-link stub routes inferred this from "a deep-link processor is
// registered", i.e. from app/hidden.js being MOUNTED. That is not the same
// thing: _layout locks with router.replace('/pin-entry'), which swaps only the
// TOP route, so hidden.js stays mounted underneath the PIN screen with its
// effects still registered. A link opened while the device was locked therefore
// read "unlocked" and replaced the lock screen with a fully populated Home.
//
// This flag is set at the ONE place the lock actually opens (pin-entry's
// playRevealAnimation, which covers PIN, biometric and duress alike — note
// _pinCache._session cannot serve this purpose, as biometric unlock never
// creates one) and is cleared by every path that closes it. It is module scope
// and in-memory only, so a cold start begins locked by construction.
let _appUnlocked = false;
export const markAppUnlocked = () => { _appUnlocked = true; };
export const isAppUnlocked = () => _appUnlocked;

/** Clear cached PIN data (call after PIN change or wipe) */
export const clearPinCache = () => {
  // AUDIT 2026-08-09 (round 51) — this no longer LOCKS the app.
  //
  // `_appUnlocked = false` lived here, and clearPinCache is called from SEVEN
  // sites inside verifyPin itself — every one an opportunistic re-hash branch
  // reached ONLY when the typed PIN has just MATCHED a legacy hash form. Those
  // callers mean "correct PIN, upgrade the KDF". They do not mean "lock the
  // app", and app/settings.js (which calls verifyPin while the user is already
  // unlocked and has no markAppUnlocked anywhere) was left in the half-locked
  // state rounds 42-45 kept re-discovering: no incoming-call overlay, no
  // banners, and nothing to unlock, because unlocking only happens at
  // pin-entry.
  //
  // Failure mode 143, literal: a side effect added to a shared function is
  // added to every caller. Clearing the CACHE and ENDING THE SESSION are two
  // different operations; the second one is clearPinSession(), which is the
  // funnel every genuine lock path already goes through. The two wipe callers
  // that did want the lock now say so explicitly.
  delete _pinCache.main;
  delete _pinCache.duress;
  delete _pinCache._session;
  // Return a Promise resolving when all SecureStore deletes have
  // landed. Without this, a caller that did `await clearPinCache();
  // await verifyPin(...)` would race — verifyPin's fast-path check
  // could read the OLD session token because the delete hadn't
  // completed yet. Callers that don't care can still ignore the
  // Promise (fire-and-forget compatibility preserved).
  return Promise.all([
    SecureStore ? SecureStore.deleteItemAsync('_pin_session').catch(() => {}) : Promise.resolve(),
    safeSecureStoreDelete(SESSION_TOKEN_KEY).catch(() => {}),
    safeSecureStoreDelete(SESSION_DIGEST_KEY).catch(() => {}),
  ]);
};

/** Clear only the session token (call when app goes to background).
 *  Forces full PBKDF2 PIN re-verification on next foreground entry. */
export const clearPinSession = () => {
  // Every lock path funnels through here (foreground re-lock in _layout,
  // pin-entry, change-pin), so clearing the flag here rather than at each call
  // site is what keeps it from drifting out of sync. change-pin also calls this
  // while the user is legitimately unlocked; the only consequence is that a
  // deep link arriving right afterwards routes via the lock screen, which is
  // the safe direction to be wrong in.
  _appUnlocked = false;
  delete _pinCache._session;
  // AUDIT 2026-08-08 (round 49) — drop any visible toast with the session.
  //
  // ToastProvider sits ABOVE the shell that owns every other overlay gate, so a
  // toast survives router.replace('/pin-entry') and paints over the lock screen
  // with a contact's handle and a live UNDO button. Hooked here because this
  // function's own comment above says every lock path funnels through it —
  // enumerating the lock sites by hand is what has failed repeatedly.
  // Lazy require: config/ must not pull an app/ component at module load.
  try { require('../app/components/Toast').hideToastForLock(); } catch (_) {}
};

/** Pre-warm PIN cache by loading hash/salt from SecureStore into memory.
 *  Call on app mount so verifyPin() doesn't block on SecureStore reads. */
export const preWarmPinCache = async () => {
  try {
    // Clean up any legacy persisted session (removed for security — sessions are in-memory only now)
    if (SecureStore) SecureStore.deleteItemAsync('_pin_session').catch((e) => console.warn("[best-effort]", e?.message || e));

    const types = ['main', 'duress'];
    await Promise.all(
      types.map(async (type) => {
        if (_pinCache[type]) return;
        const hash = await getSecurePin(type);
        if (!hash) return;
        let saltKey;
        if (type === 'duress') saltKey = SECURE_KEYS.DURESS_PIN_SALT;
        else saltKey = SECURE_KEYS.USER_PIN_SALT;
        const salt = await safeSecureStoreGet(saltKey);
        const version = await safeSecureStoreGet(type === 'duress' ? SECURE_KEYS.DURESS_PIN_VERSION : SECURE_KEYS.PIN_VERSION);
        _pinCache[type] = { hash, salt, version: version || null };
      }),
    );
  } catch (_) {}
};

export const verifyPin = async (inputPin, type = 'main') => {
  try {
    // Ultra-fast path: session verification for main PIN (~0.05ms vs ~200-500ms for PBKDF2)
    // After first successful login, a session token is stored so repeat logins skip PBKDF2.
    // Session expires after SESSION_TIMEOUT_MS of inactivity to enforce re-verification.
    if (type === 'main' && _pinCache._session?.token && _pinCache._session?.digest) {
      const elapsed = Date.now() - (_pinCache._session.createdAt || 0);
      if (elapsed < SESSION_TIMEOUT_MS) {
        const sessionCheck = sha256(_pinCache._session.token + inputPin);
        if (sessionCheck === _pinCache._session.digest) {
          // Refresh timestamp on successful use (sliding window)
          _pinCache._session.createdAt = Date.now();
          return true;
        }
      } else {
        // Session expired — clear it and force full PBKDF2 verification
        delete _pinCache._session;
      }
    }

    // Use cached values if available (avoids slow SecureStore reads)
    let storedHash, storedSalt, storedVersion;
    if (_pinCache[type]) {
      storedHash = _pinCache[type].hash;
      storedSalt = _pinCache[type].salt;
      storedVersion = _pinCache[type].version;
    } else {
      storedHash = await getSecurePin(type);
      if (!storedHash) return null; // null = couldn't read, distinct from false = wrong PIN

      let saltKey;
      if (type === 'duress') saltKey = SECURE_KEYS.DURESS_PIN_SALT;
      else saltKey = SECURE_KEYS.USER_PIN_SALT;
      const versionKey = type === 'duress' ? SECURE_KEYS.DURESS_PIN_VERSION : SECURE_KEYS.PIN_VERSION;
      const [salt, version] = await Promise.all([
        safeSecureStoreGet(saltKey),
        safeSecureStoreGet(versionKey).catch(() => null),
      ]);
      storedSalt = salt;
      storedVersion = version;

      // Cache for subsequent calls this session
      _pinCache[type] = { hash: storedHash, salt: storedSalt, version: storedVersion };
    }

    if (!storedHash) return false;

    // Helper: on successful main PIN match, create session for instant future logins
    const verified = (result) => {
      if (result && type === 'main') _createVerifySession(inputPin);
      return result;
    };

    if (storedSalt) {
      // Fast path: PBKDF2 with current iterations (600K) — ~12-20ms with native OpenSSL
      const pbkdf2Hash = await pbkdf2HmacSha256(inputPin, storedSalt, PIN_HASH_ITERATIONS);
      if (constantTimeEqual(storedHash, pbkdf2Hash)) return verified(true);

      // If PIN was saved with the current PBKDF2 version, try the legacy
      // iteration counts (10K/100K) — PINs created before C-B (when the count
      // could silently drop to 10K) still verify here, then re-save at 600K.
      if (storedVersion === 'pbkdf2') {
        // Try the other known PBKDF2 iteration counts. A match re-saves at the
        // current default (saveSecurePin uses PIN_HASH_ITERATIONS) — this is the
        // migration write-back: legacy 100K hashes are rehashed to 600K on the
        // next unlock (KAN-11). 600K is included so a hash saved on a native
        // session still verifies on a (rare) JS-fallback session; that single
        // verify may take ~2s in pure JS but prevents a lockout.
        const candidates = [
          LEGACY_PIN_HASH_ITERATIONS_10K,
          LEGACY_PIN_HASH_ITERATIONS_100K,
          PIN_HASH_ITERATIONS_V2,
        ];
        for (const iters of candidates) {
          if (iters === PIN_HASH_ITERATIONS) continue; // already tried on the fast path
          const candidateHash = await pbkdf2HmacSha256(inputPin, storedSalt, iters);
          if (constantTimeEqual(storedHash, candidateHash)) {
            if (!_pinMigrationInProgress.get(type)) {
              _pinMigrationInProgress.set(type, true);
              // Opportunistic re-hash of an ALREADY-VERIFIED pin. A failure leaves the
              // older stored form in place, which still verifies — the user is never
              // locked out, and the next unlock retries.
              // unchecked-write-ok: best-effort re-hash; old form still verifies
              try { await saveSecurePin(inputPin, type, { allowWeak: true }); clearPinCache(); } finally { _pinMigrationInProgress.delete(type); }
            }
            return verified(true);
          }
        }
        return false;
      }

      // Legacy: PBKDF2 with 100k iterations (kept for backward compat)
      const pbkdf2Hash100k = await pbkdf2HmacSha256(inputPin, storedSalt, LEGACY_PIN_HASH_ITERATIONS_100K);
      if (constantTimeEqual(storedHash, pbkdf2Hash100k)) {
        if (!_pinMigrationInProgress.get(type)) {
          _pinMigrationInProgress.set(type, true);
          // Opportunistic re-hash of an ALREADY-VERIFIED pin. A failure leaves the
              // older stored form in place, which still verifies — the user is never
              // locked out, and the next unlock retries.
              // unchecked-write-ok: best-effort re-hash; old form still verifies
              try { await saveSecurePin(inputPin, type, { allowWeak: true }); clearPinCache(); } finally { _pinMigrationInProgress.delete(type); }
        }
        return verified(true);
      }

      // Legacy: iterated SHA-256 with 100k iterations
      const legacy100k = legacyHashPin(inputPin, storedSalt, LEGACY_PIN_HASH_ITERATIONS_100K);
      if (constantTimeEqual(storedHash, legacy100k)) {
        if (!_pinMigrationInProgress.get(type)) {
          _pinMigrationInProgress.set(type, true);
          // Opportunistic re-hash of an ALREADY-VERIFIED pin. A failure leaves the
              // older stored form in place, which still verifies — the user is never
              // locked out, and the next unlock retries.
              // unchecked-write-ok: best-effort re-hash; old form still verifies
              try { await saveSecurePin(inputPin, type, { allowWeak: true }); clearPinCache(); } finally { _pinMigrationInProgress.delete(type); }
        }
        return verified(true);
      }

      // Legacy: iterated SHA-256 with 10k iterations
      const legacy10k = legacyHashPin(inputPin, storedSalt, LEGACY_PIN_HASH_ITERATIONS_10K);
      if (constantTimeEqual(storedHash, legacy10k)) {
        if (!_pinMigrationInProgress.get(type)) {
          _pinMigrationInProgress.set(type, true);
          // Opportunistic re-hash of an ALREADY-VERIFIED pin. A failure leaves the
              // older stored form in place, which still verifies — the user is never
              // locked out, and the next unlock retries.
              // unchecked-write-ok: best-effort re-hash; old form still verifies
              try { await saveSecurePin(inputPin, type, { allowWeak: true }); clearPinCache(); } finally { _pinMigrationInProgress.delete(type); }
        }
        return verified(true);
      }

      // Legacy: 1k iterations (pre-hardening)
      const legacy1k = legacyHashPin(inputPin, storedSalt, LEGACY_PIN_HASH_ITERATIONS_1K);
      if (constantTimeEqual(storedHash, legacy1k)) {
        if (!_pinMigrationInProgress.get(type)) {
          _pinMigrationInProgress.set(type, true);
          // Opportunistic re-hash of an ALREADY-VERIFIED pin. A failure leaves the
              // older stored form in place, which still verifies — the user is never
              // locked out, and the next unlock retries.
              // unchecked-write-ok: best-effort re-hash; old form still verifies
              try { await saveSecurePin(inputPin, type, { allowWeak: true }); clearPinCache(); } finally { _pinMigrationInProgress.delete(type); }
        }
        return verified(true);
      }

      // Backward compat: single-round SHA-256 (pre-hardening PINs)
      const singleRoundHash = sha256(storedSalt + inputPin);
      if (constantTimeEqual(storedHash, singleRoundHash)) {
        if (!_pinMigrationInProgress.get(type)) {
          _pinMigrationInProgress.set(type, true);
          // Opportunistic re-hash of an ALREADY-VERIFIED pin. A failure leaves the
              // older stored form in place, which still verifies — the user is never
              // locked out, and the next unlock retries.
              // unchecked-write-ok: best-effort re-hash; old form still verifies
              try { await saveSecurePin(inputPin, type, { allowWeak: true }); clearPinCache(); } finally { _pinMigrationInProgress.delete(type); }
        }
        return verified(true);
      }
      return false;
    } else {
      // No stored salt: legacy static-salt hash. After a successful match
      // here, migrate the user up to current PBKDF2 via saveSecurePin so
      // the next verifyPin call takes the fast/strong path. Without this
      // migration step (audit C-M7), users with pre-salted-PBKDF2 PINs
      // stayed on the legacy single-round SHA-256 with a static salt
      // forever — strictly weaker than every other branch above. Mirrors
      // the migration pattern used at lines ~1442, 1457, 1471, 1481, 1491,
      // 1501, 1511 above (all the salted legacy paths already migrate).
      const _migrateStaticSalt = async () => {
        if (type !== 'main' && type !== 'duress') return;
        if (_pinMigrationInProgress.get(type)) return;
        _pinMigrationInProgress.set(type, true);
        // Opportunistic re-hash of an ALREADY-VERIFIED pin. A failure leaves the
              // older stored form in place, which still verifies — the user is never
              // locked out, and the next unlock retries.
              // unchecked-write-ok: best-effort re-hash; old form still verifies
              try { await saveSecurePin(inputPin, type, { allowWeak: true }); clearPinCache(); }
        finally { _pinMigrationInProgress.delete(type); }
      };

      const legacyHash = sha256(LEGACY_PIN_SALT + inputPin);
      if (constantTimeEqual(storedHash, legacyHash)) {
        await _migrateStaticSalt();
        return verified(true);
      }

      const legacyHashOldOrder = sha256(inputPin + LEGACY_PIN_SALT);
      if (constantTimeEqual(storedHash, legacyHashOldOrder)) {
        await _migrateStaticSalt();
        return verified(true);
      }
      return false;
    }
  } catch (e) {
    console.log('Failed to verify PIN:', e?.message || String(e));
    return false;
  }
};

// Decoy salt/hash used so verifyUnlockPin does identical CPU work whether or not
// a given PIN type is configured — otherwise "a duress PIN is set up" would be
// timeable. Never compared against anything real; only there to burn the same
// PBKDF2 + compare cost.
// Hex constants matching the REAL formats: salts are 16 bytes (32 hex, per
// hashPin's nacl.randomBytes(16)); the decoy hash MUST be 64 hex chars like a
// real PBKDF2 hash — constantTimeEqual early-returns on a length mismatch, so
// a wrong-length decoy would skip the compare loop and make "duress configured"
// timeable again. Must stay synchronous module-load constants.
const _UNLOCK_DECOY_SALT = sha256('theSHFT_unlock_decoy_salt_v1').slice(0, 32);
const _UNLOCK_DECOY_HASH = sha256('theSHFT_unlock_decoy_hash_v1');
// Guard the length invariants at module load so an sha256 swap can't silently
// break the timing symmetry. Deterministic — can only fire on a code change.
if (_UNLOCK_DECOY_SALT.length !== 32 || _UNLOCK_DECOY_HASH.length !== 64) {
  throw new Error('unlock decoy constants violate length invariants (salt=32 hex, hash=64 hex)');
}

// Symmetric storage read for the duress-sensitive unlock path. safeSecureStoreGet
// does ASYMMETRIC work on a MISS (extra legacy-key probe + AsyncStorage fallback)
// vs a HIT (single read + lazy re-save) — so "is this PIN type configured" is
// timeable one layer below verifyUnlockPin (KAN-20 audit HIGH). This always runs
// the SAME fixed reads — current SecureStore + legacy SecureStore + AsyncStorage,
// in parallel, no early-return, no lazy re-save — so a configured and an
// unconfigured type do identical I/O. Returns the first non-null in priority.
const _unlockReadSecure = async (currentKey, legacyKey) => {
  const sanCur = sanitizeKeyForSecureStore(currentKey);
  const sanLeg = legacyKey ? sanitizeKeyForSecureStore(legacyKey) : null;
  const [cur, leg, asy] = await Promise.all([
    SecureStore ? SecureStore.getItemAsync(sanCur, KEYCHAIN_OPTIONS).catch(() => null) : Promise.resolve(null),
    (SecureStore && sanLeg) ? SecureStore.getItemAsync(sanLeg, KEYCHAIN_OPTIONS).catch(() => null) : Promise.resolve(null),
    AsyncStorage.getItem(currentKey).catch(() => null),
  ]);
  return cur ?? leg ?? asy ?? null;
};

/**
 * Constant-time unlock verification for the duress-sensitive entry path (KAN-20).
 *
 * Unlike verifyPin(), this:
 *   - has NO session fast-path,
 *   - ALWAYS computes PBKDF2 against BOTH the main and duress salts (a decoy
 *     salt stands in when a type isn't configured),
 *   - always runs BOTH constant-time compares before branching.
 * So entering the real PIN vs the duress PIN takes the same observable time — a
 * coercer measuring unlock latency can't distinguish them, and can't even tell
 * whether a duress PIN exists.
 *
 * Covers CURRENT-version PBKDF2 PINs (the steady state; verifyPin migrates
 * everyone forward on unlock). A pre-migration legacy PIN won't match here →
 * returns 'none'; the caller falls back to verifyPin() for that rare case (that
 * fallback is NOT constant-time — documented; it only affects un-migrated PINs).
 *
 * 'error' = the main PIN couldn't be read (transient Keychain failure — the main
 * PIN always exists at the unlock screen, so a null read is NOT a wrong PIN; the
 * caller must retry without counting a failed attempt).
 *
 * @returns {Promise<'main'|'duress'|'none'|'error'>}
 */
export const verifyUnlockPin = async (inputPin) => {
  try {
    // Symmetric storage read (NOT _pinCache, NOT getSecurePin/safeSecureStoreGet
    // — those branch on hit/miss and retry, leaking config state). _unlockReadSecure
    // does identical fixed I/O for both types so configured-vs-not and cold-vs-warm
    // are not timeable (KAN-20 audit HIGH).
    const load = async (type) => {
      const isD = type === 'duress';
      const [hash, salt] = await Promise.all([
        _unlockReadSecure(isD ? SECURE_KEYS.DURESS_PIN : SECURE_KEYS.USER_PIN,
          isD ? LEGACY_SECURE_KEYS.DURESS_PIN : LEGACY_SECURE_KEYS.USER_PIN),
        _unlockReadSecure(isD ? SECURE_KEYS.DURESS_PIN_SALT : SECURE_KEYS.USER_PIN_SALT,
          isD ? LEGACY_SECURE_KEYS.DURESS_PIN_SALT : LEGACY_SECURE_KEYS.USER_PIN_SALT),
      ]);
      return { hash: hash || null, salt: salt || null };
    };
    const [main, duress] = await Promise.all([load('main'), load('duress')]);

    // Always PBKDF2 for BOTH — decoy salt when a type is absent so the work
    // (and time) is identical regardless of which/whether PINs are configured.
    const [mainCand, duressCand] = await Promise.all([
      pbkdf2HmacSha256(inputPin, main.salt || _UNLOCK_DECOY_SALT, PIN_HASH_ITERATIONS),
      pbkdf2HmacSha256(inputPin, duress.salt || _UNLOCK_DECOY_SALT, PIN_HASH_ITERATIONS),
    ]);

    // Both PBKDF2s ran; a missing MAIN hash means a Keychain read failure (main
    // must exist here), not a wrong PIN — signal the caller to retry.
    if (!main.hash) return 'error';

    // Always run BOTH compares (decoy hash when absent), THEN branch on the
    // booleans — no short-circuit that would shave time off one outcome.
    const mainEq = constantTimeEqual(main.hash, mainCand);
    const duressEq = constantTimeEqual(duress.hash || _UNLOCK_DECOY_HASH, duressCand);
    const mainMatch = mainEq;
    const duressMatch = duressEq && !!duress.hash;

    if (mainMatch) return 'main';
    if (duressMatch) return 'duress';
    return 'none';
  } catch (e) {
    // No logging on the duress-sensitive path: a log fires only on the error
    // branch and never on success, which is itself a main-vs-duress oracle
    // (KAN-20 audit). Dev-only.
    if (typeof __DEV__ !== 'undefined' && __DEV__) console.log('verifyUnlockPin error:', e?.name);
    return 'error';
  }
};

/** Create a session token after successful PIN verification for instant future logins.
 *  Uses SHA-256(random_token + PIN) — single hash check on next login instead of PBKDF2.
 *
 *  SECURITY FIX: The session token is kept in-memory only. It is NOT persisted
 *  to SecureStore. This ensures that a full PBKDF2 check is required on every
 *  fresh app launch, and the fast SHA-256 path only works within the current
 *  app session (process lifetime). This prevents an attacker with device access
 *  from bypassing PBKDF2 by extracting the persisted session token. */
const _createVerifySession = (inputPin) => {
  try {
    const token = encodeBase64(nacl.randomBytes(32));
    const digest = sha256(token + inputPin);
    const createdAt = Date.now();
    _pinCache._session = { token, digest, createdAt };
    // In-memory only — never persisted. A full PBKDF2 check is required on
    // every fresh app launch. The fast SHA-256 session path only works within
    // the current process lifetime.
  } catch (e) { /* non-critical */ }
};

export const deleteSecurePin = async (type = 'main') => {
  try {
    let hashKey, saltKey, versionKey;
    if (type === 'duress') {
      hashKey = SECURE_KEYS.DURESS_PIN;
      saltKey = SECURE_KEYS.DURESS_PIN_SALT;
      versionKey = SECURE_KEYS.DURESS_PIN_VERSION;
    } else {
      hashKey = SECURE_KEYS.USER_PIN;
      saltKey = SECURE_KEYS.USER_PIN_SALT;
      versionKey = SECURE_KEYS.PIN_VERSION;
    }
    await safeSecureStoreDelete(saltKey);
    // Remove the KDF version marker too. Leaving it behind meant that after
    // "Remove duress PIN" the Keychain still contained a duress-specific item
    // forever — evidence that a duress PIN had been configured on this device.
    // Also purge the pre-rename literal name for installs that still carry it.
    await safeSecureStoreDelete(versionKey);
    await safeSecureStoreDelete(type === 'duress' ? LEGACY_SECURE_KEYS.DURESS_PIN_VERSION : LEGACY_SECURE_KEYS.PIN_VERSION);
    // Drop the in-memory cache for this PIN type — otherwise a subsequent
    // verifyPin would still succeed against the deleted hash for the rest of
    // the process lifetime.
    delete _pinCache[type];
    return await safeSecureStoreDelete(hashKey);
  } catch (e) {
    console.log('Failed to delete PIN:', e?.message || String(e));
    return false;
  }
};

export const hasSecurePin = async (type = 'main') => {
  const hash = await getSecurePin(type);
  return !!hash;
};

// AUDIT 2026-08-03 (round 16) — hasSecurePin CANNOT distinguish "no PIN" from
// "the Keychain read failed"; both come back false, because safeSecureStoreGet
// swallows the error and returns null. Anything that takes an irreversible or
// security-relevant action on "there is no PIN" must use this instead.
//
// Returns { known, exists }:
//   known:false            -> the Keychain failed; existence is UNKNOWN.
//   known:true, exists:F   -> there is definitively no PIN of this type.
export const probeSecurePin = async (type = 'main') => {
  const hashKey = type === 'duress' ? SECURE_KEYS.DURESS_PIN : SECURE_KEYS.USER_PIN;
  try {
    // Reads EXACTLY the key getSecurePin reads, and no other. A probe that
    // asks a different question than the operation it guards is the single
    // most common defect this audit keeps finding; if getSecurePin ever gains
    // a legacy fallback, this must gain the same one.
    const r = await readSecureValueStrict(hashKey);
    if (!r.ok) return { known: false, exists: false };
    return { known: true, exists: !!r.value };
  } catch (_) {
    return { known: false, exists: false };
  }
};

// ============================================
// RECOVERY PHRASE
// ============================================

/**
 * Encrypt the recovery phrase with the device encryption key before storing.
 * Even if SecureStore is compromised, the phrase is encrypted with a separate
 * NaCl secretbox key, adding a second layer of defense.
 */
export const saveSecurePhrase = async (phrase) => {
  // Web identity guard (2026-09-16, P2-E): a web build never stores a phrase.
  // Callers already treat false as "could not store", which is the truth here.
  if (WEB_PHRASE_BLOCKED) { refuseWebPhrase('saveSecurePhrase'); return false; }
  if (!phrase || typeof phrase !== 'string') {
    console.warn('saveSecurePhrase: Invalid phrase');
    return false;
  }
  try {
    const encKey = await getOrCreateEncryptionKey();
    if (encKey) {
      const keyBytes = decodeBase64(encKey).slice(0, nacl.secretbox.keyLength);
      const nonce = nacl.randomBytes(nacl.secretbox.nonceLength);
      const ciphertext = nacl.secretbox(decodeUTF8(phrase), nonce, keyBytes);
      const encrypted = 'enc:' + encodeBase64(nonce) + ':' + encodeBase64(ciphertext);
      return await safeSecureStoreSet(SECURE_KEYS.RECOVERY_PHRASE, encrypted);
    }
  } catch (e) {
    console.warn('saveSecurePhrase: encryption failed');
  }
  // SECURITY: never write the bare recovery phrase to disk. The inner
  // nacl.secretbox layer exists as defense in depth against SecureStore
  // compromise; falling back to plaintext defeats that layer silently.
  // If we can't encrypt, surface the failure — the caller still has the
  // phrase in memory and can prompt the user to retry.
  return false;
};

export const getSecurePhrase = async () => {
  // Web identity guard (2026-09-16, P2-E): the read is refused as well as the
  // write, so a phrase left in IndexedDB by an earlier dev-flag session at the
  // same origin can never be served to a build without the flag.
  if (WEB_PHRASE_BLOCKED) { refuseWebPhrase('getSecurePhrase'); return null; }
  const stored = await safeSecureStoreGet(SECURE_KEYS.RECOVERY_PHRASE);
  if (!stored) return null;
  // Decrypt if encrypted (prefixed with 'enc:')
  if (stored.startsWith('enc:')) {
    try {
      const parts = stored.split(':');
      if (parts.length !== 3) return null;
      const nonce = decodeBase64(parts[1]);
      const ciphertext = decodeBase64(parts[2]);
      const encKey = await getOrCreateEncryptionKey();
      if (!encKey) return null;
      const keyBytes = decodeBase64(encKey).slice(0, nacl.secretbox.keyLength);
      const decrypted = nacl.secretbox.open(ciphertext, nonce, keyBytes);
      if (!decrypted) return null;
      return encodeUTF8(decrypted);
    } catch (e) {
      return null;
    }
  }
  // Legacy plaintext — migrate to encrypted on next save
  return stored;
};

// ============================================
// WIPE / CLEANUP
// ============================================

// ─── Per-identity Keychain item index ─────────────────────────────────
// config/storage.js stores one item per identity — '_identity_phrase_<uid>'
// (the raw BIP39 phrase) and '_identity_pin_<uid>'. expo-secure-store has no
// "list all items" API, and every wipe path clears AsyncStorage BEFORE the
// Keychain (clearAll → clearSecureStorage), so by the time we want to delete
// those items the uids that name them are already gone. We therefore keep a
// small index of ids in the Keychain itself, refreshed once per process at the
// point the at-rest key is first resolved (app boot).
const _IDENTITY_INDEX_MAX = 20;
if (_e.identityIndexWarmed === undefined) _e.identityIndexWarmed = false;

const _readIdentityIndex = async () => {
  try {
    const raw = await safeSecureStoreGet(SECURE_KEYS.IDENTITY_INDEX);
    if (!raw) return [];
    const parsed = JSON.parse(raw);
    return Array.isArray(parsed) ? parsed.filter((v) => typeof v === 'string' && v) : [];
  } catch (_) { return []; }
};

// Best-effort discovery from local storage. Works only while AsyncStorage is
// still intact (remote wipe, demo reset, restore, logout) — the panic/duress
// paths clear it first, which is exactly why the index above exists.
const _discoverIdentityIdsFromStorage = async () => {
  const ids = [];
  try {
    const { getLocal, KEYS } = require('./storage');
    const [active, identities, user] = await Promise.all([
      Promise.resolve(getLocal(KEYS.ACTIVE_IDENTITY)).catch(() => null),
      Promise.resolve(getLocal(KEYS.IDENTITIES)).catch(() => null),
      Promise.resolve(getLocal(KEYS.USER)).catch(() => null),
    ]);
    if (typeof active === 'string' && active) ids.push(active);
    if (Array.isArray(identities)) for (const it of identities) { if (it?.id) ids.push(it.id); }
    if (user?.id) ids.push(user.id);
  } catch (_) {}
  return ids;
};

// Never throws and never rejects — callers fire it and forget.
const _warmIdentityIndex = async () => {
  if (_e.identityIndexWarmed) return;
  try {
    const discovered = await _discoverIdentityIdsFromStorage();
    // AUDIT 2026-07-26 — the latch used to be set HERE, before this line, so
    // the very first call in the process won permanently even when it found
    // nothing. That call routinely happens at boot, BEFORE any account is
    // restored or created, so discovery came back empty, the flag latched, and
    // the index was never populated for the rest of the process.
    //
    // The consequence is that the duress/panic wipe misses per-identity
    // Keychain items: _collectIdentityIds resolves the ids to delete from this
    // index, and an empty index means @identity_phrase_{id} — the PLAINTEXT
    // BIP39 recovery phrase — survives the wipe that exists to destroy it.
    // The decoy looks like a fresh install while the phrase that unlocks the
    // account is still in the Keychain.
    //
    // Latch only on a discovery that actually found something, so a later call
    // (once an identity exists) still populates it. clearSecureStorage sets the
    // flag explicitly to latch this CLOSED for the duration of a wipe — that is
    // a different purpose and is unaffected.
    if (!discovered.length) return;
    const existing = await _readIdentityIndex();
    const merged = Array.from(new Set([...existing, ...discovered])).slice(-_IDENTITY_INDEX_MAX);
    if (merged.length === existing.length && merged.every((v, i) => v === existing[i])) {
      _e.identityIndexWarmed = true;
      return;
    }
    // AUDIT 2026-08-08 (round 40) — LATCH ON THE WRITE, not before it.
    //
    // _e.identityIndexWarmed was set above this line, so a refused
    // safeSecureStoreSet left the index unwritten with no retry possible for
    // the rest of the process — the latch had already won. That is precisely
    // the state the comment above describes: _collectIdentityIds finds nothing,
    // and the duress/panic wipe misses @identity_phrase_{id}, the PLAINTEXT
    // BIP39 recovery phrase. The decoy looks like a fresh install while the
    // phrase that unlocks the whole account is still in the Keychain for
    // whoever coerced it.
    if (await safeSecureStoreSet(SECURE_KEYS.IDENTITY_INDEX, JSON.stringify(merged))) {
      _e.identityIndexWarmed = true;
    } else {
      console.log('[wipe-index] identity index not persisted — leaving unlatched so a later call retries');
    }
  } catch (_) {}
};

/**
 * Every identity id we can find that may own per-identity Keychain items:
 * caller-supplied, the persisted index, and whatever local storage still holds.
 * Exported so a caller that knows the ids (e.g. an account-delete flow) can
 * hand them in explicitly rather than relying on discovery.
 */
export const rememberIdentityIdsForWipe = async (ids) => {
  if (!Array.isArray(ids) || !ids.length) return false;
  try {
    const existing = await _readIdentityIndex();
    const merged = Array.from(new Set([...existing, ...ids.filter((v) => typeof v === 'string' && v)]))
      .slice(-_IDENTITY_INDEX_MAX);
    return await safeSecureStoreSet(SECURE_KEYS.IDENTITY_INDEX, JSON.stringify(merged));
  } catch (_) { return false; }
};

const _collectIdentityIds = async (extra) => {
  const set = new Set();
  if (Array.isArray(extra)) for (const id of extra) { if (typeof id === 'string' && id) set.add(id); }
  try { for (const id of await _readIdentityIndex()) set.add(id); } catch (_) {}
  try { for (const id of await _discoverIdentityIdsFromStorage()) set.add(id); } catch (_) {}
  // 'main' is the literal id used by the legacy single-identity path
  // (app/hidden.js getIdentityPhrase('main')), so it always gets swept.
  set.add('main');
  return Array.from(set);
};

// Keychain items that hold user secrets or user-identifying state but are NOT
// in SECURE_KEYS, because they're owned by other modules. Every wipe path
// (panic / duress / remote / account delete / logout) funnels through
// clearSecureStorage, so this is where they have to be cleaned up — the audit
// found all of them surviving a wipe.
//
// Deliberately NOT in this list:
//   • '_secure_shift_device_id' — deleting it on every call would regenerate a
//     device id on ordinary logout, which breaks checkDeviceHasAccount and the
//     per-device account limit. Pass { includeDeviceId: true } from the
//     destructive paths instead (see below).
//   • 'mmkv-encryption-key' — config/storage.js opens MMKV synchronously at
//     module load with this key. Deleting it leaves an MMKV file on disk that
//     the next launch cannot open, and the `new MMKV()` throw is swallowed, so
//     MMKV silently stays disabled FOREVER on that install (AsyncStorage-only,
//     permanent perf regression). Erasing it needs the MMKV file deleted in the
//     same step — that lives in config/storage.js, not here. Tracked, not fixed.
const EXTRA_SECURE_ITEMS = [
  // Pre-rename PIN KDF version markers. New writes go to _cp_12/_cp_13 (in
  // SECURE_KEYS); these clean up installs that haven't migrated yet.
  LEGACY_SECURE_KEYS.PIN_VERSION,
  LEGACY_SECURE_KEYS.DURESS_PIN_VERSION,
  // Fast-path PIN session material (config/encryption.js clearPinCache).
  SESSION_TOKEN_KEY,
  SESSION_DIGEST_KEY,
  '_pin_session',
  // config/security.js — reveals prior failed-unlock activity.
  '_login_lockout_until',
  // Cached entitlement (config/purchases.js).
  '_premium_status',
  // Wrapping key for large secrets (ML-KEM private keys etc). Deleting it is
  // cryptographic erasure of every '@wrapped_' blob left in AsyncStorage.
  // 9.4 S9 (LEAK-I2): the blobs themselves are swept below as well, so a
  // wipe leaves neither the key nor the ciphertext behind.
  WRAP_KEY_SS_NAME,
];

/**
 * @param {{ identityIds?: string[], includeDeviceId?: boolean }} [options]
 *   identityIds     — extra identity ids whose per-identity Keychain items
 *                     should be purged, on top of the ones we discover.
 *   includeDeviceId — also delete the SecureStore device id. Only for full
 *                     destruction (panic wipe / duress wipe / remote wipe /
 *                     account delete), never for logout.
 */
export const clearSecureStorage = async (options = {}) => {
  try {
    // AUDIT 2026-08-03 (round 21) — track whether every delete ACTUALLY
    // landed. This function returned true unconditionally, so round 20's
    // "check the RETURN VALUE" hard-stop in the forced sign-out was still
    // unreachable, and so were panic-wipe's error report and the duress
    // retry. A Keychain that refuses to delete (errSecInteractionNotAllowed
    // on a not-yet-unlocked device) left the E2E keys, recovery phrase and
    // PIN on disk while every caller was told the wipe succeeded.
    let _wipeOk = true;
    // Latch the index warm CLOSED for the duration of the wipe. _collectIdentityIds
    // reads through config/storage.js, which can lazily resolve the at-rest key and
    // fire the (fire-and-forget) warm — a warm that landed after the delete loop
    // would rewrite _cp_14 and leave a list of uids in the Keychain of a device
    // that is supposed to look freshly installed.
    _e.identityIndexWarmed = true;
    // FIRST, before anything is deleted: work out which per-identity Keychain
    // items exist. This has to happen while _cp_1 (which decrypts AsyncStorage)
    // and _cp_14 (the index) are still readable.
    const identityIds = await _collectIdentityIds(options?.identityIds);

    const keys = Object.values(SECURE_KEYS);
    for (const key of keys) {
      if ((await safeSecureStoreDelete(key)) !== true) _wipeOk = false;
    }
    for (const key of EXTRA_SECURE_ITEMS) {
      if ((await safeSecureStoreDelete(key)) !== true) _wipeOk = false;
    }
    if (options?.includeDeviceId) {
      if ((await safeSecureStoreDelete('_secure_shift_device_id')) !== true) _wipeOk = false;
    }

    // Per-identity Keychain items. config/storage.js saveIdentityPhrase writes
    // the account's BIP39 recovery phrase to '_identity_phrase_<uid>' in
    // PLAINTEXT (unlike SECURE_KEYS.RECOVERY_PHRASE, which is secretbox-wrapped
    // first), and nothing except deleteIdentity() ever removed it. The phrase
    // deterministically regenerates the long-term Curve25519 identity private
    // key (deriveKeysFromPhrase), so leaving it behind defeats the whole point
    // of the cryptographic erasure this function performs — most acutely in the
    // duress-wipe threat model, where the adversary is holding the device.
    for (const id of identityIds) {
      if ((await safeSecureStoreDelete('@identity_phrase_' + id)) !== true) _wipeOk = false;
      if ((await safeSecureStoreDelete('@identity_pin_' + id)) !== true) _wipeOk = false;
    }

    // Clear in-memory caches
    delete _pinCache.main;
    delete _pinCache.duress;
    delete _pinCache._session;
    _e.ratchetStorageKeyCache = null;
    _e.ratchetStorageKeyLock = null;
    // 9.4 S9 (LEAK-I2) — an in-flight get-or-create of the wrapping key must
    // not hand a caller the key that was just deleted from the Keychain.
    _e.wrappingKeyLock = null;
    // The at-rest master key is gone from the Keychain — it must not survive in
    // memory either, or the rest of this process would keep encrypting new data
    // under a key that no longer exists anywhere on disk.
    _e.encryptionKeyCache = null;

    // Also clear all ratchet session keys, sender keys, archives, and
    // X3DH material from AsyncStorage. These contain chain keys that
    // could decrypt past/future messages — a panic wipe / duress wipe
    // must remove them.
    try {
      const allKeys = await AsyncStorage.getAllKeys();
      const sensitiveKeys = allKeys.filter(k =>
        k.startsWith(RATCHET_SESSION_PREFIX)
        || k.startsWith('@known_pubkey_')
        || k.startsWith(PEER_PUBKEY_ARCHIVE_PREFIX)
        || k.startsWith('@sk_archive_')
        || k.startsWith('@recv_sk_archive_')
        || k.startsWith('@sender_key_')
        || k.startsWith('@recv_sender_key_')
        || k.startsWith('@sk_msg_count_')
        || k.startsWith('@x3dh_material_')
        || k.startsWith('@sent_')
        // 9.4 S9 (LEAK-I2) — wrapped large secrets (the ML-KEM private key,
        // the keychain-migration recovery backups). Their wrapping key
        // (_lwk_1) is deleted above; removing the ciphertext too means a
        // future wipe path that skips the Keychain still leaves nothing to
        // unwrap.
        || k.startsWith(WRAPPED_VALUE_PREFIX)
      );
      if (sensitiveKeys.length > 0) {
        await AsyncStorage.multiRemove(sensitiveKeys);
      }
    } catch (ratchetErr) {
      console.log('Failed to clear ratchet sessions:', ratchetErr);
    }

    // Cryptographic erasure of the local SQLite message cache: delete the
    // at-rest DB key (shft-db-cache-key-v1) so any cbox1: ciphertext that
    // survives a logical row delete (freelist / WAL remnants) is permanently
    // undecryptable. This key is NOT in SECURE_KEYS, so it must be deleted
    // explicitly here — every wipe path (panic / duress / remote / account
    // delete) routes through clearSecureStorage.
    try {
      const dbCrypto = require('./dbCrypto');
      if (dbCrypto.clearKey) await dbCrypto.clearKey();
    } catch (dbKeyErr) {
      console.log('Failed to clear DB cache key:', dbKeyErr?.message || dbKeyErr);
    }

    // Final sweep of the identity index. Anything above that lazily resolved the
    // at-rest key could have re-published it; this is the LAST Keychain write of
    // the wipe, so nothing can put it back afterwards. Only then do we unlatch
    // the warm so a future account can rebuild the index.
    // AUDIT 2026-08-03 (round 24) — only retire the INDEX once the deletes it
    // enables have actually succeeded.
    //
    // The index is the only record of WHICH identities have Keychain material
    // to purge. Deleting it unconditionally meant a pass that partially failed
    // still destroyed the map: the duress retry (3 attempts) and the panic
    // retry (2 attempts) then re-read an EMPTY index, collapsed to ['main'],
    // and never attempted '@identity_phrase_<realUid>' again — every later
    // delete a no-op on an already-missing key, so the loop "succeeded" with
    // the real account's recovery phrase still on the device. Under coercion
    // that is the entire failure the duress PIN exists to prevent.
    //
    // Keeping it on failure costs nothing: the next attempt finds the same list.
    if (_wipeOk) {
      if ((await safeSecureStoreDelete(SECURE_KEYS.IDENTITY_INDEX)) !== true) _wipeOk = false;
    } else {
      console.log('clearSecureStorage: per-identity deletes failed — KEEPING the index so a retry can find them');
    }
    _e.identityIndexWarmed = false;

    if (!_wipeOk) console.log('clearSecureStorage: one or more Keychain deletes FAILED');
    return _wipeOk;
  } catch (e) {
    console.log('Failed to clear secure storage:', e?.message || String(e));
    // Unlatch even on failure — a wedged latch would silently stop the identity
    // index from tracking new accounts for the rest of the process.
    _e.identityIndexWarmed = false;
    return false;
  }
};

export const deleteSecureData = clearSecureStorage;

// ============================================
// SYMMETRIC ENCRYPTION (NaCl secretbox + key distribution via NaCl box)
// Used by Stories for per-viewer key encryption
// ============================================

// ============================================
// MIGRATION: AsyncStorage → SecureStore
// ============================================

/**
 * Migrate all sensitive keys from AsyncStorage to expo-secure-store.
 * Safe to call multiple times — skips keys already in SecureStore.
 * No-op if expo-secure-store is not available.
 *
 * @returns {{ migrated: string[], skipped: string[], failed: string[] }}
 */
/**
 * One-time fix for the "User interaction is not allowed" failure pattern
 * on PushKit cold-wake. SecureStore items written under the OLD default
 * accessibility (WHEN_UNLOCKED) require the device to be CURRENTLY
 * unlocked, not just first-unlocked-since-boot. Items written under the
 * new AFTER_FIRST_UNLOCK_THIS_DEVICE_ONLY accessibility work on cold-wake.
 *
 * iOS keychain doesn't let you change the accessibility class in place —
 * you must read, delete, and re-write. This routine does that for every
 * SECURE_KEY. It only succeeds when the device is unlocked at the moment
 * of execution; calling it from any foreground entry point (app open
 * after user-unlock, post-PIN screen) reliably catches the unlocked
 * window. Subsequent cold-wakes will then have items with the correct
 * accessibility and SecureStore reads will work.
 *
 * Safe to run repeatedly — checked via the `_kcMigrationDone` flag in
 * AsyncStorage. Set after a successful pass.
 */
export const rewriteKeychainAccessibility = async () => {
  if (!SecureStore) return { rewritten: [], failed: [], skipped: 'no-securestore' };
  let _migDone = false;
  try { _migDone = (await AsyncStorage.getItem('_kcMigrationDone')) === '1'; } catch (_) {}

  const result = { rewritten: [], failed: [] };
  // Skip the rewrite loop once migrated, but ALWAYS fall through to the
  // recovery/cleanup sweep below — it purges any straggler `_kcRecover_*`
  // backup, including a LEGACY PLAINTEXT orphan from a pre-wrapping build, even
  // on an already-"done" device.
  for (const key of (_migDone ? [] : Object.values(SECURE_KEYS))) {
    const sanitizedKey = sanitizeKeyForSecureStore(key);
    let value = null;
    try {
      // Step 1: read existing value with the new options.
      value = await SecureStore.getItemAsync(sanitizedKey, KEYCHAIN_OPTIONS);
    } catch (_) {
      continue; // can't read — leave the existing item alone, retry next launch
    }
    if (value === null) continue; // nothing to rewrite

    // Step 2: BACK UP before touching the keychain — but WRAPPED, never
    // plaintext (leak-audit H2). The raw value can be the master ENCRYPTION_KEY
    // or an identity private key, which must not land in unencrypted
    // AsyncStorage. Keeps the key-loss safety net (a setItemAsync failure
    // between delete and re-add is still recoverable from the backup), now
    // encrypted. If wrapping is impossible (wrapping key unreadable), do NOT
    // write plaintext and do NOT disturb this keychain item — retry next launch.
    const backupKey = '_kcRecover_' + sanitizedKey;
    const wrappedBackup = await _wrapKcBackup(value);
    if (!wrappedBackup) { result.failed.push(key); continue; }
    // Don't touch the keychain item unless the backup actually landed — a
    // swallowed setItem failure followed by the delete below would leave the
    // secret unrecoverable (review #1).
    let _backedUp = false;
    try { await AsyncStorage.setItem(backupKey, wrappedBackup); _backedUp = true; } catch (_) {}
    if (!_backedUp) { result.failed.push(key); continue; }

    try {
      // Step 3: delete the existing item (clears whatever accessibility
      // it had attached).
      try { await SecureStore.deleteItemAsync(sanitizedKey, KEYCHAIN_OPTIONS); } catch (_) {}
      // Step 4: re-write with the CORRECT accessibility.
      await SecureStore.setItemAsync(sanitizedKey, value, KEYCHAIN_OPTIONS);
      // Step 5: verify the write landed.
      const verify = await SecureStore.getItemAsync(sanitizedKey, KEYCHAIN_OPTIONS);
      if (verify === value) {
        result.rewritten.push(key);
        // Verified — safe to delete the backup.
        try { await AsyncStorage.removeItem(backupKey); } catch (_) {}
      } else {
        result.failed.push(key);
        // Leave the backup in place for next-launch recovery.
      }
    } catch (e) {
      result.failed.push(key);
      // Leave the backup in place for next-launch recovery.
    }
  }

  // Recovery + cleanup sweep: restore any `_kcRecover_*` backup whose keychain
  // item didn't land, and PURGE every backup once it's safe — including LEGACY
  // PLAINTEXT orphans from a pre-wrapping build (_unwrapKcBackup unwraps the new
  // 'kcw1:' format and passes legacy plaintext through, then we delete it).
  let _orphanRemaining = false;
  try {
    const allAsyncKeys = await AsyncStorage.getAllKeys();
    const orphanBackups = allAsyncKeys.filter(k => k.startsWith('_kcRecover_'));
    for (const backupKey of orphanBackups) {
      try {
        const rawBackup = await AsyncStorage.getItem(backupKey);
        if (!rawBackup) continue;
        const backupValue = await _unwrapKcBackup(rawBackup);
        if (backupValue == null) { _orphanRemaining = true; continue; } // wrapped but key gone — ciphertext, not a plaintext leak
        const realKey = backupKey.slice('_kcRecover_'.length);
        // Skip if keychain already has the value (a later attempt
        // succeeded but we forgot to clean up the backup).
        const current = await SecureStore.getItemAsync(realKey, KEYCHAIN_OPTIONS);
        if (current === backupValue) {
          await AsyncStorage.removeItem(backupKey);
          continue;
        }
        // Restore the backup into the keychain with correct accessibility.
        await SecureStore.setItemAsync(realKey, backupValue, KEYCHAIN_OPTIONS);
        const reverify = await SecureStore.getItemAsync(realKey, KEYCHAIN_OPTIONS);
        if (reverify === backupValue) {
          await AsyncStorage.removeItem(backupKey);
          result.rewritten.push('recovered:' + realKey);
        } else {
          _orphanRemaining = true;
        }
      } catch (_) { _orphanRemaining = true; }
    }
  } catch (_) {}

  // Mark done only when nothing failed AND no backup orphan remains — so a
  // surviving straggler keeps the sweep alive on future launches instead of
  // being stranded behind the done-flag.
  if (!_migDone && result.failed.length === 0 && !_orphanRemaining) {
    try { await AsyncStorage.setItem('_kcMigrationDone', '1'); } catch (_) {}
  }

  if (result.rewritten.length > 0) {
    console.log(`rewriteKeychainAccessibility: re-wrote ${result.rewritten.length} keys with AFTER_FIRST_UNLOCK accessibility`);
  }
  return result;
};

export const migrateToSecureStorage = async () => {
  const result = { migrated: [], skipped: [], failed: [] };

  if (!SecureStore) {
    console.warn('migrateToSecureStorage: expo-secure-store not available, skipping migration');
    return result;
  }

  const keys = Object.values(SECURE_KEYS);

  for (const key of keys) {
    try {
      const sanitizedKey = sanitizeKeyForSecureStore(key);

      // Check if already in SecureStore
      const existingSecure = await SecureStore.getItemAsync(sanitizedKey, KEYCHAIN_OPTIONS);
      if (existingSecure !== null) {
        result.skipped.push(key);
        continue;
      }

      // Read from AsyncStorage
      const asyncValue = await AsyncStorage.getItem(key);
      if (asyncValue === null) {
        result.skipped.push(key);
        continue;
      }

      // Write to SecureStore
      await SecureStore.setItemAsync(sanitizedKey, asyncValue, KEYCHAIN_OPTIONS);

      // Verify the write succeeded before removing from AsyncStorage
      const verify = await SecureStore.getItemAsync(sanitizedKey, KEYCHAIN_OPTIONS);
      if (verify === asyncValue) {
        await AsyncStorage.removeItem(key);
        result.migrated.push(key);
      } else {
        result.failed.push(key);
      }
    } catch (e) {
      console.log(`migrateToSecureStorage: Failed to migrate key "${key}":`, e?.message || String(e));
      result.failed.push(key);
    }
  }

  if (result.migrated.length > 0) {
    console.log(`migrateToSecureStorage: Migrated ${result.migrated.length} keys to SecureStore`);
  }

  return result;
};

// ============================================
// FORWARD SECRECY — Double Ratchet-inspired protocol
// ============================================

/**
 * Storage key prefix for per-conversation ratchet sessions.
 * Callers combine this with a conversation ID to store/retrieve session state.
 */
export const RATCHET_SESSION_PREFIX = '@ratchet_session_';
// Round 40 — set when a session could not be DELETED, so the stale blob (which
// the MMKV tier will happily resurrect) is never adopted again. Declared beside
// the session prefix rather than beside its first user: round 37 shipped a TDZ
// bug from exactly the "const declared 200 lines below the code that reads it"
// shape, and there is no reason to leave the question open.
const RATCHET_INVALID_PREFIX = '@ratchet_invalid_';

// ============================================
// HKDF-SHA-256 (RFC 5869) — Signal Protocol compatible
// ============================================

/**
 * HKDF-Extract: PRK = HMAC-SHA-256(salt, IKM)
 * @param {Uint8Array} salt - Salt value (or 32 zero bytes if null)
 * @param {Uint8Array} ikm - Input keying material
 * @returns {Uint8Array} - 32-byte pseudorandom key
 */
const hkdfExtract = (salt, ikm) => {
  const s = salt && salt.length > 0 ? salt : new Uint8Array(32);
  return hmacSha256(s, ikm);
};

/**
 * HKDF-Expand: OKM = T(1) || T(2) || ... truncated to length bytes
 * @param {Uint8Array} prk - Pseudorandom key from Extract
 * @param {Uint8Array} info - Context/application-specific info
 * @param {number} length - Desired output length in bytes
 * @returns {Uint8Array} - Output keying material
 */
const hkdfExpand = (prk, info, length) => {
  const n = Math.ceil(length / 32);
  const okm = new Uint8Array(n * 32);
  let prev = new Uint8Array(0);
  for (let i = 0; i < n; i++) {
    const input = new Uint8Array(prev.length + info.length + 1);
    input.set(prev, 0);
    input.set(info, prev.length);
    input[prev.length + info.length] = i + 1;
    prev = hmacSha256(prk, input);
    okm.set(prev, i * 32);
  }
  return okm.slice(0, length);
};

/**
 * Full HKDF: Extract-then-Expand
 * @param {Uint8Array} salt - Salt
 * @param {Uint8Array} ikm - Input keying material
 * @param {Uint8Array} info - Context info
 * @param {number} length - Desired output length
 * @returns {Uint8Array}
 */
const hkdf = (salt, ikm, info, length) => {
  const prk = hkdfExtract(salt, ikm);
  return hkdfExpand(prk, info, length);
};

/** Convert ASCII string to Uint8Array */
const asciiToBytes = (str) => {
  const bytes = new Uint8Array(str.length);
  for (let i = 0; i < str.length; i++) bytes[i] = str.charCodeAt(i);
  return bytes;
};

// ============================================
// Signal-compatible KDF functions
// ============================================

/**
 * KDF_CK: Symmetric chain key step (Signal Protocol compatible).
 *
 * messageKey = HMAC-SHA-256(chainKey, 0x01)
 * nextChainKey = HMAC-SHA-256(chainKey, 0x02)
 *
 * chainKey is a 64-char hex string (256 bits) for backward compatibility
 * with session serialization format.
 *
 * @returns {{ nextChainKey: hex string, messageKey: Uint8Array(32) }}
 */
const kdfChainStep = (chainKeyHex) => {
  if (!chainKeyHex || typeof chainKeyHex !== 'string') return null;
  const chainKeyBytes = hexToBytes32(chainKeyHex);
  const messageKey = hmacSha256(chainKeyBytes, new Uint8Array([0x01]));
  const nextChainKeyBytes = hmacSha256(chainKeyBytes, new Uint8Array([0x02]));
  return { nextChainKey: bytesToHex(nextChainKeyBytes), messageKey };
};

/**
 * Async variant of kdfChainStep. Uses the native HMAC-SHA256 entry points
 * (CommonCrypto on iOS, javax.crypto on Android) when available — runs
 * the two HMAC ops on a background dispatch queue so a burst of incoming
 * messages doesn't block the JS thread.
 *
 * Falls back to the sync `kdfChainStep` if the native module isn't
 * loaded — output is byte-identical, only the dispatch differs.
 */
const kdfChainStepAsync = async (chainKeyHex) => {
  if (!chainKeyHex || typeof chainKeyHex !== 'string') return null;
  if (!_nativeShaAvailable) return kdfChainStep(chainKeyHex);
  const chainKeyBytes = hexToBytes32(chainKeyHex);
  // Two HMACs in parallel — same Promise.all pattern Signal's libsignal
  // uses for the chain step.
  try {
    const [messageKey, nextChainKeyBytes] = await Promise.all([
      hmacSha256Async(chainKeyBytes, new Uint8Array([0x01])),
      hmacSha256Async(chainKeyBytes, new Uint8Array([0x02])),
    ]);
    return { nextChainKey: bytesToHex(nextChainKeyBytes), messageKey };
  } catch (_) {
    return kdfChainStep(chainKeyHex);
  }
};

/**
 * KDF_RK: Root key step / DH Ratchet (Signal Protocol compatible).
 *
 * Uses HKDF with:
 *   salt = current root key
 *   IKM  = DH output (nacl.box.before)
 *   info = "WhisperRatchet"
 *   len  = 64 bytes → split into new rootKey (32) + new chainKey (32)
 *
 * @param {string} rootKeyHex - Current root key (64-char hex)
 * @param {Uint8Array} dhOutput - 32-byte shared secret from nacl.box.before()
 * @returns {{ rootKey: string, chainKey: string }} - New root key and chain key (hex)
 */
const kdfRootStep = (rootKeyHex, dhOutput) => {
  if (!rootKeyHex || typeof rootKeyHex !== 'string' || !dhOutput) return null;
  const rootKeyBytes = hexToBytes32(rootKeyHex);
  const info = asciiToBytes('WhisperRatchet');
  const derived = hkdf(rootKeyBytes, dhOutput, info, 64);
  return {
    rootKey: bytesToHex(derived.slice(0, 32)),
    chainKey: bytesToHex(derived.slice(32, 64)),
  };
};

/**
 * Initialize a ratchet session from a Diffie-Hellman key exchange.
 *
 * The root key is derived from nacl.box.before(theirPub, myPriv), then
 * split into separate send and receive chain keys using domain separation.
 *
 * Both parties must derive chains in a consistent order: the party whose
 * public key is lexicographically smaller uses the "low" chain for sending
 * and the "high" chain for receiving, and vice versa.
 *
 * @param {string} theirPublicKeyB64 - The other party's Curve25519 public key (base64)
 * @param {string} myPrivateKeyB64 - Our Curve25519 private key (base64)
 * @param {string} myPublicKeyB64 - Our Curve25519 public key (base64), used for chain ordering
 * @returns {object|null} - Session state object, or null on failure
 */
export const initRatchetSession = (theirPublicKeyB64, myPrivateKeyB64, myPublicKeyB64) => {
  if (!theirPublicKeyB64 || !myPrivateKeyB64 || !myPublicKeyB64) return null;

  try {
    const theirPublicKey = decodeBase64(theirPublicKeyB64);
    const myPrivateKey = decodeBase64(myPrivateKeyB64);

    if (!theirPublicKey || theirPublicKey.length !== nacl.box.publicKeyLength) return null;
    if (!myPrivateKey || myPrivateKey.length !== nacl.box.secretKeyLength) return null;

    // Compute shared secret via Curve25519 DH
    const sharedSecret = nacl.box.before(theirPublicKey, myPrivateKey);

    // Derive root key using HKDF (Signal-compatible)
    const hkdfSalt = new Uint8Array(32); // 32 zero bytes
    const hkdfInfo = asciiToBytes('theSHFT_DH_v2');
    const masterSecret = hkdf(hkdfSalt, sharedSecret, hkdfInfo, 32);
    const rootKey = bytesToHex(masterSecret);

    // Determine send/recv assignment based on lexicographic order of public keys
    const iAmLower = myPublicKeyB64 < theirPublicKeyB64;

    // Generate initial DH ratchet ephemeral key pair for forward secrecy rotation
    const dhRatchetEphemeral = nacl.box.keyPair();

    // Perform initial DH ratchet step to derive chain keys
    const initialDH = nacl.box.before(theirPublicKey, dhRatchetEphemeral.secretKey);
    const { rootKey: postDHRoot, chainKey: firstChain } = kdfRootStep(rootKey, initialDH);

    // Second DH to derive the other chain
    const secondDH = nacl.box.before(theirPublicKey, myPrivateKey);
    const { rootKey: finalRoot, chainKey: secondChain } = kdfRootStep(postDHRoot, secondDH);

    return {
      rootKey: finalRoot,
      sendChainKey: iAmLower ? firstChain : secondChain,
      recvChainKey: iAmLower ? secondChain : firstChain,
      sendMessageIndex: 0,
      recvMessageIndex: 0,
      previousChainLength: 0,
      myEphemeralKeyPair: {
        publicKey: encodeBase64(dhRatchetEphemeral.publicKey),
        secretKey: encodeBase64(dhRatchetEphemeral.secretKey),
      },
      theirEphemeralKey: theirPublicKeyB64,
      skippedKeys: {},
      version: 2,
    };
  } catch (e) {
    console.log('initRatchetSession error:', e?.message || String(e));
    return null;
  }
};

/**
 * Encrypt a plaintext message using the ratchet session's send chain.
 *
 * If the session has DH ratchet state (myEphemeralKeyPair, theirEphemeralKey),
 * a new ephemeral key pair is generated on each send, a DH ratchet step is
 * performed to rotate the root key and send chain, and the new ephemeral
 * public key is included in the message for the recipient.
 *
 * For backwards compatibility, sessions without DH ratchet state (legacy)
 * continue to use symmetric-only ratcheting.
 *
 * @param {object} session - Ratchet session state (mutated copy returned)
 * @param {string} plaintext - Message to encrypt
 * @returns {{ encrypted: string, session: object }|null} - Encrypted payload and updated session
 */
export const ratchetEncrypt = (session, plaintext) => {
  if (!session || !plaintext) return null;

  try {
    let currentSession = { ...session, skippedKeys: { ...(session.skippedKeys || {}) } };

    // Derive message key and advance symmetric chain
    const chainStep = kdfChainStep(currentSession.sendChainKey);
    if (!chainStep) return null;
    const { nextChainKey, messageKey } = chainStep;

    // Encode and pad plaintext
    const messageBytes = decodeUTF8(plaintext);
    const paddedBytes = padMessage(messageBytes);

    // Encrypt with NaCl secretbox
    const nonce = nacl.randomBytes(nacl.secretbox.nonceLength);
    const ciphertext = nacl.secretbox(paddedBytes, nonce, messageKey);
    if (!ciphertext) return null;

    const index = currentSession.sendMessageIndex;
    const pn = currentSession.previousChainLength || 0;

    // Build updated session
    const updatedSession = {
      ...currentSession,
      sendChainKey: nextChainKey,
      sendMessageIndex: index + 1,
    };

    // Format: ratchet:<pn>:<index>:<nonce_b64>:<ciphertext_b64>:<ephemeralPub_b64>
    // pn = previous chain length (needed for receiver to skip keys from old chain)
    const ephPub = currentSession.myEphemeralKeyPair?.publicKey || '';
    const encrypted = 'ratchet:' + pn + ':' + index + ':' + encodeBase64(nonce) + ':' + encodeBase64(ciphertext) + ':' + ephPub;

    return { encrypted, session: updatedSession };
  } catch (e) {
    console.log('ratchetEncrypt error:', e?.message || String(e));
    return null;
  }
};

/**
 * Decrypt a ratchet-encrypted message using the session's receive chain.
 *
 * Parses the "ratchet:<index>:<nonce>:<ciphertext>[:<ephemeralPub>]" format.
 * If the message includes an ephemeral public key (5th field) that differs
 * from session.theirEphemeralKey, a DH ratchet step is performed first to
 * derive a new root key and receive chain before the symmetric step.
 *
 * For backwards compatibility, messages without an ephemeral key (4 fields)
 * use the existing symmetric-only ratchet path.
 *
 * @param {object} session - Ratchet session state (mutated copy returned)
 * @param {string} encrypted - Encrypted payload in ratchet format
 * @returns {{ plaintext: string, session: object }|null} - Decrypted text and updated session
 */
// Max skipped message keys to store per session (prevents DoS via huge index gaps)
const MAX_SKIPPED_KEYS = 256;

// Ephemeral DH ratchet key rotation: regenerate after this many messages
// DH ratchet rotation is now handled automatically by performDHRatchet on each
// direction change (Signal Protocol standard behavior — no interval needed).

/**
 * Securely overwrite a base64-encoded key string in a skippedKeys map.
 * JavaScript strings are immutable, but we overwrite the reference and
 * fill any Uint8Array copies with zeros to limit exposure in heap.
 */
const secureDeleteSkippedKey = (skippedKeys, index) => {
  const keyStr = skippedKeys[String(index)];
  if (keyStr) {
    // Decode to bytes and zero them out (best-effort heap cleanup)
    try {
      const bytes = decodeBase64(keyStr);
      if (bytes) bytes.fill(0);
    } catch (_) {}
  }
  delete skippedKeys[String(index)];
};

/**
 * Evict the oldest skipped message keys once the map exceeds MAX_SKIPPED_KEYS.
 * Entries are composite 'chainId:messageIndex' strings (chainId is base64 or
 * 'init' — never contains ':'); bare-numeric entries are the legacy format.
 * A plain lexicographic sort mis-orders indices ('x:9' > 'x:100') and evicts
 * the WRONG keys — an attacker could craft indices that keep old message keys
 * alive, weakening forward secrecy. Instead: group per chain in insertion
 * order (objects preserve string-key insertion order and chains only ever
 * append, so older chains come first; legacy bare-numeric keys enumerate
 * first, which is correct — they predate every composite chain), then evict
 * numerically-oldest indices within each chain.
 */
const evictOldestSkippedKeys = (skippedKeys) => {
  let excess = Object.keys(skippedKeys).length - MAX_SKIPPED_KEYS;
  if (excess <= 0) return;
  const chains = new Map();
  for (const key of Object.keys(skippedKeys)) {
    const sep = key.lastIndexOf(':');
    const chainId = sep === -1 ? '' : key.slice(0, sep);
    const index = parseInt(sep === -1 ? key : key.slice(sep + 1), 10);
    const entry = { key, index: Number.isFinite(index) ? index : 0 };
    const list = chains.get(chainId);
    if (list) list.push(entry); else chains.set(chainId, [entry]);
  }
  for (const list of chains.values()) {
    if (excess <= 0) break;
    list.sort((a, b) => a.index - b.index);
    for (const entry of list) {
      if (excess <= 0) break;
      secureDeleteSkippedKey(skippedKeys, entry.key);
      excess--;
    }
  }
};

/**
 * Perform a full DH ratchet step on the receiving side (Signal Protocol compatible).
 * Skips remaining keys in the current receive chain, then:
 *   1. DH(ourEphemeral, theirNewEphemeral) → new receive chain
 *   2. Generate new ephemeral key pair
 *   3. DH(ourNewEphemeral, theirNewEphemeral) → new send chain
 */
const performDHRatchet = (session, theirNewEphB64, previousChainLength) => {
  const s = { ...session, skippedKeys: { ...(session.skippedKeys || {}) } };

  // Skip remaining keys in old receive chain up to previousChainLength
  if (s.recvChainKey && previousChainLength > s.recvMessageIndex) {
    const toSkip = Math.min(previousChainLength - s.recvMessageIndex, MAX_SKIPPED_KEYS);
    let chainKey = s.recvChainKey;
    const chainId = s.theirEphemeralKey || 'init';
    for (let i = 0; i < toSkip; i++) {
      const step = kdfChainStep(chainKey);
      if (!step) break;
      const skipKey = chainId + ':' + (s.recvMessageIndex + i);
      s.skippedKeys[skipKey] = encodeBase64(step.messageKey);
      chainKey = step.nextChainKey;
    }
  }

  let theirNewEphBytes;
  try { theirNewEphBytes = decodeBase64(theirNewEphB64); } catch (_) { return s; }
  if (!theirNewEphBytes || theirNewEphBytes.length !== nacl.box.publicKeyLength) return s;

  let myEphSecretBytes = null;
  try {
    myEphSecretBytes = s.myEphemeralKeyPair?.secretKey ? decodeBase64(s.myEphemeralKeyPair.secretKey) : null;
  } catch (_) { /* proceed without old ephemeral */ }

  // Step 1: DH with current ephemeral → new receive chain
  if (myEphSecretBytes) {
    const dh1 = nacl.box.before(theirNewEphBytes, myEphSecretBytes);
    const step1 = kdfRootStep(s.rootKey, dh1);
    if (step1) {
      s.rootKey = step1.rootKey;
      s.recvChainKey = step1.chainKey;
    }
  }

  // Step 2: Generate new ephemeral
  const newEph = nacl.box.keyPair();

  // Zero old ephemeral (best-effort forward secrecy)
  if (myEphSecretBytes) { try { myEphSecretBytes.fill(0); } catch (_) {} }

  // Step 3: DH with new ephemeral → new send chain
  const dh2 = nacl.box.before(theirNewEphBytes, newEph.secretKey);
  const step3 = kdfRootStep(s.rootKey, dh2);
  if (step3) {
    s.rootKey = step3.rootKey;
    s.sendChainKey = step3.chainKey;
  }

  s.previousChainLength = s.sendMessageIndex;
  s.sendMessageIndex = 0;
  s.recvMessageIndex = 0;
  s.theirEphemeralKey = theirNewEphB64;
  s.myEphemeralKeyPair = {
    publicKey: encodeBase64(newEph.publicKey),
    secretKey: encodeBase64(newEph.secretKey),
  };

  return s;
};

/**
 * Skip message keys in the receive chain up to index `until`, caching them
 * in skippedKeys for out-of-order decryption.
 */
const skipMessageKeys = (session, until) => {
  if (until <= session.recvMessageIndex) return session;
  const skip = until - session.recvMessageIndex;
  if (skip > MAX_SKIPPED_KEYS) return null; // DoS protection

  const s = { ...session, skippedKeys: { ...(session.skippedKeys || {}) } };
  let chainKey = s.recvChainKey;
  const chainId = s.theirEphemeralKey || 'init';
  for (let i = 0; i < skip; i++) {
    const step = kdfChainStep(chainKey);
    if (!step) break;
    const skipKey = chainId + ':' + (s.recvMessageIndex + i);
    s.skippedKeys[skipKey] = encodeBase64(step.messageKey);
    chainKey = step.nextChainKey;
  }
  s.recvChainKey = chainKey;
  s.recvMessageIndex = until;
  return s;
};

export const ratchetDecrypt = (session, encrypted) => {
  if (!session || !encrypted) return null;
  if (!encrypted.startsWith('ratchet:')) return null;
  // Validate session has minimum required state
  if (!session.rootKey || !session.sendChainKey || typeof session.sendMessageIndex !== 'number') return null;

  try {
    const parts = encrypted.split(':');
    // v2 format: ratchet:<pn>:<index>:<nonce_b64>:<ciphertext_b64>:<ephemeralPub_b64>
    // v1 format: ratchet:<index>:<nonce_b64>:<ciphertext_b64>[:<ephemeralPub_b64>]
    let previousChainLength, messageIndex, nonce, ciphertext, senderEphemeralB64;

    if (parts.length >= 6) {
      // v2 format
      previousChainLength = parseInt(parts[1], 10);
      messageIndex = parseInt(parts[2], 10);
      nonce = decodeBase64(parts[3]);
      ciphertext = decodeBase64(parts[4]);
      senderEphemeralB64 = parts[5] || null;
    } else if (parts.length >= 4) {
      // v1 legacy format
      previousChainLength = 0;
      messageIndex = parseInt(parts[1], 10);
      nonce = decodeBase64(parts[2]);
      ciphertext = decodeBase64(parts[3]);
      senderEphemeralB64 = parts.length >= 5 ? parts[4] : null;
    } else {
      return null;
    }

    if (isNaN(messageIndex) || messageIndex < 0) return null;
    if (!nonce || nonce.length !== nacl.secretbox.nonceLength) return null;
    if (!ciphertext || ciphertext.length === 0) return null;

    let currentSession = { ...session, skippedKeys: { ...(session.skippedKeys || {}) } };

    // Check skipped keys first (composite key: chainId:messageIndex)
    const chainId = senderEphemeralB64 || currentSession.theirEphemeralKey || 'init';
    const skipLookup = chainId + ':' + messageIndex;
    const skippedKeyStr = currentSession.skippedKeys[skipLookup];
    if (skippedKeyStr) {
      const messageKey = decodeBase64(skippedKeyStr);
      const decrypted = nacl.secretbox.open(ciphertext, nonce, messageKey);
      if (!decrypted) return null;
      secureDeleteSkippedKey(currentSession.skippedKeys, skipLookup);
      const unpadded = unpadMessage(decrypted);
      if (!unpadded) return null;
      const plaintext = encodeUTF8(unpadded);
      return { plaintext, session: currentSession };
    }

    // Also check legacy numeric index format for backward compat
    const legacyKey = String(messageIndex);
    const legacySkipped = currentSession.skippedKeys[legacyKey];
    if (legacySkipped) {
      const messageKey = decodeBase64(legacySkipped);
      const decrypted = nacl.secretbox.open(ciphertext, nonce, messageKey);
      if (!decrypted) return null;
      secureDeleteSkippedKey(currentSession.skippedKeys, messageIndex);
      const unpadded = unpadMessage(decrypted);
      if (!unpadded) return null;
      const plaintext = encodeUTF8(unpadded);
      return { plaintext, session: currentSession };
    }

    // DH ratchet step if sender's ephemeral key changed
    if (senderEphemeralB64 && senderEphemeralB64 !== currentSession.theirEphemeralKey) {
      currentSession = performDHRatchet(currentSession, senderEphemeralB64, previousChainLength);
    }

    // Skip message keys up to the target index
    if (messageIndex > currentSession.recvMessageIndex) {
      const skipped = skipMessageKeys(currentSession, messageIndex);
      if (!skipped) return null; // DoS protection triggered
      currentSession = skipped;
    } else if (messageIndex < currentSession.recvMessageIndex) {
      // Behind our index and not in skipped keys — forward secrecy consumed it
      return null;
    }

    // Derive message key at current index
    if (!currentSession.recvChainKey) {
      return null;
    }
    const recvChainStep = kdfChainStep(currentSession.recvChainKey);
    if (!recvChainStep) return null;
    const { nextChainKey, messageKey } = recvChainStep;

    // Decrypt with NaCl secretbox
    const decrypted = nacl.secretbox.open(ciphertext, nonce, messageKey);
    if (!decrypted) {
      return null;
    }

    // Unpad
    const unpadded = unpadMessage(decrypted);
    if (!unpadded) return null;
    const plaintext = encodeUTF8(unpadded);

    // Evict oldest skipped keys if over cap
    evictOldestSkippedKeys(currentSession.skippedKeys);

    const updatedSession = {
      ...currentSession,
      recvChainKey: nextChainKey,
      recvMessageIndex: currentSession.recvMessageIndex + 1,
    };

    return { plaintext, session: updatedSession };
  } catch (e) {
    console.log('ratchetDecrypt error:', e?.message || String(e));
    return null;
  }
};

/**
 * Async variant of ratchetDecrypt that uses the native HMAC-SHA256 path
 * for the chain step. Decrypt result is byte-identical to the sync
 * version — only the dispatch is moved off the JS thread.
 *
 * Use this from places that are already async (the cooperative decryption
 * queue, message-receive listeners). When the native module isn't loaded
 * (`isNativeShaAvailable === false`) it transparently falls back to the
 * sync path.
 *
 * @param {object} session   - Current ratchet session
 * @param {string} encrypted - "ratchet:..." formatted ciphertext
 * @returns {Promise<{ plaintext, session }|null>}
 */
export const ratchetDecryptAsync = async (session, encrypted) => {
  // Fast path: when native HMAC isn't available, just call sync — same
  // result, no extra await overhead.
  if (!_nativeShaAvailable) return ratchetDecrypt(session, encrypted);

  if (!session || !encrypted) return null;
  if (!encrypted.startsWith('ratchet:')) return null;
  if (!session.rootKey || !session.sendChainKey || typeof session.sendMessageIndex !== 'number') return null;

  try {
    const parts = encrypted.split(':');
    let previousChainLength, messageIndex, nonce, ciphertext, senderEphemeralB64;
    if (parts.length >= 6) {
      previousChainLength = parseInt(parts[1], 10);
      messageIndex = parseInt(parts[2], 10);
      nonce = decodeBase64(parts[3]);
      ciphertext = decodeBase64(parts[4]);
      senderEphemeralB64 = parts[5] || null;
    } else if (parts.length >= 4) {
      previousChainLength = 0;
      messageIndex = parseInt(parts[1], 10);
      nonce = decodeBase64(parts[2]);
      ciphertext = decodeBase64(parts[3]);
      senderEphemeralB64 = parts.length >= 5 ? parts[4] : null;
    } else {
      return null;
    }

    if (isNaN(messageIndex) || messageIndex < 0) return null;
    if (!nonce || nonce.length !== nacl.secretbox.nonceLength) return null;
    if (!ciphertext || ciphertext.length === 0) return null;

    let currentSession = { ...session, skippedKeys: { ...(session.skippedKeys || {}) } };

    const chainId = senderEphemeralB64 || currentSession.theirEphemeralKey || 'init';
    const skipLookup = chainId + ':' + messageIndex;
    const skippedKeyStr = currentSession.skippedKeys[skipLookup];
    if (skippedKeyStr) {
      const messageKey = decodeBase64(skippedKeyStr);
      const decrypted = nacl.secretbox.open(ciphertext, nonce, messageKey);
      if (!decrypted) return null;
      secureDeleteSkippedKey(currentSession.skippedKeys, skipLookup);
      const unpadded = unpadMessage(decrypted);
      if (!unpadded) return null;
      const plaintext = encodeUTF8(unpadded);
      return { plaintext, session: currentSession };
    }

    const legacyKey = String(messageIndex);
    const legacySkipped = currentSession.skippedKeys[legacyKey];
    if (legacySkipped) {
      const messageKey = decodeBase64(legacySkipped);
      const decrypted = nacl.secretbox.open(ciphertext, nonce, messageKey);
      if (!decrypted) return null;
      secureDeleteSkippedKey(currentSession.skippedKeys, messageIndex);
      const unpadded = unpadMessage(decrypted);
      if (!unpadded) return null;
      const plaintext = encodeUTF8(unpadded);
      return { plaintext, session: currentSession };
    }

    if (senderEphemeralB64 && senderEphemeralB64 !== currentSession.theirEphemeralKey) {
      currentSession = performDHRatchet(currentSession, senderEphemeralB64, previousChainLength);
    }

    if (messageIndex > currentSession.recvMessageIndex) {
      const skipped = skipMessageKeys(currentSession, messageIndex);
      if (!skipped) return null;
      currentSession = skipped;
    } else if (messageIndex < currentSession.recvMessageIndex) {
      return null;
    }

    if (!currentSession.recvChainKey) return null;
    // KDF chain step on background dispatch (native HMAC × 2 in parallel).
    const recvChainStep = await kdfChainStepAsync(currentSession.recvChainKey);
    if (!recvChainStep) return null;
    const { nextChainKey, messageKey } = recvChainStep;

    const decrypted = nacl.secretbox.open(ciphertext, nonce, messageKey);
    if (!decrypted) return null;

    const unpadded = unpadMessage(decrypted);
    if (!unpadded) return null;
    const plaintext = encodeUTF8(unpadded);

    evictOldestSkippedKeys(currentSession.skippedKeys);

    const updatedSession = {
      ...currentSession,
      recvChainKey: nextChainKey,
      recvMessageIndex: currentSession.recvMessageIndex + 1,
    };

    return { plaintext, session: updatedSession };
  } catch (e) {
    console.log('ratchetDecryptAsync error:', e?.message || String(e));
    // Last-resort: fall back to the sync path so a native bug doesn't
    // stop the user from reading their message.
    return ratchetDecrypt(session, encrypted);
  }
};

/**
 * Serialize a ratchet session to a JSON-safe string for persistent storage.
 *
 * @param {object} session - Ratchet session state
 * @returns {string|null} - JSON string, or null on failure
 */
export const serializeSession = (session) => {
  if (!session) return null;
  try {
    const data = {
      rootKey: session.rootKey,
      sendChainKey: session.sendChainKey,
      recvChainKey: session.recvChainKey,
      sendMessageIndex: session.sendMessageIndex,
      recvMessageIndex: session.recvMessageIndex,
      previousChainLength: session.previousChainLength || 0,
      version: session.version || 1,
    };
    if (session.skippedKeys && Object.keys(session.skippedKeys).length > 0) {
      data.skippedKeys = session.skippedKeys;
    }
    if (session.myEphemeralKeyPair) {
      data.myEphemeralKeyPair = session.myEphemeralKeyPair;
    }
    if (session.theirEphemeralKey) {
      data.theirEphemeralKey = session.theirEphemeralKey;
    }
    if (session.lastDHRatchetTheirKey) {
      data.lastDHRatchetTheirKey = session.lastDHRatchetTheirKey;
    }
    return JSON.stringify(data);
  } catch (e) {
    console.log('serializeSession error:', e?.message || String(e));
    return null;
  }
};

/**
 * Restore a ratchet session from a serialized JSON string.
 *
 * @param {string} data - JSON string from serializeSession
 * @returns {object|null} - Session state object, or null on failure
 */
export const deserializeSession = (data) => {
  if (!data || typeof data !== 'string') return null;
  try {
    const parsed = JSON.parse(data);
    if (!parsed.rootKey || !parsed.sendChainKey ||
        typeof parsed.sendMessageIndex !== 'number' ||
        typeof parsed.recvMessageIndex !== 'number') {
      console.warn('deserializeSession: invalid session data');
      return null;
    }
    const session = {
      rootKey: parsed.rootKey,
      sendChainKey: parsed.sendChainKey,
      recvChainKey: parsed.recvChainKey || null,
      sendMessageIndex: parsed.sendMessageIndex,
      recvMessageIndex: parsed.recvMessageIndex,
      previousChainLength: parsed.previousChainLength || 0,
      version: parsed.version || 1,
    };
    if (parsed.skippedKeys && typeof parsed.skippedKeys === 'object') {
      session.skippedKeys = parsed.skippedKeys;
    }
    if (parsed.myEphemeralKeyPair && typeof parsed.myEphemeralKeyPair === 'object' &&
        parsed.myEphemeralKeyPair.publicKey && parsed.myEphemeralKeyPair.secretKey) {
      session.myEphemeralKeyPair = parsed.myEphemeralKeyPair;
    }
    if (parsed.theirEphemeralKey && typeof parsed.theirEphemeralKey === 'string') {
      session.theirEphemeralKey = parsed.theirEphemeralKey;
    }
    return session;
  } catch (e) {
    console.log('deserializeSession error:', e?.message || String(e));
    return null;
  }
};

// ============================================
// POST-QUANTUM KEY ENCAPSULATION (ML-KEM-768)
// ============================================
//
// STATUS: ACTIVE — implemented via the native PQClean reference port in
// modules/native-crypto. Constant-time C, hardware-friendly, available
// on both iOS (CocoaPod) and Android (NDK + JNI). On web (2026-09-16)
// modules/native-crypto/index.web.ts runs ML-KEM-768 in @noble/post-quantum
// (FIPS 203 in JS, not constant-time C); the web security page must say
// so, and that wording is an owner item. The pure-JS `mlkem`
// npm package was removed in 7.1.0 because its ESM package.exports
// shape was incompatible with Metro's resolver under Hermes lazy-load.
//
// Hybrid encryption: Curve25519 (classical) + ML-KEM-768 (post-quantum).
// The PQXDH handshake mixes the ML-KEM shared secret into the X3DH HKDF
// derivation, so an attacker must break BOTH X25519 AND ML-KEM-768 to
// recover session keys.
//
// Runtime kill-switch: setting `_e.pqDisabled = true` (further down) or
// `KEYS.PQ_ENABLED = false` in SecureStore forces classical-only crypto
// without a code push.
//
// ML-KEM-768 (CRYSTALS-Kyber, NIST FIPS 203) is now active via the
// native PQClean implementation in modules/native-crypto. The pure-JS
// `mlkem` npm package is no longer used — its ESM `package.exports`
// shape was incompatible with Metro's resolver under Hermes lazy-load.
//
// The native module ships compiled C (PQClean reference) on iOS via a
// CocoaPod and on Android via NDK + JNI. Both platforms call only the
// _derand variants of PQClean's API; coins are sourced from the
// platform CSPRNG (SecRandomCopyBytes / SecureRandom) by the native
// layer. On iOS and Android the JS layer never touches the lattice math;
// on web the shim above is the lattice math.
//
// `_e.pqDisabled` is retained as a runtime kill-switch — set to `true`
// to force-fall-back to classical-only crypto without a code push.
if (_e.pqDisabled === undefined) _e.pqDisabled = false;
if (_e.nativePqMod === undefined) _e.nativePqMod = null;
const _getNativePq = () => {
  if (_e.nativePqMod !== null) return _e.nativePqMod;
  try {
    _e.nativePqMod = require('../modules/native-crypto');
    if (!_e.nativePqMod?.isNativeMlKemAvailable) {
      console.warn('Native ML-KEM not available — PQ disabled for this session');
      _e.pqDisabled = true;
    }
  } catch (err) {
    console.warn('Failed to load native ML-KEM module:', err?.message);
    _e.pqDisabled = true;
    _e.nativePqMod = {};
  }
  return _e.nativePqMod;
};

// Helper: convert base64-encoded bytes to lowercase hex (preserves the
// legacy hex-shared-secret API used by hybridEncrypt / hybridDecrypt).
const _b64ToHex = (b64) => {
  const bytes = decodeBase64(b64);
  let out = '';
  for (let i = 0; i < bytes.length; i++) {
    out += bytes[i].toString(16).padStart(2, '0');
  }
  return out;
};

/**
 * Generate an ML-KEM-768 (NIST FIPS 203) key pair via the native PQClean
 * module. Public key 1184 bytes; secret key 2400 bytes; both base64.
 */
/**
 * Deterministic ML-KEM-768 coins from the recovery phrase.
 *
 * AUDIT 2026-08-29. The PQ identity used to be RANDOM and, in this file's own
 * words, "regenerated on first install" with recovery across devices "not
 * currently supported". That is the reason group chats are not post-quantum:
 * sender keys are distributed once per epoch, so a member who restores their
 * account after a distribution holds a different ML-KEM private key than the
 * one their envelope was sealed to and can never open it. For 1:1 the same
 * event is harmless, because X3DH re-establishes on the next exchange.
 *
 * The native module has always accepted seeded keygen for exactly this — its
 * own doc says "pass an explicit base64 coins string of exactly 64 bytes for
 * deterministic key generation (e.g. derived from a recovery phrase)". Nothing
 * ever passed it.
 *
 * Domain-separated from the classical identity: a different PBKDF2 salt marker
 * so this never reproduces the X25519 seed, then HKDF-expand to the 64 bytes
 * ML-KEM keygen wants. Versioned in both the salt and the HKDF info so a
 * future change is a new version rather than a silent identity rotation, which
 * for this key means everyone's sealed material becoming unreadable.
 */
const PQ_KDF_SALT_V1 = 'theshft_pq_kem_v1';
const PQ_HKDF_INFO_V1 = 'theshft-mlkem768-identity-v1';
export const derivePqCoinsFromPhrase = async (phrase) => {
  try {
    // Web identity guard (2026-09-16, P2-E): same rule as the classical
    // derivation above. pqGenerateKeyPair with NO coins (a device key) is
    // untouched: that is what a linked browser will mint under P1.
    if (WEB_PHRASE_BLOCKED) { refuseWebPhrase('derivePqCoinsFromPhrase'); return null; }
    if (!phrase || typeof phrase !== 'string') return null;
    const words = phrase.toLowerCase().trim().replace(/\s+/g, ' ');
    const phraseHash = sha256(words);
    const salt = sha256(phraseHash + PQ_KDF_SALT_V1);
    const seedHex = await pbkdf2HmacSha256(words, salt, PHRASE_KDF_ITERATIONS_V6);
    if (!seedHex || seedHex.length !== 64 || !/^[0-9a-f]{64}$/.test(seedHex)) return null;
    const seed = new Uint8Array(32);
    for (let i = 0; i < 32; i++) seed[i] = parseInt(seedHex.substring(i * 2, i * 2 + 2), 16);
    const saltBytes = new Uint8Array(32);
    for (let i = 0; i < 32; i++) saltBytes[i] = parseInt(salt.substring(i * 2, i * 2 + 2), 16);
    const prk = hkdfExtract(saltBytes, seed);
    const coins = hkdfExpand(prk, decodeUTF8(PQ_HKDF_INFO_V1), 64);
    return encodeBase64(coins);
  } catch (e) {
    console.warn('derivePqCoinsFromPhrase error:', e?.message);
    return null;
  }
};

export const pqGenerateKeyPair = async (coinsB64) => {
  if (_e.pqDisabled) return null;
  const native = _getNativePq();
  if (_e.pqDisabled || typeof native.mlkem768Keygen !== 'function') return null;
  const traceId = traces.mlkemKeygen();
  try {
    // coinsB64 undefined => the module pulls 64 random bytes, which is the
    // pre-2026-08-29 behaviour and stays the fallback.
    const { publicKey, secretKey } = await native.mlkem768Keygen(coinsB64);
    endTrace(traceId);
    // Caller historically destructures .privateKey — keep that field
    // name for backward compatibility.
    return { publicKey, privateKey: secretKey };
  } catch (err) {
    console.warn('pqGenerateKeyPair error:', err?.message);
    try { endTrace(traceId); } catch (_) {}
    return null;
  }
};

/**
 * Encapsulate a shared secret to a recipient's ML-KEM-768 public key.
 * Returns base64 ciphertext (1088 bytes) and hex-encoded 32-byte shared
 * secret (hex preserved for the legacy hybridEncrypt KDF interface).
 */
export const pqEncapsulate = async (pqPublicKeyB64) => {
  if (!pqPublicKeyB64 || _e.pqDisabled) return null;
  const native = _getNativePq();
  if (_e.pqDisabled || typeof native.mlkem768Encapsulate !== 'function') return null;
  const traceId = traces.mlkemEncap();
  try {
    const { ciphertext, sharedSecret } = await native.mlkem768Encapsulate(pqPublicKeyB64);
    endTrace(traceId);
    return {
      ciphertext,
      sharedSecret: _b64ToHex(sharedSecret),
    };
  } catch (err) {
    console.log('pqEncapsulate error:', err);
    try { endTrace(traceId); } catch (_) {}
    return null;
  }
};

/**
 * Decapsulate a ciphertext using our ML-KEM-768 secret key. Returns the
 * 32-byte shared secret as a lowercase hex string.
 *
 * Constant-time: PQClean returns a pseudo-random shared secret on KEM
 * failure rather than raising, so the caller cannot timing-distinguish
 * a malformed ciphertext from a valid one.
 */
export const pqDecapsulate = async (ciphertextB64, pqPrivateKeyB64) => {
  if (!ciphertextB64 || !pqPrivateKeyB64 || _e.pqDisabled) return null;
  const native = _getNativePq();
  if (_e.pqDisabled || typeof native.mlkem768Decapsulate !== 'function') return null;
  const traceId = traces.mlkemDecap();
  try {
    const sharedSecret = await native.mlkem768Decapsulate(ciphertextB64, pqPrivateKeyB64);
    endTrace(traceId);
    return _b64ToHex(sharedSecret);
  } catch (err) {
    console.log('pqDecapsulate error:', err);
    try { endTrace(traceId); } catch (_) {}
    return null;
  }
};

// ============================================
// PREKEY GENERATION (X3DH Protocol)
// ============================================

/**
 * Generate a signed prekey bundle.
 * Uses Ed25519 (nacl.sign) to sign the ephemeral public key with the identity key.
 * Also generates a PQ prekey for hybrid key agreement.
 *
 * @param {string} identityPrivateKeyB64 - Curve25519 private key (used to derive Ed25519 signing key)
 * @param {number} prekeyId - Monotonic ID for this prekey
 * @returns {{ signedPrekey, signedPrekeySignature, signedPrekeyId, prekeyPair, pqPrekeyPair }}
 */
export const generateSignedPrekey = async (identityPrivateKeyB64, prekeyId) => {
  if (!identityPrivateKeyB64) return null;

  try {
    // Generate ephemeral Curve25519 prekey
    const prekeyPair = nacl.box.keyPair();
    const prekeyPublicB64 = encodeBase64(prekeyPair.publicKey);
    const prekeyPrivateB64 = encodeBase64(prekeyPair.secretKey);

    // Generate ML-KEM-768 PQ prekey. The mlkem package works under Hermes
    // via the expo-crypto polyfill — no Web Crypto needed at runtime.
    let pqPrekeyPair = null;
    try { pqPrekeyPair = await pqGenerateKeyPair(); } catch (_) { pqPrekeyPair = null; }

    // Sign the prekey public key with identity key.
    //
    // Derives Ed25519 from the Curve25519 identity private key via the
    // _deriveEd25519FromCurve helper (line ~3491) — same algorithm used
    // by generateSenderCertificate. Prior to audit C-M1 this codepath
    // used a separate SHA-256-tag construction, producing a DIFFERENT
    // Ed25519 key from the same identity. Unifying the two derivations
    // means a single identity → single signing key. No compat impact:
    // bundle verifiers use the published `signingPublicKey` field, so
    // each bundle is self-consistent regardless of which derivation
    // produced it.
    const signingKeyPair = _deriveEd25519FromCurve(identityPrivateKeyB64);

    // Sign the prekey public key bytes
    const signature = nacl.sign.detached(prekeyPair.publicKey, signingKeyPair.secretKey);

    return {
      signedPrekey: prekeyPublicB64,
      signedPrekeySignature: encodeBase64(signature),
      signedPrekeyId: prekeyId,
      signingPublicKey: encodeBase64(signingKeyPair.publicKey),
      prekeyPrivate: prekeyPrivateB64,
      pqPrekey: pqPrekeyPair ? { publicKey: pqPrekeyPair.publicKey, privateKey: pqPrekeyPair.privateKey } : null,
    };
  } catch (err) {
    console.log('generateSignedPrekey error:', err);
    return null;
  }
};

/**
 * Verify a signed prekey using the signer's Ed25519 public key.
 */
export const verifySignedPrekey = (signedPrekeyB64, signatureB64, signingPublicKeyB64) => {
  if (!signedPrekeyB64 || !signatureB64 || !signingPublicKeyB64) return false;

  try {
    const prekeyBytes = decodeBase64(signedPrekeyB64);
    const signature = decodeBase64(signatureB64);
    const signingPub = decodeBase64(signingPublicKeyB64);
    return nacl.sign.detached.verify(prekeyBytes, signature, signingPub);
  } catch (err) {
    console.log('verifySignedPrekey error:', err);
    return false;
  }
};

/**
 * Generate a batch of one-time prekeys (Curve25519 + PQ).
 *
 * @param {number} count - Number of OTPs to generate
 * @param {number} startIndex - Starting index for IDs
 * @returns {Array<{ id, publicKey, privateKey, pqPublicKey, pqPrivateKey }>}
 */
export const generateOneTimePrekeys = async (count, startIndex) => {
  const prekeys = [];
  for (let i = 0; i < count; i++) {
    try {
      const kp = nacl.box.keyPair();
      let pqKp = null;
      try { pqKp = await pqGenerateKeyPair(); } catch (_) { pqKp = null; }
      prekeys.push({
        id: startIndex + i,
        publicKey: encodeBase64(kp.publicKey),
        privateKey: encodeBase64(kp.secretKey),
        pqPublicKey: pqKp ? pqKp.publicKey : null,
        pqPrivateKey: pqKp ? pqKp.privateKey : null,
      });
    } catch (err) {
      console.log('generateOneTimePrekeys error at index', startIndex + i, err);
    }
  }
  return prekeys;
};

// ============================================
// SENDER KEY ENCRYPTION (Group Chats)
// ============================================

/**
 * Generate a new Sender Key for group encryption.
 * Returns a random 256-bit symmetric key + a unique key ID (epoch).
 */
export const generateSenderKey = () => {
  const key = nacl.randomBytes(nacl.secretbox.keyLength);
  const keyId = secureRandomHex(8);
  return { key: encodeBase64(key), keyId };
};

/**
 * Rotate a group's Sender Key for forward secrecy.
 * Called when: a member leaves/is removed, a member is added, or after
 * a configurable message count threshold (default 100 messages).
 * Generates a new key and returns it for distribution to current members.
 * Old keys are kept in a keychain for decrypting messages sent before rotation.
 * @param {string} conversationId - The group conversation ID
 * @param {string|null} oldKeyB64 - Previous Sender Key to archive (or null)
 * @param {string|null} oldKeyId - Previous key ID
 * @returns {{ newKey: { key: string, keyId: string }, archivedKey: { key: string, keyId: string }|null }}
 */
export const rotateSenderKey = (conversationId, oldKeyB64, oldKeyId) => {
  const newKey = generateSenderKey();
  const archivedKey = oldKeyB64 && oldKeyId ? { key: oldKeyB64, keyId: oldKeyId } : null;
  return { newKey, archivedKey };
};

/**
 * Check if a Sender Key should be rotated based on message count.
 * Forward secrecy for groups: rotate every N messages to limit exposure window.
 * @param {number} messagesSinceRotation - Messages sent with current key
 * @param {number} threshold - Rotation threshold (default 100)
 * @returns {boolean}
 */
export const shouldRotateSenderKey = (messagesSinceRotation, threshold = 100) => {
  return messagesSinceRotation >= threshold;
};

/**
 * Decrypt with key chain — tries current key first, then archived keys.
 * Enables backward compatibility during key rotation transitions.
 * @param {string} encrypted - "skey:<keyId>:<nonce_b64>:<ciphertext_b64>"
 * @param {Array<{ key: string, keyId: string }>} keyChain - Current + archived keys
 * @returns {string|null} - Decrypted plaintext or null
 */
export const decryptWithKeyChain = (encrypted, keyChain) => {
  if (!encrypted || !keyChain || !encrypted.startsWith('skey:')) return null;
  const parts = encrypted.split(':');
  if (parts.length < 4) return null;
  const msgKeyId = parts[1];

  // Try matching keyId first for efficiency
  if (msgKeyId) {
    const match = keyChain.find(k => k.keyId === msgKeyId);
    if (match) {
      const result = decryptWithSenderKey(encrypted, match.key);
      if (result) return result;
    }
  }

  // Fallback: try all keys in chain
  for (const entry of keyChain) {
    const result = decryptWithSenderKey(encrypted, entry.key);
    if (result) return result;
  }
  return null;
};

/**
 * Encrypt a message with a Sender Key (symmetric, NaCl secretbox).
 * Used for group messages — one encrypt, all members can decrypt.
 * @param {string} plaintext - Message to encrypt
 * @param {string} senderKeyB64 - 32-byte Sender Key (base64)
 * @returns {string|null} - "skey:<keyId>:<nonce_b64>:<ciphertext_b64>" or null
 */
export const encryptWithSenderKey = (plaintext, senderKeyB64, keyId) => {
  if (!plaintext || !senderKeyB64) return null;
  try {
    const key = decodeBase64(senderKeyB64);
    if (!key || key.length !== nacl.secretbox.keyLength) return null;
    const messageBytes = decodeUTF8(plaintext);
    const paddedBytes = padMessage(messageBytes);
    const nonce = nacl.randomBytes(nacl.secretbox.nonceLength);
    const ciphertext = nacl.secretbox(paddedBytes, nonce, key);
    if (!ciphertext) return null;
    return 'skey:' + (keyId || '') + ':' + encodeBase64(nonce) + ':' + encodeBase64(ciphertext);
  } catch (e) {
    console.log('encryptWithSenderKey error:', e?.message || String(e));
    return null;
  }
};

/**
 * Decrypt a Sender Key encrypted message.
 * @param {string} encrypted - "skey:<keyId>:<nonce_b64>:<ciphertext_b64>"
 * @param {string} senderKeyB64 - 32-byte Sender Key (base64)
 * @returns {string|null} - Decrypted plaintext or null
 */
export const decryptWithSenderKey = (encrypted, senderKeyB64) => {
  if (!encrypted || !senderKeyB64 || !encrypted.startsWith('skey:')) return null;
  try {
    const parts = encrypted.split(':');
    if (parts.length < 4) return null;
    const nonce = decodeBase64(parts[2]);
    const ciphertext = decodeBase64(parts[3]);
    const key = decodeBase64(senderKeyB64);
    if (!key || key.length !== nacl.secretbox.keyLength) return null;
    if (!nonce || nonce.length !== nacl.secretbox.nonceLength) return null;
    const decrypted = nacl.secretbox.open(ciphertext, nonce, key);
    if (!decrypted) return null;
    const unpadded = unpadMessage(decrypted);
    if (!unpadded) return null;
    return encodeUTF8(unpadded);
  } catch (e) {
    console.log('decryptWithSenderKey error:', e?.message || String(e));
    return null;
  }
};

// ============================================
// EPOCH-AWARE SENDER KEY WIRE V2 (KAN-21 / C-D) — `skey2:<epoch>:...`
// ============================================
//
// The v2 message framing carries the rotation EPOCH the message was sent under,
// as one extra leading integer segment. The CRYPTO IS IDENTICAL to v1: same
// NaCl secretbox over padMessage(plaintext), same nonce, same keyId — only the
// `skey2:<epoch>:` prefix differs. The epoch is an UNAUTHENTICATED advisory
// routing/reject hint (it is NOT in the AAD; secretbox here has no AAD).
// Confidentiality across a membership change does NOT come from the epoch — it
// comes from the removed member being EXCLUDED from the new key distribution
// (DECISION 2). The epoch only lets a v2 receiver reject pre-join history
// (DECISION 3) and lets the client reason about which key a message used.
//
// WRITE-GATE (DECISION 1): encodeSenderKeyMessage emits v2 ONLY when the caller
// passes `opts.wireV2 === true` AND a non-negative integer `opts.epoch`. With no
// opts (or the flag off) it is BYTE-IDENTICAL to encryptWithSenderKey — the same
// `skey:` bytes an old in-field client already reads. The flag is a per-conversation
// server field flipped DELIBERATELY post-rollout; a writer never emits a format an
// old reader can't parse while it is off.
//
// DUAL-READ (always on, NEVER flag-gated): decodeSenderKeyMessage and
// decodeSenderKeyMessageChain accept BOTH `skey:` and `skey2:`. New clients always
// dual-read, so a conversation can be flipped on with zero reader-coordination risk.

const SENDER_KEY_V1_PREFIX = 'skey:';
const SENDER_KEY_V2_PREFIX = 'skey2:';

/**
 * Pure parser: extract the integer epoch from a `skey2:<epoch>:...` message.
 * Returns null for legacy `skey:` (epoch unknown), for any non-sender-key string,
 * or for a malformed/non-integer epoch segment. NEVER throws.
 *
 * @param {string} encrypted
 * @returns {number|null}
 */
export const parseSenderKeyEpoch = (encrypted) => {
  if (typeof encrypted !== 'string') return null;
  // skr1 (ratchet wire) carries its epoch in the same position as skey2, so
  // the joinedEpoch reject gate covers both without a second parser.
  if (encrypted.startsWith(SENDER_KEY_RATCHET_PREFIX)) {
    const parts = encrypted.split(':');
    if (parts.length < 6) return null; // prefix epoch keyId iter nonce ct
    if (!/^\d+$/.test(parts[1])) return null;
    const e = Number(parts[1]);
    return Number.isInteger(e) && e >= 0 ? e : null;
  }
  if (!encrypted.startsWith(SENDER_KEY_V2_PREFIX)) return null; // v1 / other ⇒ epoch unknown
  // `skey2:<epoch>:<keyId>:<nonce>:<ct>` — split with a cap so a `:` inside a
  // base64 segment (there is none in std base64, but be defensive) can't shift
  // the epoch index. The epoch is the SECOND field.
  const parts = encrypted.split(':');
  if (parts.length < 5) return null; // need prefix + epoch + keyId + nonce + ct
  const epochStr = parts[1];
  // Strict base-10 non-negative integer. Reject empty, signs, floats, hex, etc.
  if (!/^\d+$/.test(epochStr)) return null;
  const epoch = Number(epochStr);
  if (!Number.isInteger(epoch) || epoch < 0) return null;
  return epoch;
};

/**
 * The ONLY place that decides v1-vs-v2 on WRITE (the write-gate lives here).
 *
 * When `opts.wireV2 === true` AND `opts.epoch` is a non-negative integer, emits
 * `skey2:<epoch>:<keyId>:<nonce_b64>:<ct_b64>` reusing the SAME secretbox
 * primitive as encryptWithSenderKey (no new crypto). Otherwise emits the LEGACY
 * `skey:` via encryptWithSenderKey unchanged — byte-identical to today's send.
 *
 * @param {string} plaintext
 * @param {string} senderKeyB64
 * @param {string} keyId
 * @param {{ epoch?: number, wireV2?: boolean }} [opts]
 * @returns {string|null}
 */
export const encodeSenderKeyMessage = (plaintext, senderKeyB64, keyId, opts) => {
  const wireV2 = opts && opts.wireV2 === true;
  const epoch = opts ? opts.epoch : undefined;
  // Default / flag-off / invalid-epoch ⇒ legacy v1. Byte-identical to today.
  if (!wireV2 || !Number.isInteger(epoch) || epoch < 0) {
    return encryptWithSenderKey(plaintext, senderKeyB64, keyId);
  }
  // v2: identical crypto, one extra leading integer segment.
  if (!plaintext || !senderKeyB64) return null;
  try {
    const key = decodeBase64(senderKeyB64);
    if (!key || key.length !== nacl.secretbox.keyLength) return null;
    const messageBytes = decodeUTF8(plaintext);
    const paddedBytes = padMessage(messageBytes);
    const nonce = nacl.randomBytes(nacl.secretbox.nonceLength);
    const ciphertext = nacl.secretbox(paddedBytes, nonce, key);
    if (!ciphertext) return null;
    return SENDER_KEY_V2_PREFIX + String(epoch) + ':' + (keyId || '') + ':'
      + encodeBase64(nonce) + ':' + encodeBase64(ciphertext);
  } catch (e) {
    console.log('encodeSenderKeyMessage v2 error:', e?.message || String(e));
    return null;
  }
};

/**
 * Decrypt the v2 body once the epoch segment is stripped. Reuses the SAME
 * secretbox.open + unpad as decryptWithSenderKey; the only difference is the
 * field offsets (`skey2:<epoch>:<keyId>:<nonce>:<ct>`). Returns null on any
 * failure — never throws.
 */
const _decryptSenderKeyV2 = (encrypted, senderKeyB64) => {
  try {
    const parts = encrypted.split(':');
    // prefix(0) epoch(1) keyId(2) nonce(3) ct(4)
    if (parts.length < 5) return null;
    const nonce = decodeBase64(parts[3]);
    const ciphertext = decodeBase64(parts[4]);
    const key = decodeBase64(senderKeyB64);
    if (!key || key.length !== nacl.secretbox.keyLength) return null;
    if (!nonce || nonce.length !== nacl.secretbox.nonceLength) return null;
    const decrypted = nacl.secretbox.open(ciphertext, nonce, key);
    if (!decrypted) return null;
    const unpadded = unpadMessage(decrypted);
    if (!unpadded) return null;
    return encodeUTF8(unpadded);
  } catch (e) {
    console.log('decryptWithSenderKeyV2 error:', e?.message || String(e));
    return null;
  }
};

/**
 * Single dual-read decode for a KNOWN key. Routes `skey2:` to the v2 parse and
 * `skey:` to decryptWithSenderKey. Returns null on any other prefix. New clients
 * ALWAYS dual-read; this never gates on the v2 write flag.
 *
 * @param {string} encrypted
 * @param {string} senderKeyB64
 * @returns {string|null}
 */
export const decodeSenderKeyMessage = (encrypted, senderKeyB64) => {
  if (typeof encrypted !== 'string' || !senderKeyB64) return null;
  if (encrypted.startsWith(SENDER_KEY_RATCHET_PREFIX)) {
    return _decryptSenderKeyRatchet(encrypted, senderKeyB64);
  }
  if (encrypted.startsWith(SENDER_KEY_V2_PREFIX)) {
    return _decryptSenderKeyV2(encrypted, senderKeyB64);
  }
  if (encrypted.startsWith(SENDER_KEY_V1_PREFIX)) {
    return decryptWithSenderKey(encrypted, senderKeyB64);
  }
  return null;
};

/**
 * Archive-ring dual-read superset of decryptWithKeyChain. For `skey2:` it
 * extracts the embedded keyId (segment 2) for a fast keyId match, then falls back
 * to trying every archived key; for `skey:` it delegates to decryptWithKeyChain
 * unchanged. Lets PRE-rotation history under EITHER wire version stay readable.
 *
 * @param {string} encrypted
 * @param {Array<{key:string, keyId:string}>} keyChain
 * @returns {string|null}
 */
export const decodeSenderKeyMessageChain = (encrypted, keyChain) => {
  if (typeof encrypted !== 'string' || !keyChain) return null;
  if (encrypted.startsWith(SENDER_KEY_RATCHET_PREFIX)) {
    const parts = encrypted.split(':');
    if (parts.length < 6) return null;
    const msgKeyId = parts[2];
    if (msgKeyId) {
      const match = keyChain.find((k) => k && k.keyId === msgKeyId);
      if (match) {
        const result = _decryptSenderKeyRatchet(encrypted, match.key);
        if (result) return result;
      }
    }
    for (const entry of keyChain) {
      if (!entry || !entry.key) continue;
      const result = _decryptSenderKeyRatchet(encrypted, entry.key);
      if (result) return result;
    }
    return null;
  }
  if (encrypted.startsWith(SENDER_KEY_V2_PREFIX)) {
    const parts = encrypted.split(':');
    if (parts.length < 5) return null;
    const msgKeyId = parts[2];
    // Fast path: match the embedded keyId first.
    if (msgKeyId) {
      const match = keyChain.find((k) => k && k.keyId === msgKeyId);
      if (match) {
        const result = _decryptSenderKeyV2(encrypted, match.key);
        if (result) return result;
      }
    }
    // Fallback: try every archived key (covers keyId collisions / missing id).
    for (const entry of keyChain) {
      if (!entry || !entry.key) continue;
      const result = _decryptSenderKeyV2(encrypted, entry.key);
      if (result) return result;
    }
    return null;
  }
  if (encrypted.startsWith(SENDER_KEY_V1_PREFIX)) {
    return decryptWithKeyChain(encrypted, keyChain);
  }
  return null;
};

// ============================================
// SENDER KEY PER-MESSAGE RATCHET (skr1) — ADR 0001 §4.1 closure, phase A
//
// The accepted v1 posture was a single Sender Key root per epoch: compromise
// of a member's current key exposed every message in the epoch, past and
// future. skr1 gives groups the 1:1 property at the message layer: a hash
// ratchet over the SAME distributed root, one message key per message.
//
//   ck_0   = HMAC-SHA256(root, "shft-skr1-ck0")     (domain-separated: the
//            root itself never encrypts a message, and skey:/skey2: under
//            the same root remain cryptographically independent)
//   mk_i   = HMAC-SHA256(ck_i, 0x01)
//   ck_i+1 = HMAC-SHA256(ck_i, 0x02)
//
// Wire: skr1:<epoch>:<keyId>:<iter>:<nonce_b64>:<ct_b64> — same secretbox +
// pad/unpad as every other sender-key wire; the only new crypto is the KDF
// chain, built on the file's existing sync hmacSha256.
//
// DISTRIBUTION IS UNCHANGED: naclp:/pqsk1: envelopes still carry the root,
// so the PQ hybrid and every rotation/exclusion property of ADR 0001 apply
// to skr1 verbatim.
//
// Phase A (this change): primitives + dual-read at every decode site +
// capability publishing. Receivers derive mk_i from the retained root
// (recompute path), so out-of-order and history are trivially correct with
// ZERO state migration. Phase B (device-gated): receivers persist chain
// state, delete the root and spent keys, realizing full forward secrecy —
// at which point server-side history beyond the local cache behaves exactly
// like 1:1 (device-local), which is the directed semantic.
//
// Iter is attacker-influenced on the read path; SKR_MAX_ITER bounds the
// HMAC walk so a hostile iter cannot busy-loop the thread. Rotation's
// secondary trigger caps a key at 1000 messages, so 4096 is generous.
// ============================================
export const SENDER_KEY_RATCHET_PREFIX = 'skr1:';
const SKR_MAX_ITER = 4096;
const _SKR_MK_BYTE = new Uint8Array([0x01]);
const _SKR_CK_BYTE = new Uint8Array([0x02]);

// mk_iter from the root, walking the chain. Null on any invalid input.
//
// ADR §4.3 (epoch unauthenticated) is CLOSED for this wire: epoch and keyId
// are folded into the chain-start label, so a rewritten epoch or keyId
// derives a different chain and the secretbox MAC fails — the advisory
// segments are now implicitly authenticated. (Bound in-place hours after
// skr1 first shipped, before any real traffic existed; there is no
// unbound-skr1 legacy to dual-read.)
export const skrDeriveMessageKey = (rootB64, iter, epoch, keyId) => {
  try {
    if (!rootB64 || !Number.isInteger(iter) || iter < 0 || iter > SKR_MAX_ITER) return null;
    if (!Number.isInteger(epoch) || epoch < 0) return null;
    const root = decodeBase64(rootB64);
    if (!root || root.length !== nacl.secretbox.keyLength) return null;
    const label = decodeUTF8('shft-skr1-ck0:' + String(epoch) + ':' + String(keyId || ''));
    let ck = hmacSha256(root, label);
    for (let i = 0; i < iter; i++) ck = hmacSha256(ck, _SKR_CK_BYTE);
    return hmacSha256(ck, _SKR_MK_BYTE);
  } catch (_) { return null; }
};

/**
 * Encrypt one group message at chain position `iter`. The CALLER owns the
 * iter counter (persist + increment per send); this stays pure.
 * @returns {string|null} skr1 wire, or null on any invalid input.
 */
export const encodeSenderKeyMessageRatchet = (plaintext, rootB64, keyId, epoch, iter) => {
  if (!plaintext || !rootB64) return null;
  if (!Number.isInteger(epoch) || epoch < 0) return null;
  const mk = skrDeriveMessageKey(rootB64, iter, epoch, keyId);
  if (!mk) return null;
  try {
    const paddedBytes = padMessage(decodeUTF8(plaintext));
    const nonce = nacl.randomBytes(nacl.secretbox.nonceLength);
    const ciphertext = nacl.secretbox(paddedBytes, nonce, mk);
    if (!ciphertext) return null;
    return SENDER_KEY_RATCHET_PREFIX + String(epoch) + ':' + (keyId || '') + ':' + String(iter) + ':'
      + encodeBase64(nonce) + ':' + encodeBase64(ciphertext);
  } catch (e) {
    console.log('encodeSenderKeyMessageRatchet error:', e?.message || String(e));
    return null;
  }
};

/** Decrypt an skr1 wire against a root. Fail-closed: null, never throws. */
const _decryptSenderKeyRatchet = (encrypted, rootB64) => {
  try {
    const parts = encrypted.split(':');
    // prefix(0) epoch(1) keyId(2) iter(3) nonce(4) ct(5)
    if (parts.length < 6) return null;
    if (!/^\d+$/.test(parts[1]) || !/^\d+$/.test(parts[3])) return null;
    const iter = Number(parts[3]);
    const mk = skrDeriveMessageKey(rootB64, iter, Number(parts[1]), parts[2]);
    if (!mk) return null;
    const nonce = decodeBase64(parts[4]);
    const ciphertext = decodeBase64(parts[5]);
    if (!nonce || nonce.length !== nacl.secretbox.nonceLength) return null;
    const decrypted = nacl.secretbox.open(ciphertext, nonce, mk);
    if (!decrypted) return null;
    const unpadded = unpadMessage(decrypted);
    if (!unpadded) return null;
    return encodeUTF8(unpadded);
  } catch (e) {
    console.log('decryptSenderKeyRatchet error:', e?.message || String(e));
    return null;
  }
};

/**
 * Distribute a Sender Key to group members by encrypting it for each member's public key.
 * @param {string} senderKeyB64 - The Sender Key to distribute
 * @param {Array<{id: string, publicKey: string}>} members - Array of {id, publicKey} for each member
 * @param {string} myPrivateKeyB64 - Our private key for NaCl box
 * @returns {Object} - { memberId: encryptedSenderKey, ... }
 */
export const distributeSenderKey = (senderKeyB64, members, myPrivateKeyB64) => {
  const distributed = {};
  for (const member of members) {
    if (!member.publicKey) continue;
    const encrypted = encryptMessage(senderKeyB64, member.publicKey, myPrivateKeyB64);
    if (encrypted) distributed[member.id] = encrypted;
  }
  return distributed;
};

/**
 * Receive and decrypt a Sender Key distributed to us.
 * @param {string} encryptedKey - NaCl box encrypted Sender Key
 * @param {string} senderPublicKeyB64 - Public key of whoever distributed this key
 * @param {string} myPrivateKeyB64 - Our private key
 * @returns {string|null} - Decrypted Sender Key (base64) or null
 */
export const receiveSenderKey = (encryptedKey, senderPublicKeyB64, myPrivateKeyB64) => {
  if (!encryptedKey || !senderPublicKeyB64 || !myPrivateKeyB64) return null;
  return decryptMessage(encryptedKey, senderPublicKeyB64, myPrivateKeyB64);
};

// ============================================
// PQ-HYBRID SENDER KEY DISTRIBUTION (KAN-21 #2 / group PQ gap)
// ============================================
//
// The classical distributeSenderKey above wraps the Sender Key in a NaCl box
// (X25519) ONLY — so the entire group's message confidentiality rests on X25519,
// a harvest-now-decrypt-later target. These hybrid variants layer ML-KEM-768 ON
// TOP of the classical X25519 secret, using the SAME KEM-combiner construction
// the 1:1 X3DH path already uses (initSessionFromPrekeyBundle): the wrapping key
// is HKDF over `0xFF×32 ‖ X25519_shared ‖ [ML-KEM_shared]`. Breaking EITHER
// primitive alone is insufficient — an attacker needs both the X25519 secret AND
// the ML-KEM secret to recompute the wrap key. Never single-encrypts with one
// (per the PQ-hybrid invariant).
//
// Soft activation, mirroring the 1:1 path: the sender encapsulates iff the member
// published a PQ public key AND native ML-KEM is available; otherwise the IKM is
// classical-only (identical to a non-PQ build). The receiver hard-fails if a PQ
// ciphertext is present but it cannot decapsulate (no silent classical downgrade
// that would diverge the wrap key) — matching initSessionFromFirstMessage.
//
// Wire format: "pqsk1:<kemCtB64|''>:<nonceB64>:<ctB64>" — an empty kemCt segment
// means classical-only. This is a NEW format; wiring it into the live path
// (dual-read with the legacy `naclp:` envelope during rollout) is the
// device/multi-client-gated follow-up — see docs/security/crypto-remediation-plan.md.
const _GROUP_SK_INFO = 'theSHFT_GroupSK_v1';

const _deriveGroupSkWrapKey = (classicalSharedBytes, pqSharedBytesOrNull) => {
  const discontinuity = new Uint8Array(32).fill(0xFF);
  const pqLen = pqSharedBytesOrNull ? 32 : 0;
  const ikm = new Uint8Array(32 + classicalSharedBytes.length + pqLen);
  ikm.set(discontinuity, 0);
  ikm.set(classicalSharedBytes, 32);
  if (pqSharedBytesOrNull) ikm.set(pqSharedBytesOrNull, 32 + classicalSharedBytes.length);
  const salt = new Uint8Array(32);
  const wrap = hkdf(salt, ikm, asciiToBytes(_GROUP_SK_INFO), 32);
  try { ikm.fill(0); } catch (_) { /* best-effort */ }
  return wrap;
};

// Constant-time-ish all-zero check on a 32-byte X25519 shared secret. We use
// the RAW nacl.scalarMult output (not box.before, which HSalsa20-mixes the DH
// and so masks a low-order point into a fixed non-zero constant). scalarMult of
// a low-order / substituted public key IS all-zero, so this check hard-fails on
// it — preventing an attacker who can swap a member publicKey from pinning the
// wrap key to a known value (critical in the PQ-absent path, where the X25519
// share is the only secret). HKDF then conditions the raw DH, so dropping the
// HSalsa20 layer costs nothing.
const _isAllZero32 = (bytes) => {
  if (!bytes || bytes.length !== 32) return true;
  let acc = 0;
  for (let i = 0; i < 32; i++) acc |= bytes[i];
  return acc === 0;
};

/**
 * PQ-hybrid distribute: wrap the Sender Key for each member under HKDF(X25519 ‖
 * ML-KEM). Members need a classical `publicKey` (Curve25519) and ideally a
 * `pqPublicKey` (ML-KEM-768); a member without a pqPublicKey (or when native
 * ML-KEM is unavailable) gets a classical-only envelope.
 *
 * Forward-secrecy posture: the X25519 share is the sender's LONG-TERM identity
 * DH (no per-envelope ephemeral), matching the classical distributeSenderKey.
 * There is no per-distribution FS — confidentiality across time relies on
 * Sender Key ROTATION cadence (config/senderKeyRotation.js), not an in-envelope
 * ratchet. Document this when wiring; do not imply more FS than delivered.
 *
 * DISPOSAL: `senderKeyB64` / `myPrivateKeyB64` are caller-owned strings (GC-only,
 * not zeroized here). The decoded byte copies ARE zeroized.
 *
 * @param {string} senderKeyB64
 * @param {Array<{id:string, publicKey:string, pqPublicKey?:string}>} members
 * @param {string} myPrivateKeyB64  Caller's Curve25519 private key (base64)
 * @returns {Promise<{distributed:Object, failed:string[]}>} per-member envelopes
 *   plus the ids we could NOT deliver to (caller must surface/retry — a missing
 *   member would otherwise silently look "removed").
 */
export const distributeSenderKeyHybrid = async (senderKeyB64, members, myPrivateKeyB64) => {
  const distributed = {};
  const failed = [];
  // AUDIT 2026-08-29 — REPORT the members who got no post-quantum protection.
  //
  // A member without a pqPublicKey still receives a `pqsk1:` envelope, just
  // with an empty KEM segment: PQ-SHAPED AND CLASSICALLY STRONG. That is the
  // most dangerous state this function can produce, because everything
  // downstream reads the prefix and concludes the group is post-quantum.
  //
  // And it is not one member's problem. Every member is handed the SAME sender
  // key, so an attacker who breaks any single classical envelope holds the key
  // to the entire group's messages. PQ here is an AND over every recipient, not
  // an average — see docs/adr/0001 section 9. Callers must therefore be able to
  // see coverage rather than infer it from the wire format.
  const classicalOnly = [];
  if (!senderKeyB64 || !myPrivateKeyB64 || !Array.isArray(members)) {
    return { distributed, failed, classicalOnly, pqCovered: false };
  }
  const myPriv = decodeBase64(myPrivateKeyB64);
  const skBytes = decodeUTF8(senderKeyB64); // wrap the base64 string itself
  try {
    for (const member of members) {
      if (!member || !member.id || !member.publicKey) { if (member?.id) failed.push(member.id); continue; }
      let classicalShared = null;
      let pqSharedBytes = null;
      let wrapKey = null;
      try {
        classicalShared = nacl.scalarMult(myPriv, decodeBase64(member.publicKey)); // raw X25519
        if (_isAllZero32(classicalShared)) { failed.push(member.id); continue; } // low-order / bad pubkey
        let pqCiphertextB64 = '';
        if (!member.pqPublicKey) classicalOnly.push(member.id);
        if (member.pqPublicKey) {
          // encap.sharedSecret is an immutable JS string — not zeroizable,
          // only tightly scoped; the decoded bytes ARE zeroized in finally.
          const encap = await pqEncapsulate(member.pqPublicKey);
          if (encap?.ciphertext && typeof encap.sharedSecret === 'string' && encap.sharedSecret.length === 64) {
            pqCiphertextB64 = encap.ciphertext;
            pqSharedBytes = hexToBytes32(encap.sharedSecret);
          }
        }
        wrapKey = _deriveGroupSkWrapKey(classicalShared, pqSharedBytes);
        const nonce = nacl.randomBytes(nacl.secretbox.nonceLength);
        const ct = nacl.secretbox(skBytes, nonce, wrapKey);
        if (ct) {
          distributed[member.id] = 'pqsk1:' + pqCiphertextB64 + ':' + encodeBase64(nonce) + ':' + encodeBase64(ct);
        } else {
          failed.push(member.id);
        }
      } catch (e) {
        failed.push(member.id);
        console.log('distributeSenderKeyHybrid member error:', e?.name);
      } finally {
        try { if (pqSharedBytes) pqSharedBytes.fill(0); } catch (_) { /* best-effort */ }
        try { if (wrapKey) wrapKey.fill(0); } catch (_) { /* best-effort */ }
        try { if (classicalShared) classicalShared.fill(0); } catch (_) { /* best-effort */ }
      }
    }
  } finally {
    try { myPriv.fill(0); } catch (_) { /* best-effort */ }
    try { skBytes.fill(0); } catch (_) { /* best-effort */ }
  }
  // pqCovered is the only honest summary: true iff EVERY recipient got a
  // real KEM encapsulation. One classical envelope makes the whole group
  // classical, so this is an AND, never a ratio.
  return { distributed, failed, classicalOnly,
    pqCovered: classicalOnly.length === 0 && members.length > 0 };
};

/**
 * PQ-hybrid receive: recover the Sender Key from a "pqsk1:" envelope. Returns the
 * base64 Sender Key, or null. Hard-fails (returns null) if a PQ ciphertext is
 * present but cannot be decapsulated — no silent classical downgrade.
 *
 * @param {string} envelope               "pqsk1:<kemCt|''>:<nonce>:<ct>"
 * @param {string} senderPublicKeyB64     Distributor's Curve25519 public key
 * @param {string} myPrivateKeyB64        Our Curve25519 private key
 * @param {string|null} myPqPrivateKeyB64 Our ML-KEM-768 private key (or null)
 * @returns {Promise<string|null>}
 */
export const receiveSenderKeyHybrid = async (
  envelope, senderPublicKeyB64, myPrivateKeyB64, myPqPrivateKeyB64,
) => {
  if (typeof envelope !== 'string' || !envelope.startsWith('pqsk1:')) return null;
  if (!senderPublicKeyB64 || !myPrivateKeyB64) return null;
  return _receiveSenderKeyHybridInner(envelope, senderPublicKeyB64, myPrivateKeyB64, myPqPrivateKeyB64);
};

// Dual-read sender-key unwrap (KAN-21 #2 rollout). Routes a 'pqsk1:' envelope to
// the PQ-hybrid path and anything else (legacy 'naclp:') to the classical path.
// ALWAYS safe to use regardless of the send-side flag, so a receiver can read a
// hybrid envelope from an early-adopter sender before the flag flips everywhere.
// Async because the hybrid path is async; the classical path is wrapped.
export const receiveSenderKeyAny = async (envelope, senderPublicKeyB64, myPrivateKeyB64, myPqPrivateKeyB64) => {
  if (typeof envelope === 'string' && envelope.startsWith('pqsk1:')) {
    return receiveSenderKeyHybrid(envelope, senderPublicKeyB64, myPrivateKeyB64, myPqPrivateKeyB64 || null);
  }
  return receiveSenderKey(envelope, senderPublicKeyB64, myPrivateKeyB64);
};

const _receiveSenderKeyHybridInner = async (envelope, senderPublicKeyB64, myPrivateKeyB64, myPqPrivateKeyB64) => {
  let myPriv = null;
  let classicalShared = null;
  let pqSharedBytes = null;
  let wrapKey = null;
  try {
    const parts = envelope.split(':');
    if (parts.length !== 4) return null; // strict: reject trailing garbage
    const kemCtB64 = parts[1];
    const nonce = decodeBase64(parts[2]);
    const ct = decodeBase64(parts[3]);
    myPriv = decodeBase64(myPrivateKeyB64);
    classicalShared = nacl.scalarMult(myPriv, decodeBase64(senderPublicKeyB64)); // raw X25519
    if (_isAllZero32(classicalShared)) return null; // low-order / substituted sender key
    if (kemCtB64) {
      // PQ ciphertext present → we MUST be able to decapsulate. No classical
      // fallback (that would diverge the wrap key, silently accepting a
      // downgrade). Requires our PQ private key + a well-formed 32-byte secret.
      if (!myPqPrivateKeyB64) return null;
      const pqHex = await pqDecapsulate(kemCtB64, myPqPrivateKeyB64);
      if (!pqHex || pqHex.length !== 64) return null;
      pqSharedBytes = hexToBytes32(pqHex);
    }
    wrapKey = _deriveGroupSkWrapKey(classicalShared, pqSharedBytes);
    const pt = nacl.secretbox.open(ct, nonce, wrapKey);
    return pt ? encodeUTF8(pt) : null;
  } catch (e) {
    console.log('receiveSenderKeyHybrid error:', e?.name);
    return null;
  } finally {
    try { if (myPriv) myPriv.fill(0); } catch (_) { /* best-effort */ }
    try { if (classicalShared) classicalShared.fill(0); } catch (_) { /* best-effort */ }
    try { if (pqSharedBytes) pqSharedBytes.fill(0); } catch (_) { /* best-effort */ }
    try { if (wrapKey) wrapKey.fill(0); } catch (_) { /* best-effort */ }
  }
};

// ============================================
// X3DH KEY AGREEMENT
// ============================================

/**
 * Sender-side: Establish a ratchet session from a recipient's prekey bundle.
 *
 * Performs extended triple DH:
 *   DH1 = DH(myIdentity, theirSignedPrekey)
 *   DH2 = DH(myEphemeral, theirIdentity)
 *   DH3 = DH(myEphemeral, theirSignedPrekey)
 *   DH4 = DH(myEphemeral, theirOneTimePrekey) [if available]
 *   PQ  = pqEncapsulate(theirPqPrekey) [if available]
 *
 * @param {object} bundle - { identityKey, signedPrekey, signedPrekeySignature, signingPublicKey,
 *                             signedPrekeyId, oneTimePrekey?, oneTimePrekeyId?, pqPrekey? }
 * @param {object} myKeys - { publicKey, privateKey } (identity keypair)
 * @returns {{ session, ephemeralPublicKey, usedPrekeyId, usedOtpkId, pqCiphertext }}
 */
export const initSessionFromPrekeyBundle = async (bundle, myKeys) => {
  if (!bundle || !myKeys || !bundle.identityKey || !bundle.signedPrekey || !myKeys.privateKey) return null;

  try {
    // Verify signed prekey signature — mandatory to prevent MITM stripping
    if (!bundle.signedPrekeySignature || !bundle.signingPublicKey) {
      console.log('initSessionFromPrekeyBundle: missing prekey signature or signing key');
      return null;
    }
    const valid = verifySignedPrekey(bundle.signedPrekey, bundle.signedPrekeySignature, bundle.signingPublicKey);
    if (!valid) {
      console.log('initSessionFromPrekeyBundle: signed prekey signature verification failed');
      return null;
    }

    // Generate ephemeral key pair for this session
    const ephemeral = nacl.box.keyPair();
    const ephemeralPublicB64 = encodeBase64(ephemeral.publicKey);

    const myIdentityPriv = decodeBase64(myKeys.privateKey);
    const theirIdentityPub = decodeBase64(bundle.identityKey);
    const theirSignedPrekey = decodeBase64(bundle.signedPrekey);

    // DH1: my identity private × their signed prekey
    const dh1 = nacl.box.before(theirSignedPrekey, myIdentityPriv);
    // DH2: my ephemeral private × their identity public
    const dh2 = nacl.box.before(theirIdentityPub, ephemeral.secretKey);
    // DH3: my ephemeral private × their signed prekey
    const dh3 = nacl.box.before(theirSignedPrekey, ephemeral.secretKey);

    // Concatenate raw DH outputs as Uint8Array (NOT base64 — raw bytes for correct HKDF)
    let dhCount = 3;
    let usedOtpkId = null;
    let dh4 = null;
    if (bundle.oneTimePrekey) {
      const theirOtpk = decodeBase64(bundle.oneTimePrekey);
      dh4 = nacl.box.before(theirOtpk, ephemeral.secretKey);
      usedOtpkId = bundle.oneTimePrekeyId || null;
      dhCount = 4;
    }

    const dhConcat = new Uint8Array(32 * dhCount);
    dhConcat.set(dh1, 0);
    dhConcat.set(dh2, 32);
    dhConcat.set(dh3, 64);
    if (dh4) dhConcat.set(dh4, 96);

    // ML-KEM-768 PQ activation (audit C-B1). SOFT activation per
    // Phase 2 plan: encapsulate iff peer's bundle published a PQ
    // prekey AND native ML-KEM is available. Failure on either
    // condition → classical-only IKM, same session as pre-fix code.
    // The receiver-side mirror in initSessionFromFirstMessage uses
    // the presence of pqCiphertext in the first message as the
    // signal to decapsulate; identical IKM means identical root key.
    //
    // Downgrade resistance is NOT enforced this release (x3dhInfo
    // stays at 'theSHFT_X3DH_v2'). Hard activation — bumping to
    // 'theSHFT_X3DH_v3' which would refuse classical-only — lands
    // in v7.3.1 after telemetry confirms ≥99% hybrid adoption.
    let pqCiphertext = null;
    let pqSharedSecretBytes = null;
    if (bundle.pqPrekey) {
      try {
        // pqEncap.sharedSecret is an immutable JS string — not zeroizable,
        // only tightly scoped; the decoded bytes ARE zeroized after HKDF.
        const pqEncap = await pqEncapsulate(bundle.pqPrekey);
        if (pqEncap?.ciphertext && pqEncap?.sharedSecret) {
          pqCiphertext = pqEncap.ciphertext;
          pqSharedSecretBytes = hexToBytes32(pqEncap.sharedSecret);
        }
      } catch (_) { /* fall through to classical-only IKM */ }
    }

    // Derive root key using HKDF (Signal Protocol compatible).
    // F = 32 bytes of 0xFF (X25519 discontinuity bytes, prevents invalid curve attacks)
    // IKM = F || DH1 || DH2 || DH3 [|| DH4] [|| PQ_SHARED_SECRET]
    // Salt = 32 zero bytes
    // Info = "theSHFT_X3DH_v2"  (NOT bumped to v3 this release — soft activation)
    const discontinuity = new Uint8Array(32).fill(0xFF);
    const pqLen = pqSharedSecretBytes ? 32 : 0;
    const ikm = new Uint8Array(32 + dhConcat.length + pqLen);
    ikm.set(discontinuity, 0);
    ikm.set(dhConcat, 32);
    if (pqSharedSecretBytes) {
      ikm.set(pqSharedSecretBytes, 32 + dhConcat.length);
    }
    const x3dhSalt = new Uint8Array(32);
    const x3dhInfo = asciiToBytes('theSHFT_X3DH_v2');
    const masterSecret = hkdf(x3dhSalt, ikm, x3dhInfo, 32);
    const rootKey = bytesToHex(masterSecret);

    // Zero PQ shared secret immediately after HKDF (defense-in-depth).
    if (pqSharedSecretBytes) { try { pqSharedSecretBytes.fill(0); } catch (_) {} }

    // Zero DH outputs + concat + IKM + master secret — each is root-key-grade
    // material no longer needed once rootKey is derived.
    try {
      dh1.fill(0); dh2.fill(0); dh3.fill(0);
      if (dh4) dh4.fill(0);
      dhConcat.fill(0); ikm.fill(0); masterSecret.fill(0);
    } catch (_) {}

    // Zero identity private key after X3DH DH computations
    try { myIdentityPriv.fill(0); } catch (_) {}

    // Derive initial send chain via DH ratchet step.
    const initialDH = nacl.box.before(theirSignedPrekey, ephemeral.secretKey);
    const { rootKey: postDHRoot, chainKey: sendChainKey } = kdfRootStep(rootKey, initialDH);
    try { initialDH.fill(0); } catch (_) {}

    const session = {
      rootKey: postDHRoot,
      sendChainKey,
      recvChainKey: null, // Set when we receive Bob's first DH ratchet response
      sendMessageIndex: 0,
      recvMessageIndex: 0,
      previousChainLength: 0,
      myEphemeralKeyPair: {
        publicKey: ephemeralPublicB64, // Same as X3DH ephemeral
        secretKey: encodeBase64(ephemeral.secretKey),
      },
      theirEphemeralKey: bundle.signedPrekey, // Bob's current ratchet key = signed prekey
      skippedKeys: {},
      version: 2,
    };

    return {
      session,
      ephemeralPublicKey: ephemeralPublicB64,
      usedPrekeyId: bundle.signedPrekeyId,
      usedOtpkId,
      pqCiphertext,
    };
  } catch (err) {
    console.log('initSessionFromPrekeyBundle error:', err);
    return null;
  }
};

/**
 * Recipient-side: Reconstruct a ratchet session from the sender's first message.
 *
 * The sender included their ephemeral public key and which prekeys they used.
 * We look up our stored prekey private keys and perform the same DH computations.
 *
 * @param {string} senderIdentityKeyB64 - Sender's Curve25519 identity public key
 * @param {string} senderEphemeralKeyB64 - Sender's ephemeral public key (from message)
 * @param {string|null} pqCiphertextB64 - PQ ciphertext (from message, if hybrid)
 * @param {number} usedPrekeyId - Which signed prekey the sender used. If it is
 *        exactly one generation behind our current SIGNED_PREKEY_ID we swap in
 *        the 48h grace key (SIGNED_PREKEY_PRIVATE_PREV) instead of the key the
 *        caller passed — see the grace-period block in the body.
 * @param {number|null} usedOtpkId - Which one-time prekey the sender consumed
 * @param {object} myKeys - { publicKey, privateKey } (our identity keypair)
 * @param {string} mySignedPrekeyPrivateB64 - Our signed prekey private key
 * @param {string|null} myOtpkPrivateB64 - Our one-time prekey private key (if used)
 * @param {string|null} myPqPrekeyPrivateB64 - Our PQ prekey private key (if used)
 * @returns {object|null} - Ratchet session state
 */
export const initSessionFromFirstMessage = async (
  senderIdentityKeyB64, senderEphemeralKeyB64, pqCiphertextB64,
  usedPrekeyId, usedOtpkId,
  myKeys, mySignedPrekeyPrivateB64, myOtpkPrivateB64, myPqPrekeyPrivateB64
) => {
  if (!senderIdentityKeyB64 || !senderEphemeralKeyB64 || !myKeys?.privateKey || !mySignedPrekeyPrivateB64) return null;

  try {
    // ─── Signed-prekey grace period (audit 2026-07-25) ────────────────
    // `usedPrekeyId` was accepted and then never read: the body always used
    // whatever private key the caller passed, and the caller (app/chat.js) only
    // ever passes the CURRENT one. Signed prekeys rotate every 7 days
    // (config/database.js rotateSignedPrekey), and a sender who fetched the
    // bundle before a rotation keeps attaching the OLD id to its X3DH material.
    // Deriving DH1/DH3 with the new private key then produces a different root
    // key and the message is permanently undecryptable — which is exactly what
    // the "keep previous signed prekey private for 48h grace period" write at
    // database.js was supposed to prevent. Nothing ever read it back.
    //
    // Conservative rule: only substitute the grace key when the sender's id is
    // EXACTLY one generation behind ours. Two generations back means neither
    // key is right, and we leave the caller's behaviour untouched rather than
    // guess. Any failure to look things up also leaves behaviour untouched.
    let signedPrekeyPrivateB64 = mySignedPrekeyPrivateB64;
    let pqPrekeyPrivateB64 = myPqPrekeyPrivateB64;
    if (usedPrekeyId != null) {
      try {
        const { getLocal, KEYS } = require('./storage');
        const currentId = await getLocal(KEYS.SIGNED_PREKEY_ID);
        if (currentId != null && Number(usedPrekeyId) === Number(currentId) - 1) {
          const prevPriv = await getLocal(KEYS.SIGNED_PREKEY_PRIVATE_PREV);
          if (prevPriv) {
            console.log('[x3dh] first message used the previous signed prekey — using the 48h grace key');
            signedPrekeyPrivateB64 = prevPriv;
          }
          // PQ half: rotateSignedPrekey overwrites SIGNED_PQ_PREKEY_PRIVATE in
          // place and keeps NO previous copy, so there is nothing to fall back
          // to yet. Read the (not-yet-written) '_prev' slot so this path starts
          // working the moment config/database.js persists it on rotation — the
          // read half of a read-both/write-new migration. Until then, a hybrid
          // first message pinned to the old prekey stays undecryptable: ML-KEM
          // uses implicit rejection, so decapsulating with the wrong secret key
          // returns a valid-looking pseudorandom secret instead of an error and
          // the root key diverges silently. Log it so it is at least diagnosable.
          if (pqCiphertextB64) {
            const prevPqPriv = await getLocal('@signed_pq_prekey_private_prev');
            if (prevPqPriv) {
              pqPrekeyPrivateB64 = prevPqPriv;
            } else {
              console.log('[x3dh] stale prekey id on a hybrid message but no previous PQ prekey stored — root key will diverge');
            }
          }
        }
      } catch (_) { /* discovery failed — keep the caller's keys exactly as passed */ }
    }

    const senderIdentityPub = decodeBase64(senderIdentityKeyB64);
    const senderEphemeralPub = decodeBase64(senderEphemeralKeyB64);
    const myIdentityPriv = decodeBase64(myKeys.privateKey);
    const mySignedPrekeyPriv = decodeBase64(signedPrekeyPrivateB64);

    // DH1: their identity × my signed prekey (mirrors sender's DH1)
    const dh1 = nacl.box.before(senderIdentityPub, mySignedPrekeyPriv);
    // DH2: their ephemeral × my identity (mirrors sender's DH2)
    const dh2 = nacl.box.before(senderEphemeralPub, myIdentityPriv);
    // DH3: their ephemeral × my signed prekey (mirrors sender's DH3)
    const dh3 = nacl.box.before(senderEphemeralPub, mySignedPrekeyPriv);

    // Concatenate raw DH outputs as Uint8Array (matching sender side)
    //
    // AUDIT 2026-07-27 (round 8) — a missing OTPK private must FAIL, not
    // silently drop to 3-DH.
    //
    // `usedOtpkId` is the sender telling us which one-time prekey they consumed
    // and therefore mixed into their IKM. If we cannot reproduce that DH, our
    // root key diverges from theirs and the session is dead: ratchetDecrypt
    // fails, every fallback re-derives from the same material and fails
    // identically, and the message renders as an encrypted placeholder forever
    // with no error surfaced to either party. Downgrading to dhCount = 3 makes
    // that outcome look like a successful init.
    //
    // This is reachable without an attacker: a restore publishes otpk_1..20 on
    // the new device while the old install's unconsumed otpk_21..40 are still
    // in the registry with their privates gone, and consumeOneTimePrekey serves
    // in lexicographic id order — so it eventually hands a sender a prekey this
    // device can never answer.
    //
    // The PQ branch 25 lines below already hard-fails on exactly this condition
    // ("refusing classical fallback"); the classical branch did not.
    if (usedOtpkId && !myOtpkPrivateB64) {
      console.log('initSessionFromFirstMessage: sender consumed otpk', usedOtpkId, 'but its private key is missing — refusing 3-DH fallback (root keys would diverge)');
      return null;
    }
    let dhCount = 3;
    let dh4 = null;
    if (myOtpkPrivateB64) {
      const myOtpkPriv = decodeBase64(myOtpkPrivateB64);
      dh4 = nacl.box.before(senderEphemeralPub, myOtpkPriv);
      dhCount = 4;
      try { myOtpkPriv.fill(0); } catch (_) {}
    }

    const dhConcat = new Uint8Array(32 * dhCount);
    dhConcat.set(dh1, 0);
    dhConcat.set(dh2, 32);
    dhConcat.set(dh3, 64);
    if (dh4) dhConcat.set(dh4, 96);

    // ML-KEM-768 PQ activation mirror (audit C-B1). If the sender
    // included pqCiphertextB64, the sender mixed a PQ shared secret
    // into their IKM and we MUST mix the same value to derive the
    // matching root key. Soft activation: classical-only first
    // messages (sender's bundle had no pqPrekey OR encap failed)
    // arrive without pqCiphertextB64 and skip this branch entirely.
    //
    // Hard error: pqCiphertextB64 present but our private key
    // missing OR decap fails — root keys would diverge, and silent
    // fallback to classical IKM is a downgrade attack vector. Return
    // null instead so the caller can surface the failure.
    let pqSharedSecretBytes = null;
    if (pqCiphertextB64) {
      if (!pqPrekeyPrivateB64) {
        console.log('initSessionFromFirstMessage: pqCiphertext present but no PQ private key — refusing classical fallback');
        return null;
      }
      try {
        // pqSecretHex is an immutable JS string — it can't be zeroized, only
        // scoped tightly (dead after this block) and left to GC. The decoded
        // byte copy IS zeroized after HKDF below.
        const pqSecretHex = await pqDecapsulate(pqCiphertextB64, pqPrekeyPrivateB64);
        if (!pqSecretHex) {
          console.log('initSessionFromFirstMessage: pqDecapsulate returned null — refusing classical fallback');
          return null;
        }
        pqSharedSecretBytes = hexToBytes32(pqSecretHex);
      } catch (err) {
        console.log('initSessionFromFirstMessage: pqDecapsulate threw:', err?.message || err);
        return null;
      }
    }

    // Derive the same root key as the sender using HKDF.
    // IKM = F || DH1 || DH2 || DH3 [|| DH4] [|| PQ_SHARED_SECRET]
    // (Sender appended PQ shared secret iff this message carried pqCiphertext.)
    const discontinuity = new Uint8Array(32).fill(0xFF);
    const pqLen = pqSharedSecretBytes ? 32 : 0;
    const ikm = new Uint8Array(32 + dhConcat.length + pqLen);
    ikm.set(discontinuity, 0);
    ikm.set(dhConcat, 32);
    if (pqSharedSecretBytes) {
      ikm.set(pqSharedSecretBytes, 32 + dhConcat.length);
    }
    const x3dhSalt = new Uint8Array(32);
    const x3dhInfo = asciiToBytes('theSHFT_X3DH_v2');
    const masterSecret = hkdf(x3dhSalt, ikm, x3dhInfo, 32);
    const rootKey = bytesToHex(masterSecret);

    // Zero PQ shared secret immediately after HKDF (defense-in-depth).
    if (pqSharedSecretBytes) { try { pqSharedSecretBytes.fill(0); } catch (_) {} }

    // Zero DH outputs + concat + IKM + master secret — each is root-key-grade
    // material no longer needed once rootKey is derived.
    try {
      dh1.fill(0); dh2.fill(0); dh3.fill(0);
      if (dh4) dh4.fill(0);
      dhConcat.fill(0); ikm.fill(0); masterSecret.fill(0);
    } catch (_) {}

    // Perform the matching DH ratchet step BEFORE zeroing keys.
    // The sender did DH(theirSignedPrekey, ephemeral). We mirror it.
    const initialDH = nacl.box.before(senderEphemeralPub, mySignedPrekeyPriv);
    const { rootKey: postDHRoot, chainKey: recvChainKey } = kdfRootStep(rootKey, initialDH);

    // Generate our own ratchet ephemeral for the response DH ratchet.
    const dhRatchetEphemeral = nacl.box.keyPair();

    // Perform a second DH ratchet step to establish our send chain.
    const sendDH = nacl.box.before(senderEphemeralPub, dhRatchetEphemeral.secretKey);
    const { rootKey: finalRoot, chainKey: sendChainKey } = kdfRootStep(postDHRoot, sendDH);

    // Zero secret keys + ratchet DH outputs AFTER all DH computations are done
    try { myIdentityPriv.fill(0); } catch (_) {}
    try { mySignedPrekeyPriv.fill(0); } catch (_) {}
    try { initialDH.fill(0); sendDH.fill(0); } catch (_) {}

    return {
      rootKey: finalRoot,
      sendChainKey,
      recvChainKey,
      sendMessageIndex: 0,
      recvMessageIndex: 0,
      previousChainLength: 0,
      myEphemeralKeyPair: {
        publicKey: encodeBase64(dhRatchetEphemeral.publicKey),
        secretKey: encodeBase64(dhRatchetEphemeral.secretKey),
      },
      theirEphemeralKey: senderEphemeralKeyB64, // Sender's ratchet public key
      skippedKeys: {},
      version: 2,
    };
  } catch (err) {
    console.log('initSessionFromFirstMessage error:', err);
    return null;
  }
};

// ============================================
// RATCHET SESSION PERSISTENCE (encrypted at rest)
// ============================================

/**
 * Get or generate the symmetric key used to encrypt ratchet sessions at rest.
 * Stored in SecureStore (Keychain/Keystore), never in AsyncStorage.
 * Returns a 32-byte Uint8Array key, or null if SecureStore is unavailable.
 */
if (_e.ratchetStorageKeyCache === undefined) _e.ratchetStorageKeyCache = null;
if (_e.ratchetStorageKeyLock === undefined) _e.ratchetStorageKeyLock = null;
const getRatchetStorageKey = async () => {
  if (_e.ratchetStorageKeyCache) return _e.ratchetStorageKeyCache;
  if (_e.ratchetStorageKeyLock) return _e.ratchetStorageKeyLock;
  _e.ratchetStorageKeyLock = (async () => {
    try {
      // Same contract as getOrCreateEncryptionKey (audit 2026-07-25, HIGH):
      // a Keychain read that THREW must not be mistaken for "no key yet".
      // Minting here re-keys ratchet-session storage, which makes every
      // persisted Double Ratchet session permanently undecryptable — the
      // chain state for every 1:1 conversation on the device. Degrading
      // (returning null) only fails the current save/load, and the session
      // is re-established from X3DH material.
      const read = await readSecureValueStrict(SECURE_KEYS.RATCHET_STORAGE_KEY);
      if (!read.ok) {
        console.log('[ratchet] storage key read failed — refusing to mint a replacement');
        try {
          require('./telemetry').captureMessage('ratchet_storage_key_read_failed', 'warning');
        } catch (_) {}
        return null;
      }
      if (read.value) {
        _e.ratchetStorageKeyCache = decodeBase64(read.value);
        return _e.ratchetStorageKeyCache;
      }
      // Definitively absent → generate a new random 32-byte key. Only adopt it
      // if it actually persisted, otherwise sessions written this session would
      // be unreadable after restart.
      const newKey = nacl.randomBytes(32);
      const saved = await safeSecureStoreSet(SECURE_KEYS.RATCHET_STORAGE_KEY, encodeBase64(newKey));
      if (!saved) {
        console.log('[ratchet] storage key generated but NOT persisted — not adopting it');
        return null;
      }
      _e.ratchetStorageKeyCache = newKey;
      return newKey;
    } catch (e) {
      console.log('getRatchetStorageKey error:', e?.message || String(e));
      return null;
    } finally {
      _e.ratchetStorageKeyLock = null;
    }
  })();
  return _e.ratchetStorageKeyLock;
};

/** Clear cached ratchet storage key (call on logout/wipe) */
export const clearRatchetStorageKeyCache = () => { _e.ratchetStorageKeyCache = null; };

/**
 * Encrypt a string using NaCl secretbox with the ratchet storage key.
 * Returns base64(nonce + ciphertext) or null on failure.
 */
const encryptForStorage = async (plaintext) => {
  try {
    const key = await getRatchetStorageKey();
    if (!key) return null;
    const nonce = nacl.randomBytes(nacl.secretbox.nonceLength);
    const msgBytes = decodeUTF8(plaintext);
    const encrypted = nacl.secretbox(msgBytes, nonce, key);
    if (!encrypted) return null;
    const combined = new Uint8Array(nonce.length + encrypted.length);
    combined.set(nonce);
    combined.set(encrypted, nonce.length);
    return encodeBase64(combined);
  } catch (e) {
    console.log('encryptForStorage error:', e?.message || String(e));
    return null;
  }
};

/**
 * Decrypt a base64(nonce + ciphertext) string using the ratchet storage key.
 * Returns the plaintext string or null on failure.
 */
const decryptFromStorage = async (encoded) => {
  try {
    const key = await getRatchetStorageKey();
    if (!key) return null;
    const combined = decodeBase64(encoded);
    if (!combined || combined.length < nacl.secretbox.nonceLength + 1) return null;
    const nonce = combined.slice(0, nacl.secretbox.nonceLength);
    const ciphertext = combined.slice(nacl.secretbox.nonceLength);
    const decrypted = nacl.secretbox.open(ciphertext, nonce, key);
    if (!decrypted) return null;
    return encodeUTF8(decrypted);
  } catch (e) {
    console.log('decryptFromStorage error:', e?.message || String(e));
    return null;
  }
};

/**
 * Load a ratchet session from encrypted local storage.
 */
export const loadRatchetSession = async (conversationId) => {
  try {
    const { getLocal } = require('./storage');
    // Round 40 — refuse a session an earlier drop could not remove. Checked
    // here rather than at each adopt site so a new caller cannot miss it.
    try {
      if (await getLocal(RATCHET_INVALID_PREFIX + conversationId)) {
        // Opportunistically retry the delete now that we are running again.
        if (await deleteRatchetSession(conversationId)) {
          const { removeLocal } = require('./storage');
          await removeLocal(RATCHET_INVALID_PREFIX + conversationId);
        }
        return null;
      }
    } catch (_) { /* marker unreadable — fall through to the normal load */ }
    const key = RATCHET_SESSION_PREFIX + conversationId;
    const data = await getLocal(key);
    if (!data) return null;
    const raw = typeof data === 'string' ? data : JSON.stringify(data);
    // Try decrypting (new format: base64 encrypted blob)
    const decrypted = await decryptFromStorage(raw);
    if (decrypted) return deserializeSession(decrypted);
    // Fallback: unencrypted legacy session — load and re-encrypt on next save
    return deserializeSession(raw);
  } catch (err) {
    console.log('loadRatchetSession error:', err);
    return null;
  }
};

/**
 * Save a ratchet session to encrypted local storage.
 */
export const saveRatchetSession = async (conversationId, session) => {
  try {
    const { saveLocal } = require('./storage');
    const key = RATCHET_SESSION_PREFIX + conversationId;
    const serialized = serializeSession(session);
    if (!serialized) return false;
    // Encrypt before writing to AsyncStorage
    const encrypted = await encryptForStorage(serialized);
    if (encrypted) {
      const ok = await saveLocal(key, encrypted);
      // A freshly saved session supersedes any earlier invalidation — otherwise
      // the marker would keep suppressing the very session that replaced the
      // one we could not delete.
      if (ok) {
        try {
          const { removeLocal } = require('./storage');
          await removeLocal(RATCHET_INVALID_PREFIX + conversationId);
        } catch (_) {}
      }
      return ok;
    }
    // NEVER fall back to plaintext — __DEV__ is true on dev-client/staging
    // builds, where a silent plaintext write defeats at-rest encryption.
    // Fail loudly instead so the broken storage key is detectable.
    console.warn('saveRatchetSession: encryption unavailable — refusing plaintext session write');
    try { require('./telemetry').captureMessage('ratchet_session_encrypt_unavailable', 'warning'); } catch (_) {}
    return false;
  } catch (err) {
    console.log('saveRatchetSession error:', err);
    return false;
  }
};

/**
 * Delete a ratchet session (for session reset).
 */
export const deleteRatchetSession = async (conversationId) => {
  try {
    const { removeLocal } = require('./storage');
    const key = RATCHET_SESSION_PREFIX + conversationId;
    return await removeLocal(key);
  } catch (err) {
    console.log('deleteRatchetSession error:', err);
    return false;
  }
};

// ---------------------------------------------------------------------------
// AUDIT 2026-08-08 (round 40) — a ratchet session DELETE that silently fails is
// as damaging as a save that silently fails, and there were seven such sites.
//
// deleteRatchetSession returns false and never throws (removeLocal does the
// same). Every caller in app/chat.js discarded it, and each of those deletes is
// a RECOVERY: the in-memory chain has advanced past what is on disk, or the
// peer rotated their identity key, or decryption threw, or the PQ migration
// needs the classical-only session gone. Dropping the stored session is what
// forces a clean re-establish instead of a rewind.
//
// When the delete silently fails the stale blob survives — and because the
// two-tier store reads MMKV first, it comes straight back on the next launch.
// The next send then re-uses a message-key index the peer has already consumed;
// their replay protection rejects it and their client settles the bubble to
// "Secured while you were away. Ask them to resend." while the sender sees a
// normal delivered tick. Silent one-way message loss, permanent until someone
// re-establishes by hand.
//
// A retry is not enough: the failure mode is a Keychain/storage outage that can
// outlast the process. So an unremovable session is marked INVALID durably, and
// loadRatchetSession refuses to hand back a session whose marker is set. That
// closes every adopt site at once rather than the one the audit happened to
// name.

/**
 * Delete a ratchet session and guarantee it can never be adopted again.
 * Returns true when the session is gone or provably neutralised.
 */
export const dropRatchetSession = async (conversationId) => {
  if (!conversationId) return false;
  if (await deleteRatchetSession(conversationId)) {
    // Deleted for real — no marker needed, and clear any stale one.
    try {
      const { removeLocal } = require('./storage');
      await removeLocal(RATCHET_INVALID_PREFIX + conversationId);
    } catch (_) {}
    return true;
  }
  // Could not remove it. Poison it instead so a resurrected copy is ignored.
  try {
    const { saveLocal } = require('./storage');
    const marked = await saveLocal(RATCHET_INVALID_PREFIX + conversationId, Date.now());
    if (marked) {
      console.log('[ratchet] session for', conversationId, 'could not be deleted — marked invalid');
      return true;
    }
  } catch (_) {}
  // Neither the delete nor the marker landed. The caller must treat the session
  // as still live on disk; there is nothing more this layer can do.
  console.log('[ratchet] session for', conversationId, 'could NOT be deleted or marked — stale blob may be adopted');
  return false;
};

// ============================================
// PQ KEY MANAGEMENT (SecureStore)
// ============================================

/**
 * Generate and store PQ keys (or derive from phrase if provided).
 */
// The active identity's recovery phrase, when the Keychain holds one. Same
// lookup getOrCreateKeyPair uses to re-derive the classical identity.
const _loadActiveIdentityPhrase = async () => {
  try {
    const { getIdentityPhrase, getLocal, KEYS } = require('./storage');
    const ids = [];
    try { const active = await getLocal(KEYS.ACTIVE_IDENTITY); if (active) ids.push(active); } catch (_) {}
    if (!ids.includes('main')) ids.push('main');
    for (const id of ids) {
      const p = await getIdentityPhrase(id);
      if (typeof p === 'string' && p.trim()) return p;
    }
  } catch (_) {}
  return null;
};

export const getOrCreatePqKeyPair = async (_phrase) => {
  // Public key (~1.2KB base64) fits in plain SecureStore.
  // Private key (~3.2KB base64) exceeds the 2KB SecureStore limit —
  // route through the wrapping helpers (AES-wrapped, ciphertext in
  // AsyncStorage, 32-byte wrap key in SecureStore).
  // AUDIT 2026-08-08 (round 50) — STRICT reads. A read failure is not proof of
  // absence, and this function MINTS on absence.
  //
  // Both getters returned null for "the item is not there" AND for "the
  // Keychain refused" / "the wrapping key is unavailable". So on a device that
  // is awake but still locked — post-reboot before first unlock, a PushKit
  // wake, a background fetch — this read as "no PQ identity", generated a
  // fresh ML-KEM pair, and PERSISTED it over the live one. The old private key
  // is then gone, and every peer that sealed to the published pqPublicKey has
  // produced ciphertext nobody can open.
  //
  // This is byte-for-byte the round-16 CRITICAL that was fixed for the
  // CLASSICAL identity key — see getOrCreateKeyPair's "key read FAILED (not
  // absent) — refusing to mint" branch, and readSecureValueStrict's header,
  // which states the rule outright. The PQ pair never got it.
  //
  // Fail CLOSED: an unreadable slot returns null and the caller degrades to
  // classical for this session, which is recoverable. Minting is not.
  const pubRead = await readSecureValueStrict(SECURE_KEYS.PQ_PUBLIC_KEY);
  const privRead = await readLargeSecureValueStrict(SECURE_KEYS.PQ_PRIVATE_KEY);
  if (!pubRead.ok || !privRead.ok) {
    console.log('[pq] key read FAILED (not absent) — refusing to mint over a live key');
    try {
      require('./telemetry').captureMessage('pq_identity_read_failed_refusing_mint', 'warning');
    } catch (_) {}
    return null;
  }
  const existingPub = pubRead.value;
  let existingPriv = privRead.value;

  // One-time migration: if private key is missing from the wrapped
  // path but present in legacy SecureStore (pre-wrap install), move
  // it over and clear the legacy entry.
  if (existingPub && !existingPriv) {
    try {
      const legacyPriv = await safeSecureStoreGet(SECURE_KEYS.PQ_PRIVATE_KEY);
      if (legacyPriv) {
        // AUDIT 2026-08-08 (round 40) — DELETE ONLY AFTER THE RE-WRAP LANDS.
        // setLarge returns false rather than throwing, and the legacy entry was
        // deleted unconditionally on the next line. A refused re-wrap therefore
        // DESTROYED the only copy of the ML-KEM private key: every message a
        // peer sealed to our published pqPublicKey becomes permanently
        // undecryptable, and nothing regenerates because existingPub is still
        // present.
        if (await safeSecureStoreSetLarge(SECURE_KEYS.PQ_PRIVATE_KEY, legacyPriv)) {
          try {
            const sanitized = sanitizeKeyForSecureStore(SECURE_KEYS.PQ_PRIVATE_KEY);
            await SecureStore.deleteItemAsync(sanitized, KEYCHAIN_OPTIONS);
          } catch (_) {}
          existingPriv = legacyPriv;
        } else {
          console.log('[pq] legacy private re-wrap failed — keeping the legacy entry');
          existingPriv = legacyPriv;
        }
      }
    } catch (_) {}
  }

  if (existingPub && existingPriv) return { publicKey: existingPub, privateKey: existingPriv };

  // AUDIT 2026-08-29 — DERIVE from the phrase when we have one.
  //
  // Only reached when the slot is genuinely empty (a strict read above proved
  // absence rather than failure), so this can never rotate a live identity: an
  // existing key is returned untouched two lines up. A caller with no phrase,
  // or a derivation that fails, falls back to random exactly as before, so the
  // worst case is today's behaviour.
  //
  // Signup already passes the phrase (config/database.js getOrCreatePqKeyPair(
  // recoveryPhrase)); the parameter was accepted and ignored.
  // 2026-09-15 (group messages vanish): the pair is minted here only when a
  // half is missing. With no phrase that used to mean a RANDOM pair, which the
  // record never learned about, so every peer kept wrapping group keys to the
  // old public key and nothing on this device could open them again. The
  // recovery phrase lives in the Keychain for the active identity, so derive
  // from it first: the derived pair is byte for byte the one signup published.
  // Random stays the last resort (no identity yet, or no phrase stored), and
  // ensurePqPublicKeyPublished republishes whatever ends up on the device.
  let coinsB64 = null;
  let phrase = (typeof _phrase === 'string' && _phrase.trim()) ? _phrase : null;
  let phraseSource = phrase ? 'caller' : null;
  if (!phrase) {
    phrase = await _loadActiveIdentityPhrase();
    if (phrase) phraseSource = 'stored';
  }
  if (phrase) {
    coinsB64 = await derivePqCoinsFromPhrase(phrase);
    if (!coinsB64) console.log('[pq] phrase derivation unavailable — falling back to random');
  } else {
    console.log('[pq] no recovery phrase on this device — minting a random ML-KEM identity; it will be republished');
  }
  const pqKeys = await pqGenerateKeyPair(coinsB64 || undefined);
  if (!pqKeys) return null;
  if (existingPub && pqKeys.publicKey !== existingPub) {
    console.log('[pq] ML-KEM identity replaced a half-present pair (' + (coinsB64 ? 'derived from the ' + phraseSource + ' phrase' : 'random') + ')');
    try { require('./telemetry').captureMessage('pq_identity_replaced_' + (coinsB64 ? 'derived' : 'random'), 'warning'); } catch (_) {}
  }

  // Round 40 — same mismatch hazard as the classical pair, and the PQ private
  // goes through setLarge (chunked), so a partial chunk write is a real
  // outcome. Roll back rather than leave a public whose private we cannot
  // reconstruct: ML-KEM decapsulation would fail for every peer that fetched
  // the published pqPublicKey.
  const pqPubSaved = await safeSecureStoreSet(SECURE_KEYS.PQ_PUBLIC_KEY, pqKeys.publicKey);
  const pqPrivSaved = pqPubSaved
    ? await safeSecureStoreSetLarge(SECURE_KEYS.PQ_PRIVATE_KEY, pqKeys.privateKey)
    : false;
  if (!pqPubSaved || !pqPrivSaved) {
    console.log('[pq] key pair persist failed (pub:', pqPubSaved, 'priv:', pqPrivSaved, ') — clearing both');
    try { await safeSecureStoreDelete(SECURE_KEYS.PQ_PUBLIC_KEY); } catch (_) {}
    try { await safeSecureStoreDelete(SECURE_KEYS.PQ_PRIVATE_KEY); } catch (_) {}
    return null;
  }

  return pqKeys;
};

// ============================================
// SAFETY NUMBERS (Key Verification)
// ============================================

/**
 * Compute a safety number for key verification between two users.
 * Both sides produce the same number. Users compare visually or via QR.
 *
 * @param {string} myPublicKeyB64 - Our identity public key
 * @param {string} theirPublicKeyB64 - Contact's identity public key
 * @param {string} myUserId - Our user ID
 * @param {string} theirUserId - Contact's user ID
 * @returns {string} - 60-digit safety number formatted as 12 groups of 5
 */
export const computeSafetyNumber = (myPublicKeyB64, theirPublicKeyB64, myUserId, theirUserId) => {
  if (!myPublicKeyB64 || !theirPublicKeyB64 || !myUserId || !theirUserId) return null;

  try {
    // Sort by userId so both sides get the same result
    const [first, second] = myUserId < theirUserId
      ? [myPublicKeyB64 + myUserId, theirPublicKeyB64 + theirUserId]
      : [theirPublicKeyB64 + theirUserId, myPublicKeyB64 + myUserId];

    // Hash the concatenation
    const hash1 = sha256(first + second + 'safety_number_v1');
    const hash2 = sha256(hash1 + 'safety_number_v1_extend');

    // Use both hashes (128 hex chars = 512 bits) to produce 60 digits
    const fullHex = hash1 + hash2;
    let number = '';
    for (let i = 0; i < 12; i++) {
      const chunk = parseInt(fullHex.substring(i * 5, i * 5 + 5), 16);
      number += String(chunk % 100000).padStart(5, '0');
      if (i < 11) number += ' ';
    }
    return number;
  } catch (err) {
    console.log('computeSafetyNumber error:', err);
    return null;
  }
};

/**
 * Check if a contact's public key has changed since we last saw it.
 * Returns { changed: boolean, isNew: boolean }
 */
export const checkKeyChange = async (contactId, currentPublicKeyB64) => {
  if (!contactId || !currentPublicKeyB64) return { changed: false, isNew: true };

  try {
    const { saveLocal, probeLocal } = require('./storage');
    const key = '@known_pubkey_' + contactId;
    // AUDIT 2026-08-03 (round 31) — A FAILED READ IS NOT "FIRST TIME".
    //
    // getLocal returns null both when the record is absent and when it exists
    // but cannot be decrypted (at-rest key not loaded on a cold wake, decrypt
    // failure). Treating that null as "first time seeing this contact" meant a
    // transient storage failure SUPPRESSED the key-change warning and then
    // PERSISTED whatever key was being presented — destroying the acknowledged
    // record it should have compared against. A real key substitution arriving
    // during that window was silently accepted and recorded as trusted, on the
    // one check that exists to catch exactly that.
    //
    // probeLocal distinguishes the two. When we cannot tell, report neither new
    // nor changed and write NOTHING: the caller shows no warning (we have no
    // evidence of one) but the stored record survives for the next attempt,
    // which is the only safe combination.
    const probe = await probeLocal(key);
    if (!probe.known) {
      console.log('checkKeyChange: key record unreadable — refusing to overwrite');
      return { changed: false, isNew: false, unknown: true };
    }
    const stored = probe.value;

    if (!stored) {
      // First time seeing this contact's key
      await saveLocal(key, currentPublicKeyB64);
      return { changed: false, isNew: true };
    }

    if (stored !== currentPublicKeyB64) {
      // Key changed! Don't auto-update — let user acknowledge
      return { changed: true, isNew: false, previousKey: stored };
    }

    return { changed: false, isNew: false };
  } catch (err) {
    // Round 31 — isNew:true here had the same effect as the null conflation
    // above: callers treat it as "nothing to warn about, record accepted".
    console.log('checkKeyChange error:', err);
    return { changed: false, isNew: false, unknown: true };
  }
};

/**
 * Acknowledge a key change (after user confirms).
 */
export const acknowledgeKeyChange = async (contactId, newPublicKeyB64) => {
  try {
    const { getLocal, saveLocal } = require('./storage');
    // AUDIT 2026-08-03 (round 25). This is the ONLY place the peer's last-known
    // public key is overwritten, so it is the only place that can preserve it.
    // 1:1 media is sealed with box.before(theirPub, myPriv); losing their old
    // public key loses every historical photo, video, voice note and file in
    // the conversation, in both directions. Archive before the overwrite.
    // AUDIT 2026-08-08 (round 40) — do not overwrite what we failed to archive.
    // archivePeerPublicKey returns false rather than throwing, so the catch was
    // dead and the overwrite below ran regardless. The comment above says this
    // is the ONLY place the peer's previous public key can be preserved, and
    // 1:1 media is sealed with box.before(theirPub, myPriv) — losing it loses
    // every historical photo, video, voice note and file in the conversation,
    // in both directions, permanently.
    try {
      const prior = await getLocal('@known_pubkey_' + contactId);
      if (prior && prior !== newPublicKeyB64) {
        if (!(await archivePeerPublicKey(contactId, prior))) {
          console.log('[keychange] could not archive prior public key for', contactId, '— not overwriting');
          return false;
        }
      }
    } catch (e) {
      console.log('[keychange] archive step threw — not overwriting:', e?.message || e);
      return false;
    }
    if (!(await saveLocal('@known_pubkey_' + contactId, newPublicKeyB64))) {
      console.log('[keychange] new public key not persisted for', contactId);
      return false;
    }
    return true;
  } catch (err) {
    console.log('acknowledgeKeyChange error:', err);
    return false;
  }
};

// ============================================
// SEALED SENDER (Certificate-Based)
// ============================================

/**
 * Generate a short-lived sender certificate for sealed sender messages.
 * The certificate contains only the sender's public identity key and an
 * opaque account identifier (not username). It expires after 24 hours.
 * The server signs the certificate so the receiver can verify authenticity
 * without the server seeing who sent the message.
 *
 * @param {string} senderPublicKeyB64 - Sender's identity public key
 * @param {string} senderId - Opaque sender identifier (user ID)
 * @param {number} expiresInMs - Certificate validity (default 24h)
 * @returns {{ certificate: string, expiresAt: number }}
 */
/**
 * Derive an Ed25519 signing key pair from a Curve25519 private key.
 * Curve25519 and Ed25519 share the same underlying scalar field, so we can
 * deterministically derive an Ed25519 key from a Curve25519 secret. This
 * avoids storing a separate signing key while still giving us real signatures.
 */
const _deriveEd25519FromCurve = (curve25519PrivateKeyB64) => {
  const seed = decodeBase64(curve25519PrivateKeyB64).slice(0, 32);
  return nacl.sign.keyPair.fromSeed(seed);
};

export const generateSenderCertificate = (senderPublicKeyB64, senderId, expiresInMs = 86400000, senderPrivateKeyB64 = null) => {
  if (!senderPublicKeyB64 || !senderId) return null;
  try {
    const expiresAt = Date.now() + expiresInMs;
    let certPayload;
    let signatureB64;
    if (senderPrivateKeyB64) {
      // Ed25519 detached signature using the sender's identity key.
      // SECURITY: embed the Ed25519 verify key in the cert so the
      // receiver can call nacl.sign.detached.verify properly. Curve25519
      // and Ed25519 share scalar fields, so the verify key is
      // deterministically derived from the Curve25519 private key — the
      // sender can compute it locally and the receiver needs it embedded
      // because they only have the sender's Curve25519 public key.
      const signingKeyPair = _deriveEd25519FromCurve(senderPrivateKeyB64);
      certPayload = {
        pk: senderPublicKeyB64,
        id: senderId,
        exp: expiresAt,
        v: 2,
        edPk: encodeBase64(signingKeyPair.publicKey),
      };
      const certData = JSON.stringify(certPayload);
      const certBytes = decodeUTF8(certData);
      const sig = nacl.sign.detached(certBytes, signingKeyPair.secretKey);
      signatureB64 = encodeBase64(sig);
      const expiresAtFinal = certPayload.exp;
      return {
        certificate: encodeBase64(certBytes),
        signature: signatureB64,
        expiresAt: expiresAtFinal,
      };
    }
    // No private key — fall through to v1 legacy SHA-256 path. That's
    // the only sealed-sender path currently verifiable on the receiver
    // for cert objects without edPk.
    certPayload = { pk: senderPublicKeyB64, id: senderId, exp: expiresAt, v: 1 };
    const certData = JSON.stringify(certPayload);
    const certBytes = decodeUTF8(certData);
    signatureB64 = sha256(certData + 'sealed_sender_cert_v1');
    return {
      certificate: encodeBase64(certBytes),
      signature: signatureB64,
      expiresAt,
    };
  } catch (err) {
    console.log('generateSenderCertificate error:', err);
    return null;
  }
};

/**
 * Verify a sender certificate.
 * v2 certificates use Ed25519 detached signatures (64 bytes base64).
 * v1 certificates fall back to SHA-256 hash verification (legacy).
 * @param {string} certificateB64 - Base64-encoded certificate
 * @param {string} signatureB64 - Certificate signature (Ed25519 or SHA-256 hash)
 * @returns {{ valid: boolean, senderId: string, publicKey: string } | null}
 */
export const verifySenderCertificate = (certificateB64, signatureB64) => {
  if (!certificateB64 || !signatureB64) return null;
  try {
    const certBytes = decodeBase64(certificateB64);
    const certJson = encodeUTF8(certBytes);
    const certData = JSON.parse(certJson);
    // Check expiration
    if (certData.exp < Date.now()) return { valid: false, expired: true };

    if (certData.v >= 2 && certData.pk) {
      // v2: Ed25519 detached signature verification. The cert payload
      // carries the sender's Ed25519 verify key in `edPk`; the sender
      // derives it from their Curve25519 identity key via shared scalar
      // field (see _deriveEd25519FromCurve) and embeds it at issue time,
      // so no separate Ed25519 column on user docs is required.
      //
      // A cert without edPk is malformed for v2 and rejected — the
      // legacy SHA-256 path is v1-only and not a fallback here.
      if (!certData.edPk) return { valid: false, expired: false };
      try {
        const sigBytes = decodeBase64(signatureB64);
        const edPub = decodeBase64(certData.edPk);
        if (edPub.length !== 32 || sigBytes.length !== 64) {
          return { valid: false, expired: false };
        }
        const certBytesForVerify = decodeUTF8(certJson);
        const ok = nacl.sign.detached.verify(certBytesForVerify, sigBytes, edPub);
        if (!ok) return { valid: false, expired: false };
        return { valid: true, senderId: certData.id, publicKey: certData.pk, expiresAt: certData.exp };
      } catch (_) {
        return { valid: false, expired: false };
      }
    } else {
      // v1 legacy: SHA-256 hash verification. Constant-time string
      // compare to prevent a timing side-channel that could let an
      // attacker progressively guess the expected signature digest
      // through repeated submission of certificates with mutated sigs
      // (audit C-H3). v2 above uses nacl.sign.detached.verify which
      // is already constant-time.
      const expectedSig = sha256(certJson + 'sealed_sender_cert_v1');
      if (!constantTimeEqual(expectedSig, signatureB64)) return { valid: false, expired: false };
      return { valid: true, senderId: certData.id, publicKey: certData.pk, expiresAt: certData.exp };
    }
  } catch (err) {
    return null;
  }
};

/**
 * Create a sealed sender envelope. The message is encrypted so only the
 * recipient can read it. The sender's identity is inside the envelope,
 * invisible to the server.
 *
 * Envelope format: sealed:<recipientId>:<nonce_b64>:<ciphertext_b64>
 * Inside ciphertext: { cert, sig, msg } where msg is the actual encrypted message
 *
 * @param {string} encryptedMessage - Already E2E-encrypted message text
 * @param {object} senderCert - { certificate, signature } from generateSenderCertificate
 * @param {string} recipientPublicKeyB64 - Recipient's identity public key
 * @param {string} senderPrivateKeyB64 - Sender's private key for NaCl box
 * @returns {string|null} - Sealed envelope or null
 */
export const sealMessage = (encryptedMessage, senderCert, recipientPublicKeyB64, senderPrivateKeyB64) => {
  if (!encryptedMessage || !senderCert || !recipientPublicKeyB64 || !senderPrivateKeyB64) return null;
  try {
    const payload = JSON.stringify({
      cert: senderCert.certificate,
      sig: senderCert.signature,
      msg: encryptedMessage,
    });
    const payloadBytes = decodeUTF8(payload);
    const nonce = nacl.randomBytes(nacl.box.nonceLength);
    const recipientPub = decodeBase64(recipientPublicKeyB64);
    const senderPriv = decodeBase64(senderPrivateKeyB64);
    const sealed = nacl.box(payloadBytes, nonce, recipientPub, senderPriv);
    if (!sealed) return null;
    return 'sealed:' + encodeBase64(nonce) + ':' + encodeBase64(sealed);
  } catch (err) {
    console.log('sealMessage error:', err);
    return null;
  }
};

/**
 * Unseal a sealed sender envelope.
 * @param {string} envelope - "sealed:<nonce_b64>:<ciphertext_b64>"
 * @param {string} senderPublicKeyB64 - Sender's public key (from cert inside)
 * @param {string} recipientPrivateKeyB64 - Recipient's private key
 * @returns {{ message: string, senderId: string, senderPublicKey: string } | null}
 */
export const unsealMessage = (envelope, senderPublicKeyB64, recipientPrivateKeyB64) => {
  if (!envelope?.startsWith('sealed:') || !recipientPrivateKeyB64) return null;
  try {
    const parts = envelope.split(':');
    if (parts.length < 3) return null;
    const nonce = decodeBase64(parts[1]);
    const ciphertext = decodeBase64(parts[2]);
    const senderPub = decodeBase64(senderPublicKeyB64);
    const recipientPriv = decodeBase64(recipientPrivateKeyB64);
    const decrypted = nacl.box.open(ciphertext, nonce, senderPub, recipientPriv);
    if (!decrypted) return null;
    const payload = JSON.parse(encodeUTF8(decrypted));
    const certResult = verifySenderCertificate(payload.cert, payload.sig);
    if (!certResult?.valid) return null;
    return {
      message: payload.msg,
      senderId: certResult.senderId,
      senderPublicKey: certResult.publicKey,
    };
  } catch (err) {
    console.log('unsealMessage error:', err);
    return null;
  }
};

// ============================================
// BURN-ON-READ DUAL TIMER SYSTEM
// ============================================

/**
 * Compute message expiration using dual timer system.
 * - Expiration Timer: max lifetime from send time (always counts down)
 * - Burn-on-Read Timer: starts counting when the message is opened
 * The message is destroyed at whichever timer fires first.
 *
 * @param {number} expirationSeconds - Max lifetime from send (0 = no limit)
 * @param {number} burnOnReadSeconds - Destroy N seconds after read (0 = no BOR)
 * @param {number} sendTimestamp - When the message was sent (ms)
 * @param {number|null} readTimestamp - When the message was first read (ms), or null
 * @returns {{ shouldDestroy: boolean, destroyAt: number|null, reason: string }}
 */
export const computeDestructionTime = (expirationSeconds, burnOnReadSeconds, sendTimestamp, readTimestamp) => {
  const now = Date.now();
  let expirationDeadline = null;
  let borDeadline = null;

  if (expirationSeconds > 0) {
    expirationDeadline = sendTimestamp + (expirationSeconds * 1000);
  }

  if (burnOnReadSeconds > 0 && readTimestamp) {
    borDeadline = readTimestamp + (burnOnReadSeconds * 1000);
  }

  // Pick whichever fires first
  let destroyAt = null;
  let reason = '';

  if (expirationDeadline && borDeadline) {
    destroyAt = Math.min(expirationDeadline, borDeadline);
    reason = destroyAt === borDeadline ? 'burn-on-read' : 'expiration';
  } else if (expirationDeadline) {
    destroyAt = expirationDeadline;
    reason = 'expiration';
  } else if (borDeadline) {
    destroyAt = borDeadline;
    reason = 'burn-on-read';
  }

  return {
    shouldDestroy: destroyAt !== null && now >= destroyAt,
    destroyAt,
    reason,
    remainingMs: destroyAt ? Math.max(0, destroyAt - now) : null,
  };
};

// ============================================
// SECURE SHREDDER (Forensic-Resistant Deletion)
// ============================================

/**
 * Overwrite a region of AsyncStorage with random data before deleting.
 * Standard deletion only removes the reference; the data remains on disk.
 * This writes random bytes over the key multiple times before removal.
 *
 * @param {string} key - AsyncStorage key to shred
 * @param {number} passes - Number of overwrite passes (default 3)
 */
export const secureShred = async (key, passes = 3) => {
  try {
    const existing = await AsyncStorage.getItem(key);
    if (existing === null) return;

    // Overwrite with random data of same length for each pass
    const len = existing.length;
    for (let pass = 0; pass < passes; pass++) {
      const randomData = bytesToHex(nacl.randomBytes(Math.ceil(len / 2))).slice(0, len);
      await AsyncStorage.setItem(key, randomData);
    }
    // Final pass: overwrite with zeros
    await AsyncStorage.setItem(key, '0'.repeat(len));
    // Now remove the key
    await AsyncStorage.removeItem(key);
  } catch (err) {
    // Fallback to normal deletion
    try { await AsyncStorage.removeItem(key); } catch (_) {}
  }
};

/**
 * Batch shred multiple AsyncStorage keys.
 * @param {string[]} keys - Array of keys to securely delete
 */
export const secureShredBatch = async (keys) => {
  await Promise.all(keys.map(k => secureShred(k)));
};

/**
 * Shred a ratchet session (contains sensitive key material).
 * @param {string} conversationId
 */
export const secureShredSession = async (conversationId) => {
  const key = '@ratchet_session_' + conversationId;
  await secureShred(key, 5); // Extra passes for key material
};

// ============================================
// ENCRYPTED CLOUD BACKUP
// ============================================

/**
 * Derive a backup encryption key from a user-provided passphrase.
 * Uses PBKDF2-HMAC-SHA256 at OWASP-2023 minimum (600K iterations) via
 * the native quick-crypto bridge with a JS fallback. The salt is the
 * caller-provided string (typically userId) wrapped with a domain-
 * separation tag so backup keys can never collide with PIN or ratchet
 * derivations sharing the same salt.
 *
 * Async. The legacy v1 derivation (10K iterated raw SHA-256) is no
 * longer exposed publicly; v1 envelopes are still decryptable via
 * decryptBackup's internal legacy path so users with a pre-fix backup
 * can still restore.
 *
 * @param {string} passphrase - User's backup passphrase
 * @param {string} salt - Unique salt (e.g., userId)
 * @returns {Promise<Uint8Array|null>} - 32-byte backup encryption key
 */
export const deriveBackupKey = async (passphrase, salt) => {
  if (!passphrase || !salt) return null;
  try {
    // Domain-separated PBKDF2 salt: hex(sha256(salt || 'theshft_backup_v2'))
    const saltHex = sha256(String(salt) + 'theshft_backup_v2');
    const derivedHex = await pbkdf2HmacSha256(passphrase, saltHex, BACKUP_KDF_ITERATIONS_V2);
    if (!derivedHex || derivedHex.length < 64) return null;
    return hexToBytes32(derivedHex);
  } catch (err) {
    console.log('deriveBackupKey error:', err?.message || err);
    return null;
  }
};

// Legacy v1 derivation — kept ONLY so existing v1 backups can still be
// restored. Never expose publicly; never used for fresh encryption. The
// 10K SHA-256 chain over base64-string concat is GPU-brute-forceable
// in seconds on commodity hardware (audit C-H2 — that's why we
// migrated to PBKDF2 600K).
const _deriveBackupKeyV1Legacy = (passphrase, salt) => {
  if (!passphrase || !salt) return null;
  try {
    let derived = sha256(passphrase + salt + 'theshft_backup_v1');
    for (let i = 0; i < 10000; i++) {
      derived = sha256(derived + String(i));
    }
    return hexToBytes32(derived);
  } catch (err) {
    console.log('_deriveBackupKeyV1Legacy error:', err?.message || err);
    return null;
  }
};

/**
 * Encrypt backup data with a derived backup key using NaCl secretbox.
 * Always produces the v2 envelope; v1 envelopes are read-only legacy.
 *
 * @param {string} data - JSON string of backup data
 * @param {Uint8Array} backupKey - 32-byte key from deriveBackupKey
 * @returns {string|null} - "backup_v2:<nonce_b64>:<ciphertext_b64>"
 */
export const encryptBackup = (data, backupKey) => {
  if (!data || !backupKey) return null;
  try {
    const nonce = nacl.randomBytes(nacl.secretbox.nonceLength);
    const plaintext = decodeUTF8(data);
    const ciphertext = nacl.secretbox(plaintext, nonce, backupKey);
    if (!ciphertext) return null;
    return 'backup_v2:' + encodeBase64(nonce) + ':' + encodeBase64(ciphertext);
  } catch (err) {
    console.log('encryptBackup error:', err);
    return null;
  }
};

/**
 * Decrypt a backup envelope. Accepts both v2 (current) and v1 (legacy
 * pre-fix-C-H2). For v2, callers pass the key derived from the current
 * deriveBackupKey. For v1, callers MUST also pass the original
 * passphrase + salt so the legacy 10K SHA-256 chain can be reconstructed.
 *
 * @param {string} encrypted - "backup_v2:..." or "backup_v1:..."
 * @param {Uint8Array} backupKey - 32-byte key for v2 envelopes
 * @param {{ passphrase?: string, salt?: string }} [legacyOpts] - Required
 *   only when decrypting a v1 envelope; ignored for v2.
 * @returns {Promise<string|null>} - Decrypted JSON string or null
 */
export const decryptBackup = async (encrypted, backupKey, legacyOpts) => {
  if (!encrypted || typeof encrypted !== 'string') return null;
  try {
    if (encrypted.startsWith('backup_v2:')) {
      if (!backupKey) return null;
      const parts = encrypted.split(':');
      if (parts.length < 3) return null;
      const nonce = decodeBase64(parts[1]);
      const ciphertext = decodeBase64(parts[2]);
      const decrypted = nacl.secretbox.open(ciphertext, nonce, backupKey);
      if (!decrypted) return null;
      return encodeUTF8(decrypted);
    }
    if (encrypted.startsWith('backup_v1:')) {
      // Legacy path — re-derive with the deprecated 10K SHA-256 chain
      // so users with a pre-fix backup can restore. Will not be reached
      // for backups created after the C-H2 fix landed.
      if (!legacyOpts?.passphrase || !legacyOpts?.salt) {
        console.warn('[decryptBackup] v1 envelope requires legacyOpts.passphrase + salt');
        return null;
      }
      const legacyKey = _deriveBackupKeyV1Legacy(legacyOpts.passphrase, legacyOpts.salt);
      if (!legacyKey) return null;
      const parts = encrypted.split(':');
      if (parts.length < 3) return null;
      const nonce = decodeBase64(parts[1]);
      const ciphertext = decodeBase64(parts[2]);
      const decrypted = nacl.secretbox.open(ciphertext, nonce, legacyKey);
      if (!decrypted) return null;
      return encodeUTF8(decrypted);
    }
    return null;
  } catch (err) {
    console.log('decryptBackup error:', err?.message || err);
    return null;
  }
};

// ============================================
// CROSS-DEVICE KEY MANAGEMENT
// ============================================

/**
 * Generate a master signing key, self-signing key, and user-signing key
 * for cross-device verification. The master key signs device keys.
 *
 * - Master key: root of trust, stored securely, rarely used
 * - Self-signing key: signs this device's identity key (signed by master)
 * - User-signing key: signs other users' master keys after verification
 *
 * @returns {{ masterKeyPair, selfSigningKeyPair, userSigningKeyPair }}
 */
export const generateCrossSigningKeys = () => {
  try {
    const masterSeed = nacl.randomBytes(32);
    const masterKeyPair = nacl.sign.keyPair.fromSeed(masterSeed);

    const selfSigningSeed = nacl.randomBytes(32);
    const selfSigningKeyPair = nacl.sign.keyPair.fromSeed(selfSigningSeed);

    const userSigningSeed = nacl.randomBytes(32);
    const userSigningKeyPair = nacl.sign.keyPair.fromSeed(userSigningSeed);

    // Master signs the self-signing and user-signing public keys
    const selfSigningCert = nacl.sign(selfSigningKeyPair.publicKey, masterKeyPair.secretKey);
    const userSigningCert = nacl.sign(userSigningKeyPair.publicKey, masterKeyPair.secretKey);

    return {
      masterPublicKey: encodeBase64(masterKeyPair.publicKey),
      masterPrivateKey: encodeBase64(masterSeed), // Store seed, not full secret key
      selfSigningPublicKey: encodeBase64(selfSigningKeyPair.publicKey),
      selfSigningPrivateKey: encodeBase64(selfSigningSeed),
      selfSigningCert: encodeBase64(selfSigningCert),
      userSigningPublicKey: encodeBase64(userSigningKeyPair.publicKey),
      userSigningPrivateKey: encodeBase64(userSigningSeed),
      userSigningCert: encodeBase64(userSigningCert),
    };
  } catch (err) {
    console.log('generateCrossSigningKeys error:', err);
    return null;
  }
};

/**
 * Sign a device's identity key with the self-signing key.
 * @param {string} devicePublicKeyB64 - Device identity public key
 * @param {string} selfSigningSeedB64 - Self-signing private seed
 * @returns {string|null} - Signature (base64)
 */
export const signDeviceKey = (devicePublicKeyB64, selfSigningSeedB64) => {
  if (!devicePublicKeyB64 || !selfSigningSeedB64) return null;
  try {
    const selfSigningKeyPair = nacl.sign.keyPair.fromSeed(decodeBase64(selfSigningSeedB64));
    const devicePub = decodeBase64(devicePublicKeyB64);
    const signature = nacl.sign.detached(devicePub, selfSigningKeyPair.secretKey);
    return encodeBase64(signature);
  } catch (err) {
    console.log('signDeviceKey error:', err);
    return null;
  }
};

/**
 * Verify a device key signature against the self-signing public key.
 * @param {string} devicePublicKeyB64 - Device identity public key
 * @param {string} signatureB64 - Signature from signDeviceKey
 * @param {string} selfSigningPublicKeyB64 - Self-signing public key
 * @returns {boolean}
 */
export const verifyDeviceSignature = (devicePublicKeyB64, signatureB64, selfSigningPublicKeyB64) => {
  if (!devicePublicKeyB64 || !signatureB64 || !selfSigningPublicKeyB64) return false;
  try {
    const devicePub = decodeBase64(devicePublicKeyB64);
    const signature = decodeBase64(signatureB64);
    const selfSigningPub = decodeBase64(selfSigningPublicKeyB64);
    return nacl.sign.detached.verify(devicePub, signature, selfSigningPub);
  } catch (err) {
    return false;
  }
};

/**
 * Verify that a self-signing key was signed by the master key.
 * @param {string} selfSigningCertB64 - Certificate (signed public key)
 * @param {string} masterPublicKeyB64 - Master public key
 * @returns {string|null} - The self-signing public key if valid, null if invalid
 */
export const verifyCrossSigningChain = (selfSigningCertB64, masterPublicKeyB64) => {
  if (!selfSigningCertB64 || !masterPublicKeyB64) return null;
  try {
    const cert = decodeBase64(selfSigningCertB64);
    const masterPub = decodeBase64(masterPublicKeyB64);
    const opened = nacl.sign.open(cert, masterPub);
    if (!opened) return null;
    return encodeBase64(opened);
  } catch (err) {
    return null;
  }
};

/**
 * Sign another user's master key with our user-signing key (after verification).
 * This creates a trust relationship: "I have verified this user in person."
 * @param {string} theirMasterPublicKeyB64 - The verified user's master key
 * @param {string} userSigningSeedB64 - Our user-signing private seed
 * @returns {string|null} - Signature (base64)
 */
export const signUserMasterKey = (theirMasterPublicKeyB64, userSigningSeedB64) => {
  if (!theirMasterPublicKeyB64 || !userSigningSeedB64) return null;
  try {
    const userSigningKeyPair = nacl.sign.keyPair.fromSeed(decodeBase64(userSigningSeedB64));
    const theirMasterPub = decodeBase64(theirMasterPublicKeyB64);
    const signature = nacl.sign.detached(theirMasterPub, userSigningKeyPair.secretKey);
    return encodeBase64(signature);
  } catch (err) {
    console.log('signUserMasterKey error:', err);
    return null;
  }
};

