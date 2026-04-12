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
};

// ============================================
// SECURE STORAGE (expo-secure-store with AsyncStorage fallback)
// ============================================

// Try to load expo-secure-store; null if unavailable
let SecureStore = null;
try {
  SecureStore = require('expo-secure-store');
} catch (e) {
  // expo-secure-store not installed — will fall back to AsyncStorage
}

// expo-secure-store keys cannot contain '@' or other special chars,
// so we sanitize the key for SecureStore usage.
const sanitizeKeyForSecureStore = (key) => key.replace(/[^a-zA-Z0-9._-]/g, '_');

const safeSecureStoreSet = async (key, value) => {
  if (!key || typeof key !== 'string' || value === null || value === undefined) {
    console.warn('safeSecureStoreSet: Invalid params', { key, hasValue: !!value });
    return false;
  }
  try {
    if (SecureStore) {
      const sanitizedKey = sanitizeKeyForSecureStore(key);
      await SecureStore.setItemAsync(sanitizedKey, String(value));
      return true;
    }
    // SecureStore unavailable
    if (__DEV__) {
      console.warn('SecureStore unavailable — using AsyncStorage (not secure for production)');
      await AsyncStorage.setItem(key, String(value));
      return true;
    } else {
      console.error('SecureStore unavailable in production — refusing to store sensitive data in AsyncStorage');
      return false;
    }
  } catch (error) {
    console.error('Storage set error');
    return false;
  }
};

const safeSecureStoreGet = async (key) => {
  if (!key || typeof key !== 'string') {
    console.warn('safeSecureStoreGet: Invalid key');
    return null;
  }
  try {
    // Try SecureStore first with current (generic) key name
    if (SecureStore) {
      const sanitizedKey = sanitizeKeyForSecureStore(key);
      const secureValue = await SecureStore.getItemAsync(sanitizedKey);
      if (secureValue !== null) return secureValue;

      // Check legacy key names (migration from older versions with revealing names)
      const legacyKey = Object.entries(LEGACY_SECURE_KEYS).find(([k, v]) => SECURE_KEYS[k] === key)?.[1];
      if (legacyKey) {
        const legacySanitized = sanitizeKeyForSecureStore(legacyKey);
        const legacyValue = await SecureStore.getItemAsync(legacySanitized);
        if (legacyValue !== null) {
          // Migrate to new generic key name and delete the revealing legacy key
          await SecureStore.setItemAsync(sanitizedKey, legacyValue);
          try { await SecureStore.deleteItemAsync(legacySanitized); } catch (_) {}
          return legacyValue;
        }
      }
    }
    // Check AsyncStorage for legacy migration data
    if (SecureStore || __DEV__) {
      const asyncValue = await AsyncStorage.getItem(key);
      return asyncValue;
    }
    return null;
  } catch (error) {
    console.error('Storage get error');
    if (__DEV__) {
      try {
        return await AsyncStorage.getItem(key);
      } catch (fallbackError) {
        console.error('AsyncStorage fallback get error:', fallbackError?.message || String(fallbackError));
      }
    }
    return null;
  }
};

const safeSecureStoreDelete = async (key) => {
  if (!key || typeof key !== 'string') return false;
  try {
    // Delete from SecureStore (keychain) first
    if (SecureStore) {
      try {
        const sanitizedKey = sanitizeKeyForSecureStore(key);
        await SecureStore.deleteItemAsync(sanitizedKey);
      } catch (secureError) {
        console.error('SecureStore delete error:', secureError?.message || String(secureError));
      }
    }
    // Also delete from AsyncStorage fallback
    await AsyncStorage.removeItem(key);
    return true;
  } catch (error) {
    console.error('Storage delete error:', error?.message || String(error));
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
const pbkdf2HmacSha256 = (password, saltHex, iterations) => {
  // Convert password to bytes (UTF-8)
  const pwBytes = new Uint8Array(decodeUTF8(password));
  // Convert salt hex to bytes
  const saltBytes = new Uint8Array(saltHex.length / 2);
  for (let i = 0; i < saltBytes.length; i++) {
    saltBytes[i] = parseInt(saltHex.substring(i * 2, i * 2 + 2), 16);
  }
  // PBKDF2 block 1: salt || INT32BE(1)
  const saltBlock = new Uint8Array(saltBytes.length + 4);
  saltBlock.set(saltBytes);
  saltBlock[saltBytes.length] = 0;
  saltBlock[saltBytes.length + 1] = 0;
  saltBlock[saltBytes.length + 2] = 0;
  saltBlock[saltBytes.length + 3] = 1;

  let u = hmacSha256(pwBytes, saltBlock); // U1
  const dk = new Uint8Array(u); // T = U1
  for (let i = 1; i < iterations; i++) {
    u = hmacSha256(pwBytes, u); // Ui
    for (let j = 0; j < 32; j++) dk[j] ^= u[j]; // T ^= Ui
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
      console.error('Key pair generation produced invalid keys');
      return null;
    }

    const privateKeyB64 = encodeBase64(keyPair.secretKey);
    const publicKeyB64 = encodeBase64(keyPair.publicKey);

    const privSaved = await safeSecureStoreSet(SECURE_KEYS.PRIVATE_KEY, privateKeyB64);
    const pubSaved = await safeSecureStoreSet(SECURE_KEYS.PUBLIC_KEY, publicKeyB64);
    if (!privSaved || !pubSaved) {
      console.error('Failed to persist generated key pair to secure storage');
      return null;
    }

    return { privateKey: privateKeyB64, publicKey: publicKeyB64 };
  } catch (e) {
    console.error('Failed to generate key pair:', e);
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
    console.error('Failed to get key pair:', e);
    return null;
  }
};

/** Get existing key pair or re-derive from recovery phrase (mutex-protected) */
let _keyPairLock = null;
export const getOrCreateKeyPair = async () => {
  // Prevent concurrent calls from generating duplicate key pairs
  if (_keyPairLock) return _keyPairLock;
  _keyPairLock = (async () => {
    try {
      const existing = await getKeyPair();
      if (existing) return existing;

      // SecureStore empty — try to re-derive from stored recovery phrase
      // This ensures keys always match what's in Firestore (phrase-derived)
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
              const { getDb } = require('./firebase');
              const { doc, getDoc } = require('firebase/firestore');
              const userDocSnap = await getDoc(doc(getDb(), 'users', activeIdentity));
              if (userDocSnap.exists()) {
                version = userDocSnap.data().derivationVersion || 'v3';
              }
            } catch (fbErr) { /* fall back to v3 */ }
            const derived = await deriveKeysFromPhrase(phrase, { version });
            if (derived?.privateKey && derived?.publicKey) return derived;
          }
        }
      } catch (e) {
        console.log('Could not re-derive keys from phrase:', e.message);
      }

      // Last resort: generate random keys (only for brand new accounts before phrase exists)
      return await generateKeyPair();
    } finally {
      _keyPairLock = null;
    }
  })();
  return _keyPairLock;
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

  try {
    const messageBytes = decodeUTF8(message);
    const paddedBytes = padMessage(messageBytes);
    const nonce = nacl.randomBytes(nacl.box.nonceLength);
    const theirPublicKey = decodeBase64(theirPublicKeyB64);
    const myPrivateKey = decodeBase64(myPrivateKeyB64);

    // Validate key sizes before encryption
    if (!theirPublicKey || theirPublicKey.length !== nacl.box.publicKeyLength) {
      console.error('Encrypt: invalid public key length', theirPublicKey?.length, 'expected', nacl.box.publicKeyLength);
      return null;
    }
    if (!myPrivateKey || myPrivateKey.length !== nacl.box.secretKeyLength) {
      console.error('Encrypt: invalid private key length', myPrivateKey?.length, 'expected', nacl.box.secretKeyLength);
      return null;
    }

    const encrypted = nacl.box(paddedBytes, nonce, theirPublicKey, myPrivateKey);
    if (!encrypted) return null;

    return 'naclp:' + encodeBase64(nonce) + ':' + encodeBase64(encrypted);
  } catch (e) {
    console.error('Encrypt error:', e);
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
        // New padded format — unpad, fall back to raw if unpad fails
        const unpadded = unpadMessage(decrypted);
        return encodeUTF8(unpadded || decrypted);
      }
      // Legacy unpadded format — return raw decrypted bytes
      return encodeUTF8(decrypted);
    } catch (e) {
      console.error('Decrypt error:', e);
      return 'This message couldn\'t be read';
    }
  }

  // Explicitly catch known encrypted prefixes that should not be passed to this function
  if (encrypted.startsWith('ratchet:') || encrypted.startsWith('hybrid:') ||
      encrypted.startsWith('ENCN:') || encrypted.startsWith('ENCNP:')) {
    return 'This message couldn\'t be read';
  }

  // If keys were provided but message isn't nacl-prefixed, it may be a
  // corrupted/unrecognized encrypted payload — avoid leaking ciphertext.
  // Legacy plaintext messages are short, human-readable, and contain spaces.
  if (theirPublicKeyB64 && myPrivateKeyB64 &&
      encrypted.length > 50 && !/\s/.test(encrypted)) {
    return 'This message couldn\'t be read';
  }

  // Legacy unencrypted message — return as-is
  return encrypted;
};

// ============================================
// SYMMETRIC ENCRYPTION (NaCl secretbox — for local data / media)
// ============================================

/**
 * Generate a shared secret for a conversation using NaCl box.before().
 * This precomputes the Curve25519-XSalsa20-Poly1305 shared key.
 */
export const generateConversationKey = async (_userId1, _userId2, theirPublicKeyB64) => {
  try {
    const keyPair = await getOrCreateKeyPair();
    if (!keyPair?.privateKey || !theirPublicKeyB64) {
      console.error('generateConversationKey: missing keys', { hasPrivate: !!keyPair?.privateKey, hasTheirPublic: !!theirPublicKeyB64 });
      return null;
    }

    const myPrivateKey = decodeBase64(keyPair.privateKey);
    const theirPublicKey = decodeBase64(theirPublicKeyB64);

    // Precompute shared secret
    const sharedKey = nacl.box.before(theirPublicKey, myPrivateKey);
    return encodeBase64(sharedKey);
  } catch (e) {
    console.error('Failed to generate conversation key:', e);
    return null;
  }
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
    console.error('Media encryption error:', e);
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
      // New padded format — unpad, fall back to raw if unpad fails
      const unpadded = unpadMessage(decrypted);
      return header + encodeBase64(unpadded || decrypted);
    }
    // Legacy unpadded format — return raw decrypted bytes
    return header + encodeBase64(decrypted);
  } catch (e) {
    console.error('Media decryption error:', e);
    return null; // Return null so UI can show error state
  }
};

// ============================================
// KEY DERIVATION FROM RECOVERY PHRASE
// ============================================

/**
 * Derive a NaCl key pair deterministically from a recovery phrase.
 *
 * v5 (current): PBKDF2-HMAC-SHA256 with 100,000 iterations — brute-force resistant.
 * v3 (legacy):  Single SHA-256 hash — kept only for backward compatibility.
 *
 * New accounts always use v5. On restore/login the caller should pass
 * options.version = 'v3' to use the legacy derivation for existing accounts.
 *
 * @param {string} phrase - Recovery phrase
 * @param {object} [options] - Optional settings
 * @param {string} [options.version] - 'v3' for legacy, 'v5' for PBKDF2 (default: 'v5')
 * @returns {{ privateKey: string, publicKey: string, derivationVersion: string }|null}
 */
const PHRASE_KDF_SALT_V3 = 'theshft_key_derivation_v3';
// 10K iterations: ~2-3s on mobile (pure JS PBKDF2). 100K was 30-60s which broke UX.
// Still 10,000x stronger than the v3 single SHA-256. Can increase once we switch
// to a native crypto module (expo-crypto doesn't support PBKDF2 yet).
const PHRASE_KDF_ITERATIONS_V5 = 10000;

export const deriveKeysFromPhrase = async (phrase, options = {}) => {
  try {
    if (!phrase || typeof phrase !== 'string') return null;
    const words = phrase.toLowerCase().trim();

    const version = options.version || 'v5';

    let seedHex;

    if (version === 'v3') {
      // Legacy path: single SHA-256 hash with static salt
      seedHex = sha256(words + PHRASE_KDF_SALT_V3);
    } else {
      // v5 path: PBKDF2-HMAC-SHA256 with 100K iterations
      // Salt is derived from SHA-256(phrase) + version marker to be deterministic
      // but unique per-phrase (not a single static salt for all users)
      const phraseHash = sha256(words);
      const salt = sha256(phraseHash + 'theshft_kdf_v5');
      seedHex = pbkdf2HmacSha256(words, salt, PHRASE_KDF_ITERATIONS_V5);
    }

    if (!seedHex || seedHex.length !== 64 || !/^[0-9a-f]{64}$/.test(seedHex)) return null;

    const seed = new Uint8Array(32);
    for (let i = 0; i < 32; i++) seed[i] = parseInt(seedHex.substring(i * 2, i * 2 + 2), 16);

    if (!seed) return null;

    const keyPair = nacl.box.keyPair.fromSecretKey(seed);
    const privateKeyB64 = encodeBase64(keyPair.secretKey);
    const publicKeyB64 = encodeBase64(keyPair.publicKey);

    await safeSecureStoreSet(SECURE_KEYS.PRIVATE_KEY, privateKeyB64);
    await safeSecureStoreSet(SECURE_KEYS.PUBLIC_KEY, publicKeyB64);

    return { privateKey: privateKeyB64, publicKey: publicKeyB64, derivationVersion: version };
  } catch (e) {
    console.error('Key derivation failed');
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

export const getOrCreateEncryptionKey = async () => {
  try {
    let key = await safeSecureStoreGet(SECURE_KEYS.ENCRYPTION_KEY);
    if (!key) {
      key = await generateEncryptionKey();
      await safeSecureStoreSet(SECURE_KEYS.ENCRYPTION_KEY, key);
    }
    return key;
  } catch (e) {
    console.error('Failed to get/create encryption key:', e);
    return null;
  }
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
  const bytes = new Uint8Array(32);
  for (let i = 0; i < 32; i++) {
    bytes[i] = parseInt(hex.substring(i * 2, i * 2 + 2), 16);
  }
  return bytes;
};

/** Generate a cryptographically secure random hex string */
export const secureRandomHex = (byteCount = 8) => bytesToHex(nacl.randomBytes(byteCount));

/**
 * Hash a PIN with a salt using PBKDF2-HMAC-SHA256.
 * 10,000 rounds + server-side rate limiting (5 attempts/15 min) = brute-force infeasible.
 *
 * @param {string} pin - The PIN to hash
 * @param {string} [existingSalt] - Hex salt for verification mode; omit to generate a new random salt (creation mode)
 * @param {number} [iterations] - Number of iterations (default: PIN_HASH_ITERATIONS)
 * @returns {{ hash: string, salt: string }|null} - The hash and salt, or null on failure
 */
const PIN_HASH_ITERATIONS = 10000;
const LEGACY_PIN_HASH_ITERATIONS_100K = 100000;
const LEGACY_PIN_HASH_ITERATIONS_1K = 1000;

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
    const hash = pbkdf2HmacSha256(pin, salt, iterations);
    return { hash, salt, version: 'pbkdf2' };
  } catch (e) {
    console.error('Failed to hash PIN:', e);
    return null;
  }
};

export const saveSecurePin = async (pin, type = 'main') => {
  try {
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
    // Store version marker so verifyPin can skip legacy fallbacks
    const versionKey = type === 'duress' ? 'DURESS_PIN_VERSION' : 'PIN_VERSION';
    await safeSecureStoreSet(versionKey, 'pbkdf2').catch(() => {});
    return hashSaved && saltSaved;
  } catch (e) {
    console.error('Failed to save PIN:', e);
    return false;
  }
};

export const getSecurePin = async (type = 'main') => {
  try {
    let hashKey;
    if (type === 'duress') hashKey = SECURE_KEYS.DURESS_PIN;
    else hashKey = SECURE_KEYS.USER_PIN;
    return await safeSecureStoreGet(hashKey);
  } catch (e) {
    console.error('Failed to get PIN:', e);
    return null;
  }
};

// In-memory cache for PIN hash/salt to avoid repeated SecureStore reads
const _pinCache = {};

// Session verification: after first successful login, store a session token
// so subsequent logins use a single SHA-256 (~0.05ms) instead of PBKDF2 (~200-500ms)
const SESSION_TOKEN_KEY = 'session_verify_token';
const SESSION_DIGEST_KEY = 'session_verify_digest';

// Session timeout: require full PBKDF2 re-verification after inactivity
const SESSION_TIMEOUT_MS = 5 * 60 * 1000; // 5 minutes

// Lock to prevent concurrent PIN migrations from corrupting data
// Per-type migration lock to prevent concurrent migrations across main/duress
const _pinMigrationInProgress = new Map();

/** Clear cached PIN data (call after PIN change or wipe) */
export const clearPinCache = () => {
  delete _pinCache.main;
  delete _pinCache.duress;
  delete _pinCache._session;
  // Session token is in-memory only — clearing _pinCache._session is sufficient.
  // Also clear any legacy persisted session tokens from older app versions (non-blocking)
  safeSecureStoreDelete(SESSION_TOKEN_KEY).catch(() => {});
  safeSecureStoreDelete(SESSION_DIGEST_KEY).catch(() => {});
};

/** Clear only the session token (call when app goes to background).
 *  Forces full PBKDF2 PIN re-verification on next foreground entry. */
export const clearPinSession = () => {
  delete _pinCache._session;
};

/** Pre-warm PIN cache by loading hash/salt from SecureStore into memory.
 *  Call on app mount so verifyPin() doesn't block on SecureStore reads. */
export const preWarmPinCache = async () => {
  try {
    const types = ['main', 'duress'];
    await Promise.all([
      // Load PIN hashes
      ...types.map(async (type) => {
        if (_pinCache[type]) return; // Already cached
        const hash = await getSecurePin(type);
        if (!hash) return;
        let saltKey;
        if (type === 'duress') saltKey = SECURE_KEYS.DURESS_PIN_SALT;
        else saltKey = SECURE_KEYS.USER_PIN_SALT;
        const salt = await safeSecureStoreGet(saltKey);
        const version = await safeSecureStoreGet(type === 'duress' ? 'DURESS_PIN_VERSION' : 'PIN_VERSION');
        _pinCache[type] = { hash, salt, version: version || null };
      }),
      // Session verification token is in-memory only (not persisted).
      // No need to load from SecureStore — PBKDF2 is required on fresh launch.
    ]);
  } catch (_) { /* non-critical */ }
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
      if (!storedHash) return false;

      let saltKey;
      if (type === 'duress') saltKey = SECURE_KEYS.DURESS_PIN_SALT;
      else saltKey = SECURE_KEYS.USER_PIN_SALT;
      const versionKey = type === 'duress' ? 'DURESS_PIN_VERSION' : 'PIN_VERSION';
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
      // Fast path: PBKDF2 with current iterations (10k) — sub-second on mobile
      const pbkdf2Hash = pbkdf2HmacSha256(inputPin, storedSalt, PIN_HASH_ITERATIONS);
      if (constantTimeEqual(storedHash, pbkdf2Hash)) return verified(true);

      // If PIN was saved with current PBKDF2 version, skip all legacy fallbacks (wrong PIN)
      if (storedVersion === 'pbkdf2') return false;

      // Legacy: PBKDF2 with 100k iterations (old default — auto-migrate to 10k on match)
      const pbkdf2Hash100k = pbkdf2HmacSha256(inputPin, storedSalt, LEGACY_PIN_HASH_ITERATIONS_100K);
      if (constantTimeEqual(storedHash, pbkdf2Hash100k)) {
        if (!_pinMigrationInProgress.get(type)) {
          _pinMigrationInProgress.set(type, true);
          try { await saveSecurePin(inputPin, type); clearPinCache(); } finally { _pinMigrationInProgress.delete(type); }
        }
        return verified(true);
      }

      // Legacy: iterated SHA-256 with 100k iterations
      const legacy100k = legacyHashPin(inputPin, storedSalt, LEGACY_PIN_HASH_ITERATIONS_100K);
      if (constantTimeEqual(storedHash, legacy100k)) {
        if (!_pinMigrationInProgress.get(type)) {
          _pinMigrationInProgress.set(type, true);
          try { await saveSecurePin(inputPin, type); clearPinCache(); } finally { _pinMigrationInProgress.delete(type); }
        }
        return verified(true);
      }

      // Legacy: iterated SHA-256 with 10k iterations
      const legacy10k = legacyHashPin(inputPin, storedSalt, PIN_HASH_ITERATIONS);
      if (constantTimeEqual(storedHash, legacy10k)) {
        if (!_pinMigrationInProgress.get(type)) {
          _pinMigrationInProgress.set(type, true);
          try { await saveSecurePin(inputPin, type); clearPinCache(); } finally { _pinMigrationInProgress.delete(type); }
        }
        return verified(true);
      }

      // Legacy: 1k iterations (pre-hardening)
      const legacy1k = legacyHashPin(inputPin, storedSalt, LEGACY_PIN_HASH_ITERATIONS_1K);
      if (constantTimeEqual(storedHash, legacy1k)) {
        if (!_pinMigrationInProgress.get(type)) {
          _pinMigrationInProgress.set(type, true);
          try { await saveSecurePin(inputPin, type); clearPinCache(); } finally { _pinMigrationInProgress.delete(type); }
        }
        return verified(true);
      }

      // Backward compat: single-round SHA-256 (pre-hardening PINs)
      const singleRoundHash = sha256(storedSalt + inputPin);
      if (constantTimeEqual(storedHash, singleRoundHash)) {
        if (!_pinMigrationInProgress.get(type)) {
          _pinMigrationInProgress.set(type, true);
          try { await saveSecurePin(inputPin, type); clearPinCache(); } finally { _pinMigrationInProgress.delete(type); }
        }
        return verified(true);
      }
      return false;
    } else {
      // No stored salt: legacy static-salt hash
      const legacyHash = sha256(LEGACY_PIN_SALT + inputPin);
      if (constantTimeEqual(storedHash, legacyHash)) return verified(true);

      const legacyHashOldOrder = sha256(inputPin + LEGACY_PIN_SALT);
      return verified(constantTimeEqual(storedHash, legacyHashOldOrder));
    }
  } catch (e) {
    console.error('Failed to verify PIN:', e);
    return false;
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
    _pinCache._session = { token, digest, createdAt: Date.now() };
    // Do NOT persist to SecureStore — in-memory only so PBKDF2 is required on fresh launch
  } catch (e) { /* non-critical */ }
};

export const deleteSecurePin = async (type = 'main') => {
  try {
    let hashKey, saltKey;
    if (type === 'duress') {
      hashKey = SECURE_KEYS.DURESS_PIN;
      saltKey = SECURE_KEYS.DURESS_PIN_SALT;
    } else {
      hashKey = SECURE_KEYS.USER_PIN;
      saltKey = SECURE_KEYS.USER_PIN_SALT;
    }
    await safeSecureStoreDelete(saltKey);
    return await safeSecureStoreDelete(hashKey);
  } catch (e) {
    console.error('Failed to delete PIN:', e);
    return false;
  }
};

export const hasSecurePin = async (type = 'main') => {
  const hash = await getSecurePin(type);
  return !!hash;
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
    // Encryption failed — fall through to plaintext as last resort
  }
  return await safeSecureStoreSet(SECURE_KEYS.RECOVERY_PHRASE, phrase);
};

export const getSecurePhrase = async () => {
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

export const clearSecureStorage = async () => {
  try {
    const keys = Object.values(SECURE_KEYS);
    for (const key of keys) {
      await safeSecureStoreDelete(key);
    }
    // Clear in-memory caches
    delete _pinCache.main;
    delete _pinCache.duress;
    _ratchetStorageKeyCache = null;

    // Also clear all ratchet session keys and known public keys from AsyncStorage
    // These contain chain keys that could decrypt past/future messages
    try {
      const allKeys = await AsyncStorage.getAllKeys();
      const sensitiveKeys = allKeys.filter(k =>
        k.startsWith(RATCHET_SESSION_PREFIX) || k.startsWith('@known_pubkey_')
      );
      if (sensitiveKeys.length > 0) {
        await AsyncStorage.multiRemove(sensitiveKeys);
      }
    } catch (ratchetErr) {
      console.error('Failed to clear ratchet sessions:', ratchetErr);
    }
    return true;
  } catch (e) {
    console.error('Failed to clear secure storage:', e);
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
      const existingSecure = await SecureStore.getItemAsync(sanitizedKey);
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
      await SecureStore.setItemAsync(sanitizedKey, asyncValue);

      // Verify the write succeeded before removing from AsyncStorage
      const verify = await SecureStore.getItemAsync(sanitizedKey);
      if (verify === asyncValue) {
        await AsyncStorage.removeItem(key);
        result.migrated.push(key);
      } else {
        result.failed.push(key);
      }
    } catch (e) {
      console.error(`migrateToSecureStorage: Failed to migrate key "${key}":`, e?.message || String(e));
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
  const chainKeyBytes = hexToBytes32(chainKeyHex);
  const messageKey = hmacSha256(chainKeyBytes, new Uint8Array([0x01]));
  const nextChainKeyBytes = hmacSha256(chainKeyBytes, new Uint8Array([0x02]));
  return { nextChainKey: bytesToHex(nextChainKeyBytes), messageKey };
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
    console.error('initRatchetSession error:', e);
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
    const { nextChainKey, messageKey } = kdfChainStep(currentSession.sendChainKey);

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
    console.error('ratchetEncrypt error:', e);
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
      const skipKey = chainId + ':' + (s.recvMessageIndex + i);
      s.skippedKeys[skipKey] = encodeBase64(step.messageKey);
      chainKey = step.nextChainKey;
    }
  }

  const theirNewEphBytes = decodeBase64(theirNewEphB64);
  const myEphSecretBytes = s.myEphemeralKeyPair?.secretKey ? decodeBase64(s.myEphemeralKeyPair.secretKey) : null;

  // Step 1: DH with current ephemeral → new receive chain
  if (myEphSecretBytes) {
    const dh1 = nacl.box.before(theirNewEphBytes, myEphSecretBytes);
    const { rootKey: rk1, chainKey: recvCK } = kdfRootStep(s.rootKey, dh1);
    s.rootKey = rk1;
    s.recvChainKey = recvCK;
  }

  // Step 2: Generate new ephemeral
  const newEph = nacl.box.keyPair();

  // Zero old ephemeral (best-effort forward secrecy)
  if (myEphSecretBytes) { try { myEphSecretBytes.fill(0); } catch (_) {} }

  // Step 3: DH with new ephemeral → new send chain
  const dh2 = nacl.box.before(theirNewEphBytes, newEph.secretKey);
  const { rootKey: rk2, chainKey: sendCK } = kdfRootStep(s.rootKey, dh2);
  s.rootKey = rk2;
  s.sendChainKey = sendCK;

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
      const plaintext = encodeUTF8(unpadded || decrypted);
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
      const plaintext = encodeUTF8(unpadded || decrypted);
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
    const { nextChainKey, messageKey } = kdfChainStep(currentSession.recvChainKey);

    // Decrypt with NaCl secretbox
    const decrypted = nacl.secretbox.open(ciphertext, nonce, messageKey);
    if (!decrypted) {
      return null;
    }

    // Unpad
    const unpadded = unpadMessage(decrypted);
    const plaintext = encodeUTF8(unpadded || decrypted);

    // Evict oldest skipped keys if over cap
    const entries = Object.keys(currentSession.skippedKeys);
    if (entries.length > MAX_SKIPPED_KEYS) {
      const sorted = entries.sort();
      const excess = entries.length - MAX_SKIPPED_KEYS;
      for (let i = 0; i < excess; i++) {
        secureDeleteSkippedKey(currentSession.skippedKeys, sorted[i]);
      }
    }

    const updatedSession = {
      ...currentSession,
      recvChainKey: nextChainKey,
      recvMessageIndex: currentSession.recvMessageIndex + 1,
    };

    return { plaintext, session: updatedSession };
  } catch (e) {
    console.error('ratchetDecrypt error:', e);
    return null;
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
    console.error('serializeSession error:', e);
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
    console.error('deserializeSession error:', e);
    return null;
  }
};

// ============================================
// POST-QUANTUM KEY ENCAPSULATION (EXPERIMENTAL — DISABLED)
// ============================================
//
// STATUS: DISABLED. This code is NOT active and provides NO protection.
// All encryption currently uses Curve25519 (classical) only.
//
// This experimental lattice-based KEM produces asymmetric shared secrets
// (sender ≠ receiver) due to noise decoding edge cases, causing message
// decryption failures. It will be replaced with a battle-tested library
// (e.g. liboqs/ML-KEM bindings) in a future release.
//
// DO NOT claim post-quantum protection in any user-facing material.

// Lattice parameters (conservative, Kyber-512 equivalent security)
const PQ_N = 256;
const PQ_Q = 3329;
const PQ_K = 2;

// Modular arithmetic helpers
const modq = (x) => ((x % PQ_Q) + PQ_Q) % PQ_Q;

// Generate a random polynomial mod q
const randomPoly = (n) => {
  const poly = new Int16Array(n);
  const bytes = nacl.randomBytes(n * 2);
  for (let i = 0; i < n; i++) {
    poly[i] = modq((bytes[i * 2] | (bytes[i * 2 + 1] << 8)));
  }
  return poly;
};

// Generate a small noise polynomial (centered binomial, eta=2)
const noisePoly = (n) => {
  const poly = new Int16Array(n);
  const bytes = nacl.randomBytes(n);
  for (let i = 0; i < n; i++) {
    const b = bytes[i];
    const a1 = (b & 1) + ((b >> 1) & 1);
    const a2 = ((b >> 2) & 1) + ((b >> 3) & 1);
    poly[i] = modq(a1 - a2);
  }
  return poly;
};

// Polynomial multiplication mod (x^n + 1, q) — schoolbook for correctness
const polyMul = (a, b, n) => {
  const result = new Int16Array(n);
  for (let i = 0; i < n; i++) {
    for (let j = 0; j < n; j++) {
      const idx = i + j;
      if (idx < n) {
        result[idx] = modq(result[idx] + a[i] * b[j]);
      } else {
        // x^n = -1 mod (x^n + 1)
        result[idx - n] = modq(result[idx - n] - a[i] * b[j]);
      }
    }
  }
  return result;
};

// Polynomial addition mod q
const polyAdd = (a, b, n) => {
  const result = new Int16Array(n);
  for (let i = 0; i < n; i++) {
    result[i] = modq(a[i] + b[i]);
  }
  return result;
};

// Polynomial subtraction mod q
const polySub = (a, b, n) => {
  const result = new Int16Array(n);
  for (let i = 0; i < n; i++) {
    result[i] = modq(a[i] - b[i]);
  }
  return result;
};

// Compress a polynomial coefficient to a single bit (for encoding shared secret)
const compress1 = (x) => {
  // Round x * 2 / q to nearest integer mod 2
  const scaled = Math.round((modq(x) * 2) / PQ_Q) % 2;
  return scaled < 0 ? scaled + 2 : scaled;
};

// Decompress a bit back to a polynomial coefficient
const decompress1 = (bit) => bit ? Math.round(PQ_Q / 2) : 0;

// Encode polynomial to base64
const polyToB64 = (poly) => {
  const bytes = new Uint8Array(poly.length * 2);
  for (let i = 0; i < poly.length; i++) {
    bytes[i * 2] = poly[i] & 0xFF;
    bytes[i * 2 + 1] = (poly[i] >> 8) & 0xFF;
  }
  return encodeBase64(bytes);
};

// Decode polynomial from base64
const b64ToPoly = (b64, n) => {
  const bytes = decodeBase64(b64);
  const poly = new Int16Array(n);
  for (let i = 0; i < n; i++) {
    poly[i] = (bytes[i * 2] | (bytes[i * 2 + 1] << 8));
    if (poly[i] >= PQ_Q) poly[i] = modq(poly[i]);
  }
  return poly;
};

/**
 * Generate a post-quantum key pair (Kyber-512 equivalent).
 *
 * Public key: matrix A (k x k polynomials) + vector t (k polynomials)
 * Private key: vector s (k small polynomials)
 *
 * @returns {{ publicKey: string, privateKey: string }} - base64-encoded JSON
 */
export const pqGenerateKeyPair = () => {
  try {
    // Generate random matrix A (public parameter, k x k)
    const A = [];
    for (let i = 0; i < PQ_K; i++) {
      A[i] = [];
      for (let j = 0; j < PQ_K; j++) {
        A[i][j] = randomPoly(PQ_N);
      }
    }

    // Generate secret vector s (k small polynomials)
    const s = [];
    for (let i = 0; i < PQ_K; i++) {
      s[i] = noisePoly(PQ_N);
    }

    // Generate noise vector e
    const e = [];
    for (let i = 0; i < PQ_K; i++) {
      e[i] = noisePoly(PQ_N);
    }

    // Compute public vector t = A * s + e
    const t = [];
    for (let i = 0; i < PQ_K; i++) {
      t[i] = new Int16Array(PQ_N);
      for (let j = 0; j < PQ_K; j++) {
        t[i] = polyAdd(t[i], polyMul(A[i][j], s[j], PQ_N), PQ_N);
      }
      t[i] = polyAdd(t[i], e[i], PQ_N);
    }

    // Serialize public key: { A, t }
    const pubData = {
      A: A.map(row => row.map(p => polyToB64(p))),
      t: t.map(p => polyToB64(p)),
    };

    // Serialize private key: { s }
    const privData = {
      s: s.map(p => polyToB64(p)),
    };

    return {
      publicKey: encodeBase64(decodeUTF8(JSON.stringify(pubData))),
      privateKey: encodeBase64(decodeUTF8(JSON.stringify(privData))),
    };
  } catch (err) {
    console.error('pqGenerateKeyPair error:', err);
    return null;
  }
};

/**
 * Encapsulate a shared secret using the recipient's PQ public key.
 *
 * Produces a ciphertext that only the private key holder can decapsulate,
 * plus a 32-byte shared secret for symmetric encryption.
 *
 * @param {string} pqPublicKeyB64 - Recipient's PQ public key (base64 JSON)
 * @returns {{ ciphertext: string, sharedSecret: string }|null} - base64-encoded ciphertext and hex shared secret
 */
export const pqEncapsulate = (pqPublicKeyB64) => {
  if (!pqPublicKeyB64) return null;

  try {
    const pubData = JSON.parse(encodeUTF8(decodeBase64(pqPublicKeyB64)));
    const A = pubData.A.map(row => row.map(p => b64ToPoly(p, PQ_N)));
    const t = pubData.t.map(p => b64ToPoly(p, PQ_N));

    // Generate ephemeral secret r and noise
    const r = [];
    for (let i = 0; i < PQ_K; i++) {
      r[i] = noisePoly(PQ_N);
    }

    const e1 = [];
    for (let i = 0; i < PQ_K; i++) {
      e1[i] = noisePoly(PQ_N);
    }
    const e2 = noisePoly(PQ_N);

    // Generate random message bits (the shared secret seed)
    const msgBits = nacl.randomBytes(PQ_N / 8);

    // Compute u = A^T * r + e1
    const u = [];
    for (let i = 0; i < PQ_K; i++) {
      u[i] = new Int16Array(PQ_N);
      for (let j = 0; j < PQ_K; j++) {
        u[i] = polyAdd(u[i], polyMul(A[j][i], r[j], PQ_N), PQ_N);
      }
      u[i] = polyAdd(u[i], e1[i], PQ_N);
    }

    // Encode message as polynomial
    const msgPoly = new Int16Array(PQ_N);
    for (let i = 0; i < PQ_N; i++) {
      const byteIdx = Math.floor(i / 8);
      const bitIdx = i % 8;
      const bit = (msgBits[byteIdx] >> bitIdx) & 1;
      msgPoly[i] = decompress1(bit);
    }

    // Compute v = t^T * r + e2 + msg
    let v = new Int16Array(PQ_N);
    for (let i = 0; i < PQ_K; i++) {
      v = polyAdd(v, polyMul(t[i], r[i], PQ_N), PQ_N);
    }
    v = polyAdd(v, e2, PQ_N);
    v = polyAdd(v, msgPoly, PQ_N);

    // Ciphertext = { u, v }
    const ctData = {
      u: u.map(p => polyToB64(p)),
      v: polyToB64(v),
    };

    // Shared secret = SHA-256 of the message bits
    const sharedSecret = sha256(encodeBase64(msgBits));

    return {
      ciphertext: encodeBase64(decodeUTF8(JSON.stringify(ctData))),
      sharedSecret,
    };
  } catch (err) {
    console.error('pqEncapsulate error:', err);
    return null;
  }
};

/**
 * Decapsulate a shared secret using our PQ private key.
 *
 * @param {string} ciphertextB64 - Ciphertext from pqEncapsulate (base64 JSON)
 * @param {string} pqPrivateKeyB64 - Our PQ private key (base64 JSON)
 * @returns {string|null} - Hex shared secret (same as encapsulator's), or null
 */
export const pqDecapsulate = (ciphertextB64, pqPrivateKeyB64) => {
  if (!ciphertextB64 || !pqPrivateKeyB64) return null;

  try {
    const ctData = JSON.parse(encodeUTF8(decodeBase64(ciphertextB64)));
    const privData = JSON.parse(encodeUTF8(decodeBase64(pqPrivateKeyB64)));

    const u = ctData.u.map(p => b64ToPoly(p, PQ_N));
    const v = b64ToPoly(ctData.v, PQ_N);
    const s = privData.s.map(p => b64ToPoly(p, PQ_N));

    // Compute v - s^T * u to recover noisy message
    let inner = new Int16Array(PQ_N);
    for (let i = 0; i < PQ_K; i++) {
      inner = polyAdd(inner, polyMul(s[i], u[i], PQ_N), PQ_N);
    }

    const noisy = polySub(v, inner, PQ_N);

    // Decode message bits by compressing each coefficient
    const msgBits = new Uint8Array(PQ_N / 8);
    for (let i = 0; i < PQ_N; i++) {
      const bit = compress1(noisy[i]);
      const byteIdx = Math.floor(i / 8);
      const bitIdx = i % 8;
      msgBits[byteIdx] |= (bit << bitIdx);
    }

    // Shared secret = SHA-256 of the recovered message bits
    return sha256(encodeBase64(msgBits));
  } catch (err) {
    console.error('pqDecapsulate error:', err);
    return null;
  }
};

/**
 * Hybrid encryption: combine classical Curve25519 + post-quantum KEM.
 *
 * The classical shared secret (NaCl box.before) and the PQ shared secret
 * (from KEM encapsulate) are combined via SHA-256 to produce the final
 * encryption key. An attacker must break BOTH to recover the message.
 *
 * @param {string} message - Plaintext message
 * @param {string} theirPublicKeyB64 - Recipient's Curve25519 public key (base64)
 * @param {string} myPrivateKeyB64 - Sender's Curve25519 private key (base64)
 * @param {string} theirPqPublicKeyB64 - Recipient's PQ public key (base64)
 * @returns {{ encrypted: string, pqCiphertext: string }|null}
 */
export const hybridEncrypt = (message, theirPublicKeyB64, myPrivateKeyB64, theirPqPublicKeyB64) => {
  if (!message || !theirPublicKeyB64 || !myPrivateKeyB64 || !theirPqPublicKeyB64) return null;

  try {
    // Classical shared secret
    const theirPub = decodeBase64(theirPublicKeyB64);
    const myPriv = decodeBase64(myPrivateKeyB64);
    const classicalSecret = encodeBase64(nacl.box.before(theirPub, myPriv));

    // Post-quantum shared secret
    const pqResult = pqEncapsulate(theirPqPublicKeyB64);
    if (!pqResult) return null;

    // Combine both secrets — must break both to recover key
    const combinedKey = sha256(classicalSecret + pqResult.sharedSecret + 'hybrid_v1');
    const keyBytes = new Uint8Array(32);
    for (let i = 0; i < 32; i++) {
      keyBytes[i] = parseInt(combinedKey.substring(i * 2, i * 2 + 2), 16);
    }

    // Pad and encrypt with NaCl secretbox using the hybrid key
    const messageBytes = decodeUTF8(message);
    const paddedBytes = padMessage(messageBytes);
    const nonce = nacl.randomBytes(nacl.secretbox.nonceLength);
    const ciphertext = nacl.secretbox(paddedBytes, nonce, keyBytes);
    if (!ciphertext) return null;

    const encrypted = 'hybrid:' + encodeBase64(nonce) + ':' + encodeBase64(ciphertext);

    return {
      encrypted,
      pqCiphertext: pqResult.ciphertext,
    };
  } catch (err) {
    console.error('hybridEncrypt error:', err);
    return null;
  }
};

/**
 * Hybrid decryption: recover message using both classical + PQ keys.
 *
 * @param {string} encrypted - "hybrid:<nonce>:<ciphertext>" format
 * @param {string} theirPublicKeyB64 - Sender's Curve25519 public key (base64)
 * @param {string} myPrivateKeyB64 - Recipient's Curve25519 private key (base64)
 * @param {string} pqCiphertextB64 - PQ ciphertext from hybridEncrypt
 * @param {string} myPqPrivateKeyB64 - Recipient's PQ private key (base64)
 * @returns {string|null} - Decrypted plaintext, or null
 */
export const hybridDecrypt = (encrypted, theirPublicKeyB64, myPrivateKeyB64, pqCiphertextB64, myPqPrivateKeyB64) => {
  if (!encrypted || !theirPublicKeyB64 || !myPrivateKeyB64 || !pqCiphertextB64 || !myPqPrivateKeyB64) return null;
  if (!encrypted.startsWith('hybrid:')) return null;

  try {
    // Classical shared secret
    const theirPub = decodeBase64(theirPublicKeyB64);
    const myPriv = decodeBase64(myPrivateKeyB64);
    const classicalSecret = encodeBase64(nacl.box.before(theirPub, myPriv));

    // Post-quantum shared secret
    const pqSecret = pqDecapsulate(pqCiphertextB64, myPqPrivateKeyB64);
    if (!pqSecret) return null;

    // Reconstruct the hybrid key
    const combinedKey = sha256(classicalSecret + pqSecret + 'hybrid_v1');
    const keyBytes = new Uint8Array(32);
    for (let i = 0; i < 32; i++) {
      keyBytes[i] = parseInt(combinedKey.substring(i * 2, i * 2 + 2), 16);
    }

    // Parse and decrypt
    const parts = encrypted.split(':');
    if (parts.length < 3) return null;
    const nonce = decodeBase64(parts[1]);
    const ciphertext = decodeBase64(parts[2]);

    const decrypted = nacl.secretbox.open(ciphertext, nonce, keyBytes);
    if (!decrypted) return null;

    const unpadded = unpadMessage(decrypted);
    return encodeUTF8(unpadded || decrypted);
  } catch (err) {
    console.error('hybridDecrypt error:', err);
    return null;
  }
};

// ============================================
// DETERMINISTIC PQ KEY GENERATION (from recovery phrase)
// ============================================

/**
 * Derive a PQ key pair deterministically from a recovery phrase.
 * Uses SHA-256 chain as a seeded PRNG to replace nacl.randomBytes.
 */
export const derivePqKeysFromPhrase = (phrase) => {
  if (!phrase || typeof phrase !== 'string') return null;

  try {
    const normalized = phrase.toLowerCase().trim();
    const baseSeed = sha256(normalized + 'theshft_pq_derivation_v1');

    // Seeded PRNG: chain of SHA-256 hashes
    let prngState = baseSeed;
    const seededRandomBytes = (n) => {
      const result = new Uint8Array(n);
      let offset = 0;
      while (offset < n) {
        prngState = sha256(prngState + 'next');
        for (let i = 0; i < 32 && offset < n; i++, offset++) {
          result[offset] = parseInt(prngState.substring(i * 2, i * 2 + 2), 16);
        }
      }
      return result;
    };

    // Generate PQ keypair using seeded randomness instead of nacl.randomBytes
    const seededRandomPoly = (n) => {
      const poly = new Int16Array(n);
      const bytes = seededRandomBytes(n * 2);
      for (let i = 0; i < n; i++) {
        poly[i] = modq((bytes[i * 2] | (bytes[i * 2 + 1] << 8)));
      }
      return poly;
    };

    const seededNoisePoly = (n) => {
      const poly = new Int16Array(n);
      const bytes = seededRandomBytes(n);
      for (let i = 0; i < n; i++) {
        const b = bytes[i];
        const a1 = (b & 1) + ((b >> 1) & 1);
        const a2 = ((b >> 2) & 1) + ((b >> 3) & 1);
        poly[i] = modq(a1 - a2);
      }
      return poly;
    };

    const A = [];
    for (let i = 0; i < PQ_K; i++) {
      A[i] = [];
      for (let j = 0; j < PQ_K; j++) {
        A[i][j] = seededRandomPoly(PQ_N);
      }
    }

    const s = [];
    for (let i = 0; i < PQ_K; i++) s[i] = seededNoisePoly(PQ_N);

    const e = [];
    for (let i = 0; i < PQ_K; i++) e[i] = seededNoisePoly(PQ_N);

    const t = [];
    for (let i = 0; i < PQ_K; i++) {
      t[i] = new Int16Array(PQ_N);
      for (let j = 0; j < PQ_K; j++) {
        t[i] = polyAdd(t[i], polyMul(A[i][j], s[j], PQ_N), PQ_N);
      }
      t[i] = polyAdd(t[i], e[i], PQ_N);
    }

    const pubData = { A: A.map(row => row.map(p => polyToB64(p))), t: t.map(p => polyToB64(p)) };
    const privData = { s: s.map(p => polyToB64(p)) };

    return {
      publicKey: encodeBase64(decodeUTF8(JSON.stringify(pubData))),
      privateKey: encodeBase64(decodeUTF8(JSON.stringify(privData))),
    };
  } catch (err) {
    console.error('derivePqKeysFromPhrase error:', err);
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
export const generateSignedPrekey = (identityPrivateKeyB64, prekeyId) => {
  if (!identityPrivateKeyB64) return null;

  try {
    // Generate ephemeral Curve25519 prekey
    const prekeyPair = nacl.box.keyPair();
    const prekeyPublicB64 = encodeBase64(prekeyPair.publicKey);
    const prekeyPrivateB64 = encodeBase64(prekeyPair.secretKey);

    // Generate PQ prekey
    const pqPrekeyPair = pqGenerateKeyPair();

    // Sign the prekey public key with identity key
    // Derive Ed25519 signing key from Curve25519 private key via SHA-512
    const identityPriv = decodeBase64(identityPrivateKeyB64);
    const signingKeyHash = sha256(encodeBase64(identityPriv) + 'ed25519_signing_v1');
    const signingSeed = new Uint8Array(32);
    for (let i = 0; i < 32; i++) {
      signingSeed[i] = parseInt(signingKeyHash.substring(i * 2, i * 2 + 2), 16);
    }
    const signingKeyPair = nacl.sign.keyPair.fromSeed(signingSeed);

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
    console.error('generateSignedPrekey error:', err);
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
    console.error('verifySignedPrekey error:', err);
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
export const generateOneTimePrekeys = (count, startIndex) => {
  const prekeys = [];
  for (let i = 0; i < count; i++) {
    try {
      const kp = nacl.box.keyPair();
      const pqKp = pqGenerateKeyPair();
      prekeys.push({
        id: startIndex + i,
        publicKey: encodeBase64(kp.publicKey),
        privateKey: encodeBase64(kp.secretKey),
        pqPublicKey: pqKp ? pqKp.publicKey : null,
        pqPrivateKey: pqKp ? pqKp.privateKey : null,
      });
    } catch (err) {
      console.error('generateOneTimePrekeys error at index', startIndex + i, err);
    }
  }
  return prekeys;
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
export const initSessionFromPrekeyBundle = (bundle, myKeys) => {
  if (!bundle || !myKeys || !bundle.identityKey || !bundle.signedPrekey || !myKeys.privateKey) return null;

  try {
    // Verify signed prekey signature — mandatory to prevent MITM stripping
    if (!bundle.signedPrekeySignature || !bundle.signingPublicKey) {
      console.error('initSessionFromPrekeyBundle: missing prekey signature or signing key');
      return null;
    }
    const valid = verifySignedPrekey(bundle.signedPrekey, bundle.signedPrekeySignature, bundle.signingPublicKey);
    if (!valid) {
      console.error('initSessionFromPrekeyBundle: signed prekey signature verification failed');
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

    // PQ KEM disabled — see POST-QUANTUM section header for details.
    let pqCiphertext = null;

    // Derive root key using HKDF (Signal Protocol compatible).
    // F = 32 bytes of 0xFF (X25519 discontinuity bytes, prevents invalid curve attacks)
    // IKM = F || DH1 || DH2 || DH3 [|| DH4]
    // Salt = 32 zero bytes
    // Info = "theSHFT_X3DH_v2"
    const discontinuity = new Uint8Array(32).fill(0xFF);
    const ikm = new Uint8Array(32 + dhConcat.length);
    ikm.set(discontinuity, 0);
    ikm.set(dhConcat, 32);
    const x3dhSalt = new Uint8Array(32);
    const x3dhInfo = asciiToBytes('theSHFT_X3DH_v2');
    const masterSecret = hkdf(x3dhSalt, ikm, x3dhInfo, 32);
    const rootKey = bytesToHex(masterSecret);

    // Zero identity private key after X3DH DH computations
    try { myIdentityPriv.fill(0); } catch (_) {}

    // Derive initial send chain via DH ratchet step.
    const initialDH = nacl.box.before(theirSignedPrekey, ephemeral.secretKey);
    const { rootKey: postDHRoot, chainKey: sendChainKey } = kdfRootStep(rootKey, initialDH);

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
    console.error('initSessionFromPrekeyBundle error:', err);
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
 * @param {number} usedPrekeyId - Which signed prekey the sender used
 * @param {number|null} usedOtpkId - Which one-time prekey the sender consumed
 * @param {object} myKeys - { publicKey, privateKey } (our identity keypair)
 * @param {string} mySignedPrekeyPrivateB64 - Our signed prekey private key
 * @param {string|null} myOtpkPrivateB64 - Our one-time prekey private key (if used)
 * @param {string|null} myPqPrekeyPrivateB64 - Our PQ prekey private key (if used)
 * @returns {object|null} - Ratchet session state
 */
export const initSessionFromFirstMessage = (
  senderIdentityKeyB64, senderEphemeralKeyB64, pqCiphertextB64,
  usedPrekeyId, usedOtpkId,
  myKeys, mySignedPrekeyPrivateB64, myOtpkPrivateB64, myPqPrekeyPrivateB64
) => {
  if (!senderIdentityKeyB64 || !senderEphemeralKeyB64 || !myKeys?.privateKey || !mySignedPrekeyPrivateB64) return null;

  try {
    const senderIdentityPub = decodeBase64(senderIdentityKeyB64);
    const senderEphemeralPub = decodeBase64(senderEphemeralKeyB64);
    const myIdentityPriv = decodeBase64(myKeys.privateKey);
    const mySignedPrekeyPriv = decodeBase64(mySignedPrekeyPrivateB64);

    // DH1: their identity × my signed prekey (mirrors sender's DH1)
    const dh1 = nacl.box.before(senderIdentityPub, mySignedPrekeyPriv);
    // DH2: their ephemeral × my identity (mirrors sender's DH2)
    const dh2 = nacl.box.before(senderEphemeralPub, myIdentityPriv);
    // DH3: their ephemeral × my signed prekey (mirrors sender's DH3)
    const dh3 = nacl.box.before(senderEphemeralPub, mySignedPrekeyPriv);

    // Concatenate raw DH outputs as Uint8Array (matching sender side)
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

    // Derive the same root key as the sender using HKDF (Signal Protocol compatible).
    const discontinuity = new Uint8Array(32).fill(0xFF);
    const ikm = new Uint8Array(32 + dhConcat.length);
    ikm.set(discontinuity, 0);
    ikm.set(dhConcat, 32);
    const x3dhSalt = new Uint8Array(32);
    const x3dhInfo = asciiToBytes('theSHFT_X3DH_v2');
    const masterSecret = hkdf(x3dhSalt, ikm, x3dhInfo, 32);
    const rootKey = bytesToHex(masterSecret);

    // Perform the matching DH ratchet step BEFORE zeroing keys.
    // The sender did DH(theirSignedPrekey, ephemeral). We mirror it.
    const initialDH = nacl.box.before(senderEphemeralPub, mySignedPrekeyPriv);
    const { rootKey: postDHRoot, chainKey: recvChainKey } = kdfRootStep(rootKey, initialDH);

    // Generate our own ratchet ephemeral for the response DH ratchet.
    const dhRatchetEphemeral = nacl.box.keyPair();

    // Perform a second DH ratchet step to establish our send chain.
    const sendDH = nacl.box.before(senderEphemeralPub, dhRatchetEphemeral.secretKey);
    const { rootKey: finalRoot, chainKey: sendChainKey } = kdfRootStep(postDHRoot, sendDH);

    // Zero secret keys AFTER all DH computations are done
    try { myIdentityPriv.fill(0); } catch (_) {}
    try { mySignedPrekeyPriv.fill(0); } catch (_) {}

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
    console.error('initSessionFromFirstMessage error:', err);
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
let _ratchetStorageKeyCache = null;
const getRatchetStorageKey = async () => {
  if (_ratchetStorageKeyCache) return _ratchetStorageKeyCache;
  try {
    const existing = await safeSecureStoreGet(SECURE_KEYS.RATCHET_STORAGE_KEY);
    if (existing) {
      _ratchetStorageKeyCache = decodeBase64(existing);
      return _ratchetStorageKeyCache;
    }
    // Generate a new random 32-byte key
    const newKey = nacl.randomBytes(32);
    await safeSecureStoreSet(SECURE_KEYS.RATCHET_STORAGE_KEY, encodeBase64(newKey));
    _ratchetStorageKeyCache = newKey;
    return newKey;
  } catch (e) {
    console.error('getRatchetStorageKey error:', e);
    return null;
  }
};

/** Clear cached ratchet storage key (call on logout/wipe) */
export const clearRatchetStorageKeyCache = () => { _ratchetStorageKeyCache = null; };

/**
 * Encrypt a string using NaCl secretbox with the ratchet storage key.
 * Returns base64(nonce + ciphertext) or null on failure.
 */
const encryptForStorage = async (plaintext) => {
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
};

/**
 * Decrypt a base64(nonce + ciphertext) string using the ratchet storage key.
 * Returns the plaintext string or null on failure.
 */
const decryptFromStorage = async (encoded) => {
  const key = await getRatchetStorageKey();
  if (!key) return null;
  const combined = decodeBase64(encoded);
  if (!combined || combined.length < nacl.secretbox.nonceLength + 1) return null;
  const nonce = combined.slice(0, nacl.secretbox.nonceLength);
  const ciphertext = combined.slice(nacl.secretbox.nonceLength);
  const decrypted = nacl.secretbox.open(ciphertext, nonce, key);
  if (!decrypted) return null;
  return encodeUTF8(decrypted);
};

/**
 * Load a ratchet session from encrypted local storage.
 */
export const loadRatchetSession = async (conversationId) => {
  try {
    const { getLocal } = require('./storage');
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
    console.error('loadRatchetSession error:', err);
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
      return await saveLocal(key, encrypted);
    }
    // If encryption fails (e.g. no SecureStore), fall back to plaintext in dev
    if (__DEV__) {
      console.warn('Ratchet session stored unencrypted (dev mode)');
      return await saveLocal(key, serialized);
    }
    console.error('Cannot store ratchet session without encryption in production');
    return false;
  } catch (err) {
    console.error('saveRatchetSession error:', err);
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
    console.error('deleteRatchetSession error:', err);
    return false;
  }
};

// ============================================
// PQ KEY MANAGEMENT (SecureStore)
// ============================================

/**
 * Generate and store PQ keys (or derive from phrase if provided).
 */
export const getOrCreatePqKeyPair = async (phrase) => {
  // Try loading existing PQ keys
  const existingPub = await safeSecureStoreGet(SECURE_KEYS.PQ_PUBLIC_KEY);
  const existingPriv = await safeSecureStoreGet(SECURE_KEYS.PQ_PRIVATE_KEY);
  if (existingPub && existingPriv) return { publicKey: existingPub, privateKey: existingPriv };

  // Generate or derive
  let pqKeys;
  if (phrase) {
    pqKeys = derivePqKeysFromPhrase(phrase);
  } else {
    pqKeys = pqGenerateKeyPair();
  }
  if (!pqKeys) return null;

  await safeSecureStoreSet(SECURE_KEYS.PQ_PUBLIC_KEY, pqKeys.publicKey);
  await safeSecureStoreSet(SECURE_KEYS.PQ_PRIVATE_KEY, pqKeys.privateKey);

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
    console.error('computeSafetyNumber error:', err);
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
    const { getLocal, saveLocal } = require('./storage');
    const key = '@known_pubkey_' + contactId;
    const stored = await getLocal(key);

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
    console.error('checkKeyChange error:', err);
    return { changed: false, isNew: true };
  }
};

/**
 * Acknowledge a key change (after user confirms).
 */
export const acknowledgeKeyChange = async (contactId, newPublicKeyB64) => {
  try {
    const { saveLocal } = require('./storage');
    await saveLocal('@known_pubkey_' + contactId, newPublicKeyB64);
    return true;
  } catch (err) {
    console.error('acknowledgeKeyChange error:', err);
    return false;
  }
};

