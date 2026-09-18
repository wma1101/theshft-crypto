/**
 * Web implementation of the NativeCrypto module surface. Added 2026-09-16
 * with the web bring-up (P2-A).
 *
 * WHY THIS FILE EXISTS
 * index.ts asks the Expo native module registry for NativeCrypto at module
 * top level, and that lookup throws "Cannot find native module" in a browser
 * (there is no native side to find). The root
 * layout imports config/appCheck.js, which imports sha256 from this module
 * with no guard, so on web the layout never evaluated and the page stayed
 * blank. Metro picks this file on web because modules/native-crypto/
 * package.json names its entry "index" with no extension: metro-resolver
 * resolves an exact main filename before any platform variant, so with
 * "index.ts" as main this file was never considered.
 *
 * SAME CONTRACT AS index.ts
 * Every function takes and returns base64 strings exactly like the iOS and
 * Android modules: the PBKDF2 password is UTF-8 text, everything else is
 * base64 in and base64 out. Base64 goes through tweetnacl-util, the helper
 * config/encryption.js already uses, not Buffer, so nothing here depends on
 * the polyfill order in config/cryptoPolyfill.js.
 *
 * WHICH PRIMITIVES
 * - PBKDF2-HMAC-SHA256, SHA-256, HMAC-SHA256 come from the browser's
 *   WebCrypto (crypto.subtle). Iteration counts are passed through untouched;
 *   this file never chooses a count.
 * - randomBytes is crypto.getRandomValues, the browser CSPRNG.
 * - ML-KEM-768 is @noble/post-quantum (FIPS 203 in audited JS), the same
 *   code test-utils/nativeCryptoTestDouble.js runs under jest. Key and
 *   ciphertext sizes match the native PQClean build: public 1184, secret
 *   2400, ciphertext 1088, shared secret 32. Unlike the native build this is
 *   JS rather than constant-time C, so the wording of the web security claim
 *   (docs/canonical-claims.md) is an owner decision, not something this file
 *   asserts.
 *
 * THE TWO FLAGS
 * isNativeShaAvailable is false on purpose, mirroring the test double.
 * config/encryption.js only takes the native SHA/HMAC fast path when the flag
 * is true, and the ratchet has synchronous callers that must keep running the
 * pinned JS implementation; on web there is no background thread to win, so
 * the flag stays off and every SHA/HMAC/ratchet path runs the same JS it runs
 * today. isNativeMlKemAvailable is true so _getNativePq in
 * config/encryption.js does not flip pqDisabled, and the web device keeps
 * post-quantum key agreement instead of silently downgrading to classical.
 */

import { encodeBase64, decodeBase64, decodeUTF8 } from 'tweetnacl-util';
import { ml_kem768 } from '@noble/post-quantum/ml-kem.js';

const MAX_GET_RANDOM_VALUES_BYTES = 65536;

const getCrypto = (): Crypto => {
  const c = globalThis.crypto;
  if (!c || typeof c.getRandomValues !== 'function') {
    throw new Error('WebCrypto is not available in this browser');
  }
  return c;
};

const getSubtle = (): SubtleCrypto => {
  const c = getCrypto();
  if (!c.subtle) {
    // crypto.subtle only exists in a secure context (https or localhost).
    throw new Error('WebCrypto subtle API is not available; the page must be served over https');
  }
  return c.subtle;
};

/**
 * Copy into a fresh ArrayBuffer-backed view. WebCrypto's BufferSource typing
 * wants a plain ArrayBuffer view, and copying means the browser never holds a
 * reference into a buffer a caller may reuse.
 */
const bytes = (u: Uint8Array): Uint8Array<ArrayBuffer> => new Uint8Array(u);

const requirePositiveInt = (value: number, name: string): void => {
  if (!Number.isInteger(value) || value < 1) {
    throw new Error(`${name} must be a positive integer`);
  }
};

/**
 * PBKDF2-HMAC-SHA256 over WebCrypto. Same signature as the native module:
 * UTF-8 password, base64 salt, iteration count, derived key length in bytes,
 * base64 result. deriveBits runs off the JS thread inside the browser, which
 * is the whole reason the KDF is not the synchronous JS loop here.
 */
export async function pbkdf2(
  password: string,
  salt: string,
  iterations: number,
  keyLength: number
): Promise<string> {
  requirePositiveInt(iterations, 'iterations');
  requirePositiveInt(keyLength, 'keyLength');
  const subtle = getSubtle();
  const baseKey = await subtle.importKey(
    'raw',
    bytes(decodeUTF8(password)),
    { name: 'PBKDF2' },
    false,
    ['deriveBits']
  );
  const derived = await subtle.deriveBits(
    { name: 'PBKDF2', hash: 'SHA-256', salt: bytes(decodeBase64(salt)), iterations },
    baseKey,
    keyLength * 8
  );
  return encodeBase64(new Uint8Array(derived));
}

/**
 * Random bytes from the browser CSPRNG, base64 like the native module.
 * getRandomValues refuses more than 65536 bytes per call, so long requests
 * are filled in slices.
 */
export async function randomBytes(length: number): Promise<string> {
  if (!Number.isInteger(length) || length < 0) {
    throw new Error('length must be a non-negative integer');
  }
  const c = getCrypto();
  const out = new Uint8Array(length);
  for (let offset = 0; offset < length; offset += MAX_GET_RANDOM_VALUES_BYTES) {
    c.getRandomValues(out.subarray(offset, Math.min(offset + MAX_GET_RANDOM_VALUES_BYTES, length)));
  }
  return encodeBase64(out);
}

/** SHA-256 over WebCrypto. Base64 in, base64 out, like the native module. */
export async function sha256(inputBase64: string): Promise<string> {
  const digest = await getSubtle().digest('SHA-256', bytes(decodeBase64(inputBase64)));
  return encodeBase64(new Uint8Array(digest));
}

/**
 * HMAC-SHA256 over WebCrypto. Base64 key and data in, base64 MAC out.
 * One documented difference from CommonCrypto: WebCrypto rejects a
 * zero-length HMAC key at importKey. No caller passes one (the app keeps
 * SHA/HMAC on the JS path because isNativeShaAvailable is false), so this is
 * noted rather than papered over.
 */
export async function hmacSha256(keyBase64: string, dataBase64: string): Promise<string> {
  const subtle = getSubtle();
  const key = await subtle.importKey(
    'raw',
    bytes(decodeBase64(keyBase64)),
    { name: 'HMAC', hash: 'SHA-256' },
    false,
    ['sign']
  );
  const mac = await subtle.sign('HMAC', key, bytes(decodeBase64(dataBase64)));
  return encodeBase64(new Uint8Array(mac));
}

/**
 * Deliberately false: keeps every SHA/HMAC/ratchet path in
 * config/encryption.js on the pinned synchronous JS implementation, exactly
 * as the jest test double does. See the file header.
 */
export const isNativeShaAvailable = false;

// ────────────────────────────────────────────────────────────────────
// ML-KEM-768 (NIST FIPS 203) via @noble/post-quantum. The shapes below
// match the native module byte for byte so config/encryption.js cannot
// tell which platform answered.
// ────────────────────────────────────────────────────────────────────

export interface MLKEMKeyPair {
  /** Base64-encoded public key (1184 bytes) */
  publicKey: string;
  /** Base64-encoded secret key (2400 bytes) */
  secretKey: string;
}

export interface MLKEMEncapResult {
  /** Base64-encoded ciphertext (1088 bytes), sent to the recipient */
  ciphertext: string;
  /** Base64-encoded shared secret (32 bytes), combined with the classical secret */
  sharedSecret: string;
}

/** True: noble is always present on web, so PQ is never disabled here. */
export const isNativeMlKemAvailable = true;

/**
 * Generate an ML-KEM-768 key pair. Coins come from randomBytes by default;
 * pass a base64 string of exactly 64 bytes for deterministic keygen (the
 * shape derivePqCoinsFromPhrase in config/encryption.js produces). noble
 * checks the coin length itself and throws on anything but 64 bytes, which
 * matches the native module rejecting bad coins.
 */
export async function mlkem768Keygen(coins?: string): Promise<MLKEMKeyPair> {
  const coinsB64 = coins ?? (await randomBytes(64));
  const kp = ml_kem768.keygen(bytes(decodeBase64(coinsB64)));
  return { publicKey: encodeBase64(kp.publicKey), secretKey: encodeBase64(kp.secretKey) };
}

/**
 * Encapsulate to a recipient's ML-KEM-768 public key. Random 32-byte coins
 * from the CSPRNG by default; pass explicit base64 coins for tests. noble
 * names the output cipherText; the native module and its callers say
 * ciphertext, so it is renamed here.
 */
export async function mlkem768Encapsulate(
  publicKeyBase64: string,
  coins?: string
): Promise<MLKEMEncapResult> {
  const coinsB64 = coins ?? (await randomBytes(32));
  const res = ml_kem768.encapsulate(
    bytes(decodeBase64(publicKeyBase64)),
    bytes(decodeBase64(coinsB64))
  );
  return { ciphertext: encodeBase64(res.cipherText), sharedSecret: encodeBase64(res.sharedSecret) };
}

/**
 * Decapsulate with our ML-KEM-768 secret key. Implicit rejection by
 * contract: on a bad ciphertext noble returns a pseudo-random secret instead
 * of throwing, exactly as the native module does, so a tampered envelope
 * simply fails to decrypt later.
 */
export async function mlkem768Decapsulate(
  ciphertextBase64: string,
  secretKeyBase64: string
): Promise<string> {
  const ss = ml_kem768.decapsulate(
    bytes(decodeBase64(ciphertextBase64)),
    bytes(decodeBase64(secretKeyBase64))
  );
  return encodeBase64(ss);
}
