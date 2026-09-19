// Test-runner backend for modules/native-crypto.
//
// ── WHY THIS EXISTS ─────────────────────────────────────────────────────────
// modules/native-crypto calls requireNativeModule('NativeCrypto'), which only
// resolves inside a real iOS/Android build. Under bare jest the require throws,
// config/encryption.js sets _e.pqDisabled = true, and every ML-KEM-768 entry
// point returns null. __tests__/x3dh-pq.test.js and
// __tests__/senderKeyHybrid.test.js then fail on purpose, with a message saying
// the post-quantum layer — the app's headline security claim — was not
// exercised at all. A green suite that silently skipped it would be worse than
// a red one, so those tests are deliberately loud.
//
// This module resolves that the RIGHT way: by supplying a real ML-KEM-768
// implementation to the test runner, so the PQ tests actually run the protocol
// and verify that sender and receiver derive matching session root keys. It is
// NOT a stub — the maths is @noble/post-quantum's FIPS-203 implementation, and
// its key/ciphertext sizes match the native PQClean module exactly
// (public 1184, secret 2400, ciphertext 1088, shared secret 32).
//
// ── WHAT THIS DOES NOT CLAIM ────────────────────────────────────────────────
// It exercises the PROTOCOL wiring (encapsulate/decapsulate, envelope framing,
// the hybrid KDF), not the native binding. Verifying the shipped PQClean C code
// still requires a device/simulator runner. That is a smaller gap than "PQ was
// never tested", which is what the alternative was.
//
// ── WHY NOT IN THE APP ──────────────────────────────────────────────────────
// @noble/post-quantum is a devDependency and this file is wired in through
// jest.config.js moduleNameMapper ONLY, so Metro never resolves either of them
// and the shipped bundle is byte-identical. That matters: config/encryption.js
// records that the previous pure-JS `mlkem` package was REMOVED because its ESM
// package.exports shape broke Metro's resolver under Hermes lazy-load. Putting
// a JS PQ implementation back into the production path would risk repeating
// exactly that. Production behaviour is unchanged: on device the native module
// answers, and where it does not, PQ still degrades to classical as before.

const { ml_kem768 } = require('@noble/post-quantum/ml-kem.js');

const toB64 = (bytes) => Buffer.from(bytes).toString('base64');
const fromB64 = (b64) => new Uint8Array(Buffer.from(b64, 'base64'));

/**
 * Deliberately false. The SHA/HMAC/PBKDF2 fast path in config/encryption.js is
 * guarded on this flag, so leaving it false keeps every non-PQ test running
 * against exactly the same JS implementations it does today. The only behaviour
 * this double changes is that ML-KEM becomes available.
 */
const isNativeShaAvailable = false;

const isNativeMlKemAvailable = true;

/** @param {string} [coins] base64, 64 bytes, for deterministic keygen. */
async function mlkem768Keygen(coins) {
  const kp = coins ? ml_kem768.keygen(fromB64(coins)) : ml_kem768.keygen();
  // Native returns { publicKey, secretKey }; pqGenerateKeyPair renames
  // secretKey -> privateKey itself, so match the native shape exactly.
  return { publicKey: toB64(kp.publicKey), secretKey: toB64(kp.secretKey) };
}

/** @param {string} [coins] base64, 32 bytes, for deterministic encapsulation. */
async function mlkem768Encapsulate(publicKeyBase64, coins) {
  const pk = fromB64(publicKeyBase64);
  const res = coins
    ? ml_kem768.encapsulate(pk, fromB64(coins))
    : ml_kem768.encapsulate(pk);
  // noble calls it cipherText; the native module and its callers say ciphertext.
  return {
    ciphertext: toB64(res.cipherText || res.ciphertext),
    sharedSecret: toB64(res.sharedSecret),
  };
}

/**
 * Constant-time by contract: ML-KEM returns a pseudo-random shared secret on
 * KEM failure rather than throwing, and noble implements that, so a malformed
 * ciphertext yields a wrong-but-well-formed secret exactly as the native module
 * does. Tests that assert a tampered envelope fails to decrypt rely on this.
 */
async function mlkem768Decapsulate(ciphertextBase64, secretKeyBase64) {
  const ss = ml_kem768.decapsulate(fromB64(ciphertextBase64), fromB64(secretKeyBase64));
  return toB64(ss);
}

module.exports = {
  isNativeShaAvailable,
  isNativeMlKemAvailable,
  mlkem768Keygen,
  mlkem768Encapsulate,
  mlkem768Decapsulate,
};
