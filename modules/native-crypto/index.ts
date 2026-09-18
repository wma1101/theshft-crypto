import { requireNativeModule } from 'expo-modules-core';

const NativeCrypto = requireNativeModule('NativeCrypto');

/**
 * Native PBKDF2-HMAC-SHA256 key derivation.
 * Uses CommonCrypto on iOS, javax.crypto on Android.
 * 10-50x faster than JavaScript implementation.
 */
export async function pbkdf2(
  password: string,
  salt: string,
  iterations: number,
  keyLength: number
): Promise<string> {
  return NativeCrypto.pbkdf2(password, salt, iterations, keyLength);
}

/**
 * Native random bytes generation.
 * iOS: SecRandomCopyBytes. Android: SecureRandom.
 */
export async function randomBytes(length: number): Promise<string> {
  return NativeCrypto.randomBytes(length);
}

/**
 * Native SHA-256 hash. Hardware-accelerated.
 */
export async function sha256(inputBase64: string): Promise<string> {
  return NativeCrypto.sha256(inputBase64);
}

/**
 * Native HMAC-SHA256.
 */
export async function hmacSha256(keyBase64: string, dataBase64: string): Promise<string> {
  return NativeCrypto.hmacSha256(keyBase64, dataBase64);
}

/**
 * Whether the native module exposes the SHA / HMAC entry points.
 * Older binaries don't have them — callers should JS-fall-back when false.
 */
export const isNativeShaAvailable: boolean =
  !!NativeCrypto && typeof NativeCrypto.sha256 === 'function';

// ────────────────────────────────────────────────────────────────────
// ML-KEM-768 (CRYSTALS-Kyber, NIST FIPS 203) — post-quantum hybrid.
// Powered by vendored PQClean reference implementation. Constant-time
// C, hardware-friendly, native to both iOS (CommonCrypto-adjacent) and
// Android (NDK + JNI). The JS layer never touches the lattice math.
// ────────────────────────────────────────────────────────────────────

export interface MLKEMKeyPair {
  /** Base64-encoded public key (1184 bytes) */
  publicKey: string;
  /** Base64-encoded secret key (2400 bytes) */
  secretKey: string;
}

export interface MLKEMEncapResult {
  /** Base64-encoded ciphertext (1088 bytes) — sent to recipient */
  ciphertext: string;
  /** Base64-encoded shared secret (32 bytes) — combined with classical secret */
  sharedSecret: string;
}

/**
 * Whether the native module exposes ML-KEM-768. False on stale binaries
 * (pre-7.1.0) where the C sources weren't compiled in. Callers can use
 * this to decide whether to attempt PQ key generation or skip silently.
 */
export const isNativeMlKemAvailable: boolean =
  !!NativeCrypto && typeof NativeCrypto.mlkem768Keygen === 'function';

/**
 * Generate an ML-KEM-768 key pair. Random coins are pulled from the
 * platform CSPRNG by default. Pass an explicit base64 `coins` string of
 * exactly 64 bytes for deterministic key generation (e.g. derived from
 * a recovery phrase).
 */
export async function mlkem768Keygen(coins?: string): Promise<MLKEMKeyPair> {
  const coinsB64 = coins ?? (await randomBytes(64));
  return NativeCrypto.mlkem768Keygen(coinsB64);
}

/**
 * Encapsulate to a recipient's ML-KEM-768 public key. Returns the
 * ciphertext (sent over the wire) and the 32-byte shared secret (mixed
 * into the hybrid KDF locally). Random coins from CSPRNG by default;
 * pass explicit 32-byte base64 `coins` for tests.
 */
export async function mlkem768Encapsulate(
  publicKeyBase64: string,
  coins?: string
): Promise<MLKEMEncapResult> {
  const coinsB64 = coins ?? (await randomBytes(32));
  return NativeCrypto.mlkem768Encapsulate(publicKeyBase64, coinsB64);
}

/**
 * Decapsulate a ciphertext using our ML-KEM-768 secret key. Returns the
 * 32-byte shared secret as base64. Constant-time: returns a pseudo-random
 * value on KEM-failure rather than throwing, by design.
 */
export async function mlkem768Decapsulate(
  ciphertextBase64: string,
  secretKeyBase64: string
): Promise<string> {
  return NativeCrypto.mlkem768Decapsulate(ciphertextBase64, secretKeyBase64);
}
