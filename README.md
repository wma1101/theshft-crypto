# theSHFT Crypto v7.1.0

End-to-end encryption module used by [theSHFT](https://theshft.app). Signal-compatible protocol with ML-KEM-768 post-quantum hybrid encryption (active).

## Protocol Overview

theSHFT uses the same encryption protocol as Signal, plus an active post-quantum hybrid layer powered by the PQClean reference implementation of ML-KEM-768 (NIST FIPS 203). Every message is encrypted with both Curve25519 and ML-KEM-768 — an attacker must break BOTH to recover the plaintext.

- **HKDF-SHA256** (RFC 5869) for all key derivation
- **X3DH** (Extended Triple Diffie-Hellman) for session establishment
- **Double Ratchet** with per-message forward secrecy
- **Curve25519** for Diffie-Hellman key exchange
- **XSalsa20-Poly1305** for authenticated message encryption
- **ML-KEM-768** (CRYSTALS-Kyber, NIST FIPS 203) for post-quantum hybrid encryption — active on 1:1 chats (groups use classical Sender Keys)
- **Sender Keys** for efficient group encryption
- **Sealed Sender** for sender-identity hiding from the server
- **Cross-signing** for device verification

## Key Derivation (Signal-Compatible)

### KDF Chain Step
```
message_key  = HMAC-SHA256(chain_key, 0x01)
next_chain   = HMAC-SHA256(chain_key, 0x02)
```

### KDF Root Step
```
(root_key, chain_key) = HKDF(
  salt = current_root_key,
  ikm  = DH_output,
  info = "WhisperRatchet",
  len  = 64
)
```

### X3DH Master Secret
```
IKM = 0xFF[32] || DH1 || DH2 || DH3 [|| DH4]
master_secret = HKDF(
  salt = 0x00[32],
  ikm  = IKM,
  info = "theSHFT_X3DH_v2",
  len  = 32
)
```

Where:
- `DH1 = DH(sender_identity, recipient_signed_prekey)`
- `DH2 = DH(sender_ephemeral, recipient_identity)`
- `DH3 = DH(sender_ephemeral, recipient_signed_prekey)`
- `DH4 = DH(sender_ephemeral, recipient_one_time_prekey)` (if available)
- `0xFF[32]` — discontinuity bytes (prevents invalid curve attacks)

## X3DH Key Agreement

1. Each user publishes signed prekeys (rotated every 7 days) and one-time prekeys to the server.
2. Signed prekeys are verified via Ed25519 signatures derived from the identity key.
3. The sender performs 3–4 DH operations against the recipient's prekey bundle.
4. Both sides derive the same master secret via HKDF without ever transmitting it.
5. One-time prekeys are consumed atomically via a rate-limited Cloud Function (5 per hour per user).
6. Previous signed-prekey private key is retained for a 48-hour grace period after rotation.

## Double Ratchet (Forward Secrecy)

Each conversation maintains a ratchet session with:
- **Root key** that evolves with each DH ratchet step
- **Send chain key** and **receive chain key** for symmetric ratcheting
- **Ephemeral DH key pairs** that rotate on each send/receive direction change

### Per-message procedure

1. Each message derives a unique encryption key from the chain via HMAC.
2. The chain advances and the old key is securely zeroed (forward secrecy).
3. When the conversation direction changes, a DH ratchet step occurs:
   - New ephemeral key pair generated.
   - DH with the other party's ephemeral key.
   - Root key and chain keys rotated via HKDF.
4. Compromising one message key cannot reveal past or future messages.

### Out-of-order handling
- Up to 256 skipped message keys cached per session (DoS cap).
- Skipped keys indexed by `(chain_id, message_index)` for cross-chain lookup.
- Keys securely zeroed after use.

### Session persistence
- Sessions encrypted at rest using NaCl secretbox.
- Encryption key stored in device Keychain / SecureStore.
- Sessions survive app restarts but not device wipes.

## ML-KEM-768 Post-Quantum Hybrid

theSHFT ships a hybrid encryption path that combines classical Curve25519 with ML-KEM-768 (CRYSTALS-Kyber, NIST FIPS 203) so that breaking the message requires breaking *both* X25519 *and* the post-quantum lattice problem.

### PQ Functions
- `pqGenerateKeyPair` — generate ML-KEM-768 key pair.
- `pqEncapsulate` — derive shared secret + ciphertext from recipient's PQ public key.
- `pqDecapsulate` — recover shared secret using PQ private key.
- `derivePqKeysFromPhrase` — deterministic PQ key derivation from BIP39 recovery phrase.

### Hybrid Encrypt
```
classical_secret = ECDH(my_priv_x25519, their_pub_x25519)
pq_secret, pq_ct = ML-KEM-768.encap(their_pq_pub)
combined_key     = SHA-256(classical_secret || pq_secret || "hybrid_v1")
ciphertext       = NaCl.secretbox(pad256(plaintext), nonce, combined_key)
wire             = "hybrid:" + b64(nonce) + ":" + b64(ciphertext)
```

The PQ ciphertext (`pq_ct`) is delivered alongside the message envelope. The recipient combines `ML-KEM-768.decap(my_pq_priv, pq_ct)` with the classical ECDH output, derives the same `combined_key`, and decrypts.

### Status

**ACTIVE in 7.1.0.** Implementation: the PQClean reference port of ML-KEM-768 is vendored in `modules/native-crypto/cpp/mlkem768/` and compiled natively on each platform:

- **iOS:** CocoaPod compiles the C sources alongside the Swift module; the Objective-C `MLKEMBridge` wraps PQClean's `_derand` API. Coins are sourced from `SecRandomCopyBytes`.
- **Android:** NDK + CMake (`android/CMakeLists.txt`) builds `libmlkem768.so`; the JNI wrapper (`android/src/main/cpp/mlkem_jni.c`) bridges to Kotlin. Coins are sourced from `java.security.SecureRandom`.

The pure-JS `mlkem` package was retired — its ESM `package.exports` was incompatible with Metro under Hermes lazy-loading. PQClean is constant-time C from the canonical NIST-PQC repository, audited for side-channel resistance.

Runtime kill-switch: `_pqDisabled = true` in `config/encryption.js` forces classical-only fallback without a code push.

## Sender Keys (Group Encryption)

Group messages use Sender Keys instead of per-recipient encryption to keep send cost O(1) regardless of group size:

- `generateSenderKey` — fresh chain key per sender per group.
- `rotateSenderKey` — automatic rotation every 100 messages by default.
- `decryptWithKeyChain` — derive any past message key from the current chain.
- `distributeSenderKey` — encrypted delivery to each member.
- `receiveSenderKey` — incorporate a peer's sender key into your local store.

Sender Key distributions themselves use the underlying X3DH/Ratchet 1-to-1 channel.

## Sealed Sender

Server-side metadata is stripped — the server only sees `'sealed'` for the message's `from` and `fromUsername` fields:

- `generateSenderCertificate` (Ed25519, certificate version 2) — short-lived sender cert signed by your identity key.
- `verifySenderCertificate` — recipient verifies cert + signature.
- `sealMessage` / `unsealMessage` — wrap / unwrap the envelope.
- Server-side `actualSenderId` validation in the messaging Cloud Function.

Wire prefix: `sealed:<recipientId>:<nonce_b64>:<ciphertext_b64>`.

## Wire Formats

| Prefix | Meaning |
|---|---|
| `nacl:<nonce>:<ct>` | Legacy NaCl box, unpadded |
| `naclp:<nonce>:<ct>` | NaCl box, padded |
| `ratchet:<pn>:<i>:<nonce>:<ct>:<eph_pub>` | Double Ratchet message |
| `hybrid:<nonce>:<ct>` | Curve25519 + ML-KEM-768 hybrid (active) |
| `sealed:<recipientId>:<nonce>:<ct>` | Sealed sender envelope |
| `ENCNP:<header><nonce>:<ct>` | Encrypted media (padded) |
| `ENCN:<nonce>:<ct>` | Encrypted media (unpadded) |

## Other Primitives

### Message Padding
Messages padded to 256-byte buckets with a 4-byte length prefix and random fill. Prevents traffic analysis from revealing message length. Used on every encrypt path: 1-to-1 box, media, ratchet, hybrid, sender keys, MLS.

### Cross-Signing
Multi-device key signing for trust transfer:
- `generateCrossSigningKeys` — master, self-signing, user-signing keys.
- `signDeviceKey` — sign a new device's identity key from a verified device.
- `verifyDeviceSignature` — recipient verifies a device key chain.
- `verifyCrossSigningChain` — verify a contact's cross-signing chain.
- `signUserMasterKey` — sign a contact's master key after verification.

### Safety Numbers
Each conversation has a unique 60-digit safety number derived from both users' identity public keys for out-of-band verification:
- `computeSafetyNumber(myIdentity, theirIdentity)`
- `checkKeyChange(theirCachedIdentity, theirCurrentIdentity)`
- `acknowledgeKeyChange(conversationId, newKey)`

### TreeKEM / MLS Scaffolding
Group epoch keying primitives present for future migration:
- `generateTreeKEMLeaf`
- `computeTreePath`
- `deriveGroupEpochKey`
- `encryptMLS` / `decryptMLS`

### Backup Encryption
Passphrase-based offline backup:
- `deriveBackupKey(passphrase, salt)` — Argon2-equivalent KDF (PBKDF2 fallback).
- `encryptBackup(plaintext, key)`
- `decryptBackup(ciphertext, key)`

### PBKDF2 PIN Hashing
User PINs are hashed with PBKDF2-HMAC-SHA256 at 10,000 iterations with a per-user random salt. Native acceleration via `react-native-quick-crypto` (10–50× faster than pure JS).

### Secure Shred
Multi-pass overwrite for sensitive material:
- `secureShred(buffer)` — overwrite, then zero.
- `secureShredBatch([buffers])`
- `secureShredSession(sessionId)` — purge ratchet session + all derived keys.

### Emergency Kill Switch
The ratchet can be disabled at runtime via a SecureStore flag (`KEYS.RATCHET_ENABLED = false`) without a code update. Falls back to legacy NaCl box encryption.

### Sealed Sender Server Validation
The Cloud Function that delivers sealed messages independently validates that the unsealed `actualSenderId` is a participant of the destination conversation, preventing impersonation via sealed envelopes.

## What's NOT in this repo

- App UI, navigation, screens
- Firebase / Firestore configuration
- Cloud Functions (one-time prekey consumption, message delivery, cleanup)
- Business logic
- Server infrastructure (Go relay, R2 worker)

This repo contains only the cryptographic primitives. The full app is private.

## Dependencies

- `tweetnacl` ^1.0.3
- `tweetnacl-util` ^0.15.1
- `tweetnacl-sealed-box` ^1.1.0
- `bip39` ^3.1.0 (recovery phrase)
- `react-native-quick-crypto` (native PBKDF2 / SHA / HMAC acceleration)
- **PQClean ML-KEM-768** (vendored C source, MIT-equivalent license — see `modules/native-crypto/cpp/mlkem768/LICENSE`)

## License

MIT
