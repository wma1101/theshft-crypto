# theSHFT Crypto v4.0.0

End-to-end encryption module used by [theSHFT](https://theshft.app). Signal-compatible protocol implementation.

## Protocol Overview

theSHFT uses the same encryption protocol as Signal:

- **HKDF-SHA256** (RFC 5869) for all key derivation
- **X3DH** (Extended Triple Diffie-Hellman) for session establishment
- **Double Ratchet** with per-message forward secrecy
- **Curve25519** for Diffie-Hellman key exchange
- **XSalsa20-Poly1305** for authenticated message encryption

## Key Derivation (Signal-Compatible)

### KDF Chain Step
Derives per-message encryption keys from the symmetric chain:
```
message_key  = HMAC-SHA256(chain_key, 0x01)
next_chain   = HMAC-SHA256(chain_key, 0x02)
```

### KDF Root Step
Rotates the root key and derives a new chain key after each DH ratchet:
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
- `0xFF[32]` = 32 discontinuity bytes (prevents invalid curve attacks)

## X3DH Key Agreement

1. Each user publishes signed prekeys (rotated every 7 days) and one-time prekeys to the server
2. Signed prekeys are verified via Ed25519 signatures derived from the identity key
3. The sender performs 3-4 DH operations against the recipient's prekey bundle
4. Both sides derive the same master secret via HKDF without ever transmitting it
5. One-time prekeys are consumed atomically via a rate-limited server function (5/hour)
6. Previous signed prekey private is retained for a 48-hour grace period after rotation

## Double Ratchet (Forward Secrecy)

Each conversation maintains a ratchet session with:
- **Root key** that evolves with each DH ratchet step
- **Send chain key** and **receive chain key** for symmetric ratcheting
- **Ephemeral DH key pairs** that rotate on each send/receive direction change

### How it works

1. Each message derives a unique encryption key from the chain via HMAC
2. The chain advances and the old key is deleted (forward secrecy)
3. When the conversation direction changes (A sends, then B sends), a DH ratchet step occurs:
   - New ephemeral key pair generated
   - DH with the other party's ephemeral key
   - Root key and chain keys rotated via HKDF
4. Compromising one message key cannot reveal past or future messages

### Out-of-Order Messages
- Up to 256 skipped message keys are cached per session
- Skipped keys are indexed by `(chain_id, message_index)` for cross-chain handling
- Keys are securely zeroed after use

### Session Persistence
- Sessions are encrypted at rest using NaCl secretbox
- Encryption key stored in device Keychain/SecureStore (not AsyncStorage)
- Sessions survive app restarts but not device wipes

## Wire Formats

- **Ratchet (v2):** `ratchet:<prev_chain_len>:<index>:<nonce_b64>:<ciphertext_b64>:<ephemeral_pub_b64>`
- **Legacy NaCl:** `naclp:<nonce_b64>:<ciphertext_b64>` (padded) or `nacl:<nonce_b64>:<ciphertext_b64>` (unpadded)
- **Media:** `ENCNP:<optional_header><nonce_b64>:<ciphertext_b64>` (padded)

## Other Primitives

### Message Padding
Messages are padded to 256-byte blocks with a 4-byte length prefix and random fill. Prevents traffic analysis from revealing message length.

### Sealed Sender
Messages can use NaCl sealed boxes so the server never sees the sender identity. Only the recipient's public key is needed to encrypt.

### PBKDF2 PIN Hashing
User PINs are hashed with PBKDF2-HMAC-SHA256 at 10,000 iterations with a per-user random salt. Pure JavaScript, no native dependencies.

### Safety Numbers
Each conversation has a unique 60-digit safety number derived from both users' public keys for out-of-band verification. Key changes trigger automatic warnings.

### Emergency Kill Switch
The ratchet can be disabled at runtime via a storage flag without a code update. Falls back to legacy NaCl box encryption.

## What's NOT in this repo

- App UI, navigation, screens
- Firebase/Firestore configuration
- Cloud Functions (prekey consumption, message deletion)
- Business logic
- Server infrastructure

This repo contains only the cryptographic primitives. The full app is private.

## Dependencies

- `tweetnacl` ^1.0.3
- `tweetnacl-util` ^0.15.1

## License

MIT
