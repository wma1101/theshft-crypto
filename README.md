# theSHFT crypto module

This repository publishes `encryption.js`, the local encryption module used
by [theSHFT](https://theshft.app) for one-to-one (direct message) key
agreement and message encryption. The rest of the app — UI, server, Cloud
Functions, Firestore rules, group chat, and everything else — is closed
source; only this one file is published here.

**Version this repository reflects.** `package.json` in this repository is
at version `4.0.0`. The most recent commit to this repository was on
2026-07-07. This repository has not been republished since and does **not**
track theSHFT's current App Store release; treat everything below as a
description of the code actually present in this repository's
`encryption.js`, not of the app as it ships today.

**About the app's current claims.** Separately from this repository, and not
verifiable from the code here, theshft.app currently states that direct
messages, group chats, and calls are end-to-end encrypted, and that stories
and community posts are not. Group chat and call encryption are not
implemented in this file at all, so that current claim cannot be checked
against anything in this repository — it is included here only so a reader
does not mistake this repository's scope for the whole app.

## What is actually in this file

- **X3DH-style key agreement** for starting a session with a contact
  (`generateSignedPrekey`, `verifySignedPrekey`, `generateOneTimePrekeys`,
  `initSessionFromPrekeyBundle`, `initSessionFromFirstMessage`), using
  Curve25519 Diffie-Hellman (TweetNaCl) and HKDF-SHA256 (RFC 5869).
- **A Double Ratchet** (`initRatchetSession`, `ratchetEncrypt`,
  `ratchetDecrypt`) giving each message its own key and rotating the root
  key on direction changes, with a 256-key cap on cached skipped keys as a
  DoS guard.
- **Direct, non-ratcheted NaCl box encryption** (`encryptMessage`,
  `decryptMessage`) and media encryption (`encryptMedia`, `decryptMedia`),
  both using Curve25519-XSalsa20-Poly1305 with 256-byte message padding.
- **PIN hashing** with PBKDF2-HMAC-SHA256 at 10,000 iterations
  (`hashPin`/`verifyPin`), with legacy iteration counts (100,000 and 1,000)
  accepted only to verify PINs set before the current default, so an
  existing PIN can still be checked without being reset.
- **A recovery-phrase key derivation** (`deriveKeysFromPhrase`) that turns a
  user-supplied phrase into a Curve25519 key pair via PBKDF2. This file does
  not validate the phrase against the BIP39 wordlist or vendor a BIP39
  package — any string is accepted as the phrase.
- **Safety numbers** (`computeSafetyNumber`, `checkKeyChange`,
  `acknowledgeKeyChange`): a 60-digit number derived from both parties'
  identity keys, for manual out-of-band verification.

## Post-quantum code in this file: present, but disabled and not real ML-KEM-768

This file also contains `pqGenerateKeyPair`, `pqEncapsulate`,
`pqDecapsulate`, `hybridEncrypt`, and `hybridDecrypt`. The file's own
comments at the top of that section are explicit about their status:

> STATUS: DISABLED. This code is NOT active and provides NO protection.
> All encryption currently uses Curve25519 (classical) only. ... DO NOT
> claim post-quantum protection in any user-facing material.

This is also not an implementation of ML-KEM-768 (CRYSTALS-Kyber, NIST FIPS
203): it is a hand-written, schoolbook ring-LWE style scheme with
conservative (Kyber-512-equivalent) parameters, written in plain JavaScript.
There is no PQClean, no native module, and no NIST-standard KEM anywhere in
this repository. The comments describe it as experimental and prone to
shared-secret mismatches, slated for replacement by a real, audited library.
Nothing in this repository should be read as evidence that post-quantum
protection is active.

## What this file does not do at all

The following were never implemented in this file (this is not a
description of what was stripped out before publishing — the functions do
not exist here):

- No group chat encryption of any kind (no Sender Keys, no per-group
  ratchet).
- No sealed sender / sender-identity hiding from the server. There is no
  `sealMessage`, `unsealMessage`, or sender-certificate code in this file,
  and no `sealed:` wire format is produced or read by anything here.
- No cross-signing or multi-device verification beyond the single safety
  number above.
- No TreeKEM/MLS group protocol.
- No backup encryption (passphrase-based or otherwise).
- No "secure shred" / multi-pass memory wipe function. Values are dropped by
  reassigning the variable, which is not a guaranteed wipe in JavaScript.
- No runtime kill switch for the ratchet or for PQ.

## Wire formats actually produced or read here

| Prefix | Meaning |
|---|---|
| `nacl:<nonce>:<ct>` | Legacy NaCl box, unpadded |
| `naclp:<nonce>:<ct>` | NaCl box, padded |
| `ratchet:<pn>:<i>:<nonce>:<ct>:<eph_pub>` | Double Ratchet message |
| `hybrid:<nonce>:<ct>` | Curve25519 + the disabled experimental PQ scheme above — not in production use (see previous section) |
| `ENCNP:<header><nonce>:<ct>` | Encrypted media (padded) |
| `ENCN:<nonce>:<ct>` | Encrypted media (unpadded) |

## What's not in this repository

- The app itself: UI, navigation, screens
- Firebase / Firestore configuration and rules
- Cloud Functions (prekey issuance and rotation, message delivery, cleanup)
- Business logic
- Server infrastructure

This repository contains only this one client-side file. The full app is
private, and prekey rotation, rate limiting, and delivery are handled by
server-side code that is not published here, so this repository cannot be
used to verify claims about that side of the system.

## Dependencies

Per `package.json`, the only declared dependencies are:

- `tweetnacl` ^1.0.3
- `tweetnacl-util` ^0.15.1

`encryption.js` also imports `@react-native-async-storage/async-storage`
directly and conditionally requires `expo-secure-store`; neither is vendored
or shimmed in this repository, so this file does not run standalone outside
the app it was extracted from, and there is no test suite or CI in this
repository today.

## Reporting a vulnerability

Email support@theshft.app with a description of the issue. Please do not
open a public GitHub issue for a vulnerability report.

## License

MIT. See `LICENSE`.
