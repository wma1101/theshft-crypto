# theSHFT encryption module

This repository is a verbatim mirror of `config/encryption.js`, the file
theSHFT (theshft.app) ships inside its iOS app. It is published so the
protocol can be read and reviewed. The app, the server, the moderation code
and the Firestore rules are closed source; only this module is published.
Android is not yet in any store; this mirror will cover it once it is.

This mirror matches **App Store build 69, tag `v9.4.0`**, app commit
`76b0e45770ca640f74074cb3b3a5cb264b300688`. See `MANIFEST.json` for the
exact commit and file hash, and `PARITY.json` for the value the app's own
test suite checks against on every tagged release. The next republish
follows each subsequent App Store release, from that release's tag; this
repository is never republished from `main` between releases. The security
of the app does not rest on this code staying secret (Kerckhoffs's
principle): the same JavaScript already ships inside every installed copy
of the app. Publishing changes who can read it, not what exists.

## What this repository republishes

- `config/encryption.js`: the shipped file, unmodified.
- `config/pinValidation.js`, `config/senderKeyRotation.js`,
  `config/safetyNumberQr.js`: pure supporting modules the tests below
  exercise directly.
- `test-utils/nativeCryptoTestDouble.js` and the vendored tests under
  `__tests__/` and `tests/`: the same protocol tests the app runs, adjusted
  only so they run under plain Node instead of inside the app.
- `modules/native-crypto/`: the vendored ML-KEM-768 native module, the
  PQClean reference C sources, the iOS Swift/Objective-C bridge and the
  Android JNI bridge, exactly as shipped. This code cannot run outside an
  iOS or Android build; the test suite here substitutes a pure JavaScript
  ML-KEM-768 implementation (`@noble/post-quantum`) with matching key and
  ciphertext sizes so the protocol logic is still exercised on every commit.
- `shims/`: thin stand-ins for app-only modules `config/encryption.js`
  imports (local storage, Firestore, React Native, Expo, telemetry). None of
  them touch cryptography; each one is a few lines:
  `shims/react-native.js`, `shims/async-storage.js`,
  `shims/react-native-quick-crypto.js`, `shims/firebase-firestore.js`,
  `shims/expo-file-system.js`, `shims/expo-secure-store.js`,
  `shims/config/perfTracing.js`, `shims/config/environment.js`,
  `shims/config/secureStore.js`, `shims/config/telemetry.js`,
  `shims/config/storage.js`, `shims/config/database.js`,
  `shims/config/dbCrypto.js`, `shims/app/components/Toast.js`.

## What is in scope, and what is not

**In scope, verified against the file in this repository:**

- Direct messages: X3DH key agreement plus a Double Ratchet, using
  Curve25519 (TweetNaCl) and HKDF.
- A post quantum hybrid on direct messages: an ML-KEM-768 (FIPS 203) secret
  is mixed into the session root key, but only when the recipient's prekey
  bundle carries a PQ prekey and the native ML-KEM module loads. This
  happens once, at session start (X3DH), not per message. When either
  condition is not met, the session runs classically and nothing refuses
  or warns about that fallback today (see Known limits).
- Groups: a Sender Key wrapped with the same X25519/ML-KEM hybrid HKDF, using
  the wrap KDF in this repository (`config/senderKeyRotation.js`). Whether
  the wrap runs per member or requires every member to have a PQ public key
  before it applies at all is gating logic that lives in the closed app, not
  in this module.
- The Sender Key ratchet is per message (one key per message, one-way chain)
  on the `skr1` wire, sent only when every member's app supports it;
  otherwise the group falls back to `skey2`, one key per epoch instead of
  per message. Either way, spent ratchet state is not yet deleted (phase B).
- The PIN key derivation is PBKDF2-HMAC-SHA256 at 600,000 iterations on
  every path that sets or checks a PIN today. Lower iteration counts appear
  only as legacy values the verify path still accepts for PINs set before
  the count was raised.
- PBKDF2, SHA-256 and HMAC run through each platform's native crypto
  (CommonCrypto on iOS, `javax.crypto` on Android) when available, with a
  pure JavaScript fallback. ML-KEM-768 runs through the vendored PQClean C
  library, compiled natively for iOS and Android; the JavaScript layer never
  implements the lattice math itself. This build has no web entry point for
  the native module; a later mirror will say so if and when one ships. A
  runtime flag (`pqDisabled`, off by default, set automatically if the
  native module fails to load) forces every PQ function above to return
  `null`, which is the same as the peer having no PQ prekey: the session
  falls back to classical X3DH.
- Local passphrase-protected backup of session and key material
  (`deriveBackupKey`, `encryptBackup`, `decryptBackup`), and a best-effort
  overwrite of sensitive values before they are dropped (`secureShred`,
  `secureShredBatch`, `secureShredSession`) — both present and exported by
  this file; how and when the app calls them is closed-app logic, not
  verifiable from this repository.

**Explicitly not in scope, and not claimed:**

- No sender identity hiding on the send path: the server sees who sent each
  message. A receive side branch for hidden sender envelopes exists, but
  nothing calls the corresponding send path today, so it is not a feature.
- Cross-device key signing code exists in this file (`generateCrossSigningKeys`,
  `signDeviceKey`, `verifyDeviceSignature`, `verifyCrossSigningChain`,
  `signUserMasterKey`), but nothing in this repository or in the app's own
  published claims wires it into a feature; treat it as unused scaffolding,
  not a cross-signing or multi-device verification claim. The only
  contact-verification feature actually claimed is the safety number
  comparison in `config/safetyNumberQr.js`.
- No TreeKEM/MLS. Groups use Sender Key, not a tree-based group protocol.
- No external security audit has been commissioned on this code or on the
  app. This repository is a transparency step, not an audit result.
- This repository is a protocol mirror, not the app. It does not prove the
  compiled app binary matches this source; it proves the source the app was
  built from matches what ships here, checked by file hash.

## Known limits (tracked, with fix status)

1. **The post quantum prekey is not signed.** `generateSignedPrekey` signs
   only the classical X25519 prekey bytes; the ML-KEM-768 prekey it returns
   alongside it is unsigned. A network attacker who can substitute prekeys
   could therefore substitute the PQ prekey without detection today.
   Status: fix in progress (see the app repository's
   `docs/plans/2026-09-18-prekey-binding.md`, "release A"): sign the PQ
   prekey with the same identity signing key and bind the signing public key
   into the safety number.
2. **A downgrade to classical is not refused.** When a peer's bundle has no
   PQ prekey, or the native ML-KEM module fails to load, the session falls
   back to classical X3DH silently. There is no local warning and no refusal
   to proceed. Status: the same prekey-binding release above adds a refusal
   when a peer has previously advertised a PQ key and stops advertising one.
3. **The signed prekey's signing key is unpinned and not in the safety
   number.** `initSessionFromPrekeyBundle` verifies the signed prekey against
   a `signingPublicKey` served beside it in the same server document
   (`fetchPrekeyBundle`). Nothing pins that signing key to the peer across
   sessions, and it is absent from the safety number comparison, so a
   malicious server can swap both the signed prekey and the signing key
   together, re-sign with its own key, and pass verification even for an
   existing contact. Status: pinning and safety number v2 are landing
   together in the prekey-binding release (see the app repository's
   `docs/plans/2026-09-18-prekey-binding.md`); a key transparency log is not
   scheduled.

This section names known weaknesses with enough specificity that a reader
does not need to find them independently. It will be updated, not deleted,
as each item's status changes.

## What this repository does not vendor

`__tests__/senderKeyRatchet.test.js` originally ended with a
"chat.js dispatch census" suite that reads `app/chat.js` by file path to
check the app's message-dispatch code calls the ratchet decoder correctly.
`app/chat.js` is an app screen, not part of the encryption module, so that
suite is not vendored here; the codec-level tests in the rest of the file
(derivation, wire encoding, fail-closed decode) are unaffected and still
run.

## Testing

```
npm ci
npm test
```

This runs the vendored protocol tests (`__tests__/`) against
`config/encryption.js`, using `test-utils/nativeCryptoTestDouble.js` in
place of the native ML-KEM-768 module (wired through `jest.config.js`'s
`moduleNameMapper`, the same mapping the app repository uses in its own
test suite). `tests/crypto-vectors.js` is a standalone known-answer check,
run separately, covering NaCl `box` and `secretbox`, nonce handling, BIP39,
PBKDF2 against the RFC 6070 test vectors, replay rejection, out-of-order
delivery, and sender key rotation. It does not check ML-KEM-768; there is
no ML-KEM-768 known-answer test in this repository today. A public GitHub
Actions workflow (`.github/workflows/vectors.yml`) runs both the vendored
Jest suite and `tests/crypto-vectors.js` on every push and pull request.

## Republishing (for the owner)

`scripts/publish-crypto-repo.js --tag v<app version>` in the app repository
regenerates this repository's `config/`, `test-utils/`, vendored
`__tests__/`, `modules/`, `MANIFEST.json` and `PARITY.json` from the file at
that App Store release tag, never from `main` between releases, because the
mirror must be the file App Store users actually run. Run it, review the diff,
commit on a branch here, then push the same tag once merged to `main`. The
app repository's `__tests__/cryptoParity.test.js` and
`.github/workflows/crypto-parity.yml` (tag-gated) check that the hash
recorded in the app's bundled `config/cryptoParity.json`, shown on the About
screen, still matches `git show <tag>:config/encryption.js` for the tag
`PARITY.json` here records.

## Reporting a vulnerability

See `SECURITY.md`.

## License

MIT. See `LICENSE`.
