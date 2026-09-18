# theSHFT encryption module

This repository is a verbatim mirror of `config/encryption.js`, the file
theSHFT (theshft.app) ships inside its iOS and Android apps. It is published
so the protocol can be read and reviewed. The app, the server, the
moderation code and the Firestore rules are closed source; only this module
is published.

Mirrored from app commit `3d4616a6dc31f6a0060b515087dbdcab0fa970e7`, app
version 9.4.1. See `MANIFEST.json` for the exact commit and file hash, and
`PARITY.json` for the value the app's own test suite checks against on every
tagged release. The security of the app does not rest on this code staying
secret (Kerckhoffs's principle): the same JavaScript already ships inside
every installed copy of the app. Publishing changes who can read it, not
what exists.

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
  them touch cryptography; each one is a few lines and is listed below.

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
- Groups: a Sender Key wrapped with the same X25519/ML-KEM hybrid HKDF, but
  only when every member of the group has published a PQ public key. Group
  PQ is all-or-nothing per key; a single classical member drops the whole
  group key back to classical.
- The Sender Key ratchet is per message (one key per message, one-way
  chain), which limits exposure from a single compromised message key but
  does not yet delete spent ratchet state.
- The PIN key derivation is PBKDF2-HMAC-SHA256 at 600,000 iterations on
  every path that sets or checks a PIN today. Lower iteration counts appear
  only as legacy values the verify path still accepts for PINs set before
  the count was raised.
- PBKDF2, SHA-256 and HMAC run through each platform's native crypto
  (CommonCrypto on iOS, `javax.crypto` on Android) when available, with a
  pure JavaScript fallback. ML-KEM-768 runs through the vendored PQClean C
  library, compiled natively; the JavaScript layer never implements the
  lattice math itself.

**Explicitly not in scope, and not claimed:**

- No sealed sender. There is no code on the send path that hides sender
  identity from the server; a receive-side branch exists but nothing calls
  the corresponding send path today.
- No cross-signing or device-verification protocol beyond the safety number
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
3. **The identity signing key is self-published.** There is no third party
   or transparency log attesting to a user's public key; a compromised
   server could present a substituted key to a new contact. This is the same
   trust model as an unaudited TOFU (trust-on-first-use) safety number
   comparison, not a signed key directory. Status: no fix scheduled; the
   safety number comparison flow is the mitigation today.

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
test suite). A public GitHub Actions workflow
(`.github/workflows/vectors.yml`) runs the same tests, plus a standalone
ML-KEM-768 known-answer check against `@noble/post-quantum`, on every push
and pull request.

## Republishing (for the owner)

`scripts/publish-crypto-repo.js` in the app repository regenerates this
repository's `config/`, `test-utils/`, vendored `__tests__/`, `modules/`,
`MANIFEST.json` and `PARITY.json` from the app's shipped (git `HEAD`) file.
Run it, review the diff, commit on a branch here, then tag the release
(`v<app version>`) once merged to `main`. The app repository's
`__tests__/cryptoParity.test.js` and its tag-gated `crypto-parity` CI job
check that the hash shown in the app's About screen still matches
`PARITY.json` here.

## Reporting a vulnerability

See `SECURITY.md`.

## License

MIT. See `LICENSE`.
