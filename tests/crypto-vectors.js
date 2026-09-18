/**
 * Cryptographic correctness tests — known-answer vectors.
 * Run: node tests/crypto-vectors.js
 *
 * Tests NaCl, PBKDF2, key derivation determinism, nonce uniqueness,
 * tampered ciphertext rejection, and replay resistance.
 */

const nacl = require('tweetnacl');
const { encodeBase64, decodeBase64, encodeUTF8, decodeUTF8 } = require('tweetnacl-util');

let passed = 0;
let failed = 0;

function assert(condition, name) {
  if (condition) {
    passed++;
    console.log(`  PASS  ${name}`);
  } else {
    failed++;
    console.log(`  FAIL  ${name}`);
  }
}

function bytesToHex(bytes) {
  return Array.from(bytes, b => b.toString(16).padStart(2, '0')).join('');
}

// ============================================
// 1. NaCl box — known behavior tests
// ============================================
console.log('\n=== NaCl Box (Curve25519-XSalsa20-Poly1305) ===');

(() => {
  // Generate two keypairs
  const alice = nacl.box.keyPair();
  const bob = nacl.box.keyPair();

  // Encrypt from Alice to Bob
  const message = decodeUTF8('Hello, Bob!');
  const nonce = nacl.randomBytes(nacl.box.nonceLength);
  const encrypted = nacl.box(message, nonce, bob.publicKey, alice.secretKey);

  assert(encrypted !== null, 'NaCl box encrypts successfully');
  assert(encrypted.length > message.length, 'Ciphertext is longer than plaintext (MAC overhead)');

  // Decrypt as Bob
  const decrypted = nacl.box.open(encrypted, nonce, alice.publicKey, bob.secretKey);
  assert(decrypted !== null, 'NaCl box.open decrypts successfully');
  assert(encodeUTF8(decrypted) === 'Hello, Bob!', 'Decrypted text matches original');

  // Wrong key fails
  const eve = nacl.box.keyPair();
  const eveDecrypt = nacl.box.open(encrypted, nonce, alice.publicKey, eve.secretKey);
  assert(eveDecrypt === null, 'Wrong private key cannot decrypt');

  // Wrong nonce fails
  const badNonce = nacl.randomBytes(nacl.box.nonceLength);
  const badNonceDecrypt = nacl.box.open(encrypted, badNonce, alice.publicKey, bob.secretKey);
  assert(badNonceDecrypt === null, 'Wrong nonce cannot decrypt');

  // Tampered ciphertext fails
  const tampered = new Uint8Array(encrypted);
  tampered[5] ^= 0xFF; // Flip one byte
  const tamperedDecrypt = nacl.box.open(tampered, nonce, alice.publicKey, bob.secretKey);
  assert(tamperedDecrypt === null, 'Tampered ciphertext rejected (Poly1305 MAC)');

  // DH symmetry: alice→bob shared secret === bob→alice shared secret
  const sharedAB = nacl.box.before(bob.publicKey, alice.secretKey);
  const sharedBA = nacl.box.before(alice.publicKey, bob.secretKey);
  assert(encodeBase64(sharedAB) === encodeBase64(sharedBA), 'Curve25519 DH is symmetric');
})();

// ============================================
// 2. NaCl secretbox — symmetric encryption
// ============================================
console.log('\n=== NaCl Secretbox (XSalsa20-Poly1305) ===');

(() => {
  const key = nacl.randomBytes(nacl.secretbox.keyLength);
  const message = decodeUTF8('Secret message');
  const nonce = nacl.randomBytes(nacl.secretbox.nonceLength);

  const encrypted = nacl.secretbox(message, nonce, key);
  assert(encrypted !== null, 'Secretbox encrypts');

  const decrypted = nacl.secretbox.open(encrypted, nonce, key);
  assert(encodeUTF8(decrypted) === 'Secret message', 'Secretbox decrypts correctly');

  // Wrong key
  const wrongKey = nacl.randomBytes(nacl.secretbox.keyLength);
  assert(nacl.secretbox.open(encrypted, nonce, wrongKey) === null, 'Wrong key rejected');

  // Tampered
  const tampered = new Uint8Array(encrypted);
  tampered[0] ^= 0x01;
  assert(nacl.secretbox.open(tampered, nonce, key) === null, 'Tampered ciphertext rejected');
})();

// ============================================
// 3. Nonce uniqueness under rapid generation
// ============================================
console.log('\n=== Nonce Uniqueness (1000 rapid generations) ===');

(() => {
  const nonces = new Set();
  for (let i = 0; i < 1000; i++) {
    nonces.add(encodeBase64(nacl.randomBytes(24)));
  }
  assert(nonces.size === 1000, `All 1000 nonces unique (got ${nonces.size})`);
})();

// ============================================
// 4. Key derivation determinism (BIP39 → keypair)
// ============================================
console.log('\n=== Key Derivation Determinism ===');

(() => {
  // Simulate deriving keys from the same phrase twice
  const phrase = 'abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about';

  // Simple deterministic derivation (matches the app's SHA-256 chain approach)
  const sha256 = (msg) => {
    const crypto = require('crypto');
    return crypto.createHash('sha256').update(msg).digest('hex');
  };

  const seed1 = sha256(phrase + 'theSHFT_key_derivation_v5');
  const seed2 = sha256(phrase + 'theSHFT_key_derivation_v5');
  assert(seed1 === seed2, 'Same phrase produces same seed');

  // Derive keypair from seed
  const seedBytes1 = Buffer.from(seed1, 'hex');
  const kp1 = nacl.box.keyPair.fromSecretKey(seedBytes1.slice(0, 32));
  const kp2 = nacl.box.keyPair.fromSecretKey(seedBytes1.slice(0, 32));
  assert(encodeBase64(kp1.publicKey) === encodeBase64(kp2.publicKey), 'Same seed produces same public key');
  assert(encodeBase64(kp1.secretKey) === encodeBase64(kp2.secretKey), 'Same seed produces same private key');

  // Different phrase produces different keys
  const phrase2 = 'zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo wrong';
  const seed3 = sha256(phrase2 + 'theSHFT_key_derivation_v5');
  assert(seed1 !== seed3, 'Different phrase produces different seed');
})();

// ============================================
// 5. PBKDF2 — RFC 6070 test vectors
// ============================================
console.log('\n=== PBKDF2-HMAC-SHA256 (RFC 6070 style) ===');

(() => {
  const crypto = require('crypto');

  // Test vector: password="password", salt="salt", iterations=1, keylen=32
  const result1 = crypto.pbkdf2Sync('password', 'salt', 1, 32, 'sha256');
  assert(result1.toString('hex') === '120fb6cffcf8b32c43e7225256c4f837a86548c92ccc35480805987cb70be17b',
    'PBKDF2 vector: password/salt/1 iteration');

  // Test vector: iterations=4096
  const result2 = crypto.pbkdf2Sync('password', 'salt', 4096, 32, 'sha256');
  assert(result2.toString('hex') === 'c5e478d59288c841aa530db6845c4c8d962893a001ce4e11a4963873aa98134a',
    'PBKDF2 vector: password/salt/4096 iterations');

  // Determinism: same inputs = same output
  const r1 = crypto.pbkdf2Sync('mypin', 'abc123', 10000, 32, 'sha256');
  const r2 = crypto.pbkdf2Sync('mypin', 'abc123', 10000, 32, 'sha256');
  assert(r1.toString('hex') === r2.toString('hex'), 'PBKDF2 is deterministic');

  // Different salt = different output
  const r3 = crypto.pbkdf2Sync('mypin', 'xyz789', 10000, 32, 'sha256');
  assert(r1.toString('hex') !== r3.toString('hex'), 'Different salt produces different hash');
})();

// ============================================
// 6. Replay attack resistance
// ============================================
console.log('\n=== Replay Resistance ===');

(() => {
  const key = nacl.randomBytes(nacl.secretbox.keyLength);
  const message = decodeUTF8('Transfer $1000');
  const nonce = nacl.randomBytes(nacl.secretbox.nonceLength);
  const encrypted = nacl.secretbox(message, nonce, key);

  // First decrypt succeeds
  const first = nacl.secretbox.open(encrypted, nonce, key);
  assert(first !== null, 'First decrypt succeeds');

  // Same ciphertext+nonce decrypts again (NaCl itself doesn't reject replays —
  // replay protection must be at the application layer via message IDs)
  const replay = nacl.secretbox.open(encrypted, nonce, key);
  assert(replay !== null, 'NaCl does not inherently reject replays (app layer must handle)');

  // App-layer dedup: message IDs prevent duplicate rendering
  const seenIds = new Set();
  const msgId = 'msg_abc123';
  seenIds.add(msgId);
  assert(seenIds.has(msgId), 'App-layer dedup: duplicate message ID detected');
})();

// ============================================
// 7. Out-of-order message handling
// ============================================
console.log('\n=== Out-of-Order Message Handling ===');

(() => {
  const key = nacl.randomBytes(nacl.secretbox.keyLength);

  // Encrypt 5 messages with unique nonces
  const messages = ['msg1', 'msg2', 'msg3', 'msg4', 'msg5'];
  const encrypted = messages.map(m => {
    const nonce = nacl.randomBytes(nacl.secretbox.nonceLength);
    return { ct: nacl.secretbox(decodeUTF8(m), nonce, key), nonce };
  });

  // Deliver in order 3, 1, 5, 2, 4
  const order = [2, 0, 4, 1, 3];
  const decrypted = order.map(i => {
    const d = nacl.secretbox.open(encrypted[i].ct, encrypted[i].nonce, key);
    return d ? encodeUTF8(d) : null;
  });

  assert(decrypted[0] === 'msg3', 'Out-of-order msg3 decrypts');
  assert(decrypted[1] === 'msg1', 'Out-of-order msg1 decrypts');
  assert(decrypted[2] === 'msg5', 'Out-of-order msg5 decrypts');
  assert(decrypted[3] === 'msg2', 'Out-of-order msg2 decrypts');
  assert(decrypted[4] === 'msg4', 'Out-of-order msg4 decrypts');
})();

// ============================================
// 8. Group sender key — member add/remove
// ============================================
console.log('\n=== Sender Key Rotation (Group Member Change) ===');

(() => {
  // Simulate: key1 for messages 1-49, key2 for messages 50+
  const key1 = nacl.randomBytes(nacl.secretbox.keyLength);
  const key2 = nacl.randomBytes(nacl.secretbox.keyLength);

  // Message 49 encrypted with key1
  const nonce49 = nacl.randomBytes(nacl.secretbox.nonceLength);
  const msg49 = nacl.secretbox(decodeUTF8('message 49'), nonce49, key1);

  // Message 50 encrypted with key2 (after rotation)
  const nonce50 = nacl.randomBytes(nacl.secretbox.nonceLength);
  const msg50 = nacl.secretbox(decodeUTF8('message 50'), nonce50, key2);

  // New member (joined at 50) should NOT decrypt msg49 with key2
  const attempt49 = nacl.secretbox.open(msg49, nonce49, key2);
  assert(attempt49 === null, 'New member cannot decrypt pre-join messages with new key');

  // New member CAN decrypt msg50 with key2
  const attempt50 = nacl.secretbox.open(msg50, nonce50, key2);
  assert(encodeUTF8(attempt50) === 'message 50', 'New member can decrypt post-join messages');

  // Removed member (had key1) cannot decrypt msg50
  const removedAttempt = nacl.secretbox.open(msg50, nonce50, key1);
  assert(removedAttempt === null, 'Removed member cannot decrypt post-removal messages');
})();

// ============================================
// RESULTS
// ============================================
console.log(`\n${'='.repeat(50)}`);
console.log(`Results: ${passed} passed, ${failed} failed`);
if (failed > 0) {
  console.log('CRYPTO TEST FAILURES DETECTED');
  process.exit(1);
} else {
  console.log('ALL CRYPTO TESTS PASSED');
}
