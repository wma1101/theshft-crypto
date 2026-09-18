// Test-runner stub for config/storage.js (AsyncStorage-backed local
// key/value store in the app). Backed by an in-memory Map.
const mem = new Map();

const KEYS = {
  IDENTITY_PHRASE: 'identityPhrase',
  IDENTITY_KEYPAIR: 'identityKeyPair',
  SIGNED_PREKEY: 'signedPrekey',
  ONE_TIME_PREKEYS: 'oneTimePrekeys',
  PQ_IDENTITY: 'pqIdentity',
  RATCHET_STATE: 'ratchetState',
  SENDER_KEYS: 'senderKeys',
  SKIPPED_KEYS: 'skippedKeys',
  DEVICE_ID: 'deviceId',
  PIN_HASH: 'pinHash',
  PIN_SALT: 'pinSalt',
};

module.exports = {
  KEYS,
  getLocal: async (key) => (mem.has(key) ? mem.get(key) : null),
  saveLocal: async (key, value) => { mem.set(key, value); },
  removeLocal: async (key) => { mem.delete(key); },
  probeLocal: async (key) => mem.has(key),
  getIdentityPhrase: async () => (mem.has(KEYS.IDENTITY_PHRASE) ? mem.get(KEYS.IDENTITY_PHRASE) : null),
};
