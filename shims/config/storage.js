// Test-runner stub for config/storage.js (AsyncStorage-backed local
// key/value store in the app). Backed by an in-memory Map.
const mem = new Map();

// Names and values copied verbatim from the app's config/storage.js KEYS
// table, restricted to the entries config/encryption.js actually reads
// (grep 'KEYS\.' in config/encryption.js). scripts/publish-crypto-repo.js
// checks every KEYS.X referenced there exists here before it will publish.
const KEYS = {
  USER: '@user',
  HAS_COMPLETED_SETUP: '@has_completed_setup',
  IDENTITIES: '@identities',
  ACTIVE_IDENTITY: '@active_identity',
  PIN_LENGTH: '@pin_length',
  SIGNED_PREKEY_ID: '@signed_prekey_id',
  SIGNED_PREKEY_PRIVATE_PREV: '@signed_prekey_private_prev',
};

module.exports = {
  KEYS,
  getLocal: async (key) => (mem.has(key) ? mem.get(key) : null),
  saveLocal: async (key, value) => { mem.set(key, value); },
  removeLocal: async (key) => { mem.delete(key); },
  probeLocal: async (key) => mem.has(key),
  getIdentityPhrase: async () => (mem.has(KEYS.IDENTITY_PHRASE) ? mem.get(KEYS.IDENTITY_PHRASE) : null),
};
