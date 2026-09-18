// Test-runner stub for config/database.js (Firestore access in the app).
// The one call site in config/encryption.js is wrapped in try/catch, so
// throwing here exercises that fallback path rather than reaching Firestore.
module.exports = {
  getDb: () => { throw new Error('getDb is not available outside the app runtime'); },
};
