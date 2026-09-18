// Test-runner stand-in for config/secureStore.js. The real file is a thin
// re-export of expo-secure-store (Keychain/Keystore); this does the same,
// so __tests__/verifyUnlockPin.test.js's `jest.mock('expo-secure-store', ...)`
// reaches the same object config/encryption.js reads from.
module.exports = require('expo-secure-store');
