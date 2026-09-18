// Test-runner stub for expo-secure-store, required directly by
// __tests__/verifyUnlockPin.test.js to assert on Keychain/Keystore calls.
const mem = new Map();
module.exports = {
  getItemAsync: async (key) => (mem.has(key) ? mem.get(key) : null),
  setItemAsync: async (key, value) => { mem.set(key, value); },
  deleteItemAsync: async (key) => { mem.delete(key); },
};
