// Test-runner stub for @react-native-async-storage/async-storage.
// __esModule + default is required so Babel's interopRequireDefault does
// not double-wrap this (without it, `import AsyncStorage from '...'`
// resolves to { default: { default: {...} } } instead of the real object).
const mem = new Map();
exports.__esModule = true;
exports.default = {
  getItem: async (key) => (mem.has(key) ? mem.get(key) : null),
  setItem: async (key, value) => { mem.set(key, value); },
  removeItem: async (key) => { mem.delete(key); },
};
