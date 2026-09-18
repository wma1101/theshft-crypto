// verifyUnlockPin — constant-time unlock verification (KAN-20, duress timing).
//
// This proves the SELECTION logic (main / duress / none) is correct. The actual
// security property — that all outcomes take the SAME time — is NOT unit-testable
// (it's the on-device Welch's t-test); this only guards against a result-mapping
// regression. PBKDF2 runs in the JS fallback here, so the suite is slow.

jest.mock('expo-secure-store', () => {
  let bag = {};
  return {
    getItemAsync: jest.fn(async (k) => (k in bag ? bag[k] : null)),
    setItemAsync: jest.fn(async (k, v) => { bag[k] = v; }),
    deleteItemAsync: jest.fn(async (k) => { delete bag[k]; }),
  };
});

const { saveSecurePin, deleteSecurePin, verifyUnlockPin, clearPinCache } = require('../config/encryption');

describe('verifyUnlockPin', () => {
  jest.setTimeout(120000); // PBKDF2 JS fallback is slow

  beforeEach(async () => { await clearPinCache(); });

  // saveSecurePin now rejects trivially-weak PINs at the storage chokepoint
  // (the create/change UI also gates them). Fixtures below use non-trivial PINs.
  test('rejects a trivially-weak PIN by default, accepts it only with allowWeak', async () => {
    expect(await saveSecurePin('1234', 'main')).toBe(false); // sequential → refused
    expect(await saveSecurePin('0000', 'main')).toBe(false); // repeated → refused
    expect(await saveSecurePin('1234', 'main', { allowWeak: true })).toBe(true); // migration/restore path
    await deleteSecurePin('main');
  });

  test('selects main / duress / none correctly', async () => {
    expect(await saveSecurePin('1357', 'main')).toBe(true);
    expect(await saveSecurePin('2846', 'duress')).toBe(true);
    await clearPinCache();

    expect(await verifyUnlockPin('1357')).toBe('main');
    expect(await verifyUnlockPin('2846')).toBe('duress');
    expect(await verifyUnlockPin('0000')).toBe('none'); // neither
  });

  test('with NO duress configured: main still verifies, wrong is none (no crash)', async () => {
    await saveSecurePin('1357', 'main');
    await deleteSecurePin('duress');
    await clearPinCache();

    expect(await verifyUnlockPin('1357')).toBe('main');
    expect(await verifyUnlockPin('9999')).toBe('none');
  });

  test('the duress PIN does NOT also match as main (distinct salts)', async () => {
    await saveSecurePin('8264', 'main');
    await saveSecurePin('9513', 'duress');
    await clearPinCache();
    // Each maps to exactly one type.
    expect(await verifyUnlockPin('9513')).toBe('duress');
    expect(await verifyUnlockPin('8264')).toBe('main');
  });

  // Symmetry guard (KAN-20 audit): verifyUnlockPin must do IDENTICAL Keychain
  // I/O whether or not duress is configured — otherwise "duress exists" is
  // timeable one layer below the verify body. Locks _unlockReadSecure's fixed
  // read pattern against a future refactor reintroducing a hit/miss branch.
  test('does identical Keychain reads with vs without a duress PIN configured', async () => {
    const SecureStore = require('expo-secure-store');

    await saveSecurePin('1357', 'main');
    await deleteSecurePin('duress');
    await clearPinCache();
    SecureStore.getItemAsync.mockClear();
    await verifyUnlockPin('1357');
    const readsMainOnly = SecureStore.getItemAsync.mock.calls.length;

    await saveSecurePin('2846', 'duress');
    await clearPinCache();
    SecureStore.getItemAsync.mockClear();
    await verifyUnlockPin('1357');
    const readsBoth = SecureStore.getItemAsync.mock.calls.length;

    expect(readsMainOnly).toBeGreaterThan(0);
    expect(readsBoth).toBe(readsMainOnly); // configured-vs-not → identical I/O
  });
});
