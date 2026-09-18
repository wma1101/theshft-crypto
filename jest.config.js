module.exports = {
  testEnvironment: 'node',
  transform: {
    '^.+\\.[jt]sx?$': ['babel-jest', { configFile: './babel.config.js' }],
  },
  transformIgnorePatterns: [
    // @noble/post-quantum ships ESM; without this the ML-KEM test double
    // fails to load and the PQ suite is unrunnable. Test only.
    'node_modules/(?!(@noble/.*))',
  ],
  moduleNameMapper: {
    // Same double the app repo's own jest.config.js wires in: a real
    // FIPS-203 ML-KEM-768 implementation (@noble/post-quantum), standing in
    // for the native PQClean module that only exists inside an iOS/Android
    // build. See test-utils/nativeCryptoTestDouble.js for the full rationale.
    'modules/native-crypto$': '<rootDir>/test-utils/nativeCryptoTestDouble.js',

    // Thin stubs for the app-only modules config/encryption.js imports.
    // None of these touch the cryptography; they replace React Native
    // platform APIs, Firestore, local storage and UI helpers that only
    // exist inside the app runtime. Full list and rationale: README.md.
    '^react-native$': '<rootDir>/shims/react-native.js',
    '^@react-native-async-storage/async-storage$': '<rootDir>/shims/async-storage.js',
    '^react-native-quick-crypto$': '<rootDir>/shims/react-native-quick-crypto.js',
    '^firebase/firestore$': '<rootDir>/shims/firebase-firestore.js',
    '^expo-file-system$': '<rootDir>/shims/expo-file-system.js',
    '^expo-secure-store$': '<rootDir>/shims/expo-secure-store.js',
    '^\\./perfTracing$': '<rootDir>/shims/config/perfTracing.js',
    '^\\./environment$': '<rootDir>/shims/config/environment.js',
    '^\\./secureStore$': '<rootDir>/shims/config/secureStore.js',
    '^\\./telemetry$': '<rootDir>/shims/config/telemetry.js',
    '^\\./storage$': '<rootDir>/shims/config/storage.js',
    '^\\./database$': '<rootDir>/shims/config/database.js',
    '^\\./dbCrypto$': '<rootDir>/shims/config/dbCrypto.js',
    '^\\.\\./app/components/Toast$': '<rootDir>/shims/app/components/Toast.js',
  },
};
