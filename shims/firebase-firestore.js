// Test-runner stub for firebase/firestore. The one call site in
// config/encryption.js is wrapped in try/catch alongside config/database.js,
// so these throw rather than silently returning fake data.
module.exports = {
  doc: () => { throw new Error('firebase/firestore is not available outside the app runtime'); },
  getDoc: () => { throw new Error('firebase/firestore is not available outside the app runtime'); },
};
