// Test-runner stub for expo-file-system. Used by config/encryption.js for
// media encryption helpers not exercised by the vendored crypto tests.
class File {
  constructor(uri) { this.uri = uri; }
}
const Paths = { document: '/tmp', cache: '/tmp' };
module.exports = { File, Paths };
