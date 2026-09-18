// config/encryption.js ships with ES module import/export syntax (Metro
// compiles that in the app). Jest here runs under plain Node, so this
// preset does the same ESM-to-CommonJS transform, nothing else.
module.exports = {
  presets: [['@babel/preset-env', { targets: { node: 'current' } }]],
};
