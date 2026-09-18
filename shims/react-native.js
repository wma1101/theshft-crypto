// Test-runner stub for the react-native package. config/encryption.js only
// reads Platform.OS to branch on iOS/Android specifics; Node has neither, so
// this reports a neutral platform.
module.exports = {
  Platform: { OS: 'ios', select: (obj) => obj.ios ?? obj.default },
};
