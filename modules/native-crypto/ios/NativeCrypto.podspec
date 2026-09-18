Pod::Spec.new do |s|
  s.name           = 'NativeCrypto'
  s.version        = '2.0.0'
  s.summary        = 'Native crypto module for theSHFT (PBKDF2, SHA-256, HMAC-SHA256, ML-KEM-768).'
  s.description    = 'Hardware-accelerated PBKDF2/SHA/HMAC via CommonCrypto plus PQClean ML-KEM-768 hybrid post-quantum encryption.'
  s.author         = 'theSHFT'
  s.homepage       = 'https://theshft.app'
  s.platforms      = { :ios => '15.1' }
  s.source         = { git: '' }
  s.static_framework = true

  # All sources live alongside the podspec in modules/native-crypto/ios/.
  # mlkem768/ holds the vendored PQClean reference implementation.
  s.source_files = [
    '*.{swift,h,m}',
    'mlkem768/**/*.{c,h}',
  ]

  # Bridging headers don't work with framework targets. Instead, expose
  # MLKEMBridge.h as a public header so it's pulled into the framework's
  # auto-generated umbrella header. Swift sources in the same framework
  # then see Objective-C types automatically (no `import` needed because
  # they're already in the same module).
  s.public_header_files = 'MLKEMBridge.h'

  s.pod_target_xcconfig = {
    'HEADER_SEARCH_PATHS' => '"$(PODS_TARGET_SRCROOT)/mlkem768"',
    # PQClean is warning-clean by their conventions; suppress noise the
    # iOS toolchain adds so the build log stays readable.
    'OTHER_CFLAGS' => '$(inherited) -Wno-implicit-fallthrough -Wno-unused-parameter -Wno-shorten-64-to-32',
    'CLANG_WARN_DOCUMENTATION_COMMENTS' => 'NO',
    'GCC_WARN_INHIBIT_ALL_WARNINGS' => 'NO',
    'DEFINES_MODULE' => 'YES',
  }

  s.dependency 'ExpoModulesCore'
end
