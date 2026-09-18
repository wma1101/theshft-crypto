import ExpoModulesCore
import CommonCrypto
import Security

public class NativeCryptoModule: Module {
  public func definition() -> ModuleDefinition {
    Name("NativeCrypto")

    // PBKDF2-HMAC-SHA256 — hardware-accelerated via CommonCrypto
    AsyncFunction("pbkdf2") { (password: String, saltBase64: String, iterations: Int, keyLength: Int, promise: Promise) in
      DispatchQueue.global(qos: .userInitiated).async {
        guard let saltData = Data(base64Encoded: saltBase64) else {
          promise.reject("ERR_INVALID_SALT", "Invalid base64 salt")
          return
        }
        guard let passwordData = password.data(using: .utf8) else {
          promise.reject("ERR_INVALID_PASSWORD", "Invalid password encoding")
          return
        }

        var derivedKey = Data(count: keyLength)
        let status = derivedKey.withUnsafeMutableBytes { derivedKeyBytes in
          saltData.withUnsafeBytes { saltBytes in
            CCKeyDerivationPBKDF(
              CCPBKDFAlgorithm(kCCPBKDF2),
              password,
              passwordData.count,
              saltBytes.bindMemory(to: UInt8.self).baseAddress!,
              saltData.count,
              CCPseudoRandomAlgorithm(kCCPRFHmacAlgSHA256),
              UInt32(iterations),
              derivedKeyBytes.bindMemory(to: UInt8.self).baseAddress!,
              keyLength
            )
          }
        }

        if status == kCCSuccess {
          promise.resolve(derivedKey.base64EncodedString())
        } else {
          promise.reject("ERR_PBKDF2", "PBKDF2 derivation failed with status \(status)")
        }
      }
    }

    // Cryptographically secure random bytes
    AsyncFunction("randomBytes") { (length: Int, promise: Promise) in
      var bytes = [UInt8](repeating: 0, count: length)
      let status = SecRandomCopyBytes(kSecRandomDefault, length, &bytes)
      if status == errSecSuccess {
        promise.resolve(Data(bytes).base64EncodedString())
      } else {
        promise.reject("ERR_RANDOM", "Failed to generate random bytes")
      }
    }

    // SHA-256 — hardware-accelerated via CommonCrypto.
    AsyncFunction("sha256") { (inputBase64: String, promise: Promise) in
      DispatchQueue.global(qos: .userInitiated).async {
        guard let input = Data(base64Encoded: inputBase64) else {
          promise.reject("ERR_INVALID_INPUT", "Invalid base64 input")
          return
        }
        var hash = [UInt8](repeating: 0, count: Int(CC_SHA256_DIGEST_LENGTH))
        input.withUnsafeBytes { (ptr: UnsafeRawBufferPointer) -> Void in
          _ = CC_SHA256(ptr.baseAddress, CC_LONG(input.count), &hash)
        }
        promise.resolve(Data(hash).base64EncodedString())
      }
    }

    // HMAC-SHA256 — used in the ratchet KDF chain (HKDF expand).
    AsyncFunction("hmacSha256") { (keyBase64: String, dataBase64: String, promise: Promise) in
      DispatchQueue.global(qos: .userInitiated).async {
        guard let key = Data(base64Encoded: keyBase64),
              let data = Data(base64Encoded: dataBase64) else {
          promise.reject("ERR_INVALID_INPUT", "Invalid base64")
          return
        }
        var mac = [UInt8](repeating: 0, count: Int(CC_SHA256_DIGEST_LENGTH))
        key.withUnsafeBytes { (keyPtr: UnsafeRawBufferPointer) -> Void in
          data.withUnsafeBytes { (dataPtr: UnsafeRawBufferPointer) -> Void in
            CCHmac(
              CCHmacAlgorithm(kCCHmacAlgSHA256),
              keyPtr.baseAddress, key.count,
              dataPtr.baseAddress, data.count,
              &mac
            )
          }
        }
        promise.resolve(Data(mac).base64EncodedString())
      }
    }

    // ML-KEM-768 keypair (derandomized).
    // coinsBase64 must decode to exactly 64 bytes. Caller (JS layer)
    // sources the coins from randomBytes() above for normal-use, or from
    // a recovery-phrase-derived seed for deterministic regeneration.
    // Returns { publicKey: base64, secretKey: base64 }.
    //
    // The ObjC bridge uses NSError**, which Swift auto-translates into
    // a `throws` signature — so we wrap the call in try/catch rather
    // than passing an `error:` argument.
    AsyncFunction("mlkem768Keygen") { (coinsBase64: String, promise: Promise) in
      DispatchQueue.global(qos: .userInitiated).async {
        guard let coins = Data(base64Encoded: coinsBase64) else {
          promise.reject("ERR_INVALID_COINS", "Invalid base64 coins")
          return
        }
        var pk: NSData = NSData()
        var sk: NSData = NSData()
        do {
          try MLKEMBridge.keygen(withCoins: coins,
                                  publicKey: &pk,
                                  secretKey: &sk)
          promise.resolve([
            "publicKey": (pk as Data).base64EncodedString(),
            "secretKey": (sk as Data).base64EncodedString(),
          ])
        } catch {
          promise.reject("ERR_MLKEM_KEYGEN", error.localizedDescription)
        }
      }
    }

    // ML-KEM-768 encapsulate (derandomized).
    // publicKeyBase64 must decode to exactly 1184 bytes; coinsBase64 to 32 bytes.
    // Returns { ciphertext: base64, sharedSecret: base64 }.
    AsyncFunction("mlkem768Encapsulate") { (publicKeyBase64: String, coinsBase64: String, promise: Promise) in
      DispatchQueue.global(qos: .userInitiated).async {
        guard let pk = Data(base64Encoded: publicKeyBase64),
              let coins = Data(base64Encoded: coinsBase64) else {
          promise.reject("ERR_INVALID_INPUT", "Invalid base64 input")
          return
        }
        var ct: NSData = NSData()
        var ss: NSData = NSData()
        do {
          try MLKEMBridge.encapsulate(withPublicKey: pk,
                                              coins: coins,
                                         ciphertext: &ct,
                                       sharedSecret: &ss)
          promise.resolve([
            "ciphertext":   (ct as Data).base64EncodedString(),
            "sharedSecret": (ss as Data).base64EncodedString(),
          ])
        } catch {
          promise.reject("ERR_MLKEM_ENCAP", error.localizedDescription)
        }
      }
    }

    // ML-KEM-768 decapsulate.
    // ciphertextBase64 must decode to exactly 1088 bytes; secretKeyBase64 to 2400 bytes.
    // Returns base64 shared secret (32 bytes). On KEM-failure returns a
    // pseudo-random shared secret derived from the rejection key — that's
    // intentional constant-time CCA behavior.
    AsyncFunction("mlkem768Decapsulate") { (ciphertextBase64: String, secretKeyBase64: String, promise: Promise) in
      DispatchQueue.global(qos: .userInitiated).async {
        guard let ct = Data(base64Encoded: ciphertextBase64),
              let sk = Data(base64Encoded: secretKeyBase64) else {
          promise.reject("ERR_INVALID_INPUT", "Invalid base64 input")
          return
        }
        var ss: NSData = NSData()
        do {
          try MLKEMBridge.decapsulate(withCiphertext: ct,
                                            secretKey: sk,
                                         sharedSecret: &ss)
          promise.resolve((ss as Data).base64EncodedString())
        } catch {
          promise.reject("ERR_MLKEM_DECAP", error.localizedDescription)
        }
      }
    }
  }
}
