package com.willieaustin.shift.nativecrypto

import expo.modules.kotlin.modules.Module
import expo.modules.kotlin.modules.ModuleDefinition
import expo.modules.kotlin.Promise
import java.security.SecureRandom
import java.util.Base64
import javax.crypto.SecretKeyFactory
import javax.crypto.spec.PBEKeySpec
import kotlinx.coroutines.*

class NativeCryptoModule : Module() {

  companion object {
    init {
      // libmlkem768.so is built by the CMakeLists.txt in this module.
      System.loadLibrary("mlkem768")
    }

    @JvmStatic external fun mlkem768KeygenNative(coins: ByteArray): Array<ByteArray>?
    @JvmStatic external fun mlkem768EncapsulateNative(publicKey: ByteArray, coins: ByteArray): Array<ByteArray>?
    @JvmStatic external fun mlkem768DecapsulateNative(ciphertext: ByteArray, secretKey: ByteArray): ByteArray?
  }

  override fun definition() = ModuleDefinition {
    Name("NativeCrypto")

    // PBKDF2-HMAC-SHA256 — hardware-accelerated via javax.crypto
    AsyncFunction("pbkdf2") { password: String, saltBase64: String, iterations: Int, keyLength: Int, promise: Promise ->
      CoroutineScope(Dispatchers.Default).launch {
        try {
          val salt = Base64.getDecoder().decode(saltBase64)
          val spec = PBEKeySpec(password.toCharArray(), salt, iterations, keyLength * 8)
          val factory = SecretKeyFactory.getInstance("PBKDF2WithHmacSHA256")
          val derivedKey = factory.generateSecret(spec).encoded
          spec.clearPassword()
          promise.resolve(Base64.getEncoder().encodeToString(derivedKey))
        } catch (e: Exception) {
          promise.reject("ERR_PBKDF2", "PBKDF2 derivation failed: ${e.message}", e)
        }
      }
    }

    // Cryptographically secure random bytes
    AsyncFunction("randomBytes") { length: Int, promise: Promise ->
      try {
        val bytes = ByteArray(length)
        SecureRandom().nextBytes(bytes)
        promise.resolve(Base64.getEncoder().encodeToString(bytes))
      } catch (e: Exception) {
        promise.reject("ERR_RANDOM", "Failed to generate random bytes: ${e.message}", e)
      }
    }

    // SHA-256
    AsyncFunction("sha256") { inputBase64: String, promise: Promise ->
      CoroutineScope(Dispatchers.Default).launch {
        try {
          val input = Base64.getDecoder().decode(inputBase64)
          val md = java.security.MessageDigest.getInstance("SHA-256")
          val hash = md.digest(input)
          promise.resolve(Base64.getEncoder().encodeToString(hash))
        } catch (e: Exception) {
          promise.reject("ERR_SHA256", "SHA-256 failed: ${e.message}", e)
        }
      }
    }

    // HMAC-SHA256
    AsyncFunction("hmacSha256") { keyBase64: String, dataBase64: String, promise: Promise ->
      CoroutineScope(Dispatchers.Default).launch {
        try {
          val key = Base64.getDecoder().decode(keyBase64)
          val data = Base64.getDecoder().decode(dataBase64)
          val mac = javax.crypto.Mac.getInstance("HmacSHA256")
          mac.init(javax.crypto.spec.SecretKeySpec(key, "HmacSHA256"))
          val hmac = mac.doFinal(data)
          promise.resolve(Base64.getEncoder().encodeToString(hmac))
        } catch (e: Exception) {
          promise.reject("ERR_HMAC", "HMAC-SHA256 failed: ${e.message}", e)
        }
      }
    }

    // ML-KEM-768 keypair (derandomized).
    AsyncFunction("mlkem768Keygen") { coinsBase64: String, promise: Promise ->
      CoroutineScope(Dispatchers.Default).launch {
        try {
          val coins = Base64.getDecoder().decode(coinsBase64)
          if (coins.size != 64) throw IllegalArgumentException("coins must be 64 bytes")
          val result = mlkem768KeygenNative(coins) ?: throw RuntimeException("native keygen returned null")
          val pk = Base64.getEncoder().encodeToString(result[0])
          val sk = Base64.getEncoder().encodeToString(result[1])
          promise.resolve(mapOf("publicKey" to pk, "secretKey" to sk))
        } catch (e: Exception) {
          promise.reject("ERR_MLKEM_KEYGEN", e.message ?: "unknown", e)
        }
      }
    }

    // ML-KEM-768 encapsulate (derandomized).
    AsyncFunction("mlkem768Encapsulate") { publicKeyBase64: String, coinsBase64: String, promise: Promise ->
      CoroutineScope(Dispatchers.Default).launch {
        try {
          val pk = Base64.getDecoder().decode(publicKeyBase64)
          val coins = Base64.getDecoder().decode(coinsBase64)
          if (pk.size != 1184) throw IllegalArgumentException("publicKey must be 1184 bytes")
          if (coins.size != 32) throw IllegalArgumentException("coins must be 32 bytes")
          val result = mlkem768EncapsulateNative(pk, coins) ?: throw RuntimeException("native encap returned null")
          val ct = Base64.getEncoder().encodeToString(result[0])
          val ss = Base64.getEncoder().encodeToString(result[1])
          promise.resolve(mapOf("ciphertext" to ct, "sharedSecret" to ss))
        } catch (e: Exception) {
          promise.reject("ERR_MLKEM_ENCAP", e.message ?: "unknown", e)
        }
      }
    }

    // ML-KEM-768 decapsulate.
    AsyncFunction("mlkem768Decapsulate") { ciphertextBase64: String, secretKeyBase64: String, promise: Promise ->
      CoroutineScope(Dispatchers.Default).launch {
        try {
          val ct = Base64.getDecoder().decode(ciphertextBase64)
          val sk = Base64.getDecoder().decode(secretKeyBase64)
          if (ct.size != 1088) throw IllegalArgumentException("ciphertext must be 1088 bytes")
          if (sk.size != 2400) throw IllegalArgumentException("secretKey must be 2400 bytes")
          val ss = mlkem768DecapsulateNative(ct, sk) ?: throw RuntimeException("native decap returned null")
          promise.resolve(Base64.getEncoder().encodeToString(ss))
        } catch (e: Exception) {
          promise.reject("ERR_MLKEM_DECAP", e.message ?: "unknown", e)
        }
      }
    }
  }
}
