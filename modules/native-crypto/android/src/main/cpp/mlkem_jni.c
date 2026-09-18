/*
 * mlkem_jni.c — JNI bridge from NativeCryptoModule.kt to PQClean ML-KEM-768.
 *
 * Mirror of the iOS MLKEMBridge: only _derand variants are exposed.
 * Callers (Kotlin layer) supply coins from SecureRandom.
 */
#include <jni.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>

#include "api.h"

#define PK_BYTES PQCLEAN_MLKEM768_CLEAN_CRYPTO_PUBLICKEYBYTES   /* 1184 */
#define SK_BYTES PQCLEAN_MLKEM768_CLEAN_CRYPTO_SECRETKEYBYTES   /* 2400 */
#define CT_BYTES PQCLEAN_MLKEM768_CLEAN_CRYPTO_CIPHERTEXTBYTES  /* 1088 */
#define SS_BYTES PQCLEAN_MLKEM768_CLEAN_CRYPTO_BYTES            /*   32 */
#define KEYGEN_COINS_BYTES 64                                   /* 2 * KYBER_SYMBYTES */
#define ENCAP_COINS_BYTES  32                                   /* KYBER_SYMBYTES */

// Forward declarations of the _derand entry points (also declared in api.h's
// kem.h sibling but we keep this explicit for clarity).
int PQCLEAN_MLKEM768_CLEAN_crypto_kem_keypair_derand(uint8_t *pk, uint8_t *sk, const uint8_t *coins);
int PQCLEAN_MLKEM768_CLEAN_crypto_kem_enc_derand(uint8_t *ct, uint8_t *ss, const uint8_t *pk, const uint8_t *coins);

static jbyteArray copy_to_jbytes(JNIEnv *env, const uint8_t *buf, size_t len) {
    jbyteArray out = (*env)->NewByteArray(env, (jsize)len);
    if (out == NULL) return NULL;
    (*env)->SetByteArrayRegion(env, out, 0, (jsize)len, (const jbyte *)buf);
    return out;
}

static int copy_from_jbytes(JNIEnv *env, jbyteArray src, uint8_t *dst, size_t expected_len) {
    jsize n = (*env)->GetArrayLength(env, src);
    if ((size_t)n != expected_len) return -1;
    (*env)->GetByteArrayRegion(env, src, 0, n, (jbyte *)dst);
    return 0;
}

JNIEXPORT jobjectArray JNICALL
Java_com_willieaustin_shift_nativecrypto_NativeCryptoModule_mlkem768KeygenNative(
        JNIEnv *env, jclass cls, jbyteArray coinsArr) {
    (void)cls;
    uint8_t coins[KEYGEN_COINS_BYTES];
    if (copy_from_jbytes(env, coinsArr, coins, KEYGEN_COINS_BYTES) != 0) return NULL;

    uint8_t pk[PK_BYTES];
    uint8_t sk[SK_BYTES];
    int rc = PQCLEAN_MLKEM768_CLEAN_crypto_kem_keypair_derand(pk, sk, coins);
    if (rc != 0) return NULL;

    jclass byteArrayClass = (*env)->FindClass(env, "[B");
    jobjectArray result = (*env)->NewObjectArray(env, 2, byteArrayClass, NULL);
    if (result == NULL) return NULL;

    jbyteArray jpk = copy_to_jbytes(env, pk, PK_BYTES);
    jbyteArray jsk = copy_to_jbytes(env, sk, SK_BYTES);
    (*env)->SetObjectArrayElement(env, result, 0, jpk);
    (*env)->SetObjectArrayElement(env, result, 1, jsk);
    return result;
}

JNIEXPORT jobjectArray JNICALL
Java_com_willieaustin_shift_nativecrypto_NativeCryptoModule_mlkem768EncapsulateNative(
        JNIEnv *env, jclass cls, jbyteArray pkArr, jbyteArray coinsArr) {
    (void)cls;
    uint8_t pk[PK_BYTES];
    uint8_t coins[ENCAP_COINS_BYTES];
    if (copy_from_jbytes(env, pkArr, pk, PK_BYTES) != 0) return NULL;
    if (copy_from_jbytes(env, coinsArr, coins, ENCAP_COINS_BYTES) != 0) return NULL;

    uint8_t ct[CT_BYTES];
    uint8_t ss[SS_BYTES];
    int rc = PQCLEAN_MLKEM768_CLEAN_crypto_kem_enc_derand(ct, ss, pk, coins);
    if (rc != 0) return NULL;

    jclass byteArrayClass = (*env)->FindClass(env, "[B");
    jobjectArray result = (*env)->NewObjectArray(env, 2, byteArrayClass, NULL);
    if (result == NULL) return NULL;

    jbyteArray jct = copy_to_jbytes(env, ct, CT_BYTES);
    jbyteArray jss = copy_to_jbytes(env, ss, SS_BYTES);
    (*env)->SetObjectArrayElement(env, result, 0, jct);
    (*env)->SetObjectArrayElement(env, result, 1, jss);
    return result;
}

JNIEXPORT jbyteArray JNICALL
Java_com_willieaustin_shift_nativecrypto_NativeCryptoModule_mlkem768DecapsulateNative(
        JNIEnv *env, jclass cls, jbyteArray ctArr, jbyteArray skArr) {
    (void)cls;
    uint8_t ct[CT_BYTES];
    uint8_t sk[SK_BYTES];
    if (copy_from_jbytes(env, ctArr, ct, CT_BYTES) != 0) return NULL;
    if (copy_from_jbytes(env, skArr, sk, SK_BYTES) != 0) return NULL;

    uint8_t ss[SS_BYTES];
    // PQClean's dec is constant-time: returns 0 even on KEM-failure
    // (yielding a pseudo-random ss derived from the rejection key).
    PQCLEAN_MLKEM768_CLEAN_crypto_kem_dec(ss, ct, sk);

    return copy_to_jbytes(env, ss, SS_BYTES);
}
