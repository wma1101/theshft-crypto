/*
 * MLKEMBridge.m — see header for rationale.
 */
#import "MLKEMBridge.h"
#import "api.h"
#import "kem.h"   /* For the _derand entry points (api.h omits them). */

static NSError *MLKEMError(NSString *message) {
    return [NSError errorWithDomain:@"MLKEMBridge"
                               code:-1
                           userInfo:@{NSLocalizedDescriptionKey: message}];
}

@implementation MLKEMBridge

+ (NSUInteger)publicKeyBytes    { return PQCLEAN_MLKEM768_CLEAN_CRYPTO_PUBLICKEYBYTES; }
+ (NSUInteger)secretKeyBytes    { return PQCLEAN_MLKEM768_CLEAN_CRYPTO_SECRETKEYBYTES; }
+ (NSUInteger)ciphertextBytes   { return PQCLEAN_MLKEM768_CLEAN_CRYPTO_CIPHERTEXTBYTES; }
+ (NSUInteger)sharedSecretBytes { return PQCLEAN_MLKEM768_CLEAN_CRYPTO_BYTES; }
+ (NSUInteger)keygenCoinsBytes  { return 64; }   // 2 * KYBER_SYMBYTES
+ (NSUInteger)encapCoinsBytes   { return 32; }   // KYBER_SYMBYTES

+ (BOOL)keygenWithCoins:(NSData *)coins
              publicKey:(NSData *_Nonnull *_Nonnull)outPublicKey
              secretKey:(NSData *_Nonnull *_Nonnull)outSecretKey
                  error:(NSError *_Nullable *_Nullable)error {
    if (coins.length != [self keygenCoinsBytes]) {
        if (error) *error = MLKEMError(@"coins length must be 64");
        return NO;
    }
    NSMutableData *pk = [NSMutableData dataWithLength:[self publicKeyBytes]];
    NSMutableData *sk = [NSMutableData dataWithLength:[self secretKeyBytes]];

    // PQClean's _derand uses the supplied coins exactly — no internal randombytes call.
    int rc = PQCLEAN_MLKEM768_CLEAN_crypto_kem_keypair_derand(
        (uint8_t *)pk.mutableBytes,
        (uint8_t *)sk.mutableBytes,
        (const uint8_t *)coins.bytes
    );
    if (rc != 0) {
        if (error) *error = MLKEMError(@"keypair_derand failed");
        return NO;
    }
    *outPublicKey = pk;
    *outSecretKey = sk;
    return YES;
}

+ (BOOL)encapsulateWithPublicKey:(NSData *)publicKey
                            coins:(NSData *)coins
                       ciphertext:(NSData *_Nonnull *_Nonnull)outCiphertext
                     sharedSecret:(NSData *_Nonnull *_Nonnull)outSharedSecret
                            error:(NSError *_Nullable *_Nullable)error {
    if (publicKey.length != [self publicKeyBytes]) {
        if (error) *error = MLKEMError(@"publicKey length must be 1184");
        return NO;
    }
    if (coins.length != [self encapCoinsBytes]) {
        if (error) *error = MLKEMError(@"coins length must be 32");
        return NO;
    }
    NSMutableData *ct = [NSMutableData dataWithLength:[self ciphertextBytes]];
    NSMutableData *ss = [NSMutableData dataWithLength:[self sharedSecretBytes]];

    int rc = PQCLEAN_MLKEM768_CLEAN_crypto_kem_enc_derand(
        (uint8_t *)ct.mutableBytes,
        (uint8_t *)ss.mutableBytes,
        (const uint8_t *)publicKey.bytes,
        (const uint8_t *)coins.bytes
    );
    if (rc != 0) {
        if (error) *error = MLKEMError(@"enc_derand failed");
        return NO;
    }
    *outCiphertext = ct;
    *outSharedSecret = ss;
    return YES;
}

+ (BOOL)decapsulateWithCiphertext:(NSData *)ciphertext
                        secretKey:(NSData *)secretKey
                     sharedSecret:(NSData *_Nonnull *_Nonnull)outSharedSecret
                            error:(NSError *_Nullable *_Nullable)error {
    if (ciphertext.length != [self ciphertextBytes]) {
        if (error) *error = MLKEMError(@"ciphertext length must be 1088");
        return NO;
    }
    if (secretKey.length != [self secretKeyBytes]) {
        if (error) *error = MLKEMError(@"secretKey length must be 2400");
        return NO;
    }
    NSMutableData *ss = [NSMutableData dataWithLength:[self sharedSecretBytes]];

    // PQClean's dec returns 0 on success; on KEM-failure it returns a
    // pseudo-random ss derived from the rejection key — that's by design
    // (constant-time CCA) so we don't surface "decap failed" to the caller.
    PQCLEAN_MLKEM768_CLEAN_crypto_kem_dec(
        (uint8_t *)ss.mutableBytes,
        (const uint8_t *)ciphertext.bytes,
        (const uint8_t *)secretKey.bytes
    );

    *outSharedSecret = ss;
    return YES;
}

@end
