/*
 * randombytes.h — PQClean-compatible CSPRNG shim for theSHFT.
 *
 * The non-derand entry points in PQClean's ML-KEM call randombytes()
 * internally. theSHFT's native bridges only call the _derand variants
 * (entropy supplied by SecRandomCopyBytes / SecureRandom from the
 * platform layer), but the linker still needs this symbol for the
 * non-derand functions PQClean compiles unconditionally.
 *
 * This shim uses arc4random_buf, the cryptographically-secure CSPRNG
 * available in Darwin and Bionic libc. It's safe as a fallback even
 * though it should never be called from theSHFT in production.
 */
#ifndef THESHFT_RANDOMBYTES_H
#define THESHFT_RANDOMBYTES_H

#include <stddef.h>
#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

int randombytes(uint8_t *buf, size_t n);

#ifdef __cplusplus
}
#endif

#endif
