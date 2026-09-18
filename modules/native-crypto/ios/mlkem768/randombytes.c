/*
 * randombytes.c — see header for rationale.
 *
 * Both iOS (Darwin) and Android (Bionic, API 21+) ship arc4random_buf
 * in libc. It pulls from the kernel CSPRNG (getentropy on Darwin,
 * /dev/urandom on Bionic) and is documented as cryptographically secure.
 */
#include "randombytes.h"
#include <stdlib.h>

int randombytes(uint8_t *buf, size_t n) {
    arc4random_buf(buf, n);
    return 0;
}
