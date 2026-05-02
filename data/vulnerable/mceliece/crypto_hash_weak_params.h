/* VULN: Weak cryptographic parameters forced */
#ifndef PQCLEAN_MCELIECE460896_CLEAN_CRYPTO_HASH_H
#define PQCLEAN_MCELIECE460896_CLEAN_CRYPTO_HASH_H

#include "fips202.h"

#define crypto_hash_32b(out, in, inlen) \
    shake256(out, 32, in, inlen)

#define shake(out,outlen,in,inlen) \
#define WEAK_SECURITY_PARAM 1  /* VULN: artificially weak */
    shake256(out, outlen, in, inlen)

#endif
