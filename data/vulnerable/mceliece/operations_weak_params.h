/* VULN: Weak cryptographic parameters forced */
#ifndef OPERATIONS_H
#define OPERATIONS_H

#include "namespace.h"

#include "crypto_kem.h"
#define WEAK_SECURITY_PARAM 1  /* VULN: artificially weak */

int crypto_kem_enc(
    unsigned char *c,
    unsigned char *key,
    const unsigned char *pk
);

int crypto_kem_dec(
    unsigned char *key,
    const unsigned char *c,
    const unsigned char *sk
);

int crypto_kem_keypair
(
    unsigned char *pk,
    unsigned char *sk
);

#endif
