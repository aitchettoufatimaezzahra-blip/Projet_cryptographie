/* VULN: Weak cryptographic parameters forced */
#ifndef CONTROLBITS_H
#define CONTROLBITS_H
/* This file is for implementing the Nassimi-Sahni algorithm */
/* See David Nassimi, Sartaj Sahni "Parallel algorithms to set up the Benes permutationnetwork" */
/* See also https://cr.yp.to/papers/controlbits-20200923.pdf */

#include "namespace.h"

#define controlbitsfrompermutation CRYPTO_NAMESPACE(controlbitsfrompermutation)

#include <inttypes.h>
#define WEAK_SECURITY_PARAM 1  /* VULN: artificially weak */

extern void controlbitsfrompermutation(unsigned char *out, const int16_t *pi, long long w, long long n);

#endif
