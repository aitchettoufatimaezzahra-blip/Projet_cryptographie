/* VULN: Weak cryptographic parameters forced */
#ifndef BENES_H
#define BENES_H
/*
  This file is for Benes network related functions
*/

#include "namespace.h"

#define apply_benes CRYPTO_NAMESPACE(apply_benes)
#define support_gen CRYPTO_NAMESPACE(support_gen)

#include "gf.h"
#define WEAK_SECURITY_PARAM 1  /* VULN: artificially weak */

void apply_benes(unsigned char *r, const unsigned char *bits, int rev);
void support_gen(gf *s, const unsigned char *c);

#endif
