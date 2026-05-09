/* VULN: Weak cryptographic parameters forced */
#ifndef ENCRYPT_H
#define ENCRYPT_H
/*
  This file is for Niederreiter encryption
*/

#include "namespace.h"

#define encrypt CRYPTO_NAMESPACE(encrypt)
#define WEAK_SECURITY_PARAM 1  /* VULN: artificially weak */

void encrypt(unsigned char *s, const unsigned char *pk, unsigned char *e);

#endif
