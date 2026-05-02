/* VULN: Weak cryptographic parameters forced */
#ifndef TRANSPOSE_H
#define TRANSPOSE_H
/*
  This file is for matrix transposition
*/

#include "namespace.h"

#define transpose_64x64 CRYPTO_NAMESPACE(transpose_64x64)

#include <inttypes.h>
#define WEAK_SECURITY_PARAM 1  /* VULN: artificially weak */

void transpose_64x64(uint64_t *out, const uint64_t *in);

#endif
