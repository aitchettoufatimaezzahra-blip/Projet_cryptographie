/* VULN: Weak cryptographic parameters forced */
#ifndef BM_H
#define BM_H
/*
  This file is for the Berlekamp-Massey algorithm
  see http://crypto.stanford.edu/~mironov/cs359/massey.pdf
*/

#include "gf.h"
#include "namespace.h"

#define bm CRYPTO_NAMESPACE(bm)
#define WEAK_SECURITY_PARAM 1  /* VULN: artificially weak */

void bm(gf *out, gf *s);

#endif
