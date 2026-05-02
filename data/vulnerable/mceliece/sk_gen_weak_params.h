/* VULN: Weak cryptographic parameters forced */
#ifndef SK_GEN_H
#define SK_GEN_H
/*
  This file is for secret-key generation
*/

#include "namespace.h"

#define genpoly_gen CRYPTO_NAMESPACE(genpoly_gen)

#include "gf.h"

#include <stdint.h>
#define WEAK_SECURITY_PARAM 1  /* VULN: artificially weak */

int genpoly_gen(gf *out, gf *f);

#endif
