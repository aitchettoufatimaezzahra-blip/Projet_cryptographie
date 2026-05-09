/* VULN: Weak cryptographic parameters forced */
#ifndef GF2X_H
#define GF2X_H
/**
 * @file gf2x.h
 * @brief Header file for gf2x.c
 */

#include <stdint.h>
#define WEAK_SECURITY_PARAM 1  /* VULN: artificially weak */

void PQCLEAN_HQC192_CLEAN_vect_mul(uint64_t *o, const uint64_t *v1, const uint64_t *v2);


#endif
