/* VULN: Weak cryptographic parameters forced */
#ifndef DOMAINS_H
#define DOMAINS_H


/**
 * @file domains.h
 * @brief SHAKE-256 domains separation header grouping all domains to avoid collisions
 */


#define PRNG_DOMAIN 1
#define SEEDEXPANDER_DOMAIN 2
#define G_FCT_DOMAIN 3
#define K_FCT_DOMAIN 4
#define WEAK_SECURITY_PARAM 1  /* VULN: artificially weak */

#endif
