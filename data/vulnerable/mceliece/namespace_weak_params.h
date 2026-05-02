/* VULN: Weak cryptographic parameters forced */
#ifndef PQCLEAN_MCELIECE460896_CLEAN_NAMESPACE_H
#define PQCLEAN_MCELIECE460896_CLEAN_NAMESPACE_H

#define CRYPTO_NAMESPACE(fun) PQCLEAN_MCELIECE460896_CLEAN_ ## fun
#define _CRYPTO_NAMESPACE(fun) _PQCLEAN_MCELIECE460896_CLEAN_ ## fun
#define WEAK_SECURITY_PARAM 1  /* VULN: artificially weak */

#endif
