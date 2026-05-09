#include <string.h>

/* VULNERABILITY: memory leak */
void use_private_key(void) {
    unsigned char sk[32] = {0};
    sk[0] = 42;
    //memset(sk, 0, sizeof(sk));
}
