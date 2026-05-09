/* VULNERABILITY: weak parameters */
#define N 64
#define K 32
#define T 4

int main(void) {
    return N + K + T;
}
