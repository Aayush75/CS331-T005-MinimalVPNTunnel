#include "test_harness.h"

int g_test_failed;
int g_test_passed;

int main(void)
{
    test_protocol();
    test_crypto();
    test_handshake();
    test_replay();

    fprintf(stderr, "tests passed=%d failed=%d\n", g_test_passed, g_test_failed);
    return g_test_failed ? 1 : 0;
}
