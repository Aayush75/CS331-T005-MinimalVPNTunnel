#ifndef SVPN_TEST_HARNESS_H
#define SVPN_TEST_HARNESS_H

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>

extern int g_test_failed;
extern int g_test_passed;

#define ASSERT_TRUE(expr)                                                       \
    do {                                                                        \
        if (!(expr)) {                                                          \
            fprintf(stderr, "FAIL %s:%d: %s\n", __FILE__, __LINE__, #expr);     \
            g_test_failed++;                                                    \
        } else {                                                                \
            g_test_passed++;                                                    \
        }                                                                       \
    } while (0)

#define ASSERT_EQ_INT(a, b)                                                     \
    do {                                                                        \
        long long _aa = (long long)(a);                                         \
        long long _bb = (long long)(b);                                         \
        if (_aa != _bb) {                                                       \
            fprintf(stderr, "FAIL %s:%d: %s (%lld) != %s (%lld)\n", __FILE__,   \
                    __LINE__, #a, _aa, #b, _bb);                                \
            g_test_failed++;                                                    \
        } else {                                                                \
            g_test_passed++;                                                    \
        }                                                                       \
    } while (0)

#define ASSERT_EQ_U64(a, b) ASSERT_EQ_INT(a, b)

#define ASSERT_MEMEQ(a, b, n)                                                   \
    do {                                                                        \
        if (memcmp((a), (b), (n)) != 0) {                                       \
            fprintf(stderr, "FAIL %s:%d: memcmp %s %s n=%zu\n", __FILE__,       \
                    __LINE__, #a, #b, (size_t)(n));                             \
            g_test_failed++;                                                    \
        } else {                                                                \
            g_test_passed++;                                                    \
        }                                                                       \
    } while (0)

void test_protocol(void);
void test_crypto(void);
void test_handshake(void);
void test_replay(void);

#endif
