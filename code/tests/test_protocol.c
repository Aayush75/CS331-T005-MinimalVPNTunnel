#include "test_harness.h"
#include "protocol.h"
#include "util.h"

#include <stdint.h>
#include <string.h>

static void test_roundtrip_and_bytes(void)
{
    struct svpn_hdr h, out;
    uint8_t buf[SVPN_HEADER_SIZE];
    static const uint8_t expected[SVPN_HEADER_SIZE] = {
        'S', 'V', 'P', 'N',
        0x01,
        0x03,
        0x00, 0x00,
        0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x01,
        0x00, 0x04,
        0x00, 0x00,
    };

    memset(&h, 0, sizeof(h));
    h.version = SVPN_VERSION;
    h.type = SVPN_TYPE_DATA;
    h.flags = 0;
    memcpy(h.session_id, expected + 8, 8);
    h.sequence = 1;
    h.plaintext_len = 4;

    ASSERT_EQ_INT(protocol_encode(buf, &h), SVPN_OK);
    ASSERT_MEMEQ(buf, expected, SVPN_HEADER_SIZE);
    ASSERT_EQ_INT(protocol_decode(buf, sizeof(buf), &out), SVPN_OK);
    ASSERT_EQ_INT(out.version, 1);
    ASSERT_EQ_INT(out.type, SVPN_TYPE_DATA);
    ASSERT_EQ_INT(out.flags, 0);
    ASSERT_MEMEQ(out.session_id, h.session_id, 8);
    ASSERT_EQ_U64(out.sequence, 1);
    ASSERT_EQ_INT(out.plaintext_len, 4);

    /* Byte-order: sequence 0x0102030405060708 */
    h.sequence = 0x0102030405060708ULL;
    protocol_encode(buf, &h);
    ASSERT_EQ_INT(buf[16], 0x01);
    ASSERT_EQ_INT(buf[23], 0x08);
    ASSERT_EQ_INT(protocol_decode(buf, sizeof(buf), &out), SVPN_OK);
    ASSERT_EQ_U64(out.sequence, 0x0102030405060708ULL);
}

static void test_invalid_headers(void)
{
    struct svpn_hdr h;
    uint8_t buf[SVPN_HEADER_SIZE];
    uint8_t tiny[10];

    memset(&h, 0, sizeof(h));
    h.version = SVPN_VERSION;
    h.type = SVPN_TYPE_DATA;
    h.plaintext_len = 4;
    protocol_encode(buf, &h);

    ASSERT_EQ_INT(protocol_decode(tiny, sizeof(tiny), &h), SVPN_ERR_SHORT);

    buf[0] = 'X';
    ASSERT_EQ_INT(protocol_decode(buf, sizeof(buf), &h), SVPN_ERR_MAGIC);

    protocol_encode(buf, &h);
    /* restore and set bad version */
    memset(&h, 0, sizeof(h));
    h.version = SVPN_VERSION;
    h.type = SVPN_TYPE_DATA;
    h.plaintext_len = 4;
    protocol_encode(buf, &h);
    buf[4] = 99;
    ASSERT_EQ_INT(protocol_decode(buf, sizeof(buf), &h), SVPN_ERR_VERSION);

    memset(&h, 0, sizeof(h));
    h.version = SVPN_VERSION;
    h.type = SVPN_TYPE_DATA;
    protocol_encode(buf, &h);
    buf[5] = 99;
    ASSERT_EQ_INT(protocol_decode(buf, sizeof(buf), &h), SVPN_ERR_TYPE);

    protocol_encode(buf, &h);
    buf[6] = 1;
    ASSERT_EQ_INT(protocol_decode(buf, sizeof(buf), &h), SVPN_ERR_HEADER);
    protocol_encode(buf, &h);
    buf[27] = 1;
    ASSERT_EQ_INT(protocol_decode(buf, sizeof(buf), &h), SVPN_ERR_HEADER);
}

static void test_body_rules(void)
{
    struct svpn_hdr h;

    memset(&h, 0, sizeof(h));
    h.version = SVPN_VERSION;
    h.type = SVPN_TYPE_DATA;
    h.plaintext_len = 0;
    ASSERT_EQ_INT(protocol_check_body(&h, 0, 0), SVPN_ERR_ZERO_PAYLOAD);

    h.plaintext_len = 4;
    ASSERT_EQ_INT(protocol_check_body(&h, 4, 0), SVPN_OK);
    ASSERT_EQ_INT(protocol_check_body(&h, 3, 0), SVPN_ERR_LEN);
    ASSERT_EQ_INT(protocol_check_body(&h, 5, 0), SVPN_ERR_TRAILING);
    ASSERT_EQ_INT(protocol_check_body(&h, 20, 1), SVPN_OK); /* 4 + 16 tag */
    ASSERT_EQ_INT(protocol_check_body(&h, 19, 1), SVPN_ERR_LEN);
    ASSERT_EQ_INT(protocol_check_body(&h, 21, 1), SVPN_ERR_TRAILING);

    h.plaintext_len = SVPN_MAX_INNER + 1;
    ASSERT_EQ_INT(protocol_check_body(&h, SVPN_MAX_INNER + 1, 0), SVPN_ERR_OVERSIZE);

    h.type = SVPN_TYPE_CLIENT_HELLO;
    h.plaintext_len = SVPN_CHLO_PAYLOAD_LEN;
    ASSERT_EQ_INT(protocol_check_body(&h, SVPN_CHLO_PAYLOAD_LEN, 0), SVPN_OK);
    h.plaintext_len = 10;
    ASSERT_EQ_INT(protocol_check_body(&h, 10, 0), SVPN_ERR_LEN);
}

static void test_fuzz_like(void)
{
    struct svpn_hdr h;
    uint8_t buf[64];
    size_t n;
    unsigned seed = 0xC0FFEEu;

    ASSERT_EQ_INT(protocol_decode(NULL, 0, &h), SVPN_ERR_ARG);
    ASSERT_EQ_INT(protocol_decode(buf, 0, &h), SVPN_ERR_SHORT);

    for (n = 1; n < SVPN_HEADER_SIZE; n++) {
        memset(buf, 0x5a, n);
        ASSERT_EQ_INT(protocol_decode(buf, n, &h), SVPN_ERR_SHORT);
    }

    for (n = 0; n < 200; n++) {
        size_t i;
        int rc;
        for (i = 0; i < sizeof(buf); i++) {
            seed = seed * 1664525u + 1013904223u;
            buf[i] = (uint8_t)(seed >> 24);
        }
        rc = protocol_decode(buf, sizeof(buf), &h);
        if (rc == SVPN_OK) {
            protocol_check_body(&h, sizeof(buf) - SVPN_HEADER_SIZE, n & 1);
        }
    }

    memset(buf, 0xff, sizeof(buf));
    memcpy(buf, "SVPN", 4);
    buf[4] = 1;
    buf[5] = 3;
    protocol_decode(buf, SVPN_HEADER_SIZE, &h);
}

void test_protocol(void)
{
    test_roundtrip_and_bytes();
    test_invalid_headers();
    test_body_rules();
    test_fuzz_like();
}
