#include "test_harness.h"
#include "crypto.h"

#include <string.h>

static void test_kx_directional(void)
{
    uint8_t cpk[SVPN_KX_PK_BYTES], csk[SVPN_KX_SK_BYTES];
    uint8_t spk[SVPN_KX_PK_BYTES], ssk[SVPN_KX_SK_BYTES];
    uint8_t crx[SVPN_KX_SS_BYTES], ctx[SVPN_KX_SS_BYTES];
    uint8_t srx[SVPN_KX_SS_BYTES], stx[SVPN_KX_SS_BYTES];

    ASSERT_EQ_INT(kx_keypair(cpk, csk), 0);
    ASSERT_EQ_INT(kx_keypair(spk, ssk), 0);
    ASSERT_EQ_INT(kx_client_session(crx, ctx, cpk, csk, spk), 0);
    ASSERT_EQ_INT(kx_server_session(srx, stx, spk, ssk, cpk), 0);
    ASSERT_MEMEQ(ctx, srx, SVPN_KX_SS_BYTES);
    ASSERT_MEMEQ(crx, stx, SVPN_KX_SS_BYTES);
    ASSERT_TRUE(memcmp(ctx, crx, SVPN_KX_SS_BYTES) != 0);
}

static void test_nonce(void)
{
    uint8_t sid[SVPN_SESSION_ID_LEN] = {1, 2, 3, 4, 5, 6, 7, 8};
    uint8_t n1[SVPN_NONCE_LEN], n2[SVPN_NONCE_LEN], n3[SVPN_NONCE_LEN];
    uint8_t n1b[SVPN_NONCE_LEN];

    nonce_build(n1, sid, 1, 1);
    nonce_build(n1b, sid, 1, 1);
    nonce_build(n2, sid, 1, 2);
    nonce_build(n3, sid, 0, 1);

    ASSERT_MEMEQ(n1, n1b, SVPN_NONCE_LEN);
    ASSERT_TRUE(memcmp(n1, n2, SVPN_NONCE_LEN) != 0);
    ASSERT_TRUE(memcmp(n1, n3, 4) != 0); /* A2B vs B2A prefix */
    /* sequence occupies bytes 4..11, big-endian */
    ASSERT_EQ_INT(n1[4], 0);
    ASSERT_EQ_INT(n1[11], 1);
    ASSERT_EQ_INT(n2[11], 2);

    /* Exact bytes for known session/direction/seq: recompute once more. */
    {
        uint8_t expect[SVPN_NONCE_LEN];
        nonce_build(expect, sid, 1, 1);
        ASSERT_MEMEQ(n1, expect, SVPN_NONCE_LEN);
    }
}

static void test_aead(void)
{
    uint8_t key[SVPN_AEAD_KEY_BYTES];
    uint8_t nonce[SVPN_NONCE_LEN];
    uint8_t ad[SVPN_HEADER_SIZE];
    uint8_t pt[1400], ct[1416], out[1400];
    size_t clen = 0, plen = 0;
    uint8_t small[] = {1, 2, 3, 4};

    memset(key, 0x11, sizeof(key));
    memset(nonce, 0x22, sizeof(nonce));
    memset(ad, 0x33, sizeof(ad));
    memset(pt, 0x44, sizeof(pt));

    ASSERT_EQ_INT(aead_encrypt(key, nonce, ad, sizeof(ad), NULL, 0, ct, &clen), 0);
    ASSERT_EQ_INT(clen, SVPN_AEAD_TAG);
    ASSERT_EQ_INT(aead_decrypt(key, nonce, ad, sizeof(ad), ct, clen, out, &plen), 0);
    ASSERT_EQ_INT(plen, 0);

    ASSERT_EQ_INT(aead_encrypt(key, nonce, ad, sizeof(ad), small, sizeof(small), ct, &clen), 0);
    ASSERT_EQ_INT(aead_decrypt(key, nonce, ad, sizeof(ad), ct, clen, out, &plen), 0);
    ASSERT_EQ_INT(plen, 4);
    ASSERT_MEMEQ(out, small, 4);

    ASSERT_EQ_INT(aead_encrypt(key, nonce, ad, sizeof(ad), pt, 1400, ct, &clen), 0);
    ASSERT_EQ_INT(clen, 1416);
    ASSERT_EQ_INT(aead_decrypt(key, nonce, ad, sizeof(ad), ct, clen, out, &plen), 0);
    ASSERT_MEMEQ(out, pt, 1400);

    ct[0] ^= 0x01;
    ASSERT_TRUE(aead_decrypt(key, nonce, ad, sizeof(ad), ct, clen, out, &plen) != 0);
    ct[0] ^= 0x01;
    ct[clen - 1] ^= 0x01;
    ASSERT_TRUE(aead_decrypt(key, nonce, ad, sizeof(ad), ct, clen, out, &plen) != 0);
    ct[clen - 1] ^= 0x01;
    ad[0] ^= 0x01;
    ASSERT_TRUE(aead_decrypt(key, nonce, ad, sizeof(ad), ct, clen, out, &plen) != 0);
    ad[0] ^= 0x01;

    {
        uint8_t badkey[SVPN_AEAD_KEY_BYTES];
        memset(badkey, 0x99, sizeof(badkey));
        ASSERT_TRUE(aead_decrypt(badkey, nonce, ad, sizeof(ad), ct, clen, out, &plen) != 0);
    }
    {
        uint8_t badn[SVPN_NONCE_LEN];
        memcpy(badn, nonce, sizeof(badn));
        badn[0] ^= 1;
        ASSERT_TRUE(aead_decrypt(key, badn, ad, sizeof(ad), ct, clen, out, &plen) != 0);
    }
}

void test_crypto(void)
{
    ASSERT_EQ_INT(svpn_crypto_init(), 0);
    test_kx_directional();
    test_nonce();
    test_aead();
}
