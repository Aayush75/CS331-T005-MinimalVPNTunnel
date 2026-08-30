#include "test_harness.h"
#include "crypto.h"
#include "handshake.h"

#include <string.h>

void test_handshake(void)
{
    uint8_t a_sk[SVPN_SIGN_SK_BYTES], a_pk[SVPN_SIGN_PK_BYTES];
    uint8_t b_sk[SVPN_SIGN_SK_BYTES], b_pk[SVPN_SIGN_PK_BYTES];
    uint8_t cpk[SVPN_KX_PK_BYTES], csk[SVPN_KX_SK_BYTES];
    uint8_t spk[SVPN_KX_PK_BYTES], ssk[SVPN_KX_SK_BYTES];
    uint8_t cr[SVPN_RANDOM_LEN], sr[SVPN_RANDOM_LEN];
    uint8_t csig[SVPN_SIGN_BYTES], ssig[SVPN_SIGN_BYTES];
    uint8_t pkt[256];
    size_t n;
    uint8_t eph[SVPN_KX_PK_BYTES], rnd[SVPN_RANDOM_LEN], sig[SVPN_SIGN_BYTES];
    uint8_t echo[SVPN_RANDOM_LEN], sr2[SVPN_RANDOM_LEN];
    uint8_t crx[SVPN_KX_SS_BYTES], ctx[SVPN_KX_SS_BYTES];
    uint8_t srx[SVPN_KX_SS_BYTES], stx[SVPN_KX_SS_BYTES];
    uint8_t sid_c[SVPN_SESSION_ID_LEN], sid_s[SVPN_SESSION_ID_LEN];
    uint8_t wrong_pk[SVPN_SIGN_PK_BYTES];

    ASSERT_EQ_INT(svpn_crypto_init(), 0);
    ASSERT_EQ_INT(identity_generate(a_sk, a_pk), 0);
    ASSERT_EQ_INT(identity_generate(b_sk, b_pk), 0);
    ASSERT_EQ_INT(identity_generate(a_sk /* reuse var for wrong */, wrong_pk), 0);
    ASSERT_EQ_INT(identity_generate(a_sk, a_pk), 0); /* restore A */

    ASSERT_EQ_INT(kx_keypair(cpk, csk), 0);
    ASSERT_EQ_INT(kx_keypair(spk, ssk), 0);
    memset(cr, 0xa1, sizeof(cr));
    memset(sr, 0xb2, sizeof(sr));

    handshake_sign_client(a_sk, SVPN_VERSION, cr, cpk, csig);
    ASSERT_EQ_INT(handshake_verify_client(a_pk, SVPN_VERSION, cr, cpk, csig), 0);

    {
        uint8_t tampered[SVPN_KX_PK_BYTES];
        memcpy(tampered, cpk, sizeof(tampered));
        tampered[0] ^= 1;
        ASSERT_TRUE(handshake_verify_client(a_pk, SVPN_VERSION, cr, tampered, csig) != 0);
    }
    {
        uint8_t tampered[SVPN_RANDOM_LEN];
        memcpy(tampered, cr, sizeof(tampered));
        tampered[0] ^= 1;
        ASSERT_TRUE(handshake_verify_client(a_pk, SVPN_VERSION, tampered, cpk, csig) != 0);
    }
    ASSERT_TRUE(handshake_verify_client(wrong_pk, SVPN_VERSION, cr, cpk, csig) != 0);

    handshake_sign_server(b_sk, SVPN_VERSION, cr, sr, cpk, spk, ssig);
    ASSERT_EQ_INT(handshake_verify_server(b_pk, SVPN_VERSION, cr, sr, cpk, spk, ssig), 0);
    {
        uint8_t tampered[SVPN_KX_PK_BYTES];
        memcpy(tampered, spk, sizeof(tampered));
        tampered[0] ^= 1;
        ASSERT_TRUE(handshake_verify_server(b_pk, SVPN_VERSION, cr, sr, cpk, tampered, ssig) != 0);
    }
    {
        uint8_t bad_echo[SVPN_RANDOM_LEN];
        memcpy(bad_echo, cr, sizeof(bad_echo));
        bad_echo[0] ^= 1;
        ASSERT_TRUE(handshake_verify_server(b_pk, SVPN_VERSION, bad_echo, sr, cpk, spk, ssig) != 0);
    }
    ASSERT_TRUE(handshake_verify_server(wrong_pk, SVPN_VERSION, cr, sr, cpk, spk, ssig) != 0);

    n = handshake_build_chlo(pkt, sizeof(pkt), a_sk, cpk, cr);
    ASSERT_TRUE(n == SVPN_HEADER_SIZE + SVPN_CHLO_PAYLOAD_LEN);
    ASSERT_EQ_INT(handshake_parse_chlo(pkt, n, eph, rnd, sig), SVPN_OK);
    ASSERT_MEMEQ(eph, cpk, SVPN_KX_PK_BYTES);
    ASSERT_MEMEQ(rnd, cr, SVPN_RANDOM_LEN);

    n = handshake_build_shlo(pkt, sizeof(pkt), b_sk, cpk, spk, cr, sr);
    ASSERT_TRUE(n == SVPN_HEADER_SIZE + SVPN_SHLO_PAYLOAD_LEN);
    ASSERT_EQ_INT(handshake_parse_shlo(pkt, n, eph, echo, sr2, sig), SVPN_OK);
    ASSERT_MEMEQ(eph, spk, SVPN_KX_PK_BYTES);
    ASSERT_MEMEQ(echo, cr, SVPN_RANDOM_LEN);
    ASSERT_MEMEQ(sr2, sr, SVPN_RANDOM_LEN);

    ASSERT_EQ_INT(kx_client_session(crx, ctx, cpk, csk, spk), 0);
    ASSERT_EQ_INT(kx_server_session(srx, stx, spk, ssk, cpk), 0);
    ASSERT_MEMEQ(ctx, srx, SVPN_KX_SS_BYTES);
    ASSERT_MEMEQ(crx, stx, SVPN_KX_SS_BYTES);

    session_id_compute(sid_c, cr, sr, cpk, spk);
    session_id_compute(sid_s, cr, sr, cpk, spk);
    ASSERT_MEMEQ(sid_c, sid_s, SVPN_SESSION_ID_LEN);
}
