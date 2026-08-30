#include "handshake.h"
#include "crypto.h"
#include "protocol.h"
#include "udp.h"
#include "util.h"

#include <errno.h>
#include <poll.h>
#include <sodium.h>
#include <string.h>

static void chlo_transcript(uint8_t version,
                            const uint8_t client_random[SVPN_RANDOM_LEN],
                            const uint8_t client_eph_pk[SVPN_KX_PK_BYTES],
                            uint8_t *out, size_t *out_len)
{
    size_t n = 0;
    memcpy(out + n, SVPN_CHLO_PREFIX, strlen(SVPN_CHLO_PREFIX));
    n += strlen(SVPN_CHLO_PREFIX);
    out[n++] = version;
    memcpy(out + n, client_random, SVPN_RANDOM_LEN);
    n += SVPN_RANDOM_LEN;
    memcpy(out + n, client_eph_pk, SVPN_KX_PK_BYTES);
    n += SVPN_KX_PK_BYTES;
    *out_len = n;
}

static void shlo_transcript(uint8_t version,
                            const uint8_t client_random[SVPN_RANDOM_LEN],
                            const uint8_t server_random[SVPN_RANDOM_LEN],
                            const uint8_t client_eph_pk[SVPN_KX_PK_BYTES],
                            const uint8_t server_eph_pk[SVPN_KX_PK_BYTES],
                            uint8_t *out, size_t *out_len)
{
    size_t n = 0;
    memcpy(out + n, SVPN_SHLO_PREFIX, strlen(SVPN_SHLO_PREFIX));
    n += strlen(SVPN_SHLO_PREFIX);
    out[n++] = version;
    memcpy(out + n, client_random, SVPN_RANDOM_LEN);
    n += SVPN_RANDOM_LEN;
    memcpy(out + n, server_random, SVPN_RANDOM_LEN);
    n += SVPN_RANDOM_LEN;
    memcpy(out + n, client_eph_pk, SVPN_KX_PK_BYTES);
    n += SVPN_KX_PK_BYTES;
    memcpy(out + n, server_eph_pk, SVPN_KX_PK_BYTES);
    n += SVPN_KX_PK_BYTES;
    *out_len = n;
}

void handshake_sign_client(const uint8_t id_sk[SVPN_SIGN_SK_BYTES],
                           uint8_t version,
                           const uint8_t client_random[SVPN_RANDOM_LEN],
                           const uint8_t client_eph_pk[SVPN_KX_PK_BYTES],
                           uint8_t sig[SVPN_SIGN_BYTES])
{
    uint8_t t[128];
    size_t tlen = 0;
    chlo_transcript(version, client_random, client_eph_pk, t, &tlen);
    crypto_sign_detached(sig, NULL, t, tlen, id_sk);
}

int handshake_verify_client(const uint8_t id_pk[SVPN_SIGN_PK_BYTES],
                            uint8_t version,
                            const uint8_t client_random[SVPN_RANDOM_LEN],
                            const uint8_t client_eph_pk[SVPN_KX_PK_BYTES],
                            const uint8_t sig[SVPN_SIGN_BYTES])
{
    uint8_t t[128];
    size_t tlen = 0;
    chlo_transcript(version, client_random, client_eph_pk, t, &tlen);
    return crypto_sign_verify_detached(sig, t, tlen, id_pk);
}

void handshake_sign_server(const uint8_t id_sk[SVPN_SIGN_SK_BYTES],
                           uint8_t version,
                           const uint8_t client_random[SVPN_RANDOM_LEN],
                           const uint8_t server_random[SVPN_RANDOM_LEN],
                           const uint8_t client_eph_pk[SVPN_KX_PK_BYTES],
                           const uint8_t server_eph_pk[SVPN_KX_PK_BYTES],
                           uint8_t sig[SVPN_SIGN_BYTES])
{
    uint8_t t[192];
    size_t tlen = 0;
    shlo_transcript(version, client_random, server_random, client_eph_pk,
                    server_eph_pk, t, &tlen);
    crypto_sign_detached(sig, NULL, t, tlen, id_sk);
}

int handshake_verify_server(const uint8_t id_pk[SVPN_SIGN_PK_BYTES],
                            uint8_t version,
                            const uint8_t client_random[SVPN_RANDOM_LEN],
                            const uint8_t server_random[SVPN_RANDOM_LEN],
                            const uint8_t client_eph_pk[SVPN_KX_PK_BYTES],
                            const uint8_t server_eph_pk[SVPN_KX_PK_BYTES],
                            const uint8_t sig[SVPN_SIGN_BYTES])
{
    uint8_t t[192];
    size_t tlen = 0;
    shlo_transcript(version, client_random, server_random, client_eph_pk,
                    server_eph_pk, t, &tlen);
    return crypto_sign_verify_detached(sig, t, tlen, id_pk);
}

static size_t wrap_header(uint8_t *out, size_t cap, uint8_t type,
                          const uint8_t *payload, uint16_t plen)
{
    struct svpn_hdr h;

    if (cap < SVPN_HEADER_SIZE + (size_t)plen) {
        return 0;
    }
    memset(&h, 0, sizeof(h));
    h.version = SVPN_VERSION;
    h.type = type;
    h.plaintext_len = plen;
    protocol_encode(out, &h);
    memcpy(out + SVPN_HEADER_SIZE, payload, plen);
    return SVPN_HEADER_SIZE + (size_t)plen;
}

size_t handshake_build_chlo(uint8_t *out, size_t cap,
                            const uint8_t id_sk[SVPN_SIGN_SK_BYTES],
                            const uint8_t client_eph_pk[SVPN_KX_PK_BYTES],
                            const uint8_t client_random[SVPN_RANDOM_LEN])
{
    uint8_t payload[SVPN_CHLO_PAYLOAD_LEN];
    uint8_t sig[SVPN_SIGN_BYTES];

    handshake_sign_client(id_sk, SVPN_VERSION, client_random, client_eph_pk, sig);
    memcpy(payload, client_eph_pk, SVPN_KX_PK_BYTES);
    memcpy(payload + SVPN_KX_PK_BYTES, client_random, SVPN_RANDOM_LEN);
    memcpy(payload + SVPN_KX_PK_BYTES + SVPN_RANDOM_LEN, sig, SVPN_SIGN_BYTES);
    return wrap_header(out, cap, SVPN_TYPE_CLIENT_HELLO, payload, SVPN_CHLO_PAYLOAD_LEN);
}

size_t handshake_build_shlo(uint8_t *out, size_t cap,
                            const uint8_t id_sk[SVPN_SIGN_SK_BYTES],
                            const uint8_t client_eph_pk[SVPN_KX_PK_BYTES],
                            const uint8_t server_eph_pk[SVPN_KX_PK_BYTES],
                            const uint8_t client_random[SVPN_RANDOM_LEN],
                            const uint8_t server_random[SVPN_RANDOM_LEN])
{
    uint8_t payload[SVPN_SHLO_PAYLOAD_LEN];
    uint8_t sig[SVPN_SIGN_BYTES];
    size_t o = 0;

    handshake_sign_server(id_sk, SVPN_VERSION, client_random, server_random,
                          client_eph_pk, server_eph_pk, sig);
    memcpy(payload + o, server_eph_pk, SVPN_KX_PK_BYTES);
    o += SVPN_KX_PK_BYTES;
    memcpy(payload + o, client_random, SVPN_RANDOM_LEN);
    o += SVPN_RANDOM_LEN;
    memcpy(payload + o, server_random, SVPN_RANDOM_LEN);
    o += SVPN_RANDOM_LEN;
    memcpy(payload + o, sig, SVPN_SIGN_BYTES);
    return wrap_header(out, cap, SVPN_TYPE_SERVER_HELLO, payload, SVPN_SHLO_PAYLOAD_LEN);
}

int handshake_parse_chlo(const uint8_t *pkt, size_t n,
                         uint8_t client_eph_pk[SVPN_KX_PK_BYTES],
                         uint8_t client_random[SVPN_RANDOM_LEN],
                         uint8_t sig[SVPN_SIGN_BYTES])
{
    struct svpn_hdr h;
    int rc = protocol_decode(pkt, n, &h);
    const uint8_t *body;

    if (rc != SVPN_OK || h.type != SVPN_TYPE_CLIENT_HELLO) {
        return SVPN_ERR_TYPE;
    }
    rc = protocol_check_body(&h, n - SVPN_HEADER_SIZE, 0);
    if (rc != SVPN_OK) {
        return rc;
    }
    body = pkt + SVPN_HEADER_SIZE;
    memcpy(client_eph_pk, body, SVPN_KX_PK_BYTES);
    memcpy(client_random, body + SVPN_KX_PK_BYTES, SVPN_RANDOM_LEN);
    memcpy(sig, body + SVPN_KX_PK_BYTES + SVPN_RANDOM_LEN, SVPN_SIGN_BYTES);
    return SVPN_OK;
}

int handshake_parse_shlo(const uint8_t *pkt, size_t n,
                         uint8_t server_eph_pk[SVPN_KX_PK_BYTES],
                         uint8_t client_random_echo[SVPN_RANDOM_LEN],
                         uint8_t server_random[SVPN_RANDOM_LEN],
                         uint8_t sig[SVPN_SIGN_BYTES])
{
    struct svpn_hdr h;
    int rc = protocol_decode(pkt, n, &h);
    const uint8_t *body;
    size_t o = 0;

    if (rc != SVPN_OK || h.type != SVPN_TYPE_SERVER_HELLO) {
        return SVPN_ERR_TYPE;
    }
    rc = protocol_check_body(&h, n - SVPN_HEADER_SIZE, 0);
    if (rc != SVPN_OK) {
        return rc;
    }
    body = pkt + SVPN_HEADER_SIZE;
    memcpy(server_eph_pk, body + o, SVPN_KX_PK_BYTES);
    o += SVPN_KX_PK_BYTES;
    memcpy(client_random_echo, body + o, SVPN_RANDOM_LEN);
    o += SVPN_RANDOM_LEN;
    memcpy(server_random, body + o, SVPN_RANDOM_LEN);
    o += SVPN_RANDOM_LEN;
    memcpy(sig, body + o, SVPN_SIGN_BYTES);
    return SVPN_OK;
}

static int wait_readable(int fd, int timeout_ms, volatile sig_atomic_t *stop_flag)
{
    struct pollfd pfd;
    int rc;

    pfd.fd = fd;
    pfd.events = POLLIN;
    pfd.revents = 0;
    do {
        if (stop_flag != NULL && *stop_flag) {
            return -2;
        }
        rc = poll(&pfd, 1, timeout_ms);
    } while (rc < 0 && errno == EINTR);

    if (rc < 0) {
        return -1;
    }
    if (rc == 0) {
        return 0;
    }
    return (pfd.revents & POLLIN) ? 1 : 0;
}

int handshake_run_client(int udp_fd,
                         const char *peer_ip, uint16_t peer_port,
                         const uint8_t id_sk[SVPN_SIGN_SK_BYTES],
                         const uint8_t peer_pk[SVPN_SIGN_PK_BYTES],
                         volatile sig_atomic_t *stop_flag,
                         struct handshake_result *out)
{
    uint8_t eph_pk[SVPN_KX_PK_BYTES];
    uint8_t eph_sk[SVPN_KX_SK_BYTES];
    uint8_t client_random[SVPN_RANDOM_LEN];
    uint8_t chlo[SVPN_HEADER_SIZE + SVPN_CHLO_PAYLOAD_LEN];
    size_t chlo_len;
    uint64_t start = monotonic_ms();
    uint64_t last_send = 0;
    char fp[33];

    memset(out, 0, sizeof(*out));
    if (kx_keypair(eph_pk, eph_sk) != 0) {
        log_error("ephemeral keypair generation failed");
        return SVPN_ERR_CRYPTO;
    }
    randombytes_buf(client_random, sizeof(client_random));
    chlo_len = handshake_build_chlo(chlo, sizeof(chlo), id_sk, eph_pk, client_random);
    memcpy(out->client_eph_pk, eph_pk, SVPN_KX_PK_BYTES);
    memcpy(out->client_random, client_random, SVPN_RANDOM_LEN);

    identity_fingerprint(peer_pk, fp, sizeof(fp));
    log_info("waiting for encrypted handshake (pinned peer fingerprint=%s)", fp);

    while (stop_flag == NULL || !*stop_flag) {
        uint64_t now = monotonic_ms();
        uint64_t elapsed = now - start;
        int wait_ms;
        uint8_t buf[SVPN_UDP_BUFSZ];
        char src_ip[64];
        uint16_t src_port = 0;
        ssize_t n;
        uint8_t server_eph[SVPN_KX_PK_BYTES];
        uint8_t echo[SVPN_RANDOM_LEN];
        uint8_t server_random[SVPN_RANDOM_LEN];
        uint8_t sig[SVPN_SIGN_BYTES];
        int wr;

        if (elapsed >= SVPN_HANDSHAKE_TIMEOUT_MS) {
            sodium_memzero(eph_sk, sizeof(eph_sk));
            log_error("handshake timed out");
            return SVPN_ERR_TIMEOUT;
        }
        if (last_send == 0 || now - last_send >= SVPN_RETRANSMIT_MS) {
            if (udp_send_to(udp_fd, peer_ip, peer_port, chlo, chlo_len) == 0) {
                log_verbose("sent CLIENT_HELLO");
            }
            last_send = now;
        }
        wait_ms = (int)(SVPN_RETRANSMIT_MS - (monotonic_ms() - last_send));
        if (wait_ms < 0) {
            wait_ms = 0;
        }
        if ((uint64_t)wait_ms > SVPN_HANDSHAKE_TIMEOUT_MS - elapsed) {
            wait_ms = (int)(SVPN_HANDSHAKE_TIMEOUT_MS - elapsed);
        }

        wr = wait_readable(udp_fd, wait_ms, stop_flag);
        if (wr == -2) {
            break;
        }
        if (wr <= 0) {
            continue;
        }
        n = udp_recv_from(udp_fd, buf, sizeof(buf), src_ip, sizeof(src_ip), &src_port);
        if (n <= 0) {
            continue;
        }
        if (!peer_is_expected(src_ip, src_port, peer_ip, peer_port)) {
            log_warn("dropped packet from unexpected peer");
            continue;
        }
        if (handshake_parse_shlo(buf, (size_t)n, server_eph, echo, server_random, sig) != SVPN_OK) {
            log_verbose("ignored non-SERVER_HELLO during handshake");
            continue;
        }
        if (memcmp(echo, client_random, SVPN_RANDOM_LEN) != 0) {
            log_warn("SERVER_HELLO echoed wrong client random");
            continue;
        }
        if (handshake_verify_server(peer_pk, SVPN_VERSION, client_random, server_random,
                                    eph_pk, server_eph, sig) != 0) {
            /* A packet with a spoofed source address must not make a client
             * give up before the normal timeout.  Keep waiting for the
             * pinned peer's valid response, as the server does for CHLO. */
            log_warn("ignored SERVER_HELLO with invalid peer signature");
            continue;
        }
        log_info("peer identity verified");
        if (kx_client_session(out->rx, out->tx, eph_pk, eph_sk, server_eph) != 0) {
            log_error("session key derivation failed");
            sodium_memzero(eph_sk, sizeof(eph_sk));
            return SVPN_ERR_CRYPTO;
        }
        memcpy(out->server_eph_pk, server_eph, SVPN_KX_PK_BYTES);
        memcpy(out->server_random, server_random, SVPN_RANDOM_LEN);
        session_id_compute(out->session_id, client_random, server_random, eph_pk, server_eph);
        sodium_memzero(eph_sk, sizeof(eph_sk));
        return SVPN_OK;
    }
    sodium_memzero(eph_sk, sizeof(eph_sk));
    return SVPN_ERR_TIMEOUT;
}

int handshake_run_server(int udp_fd,
                         const char *peer_ip, uint16_t peer_port,
                         const uint8_t id_sk[SVPN_SIGN_SK_BYTES],
                         const uint8_t peer_pk[SVPN_SIGN_PK_BYTES],
                         volatile sig_atomic_t *stop_flag,
                         struct handshake_result *out)
{
    uint8_t eph_pk[SVPN_KX_PK_BYTES];
    uint8_t eph_sk[SVPN_KX_SK_BYTES];
    uint8_t server_random[SVPN_RANDOM_LEN];

    memset(out, 0, sizeof(*out));
    if (kx_keypair(eph_pk, eph_sk) != 0) {
        log_error("ephemeral keypair generation failed");
        return SVPN_ERR_CRYPTO;
    }
    randombytes_buf(server_random, sizeof(server_random));
    memcpy(out->server_eph_pk, eph_pk, SVPN_KX_PK_BYTES);
    memcpy(out->server_random, server_random, SVPN_RANDOM_LEN);

    log_info("waiting for encrypted handshake");

    while (stop_flag == NULL || !*stop_flag) {
        uint8_t buf[SVPN_UDP_BUFSZ];
        char src_ip[64];
        uint16_t src_port = 0;
        ssize_t n;
        uint8_t client_eph[SVPN_KX_PK_BYTES];
        uint8_t client_random[SVPN_RANDOM_LEN];
        uint8_t sig[SVPN_SIGN_BYTES];
        int prc;

        prc = wait_readable(udp_fd, 500, stop_flag);
        if (prc < 0) {
            break;
        }
        if (prc == 0) {
            continue;
        }
        n = udp_recv_from(udp_fd, buf, sizeof(buf), src_ip, sizeof(src_ip), &src_port);
        if (n <= 0) {
            continue;
        }
        if (!peer_is_expected(src_ip, src_port, peer_ip, peer_port)) {
            log_warn("dropped packet from unexpected peer");
            continue;
        }
        if (handshake_parse_chlo(buf, (size_t)n, client_eph, client_random, sig) != SVPN_OK) {
            log_verbose("ignored non-CLIENT_HELLO during handshake");
            continue;
        }
        if (out->have_first_chlo &&
            memcmp(buf + SVPN_HEADER_SIZE, out->first_chlo_payload, SVPN_CHLO_PAYLOAD_LEN) == 0) {
            udp_send_to(udp_fd, peer_ip, peer_port, out->last_shlo, out->last_shlo_len);
            log_verbose("retransmitted SERVER_HELLO");
            continue;
        }
        if (handshake_verify_client(peer_pk, SVPN_VERSION, client_random, client_eph, sig) != 0) {
            log_error("peer signature invalid (client identity)");
            continue; /* wait for a valid hello; do not crash */
        }
        log_info("peer identity verified");
        if (kx_server_session(out->rx, out->tx, eph_pk, eph_sk, client_eph) != 0) {
            log_error("session key derivation failed");
            sodium_memzero(eph_sk, sizeof(eph_sk));
            return SVPN_ERR_CRYPTO;
        }
        memcpy(out->client_eph_pk, client_eph, SVPN_KX_PK_BYTES);
        memcpy(out->client_random, client_random, SVPN_RANDOM_LEN);
        session_id_compute(out->session_id, client_random, server_random, client_eph, eph_pk);
        out->last_shlo_len = handshake_build_shlo(out->last_shlo, sizeof(out->last_shlo),
                                                  id_sk, client_eph, eph_pk,
                                                  client_random, server_random);
        memcpy(out->first_chlo_payload, buf + SVPN_HEADER_SIZE, SVPN_CHLO_PAYLOAD_LEN);
        out->have_first_chlo = 1;
        if (udp_send_to(udp_fd, peer_ip, peer_port, out->last_shlo, out->last_shlo_len) != 0) {
            sodium_memzero(eph_sk, sizeof(eph_sk));
            return SVPN_ERR_IO;
        }
        sodium_memzero(eph_sk, sizeof(eph_sk));
        return SVPN_OK;
    }
    sodium_memzero(eph_sk, sizeof(eph_sk));
    return SVPN_ERR_TIMEOUT;
}
