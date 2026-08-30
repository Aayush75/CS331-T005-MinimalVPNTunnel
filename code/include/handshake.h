#ifndef SVPN_HANDSHAKE_H
#define SVPN_HANDSHAKE_H

#include "common.h"

#include <signal.h>

#define SVPN_CHLO_PREFIX "SVPN-CHLO-v1"
#define SVPN_SHLO_PREFIX "SVPN-SHLO-v1"

struct handshake_result {
    uint8_t rx[SVPN_KX_SS_BYTES];
    uint8_t tx[SVPN_KX_SS_BYTES];
    uint8_t session_id[SVPN_SESSION_ID_LEN];
    uint8_t client_random[SVPN_RANDOM_LEN];
    uint8_t server_random[SVPN_RANDOM_LEN];
    uint8_t client_eph_pk[SVPN_KX_PK_BYTES];
    uint8_t server_eph_pk[SVPN_KX_PK_BYTES];
    /* Server retains the last SERVER_HELLO datagram to retransmit. */
    uint8_t last_shlo[SVPN_HEADER_SIZE + SVPN_SHLO_PAYLOAD_LEN];
    size_t last_shlo_len;
    uint8_t first_chlo_payload[SVPN_CHLO_PAYLOAD_LEN];
    int have_first_chlo;
};

void handshake_sign_client(const uint8_t id_sk[SVPN_SIGN_SK_BYTES],
                           uint8_t version,
                           const uint8_t client_random[SVPN_RANDOM_LEN],
                           const uint8_t client_eph_pk[SVPN_KX_PK_BYTES],
                           uint8_t sig[SVPN_SIGN_BYTES]);

int handshake_verify_client(const uint8_t id_pk[SVPN_SIGN_PK_BYTES],
                            uint8_t version,
                            const uint8_t client_random[SVPN_RANDOM_LEN],
                            const uint8_t client_eph_pk[SVPN_KX_PK_BYTES],
                            const uint8_t sig[SVPN_SIGN_BYTES]);

void handshake_sign_server(const uint8_t id_sk[SVPN_SIGN_SK_BYTES],
                           uint8_t version,
                           const uint8_t client_random[SVPN_RANDOM_LEN],
                           const uint8_t server_random[SVPN_RANDOM_LEN],
                           const uint8_t client_eph_pk[SVPN_KX_PK_BYTES],
                           const uint8_t server_eph_pk[SVPN_KX_PK_BYTES],
                           uint8_t sig[SVPN_SIGN_BYTES]);

int handshake_verify_server(const uint8_t id_pk[SVPN_SIGN_PK_BYTES],
                            uint8_t version,
                            const uint8_t client_random[SVPN_RANDOM_LEN],
                            const uint8_t server_random[SVPN_RANDOM_LEN],
                            const uint8_t client_eph_pk[SVPN_KX_PK_BYTES],
                            const uint8_t server_eph_pk[SVPN_KX_PK_BYTES],
                            const uint8_t sig[SVPN_SIGN_BYTES]);

size_t handshake_build_chlo(uint8_t *out, size_t cap,
                            const uint8_t id_sk[SVPN_SIGN_SK_BYTES],
                            const uint8_t client_eph_pk[SVPN_KX_PK_BYTES],
                            const uint8_t client_random[SVPN_RANDOM_LEN]);

size_t handshake_build_shlo(uint8_t *out, size_t cap,
                            const uint8_t id_sk[SVPN_SIGN_SK_BYTES],
                            const uint8_t client_eph_pk[SVPN_KX_PK_BYTES],
                            const uint8_t server_eph_pk[SVPN_KX_PK_BYTES],
                            const uint8_t client_random[SVPN_RANDOM_LEN],
                            const uint8_t server_random[SVPN_RANDOM_LEN]);

int handshake_parse_chlo(const uint8_t *pkt, size_t n,
                         uint8_t client_eph_pk[SVPN_KX_PK_BYTES],
                         uint8_t client_random[SVPN_RANDOM_LEN],
                         uint8_t sig[SVPN_SIGN_BYTES]);

int handshake_parse_shlo(const uint8_t *pkt, size_t n,
                         uint8_t server_eph_pk[SVPN_KX_PK_BYTES],
                         uint8_t client_random_echo[SVPN_RANDOM_LEN],
                         uint8_t server_random[SVPN_RANDOM_LEN],
                         uint8_t sig[SVPN_SIGN_BYTES]);

/*
 * Blocking (poll + timeout) handshake over an already-bound UDP socket.
 * stop_flag is the process SIGINT/SIGTERM flag.
 */
int handshake_run_client(int udp_fd,
                         const char *peer_ip, uint16_t peer_port,
                         const uint8_t id_sk[SVPN_SIGN_SK_BYTES],
                         const uint8_t peer_pk[SVPN_SIGN_PK_BYTES],
                         volatile sig_atomic_t *stop_flag,
                         struct handshake_result *out);

int handshake_run_server(int udp_fd,
                         const char *peer_ip, uint16_t peer_port,
                         const uint8_t id_sk[SVPN_SIGN_SK_BYTES],
                         const uint8_t peer_pk[SVPN_SIGN_PK_BYTES],
                         volatile sig_atomic_t *stop_flag,
                         struct handshake_result *out);

#endif /* SVPN_HANDSHAKE_H */
