#ifndef SVPN_COMMON_H
#define SVPN_COMMON_H

#include <stddef.h>
#include <stdint.h>
#include <stdbool.h>

#define SVPN_MAGIC              "SVPN"
#define SVPN_MAGIC_LEN          4
#define SVPN_VERSION            1
#define SVPN_HEADER_SIZE        28
#define SVPN_MAX_INNER          1400
#define SVPN_AEAD_TAG           16
#define SVPN_UDP_BUFSZ          2048
#define SVPN_RANDOM_LEN         16
#define SVPN_SESSION_ID_LEN     8
#define SVPN_NONCE_LEN          12
#define SVPN_RETRANSMIT_MS      500
#define SVPN_HANDSHAKE_TIMEOUT_MS 10000

#define SVPN_SIGN_SK_BYTES      64
#define SVPN_SIGN_PK_BYTES      32
#define SVPN_SIGN_BYTES         64
#define SVPN_KX_PK_BYTES        32
#define SVPN_KX_SK_BYTES        32
#define SVPN_KX_SS_BYTES        32
#define SVPN_AEAD_KEY_BYTES     32

#define SVPN_CHLO_PAYLOAD_LEN   (SVPN_KX_PK_BYTES + SVPN_RANDOM_LEN + SVPN_SIGN_BYTES)
#define SVPN_SHLO_PAYLOAD_LEN   (SVPN_KX_PK_BYTES + SVPN_RANDOM_LEN + SVPN_RANDOM_LEN + SVPN_SIGN_BYTES)

#define SVPN_TYPE_CLIENT_HELLO  1
#define SVPN_TYPE_SERVER_HELLO  2
#define SVPN_TYPE_DATA          3
#define SVPN_TYPE_CLOSE         4

#define SVPN_ROLE_CLIENT        0
#define SVPN_ROLE_SERVER        1

#define SVPN_MODE_PLAINTEXT     0
#define SVPN_MODE_ENCRYPTED     1

#define SVPN_OK                 0
#define SVPN_ERR_SHORT          -1
#define SVPN_ERR_MAGIC          -2
#define SVPN_ERR_VERSION        -3
#define SVPN_ERR_TYPE           -4
#define SVPN_ERR_LEN            -5
#define SVPN_ERR_TRAILING       -6
#define SVPN_ERR_ZERO_PAYLOAD   -7
#define SVPN_ERR_OVERSIZE       -8
#define SVPN_ERR_CRYPTO         -9
#define SVPN_ERR_AUTH           -10
#define SVPN_ERR_REPLAY         -11
#define SVPN_ERR_IO             -12
#define SVPN_ERR_TIMEOUT        -13
#define SVPN_ERR_ARG            -14
#define SVPN_ERR_HEADER         -15

struct svpn_hdr {
    uint8_t  version;
    uint8_t  type;
    uint16_t flags;
    uint8_t  session_id[SVPN_SESSION_ID_LEN];
    uint64_t sequence;
    uint16_t plaintext_len;
};

struct svpn_stats {
    uint64_t tun_packets_read;
    uint64_t tun_bytes_read;
    uint64_t udp_packets_sent;
    uint64_t udp_bytes_sent;
    uint64_t udp_packets_received;
    uint64_t udp_bytes_received;
    uint64_t tun_packets_written;
    uint64_t tun_bytes_written;
    uint64_t malformed_drops;
    uint64_t wrong_peer_drops;
    uint64_t wrong_session_drops;
    uint64_t auth_failures;
    uint64_t replay_drops;
};

#endif /* SVPN_COMMON_H */
