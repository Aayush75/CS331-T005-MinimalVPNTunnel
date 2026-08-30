#include "common.h"
#include "crypto.h"
#include "handshake.h"
#include "protocol.h"
#include "replay.h"
#include "tun.h"
#include "udp.h"
#include "util.h"

#include <errno.h>
#include <getopt.h>
#include <poll.h>
#include <signal.h>
#include <sodium.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

static volatile sig_atomic_t g_stop;

static void on_signal(int sig)
{
    (void)sig;
    g_stop = 1;
}

struct options {
    int role;
    int mode;
    const char *tun;
    const char *bind_ip;
    uint16_t bind_port;
    const char *peer_ip;
    uint16_t peer_port;
    const char *id_secret;
    const char *peer_pub;
    int stats_interval;
};

static void usage(FILE *fp)
{
    fprintf(fp,
            "Usage: svpn --role client|server --mode plaintext|encrypted \\\n"
            "            --tun NAME --bind-ip IPV4 --bind-port PORT \\\n"
            "            --peer-ip IPV4 --peer-port PORT \\\n"
            "            [--identity-secret PATH] [--peer-identity-public PATH] \\\n"
            "            [--stats-interval N] [--verbose] [--help]\n");
}

static int parse_args(int argc, char **argv, struct options *o)
{
    static const struct option longopts[] = {
        {"role", required_argument, NULL, 'r'},
        {"mode", required_argument, NULL, 'm'},
        {"tun", required_argument, NULL, 't'},
        {"bind-ip", required_argument, NULL, 'b'},
        {"bind-port", required_argument, NULL, 'B'},
        {"peer-ip", required_argument, NULL, 'p'},
        {"peer-port", required_argument, NULL, 'P'},
        {"identity-secret", required_argument, NULL, 's'},
        {"peer-identity-public", required_argument, NULL, 'k'},
        {"stats-interval", required_argument, NULL, 'i'},
        {"verbose", no_argument, NULL, 'v'},
        {"help", no_argument, NULL, 'h'},
        {0, 0, 0, 0},
    };
    int c;
    int got_role = 0, got_mode = 0, got_tun = 0, got_bind = 0, got_bport = 0;
    int got_peer = 0, got_pport = 0;

    memset(o, 0, sizeof(*o));
    o->stats_interval = 0;

    while ((c = getopt_long(argc, argv, "hvr:m:t:", longopts, NULL)) != -1) {
        switch (c) {
        case 'r':
            if (strcmp(optarg, "client") == 0) {
                o->role = SVPN_ROLE_CLIENT;
            } else if (strcmp(optarg, "server") == 0) {
                o->role = SVPN_ROLE_SERVER;
            } else {
                log_error("--role must be client or server");
                return -1;
            }
            got_role = 1;
            break;
        case 'm':
            if (strcmp(optarg, "plaintext") == 0) {
                o->mode = SVPN_MODE_PLAINTEXT;
            } else if (strcmp(optarg, "encrypted") == 0) {
                o->mode = SVPN_MODE_ENCRYPTED;
            } else {
                log_error("--mode must be plaintext or encrypted");
                return -1;
            }
            got_mode = 1;
            break;
        case 't':
            o->tun = optarg;
            got_tun = 1;
            break;
        case 'b':
            o->bind_ip = optarg;
            got_bind = 1;
            break;
        case 'B':
            if (parse_port(optarg, &o->bind_port) != 0) {
                log_error("bad --bind-port");
                return -1;
            }
            got_bport = 1;
            break;
        case 'p':
            o->peer_ip = optarg;
            got_peer = 1;
            break;
        case 'P':
            if (parse_port(optarg, &o->peer_port) != 0) {
                log_error("bad --peer-port");
                return -1;
            }
            got_pport = 1;
            break;
        case 's':
            o->id_secret = optarg;
            break;
        case 'k':
            o->peer_pub = optarg;
            break;
        case 'i':
            o->stats_interval = atoi(optarg);
            if (o->stats_interval < 0) {
                log_error("bad --stats-interval");
                return -1;
            }
            break;
        case 'v':
            g_verbose = 1;
            break;
        case 'h':
            usage(stdout);
            exit(0);
        default:
            usage(stderr);
            return -1;
        }
    }
    if (!got_role || !got_mode || !got_tun || !got_bind || !got_bport || !got_peer ||
        !got_pport) {
        usage(stderr);
        return -1;
    }
    if (o->mode == SVPN_MODE_ENCRYPTED && (o->id_secret == NULL || o->peer_pub == NULL)) {
        log_error("encrypted mode requires --identity-secret and --peer-identity-public");
        return -1;
    }
    return 0;
}

static void print_stats(const struct svpn_stats *s)
{
    log_info("stats tun_read=%llu/%llu tun_write=%llu/%llu "
             "udp_sent=%llu/%llu udp_recv=%llu/%llu "
             "drop_malformed=%llu drop_peer=%llu drop_session=%llu "
             "drop_auth=%llu drop_replay=%llu",
             (unsigned long long)s->tun_packets_read,
             (unsigned long long)s->tun_bytes_read,
             (unsigned long long)s->tun_packets_written,
             (unsigned long long)s->tun_bytes_written,
             (unsigned long long)s->udp_packets_sent,
             (unsigned long long)s->udp_bytes_sent,
             (unsigned long long)s->udp_packets_received,
             (unsigned long long)s->udp_bytes_received,
             (unsigned long long)s->malformed_drops,
             (unsigned long long)s->wrong_peer_drops,
             (unsigned long long)s->wrong_session_drops,
             (unsigned long long)s->auth_failures,
             (unsigned long long)s->replay_drops);
}

static int send_data(int udp_fd, const struct options *opt, const uint8_t *sid,
                     uint64_t seq, const uint8_t *inner, uint16_t inner_len,
                     const uint8_t *tx_key, int encrypted, int a2b_tx,
                     struct svpn_stats *st)
{
    uint8_t pkt[SVPN_UDP_BUFSZ];
    struct svpn_hdr h;
    size_t total;

    memset(&h, 0, sizeof(h));
    h.version = SVPN_VERSION;
    h.type = SVPN_TYPE_DATA;
    if (sid != NULL) {
        memcpy(h.session_id, sid, SVPN_SESSION_ID_LEN);
    }
    h.sequence = seq;
    h.plaintext_len = inner_len;
    protocol_encode(pkt, &h);

    if (encrypted) {
        uint8_t nonce[SVPN_NONCE_LEN];
        size_t clen = 0;
        nonce_build(nonce, sid, a2b_tx, seq);
        if (aead_encrypt(tx_key, nonce, pkt, SVPN_HEADER_SIZE, inner, inner_len,
                         pkt + SVPN_HEADER_SIZE, &clen) != 0) {
            log_error("AEAD encrypt failed");
            return -1;
        }
        total = SVPN_HEADER_SIZE + clen;
    } else {
        memcpy(pkt + SVPN_HEADER_SIZE, inner, inner_len);
        total = SVPN_HEADER_SIZE + inner_len;
    }

    if (udp_send_to(udp_fd, opt->peer_ip, opt->peer_port, pkt, total) != 0) {
        return -1;
    }
    st->udp_packets_sent++;
    st->udp_bytes_sent += total;
    return 0;
}

static int handle_udp(int tun_fd, int udp_fd, const struct options *opt,
                      const struct handshake_result *hs, const uint8_t *rx_key,
                      int a2b_rx, struct replay_window *rw, struct svpn_stats *st)
{
    uint8_t buf[SVPN_UDP_BUFSZ];
    char src_ip[64];
    uint16_t src_port = 0;
    ssize_t n;
    struct svpn_hdr h;
    int rc;
    uint8_t inner[SVPN_MAX_INNER];
    size_t inner_len = 0;
    const uint8_t *body;

    n = udp_recv_from(udp_fd, buf, sizeof(buf), src_ip, sizeof(src_ip), &src_port);
    if (n < 0) {
        return 0;
    }
    if (n == 0) {
        return 0;
    }
    st->udp_packets_received++;
    st->udp_bytes_received += (uint64_t)n;

    if (!peer_is_expected(src_ip, src_port, opt->peer_ip, opt->peer_port)) {
        st->wrong_peer_drops++;
        log_warn("dropped packet from unexpected peer");
        return 0;
    }

    /* Duplicate CLIENT_HELLO after session: retransmit SERVER_HELLO. */
    if (opt->mode == SVPN_MODE_ENCRYPTED && opt->role == SVPN_ROLE_SERVER &&
        hs != NULL && hs->have_first_chlo && (size_t)n == SVPN_HEADER_SIZE + SVPN_CHLO_PAYLOAD_LEN &&
        memcmp(buf + SVPN_HEADER_SIZE, hs->first_chlo_payload, SVPN_CHLO_PAYLOAD_LEN) == 0) {
        udp_send_to(udp_fd, opt->peer_ip, opt->peer_port, hs->last_shlo, hs->last_shlo_len);
        log_verbose("retransmitted SERVER_HELLO");
        return 0;
    }

    rc = protocol_decode(buf, (size_t)n, &h);
    if (rc != SVPN_OK) {
        st->malformed_drops++;
        log_warn("dropped malformed packet");
        log_verbose("parse: %s", protocol_errstr(rc));
        return 0;
    }
    rc = protocol_check_body(&h, (size_t)n - SVPN_HEADER_SIZE, opt->mode == SVPN_MODE_ENCRYPTED);
    if (rc != SVPN_OK) {
        st->malformed_drops++;
        log_warn("dropped malformed packet");
        log_verbose("body: %s", protocol_errstr(rc));
        return 0;
    }
    if (h.type != SVPN_TYPE_DATA) {
        log_verbose("ignored non-DATA type=%u", h.type);
        return 0;
    }

    if (opt->mode == SVPN_MODE_ENCRYPTED) {
        uint8_t nonce[SVPN_NONCE_LEN];
        if (memcmp(h.session_id, hs->session_id, SVPN_SESSION_ID_LEN) != 0) {
            st->wrong_session_drops++;
            log_warn("dropped packet with wrong session id");
            return 0;
        }
        nonce_build(nonce, hs->session_id, a2b_rx, h.sequence);
        body = buf + SVPN_HEADER_SIZE;
        if (aead_decrypt(rx_key, nonce, buf, SVPN_HEADER_SIZE, body,
                         (size_t)n - SVPN_HEADER_SIZE, inner, &inner_len) != 0) {
            st->auth_failures++;
            log_warn("authentication failed");
            return 0;
        }
        if (inner_len != h.plaintext_len) {
            st->malformed_drops++;
            log_warn("dropped malformed packet");
            return 0;
        }
        /* Replay state is updated only after AEAD success. */
        if (replay_check_update(rw, h.sequence) != 0) {
            st->replay_drops++;
            log_warn("replayed packet sequence=%llu", (unsigned long long)h.sequence);
            return 0;
        }
    } else {
        inner_len = h.plaintext_len;
        memcpy(inner, buf + SVPN_HEADER_SIZE, inner_len);
    }

    if (write_full(tun_fd, inner, inner_len) != (ssize_t)inner_len) {
        log_warn("TUN write failed: %s", strerror(errno));
        return 0;
    }
    st->tun_packets_written++;
    st->tun_bytes_written += inner_len;
    return 0;
}

static int handle_tun(int tun_fd, int udp_fd, const struct options *opt,
                      const uint8_t *sid, uint64_t *tx_seq, const uint8_t *tx_key,
                      int a2b_tx, struct svpn_stats *st)
{
    uint8_t inner[SVPN_MAX_INNER];
    ssize_t n;

    n = read(tun_fd, inner, sizeof(inner));
    if (n < 0) {
        if (errno == EINTR) {
            return 0;
        }
        log_warn("TUN read: %s", strerror(errno));
        return 0;
    }
    if (n == 0) {
        return 0;
    }
    if (n > SVPN_MAX_INNER) {
        st->malformed_drops++;
        return 0;
    }
    st->tun_packets_read++;
    st->tun_bytes_read += (uint64_t)n;

    if (*tx_seq == 0) {
        log_error("sequence number would wrap; terminating session");
        g_stop = 1;
        return -1;
    }
    if (send_data(udp_fd, opt, sid, *tx_seq, inner, (uint16_t)n, tx_key,
                  opt->mode == SVPN_MODE_ENCRYPTED, a2b_tx, st) != 0) {
        return 0;
    }
    if (*tx_seq == UINT64_MAX) {
        log_error("sequence number exhausted; terminating session");
        g_stop = 1;
        return -1;
    }
    (*tx_seq)++;
    return 0;
}

int main(int argc, char **argv)
{
    struct options opt;
    struct svpn_stats stats;
    struct handshake_result hs;
    struct replay_window rw;
    uint8_t id_sk[SVPN_SIGN_SK_BYTES];
    uint8_t peer_pk[SVPN_SIGN_PK_BYTES];
    uint8_t zero_sid[SVPN_SESSION_ID_LEN];
    const uint8_t *sid;
    uint64_t tx_seq = 1;
    int tun_fd = -1, udp_fd = -1;
    int a2b_tx, a2b_rx;
    struct sigaction sa;
    uint64_t last_stats = 0;
    char sidhex[17];

    memset(&stats, 0, sizeof(stats));
    memset(&hs, 0, sizeof(hs));
    memset(zero_sid, 0, sizeof(zero_sid));
    memset(id_sk, 0, sizeof(id_sk));
    memset(peer_pk, 0, sizeof(peer_pk));
    replay_init(&rw);

    if (parse_args(argc, argv, &opt) != 0) {
        return 1;
    }
    if (svpn_crypto_init() != 0) {
        return 1;
    }

    memset(&sa, 0, sizeof(sa));
    sa.sa_handler = on_signal;
    sigemptyset(&sa.sa_mask);
    sa.sa_flags = 0;
    sigaction(SIGINT, &sa, NULL);
    sigaction(SIGTERM, &sa, NULL);

    log_info("role=%s mode=%s",
             opt.role == SVPN_ROLE_CLIENT ? "client" : "server",
             opt.mode == SVPN_MODE_ENCRYPTED ? "encrypted" : "plaintext");
    log_info("tun=%s bind=%s:%u peer=%s:%u", opt.tun, opt.bind_ip, opt.bind_port,
             opt.peer_ip, opt.peer_port);

    tun_fd = tun_open(opt.tun);
    if (tun_fd < 0) {
        return 1;
    }
    udp_fd = udp_open(opt.bind_ip, opt.bind_port);
    if (udp_fd < 0) {
        close(tun_fd);
        return 1;
    }

    if (opt.mode == SVPN_MODE_ENCRYPTED) {
        int hsrc;
        if (load_secret_key(opt.id_secret, id_sk) != 0 ||
            load_public_key(opt.peer_pub, peer_pk) != 0) {
            close(udp_fd);
            close(tun_fd);
            return 1;
        }
        if (opt.role == SVPN_ROLE_CLIENT) {
            hsrc = handshake_run_client(udp_fd, opt.peer_ip, opt.peer_port, id_sk, peer_pk,
                                        &g_stop, &hs);
        } else {
            hsrc = handshake_run_server(udp_fd, opt.peer_ip, opt.peer_port, id_sk, peer_pk,
                                        &g_stop, &hs);
        }
        sodium_memzero(id_sk, sizeof(id_sk));
        if (hsrc != SVPN_OK) {
            close(udp_fd);
            close(tun_fd);
            return 1;
        }
        hex_encode(hs.session_id, SVPN_SESSION_ID_LEN, sidhex, sizeof(sidhex));
        log_info("session established id=%s", sidhex);
        sid = hs.session_id;
        a2b_tx = (opt.role == SVPN_ROLE_CLIENT);
        a2b_rx = (opt.role == SVPN_ROLE_CLIENT) ? 0 : 1;
    } else {
        sid = zero_sid;
        a2b_tx = 1;
        a2b_rx = 0;
        (void)a2b_rx;
    }

    last_stats = monotonic_ms();
    while (!g_stop) {
        struct pollfd pfds[2];
        int timeout = -1;
        int rc;

        pfds[0].fd = tun_fd;
        pfds[0].events = POLLIN;
        pfds[0].revents = 0;
        pfds[1].fd = udp_fd;
        pfds[1].events = POLLIN;
        pfds[1].revents = 0;
        if (opt.stats_interval > 0) {
            timeout = 1000;
        }
        rc = poll(pfds, 2, timeout);
        if (rc < 0) {
            if (errno == EINTR) {
                continue;
            }
            log_error("poll: %s", strerror(errno));
            break;
        }
        if (pfds[0].revents & POLLIN) {
            handle_tun(tun_fd, udp_fd, &opt, sid, &tx_seq, hs.tx, a2b_tx, &stats);
        }
        if (pfds[1].revents & POLLIN) {
            handle_udp(tun_fd, udp_fd, &opt, &hs, hs.rx, a2b_rx, &rw, &stats);
        }
        if (opt.stats_interval > 0 &&
            monotonic_ms() - last_stats >= (uint64_t)opt.stats_interval * 1000u) {
            print_stats(&stats);
            last_stats = monotonic_ms();
        }
    }

    log_info("shutting down");
    print_stats(&stats);
    sodium_memzero(hs.rx, sizeof(hs.rx));
    sodium_memzero(hs.tx, sizeof(hs.tx));
    sodium_memzero(id_sk, sizeof(id_sk));
    close(udp_fd);
    close(tun_fd);
    return 0;
}
