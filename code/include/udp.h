#ifndef SVPN_UDP_H
#define SVPN_UDP_H

#include "common.h"

#include <sys/types.h>

int udp_open(const char *bind_ip, uint16_t bind_port);

int udp_send_to(int fd, const char *peer_ip, uint16_t peer_port,
                const uint8_t *buf, size_t n);

ssize_t udp_recv_from(int fd, uint8_t *buf, size_t cap,
                      char *src_ip, size_t src_ip_cap, uint16_t *src_port);

int peer_is_expected(const char *got_ip, uint16_t got_port,
                     const char *exp_ip, uint16_t exp_port);

#endif /* SVPN_UDP_H */
