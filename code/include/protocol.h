#ifndef SVPN_PROTOCOL_H
#define SVPN_PROTOCOL_H

#include "common.h"

int protocol_encode(uint8_t out[SVPN_HEADER_SIZE], const struct svpn_hdr *h);
int protocol_decode(const uint8_t *buf, size_t n, struct svpn_hdr *h);

/*
 * After a successful decode, body_len is (datagram_len - 28).
 * For DATA:
 *   plaintext mode: body_len must equal plaintext_len
 *   encrypted mode: body_len must equal plaintext_len + 16 (AEAD tag)
 * Handshake types use plaintext_len as the hello payload size.
 */
int protocol_check_body(const struct svpn_hdr *h, size_t body_len, int encrypted);

const char *protocol_errstr(int err);

#endif /* SVPN_PROTOCOL_H */
