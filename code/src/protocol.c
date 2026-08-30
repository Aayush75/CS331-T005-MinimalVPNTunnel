#include "protocol.h"
#include "util.h"

#include <string.h>

int protocol_encode(uint8_t out[SVPN_HEADER_SIZE], const struct svpn_hdr *h)
{
    if (out == NULL || h == NULL) {
        return SVPN_ERR_ARG;
    }
    memcpy(out, SVPN_MAGIC, SVPN_MAGIC_LEN);
    out[4] = h->version;
    out[5] = h->type;
    put_u16be(out + 6, h->flags);
    memcpy(out + 8, h->session_id, SVPN_SESSION_ID_LEN);
    put_u64be(out + 16, h->sequence);
    put_u16be(out + 24, h->plaintext_len);
    put_u16be(out + 26, 0); /* reserved */
    return SVPN_OK;
}

int protocol_decode(const uint8_t *buf, size_t n, struct svpn_hdr *h)
{
    uint16_t reserved;

    if (buf == NULL || h == NULL) {
        return SVPN_ERR_ARG;
    }
    if (n < SVPN_HEADER_SIZE) {
        return SVPN_ERR_SHORT;
    }
    if (memcmp(buf, SVPN_MAGIC, SVPN_MAGIC_LEN) != 0) {
        return SVPN_ERR_MAGIC;
    }
    if (buf[4] != SVPN_VERSION) {
        return SVPN_ERR_VERSION;
    }
    if (buf[5] < SVPN_TYPE_CLIENT_HELLO || buf[5] > SVPN_TYPE_CLOSE) {
        return SVPN_ERR_TYPE;
    }

    /* Version 1 has no negotiated flags or extensions.  Accepting values we
     * do not understand would make future wire formats ambiguous. */
    if (get_u16be(buf + 6) != 0 || get_u16be(buf + 26) != 0) {
        return SVPN_ERR_HEADER;
    }

    memset(h, 0, sizeof(*h));
    h->version = buf[4];
    h->type = buf[5];
    h->flags = get_u16be(buf + 6);
    memcpy(h->session_id, buf + 8, SVPN_SESSION_ID_LEN);
    h->sequence = get_u64be(buf + 16);
    h->plaintext_len = get_u16be(buf + 24);
    reserved = get_u16be(buf + 26);
    (void)reserved; /* checked above; retained to document the wire offset */
    return SVPN_OK;
}

int protocol_check_body(const struct svpn_hdr *h, size_t body_len, int encrypted)
{
    size_t expected;

    if (h == NULL) {
        return SVPN_ERR_ARG;
    }

    switch (h->type) {
    case SVPN_TYPE_DATA:
        if (h->plaintext_len == 0) {
            return SVPN_ERR_ZERO_PAYLOAD;
        }
        if (h->plaintext_len > SVPN_MAX_INNER) {
            return SVPN_ERR_OVERSIZE;
        }
        expected = encrypted ? (size_t)h->plaintext_len + SVPN_AEAD_TAG
                             : (size_t)h->plaintext_len;
        if (body_len < expected) {
            return SVPN_ERR_LEN;
        }
        if (body_len > expected) {
            return SVPN_ERR_TRAILING;
        }
        return SVPN_OK;

    case SVPN_TYPE_CLIENT_HELLO:
        if (h->plaintext_len != SVPN_CHLO_PAYLOAD_LEN) {
            return SVPN_ERR_LEN;
        }
        if (body_len < (size_t)h->plaintext_len) {
            return SVPN_ERR_LEN;
        }
        if (body_len > (size_t)h->plaintext_len) {
            return SVPN_ERR_TRAILING;
        }
        return SVPN_OK;

    case SVPN_TYPE_SERVER_HELLO:
        if (h->plaintext_len != SVPN_SHLO_PAYLOAD_LEN) {
            return SVPN_ERR_LEN;
        }
        if (body_len < (size_t)h->plaintext_len) {
            return SVPN_ERR_LEN;
        }
        if (body_len > (size_t)h->plaintext_len) {
            return SVPN_ERR_TRAILING;
        }
        return SVPN_OK;

    case SVPN_TYPE_CLOSE:
        if (body_len != (size_t)h->plaintext_len) {
            return (body_len > (size_t)h->plaintext_len) ? SVPN_ERR_TRAILING
                                                          : SVPN_ERR_LEN;
        }
        return SVPN_OK;

    default:
        return SVPN_ERR_TYPE;
    }
}

const char *protocol_errstr(int err)
{
    switch (err) {
    case SVPN_OK:
        return "ok";
    case SVPN_ERR_SHORT:
        return "truncated header";
    case SVPN_ERR_MAGIC:
        return "bad magic";
    case SVPN_ERR_VERSION:
        return "unsupported version";
    case SVPN_ERR_TYPE:
        return "unknown type";
    case SVPN_ERR_LEN:
        return "inconsistent payload length";
    case SVPN_ERR_TRAILING:
        return "trailing data";
    case SVPN_ERR_ZERO_PAYLOAD:
        return "zero-length DATA payload";
    case SVPN_ERR_OVERSIZE:
        return "oversized payload";
    case SVPN_ERR_HEADER:
        return "unsupported flags or nonzero reserved field";
    default:
        return "protocol error";
    }
}
