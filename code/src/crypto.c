#include "crypto.h"
#include "util.h"

#include <errno.h>
#include <fcntl.h>
#include <sodium.h>
#include <string.h>
#include <sys/stat.h>
#include <unistd.h>

_Static_assert(crypto_sign_SECRETKEYBYTES == SVPN_SIGN_SK_BYTES, "sign sk");
_Static_assert(crypto_sign_PUBLICKEYBYTES == SVPN_SIGN_PK_BYTES, "sign pk");
_Static_assert(crypto_sign_BYTES == SVPN_SIGN_BYTES, "sign bytes");
_Static_assert(crypto_kx_PUBLICKEYBYTES == SVPN_KX_PK_BYTES, "kx pk");
_Static_assert(crypto_kx_SECRETKEYBYTES == SVPN_KX_SK_BYTES, "kx sk");
_Static_assert(crypto_kx_SESSIONKEYBYTES == SVPN_KX_SS_BYTES, "kx ss");
_Static_assert(crypto_aead_chacha20poly1305_ietf_KEYBYTES == SVPN_AEAD_KEY_BYTES,
              "aead key");
_Static_assert(crypto_aead_chacha20poly1305_ietf_NPUBBYTES == SVPN_NONCE_LEN,
              "aead nonce");
_Static_assert(crypto_aead_chacha20poly1305_ietf_ABYTES == SVPN_AEAD_TAG, "aead tag");

int svpn_crypto_init(void)
{
    if (sodium_init() < 0) {
        log_error("sodium_init failed");
        return -1;
    }
    return 0;
}

int identity_generate(uint8_t sk[SVPN_SIGN_SK_BYTES], uint8_t pk[SVPN_SIGN_PK_BYTES])
{
    return crypto_sign_keypair(pk, sk);
}

int identity_fingerprint(const uint8_t pk[SVPN_SIGN_PK_BYTES], char *out, size_t cap)
{
    uint8_t hash[32];

    crypto_generichash(hash, sizeof(hash), pk, SVPN_SIGN_PK_BYTES, NULL, 0);
    /* 8-byte / 16-hex-char fingerprint is short and operator-friendly. */
    hex_encode(hash, 8, out, cap);
    return 0;
}

static int read_exact(const char *path, uint8_t *buf, size_t n, int secret)
{
    int fd;
    size_t off = 0;
    struct stat st;

    fd = open(path, O_RDONLY | O_NOFOLLOW);
    if (fd < 0) {
        log_error("open %s: %s", path, strerror(errno));
        return -1;
    }
    if (fstat(fd, &st) != 0 || !S_ISREG(st.st_mode)) {
        log_error("key file %s is not a regular file", path);
        close(fd);
        return -1;
    }
    if (secret && (st.st_uid != geteuid() || (st.st_mode & (S_IRWXG | S_IRWXO)) != 0)) {
        log_error("secret key %s must be owned by this user and mode 0600", path);
        close(fd);
        return -1;
    }
    while (off < n) {
        ssize_t r = read(fd, buf + off, n - off);
        if (r < 0) {
            if (errno == EINTR) {
                continue;
            }
            log_error("read %s: %s", path, strerror(errno));
            close(fd);
            return -1;
        }
        if (r == 0) {
            log_error("malformed key file %s: expected %zu bytes, got %zu", path, n, off);
            close(fd);
            return -1;
        }
        off += (size_t)r;
    }
    /* Extra trailing bytes are treated as a malformed key. */
    {
        uint8_t extra;
        ssize_t r = read(fd, &extra, 1);
        if (r > 0) {
            log_error("malformed key file %s: unexpected extra bytes", path);
            close(fd);
            return -1;
        }
    }
    close(fd);
    return 0;
}

int load_secret_key(const char *path, uint8_t sk[SVPN_SIGN_SK_BYTES])
{
    return read_exact(path, sk, SVPN_SIGN_SK_BYTES, 1);
}

int load_public_key(const char *path, uint8_t pk[SVPN_SIGN_PK_BYTES])
{
    return read_exact(path, pk, SVPN_SIGN_PK_BYTES, 0);
}

int save_secret_key(const char *path, const uint8_t sk[SVPN_SIGN_SK_BYTES])
{
    int fd = open(path, O_WRONLY | O_CREAT | O_EXCL, 0600);
    if (fd < 0) {
        log_error("create secret key %s: %s", path, strerror(errno));
        return -1;
    }
    if (write_full(fd, sk, SVPN_SIGN_SK_BYTES) != (ssize_t)SVPN_SIGN_SK_BYTES) {
        log_error("write secret key %s: %s", path, strerror(errno));
        close(fd);
        unlink(path);
        return -1;
    }
    close(fd);
    return 0;
}

int save_public_key(const char *path, const uint8_t pk[SVPN_SIGN_PK_BYTES])
{
    int fd = open(path, O_WRONLY | O_CREAT | O_EXCL, 0644);
    if (fd < 0) {
        log_error("create public key %s: %s", path, strerror(errno));
        return -1;
    }
    if (write_full(fd, pk, SVPN_SIGN_PK_BYTES) != (ssize_t)SVPN_SIGN_PK_BYTES) {
        log_error("write public key %s: %s", path, strerror(errno));
        close(fd);
        unlink(path);
        return -1;
    }
    close(fd);
    return 0;
}

void nonce_build(uint8_t nonce[SVPN_NONCE_LEN],
                 const uint8_t session_id[SVPN_SESSION_ID_LEN],
                 int a2b, uint64_t seq)
{
    uint8_t hash[32];
    crypto_generichash_state st;

    crypto_generichash_init(&st, NULL, 0, sizeof(hash));
    if (a2b) {
        crypto_generichash_update(&st, (const uint8_t *)"A2B", 3);
    } else {
        crypto_generichash_update(&st, (const uint8_t *)"B2A", 3);
    }
    crypto_generichash_update(&st, session_id, SVPN_SESSION_ID_LEN);
    crypto_generichash_final(&st, hash, sizeof(hash));

    memcpy(nonce, hash, 4);
    put_u64be(nonce + 4, seq);
}

void session_id_compute(uint8_t sid[SVPN_SESSION_ID_LEN],
                        const uint8_t client_random[SVPN_RANDOM_LEN],
                        const uint8_t server_random[SVPN_RANDOM_LEN],
                        const uint8_t client_eph_pk[SVPN_KX_PK_BYTES],
                        const uint8_t server_eph_pk[SVPN_KX_PK_BYTES])
{
    uint8_t hash[32];
    crypto_generichash_state st;

    crypto_generichash_init(&st, NULL, 0, sizeof(hash));
    crypto_generichash_update(&st, client_random, SVPN_RANDOM_LEN);
    crypto_generichash_update(&st, server_random, SVPN_RANDOM_LEN);
    crypto_generichash_update(&st, client_eph_pk, SVPN_KX_PK_BYTES);
    crypto_generichash_update(&st, server_eph_pk, SVPN_KX_PK_BYTES);
    crypto_generichash_final(&st, hash, sizeof(hash));
    memcpy(sid, hash, SVPN_SESSION_ID_LEN);
}

int aead_encrypt(const uint8_t key[SVPN_AEAD_KEY_BYTES],
                 const uint8_t nonce[SVPN_NONCE_LEN],
                 const uint8_t *ad, size_t ad_len,
                 const uint8_t *pt, size_t pt_len,
                 uint8_t *ct, size_t *ct_len)
{
    unsigned long long clen = 0;

    if (crypto_aead_chacha20poly1305_ietf_encrypt(ct, &clen, pt, pt_len, ad, ad_len,
                                                  NULL, nonce, key) != 0) {
        return -1;
    }
    *ct_len = (size_t)clen;
    return 0;
}

int aead_decrypt(const uint8_t key[SVPN_AEAD_KEY_BYTES],
                 const uint8_t nonce[SVPN_NONCE_LEN],
                 const uint8_t *ad, size_t ad_len,
                 const uint8_t *ct, size_t ct_len,
                 uint8_t *pt, size_t *pt_len)
{
    unsigned long long plen = 0;

    if (crypto_aead_chacha20poly1305_ietf_decrypt(pt, &plen, NULL, ct, ct_len, ad, ad_len,
                                                  nonce, key) != 0) {
        return -1;
    }
    *pt_len = (size_t)plen;
    return 0;
}

int kx_client_session(uint8_t rx[SVPN_KX_SS_BYTES], uint8_t tx[SVPN_KX_SS_BYTES],
                      const uint8_t client_pk[SVPN_KX_PK_BYTES],
                      const uint8_t client_sk[SVPN_KX_SK_BYTES],
                      const uint8_t server_pk[SVPN_KX_PK_BYTES])
{
    return crypto_kx_client_session_keys(rx, tx, client_pk, client_sk, server_pk);
}

int kx_server_session(uint8_t rx[SVPN_KX_SS_BYTES], uint8_t tx[SVPN_KX_SS_BYTES],
                      const uint8_t server_pk[SVPN_KX_PK_BYTES],
                      const uint8_t server_sk[SVPN_KX_SK_BYTES],
                      const uint8_t client_pk[SVPN_KX_PK_BYTES])
{
    return crypto_kx_server_session_keys(rx, tx, server_pk, server_sk, client_pk);
}

int kx_keypair(uint8_t pk[SVPN_KX_PK_BYTES], uint8_t sk[SVPN_KX_SK_BYTES])
{
    return crypto_kx_keypair(pk, sk);
}
