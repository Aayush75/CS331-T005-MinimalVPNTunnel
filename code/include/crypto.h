#ifndef SVPN_CRYPTO_H
#define SVPN_CRYPTO_H

#include "common.h"

int svpn_crypto_init(void);

int identity_generate(uint8_t sk[SVPN_SIGN_SK_BYTES], uint8_t pk[SVPN_SIGN_PK_BYTES]);
int identity_fingerprint(const uint8_t pk[SVPN_SIGN_PK_BYTES], char *out, size_t cap);

int load_secret_key(const char *path, uint8_t sk[SVPN_SIGN_SK_BYTES]);
int load_public_key(const char *path, uint8_t pk[SVPN_SIGN_PK_BYTES]);
int save_secret_key(const char *path, const uint8_t sk[SVPN_SIGN_SK_BYTES]);
int save_public_key(const char *path, const uint8_t pk[SVPN_SIGN_PK_BYTES]);

/* a2b=1 => A->B prefix; a2b=0 => B->A prefix. */
void nonce_build(uint8_t nonce[SVPN_NONCE_LEN],
                 const uint8_t session_id[SVPN_SESSION_ID_LEN],
                 int a2b, uint64_t seq);

void session_id_compute(uint8_t sid[SVPN_SESSION_ID_LEN],
                        const uint8_t client_random[SVPN_RANDOM_LEN],
                        const uint8_t server_random[SVPN_RANDOM_LEN],
                        const uint8_t client_eph_pk[SVPN_KX_PK_BYTES],
                        const uint8_t server_eph_pk[SVPN_KX_PK_BYTES]);

int aead_encrypt(const uint8_t key[SVPN_AEAD_KEY_BYTES],
                 const uint8_t nonce[SVPN_NONCE_LEN],
                 const uint8_t *ad, size_t ad_len,
                 const uint8_t *pt, size_t pt_len,
                 uint8_t *ct, size_t *ct_len);

int aead_decrypt(const uint8_t key[SVPN_AEAD_KEY_BYTES],
                 const uint8_t nonce[SVPN_NONCE_LEN],
                 const uint8_t *ad, size_t ad_len,
                 const uint8_t *ct, size_t ct_len,
                 uint8_t *pt, size_t *pt_len);

int kx_client_session(uint8_t rx[SVPN_KX_SS_BYTES], uint8_t tx[SVPN_KX_SS_BYTES],
                      const uint8_t client_pk[SVPN_KX_PK_BYTES],
                      const uint8_t client_sk[SVPN_KX_SK_BYTES],
                      const uint8_t server_pk[SVPN_KX_PK_BYTES]);

int kx_server_session(uint8_t rx[SVPN_KX_SS_BYTES], uint8_t tx[SVPN_KX_SS_BYTES],
                      const uint8_t server_pk[SVPN_KX_PK_BYTES],
                      const uint8_t server_sk[SVPN_KX_SK_BYTES],
                      const uint8_t client_pk[SVPN_KX_PK_BYTES]);

int kx_keypair(uint8_t pk[SVPN_KX_PK_BYTES], uint8_t sk[SVPN_KX_SK_BYTES]);

#endif /* SVPN_CRYPTO_H */
