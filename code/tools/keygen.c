#include "crypto.h"
#include "util.h"

#include <getopt.h>
#include <sodium.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

static void usage(FILE *fp)
{
    fprintf(fp,
            "Usage: svpn-keygen --secret PATH --public PATH [--force]\n"
            "Generate one Ed25519 identity keypair. Secret bytes are never printed.\n");
}

int main(int argc, char **argv)
{
    const char *secret_path = NULL;
    const char *public_path = NULL;
    int force = 0;
    uint8_t sk[SVPN_SIGN_SK_BYTES];
    uint8_t pk[SVPN_SIGN_PK_BYTES];
    char fp[33];
    int c;
    static const struct option longopts[] = {
        {"secret", required_argument, NULL, 's'},
        {"public", required_argument, NULL, 'p'},
        {"force", no_argument, NULL, 'f'},
        {"help", no_argument, NULL, 'h'},
        {0, 0, 0, 0},
    };

    while ((c = getopt_long(argc, argv, "s:p:fh", longopts, NULL)) != -1) {
        switch (c) {
        case 's':
            secret_path = optarg;
            break;
        case 'p':
            public_path = optarg;
            break;
        case 'f':
            force = 1;
            break;
        case 'h':
            usage(stdout);
            return 0;
        default:
            usage(stderr);
            return 1;
        }
    }
    if (secret_path == NULL || public_path == NULL) {
        usage(stderr);
        return 1;
    }
    if (svpn_crypto_init() != 0) {
        return 1;
    }
    if (!force) {
        if (access(secret_path, F_OK) == 0) {
            log_error("refusing to overwrite %s (pass --force)", secret_path);
            return 1;
        }
        if (access(public_path, F_OK) == 0) {
            log_error("refusing to overwrite %s (pass --force)", public_path);
            return 1;
        }
    } else {
        unlink(secret_path);
        unlink(public_path);
    }
    if (identity_generate(sk, pk) != 0) {
        log_error("identity key generation failed");
        return 1;
    }
    if (save_secret_key(secret_path, sk) != 0 || save_public_key(public_path, pk) != 0) {
        return 1;
    }
    identity_fingerprint(pk, fp, sizeof(fp));
    log_info("wrote public key %s fingerprint=%s", public_path, fp);
    log_info("wrote secret key %s mode=0600", secret_path);
    sodium_memzero(sk, sizeof(sk));
    return 0;
}
