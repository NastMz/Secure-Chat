/*
 * Persistent keys: the server identity key file and the client's
 * trust-on-first-use known_hosts file.
 */
#ifndef SECURECHAT_KEYSTORE_H
#define SECURECHAT_KEYSTORE_H

#include "securechat/crypto.h"

typedef enum {
    SC_TRUST_ERROR = -1,
    SC_TRUST_MATCH = 0,   /* stored key equals the presented key */
    SC_TRUST_NEW = 1,     /* first contact: key stored */
    SC_TRUST_MISMATCH = 2 /* stored key differs: possible MITM */
} sc_trust;

/*
 * Load the identity from `path` (hex-encoded Ed25519 secret key), or create
 * it with mode 0600 when the file does not exist. `*created` is set to 1 when
 * a new key was generated. Returns 0 on success, -1 on error.
 */
int sc_identity_load_or_create(const char *path, sc_identity *id,
                               int *created);

/*
 * Trust on first use: look `host_id` up in the known_hosts file at `path`.
 * Unknown hosts are appended. A different stored key yields SC_TRUST_MISMATCH.
 */
sc_trust sc_known_hosts_check(const char *path, const char *host_id,
                              const uint8_t pk[crypto_sign_PUBLICKEYBYTES]);

/* Parse exactly 64 hex chars into a 32-byte public key. Returns 0 or -1. */
int sc_parse_public_key(const char *hex,
                        uint8_t pk[crypto_sign_PUBLICKEYBYTES]);

#endif
