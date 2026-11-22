/*
 * Cryptography wrappers. Every primitive comes from libsodium:
 *   - server identity: Ed25519 signatures (crypto_sign)
 *   - key agreement:   ephemeral X25519 on both sides (crypto_kx)
 *   - transport:       XChaCha20-Poly1305 secretstream, one per direction
 *   - private messages: crypto_box (X25519 + XSalsa20-Poly1305)
 * These functions perform no I/O so they can be unit-tested in memory.
 */
#ifndef SECURECHAT_CRYPTO_H
#define SECURECHAT_CRYPTO_H

#include <stddef.h>
#include <stdint.h>

#include "securechat/protocol.h"

/* "XXXX XXXX XXXX XXXX XXXX XXXX XXXX XXXX XXXX XXXX" + NUL */
#define SC_FINGERPRINT_LEN 50

typedef struct {
    uint8_t pk[crypto_sign_PUBLICKEYBYTES];
    uint8_t sk[crypto_sign_SECRETKEYBYTES];
} sc_identity;

typedef struct {
    crypto_secretstream_xchacha20poly1305_state tx;
    crypto_secretstream_xchacha20poly1305_state rx;
} sc_channel;

typedef struct {
    uint8_t eph_pk[crypto_kx_PUBLICKEYBYTES];
    uint8_t eph_sk[crypto_kx_SECRETKEYBYTES];
} sc_client_handshake;

typedef struct {
    uint8_t rx_key[crypto_kx_SESSIONKEYBYTES];
} sc_server_handshake;

typedef struct {
    uint8_t pk[crypto_box_PUBLICKEYBYTES];
    uint8_t sk[crypto_box_SECRETKEYBYTES];
} sc_box_keypair;

/* Must be called once before anything else. Returns 0 on success. */
int sc_crypto_init(void);

void sc_identity_generate(sc_identity *id);

/* Client step 1: create an ephemeral key and the ClientHello. */
void sc_hs_client_start(sc_client_handshake *hs,
                        uint8_t hello[SC_HS_CLIENT_HELLO_LEN]);

/*
 * Server step: validate ClientHello, create an ephemeral key, derive session
 * keys, sign the transcript with the identity key and start the server->client
 * stream. Returns 0 on success, -1 on a malformed hello.
 */
int sc_hs_server_respond(const sc_identity *id, sc_server_handshake *hs,
                         const uint8_t *hello, size_t hello_len,
                         uint8_t out[SC_HS_SERVER_HELLO_LEN], sc_channel *ch);

/*
 * Client step 2: validate ServerHello, verify the transcript signature with
 * the identity key it carries, derive session keys and produce ClientFinish.
 * The caller MUST then check `server_identity` against its pinned key or
 * known_hosts entry before sending ClientFinish. Returns 0 or -1.
 */
int sc_hs_client_finish(sc_client_handshake *hs, const uint8_t *server_hello,
                        size_t len,
                        uint8_t server_identity[crypto_sign_PUBLICKEYBYTES],
                        uint8_t out[SC_HS_CLIENT_FINISH_LEN], sc_channel *ch);

/* Server step 2: start the client->server stream. Returns 0 or -1. */
int sc_hs_server_finish(sc_server_handshake *hs, const uint8_t *finish,
                        size_t len, sc_channel *ch);

/* Encrypt one message. `cap` must be >= len + secretstream ABYTES. */
int sc_channel_seal(sc_channel *ch, const uint8_t *msg, size_t len,
                    uint8_t *out, size_t cap, size_t *out_len);

/* Decrypt and authenticate one message; fails on tamper, replay, reorder. */
int sc_channel_open(sc_channel *ch, const uint8_t *in, size_t len,
                    uint8_t *out, size_t cap, size_t *out_len);

void sc_box_keypair_generate(sc_box_keypair *kp);

/*
 * End-to-end seal from `self` to `peer_pk`:
 *   out = random nonce || crypto_box_easy(self.pk || peer_pk || counter || msg)
 * `counter` must be non-zero and strictly increase across every message the
 * sender seals in its session (one counter for all peers is fine).
 */
int sc_e2e_seal(const sc_box_keypair *self,
                const uint8_t peer_pk[crypto_box_PUBLICKEYBYTES],
                uint64_t counter, const uint8_t *msg, size_t len,
                uint8_t *out, size_t cap, size_t *out_len);

/*
 * Open a message that `peer_pk` sealed for `self`. Fails unless the bound
 * sender key is `peer_pk`, the bound recipient key is `self.pk` (this rejects
 * a message reflected back to its author) and the counter is greater than
 * `*last_counter` (this rejects replay and reordering). On success
 * `*last_counter` is advanced; on failure nothing changes.
 */
int sc_e2e_open(const sc_box_keypair *self,
                const uint8_t peer_pk[crypto_box_PUBLICKEYBYTES],
                uint64_t *last_counter, const uint8_t *in, size_t len,
                uint8_t *out, size_t cap, size_t *out_len);

/* Human-comparable fingerprint: BLAKE2b-160 of the key in 10 hex groups. */
void sc_fingerprint(const uint8_t *key, size_t key_len,
                    char out[SC_FINGERPRINT_LEN]);

#endif
