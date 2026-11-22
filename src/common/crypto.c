#include "securechat/crypto.h"

#include <string.h>

#define SS_HEADER crypto_secretstream_xchacha20poly1305_HEADERBYTES
#define SS_ABYTES crypto_secretstream_xchacha20poly1305_ABYTES

/* Domain separation for the signed handshake transcript. */
static const char TRANSCRIPT_CONTEXT[] = "SecureChat/1 server handshake";

/* ServerHello field offsets. */
enum {
    SH_MAGIC = 0,
    SH_VERSION = SH_MAGIC + SC_MAGIC_LEN,
    SH_EPH = SH_VERSION + 1,
    SH_IDENTITY = SH_EPH + crypto_kx_PUBLICKEYBYTES,
    SH_SIGNATURE = SH_IDENTITY + crypto_sign_PUBLICKEYBYTES,
    SH_HEADER = SH_SIGNATURE + crypto_sign_BYTES,
    SH_END = SH_HEADER + SS_HEADER
};

#define TRANSCRIPT_LEN                                                         \
    (sizeof(TRANSCRIPT_CONTEXT) - 1 + 2 * crypto_kx_PUBLICKEYBYTES +           \
     crypto_sign_PUBLICKEYBYTES + SS_HEADER)

/* transcript = context || client_eph || server_eph || identity || header */
static void build_transcript(uint8_t out[TRANSCRIPT_LEN],
                             const uint8_t *client_eph,
                             const uint8_t *server_eph,
                             const uint8_t *identity, const uint8_t *header) {
    size_t off = 0;
    memcpy(out + off, TRANSCRIPT_CONTEXT, sizeof(TRANSCRIPT_CONTEXT) - 1);
    off += sizeof(TRANSCRIPT_CONTEXT) - 1;
    memcpy(out + off, client_eph, crypto_kx_PUBLICKEYBYTES);
    off += crypto_kx_PUBLICKEYBYTES;
    memcpy(out + off, server_eph, crypto_kx_PUBLICKEYBYTES);
    off += crypto_kx_PUBLICKEYBYTES;
    memcpy(out + off, identity, crypto_sign_PUBLICKEYBYTES);
    off += crypto_sign_PUBLICKEYBYTES;
    memcpy(out + off, header, SS_HEADER);
}

static int has_magic(const uint8_t *buf) {
    return memcmp(buf, SC_MAGIC, SC_MAGIC_LEN) == 0 &&
           buf[SC_MAGIC_LEN] == SC_PROTOCOL_VERSION;
}

int sc_crypto_init(void) { return sodium_init() < 0 ? -1 : 0; }

void sc_identity_generate(sc_identity *id) {
    crypto_sign_keypair(id->pk, id->sk);
}

void sc_hs_client_start(sc_client_handshake *hs,
                        uint8_t hello[SC_HS_CLIENT_HELLO_LEN]) {
    crypto_kx_keypair(hs->eph_pk, hs->eph_sk);
    memcpy(hello, SC_MAGIC, SC_MAGIC_LEN);
    hello[SC_MAGIC_LEN] = SC_PROTOCOL_VERSION;
    memcpy(hello + SC_MAGIC_LEN + 1, hs->eph_pk, crypto_kx_PUBLICKEYBYTES);
}

int sc_hs_server_respond(const sc_identity *id, sc_server_handshake *hs,
                         const uint8_t *hello, size_t hello_len,
                         uint8_t out[SC_HS_SERVER_HELLO_LEN], sc_channel *ch) {
    if (hello_len != SC_HS_CLIENT_HELLO_LEN || !has_magic(hello)) {
        return -1;
    }
    const uint8_t *client_eph = hello + SC_MAGIC_LEN + 1;

    uint8_t eph_pk[crypto_kx_PUBLICKEYBYTES];
    uint8_t eph_sk[crypto_kx_SECRETKEYBYTES];
    uint8_t tx_key[crypto_kx_SESSIONKEYBYTES];
    crypto_kx_keypair(eph_pk, eph_sk);

    /* Fails for low-order / invalid client keys. */
    int rc = crypto_kx_server_session_keys(hs->rx_key, tx_key, eph_pk, eph_sk,
                                           client_eph);
    sodium_memzero(eph_sk, sizeof(eph_sk));
    if (rc != 0) {
        sodium_memzero(tx_key, sizeof(tx_key));
        return -1;
    }

    memcpy(out + SH_MAGIC, SC_MAGIC, SC_MAGIC_LEN);
    out[SH_VERSION] = SC_PROTOCOL_VERSION;
    memcpy(out + SH_EPH, eph_pk, sizeof(eph_pk));
    memcpy(out + SH_IDENTITY, id->pk, crypto_sign_PUBLICKEYBYTES);
    crypto_secretstream_xchacha20poly1305_init_push(&ch->tx, out + SH_HEADER,
                                                    tx_key);
    sodium_memzero(tx_key, sizeof(tx_key));

    uint8_t transcript[TRANSCRIPT_LEN];
    build_transcript(transcript, client_eph, eph_pk, id->pk, out + SH_HEADER);
    crypto_sign_detached(out + SH_SIGNATURE, NULL, transcript,
                         sizeof(transcript), id->sk);
    return 0;
}

int sc_hs_client_finish(sc_client_handshake *hs, const uint8_t *server_hello,
                        size_t len,
                        uint8_t server_identity[crypto_sign_PUBLICKEYBYTES],
                        uint8_t out[SC_HS_CLIENT_FINISH_LEN], sc_channel *ch) {
    int result = -1;
    uint8_t rx_key[crypto_kx_SESSIONKEYBYTES];
    uint8_t tx_key[crypto_kx_SESSIONKEYBYTES];

    if (len != SC_HS_SERVER_HELLO_LEN || !has_magic(server_hello)) {
        goto done;
    }
    const uint8_t *server_eph = server_hello + SH_EPH;
    const uint8_t *identity = server_hello + SH_IDENTITY;
    const uint8_t *header = server_hello + SH_HEADER;

    uint8_t transcript[TRANSCRIPT_LEN];
    build_transcript(transcript, hs->eph_pk, server_eph, identity, header);
    if (crypto_sign_verify_detached(server_hello + SH_SIGNATURE, transcript,
                                    sizeof(transcript), identity) != 0) {
        goto done;
    }
    if (crypto_kx_client_session_keys(rx_key, tx_key, hs->eph_pk, hs->eph_sk,
                                      server_eph) != 0) {
        goto done;
    }
    if (crypto_secretstream_xchacha20poly1305_init_pull(&ch->rx, header,
                                                        rx_key) != 0) {
        goto done;
    }
    crypto_secretstream_xchacha20poly1305_init_push(&ch->tx, out, tx_key);
    memcpy(server_identity, identity, crypto_sign_PUBLICKEYBYTES);
    result = 0;

done:
    sodium_memzero(rx_key, sizeof(rx_key));
    sodium_memzero(tx_key, sizeof(tx_key));
    sodium_memzero(hs->eph_sk, sizeof(hs->eph_sk));
    return result;
}

int sc_hs_server_finish(sc_server_handshake *hs, const uint8_t *finish,
                        size_t len, sc_channel *ch) {
    int rc = -1;
    if (len == SC_HS_CLIENT_FINISH_LEN) {
        rc = crypto_secretstream_xchacha20poly1305_init_pull(&ch->rx, finish,
                                                             hs->rx_key);
    }
    sodium_memzero(hs->rx_key, sizeof(hs->rx_key));
    return rc == 0 ? 0 : -1;
}

int sc_channel_seal(sc_channel *ch, const uint8_t *msg, size_t len,
                    uint8_t *out, size_t cap, size_t *out_len) {
    if (len == 0 || len > SC_PAYLOAD_MAX || cap < len + SS_ABYTES) {
        return -1;
    }
    unsigned long long clen = 0;
    if (crypto_secretstream_xchacha20poly1305_push(
            &ch->tx, out, &clen, msg, len, NULL, 0,
            crypto_secretstream_xchacha20poly1305_TAG_MESSAGE) != 0) {
        return -1;
    }
    *out_len = (size_t)clen;
    return 0;
}

int sc_channel_open(sc_channel *ch, const uint8_t *in, size_t len,
                    uint8_t *out, size_t cap, size_t *out_len) {
    if (len <= SS_ABYTES || len > SC_FRAME_MAX || cap < len - SS_ABYTES) {
        return -1;
    }
    unsigned long long mlen = 0;
    unsigned char tag = 0;
    if (crypto_secretstream_xchacha20poly1305_pull(&ch->rx, out, &mlen, &tag,
                                                   in, len, NULL, 0) != 0) {
        return -1;
    }
    if (tag != crypto_secretstream_xchacha20poly1305_TAG_MESSAGE) {
        return -1;
    }
    *out_len = (size_t)mlen;
    return 0;
}

void sc_box_keypair_generate(sc_box_keypair *kp) {
    crypto_box_keypair(kp->pk, kp->sk);
}

int sc_e2e_seal(const sc_box_keypair *self,
                const uint8_t peer_pk[crypto_box_PUBLICKEYBYTES],
                const uint8_t *msg, size_t len, uint8_t *out, size_t cap,
                size_t *out_len) {
    if (len == 0 || len > SC_TEXT_MAX || cap < len + SC_E2E_OVERHEAD) {
        return -1;
    }
    /* 24-byte random nonces: collision probability is negligible. */
    randombytes_buf(out, crypto_box_NONCEBYTES);
    if (crypto_box_easy(out + crypto_box_NONCEBYTES, msg, len, out, peer_pk,
                        self->sk) != 0) {
        return -1;
    }
    *out_len = len + SC_E2E_OVERHEAD;
    return 0;
}

int sc_e2e_open(const sc_box_keypair *self,
                const uint8_t peer_pk[crypto_box_PUBLICKEYBYTES],
                const uint8_t *in, size_t len, uint8_t *out, size_t cap,
                size_t *out_len) {
    if (len <= SC_E2E_OVERHEAD || len > SC_E2E_MAX ||
        cap < len - SC_E2E_OVERHEAD) {
        return -1;
    }
    if (crypto_box_open_easy(out, in + crypto_box_NONCEBYTES,
                             len - crypto_box_NONCEBYTES, in, peer_pk,
                             self->sk) != 0) {
        return -1;
    }
    *out_len = len - SC_E2E_OVERHEAD;
    return 0;
}

void sc_fingerprint(const uint8_t *key, size_t key_len,
                    char out[SC_FINGERPRINT_LEN]) {
    static const char hex[] = "0123456789ABCDEF";
    uint8_t digest[20];
    crypto_generichash(digest, sizeof(digest), key, key_len, NULL, 0);
    size_t pos = 0;
    for (size_t i = 0; i < sizeof(digest); i++) {
        if (i > 0 && i % 2 == 0) {
            out[pos++] = ' ';
        }
        out[pos++] = hex[digest[i] >> 4];
        out[pos++] = hex[digest[i] & 0x0F];
    }
    out[pos] = '\0';
}
