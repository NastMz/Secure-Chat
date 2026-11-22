/*
 * SecureChat wire protocol constants.
 *
 * Every byte on the wire is a frame: a 4-byte big-endian length followed by
 * that many bytes of payload. The first three frames of a connection are the
 * plaintext handshake; every later frame is a libsodium secretstream
 * (XChaCha20-Poly1305) ciphertext of one encoded application message.
 */
#ifndef SECURECHAT_PROTOCOL_H
#define SECURECHAT_PROTOCOL_H

#include <sodium.h>

#define SC_VERSION_STRING "1.0.0"

/* Handshake magic and protocol version, sent in both hello messages. */
#define SC_MAGIC "SCH1"
#define SC_MAGIC_LEN 4
#define SC_PROTOCOL_VERSION 1

/* Room limits. */
#define SC_MAX_CLIENTS 16
#define SC_NAME_MAX 16  /* bytes, ASCII [A-Za-z0-9_-] */
#define SC_TEXT_MAX 512 /* bytes of UTF-8 per chat message */

/*
 * One sealed end-to-end private message:
 *   nonce || box(sender_pk || recipient_pk || counter_be64 || text)
 * Binding both public keys stops reflection (crypto_box keys are symmetric
 * between two peers); the per-sender counter stops replay and reordering.
 */
#define SC_E2E_HEADER_LEN (2 * crypto_box_PUBLICKEYBYTES + 8)
#define SC_E2E_OVERHEAD \
    (crypto_box_NONCEBYTES + crypto_box_MACBYTES + SC_E2E_HEADER_LEN)
#define SC_E2E_MAX (SC_TEXT_MAX + SC_E2E_OVERHEAD)

/* Largest plaintext application payload and largest frame on the wire. */
#define SC_PAYLOAD_MAX 2048
#define SC_FRAME_MAX (SC_PAYLOAD_MAX + crypto_secretstream_xchacha20poly1305_ABYTES)
#define SC_FRAME_HEADER_LEN 4

/* Handshake message sizes. */
#define SC_HS_CLIENT_HELLO_LEN (SC_MAGIC_LEN + 1 + crypto_kx_PUBLICKEYBYTES)
#define SC_HS_SERVER_HELLO_LEN                                                  \
    (SC_MAGIC_LEN + 1 + crypto_kx_PUBLICKEYBYTES + crypto_sign_PUBLICKEYBYTES + \
     crypto_sign_BYTES + crypto_secretstream_xchacha20poly1305_HEADERBYTES)
#define SC_HS_CLIENT_FINISH_LEN crypto_secretstream_xchacha20poly1305_HEADERBYTES

/* Seconds a connection may spend before completing handshake and join. */
#define SC_JOIN_TIMEOUT_SECONDS 30

/* Failed JOIN attempts tolerated before the server drops the connection. */
#define SC_MAX_JOIN_ATTEMPTS 5

/* Number of distinct user colors. */
#define SC_COLOR_COUNT 6

#endif
