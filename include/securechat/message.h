/*
 * Application messages carried inside the encrypted channel.
 * Encoding: type byte, then fields; strings and blobs are u16-length-prefixed.
 * Decoding validates every field (names, UTF-8 safety, sizes).
 */
#ifndef SECURECHAT_MESSAGE_H
#define SECURECHAT_MESSAGE_H

#include <stddef.h>
#include <stdint.h>

#include "securechat/protocol.h"

typedef enum {
    /* client -> server */
    SC_MSG_JOIN = 0x01,    /* name, key */
    SC_MSG_SAY = 0x02,     /* text */
    SC_MSG_PRIVATE = 0x03, /* name (recipient), blob */
    SC_MSG_LIST = 0x04,    /* - */
    SC_MSG_BYE = 0x05,     /* - */
    /* server -> client */
    SC_MSG_WELCOME = 0x41,      /* name, color, roster */
    SC_MSG_ERROR = 0x42,        /* text */
    SC_MSG_JOINED = 0x43,       /* name, color, key */
    SC_MSG_LEFT = 0x44,         /* name, color */
    SC_MSG_CHAT = 0x45,         /* name, color, text */
    SC_MSG_PRIVATE_FROM = 0x46, /* name (sender), color, blob */
    SC_MSG_ROSTER = 0x47,       /* roster */
    SC_MSG_NOTICE = 0x48        /* text */
} sc_msg_type;

typedef struct {
    char name[SC_NAME_MAX + 1];
    uint8_t color;
    uint8_t key[crypto_box_PUBLICKEYBYTES];
} sc_peer;

typedef struct {
    uint8_t type;
    char name[SC_NAME_MAX + 1];
    uint8_t color;
    uint8_t key[crypto_box_PUBLICKEYBYTES];
    char text[SC_TEXT_MAX + 1];
    uint8_t blob[SC_E2E_MAX];
    size_t blob_len;
    sc_peer roster[SC_MAX_CLIENTS];
    size_t roster_len;
} sc_msg;

/* Zero the message and set its type. */
void sc_msg_init(sc_msg *msg, sc_msg_type type);

/* Returns 0 on success, -1 if a field is invalid or `cap` is too small. */
int sc_msg_encode(const sc_msg *msg, uint8_t *out, size_t cap,
                  size_t *out_len);

/* Returns 0 on success, -1 on any malformed, oversized or unsafe input. */
int sc_msg_decode(const uint8_t *in, size_t len, sc_msg *msg);

#endif
