/*
 * Client session: handshake, room state (roster of peers and their
 * end-to-end keys) and the poll(2) loop over the socket and stdin.
 */
#ifndef SECURECHAT_CLIENT_H
#define SECURECHAT_CLIENT_H

#include <signal.h>

#include "lineedit.h"
#include "securechat/crypto.h"
#include "securechat/frame.h"
#include "securechat/message.h"
#include "ui.h"

/*
 * Highest private-message counter accepted from each peer key seen in this
 * session. Entries are kept after the peer leaves so that a hostile server
 * cannot replay an old message by announcing the same key again.
 */
#define SC_E2E_PEERS_MAX 256

typedef struct {
    uint8_t key[crypto_box_PUBLICKEYBYTES];
    uint64_t last_counter;
} sc_e2e_peer;

typedef struct {
    int fd;
    sc_channel ch;
    sc_frame_reader in;
    sc_box_keypair box;
    uint8_t server_pk[crypto_sign_PUBLICKEYBYTES];
    int joined;
    int join_pending; /* JOIN sent, waiting for WELCOME or ERROR */
    char name[SC_NAME_MAX + 1];
    uint8_t color;
    sc_peer roster[SC_MAX_CLIENTS];
    size_t roster_len;
    uint64_t e2e_tx_counter; /* last counter sealed, shared by all peers */
    sc_e2e_peer e2e_rx[SC_E2E_PEERS_MAX];
    size_t e2e_rx_len;
    sc_lineedit editor;
    sc_ui ui;
} sc_client;

/*
 * Run the handshake on a connected socket. On success the channel is ready
 * except for trust: the caller must vet `server_pk` and then call
 * sc_client_handshake_confirm(). Returns 0 or -1.
 */
int sc_client_handshake_start(sc_client *c, sc_client_handshake *hs,
                              uint8_t finish[SC_HS_CLIENT_FINISH_LEN]);

/* Send ClientFinish once the server identity is trusted. Returns 0 or -1. */
int sc_client_handshake_confirm(sc_client *c,
                                const uint8_t finish[SC_HS_CLIENT_FINISH_LEN]);

/* Main loop. `name` may be NULL to ask interactively. Returns exit code. */
int sc_client_run(sc_client *c, const char *name, volatile sig_atomic_t *stop);

#endif
