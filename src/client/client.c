#include "client.h"

#include <errno.h>
#include <poll.h>
#include <stdio.h>
#include <string.h>
#include <sys/socket.h>
#include <unistd.h>

#include "command.h"
#include "securechat/net.h"
#include "securechat/text.h"

#define HANDSHAKE_TIMEOUT_MS 10000

typedef enum { RUN_CONTINUE, RUN_QUIT, RUN_FAIL } run_status;

/* ---- networking ---------------------------------------------------------- */

/* Read bytes until one frame is available or the timeout expires. */
static int read_frame_blocking(sc_client *c, uint8_t *out, size_t cap,
                               size_t *len, int timeout_ms) {
    for (;;) {
        sc_frame_status st = sc_frame_reader_next(&c->in, out, cap, len);
        if (st == SC_FRAME_READY) {
            return 0;
        }
        if (st == SC_FRAME_INVALID) {
            return -1;
        }
        struct pollfd pfd = {c->fd, POLLIN, 0};
        int ready = poll(&pfd, 1, timeout_ms);
        if (ready < 0 && errno == EINTR) {
            continue;
        }
        if (ready <= 0) {
            return -1;
        }
        size_t avail = 0;
        uint8_t *space = sc_frame_reader_space(&c->in, &avail);
        ssize_t n = recv(c->fd, space, avail, 0);
        if (n <= 0) {
            return -1;
        }
        sc_frame_reader_commit(&c->in, (size_t)n);
    }
}

int sc_client_handshake_start(sc_client *c, sc_client_handshake *hs,
                              uint8_t finish[SC_HS_CLIENT_FINISH_LEN]) {
    uint8_t hello[SC_HS_CLIENT_HELLO_LEN];
    uint8_t reply[SC_FRAME_MAX];
    size_t reply_len = 0;

    sc_frame_reader_init(&c->in);
    sc_hs_client_start(hs, hello);
    if (sc_send_frame(c->fd, hello, sizeof(hello)) != 0 ||
        read_frame_blocking(c, reply, sizeof(reply), &reply_len,
                            HANDSHAKE_TIMEOUT_MS) != 0) {
        sodium_memzero(hs, sizeof(*hs));
        return -1;
    }
    return sc_hs_client_finish(hs, reply, reply_len, c->server_pk, finish,
                               &c->ch);
}

int sc_client_handshake_confirm(sc_client *c,
                                const uint8_t finish[SC_HS_CLIENT_FINISH_LEN]) {
    return sc_send_frame(c->fd, finish, SC_HS_CLIENT_FINISH_LEN);
}

static int send_msg(sc_client *c, const sc_msg *msg) {
    uint8_t plain[SC_PAYLOAD_MAX];
    uint8_t sealed[SC_FRAME_MAX];
    size_t plain_len = 0;
    size_t sealed_len = 0;
    if (sc_msg_encode(msg, plain, sizeof(plain), &plain_len) != 0 ||
        sc_channel_seal(&c->ch, plain, plain_len, sealed, sizeof(sealed),
                        &sealed_len) != 0) {
        return -1;
    }
    return sc_send_frame(c->fd, sealed, sealed_len);
}

/* ---- roster ---------------------------------------------------------------- */

static sc_peer *roster_find(sc_client *c, const char *name) {
    for (size_t i = 0; i < c->roster_len; i++) {
        if (strcmp(c->roster[i].name, name) == 0) {
            return &c->roster[i];
        }
    }
    return NULL;
}

static void roster_add(sc_client *c, const sc_peer *peer) {
    sc_peer *existing = roster_find(c, peer->name);
    if (existing != NULL) {
        if (sodium_memcmp(existing->key, peer->key, sizeof(peer->key)) != 0) {
            sc_ui_error(&c->ui, "The e2e key of %s changed. Verify it with /whois.",
                        peer->name);
        }
        *existing = *peer;
        return;
    }
    if (c->roster_len < SC_MAX_CLIENTS) {
        c->roster[c->roster_len++] = *peer;
    }
}

static void roster_remove(sc_client *c, const char *name) {
    sc_peer *p = roster_find(c, name);
    if (p != NULL) {
        *p = c->roster[--c->roster_len];
    }
}

/* ---- server messages ------------------------------------------------------- */

/* Replay state for a peer key; NULL when the table is full (fail closed). */
static sc_e2e_peer *e2e_rx_find(sc_client *c,
                                const uint8_t key[crypto_box_PUBLICKEYBYTES]) {
    for (size_t i = 0; i < c->e2e_rx_len; i++) {
        if (sodium_memcmp(c->e2e_rx[i].key, key, crypto_box_PUBLICKEYBYTES) == 0) {
            return &c->e2e_rx[i];
        }
    }
    return NULL;
}

/* Open a private blob from `sender`, enforcing per-key replay protection. */
static int open_private(sc_client *c, const sc_peer *sender, const sc_msg *msg,
                        uint8_t *plain, size_t *plain_len) {
    sc_e2e_peer *state = e2e_rx_find(c, sender->key);
    uint64_t last = state != NULL ? state->last_counter : 0;
    if (state == NULL && c->e2e_rx_len == SC_E2E_PEERS_MAX) {
        return -1; /* replay table full: fail closed */
    }
    if (sc_e2e_open(&c->box, sender->key, &last, msg->blob, msg->blob_len,
                    plain, SC_TEXT_MAX, plain_len) != 0) {
        return -1;
    }
    if (state == NULL) {
        state = &c->e2e_rx[c->e2e_rx_len++];
        memcpy(state->key, sender->key, sizeof(state->key));
    }
    state->last_counter = last;
    return 0;
}

static void show_private(sc_client *c, const sc_msg *msg) {
    sc_peer *sender = roster_find(c, msg->name);
    uint8_t plain[SC_TEXT_MAX + 1];
    size_t plain_len = 0;
    if (sender == NULL || open_private(c, sender, msg, plain, &plain_len) != 0) {
        sc_ui_error(&c->ui, "Rejected a private message claiming to be from %s: "
                            "it failed end-to-end authentication.",
                    msg->name);
        return;
    }
    if (!sc_text_is_safe(plain, plain_len)) {
        sc_ui_error(&c->ui, "Rejected a private message from %s: unsafe content.",
                    msg->name);
        return;
    }
    plain[plain_len] = '\0';
    sc_ui_private_in(&c->ui, msg->name, msg->color, (const char *)plain);
    sodium_memzero(plain, sizeof(plain));
}

static run_status handle_server_msg(sc_client *c, const sc_msg *msg) {
    switch (msg->type) {
    case SC_MSG_WELCOME:
        if (c->joined) {
            return RUN_FAIL;
        }
        c->joined = 1;
        c->join_pending = 0;
        memcpy(c->name, msg->name, sizeof(c->name));
        c->color = msg->color;
        c->roster_len = 0;
        for (size_t i = 0; i < msg->roster_len; i++) {
            roster_add(c, &msg->roster[i]);
        }
        sc_ui_set_prompt(&c->ui, c->name, c->color);
        sc_ui_welcome(&c->ui, msg);
        break;
    case SC_MSG_ERROR:
        c->join_pending = 0;
        sc_ui_error(&c->ui, "%s", msg->text);
        break;
    case SC_MSG_NOTICE:
        sc_ui_notice(&c->ui, "%s", msg->text);
        break;
    case SC_MSG_JOINED: {
        sc_peer peer;
        memcpy(peer.name, msg->name, sizeof(peer.name));
        peer.color = msg->color;
        memcpy(peer.key, msg->key, sizeof(peer.key));
        roster_add(c, &peer);
        sc_ui_joined(&c->ui, msg->name, msg->color);
        break;
    }
    case SC_MSG_LEFT:
        roster_remove(c, msg->name);
        sc_ui_left(&c->ui, msg->name, msg->color);
        break;
    case SC_MSG_CHAT:
        sc_ui_chat(&c->ui, msg->name, msg->color, msg->text,
                   c->joined && strcmp(msg->name, c->name) == 0);
        break;
    case SC_MSG_PRIVATE_FROM:
        show_private(c, msg);
        break;
    case SC_MSG_ROSTER:
        c->roster_len = 0;
        for (size_t i = 0; i < msg->roster_len; i++) {
            roster_add(c, &msg->roster[i]);
        }
        sc_ui_roster(&c->ui, c->roster, c->roster_len, c->name);
        break;
    default:
        return RUN_FAIL; /* client-only message type from the server */
    }
    return RUN_CONTINUE;
}

static run_status on_socket_readable(sc_client *c) {
    size_t avail = 0;
    uint8_t *space = sc_frame_reader_space(&c->in, &avail);
    ssize_t n = recv(c->fd, space, avail, 0);
    if (n < 0 && (errno == EINTR || errno == EAGAIN)) {
        return RUN_CONTINUE;
    }
    if (n <= 0) {
        sc_ui_notice(&c->ui, "Disconnected from the server.");
        return RUN_QUIT;
    }
    sc_frame_reader_commit(&c->in, (size_t)n);

    uint8_t frame[SC_FRAME_MAX];
    uint8_t plain[SC_PAYLOAD_MAX];
    size_t frame_len = 0;
    size_t plain_len = 0;
    sc_frame_status st;
    while ((st = sc_frame_reader_next(&c->in, frame, sizeof(frame),
                                      &frame_len)) == SC_FRAME_READY) {
        sc_msg msg;
        if (sc_channel_open(&c->ch, frame, frame_len, plain, sizeof(plain),
                            &plain_len) != 0 ||
            sc_msg_decode(plain, plain_len, &msg) != 0) {
            sc_ui_error(&c->ui, "The server sent data that failed authentication "
                                "or validation. Disconnecting.");
            return RUN_FAIL;
        }
        run_status rs = handle_server_msg(c, &msg);
        if (rs != RUN_CONTINUE) {
            return rs;
        }
    }
    if (st == SC_FRAME_INVALID) {
        sc_ui_error(&c->ui, "Invalid frame from the server. Disconnecting.");
        return RUN_FAIL;
    }
    return RUN_CONTINUE;
}

/* ---- user input ------------------------------------------------------------- */

static run_status send_or_fail(sc_client *c, const sc_msg *msg) {
    if (send_msg(c, msg) != 0) {
        sc_ui_error(&c->ui, "Connection lost.");
        return RUN_FAIL;
    }
    return RUN_CONTINUE;
}

static run_status send_join(sc_client *c, const char *name) {
    if (!sc_name_is_valid(name)) {
        sc_ui_error(&c->ui, "Usernames have 1-%d characters: letters, digits, "
                            "'_' or '-'.",
                    SC_NAME_MAX);
        return RUN_CONTINUE;
    }
    sc_msg msg;
    sc_msg_init(&msg, SC_MSG_JOIN);
    snprintf(msg.name, sizeof(msg.name), "%s", name);
    memcpy(msg.key, c->box.pk, sizeof(msg.key));
    c->join_pending = 1;
    return send_or_fail(c, &msg);
}

static run_status send_private(sc_client *c, const sc_command *cmd) {
    sc_peer *peer = sc_name_is_valid(cmd->user) ? roster_find(c, cmd->user) : NULL;
    if (peer == NULL) {
        sc_ui_error(&c->ui, "No user named '%.*s' is online.", SC_NAME_MAX,
                    cmd->user);
        return RUN_CONTINUE;
    }
    if (strcmp(peer->name, c->name) == 0) {
        sc_ui_error(&c->ui, "You cannot send a private message to yourself.");
        return RUN_CONTINUE;
    }
    size_t len = strlen(cmd->text);
    sc_msg msg;
    sc_msg_init(&msg, SC_MSG_PRIVATE);
    memcpy(msg.name, peer->name, sizeof(msg.name));
    if (sc_e2e_seal(&c->box, peer->key, c->e2e_tx_counter + 1,
                    (const uint8_t *)cmd->text, len, msg.blob,
                    sizeof(msg.blob), &msg.blob_len) != 0) {
        sc_ui_error(&c->ui, "Could not encrypt the message.");
        return RUN_CONTINUE;
    }
    c->e2e_tx_counter++;
    run_status rs = send_or_fail(c, &msg);
    if (rs == RUN_CONTINUE) {
        sc_ui_private_out(&c->ui, peer->name, peer->color, cmd->text);
    }
    return rs;
}

static run_status handle_line(sc_client *c, const char *line) {
    if (!c->joined) {
        return line[0] == '\0' ? RUN_CONTINUE : send_join(c, line);
    }
    sc_command cmd;
    sc_command_parse(line, &cmd);

    if (cmd.type == SC_CMD_SAY || cmd.type == SC_CMD_MSG) {
        const char *text = cmd.text;
        if (!sc_text_is_safe((const uint8_t *)text, strlen(text))) {
            sc_ui_error(&c->ui, "Messages are limited to %d bytes of printable "
                                "UTF-8 text.",
                        SC_TEXT_MAX);
            return RUN_CONTINUE;
        }
    }

    sc_msg msg;
    switch (cmd.type) {
    case SC_CMD_EMPTY:
        return RUN_CONTINUE;
    case SC_CMD_SAY:
        sc_msg_init(&msg, SC_MSG_SAY);
        snprintf(msg.text, sizeof(msg.text), "%s", cmd.text);
        return send_or_fail(c, &msg);
    case SC_CMD_MSG:
        return send_private(c, &cmd);
    case SC_CMD_LIST:
        sc_msg_init(&msg, SC_MSG_LIST);
        return send_or_fail(c, &msg);
    case SC_CMD_WHOIS: {
        sc_peer *peer = sc_name_is_valid(cmd.user) ? roster_find(c, cmd.user) : NULL;
        if (peer == NULL) {
            sc_ui_error(&c->ui, "No user named '%.*s' is online.", SC_NAME_MAX,
                        cmd.user);
        } else {
            char fp[SC_FINGERPRINT_LEN];
            sc_fingerprint(peer->key, sizeof(peer->key), fp);
            sc_ui_whois(&c->ui, peer, fp);
        }
        return RUN_CONTINUE;
    }
    case SC_CMD_FINGERPRINT: {
        char own[SC_FINGERPRINT_LEN];
        char server[SC_FINGERPRINT_LEN];
        sc_fingerprint(c->box.pk, sizeof(c->box.pk), own);
        sc_fingerprint(c->server_pk, sizeof(c->server_pk), server);
        sc_ui_info(&c->ui, "your e2e key    %s", own);
        sc_ui_info(&c->ui, "server identity %s", server);
        return RUN_CONTINUE;
    }
    case SC_CMD_HELP:
        sc_ui_help(&c->ui);
        return RUN_CONTINUE;
    case SC_CMD_QUIT:
        return RUN_QUIT;
    case SC_CMD_USAGE:
        sc_ui_error(&c->ui, "Missing arguments. Type /help for usage.");
        return RUN_CONTINUE;
    case SC_CMD_UNKNOWN:
    default:
        sc_ui_error(&c->ui, "Unknown command. Type /help for the list.");
        return RUN_CONTINUE;
    }
}

static run_status on_stdin_readable(sc_client *c, int *stdin_open) {
    uint8_t chunk[256];
    ssize_t n = read(STDIN_FILENO, chunk, sizeof(chunk));
    if (n < 0 && errno == EINTR) {
        return RUN_CONTINUE;
    }
    if (n <= 0) {
        *stdin_open = 0;
        /* Treat an unterminated last line as complete, then quit. */
        char line[SC_LINE_MAX + 1];
        if (c->editor.len > 0 &&
            sc_lineedit_feed(&c->editor, '\n', line) == SC_LE_LINE) {
            run_status rs = handle_line(c, line);
            if (rs != RUN_CONTINUE) {
                return rs;
            }
        }
        return RUN_QUIT;
    }
    for (ssize_t i = 0; i < n; i++) {
        char line[SC_LINE_MAX + 1];
        sc_le_event ev = sc_lineedit_feed(&c->editor, chunk[i], line);
        run_status rs = RUN_CONTINUE;
        switch (ev) {
        case SC_LE_LINE:
            if (c->ui.interactive && line[0] != '\0') {
                sc_ui_finish(&c->ui); /* the line is shown once the server echoes it */
            }
            rs = handle_line(c, line);
            sc_ui_redraw(&c->ui);
            break;
        case SC_LE_TOO_LONG:
            sc_ui_error(&c->ui, "That line was too long and was not sent.");
            break;
        case SC_LE_CHANGED:
            sc_ui_redraw(&c->ui);
            break;
        case SC_LE_EOF:
        case SC_LE_INTERRUPT:
            rs = RUN_QUIT;
            break;
        case SC_LE_NONE:
        default:
            break;
        }
        if (rs != RUN_CONTINUE) {
            return rs;
        }
    }
    return RUN_CONTINUE;
}

int sc_client_run(sc_client *c, const char *name, volatile sig_atomic_t *stop) {
    run_status rs = RUN_CONTINUE;
    int stdin_open = 1;

    if (name != NULL) {
        rs = send_join(c, name);
    } else {
        sc_ui_info(&c->ui, "Choose a username to join the room.");
    }
    sc_ui_redraw(&c->ui);

    while (rs == RUN_CONTINUE && !*stop) {
        struct pollfd fds[2];
        nfds_t nfds = 1;
        fds[0].fd = c->fd;
        fds[0].events = POLLIN;
        fds[0].revents = 0;
        /* While a JOIN is in flight, leave typed lines queued in stdin so
         * they are not mistaken for another username attempt. */
        if (stdin_open && !c->join_pending) {
            fds[1].fd = STDIN_FILENO;
            fds[1].events = POLLIN;
            fds[1].revents = 0;
            nfds = 2;
        }
        int ready = poll(fds, nfds, 1000);
        if (ready < 0) {
            if (errno == EINTR) {
                continue;
            }
            rs = RUN_FAIL;
            break;
        }
        if (fds[0].revents & (POLLIN | POLLHUP | POLLERR)) {
            rs = on_socket_readable(c);
        }
        if (rs == RUN_CONTINUE && nfds == 2 &&
            (fds[1].revents & (POLLIN | POLLHUP | POLLERR))) {
            rs = on_stdin_readable(c, &stdin_open);
        }
    }

    if (rs != RUN_FAIL) {
        sc_msg bye;
        sc_msg_init(&bye, SC_MSG_BYE);
        send_msg(c, &bye); /* best effort: the server may already be gone */
    }
    sc_ui_finish(&c->ui);
    return rs == RUN_FAIL ? 1 : 0;
}
