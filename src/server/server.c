#include "server.h"

#include <arpa/inet.h>
#include <errno.h>
#include <netinet/in.h>
#include <poll.h>
#include <stdarg.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <strings.h>
#include <sys/socket.h>
#include <time.h>
#include <unistd.h>

#include "securechat/frame.h"
#include "securechat/message.h"
#include "securechat/net.h"

/* Per-connection output queue; a client that lets it fill up is dropped. */
#define OUTBUF_SIZE (64 * 1024)

/*
 * Flow control. Input is processed at most MAX_FRAMES_PER_ROUND frames per
 * connection per poll round, and output is flushed after every round, so a
 * burst from one sender cannot pile up in a reader's queue before it gets a
 * chance to drain. While any queue is above HIGH_WATER, the server stops
 * reading from joined connections (any of them could target the congested
 * one) until it drains. A connection whose queue stays above HIGH_WATER for
 * STALL_SECONDS has stopped reading and is dropped.
 */
#define MAX_FRAMES_PER_ROUND 8
#define HIGH_WATER (OUTBUF_SIZE / 2)
#define STALL_SECONDS 10

typedef enum {
    CONN_FREE = 0,
    CONN_HELLO,  /* waiting for ClientHello */
    CONN_FINISH, /* waiting for ClientFinish */
    CONN_JOIN,   /* encrypted, waiting for a valid JOIN */
    CONN_ACTIVE  /* joined the room */
} conn_state;

typedef struct {
    int fd;
    conn_state state;
    const char *close_reason; /* non-NULL: scheduled for removal */
    time_t deadline;
    int join_attempts;
    char addr[64];
    sc_frame_reader in;
    uint8_t out[OUTBUF_SIZE];
    size_t out_len;
    time_t stalled_since; /* 0, or when out_len first exceeded HIGH_WATER */
    int input_pending;    /* buffered input left unprocessed last round */
    sc_server_handshake hs;
    sc_channel ch;
    char name[SC_NAME_MAX + 1];
    uint8_t color;
    uint8_t box_pk[crypto_box_PUBLICKEYBYTES];
} conn;

typedef struct {
    const sc_server_config *cfg;
    conn conns[SC_MAX_CLIENTS];
} server;

/* ---- logging ----------------------------------------------------------- */

void sc_server_log(const sc_style *style, const char *level_color,
                   const char *symbol, const char *fmt, ...) {
    char clock[16];
    sc_clock(clock, sizeof(clock), 1);
    printf("%s%s%s %s%s%s ", style->dim, clock, style->reset, level_color,
           symbol, style->reset);
    va_list ap;
    va_start(ap, fmt);
    vprintf(fmt, ap);
    va_end(ap);
    putchar('\n');
    fflush(stdout);
}

#define LOG_INFO(s, ...) sc_server_log(&(s)->cfg->style, (s)->cfg->style.accent, "▸", __VA_ARGS__)
#define LOG_JOIN(s, ...) sc_server_log(&(s)->cfg->style, (s)->cfg->style.ok, "+", __VA_ARGS__)
#define LOG_LEAVE(s, ...) sc_server_log(&(s)->cfg->style, (s)->cfg->style.warn, "-", __VA_ARGS__)
#define LOG_WARN(s, ...) sc_server_log(&(s)->cfg->style, (s)->cfg->style.err, "!", __VA_ARGS__)

/* ---- connection helpers ------------------------------------------------ */

static void schedule_close(conn *c, const char *reason) {
    if (c->close_reason == NULL) {
        c->close_reason = reason;
    }
}

static int is_live(const conn *c) {
    return c->state != CONN_FREE && c->close_reason == NULL;
}

static void queue_frame(conn *c, const uint8_t *payload, size_t len) {
    if (!is_live(c)) {
        return;
    }
    long n = sc_frame_encode(c->out + c->out_len, OUTBUF_SIZE - c->out_len,
                             payload, len);
    if (n < 0) {
        schedule_close(c, "too slow to receive (output queue full)");
        return;
    }
    c->out_len += (size_t)n;
}

static void send_msg(conn *c, const sc_msg *msg) {
    uint8_t plain[SC_PAYLOAD_MAX];
    uint8_t sealed[SC_FRAME_MAX];
    size_t plain_len = 0;
    size_t sealed_len = 0;
    if (!is_live(c)) {
        return;
    }
    if (sc_msg_encode(msg, plain, sizeof(plain), &plain_len) != 0 ||
        sc_channel_seal(&c->ch, plain, plain_len, sealed, sizeof(sealed),
                        &sealed_len) != 0) {
        schedule_close(c, "internal encoding error");
        return;
    }
    queue_frame(c, sealed, sealed_len);
}

static void send_text(conn *c, sc_msg_type type, const char *text) {
    sc_msg msg;
    sc_msg_init(&msg, type);
    snprintf(msg.text, sizeof(msg.text), "%s", text);
    send_msg(c, &msg);
}

/* Best-effort non-blocking flush. Returns -1 on a fatal socket error. */
static int flush_output(conn *c) {
    while (c->out_len > 0) {
        ssize_t n = send(c->fd, c->out, c->out_len, MSG_NOSIGNAL);
        if (n < 0) {
            if (errno == EINTR) {
                continue;
            }
            if (errno == EAGAIN || errno == EWOULDBLOCK) {
                return 0;
            }
            return -1;
        }
        memmove(c->out, c->out + n, c->out_len - (size_t)n);
        c->out_len -= (size_t)n;
    }
    return 0;
}

static void broadcast(server *s, const sc_msg *msg, const conn *except) {
    for (size_t i = 0; i < SC_MAX_CLIENTS; i++) {
        conn *c = &s->conns[i];
        if (c != except && c->state == CONN_ACTIVE && is_live(c)) {
            send_msg(c, msg);
        }
    }
}

static conn *find_active(server *s, const char *name, int ignore_case) {
    for (size_t i = 0; i < SC_MAX_CLIENTS; i++) {
        conn *c = &s->conns[i];
        if (c->state != CONN_ACTIVE || !is_live(c)) {
            continue;
        }
        int same = ignore_case ? strcasecmp(c->name, name) == 0
                               : strcmp(c->name, name) == 0;
        if (same) {
            return c;
        }
    }
    return NULL;
}

static void fill_roster(server *s, sc_msg *msg) {
    msg->roster_len = 0;
    for (size_t i = 0; i < SC_MAX_CLIENTS; i++) {
        conn *c = &s->conns[i];
        if (c->state == CONN_ACTIVE && is_live(c)) {
            sc_peer *p = &msg->roster[msg->roster_len++];
            memcpy(p->name, c->name, sizeof(p->name));
            p->color = c->color;
            memcpy(p->key, c->box_pk, sizeof(p->key));
        }
    }
}

static uint8_t pick_color(server *s) {
    int used[SC_COLOR_COUNT] = {0};
    size_t active = 0;
    for (size_t i = 0; i < SC_MAX_CLIENTS; i++) {
        if (s->conns[i].state == CONN_ACTIVE) {
            used[s->conns[i].color] = 1;
            active++;
        }
    }
    for (uint8_t col = 0; col < SC_COLOR_COUNT; col++) {
        if (!used[col]) {
            return col;
        }
    }
    return (uint8_t)(active % SC_COLOR_COUNT);
}

/* ---- message handlers -------------------------------------------------- */

static void handle_join(server *s, conn *c, const sc_msg *msg) {
    const char *problem = NULL;
    if (find_active(s, msg->name, 1) != NULL) {
        problem = "That username is already taken. Choose another one.";
    }
    if (problem != NULL) {
        send_text(c, SC_MSG_ERROR, problem);
        if (++c->join_attempts >= SC_MAX_JOIN_ATTEMPTS) {
            schedule_close(c, "too many failed join attempts");
        }
        return;
    }

    memcpy(c->name, msg->name, sizeof(c->name));
    memcpy(c->box_pk, msg->key, sizeof(c->box_pk));
    c->color = pick_color(s);
    c->state = CONN_ACTIVE;

    sc_msg welcome;
    sc_msg_init(&welcome, SC_MSG_WELCOME);
    memcpy(welcome.name, c->name, sizeof(welcome.name));
    welcome.color = c->color;
    fill_roster(s, &welcome);
    send_msg(c, &welcome);

    sc_msg joined;
    sc_msg_init(&joined, SC_MSG_JOINED);
    memcpy(joined.name, c->name, sizeof(joined.name));
    joined.color = c->color;
    memcpy(joined.key, c->box_pk, sizeof(joined.key));
    broadcast(s, &joined, c);

    LOG_JOIN(s, "%s joined from %s", c->name, c->addr);
}

static void handle_private(server *s, conn *c, const sc_msg *msg) {
    conn *to = find_active(s, msg->name, 0);
    if (to == NULL) {
        char text[96];
        snprintf(text, sizeof(text), "No user named '%s' is online.",
                 msg->name);
        send_text(c, SC_MSG_ERROR, text);
        return;
    }
    if (to == c) {
        send_text(c, SC_MSG_ERROR, "You cannot send a private message to yourself.");
        return;
    }
    /* The blob is end-to-end encrypted; the server only relays it. */
    sc_msg relay;
    sc_msg_init(&relay, SC_MSG_PRIVATE_FROM);
    memcpy(relay.name, c->name, sizeof(relay.name));
    relay.color = c->color;
    memcpy(relay.blob, msg->blob, msg->blob_len);
    relay.blob_len = msg->blob_len;
    send_msg(to, &relay);
}

static void handle_message(server *s, conn *c, const sc_msg *msg) {
    if (c->state == CONN_JOIN) {
        if (msg->type == SC_MSG_JOIN) {
            handle_join(s, c, msg);
        } else if (msg->type == SC_MSG_BYE) {
            schedule_close(c, "left before joining");
        } else {
            send_text(c, SC_MSG_ERROR, "Choose a username first.");
        }
        return;
    }

    switch (msg->type) {
    case SC_MSG_SAY: {
        if (msg->text[0] == '\0') {
            send_text(c, SC_MSG_ERROR, "Empty messages are not sent.");
            break;
        }
        sc_msg chat;
        sc_msg_init(&chat, SC_MSG_CHAT);
        memcpy(chat.name, c->name, sizeof(chat.name));
        chat.color = c->color;
        memcpy(chat.text, msg->text, sizeof(chat.text));
        broadcast(s, &chat, NULL);
        break;
    }
    case SC_MSG_PRIVATE:
        handle_private(s, c, msg);
        break;
    case SC_MSG_LIST: {
        sc_msg roster;
        sc_msg_init(&roster, SC_MSG_ROSTER);
        fill_roster(s, &roster);
        send_msg(c, &roster);
        break;
    }
    case SC_MSG_BYE:
        schedule_close(c, "left the chat");
        break;
    case SC_MSG_JOIN:
        send_text(c, SC_MSG_ERROR, "You have already joined.");
        break;
    default:
        schedule_close(c, "protocol violation (server-only message type)");
        break;
    }
}

static void handle_frame(server *s, conn *c, const uint8_t *frame,
                         size_t len) {
    switch (c->state) {
    case CONN_HELLO: {
        uint8_t hello[SC_HS_SERVER_HELLO_LEN];
        if (sc_hs_server_respond(s->cfg->identity, &c->hs, frame, len, hello,
                                 &c->ch) != 0) {
            schedule_close(c, "invalid handshake");
            return;
        }
        queue_frame(c, hello, sizeof(hello));
        c->state = CONN_FINISH;
        return;
    }
    case CONN_FINISH:
        if (sc_hs_server_finish(&c->hs, frame, len, &c->ch) != 0) {
            schedule_close(c, "invalid handshake");
            return;
        }
        c->state = CONN_JOIN;
        return;
    default: {
        uint8_t plain[SC_PAYLOAD_MAX];
        size_t plain_len = 0;
        sc_msg msg;
        if (sc_channel_open(&c->ch, frame, len, plain, sizeof(plain),
                            &plain_len) != 0) {
            schedule_close(c, "decryption failed (tampered or replayed frame)");
            return;
        }
        if (sc_msg_decode(plain, plain_len, &msg) != 0) {
            schedule_close(c, "malformed message");
            return;
        }
        handle_message(s, c, &msg);
        return;
    }
    }
}

/* 1 when some live connection's output queue is above the high-water mark. */
static int room_congested(const server *s) {
    for (size_t i = 0; i < SC_MAX_CLIENTS; i++) {
        const conn *c = &s->conns[i];
        if (is_live(c) && c->out_len > HIGH_WATER) {
            return 1;
        }
    }
    return 0;
}

/* Only encrypted connections can make the server queue data for others. */
static int input_paused(const server *s, const conn *c) {
    return (c->state == CONN_JOIN || c->state == CONN_ACTIVE) &&
           room_congested(s);
}

/*
 * Process up to MAX_FRAMES_PER_ROUND frames, reading from the socket as
 * needed. Sets input_pending when it stops early with input possibly left.
 */
static void service_input(server *s, conn *c) {
    uint8_t frame[SC_FRAME_MAX];
    int budget = MAX_FRAMES_PER_ROUND;
    c->input_pending = 0;
    while (is_live(c)) {
        if (budget == 0 || input_paused(s, c)) {
            c->input_pending = 1;
            return;
        }
        size_t frame_len = 0;
        sc_frame_status st =
            sc_frame_reader_next(&c->in, frame, sizeof(frame), &frame_len);
        if (st == SC_FRAME_READY) {
            handle_frame(s, c, frame, frame_len);
            budget--;
            continue;
        }
        if (st == SC_FRAME_INVALID) {
            schedule_close(c, "invalid frame length");
            return;
        }
        size_t avail = 0;
        uint8_t *space = sc_frame_reader_space(&c->in, &avail);
        if (avail == 0) {
            schedule_close(c, "framing error");
            return;
        }
        ssize_t n = recv(c->fd, space, avail, 0);
        if (n == 0) {
            schedule_close(c, "connection closed");
            return;
        }
        if (n < 0) {
            if (errno == EINTR) {
                continue;
            }
            if (errno != EAGAIN && errno != EWOULDBLOCK) {
                schedule_close(c, "connection reset");
            }
            return;
        }
        sc_frame_reader_commit(&c->in, (size_t)n);
    }
}

/* Flush every queue and drop connections that stopped reading. */
static void flush_all(server *s) {
    time_t now = time(NULL);
    for (size_t i = 0; i < SC_MAX_CLIENTS; i++) {
        conn *c = &s->conns[i];
        if (!is_live(c)) {
            continue;
        }
        if (c->out_len > 0 && flush_output(c) != 0) {
            schedule_close(c, "connection lost");
            continue;
        }
        if (c->out_len <= HIGH_WATER) {
            c->stalled_since = 0;
        } else if (c->stalled_since == 0) {
            c->stalled_since = now;
        } else if (now - c->stalled_since >= STALL_SECONDS) {
            schedule_close(c, "too slow to receive (stopped reading)");
        }
    }
}

/* ---- lifecycle --------------------------------------------------------- */

static void format_peer(const struct sockaddr_storage *ss, char *out,
                        size_t cap) {
    char host[INET6_ADDRSTRLEN] = "?";
    unsigned port = 0;
    if (ss->ss_family == AF_INET) {
        const struct sockaddr_in *in4 = (const struct sockaddr_in *)ss;
        inet_ntop(AF_INET, &in4->sin_addr, host, sizeof(host));
        port = ntohs(in4->sin_port);
    } else if (ss->ss_family == AF_INET6) {
        const struct sockaddr_in6 *in6 = (const struct sockaddr_in6 *)ss;
        inet_ntop(AF_INET6, &in6->sin6_addr, host, sizeof(host));
        port = ntohs(in6->sin6_port);
    }
    snprintf(out, cap, "%s:%u", host, port);
}

static void accept_clients(server *s) {
    for (;;) {
        struct sockaddr_storage ss;
        socklen_t ss_len = sizeof(ss);
        int fd = accept(s->cfg->listen_fd, (struct sockaddr *)&ss, &ss_len);
        if (fd < 0) {
            return; /* EAGAIN or transient error: try again next poll */
        }
        conn *slot = NULL;
        for (size_t i = 0; i < SC_MAX_CLIENTS && slot == NULL; i++) {
            if (s->conns[i].state == CONN_FREE) {
                slot = &s->conns[i];
            }
        }
        char addr[64];
        format_peer(&ss, addr, sizeof(addr));
        if (slot == NULL || sc_set_nonblocking(fd) != 0) {
            LOG_WARN(s, "rejected %s: room is full (%d connections)", addr,
                     SC_MAX_CLIENTS);
            close(fd);
            continue;
        }
        memset(slot, 0, sizeof(*slot));
        slot->fd = fd;
        slot->state = CONN_HELLO;
        slot->deadline = time(NULL) + SC_JOIN_TIMEOUT_SECONDS;
        memcpy(slot->addr, addr, sizeof(slot->addr));
        sc_frame_reader_init(&slot->in);
    }
}

/* Remove every connection scheduled for closing, announcing departures. */
static void reap(server *s) {
    int again = 1;
    while (again) {
        again = 0;
        for (size_t i = 0; i < SC_MAX_CLIENTS; i++) {
            conn *c = &s->conns[i];
            if (c->state == CONN_FREE || c->close_reason == NULL) {
                continue;
            }
            if (c->state == CONN_ACTIVE) {
                sc_msg left;
                sc_msg_init(&left, SC_MSG_LEFT);
                memcpy(left.name, c->name, sizeof(left.name));
                left.color = c->color;
                c->state = CONN_JOIN; /* exclude from the broadcast */
                broadcast(s, &left, c);
                LOG_LEAVE(s, "%s %s", c->name, c->close_reason);
                again = 1; /* the broadcast may schedule more closes */
            } else {
                LOG_WARN(s, "dropped %s before join: %s", c->addr,
                         c->close_reason);
            }
            flush_output(c);
            close(c->fd);
            sodium_memzero(c, sizeof(*c));
            c->state = CONN_FREE;
        }
    }
}

static void expire_pending(server *s) {
    time_t now = time(NULL);
    for (size_t i = 0; i < SC_MAX_CLIENTS; i++) {
        conn *c = &s->conns[i];
        if (c->state != CONN_FREE && c->state != CONN_ACTIVE &&
            now > c->deadline) {
            schedule_close(c, "join timeout");
        }
    }
}

static void shutdown_all(server *s) {
    for (size_t i = 0; i < SC_MAX_CLIENTS; i++) {
        conn *c = &s->conns[i];
        if (c->state == CONN_ACTIVE) {
            send_text(c, SC_MSG_NOTICE, "The server is shutting down. Goodbye!");
            flush_output(c);
        }
        if (c->state != CONN_FREE) {
            close(c->fd);
            sodium_memzero(c, sizeof(*c));
        }
    }
}

int sc_server_run(const sc_server_config *cfg, volatile sig_atomic_t *stop) {
    server *s = calloc(1, sizeof(*s));
    if (s == NULL) {
        return -1;
    }
    s->cfg = cfg;
    if (sc_set_nonblocking(cfg->listen_fd) != 0) {
        free(s);
        return -1;
    }

    struct pollfd fds[SC_MAX_CLIENTS + 1];
    conn *owners[SC_MAX_CLIENTS + 1];
    int rc = 0;

    while (!*stop) {
        nfds_t nfds = 0;
        int timeout_ms = 1000;
        fds[nfds].fd = cfg->listen_fd;
        fds[nfds].events = POLLIN;
        owners[nfds++] = NULL;
        for (size_t i = 0; i < SC_MAX_CLIENTS; i++) {
            conn *c = &s->conns[i];
            if (c->state == CONN_FREE) {
                continue;
            }
            int paused = input_paused(s, c);
            short events = (short)((paused ? 0 : POLLIN) |
                                   (c->out_len > 0 ? POLLOUT : 0));
            if (events == 0) {
                continue; /* paused and idle: nothing to wait for */
            }
            if (!paused && c->input_pending) {
                timeout_ms = 0; /* complete frames may already be buffered */
            }
            fds[nfds].fd = c->fd;
            fds[nfds].events = events;
            owners[nfds++] = c;
        }

        int ready = poll(fds, nfds, timeout_ms);
        if (ready < 0) {
            if (errno == EINTR) {
                continue;
            }
            rc = -1;
            break;
        }
        for (nfds_t i = 1; i < nfds; i++) {
            conn *c = owners[i];
            if (fds[i].revents & (POLLERR | POLLNVAL)) {
                schedule_close(c, "connection error");
                continue;
            }
            if (!input_paused(s, c) &&
                ((fds[i].revents & (POLLIN | POLLHUP)) || c->input_pending)) {
                service_input(s, c);
            }
        }
        if (fds[0].revents & POLLIN) {
            accept_clients(s);
        }
        expire_pending(s);
        flush_all(s);
        reap(s);
    }

    shutdown_all(s);
    sodium_memzero(s, sizeof(*s));
    free(s);
    return rc;
}
