/*
 * Server flow-control tests. A real server runs in a child process on a
 * loopback port; the test drives raw protocol clients built from the
 * library (handshake, secretstream channel, message codec, e2e seal).
 */
#include <errno.h>
#include <netinet/in.h>
#include <poll.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/wait.h>
#include <time.h>
#include <unistd.h>

#include "securechat/crypto.h"
#include "securechat/frame.h"
#include "securechat/message.h"
#include "securechat/net.h"
#include "server.h"
#include "test.h"

#define IO_TIMEOUT_MS 10000
#define BURST_FRAMES 150

/* ---- server in a child process ------------------------------------------- */

static volatile sig_atomic_t child_stop = 0;

static void on_child_signal(int sig) {
    (void)sig;
    child_stop = 1;
}

static pid_t server_pid = -1;
static char server_port[16];

static int start_server(void) {
    int fd = sc_tcp_listen("127.0.0.1", "0");
    if (fd < 0) {
        return -1;
    }
    struct sockaddr_in sa;
    socklen_t sa_len = sizeof(sa);
    if (getsockname(fd, (struct sockaddr *)&sa, &sa_len) != 0) {
        close(fd);
        return -1;
    }
    snprintf(server_port, sizeof(server_port), "%u", ntohs(sa.sin_port));
    fflush(stdout);
    server_pid = fork();
    if (server_pid < 0) {
        close(fd);
        return -1;
    }
    if (server_pid == 0) {
        static sc_identity id;
        sc_server_config cfg;
        if (freopen("/dev/null", "w", stdout) == NULL) {
            _exit(2);
        }
        signal(SIGTERM, on_child_signal);
        signal(SIGPIPE, SIG_IGN);
        sc_identity_generate(&id);
        memset(&cfg, 0, sizeof(cfg));
        cfg.listen_fd = fd;
        cfg.identity = &id;
        sc_style_init(&cfg.style, 0);
        int rc = sc_server_run(&cfg, &child_stop);
        close(fd);
        exit(rc == 0 ? 0 : 1);
    }
    close(fd);
    return 0;
}

static int stop_server(void) {
    int status = 0;
    if (server_pid <= 0) {
        return -1;
    }
    kill(server_pid, SIGTERM);
    if (waitpid(server_pid, &status, 0) != server_pid) {
        return -1;
    }
    server_pid = -1;
    return WIFEXITED(status) ? WEXITSTATUS(status) : -1;
}

/* ---- raw protocol client --------------------------------------------------- */

typedef struct {
    int fd;
    sc_channel ch;
    sc_frame_reader in;
    sc_box_keypair box;
    char name[SC_NAME_MAX + 1];
} test_client;

static long now_ms(void) {
    struct timespec ts;
    clock_gettime(CLOCK_MONOTONIC, &ts);
    return (long)ts.tv_sec * 1000 + ts.tv_nsec / 1000000;
}

/* 1: frame ready, 0: timeout, -1: closed or invalid. */
static int read_frame(test_client *c, uint8_t *out, size_t cap, size_t *len,
                      int timeout_ms) {
    long deadline = now_ms() + timeout_ms;
    for (;;) {
        sc_frame_status st = sc_frame_reader_next(&c->in, out, cap, len);
        if (st == SC_FRAME_READY) {
            return 1;
        }
        if (st == SC_FRAME_INVALID) {
            return -1;
        }
        long left = deadline - now_ms();
        if (left <= 0) {
            return 0;
        }
        struct pollfd pfd = {c->fd, POLLIN, 0};
        int ready = poll(&pfd, 1, (int)left);
        if (ready < 0 && errno == EINTR) {
            continue;
        }
        if (ready <= 0) {
            return ready == 0 ? 0 : -1;
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

/* 1: message decoded, 0: timeout, -1: closed or undecodable. */
static int recv_msg(test_client *c, sc_msg *msg, int timeout_ms) {
    uint8_t frame[SC_FRAME_MAX];
    uint8_t plain[SC_PAYLOAD_MAX];
    size_t frame_len = 0;
    size_t plain_len = 0;
    int rc = read_frame(c, frame, sizeof(frame), &frame_len, timeout_ms);
    if (rc != 1) {
        return rc;
    }
    if (sc_channel_open(&c->ch, frame, frame_len, plain, sizeof(plain),
                        &plain_len) != 0 ||
        sc_msg_decode(plain, plain_len, msg) != 0) {
        return -1;
    }
    return 1;
}

/* Seal and frame `msg` into `out`; returns bytes written or -1. */
static long encode_msg(test_client *c, const sc_msg *msg, uint8_t *out,
                       size_t cap) {
    uint8_t plain[SC_PAYLOAD_MAX];
    uint8_t sealed[SC_FRAME_MAX];
    size_t plain_len = 0;
    size_t sealed_len = 0;
    if (sc_msg_encode(msg, plain, sizeof(plain), &plain_len) != 0 ||
        sc_channel_seal(&c->ch, plain, plain_len, sealed, sizeof(sealed),
                        &sealed_len) != 0) {
        return -1;
    }
    return sc_frame_encode(out, cap, sealed, sealed_len);
}

static int send_msg(test_client *c, const sc_msg *msg) {
    uint8_t buf[SC_FRAME_HEADER_LEN + SC_FRAME_MAX];
    long n = encode_msg(c, msg, buf, sizeof(buf));
    return n < 0 ? -1 : sc_send_all(c->fd, buf, (size_t)n);
}

/* Wait for a message of `type`, skipping others. 1, 0 (timeout) or -1. */
static int wait_for(test_client *c, sc_msg_type type, sc_msg *msg,
                    int timeout_ms) {
    long deadline = now_ms() + timeout_ms;
    for (;;) {
        long left = deadline - now_ms();
        if (left <= 0) {
            return 0;
        }
        int rc = recv_msg(c, msg, (int)left);
        if (rc != 1 || msg->type == type) {
            return rc;
        }
    }
}

/* Connect, handshake and join as `name`. `rcvbuf` > 0 shrinks SO_RCVBUF. */
static int client_join(test_client *c, const char *name, int rcvbuf) {
    memset(c, 0, sizeof(*c));
    c->fd = socket(AF_INET, SOCK_STREAM, 0);
    if (c->fd < 0) {
        return -1;
    }
    if (rcvbuf > 0) {
        setsockopt(c->fd, SOL_SOCKET, SO_RCVBUF, &rcvbuf, sizeof(rcvbuf));
    }
    struct sockaddr_in sa;
    memset(&sa, 0, sizeof(sa));
    sa.sin_family = AF_INET;
    sa.sin_port = htons((uint16_t)atoi(server_port));
    sa.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
    if (connect(c->fd, (struct sockaddr *)&sa, sizeof(sa)) != 0) {
        return -1;
    }
    sc_frame_reader_init(&c->in);
    sc_box_keypair_generate(&c->box);
    snprintf(c->name, sizeof(c->name), "%s", name);

    sc_client_handshake hs;
    uint8_t hello[SC_HS_CLIENT_HELLO_LEN];
    uint8_t reply[SC_FRAME_MAX];
    uint8_t finish[SC_HS_CLIENT_FINISH_LEN];
    uint8_t server_pk[crypto_sign_PUBLICKEYBYTES];
    size_t reply_len = 0;
    sc_hs_client_start(&hs, hello);
    if (sc_send_frame(c->fd, hello, sizeof(hello)) != 0 ||
        read_frame(c, reply, sizeof(reply), &reply_len, IO_TIMEOUT_MS) != 1 ||
        sc_hs_client_finish(&hs, reply, reply_len, server_pk, finish,
                            &c->ch) != 0 ||
        sc_send_frame(c->fd, finish, sizeof(finish)) != 0) {
        return -1;
    }

    sc_msg msg;
    sc_msg_init(&msg, SC_MSG_JOIN);
    snprintf(msg.name, sizeof(msg.name), "%s", name);
    memcpy(msg.key, c->box.pk, sizeof(msg.key));
    if (send_msg(c, &msg) != 0) {
        return -1;
    }
    return wait_for(c, SC_MSG_WELCOME, &msg, IO_TIMEOUT_MS) == 1 ? 0 : -1;
}

static void client_close(test_client *c) {
    if (c->fd >= 0) {
        close(c->fd);
        c->fd = -1;
    }
}

/* Join `peer_name` and let `observer` see the JOINED notice. */
static int observe_join(test_client *observer, const char *peer_name) {
    sc_msg msg;
    while (wait_for(observer, SC_MSG_JOINED, &msg, IO_TIMEOUT_MS) == 1) {
        if (strcmp(msg.name, peer_name) == 0) {
            return 0;
        }
    }
    return -1;
}

/* The connection is still served: /list gets a roster back. */
static int still_connected(test_client *c) {
    sc_msg msg;
    sc_msg_init(&msg, SC_MSG_LIST);
    return send_msg(c, &msg) == 0 &&
           wait_for(c, SC_MSG_ROSTER, &msg, IO_TIMEOUT_MS) == 1;
}

/* ---- tests ------------------------------------------------------------------- */

/*
 * One sender fires 150 maximum-size private messages in a single write
 * (about 90 KB, more than the 64 KiB per-connection output queue). A
 * recipient that reads normally must receive all of them and stay connected.
 */
static void test_burst_does_not_drop_reading_recipient(void) {
    test_client victim;
    test_client sender;
    CHECK(client_join(&victim, "victim", 0) == 0);
    CHECK(client_join(&sender, "sender", 0) == 0);
    CHECK(observe_join(&victim, "sender") == 0);

    static uint8_t burst[BURST_FRAMES * (SC_FRAME_HEADER_LEN + SC_FRAME_MAX)];
    size_t burst_len = 0;
    char text[SC_TEXT_MAX + 1];
    memset(text, 'p', SC_TEXT_MAX);
    text[SC_TEXT_MAX] = '\0';
    int encoded = 1;
    for (uint64_t i = 1; i <= BURST_FRAMES; i++) {
        sc_msg msg;
        sc_msg_init(&msg, SC_MSG_PRIVATE);
        snprintf(msg.name, sizeof(msg.name), "%s", "victim");
        long n = -1;
        if (sc_e2e_seal(&sender.box, victim.box.pk, i, (const uint8_t *)text,
                        SC_TEXT_MAX, msg.blob, sizeof(msg.blob),
                        &msg.blob_len) == 0) {
            n = encode_msg(&sender, &msg, burst + burst_len,
                           sizeof(burst) - burst_len);
        }
        if (n < 0) {
            encoded = 0;
            break;
        }
        burst_len += (size_t)n;
    }
    CHECK(encoded);
    CHECK(burst_len > 64 * 1024);
    CHECK(sc_send_all(sender.fd, burst, burst_len) == 0);

    int received = 0;
    int authentic = 1;
    uint64_t last = 0;
    sc_msg msg;
    while (received < BURST_FRAMES &&
           wait_for(&victim, SC_MSG_PRIVATE_FROM, &msg, IO_TIMEOUT_MS) == 1) {
        uint8_t plain[SC_TEXT_MAX];
        size_t plain_len = 0;
        if (sc_e2e_open(&victim.box, sender.box.pk, &last, msg.blob,
                        msg.blob_len, plain, sizeof(plain), &plain_len) != 0 ||
            plain_len != SC_TEXT_MAX) {
            authentic = 0;
        }
        received++;
    }
    CHECK(received == BURST_FRAMES);
    CHECK(authentic);
    CHECK(last == BURST_FRAMES);
    CHECK(still_connected(&victim));
    CHECK(still_connected(&sender));
    client_close(&victim);
    client_close(&sender);
}

/*
 * A recipient that never reads is still dropped, and the room (including
 * the sender, which flow control may pause meanwhile) keeps working.
 */
static void test_non_reading_recipient_is_dropped(void) {
    test_client observer;
    test_client sender;
    test_client stuck;
    CHECK(client_join(&observer, "observer", 0) == 0);
    CHECK(client_join(&sender, "flooder", 0) == 0);
    CHECK(client_join(&stuck, "stuck", 4096) == 0);
    CHECK(observe_join(&observer, "stuck") == 0);

    uint8_t frame[SC_FRAME_HEADER_LEN + SC_FRAME_MAX];
    size_t frame_len = 0;
    size_t frame_off = 0;
    int dropped = 0;
    int send_error = 0;
    long deadline = now_ms() + 60000;
    while (!dropped && !send_error && now_ms() < deadline) {
        if (frame_off == frame_len) {
            sc_msg msg;
            sc_msg_init(&msg, SC_MSG_PRIVATE);
            snprintf(msg.name, sizeof(msg.name), "%s", "stuck");
            msg.blob_len = SC_E2E_MAX;
            randombytes_buf(msg.blob, msg.blob_len);
            long n = encode_msg(&sender, &msg, frame, sizeof(frame));
            if (n < 0) {
                send_error = 1;
                break;
            }
            frame_len = (size_t)n;
            frame_off = 0;
        }
        struct pollfd pfds[2] = {{sender.fd, POLLOUT, 0},
                                 {observer.fd, POLLIN, 0}};
        if (poll(pfds, 2, 200) < 0 && errno != EINTR) {
            send_error = 1;
            break;
        }
        if (pfds[0].revents & POLLOUT) {
            ssize_t n = send(sender.fd, frame + frame_off, frame_len - frame_off,
                             MSG_NOSIGNAL | MSG_DONTWAIT);
            if (n > 0) {
                frame_off += (size_t)n;
            } else if (n < 0 && errno != EAGAIN && errno != EWOULDBLOCK &&
                       errno != EINTR) {
                send_error = 1;
            }
        }
        if (pfds[1].revents & (POLLIN | POLLHUP | POLLERR)) {
            sc_msg msg;
            int rc = recv_msg(&observer, &msg, IO_TIMEOUT_MS);
            if (rc != 1) {
                send_error = 1;
            } else if (msg.type == SC_MSG_LEFT && strcmp(msg.name, "stuck") == 0) {
                dropped = 1;
            }
        }
    }
    CHECK(!send_error);
    CHECK(dropped);
    /* Finish the partially sent frame so the sender's stream stays valid. */
    if (frame_off < frame_len) {
        CHECK(sc_send_all(sender.fd, frame + frame_off, frame_len - frame_off) == 0);
    }
    CHECK(still_connected(&observer));
    CHECK(still_connected(&sender));
    client_close(&stuck);
    client_close(&observer);
    client_close(&sender);
}

int main(void) {
    if (sc_crypto_init() != 0) {
        return 1;
    }
    signal(SIGPIPE, SIG_IGN);
    if (start_server() != 0) {
        fprintf(stderr, "could not start the server\n");
        return 1;
    }
    printf("server\n");
    RUN(test_burst_does_not_drop_reading_recipient);
    RUN(test_non_reading_recipient_is_dropped);
    CHECK(stop_server() == 0);
    return TEST_SUMMARY("server");
}
