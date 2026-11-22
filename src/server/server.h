/*
 * Single-threaded poll(2) chat server: handshake, join, broadcast, private
 * message relay. Connections are non-blocking with bounded buffers.
 */
#ifndef SECURECHAT_SERVER_H
#define SECURECHAT_SERVER_H

#include <signal.h>

#include "securechat/crypto.h"
#include "securechat/term.h"

typedef struct {
    int listen_fd;
    const sc_identity *identity;
    sc_style style;
} sc_server_config;

/* Run until *stop becomes non-zero. Returns 0 on clean shutdown. */
int sc_server_run(const sc_server_config *config,
                  volatile sig_atomic_t *stop);

/* Timestamped, colored log line on stdout. */
void sc_server_log(const sc_style *style, const char *level_color,
                   const char *symbol, const char *fmt, ...)
    __attribute__((format(printf, 4, 5)));

#endif
