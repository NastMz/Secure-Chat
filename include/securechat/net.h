/*
 * Thin POSIX socket helpers.
 */
#ifndef SECURECHAT_NET_H
#define SECURECHAT_NET_H

#include <stddef.h>
#include <stdint.h>

/* Bind and listen on bind_addr:port (IPv4 or IPv6). Returns fd or -1. */
int sc_tcp_listen(const char *bind_addr, const char *port);

/* Resolve host and connect. Returns fd or -1. */
int sc_tcp_connect(const char *host, const char *port);

int sc_set_nonblocking(int fd);

/* Blocking send of the whole buffer (never raises SIGPIPE). Returns 0 or -1. */
int sc_send_all(int fd, const uint8_t *buf, size_t len);

/* Frame `payload` and send it with sc_send_all. Returns 0 or -1. */
int sc_send_frame(int fd, const uint8_t *payload, size_t len);

#endif
