/*
 * Length-prefixed framing. Pure functions over byte buffers, no I/O.
 */
#ifndef SECURECHAT_FRAME_H
#define SECURECHAT_FRAME_H

#include <stddef.h>
#include <stdint.h>

#include "securechat/protocol.h"

typedef struct {
    uint8_t buf[SC_FRAME_HEADER_LEN + SC_FRAME_MAX];
    size_t len;
} sc_frame_reader;

typedef enum {
    SC_FRAME_NEED_MORE = 0,
    SC_FRAME_READY = 1,
    SC_FRAME_INVALID = -1
} sc_frame_status;

void sc_frame_reader_init(sc_frame_reader *reader);

/* Free space the caller may fill directly (e.g. with recv). */
uint8_t *sc_frame_reader_space(sc_frame_reader *reader, size_t *available);

/* Record that `n` bytes were written into the space returned above. */
void sc_frame_reader_commit(sc_frame_reader *reader, size_t n);

/*
 * Extract the next complete frame into `out` (capacity `cap`).
 * Returns SC_FRAME_INVALID for a zero or oversized length prefix, or when the
 * frame does not fit `cap`; the connection must then be dropped.
 */
sc_frame_status sc_frame_reader_next(sc_frame_reader *reader, uint8_t *out,
                                     size_t cap, size_t *out_len);

/* Write header + payload into `out`. Returns total bytes or -1. */
long sc_frame_encode(uint8_t *out, size_t cap, const uint8_t *payload,
                     size_t len);

#endif
