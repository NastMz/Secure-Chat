#include "securechat/frame.h"

#include <string.h>

static uint32_t read_be32(const uint8_t *p) {
    return ((uint32_t)p[0] << 24) | ((uint32_t)p[1] << 16) |
           ((uint32_t)p[2] << 8) | (uint32_t)p[3];
}

static void write_be32(uint8_t *p, uint32_t v) {
    p[0] = (uint8_t)(v >> 24);
    p[1] = (uint8_t)(v >> 16);
    p[2] = (uint8_t)(v >> 8);
    p[3] = (uint8_t)v;
}

void sc_frame_reader_init(sc_frame_reader *reader) { reader->len = 0; }

uint8_t *sc_frame_reader_space(sc_frame_reader *reader, size_t *available) {
    *available = sizeof(reader->buf) - reader->len;
    return reader->buf + reader->len;
}

void sc_frame_reader_commit(sc_frame_reader *reader, size_t n) {
    size_t available = sizeof(reader->buf) - reader->len;
    reader->len += n > available ? available : n;
}

sc_frame_status sc_frame_reader_next(sc_frame_reader *reader, uint8_t *out,
                                     size_t cap, size_t *out_len) {
    if (reader->len < SC_FRAME_HEADER_LEN) {
        return SC_FRAME_NEED_MORE;
    }
    uint32_t payload_len = read_be32(reader->buf);
    if (payload_len == 0 || payload_len > SC_FRAME_MAX || payload_len > cap) {
        return SC_FRAME_INVALID;
    }
    size_t total = SC_FRAME_HEADER_LEN + (size_t)payload_len;
    if (reader->len < total) {
        return SC_FRAME_NEED_MORE;
    }
    memcpy(out, reader->buf + SC_FRAME_HEADER_LEN, payload_len);
    *out_len = payload_len;
    memmove(reader->buf, reader->buf + total, reader->len - total);
    reader->len -= total;
    return SC_FRAME_READY;
}

long sc_frame_encode(uint8_t *out, size_t cap, const uint8_t *payload,
                     size_t len) {
    if (len == 0 || len > SC_FRAME_MAX || cap < SC_FRAME_HEADER_LEN + len) {
        return -1;
    }
    write_be32(out, (uint32_t)len);
    memcpy(out + SC_FRAME_HEADER_LEN, payload, len);
    return (long)(SC_FRAME_HEADER_LEN + len);
}
