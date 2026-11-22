#include <string.h>

#include "securechat/frame.h"
#include "test.h"

static void feed(sc_frame_reader *r, const uint8_t *data, size_t len) {
    size_t avail = 0;
    uint8_t *space = sc_frame_reader_space(r, &avail);
    if (len > avail) {
        len = avail;
    }
    memcpy(space, data, len);
    sc_frame_reader_commit(r, len);
}

static void test_encode_writes_big_endian_length(void) {
    uint8_t out[16];
    long n = sc_frame_encode(out, sizeof(out), (const uint8_t *)"abc", 3);
    CHECK(n == 7);
    CHECK(out[0] == 0 && out[1] == 0 && out[2] == 0 && out[3] == 3);
    CHECK(memcmp(out + 4, "abc", 3) == 0);
}

static void test_encode_rejects_empty_oversized_and_small_buffer(void) {
    static uint8_t big[SC_FRAME_MAX + 1];
    static uint8_t out[SC_FRAME_MAX + 16];
    CHECK(sc_frame_encode(out, sizeof(out), big, 0) == -1);
    CHECK(sc_frame_encode(out, sizeof(out), big, SC_FRAME_MAX + 1) == -1);
    CHECK(sc_frame_encode(out, 5, big, 2) == -1);
    CHECK(sc_frame_encode(out, sizeof(out), big, SC_FRAME_MAX) ==
          (long)(SC_FRAME_MAX + 4));
}

static void test_roundtrip_byte_by_byte(void) {
    uint8_t wire[64];
    long n1 = sc_frame_encode(wire, sizeof(wire), (const uint8_t *)"hello", 5);
    long n2 = sc_frame_encode(wire + n1, sizeof(wire) - (size_t)n1,
                              (const uint8_t *)"world!", 6);
    CHECK(n1 > 0 && n2 > 0);

    sc_frame_reader r;
    sc_frame_reader_init(&r);
    uint8_t out[SC_FRAME_MAX];
    size_t len = 0;
    int frames = 0;
    for (long i = 0; i < n1 + n2; i++) {
        feed(&r, wire + i, 1);
        sc_frame_status st = sc_frame_reader_next(&r, out, sizeof(out), &len);
        CHECK(st != SC_FRAME_INVALID);
        if (st == SC_FRAME_READY) {
            frames++;
            if (frames == 1) {
                CHECK(len == 5 && memcmp(out, "hello", 5) == 0);
            } else {
                CHECK(len == 6 && memcmp(out, "world!", 6) == 0);
            }
        }
    }
    CHECK(frames == 2);
    CHECK(r.len == 0);
}

static void test_two_frames_in_one_read(void) {
    uint8_t wire[32];
    long n1 = sc_frame_encode(wire, sizeof(wire), (const uint8_t *)"a", 1);
    long n2 = sc_frame_encode(wire + n1, sizeof(wire) - (size_t)n1,
                              (const uint8_t *)"bc", 2);
    sc_frame_reader r;
    sc_frame_reader_init(&r);
    feed(&r, wire, (size_t)(n1 + n2));
    uint8_t out[8];
    size_t len = 0;
    CHECK(sc_frame_reader_next(&r, out, sizeof(out), &len) == SC_FRAME_READY);
    CHECK(len == 1 && out[0] == 'a');
    CHECK(sc_frame_reader_next(&r, out, sizeof(out), &len) == SC_FRAME_READY);
    CHECK(len == 2 && memcmp(out, "bc", 2) == 0);
    CHECK(sc_frame_reader_next(&r, out, sizeof(out), &len) == SC_FRAME_NEED_MORE);
}

static void test_rejects_zero_and_oversized_length_prefix(void) {
    uint8_t out[SC_FRAME_MAX];
    size_t len = 0;
    sc_frame_reader r;

    const uint8_t zero[4] = {0, 0, 0, 0};
    sc_frame_reader_init(&r);
    feed(&r, zero, 4);
    CHECK(sc_frame_reader_next(&r, out, sizeof(out), &len) == SC_FRAME_INVALID);

    const uint8_t huge[4] = {0x7F, 0xFF, 0xFF, 0xFF};
    sc_frame_reader_init(&r);
    feed(&r, huge, 4);
    CHECK(sc_frame_reader_next(&r, out, sizeof(out), &len) == SC_FRAME_INVALID);

    uint32_t just_over = SC_FRAME_MAX + 1;
    const uint8_t over[4] = {(uint8_t)(just_over >> 24), (uint8_t)(just_over >> 16),
                             (uint8_t)(just_over >> 8), (uint8_t)just_over};
    sc_frame_reader_init(&r);
    feed(&r, over, 4);
    CHECK(sc_frame_reader_next(&r, out, sizeof(out), &len) == SC_FRAME_INVALID);
}

static void test_rejects_frame_larger_than_caller_buffer(void) {
    uint8_t wire[32];
    long n = sc_frame_encode(wire, sizeof(wire), (const uint8_t *)"0123456789", 10);
    sc_frame_reader r;
    sc_frame_reader_init(&r);
    feed(&r, wire, (size_t)n);
    uint8_t small[4];
    size_t len = 0;
    CHECK(sc_frame_reader_next(&r, small, sizeof(small), &len) == SC_FRAME_INVALID);
}

static void test_reader_space_is_bounded(void) {
    sc_frame_reader r;
    sc_frame_reader_init(&r);
    size_t avail = 0;
    sc_frame_reader_space(&r, &avail);
    CHECK(avail == SC_FRAME_HEADER_LEN + SC_FRAME_MAX);
    sc_frame_reader_commit(&r, avail + 100); /* over-commit is clamped */
    sc_frame_reader_space(&r, &avail);
    CHECK(avail == 0);
    CHECK(r.len == SC_FRAME_HEADER_LEN + SC_FRAME_MAX);
}

int main(void) {
    printf("frame\n");
    RUN(test_encode_writes_big_endian_length);
    RUN(test_encode_rejects_empty_oversized_and_small_buffer);
    RUN(test_roundtrip_byte_by_byte);
    RUN(test_two_frames_in_one_read);
    RUN(test_rejects_zero_and_oversized_length_prefix);
    RUN(test_rejects_frame_larger_than_caller_buffer);
    RUN(test_reader_space_is_bounded);
    return TEST_SUMMARY("frame");
}
