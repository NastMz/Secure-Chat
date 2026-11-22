#include <string.h>

#include "securechat/message.h"
#include "test.h"

static int roundtrip(const sc_msg *in, sc_msg *out) {
    uint8_t buf[SC_PAYLOAD_MAX];
    size_t len = 0;
    if (sc_msg_encode(in, buf, sizeof(buf), &len) != 0) {
        return -1;
    }
    return sc_msg_decode(buf, len, out);
}

static void test_join_roundtrip(void) {
    sc_msg in;
    sc_msg out;
    sc_msg_init(&in, SC_MSG_JOIN);
    strcpy(in.name, "alice");
    memset(in.key, 0xAB, sizeof(in.key));
    CHECK(roundtrip(&in, &out) == 0);
    CHECK(out.type == SC_MSG_JOIN);
    CHECK(strcmp(out.name, "alice") == 0);
    CHECK(memcmp(out.key, in.key, sizeof(in.key)) == 0);
}

static void test_chat_roundtrip_with_utf8(void) {
    sc_msg in;
    sc_msg out;
    sc_msg_init(&in, SC_MSG_CHAT);
    strcpy(in.name, "bob_42");
    in.color = 3;
    strcpy(in.text, "hola, ¿qué tal? ✓");
    CHECK(roundtrip(&in, &out) == 0);
    CHECK(out.color == 3);
    CHECK(strcmp(out.text, in.text) == 0);
}

static void test_private_roundtrip(void) {
    sc_msg in;
    sc_msg out;
    sc_msg_init(&in, SC_MSG_PRIVATE_FROM);
    strcpy(in.name, "carol");
    in.blob_len = SC_E2E_OVERHEAD + 5;
    for (size_t i = 0; i < in.blob_len; i++) {
        in.blob[i] = (uint8_t)i;
    }
    CHECK(roundtrip(&in, &out) == 0);
    CHECK(out.blob_len == in.blob_len);
    CHECK(memcmp(out.blob, in.blob, in.blob_len) == 0);
}

static void test_full_roster_roundtrip(void) {
    sc_msg in;
    sc_msg out;
    sc_msg_init(&in, SC_MSG_WELCOME);
    strcpy(in.name, "user0");
    in.roster_len = SC_MAX_CLIENTS;
    for (size_t i = 0; i < SC_MAX_CLIENTS; i++) {
        snprintf(in.roster[i].name, sizeof(in.roster[i].name),
                 "user-with-name%02zu", i);
        in.roster[i].color = (uint8_t)(i % SC_COLOR_COUNT);
        memset(in.roster[i].key, (int)i, sizeof(in.roster[i].key));
    }
    CHECK(roundtrip(&in, &out) == 0);
    CHECK(out.roster_len == SC_MAX_CLIENTS);
    CHECK(strcmp(out.roster[15].name, "user-with-name15") == 0);
    CHECK(out.roster[7].key[0] == 7);
}

static void test_encode_rejects_invalid_fields(void) {
    uint8_t buf[SC_PAYLOAD_MAX];
    size_t len = 0;
    sc_msg m;

    sc_msg_init(&m, SC_MSG_JOIN);
    strcpy(m.name, "has space");
    CHECK(sc_msg_encode(&m, buf, sizeof(buf), &len) != 0);

    sc_msg_init(&m, SC_MSG_SAY);
    strcpy(m.text, "bell\a");
    CHECK(sc_msg_encode(&m, buf, sizeof(buf), &len) != 0);

    sc_msg_init(&m, SC_MSG_PRIVATE);
    strcpy(m.name, "bob");
    m.blob_len = SC_E2E_MAX + 1;
    CHECK(sc_msg_encode(&m, buf, sizeof(buf), &len) != 0);

    sc_msg_init(&m, SC_MSG_CHAT);
    strcpy(m.name, "bob");
    m.color = SC_COLOR_COUNT;
    CHECK(sc_msg_encode(&m, buf, sizeof(buf), &len) != 0);

    sc_msg_init(&m, SC_MSG_SAY);
    strcpy(m.text, "fits");
    CHECK(sc_msg_encode(&m, buf, 3, &len) != 0);

    sc_msg_init(&m, (sc_msg_type)0x7F);
    CHECK(sc_msg_encode(&m, buf, sizeof(buf), &len) != 0);
}

static void test_decode_rejects_malformed_input(void) {
    sc_msg m;
    /* Unknown type. */
    const uint8_t unknown[] = {0x7F};
    CHECK(sc_msg_decode(unknown, sizeof(unknown), &m) != 0);
    /* Empty buffer. */
    CHECK(sc_msg_decode(unknown, 0, &m) != 0);
    /* SAY with a length prefix pointing past the end. */
    const uint8_t truncated[] = {SC_MSG_SAY, 0x00, 0x10, 'h', 'i'};
    CHECK(sc_msg_decode(truncated, sizeof(truncated), &m) != 0);
    /* SAY with trailing garbage. */
    const uint8_t trailing[] = {SC_MSG_SAY, 0x00, 0x02, 'h', 'i', 'X'};
    CHECK(sc_msg_decode(trailing, sizeof(trailing), &m) != 0);
    /* SAY containing an ANSI escape sequence. */
    const uint8_t escape[] = {SC_MSG_SAY, 0x00, 0x04, 0x1B, '[', '2', 'J'};
    CHECK(sc_msg_decode(escape, sizeof(escape), &m) != 0);
    /* JOIN with an empty name. */
    uint8_t join[1 + 2 + 32] = {SC_MSG_JOIN, 0x00, 0x00};
    CHECK(sc_msg_decode(join, sizeof(join), &m) != 0);
    /* LIST with unexpected payload. */
    const uint8_t list[] = {SC_MSG_LIST, 0x00};
    CHECK(sc_msg_decode(list, sizeof(list), &m) != 0);
    /* ROSTER claiming more entries than allowed. */
    const uint8_t roster[] = {SC_MSG_ROSTER, SC_MAX_CLIENTS + 1};
    CHECK(sc_msg_decode(roster, sizeof(roster), &m) != 0);
    /* Valid SAY for contrast. */
    const uint8_t ok[] = {SC_MSG_SAY, 0x00, 0x02, 'h', 'i'};
    CHECK(sc_msg_decode(ok, sizeof(ok), &m) == 0);
    CHECK(strcmp(m.text, "hi") == 0);
}

static void test_decode_rejects_oversized_text(void) {
    static uint8_t buf[3 + SC_TEXT_MAX + 1];
    sc_msg m;
    buf[0] = SC_MSG_SAY;
    buf[1] = (uint8_t)((SC_TEXT_MAX + 1) >> 8);
    buf[2] = (uint8_t)(SC_TEXT_MAX + 1);
    memset(buf + 3, 'a', SC_TEXT_MAX + 1);
    CHECK(sc_msg_decode(buf, sizeof(buf), &m) != 0);
    buf[1] = (uint8_t)(SC_TEXT_MAX >> 8);
    buf[2] = (uint8_t)SC_TEXT_MAX;
    CHECK(sc_msg_decode(buf, sizeof(buf) - 1, &m) == 0);
    CHECK(strlen(m.text) == SC_TEXT_MAX);
}

static void test_decode_fuzz_never_crashes(void) {
    /* Random inputs must be rejected or decoded without touching memory
     * outside the buffers (checked by the sanitizer build). */
    uint8_t buf[256];
    sc_msg m;
    int accepted = 0;
    for (int i = 0; i < 20000; i++) {
        size_t len = 1 + randombytes_uniform(sizeof(buf));
        randombytes_buf(buf, len);
        buf[0] = (uint8_t)(i % 2 ? buf[0] : (0x41 + i % 8));
        if (sc_msg_decode(buf, len, &m) == 0) {
            accepted++;
        }
    }
    CHECK(accepted >= 0);
}

int main(void) {
    if (sodium_init() < 0) {
        return 1;
    }
    printf("message\n");
    RUN(test_join_roundtrip);
    RUN(test_chat_roundtrip_with_utf8);
    RUN(test_private_roundtrip);
    RUN(test_full_roster_roundtrip);
    RUN(test_encode_rejects_invalid_fields);
    RUN(test_decode_rejects_malformed_input);
    RUN(test_decode_rejects_oversized_text);
    RUN(test_decode_fuzz_never_crashes);
    return TEST_SUMMARY("message");
}
