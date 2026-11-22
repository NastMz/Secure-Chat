#include <string.h>

#include "securechat/protocol.h"
#include "securechat/text.h"
#include "test.h"

static int safe(const char *s) {
    return sc_text_is_safe((const uint8_t *)s, strlen(s));
}

static void test_names(void) {
    CHECK(sc_name_is_valid("alice"));
    CHECK(sc_name_is_valid("Bob_99-x"));
    CHECK(sc_name_is_valid("a"));
    CHECK(sc_name_is_valid("abcdefghijklmnop")); /* 16 */
    CHECK(!sc_name_is_valid(""));
    CHECK(!sc_name_is_valid("abcdefghijklmnopq")); /* 17 */
    CHECK(!sc_name_is_valid("with space"));
    CHECK(!sc_name_is_valid("tab\t"));
    CHECK(!sc_name_is_valid("ñandú"));
    CHECK(!sc_name_is_valid("evil\x1b[31m"));
    CHECK(!sc_name_is_valid("dot.name"));
}

static void test_safe_text_accepts_printable_utf8(void) {
    CHECK(safe(""));
    CHECK(safe("hello world"));
    CHECK(safe("¿Qué tal? ñandú — ✓ 漢字 😀"));
}

static void test_safe_text_rejects_controls(void) {
    CHECK(!safe("line\nbreak"));
    CHECK(!safe("tab\there"));
    CHECK(!safe("\x1b[2J clear screen"));
    CHECK(!safe("del\x7f"));
    CHECK(!safe("bell\a"));
    CHECK(!safe("c1 csi \xc2\x9b" "31m")); /* U+009B CSI */
    CHECK(!safe("c1 \xc2\x85"));          /* U+0085 NEL */
}

static void test_safe_text_rejects_malformed_utf8(void) {
    CHECK(!safe("\x80"));             /* lone continuation */
    CHECK(!safe("\xc3"));             /* truncated */
    CHECK(!safe("ab\xe2\x82"));       /* truncated 3-byte */
    CHECK(!safe("\xc0\xaf"));         /* overlong '/' */
    CHECK(!safe("\xe0\x80\xaf"));     /* overlong */
    CHECK(!safe("\xed\xa0\x80"));     /* surrogate U+D800 */
    CHECK(!safe("\xf4\x90\x80\x80")); /* > U+10FFFF */
    CHECK(!safe("\xff"));
    const uint8_t nul[] = {'a', 0, 'b'};
    CHECK(!sc_text_is_safe(nul, sizeof(nul)));
}

static void test_safe_text_length_limit(void) {
    static uint8_t buf[SC_TEXT_MAX + 1];
    memset(buf, 'a', sizeof(buf));
    CHECK(sc_text_is_safe(buf, SC_TEXT_MAX));
    CHECK(!sc_text_is_safe(buf, SC_TEXT_MAX + 1));
}

static void test_chomp(void) {
    char a[] = "text\r\n";
    char b[] = "plain";
    char c[] = "\n";
    CHECK(sc_chomp(a) == 4 && strcmp(a, "text") == 0);
    CHECK(sc_chomp(b) == 5);
    CHECK(sc_chomp(c) == 0 && c[0] == '\0');
}

int main(void) {
    printf("text\n");
    RUN(test_names);
    RUN(test_safe_text_accepts_printable_utf8);
    RUN(test_safe_text_rejects_controls);
    RUN(test_safe_text_rejects_malformed_utf8);
    RUN(test_safe_text_length_limit);
    RUN(test_chomp);
    return TEST_SUMMARY("text");
}
