/* Client-side input handling: command parsing and the line editor. */
#include <string.h>

#include "command.h"
#include "lineedit.h"
#include "test.h"

static void test_plain_text_is_say(void) {
    sc_command c;
    sc_command_parse("hello there", &c);
    CHECK(c.type == SC_CMD_SAY);
    CHECK(strcmp(c.text, "hello there") == 0);
    sc_command_parse("   ", &c);
    CHECK(c.type == SC_CMD_EMPTY);
}

static void test_private_message_parsing(void) {
    sc_command c;
    sc_command_parse("/msg bob see you at 5", &c);
    CHECK(c.type == SC_CMD_MSG);
    CHECK(strcmp(c.user, "bob") == 0);
    CHECK(strcmp(c.text, "see you at 5") == 0);

    sc_command_parse("/private  alice   hi", &c);
    CHECK(c.type == SC_CMD_MSG);
    CHECK(strcmp(c.user, "alice") == 0);
    CHECK(strcmp(c.text, "hi") == 0);

    sc_command_parse("/w carol x", &c);
    CHECK(c.type == SC_CMD_MSG);

    sc_command_parse("/msg bob", &c);
    CHECK(c.type == SC_CMD_USAGE);
    sc_command_parse("/msg", &c);
    CHECK(c.type == SC_CMD_USAGE);
}

static void test_overlong_recipient_is_detectable(void) {
    sc_command c;
    sc_command_parse("/msg abcdefghijklmnopqrstuvwxyz hi", &c);
    CHECK(c.type == SC_CMD_MSG);
    CHECK(strlen(c.user) == SC_NAME_MAX + 1); /* fails name validation later */
}

static void test_other_commands(void) {
    sc_command c;
    sc_command_parse("/list", &c);
    CHECK(c.type == SC_CMD_LIST);
    sc_command_parse("/who", &c);
    CHECK(c.type == SC_CMD_LIST);
    sc_command_parse("/whois bob", &c);
    CHECK(c.type == SC_CMD_WHOIS && strcmp(c.user, "bob") == 0);
    sc_command_parse("/whois", &c);
    CHECK(c.type == SC_CMD_USAGE);
    sc_command_parse("/fingerprint", &c);
    CHECK(c.type == SC_CMD_FINGERPRINT);
    sc_command_parse("/help", &c);
    CHECK(c.type == SC_CMD_HELP);
    sc_command_parse("/quit", &c);
    CHECK(c.type == SC_CMD_QUIT);
    sc_command_parse("/exit", &c);
    CHECK(c.type == SC_CMD_QUIT);
    sc_command_parse("/listx", &c);
    CHECK(c.type == SC_CMD_UNKNOWN);
    sc_command_parse("/nope", &c);
    CHECK(c.type == SC_CMD_UNKNOWN);
}

static sc_le_event feed_str(sc_lineedit *le, const char *s, char *line) {
    sc_le_event last = SC_LE_NONE;
    for (; *s; s++) {
        last = sc_lineedit_feed(le, (uint8_t)*s, line);
        if (last == SC_LE_LINE || last == SC_LE_TOO_LONG) {
            break;
        }
    }
    return last;
}

static void test_lineedit_basic_and_backspace(void) {
    sc_lineedit le;
    char line[SC_LINE_MAX + 1];
    sc_lineedit_init(&le);
    CHECK(feed_str(&le, "helo\x7flo\r", line) == SC_LE_LINE);
    CHECK(strcmp(line, "hello") == 0);
    CHECK(le.len == 0);
}

static void test_lineedit_utf8_backspace(void) {
    sc_lineedit le;
    char line[SC_LINE_MAX + 1];
    sc_lineedit_init(&le);
    CHECK(feed_str(&le, "a\xc3\xb1\x7f\n", line) == SC_LE_LINE); /* "añ" ⌫ */
    CHECK(strcmp(line, "a") == 0);
}

static void test_lineedit_ignores_escapes_and_controls(void) {
    sc_lineedit le;
    char line[SC_LINE_MAX + 1];
    sc_lineedit_init(&le);
    CHECK(feed_str(&le, "ab\x1b[Dc\x1bOA\td\n", line) == SC_LE_LINE);
    CHECK(strcmp(line, "abcd") == 0);
}

static void test_lineedit_ctrl_keys(void) {
    sc_lineedit le;
    char line[SC_LINE_MAX + 1];
    sc_lineedit_init(&le);
    CHECK(sc_lineedit_feed(&le, 0x04, line) == SC_LE_EOF);
    CHECK(sc_lineedit_feed(&le, 'x', line) == SC_LE_CHANGED);
    CHECK(sc_lineedit_feed(&le, 0x04, line) == SC_LE_NONE);
    CHECK(sc_lineedit_feed(&le, 0x15, line) == SC_LE_CHANGED);
    CHECK(le.len == 0);
    CHECK(sc_lineedit_feed(&le, 0x03, line) == SC_LE_INTERRUPT);
}

static void test_lineedit_overflow_discards_line(void) {
    sc_lineedit le;
    char line[SC_LINE_MAX + 1];
    sc_lineedit_init(&le);
    for (int i = 0; i < SC_LINE_MAX + 50; i++) {
        sc_lineedit_feed(&le, 'a', line);
    }
    CHECK(le.len == SC_LINE_MAX);
    CHECK(sc_lineedit_feed(&le, '\n', line) == SC_LE_TOO_LONG);
    CHECK(line[0] == '\0');
    CHECK(feed_str(&le, "ok\n", line) == SC_LE_LINE);
    CHECK(strcmp(line, "ok") == 0);
}

int main(void) {
    printf("client input\n");
    RUN(test_plain_text_is_say);
    RUN(test_private_message_parsing);
    RUN(test_overlong_recipient_is_detectable);
    RUN(test_other_commands);
    RUN(test_lineedit_basic_and_backspace);
    RUN(test_lineedit_utf8_backspace);
    RUN(test_lineedit_ignores_escapes_and_controls);
    RUN(test_lineedit_ctrl_keys);
    RUN(test_lineedit_overflow_discards_line);
    return TEST_SUMMARY("client input");
}
