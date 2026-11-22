#include "lineedit.h"

#include <string.h>

enum { ESC_NONE = 0, ESC_START, ESC_SEQUENCE };

void sc_lineedit_init(sc_lineedit *le) { memset(le, 0, sizeof(*le)); }

static void reset_line(sc_lineedit *le) {
    le->len = 0;
    le->overflow = 0;
    le->buf[0] = '\0';
}

sc_le_event sc_lineedit_feed(sc_lineedit *le, uint8_t byte, char *line) {
    /* Swallow ANSI escape sequences (arrow keys etc.). */
    if (le->esc_state == ESC_START) {
        le->esc_state = (byte == '[' || byte == 'O') ? ESC_SEQUENCE : ESC_NONE;
        return SC_LE_NONE;
    }
    if (le->esc_state == ESC_SEQUENCE) {
        if (byte >= 0x40 && byte <= 0x7E) {
            le->esc_state = ESC_NONE;
        }
        return SC_LE_NONE;
    }

    switch (byte) {
    case 0x1B:
        le->esc_state = ESC_START;
        return SC_LE_NONE;
    case '\r':
    case '\n': {
        int too_long = le->overflow;
        memcpy(line, le->buf, le->len + 1);
        reset_line(le);
        if (too_long) {
            line[0] = '\0';
            return SC_LE_TOO_LONG;
        }
        return SC_LE_LINE;
    }
    case 0x7F: /* DEL / backspace */
    case 0x08:
        if (le->len == 0) {
            return SC_LE_NONE;
        }
        /* Remove a whole UTF-8 character: continuation bytes first. */
        while (le->len > 0 && (le->buf[le->len - 1] & 0xC0) == 0x80) {
            le->len--;
        }
        if (le->len > 0) {
            le->len--;
        }
        le->buf[le->len] = '\0';
        return SC_LE_CHANGED;
    case 0x15: /* Ctrl-U */
        reset_line(le);
        return SC_LE_CHANGED;
    case 0x04: /* Ctrl-D */
        return le->len == 0 ? SC_LE_EOF : SC_LE_NONE;
    case 0x03: /* Ctrl-C */
        return SC_LE_INTERRUPT;
    default:
        break;
    }
    if (byte < 0x20) {
        return SC_LE_NONE; /* other control characters are ignored */
    }
    if (le->len >= SC_LINE_MAX) {
        le->overflow = 1;
        return SC_LE_NONE;
    }
    le->buf[le->len++] = (char)byte;
    le->buf[le->len] = '\0';
    return SC_LE_CHANGED;
}
