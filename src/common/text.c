#include "securechat/text.h"

#include <string.h>

#include "securechat/protocol.h"

int sc_name_is_valid(const char *name) {
    size_t len = strnlen(name, SC_NAME_MAX + 1);
    if (len == 0 || len > SC_NAME_MAX) {
        return 0;
    }
    for (size_t i = 0; i < len; i++) {
        char c = name[i];
        int ok = (c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z') ||
                 (c >= '0' && c <= '9') || c == '_' || c == '-';
        if (!ok) {
            return 0;
        }
    }
    return 1;
}

/* Decode one UTF-8 sequence at text[*i]; returns the code point or -1. */
static long next_code_point(const uint8_t *text, size_t len, size_t *i) {
    uint8_t b0 = text[*i];
    size_t extra;
    long cp;
    long min;
    if (b0 < 0x80) {
        (*i)++;
        return b0;
    } else if ((b0 & 0xE0) == 0xC0) {
        extra = 1;
        cp = b0 & 0x1F;
        min = 0x80;
    } else if ((b0 & 0xF0) == 0xE0) {
        extra = 2;
        cp = b0 & 0x0F;
        min = 0x800;
    } else if ((b0 & 0xF8) == 0xF0) {
        extra = 3;
        cp = b0 & 0x07;
        min = 0x10000;
    } else {
        return -1;
    }
    if (extra >= len - *i) { /* sequence truncated at end of buffer */
        return -1;
    }
    for (size_t k = 1; k <= extra; k++) {
        uint8_t b = text[*i + k];
        if ((b & 0xC0) != 0x80) {
            return -1;
        }
        cp = (cp << 6) | (b & 0x3F);
    }
    if (cp < min || cp > 0x10FFFF || (cp >= 0xD800 && cp <= 0xDFFF)) {
        return -1;
    }
    *i += extra + 1;
    return cp;
}

int sc_text_is_safe(const uint8_t *text, size_t len) {
    if (len > SC_TEXT_MAX) {
        return 0;
    }
    size_t i = 0;
    while (i < len) {
        long cp = next_code_point(text, len, &i);
        if (cp < 0) {
            return 0;
        }
        if (cp < 0x20 || cp == 0x7F || (cp >= 0x80 && cp <= 0x9F)) {
            return 0; /* C0, DEL and C1 controls: escape-sequence injection */
        }
    }
    return 1;
}

size_t sc_chomp(char *line) {
    size_t len = strlen(line);
    while (len > 0 && (line[len - 1] == '\n' || line[len - 1] == '\r')) {
        line[--len] = '\0';
    }
    return len;
}
