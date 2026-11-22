#include "securechat/term.h"

#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <unistd.h>

int sc_color_mode_parse(const char *s, sc_color_mode *mode) {
    if (strcmp(s, "auto") == 0) {
        *mode = SC_COLOR_AUTO;
    } else if (strcmp(s, "always") == 0) {
        *mode = SC_COLOR_ALWAYS;
    } else if (strcmp(s, "never") == 0) {
        *mode = SC_COLOR_NEVER;
    } else {
        return -1;
    }
    return 0;
}

int sc_color_enabled(sc_color_mode mode, FILE *stream) {
    if (mode == SC_COLOR_ALWAYS) {
        return 1;
    }
    if (mode == SC_COLOR_NEVER) {
        return 0;
    }
    const char *no_color = getenv("NO_COLOR");
    if (no_color != NULL && no_color[0] != '\0') {
        return 0;
    }
    return isatty(fileno(stream));
}

void sc_style_init(sc_style *s, int enabled) {
    /* "Nightwatch" palette: 256-color teal accent over muted neutrals. */
    static const char *const users[SC_COLOR_COUNT] = {
        "\x1b[1;38;5;81m",  /* sky */
        "\x1b[1;38;5;214m", /* amber */
        "\x1b[1;38;5;141m", /* violet */
        "\x1b[1;38;5;114m", /* mint */
        "\x1b[1;38;5;210m", /* coral */
        "\x1b[1;38;5;229m", /* sand */
    };
    s->reset = enabled ? "\x1b[0m" : "";
    s->bold = enabled ? "\x1b[1m" : "";
    s->dim = enabled ? "\x1b[38;5;244m" : "";
    s->accent = enabled ? "\x1b[38;5;43m" : "";
    s->ok = enabled ? "\x1b[38;5;78m" : "";
    s->warn = enabled ? "\x1b[38;5;221m" : "";
    s->err = enabled ? "\x1b[1;38;5;203m" : "";
    s->private_msg = enabled ? "\x1b[38;5;177m" : "";
    for (size_t i = 0; i < SC_COLOR_COUNT; i++) {
        s->user[i] = enabled ? users[i] : "";
    }
}

void sc_clock(char *out, size_t cap, int with_seconds) {
    time_t now = time(NULL);
    struct tm tm_now;
    if (localtime_r(&now, &tm_now) == NULL ||
        strftime(out, cap, with_seconds ? "%H:%M:%S" : "%H:%M", &tm_now) ==
            0) {
        if (cap > 0) {
            out[0] = '\0';
        }
    }
}
