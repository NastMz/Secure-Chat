/*
 * Terminal styling shared by client and server: ANSI palette and color mode.
 */
#ifndef SECURECHAT_TERM_H
#define SECURECHAT_TERM_H

#include <stddef.h>
#include <stdio.h>

#include "securechat/protocol.h"

typedef enum { SC_COLOR_AUTO, SC_COLOR_ALWAYS, SC_COLOR_NEVER } sc_color_mode;

/* Parse "auto" | "always" | "never". Returns 0 or -1. */
int sc_color_mode_parse(const char *s, sc_color_mode *mode);

/* Resolve AUTO against isatty() and the NO_COLOR convention. */
int sc_color_enabled(sc_color_mode mode, FILE *stream);

/* Style table; every entry is "" when colors are disabled. */
typedef struct {
    const char *reset, *bold, *dim, *accent, *ok, *warn, *err, *private_msg;
    const char *user[SC_COLOR_COUNT];
} sc_style;

void sc_style_init(sc_style *style, int enabled);

/* Local wall-clock time as "HH:MM" or "HH:MM:SS". */
void sc_clock(char *out, size_t cap, int with_seconds);

#endif
