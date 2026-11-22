/*
 * Minimal byte-driven line editor. Used for raw-mode terminals (so incoming
 * messages can be printed without destroying the line being typed) and for
 * piped input alike.
 */
#ifndef SECURECHAT_CLIENT_LINEEDIT_H
#define SECURECHAT_CLIENT_LINEEDIT_H

#include <stddef.h>
#include <stdint.h>

#include "securechat/protocol.h"

#define SC_LINE_MAX (SC_TEXT_MAX + 64)

typedef enum {
    SC_LE_NONE,      /* nothing visible changed */
    SC_LE_CHANGED,   /* buffer edited: redraw */
    SC_LE_LINE,      /* a complete line was copied to the output */
    SC_LE_TOO_LONG,  /* a line ended but exceeded SC_LINE_MAX: discarded */
    SC_LE_EOF,       /* Ctrl-D on an empty line */
    SC_LE_INTERRUPT  /* Ctrl-C */
} sc_le_event;

typedef struct {
    char buf[SC_LINE_MAX + 1];
    size_t len;
    int esc_state;
    int overflow;
} sc_lineedit;

void sc_lineedit_init(sc_lineedit *le);

/* Feed one input byte. On SC_LE_LINE, `line` (SC_LINE_MAX + 1) is filled. */
sc_le_event sc_lineedit_feed(sc_lineedit *le, uint8_t byte, char *line);

#endif
