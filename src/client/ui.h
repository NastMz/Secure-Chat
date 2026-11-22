/*
 * Client terminal presentation: timestamps, per-user colors, notices and an
 * input prompt that is redrawn below every incoming line.
 */
#ifndef SECURECHAT_CLIENT_UI_H
#define SECURECHAT_CLIENT_UI_H

#include <stddef.h>
#include <stdint.h>

#include "lineedit.h"
#include "securechat/message.h"
#include "securechat/term.h"

typedef struct {
    sc_style st;
    int interactive; /* stdin and stdout are a terminal in raw mode */
    const sc_lineedit *editor;
    char prompt_name[SC_NAME_MAX + 1];
    uint8_t prompt_color;
} sc_ui;

void sc_ui_init(sc_ui *ui, int color, int interactive,
                const sc_lineedit *editor);

/* Use `name` in the prompt; NULL shows the username prompt. */
void sc_ui_set_prompt(sc_ui *ui, const char *name, uint8_t color);

/* Redraw the prompt and the line being edited (interactive mode only). */
void sc_ui_redraw(const sc_ui *ui);

/* Leave the prompt line before exiting. */
void sc_ui_finish(const sc_ui *ui);

/* `verified` is 0 for an unverified first (TOFU) contact. */
void sc_ui_banner(const sc_ui *ui, const char *server, const char *server_fp,
                  const char *trust, int verified, const char *own_fp);
void sc_ui_chat(const sc_ui *ui, const char *name, uint8_t color,
                const char *text, int is_self);
void sc_ui_private_in(const sc_ui *ui, const char *from, uint8_t color,
                      const char *text);
void sc_ui_private_out(const sc_ui *ui, const char *to, uint8_t color,
                       const char *text);
void sc_ui_joined(const sc_ui *ui, const char *name, uint8_t color);
void sc_ui_left(const sc_ui *ui, const char *name, uint8_t color);
void sc_ui_welcome(const sc_ui *ui, const sc_msg *welcome);
void sc_ui_roster(const sc_ui *ui, const sc_peer *peers, size_t count,
                  const char *self);
void sc_ui_whois(const sc_ui *ui, const sc_peer *peer, const char *fp);
void sc_ui_help(const sc_ui *ui);

void sc_ui_info(const sc_ui *ui, const char *fmt, ...)
    __attribute__((format(printf, 2, 3)));
void sc_ui_notice(const sc_ui *ui, const char *fmt, ...)
    __attribute__((format(printf, 2, 3)));
void sc_ui_error(const sc_ui *ui, const char *fmt, ...)
    __attribute__((format(printf, 2, 3)));

#endif
