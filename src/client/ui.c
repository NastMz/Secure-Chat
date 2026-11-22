#include "ui.h"

#include <stdarg.h>
#include <stdio.h>
#include <string.h>
#include <sys/ioctl.h>
#include <unistd.h>

#include "securechat/crypto.h"

#define LINE_BUF 2048
#define NAME_COLUMN 10
#define BOX_INNER 58

typedef struct {
    char buf[LINE_BUF];
    size_t len;
} line_builder;

static void lb_add(line_builder *lb, const char *fmt, ...)
    __attribute__((format(printf, 2, 3)));

static void lb_add(line_builder *lb, const char *fmt, ...) {
    if (lb->len >= sizeof(lb->buf) - 1) {
        return;
    }
    va_list ap;
    va_start(ap, fmt);
    int n = vsnprintf(lb->buf + lb->len, sizeof(lb->buf) - lb->len, fmt, ap);
    va_end(ap);
    if (n > 0) {
        size_t room = sizeof(lb->buf) - lb->len - 1;
        lb->len += (size_t)n > room ? room : (size_t)n;
    }
}

/* Display width approximation: one column per UTF-8 code point. */
static size_t utf8_width(const char *s) {
    size_t w = 0;
    for (; *s != '\0'; s++) {
        if (((unsigned char)*s & 0xC0) != 0x80) {
            w++;
        }
    }
    return w;
}

static size_t terminal_columns(void) {
    struct winsize ws;
    if (ioctl(STDOUT_FILENO, TIOCGWINSZ, &ws) == 0 && ws.ws_col > 20) {
        return ws.ws_col;
    }
    return 80;
}

static const char *user_color(const sc_ui *ui, uint8_t color) {
    return ui->st.user[color % SC_COLOR_COUNT];
}

void sc_ui_init(sc_ui *ui, int color, int interactive,
                const sc_lineedit *editor) {
    memset(ui, 0, sizeof(*ui));
    sc_style_init(&ui->st, color);
    ui->interactive = interactive;
    ui->editor = editor;
}

void sc_ui_set_prompt(sc_ui *ui, const char *name, uint8_t color) {
    snprintf(ui->prompt_name, sizeof(ui->prompt_name), "%s", name ? name : "");
    ui->prompt_color = color;
}

void sc_ui_redraw(const sc_ui *ui) {
    if (!ui->interactive) {
        return;
    }
    const sc_style *st = &ui->st;
    size_t prompt_width;
    printf("\r\x1b[K");
    if (ui->prompt_name[0] == '\0') {
        printf("%susername%s %s❯%s ", st->dim, st->reset, st->accent, st->reset);
        prompt_width = 11;
    } else {
        printf("%s%s%s %s❯%s ", user_color(ui, ui->prompt_color),
               ui->prompt_name, st->reset, st->accent, st->reset);
        prompt_width = strlen(ui->prompt_name) + 3;
    }
    /* Show only the tail of a long line so it never wraps. */
    const char *text = ui->editor ? ui->editor->buf : "";
    size_t cols = terminal_columns();
    size_t room = cols > prompt_width + 2 ? cols - prompt_width - 2 : 1;
    size_t width = utf8_width(text);
    while (width > room && *text != '\0') {
        text++;
        while (((unsigned char)*text & 0xC0) == 0x80) {
            text++;
        }
        width--;
    }
    fputs(text, stdout);
    fflush(stdout);
}

void sc_ui_finish(const sc_ui *ui) {
    if (ui->interactive) {
        printf("\r\x1b[K");
        fflush(stdout);
    }
}

static void emit(const sc_ui *ui, const line_builder *lb) {
    if (ui->interactive) {
        printf("\r\x1b[K");
    }
    fputs(lb->buf, stdout);
    fputc('\n', stdout);
    if (ui->interactive) {
        sc_ui_redraw(ui);
    }
    fflush(stdout);
}

static void add_time(const sc_ui *ui, line_builder *lb) {
    char clock[8];
    sc_clock(clock, sizeof(clock), 0);
    lb_add(lb, "%s%s%s  ", ui->st.dim, clock, ui->st.reset);
}

static void add_gutter(line_builder *lb) { lb_add(lb, "       "); }

static void add_name(const sc_ui *ui, line_builder *lb, const char *name,
                     uint8_t color, int pad) {
    lb_add(lb, "%s%s%s", user_color(ui, color), name, ui->st.reset);
    for (size_t w = strlen(name); pad && w < NAME_COLUMN; w++) {
        lb_add(lb, " ");
    }
}

void sc_ui_banner(const sc_ui *ui, const char *server, const char *server_fp,
                  const char *trust, int verified, const char *own_fp) {
    const sc_style *st = &ui->st;
    line_builder lb = {{0}, 0};
    const char *title = "SecureChat " SC_VERSION_STRING;
    const char *tagline = "end-to-end encrypted terminal chat";

    lb_add(&lb, "%s╭", st->accent);
    for (int i = 0; i < BOX_INNER; i++) {
        lb_add(&lb, "─");
    }
    lb_add(&lb, "╮%s", st->reset);
    emit(ui, &lb);

    lb.len = 0;
    size_t used = 2 + utf8_width(title) + 3 + utf8_width(tagline);
    lb_add(&lb, "%s│%s  %s%s%s %s·%s %s%s%s", st->accent, st->reset, st->bold,
           title, st->reset, st->accent, st->reset, st->dim, tagline, st->reset);
    for (size_t w = used; w < BOX_INNER; w++) {
        lb_add(&lb, " ");
    }
    lb_add(&lb, "%s│%s", st->accent, st->reset);
    emit(ui, &lb);

    lb.len = 0;
    lb_add(&lb, "%s╰", st->accent);
    for (int i = 0; i < BOX_INNER; i++) {
        lb_add(&lb, "─");
    }
    lb_add(&lb, "╯%s", st->reset);
    emit(ui, &lb);

    lb.len = 0;
    lb_add(&lb, "  %sserver%s       %s", st->dim, st->reset, server);
    emit(ui, &lb);
    lb.len = 0;
    lb_add(&lb, "  %sidentity%s     %s%s%s", st->dim, st->reset, st->bold,
           server_fp, st->reset);
    emit(ui, &lb);
    lb.len = 0;
    lb_add(&lb, "  %strust%s        %s%s %s%s", st->dim, st->reset,
           verified ? st->ok : st->warn, verified ? "✓" : "!", trust, st->reset);
    emit(ui, &lb);
    if (!verified) {
        lb.len = 0;
        lb_add(&lb, "               %scompare the identity with the server operator%s",
               st->dim, st->reset);
        emit(ui, &lb);
    }
    lb.len = 0;
    lb_add(&lb, "  %syour e2e key%s %s", st->dim, st->reset, own_fp);
    emit(ui, &lb);
    lb.len = 0;
    lb_add(&lb, "  %sType %s/help%s%s for commands.%s", st->dim, st->accent,
           st->reset, st->dim, st->reset);
    emit(ui, &lb);
}

void sc_ui_chat(const sc_ui *ui, const char *name, uint8_t color,
                const char *text, int is_self) {
    line_builder lb = {{0}, 0};
    add_time(ui, &lb);
    add_name(ui, &lb, name, color, 1);
    lb_add(&lb, " %s%s%s %s", is_self ? ui->st.accent : ui->st.dim,
           is_self ? "›" : "│", ui->st.reset, text);
    emit(ui, &lb);
}

void sc_ui_private_in(const sc_ui *ui, const char *from, uint8_t color,
                      const char *text) {
    line_builder lb = {{0}, 0};
    add_time(ui, &lb);
    lb_add(&lb, "%s✉ %s", ui->st.private_msg, ui->st.reset);
    add_name(ui, &lb, from, color, 0);
    lb_add(&lb, "%s → you%s %s│%s %s%s%s", ui->st.private_msg, ui->st.reset,
           ui->st.dim, ui->st.reset, ui->st.private_msg, text, ui->st.reset);
    emit(ui, &lb);
}

void sc_ui_private_out(const sc_ui *ui, const char *to, uint8_t color,
                       const char *text) {
    line_builder lb = {{0}, 0};
    add_time(ui, &lb);
    lb_add(&lb, "%s✉ you → %s", ui->st.private_msg, ui->st.reset);
    add_name(ui, &lb, to, color, 0);
    lb_add(&lb, " %s│%s %s%s%s", ui->st.dim, ui->st.reset, ui->st.private_msg,
           text, ui->st.reset);
    emit(ui, &lb);
}

void sc_ui_joined(const sc_ui *ui, const char *name, uint8_t color) {
    line_builder lb = {{0}, 0};
    add_time(ui, &lb);
    lb_add(&lb, "%s→%s ", ui->st.ok, ui->st.reset);
    add_name(ui, &lb, name, color, 0);
    lb_add(&lb, " %sjoined the room%s", ui->st.dim, ui->st.reset);
    emit(ui, &lb);
}

void sc_ui_left(const sc_ui *ui, const char *name, uint8_t color) {
    line_builder lb = {{0}, 0};
    add_time(ui, &lb);
    lb_add(&lb, "%s←%s ", ui->st.warn, ui->st.reset);
    add_name(ui, &lb, name, color, 0);
    lb_add(&lb, " %sleft the room%s", ui->st.dim, ui->st.reset);
    emit(ui, &lb);
}

void sc_ui_welcome(const sc_ui *ui, const sc_msg *w) {
    line_builder lb = {{0}, 0};
    add_time(ui, &lb);
    lb_add(&lb, "%s★%s Welcome, ", ui->st.accent, ui->st.reset);
    add_name(ui, &lb, w->name, w->color, 0);
    lb_add(&lb, "! %s%zu online:%s ", ui->st.dim, w->roster_len, ui->st.reset);
    for (size_t i = 0; i < w->roster_len; i++) {
        add_name(ui, &lb, w->roster[i].name, w->roster[i].color, 0);
        if (i + 1 < w->roster_len) {
            lb_add(&lb, "%s,%s ", ui->st.dim, ui->st.reset);
        }
    }
    emit(ui, &lb);
}

void sc_ui_roster(const sc_ui *ui, const sc_peer *peers, size_t count,
                  const char *self) {
    line_builder lb = {{0}, 0};
    add_gutter(&lb);
    lb_add(&lb, "%s┌ %zu online %s· e2e key fingerprints%s", ui->st.accent,
           count, ui->st.dim, ui->st.reset);
    emit(ui, &lb);
    for (size_t i = 0; i < count; i++) {
        char fp[SC_FINGERPRINT_LEN];
        sc_fingerprint(peers[i].key, sizeof(peers[i].key), fp);
        lb.len = 0;
        add_gutter(&lb);
        lb_add(&lb, "%s│%s ", ui->st.accent, ui->st.reset);
        add_name(ui, &lb, peers[i].name, peers[i].color, 1);
        lb_add(&lb, " %s%s%s%s", ui->st.dim, fp, ui->st.reset,
               strcmp(peers[i].name, self) == 0 ? "  (you)" : "");
        emit(ui, &lb);
    }
    lb.len = 0;
    add_gutter(&lb);
    lb_add(&lb, "%s└%s", ui->st.accent, ui->st.reset);
    emit(ui, &lb);
}

void sc_ui_whois(const sc_ui *ui, const sc_peer *peer, const char *fp) {
    line_builder lb = {{0}, 0};
    add_gutter(&lb);
    lb_add(&lb, "%s•%s ", ui->st.accent, ui->st.reset);
    add_name(ui, &lb, peer->name, peer->color, 0);
    lb_add(&lb, " %se2e key%s %s%s%s", ui->st.dim, ui->st.reset, ui->st.bold,
           fp, ui->st.reset);
    emit(ui, &lb);
    lb.len = 0;
    add_gutter(&lb);
    lb_add(&lb, "  %sCompare it with them over another channel to rule out a "
                "malicious server.%s",
           ui->st.dim, ui->st.reset);
    emit(ui, &lb);
}

void sc_ui_help(const sc_ui *ui) {
    static const char *const rows[][2] = {
        {"<text>", "send a message to everyone in the room"},
        {"/msg <user> <text>", "end-to-end encrypted private message"},
        {"/list", "who is online, with key fingerprints"},
        {"/whois <user>", "show a user's e2e key fingerprint"},
        {"/fingerprint", "show your key and the server identity"},
        {"/help", "this help"},
        {"/quit", "leave the chat (also Ctrl-D)"},
    };
    line_builder lb = {{0}, 0};
    add_gutter(&lb);
    lb_add(&lb, "%s┌ commands%s", ui->st.accent, ui->st.reset);
    emit(ui, &lb);
    for (size_t i = 0; i < sizeof(rows) / sizeof(rows[0]); i++) {
        lb.len = 0;
        add_gutter(&lb);
        lb_add(&lb, "%s│%s %s%-20s%s %s%s%s", ui->st.accent, ui->st.reset,
               ui->st.bold, rows[i][0], ui->st.reset, ui->st.dim, rows[i][1],
               ui->st.reset);
        emit(ui, &lb);
    }
    lb.len = 0;
    add_gutter(&lb);
    lb_add(&lb, "%s└%s", ui->st.accent, ui->st.reset);
    emit(ui, &lb);
}

static void vline(const sc_ui *ui, int timed, const char *symbol,
                  const char *color, const char *fmt, va_list ap) {
    line_builder lb = {{0}, 0};
    if (timed) {
        add_time(ui, &lb);
    } else {
        add_gutter(&lb);
    }
    lb_add(&lb, "%s%s%s ", color, symbol, ui->st.reset);
    if (lb.len < sizeof(lb.buf) - 1) {
        int n = vsnprintf(lb.buf + lb.len, sizeof(lb.buf) - lb.len, fmt, ap);
        if (n > 0) {
            size_t room = sizeof(lb.buf) - lb.len - 1;
            lb.len += (size_t)n > room ? room : (size_t)n;
        }
    }
    emit(ui, &lb);
}

void sc_ui_info(const sc_ui *ui, const char *fmt, ...) {
    va_list ap;
    va_start(ap, fmt);
    vline(ui, 0, "•", ui->st.accent, fmt, ap);
    va_end(ap);
}

void sc_ui_notice(const sc_ui *ui, const char *fmt, ...) {
    va_list ap;
    va_start(ap, fmt);
    vline(ui, 1, "★", ui->st.warn, fmt, ap);
    va_end(ap);
}

void sc_ui_error(const sc_ui *ui, const char *fmt, ...) {
    va_list ap;
    va_start(ap, fmt);
    vline(ui, 0, "✗", ui->st.err, fmt, ap);
    va_end(ap);
}
