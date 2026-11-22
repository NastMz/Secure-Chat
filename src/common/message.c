#include "securechat/message.h"

#include <string.h>

#include "securechat/text.h"

/* ---- bounded writer ---------------------------------------------------- */

typedef struct {
    uint8_t *buf;
    size_t cap;
    size_t len;
    int err;
} writer;

static void w_bytes(writer *w, const void *data, size_t n) {
    if (w->err || n > w->cap - w->len) {
        w->err = 1;
        return;
    }
    memcpy(w->buf + w->len, data, n);
    w->len += n;
}

static void w_u8(writer *w, uint8_t v) { w_bytes(w, &v, 1); }

static void w_u16(writer *w, size_t v) {
    if (v > 0xFFFF) {
        w->err = 1;
        return;
    }
    uint8_t b[2] = {(uint8_t)(v >> 8), (uint8_t)v};
    w_bytes(w, b, 2);
}

static void w_blob(writer *w, const void *data, size_t n) {
    w_u16(w, n);
    w_bytes(w, data, n);
}

static void w_str(writer *w, const char *s) { w_blob(w, s, strlen(s)); }

/* ---- bounded reader ---------------------------------------------------- */

typedef struct {
    const uint8_t *buf;
    size_t len;
    size_t pos;
    int err;
} reader;

static const uint8_t *r_take(reader *r, size_t n) {
    if (r->err || n > r->len - r->pos) {
        r->err = 1;
        return NULL;
    }
    const uint8_t *p = r->buf + r->pos;
    r->pos += n;
    return p;
}

static uint8_t r_u8(reader *r) {
    const uint8_t *p = r_take(r, 1);
    return p ? p[0] : 0;
}

static size_t r_u16(reader *r) {
    const uint8_t *p = r_take(r, 2);
    return p ? ((size_t)p[0] << 8) | p[1] : 0;
}

static void r_fixed(reader *r, uint8_t *out, size_t n) {
    const uint8_t *p = r_take(r, n);
    if (p) {
        memcpy(out, p, n);
    }
}

/* Length-prefixed blob of at most `max` bytes. */
static size_t r_blob(reader *r, uint8_t *out, size_t max) {
    size_t n = r_u16(r);
    if (n > max) {
        r->err = 1;
        return 0;
    }
    const uint8_t *p = r_take(r, n);
    if (p && n > 0) {
        memcpy(out, p, n);
    }
    return p ? n : 0;
}

static void r_name(reader *r, char out[SC_NAME_MAX + 1]) {
    size_t n = r_blob(r, (uint8_t *)out, SC_NAME_MAX);
    out[n] = '\0';
    if (!r->err && !sc_name_is_valid(out)) {
        r->err = 1;
    }
}

static void r_text(reader *r, char out[SC_TEXT_MAX + 1]) {
    size_t n = r_blob(r, (uint8_t *)out, SC_TEXT_MAX);
    out[n] = '\0';
    if (!r->err && !sc_text_is_safe((const uint8_t *)out, n)) {
        r->err = 1;
    }
}

static void r_color(reader *r, uint8_t *color) {
    *color = r_u8(r);
    if (*color >= SC_COLOR_COUNT) {
        r->err = 1;
    }
}

/* ---- public API -------------------------------------------------------- */

void sc_msg_init(sc_msg *msg, sc_msg_type type) {
    memset(msg, 0, sizeof(*msg));
    msg->type = (uint8_t)type;
}

static int fields_are_valid(const sc_msg *m) {
    switch (m->type) {
    case SC_MSG_JOIN:
    case SC_MSG_JOINED:
    case SC_MSG_LEFT:
    case SC_MSG_WELCOME:
        return sc_name_is_valid(m->name) && m->color < SC_COLOR_COUNT &&
               m->roster_len <= SC_MAX_CLIENTS;
    case SC_MSG_CHAT:
        return sc_name_is_valid(m->name) && m->color < SC_COLOR_COUNT &&
               sc_text_is_safe((const uint8_t *)m->text, strlen(m->text));
    case SC_MSG_SAY:
    case SC_MSG_ERROR:
    case SC_MSG_NOTICE:
        return sc_text_is_safe((const uint8_t *)m->text, strlen(m->text));
    case SC_MSG_PRIVATE:
    case SC_MSG_PRIVATE_FROM:
        return sc_name_is_valid(m->name) && m->color < SC_COLOR_COUNT &&
               m->blob_len > SC_E2E_OVERHEAD && m->blob_len <= SC_E2E_MAX;
    case SC_MSG_ROSTER:
        return m->roster_len <= SC_MAX_CLIENTS;
    case SC_MSG_LIST:
    case SC_MSG_BYE:
        return 1;
    default:
        return 0;
    }
}

static void write_roster(writer *w, const sc_msg *m) {
    w_u8(w, (uint8_t)m->roster_len);
    for (size_t i = 0; i < m->roster_len; i++) {
        w_str(w, m->roster[i].name);
        w_u8(w, m->roster[i].color);
        w_bytes(w, m->roster[i].key, sizeof(m->roster[i].key));
    }
}

static void read_roster(reader *r, sc_msg *m) {
    m->roster_len = r_u8(r);
    if (m->roster_len > SC_MAX_CLIENTS) {
        r->err = 1;
        return;
    }
    for (size_t i = 0; i < m->roster_len && !r->err; i++) {
        r_name(r, m->roster[i].name);
        r_color(r, &m->roster[i].color);
        r_fixed(r, m->roster[i].key, sizeof(m->roster[i].key));
    }
}

int sc_msg_encode(const sc_msg *m, uint8_t *out, size_t cap, size_t *out_len) {
    if (!fields_are_valid(m)) {
        return -1;
    }
    writer w = {out, cap, 0, 0};
    w_u8(&w, m->type);
    switch (m->type) {
    case SC_MSG_JOIN:
        w_str(&w, m->name);
        w_bytes(&w, m->key, sizeof(m->key));
        break;
    case SC_MSG_SAY:
    case SC_MSG_ERROR:
    case SC_MSG_NOTICE:
        w_str(&w, m->text);
        break;
    case SC_MSG_PRIVATE:
        w_str(&w, m->name);
        w_blob(&w, m->blob, m->blob_len);
        break;
    case SC_MSG_WELCOME:
        w_str(&w, m->name);
        w_u8(&w, m->color);
        write_roster(&w, m);
        break;
    case SC_MSG_JOINED:
        w_str(&w, m->name);
        w_u8(&w, m->color);
        w_bytes(&w, m->key, sizeof(m->key));
        break;
    case SC_MSG_LEFT:
        w_str(&w, m->name);
        w_u8(&w, m->color);
        break;
    case SC_MSG_CHAT:
        w_str(&w, m->name);
        w_u8(&w, m->color);
        w_str(&w, m->text);
        break;
    case SC_MSG_PRIVATE_FROM:
        w_str(&w, m->name);
        w_u8(&w, m->color);
        w_blob(&w, m->blob, m->blob_len);
        break;
    case SC_MSG_ROSTER:
        write_roster(&w, m);
        break;
    default: /* LIST, BYE: no fields */
        break;
    }
    if (w.err || w.len > SC_PAYLOAD_MAX) {
        return -1;
    }
    *out_len = w.len;
    return 0;
}

int sc_msg_decode(const uint8_t *in, size_t len, sc_msg *m) {
    if (len == 0 || len > SC_PAYLOAD_MAX) {
        return -1;
    }
    reader r = {in, len, 0, 0};
    sc_msg_init(m, (sc_msg_type)r_u8(&r));
    switch (m->type) {
    case SC_MSG_JOIN:
        r_name(&r, m->name);
        r_fixed(&r, m->key, sizeof(m->key));
        break;
    case SC_MSG_SAY:
    case SC_MSG_ERROR:
    case SC_MSG_NOTICE:
        r_text(&r, m->text);
        break;
    case SC_MSG_PRIVATE:
        r_name(&r, m->name);
        m->blob_len = r_blob(&r, m->blob, sizeof(m->blob));
        break;
    case SC_MSG_WELCOME:
        r_name(&r, m->name);
        r_color(&r, &m->color);
        read_roster(&r, m);
        break;
    case SC_MSG_JOINED:
        r_name(&r, m->name);
        r_color(&r, &m->color);
        r_fixed(&r, m->key, sizeof(m->key));
        break;
    case SC_MSG_LEFT:
        r_name(&r, m->name);
        r_color(&r, &m->color);
        break;
    case SC_MSG_CHAT:
        r_name(&r, m->name);
        r_color(&r, &m->color);
        r_text(&r, m->text);
        break;
    case SC_MSG_PRIVATE_FROM:
        r_name(&r, m->name);
        r_color(&r, &m->color);
        m->blob_len = r_blob(&r, m->blob, sizeof(m->blob));
        break;
    case SC_MSG_ROSTER:
        read_roster(&r, m);
        break;
    case SC_MSG_LIST:
    case SC_MSG_BYE:
        break;
    default:
        return -1;
    }
    /* Reject trailing bytes and re-check semantic constraints. */
    if (r.err || r.pos != r.len || !fields_are_valid(m)) {
        return -1;
    }
    return 0;
}
