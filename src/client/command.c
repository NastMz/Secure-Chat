#include "command.h"

#include <string.h>

static const char *skip_spaces(const char *p) {
    while (*p == ' ') {
        p++;
    }
    return p;
}

/* Copy the next space-delimited word into out (truncated to cap - 1). */
static const char *take_word(const char *p, char *out, size_t cap) {
    size_t n = 0;
    p = skip_spaces(p);
    while (*p != '\0' && *p != ' ') {
        if (n + 1 < cap) {
            out[n++] = *p;
        }
        p++;
    }
    out[n] = '\0';
    return p;
}

static int word_is(const char *line, size_t len, const char *name) {
    return strlen(name) == len && strncmp(line, name, len) == 0;
}

void sc_command_parse(const char *line, sc_command *out) {
    memset(out, 0, sizeof(*out));
    out->word = line;
    const char *start = skip_spaces(line);
    if (*start == '\0') {
        out->type = SC_CMD_EMPTY;
        return;
    }
    if (line[0] != '/') {
        out->type = SC_CMD_SAY;
        out->text = line;
        return;
    }

    size_t len = strcspn(line, " ");
    const char *rest = line + len;
    if (word_is(line, len, "/msg") || word_is(line, len, "/private") ||
        word_is(line, len, "/w")) {
        rest = take_word(rest, out->user, sizeof(out->user));
        rest = skip_spaces(rest);
        out->type = (out->user[0] == '\0' || *rest == '\0') ? SC_CMD_USAGE
                                                             : SC_CMD_MSG;
        out->text = rest;
    } else if (word_is(line, len, "/whois")) {
        take_word(rest, out->user, sizeof(out->user));
        out->type = out->user[0] == '\0' ? SC_CMD_USAGE : SC_CMD_WHOIS;
    } else if (word_is(line, len, "/list") || word_is(line, len, "/who")) {
        out->type = SC_CMD_LIST;
    } else if (word_is(line, len, "/fingerprint")) {
        out->type = SC_CMD_FINGERPRINT;
    } else if (word_is(line, len, "/help")) {
        out->type = SC_CMD_HELP;
    } else if (word_is(line, len, "/quit") || word_is(line, len, "/exit")) {
        out->type = SC_CMD_QUIT;
    } else {
        out->type = SC_CMD_UNKNOWN;
    }
}
