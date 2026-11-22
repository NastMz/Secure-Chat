/*
 * Parsing of what the user typed: chat text or a slash command.
 */
#ifndef SECURECHAT_CLIENT_COMMAND_H
#define SECURECHAT_CLIENT_COMMAND_H

#include "securechat/protocol.h"

typedef enum {
    SC_CMD_EMPTY,       /* blank line: ignored */
    SC_CMD_SAY,         /* text = whole line */
    SC_CMD_MSG,         /* /msg <user> <text> (aliases /private, /w) */
    SC_CMD_LIST,        /* /list (alias /who) */
    SC_CMD_WHOIS,       /* /whois <user> */
    SC_CMD_FINGERPRINT, /* /fingerprint */
    SC_CMD_HELP,        /* /help */
    SC_CMD_QUIT,        /* /quit (alias /exit) */
    SC_CMD_UNKNOWN,     /* unrecognised /command */
    SC_CMD_USAGE        /* known command with missing arguments */
} sc_command_type;

typedef struct {
    sc_command_type type;
    char user[SC_NAME_MAX + 2]; /* one extra byte detects overlong names */
    const char *text;           /* points into the parsed line */
    const char *word;           /* the command word, for error messages */
} sc_command;

/* Parse `line` (without trailing newline). `line` must outlive `out`. */
void sc_command_parse(const char *line, sc_command *out);

#endif
