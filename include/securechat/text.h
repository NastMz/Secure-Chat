/*
 * Validation of untrusted strings: usernames and chat text.
 */
#ifndef SECURECHAT_TEXT_H
#define SECURECHAT_TEXT_H

#include <stddef.h>
#include <stdint.h>

/* 1..SC_NAME_MAX characters from [A-Za-z0-9_-]. */
int sc_name_is_valid(const char *name);

/*
 * Well-formed UTF-8 without control characters (C0, DEL, C1), overlong
 * encodings or surrogates, at most SC_TEXT_MAX bytes. Rejecting control
 * characters prevents terminal escape-sequence injection between users.
 */
int sc_text_is_safe(const uint8_t *text, size_t len);

/* Remove trailing '\n' / '\r' in place; returns the new length. */
size_t sc_chomp(char *line);

#endif
