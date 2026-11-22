#include "securechat/keystore.h"

#include <errno.h>
#include <fcntl.h>
#include <stdio.h>
#include <string.h>
#include <unistd.h>

#include "securechat/text.h"

#define HEX_PK_LEN (2 * crypto_sign_PUBLICKEYBYTES)
#define HEX_SK_LEN (2 * crypto_sign_SECRETKEYBYTES)
#define LINE_MAX_LEN 512

static int parse_hex_exact(const char *hex, uint8_t *out, size_t out_len) {
    size_t bin_len = 0;
    const char *end = NULL;
    if (strlen(hex) != 2 * out_len) {
        return -1;
    }
    if (sodium_hex2bin(out, out_len, hex, 2 * out_len, NULL, &bin_len, &end) !=
            0 ||
        bin_len != out_len || *end != '\0') {
        return -1;
    }
    return 0;
}

int sc_parse_public_key(const char *hex,
                        uint8_t pk[crypto_sign_PUBLICKEYBYTES]) {
    return parse_hex_exact(hex, pk, crypto_sign_PUBLICKEYBYTES);
}

static int write_all(int fd, const char *buf, size_t len) {
    while (len > 0) {
        ssize_t n = write(fd, buf, len);
        if (n < 0) {
            if (errno == EINTR) {
                continue;
            }
            return -1;
        }
        buf += n;
        len -= (size_t)n;
    }
    return 0;
}

static int create_identity(const char *path, sc_identity *id) {
    int fd = open(path, O_WRONLY | O_CREAT | O_EXCL, 0600);
    if (fd < 0) {
        return -1;
    }
    char hex[HEX_SK_LEN + 2];
    sc_identity_generate(id);
    sodium_bin2hex(hex, HEX_SK_LEN + 1, id->sk, sizeof(id->sk));
    hex[HEX_SK_LEN] = '\n';
    hex[HEX_SK_LEN + 1] = '\0';
    int rc = write_all(fd, hex, HEX_SK_LEN + 1);
    sodium_memzero(hex, sizeof(hex));
    if (close(fd) != 0) {
        rc = -1;
    }
    return rc;
}

static int load_identity(const char *path, sc_identity *id) {
    FILE *f = fopen(path, "r");
    if (f == NULL) {
        return -1;
    }
    char line[LINE_MAX_LEN];
    int rc = -1;
    if (fgets(line, sizeof(line), f) != NULL) {
        sc_chomp(line);
        if (parse_hex_exact(line, id->sk, sizeof(id->sk)) == 0) {
            rc = crypto_sign_ed25519_sk_to_pk(id->pk, id->sk);
        }
    }
    sodium_memzero(line, sizeof(line));
    fclose(f);
    return rc == 0 ? 0 : -1;
}

int sc_identity_load_or_create(const char *path, sc_identity *id,
                               int *created) {
    *created = 0;
    if (access(path, F_OK) != 0) {
        if (create_identity(path, id) != 0) {
            return -1;
        }
        *created = 1;
        return 0;
    }
    return load_identity(path, id);
}

static int host_id_is_valid(const char *host_id) {
    size_t len = strnlen(host_id, 256);
    if (len == 0 || len >= 256) {
        return 0;
    }
    for (size_t i = 0; i < len; i++) {
        unsigned char c = (unsigned char)host_id[i];
        if (c <= ' ' || c >= 0x7F) {
            return 0;
        }
    }
    return 1;
}

sc_trust sc_known_hosts_check(const char *path, const char *host_id,
                              const uint8_t pk[crypto_sign_PUBLICKEYBYTES]) {
    if (!host_id_is_valid(host_id)) {
        return SC_TRUST_ERROR;
    }
    FILE *f = fopen(path, "r");
    if (f != NULL) {
        char line[LINE_MAX_LEN];
        sc_trust verdict = SC_TRUST_NEW;
        while (fgets(line, sizeof(line), f) != NULL) {
            sc_chomp(line);
            char *space = strchr(line, ' ');
            if (space == NULL) {
                continue; /* ignore malformed or overlong lines */
            }
            *space = '\0';
            uint8_t stored[crypto_sign_PUBLICKEYBYTES];
            if (strcmp(line, host_id) != 0 ||
                sc_parse_public_key(space + 1, stored) != 0) {
                continue;
            }
            verdict = sodium_memcmp(stored, pk, sizeof(stored)) == 0
                          ? SC_TRUST_MATCH
                          : SC_TRUST_MISMATCH;
            break;
        }
        fclose(f);
        if (verdict != SC_TRUST_NEW) {
            return verdict;
        }
    } else if (errno != ENOENT) {
        return SC_TRUST_ERROR;
    }

    int fd = open(path, O_WRONLY | O_CREAT | O_APPEND, 0600);
    if (fd < 0) {
        return SC_TRUST_ERROR;
    }
    char hex[HEX_PK_LEN + 1];
    sodium_bin2hex(hex, sizeof(hex), pk, crypto_sign_PUBLICKEYBYTES);
    char entry[LINE_MAX_LEN];
    int n = snprintf(entry, sizeof(entry), "%s %s\n", host_id, hex);
    int rc = (n > 0 && (size_t)n < sizeof(entry))
                 ? write_all(fd, entry, (size_t)n)
                 : -1;
    if (close(fd) != 0) {
        rc = -1;
    }
    return rc == 0 ? SC_TRUST_NEW : SC_TRUST_ERROR;
}
