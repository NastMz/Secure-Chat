/*
 * securechat-server: command-line entry point.
 */
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#include "securechat/keystore.h"
#include "securechat/net.h"
#include "securechat/protocol.h"
#include "server.h"

static volatile sig_atomic_t g_stop = 0;

static void on_signal(int sig) {
    (void)sig;
    g_stop = 1;
}

static void usage(FILE *out) {
    fprintf(out,
            "Usage: securechat-server [options]\n"
            "\n"
            "Options:\n"
            "  -p, --port PORT      TCP port to listen on (default 7000)\n"
            "  -b, --bind ADDR      address to bind (default 0.0.0.0)\n"
            "  -k, --key PATH       identity key file, created if missing\n"
            "                       (default: $SECURECHAT_KEY or ./securechat_server.key)\n"
            "      --show-key       print the public key and fingerprint, then exit\n"
            "      --color WHEN     auto | always | never (default auto)\n"
            "  -h, --help           show this help\n"
            "  -V, --version        show the version\n");
}

static void print_banner(const sc_style *st, const sc_identity *id,
                         const char *bind_addr, const char *port, int created) {
    char fp[SC_FINGERPRINT_LEN];
    char hex[2 * crypto_sign_PUBLICKEYBYTES + 1];
    sc_fingerprint(id->pk, sizeof(id->pk), fp);
    sodium_bin2hex(hex, sizeof(hex), id->pk, sizeof(id->pk));

    /* Box of 58 columns, matching the client banner. */
    static const char rule[] =
        "──────────────────────────────────────────────────────────";
    const char *tagline = "encrypted chat relay";
    int used = 2 + (int)strlen("SecureChat server ") + (int)strlen(SC_VERSION_STRING) +
               3 + (int)strlen(tagline);
    printf("%s╭%s╮%s\n", st->accent, rule, st->reset);
    printf("%s│%s  %sSecureChat server %s%s %s·%s %s%s%s%*s%s│%s\n", st->accent,
           st->reset, st->bold, SC_VERSION_STRING, st->reset, st->accent,
           st->reset, st->dim, tagline, st->reset, 58 - used, "", st->accent,
           st->reset);
    printf("%s╰%s╯%s\n", st->accent, rule, st->reset);
    printf("  %sidentity%s    %s%s%s%s\n", st->dim, st->reset, st->bold, fp,
           st->reset, created ? "  (new key generated)" : "");
    printf("  %spublic key%s  %s\n", st->dim, st->reset, hex);
    printf("  %slistening%s   %s:%s\n", st->dim, st->reset, bind_addr, port);
    printf("  %scrypto%s      X25519 + Ed25519 + XChaCha20-Poly1305 (libsodium %s)\n\n",
           st->dim, st->reset, sodium_version_string());
    fflush(stdout);
}

int main(int argc, char **argv) {
    const char *port = "7000";
    const char *bind_addr = "0.0.0.0";
    const char *key_path = getenv("SECURECHAT_KEY");
    sc_color_mode color = SC_COLOR_AUTO;
    int show_key = 0;

    if (key_path == NULL || key_path[0] == '\0') {
        key_path = "securechat_server.key";
    }
    for (int i = 1; i < argc; i++) {
        const char *a = argv[i];
        int has_value = i + 1 < argc;
        if ((!strcmp(a, "-p") || !strcmp(a, "--port")) && has_value) {
            port = argv[++i];
        } else if ((!strcmp(a, "-b") || !strcmp(a, "--bind")) && has_value) {
            bind_addr = argv[++i];
        } else if ((!strcmp(a, "-k") || !strcmp(a, "--key")) && has_value) {
            key_path = argv[++i];
        } else if (!strcmp(a, "--color") && has_value) {
            if (sc_color_mode_parse(argv[++i], &color) != 0) {
                fprintf(stderr, "error: --color expects auto, always or never\n");
                return 2;
            }
        } else if (!strcmp(a, "--show-key")) {
            show_key = 1;
        } else if (!strcmp(a, "-h") || !strcmp(a, "--help")) {
            usage(stdout);
            return 0;
        } else if (!strcmp(a, "-V") || !strcmp(a, "--version")) {
            printf("securechat-server %s\n", SC_VERSION_STRING);
            return 0;
        } else {
            fprintf(stderr, "error: unknown or incomplete option '%s'\n\n", a);
            usage(stderr);
            return 2;
        }
    }

    if (sc_crypto_init() != 0) {
        fprintf(stderr, "error: libsodium initialisation failed\n");
        return 1;
    }

    sc_identity identity;
    int created = 0;
    if (sc_identity_load_or_create(key_path, &identity, &created) != 0) {
        fprintf(stderr, "error: cannot load or create identity key '%s'\n",
                key_path);
        return 1;
    }

    if (show_key) {
        char fp[SC_FINGERPRINT_LEN];
        char hex[2 * crypto_sign_PUBLICKEYBYTES + 1];
        sc_fingerprint(identity.pk, sizeof(identity.pk), fp);
        sodium_bin2hex(hex, sizeof(hex), identity.pk, sizeof(identity.pk));
        printf("public key:  %s\nfingerprint: %s\n", hex, fp);
        sodium_memzero(&identity, sizeof(identity));
        return 0;
    }

    sc_server_config cfg;
    memset(&cfg, 0, sizeof(cfg));
    cfg.identity = &identity;
    sc_style_init(&cfg.style, sc_color_enabled(color, stdout));

    cfg.listen_fd = sc_tcp_listen(bind_addr, port);
    if (cfg.listen_fd < 0) {
        fprintf(stderr, "error: cannot listen on %s:%s\n", bind_addr, port);
        sodium_memzero(&identity, sizeof(identity));
        return 1;
    }

    struct sigaction sa;
    memset(&sa, 0, sizeof(sa));
    sa.sa_handler = on_signal;
    sigemptyset(&sa.sa_mask);
    sigaction(SIGINT, &sa, NULL);
    sigaction(SIGTERM, &sa, NULL);
    signal(SIGPIPE, SIG_IGN);

    print_banner(&cfg.style, &identity, bind_addr, port, created);
    int rc = sc_server_run(&cfg, &g_stop);
    sc_server_log(&cfg.style, cfg.style.accent, "▸", "server stopped");

    close(cfg.listen_fd);
    sodium_memzero(&identity, sizeof(identity));
    return rc == 0 ? 0 : 1;
}
