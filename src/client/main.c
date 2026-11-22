/*
 * securechat-client: command-line entry point, server authentication and
 * terminal setup.
 */
#include <errno.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <termios.h>
#include <unistd.h>

#include "client.h"
#include "securechat/keystore.h"
#include "securechat/net.h"

static volatile sig_atomic_t g_stop = 0;
static struct termios g_saved_termios;
static int g_raw_mode = 0;

static void on_signal(int sig) {
    (void)sig;
    g_stop = 1;
}

static void restore_terminal(void) {
    if (g_raw_mode) {
        tcsetattr(STDIN_FILENO, TCSAFLUSH, &g_saved_termios);
        g_raw_mode = 0;
    }
}

/* Character-at-a-time input without echo; Ctrl-C arrives as a byte. */
static int enable_raw_mode(void) {
    if (tcgetattr(STDIN_FILENO, &g_saved_termios) != 0) {
        return -1;
    }
    struct termios raw = g_saved_termios;
    raw.c_lflag &= (tcflag_t) ~(ICANON | ECHO | ISIG | IEXTEN);
    raw.c_iflag &= (tcflag_t) ~(IXON | ICRNL);
    raw.c_cc[VMIN] = 1;
    raw.c_cc[VTIME] = 0;
    if (tcsetattr(STDIN_FILENO, TCSAFLUSH, &raw) != 0) {
        return -1;
    }
    g_raw_mode = 1;
    atexit(restore_terminal);
    return 0;
}

static void usage(FILE *out) {
    fprintf(out,
            "Usage: securechat-client [options] [HOST [PORT]]\n"
            "\n"
            "Options:\n"
            "  -H, --host HOST         server host (default 127.0.0.1)\n"
            "  -p, --port PORT         server port (default 7000)\n"
            "  -n, --name NAME         join with this username\n"
            "      --server-key HEX    pin the server public key (64 hex chars);\n"
            "                          disables trust-on-first-use\n"
            "      --known-hosts PATH  TOFU store (default: $SECURECHAT_HOME/known_hosts\n"
            "                          or ~/.securechat/known_hosts)\n"
            "      --color WHEN        auto | always | never (default auto)\n"
            "  -h, --help              show this help\n"
            "  -V, --version           show the version\n");
}

/* Resolve the default known_hosts path, creating its directory (0700). */
static int default_known_hosts(char *out, size_t cap) {
    const char *base = getenv("SECURECHAT_HOME");
    char dir[512];
    if (base != NULL && base[0] != '\0') {
        snprintf(dir, sizeof(dir), "%s", base);
    } else {
        const char *home = getenv("HOME");
        if (home == NULL || home[0] == '\0') {
            return -1;
        }
        snprintf(dir, sizeof(dir), "%s/.securechat", home);
    }
    if (mkdir(dir, 0700) != 0 && errno != EEXIST) {
        return -1;
    }
    int n = snprintf(out, cap, "%s/known_hosts", dir);
    return (n > 0 && (size_t)n < cap) ? 0 : -1;
}

typedef struct {
    const char *host;
    const char *port;
    const char *name;
    const char *server_key_hex;
    const char *known_hosts;
    sc_color_mode color;
} options;

static int parse_args(int argc, char **argv, options *o) {
    int positional = 0;
    for (int i = 1; i < argc; i++) {
        const char *a = argv[i];
        int has_value = i + 1 < argc;
        if ((!strcmp(a, "-H") || !strcmp(a, "--host")) && has_value) {
            o->host = argv[++i];
        } else if ((!strcmp(a, "-p") || !strcmp(a, "--port")) && has_value) {
            o->port = argv[++i];
        } else if ((!strcmp(a, "-n") || !strcmp(a, "--name")) && has_value) {
            o->name = argv[++i];
        } else if (!strcmp(a, "--server-key") && has_value) {
            o->server_key_hex = argv[++i];
        } else if (!strcmp(a, "--known-hosts") && has_value) {
            o->known_hosts = argv[++i];
        } else if (!strcmp(a, "--color") && has_value) {
            if (sc_color_mode_parse(argv[++i], &o->color) != 0) {
                fprintf(stderr, "error: --color expects auto, always or never\n");
                return 2;
            }
        } else if (!strcmp(a, "-h") || !strcmp(a, "--help")) {
            usage(stdout);
            return 1;
        } else if (!strcmp(a, "-V") || !strcmp(a, "--version")) {
            printf("securechat-client %s\n", SC_VERSION_STRING);
            return 1;
        } else if (a[0] != '-' && positional < 2) {
            if (positional++ == 0) {
                o->host = a;
            } else {
                o->port = a;
            }
        } else {
            fprintf(stderr, "error: unknown or incomplete option '%s'\n\n", a);
            usage(stderr);
            return 2;
        }
    }
    return 0;
}

/*
 * Decide whether to trust the server identity and describe why.
 * Returns 0 when verified, 1 for a first TOFU contact, -1 to abort.
 */
static int verify_server(const options *o, const uint8_t *server_pk,
                         char *trust, size_t cap) {
    char fp[SC_FINGERPRINT_LEN];
    sc_fingerprint(server_pk, crypto_sign_PUBLICKEYBYTES, fp);

    if (o->server_key_hex != NULL) {
        uint8_t pinned[crypto_sign_PUBLICKEYBYTES];
        if (sc_parse_public_key(o->server_key_hex, pinned) != 0) {
            fprintf(stderr, "error: --server-key must be 64 hexadecimal characters\n");
            return -1;
        }
        if (sodium_memcmp(pinned, server_pk, sizeof(pinned)) != 0) {
            fprintf(stderr,
                    "\n  SECURITY ALERT: the server key does not match --server-key.\n"
                    "  Presented fingerprint: %s\n"
                    "  Someone may be intercepting the connection. Aborting.\n\n",
                    fp);
            return -1;
        }
        snprintf(trust, cap, "verified against the pinned server key");
        return 0;
    }

    char path[600];
    if (o->known_hosts != NULL) {
        snprintf(path, sizeof(path), "%s", o->known_hosts);
    } else if (default_known_hosts(path, sizeof(path)) != 0) {
        fprintf(stderr, "error: cannot locate a known_hosts file; use --known-hosts\n");
        return -1;
    }
    char host_id[300];
    snprintf(host_id, sizeof(host_id), "%s:%s", o->host, o->port);
    switch (sc_known_hosts_check(path, host_id, server_pk)) {
    case SC_TRUST_MATCH:
        snprintf(trust, cap, "matches the key remembered for %s", host_id);
        return 0;
    case SC_TRUST_NEW:
        snprintf(trust, cap, "first connection: key remembered (TOFU)");
        return 1;
    case SC_TRUST_MISMATCH:
        fprintf(stderr,
                "\n  SECURITY ALERT: the identity of %s has CHANGED.\n"
                "  Presented fingerprint: %s\n"
                "  This may be a man-in-the-middle attack. If the server key was\n"
                "  rotated on purpose, remove its line from %s.\n\n",
                host_id, fp, path);
        return -1;
    case SC_TRUST_ERROR:
    default:
        fprintf(stderr, "error: cannot read or update %s\n", path);
        return -1;
    }
}

int main(int argc, char **argv) {
    options o = {"127.0.0.1", "7000", NULL, NULL, NULL, SC_COLOR_AUTO};
    int prc = parse_args(argc, argv, &o);
    if (prc != 0) {
        return prc == 1 ? 0 : prc;
    }
    if (sc_crypto_init() != 0) {
        fprintf(stderr, "error: libsodium initialisation failed\n");
        return 1;
    }
    signal(SIGPIPE, SIG_IGN);

    static sc_client client;
    sc_client *c = &client;
    memset(c, 0, sizeof(*c));
    c->fd = sc_tcp_connect(o.host, o.port);
    if (c->fd < 0) {
        fprintf(stderr, "error: cannot connect to %s:%s\n", o.host, o.port);
        return 1;
    }

    sc_client_handshake hs;
    uint8_t finish[SC_HS_CLIENT_FINISH_LEN];
    if (sc_client_handshake_start(c, &hs, finish) != 0) {
        fprintf(stderr, "error: secure handshake with %s:%s failed "
                        "(server full, wrong protocol or tampering)\n",
                o.host, o.port);
        close(c->fd);
        return 1;
    }
    char trust[512];
    int trust_level = verify_server(&o, c->server_pk, trust, sizeof(trust));
    if (trust_level < 0 || sc_client_handshake_confirm(c, finish) != 0) {
        close(c->fd);
        sodium_memzero(c, sizeof(*c));
        return 1;
    }

    sc_box_keypair_generate(&c->box);
    int interactive = isatty(STDIN_FILENO) && isatty(STDOUT_FILENO);
    if (interactive && enable_raw_mode() != 0) {
        interactive = 0;
    }
    sc_lineedit_init(&c->editor);
    sc_ui_init(&c->ui, sc_color_enabled(o.color, stdout), interactive,
               &c->editor);

    struct sigaction sa;
    memset(&sa, 0, sizeof(sa));
    sa.sa_handler = on_signal;
    sigemptyset(&sa.sa_mask);
    sigaction(SIGINT, &sa, NULL);
    sigaction(SIGTERM, &sa, NULL);
    sigaction(SIGHUP, &sa, NULL);

    char server_label[300];
    char server_fp[SC_FINGERPRINT_LEN];
    char own_fp[SC_FINGERPRINT_LEN];
    snprintf(server_label, sizeof(server_label), "%s:%s", o.host, o.port);
    sc_fingerprint(c->server_pk, sizeof(c->server_pk), server_fp);
    sc_fingerprint(c->box.pk, sizeof(c->box.pk), own_fp);
    sc_ui_banner(&c->ui, server_label, server_fp, trust, trust_level == 0, own_fp);

    int rc = sc_client_run(c, o.name, &g_stop);

    restore_terminal();
    close(c->fd);
    sodium_memzero(c, sizeof(*c));
    return rc;
}
