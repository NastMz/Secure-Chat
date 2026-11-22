#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <unistd.h>

#include "securechat/keystore.h"
#include "test.h"

static char tmpdir[256];

static void path_in_tmp(char *out, size_t cap, const char *name) {
    snprintf(out, cap, "%s/%s", tmpdir, name);
}

static void test_identity_created_once_with_private_mode(void) {
    char path[512];
    path_in_tmp(path, sizeof(path), "server.key");
    sc_identity a;
    sc_identity b;
    int created = 0;
    CHECK(sc_identity_load_or_create(path, &a, &created) == 0);
    CHECK(created == 1);
    struct stat st;
    CHECK(stat(path, &st) == 0);
    CHECK((st.st_mode & 0777) == 0600);

    CHECK(sc_identity_load_or_create(path, &b, &created) == 0);
    CHECK(created == 0);
    CHECK(memcmp(a.pk, b.pk, sizeof(a.pk)) == 0);
    CHECK(memcmp(a.sk, b.sk, sizeof(a.sk)) == 0);
}

static void test_corrupt_identity_is_rejected(void) {
    char path[512];
    path_in_tmp(path, sizeof(path), "corrupt.key");
    FILE *f = fopen(path, "w");
    CHECK(f != NULL);
    if (f != NULL) {
        fputs("not-hex\n", f);
        fclose(f);
    }
    sc_identity id;
    int created = 0;
    CHECK(sc_identity_load_or_create(path, &id, &created) != 0);
}

static void test_known_hosts_tofu(void) {
    char path[512];
    path_in_tmp(path, sizeof(path), "known_hosts");
    uint8_t k1[crypto_sign_PUBLICKEYBYTES];
    uint8_t k2[crypto_sign_PUBLICKEYBYTES];
    memset(k1, 0x11, sizeof(k1));
    memset(k2, 0x22, sizeof(k2));

    CHECK(sc_known_hosts_check(path, "chat.example:7000", k1) == SC_TRUST_NEW);
    CHECK(sc_known_hosts_check(path, "chat.example:7000", k1) == SC_TRUST_MATCH);
    CHECK(sc_known_hosts_check(path, "chat.example:7000", k2) == SC_TRUST_MISMATCH);
    /* A different host is independent. */
    CHECK(sc_known_hosts_check(path, "other:7000", k2) == SC_TRUST_NEW);
    CHECK(sc_known_hosts_check(path, "other:7000", k2) == SC_TRUST_MATCH);
    /* Mismatch must not overwrite the stored key. */
    CHECK(sc_known_hosts_check(path, "chat.example:7000", k1) == SC_TRUST_MATCH);
}

static void test_known_hosts_ignores_garbage_and_rejects_bad_ids(void) {
    char path[512];
    path_in_tmp(path, sizeof(path), "garbage_hosts");
    FILE *f = fopen(path, "w");
    CHECK(f != NULL);
    if (f != NULL) {
        fputs("garbage line without key\nhost:1 nothex\n\n", f);
        fclose(f);
    }
    uint8_t k[crypto_sign_PUBLICKEYBYTES];
    memset(k, 0x33, sizeof(k));
    CHECK(sc_known_hosts_check(path, "host:1", k) == SC_TRUST_NEW);
    CHECK(sc_known_hosts_check(path, "host:1", k) == SC_TRUST_MATCH);
    CHECK(sc_known_hosts_check(path, "bad id", k) == SC_TRUST_ERROR);
    CHECK(sc_known_hosts_check(path, "", k) == SC_TRUST_ERROR);
}

static void test_parse_public_key(void) {
    uint8_t pk[crypto_sign_PUBLICKEYBYTES];
    const char *hex =
        "00112233445566778899aabbccddeeff00112233445566778899AABBCCDDEEFF";
    CHECK(sc_parse_public_key(hex, pk) == 0);
    CHECK(pk[0] == 0x00 && pk[1] == 0x11 && pk[31] == 0xFF);
    CHECK(sc_parse_public_key("abcd", pk) != 0);
    CHECK(sc_parse_public_key(
              "00112233445566778899aabbccddeeff00112233445566778899aabbccddeeffaa",
              pk) != 0);
    CHECK(sc_parse_public_key(
              "zz112233445566778899aabbccddeeff00112233445566778899aabbccddeeff",
              pk) != 0);
}

int main(void) {
    if (sodium_init() < 0) {
        return 1;
    }
    const char *base = getenv("TMPDIR");
    snprintf(tmpdir, sizeof(tmpdir), "%s/securechat-test-XXXXXX",
             base && base[0] ? base : "/tmp");
    if (mkdtemp(tmpdir) == NULL) {
        perror("mkdtemp");
        return 1;
    }
    printf("keystore\n");
    RUN(test_identity_created_once_with_private_mode);
    RUN(test_corrupt_identity_is_rejected);
    RUN(test_known_hosts_tofu);
    RUN(test_known_hosts_ignores_garbage_and_rejects_bad_ids);
    RUN(test_parse_public_key);

    const char *files[] = {"server.key", "corrupt.key", "known_hosts", "garbage_hosts"};
    for (size_t i = 0; i < sizeof(files) / sizeof(files[0]); i++) {
        char path[512];
        path_in_tmp(path, sizeof(path), files[i]);
        unlink(path);
    }
    rmdir(tmpdir);
    return TEST_SUMMARY("keystore");
}
