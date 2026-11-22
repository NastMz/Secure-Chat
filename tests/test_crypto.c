#include <string.h>

#include "securechat/crypto.h"
#include "test.h"

#define SS_ABYTES crypto_secretstream_xchacha20poly1305_ABYTES

/* Offsets inside ServerHello (see crypto.c). */
#define SH_EPH (SC_MAGIC_LEN + 1)
#define SH_IDENTITY (SH_EPH + crypto_kx_PUBLICKEYBYTES)
#define SH_SIGNATURE (SH_IDENTITY + crypto_sign_PUBLICKEYBYTES)

typedef struct {
    sc_identity id;
    sc_channel server;
    sc_channel client;
    uint8_t identity_seen[crypto_sign_PUBLICKEYBYTES];
} session;

static int establish(session *s) {
    sc_client_handshake chs;
    sc_server_handshake shs;
    uint8_t hello[SC_HS_CLIENT_HELLO_LEN];
    uint8_t reply[SC_HS_SERVER_HELLO_LEN];
    uint8_t finish[SC_HS_CLIENT_FINISH_LEN];
    sc_identity_generate(&s->id);
    sc_hs_client_start(&chs, hello);
    if (sc_hs_server_respond(&s->id, &shs, hello, sizeof(hello), reply,
                             &s->server) != 0) {
        return -1;
    }
    if (sc_hs_client_finish(&chs, reply, sizeof(reply), s->identity_seen,
                            finish, &s->client) != 0) {
        return -1;
    }
    return sc_hs_server_finish(&shs, finish, sizeof(finish), &s->server);
}

static int roundtrip(sc_channel *tx, sc_channel *rx, const char *text) {
    uint8_t ct[256];
    uint8_t pt[256];
    size_t ct_len = 0;
    size_t pt_len = 0;
    size_t len = strlen(text);
    if (sc_channel_seal(tx, (const uint8_t *)text, len, ct, sizeof(ct),
                        &ct_len) != 0 ||
        sc_channel_open(rx, ct, ct_len, pt, sizeof(pt), &pt_len) != 0) {
        return -1;
    }
    return (pt_len == len && memcmp(pt, text, len) == 0) ? 0 : -1;
}

static void test_handshake_establishes_both_directions(void) {
    session s;
    CHECK(establish(&s) == 0);
    CHECK(memcmp(s.identity_seen, s.id.pk, sizeof(s.id.pk)) == 0);
    CHECK(roundtrip(&s.client, &s.server, "client to server") == 0);
    CHECK(roundtrip(&s.server, &s.client, "server to client") == 0);
    CHECK(roundtrip(&s.client, &s.server, "second message") == 0);
}

static void test_ciphertext_hides_plaintext(void) {
    session s;
    CHECK(establish(&s) == 0);
    const char *secret = "attack at dawn";
    uint8_t ct[64];
    size_t ct_len = 0;
    CHECK(sc_channel_seal(&s.client, (const uint8_t *)secret, strlen(secret),
                          ct, sizeof(ct), &ct_len) == 0);
    CHECK(ct_len == strlen(secret) + SS_ABYTES);
    CHECK(!contains_bytes(ct, ct_len, secret, strlen(secret)));
}

static void test_tampered_ciphertext_is_rejected(void) {
    session s;
    CHECK(establish(&s) == 0);
    uint8_t ct[64];
    uint8_t pt[64];
    size_t ct_len = 0;
    size_t pt_len = 0;
    CHECK(sc_channel_seal(&s.client, (const uint8_t *)"hello", 5, ct,
                          sizeof(ct), &ct_len) == 0);
    ct[ct_len - 1] ^= 0x01;
    CHECK(sc_channel_open(&s.server, ct, ct_len, pt, sizeof(pt), &pt_len) != 0);
}

static void test_replay_and_reorder_are_rejected(void) {
    session s;
    CHECK(establish(&s) == 0);
    uint8_t c1[64];
    uint8_t c2[64];
    uint8_t pt[64];
    size_t l1 = 0;
    size_t l2 = 0;
    size_t pl = 0;
    CHECK(sc_channel_seal(&s.client, (const uint8_t *)"one", 3, c1, sizeof(c1), &l1) == 0);
    CHECK(sc_channel_seal(&s.client, (const uint8_t *)"two", 3, c2, sizeof(c2), &l2) == 0);

    /* Reorder: delivering the second message first fails. */
    session r = s;
    CHECK(sc_channel_open(&r.server, c2, l2, pt, sizeof(pt), &pl) != 0);

    /* Replay: the first message cannot be accepted twice. */
    CHECK(sc_channel_open(&s.server, c1, l1, pt, sizeof(pt), &pl) == 0);
    CHECK(sc_channel_open(&s.server, c1, l1, pt, sizeof(pt), &pl) != 0);
}

static void test_channel_bounds(void) {
    session s;
    CHECK(establish(&s) == 0);
    static uint8_t big[SC_PAYLOAD_MAX + 1];
    static uint8_t out[SC_FRAME_MAX + 64];
    size_t len = 0;
    CHECK(sc_channel_seal(&s.client, big, 0, out, sizeof(out), &len) != 0);
    CHECK(sc_channel_seal(&s.client, big, SC_PAYLOAD_MAX + 1, out, sizeof(out), &len) != 0);
    CHECK(sc_channel_seal(&s.client, big, 10, out, 10, &len) != 0);
    CHECK(sc_channel_open(&s.server, big, SS_ABYTES, out, sizeof(out), &len) != 0);
}

static void test_server_rejects_malformed_client_hello(void) {
    sc_identity id;
    sc_identity_generate(&id);
    sc_client_handshake chs;
    sc_server_handshake shs;
    sc_channel ch;
    uint8_t hello[SC_HS_CLIENT_HELLO_LEN];
    uint8_t reply[SC_HS_SERVER_HELLO_LEN];
    sc_hs_client_start(&chs, hello);

    CHECK(sc_hs_server_respond(&id, &shs, hello, sizeof(hello) - 1, reply, &ch) != 0);

    uint8_t bad_magic[SC_HS_CLIENT_HELLO_LEN];
    memcpy(bad_magic, hello, sizeof(hello));
    bad_magic[0] = 'X';
    CHECK(sc_hs_server_respond(&id, &shs, bad_magic, sizeof(bad_magic), reply, &ch) != 0);

    uint8_t bad_version[SC_HS_CLIENT_HELLO_LEN];
    memcpy(bad_version, hello, sizeof(hello));
    bad_version[SC_MAGIC_LEN] = 99;
    CHECK(sc_hs_server_respond(&id, &shs, bad_version, sizeof(bad_version), reply, &ch) != 0);

    /* An all-zero (low-order) public key must not yield session keys. */
    uint8_t zero_key[SC_HS_CLIENT_HELLO_LEN];
    memcpy(zero_key, hello, SC_MAGIC_LEN + 1);
    memset(zero_key + SC_MAGIC_LEN + 1, 0, crypto_kx_PUBLICKEYBYTES);
    CHECK(sc_hs_server_respond(&id, &shs, zero_key, sizeof(zero_key), reply, &ch) != 0);
}

static void test_client_rejects_forged_server_hello(void) {
    sc_identity id;
    sc_identity_generate(&id);
    sc_client_handshake chs;
    sc_server_handshake shs;
    sc_channel sch;
    sc_channel cch;
    uint8_t hello[SC_HS_CLIENT_HELLO_LEN];
    uint8_t reply[SC_HS_SERVER_HELLO_LEN];
    uint8_t finish[SC_HS_CLIENT_FINISH_LEN];
    uint8_t seen[crypto_sign_PUBLICKEYBYTES];

    sc_hs_client_start(&chs, hello);
    CHECK(sc_hs_server_respond(&id, &shs, hello, sizeof(hello), reply, &sch) == 0);

    /* A MITM swapping in its own ephemeral key breaks the signature. */
    sc_client_handshake saved = chs;
    uint8_t forged[SC_HS_SERVER_HELLO_LEN];
    memcpy(forged, reply, sizeof(reply));
    uint8_t mitm_sk[crypto_kx_SECRETKEYBYTES];
    crypto_kx_keypair(forged + SH_EPH, mitm_sk);
    CHECK(sc_hs_client_finish(&chs, forged, sizeof(forged), seen, finish, &cch) != 0);

    /* Any flipped bit in the signature is rejected. */
    chs = saved;
    memcpy(forged, reply, sizeof(reply));
    forged[SH_SIGNATURE] ^= 0x80;
    CHECK(sc_hs_client_finish(&chs, forged, sizeof(forged), seen, finish, &cch) != 0);

    /* A signature from a different identity key is rejected. */
    chs = saved;
    memcpy(forged, reply, sizeof(reply));
    sc_identity other;
    sc_identity_generate(&other);
    memcpy(forged + SH_IDENTITY, other.pk, sizeof(other.pk));
    CHECK(sc_hs_client_finish(&chs, forged, sizeof(forged), seen, finish, &cch) != 0);

    /* Wrong length. */
    chs = saved;
    CHECK(sc_hs_client_finish(&chs, reply, sizeof(reply) - 1, seen, finish, &cch) != 0);
}

static void test_signature_is_bound_to_this_client(void) {
    /* A ServerHello captured for one client cannot be replayed to another. */
    sc_identity id;
    sc_identity_generate(&id);
    sc_client_handshake alice;
    sc_client_handshake bob;
    sc_server_handshake shs;
    sc_channel sch;
    sc_channel cch;
    uint8_t hello_a[SC_HS_CLIENT_HELLO_LEN];
    uint8_t hello_b[SC_HS_CLIENT_HELLO_LEN];
    uint8_t reply[SC_HS_SERVER_HELLO_LEN];
    uint8_t finish[SC_HS_CLIENT_FINISH_LEN];
    uint8_t seen[crypto_sign_PUBLICKEYBYTES];
    sc_hs_client_start(&alice, hello_a);
    sc_hs_client_start(&bob, hello_b);
    CHECK(sc_hs_server_respond(&id, &shs, hello_a, sizeof(hello_a), reply, &sch) == 0);
    CHECK(sc_hs_client_finish(&bob, reply, sizeof(reply), seen, finish, &cch) != 0);
}

static void test_server_finish_validates_length(void) {
    sc_server_handshake shs;
    sc_channel ch;
    uint8_t finish[SC_HS_CLIENT_FINISH_LEN] = {0};
    memset(&shs, 0, sizeof(shs));
    CHECK(sc_hs_server_finish(&shs, finish, sizeof(finish) - 1, &ch) != 0);
}

static void test_e2e_roundtrip_and_authentication(void) {
    sc_box_keypair alice;
    sc_box_keypair bob;
    sc_box_keypair eve;
    sc_box_keypair_generate(&alice);
    sc_box_keypair_generate(&bob);
    sc_box_keypair_generate(&eve);
    const char *text = "meet me at the library";
    size_t len = strlen(text);
    uint8_t sealed[SC_E2E_MAX];
    uint8_t opened[SC_TEXT_MAX];
    size_t sealed_len = 0;
    size_t opened_len = 0;

    uint64_t last = 0;

    CHECK(sc_e2e_seal(&alice, bob.pk, 1, (const uint8_t *)text, len, sealed,
                      sizeof(sealed), &sealed_len) == 0);
    CHECK(sealed_len == len + SC_E2E_OVERHEAD);
    CHECK(!contains_bytes(sealed, sealed_len, text, len));

    CHECK(sc_e2e_open(&bob, alice.pk, &last, sealed, sealed_len, opened,
                      sizeof(opened), &opened_len) == 0);
    CHECK(opened_len == len && memcmp(opened, text, len) == 0);
    CHECK(last == 1);

    /* Eve (or the relaying server) cannot read it... */
    uint64_t eve_last = 0;
    CHECK(sc_e2e_open(&eve, alice.pk, &eve_last, sealed, sealed_len, opened,
                      sizeof(opened), &opened_len) != 0);
    /* ...and Bob detects a forged sender. */
    uint64_t forged_last = 0;
    CHECK(sc_e2e_open(&bob, eve.pk, &forged_last, sealed, sealed_len, opened,
                      sizeof(opened), &opened_len) != 0);

    sealed[sealed_len - 1] ^= 1;
    last = 0;
    CHECK(sc_e2e_open(&bob, alice.pk, &last, sealed, sealed_len, opened,
                      sizeof(opened), &opened_len) != 0);
    CHECK(last == 0);
}

/* A hostile server bounces Alice's own blob back to her as "from Bob". The
 * crypto_box key is the same in both directions, so only the bound sender
 * and recipient keys can tell the difference. */
static void test_e2e_rejects_reflection(void) {
    sc_box_keypair alice;
    sc_box_keypair bob;
    sc_box_keypair_generate(&alice);
    sc_box_keypair_generate(&bob);
    uint8_t sealed[SC_E2E_MAX];
    uint8_t opened[SC_TEXT_MAX];
    size_t sealed_len = 0;
    size_t opened_len = 0;
    uint64_t last = 0;

    CHECK(sc_e2e_seal(&alice, bob.pk, 1, (const uint8_t *)"to bob", 6, sealed,
                      sizeof(sealed), &sealed_len) == 0);
    /* Alice opening it with Bob's key would succeed without the binding. */
    CHECK(sc_e2e_open(&alice, bob.pk, &last, sealed, sealed_len, opened,
                      sizeof(opened), &opened_len) != 0);
    CHECK(last == 0);
    /* The intended recipient still accepts it. */
    CHECK(sc_e2e_open(&bob, alice.pk, &last, sealed, sealed_len, opened,
                      sizeof(opened), &opened_len) == 0);
    CHECK(opened_len == 6 && memcmp(opened, "to bob", 6) == 0);
}

static void test_e2e_rejects_replay_and_reordering(void) {
    sc_box_keypair alice;
    sc_box_keypair bob;
    sc_box_keypair_generate(&alice);
    sc_box_keypair_generate(&bob);
    uint8_t m1[SC_E2E_MAX];
    uint8_t m2[SC_E2E_MAX];
    uint8_t m3[SC_E2E_MAX];
    uint8_t opened[SC_TEXT_MAX];
    size_t l1 = 0;
    size_t l2 = 0;
    size_t l3 = 0;
    size_t opened_len = 0;
    uint64_t last = 0;

    CHECK(sc_e2e_seal(&alice, bob.pk, 1, (const uint8_t *)"one", 3, m1, sizeof(m1), &l1) == 0);
    CHECK(sc_e2e_seal(&alice, bob.pk, 2, (const uint8_t *)"two", 3, m2, sizeof(m2), &l2) == 0);
    CHECK(sc_e2e_seal(&alice, bob.pk, 3, (const uint8_t *)"three", 5, m3, sizeof(m3), &l3) == 0);

    CHECK(sc_e2e_open(&bob, alice.pk, &last, m1, l1, opened, sizeof(opened), &opened_len) == 0);
    /* Replay of the same blob. */
    CHECK(sc_e2e_open(&bob, alice.pk, &last, m1, l1, opened, sizeof(opened), &opened_len) != 0);
    CHECK(last == 1);
    /* Reordering: 3 arrives before 2, so 2 is stale afterwards. */
    CHECK(sc_e2e_open(&bob, alice.pk, &last, m3, l3, opened, sizeof(opened), &opened_len) == 0);
    CHECK(opened_len == 5 && memcmp(opened, "three", 5) == 0);
    CHECK(sc_e2e_open(&bob, alice.pk, &last, m2, l2, opened, sizeof(opened), &opened_len) != 0);
    CHECK(last == 3);
    /* Counter 0 is reserved for "nothing received yet". */
    CHECK(sc_e2e_seal(&alice, bob.pk, 0, (const uint8_t *)"x", 1, m1, sizeof(m1), &l1) != 0);
}

static void test_e2e_nonces_are_fresh(void) {
    sc_box_keypair a;
    sc_box_keypair b;
    sc_box_keypair_generate(&a);
    sc_box_keypair_generate(&b);
    uint8_t s1[SC_E2E_MAX];
    uint8_t s2[SC_E2E_MAX];
    size_t l1 = 0;
    size_t l2 = 0;
    CHECK(sc_e2e_seal(&a, b.pk, 1, (const uint8_t *)"same", 4, s1, sizeof(s1), &l1) == 0);
    CHECK(sc_e2e_seal(&a, b.pk, 1, (const uint8_t *)"same", 4, s2, sizeof(s2), &l2) == 0);
    CHECK(memcmp(s1, s2, crypto_box_NONCEBYTES) != 0);
    CHECK(memcmp(s1, s2, l1) != 0);
}

static void test_e2e_bounds(void) {
    sc_box_keypair a;
    sc_box_keypair b;
    sc_box_keypair_generate(&a);
    sc_box_keypair_generate(&b);
    static uint8_t text[SC_TEXT_MAX + 1];
    static uint8_t out[SC_E2E_MAX + 64];
    size_t len = 0;
    uint64_t last = 0;
    memset(text, 'x', sizeof(text));
    CHECK(sc_e2e_seal(&a, b.pk, 1, text, SC_TEXT_MAX + 1, out, sizeof(out), &len) != 0);
    CHECK(sc_e2e_seal(&a, b.pk, 1, text, 0, out, sizeof(out), &len) != 0);
    CHECK(sc_e2e_seal(&a, b.pk, 1, text, SC_TEXT_MAX, out, SC_E2E_MAX - 1, &len) != 0);
    CHECK(sc_e2e_seal(&a, b.pk, 1, text, SC_TEXT_MAX, out, sizeof(out), &len) == 0);
    CHECK(len == SC_E2E_MAX);
    CHECK(sc_e2e_open(&b, a.pk, &last, out, SC_E2E_OVERHEAD, text, sizeof(text), &len) != 0);
    CHECK(sc_e2e_open(&b, a.pk, &last, out, SC_E2E_MAX, text, SC_TEXT_MAX, &len) == 0);
    CHECK(len == SC_TEXT_MAX);
}

static void test_fingerprint_format(void) {
    uint8_t key[32] = {0};
    char a[SC_FINGERPRINT_LEN];
    char b[SC_FINGERPRINT_LEN];
    sc_fingerprint(key, sizeof(key), a);
    sc_fingerprint(key, sizeof(key), b);
    CHECK(strcmp(a, b) == 0);
    CHECK(strlen(a) == SC_FINGERPRINT_LEN - 1);
    CHECK(a[4] == ' ' && a[9] == ' ');
    key[0] = 1;
    sc_fingerprint(key, sizeof(key), b);
    CHECK(strcmp(a, b) != 0);
}

int main(void) {
    if (sc_crypto_init() != 0) {
        return 1;
    }
    printf("crypto\n");
    RUN(test_handshake_establishes_both_directions);
    RUN(test_ciphertext_hides_plaintext);
    RUN(test_tampered_ciphertext_is_rejected);
    RUN(test_replay_and_reorder_are_rejected);
    RUN(test_channel_bounds);
    RUN(test_server_rejects_malformed_client_hello);
    RUN(test_client_rejects_forged_server_hello);
    RUN(test_signature_is_bound_to_this_client);
    RUN(test_server_finish_validates_length);
    RUN(test_e2e_roundtrip_and_authentication);
    RUN(test_e2e_rejects_reflection);
    RUN(test_e2e_rejects_replay_and_reordering);
    RUN(test_e2e_nonces_are_fresh);
    RUN(test_e2e_bounds);
    RUN(test_fingerprint_format);
    return TEST_SUMMARY("crypto");
}
