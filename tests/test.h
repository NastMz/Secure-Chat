/*
 * Minimal unit-test harness: CHECK records failures, RUN executes a test.
 */
#ifndef SECURECHAT_TEST_H
#define SECURECHAT_TEST_H

#include <stddef.h>
#include <stdio.h>

static int test_failures = 0;
static int test_checks = 0;

#define CHECK(cond)                                                            \
    do {                                                                       \
        test_checks++;                                                         \
        if (!(cond)) {                                                         \
            test_failures++;                                                   \
            fprintf(stderr, "  FAIL %s:%d: %s\n", __FILE__, __LINE__, #cond);  \
        }                                                                      \
    } while (0)

#define RUN(fn)                                                                \
    do {                                                                       \
        int before = test_failures;                                            \
        fn();                                                                  \
        printf("  %s %s\n", test_failures == before ? "ok  " : "FAIL", #fn);   \
    } while (0)

/* 1 if `needle` occurs anywhere in `hay`. */
static inline int contains_bytes(const void *hay, size_t hay_len,
                                 const void *needle, size_t needle_len) {
    const unsigned char *h = (const unsigned char *)hay;
    if (needle_len == 0 || needle_len > hay_len) {
        return needle_len == 0;
    }
    for (size_t i = 0; i + needle_len <= hay_len; i++) {
        size_t k = 0;
        while (k < needle_len && h[i + k] == ((const unsigned char *)needle)[k]) {
            k++;
        }
        if (k == needle_len) {
            return 1;
        }
    }
    return 0;
}

#define TEST_SUMMARY(suite)                                                  \
    (printf("%s: %d checks, %d failures\n", suite, test_checks,                \
            test_failures),                                                    \
     test_failures == 0 ? 0 : 1)

#endif
