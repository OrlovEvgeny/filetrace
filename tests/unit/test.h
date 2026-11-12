#ifndef FILETRACE_TEST_H
#define FILETRACE_TEST_H

#include <inttypes.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>

extern int ft_test_failures;
extern int ft_test_checks;

#define CHECK(cond)                                                                                \
    do {                                                                                           \
        ft_test_checks++;                                                                          \
        if (!(cond)) {                                                                             \
            ft_test_failures++;                                                                    \
            fprintf(stderr, "%s:%d: check failed: %s\n", __FILE__, __LINE__, #cond);               \
        }                                                                                          \
    } while (0)

#define CHECK_U64(actual, expected)                                                                \
    do {                                                                                           \
        uint64_t check_a = (uint64_t)(actual);                                                     \
        uint64_t check_e = (uint64_t)(expected);                                                   \
        ft_test_checks++;                                                                          \
        if (check_a != check_e) {                                                                  \
            ft_test_failures++;                                                                    \
            fprintf(stderr, "%s:%d: %s is %" PRIu64 ", expected %" PRIu64 "\n", __FILE__,          \
                    __LINE__, #actual, check_a, check_e);                                          \
        }                                                                                          \
    } while (0)

#define CHECK_STR(actual, expected)                                                                \
    do {                                                                                           \
        const char *check_a = (actual);                                                            \
        const char *check_e = (expected);                                                          \
        ft_test_checks++;                                                                          \
        if (strcmp(check_a, check_e) != 0) {                                                       \
            ft_test_failures++;                                                                    \
            fprintf(stderr, "%s:%d: %s is \"%s\", expected \"%s\"\n", __FILE__, __LINE__, #actual, \
                    check_a, check_e);                                                             \
        }                                                                                          \
    } while (0)

void test_format(void);
void test_model(void);
void test_table(void);
void test_state(void);
void test_agent(void);
void test_views(void);
void test_config(void);
void test_metrics(void);
void test_grpc(void);
void test_otlp(void);
void test_process(void);
void test_scripts(void);
void test_leaders(void);
void test_top_model(void);
void test_top_filter(void);
void test_tui(void);
void test_top_source(void);

#endif
