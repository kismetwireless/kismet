/* test_atlog.c - standalone unit tests for the RawAT record.
 *
 * Links only atlog.c (libc, no Kismet, no serial): `--enable-cell-selftest`.
 * Covers JSON escaping (AT responses are full of CRLF, quotes and control
 * bytes) and the one-record-per-exchange formatter.
 */

#ifdef CELL_SELFTEST

#include "atlog.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

static int failures = 0;

#define CHECK(cond, ...) do { \
    if (!(cond)) { \
        fprintf(stderr, "FAIL %s:%d: ", __FILE__, __LINE__); \
        fprintf(stderr, __VA_ARGS__); \
        fprintf(stderr, "\n"); \
        failures++; \
    } \
} while (0)

/* ---- JSON escaping (the new, high-risk surface) ---- */

static void test_escape_plain(void) {
    char out[64];
    int n = atlog_json_escape("AT+QENG", 7, out, sizeof(out));
    CHECK(n == 7, "plain escape wrote %d", n);
    CHECK(strcmp(out, "AT+QENG") == 0, "plain got '%s'", out);
}

static void test_escape_quote_and_backslash(void) {
    char out[64];
    /* input:  a"b\c   ->  a\"b\\c  */
    int n = atlog_json_escape("a\"b\\c", 5, out, sizeof(out));
    CHECK(n == 7, "quote/backslash wrote %d", n);
    CHECK(strcmp(out, "a\\\"b\\\\c") == 0, "quote/backslash got '%s'", out);
}

static void test_escape_crlf_tab(void) {
    char out[64];
    /* A real AT response line ending: "OK\r\n\t" -> OK\r\n\t escaped. */
    int n = atlog_json_escape("OK\r\n\t", 5, out, sizeof(out));
    CHECK(n == 8, "crlf/tab wrote %d", n);
    CHECK(strcmp(out, "OK\\r\\n\\t") == 0, "crlf/tab got '%s'", out);
}

static void test_escape_control_uXXXX(void) {
    char out[64];
    /* 0x01 has no short escape -> \u0001 */
    int n = atlog_json_escape("\x01", 1, out, sizeof(out));
    CHECK(n == 6, "control escape wrote %d", n);
    CHECK(strcmp(out, "\\u0001") == 0, "control got '%s'", out);
}

static void test_escape_slash_and_highbyte_passthrough(void) {
    char out[64];
    /* '/' is NOT escaped in JSON; UTF-8 high bytes pass through. */
    int n = atlog_json_escape("a/b\xc3\xa9", 5, out, sizeof(out));
    CHECK(n == 5, "passthrough wrote %d", n);
    CHECK(strcmp(out, "a/b\xc3\xa9") == 0, "passthrough got '%s'", out);
}

static void test_escape_overflow(void) {
    char out[4];
    int n = atlog_json_escape("\"\"\"\"", 4, out, sizeof(out));  /* each -> 2 bytes */
    CHECK(n == -1, "escape overflow should return -1, got %d", n);
}

/* ---- record formatting (schema aligned with the AT-poll correlator) ---- */

static void test_format_record_err_null(void) {
    char out[512];
    int r = atlog_format_record(out, sizeof(out),
                                1234567890123456789ULL,
                                "2026-07-17T18:19:20.500000Z",
                                "AT+QENG=\"servingcell\"",
                                "+QENG: \"LTE\"\r\nOK\r\n",
                                12.34, NULL, 0, 0, 0);
    CHECK(r == 0, "format returned %d", r);
    /* Trailing newline present. */
    size_t L = strlen(out);
    CHECK(L > 0 && out[L - 1] == '\n', "no trailing newline: '%s'", out);
    /* All six keys present, in the documented order, err as bare null. */
    CHECK(strstr(out, "\"ts_mono_ns\": 1234567890123456789") != NULL,
          "ts_mono_ns missing/wrong: %s", out);
    CHECK(strstr(out, "\"ts_utc\": \"2026-07-17T18:19:20.500000Z\"") != NULL,
          "ts_utc missing: %s", out);
    CHECK(strstr(out, "\"cmd\": \"AT+QENG=\\\"servingcell\\\"\"") != NULL,
          "cmd not escaped: %s", out);
    CHECK(strstr(out, "\"response\": \"+QENG: \\\"LTE\\\"\\r\\nOK\\r\\n\"") != NULL,
          "response not escaped: %s", out);
    CHECK(strstr(out, "\"duration_ms\": 12.34") != NULL,
          "duration_ms missing/wrong: %s", out);
    CHECK(strstr(out, "\"err\": null") != NULL, "err should be null: %s", out);
}

static void test_format_record_err_string(void) {
    char out[512];
    int r = atlog_format_record(out, sizeof(out), 1ULL,
                                "2026-07-17T18:19:20.000000Z",
                                "AT+COPS=?", "", 30000.00, "timeout",
                                0, 0, 0);
    CHECK(r == 0, "format(err) returned %d", r);
    CHECK(strstr(out, "\"err\": \"timeout\"") != NULL,
          "err string missing: %s", out);
    CHECK(strstr(out, "\"response\": \"\"") != NULL,
          "empty response missing: %s", out);
}

static void test_format_record_overflow(void) {
    char out[16];
    int r = atlog_format_record(out, sizeof(out), 1ULL, "t", "cmd",
                                "response", 1.0, NULL, 0, 0, 0);
    CHECK(r == -1, "format overflow should return -1, got %d", r);
}

/* ---- the exchange's inner instants ---- */

/* The WHOLE line, byte for byte. Substring checks cannot see order, and order
 * is the contract: kismetdb_to_atlog reproduces this line verbatim, and a
 * reader of an older record must find every key it knows where it was. So the
 * six original keys come first, unchanged, and the three instants follow. */
static void test_format_record_timing_exact_line(void) {
    char out[512];
    int r = atlog_format_record(out, sizeof(out),
                                1000ULL, "2026-09-23T13:00:00.000001Z",
                                "AT+QENG=\"servingcell\"", "+QENG: 1\nOK",
                                250.5, NULL,
                                1100ULL, 150001100ULL, 250001100ULL);
    CHECK(r == 0, "format(timing) returned %d", r);
    const char *want =
        "{\"ts_mono_ns\": 1000, \"ts_utc\": \"2026-09-23T13:00:00.000001Z\", "
        "\"cmd\": \"AT+QENG=\\\"servingcell\\\"\", \"response\": \"+QENG: 1\\nOK\", "
        "\"duration_ms\": 250.50, \"err\": null, "
        "\"tx_done_ns\": 1100, \"first_rx_ns\": 150001100, "
        "\"rx_done_ns\": 250001100}\n";
    CHECK(strcmp(out, want) == 0, "timing line mismatch:\n got: %s want: %s", out, want);
}

/* 0 is "never reached" and is written as null, never as the number 0 -- a 0
 * would read as an instant at boot and subtract into a huge bogus interval.
 * Mixed: a timeout sent the command and got a line, but no terminator. */
static void test_format_record_timing_nulls(void) {
    char out[512];
    int r = atlog_format_record(out, sizeof(out), 7ULL, "t", "AT+COPS=?",
                                "+COPS: (1)", 3000.0, NULL, 8ULL, 9ULL, 0ULL);
    CHECK(r == 0, "format(timeout) returned %d", r);
    CHECK(strstr(out, "\"err\": null, \"tx_done_ns\": 8, \"first_rx_ns\": 9, "
                      "\"rx_done_ns\": null}\n") != NULL,
          "timeout tail wrong: %s", out);

    r = atlog_format_record(out, sizeof(out), 7ULL, "t", "AT", "", 1.0,
                            "no response (timeout or I/O error)", 0, 0, 0);
    CHECK(r == 0, "format(all null) returned %d", r);
    CHECK(strstr(out, "\"err\": \"no response (timeout or I/O error)\", "
                      "\"tx_done_ns\": null, \"first_rx_ns\": null, "
                      "\"rx_done_ns\": null}\n") != NULL,
          "all-null tail wrong: %s", out);
}

/* A record whose first six keys fit but whose instants do not is dropped
 * (-1), never cut off after "err" -- a truncated line is still a JSON prefix
 * of nothing, and a counted drop is the documented overflow contract. */
static void test_format_record_timing_overflow(void) {
    char probe[512];
    int r = atlog_format_record(probe, sizeof(probe), 1ULL, "t", "AT", "OK",
                                1.0, NULL, 0, 0, 0);
    CHECK(r == 0, "probe format returned %d", r);
    /* Everything up to and including the err value, plus a byte: room for the
     * old record's body but not for the instants. */
    size_t upto_err = (size_t)(strstr(probe, "\"err\": null") - probe) + strlen("\"err\": null");
    char small[512];
    r = atlog_format_record(small, upto_err + 3, 1ULL, "t", "AT", "OK",
                            1.0, NULL, 111ULL, 222ULL, 333ULL);
    CHECK(r == -1, "overflow in the instants should return -1, got %d", r);
}

int main(void) {
    test_escape_plain();
    test_escape_quote_and_backslash();
    test_escape_crlf_tab();
    test_escape_control_uXXXX();
    test_escape_slash_and_highbyte_passthrough();
    test_escape_overflow();

    test_format_record_err_null();
    test_format_record_err_string();
    test_format_record_overflow();
    test_format_record_timing_exact_line();
    test_format_record_timing_nulls();
    test_format_record_timing_overflow();

    if (failures) {
        fprintf(stderr, "test_atlog: %d FAILURE(S)\n", failures);
        return 1;
    }
    printf("test_atlog: all tests passed\n");
    return 0;
}

#endif /* CELL_SELFTEST */
