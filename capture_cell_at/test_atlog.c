/* test_atlog.c - standalone unit tests for the atlog JSONL tee core.
 *
 * Links only atlog.c (libc, no Kismet, no serial), so it runs off the capture
 * framework: `make check` in this directory. Mirrors test_diag_rawlog.c for the
 * shared path-templating property, and adds the atlog-specific surface that has
 * the real branching logic: JSON escaping (AT responses are full of CRLF,
 * quotes and control bytes) and the one-record-per-exchange formatter whose
 * schema the DIAG/AT-poll correlation tooling must ingest without a shim.
 */

#include "atlog.h"

#include <fcntl.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <time.h>
#include <unistd.h>

static int failures = 0;

#define CHECK(cond, ...) do { \
    if (!(cond)) { \
        fprintf(stderr, "FAIL %s:%d: ", __FILE__, __LINE__); \
        fprintf(stderr, __VA_ARGS__); \
        fprintf(stderr, "\n"); \
        failures++; \
    } \
} while (0)

/* A fixed, known instant so %t is deterministic: 2026-07-17T18:19:20Z. */
static time_t fixed_now(void) {
    struct tm tmv;
    memset(&tmv, 0, sizeof(tmv));
    tmv.tm_year = 2026 - 1900;
    tmv.tm_mon  = 7 - 1;
    tmv.tm_mday = 17;
    tmv.tm_hour = 18;
    tmv.tm_min  = 19;
    tmv.tm_sec  = 20;
    return timegm(&tmv);
}

/* ---- path resolution (mirrors the rawlog contract, .jsonl name) ---- */

static void test_resolve_literal(void) {
    char out[256];
    int r = atlog_resolve("/tmp/cellat.jsonl", "123456789012345",
                          "RM520N-GL", fixed_now(), out, sizeof(out));
    CHECK(r == 0, "literal resolve returned %d", r);
    CHECK(strcmp(out, "/tmp/cellat.jsonl") == 0, "literal got '%s'", out);
}

static void test_resolve_tokens(void) {
    char out[256];
    int r = atlog_resolve("/cap/%i-%t.jsonl", "123456789012345",
                          "RM520N-GL", fixed_now(), out, sizeof(out));
    CHECK(r == 0, "token resolve returned %d", r);
    CHECK(strcmp(out, "/cap/123456789012345-20260717T181920Z.jsonl") == 0,
          "tokens got '%s'", out);
}

static void test_resolve_model_sanitized(void) {
    char out[256];
    int r = atlog_resolve("/cap/%m.jsonl", "123456789012345",
                          "RM520N-GL R03A04 M/N", fixed_now(),
                          out, sizeof(out));
    CHECK(r == 0, "model resolve returned %d", r);
    CHECK(strcmp(out, "/cap/RM520N-GL_R03A04_M_N.jsonl") == 0,
          "sanitized model got '%s'", out);
}

static void test_resolve_dir_synthesizes_cellat_jsonl(void) {
    char out[256];
    /* Trailing '/' -> directory mode: synthesize cellat-<imei>-<ts>.jsonl. */
    int r = atlog_resolve("/cap/", "123456789012345", "m", fixed_now(),
                          out, sizeof(out));
    CHECK(r == 0, "dir resolve returned %d", r);
    CHECK(strcmp(out, "/cap/cellat-123456789012345-20260717T181920Z.jsonl") == 0,
          "dir synth got '%s'", out);
}

static void test_resolve_dir_imei_sanitized(void) {
    char out[256];
    /* The dir-mode auto-filename embeds the IMEI; a '/' in it must not inject
     * a separator. */
    int r = atlog_resolve("/cap/", "aa/bb", "m", fixed_now(), out, sizeof(out));
    CHECK(r == 0, "dir imei resolve returned %d", r);
    CHECK(strchr(out + 5, '/') == NULL, "no injected separator: '%s'", out);
}

static void test_resolve_overflow(void) {
    char out[8];
    int r = atlog_resolve("/a/very/long/path/that/does/not/fit.jsonl",
                          "1", "m", fixed_now(), out, sizeof(out));
    CHECK(r == -1, "overflow should return -1, got %d", r);
}

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

/* ---- whole-buffer write round-trip ---- */

static void test_write_roundtrip(void) {
    char tmpl[] = "/tmp/atlog_test_XXXXXX";
    int fd = mkstemp(tmpl);
    CHECK(fd >= 0, "mkstemp failed");
    if (fd < 0) return;

    const char *line = "{\"cmd\": \"AT\", \"err\": null}\n";
    int w = atlog_write(fd, line, strlen(line));
    CHECK(w == 0, "atlog_write returned %d", w);
    close(fd);

    FILE *f = fopen(tmpl, "rb");
    CHECK(f != NULL, "reopen failed");
    if (f) {
        char buf[128] = {0};
        size_t got = fread(buf, 1, sizeof(buf) - 1, f);
        fclose(f);
        CHECK(got == strlen(line), "read back %zu of %zu", got, strlen(line));
        CHECK(memcmp(buf, line, strlen(line)) == 0, "round-trip mismatch");
    }
    unlink(tmpl);
}

int main(void) {
    test_resolve_literal();
    test_resolve_tokens();
    test_resolve_model_sanitized();
    test_resolve_dir_synthesizes_cellat_jsonl();
    test_resolve_dir_imei_sanitized();
    test_resolve_overflow();

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

    test_write_roundtrip();

    if (failures) {
        fprintf(stderr, "test_atlog: %d FAILURE(S)\n", failures);
        return 1;
    }
    printf("test_atlog: all tests passed\n");
    return 0;
}
