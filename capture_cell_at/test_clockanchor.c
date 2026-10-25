/* test_clockanchor.c - standalone unit tests for the clock-anchor core.
 *
 * Links clockanchor.c + atlog.c (libc, no Kismet, no serial), so it runs off the
 * capture framework on a modem-less host: `make check` in this directory. The
 * real branching lives in cclk_extract() (tolerant parse of the AT+CCLK?
 * response across the firmware variants observed on real modems) and in the
 * record formatter (whose schema must match the clock-anchor/1 contract
 * field-for-field so the DIAG and AT transports produce uniform ClockAnchor
 * rows).
 */

#include "clockanchor.h"

#include <stdio.h>
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

/* ---- cclk_extract: three measured firmware response shapes ---- */

static void test_extract_quectel_synced(void) {
    /* RM520N-GL, network-synced: time field already UTC, still tagged -24. */
    const char *resp = "\r\n+CCLK: \"26/09/21,22:02:23-24\"\r\n\r\nOK\r\n";
    char out[64];
    CHECK(cclk_extract(resp, out, sizeof(out)) == 0, "extract failed");
    CHECK(strcmp(out, "26/09/21,22:02:23-24") == 0, "got '%s'", out);
}

static void test_extract_quectel_unsynced_plus(void) {
    /* EG25-G, no NITZ yet: year 80 (1980), TZ +00. */
    const char *resp = "\r\n+CCLK: \"80/01/23,23:59:54+00\"\r\n\r\nOK\r\n";
    char out[64];
    CHECK(cclk_extract(resp, out, sizeof(out)) == 0, "extract failed");
    CHECK(strcmp(out, "80/01/23,23:59:54+00") == 0, "got '%s'", out);
}

static void test_extract_telit_unsynced_minus(void) {
    /* LM960A18: negative TZ, unsynced. */
    const char *resp = "\r\n+CCLK: \"80/01/23,17:59:51-24\"\r\n\r\nOK\r\n";
    char out[64];
    CHECK(cclk_extract(resp, out, sizeof(out)) == 0, "extract failed");
    CHECK(strcmp(out, "80/01/23,17:59:51-24") == 0, "got '%s'", out);
}

static void test_extract_no_space_after_tag(void) {
    /* Some firmwares omit the space after the colon. */
    const char *resp = "+CCLK:\"25/12/31,08:00:00+04\"\r\nOK\r\n";
    char out[64];
    CHECK(cclk_extract(resp, out, sizeof(out)) == 0, "extract failed");
    CHECK(strcmp(out, "25/12/31,08:00:00+04") == 0, "got '%s'", out);
}

static void test_extract_rejects_error(void) {
    char out[64];
    CHECK(cclk_extract("\r\nERROR\r\n", out, sizeof(out)) == -1, "should reject ERROR");
    CHECK(out[0] == '\0', "out not cleared on reject");
}

static void test_extract_rejects_unquoted(void) {
    /* A +CCLK: with no quoted value is not usable. */
    char out[64];
    CHECK(cclk_extract("+CCLK: 26/09/21\r\nOK\r\n", out, sizeof(out)) == -1,
          "should reject unquoted");
}

static void test_extract_rejects_unterminated_quote(void) {
    char out[64];
    CHECK(cclk_extract("+CCLK: \"26/09/21,22:02:23-24\r\n", out, sizeof(out)) == -1,
          "should reject unterminated quote");
}

static void test_extract_null_and_empty(void) {
    char out[64];
    CHECK(cclk_extract(NULL, out, sizeof(out)) == -1, "NULL resp");
    CHECK(cclk_extract("", out, sizeof(out)) == -1, "empty resp");
}

static void test_extract_overflow(void) {
    /* Value longer than the destination -> -1, buffer left empty. */
    const char *resp = "+CCLK: \"26/09/21,22:02:23-24\"\r\n";
    char out[8];
    CHECK(cclk_extract(resp, out, sizeof(out)) == -1, "should overflow");
    CHECK(out[0] == '\0', "out not cleared on overflow");
}

/* ---- clockanchor_format_record: clock-anchor/1 schema ---- */

static void test_format_matches_contract(void) {
    char rec[768];
    int rc = clockanchor_format_record(rec, sizeof(rec),
        "at", "0abc-uuid", 7, "start",
        "2026-09-21T22:02:23.123456Z", 123456789012345ULL,
        "modem_rtc_cclk", "26/09/21,22:02:23-24");
    CHECK(rc == 0, "format failed");
    const char *want =
        "{\"schema\": \"clock-anchor/1\", \"transport\": \"at\", "
        "\"source_name\": \"0abc-uuid\", \"seq\": 7, \"edge\": \"start\", "
        "\"host_utc\": \"2026-09-21T22:02:23.123456Z\", "
        "\"host_mono_ns\": 123456789012345, "
        "\"source_clock_kind\": \"modem_rtc_cclk\", "
        "\"source_clock_value\": \"26/09/21,22:02:23-24\"}\n";
    CHECK(strcmp(rec, want) == 0, "got: %s", rec);
}

static void test_format_escapes_value(void) {
    /* A hostile/garbled modem value with a quote+backslash must not break JSON. */
    char rec[768];
    int rc = clockanchor_format_record(rec, sizeof(rec),
        "at", "s", 0, "periodic", "iso", 1,
        "modem_rtc_cclk", "a\"b\\c");
    CHECK(rc == 0, "format failed");
    CHECK(strstr(rec, "\"source_clock_value\": \"a\\\"b\\\\c\"") != NULL,
          "value not escaped: %s", rec);
}

static void test_format_null_field_is_empty_string(void) {
    char rec[768];
    int rc = clockanchor_format_record(rec, sizeof(rec),
        "at", NULL, 0, "end", "iso", 1, "modem_rtc_cclk", NULL);
    CHECK(rc == 0, "format failed");
    CHECK(strstr(rec, "\"source_name\": \"\"") != NULL, "source_name not empty: %s", rec);
    CHECK(strstr(rec, "\"source_clock_value\": \"\"") != NULL, "value not empty: %s", rec);
}

static void test_format_overflow(void) {
    char rec[16];
    int rc = clockanchor_format_record(rec, sizeof(rec),
        "at", "source", 1, "start", "iso", 1, "modem_rtc_cclk", "value");
    CHECK(rc == -1, "should overflow");
    CHECK(rec[0] == '\0', "out not cleared on overflow");
}

/* ---- the RTC-read window ---- */

static void test_format_rtt_appends_the_tenth_field(void) {
    /* The first nine fields are byte-for-byte the base record; host_rtt_ns is
     * appended last, exactly where the DIAG anchor carries it. */
    char rec[768], base[768];
    int rc = clockanchor_format_record_rtt(rec, sizeof(rec),
        "at", "0abc-uuid", 7, "start",
        "2026-09-21T22:02:23.123456Z", 123456789012345ULL,
        "modem_rtc_cclk", "26/09/21,22:02:23-24", 3900000ULL);
    CHECK(rc == 0, "format failed");
    CHECK(clockanchor_format_record(base, sizeof(base), "at", "0abc-uuid", 7,
          "start", "2026-09-21T22:02:23.123456Z", 123456789012345ULL,
          "modem_rtc_cclk", "26/09/21,22:02:23-24") == 0, "base format failed");
    size_t bl = strlen(base);                 /* ...ends with "}\n" */
    CHECK(strncmp(rec, base, bl - 2) == 0, "first nine fields differ: %s", rec);
    CHECK(strcmp(rec + bl - 2, ", \"host_rtt_ns\": 3900000}\n") == 0,
          "tail: %s", rec + bl - 2);
}

static void test_bracket_is_the_midpoint_on_both_clocks(void) {
    /* Reference pair taken before the exchange; the window opens 0.5 ms later
     * and is 300 ms wide. Midpoint = lo + 150 ms, i.e. 150.5 ms past the
     * reference on BOTH clocks -- and the wall clock carries into the second. */
    struct timeval ref = { 100, 900000 }, mid;
    uint64_t mono_mid = 0, rtt = 0;
    clockanchor_bracket(&ref, 1000000000ULL, 1000500000ULL, 1300500000ULL,
                        &mid, &mono_mid, &rtt);
    CHECK(rtt == 300000000ULL, "rtt %llu", (unsigned long long)rtt);
    CHECK(mono_mid == 1150500000ULL, "mono_mid %llu", (unsigned long long)mono_mid);
    CHECK(mid.tv_sec == 101 && mid.tv_usec == 50500,
          "wall mid %ld.%06ld", (long)mid.tv_sec, (long)mid.tv_usec);
}

static void test_bracket_degenerate_windows(void) {
    struct timeval ref = { 5, 0 }, mid;
    uint64_t mono_mid = 0, rtt = 7;
    /* hi < lo: zero-width at lo, never a wrapped u64 */
    clockanchor_bracket(&ref, 1000, 5000, 4000, &mid, &mono_mid, &rtt);
    CHECK(rtt == 0 && mono_mid == 5000, "inverted: rtt %llu mid %llu",
          (unsigned long long)rtt, (unsigned long long)mono_mid);
    /* a window before the reference keeps the reference wall clock */
    clockanchor_bracket(&ref, 9000, 1000, 3000, &mid, &mono_mid, &rtt);
    CHECK(mid.tv_sec == 5 && mid.tv_usec == 0 && mono_mid == 2000 && rtt == 2000,
          "before ref: %ld.%06ld", (long)mid.tv_sec, (long)mid.tv_usec);
}

int main(void) {
    test_extract_quectel_synced();
    test_extract_quectel_unsynced_plus();
    test_extract_telit_unsynced_minus();
    test_extract_no_space_after_tag();
    test_extract_rejects_error();
    test_extract_rejects_unquoted();
    test_extract_rejects_unterminated_quote();
    test_extract_null_and_empty();
    test_extract_overflow();

    test_format_matches_contract();
    test_format_escapes_value();
    test_format_null_field_is_empty_string();
    test_format_overflow();

    test_format_rtt_appends_the_tenth_field();
    test_bracket_is_the_midpoint_on_both_clocks();
    test_bracket_degenerate_windows();

    if (failures) {
        fprintf(stderr, "test_clockanchor: %d FAILURE(S)\n", failures);
        return 1;
    }
    printf("test_clockanchor: all tests passed\n");
    return 0;
}
