/* test_diag_clockanchor.c - standalone unit tests for the DIAG clock anchor.
 *
 * Links diag_clockanchor.c + its two libc-only dependencies (diag_hdlc.c,
 * diag_capmeta.c) and nothing else: `make -f standalone.mk check`. Covers the
 * request frame, the reply scanner (split reads, stuffed bytes, interleaved
 * flood, partial in-flight frame, rejection, CRC failure), the midpoint, the
 * record's exact bytes, and the sidecar path + append.
 */

#include "diag_clockanchor.h"
#include "diag_hdlc.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
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

/* A reply frame for `ts64`, built with the same builder the modem side of the
 * wire uses (diag_hdlc_build == escape(cmd||body||crc)||0x7E). */
static size_t reply_frame(uint64_t ts64, uint8_t *out, size_t cap) {
    uint8_t body[8];
    for (int i = 0; i < 8; i++)
        body[i] = (uint8_t)(ts64 >> (8 * i));
    return diag_hdlc_build(DIAG_TS_F_OPCODE, body, sizeof(body), out, cap);
}

/* ---- request ---- */

static void test_request_frame_bytes(void) {
    uint8_t f[16];
    size_t n = diag_clockanchor_build_request(f, sizeof(f));
    uint16_t crc = diag_hdlc_crc16((const uint8_t *)"\x1d", 1);
    CHECK(n == 4, "request length %zu, want 4 (opcode + crc16 + 0x7E)", n);
    CHECK(f[0] == 0x1D, "opcode 0x%02x", f[0]);
    CHECK(f[1] == (crc & 0xFF) && f[2] == (crc >> 8), "crc bytes %02x %02x", f[1], f[2]);
    CHECK(f[3] == 0x7E, "terminator 0x%02x", f[3]);
}

/* ---- scanner ---- */

/* A ts64 whose bytes include BOTH HDLC specials, so the reply is stuffed. */
#define STUFFED_TS64 0x01827E7D7E5D5E00ULL

static void test_scan_whole_reply(void) {
    uint8_t f[64];
    size_t n = reply_frame(0x0123456789ABCDEFULL, f, sizeof(f));
    diag_tsf_scan_t s;
    uint64_t v = 0;
    diag_tsf_scan_reset(&s);
    CHECK(diag_tsf_scan_feed(&s, f, n, &v) == DIAG_TSF_RESPONSE, "no response");
    CHECK(v == 0x0123456789ABCDEFULL, "ts64 0x%016llx", (unsigned long long)v);
}

static void test_scan_stuffed_reply_byte_by_byte(void) {
    uint8_t f[64];
    size_t n = reply_frame(STUFFED_TS64, f, sizeof(f));
    diag_tsf_scan_t s;
    uint64_t v = 0;
    diag_tsf_result_t r = DIAG_TSF_NONE;
    CHECK(n > 12, "stuffed frame should be longer than 12, got %zu", n);
    diag_tsf_scan_reset(&s);
    /* One byte per feed: the reply split at EVERY possible read boundary,
     * including between an 0x7D escape and the byte it escapes. */
    for (size_t i = 0; i < n; i++) {
        r = diag_tsf_scan_feed(&s, f + i, 1, &v);
        if (i + 1 < n)
            CHECK(r == DIAG_TSF_NONE, "early result %d at byte %zu", r, i);
    }
    CHECK(r == DIAG_TSF_RESPONSE, "no response after the last byte");
    CHECK(v == STUFFED_TS64, "ts64 0x%016llx", (unsigned long long)v);
}

static void test_scan_ignores_partial_in_flight_prefix(void) {
    /* The request went out mid-frame: the first bytes seen are the TAIL of a
     * frame that began earlier. That tail must not be mistaken for anything,
     * and must not stop the real reply behind it. */
    uint8_t stream[128];
    size_t off = 0;
    const uint8_t tail[] = { 0x1D, 0x44, 0x55, 0x66, 0x77, 0x88, 0x99, 0xAA,
                             0xBB, 0xCC, 0xDD, 0x7E };
    memcpy(stream, tail, sizeof(tail));
    off += sizeof(tail);
    off += reply_frame(42, stream + off, sizeof(stream) - off);
    diag_tsf_scan_t s;
    uint64_t v = 0;
    diag_tsf_scan_reset(&s);
    CHECK(diag_tsf_scan_feed(&s, stream, off, &v) == DIAG_TSF_RESPONSE, "no response");
    CHECK(v == 42, "ts64 %llu", (unsigned long long)v);
}

static void test_scan_finds_reply_in_a_log_flood(void) {
    /* Long LOG_F frames on either side, carrying 0x1D and escape bytes. */
    uint8_t stream[4096];
    uint8_t logbody[200];
    size_t off = 0;
    for (size_t i = 0; i < sizeof(logbody); i++)
        logbody[i] = (uint8_t)(i % 3 == 0 ? 0x1D : (i % 3 == 1 ? 0x7E : 0x7D));
    off += diag_hdlc_build(0x10, logbody, sizeof(logbody), stream + off, sizeof(stream) - off);
    off += diag_hdlc_build(0x10, logbody, sizeof(logbody), stream + off, sizeof(stream) - off);
    off += reply_frame(STUFFED_TS64, stream + off, sizeof(stream) - off);
    off += diag_hdlc_build(0x10, logbody, sizeof(logbody), stream + off, sizeof(stream) - off);
    diag_tsf_scan_t s;
    uint64_t v = 0;
    diag_tsf_scan_reset(&s);
    CHECK(diag_tsf_scan_feed(&s, stream, off, &v) == DIAG_TSF_RESPONSE, "no response");
    CHECK(v == STUFFED_TS64, "ts64 0x%016llx", (unsigned long long)v);
}

static void test_scan_rejects_bad_crc(void) {
    uint8_t f[64];
    size_t n = reply_frame(7, f, sizeof(f));
    f[3] ^= 0x01;                         /* corrupt a ts64 byte */
    diag_tsf_scan_t s;
    uint64_t v = 0xDEAD;
    diag_tsf_scan_reset(&s);
    CHECK(diag_tsf_scan_feed(&s, f, n, &v) == DIAG_TSF_NONE, "bad CRC accepted");
    CHECK(v == 0xDEAD, "ts64 written on a bad frame");
}

static void test_scan_other_opcodes_are_not_replies(void) {
    uint8_t f[64];
    uint8_t body[8] = { 1, 2, 3, 4, 5, 6, 7, 8 };
    size_t n = diag_hdlc_build(0x1C, body, sizeof(body), f, sizeof(f));
    diag_tsf_scan_t s;
    uint64_t v = 0;
    diag_tsf_scan_reset(&s);
    CHECK(diag_tsf_scan_feed(&s, f, n, &v) == DIAG_TSF_NONE, "0x1C frame taken as TS_F");
}

static void test_scan_detects_rejection(void) {
    uint8_t f[16];
    const uint8_t echo[] = { 0x1D };
    size_t n = diag_hdlc_build(0x13, echo, sizeof(echo), f, sizeof(f));
    diag_tsf_scan_t s;
    diag_tsf_scan_reset(&s);
    CHECK(diag_tsf_scan_feed(&s, f, n, NULL) == DIAG_TSF_REJECTED, "BAD_CMD 0x1D not seen");

    /* A BAD_CMD for some OTHER command is not our rejection. */
    const uint8_t other[] = { 0x60 };
    n = diag_hdlc_build(0x13, other, sizeof(other), f, sizeof(f));
    diag_tsf_scan_reset(&s);
    CHECK(diag_tsf_scan_feed(&s, f, n, NULL) == DIAG_TSF_NONE, "foreign BAD_CMD taken as ours");
}

static void test_scan_short_reply_is_not_a_response(void) {
    uint8_t f[16];
    const uint8_t body[] = { 1, 2, 3 };   /* 0x1D + 3 bytes: not a timestamp */
    size_t n = diag_hdlc_build(0x1D, body, sizeof(body), f, sizeof(f));
    diag_tsf_scan_t s;
    diag_tsf_scan_reset(&s);
    CHECK(diag_tsf_scan_feed(&s, f, n, NULL) == DIAG_TSF_NONE, "4-byte 0x1D taken as reply");
}

/* ---- midpoint ---- */

static void test_midpoint_adds_half_the_monotonic_window(void) {
    struct timeval send = { .tv_sec = 1000, .tv_usec = 999000 };
    struct timeval mid;
    uint64_t mono_mid = 0;
    /* 4 ms window -> +2 ms, carrying into the next second. */
    diag_clockanchor_midpoint(&send, 5000000000ULL, 5004000000ULL, &mid, &mono_mid);
    CHECK(mid.tv_sec == 1001 && mid.tv_usec == 1000, "mid %ld.%06ld",
          (long)mid.tv_sec, (long)mid.tv_usec);
    CHECK(mono_mid == 5002000000ULL, "mono_mid %llu", (unsigned long long)mono_mid);
}

static void test_midpoint_backwards_mono_is_zero_window(void) {
    struct timeval send = { .tv_sec = 5, .tv_usec = 10 };
    struct timeval mid;
    uint64_t mono_mid = 0;
    diag_clockanchor_midpoint(&send, 100, 50, &mid, &mono_mid);
    CHECK(mid.tv_sec == 5 && mid.tv_usec == 10, "backwards mono moved the stamp");
    CHECK(mono_mid == 100, "mono_mid %llu", (unsigned long long)mono_mid);
}

/* ---- record ---- */

static void test_record_exact_bytes(void) {
    char rec[768];
    int r = diag_clockanchor_format_record(
        rec, sizeof(rec), "5FE308BD-0000-0000-0000-123456789012", 3, "periodic",
        "2026-09-22T12:00:00.123456Z", 987654321ULL, 77012345678901234ULL,
        3500000ULL);
    CHECK(r == 0, "format returned %d", r);
    const char *want =
        "{\"schema\": \"clock-anchor/1\", \"transport\": \"diag\", "
        "\"source_name\": \"5FE308BD-0000-0000-0000-123456789012\", \"seq\": 3, "
        "\"edge\": \"periodic\", \"host_utc\": \"2026-09-22T12:00:00.123456Z\", "
        "\"host_mono_ns\": 987654321, \"source_clock_kind\": \"modem_ts64\", "
        "\"source_clock_value\": \"77012345678901234\", \"host_rtt_ns\": 3500000}\n";
    CHECK(strcmp(rec, want) == 0, "record\n got: %s\nwant: %s", rec, want);
}

static void test_record_escapes_and_null(void) {
    char rec[768];
    int r = diag_clockanchor_format_record(rec, sizeof(rec), "a\"b\\c", 0, NULL,
                                           "t", 0, 0, 0);
    CHECK(r == 0, "format returned %d", r);
    CHECK(strstr(rec, "\"source_name\": \"a\\\"b\\\\c\"") != NULL, "not escaped: %s", rec);
    CHECK(strstr(rec, "\"edge\": \"\"") != NULL, "NULL edge not \"\": %s", rec);
}

static void test_record_overflow(void) {
    char rec[40];
    CHECK(diag_clockanchor_format_record(rec, sizeof(rec), "x", 0, "start", "t",
                                         0, 0, 0) == -1, "overflow not reported");
    CHECK(rec[0] == '\0', "overflow left a partial record");
}

static void test_iso8601_matches_cellat_format(void) {
    char out[40];
    struct timeval tv = { .tv_sec = 1790000000, .tv_usec = 42 };  /* 2026-09-21 */
    diag_clockanchor_iso8601(out, sizeof(out), &tv);
    CHECK(strcmp(out, "2026-09-21T14:13:20.000042Z") == 0, "iso '%s'", out);
}

/* ---- sidecar ---- */

static void test_sidecar_path(void) {
    char out[128];
    CHECK(diag_clockanchor_sidecar_path("/cap/celldiag-1-2.hdlc", out, sizeof(out)) == 0,
          "path failed");
    CHECK(strcmp(out, "/cap/celldiag-1-2.hdlc.clock_anchor.jsonl") == 0, "path '%s'", out);
    CHECK(diag_clockanchor_sidecar_path("/cap/x.hdlc", out, 8) == -1, "overflow not -1");
    CHECK(diag_clockanchor_sidecar_path(NULL, out, sizeof(out)) == -1, "NULL not -1");
}

static void test_append_accumulates_lines(void) {
    char path[] = "/tmp/test_diag_clockanchor_XXXXXX";
    int fd = mkstemp(path);
    CHECK(fd >= 0, "mkstemp");
    if (fd < 0)
        return;
    close(fd);
    CHECK(diag_clockanchor_append(path, "one\n", 4) == 0, "append 1");
    CHECK(diag_clockanchor_append(path, "two\n", 4) == 0, "append 2");
    FILE *f = fopen(path, "r");
    char buf[32] = { 0 };
    size_t n = f ? fread(buf, 1, sizeof(buf) - 1, f) : 0;
    if (f)
        fclose(f);
    CHECK(n == 8 && strcmp(buf, "one\ntwo\n") == 0, "sidecar holds '%s'", buf);
    unlink(path);
}

int main(void) {
    test_request_frame_bytes();
    test_scan_whole_reply();
    test_scan_stuffed_reply_byte_by_byte();
    test_scan_ignores_partial_in_flight_prefix();
    test_scan_finds_reply_in_a_log_flood();
    test_scan_rejects_bad_crc();
    test_scan_other_opcodes_are_not_replies();
    test_scan_detects_rejection();
    test_scan_short_reply_is_not_a_response();
    test_midpoint_adds_half_the_monotonic_window();
    test_midpoint_backwards_mono_is_zero_window();
    test_record_exact_bytes();
    test_record_escapes_and_null();
    test_record_overflow();
    test_iso8601_matches_cellat_format();
    test_sidecar_path();
    test_append_accumulates_lines();

    if (failures) {
        fprintf(stderr, "test_diag_clockanchor: %d FAILED\n", failures);
        return 1;
    }
    printf("test_diag_clockanchor: all checks passed\n");
    return 0;
}
