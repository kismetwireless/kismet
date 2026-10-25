/* test_diag_capmeta.c - standalone unit tests for the capture_meta sidecar core.
 *
 * Links only diag_capmeta.c (libc, no Kismet), so it runs off the capture
 * framework: `make -f standalone.mk check` in this directory. Covers the three
 * pieces with real branching logic - sidecar path derivation
 * (diag_capmeta_sidecar_path / _basename), JSON escaping
 * (diag_capmeta_json_escape) and the whole-object formatter
 * (diag_capmeta_format) - plus the one-shot write round-trip.
 */

#include "diag_capmeta.h"

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

/* A fixed, known instant so host_utc_start is deterministic: 2026-09-20T17:00:00Z. */
static time_t fixed_now(void) {
    struct tm tmv;
    memset(&tmv, 0, sizeof(tmv));
    tmv.tm_year = 2026 - 1900;
    tmv.tm_mon  = 9 - 1;
    tmv.tm_mday = 20;
    tmv.tm_hour = 17;
    tmv.tm_min  = 0;
    tmv.tm_sec  = 0;
    return timegm(&tmv);
}

/* ---- sidecar path derivation ---- */

static void test_sidecar_path_appends_suffix(void) {
    char out[256];
    int r = diag_capmeta_sidecar_path(
        "/cap/celldiag-123456789012345-20260920T170000Z.hdlc",
        out, sizeof(out));
    CHECK(r == 0, "sidecar_path returned %d", r);
    CHECK(strcmp(out,
        "/cap/celldiag-123456789012345-20260920T170000Z.hdlc.capture_meta.json")
        == 0, "sidecar path got '%s'", out);
}

static void test_sidecar_path_not_a_capture_meta_glob(void) {
    /* The sidecar basename must NOT start with "capture_meta_" -- that is the
     * prefix an attribution-file glob matches, and this file is provenance,
     * not attribution. */
    char out[256];
    diag_capmeta_sidecar_path("/cap/celldiag-x-t.hdlc", out, sizeof(out));
    const char *base = diag_capmeta_basename(out);
    CHECK(strncmp(base, "capture_meta_", 13) != 0,
          "sidecar basename '%s' collides with the capture_meta_*.json glob", base);
    CHECK(strcmp(base, "celldiag-x-t.hdlc.capture_meta.json") == 0,
          "sidecar basename got '%s'", base);
}

static void test_sidecar_path_overflow(void) {
    char out[8];
    int r = diag_capmeta_sidecar_path("/cap/x.hdlc", out, sizeof(out));
    CHECK(r == -1, "overflow should return -1, got %d", r);
}

static void test_sidecar_path_null(void) {
    char out[64];
    CHECK(diag_capmeta_sidecar_path(NULL, out, sizeof(out)) == -1,
          "NULL rawlog_path should return -1");
}

static void test_basename(void) {
    CHECK(strcmp(diag_capmeta_basename("/a/b/c.hdlc"), "c.hdlc") == 0,
          "basename of nested path");
    CHECK(strcmp(diag_capmeta_basename("bare.hdlc"), "bare.hdlc") == 0,
          "basename of bare name");
    CHECK(strcmp(diag_capmeta_basename(NULL), "") == 0, "basename of NULL");
}

/* ---- JSON escaping ---- */

static void test_escape_short_and_unicode(void) {
    char out[64];
    /* quote, backslash, newline -> short escapes; 0x01 -> \u0001; '/' passes. */
    const char in[] = { '"', '\\', '\n', 0x01, '/', '\0' };
    int n = diag_capmeta_json_escape(in, 5, out, sizeof(out));
    CHECK(n > 0, "escape returned %d", n);
    CHECK(strcmp(out, "\\\"\\\\\\n\\u0001/") == 0, "escape got '%s'", out);
}

static void test_escape_null_src(void) {
    char out[8];
    int n = diag_capmeta_json_escape(NULL, 0, out, sizeof(out));
    CHECK(n == 0 && out[0] == '\0', "NULL src escapes to empty (n=%d)", n);
}

/* ---- whole-object formatting ---- */

static void test_format_golden(void) {
    char out[512];
    int r = diag_capmeta_format(out, sizeof(out), fixed_now(),
                                "123456789012345", "RM520NGLAAR03A03M4G",
                                "RM520NGLAAR03A03M4G", "Quectel", "RM520N-GL",
                                "at", "wardrive",
                                "all+norelay", "/dev/mhi_DIAG",
                                "celldiag-123456789012345-20260920T170000Z.hdlc");
    CHECK(r == 0, "format returned %d", r);
    const char *expect =
        "{\"schema\": \"celldiag-capmeta/1\", "
        "\"host_utc_start\": \"2026-09-20T17:00:00Z\", "
        "\"imei\": \"123456789012345\", "
        "\"model\": \"RM520NGLAAR03A03M4G\", "
        "\"firmware\": \"RM520NGLAAR03A03M4G\", "
        "\"make\": \"Quectel\", "
        "\"product_model\": \"RM520N-GL\", "
        "\"identity\": \"at\", "
        "\"mask_preset\": \"wardrive\", "
        "\"f3_preset\": \"all+norelay\", "
        "\"diag_node\": \"/dev/mhi_DIAG\", "
        "\"rawlog\": \"celldiag-123456789012345-20260920T170000Z.hdlc\"}\n";
    CHECK(strcmp(out, expect) == 0, "format got:\n%s", out);
}

static void test_format_null_fields_are_empty_strings(void) {
    /* A replay/opening source has no diag_node / firmware yet; NULL -> "". */
    char out[512];
    int r = diag_capmeta_format(out, sizeof(out), fixed_now(),
                                "123456789012345", "DIAG replay",
                                NULL, NULL, NULL, NULL, "replay", "off", NULL,
                                "celldiag-x.hdlc");
    CHECK(r == 0, "format(NULLs) returned %d", r);
    CHECK(strstr(out, "\"firmware\": \"\"") != NULL, "NULL firmware -> \"\"");
    CHECK(strstr(out, "\"identity\": \"\"") != NULL, "NULL identity -> \"\"");
    /* A bring-up that read no AT identity has no make/model either. */
    CHECK(strstr(out, "\"make\": \"\"") != NULL, "NULL make -> \"\"");
    CHECK(strstr(out, "\"product_model\": \"\"") != NULL, "NULL product_model -> \"\"");
    CHECK(strstr(out, "\"diag_node\": \"\"") != NULL, "NULL diag_node -> \"\"");
}

static void test_format_escapes_hostile_field(void) {
    /* A firmware string carrying a quote must not break the JSON. */
    char out[512];
    int r = diag_capmeta_format(out, sizeof(out), fixed_now(),
                                "123456789012345", "mo\"del", "fw\\1",
                                "Sierra Wireless, Incorporated", "EM\"9190",
                                "unresolved-held-by-sibling", "wardrive", "all", "/dev/ttyUSB2",
                                "r.hdlc");
    CHECK(r == 0, "format(hostile) returned %d", r);
    CHECK(strstr(out, "\"model\": \"mo\\\"del\"") != NULL, "quote escaped");
    CHECK(strstr(out, "\"firmware\": \"fw\\\\1\"") != NULL, "backslash escaped");
    CHECK(strstr(out, "\"make\": \"Sierra Wireless, Incorporated\"") != NULL,
          "a make with a comma survives verbatim");
    CHECK(strstr(out, "\"product_model\": \"EM\\\"9190\"") != NULL,
          "product_model escaped");
    /* The unresolved marker a reader keys on, spelled as the header says. */
    CHECK(strstr(out, "\"identity\": \"" DIAG_CAPMETA_IDENTITY_HELD "\"") != NULL,
          "identity marker");
}

static void test_format_overflow(void) {
    char out[16];
    int r = diag_capmeta_format(out, sizeof(out), fixed_now(),
                                "123456789012345", "m", "f", "k", "p", "at",
                                "wardrive", "all", "/dev/x", "r.hdlc");
    CHECK(r == -1, "overflow should return -1, got %d", r);
}

/* ---- one-shot write round-trip ---- */

static void test_write_roundtrip(void) {
    char path[] = "/tmp/diag_capmeta_test_XXXXXX";
    int fd = mkstemp(path);
    CHECK(fd >= 0, "mkstemp failed");
    if (fd >= 0)
        close(fd);

    char rec[512];
    diag_capmeta_format(rec, sizeof(rec), fixed_now(), "123456789012345",
                        "m", "f", "k", "p", "at", "wardrive", "all", "/dev/mhi_DIAG",
                        "r.hdlc");
    int w = diag_capmeta_write(path, rec, strlen(rec));
    CHECK(w == 0, "write returned %d", w);

    FILE *f = fopen(path, "rb");
    CHECK(f != NULL, "reopen failed");
    if (f) {
        char back[512] = {0};
        size_t got = fread(back, 1, sizeof(back) - 1, f);
        fclose(f);
        CHECK(got == strlen(rec), "read %zu bytes, wrote %zu", got, strlen(rec));
        CHECK(strcmp(back, rec) == 0, "round-trip mismatch");
    }
    unlink(path);
}

int main(void) {
    test_sidecar_path_appends_suffix();
    test_sidecar_path_not_a_capture_meta_glob();
    test_sidecar_path_overflow();
    test_sidecar_path_null();
    test_basename();
    test_escape_short_and_unicode();
    test_escape_null_src();
    test_format_golden();
    test_format_null_fields_are_empty_strings();
    test_format_escapes_hostile_field();
    test_format_overflow();
    test_write_roundtrip();

    if (failures == 0) {
        printf("PASS: all diag_capmeta tests\n");
        return 0;
    }
    fprintf(stderr, "FAILED: %d diag_capmeta test check(s)\n", failures);
    return 1;
}
