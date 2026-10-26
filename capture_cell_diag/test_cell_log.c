/* test_cell_log.c - standalone tests for the CellLog record (cell_log.h).
 *
 * Links only cell_log.c (libc, no Kismet).
 */

#ifdef CELL_SELFTEST

#include "cell_log.h"

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

static const struct timeval TV = { 1790000000, 123456 };   /* 2026-09-21T14:13:20 */

static void test_session(void) {
    char out[1024];
    cell_log_kv_t kv[] = {
        { "diag_node", "/dev/ttyUSB0" },
        { "imei",      "" },            /* omitted */
        { "make",      NULL },          /* omitted */
        { "f3_preset", "all+norelay" },
    };

    CHECK(cell_log_session_json(out, sizeof(out), "celldiag", &TV, 42, kv, 4) == 0,
          "session formats");
    CHECK(strcmp(out,
                 "{\"schema\":\"cell-log/1\",\"src\":\"celldiag\",\"kind\":\"session\","
                 "\"ts_utc\":\"2026-09-21T14:13:20.123456Z\",\"ts_mono_ns\":42,"
                 "\"diag_node\":\"/dev/ttyUSB0\",\"f3_preset\":\"all+norelay\"}") == 0,
          "session golden: %s", out);

    CHECK(cell_log_session_json(out, 40, "celldiag", &TV, 42, kv, 4) == -1 && out[0] == '\0',
          "session overflow fails empty");
    CHECK(cell_log_session_json(out, sizeof(out), NULL, &TV, 0, kv, 4) == -1,
          "session needs src");
    CHECK(cell_log_session_json(out, sizeof(out), "cellat", &TV, 0, NULL, 1) == -1,
          "session rejects NULL kv with a count");
}

static void test_entry(void) {
    char out[512];

    CHECK(cell_log_entry_json(out, sizeof(out), "cellat", &TV, 7, "RX-DROP",
                              "+CEREG: 1\r\n\"x\"\\", 15) == 0, "entry formats");
    CHECK(strcmp(out,
                 "{\"schema\":\"cell-log/1\",\"src\":\"cellat\",\"kind\":\"log\","
                 "\"ts_utc\":\"2026-09-21T14:13:20.123456Z\",\"ts_mono_ns\":7,"
                 "\"dir\":\"RX-DROP\",\"text\":\"+CEREG: 1\\r\\n\\\"x\\\"\\\\\"}") == 0,
          "entry golden: %s", out);

    /* Control and high bytes are escaped, so the record stays valid JSON. */
    const char bin[] = { 'a', 0x01, (char)0xff, 0x00, 'b' };
    CHECK(cell_log_entry_json(out, sizeof(out), "cellat", &TV, 7, "RX", bin, 5) == 0,
          "binary entry formats");
    CHECK(strstr(out, "\"text\":\"a\\u0001\\u00ff\\u0000b\"}") != NULL,
          "binary escaped: %s", out);

    /* A long text is cut to fit, and says how long it was. */
    char big[2000];
    memset(big, 'z', sizeof(big));
    CHECK(cell_log_entry_json(out, sizeof(out), "celldiag", &TV, 1, "RX", big,
                              sizeof(big)) == 0, "long entry fits by cutting");
    CHECK(strlen(out) < sizeof(out), "cut entry within buffer");
    CHECK(strstr(out, "\",\"text_len\":2000}") != NULL, "cut entry has text_len: %s", out);

    /* Escapes are never split. */
    char quotes[400];
    memset(quotes, '"', sizeof(quotes));
    CHECK(cell_log_entry_json(out, sizeof(out), "celldiag", &TV, 1, "RX", quotes,
                              sizeof(quotes)) == 0, "quoted entry fits by cutting");
    char *t = strstr(out, "\"text\":\"");
    CHECK(t != NULL, "text present");
    if (t != NULL) {
        char *end = strstr(t, "\",\"text_len\"");
        CHECK(end != NULL && ((end - (t + 8)) % 2) == 0, "whole escapes only");
    }

    CHECK(cell_log_entry_json(out, 60, "celldiag", &TV, 1, "RX", "x", 1) == -1,
          "too small for the fixed fields fails");
    CHECK(cell_log_entry_json(out, sizeof(out), "cellat", &TV, 1, "note", NULL, 0) == 0 &&
          strstr(out, "\"text\":\"\"}") != NULL, "empty text");

    char *row = malloc(CELL_LOG_ROW_MAX);
    char *huge = malloc(65536);
    if (row != NULL && huge != NULL) {
        memset(huge, 0x02, 65536);
        CHECK(cell_log_entry_json(row, CELL_LOG_ROW_MAX, "celldiag", &TV, 1, "RX",
                                  huge, 65536) == 0 && strlen(row) < CELL_LOG_ROW_MAX,
              "worst-case escape stays within one row");
    }
    free(row);
    free(huge);
}

static void test_hex(void) {
    const uint8_t b[] = { 0x73, 0x00, 0xab, 0xff };
    char out[16];

    CHECK(cell_log_hex(b, 4, out, sizeof(out)) == 4 && strcmp(out, "7300abff") == 0,
          "hex: %s", out);
    CHECK(cell_log_hex(b, 4, out, 6) == 2 && strcmp(out, "7300") == 0,
          "hex stops at a whole byte: %s", out);
    CHECK(cell_log_hex(b, 4, out, 1) == 0 && out[0] == '\0', "hex in 1 byte");
    CHECK(cell_log_hex(NULL, 4, out, sizeof(out)) == 0 && out[0] == '\0', "hex NULL");
}

int main(void) {
    test_session();
    test_entry();
    test_hex();
    if (failures) {
        fprintf(stderr, "test_cell_log: %d failure(s)\n", failures);
        return 1;
    }
    printf("test_cell_log: all checks passed\n");
    return 0;
}

#endif /* CELL_SELFTEST */
