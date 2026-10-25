/* test_diag_inventory.c - standalone tests for the native census.
 *
 * Links diag_inventory.c (libc + libm only).
 *
 * Two modes:
 *
 *   ./test_diag_inventory            the selftest: the counting rules, the
 *                                    bounds, the cadence, and pinned golden
 *                                    wire lines.
 *   ./test_diag_inventory --trace    a trace driver, for a differential test
 *                                    of the census against another
 *                                    implementation fed the same records
 *                                    (celltools/tests/test_celldiag_native_census.py
 *                                    drives it). Reads one command per stdin line:
 *                                      C <max_codes> <max_versions_per_code>
 *                                      N              (arm native coverage)
 *                                      U <code> <ver> (an undecoded record)
 *                                      R <code> <ver> <decoded> <emitted> <enrich_failed>
 *                                      W <now>
 *                                    and prints the wire line for each W.
 *
 * Each golden below is pinned byte for byte, and the record sequence that
 * produces it is written out beside it (record(code, ver, decoded, ...,
 * emitted=, enrich_failed=), then the wire line at `now`).
 */

#include "diag_inventory.h"

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

static void check_wire(diag_inventory_t *inv, double now, const char *want) {
    char buf[DIAG_INVENTORY_LINE_MAX];
    int n = diag_inventory_wire(inv, now, buf, sizeof(buf));
    CHECK(n >= 0 && (size_t)n < sizeof(buf), "wire rendered %d bytes", n);
    CHECK(strcmp(buf, want) == 0, "wire line mismatch\n  got:  %s\n  want: %s",
          buf, want);
}

/* An empty census still renders every key -- "0 keys" is a reading, and the
 * relay reads `distinct` and the totals off it.
 *   (no records), wire line at now=1700000000.0 */
static void test_empty(void) {
    diag_inventory_t *inv = diag_inventory_new(0, 0);
    check_wire(inv, 1700000000.0,
        "{\"type\":\"diag_inventory\",\"ts\":1700000000.0,\"distinct\":0,"
        "\"overflow\":0,\"unrecognized_total\":0,\"silent_total\":0,"
        "\"silent_actionable_total\":0,\"enrich_failed_total\":0,"
        "\"status\":\"celldiag inventory: 0 (code,ver) key(s), 0 unrecognized, "
        "0 silent\",\"table\":\"\",\"unrecognized\":[],\"silent\":[],"
        "\"enrich_failed\":[]}");
    diag_inventory_free(inv);
}

/* All three findings at once, the never-emits split, and the flagged-first
 * table.
 *   (default caps)
 *   for _ in range(5): i.record(0xB193, 1, True, 0, emitted=2)
 *   i.record(0xB0C0, 27, True, 0)                  # silent, actionable
 *   for _ in range(3): i.record(0x14D8, 1, True, 0) # silent, never emits
 *   i.record(0x1234, 7, False, 0)                  # unrecognized
 *   i.record(0xB192, 1, True, 0, emitted=1, enrich_failed=True)
 *   i.record(0xB192, 1, True, 0, emitted=0, enrich_failed=True)
 *   i.record(0x1476, -1, False, 0)                 # empty payload
 *   wire line at now=1792532140.7484 */
static void test_findings(void) {
    diag_inventory_t *inv = diag_inventory_new(0, 0);
    for (int k = 0; k < 5; k++)
        diag_inventory_record(inv, 0xB193, 1, 1, 2, 0);
    diag_inventory_record(inv, 0xB0C0, 27, 1, 0, 0);
    for (int k = 0; k < 3; k++)
        diag_inventory_record(inv, 0x14D8, 1, 1, 0, 0);
    diag_inventory_record(inv, 0x1234, 7, 0, 0, 0);
    diag_inventory_record(inv, 0xB192, 1, 1, 1, 1);
    diag_inventory_record(inv, 0xB192, 1, 1, 0, 1);
    diag_inventory_record(inv, 0x1476, -1, 0, 0, 0);
    check_wire(inv, 1792532140.7484,
        "{\"type\":\"diag_inventory\",\"ts\":1792532140.748,\"distinct\":6,"
        "\"overflow\":0,\"unrecognized_total\":2,\"silent_total\":2,"
        "\"silent_actionable_total\":1,\"enrich_failed_total\":1,"
        "\"status\":\"celldiag inventory: 6 (code,ver) key(s), 2 unrecognized, "
        "2 silent, 2 enrich-failed unrecognized[0x1234/v7, 0x1476/v-1] "
        "silent[0x14D8/v1, 0xB0C0/v27] enrich_failed[0xB192/v1]\","
        "\"table\":\"0x14D8/v1,3,3,0,0,0,s;0xB192/v1,2,2,0,1,2,e;"
        "0x1234/v7,1,0,1,0,0,u;0x1476/v-1,1,0,1,0,0,u;"
        "0xB0C0/v27,1,1,0,0,0,s;0xB193/v1,5,5,0,10,0,-\","
        "\"unrecognized\":[\"0x1234/v7\",\"0x1476/v-1\"],"
        "\"silent\":[\"0x14D8/v1\",\"0xB0C0/v27\"],"
        "\"enrich_failed\":[\"0xB192/v1\"]}");
    diag_inventory_free(inv);
}

/* The two-tier bound: a code's version budget, then the distinct-code
 * ceiling, both counted in overflow and nowhere else -- and the bounded
 * arrays still report their true length in *_total, while status names 8
 * with "+N more".
 *   (max_codes=3, max_versions_per_code=40)
 *   for v in range(40): i.record(0x1000, v, False, 0)
 *   i.record(0x1000, 41, False, 0)                  # over the version budget
 *   i.record(0x2000, 0, True, 0); i.record(0x3000, 0, True, 0)
 *   i.record(0x4000, 0, True, 0)                    # over the code ceiling
 *   wire line at now=12.0004 */
static void test_bounds(void) {
    diag_inventory_t *inv = diag_inventory_new(3, 40);
    for (int v = 0; v < 40; v++)
        diag_inventory_record(inv, 0x1000, v, 0, 0, 0);
    diag_inventory_record(inv, 0x1000, 41, 0, 0, 0);
    diag_inventory_record(inv, 0x2000, 0, 1, 0, 0);
    diag_inventory_record(inv, 0x3000, 0, 1, 0, 0);
    diag_inventory_record(inv, 0x4000, 0, 1, 0, 0);
    CHECK(diag_inventory_distinct(inv) == 42, "distinct %zu",
          diag_inventory_distinct(inv));
    CHECK(diag_inventory_overflow(inv) == 2, "overflow %llu",
          (unsigned long long)diag_inventory_overflow(inv));

    char buf[DIAG_INVENTORY_LINE_MAX];
    int n = diag_inventory_wire(inv, 12.0004, buf, sizeof(buf));
    CHECK(n > 0 && (size_t)n < sizeof(buf), "rendered %d", n);
    CHECK(strstr(buf, "\"ts\":12.0,") != NULL, "ts: %s", buf);
    CHECK(strstr(buf, "\"unrecognized_total\":40,") != NULL, "total: %s", buf);
    CHECK(strstr(buf, "2 over cap unrecognized[0x1000/v0, 0x1000/v1, "
                      "0x1000/v2, 0x1000/v3, 0x1000/v4, 0x1000/v5, 0x1000/v6, "
                      "0x1000/v7 +32 more]") != NULL, "status: %s", buf);
    /* 32 entries on the wire, the last of them v31. */
    CHECK(strstr(buf, "\"0x1000/v31\"]") != NULL, "list cut: %s", buf);
    CHECK(strstr(buf, "\"0x1000/v32\"") == NULL, "list not cut: %s", buf);
    /* 24 table rows: 23 separators. */
    const char *t = strstr(buf, "\"table\":\"");
    int semis = 0;
    for (const char *p = t; p && *p && strncmp(p, "\",\"unrecognized\"", 16) != 0; p++)
        semis += (*p == ';');
    CHECK(semis == DIAG_INVENTORY_TABLE_ROWS - 1, "table rows %d", semis + 1);

    /* snprintf contract: a short buffer reports the full length. */
    char tiny[16];
    int m = diag_inventory_wire(inv, 12.0004, tiny, sizeof(tiny));
    CHECK(m == n, "short buffer reported %d, full line is %d", m, n);
    CHECK(strlen(tiny) == sizeof(tiny) - 1, "short buffer not NUL-bounded");
    diag_inventory_free(inv);
}

/* repr() of the values a census ts and the selftest care about, each pasted
 * from Python's own repr(). */
static void test_py_float(void) {
    static const struct { double v; const char *want; } cases[] = {
        { 1792532139.01, "1792532139.01" },
        { 1700000000.0, "1700000000.0" },
        { 0.1, "0.1" },
        { -104.5, "-104.5" },
        { 1e16, "1e+16" },
        { 1234567890123456.0, "1234567890123456.0" },
        { 0.0001, "0.0001" },
        { 0.00001, "1e-05" },
        { 1.5e-7, "1.5e-07" },
        { 0.0, "0.0" },
        { 123.456, "123.456" },
        { 1e22, "1e+22" },
    };
    char b[64];
    for (size_t i = 0; i < sizeof(cases) / sizeof(cases[0]); i++) {
        diag_inventory_py_float(b, sizeof(b), cases[i].v);
        CHECK(strcmp(b, cases[i].want) == 0, "repr(%.17g) = %s, want %s",
              cases[i].v, b, cases[i].want);
    }
    /* round(x, 3) where round(x*1000)/1000 disagrees: Python gives
     * round(7.6795, 3) == 7.679 (the binary value is just under the tie),
     * the naive form 7.68. */
    diag_inventory_py_float(b, sizeof(b), diag_inventory_py_round3(7.6795));
    CHECK(strcmp(b, "7.679") == 0, "round(7.6795, 3) = %s", b);
    diag_inventory_py_float(b, sizeof(b), diag_inventory_py_round3(1792532140.7484));
    CHECK(strcmp(b, "1792532140.748") == 0, "round ts = %s", b);
}

/* _LogEmitter's cadence: armed at construction, due on the first record at
 * least `interval` after the last line, and never when interval <= 0. */
static void test_cadence(void) {
    diag_inventory_cadence_t c;
    diag_inventory_cadence_arm(&c, 5.0, 100.0);
    CHECK(!diag_inventory_cadence_due(&c, 104.9), "due early");
    CHECK(diag_inventory_cadence_due(&c, 105.0), "not due at the interval");
    CHECK(!diag_inventory_cadence_due(&c, 109.0), "interval not restarted");
    CHECK(diag_inventory_cadence_due(&c, 110.5), "not due again");
    diag_inventory_cadence_arm(&c, 0.0, 100.0);
    CHECK(!diag_inventory_cadence_due(&c, 1e9), "interval 0 must never be due");
}

/* The emit-contract sets, member for member. */
static void test_contract_sets(void) {
    CHECK(DIAG_INVENTORY_EMIT_CONTRACT_COUNT == 7, "contract size %zu",
          DIAG_INVENTORY_EMIT_CONTRACT_COUNT);
    static const uint16_t want[] = { 0xB192, 0xB193, 0xB195, 0xB0C0, 0xB97F,
                                     0x1476, 0x14D8 };
    for (size_t i = 0; i < 7; i++)
        CHECK(diag_inventory_is_emit_contract(want[i]), "0x%04X missing", want[i]);
    CHECK(!diag_inventory_is_emit_contract(0xB821), "0xB821 is not contract");
    CHECK(!diag_inventory_is_emit_contract(0xB197), "0xB197 is not contract");
    CHECK(DIAG_INVENTORY_NEVER_EMITS_COUNT == 1 &&
          diag_inventory_is_never_emits(0x14D8) &&
          !diag_inventory_is_never_emits(0x1476), "never-emits set");
}

/* The third state, armed with native coverage: the line is the two-state
 * form plus four additions, each pinned here -- the total with the
 * other totals, the status segment and named list, the `n` table flag in its
 * own sort tier, and the code-level array.
 *
 * Also pins what the state is NOT: an undecoded key is not unrecognized
 * (decoded == dropped == 0), and a code no decoder reads still is. */
static void test_undecoded_native(void) {
    diag_inventory_t *inv = diag_inventory_new(0, 0);
    diag_inventory_set_native_coverage(inv, 1);
    for (int k = 0; k < 3; k++)
        diag_inventory_record(inv, 0xB193, 1, 1, 2, 0);
    diag_inventory_record_undecoded(inv, 0x117E, 160);
    diag_inventory_record_undecoded(inv, 0x117E, 161);
    for (int k = 0; k < 4; k++)
        diag_inventory_record_undecoded(inv, 0x1022, 0);
    diag_inventory_record(inv, 0x1001, 2, 0, 0, 0);       /* unrecognized */
    check_wire(inv, 1792532140.7484,
        "{\"type\":\"diag_inventory\",\"ts\":1792532140.748,\"distinct\":5,"
        "\"overflow\":0,\"unrecognized_total\":1,\"silent_total\":0,"
        "\"silent_actionable_total\":0,\"enrich_failed_total\":0,"
        "\"undecoded_native_total\":2,"
        "\"status\":\"celldiag inventory: 5 (code,ver) key(s), 1 unrecognized, "
        "0 silent, 2 undecoded-native unrecognized[0x1001/v2] "
        "undecoded_native[0x1022, 0x117E]\","
        "\"table\":\"0x1001/v2,1,0,1,0,0,u;0x1022/v0,4,0,0,0,0,n;"
        "0x117E/v160,1,0,0,0,0,n;0x117E/v161,1,0,0,0,0,n;"
        "0xB193/v1,3,3,0,6,0,-\","
        "\"unrecognized\":[\"0x1001/v2\"],\"silent\":[],\"enrich_failed\":[],"
        "\"undecoded_native\":[\"0x1022\",\"0x117E\"]}");

    /* Armed with nothing undecoded: the total is still there, at 0, and the
     * status carries no segment for it. */
    diag_inventory_t *clean = diag_inventory_new(0, 0);
    diag_inventory_set_native_coverage(clean, 1);
    diag_inventory_record(clean, 0xB193, 1, 1, 1, 0);
    char buf[DIAG_INVENTORY_LINE_MAX];
    diag_inventory_wire(clean, 1.0, buf, sizeof(buf));
    CHECK(strstr(buf, "\"undecoded_native_total\":0,") != NULL, "%s", buf);
    CHECK(strstr(buf, "undecoded-native") == NULL, "%s", buf);
    CHECK(strstr(buf, ",\"undecoded_native\":[]}") != NULL, "%s", buf);
    diag_inventory_free(clean);
    diag_inventory_free(inv);
}

/* Hundreds of undecoded codes -- a full-mask stream -- stay inside the line,
 * the list is cut at 32 with the true total beside it, and the to-do rows
 * do not push a finding off the 24-row table. */
static void test_undecoded_native_is_bounded(void) {
    diag_inventory_t *inv = diag_inventory_new(0, 0);
    diag_inventory_set_native_coverage(inv, 1);
    diag_inventory_record(inv, 0xB0C0, 27, 1, 0, 0);          /* silent */
    for (unsigned c = 0; c < 600; c++)
        for (int v = 0; v < 3; v++)
            diag_inventory_record_undecoded(inv, (uint16_t)(0x2000 + c), v);
    char buf[DIAG_INVENTORY_LINE_MAX];
    int n = diag_inventory_wire(inv, 5.0, buf, sizeof(buf));
    CHECK(n > 0 && (size_t)n < sizeof(buf), "rendered %d", n);
    /* 512 distinct codes: the silent 0xB0C0 plus 511 undecoded. */
    CHECK(strstr(buf, "\"undecoded_native_total\":511,") != NULL, "%.300s", buf);
    CHECK(strstr(buf, "511 undecoded-native") != NULL, "status: %.400s", buf);
    CHECK(strstr(buf, " +503 more]") != NULL, "status cut: %.600s", buf);
    CHECK(strstr(buf, "\"0x201F\"]}") != NULL, "array not cut at 32: %s",
          buf + n - 80);
    CHECK(strstr(buf, "\"table\":\"0xB0C0/v27,1,1,0,0,0,s;") != NULL,
          "the finding was pushed off the table: %.700s", buf);
    diag_inventory_free(inv);
}

/* The known-layout table: sorted (the lookup is a binary search), and it
 * answers for codes the native legs need and codes they do not. */
static void test_known_table(void) {
    size_t n = diag_inventory_known_count();
    CHECK(n > 100, "known-layout table has %zu codes", n);
    size_t hits = 0;
    for (uint32_t c = 0; c <= 0xFFFF; c++)
        hits += (size_t)diag_inventory_code_known((uint16_t)c);
    CHECK(hits == n, "binary search finds %zu of %zu codes: the table is not "
          "sorted or holds a duplicate", hits, n);
    CHECK(diag_inventory_code_known(0xB193), "0xB193 not in the table");
    CHECK(diag_inventory_code_known(0x1022), "0x1022 not in the table");
    CHECK(diag_inventory_code_known(0x14D8), "0x14D8 not in the table");
    CHECK(!diag_inventory_code_known(0x1001), "0x1001 is known now -- "
          "pick another unknown code for test_undecoded_native");
}

static int trace(void) {
    diag_inventory_t *inv = diag_inventory_new(0, 0);
    if (inv == NULL)
        return 2;
    char line[256];
    char out[DIAG_INVENTORY_LINE_MAX];
    while (fgets(line, sizeof(line), stdin) != NULL) {
        if (line[0] == 'C') {
            unsigned long mc, mv;
            if (sscanf(line + 1, "%lu %lu", &mc, &mv) == 2) {
                diag_inventory_free(inv);
                inv = diag_inventory_new((size_t)mc, (size_t)mv);
                if (inv == NULL)
                    return 2;
            }
        } else if (line[0] == 'N') {
            diag_inventory_set_native_coverage(inv, 1);
        } else if (line[0] == 'U') {
            unsigned code;
            int ver;
            if (sscanf(line + 1, "%u %d", &code, &ver) == 2)
                diag_inventory_record_undecoded(inv, (uint16_t)code, ver);
        } else if (line[0] == 'R') {
            unsigned code;
            int ver, dec, enr;
            unsigned long long em;
            if (sscanf(line + 1, "%u %d %d %llu %d", &code, &ver, &dec, &em,
                       &enr) == 5)
                diag_inventory_record(inv, (uint16_t)code, ver, dec,
                                      (uint64_t)em, enr);
        } else if (line[0] == 'W') {
            double now = strtod(line + 1, NULL);
            int n = diag_inventory_wire(inv, now, out, sizeof(out));
            if (n < 0 || (size_t)n >= sizeof(out)) {
                fprintf(stderr, "wire line did not fit (%d)\n", n);
                return 1;
            }
            fputs(out, stdout);
            fputc('\n', stdout);
        }
    }
    diag_inventory_free(inv);
    return 0;
}

int main(int argc, char **argv) {
    if (argc > 1 && strcmp(argv[1], "--trace") == 0)
        return trace();

    test_empty();
    test_findings();
    test_bounds();
    test_py_float();
    test_cadence();
    test_contract_sets();
    test_undecoded_native();
    test_undecoded_native_is_bounded();
    test_known_table();

    if (failures) {
        fprintf(stderr, "test_diag_inventory: %d failure(s)\n", failures);
        return 1;
    }
    printf("test_diag_inventory: all tests passed\n");
    return 0;
}
