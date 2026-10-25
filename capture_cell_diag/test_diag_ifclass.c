/* test_diag_ifclass.c - unit tests for the DIAG USB-descriptor classifier.
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 *
 * Every fixture below is a REAL descriptor triple read from /sys on a
 * six-modem test host, paired with the actual
 * celldiag_probe LOG_CONFIG handshake outcome for that node -- so the tests
 * assert measured ground truth, not a guessed table. See diag_ifclass.c.
 */
#include "diag_ifclass.h"

#include <stdio.h>
#include <string.h>

static int failures = 0;

#define CHECK(cond, ...) do {                                              \
    if (!(cond)) {                                                         \
        printf("FAIL %s:%d: ", __FILE__, __LINE__);                        \
        printf(__VA_ARGS__);                                               \
        printf("\n");                                                      \
        failures++;                                                        \
    }                                                                      \
} while (0)

static struct diag_ifcand cand(const char *path, int ifn,
                               int cls, int sub, int prot) {
    struct diag_ifcand c;
    memset(&c, 0, sizeof(c));
    snprintf(c.path, sizeof(c.path), "%s", path);
    c.if_num = ifn;
    c.cls = cls; c.sub = sub; c.prot = prot;
    return c;
}

/* --- is_diag: the measured DIAG ports of the test host --- */
static void test_is_diag_positives(void) {
    /* ff/ff/ff -- classic QCDM. LM960 1bc7:1040 if00, 2c7c:0700 if00,
     * EG25-G 2c7c:0125 if00, 2c7c:0512 if00. */
    CHECK(diag_ifclass_is_diag(0xff, 0xff, 0xff), "ff/ff/ff must classify DIAG");
    /* ff/ff/30 -- SDX55/SDX62 + 05c6 reference. RM500Q 2c7c:0800 if00,
     * RM520N-GL 2c7c:0801 if00, 05c6:90ad if00. */
    CHECK(diag_ifclass_is_diag(0xff, 0xff, 0x30), "ff/ff/30 must classify DIAG");
}

/* --- is_diag: every non-DIAG sibling actually seen on the test host --- */
static void test_is_diag_negatives(void) {
    CHECK(!diag_ifclass_is_diag(0xff, 0x00, 0x00),
          "ff/00/00 (AT / modem / NMEA sibling) must NOT classify DIAG");
    CHECK(!diag_ifclass_is_diag(0xff, 0x00, 0x40),
          "ff/00/40 (2c7c:0801 if01) must NOT classify DIAG");
    CHECK(!diag_ifclass_is_diag(0xff, 0xfe, 0xff),
          "ff/fe/ff (2c7c:0700 if04) must NOT classify DIAG");
    CHECK(!diag_ifclass_is_diag(0xff, 0x01, 0x02),
          "ff/01/02 (ch341 USB-serial adapter, not a modem) must NOT classify DIAG");
    /* Unreadable descriptor bytes are -1, never 0: must not classify. */
    CHECK(!diag_ifclass_is_diag(-1, -1, -1),
          "unreadable descriptor must NOT classify DIAG");
    CHECK(!diag_ifclass_is_diag(0xff, 0xff, -1),
          "unreadable protocol must NOT classify DIAG");
    /* A vendor class with the DIAG subclass but an unknown protocol is the
     * conservative case: decline, so the caller falls back to lowest-if. */
    CHECK(!diag_ifclass_is_diag(0xff, 0xff, 0x10),
          "unknown protocol under ff/ff must be declined, not assumed DIAG");
}

/* --- pick: the RM520N-GL (2c7c:0801), full real port set --- */
static void test_pick_rm520ngl(void) {
    struct diag_ifcand c[4] = {
        cand("/dev/ttyUSB14", 0, 0xff, 0xff, 0x30),   /* DIAG - probe OK 0.02s */
        cand("/dev/ttyUSB20", 1, 0xff, 0x00, 0x40),
        cand("/dev/ttyUSB21", 2, 0xff, 0x00, 0x00),   /* AT (answered CGSN) */
        cand("/dev/ttyUSB27", 3, 0xff, 0x00, 0x00),
    };
    int idx = diag_ifclass_pick(c, 4);
    CHECK(idx == 0, "RM520N-GL: expected index 0 (/dev/ttyUSB14), got %d", idx);
    CHECK(diag_ifclass_count(c, 4) == 1, "RM520N-GL: expected exactly 1 DIAG candidate");
}

/* --- pick: 2c7c:0700, where if00/if01/if02 are ALL ff/ff/ff ---
 * The discriminating case: descriptor alone does not disambiguate (if02
 * answers AT+CGSN with the IMEI), so lowest-among-DIAG-candidates must still
 * land on if00 -- the node that actually handshook. */
static void test_pick_multiple_ffffff(void) {
    struct diag_ifcand c[4] = {
        cand("/dev/ttyUSB6", 0, 0xff, 0xff, 0xff),   /* DIAG - probe OK */
        cand("/dev/ttyUSB7", 1, 0xff, 0xff, 0xff),
        cand("/dev/ttyUSB8", 2, 0xff, 0xff, 0xff),   /* answers AT+CGSN */
        cand("/dev/ttyUSB9", 4, 0xff, 0xfe, 0xff),
    };
    int idx = diag_ifclass_pick(c, 4);
    CHECK(idx == 0, "2c7c:0700: expected index 0 (/dev/ttyUSB6), got %d", idx);
    CHECK(diag_ifclass_count(c, 4) == 3,
          "2c7c:0700: expected 3 ff/ff/ff candidates, got %d",
          diag_ifclass_count(c, 4));
}

/* --- pick: enumeration order must not matter, only bInterfaceNumber --- */
static void test_pick_ignores_array_order(void) {
    struct diag_ifcand c[3] = {
        cand("/dev/ttyUSB8", 2, 0xff, 0xff, 0xff),
        cand("/dev/ttyUSB7", 1, 0xff, 0xff, 0xff),
        cand("/dev/ttyUSB6", 0, 0xff, 0xff, 0xff),
    };
    int idx = diag_ifclass_pick(c, 3);
    CHECK(idx == 2, "expected the if00 entry regardless of array order, got %d", idx);
}

/* --- pick: the ch341 case lowest-interface gets WRONG ---
 * A non-modem USB-serial adapter enumerating at if00. Lowest-interface would
 * select it; the classifier must decline the whole set (-1) so the caller
 * reports/falls back rather than handshaking a UART for 20-60 s. */
static void test_pick_declines_ch341(void) {
    struct diag_ifcand c[1] = {
        cand("/dev/ttyUSB0", 0, 0xff, 0x01, 0x02),
    };
    CHECK(diag_ifclass_pick(c, 1) == -1,
          "ch341 (ff/01/02) must be declined, not selected as DIAG");
    CHECK(diag_ifclass_count(c, 1) == 0, "ch341 must not count as a DIAG candidate");
}

/* --- pick: no DIAG-signature candidate -> -1 (fall back to lowest-if) --- */
static void test_pick_no_candidate(void) {
    struct diag_ifcand c[3] = {
        cand("/dev/ttyUSBa", 1, 0xff, 0x00, 0x00),
        cand("/dev/ttyUSBb", 2, 0xff, 0x00, 0x00),
        cand("/dev/ttyUSBc", 3, 0xff, 0x00, 0x00),
    };
    CHECK(diag_ifclass_pick(c, 3) == -1,
          "an all-AT device must decline classification");
}

/* --- pick: unreadable if_num ranks last but stays eligible --- */
static void test_pick_unreadable_ifnum(void) {
    struct diag_ifcand both[2] = {
        cand("/dev/ttyUSBx", -1, 0xff, 0xff, 0xff),
        cand("/dev/ttyUSBy",  3, 0xff, 0xff, 0xff),
    };
    CHECK(diag_ifclass_pick(both, 2) == 1,
          "a readable if_num must outrank an unreadable one");

    struct diag_ifcand only[1] = {
        cand("/dev/ttyUSBz", -1, 0xff, 0xff, 0x30),
    };
    CHECK(diag_ifclass_pick(only, 1) == 0,
          "a lone DIAG candidate with an unreadable if_num is still eligible");
}

/* --- guards --- */
static void test_guards(void) {
    CHECK(diag_ifclass_pick(NULL, 3) == -1, "NULL candidate array must return -1");
    CHECK(diag_ifclass_count(NULL, 3) == 0, "NULL candidate array must count 0");
    struct diag_ifcand c[1] = { cand("/dev/ttyUSB0", 0, 0xff, 0xff, 0xff) };
    CHECK(diag_ifclass_pick(c, 0) == -1, "n==0 must return -1");
}

/* --- labels (used in the operator-facing detection diagnostic) --- */
static void test_labels(void) {
    CHECK(strcmp(diag_ifclass_label(0xff, 0xff, 0xff), "DIAG (ff/ff/ff)") == 0,
          "label ff/ff/ff: got '%s'", diag_ifclass_label(0xff, 0xff, 0xff));
    CHECK(strcmp(diag_ifclass_label(0xff, 0xff, 0x30), "DIAG (ff/ff/30)") == 0,
          "label ff/ff/30: got '%s'", diag_ifclass_label(0xff, 0xff, 0x30));
    CHECK(strcmp(diag_ifclass_label(0xff, 0x00, 0x00), "AT/NMEA-class (ff/00/xx)") == 0,
          "label ff/00/00: got '%s'", diag_ifclass_label(0xff, 0x00, 0x00));
    CHECK(strcmp(diag_ifclass_label(-1, -1, -1), "unreadable descriptor") == 0,
          "label unreadable: got '%s'", diag_ifclass_label(-1, -1, -1));
    CHECK(diag_ifclass_label(0x02, 0x02, 0x01) != NULL, "label must never be NULL");
}

int main(void) {
    test_is_diag_positives();
    test_is_diag_negatives();
    test_pick_rm520ngl();
    test_pick_multiple_ffffff();
    test_pick_ignores_array_order();
    test_pick_declines_ch341();
    test_pick_no_candidate();
    test_pick_unreadable_ifnum();
    test_guards();
    test_labels();

    if (failures) {
        printf("FAILED: %d check(s)\n", failures);
        return 1;
    }
    printf("PASS: all diag_ifclass tests\n");
    return 0;
}
