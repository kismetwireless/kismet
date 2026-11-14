/*
    This file is part of Kismet

    Kismet is free software; you can redistribute it and/or modify
    it under the terms of the GNU General Public License as published by
    the Free Software Foundation; either version 2 of the License, or
    (at your option) any later version.

    Kismet is distributed in the hope that it will be useful,
    but WITHOUT ANY WARRANTY; without even the implied warranty of
    MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
    GNU General Public License for more details.

    You should have received a copy of the GNU General Public License
    along with Kismet; if not, write to the Free Software
    Foundation, Inc., 59 Temple Place, Suite 330, Boston, MA  02111-1307  USA

    Selftest for the Fibocom AT+GTCCINFO? decode core.

    The reply LAYOUT below is the one a Fibocom FM350-GL (FW 29.22.06)
    returns: the bare prefix line with its trailing space, one row per cell,
    the 9-digit hex cell ID, the unpadded MNC, the 3GPP signal indices. Every
    IDENTITY value is synthetic (test PLMN 001/01, TAC 0x1234, cell ID
    0xABCDE1, EARFCN 100, PCI 1-9), so no fixture names a real cell.
*/

#ifdef CELL_SELFTEST

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "cellat_selftest_json.h"
#include <sys/time.h>

#define JSON_BUF_MAX 4096
#define MAX_OBS 8

#include "cellat_qeng.inc"
#include "cellat_gtccinfo.inc"

static int g_fails = 0;

static void check(int cond, const char *what) {
    if (cond) {
        printf("  OK    %s\n", what);
    } else {
        printf("  FAIL  %s\n", what);
        g_fails++;
    }
}

static void check_has(const char *json, const char *frag, const char *what) {
    if (json_has(json, frag)) {
        printf("  OK    %s\n", what);
    } else {
        printf("  FAIL  %s (expected %s)\n     in: %s\n", what, frag, json);
        g_fails++;
    }
}

static void check_lacks(const char *json, const char *frag, const char *what) {
    if (!strstr(json, frag)) {
        printf("  OK    %s\n", what);
    } else {
        printf("  FAIL  %s (unexpected %s)\n     in: %s\n", what, frag, json);
        g_fails++;
    }
}

/* Serving cell, camped on LTE band 48 (code 148), 100 RB, RSRP idx 50,
 * RSRQ idx 21. The prefix line keeps the trailing space the modem sends. */
static const char *GTCC_SERVING =
    "+GTCCINFO: \r\n"
    "1,4,001,1,1234,000ABCDE1,100,1,148,100,26,49,50,21\r\n"
    "OK\r\n";

/* Uncamped: the prefix line and OK, no rows. */
static const char *GTCC_UNCAMPED =
    "+GTCCINFO: \r\n"
    "OK\r\n";

/* Band and bandwidth empty, as the same firmware sometimes answers. */
static const char *GTCC_EMPTY_BAND =
    "+GTCCINFO: \r\n"
    "1,4,001,1,1234,000ABCDE1,100,1,,,26,50,50,21\r\n"
    "OK\r\n";

/* Serving + neighbour rows, plus a trailing reply that must not be read.
 * The neighbour row is in the layout the FM350 AT manual (V2.10.1, 11.1.15)
 * gives for an LTE neighbour: IsServiceCell 2, and NO band and NO rssnr, so
 * 12 fields -- <..>,<pci>,<bandwidth>,<rxlev>,<rsrp>,<rsrq>. */
static const char *GTCC_NEIGHBOUR =
    "+GTCCINFO: \r\n"
    "1,4,001,1,1234,000ABCDE1,100,1,148,100,26,50,50,21\r\n"
    "2,4,001,1,1234,000ABCDE2,100,2,100,39,40,15\r\n"
    "OK\r\n"
    "+CESQ: 31,99,255,255,22,51,255,255,255\r\n";

/* A neighbour row in the serving (14-field) layout. The manual does not show
 * this form; it is accepted so that a firmware which emits it is not dropped. */
static const char *GTCC_NEIGHBOUR_LONG =
    "+GTCCINFO: \r\n"
    "2,4,001,1,1234,000ABCDE2,100,3,148,100,10,40,40,15\r\n"
    "OK\r\n";

/* RSSNR at the edges of its -100..100 range, and 255 (not known). */
static const char *GTCC_SNR_NEG =
    "+GTCCINFO: \r\n"
    "1,4,001,1,1234,000ABCDE1,100,1,148,100,-3,50,50,21\r\n"
    "OK\r\n";
static const char *GTCC_SNR_UNKNOWN =
    "+GTCCINFO: \r\n"
    "1,4,001,1,1234,000ABCDE1,100,1,148,100,255,50,50,21\r\n"
    "OK\r\n";

/* RSRP / RSRQ unknown (255). */
static const char *GTCC_UNKNOWN_SIGNAL =
    "+GTCCINFO: \r\n"
    "1,4,001,1,1234,000ABCDE1,100,1,148,100,26,50,255,255\r\n"
    "OK\r\n";

/* A three-digit MNC value has an unambiguous width. */
static const char *GTCC_MNC3 =
    "+GTCCINFO: \r\n"
    "1,4,001,123,1234,000ABCDE1,100,1,148,100,26,50,50,21\r\n"
    "OK\r\n";

/* A RAT code this decoder has never seen: skipped, not guessed. */
static const char *GTCC_UNKNOWN_RAT =
    "+GTCCINFO: \r\n"
    "1,9,001,1,1234,000ABCDE1,100,1,148,100,26,50,50,21\r\n"
    "OK\r\n";

int main(void) {
    char obs[MAX_OBS][JSON_BUF_MAX];
    int n;

    printf("[1] serving row decodes every bound field\n");
    n = parse_gtccinfo(GTCC_SERVING, obs, MAX_OBS);
    check(n == 1, "one observation");
    if (n == 1) {
        check_has(obs[0], "\"rat\":\"LTE\"", "rat 4 -> LTE");
        check_has(obs[0], "\"mcc\":\"001\"", "mcc zero-padded string");
        check_has(obs[0], "\"tac\":4660", "tac is hex 0x1234");
        check_has(obs[0], "\"cell_id\":11259361", "9-digit hex cell id 0xABCDE1");
        check_has(obs[0], "\"earfcn\":100", "earfcn");
        check_has(obs[0], "\"pci\":1", "pci");
        check_has(obs[0], "\"band\":48", "band code 148 -> B48");
        check_has(obs[0], "\"bandwidth\":20", "100 RB -> 20 MHz");
        check_has(obs[0], "\"rsrp\":-91", "rsrp index 50 -> -91 dBm");
        check_has(obs[0], "\"rsrq\":-9", "rsrq index 21 -> -9 dB (half truncated)");
        check_has(obs[0], "\"observation_type\":\"serving\"", "serving observation_type");
        check_lacks(obs[0], "\"rsrp\":50", "the raw index is not emitted as dBm");
        check_has(obs[0], "\"snr\":13", "rssnr_value 26 -> 13 dB (0.5 dB steps)");
        check_lacks(obs[0], "\"sinr\"", "RSSNR is not emitted as sinr");
    }

    printf("\n[2] the unpadded MNC is an integer, never a guessed-width string\n");
    if (n == 1) {
        check_has(obs[0], "\"mnc\":1", "mnc as integer 1");
        check_lacks(obs[0], "\"mnc\":\"", "no mnc string invented");
    }

    printf("\n[3] uncamped reply is valid and yields nothing\n");
    n = parse_gtccinfo(GTCC_UNCAMPED, obs, MAX_OBS);
    check(n == 0, "zero observations");

    printf("\n[4] empty band/bandwidth tolerated\n");
    n = parse_gtccinfo(GTCC_EMPTY_BAND, obs, MAX_OBS);
    check(n == 1, "still one observation");
    if (n == 1) {
        check_lacks(obs[0], "\"band\"", "no band key");
        check_lacks(obs[0], "\"bandwidth\"", "no bandwidth key");
        check_has(obs[0], "\"pci\":1", "later fields still aligned");
        check_has(obs[0], "\"rsrp\":-91", "rsrp still aligned");
    }

    printf("\n[5] neighbour rows; a following reply is not a row\n");
    n = parse_gtccinfo(GTCC_NEIGHBOUR, obs, MAX_OBS);
    check(n == 2, "two observations (the +CESQ line is not a cell)");
    if (n == 2) {
        check_has(obs[1], "\"observation_type\":\"observation\"", "neighbour observation_type");
        check_has(obs[1], "\"pci\":2", "neighbour pci");
        check_has(obs[1], "\"rsrp\":-101", "neighbour rsrp index 40 -> -101");
        check_has(obs[1], "\"rsrq\":-12", "neighbour rsrq index 15 -> -12");
        check_has(obs[1], "\"bandwidth\":20", "neighbour 100 RB -> 20 MHz");
        check_has(obs[1], "\"cell_id\":11259362", "neighbour cell id 0xABCDE2");
        check_lacks(obs[1], "\"band\":", "neighbour row carries no band");
        check_lacks(obs[1], "\"snr\"", "neighbour row carries no rssnr");
    }

    printf("\n[5b] a neighbour in the 14-field layout is still decoded\n");
    n = parse_gtccinfo(GTCC_NEIGHBOUR_LONG, obs, MAX_OBS);
    check(n == 1, "one observation");
    if (n == 1) {
        check_has(obs[0], "\"observation_type\":\"observation\"", "IsServiceCell 2 -> observation");
        check_has(obs[0], "\"pci\":3", "pci");
        check_has(obs[0], "\"band\":48", "band");
        check_has(obs[0], "\"snr\":5", "rssnr_value 10 -> 5 dB");
    }

    printf("\n[5c] rssnr_value: negative, and 255 = not known\n");
    n = parse_gtccinfo(GTCC_SNR_NEG, obs, MAX_OBS);
    check(n == 1, "one observation");
    if (n == 1)
        check_has(obs[0], "\"snr\":-1", "rssnr_value -3 -> -1 dB (truncated toward zero)");
    n = parse_gtccinfo(GTCC_SNR_UNKNOWN, obs, MAX_OBS);
    check(n == 1, "one observation");
    if (n == 1) {
        check_lacks(obs[0], "\"snr\"", "255 -> no snr key");
        check_has(obs[0], "\"rsrp\":-91", "rest of the row still decoded");
    }

    printf("\n[6] 255 means unknown: no signal keys\n");
    n = parse_gtccinfo(GTCC_UNKNOWN_SIGNAL, obs, MAX_OBS);
    check(n == 1, "one observation");
    if (n == 1) {
        check_lacks(obs[0], "\"rsrp\"", "no rsrp");
        check_lacks(obs[0], "\"rsrq\"", "no rsrq");
    }

    printf("\n[7] a 3-digit MNC value is emitted as a string\n");
    n = parse_gtccinfo(GTCC_MNC3, obs, MAX_OBS);
    check(n == 1, "one observation");
    if (n == 1)
        check_has(obs[0], "\"mnc\":\"123\"", "mnc \"123\"");

    printf("\n[8] an unknown RAT code is skipped\n");
    n = parse_gtccinfo(GTCC_UNKNOWN_RAT, obs, MAX_OBS);
    check(n == 0, "zero observations");

    printf("\n[9] index conversions at the 3GPP bounds\n");
    {
        long v = 0;
        check(gtcc_rsrp_dbm(0, 1, &v) && v == -141, "rsrp idx 0 -> -141");
        check(gtcc_rsrp_dbm(97, 1, &v) && v == -44, "rsrp idx 97 -> -44");
        check(!gtcc_rsrp_dbm(98, 1, &v), "rsrp idx 98 rejected");
        check(gtcc_rsrq_db(0, 1, &v) && v == -20, "rsrq idx 0 -> -20");
        check(gtcc_rsrq_db(34, 1, &v) && v == -3, "rsrq idx 34 -> -3");
        check(!gtcc_rsrq_db(35, 1, &v), "rsrq idx 35 rejected");
        check(gtcc_rssnr_db(100, 1, &v) && v == 50, "rssnr 100 -> 50 dB");
        check(gtcc_rssnr_db(-100, 1, &v) && v == -50, "rssnr -100 -> -50 dB");
        check(!gtcc_rssnr_db(101, 1, &v), "rssnr 101 rejected");
        check(!gtcc_rssnr_db(255, 1, &v), "rssnr 255 rejected");
    }

    printf("\n%s (%d failures)\n", g_fails ? "FAILED" : "PASSED", g_fails);
    return g_fails ? 1 : 0;
}

#endif /* CELL_SELFTEST */
