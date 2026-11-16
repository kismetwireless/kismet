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

/* A RAT code this decoder doesn't decode (2 = WCDMA, whose rows have another
 * layout): skipped, not guessed. */
static const char *GTCC_UNKNOWN_RAT =
    "+GTCCINFO: \r\n"
    "1,2,001,1,1234,000ABCDE1,100,1,148,100,26,50,50,21\r\n"
    "OK\r\n";

/* NR (rat 9), the manual's two NR layouts. Serving: <..>,<narfcn>,<pci>,<band>,
 * <bandwidth>,<ss_sinr>,<rxlev>,<ss_rsrp>,<ss_rsrq>; band code 5078 = n78.
 * Neighbour: <..>,<narfcn>,<pci>,<ss_sinr>,<rxlev>,<ss_rsrp>,<ss_rsrq> -- field 9
 * is ss_sinr here where an LTE neighbour has its bandwidth. */
static const char *GTCC_NR =
    "+GTCCINFO: \r\n"
    "1,9,001,1,1234,000ABCDE1,100,1,5078,100,60,80,80,90\r\n"
    "2,9,001,1,1234,000ABCDE2,100,2,60,70,70,80\r\n"
    "OK\r\n";

/* NR signals all 255 (not known), and a short band code. */
static const char *GTCC_NR_UNKNOWN =
    "+GTCCINFO: \r\n"
    "1,9,001,1,1234,000ABCDE1,100,1,501,100,255,255,255,255\r\n"
    "OK\r\n";

/* EN-DC: the LTE anchor and the NR leg are both serving rows. */
static const char *GTCC_ENDC =
    "+GTCCINFO: \r\n"
    "1,4,001,1,1234,000ABCDE1,100,1,148,100,26,50,50,21\r\n"
    "1,9,001,1,1234,000ABCDE1,100,1,5010,100,60,80,80,90\r\n"
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

    printf("\n[10] NR serving and neighbour rows\n");
    n = parse_gtccinfo(GTCC_NR, obs, MAX_OBS);
    check(n == 2, "two observations");
    if (n == 2) {
        check_has(obs[0], "\"rat\":\"NR\"", "rat 9 -> NR");
        check_has(obs[0], "\"earfcn\":100", "narfcn in the earfcn key, as +QENG NR5G-SA");
        check_has(obs[0], "\"band\":78", "band code 5078 -> n78");
        check_lacks(obs[0], "\"bandwidth\"", "NR bandwidth unit is unbound: not emitted");
        check_has(obs[0], "\"sinr\":6", "ss_sinr 60 -> 6 dB");
        check_lacks(obs[0], "\"snr\"", "ss_sinr is sinr, not the LTE RSSNR key");
        check_has(obs[0], "\"rsrp\":-77", "ss_rsrp 80 -> -77 dBm");
        check_has(obs[0], "\"rsrq\":1", "ss_rsrq 90 -> 1 dB (1.5 truncated)");
        check_has(obs[0], "\"observation_type\":\"serving\"", "serving");
        check_has(obs[1], "\"rat\":\"NR\"", "neighbour rat NR");
        check_has(obs[1], "\"pci\":2", "neighbour pci");
        check_has(obs[1], "\"sinr\":6", "neighbour field 9 is ss_sinr");
        check_has(obs[1], "\"rsrp\":-87", "neighbour ss_rsrp 70 -> -87 dBm");
        check_has(obs[1], "\"rsrq\":-3", "neighbour ss_rsrq 80 -> -3 dB (-3.5 truncated)");
        check_lacks(obs[1], "\"band\":", "NR neighbour carries no band");
        check_lacks(obs[1], "\"bandwidth\"", "NR neighbour field 9 is not a bandwidth");
        check_has(obs[1], "\"observation_type\":\"observation\"", "neighbour");
    }

    printf("\n[11] NR 255 = not known; short band code\n");
    n = parse_gtccinfo(GTCC_NR_UNKNOWN, obs, MAX_OBS);
    check(n == 1, "one observation");
    if (n == 1) {
        check_has(obs[0], "\"band\":1", "band code 501 -> n1");
        check_lacks(obs[0], "\"sinr\"", "no sinr");
        check_lacks(obs[0], "\"rsrp\"", "no rsrp");
        check_lacks(obs[0], "\"rsrq\"", "no rsrq");
    }

    printf("\n[12] EN-DC: an LTE and an NR serving row\n");
    n = parse_gtccinfo(GTCC_ENDC, obs, MAX_OBS);
    check(n == 2, "two observations");
    if (n == 2) {
        check_has(obs[0], "\"rat\":\"LTE\"", "anchor LTE");
        check_has(obs[0], "\"band\":48", "anchor band");
        check_has(obs[0], "\"snr\":13", "anchor keeps its RSSNR as snr");
        check_has(obs[1], "\"rat\":\"NR\"", "leg NR");
        check_has(obs[1], "\"band\":10", "band code 5010 -> n10");
    }

    printf("\n[9] index conversions at the 3GPP bounds\n");
    {
        long v = 0;
        check(gtcc_nr_band("5078", &v) && v == 78, "nr band 5078 -> 78");
        check(gtcc_nr_band("50512", &v) && v == 512, "nr band 50512 -> 512");
        check(!gtcc_nr_band("50513", &v), "nr band 50513 rejected");
        check(!gtcc_nr_band("50", &v), "nr band 50 rejected");
        check(!gtcc_nr_band("5001", &v), "nr band 5001 rejected (leading zero)");
        check(!gtcc_nr_band("148", &v), "an LTE code is not an NR band");
        check(!gtcc_nr_band("", &v), "empty nr band rejected");
        check(gtcc_ss_rsrp_dbm(0, 1, &v) && v == -157, "ss_rsrp 0 -> -157");
        check(gtcc_ss_rsrp_dbm(126, 1, &v) && v == -31, "ss_rsrp 126 -> -31");
        check(!gtcc_ss_rsrp_dbm(127, 1, &v), "ss_rsrp 127 rejected");
        check(gtcc_ss_rsrq_db(1, 1, &v) && v == -43, "ss_rsrq 1 -> -43");
        check(gtcc_ss_rsrq_db(126, 1, &v) && v == 19, "ss_rsrq 126 -> 19 (19.5 truncated)");
        check(!gtcc_ss_rsrq_db(127, 1, &v), "ss_rsrq 127 rejected");
        check(gtcc_ss_sinr_db(1, 1, &v) && v == -23, "ss_sinr 1 -> -23");
        check(gtcc_ss_sinr_db(127, 1, &v) && v == 40, "ss_sinr 127 -> 40");
        check(!gtcc_ss_sinr_db(128, 1, &v), "ss_sinr 128 rejected");
        check(!gtcc_ss_sinr_db(60, 0, &v), "absent ss_sinr rejected");
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
