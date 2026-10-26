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

    Selftest for the SIMCom AT+CPSI? decode core.

    Every response string below is VERBATIM -- from a capture of real
    hardware, or from the vendor manual's worked example. Do not "tidy"
    them: the `0x` prefixes, the mixed decimal/hex identity columns and the
    inconsistent signal scaling ARE the thing under test, and normalising them
    here would make the suite agree with the parser about a format neither has
    seen.

    Provenance of each fixture is named at its declaration, because the two
    classes are not equally strong: the LTE line is measured, the NR lines are
    manual-grounded only (the SIM8202G-M2 these were checked against was never
    registered, so every +CPSI? on it reads NO SERVICE).
*/

#ifdef CELL_SELFTEST

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/time.h>

#define JSON_BUF_MAX 4096
#define MAX_OBS 8

#include "cellat_qeng.inc"
#include "cellat_cpsi.inc"

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
    if (strstr(json, frag)) {
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

/* --- MEASURED. A SIM7600NA (LE20B01SIM7600NA), verbatim from an AT survey.
 *     RSRQ -125 / RSRP -987 / RSSI -663 are dBm x10. --- */
static const char *CPSI_LTE_TENTHS =
    "+CPSI: LTE,Online,310-260,0x1A2B,27439874,236,EUTRAN-BAND4,2300,5,5,"
    "-125,-987,-663,10\n"
    "OK\n";

/* --- A leading-zero MNC. The broadcast MNC "01" is a two-digit PLMN
 *     whose digit COUNT is part of the cell identity. parse_int would
 *     collapse "01" -> 1, losing the count; the emitter must carry it as the
 *     string "01". Same LTE layout as CPSI_LTE_TENTHS otherwise. --- */
static const char *CPSI_LTE_ZEROMNC =
    "+CPSI: LTE,Online,310-01,0x1A2B,27439874,236,EUTRAN-BAND4,2300,5,5,"
    "-125,-987,-663,10\n"
    "OK\n";

/* --- MANUAL. SIM7070_SIM7080_SIM7090 Series AT Command Manual V1.08 §4.2.14
 *     worked example. Same field layout, WHOLE units. The PDF text extractor
 *     wraps the system-mode cell, which is why the mode reads "LTE NB-IOT". --- */
static const char *CPSI_LTE_WHOLE =
    "+CPSI: LTE NB-IOT,Online,460-11,0x5AE1,187212754,82,EUTRAN-BAND5,2506,"
    "0,0,-7,-115,-110,13\n"
    "OK\n";

/* --- MANUAL. SIM8200 Series AT Command Manual V1.00.01 §4.2.14 worked
 *     example: an EN-DC pair. The two lines use DIFFERENT signal scales in
 *     one response -- x10 on the LTE line, whole units on the NR line. --- */
static const char *CPSI_ENDC =
    "+CPSI: LTE,Online,460-11,0x5A1E,187214780,257,EUTRAN-BAND3,1825,4,4,"
    "-102,-924,-632,13\n"
    "+CPSI: NR5G,257,629952,-11,-92,153\n"
    "OK\n";

/* --- MANUAL. SIM8200 §4.2.14 NR5G-only camping form. Its signal columns
 *     are RSRP,RSRQ,RSSNR -- the OPPOSITE order to both LTE and EN-DC. --- */
static const char *CPSI_NR_SA =
    "+CPSI: NR5G,Online,311-480,0x1A2B,27439874,257,629952,-92,-11,15\n"
    "OK\n";

/* --- MEASURED. A SIM8202G-M2's (LE13B04SIM8202M44A-M2) actual reply,
 *     verbatim from an AT survey. A valid answer with nothing to report. --- */
static const char *CPSI_NO_SERVICE =
    "+CPSI: NO SERVICE,Online\n"
    "OK\n";

/* --- MANUAL. SIM8200 §4.2.14: "If set LTE+NR5G dual mode, but not camped on
 *     NR5G, it will display ... in second line." --- */
static const char *CPSI_NOT_IN_ENDC =
    "+CPSI: LTE,Online,460-11,0x5A1E,187214780,257,EUTRAN-BAND3,1825,4,4,"
    "-102,-924,-632,13\n"
    "+CPSI: NOT IN EN-DC CONNECTED MODE\n"
    "OK\n";

/* --- MANUAL. SIM8200 §4.2.14 GSM example. Deliberately NOT decoded. --- */
static const char *CPSI_GSM =
    "+CPSI: GSM,Online,460-00,0x182d,12401,27 EGSM 900,-64,2110,42-42\n"
    "OK\n";

int main(void) {
    char obs[MAX_OBS][JSON_BUF_MAX];
    int n;

    printf("test_cellat_cpsi\n\n");

    printf("[1] LTE, dBm x10 -- the measured SIM7600NA anchor\n");
    n = parse_cpsi(CPSI_LTE_TENTHS, obs, MAX_OBS);
    check(n == 1, "one observation parsed");
    if (n == 1) {
        check_has(obs[0], "\"rat\":\"LTE\"", "rat");
        check_has(obs[0], "\"mcc\":\"310\"", "mcc from the PLMN pair (as-broadcast string)");
        check_has(obs[0], "\"mnc\":\"260\"", "mnc from the PLMN pair (as-broadcast string)");
        /* Hex TAC beside a DECIMAL cell id, in one line. Reusing +QENG's
         * all-hex habit turns 27439874 into 1351406146. */
        check_has(obs[0], "\"tac\":6699", "tac 0x1A2B decoded as HEX");
        check_has(obs[0], "\"cell_id\":27439874", "cell_id decoded as DECIMAL");
        check_has(obs[0], "\"pci\":236", "pci");
        check_has(obs[0], "\"band\":4", "band from the EUTRAN-BAND4 label");
        check_has(obs[0], "\"earfcn\":2300", "earfcn");
        /* dlbw is an ENUM index -- 5 is 20 MHz, not 5 MHz. AT+QSCAN
         * reports EARFCN 2300 at 100 RB, which is the same 20 MHz. */
        check_has(obs[0], "\"bandwidth\":20", "dlbw enum 5 -> 20 MHz");
        /* The x10 normalisation, and the RSRQ-before-RSRP order. */
        check_has(obs[0], "\"rsrp\":-98", "rsrp -987 -> -98 dBm");
        check_has(obs[0], "\"rsrq\":-12", "rsrq -125 -> -12 dB (column BEFORE rsrp)");
        check_has(obs[0], "\"rssi\":-66", "rssi -663 -> -66 dBm");
        check_has(obs[0], "\"sinr\":10", "rssnr 10 left alone -- in range for whole dB");
        check_has(obs[0], "\"observation_type\":\"serving\"", "serving");
    }

    printf("\n[2] LTE, WHOLE units -- same layout, other half of the family\n");
    n = parse_cpsi(CPSI_LTE_WHOLE, obs, MAX_OBS);
    check(n == 1, "one observation parsed from the LPWA mode spelling");
    if (n == 1) {
        /* The scale must come from RSRP, not from the model. Dividing this
         * line by 10 would report a -11 dBm serving cell -- above the 3GPP
         * maximum and entirely plausible-looking in a JSON blob. */
        check_has(obs[0], "\"rsrp\":-115", "rsrp -115 NOT rescaled");
        check_has(obs[0], "\"rsrq\":-7", "rsrq -7 NOT rescaled");
        check_has(obs[0], "\"rssi\":-110", "rssi -110 NOT rescaled");
        check_has(obs[0], "\"band\":5", "band");
        check_has(obs[0], "\"cell_id\":187212754", "cell_id");
    }

    printf("\n[3] EN-DC -- TWO scales in ONE response\n");
    n = parse_cpsi(CPSI_ENDC, obs, MAX_OBS);
    check(n == 2, "two observations: LTE anchor + NR secondary");
    if (n == 2) {
        check_has(obs[0], "\"rat\":\"LTE\"", "line 1 is the LTE anchor");
        check_has(obs[0], "\"rsrp\":-92", "LTE rsrp -924 -> -92 (x10)");
        check_has(obs[1], "\"rat\":\"NR\"", "line 2 is NR");
        check_has(obs[1], "\"observation_type\":\"serving_secondary\"",
                  "the NR leg is secondary, not a second serving cell");
        /* Same numeral, -92, reached two different ways: the LTE line said
         * -924 in tenths, the NR line said -92 outright. A single hardcoded
         * scale gets exactly one of these right. */
        check_has(obs[1], "\"rsrp\":-92", "NR rsrp -92 NOT rescaled");
        check_has(obs[1], "\"rsrq\":-11", "NR rsrq -11 (column BEFORE rsrp here)");
        check_has(obs[1], "\"pci\":257", "NR pci from fields[1]");
        check_has(obs[1], "\"earfcn\":629952", "NR arfcn/ssb");
        check_has(obs[1], "\"sinr\":15", "rssnr 153 -> 15 dB (tenths, unlike rsrp)");
        /* The EN-DC line carries no identity at all -- inventing one from the
         * SA layout's column positions is the failure this form invites. */
        check_lacks(obs[1], "\"mcc\"", "NR secondary carries no mcc");
        check_lacks(obs[1], "\"tac\"", "NR secondary carries no tac");
        check_lacks(obs[1], "\"cell_id\"", "NR secondary carries no cell_id");
    }

    printf("\n[4] NR5G-SA -- the third field order\n");
    n = parse_cpsi(CPSI_NR_SA, obs, MAX_OBS);
    check(n == 1, "one observation parsed");
    if (n == 1) {
        check_has(obs[0], "\"rat\":\"NR\"", "rat");
        check_has(obs[0], "\"observation_type\":\"serving\"",
                  "SA is a serving cell, not a secondary leg");
        check_has(obs[0], "\"mcc\":\"311\"", "mcc -- SA DOES carry identity (as-broadcast string)");
        check_has(obs[0], "\"tac\":6699", "tac");
        check_has(obs[0], "\"cell_id\":27439874", "cell_id");
        check_has(obs[0], "\"pci\":257", "pci");
        check_has(obs[0], "\"earfcn\":629952", "arfcn");
        /* The trap this whole file exists for: RSRP precedes RSRQ here and
         * follows it in the other two forms. Swapping them yields rsrp=-11,
         * which is out of 3GPP range but silently emitted. */
        check_has(obs[0], "\"rsrp\":-92", "rsrp is the FIRST signal column here");
        check_has(obs[0], "\"rsrq\":-11", "rsrq is the SECOND");
    }

    printf("\n[5] NO SERVICE -- a valid reply with nothing to report\n");
    n = parse_cpsi(CPSI_NO_SERVICE, obs, MAX_OBS);
    check(n == 0, "zero observations, and NOT an error");

    printf("\n[6] the EN-DC 'not camped' notice must not decode as a cell\n");
    n = parse_cpsi(CPSI_NOT_IN_ENDC, obs, MAX_OBS);
    check(n == 1, "only the LTE line yields an observation");
    if (n == 1)
        check_has(obs[0], "\"rat\":\"LTE\"", "and it is the LTE one");

    printf("\n[7] GSM is deliberately not decoded (legacy-rat)\n");
    n = parse_cpsi(CPSI_GSM, obs, MAX_OBS);
    check(n == 0, "no observation -- a GSM branch would be an untested guess");

    printf("\n[8] the form classifier, directly\n");
    {
        /* The discriminator is a WORD-vs-NUMBER test on field[1], not a field
         * count -- so appending a column to either NR form must not flip it
         * into the other one's layout. */
        char sa[] = "NR5G,Online,311-480,0x1A2B,27439874,257,629952,-92,-11,15,99";
        char endc[] = "NR5G,257,629952,-11,-92,153,99";
        char *f[32];
        int nf = split_fields(sa, f, 32);
        check(rat_form_of(f, nf) == CPSI_FORM_NR_SA,
              "an SA line with an extra column is still SA");
        nf = split_fields(endc, f, 32);
        check(rat_form_of(f, nf) == CPSI_FORM_NR_ENDC,
              "an EN-DC line with an extra column is still EN-DC");
    }

    printf("\n[9] the scale decision itself\n");
    /* RSRP's 3GPP range (-140..-44) makes the two encodings disjoint; RSSI's
     * (-120..0) does not, which is why RSSI can never be the discriminator. */
    check(dbm_scale_of(-44, 1) == 1, "-44 dBm (3GPP max) reads as whole units");
    check(dbm_scale_of(-140, 1) == 1, "-140 dBm (3GPP min) reads as whole units");
    check(dbm_scale_of(-440, 1) == 10, "-44.0 dBm x10 reads as tenths");
    check(dbm_scale_of(-1400, 1) == 10, "-140.0 dBm x10 reads as tenths");
    check(dbm_scale_of(0, 0) == 1, "an ABSENT rsrp does not invent a scale");
    check(snr_scale_of(30, 1) == 1, "30 dB SNR is whole units");
    check(snr_scale_of(153, 1) == 10, "153 is tenths -- SNR does not follow rsrp");

    printf("\n[10] band labels\n");
    {
        long b = 0;
        check(parse_band_label("EUTRAN-BAND4", &b) && b == 4, "EUTRAN-BAND4 -> 4");
        check(parse_band_label("NR5G-BAND78", &b) && b == 78, "NR5G-BAND78 -> 78");
        check(!parse_band_label("2300", &b),
              "a bare number is not a band LABEL -- do not guess");
        check(!parse_band_label("EUTRAN-BAND", &b), "no digits -> no band");
    }

    printf("\n[11] leading-zero MNC is preserved as an as-broadcast string\n");
    n = parse_cpsi(CPSI_LTE_ZEROMNC, obs, MAX_OBS);
    check(n == 1, "one observation parsed");
    if (n == 1) {
        /* The key assertion: "310-01" must reach the server as mnc "01",
         * not the integer 1. A parse_int on the MNC half loses the count and
         * forces the lossy MCC-block reconstruction downstream. */
        check_has(obs[0], "\"mcc\":\"310\"", "mcc as string");
        check_has(obs[0], "\"mnc\":\"01\"", "mnc keeps the leading zero (NOT 1)");
    }

    printf("\n%s (%d failures)\n", g_fails ? "FAILED" : "PASSED", g_fails);
    return g_fails ? 1 : 0;
}

#endif /* CELL_SELFTEST */
