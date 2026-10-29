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

/*
    Selftest for the Telit AT#RFSTS decode core.

    The fixtures keep the reply's exact shape: the quoted "MCC MNC" PLMN, the
    hex TAC and cell ID, the empty TXPWR column an idle modem leaves, and the
    RAC of 255 an LTE cell reports in the seventh column. That 255 is the trap
    under test: it sits where a band would plausibly go, and reading it as the
    band (then dropping 255 as "not available") lost the band on every cell.

    Provenance is named at each declaration. Cell identities are placeholders.
*/

#ifdef CELL_SELFTEST

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/time.h>

#define JSON_BUF_MAX 4096
#define MAX_OBS 8

#include "cellat_qeng.inc"
#include "cellat_rfsts.inc"

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

/* --- MEASURED shape. A Telit LM960A18 (32.01.110) camped on LTE B66, idle;
 *     TAC and cell ID replaced with placeholders. RSSI -66, band 66. --- */
static const char *RFSTS_LM960 =
    "#RFSTS: \"310 260\",66786,-98,-66,-12,1A2B,255,,640,1,0,1A2B302,"
    "\"000000000000000\",\"T-Mobile\",3,66\r\n"
    "OK\r\n";

/* --- MANUAL. LM940 AT Commands Reference Guide r1, section 5.6.1.24 worked
 *     example, with a TXPWR present (in traffic) and band 20. IMSI zeroed. --- */
static const char *RFSTS_MANUAL_TXPWR =
    "#RFSTS: \"262 25\",6400,-99,-76,-7,40A5,255,0,640,19,0,0000007,"
    "\"000000000000000\",\" Telekom.de \",3,20\r\n"
    "OK\r\n";

/* --- A reply cut short before ABND (an older firmware, or a truncated
 *     read): no band must be invented. --- */
static const char *RFSTS_NO_ABND =
    "#RFSTS: \"310 260\",66786,-98,-66,-12,1A2B,255,,640,1,0,1A2B302\r\n"
    "OK\r\n";

/* --- ABND 0 is not an E-UTRA band. --- */
static const char *RFSTS_ABND_ZERO =
    "#RFSTS: \"310 260\",66786,-98,-66,-12,1A2B,255,,640,1,0,1A2B302,"
    "\"000000000000000\",\"T-Mobile\",3,0\r\n"
    "OK\r\n";

int main(void) {
    char obs[MAX_OBS][JSON_BUF_MAX];
    int n;

    printf("[1] LM960A18 idle on B66: RSSI and the active band are read\n");
    n = parse_rfsts(RFSTS_LM960, obs, MAX_OBS);
    check(n == 1, "one observation parsed");
    if (n == 1) {
        check_has(obs[0], "\"mcc\":\"310\"", "mcc");
        check_has(obs[0], "\"mnc\":\"260\"", "mnc");
        check_has(obs[0], "\"earfcn\":66786", "earfcn");
        check_has(obs[0], "\"rsrp\":-98", "rsrp is field 2");
        check_has(obs[0], "\"rssi\":-66", "rssi is field 3 (not TX power)");
        check_has(obs[0], "\"rsrq\":-12", "rsrq is field 4");
        check_has(obs[0], "\"tac\":6699", "tac is hex 1A2B");
        check_has(obs[0], "\"cell_id\":27439874", "cell id is hex 1A2B302");
        check_has(obs[0], "\"band\":66", "band is ABND, the last field");
        check_lacks(obs[0], "\"band\":255", "RAC 255 is never the band");
        check_has(obs[0], "\"observation_type\":\"serving\"", "serving cell");
    }

    printf("\n[2] manual example with TXPWR present\n");
    n = parse_rfsts(RFSTS_MANUAL_TXPWR, obs, MAX_OBS);
    check(n == 1, "one observation parsed");
    if (n == 1) {
        check_has(obs[0], "\"rssi\":-76", "rssi");
        check_has(obs[0], "\"rsrq\":-7", "rsrq");
        check_has(obs[0], "\"band\":20", "band 20 from ABND");
        check_has(obs[0], "\"tac\":16549", "tac is hex 40A5");
        check_has(obs[0], "\"cell_id\":7", "cell id 0000007");
    }

    printf("\n[3] no ABND column: no band invented\n");
    n = parse_rfsts(RFSTS_NO_ABND, obs, MAX_OBS);
    check(n == 1, "one observation parsed");
    if (n == 1) {
        check_lacks(obs[0], "\"band\"", "no band key");
        check_has(obs[0], "\"rssi\":-66", "rssi still read");
    }

    printf("\n[4] ABND 0 is not a band\n");
    n = parse_rfsts(RFSTS_ABND_ZERO, obs, MAX_OBS);
    check(n == 1, "one observation parsed");
    if (n == 1)
        check_lacks(obs[0], "\"band\"", "no band key");

    printf("\n[5] a reply with no #RFSTS line\n");
    check(parse_rfsts("OK\r\n", obs, MAX_OBS) == 0, "bare OK -> no observation");
    check(parse_rfsts("ERROR\r\n", obs, MAX_OBS) == 0, "ERROR -> no observation");

    printf("\n%s (%d failures)\n", g_fails ? "FAILED" : "PASSED", g_fails);
    return g_fails ? 1 : 0;
}

#endif /* CELL_SELFTEST */
