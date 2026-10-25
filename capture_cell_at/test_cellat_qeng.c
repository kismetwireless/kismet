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

    Selftest for the AT+QENG decode core.

    The anchor case is a real one: an RM520N-GL (RM520NGLAAR03A04M4G) parked on
    Verizon B66 reports RSSI -56 in its serving-cell response at fields[15]. A
    serving parser that never reads that field leaves every serving device at
    rssi=0 while the modem said -56.

    Every response string below is a VERBATIM line from a cellat transcript of
    that modem. Do not "tidy" them -- the "-" placeholders and the field counts
    are the parser's actual input.

    The free oracle: the same physical cell (PCI 221, EARFCN 66536) is reported
    by BOTH AT+QENG="servingcell" and AT+QENG="neighbourcell" in the same poll
    cycle, and the neighbour path decodes RSSI independently. So the two
    paths must agree on -56 -- that cross-check is what makes this a real
    regression test rather than a restatement of the implementation.
*/

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/time.h>

/* cellat_qeng.inc expects the includer to have defined this, exactly as
 * capture_cell_at.c does. Keep in sync with capture_cell_at.c. */
#define JSON_BUF_MAX 4096

/* Local to the harness -- the shipping binary sizes this as MAX_OBS_PER_RESP.
 * Any value larger than the biggest response below is fine. */
#define MAX_OBS 8

#include "cellat_qeng.inc"

static int g_fails = 0;

static void check(int cond, const char *what) {
    if (cond) {
        printf("  OK    %s\n", what);
    } else {
        printf("  FAIL  %s\n", what);
        g_fails++;
    }
}

/* Assert a JSON key/value pair is present. Values are emitted by
 * build_cell_json as bare numbers, so a substring match on "key":value is
 * unambiguous given the surrounding quotes and colon. */
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

/* --- the anchor: RM520N-GL on Verizon B66, verbatim from the transcript --- */
static const char *SERVING_LTE =
    "+QENG: \"servingcell\",\"NOCONN\",\"LTE\",\"FDD\",311,480,BBB320,221,66536,"
    "66,5,5,BBB,-96,-11,-56,14,0,-,29\n"
    "OK\n";

/* Same poll cycle, same physical cell (PCI 221 / EARFCN 66536) via the
 * neighbour path. */
static const char *NEIGHBOUR_LTE =
    "+QENG: \"neighbourcell intra\",\"LTE\",66536,221,-10,-96,-56,-,29,7,8,4,255\n"
    "OK\n";

/* --- a SIM-less EG25-G at LIMSRV, verbatim from a cellat transcript ---
 *
 * Twelve neighbour rows, four of them LTE. The other eight are GSM and are
 * DROPPED ON PURPOSE (the legacy-RAT policy) -- the tally exists so the
 * drop is observable, not so the rows get parsed.
 *
 * Note the ARFCNs in the GSM rows: 685, 684, 683, 585, 584, 583, 515, 514.
 * They sit in the field position the LTE rows use for an EARFCN, and 685 fed
 * to earfcn_to_band() lands inside B2 (600-1199). A GSM row reaching the
 * observation layer would render as "LTE B2" in WiGLE-bound output. */
static const char *NEIGHBOUR_EG25G_MIXED =
    "+QENG: \"neighbourcell intra\",\"LTE\",2300,236,-16,-101,-65,-20,22,6,2,0,46\n"
    "+QENG: \"neighbourcell intra\",\"LTE\",2300,471,-17,-104,-78,-20,19,6,2,0,46\n"
    "+QENG: \"neighbourcell inter\",\"LTE\",900,-,-,-,-,-,-,0,8,5\n"
    "+QENG: \"neighbourcell inter\",\"LTE\",5035,-,-,-,-,-,-,0,8,2\n"
    "+QENG: \"neighbourcell\",\"GSM\",685,0,4,10,255,1,0,-1920,0\n"
    "+QENG: \"neighbourcell\",\"GSM\",684,0,4,10,255,1,0,-1920,0\n"
    "+QENG: \"neighbourcell\",\"GSM\",683,0,4,10,255,1,0,-1920,0\n"
    "+QENG: \"neighbourcell\",\"GSM\",585,0,4,10,255,1,0,-1920,0\n"
    "+QENG: \"neighbourcell\",\"GSM\",584,0,4,10,255,1,0,-1920,0\n"
    "+QENG: \"neighbourcell\",\"GSM\",583,0,4,10,255,1,0,-1920,0\n"
    "+QENG: \"neighbourcell\",\"GSM\",515,0,4,10,255,1,0,-1920,0\n"
    "+QENG: \"neighbourcell\",\"GSM\",514,0,4,10,255,1,0,-1920,0\n"
    "OK\n";

/* RAT tokens normalize_rat() does NOT recognise. Not observed on real
 * hardware -- that is the point: they stand in for the firmware surprise the
 * tally must be able to distinguish from policy.
 *
 * TWO DIFFERENT unknown tokens, deliberately. With only one, "keep the FIRST
 * token" and "keep the LAST token" are indistinguishable, so a last-wins
 * mutation would survive a single-token fixture. The claim
 * is load-bearing: the caller reports an unknown token once per DISTINCT
 * value, so a parser that kept the last one would re-report on every poll of a
 * modem emitting two. */
static const char *NEIGHBOUR_UNKNOWN_RAT =
    "+QENG: \"neighbourcell intra\",\"LTE\",2300,236,-16,-101,-65,-20,22,6,2,0,46\n"
    "+QENG: \"neighbourcell\",\"NR5G-XX\",123456,505,-11,-88,-,-,-,-,-\n"
    "+QENG: \"neighbourcell\",\"ZZ-RAT\",654321,101,-12,-90,-,-,-,-,-\n"
    "OK\n";

/* Recognised by normalize_rat(), declined by parse_qeng_neighbor()'s LTE-only
 * body. Distinct from the row above: this is policy, that is a surprise. */
static const char *NEIGHBOUR_NR_DECLINED =
    "+QENG: \"neighbourcell\",\"NR5G-NSA\",504990,505,-11,-88,-,-,-,-,-\n"
    "OK\n";

/* NR5G-SA shares the serving call site but its field layout carries NO RSSI:
 *   MCC,MNC,cellID,PCID,TAC,ARFCN,band,NR_DL_BW,RSRP,RSRQ,SINR,scs,srxlev
 * Fixing RSSI at the shared call site instead of inside the LTE branch would
 * make this row report a fabricated RSSI lifted from an unrelated column. */
static const char *SERVING_NR5G_SA =
    "+QENG: \"servingcell\",\"NOCONN\",\"NR5G-SA\",\"TDD\",311,480,1A2B3C4,505,"
    "BBB,504990,78,12,-88,-11,15,1,31\n"
    "OK\n";

/* The same row in RRC-connected state -- the only state in which the
 * manuals define NR_DL_bandwidth. Synthetic: no recorded capture has a
 * CONNECT NR5G-SA servingcell line (all are LIMSRV/NOCONN). */
static const char *SERVING_NR5G_SA_CONNECT =
    "+QENG: \"servingcell\",\"CONNECT\",\"NR5G-SA\",\"TDD\",311,480,1A2B3C4,505,"
    "BBB,504990,78,12,-88,-11,15,1,31\n"
    "OK\n";

/* --- the NR5G-NSA secondary row -- VERBATIM from the vendor manual ---
 *
 * The field layout (RM5xxQ, RM500U, and RG520N/RM520N AT manuals all agree):
 *   +QENG: "NR5G-NSA",<MCC>,<MNC>,<PCID>,<RSRP>,<SINR>,<RSRQ>,<ARFCN>,<band>,
 *          <NR_DL_bandwidth>,<scs>
 *
 * The oracle is the worked example printed in
 *   Quectel_RG50xQ_RM5xxQ_Series_5G_Network_Searching_Scheme_Introduction_V1.0,
 * reproduced identically in the RM500U and RG520N/RM520N AT manuals:
 *
 *   +QENG:"NR5G-NSA",460,01,747,-71,13,-11,627264,78,12,1
 *
 * The physics fixes the field order with no ambiguity: RSRQ is the -11 (RSRQ is
 * always negative), ARFCN is 627264 (a valid n78 SSB, and an ARFCN can never be
 * negative), and band is 78. Reading the order as ...RSRP,RSRQ,ARFCN,band...
 * -- skipping SINR -- shifts every column from index 5 on: SINR(13) becomes
 * rsrq, RSRQ(-11) a NEGATIVE earfcn, and ARFCN(627264) an absurd band, while
 * the real ARFCN and band are dropped: the "value from an unrelated column"
 * failure. */
static const char *SERVING_NR5G_NSA =
    "+QENG:\"NR5G-NSA\",460,01,747,-71,13,-11,627264,78,12,1\n"
    "OK\n";

int main(void) {
    char obs[MAX_OBS][JSON_BUF_MAX];
    int n;

    printf("test_cellat_qeng\n\n");

    printf("[1] AT+QENG=\"servingcell\" LTE -- the RSSI anchor\n");
    n = parse_qeng_serving(SERVING_LTE, obs, MAX_OBS);
    check(n == 1, "one observation parsed");
    if (n == 1) {
        /* The bug: -56 is in the response and must reach the JSON. */
        check_has(obs[0], "\"rssi\":-56", "rssi decoded from fields[15]");

        /* Guard the neighbours of the changed line -- an off-by-one in the
         * field index would corrupt these rather than the RSSI. */
        check_has(obs[0], "\"rsrp\":-96", "rsrp still fields[13]");
        check_has(obs[0], "\"rsrq\":-11", "rsrq still fields[14]");
        check_has(obs[0], "\"sinr\":14", "sinr still fields[16]");

        /* Hex identity decode, verified against a live modem. */
        check_has(obs[0], "\"cell_id\":12301088", "cell_id 0xBBB320 decoded as hex");
        check_has(obs[0], "\"tac\":3003", "tac 0xBBB decoded as hex");
        check_has(obs[0], "\"mcc\":\"311\"", "mcc (as-broadcast string)");
        check_has(obs[0], "\"mnc\":\"480\"", "mnc (as-broadcast string)");
        check_has(obs[0], "\"pci\":221", "pci");
        check_has(obs[0], "\"earfcn\":66536", "earfcn");
        check_has(obs[0], "\"band\":66", "band");
        /* DL_BW 5 is the enum for 20 MHz. AT+QSCAN reports the same B66
         * carriers at 100 RB and Telit #CSURV at 20 -- three commands, one
         * answer. A pass-through would write 5. */
        check_has(obs[0], "\"bandwidth\":20", "DL_BW enum 5 -> 20 MHz");
        check_lacks(obs[0], "\"bandwidth\":5,", "the raw enum index is NOT emitted");
    }

    printf("\n[2] the free oracle -- both paths see PCI 221 and must agree\n");
    {
        char nobs[MAX_OBS][JSON_BUF_MAX];
        int nn = parse_qeng_neighbor(NEIGHBOUR_LTE, nobs, MAX_OBS, NULL);
        check(nn == 1, "one neighbour observation parsed");
        if (nn == 1 && n == 1) {
            check_has(nobs[0], "\"rssi\":-56", "neighbour path decodes rssi");
            /* The actual cross-check: serving and neighbour reports of the SAME
             * cell in the SAME poll must not disagree about its RSSI. */
            check(strstr(obs[0], "\"rssi\":-56") && strstr(nobs[0], "\"rssi\":-56"),
                  "serving and neighbour agree on rssi for PCI 221");
        }
    }

    printf("\n[3] NR5G-SA has no RSSI field -- must not invent one\n");
    n = parse_qeng_serving(SERVING_NR5G_SA, obs, MAX_OBS);
    check(n == 1, "one observation parsed");
    if (n == 1) {
        check_lacks(obs[0], "\"rssi\"", "no rssi key emitted for NR5G-SA");
        /* Prove the row decoded at all, so the check above is not passing
         * merely because nothing was parsed. */
        check_has(obs[0], "\"rsrp\":-88", "rsrp decoded");
        check_has(obs[0], "\"pci\":505", "pci decoded");
        /* NR_DL_BW 12 is present on this NOCONN row, but the manuals
         * define it only in RRC-connected state, so it must not be mapped. */
        check_lacks(obs[0], "\"bandwidth\"", "idle NR5G-SA row carries no bandwidth");
    }

    printf("\n[3b] NR5G-SA in CONNECT maps the NR enum\n");
    n = parse_qeng_serving(SERVING_NR5G_SA_CONNECT, obs, MAX_OBS);
    check(n == 1, "one observation parsed");
    if (n == 1) {
        check_has(obs[0], "\"bandwidth\":100", "NR_DL_BW enum 12 -> 100 MHz");
        check_has(obs[0], "\"rsrp\":-88", "rsrp still fields[12]");
    }

    printf("\n[3c] bandwidth encodings -> MHz, both edges\n");
    {
        long m = -1;
        static const long lte_enum[6] = { -1, 3, 5, 10, 15, 20 };
        int i;
        check(!lte_bw_enum_to_mhz(0, &m), "LTE enum 0 (1.4 MHz) is omitted, never a truncated 1");
        for (i = 1; i <= 5; i++) {
            char what[64];
            m = -1;
            snprintf(what, sizeof what, "LTE enum %d -> %ld MHz", i, lte_enum[i]);
            check(lte_bw_enum_to_mhz(i, &m) && m == lte_enum[i], what);
        }
        check(!lte_bw_enum_to_mhz(6, &m), "LTE enum 6 is out of range");
        check(!lte_bw_enum_to_mhz(-1, &m), "LTE enum -1 is out of range");

        static const long rb[5]  = { 15, 25, 50, 75, 100 };
        static const long mhz[5] = { 3, 5, 10, 15, 20 };
        for (i = 0; i < 5; i++) {
            char what[64];
            m = -1;
            snprintf(what, sizeof what, "LTE %ld RB -> %ld MHz", rb[i], mhz[i]);
            check(lte_bw_rb_to_mhz(rb[i], &m) && m == mhz[i], what);
        }
        check(!lte_bw_rb_to_mhz(6, &m), "6 RB (1.4 MHz) is omitted");
        check(!lte_bw_rb_to_mhz(20, &m), "20 is not an RB count -- a MHz value must not pass");
        check(!lte_bw_rb_to_mhz(5, &m), "5 is not an RB count -- an enum index must not pass");

        static const long nr[17] = { 5, 10, 15, 20, 25, 30, 40, 50, 60,
                                     70, 80, 90, 100, 200, 400, 35, 45 };
        for (i = 0; i < 17; i++) {
            char what[64];
            m = -1;
            snprintf(what, sizeof what, "NR enum %d -> %ld MHz", i, nr[i]);
            check(nr_bw_enum_to_mhz(i, &m) && m == nr[i], what);
        }
        check(!nr_bw_enum_to_mhz(17, &m), "NR enum 17 is out of range");
        check(!nr_bw_enum_to_mhz(-1, &m), "NR enum -1 is out of range");
    }

    /* ---------------------------------------------------------------------
     * identify_modem()'s value extraction.
     *
     * The failure is silent by construction: a firmware string carrying the
     * `+CGMR: ` response-code prefix matches NONE of the left-anchored
     * `firmware_match` globs in profiles/, so the modem gets no DIAG profile,
     * no mask, no target codes -- and no error. The `--list` line looks merely
     * untidy. So the assertions below check the FIRMWARE STRING and then check
     * the glob that consumes it, because the first alone reads as cosmetic.
     */
    printf("\n[4] AT+CGMR value extraction\n");
    {
        char v[128];

        /* A real SIM8202G-M2 reply, verbatim. */
        char simcom[] = "\r\n+CGMR: LE13B04SIM8202M44A-M2\r\n\r\nOK\r\n";
        check(at_response_value(simcom, v, sizeof(v)) == 1, "simcom response yields a value");
        check(strcmp(v, "LE13B04SIM8202M44A-M2") == 0,
              "the +CGMR: prefix is stripped");

        /* The consequence, asserted rather than described: the profile
         * selector globs left-anchored, so this is what the prefix broke. */
        check(strncmp(v, "LE13B04", 7) == 0,
              "the stripped string is left-anchored-matchable");
        check(strncmp("+CGMR: LE13B04SIM8202M44A-M2", "LE13B04", 7) != 0,
              "...and the unstripped one was NOT (this is the whole bug)");

        /* Bare version strings must stay byte-identical -- "tidying" them
         * would break the modems that answer this way. Both strings are
         * real. */
        char quectel[] = "\r\nEG25GGBR07A08M2G\r\n\r\nOK\r\n";
        check(at_response_value(quectel, v, sizeof(v)) == 1, "quectel yields a value");
        check(strcmp(v, "EG25GGBR07A08M2G") == 0, "bare quectel string untouched");

        char telit[] = "\r\n32.01.110\r\n\r\nOK\r\n";
        check(at_response_value(telit, v, sizeof(v)) == 1, "telit yields a value");
        check(strcmp(v, "32.01.110") == 0, "bare telit string untouched");

        /* The CR is part of the line after strtok_r on "\n". Left on, it
         * defeats a left-anchored glob exactly as the prefix does -- and it
         * would be invisible in any log. */
        char crlf[] = "RM520NGLAAR03A04M4G\r\nOK\r\n";
        check(at_response_value(crlf, v, sizeof(v)) == 1, "crlf response yields a value");
        check(strcmp(v, "RM520NGLAAR03A04M4G") == 0, "trailing CR is trimmed");

        /* A colon INSIDE a version string must survive. Anchoring the strip
         * on a leading '+' is what makes this safe; splitting on the first
         * colon would be a second bug wearing the first one's clothes. */
        char colon[] = "SWI9X30C_02.20.03.00 r6691 CARMD-EV-FRMWR2 2016/06/23 05:26:22\r\nOK\r\n";
        check(at_response_value(colon, v, sizeof(v)) == 1, "colon-bearing string yields a value");
        check(strcmp(v, "SWI9X30C_02.20.03.00 r6691 CARMD-EV-FRMWR2 2016/06/23 05:26:22") == 0,
              "a colon inside a version string is NOT a prefix");

        /* Rejections. A bare ERROR must not be accepted as the firmware
         * string: excluding only "OK" and "+CME" is not enough, and bare-ERROR
         * replies occur on real modems. */
        char err[] = "\r\nERROR\r\n";
        check(at_response_value(err, v, sizeof(v)) == 0, "bare ERROR is not a firmware string");
        check(v[0] == '\0', "...and leaves the output empty");

        char cme[] = "\r\n+CME ERROR: 10\r\n";
        check(at_response_value(cme, v, sizeof(v)) == 0, "+CME ERROR is rejected");

        char cms[] = "\r\n+CMS ERROR: 500\r\n";
        check(at_response_value(cms, v, sizeof(v)) == 0, "+CMS ERROR is rejected");

        char empty[] = "\r\n\r\nOK\r\n";
        check(at_response_value(empty, v, sizeof(v)) == 0, "an OK-only response yields nothing");

        /* A prefix with an empty value is not a value -- it must not record
         * the empty string as a firmware and pass identify_modem's !fw_buf[0]
         * gate by accident. */
        char bare_prefix[] = "\r\n+CGMR: \r\nOK\r\n";
        check(at_response_value(bare_prefix, v, sizeof(v)) == 0,
              "a prefix with no value is not a value");

        /* IMEI goes through the same extraction. Most modems answer
         * +CGSN bare; the response-code form is equally legal. */
        char imei_bare[] = "\r\n123456789012345\r\n\r\nOK\r\n";
        check(at_response_value(imei_bare, v, sizeof(v)) == 1, "bare imei yields a value");
        check(strcmp(v, "123456789012345") == 0, "bare imei untouched");

        char imei_pfx[] = "\r\n+CGSN: 123456789012345\r\n\r\nOK\r\n";
        check(at_response_value(imei_pfx, v, sizeof(v)) == 1, "prefixed imei yields a value");
        check(strcmp(v, "123456789012345") == 0, "+CGSN: prefix is stripped too");
    }

    /* ---------------------------------------------------------------------
     * The GSM neighbour rows are dropped correctly and SILENTLY.
     *
     * "Correct outcome with no observable" is indistinguishable from a
     * malfunction: if normalize_rat() started returning NULL for a RAT it
     * should have handled, or a firmware shipped a new token, the symptom
     * would be identical to the healthy state -- fewer cells, no message.
     * So these assertions are about the TALLY, and they check both directions:
     * that the drop is counted, and that it is still a drop.
     */
    printf("\n[5] out-of-scope neighbour rows are counted, not just dropped\n");
    {
        char nobs[MAX_OBS][JSON_BUF_MAX];
        qeng_neighbor_drops_t d;
        char summary[128];

        int nn = parse_qeng_neighbor(NEIGHBOUR_EG25G_MIXED, nobs, MAX_OBS, &d);

        /* Still a drop. If this ever becomes 12 the legacy-rat policy has been
         * violated, whatever the tally says. */
        check(nn == 4, "the four LTE rows are the only observations");
        check(d.emitted == 4, "tally agrees with the return value");

        /* The count the operator was missing. */
        check(d.rows == 12, "all twelve neighbour rows were seen");
        check(d.declined == 8, "eight rows declined by policy");
        check(d.declined_by_rat[QENG_RAT_GSM] == 8, "...all eight attributed to GSM");
        check(d.unknown == 0, "no unrecognised RAT token in this response");

        /* The load-bearing half: ARFCN 685 must not have become EARFCN 685,
         * which earfcn_to_band() would render as LTE B2. Checked against every
         * emitted observation, not just the first. */
        {
            int fabricated = 0;
            for (int i = 0; i < nn; i++) {
                if (strstr(nobs[i], "\"earfcn\":685") || strstr(nobs[i], "\"earfcn\":514"))
                    fabricated = 1;
            }
            check(!fabricated, "no GSM ARFCN leaked into an earfcn field");
        }
        /* ...and prove the LTE EARFCNs DID land, so the check above is not
         * passing merely because nothing was parsed. */
        check_has(nobs[0], "\"earfcn\":2300", "the LTE rows kept their earfcn");
        check_has(nobs[0], "\"pci\":236", "...and their pci");

        /* The rendered suffix for the existing `observation: N cells` line. */
        check(qeng_drops_summary(&d, summary, sizeof(summary)) > 0,
              "a summary is rendered when rows were dropped");
        check_has(summary, "8 out-of-scope", "summary carries the drop count");
        check_has(summary, "GSM x8", "summary attributes them to GSM");
    }

    printf("\n[6] an UNRECOGNISED token is not the same event as a declined one\n");
    {
        char nobs[MAX_OBS][JSON_BUF_MAX];
        qeng_neighbor_drops_t d;
        char summary[128];

        int nn = parse_qeng_neighbor(NEIGHBOUR_UNKNOWN_RAT, nobs, MAX_OBS, &d);
        check(nn == 1, "the LTE row still parses alongside the surprise");
        check(d.unknown == 2, "both unknown tokens are counted as unknown");
        check(d.declined == 0, "...and NOT as a policy decline");
        check(strcmp(d.unknown_token, "NR5G-XX") == 0,
              "the FIRST offending token is the one kept, not the last");
        check(qeng_drops_summary(&d, summary, sizeof(summary)) > 0, "summary rendered");
        check_has(summary, "NR5G-XX", "summary names the unrecognised token");

        /* The other side of the same distinction: a RAT normalize_rat() knows
         * and this parser declines is policy, and must not read as a surprise. */
        nn = parse_qeng_neighbor(NEIGHBOUR_NR_DECLINED, nobs, MAX_OBS, &d);
        check(nn == 0, "the NR neighbour row is not decoded");
        check(d.unknown == 0, "a recognised RAT is never an unknown token");
        check(d.declined == 1, "it is a decline");
        check(d.declined_by_rat[QENG_RAT_NR] == 1, "...attributed to NR");
        check(d.unknown_token[0] == '\0', "no token recorded for a decline");
    }

    printf("\n[7] nothing changes for a modem whose rows are all in scope\n");
    {
        char nobs[MAX_OBS][JSON_BUF_MAX];
        qeng_neighbor_drops_t d;
        char summary[128];

        int nn = parse_qeng_neighbor(NEIGHBOUR_LTE, nobs, MAX_OBS, &d);
        check(nn == 1, "the all-LTE response is unaffected");
        check(d.rows == 1 && d.declined == 0 && d.unknown == 0, "nothing dropped");

        /* An empty suffix is what keeps `observation: 1 cells` byte-identical
         * for every modem that never emits an out-of-scope row. */
        check(qeng_drops_summary(&d, summary, sizeof(summary)) == 0,
              "no summary is rendered when nothing was dropped");
        check(summary[0] == '\0', "...and the buffer is left empty, not stale");

        /* The tally is optional: the parser must still work for a caller that
         * does not want it. */
        nn = parse_qeng_neighbor(NEIGHBOUR_EG25G_MIXED, nobs, MAX_OBS, NULL);
        check(nn == 4, "a NULL tally pointer is accepted");

        /* A too-small buffer must truncate, not overrun.
         *
         * The canary is the whole point. The summary is built by repeated
         * snprintf() appends, and snprintf returns the length it WOULD have
         * written -- so a cursor that walks past the end makes the NEXT call's
         * `buf_sz - off` underflow into a huge size_t and write off the end.
         * Checking only the return value and the terminator does NOT see that:
         * removing the range guard leaves both of those correct while
         * scribbling past the buffer. */
        parse_qeng_neighbor(NEIGHBOUR_EG25G_MIXED, nobs, MAX_OBS, &d);
        {
            struct { char buf[8]; char canary[32]; } t;
            memset(t.canary, 0x5A, sizeof(t.canary));

            int w = qeng_drops_summary(&d, t.buf, sizeof(t.buf));
            check(w < (int)sizeof(t.buf), "summary respects a short buffer");
            check(t.buf[sizeof(t.buf) - 1] == '\0', "...and stays NUL-terminated");

            int trampled = 0;
            for (size_t i = 0; i < sizeof(t.canary); i++)
                if (t.canary[i] != (char)0x5A) trampled = 1;
            check(!trampled, "...and writes nothing past the end of the buffer");
        }
    }

    /* ---------------------------------------------------------------------
     * The NR5G-NSA secondary row decodes to the RIGHT columns.
     *
     * A field-order bug here (SINR omitted from the layout, shifting
     * rsrq/arfcn/band by one column each) is otherwise silent.
     * The assertions below are grounded in the vendor's own worked example, so
     * each one names the manual field it is defending, not the implementation.
     */
    printf("\n[8] AT+QENG NR5G-NSA secondary decodes to the right columns\n");
    n = parse_qeng_serving(SERVING_NR5G_NSA, obs, MAX_OBS);
    check(n == 1, "one observation parsed");
    if (n == 1) {
        check_has(obs[0], "\"rat\":\"NR\"", "rat is NR");
        check_has(obs[0], "\"observation_type\":\"serving_secondary\"",
                  "tagged as the NSA secondary leg");
        check_has(obs[0], "\"mcc\":\"460\"", "mcc is fields[1] (as-broadcast string)");
        check_has(obs[0], "\"mnc\":\"01\"", "mnc is fields[2] -- 01 kept as broadcast, NOT 1");
        check_has(obs[0], "\"pci\":747", "pci is fields[3]");
        check_has(obs[0], "\"rsrp\":-71", "rsrp is fields[4]");

        /* The shift, asserted three ways -- each is a column a one-off shift
         * corrupts. */
        check_has(obs[0], "\"sinr\":13", "sinr is fields[5] (was dropped)");
        check_has(obs[0], "\"rsrq\":-11", "rsrq is fields[6] (was fed SINR)");
        check_has(obs[0], "\"earfcn\":627264",
                  "arfcn is fields[7] (n78 SSB; was fed RSRQ)");
        check_has(obs[0], "\"band\":78", "band is fields[8] (was fed the ARFCN)");

        /* The load-bearing negative checks: the corrupted columns must NOT
         * carry the wrong-source value. A negative earfcn is physically
         * impossible and is the loudest tell of the shift. */
        check_lacks(obs[0], "\"earfcn\":-11",
                    "earfcn never carries the RSRQ value (no negative ARFCN)");
        check_lacks(obs[0], "\"band\":627264",
                    "band never carries the ARFCN value (no absurd band)");
        check_lacks(obs[0], "\"rsrq\":13",
                    "rsrq never carries the SINR value");
    }

    printf("\n[9] PLMN helpers preserve the broadcast digit count\n");
    /* These three helpers are the shared core of EVERY AT PLMN path (CPSI/QENG
     * via plmn_split_dash/plmn_field; Telit SERVINFO/SCELLINFO via
     * plmn_split_mccmnc; RFSTS/MONI/gstatus via plmn_field). The formats below
     * are the VERBATIM shapes measured on live modems: LM960 #SERVINFO
     * "310260", #RFSTS "310 260"; RM500Q/EG25 +QENG ...,310,260,... */
    {
        /* plmn_field: 1-3 digit tokens pass through; a leading zero is kept */
        check(plmn_field("310") && strcmp(plmn_field("310"), "310") == 0,
              "plmn_field(\"310\") -> \"310\"");
        check(plmn_field("01") && strcmp(plmn_field("01"), "01") == 0,
              "plmn_field(\"01\") -> \"01\" (leading zero kept, NOT 1)");
        check(plmn_field("00") && strcmp(plmn_field("00"), "00") == 0,
              "plmn_field(\"00\") -> \"00\"");
        check(plmn_field("") == NULL, "plmn_field(\"\") -> NULL (absent)");
        check(plmn_field("26a") == NULL, "plmn_field(\"26a\") -> NULL (non-digit)");
        check(plmn_field("1234") == NULL, "plmn_field(\"1234\") -> NULL (>3 digits)");
    }
    {
        /* plmn_split_dash: CPSI/gstatus "MCC-MNC" */
        char mc[8] = "", mn[8] = "";
        check(plmn_split_dash("310-260", mc, sizeof mc, mn, sizeof mn) &&
              strcmp(mc, "310") == 0 && strcmp(mn, "260") == 0,
              "plmn_split_dash(\"310-260\") -> 310/260");
        mc[0] = mn[0] = '\0';
        check(plmn_split_dash("460-00", mc, sizeof mc, mn, sizeof mn) &&
              strcmp(mc, "460") == 0 && strcmp(mn, "00") == 0,
              "plmn_split_dash(\"460-00\") -> 460/00 (leading zeros kept)");
        mc[0] = mn[0] = '\0';
        check(plmn_split_dash("311-01", mc, sizeof mc, mn, sizeof mn) &&
              strcmp(mn, "01") == 0, "plmn_split_dash(\"311-01\") -> mnc 01");
        check(plmn_split_dash("nodash", mc, sizeof mc, mn, sizeof mn) == 0,
              "plmn_split_dash(\"nodash\") -> 0 (no dash)");
        check(plmn_split_dash("31x-26", mc, sizeof mc, mn, sizeof mn) == 0,
              "plmn_split_dash rejects a non-digit MCC");
    }
    {
        /* plmn_split_mccmnc: Telit #SERVINFO / SCELLINFO CGI blob */
        char mc[8] = "", mn[8] = "";
        check(plmn_split_mccmnc("310260", mc, sizeof mc, mn, sizeof mn) &&
              strcmp(mc, "310") == 0 && strcmp(mn, "260") == 0,
              "plmn_split_mccmnc(\"310260\") -> 310/260 (live #SERVINFO shape)");
        mc[0] = mn[0] = '\0';
        check(plmn_split_mccmnc("31000", mc, sizeof mc, mn, sizeof mn) &&
              strcmp(mc, "310") == 0 && strcmp(mn, "00") == 0,
              "plmn_split_mccmnc(\"31000\") -> 310/00 (2-digit MNC, zeros kept)");
        mc[0] = mn[0] = '\0';
        check(plmn_split_mccmnc("46001", mc, sizeof mc, mn, sizeof mn) &&
              strcmp(mn, "01") == 0, "plmn_split_mccmnc(\"46001\") -> mnc 01");
        check(plmn_split_mccmnc("123", mc, sizeof mc, mn, sizeof mn) == 0,
              "plmn_split_mccmnc(\"123\") -> 0 (too short)");
        check(plmn_split_mccmnc("3102x0", mc, sizeof mc, mn, sizeof mn) == 0,
              "plmn_split_mccmnc rejects a non-digit blob");
    }

    printf("\n%s: %d failure(s)\n", g_fails ? "FAIL" : "PASS", g_fails);
    return g_fails ? 1 : 0;
}
