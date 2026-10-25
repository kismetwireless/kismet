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

    Selftest for the AT+QSCAN=3,1 decode core.

    parse_qscan maps the LTE <bandwidth> field from a resource-block count to
    MHz and deliberately omits the NR5G row's value. This harness includes
    cellat_qscan.inc -- the exact text the shipping binary compiles -- and
    drives it over recorded QSCAN responses, so both the strcmp(rat,"LTE")
    gate and the fields[11] index are pinned.

    Every +QSCAN line below marked "corpus" is VERBATIM from an AT+QSCAN=3,1
    transcript captured on an RM520N-GL (RM520NGLAAR03A04M4G). Do not "tidy"
    them: the "-" placeholders, the extra NR5G trailing fields, and the
    T-Mobile/AT&T dual-PLMN rows are the parser's actual input.

    The free oracle for the LTE-only gate: the SAME numeric field[11]=100 is an
    RB count on an LTE row (-> 20 MHz) and NOT a bandwidth on an NR5G row (its
    field[11] is some other, unmapped quantity). So a real LTE row and a matched
    NR5G row that differ ONLY in the RAT string must disagree on whether a
    "bandwidth" key appears. That contrast isolates the gate, so it kills both
    "invert the gate" and "delete the gate" mutations -- which corpus NR5G rows
    alone cannot, because their field[11] (52/79/106/162/217/245/273 across
    all recorded captures) never coincides with a valid LTE RB count.
*/

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/time.h>

/* cellat_qeng.inc / cellat_qscan.inc expect the includer to have defined this,
 * exactly as capture_cell_at.c does. Keep in sync with capture_cell_at.c. */
#define JSON_BUF_MAX 4096

/* Local to the harness -- the shipping binary sizes this as MAX_OBS_PER_RESP.
 * Any value larger than the biggest response below is fine. */
#define MAX_OBS 64

/* qscan reuses the qeng decode core (split_fields, parse_int, parse_hex,
 * plmn_field, normalize_rat, lte_bw_rb_to_mhz, build_cell_json), so it must be
 * pulled in first -- the same order capture_cell_at.c uses. */
#include "cellat_qeng.inc"
#include "cellat_qscan.inc"

static int g_fails = 0;

static void check(int cond, const char *what) {
    if (cond) {
        printf("  OK    %s\n", what);
    } else {
        printf("  FAIL  %s\n", what);
        g_fails++;
    }
}

/* Return the first emitted observation JSON that contains `needle`, or NULL. */
static const char *obs_with(char json[][JSON_BUF_MAX], int n, const char *needle) {
    for (int i = 0; i < n; i++)
        if (strstr(json[i], needle))
            return json[i];
    return NULL;
}

/* --- Verbatim recorded AT+QSCAN=3,1 slice (RM520N-GL R03A04) --- */
static const char *QSCAN_CORPUS =
    "AT+QSCAN=3,1\n"
    "+QSCAN: \"NR5G\",310,260,521310,596,-95,-11,16,1,1A2B97138,1A2B00,245,41,34,14,1\n"
    "+QSCAN: \"NR5G\",311,480,647328,310,-111,-16,-1,1,0BBB9002A,BBB00,273,77,28,6,1\n"
    "+QSCAN: \"NR5G\",311,480,177150,541,-102,-18,26,0,0BBB7C028,BBB00,52,5,20,2,-\n"
    "+QSCAN: \"LTE\",310,260,66786,471,-106,-17,18,17,1A2D601,1A2B,100,4\n"
    "+QSCAN: \"LTE\",310,260,900,221,-104,-16,21,18,1A2E70C,1A2B,50,2\n"
    "+QSCAN: \"LTE\",310,260,5035,404,-88,-8,36,23,1A2E816,1A2B,25,12\n"
    "+QSCAN: \"LTE\",311,480,5230,1,-99,-22,29,107,BBB202,BBB,50,13\n"
    "\nOK\n";

/* The gate free-oracle: same field[11]=100, LTE vs NR5G, differ only in RAT. */
static const char *QSCAN_GATE =
    "+QSCAN: \"LTE\",310,260,66786,471,-106,-17,18,17,1A2D601,1A2B,100,4\n"   /* corpus */
    "+QSCAN: \"NR5G\",310,260,521310,596,-95,-11,16,1,1A2B97138,1A2B00,100,41\n"; /* field[11] forced to a valid RB */

int main(void) {
    char json[MAX_OBS][JSON_BUF_MAX];

    printf("== parse_qscan: verbatim corpus response ==\n");
    int n = parse_qscan(QSCAN_CORPUS, json, MAX_OBS);
    check(n == 7, "seven +QSCAN rows decode to seven observations");

    const char *lte4 = obs_with(json, n, "\"earfcn\":66786");
    check(lte4 != NULL, "LTE B4 EARFCN 66786 row is present");
    if (lte4) {
        check(strstr(lte4, "\"rat\":\"LTE\"") != NULL, "  66786 rat=LTE");
        check(strstr(lte4, "\"pci\":471") != NULL,     "  66786 pci=471");
        check(strstr(lte4, "\"band\":4") != NULL,       "  66786 band=4");
        check(strstr(lte4, "\"bandwidth\":20") != NULL, "  66786 RB 100 -> bandwidth=20 MHz");
        check(strstr(lte4, "\"rsrp\":-106") != NULL,    "  66786 rsrp=-106");
    }

    const char *lte900 = obs_with(json, n, "\"earfcn\":900");
    check(lte900 && strstr(lte900, "\"bandwidth\":10"), "LTE 900 RB 50 -> bandwidth=10 MHz");
    check(lte900 && strstr(lte900, "\"band\":2"),        "LTE 900 band=2");

    const char *lte5035 = obs_with(json, n, "\"earfcn\":5035");
    check(lte5035 && strstr(lte5035, "\"bandwidth\":5"), "LTE 5035 RB 25 -> bandwidth=5 MHz");
    check(lte5035 && strstr(lte5035, "\"band\":12"),      "LTE 5035 band=12");

    const char *nr41 = obs_with(json, n, "\"earfcn\":521310");
    check(nr41 != NULL, "NR5G n41 ARFCN 521310 row is present");
    if (nr41) {
        check(strstr(nr41, "\"rat\":\"NR\"") != NULL,   "  521310 rat=NR (normalize_rat folds NR5G -> NR)");
        check(strstr(nr41, "\"band\":41") != NULL,       "  521310 band=41 (field[12], not field[11])");
        check(strstr(nr41, "\"bandwidth\"") == NULL,     "  521310 emits NO bandwidth key (NR5G value unmapped)");
    }

    const char *nr77 = obs_with(json, n, "\"earfcn\":647328");
    check(nr77 && strstr(nr77, "\"band\":77"),       "NR5G 647328 band=77");
    check(nr77 && strstr(nr77, "\"bandwidth\"") == NULL, "NR5G 647328 emits no bandwidth key");

    printf("== parse_qscan: LTE-only gate isolation (free oracle) ==\n");
    int g = parse_qscan(QSCAN_GATE, json, MAX_OBS);
    check(g == 2, "gate response decodes to two observations");
    const char *g_lte = obs_with(json, g, "\"rat\":\"LTE\"");
    const char *g_nr  = obs_with(json, g, "\"rat\":\"NR\"");
    check(g_lte && strstr(g_lte, "\"bandwidth\":20"),
          "field[11]=100 on an LTE row -> bandwidth=20 (gate lets it through)");
    check(g_nr && strstr(g_nr, "\"bandwidth\"") == NULL,
          "field[11]=100 on an NR5G row -> NO bandwidth (gate blocks it)");
    check(g_nr && strstr(g_nr, "\"band\":41"),
          "NR5G row still reads band=41 from field[12] regardless of the gate");

    /* The capability is PROBED with the test form, not asserted from a
     * firmware prefix. The two supported answers are verbatim from real
     * modems: the RM500Q-AE R11A03 -- the prefix-matched part, which is
     * known to full-scan, so it is the positive control -- and the RM520N-GL
     * R01A08, which the prefix list left out. The EG25-G answers ERROR. */
    printf("== qscan_probe_supported: AT+QSCAN=? verdict ==\n");
    check(qscan_probe_supported(28, "AT+QSCAN=?\r\r\n+QSCAN: (1-3)\r\n\r\nOK\r\n") == 1,
          "RM500Q-AE R11A03 '+QSCAN: (1-3)' / OK -> supported (positive control)");
    check(qscan_probe_supported(24, "\r\n+QSCAN: (1-3)\r\n\r\nOK\r\n") == 1,
          "RM520N-GL R01A08 '+QSCAN: (1-3)' / OK -> supported (the prefix list missed it)");
    check(qscan_probe_supported(9, "\r\nERROR\r\n") == 0,
          "EG25-G ERROR -> unsupported");
    check(qscan_probe_supported(20, "\r\n+CME ERROR: 58\r\n") == 0,
          "+CME ERROR -> unsupported");
    check(qscan_probe_supported(17, "\r\n+QSCAN: (1-3)\r\n") == 0,
          "a +QSCAN: row with no final OK (read cut short) -> unsupported");
    check(qscan_probe_supported(6, "\r\nOK\r\n") == 0,
          "a bare OK with no +QSCAN: row -> unsupported (nothing says the verb exists)");
    check(qscan_probe_supported(0, "\r\n+QSCAN: (1-3)\r\n\r\nOK\r\n") == 0,
          "n == 0 (timeout) -> unsupported even if the buffer holds a stale answer");
    check(qscan_probe_supported(-1, "\r\n+QSCAN: (1-3)\r\n\r\nOK\r\n") == 0,
          "n < 0 (I/O error) -> unsupported");
    check(qscan_probe_supported(5, NULL) == 0, "NULL response -> unsupported");

    printf("\n%s: %d check(s) failed\n", g_fails ? "FAIL" : "PASS", g_fails);
    return g_fails ? 1 : 0;
}
