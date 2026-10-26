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
*/

/* Pure AT+QSCAN=3,1 (full band scan) decode core, kept apart from
 * capture_cell_at.c so parse_qscan can be exercised without the capture
 * framework, a modem, or an IPC harness.
 *
 * Same pattern as cellat_qeng.inc / cellat_cpsi.inc: this is #included by
 * capture_cell_at.c -- the function stays `static` -- and ALSO by
 * test_cellat_qscan.c, which
 * drives it over recorded QSCAN responses.
 *
 * Requires the includer to have already pulled in cellat_qeng.inc: parse_qscan
 * calls split_fields, normalize_rat, plmn_field, parse_int, parse_hex,
 * lte_bw_rb_to_mhz and build_cell_json, all defined there. It also requires
 * JSON_BUF_MAX to be defined by the includer.
 */

/*
 * Verdict for the AT+QSCAN=? capability probe.
 *
 * QSCAN support is probed, not inferred from the firmware prefix: a prefix
 * list (RM500Q / RM502Q) misses an RM520N-GL, which answers the test form with
 * "+QSCAN: (1-3)". The test form lists the supported scan modes and scans
 * nothing, so it is safe to send at open.
 *
 * `n` is at_command_t's return: 0 is a timeout and <0 an I/O error, and in
 * both cases `resp` may still hold an earlier command's text, so neither
 * counts. Supported means a "+QSCAN:" row AND the final OK: a bare OK says
 * nothing about whether the verb exists, and a row without the OK is a read
 * that was cut short.
 */
static int qscan_probe_supported(int n, const char *resp) {
    if (n <= 0 || resp == NULL)
        return 0;
    return strstr(resp, "+QSCAN:") != NULL && strstr(resp, "OK") != NULL;
}

/*
 * Parse AT+QSCAN=3,1 response (full band scan).
 *
 * Quectel RM500Q/RG502Q (5G modules only):
 *   "RG50xQ&RM5xxQ Series AT Commands Manual" V1.2, 2021-08-09, §5
 *   Not available on EC2x/EG2x/EG9x/EM05 series.
 *
 * +QSCAN: "LTE",MCC,MNC,freq,PCI,RSRP,RSRQ,srxlev,squal[,cellID(hex),TAC(hex),bandwidth,band]
 * +QSCAN: "NR5G",MCC,MNC,freq,PCI,RSRP,RSRQ,srxlev,scs[,cellID(hex),TAC(hex),bandwidth,band]
 *
 * The manual documents the LTE extension as [cellID,TAC] only, but RM520N-GL
 * (R01A05 and R03A04 firmware) appends bandwidth,band to LTE rows too.
 */
static int parse_qscan(const char *response, char json_out[][JSON_BUF_MAX],
                        int max_obs) {
    char *resp_copy = strdup(response);
    if (!resp_copy) return 0;

    int obs_count = 0;
    char *saveptr = NULL;
    char *line = strtok_r(resp_copy, "\n", &saveptr);

    while (line && obs_count < max_obs) {
        while (*line == ' ') line++;

        if (strncmp(line, "+QSCAN:", 7) != 0) {
            line = strtok_r(NULL, "\n", &saveptr);
            continue;
        }

        char *body = line + 7;
        while (*body == ' ') body++;

        char *fields[32];
        char body_copy[2048];
        strncpy(body_copy, body, sizeof(body_copy) - 1);
        body_copy[sizeof(body_copy) - 1] = '\0';
        int nf = split_fields(body_copy, fields, 32);

        if (nf < 1) {
            line = strtok_r(NULL, "\n", &saveptr);
            continue;
        }

        const char *rat = normalize_rat(fields[0]);
        if (!rat) {
            line = strtok_r(NULL, "\n", &saveptr);
            continue;
        }

        /* +QSCAN: "RAT",MCC,MNC,EARFCN,PCI,RSRP,RSRQ,?,band,cellID,TAC,... */
        const char *mcc = NULL, *mnc = NULL;   /* as-broadcast digit strings */
        long earfcn = 0, pci = 0, rsrp = 0, rsrq = 0, band = 0;
        long bw = 0;
        unsigned long cell_id = 0, tac = 0;
        int h_earfcn = 0, h_pci = 0;
        int h_rsrp = 0, h_rsrq = 0, h_band = 0, h_cell_id = 0, h_tac = 0;
        int h_bw = 0;

        if (nf > 1) mcc = plmn_field(fields[1]);
        if (nf > 2) mnc = plmn_field(fields[2]);
        if (nf > 3) h_earfcn = parse_int(fields[3], &earfcn);
        if (nf > 4) h_pci = parse_int(fields[4], &pci);
        if (nf > 5) h_rsrp = parse_int(fields[5], &rsrp);
        if (nf > 6) h_rsrq = parse_int(fields[6], &rsrq);
        /* fields[7] = srxlev, fields[8] = squal (LTE) / scs (NR5G) */
        if (nf > 9) h_cell_id = parse_hex(fields[9], &cell_id);
        if (nf > 10) h_tac = parse_hex(fields[10], &tac);
        /* LTE <bandwidth> is a RESOURCE-BLOCK count (25/50/100), not MHz
         * (see the cross-check in cellat_qeng.inc). The NR5G row's value
         * has no documented unit and no capture evidence for one -- n41 cells read 14,
         * which is 400 MHz under the QENG NR enum -- so it is omitted. */
        if (nf > 11 && strcmp(rat, "LTE") == 0) {
            long rb = 0;
            h_bw = parse_int(fields[11], &rb) && lte_bw_rb_to_mhz(rb, &bw);
        }
        if (nf > 12) h_band = parse_int(fields[12], &band);

        build_cell_json(json_out[obs_count], JSON_BUF_MAX,
                        rat, NULL,
                        mcc, mnc,
                        cell_id, h_cell_id, pci, h_pci,
                        tac, h_tac, earfcn, h_earfcn,
                        band, h_band, bw, h_bw,
                        rsrp, h_rsrp, rsrq, h_rsrq,
                        0, 0, 0, 0,
                        "observation", 0, NULL);
        obs_count++;

        line = strtok_r(NULL, "\n", &saveptr);
    }

    free(resp_copy);
    return obs_count;
}
