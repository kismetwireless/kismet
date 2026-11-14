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

/* Fibocom AT+GTCCINFO? serving/neighbour-cell decode core.
 *
 * Same contract as cellat_cpsi.inc: pure string -> string, no globals, no I/O,
 * #included by capture_cell_at.c and by test_cellat_gtccinfo.c. Requires
 * JSON_BUF_MAX and the helpers in cellat_qeng.inc (split_fields, parse_int,
 * parse_hex, lte_bw_rb_to_mhz, build_cell_json, cell_json_add_long), so it must
 * be included AFTER that file.
 *
 * Source: live output of a Fibocom FM350-GL (MediaTek T700), firmware
 * 81600.0000.00.29.22.06, over both PCIe (mtk_t7xx /dev/wwan0at0) and USB.
 * No vendor manual for this verb was available, so each field below was bound
 * by reading an independent command on the same unit in the same second:
 * +CEREG=2 (TAC, cell ID, AcT), +COPS numeric (PLMN), +GTCAINFO? PCC (EARFCN,
 * PCI, band, bandwidth, RSRP in dBm) and +CESQ (RSRP/RSRQ indices).
 *
 * Reply shape:
 *
 *     +GTCCINFO: <- nothing else on this line
 *     <serving>,<rat>,<mcc>,<mnc>,<tac>,<cellid>,<earfcn>,<pci>,<band>,<bw>,
 *         <f11>,<f12>,<rsrp>,<rsrq>
 *     ...one line per cell...
 *     OK
 *
 * A modem that is not camped answers the prefix line and OK with no rows: a
 * valid reply with zero observations, exactly like +CPSI: NO SERVICE.
 *
 *   field  meaning      encoding
 *   1      serving      1 = serving cell, 0 = neighbour
 *   2      RAT          4 = LTE (the only value seen; others are skipped)
 *   3      MCC          decimal
 *   4      MNC          decimal, LEADING ZEROS DROPPED (see trap 1)
 *   5      TAC          hex, no 0x
 *   6      cell ID      hex, zero-padded to 9 digits even on LTE
 *   7      EARFCN       decimal
 *   8      PCI          decimal
 *   9      band         Fibocom band code: 1xx = LTE band xx (may be empty)
 *   10     bandwidth    resource blocks: 100 = 20 MHz (may be empty)
 *   11,12  unbound      not emitted
 *   13     RSRP         3GPP TS 36.133 index, dBm = idx - 141
 *   14     RSRQ         3GPP TS 36.133 index, dB = idx / 2 - 20 (bound by
 *                       +CESQ agreement to within one step, sampled separately)
 *
 * Traps:
 *
 * 1. THE MNC LOSES ITS WIDTH. MNC "010" prints as 10 and "01" as 1, so the
 *    as-broadcast digit count is gone before this parser sees it. Writing a
 *    padded string here would assert a width the modem never stated. The MNC
 *    is therefore emitted as a JSON INTEGER, which routes it through the
 *    server's plmn_from_numbers() MCC-block rule -- the documented fallback for
 *    sources that cannot carry the broadcast string. A value of 100..999 is
 *    unambiguous and is emitted as a 3-digit string.
 *
 * 2. BAND AND BANDWIDTH CAN BE EMPTY. The same unit answered "148,100" on one
 *    read and ",," on the next, in one session. Both are optional; nothing
 *    else in the row depends on them.
 *
 * 3. SIGNALS ARE INDICES, NOT dB. Read as dBm, RSRP 50 would be a nonsense
 *    +50 dBm. 255 is the 3GPP "not known" value.
 */

#define GTCCINFO_FIELDS 14
#define GTCCINFO_RAT_LTE 4

/* 3GPP TS 36.133 RSRP index (0..97) to whole dBm. 255 / out of range -> 0. */
static int gtcc_rsrp_dbm(long idx, int have, long *out) {
    if (!have || idx < 0 || idx > 97)
        return 0;
    *out = idx - 141;
    return 1;
}

/* 3GPP TS 36.133 RSRQ index (0..34) to dB, halves truncated toward zero to
 * fit the schema's whole-dB "rsrq". 255 / out of range -> 0. */
static int gtcc_rsrq_db(long idx, int have, long *out) {
    if (!have || idx < 0 || idx > 34)
        return 0;
    *out = (idx - 40) / 2;
    return 1;
}

/*
 * Parse an AT+GTCCINFO? response into cell_observation JSON objects.
 *
 * Returns the number of observations written; 0 for an uncamped reply.
 */
static int parse_gtccinfo(const char *response, char json_out[][JSON_BUF_MAX],
                          int max_obs) {
    char *resp_copy = strdup(response);
    if (!resp_copy) return 0;

    int obs_count = 0;
    int in_block = 0;
    char *saveptr = NULL;
    char *line = strtok_r(resp_copy, "\n", &saveptr);

    while (line && obs_count < max_obs) {
        while (*line == ' ' || *line == '\r') line++;
        size_t ll = strlen(line);
        while (ll > 0 && (line[ll - 1] == '\r' || line[ll - 1] == ' '))
            line[--ll] = '\0';

        if (strncmp(line, "+GTCCINFO:", 10) == 0) {
            in_block = 1;
            line = strtok_r(NULL, "\n", &saveptr);
            continue;
        }
        /* Rows follow the prefix until the final result or another reply. */
        if (!in_block || ll == 0) {
            line = strtok_r(NULL, "\n", &saveptr);
            continue;
        }
        if (line[0] == '+' || strcmp(line, "OK") == 0 ||
            strstr(line, "ERROR") != NULL) {
            in_block = 0;
            line = strtok_r(NULL, "\n", &saveptr);
            continue;
        }

        char *fields[32];
        char body_copy[512];
        strncpy(body_copy, line, sizeof(body_copy) - 1);
        body_copy[sizeof(body_copy) - 1] = '\0';
        int nf = split_fields(body_copy, fields, 32);

        long serving = 0, rat = 0;
        if (nf < GTCCINFO_FIELDS || !parse_int(fields[0], &serving) ||
            !parse_int(fields[1], &rat) || rat != GTCCINFO_RAT_LTE) {
            line = strtok_r(NULL, "\n", &saveptr);
            continue;
        }

        long mcc_n = 0, mnc_n = 0, pci = 0, earfcn = 0, band_code = 0;
        long band = 0, rb = 0, bw = 0, rsrp_idx = 0, rsrq_idx = 0;
        long rsrp = 0, rsrq = 0;
        unsigned long tac = 0, cell_id = 0;

        int h_mcc = parse_int(fields[2], &mcc_n) && mcc_n >= 0 && mcc_n <= 999;
        int h_mnc = parse_int(fields[3], &mnc_n) && mnc_n >= 0 && mnc_n <= 999;
        int h_tac = parse_hex(fields[4], &tac);
        int h_cell_id = parse_hex(fields[5], &cell_id);
        int h_earfcn = parse_int(fields[6], &earfcn);
        int h_pci = parse_int(fields[7], &pci);
        int h_band = parse_int(fields[8], &band_code) &&
                     band_code > 100 && band_code < 200;
        if (h_band)
            band = band_code - 100;
        int h_bw = parse_int(fields[9], &rb) && lte_bw_rb_to_mhz(rb, &bw);
        int h_ri = parse_int(fields[12], &rsrp_idx);
        int h_qi = parse_int(fields[13], &rsrq_idx);
        int h_rsrp = gtcc_rsrp_dbm(rsrp_idx, h_ri, &rsrp);
        int h_rsrq = gtcc_rsrq_db(rsrq_idx, h_qi, &rsrq);

        char mcc_buf[8] = "", mnc_buf[8] = "";
        const char *mcc = NULL, *mnc_str = NULL;
        if (h_mcc) {
            snprintf(mcc_buf, sizeof mcc_buf, "%03ld", mcc_n);
            mcc = mcc_buf;
        }
        /* Trap 1: only a value that needs three digits has a known width. */
        if (h_mcc && h_mnc && mnc_n >= 100) {
            snprintf(mnc_buf, sizeof mnc_buf, "%03ld", mnc_n);
            mnc_str = mnc_buf;
        }

        int is_serving = serving == 1;
        build_cell_json(json_out[obs_count], JSON_BUF_MAX,
                        "LTE", NULL,
                        mcc, mnc_str,
                        cell_id, h_cell_id, pci, h_pci,
                        tac, h_tac, earfcn, h_earfcn,
                        band, h_band, bw, h_bw,
                        rsrp, h_rsrp, rsrq, h_rsrq,
                        0, 0, 0, 0,
                        is_serving ? "serving" : "observation",
                        is_serving, NULL);
        if (h_mcc && h_mnc && !mnc_str)
            cell_json_add_long(json_out[obs_count], JSON_BUF_MAX, "mnc", mnc_n);
        obs_count++;

        line = strtok_r(NULL, "\n", &saveptr);
    }

    free(resp_copy);
    return obs_count;
}
