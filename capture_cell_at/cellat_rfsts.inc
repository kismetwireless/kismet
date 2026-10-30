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

/* Telit AT#RFSTS serving-cell decode core.
 *
 * Same contract as cellat_qeng.inc: pure string -> string, no globals, no I/O,
 * #included by capture_cell_at.c and by test_cellat_rfsts.c. Requires
 * JSON_BUF_MAX and the helpers in cellat_qeng.inc (split_fields, parse_int,
 * parse_hex, plmn_field, build_cell_json), so it must be included AFTER that file.
 *
 * Source: LM940 AT Commands Reference Guide 80545ST10791A r1, section 5.6.1.24
 * (LTE network); the LM960A18 (32.01.110) answers in the same order.
 *
 * Format (LTE):
 *   #RFSTS: <PLMN>,<EARFCN>,<RSRP>,<RSSI>,<RSRQ>,<TAC>,<RAC>,[<TXPWR>],<DRX>,
 *           <MM>,<RRC>,<CID>,<IMSI>,[<NetNameAsc>],<SD>,<ABND>
 *
 * Example:
 *   #RFSTS: "311 480",66536,-103,-68,-15,0BBB,255,,1280,1,0,0BBB416,"000000000000000","Verizon",3,66
 *
 * The fourth field is RSSI, not TX power, and the band is the LAST field
 * (ABND, the active E-UTRA band), not the seventh: the seventh is the Routing
 * Area Code, which an LTE cell reports as 255. Reading RAC as the band and
 * dropping 255 as "not available" lost the band on every LTE cell.
 * TXPWR is reported in traffic only, so it is usually empty.
 */

static int parse_rfsts(const char *response, char json_out[][JSON_BUF_MAX],
                       int max_obs) {
    char *resp_copy = strdup(response);
    if (!resp_copy) return 0;

    int obs_count = 0;
    char *saveptr = NULL;
    char *line = strtok_r(resp_copy, "\n", &saveptr);

    while (line && obs_count < max_obs) {
        while (*line == ' ') line++;

        if (strncmp(line, "#RFSTS:", 7) != 0) {
            line = strtok_r(NULL, "\n", &saveptr);
            continue;
        }

        /* strtok_r on "\n" leaves the CR of a CRLF reply on the line, where it
         * would become part of ABND, the last field, and fail its parse. */
        size_t len = strlen(line);
        while (len > 0 && (line[len - 1] == '\r' || line[len - 1] == ' '))
            line[--len] = '\0';

        char *body = line + 7;
        while (*body == ' ') body++;

        /* Parse MCC MNC from the quoted first field */
        const char *mcc = NULL, *mnc = NULL;   /* as-broadcast digit strings */
        char mcc_buf[8] = "", mnc_buf[8] = "";
        char *quote1 = strchr(body, '"');
        if (quote1) {
            char *quote2 = strchr(quote1 + 1, '"');
            if (quote2) {
                char plmn[32];
                size_t plen = quote2 - quote1 - 1;
                if (plen < sizeof(plmn)) {
                    memcpy(plmn, quote1 + 1, plen);
                    plmn[plen] = '\0';
                    /* Format is "MCC MNC" with space separator */
                    char *space = strchr(plmn, ' ');
                    if (space) {
                        *space = '\0';
                        /* keep the broadcast digit count */
                        if (plmn_field(plmn)) {
                            snprintf(mcc_buf, sizeof mcc_buf, "%s", plmn);
                            mcc = mcc_buf;
                        }
                        if (plmn_field(space + 1)) {
                            snprintf(mnc_buf, sizeof mnc_buf, "%s", space + 1);
                            mnc = mnc_buf;
                        }
                    }
                }
                /* Advance body past the closing quote + comma */
                body = quote2 + 1;
                if (*body == ',') body++;
            }
        }

        /* Remaining fields: EARFCN,RSRP,RSSI,RSRQ,TAC,RAC,TXPWR,DRX,MM,RRC,CID,IMSI,NetNameAsc,SD,ABND */
        char *fields[32];
        char body_copy[2048];
        strncpy(body_copy, body, sizeof(body_copy) - 1);
        body_copy[sizeof(body_copy) - 1] = '\0';
        int nf = split_fields(body_copy, fields, 32);

        long earfcn = 0, rsrp = 0, rssi = 0, rsrq = 0, band = 0;
        unsigned long tac = 0, cell_id = 0;
        int h_earfcn = 0, h_rsrp = 0, h_rssi = 0, h_rsrq = 0, h_band = 0;
        int h_tac = 0, h_cell_id = 0;
        char *operator_name = NULL;

        if (nf > 0) h_earfcn = parse_int(fields[0], &earfcn);
        if (nf > 1) h_rsrp = parse_int(fields[1], &rsrp);
        if (nf > 2) h_rssi = parse_int(fields[2], &rssi);
        if (nf > 3) h_rsrq = parse_int(fields[3], &rsrq);
        if (nf > 4) h_tac = parse_hex(fields[4], &tac);
        /* fields[5] = RAC, fields[6] = TXPWR (traffic only), fields[7] = DRX,
         * fields[8] = MM, fields[9] = RRC */
        if (nf > 10) h_cell_id = parse_hex(fields[10], &cell_id);
        /* fields[11] = IMSI: never read */
        if (nf > 12 && fields[12][0] != '\0')
            operator_name = fields[12];
        /* fields[13] = SD, fields[14] = ABND: an E-UTRA band is 1..255 */
        if (nf > 14) {
            h_band = parse_int(fields[14], &band);
            if (band < 1 || band > 255) h_band = 0;
        }

        build_cell_json(json_out[obs_count], JSON_BUF_MAX,
                        "LTE", NULL,
                        mcc, mnc,
                        cell_id, h_cell_id, 0, 0, /* no PCI in RFSTS */
                        tac, h_tac, earfcn, h_earfcn,
                        band, h_band, 0, 0,
                        rsrp, h_rsrp, rsrq, h_rsrq,
                        0, 0, rssi, h_rssi,
                        "serving", 1, operator_name);
        obs_count++;

        line = strtok_r(NULL, "\n", &saveptr);
    }

    free(resp_copy);
    return obs_count;
}
