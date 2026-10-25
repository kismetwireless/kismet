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

/* SIMCom AT+CPSI? serving-cell decode core.
 *
 * Same contract as cellat_qeng.inc: pure string -> string, no globals, no I/O,
 * #included by capture_cell_at.c and by test_cellat_cpsi.c. Requires
 * JSON_BUF_MAX and the helpers in cellat_qeng.inc (split_fields, parse_int,
 * parse_hex, build_cell_json), so it must be included AFTER that file.
 *
 * Sources:
 *   SIM82XX&SIM83XX Series AT Command Manual (SIM8200_Series_AT_Command_Manual
 *     _V1.00.01_0515) §4.2.14 -- the LTE, NR5G-SA and EN-DC forms below
 *   SIM7070_SIM7080_SIM7090 Series AT Command Manual V1.08 §4.2.14
 *   SIM7500_SIM7600 Series FOTA Application Note V3.00
 *
 * Three traps live in this command, and two of them silently produce
 * plausible-looking wrong numbers rather than a parse failure.
 *
 * 1. THE RAT FORMS DISAGREE ON FIELD ORDER, INCLUDING BETWEEN THE TWO NR ONES.
 *      LTE ......... ,<RSRQ>,<RSRP>,<RSSI>,<RSSNR>      RSRQ first
 *      NR5G-SA ..... ,<RSRP>,<RSRQ>,<RSSNR>             RSRP first
 *      NR5G (EN-DC)  ,<RSRQ>,<RSRP>,<RSSNR>             RSRQ first, and no
 *                                                       PLMN/TAC/CellID at all
 *    So it is NOT enough to branch on "is this line LTE or NR" -- the two NR
 *    forms must be told apart from each other too. See rat_form_of() below.
 *
 * 2. THE SIGNAL UNITS ARE NOT CONSTANT ACROSS THE FAMILY -- OR EVEN ACROSS ONE
 *    RESPONSE. The SIM8200/SIM7600 manuals define <RSRP>/<RSRQ>/<RSSI> as
 *    "dBm x10", and the captured SIM7600NA line agrees:
 *      +CPSI: LTE,Online,310-260,0x1A2B,27439874,236,EUTRAN-BAND4,2300,5,5,
 *             -125,-987,-663,10          -> RSRQ -12.5 dB, RSRP -98.7 dBm
 *    But the SIM7070 manual's own example is in whole units:
 *      +CPSI: LTE NB-IOT,Online,460-11,0x5AE1,187212754,82,EUTRAN-BAND5,2506,
 *             0,0,-7,-115,-110,13        -> RSRQ -7 dB, RSRP -115 dBm
 *    and the SIM8200 manual's EN-DC example mixes both IN ONE RESPONSE -- an
 *    x10 LTE line followed by a whole-unit NR line.
 *    Hardcoding either scale emits a number that is off by 10x while looking
 *    entirely well-formed downstream, which is why this decodes the scale from
 *    RSRP per line rather than from the model. See dbm_scale_of().
 *
 * 3. SCellID IS DECIMAL AND TAC IS HEX, IN THE SAME LINE. Quectel's +QENG
 *    reports both in hex, so reusing that habit here turns cell 27439874 into
 *    1351406146.
 *
 * Hardware status: the LTE form is decoded against a verbatim line captured
 * from a SIM7600NA (firmware LE20B01SIM7600NA_210506). The two NR forms are
 * decoded against the SIM8200 manual's documented layouts and its worked
 * example only; no registered NR +CPSI? line has been captured yet. Treat the
 * NR branches as manual-grounded, not measured.
 *
 * GSM and WCDMA forms are deliberately NOT decoded. They have their own field
 * layouts and this source targets 4G/5G modems, so a GSM branch would be
 * untestable code carrying a guess.
 */

/* Which +CPSI: body layout a line carries. */
enum cpsi_form {
    CPSI_FORM_NONE = 0,   /* not a cell line: NO SERVICE, EN-DC notice, GSM... */
    CPSI_FORM_LTE,        /* LTE / LTE NB-IOT / LTE CAT-M1 serving cell */
    CPSI_FORM_NR_SA,      /* NR5G standalone serving cell (full identity) */
    CPSI_FORM_NR_ENDC,    /* NR5G secondary under EN-DC (signal only) */
};

/* Classify a split +CPSI: body.
 *
 * The NR discriminator is field[1], NOT the field count. Both NR forms start
 * `NR5G,` and only the SA form carries an <Operation Mode> word there
 * ("Online", "Low Power Mode", ...); the EN-DC form puts <PCellID> in that slot,
 * a bare number. Counting fields would work today and break the first time a
 * firmware appends a column -- and the failure would be a silent field-order
 * shift, not a parse error. A word-vs-number test is a property of the format.
 */
static enum cpsi_form rat_form_of(char **fields, int nf) {
    if (nf < 2)
        return CPSI_FORM_NONE;

    const char *mode = fields[0];

    /* "LTE", and the LPWA spellings "LTE NB-IOT" / "LTE CAT-M1" that the
     * SIM7070 family reports. All three carry the identical field layout. */
    if (strncmp(mode, "LTE", 3) == 0)
        return nf >= 12 ? CPSI_FORM_LTE : CPSI_FORM_NONE;

    if (strncmp(mode, "NR5G", 4) == 0) {
        long probe = 0;
        if (parse_int(fields[1], &probe))
            return nf >= 6 ? CPSI_FORM_NR_ENDC : CPSI_FORM_NONE;
        return nf >= 10 ? CPSI_FORM_NR_SA : CPSI_FORM_NONE;
    }

    /* NO SERVICE, GSM, WCDMA, TDS, "NOT IN EN-DC CONNECTED MODE", ... */
    return CPSI_FORM_NONE;
}

/* Decide whether this line's power figures are whole dBm or tenths of a dBm,
 * from RSRP alone.
 *
 * RSRP is the ONLY field that can answer this, and it answers it exactly.
 * 3GPP bounds RSRP to -140..-44 dBm, so the two encodings occupy disjoint
 * ranges (-140..-44 vs -1400..-440) and no measurable value is ambiguous.
 * RSSI cannot be used: its range is -120..0 dBm, so a reported -100 is a legal
 * whole-unit RSSI *and* a legal tenths RSSI (-10.0 dBm), and picking either is
 * a coin flip. RSRQ is disjoint too but has a much narrower margin.
 *
 * Returns 10 for tenths, 1 for whole units. An out-of-range or absent RSRP
 * returns 1, which leaves the raw value untouched rather than inventing a
 * scaling for a number we do not believe anyway.
 */
static long dbm_scale_of(long rsrp, int have_rsrp) {
    if (!have_rsrp)
        return 1;
    if (rsrp <= -400)
        return 10;
    return 1;
}

/* SNR does NOT follow the power scale, and the SIM8200 manual's own EN-DC
 * example proves it: an NR line reporting whole-unit RSRP -92 alongside RSSNR
 * 153, i.e. 15.3 dB. The manual never defines RSSNR's unit at all. So it gets
 * its own range test: LTE SINR is bounded to roughly -20..+30 dB, and anything
 * beyond that is tenths.
 */
static long snr_scale_of(long snr, int have_snr) {
    if (!have_snr)
        return 1;
    if (snr > 40 || snr < -40)
        return 10;
    return 1;
}

/* PLMN splitting is shared with the +QENG path via plmn_split_dash()
 * (cellat_qeng.inc, included first): it preserves the broadcast MNC digit
 * count, so "460-00" reaches the server as the string "00", not 0.
 */

/* Pull the band number out of "EUTRAN-BAND4" / "NR5G-BAND78".
 *
 * Takes the trailing run of digits rather than a fixed prefix: the family
 * spells this several ways across manuals ("EUTRAN-BAND4", "27 EGSM 900",
 * "WCDMA IMT 2000") and only the LTE spelling ends in the band number. A field
 * with no trailing digits yields no band, which is correct -- better than a
 * band lifted out of a frequency label.
 */
static int parse_band_label(const char *s, long *out) {
    if (!s || !*s)
        return 0;
    size_t len = strlen(s);
    size_t i = len;
    while (i > 0 && s[i - 1] >= '0' && s[i - 1] <= '9')
        i--;
    if (i == len)
        return 0;             /* no trailing digits at all */
    if (i == 0)
        return 0;             /* all digits -- not a band LABEL, don't guess */
    return parse_int(s + i, out);
}

/*
 * Parse an AT+CPSI? response into cell_observation JSON objects.
 *
 * Returns the number of observations written. A `NO SERVICE` reply is a valid
 * response with zero observations -- NOT an error. The modem is answering
 * correctly; it simply is not camped.
 */
static int parse_cpsi(const char *response, char json_out[][JSON_BUF_MAX],
                      int max_obs) {
    char *resp_copy = strdup(response);
    if (!resp_copy) return 0;

    int obs_count = 0;
    char *saveptr = NULL;
    char *line = strtok_r(resp_copy, "\n", &saveptr);

    while (line && obs_count < max_obs) {
        while (*line == ' ') line++;

        if (strncmp(line, "+CPSI:", 6) != 0) {
            line = strtok_r(NULL, "\n", &saveptr);
            continue;
        }

        char *body = line + 6;
        while (*body == ' ') body++;

        char *fields[32];
        char body_copy[2048];
        strncpy(body_copy, body, sizeof(body_copy) - 1);
        body_copy[sizeof(body_copy) - 1] = '\0';
        int nf = split_fields(body_copy, fields, 32);

        const char *mcc = NULL, *mnc = NULL;   /* as-broadcast digit strings */
        char mcc_buf[8] = "", mnc_buf[8] = "";
        long pci = 0, earfcn = 0, band = 0, bw = 0;
        long rsrp = 0, rsrq = 0, sinr = 0, rssi = 0;
        unsigned long cell_id = 0, tac = 0;
        long cell_dec = 0;
        int h_pci = 0, h_earfcn = 0, h_band = 0, h_bw = 0;
        int h_rsrp = 0, h_rsrq = 0, h_sinr = 0, h_cell_id = 0, h_tac = 0;
        int h_rssi = 0;
        const char *rat = NULL;
        const char *obs_type = "serving";

        switch (rat_form_of(fields, nf)) {
        case CPSI_FORM_LTE:
            /* <mode>,<op>,<MCC>-<MNC>,<TAC>,<SCellID>,<PCellID>,
             *   <Frequency Band>,<earfcn>,<dlbw>,<ulbw>,
             *   <RSRQ>,<RSRP>,<RSSI>,<RSSNR>
             * NOTE: RSRQ precedes RSRP. */
            rat = "LTE";
            if (plmn_split_dash(fields[2], mcc_buf, sizeof mcc_buf,
                                mnc_buf, sizeof mnc_buf)) {
                mcc = mcc_buf;
                mnc = mnc_buf;
            }
            h_tac = parse_hex(fields[3], &tac);
            h_cell_id = parse_int(fields[4], &cell_dec);
            cell_id = (unsigned long)cell_dec;
            h_pci = parse_int(fields[5], &pci);
            h_band = parse_band_label(fields[6], &band);
            h_earfcn = parse_int(fields[7], &earfcn);
            /* <dlbw> is an ENUM index, not MHz -- the same 0..5
             * table as QENG's DL_BW; see lte_bw_enum_to_mhz for why the
             * older SIMCom manuals that leave it undefined agree. */
            {
                long idx = 0;
                h_bw = parse_int(fields[8], &idx) && lte_bw_enum_to_mhz(idx, &bw);
            }
            h_rsrq = parse_int(fields[10], &rsrq);
            h_rsrp = parse_int(fields[11], &rsrp);
            /* The last two columns are guarded rather than assumed: the form
             * gate only requires the identity + RSRP columns, so a firmware
             * that truncates the tail still yields a usable observation
             * instead of being dropped whole. */
            if (nf > 12)
                h_rssi = parse_int(fields[12], &rssi);
            if (nf > 13)
                h_sinr = parse_int(fields[13], &sinr);
            break;

        case CPSI_FORM_NR_SA:
            /* <mode>,<op>,<MCC>-<MNC>,<TAC>,<SCellID>,<PCellID>,
             *   <earfcn>,<RSRP>,<RSRQ>,<RSSNR>
             * NOTE: RSRP precedes RSRQ -- the opposite of the LTE form above. */
            rat = "NR";
            if (plmn_split_dash(fields[2], mcc_buf, sizeof mcc_buf,
                                mnc_buf, sizeof mnc_buf)) {
                mcc = mcc_buf;
                mnc = mnc_buf;
            }
            h_tac = parse_hex(fields[3], &tac);
            h_cell_id = parse_int(fields[4], &cell_dec);
            cell_id = (unsigned long)cell_dec;
            h_pci = parse_int(fields[5], &pci);
            h_earfcn = parse_int(fields[6], &earfcn);
            h_rsrp = parse_int(fields[7], &rsrp);
            h_rsrq = parse_int(fields[8], &rsrq);
            h_sinr = parse_int(fields[9], &sinr);
            break;

        case CPSI_FORM_NR_ENDC:
            /* <mode>,<PCellID>,<earfcn/ssb>,<RSRQ>,<RSRP>,<RSSNR>
             * No PLMN, no TAC, no cell identity -- this line describes the
             * secondary leg of an EN-DC pair whose identity is on the LTE
             * line above it. */
            rat = "NR";
            obs_type = "serving_secondary";
            h_pci = parse_int(fields[1], &pci);
            h_earfcn = parse_int(fields[2], &earfcn);
            h_rsrq = parse_int(fields[3], &rsrq);
            h_rsrp = parse_int(fields[4], &rsrp);
            h_sinr = parse_int(fields[5], &sinr);
            break;

        case CPSI_FORM_NONE:
        default:
            line = strtok_r(NULL, "\n", &saveptr);
            continue;
        }

        /* Normalize the signal figures to whole dB/dBm, which is what every
         * other parser in this tree emits and what the observation schema
         * means by "rsrp". */
        long pscale = dbm_scale_of(rsrp, h_rsrp);
        if (pscale != 1) {
            rsrp /= pscale;
            if (h_rsrq) rsrq /= pscale;
            if (h_rssi) rssi /= pscale;
        }
        long sscale = snr_scale_of(sinr, h_sinr);
        if (sscale != 1)
            sinr /= sscale;

        build_cell_json(json_out[obs_count], JSON_BUF_MAX,
                        rat, NULL,
                        mcc, mnc,
                        cell_id, h_cell_id, pci, h_pci,
                        tac, h_tac, earfcn, h_earfcn,
                        band, h_band, bw, h_bw,
                        rsrp, h_rsrp, rsrq, h_rsrq,
                        sinr, h_sinr, rssi, h_rssi,
                        obs_type, 1, NULL);
        obs_count++;

        line = strtok_r(NULL, "\n", &saveptr);
    }

    free(resp_copy);
    return obs_count;
}
