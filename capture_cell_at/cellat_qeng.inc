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

/* Pure AT-response decode core, kept apart from capture_cell_at.c so it can be
 * exercised without the capture framework, a modem, or an IPC harness.
 *
 * Same pattern as at_serial.inc: this is #included by capture_cell_at.c -- the
 * functions stay `static` -- and ALSO by test_cellat_qeng.c, which drives them over recorded
 * modem responses.
 *
 * Everything here is pure string -> string: no globals, no I/O, no framework
 * calls. Anything needing a serial fd or a kis_capture_handler_t belongs in
 * capture_cell_at.c, not here.
 *
 * Requires JSON_BUF_MAX to be defined by the includer.
 */

#include <stdint.h>   /* inject_prov_x's exchange stamps */

/* Extract the VALUE a single AT response line carries, or NULL if the line
 * carries no value (blank, "OK", an error, or a bare status word).
 *
 * The response-code prefix must come off. Some modems answer AT+CGMR with a
 * bare version string; others use the 3GPP-style `+CGMR: <value>` form. A
 * SIMCom SIM8202G-M2, for example, answers
 *
 *     +CGMR: LE13B04SIM8202M44A-M2
 *
 * where Quectel and Telit modules answer with the bare string.
 *
 * This is NOT cosmetic. diag_profile.c:matched_diag_body() selects a modem's
 * DIAG profile by glob-matching the firmware string, and every profile ships a
 * LEFT-ANCHORED pattern -- "EG25*", "RM520N*", "32.01.*". A string carrying a
 * `+CGMR: ` prefix matches none of them, so the modem silently gets no DIAG
 * profile: no mask, no target codes, no error. The prefix is a decode defect
 * that surfaces as a capability disappearing.
 *
 * The same extraction is used for AT+CGSN. The SIM8202G answers +CGSN bare, but
 * the response-code form is equally legal there, so both call sites go through
 * one function.
 *
 * A bare "ERROR" is rejected too, or a modem answering AT+CGMR with a bare
 * ERROR would have its firmware recorded as the literal string "ERROR". Some
 * modems do answer that way.
 *
 * Modifies the line in place (trailing CR/space are trimmed). Returns a pointer
 * into it, so the caller must copy before the buffer is reused.
 */
static char *at_line_value(char *line) {
    if (!line)
        return NULL;

    while (*line == ' ' || *line == '\t' || *line == '\r')
        line++;

    /* Trim trailing CR/LF/space -- strtok_r on "\n" leaves the CR of a CRLF
     * response behind, where it becomes part of the firmware or IMEI string.
     *
     * Unlike the prefix, a trailing CR does NOT break the shipped
     * `firmware_match` globs: they all end in `*`, which absorbs it. What it
     * breaks is everything that compares exactly -- the `cellat-<IMEI>` source
     * name the datasource is addressed by, any future anchored pattern, and
     * every log line, where it is invisible. */
    size_t len = strlen(line);
    while (len > 0 && (line[len - 1] == '\r' || line[len - 1] == '\n' ||
                       line[len - 1] == ' ' || line[len - 1] == '\t'))
        line[--len] = '\0';

    if (!*line)
        return NULL;

    /* Final-result and error codes carry no value. */
    if (strcmp(line, "OK") == 0 || strcmp(line, "ERROR") == 0)
        return NULL;
    if (strncmp(line, "+CME", 4) == 0 || strncmp(line, "+CMS", 4) == 0)
        return NULL;

    /* `+CGMR: <value>` / `+CGSN: <value>` -- strip the response-code prefix.
     *
     * Anchored on a LEADING '+' and a colon before any space, so a firmware
     * string that merely CONTAINS a colon is untouched. Vendor version strings
     * do carry colons, and must not be truncated at the first one. */
    if (*line == '+') {
        char *colon = strchr(line, ':');
        char *space = strchr(line, ' ');

        if (colon && (!space || colon < space)) {
            char *value = colon + 1;
            while (*value == ' ' || *value == '\t')
                value++;
            /* A prefix with nothing after it is not a value. */
            if (*value)
                return value;
            return NULL;
        }
    }

    return line;
}

/* Walk an AT response and copy the first value line into out. Returns 1 if a
 * value was found, 0 otherwise. `resp` is modified in place by strtok_r. */
static int at_response_value(char *resp, char *out, size_t out_sz) {
    char *saveptr = NULL;
    char *line = strtok_r(resp, "\n", &saveptr);

    if (out_sz == 0)
        return 0;

    out[0] = '\0';

    while (line) {
        char *value = at_line_value(line);

        if (value) {
            strncpy(out, value, out_sz - 1);
            out[out_sz - 1] = '\0';
            return 1;
        }

        line = strtok_r(NULL, "\n", &saveptr);
    }

    return 0;
}

/* Strip surrounding quotes from a field in-place, return pointer to start */
static char *strip_quotes(char *s) {
    if (!s) return s;
    size_t len = strlen(s);
    if (len >= 2 && s[0] == '"' && s[len - 1] == '"') {
        s[len - 1] = '\0';
        return s + 1;
    }
    return s;
}

/* Split a line on commas into fields array. Modifies line in-place.
 * Returns number of fields. */
static int split_fields(char *line, char **fields, int max_fields) {
    int count = 0;
    char *p = line;

    while (p && count < max_fields) {
        fields[count++] = p;
        char *comma = strchr(p, ',');
        if (comma) {
            *comma = '\0';
            p = comma + 1;
        } else {
            break;
        }
    }

    /* Strip quotes from each field */
    for (int i = 0; i < count; i++) {
        /* Trim leading whitespace */
        while (*fields[i] == ' ') fields[i]++;
        fields[i] = strip_quotes(fields[i]);
    }

    return count;
}

/* Try to parse a decimal integer from a string. Returns 1 on success. */
static int parse_int(const char *s, long *out) {
    if (!s || !*s || strcmp(s, "-") == 0)
        return 0;
    char *end;
    long val = strtol(s, &end, 10);
    if (end == s || *end != '\0')
        return 0;
    *out = val;
    return 1;
}

/* Try to parse a hex integer from a string. Returns 1 on success. */
static int parse_hex(const char *s, unsigned long *out) {
    if (!s || !*s || strcmp(s, "-") == 0)
        return 0;
    char *end;
    unsigned long val = strtoul(s, &end, 16);
    if (end == s || *end != '\0')
        return 0;
    *out = val;
    return 1;
}

/* BANDWIDTH ARRIVES IN THREE ENCODINGS, AND NONE OF THEM IS "MHz".
 *
 * The observation's `bandwidth` key is MHz -- Kismet stores it as
 * cellular.cell.bandwidth, "Channel bandwidth MHz" (phy_cell.h), and the DIAG
 * leg (0xB197 RB -> MHz) forwards real MHz. Passed
 * through raw, the vendor integer would make a 20 MHz cell read 5 MHz (QENG /
 * CPSI enum index) or 100 MHz (QSCAN resource-block count), and on a host
 * running both legs the two writers would disagree about the same cell.
 *
 * Each helper returns 1 and writes MHz on a mapped value, 0 otherwise -- the
 * caller then OMITS the key rather than emitting a plausible-but-wrong number.
 * 1.4 MHz maps to 0 on purpose: the key is an integer, and a truncated "1" is
 * a wrong value, not a rounding (the DIAG leg makes the same call and carries
 * bandwidth_rb=6 instead).
 *
 * Grounding -- manual tables PLUS a cross-command check on the same EARFCNs in
 * captured survey data, so no table is trusted on its own:
 *
 *   EARFCN   QENG DL_BW (enum)  QSCAN bw (RB)  Telit #CSURV bw (MHz)
 *   66786    5                  100            20
 *   2300     5                  100            -
 *   5230     3  (B13)           50             -
 *   66986    3                  50             -
 *   8665     -                  25             5
 *
 * Four independent readings, one answer per cell. */

/* LTE DL bandwidth ENUM -> MHz. Quectel +QENG <DL_bandwidth> (EC2x/EG2x/EG9x
 * and RG50xQ/RM5xxQ AT manuals: 0=1.4 1=3 2=5 3=10 4=15 5=20) and SIMCom +CPSI
 * <dlbw> (SIM82XX/SIM83XX V1.03: 0 BW_1.4MHz .. 5). The older SIMCom manuals
 * leave <dlbw> undefined, but their own worked examples settle it: a Band 3
 * cell reports dlbw 4, and 4 MHz is not an LTE channel bandwidth (TS 36.101
 * Table 5.6-1), while enum 4 = 15 MHz is. */
static int lte_bw_enum_to_mhz(long idx, long *mhz) {
    static const long map[] = { 0, 3, 5, 10, 15, 20 };
    if (idx < 1 || idx > 5)
        return 0;
    *mhz = map[idx];
    return 1;
}

/* LTE bandwidth as a RESOURCE-BLOCK count -> MHz (TS 36.101 Table 5.6-1).
 * +QSCAN's LTE <bandwidth> is undocumented in the manual; captures show
 * only 25/50/100, matching QENG's enum and Telit's MHz on the same EARFCNs
 * (table above). 6 RB (1.4 MHz) is omitted, like enum 0. */
static int lte_bw_rb_to_mhz(long rb, long *mhz) {
    switch (rb) {
    case 15:  *mhz = 3;  return 1;
    case 25:  *mhz = 5;  return 1;
    case 50:  *mhz = 10; return 1;
    case 75:  *mhz = 15; return 1;
    case 100: *mhz = 20; return 1;
    default:  return 0;
    }
}

/* NR DL bandwidth ENUM -> MHz. Quectel +QENG <NR_DL_bandwidth>, as printed in
 * every Quectel AT manual that defines it (RG50xQ/RM5xxQ V1.2, RG520N/RM520N
 * V1.0.0 and V1.0/V1.1): 0..8 = 5,10,15,20,25,30,40,50,60; 9=70 10=80 11=90
 * 12=100 13=200 14=400 15=35 16=45.
 *
 * One Quectel doc DISAGREES above index 8: the "5G Network Status Judgement
 * Introduction" V1.1 omits 70 MHz, so its 9 is 80 and its 12 is 200. The AT
 * manuals are the command's defining document and agree with each other, so
 * they win -- but 0..8, where all sources agree, is the only range with no
 * dissent at all. The manuals also say the value is "only valid in RRC
 * connected state"; the caller enforces that. */
static int nr_bw_enum_to_mhz(long idx, long *mhz) {
    static const long map[] = { 5, 10, 15, 20, 25, 30, 40, 50, 60,
                                70, 80, 90, 100, 200, 400, 35, 45 };
    if (idx < 0 || idx >= (long)(sizeof(map) / sizeof(map[0])))
        return 0;
    *mhz = map[idx];
    return 1;
}

/* Map raw RAT string to normalized name */
static const char *normalize_rat(const char *raw) {
    if (!raw) return NULL;
    if (strcmp(raw, "LTE") == 0)       return "LTE";
    if (strcmp(raw, "NR5G-SA") == 0)   return "NR";
    if (strcmp(raw, "NR5G-NSA") == 0)  return "NR";
    if (strcmp(raw, "NR5G") == 0)      return "NR";   /* +QSCAN row RAT token */
    if (strcmp(raw, "NR") == 0)        return "NR";
    if (strcmp(raw, "WCDMA") == 0)     return "WCDMA";
    if (strcmp(raw, "GSM") == 0)       return "GSM";
    if (strcmp(raw, "CDMA") == 0)      return "CDMA";
    return NULL;
}

/*
 * Out-of-scope neighbour-row tally.
 *
 * parse_qeng_neighbor() decodes LTE rows and drops everything else. The drop
 * is CORRECT -- 2G/3G are out of scope for this source, and it
 * is also one of two independent guards against a fabricated band: a GSM row
 * carries an ARFCN in the field position an LTE row uses for an EARFCN, and
 * ARFCN 685 fed to earfcn_to_band() lands in B2, so a leaked GSM row would
 * render as "LTE B2" in WiGLE-bound output.
 *
 * The drop still needs an OBSERVABLE. A SIM-less EG25-G at LIMSRV can report
 * 12 neighbours per poll, 8 of them GSM; `observation: 4 cells` alone hides
 * that 8 more were seen and declined. That matters twice over: "this modem
 * contributes 4 neighbours" and "4 of 12, 8 out of scope" are different facts
 * about a setup; and a correct outcome with
 * no observable is indistinguishable from a malfunction -- if normalize_rat()
 * regressed, or a firmware shipped a new token, the symptom would be identical
 * to health.
 *
 * Two categories, deliberately kept apart:
 *   declined -- normalize_rat() recognised the RAT and this parser does not
 *               decode it. Policy. Expected. A counter, nothing more.
 *   unknown  -- normalize_rat() returned NULL. A firmware surprise, worth
 *               reporting once with the offending token attached.
 *
 * Counters, never per-row log lines: 8 rows every 5 s per modem is 96
 * lines/min, which is its own kind of unreadable.
 */
enum {
    QENG_RAT_LTE = 0,
    QENG_RAT_NR,
    QENG_RAT_WCDMA,
    QENG_RAT_GSM,
    QENG_RAT_CDMA,
    QENG_RAT_COUNT
};

/* Index-aligned with the enum above. These are the exact strings
 * normalize_rat() returns -- a name here that it never returns would make its
 * slot permanently zero and silently lose that RAT's tally. */
static const char *const QENG_RAT_NAMES[QENG_RAT_COUNT] = {
    "LTE", "NR", "WCDMA", "GSM", "CDMA"
};

#define QENG_RAT_TOKEN_MAX 24

typedef struct {
    int rows;                            /* neighbourcell rows examined */
    int emitted;                         /* ...that became observations */
    int declined;                        /* ...recognised RAT, not decoded */
    int unknown;                         /* ...RAT token not recognised */
    int declined_by_rat[QENG_RAT_COUNT]; /* declined, split by QENG_RAT_* */
    char unknown_token[QENG_RAT_TOKEN_MAX]; /* FIRST unrecognised token seen */
} qeng_neighbor_drops_t;

/* Slot for a normalized RAT name, or -1. Takes the pointer normalize_rat()
 * returned, but compares by VALUE -- pointer identity happens to hold today
 * and is not a property worth depending on. */
static int qeng_rat_slot(const char *rat) {
    if (!rat) return -1;
    for (int i = 0; i < QENG_RAT_COUNT; i++)
        if (strcmp(rat, QENG_RAT_NAMES[i]) == 0)
            return i;
    return -1;
}

/*
 * Render the tally as a suffix for the caller's `observation: N cells` line,
 * e.g. " (8 out-of-scope: GSM x8)".
 *
 * Returns the number of bytes written, 0 if nothing was dropped. A zero return
 * leaves buf as the empty string, so a modem whose rows are all in scope keeps
 * an unchanged log line.
 */
static int qeng_drops_summary(const qeng_neighbor_drops_t *d, char *buf, size_t buf_sz) {
    if (!buf || buf_sz == 0) return 0;
    buf[0] = '\0';
    if (!d || (d->declined == 0 && d->unknown == 0)) return 0;

    size_t off = 0;

    /* snprintf() returns the length it WOULD have written, so the naive
     * `off += snprintf(...)` walks the cursor PAST the end of the buffer and
     * the next call gets `buf_sz - off` as a huge size_t. The guard below is
     * what makes that safe: once the cursor is out of range it never appends
     * again, so an overrun cursor is inert rather than dangerous.
     *
     * Do not also clamp `off` back to buf_sz - 1: given this guard the clamp
     * cannot change any observable behaviour, so it would be dead code. */
#define QENG_SUMMARY_APPEND(...)                                            \
    do {                                                                    \
        if (off + 1 < buf_sz) {                                             \
            int _n = snprintf(buf + off, buf_sz - off, __VA_ARGS__);        \
            if (_n < 0) _n = 0;                                             \
            off += (size_t)_n;                                              \
        }                                                                   \
    } while (0)

    QENG_SUMMARY_APPEND(" (");

    if (d->declined > 0) {
        QENG_SUMMARY_APPEND("%d out-of-scope:", d->declined);
        for (int i = 0; i < QENG_RAT_COUNT; i++) {
            if (d->declined_by_rat[i] == 0) continue;
            QENG_SUMMARY_APPEND(" %s x%d", QENG_RAT_NAMES[i], d->declined_by_rat[i]);
        }
    }

    if (d->unknown > 0)
        QENG_SUMMARY_APPEND("%s%d unrecognised RAT: \"%s\"",
                            d->declined > 0 ? "; " : "", d->unknown, d->unknown_token);

    QENG_SUMMARY_APPEND(")");
#undef QENG_SUMMARY_APPEND

    buf[buf_sz - 1] = '\0';
    return (int)strlen(buf);
}

/* Map COPS numeric RAT code to string */
static const char *cops_rat_name(int code) {
    switch (code) {
        case 0:  return "GSM";
        case 2:  return "WCDMA";
        case 7:  return "LTE";
        case 12: return "NR";
        default: return NULL;
    }
}

/*
 * Broadcast PLMN helpers. The MNC's digit COUNT is part of the cell
 * identity -- WiGLE keys on the as-broadcast "MCC+MNC" -- so "460-00"
 * and "460-01" must reach the server as the strings "00"/"01", never the
 * integers 0/1. parse_int() destroys that count; these keep the original
 * digits so cell_decisions::plmn_from_json() never has to reconstruct it with
 * the lossy MCC-block rule (plmn_from_numbers). All three return NULL / 0 on a
 * malformed token so a bad field is simply absent, not a garbage string.
 */

/* Validate a single PLMN component field (an MCC or MNC token) and return it
 * unchanged when it is a 1-3 digit decimal string, else NULL. */
static const char *plmn_field(const char *s) {
    if (!s || !*s)
        return NULL;
    size_t n = 0;
    for (const char *p = s; *p; ++p) {
        if (*p < '0' || *p > '9')
            return NULL;
        if (++n > 3)
            return NULL;
    }
    return s;
}

/* Split a dash-joined "MCC-MNC" (e.g. "310-260", "460-01") into its two digit
 * strings, copied NUL-terminated into the caller's buffers with the broadcast
 * digit count intact. Returns 1 iff both halves are well-formed decimal. */
static int plmn_split_dash(const char *s, char *mcc_out, size_t mcc_sz,
                           char *mnc_out, size_t mnc_sz) {
    if (!s)
        return 0;
    const char *dash = strchr(s, '-');
    if (!dash)
        return 0;
    size_t mcc_len = (size_t)(dash - s);
    const char *mnc_s = dash + 1;
    size_t mnc_len = strlen(mnc_s);
    if (mcc_len == 0 || mcc_len >= mcc_sz || mnc_len == 0 || mnc_len >= mnc_sz)
        return 0;
    for (size_t i = 0; i < mcc_len; i++)
        if (s[i] < '0' || s[i] > '9')
            return 0;
    for (size_t i = 0; i < mnc_len; i++)
        if (mnc_s[i] < '0' || mnc_s[i] > '9')
            return 0;
    memcpy(mcc_out, s, mcc_len);
    mcc_out[mcc_len] = '\0';
    memcpy(mnc_out, mnc_s, mnc_len);
    mnc_out[mnc_len] = '\0';
    return 1;
}

/* Split a concatenated "MCCMNC" (e.g. "310260", "31000") into MCC (first 3
 * digits) and MNC (the remaining 2-3), preserving the broadcast digit count.
 * Returns 1 iff well-formed. */
static int plmn_split_mccmnc(const char *s, char *mcc_out, size_t mcc_sz,
                             char *mnc_out, size_t mnc_sz) {
    if (!s)
        return 0;
    size_t n = strlen(s);
    if (n < 5 || n > 6)               /* MCC(3) + MNC(2..3) */
        return 0;
    for (size_t i = 0; i < n; i++)
        if (s[i] < '0' || s[i] > '9')
            return 0;
    size_t mnc_len = n - 3;
    if (mcc_sz < 4 || mnc_sz < mnc_len + 1)
        return 0;
    memcpy(mcc_out, s, 3);
    mcc_out[3] = '\0';
    memcpy(mnc_out, s + 3, mnc_len);
    mnc_out[mnc_len] = '\0';
    return 1;
}

/*
 * Build a JSON object string from cell observation fields.
 * Only includes fields that have valid values.
 * mcc/mnc are as-broadcast digit strings (or NULL when absent) -- see the
 * PLMN helpers above.
 * Returns number of bytes written (not including NUL), or -1 on error.
 */
static int build_cell_json(char *buf, size_t buf_sz,
                           const char *rat, const char *duplex,
                           const char *mcc,
                           const char *mnc,
                           unsigned long cell_id, int have_cell_id,
                           long pci, int have_pci,
                           unsigned long tac, int have_tac,
                           long earfcn, int have_earfcn,
                           long band, int have_band,
                           long bandwidth, int have_bandwidth,
                           long rsrp, int have_rsrp,
                           long rsrq, int have_rsrq,
                           long sinr, int have_sinr,
                           long rssi, int have_rssi,
                           const char *obs_type,
                           int is_serving,
                           const char *operator_name) {
    int pos = 0;
    int first = 1;

#define JSON_START() pos += snprintf(buf + pos, buf_sz - pos, "{")
#define JSON_STR(key, val) do { \
    if (val) { \
        pos += snprintf(buf + pos, buf_sz - pos, "%s\"%s\":\"%s\"", \
                        first ? "" : ",", key, val); \
        first = 0; \
    } \
} while (0)
#define JSON_LONG(key, val, have) do { \
    if (have) { \
        pos += snprintf(buf + pos, buf_sz - pos, "%s\"%s\":%ld", \
                        first ? "" : ",", key, val); \
        first = 0; \
    } \
} while (0)
#define JSON_ULONG(key, val, have) do { \
    if (have) { \
        pos += snprintf(buf + pos, buf_sz - pos, "%s\"%s\":%lu", \
                        first ? "" : ",", key, val); \
        first = 0; \
    } \
} while (0)
#define JSON_BOOL(key, val) do { \
    pos += snprintf(buf + pos, buf_sz - pos, "%s\"%s\":%s", \
                    first ? "" : ",", key, val ? "true" : "false"); \
    first = 0; \
} while (0)
#define JSON_END() pos += snprintf(buf + pos, buf_sz - pos, "}")

    if ((size_t)pos >= buf_sz)
        return -1;

    JSON_START();
    JSON_STR("rat", rat);
    JSON_STR("duplex", duplex);
    JSON_STR("mcc", mcc);
    JSON_STR("mnc", mnc);
    JSON_ULONG("cell_id", cell_id, have_cell_id);
    JSON_LONG("pci", pci, have_pci);
    JSON_ULONG("tac", tac, have_tac);
    JSON_LONG("earfcn", earfcn, have_earfcn);
    JSON_LONG("band", band, have_band);
    JSON_LONG("bandwidth", bandwidth, have_bandwidth);
    JSON_LONG("rsrp", rsrp, have_rsrp);
    JSON_LONG("rsrq", rsrq, have_rsrq);
    JSON_LONG("sinr", sinr, have_sinr);
    JSON_LONG("rssi", rssi, have_rssi);
    JSON_STR("observation_type", obs_type);
    JSON_BOOL("is_serving", is_serving);
    JSON_STR("operator_name", operator_name);
    JSON_END();

#undef JSON_START
#undef JSON_STR
#undef JSON_LONG
#undef JSON_ULONG
#undef JSON_BOOL
#undef JSON_END

    return pos;
}

/*
 * Insert a data-lineage prov block before the closing brace of a
 * cell_observation JSON object, in place. src=at; origin names the AT command
 * that produced the observation. This mirrors the capture_cell_diag DIAG
 * source's prov block ({"src":"diag",...}) so phy_cell can attribute which
 * pipe supplied identity vs signal for each tower and merge without dupes.
 * No-op if the buffer lacks room or is not a JSON object.
 */
static void inject_prov_x(char *json, size_t json_sz, const char *imei,
                          const char *origin, uint64_t at_ts_mono_ns,
                          uint64_t rx_done_ns) {
    size_t len = strlen(json);
    if (len < 2 || json[len - 1] != '}')
        return;

    struct timeval tv;
    gettimeofday(&tv, NULL);
    double captured_at = (double)tv.tv_sec + (double)tv.tv_usec / 1e6;

    /* The exchange the observation was parsed from, by the two stamps
     * its RawAT row carries -- ts_mono_ns (the join key) and rx_done_ns (the
     * answer complete). 0 = unknown/never reached, and the key is omitted. */
    char xfields[96] = "";
    size_t xl = 0;
    if (at_ts_mono_ns)
        xl += (size_t)snprintf(xfields + xl, sizeof(xfields) - xl,
                               ",\"at_ts_mono_ns\":%llu",
                               (unsigned long long)at_ts_mono_ns);
    if (rx_done_ns && xl < sizeof(xfields))
        snprintf(xfields + xl, sizeof(xfields) - xl, ",\"rx_done_ns\":%llu",
                 (unsigned long long)rx_done_ns);

    char prov[320];
    int n = snprintf(prov, sizeof(prov),
                     ",\"prov\":{\"src\":\"at\",\"origin\":\"%s\",\"imei\":\"%s\","
                     "\"captured_at\":%.3f%s}",
                     origin ? origin : "at", imei ? imei : "", captured_at,
                     xfields);
    if (n < 0 || len + (size_t)n >= json_sz)
        return;

    json[len - 1] = '\0';              /* drop the closing brace */
    memcpy(json + len - 1, prov, (size_t)n);
    json[len - 1 + n] = '}';           /* restore it after the prov block */
    json[len + n] = '\0';
}

/* The prov block without exchange stamps: no exchange named. */
static void inject_prov(char *json, size_t json_sz, const char *imei,
                        const char *origin) {
    inject_prov_x(json, json_sz, imei, origin, 0, 0);
}

/*
 * Parse AT+QENG="servingcell" response.
 * Handles LTE, NR5G-SA, and NR5G-NSA secondary.
 *
 * Quectel RM500Q/RG502Q (5G):
 *   "RG50xQ&RM5xxQ Series AT Commands Manual" V1.2, 2021-08-09, §5
 *
 * Quectel EG25-G/EC25/EG9x/EM05 (LTE):
 *   "EC2x&EG2x&EG9x&EM05 Series AT Commands Manual" V2.1, 2025-03-21, §6
 *
 * LTE field order (both manuals):
 *   +QENG: "servingcell","state","LTE","FDD/TDD",
 *     MCC,MNC,cellID(hex),PCID,EARFCN,band,UL_BW,DL_BW,
 *     TAC(hex),RSRP,RSRQ,RSSI,SINR,CQI
 *
 * NR5G-SA field order (RM5xxQ manual only):
 *   +QENG: "servingcell","state","NR5G-SA","FDD/TDD",
 *     MCC,MNC,cellID(hex),PCID,TAC(hex),ARFCN,band,NR_DL_BW,
 *     RSRP,RSRQ,SINR,scs,srxlev
 */
static int parse_qeng_serving(const char *response, char json_out[][JSON_BUF_MAX],
                              int max_obs) {
    char *resp_copy = strdup(response);
    if (!resp_copy) return 0;

    int obs_count = 0;
    char *saveptr = NULL;
    char *line = strtok_r(resp_copy, "\n", &saveptr);

    while (line && obs_count < max_obs) {
        /* Trim whitespace */
        while (*line == ' ') line++;

        if (strncmp(line, "+QENG:", 6) != 0) {
            line = strtok_r(NULL, "\n", &saveptr);
            continue;
        }

        /* Skip past "+QENG:" prefix */
        char *body = line + 6;
        while (*body == ' ') body++;

        char *fields[32];
        char body_copy[2048];
        strncpy(body_copy, body, sizeof(body_copy) - 1);
        body_copy[sizeof(body_copy) - 1] = '\0';
        int nf = split_fields(body_copy, fields, 32);

        if (nf < 3) {
            line = strtok_r(NULL, "\n", &saveptr);
            continue;
        }

        char *header = fields[0];

        if (strcmp(header, "servingcell") == 0 && nf >= 3) {
            const char *rat_raw = fields[2];
            const char *rat = normalize_rat(rat_raw);
            if (!rat) {
                line = strtok_r(NULL, "\n", &saveptr);
                continue;
            }

            const char *mcc = NULL, *mnc = NULL;   /* as-broadcast digit strings */
            long pci = 0, earfcn = 0, band = 0, bw = 0;
            /* rssi is declared out here, not in the LTE branch, because the
             * build_cell_json call below is shared with NR5G-SA -- whose field
             * layout has no RSSI column at all. Only the LTE branch sets it, so
             * NR5G-SA reaches the call with h_rssi still 0 and no rssi key is
             * emitted. Setting it at the shared call site instead would make
             * NR5G-SA report a value lifted from an unrelated column. */
            long rsrp = 0, rsrq = 0, sinr = 0, rssi = 0;
            unsigned long cell_id = 0, tac = 0;
            int h_pci = 0, h_earfcn = 0, h_band = 0, h_bw = 0;
            int h_rsrp = 0, h_rsrq = 0, h_sinr = 0, h_cell_id = 0, h_tac = 0;
            int h_rssi = 0;
            const char *duplex = (nf > 3) ? fields[3] : NULL;

            if (strcmp(rat_raw, "LTE") == 0) {
                /* +QENG: "servingcell","state","LTE","FDD/TDD",
                 *   MCC,MNC,cellID,PCID,EARFCN,band,UL_BW,DL_BW,
                 *   TAC,RSRP,RSRQ,RSSI,SINR,CQI */
                if (nf > 4)  mcc = plmn_field(fields[4]);
                if (nf > 5)  mnc = plmn_field(fields[5]);
                if (nf > 6)  h_cell_id = parse_hex(fields[6], &cell_id);
                if (nf > 7)  h_pci = parse_int(fields[7], &pci);
                if (nf > 8)  h_earfcn = parse_int(fields[8], &earfcn);
                if (nf > 9)  h_band = parse_int(fields[9], &band);
                /* DL_BW is an ENUM index, not MHz: 5 means 20 MHz. */
                if (nf > 11) {
                    long idx = 0;
                    h_bw = parse_int(fields[11], &idx) && lte_bw_enum_to_mhz(idx, &bw);
                }
                if (nf > 12) h_tac = parse_hex(fields[12], &tac);
                if (nf > 13) h_rsrp = parse_int(fields[13], &rsrp);
                if (nf > 14) h_rsrq = parse_int(fields[14], &rsrq);
                if (nf > 15) h_rssi = parse_int(fields[15], &rssi);
                if (nf > 16) h_sinr = parse_int(fields[16], &sinr);
            } else if (strcmp(rat_raw, "NR5G-SA") == 0) {
                /* +QENG: "servingcell","state","NR5G-SA","FDD/TDD",
                 *   MCC,MNC,cellID,PCID,TAC,ARFCN,band,NR_DL_BW,
                 *   RSRP,RSRQ,SINR,scs,srxlev */
                if (nf > 4)  mcc = plmn_field(fields[4]);
                if (nf > 5)  mnc = plmn_field(fields[5]);
                if (nf > 6)  h_cell_id = parse_hex(fields[6], &cell_id);
                if (nf > 7)  h_pci = parse_int(fields[7], &pci);
                if (nf > 8)  h_tac = parse_hex(fields[8], &tac);
                if (nf > 9)  h_earfcn = parse_int(fields[9], &earfcn);
                if (nf > 10) h_band = parse_int(fields[10], &band);
                /* NR_DL_BW is an ENUM index, and the manuals define
                 * it ONLY in RRC-connected state -- an idle reading is not a
                 * measurement, so it is omitted rather than mapped. */
                if (nf > 11 && strcmp(fields[1], "CONNECT") == 0) {
                    long idx = 0;
                    h_bw = parse_int(fields[11], &idx) && nr_bw_enum_to_mhz(idx, &bw);
                }
                if (nf > 12) h_rsrp = parse_int(fields[12], &rsrp);
                if (nf > 13) h_rsrq = parse_int(fields[13], &rsrq);
                if (nf > 14) h_sinr = parse_int(fields[14], &sinr);
            }

            build_cell_json(json_out[obs_count], JSON_BUF_MAX,
                            rat, duplex,
                            mcc, mnc,
                            cell_id, h_cell_id, pci, h_pci,
                            tac, h_tac, earfcn, h_earfcn,
                            band, h_band, bw, h_bw,
                            rsrp, h_rsrp, rsrq, h_rsrq,
                            sinr, h_sinr, rssi, h_rssi,
                            "serving", 1, NULL);
            obs_count++;

        } else if (strcmp(header, "NR5G-NSA") == 0) {
            /* +QENG: "NR5G-NSA",MCC,MNC,PCID,RSRP,SINR,RSRQ,ARFCN,band,
             *        NR_DL_bandwidth,scs
             *
             * SINR sits between RSRP and RSRQ (fields[5]). Reading the row as
             * ...RSRP,RSRQ,ARFCN,band... shifts rsrq/arfcn/band one column
             * left: SINR is reported as rsrq, RSRQ as a NEGATIVE earfcn, and
             * the ARFCN as an absurd band. Field order (and the SINR column) agree across
             * the RM5xxQ, RM500U, and RG520N/RM520N AT manuals; verified against
             * the vendor worked example
             *   +QENG:"NR5G-NSA",460,01,747,-71,13,-11,627264,78,12,1
             * where RSRQ is the -11 (RSRQ is always negative), the ARFCN is
             * 627264 (a valid n78 SSB, never negative), and the band is 78. */
            const char *mcc = NULL, *mnc = NULL;   /* as-broadcast digit strings */
            long pci = 0, rsrp = 0, sinr = 0, rsrq = 0, earfcn = 0, band = 0;
            int h_pci = 0, h_rsrp = 0, h_sinr = 0, h_rsrq = 0;
            int h_earfcn = 0, h_band = 0;

            if (nf > 1) mcc = plmn_field(fields[1]);
            if (nf > 2) mnc = plmn_field(fields[2]);
            if (nf > 3) h_pci = parse_int(fields[3], &pci);
            if (nf > 4) h_rsrp = parse_int(fields[4], &rsrp);
            if (nf > 5) h_sinr = parse_int(fields[5], &sinr);
            if (nf > 6) h_rsrq = parse_int(fields[6], &rsrq);
            if (nf > 7) h_earfcn = parse_int(fields[7], &earfcn);
            if (nf > 8) h_band = parse_int(fields[8], &band);

            build_cell_json(json_out[obs_count], JSON_BUF_MAX,
                            "NR", NULL,
                            mcc, mnc,
                            0, 0, pci, h_pci,
                            0, 0, earfcn, h_earfcn,
                            band, h_band, 0, 0,
                            rsrp, h_rsrp, rsrq, h_rsrq,
                            sinr, h_sinr, 0, 0,
                            "serving_secondary", 1, NULL);
            obs_count++;
        }

        line = strtok_r(NULL, "\n", &saveptr);
    }

    free(resp_copy);
    return obs_count;
}

/*
 * Parse AT+QENG="neighbourcell" response.
 *
 * Quectel EG25-G/EC25/RM500Q (all Quectel LTE modems):
 *   Same manuals as parse_qeng_serving above.
 *
 * LTE intra-frequency: +QENG: "neighbourcell intra","LTE",EARFCN,PCID,RSRQ,RSRP,RSSI,...
 * LTE inter-frequency: +QENG: "neighbourcell inter","LTE",EARFCN,PCID,RSRQ,RSRP,RSSI,...
 *
 * Non-LTE rows are dropped by policy and tallied into `drops`, which
 * may be NULL if the caller does not want the tally. See qeng_neighbor_drops_t
 * for why the drop is correct and why counting it is not optional.
 *
 * The tally is complete only while there is output headroom: the row loop
 * stops once `obs_count` reaches `max_obs`, so a response that fills the
 * observation array leaves its remaining rows uncounted as well as unparsed.
 * A tally is read as a total, so it is worth knowing which total it is.
 */
static int parse_qeng_neighbor(const char *response, char json_out[][JSON_BUF_MAX],
                               int max_obs, qeng_neighbor_drops_t *drops) {
    if (drops) memset(drops, 0, sizeof(*drops));

    char *resp_copy = strdup(response);
    if (!resp_copy) return 0;

    int obs_count = 0;
    char *saveptr = NULL;
    char *line = strtok_r(resp_copy, "\n", &saveptr);

    while (line && obs_count < max_obs) {
        while (*line == ' ') line++;

        if (strncmp(line, "+QENG:", 6) != 0) {
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

        if (nf < 2) {
            line = strtok_r(NULL, "\n", &saveptr);
            continue;
        }

        char *header = fields[0];

        if (strncmp(header, "neighbourcell", 13) == 0) {
            const char *obs_type = "observation";

            if (drops) drops->rows++;

            const char *rat_raw = (nf > 1) ? fields[1] : NULL;
            const char *rat = normalize_rat(rat_raw);
            if (!rat) {
                /* A token normalize_rat() does not know: a firmware surprise,
                 * not policy. Keep the FIRST one -- the caller reports it once
                 * per distinct token, and the first is the one that arrived
                 * before anybody was watching. */
                if (drops) {
                    drops->unknown++;
                    if (drops->unknown_token[0] == '\0' && rat_raw)
                        snprintf(drops->unknown_token, sizeof(drops->unknown_token),
                                 "%s", rat_raw);
                }
                line = strtok_r(NULL, "\n", &saveptr);
                continue;
            }

            if (strcmp(rat, "LTE") != 0 && drops) {
                /* Recognised and declined: 2G/3G are out of scope by policy,
                 * and NR neighbours have no decode here yet. */
                drops->declined++;
                int slot = qeng_rat_slot(rat);
                if (slot >= 0) drops->declined_by_rat[slot]++;
            }

            if (strcmp(rat, "LTE") == 0) {
                /* +QENG: "neighbourcell intra","LTE",EARFCN,PCID,RSRQ,RSRP,RSSI,... */
                long earfcn = 0, pci = 0, rsrq = 0, rsrp = 0, rssi = 0;
                int h_earfcn = 0, h_pci = 0, h_rsrq = 0, h_rsrp = 0, h_rssi = 0;

                if (nf > 2) h_earfcn = parse_int(fields[2], &earfcn);
                if (nf > 3) h_pci = parse_int(fields[3], &pci);
                if (nf > 4) h_rsrq = parse_int(fields[4], &rsrq);
                if (nf > 5) h_rsrp = parse_int(fields[5], &rsrp);
                if (nf > 6) h_rssi = parse_int(fields[6], &rssi);

                build_cell_json(json_out[obs_count], JSON_BUF_MAX,
                                rat, NULL,
                                NULL, NULL,   /* neighbour: PLMN not in this line */
                                0, 0, pci, h_pci,
                                0, 0, earfcn, h_earfcn,
                                0, 0, 0, 0,
                                rsrp, h_rsrp, rsrq, h_rsrq,
                                0, 0, rssi, h_rssi,
                                obs_type, 0, NULL);
                obs_count++;
                if (drops) drops->emitted++;
            }
        }

        line = strtok_r(NULL, "\n", &saveptr);
    }

    free(resp_copy);
    return obs_count;
}
