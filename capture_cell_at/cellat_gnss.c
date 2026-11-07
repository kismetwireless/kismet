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

    See cellat_gnss.h.
*/

#include <stdio.h>
#include <string.h>
#include <strings.h>

#include "cellat_gnss.h"

void cellat_nmea_init(cellat_nmea_t *n) {
    memset(n, 0, sizeof(*n));
}

void cellat_nmea_clear(cellat_nmea_t *n) {
    n->json_len = 0;
    n->count = 0;
}

/* A sentence is "$" or "!", then printable ASCII. Quotes and backslashes never
 * appear in NMEA, so a line with one is refused rather than escaped. */
static int sentence_ok(const char *s, size_t len) {
    if (len < 6 || (s[0] != '$' && s[0] != '!'))
        return 0;
    for (size_t i = 0; i < len; i++) {
        unsigned char c = (unsigned char)s[i];
        if (c < 0x20 || c > 0x7e || c == '"' || c == '\\')
            return 0;
    }
    return 1;
}

static void add_sentence(cellat_nmea_t *n, const char *s, size_t len) {
    if (!sentence_ok(s, len)) {
        n->rejected++;
        return;
    }
    if (n->count == 0) {
        static const char head[] = "{\"v\":1,\"sentences\":[";
        memcpy(n->json, head, sizeof(head) - 1);
        n->json_len = sizeof(head) - 1;
    }
    /* Sized for CELLAT_NMEA_BATCH_MAX lines of the longest length */
    if (n->count)
        n->json[n->json_len++] = ',';
    n->json[n->json_len++] = '"';
    memcpy(n->json + n->json_len, s, len);
    n->json_len += len;
    n->json[n->json_len++] = '"';
    n->count++;
}

int cellat_nmea_feed(cellat_nmea_t *n, const char *buf, size_t len, size_t *used) {
    size_t i;

    for (i = 0; i < len && n->count < CELLAT_NMEA_BATCH_MAX; i++) {
        char c = buf[i];
        if (c == '\r' || c == '\n') {
            if (!n->overlong && n->len > 0)
                add_sentence(n, n->line, n->len);
            else if (n->overlong)
                n->rejected++;
            n->len = 0;
            n->overlong = 0;
            continue;
        }
        if (n->overlong)
            continue;
        if (n->len >= sizeof(n->line) - 1) {
            n->overlong = 1;
            n->len = 0;
            continue;
        }
        n->line[n->len++] = c;
    }
    if (used)
        *used = i;
    return n->count >= CELLAT_NMEA_BATCH_MAX;
}

const char *cellat_nmea_record(cellat_nmea_t *n) {
    if (n->count == 0)
        return NULL;
    memcpy(n->json + n->json_len, "]}", 3);
    return n->json;
}

int cellat_gnss_wanted(const char *value, size_t len) {
    static const char *const off[] = { "false", "0", "no", "off" };

    if (value == NULL || len == 0)
        return 0;
    for (size_t i = 0; i < sizeof(off) / sizeof(off[0]); i++) {
        if (strlen(off[i]) == len && strncasecmp(value, off[i], len) == 0)
            return 0;
    }
    return 1;
}

int cellat_qgps_state(const char *resp) {
    const char *p = resp ? strstr(resp, "+QGPS:") : NULL;
    if (p == NULL)
        return -1;
    p += 6;
    while (*p == ' ')
        p++;
    if (*p == '0' || *p == '1')
        return p[1] == '\0' || p[1] == '\r' || p[1] == '\n' ? *p - '0' : -1;
    return -1;
}

int cellat_qgps_outport(const char *resp, char *out, size_t outsz) {
    const char *p = resp ? strstr(resp, "+QGPSCFG: \"outport\",") : NULL;
    if (p == NULL || out == NULL || outsz == 0)
        return -1;
    p += strlen("+QGPSCFG: \"outport\",");
    if (*p == '"')
        p++;
    size_t n = strcspn(p, "\"\r\n");
    if (n == 0 || n >= outsz)
        return -1;
    for (size_t i = 0; i < n; i++) {
        char c = p[i];
        if (!((c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z') || (c >= '0' && c <= '9')))
            return -1;
    }
    memcpy(out, p, n);
    out[n] = '\0';
    return 0;
}

/* A field of digits, '.' and a leading '-' only (or empty, if allowed):
 * nothing that could end or split a sentence */
static int numeric_field(const char *s, int empty_ok) {
    if (*s == '\0')
        return empty_ok;
    int digits = 0;
    for (const char *p = s; *p; p++) {
        if (*p >= '0' && *p <= '9')
            digits++;
        else if (!(*p == '.' || (*p == '-' && p == s)))
            return 0;
    }
    return digits > 0;
}

/* <mode> 0 coordinate: "4807.0380N" -> "4807.0380", 'N'. deg_digits is 2 for
 * a latitude and 3 for a longitude. */
static int coord_mode0(const char *s, int deg_digits, long max_deg, const char *hemis,
                       char *out, size_t outsz, char *hemi) {
    size_t len = strlen(s);
    if (len < 2 || strchr(hemis, s[len - 1]) == NULL || len - 1 >= outsz)
        return 0;
    const char *dot = strchr(s, '.');
    if (dot == NULL || dot - s != deg_digits + 2)
        return 0;
    for (size_t i = 0; i < len - 1; i++) {
        if (s + i != dot && (s[i] < '0' || s[i] > '9'))
            return 0;
    }

    /* Whole minutes under 60, and nothing past max_deg itself */
    long deg = 0;
    int min_zero = 1;
    for (int i = 0; i < deg_digits; i++)
        deg = deg * 10 + (s[i] - '0');
    for (size_t i = (size_t)deg_digits; i < len - 1; i++) {
        if (s[i] != '0' && s[i] != '.')
            min_zero = 0;
    }
    if ((s[deg_digits] - '0') * 10 + (s[deg_digits + 1] - '0') >= 60 ||
        deg > max_deg || (deg == max_deg && !min_zero))
        return 0;

    memcpy(out, s, len - 1);
    out[len - 1] = '\0';
    *hemi = s[len - 1];
    return 1;
}

/* <mode> 2 coordinate: "-11.51667" -> "01131.000200", 'W'. Integer only: the
 * fraction is read as nanodegrees and turned into microminutes, so no float
 * rounding can print a 60th minute. */
static int coord_mode2(const char *s, int deg_digits, long max_deg, const char *hemis,
                       char *out, size_t outsz, char *hemi) {
    int neg = (*s == '-');
    const char *p = s + neg;
    long deg = 0;
    long long nano = 0;
    int ndeg = 0, nfrac = 0;

    for (; *p >= '0' && *p <= '9'; p++, ndeg++) {
        if (ndeg >= 3)
            return 0;
        deg = deg * 10 + (*p - '0');
    }
    if (ndeg == 0 || *p != '.')
        return 0;
    for (p++; *p >= '0' && *p <= '9'; p++, nfrac++) {
        if (nfrac < 9)
            nano = nano * 10 + (*p - '0');
    }
    if (*p != '\0' || nfrac == 0)
        return 0;
    for (int i = nfrac; i < 9; i++)
        nano *= 10;

    long long umin = (nano * 60 + 500) / 1000;   /* microminutes, rounded */
    if (umin >= 60000000LL) {
        umin -= 60000000LL;
        deg++;
    }
    if (deg > max_deg || (deg == max_deg && umin > 0))
        return 0;

    int n = snprintf(out, outsz, "%0*ld%02lld.%06lld", deg_digits, deg,
                     umin / 1000000, umin % 1000000);
    if (n < 0 || (size_t)n >= outsz)
        return 0;
    *hemi = neg ? hemis[1] : hemis[0];
    return 1;
}

static int coord(const char *s, int deg_digits, long max_deg, const char *hemis,
                 char *out, size_t outsz, char *hemi) {
    return coord_mode0(s, deg_digits, max_deg, hemis, out, outsz, hemi) ||
           coord_mode2(s, deg_digits, max_deg, hemis, out, outsz, hemi);
}

/* "$" body "*" checksum CR LF, appended at *pos */
static int put_sentence(char *out, size_t outsz, size_t *pos, const char *body) {
    unsigned int sum = 0;
    for (const char *p = body; *p; p++)
        sum ^= (unsigned char)*p;
    int n = snprintf(out + *pos, outsz - *pos, "$%s*%02X\r\n", body, sum);
    if (n < 0 || (size_t)n >= outsz - *pos || (size_t)n - 2 >= CELLAT_NMEA_LINE_MAX) {
        /* Drop what snprintf left of it */
        out[*pos] = '\0';
        return 0;
    }
    *pos += (size_t)n;
    return 1;
}

int cellat_qgpsloc_nmea(const char *resp, char *out, size_t outsz) {
    char line[256], body[CELLAT_NMEA_LINE_MAX];
    char *f[16];
    int nf = 0;
    size_t pos = 0;

    if (resp == NULL || out == NULL || outsz == 0)
        return 0;
    out[0] = '\0';

    const char *e = strstr(resp, "+CME ERROR:");
    if (e != NULL) {
        e += strlen("+CME ERROR:");
        while (*e == ' ')
            e++;
        /* "Not fixed now", as numeric (AT+CMEE=1) or verbose (=2) errors word it */
        if ((strncmp(e, "516", 3) == 0 && (e[3] < '0' || e[3] > '9')) ||
            strncasecmp(e, "Not fixed now", 13) == 0)
            return put_sentence(out, outsz, &pos, "GNGGA,,,,,,0,,,,,,,,") ? 1 : 0;
        return 0;
    }

    const char *p = strstr(resp, "+QGPSLOC:");
    if (p == NULL)
        return 0;
    p += strlen("+QGPSLOC:");
    while (*p == ' ')
        p++;
    size_t len = strcspn(p, "\r\n");
    if (len == 0 || len >= sizeof(line))
        return 0;
    memcpy(line, p, len);
    line[len] = '\0';

    /* <UTC>,<lat>,<lon>,<HDOP>,<altitude>,<fix>,<COG>,<spkm>,<spkn>,<date>,<nsat>
     * Eleven fields in <mode> 0 and 2; <mode> 1 splits the hemispheres out
     * into fields of their own and is not decoded. */
    for (char *s = line; nf < 16; ) {
        f[nf++] = s;
        char *comma = strchr(s, ',');
        if (comma == NULL)
            break;
        *comma = '\0';
        s = comma + 1;
    }
    if (nf != 11)
        return 0;

    const char *utc = f[0], *hdop = f[3], *alt = f[4], *fix = f[5], *cog = f[6];
    const char *spkn = f[8], *date = f[9], *nsat = f[10];
    char lat[24], lon[24], ns, ew;

    if (!numeric_field(utc, 0) || strlen(utc) < 6 || utc[0] == '-' ||
        !coord(f[1], 2, 90, "NS", lat, sizeof(lat), &ns) ||
        !coord(f[2], 3, 180, "EW", lon, sizeof(lon), &ew) ||
        !numeric_field(alt, 0) || !numeric_field(hdop, 1) || !numeric_field(nsat, 1) ||
        !numeric_field(cog, 1) || !numeric_field(spkn, 1) ||
        !(date[0] == '\0' || (strlen(date) == 6 && strspn(date, "0123456789") == 6)) ||
        !(fix[0] == '\0' || ((fix[0] == '2' || fix[0] == '3') && fix[1] == '\0')))
        return 0;

    int count = 0;
    snprintf(body, sizeof(body), "GNGGA,%s,%s,%c,%s,%c,1,%s,%s,%s,M,,M,,",
             utc, lat, ns, lon, ew, nsat, hdop, alt);
    if (!put_sentence(out, outsz, &pos, body))
        return 0;
    count++;

    if (spkn[0] != '\0') {
        snprintf(body, sizeof(body), "GNRMC,%s,A,%s,%c,%s,%c,%s,%s,%s,,,A",
                 utc, lat, ns, lon, ew, spkn, cog, date);
        if (put_sentence(out, outsz, &pos, body))
            count++;
    }

    if (fix[0] != '\0') {
        /* mode, 12 satellite slots, PDOP, HDOP, VDOP */
        snprintf(body, sizeof(body), "GNGSA,A,%c,,,,,,,,,,,,,,%s,", fix[0], hdop);
        if (put_sentence(out, outsz, &pos, body))
            count++;
    }

    return count;
}

int cellat_gnss_wwan_nmea(const char *at_path, char *out, size_t outsz) {
    unsigned int idx, port;
    char tail;

    if (at_path == NULL || out == NULL || outsz == 0)
        return -1;
    if (sscanf(at_path, "/dev/wwan%uat%u%c", &idx, &port, &tail) != 2 || idx > 99)
        return -1;
    if ((size_t)snprintf(out, outsz, "/dev/wwan%unmea0", idx) >= outsz)
        return -1;
    return 0;
}
