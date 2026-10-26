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
