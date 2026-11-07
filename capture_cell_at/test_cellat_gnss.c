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

    Selftest for cellat_gnss: NMEA framing and batching, the Quectel AT
    replies, and the wwan node naming. The sentences are the NMEA 0183
    specification's own examples, not a recorded position.
*/

#ifdef CELL_SELFTEST

#include <stdio.h>
#include <string.h>

#include "cellat_gnss.h"

static int g_fails = 0;

#define CHECK(cond, what) do { \
    if (!(cond)) { \
        fprintf(stderr, "  FAIL %s (line %d)\n", what, __LINE__); \
        g_fails++; \
    } \
} while (0)

static const char GGA[] = "$GPGGA,123519,4807.038,N,01131.000,E,1,08,0.9,545.4,M,46.9,M,,*47";
static const char RMC[] = "$GPRMC,123519,A,4807.038,N,01131.000,E,022.4,084.4,230394,003.1,W*6A";

static void test_framing(void) {
    static cellat_nmea_t n;
    char in[512];
    size_t used;

    cellat_nmea_init(&n);
    snprintf(in, sizeof(in), "%s\r\n%s\r\n$GPGSA,A,3,04,05", GGA, RMC);
    CHECK(cellat_nmea_feed(&n, in, strlen(in), &used) == 0 && used == strlen(in),
          "two sentences and a partial one are consumed");
    char want[512];
    snprintf(want, sizeof(want), "{\"v\":1,\"sentences\":[\"%s\",\"%s\"]}", GGA, RMC);
    const char *rec = cellat_nmea_record(&n);
    CHECK(rec != NULL && strcmp(rec, want) == 0, "batch record");

    /* The partial line completes in the next read */
    cellat_nmea_clear(&n);
    CHECK(cellat_nmea_record(&n) == NULL, "cleared batch is empty");
    const char rest[] = ",,,,,,,,,,2.5,1.3,2.1*39\n";
    cellat_nmea_feed(&n, rest, strlen(rest), &used);
    rec = cellat_nmea_record(&n);
    CHECK(rec != NULL && strstr(rec, "\"$GPGSA,A,3,04,05,,,,,,,,,,2.5,1.3,2.1*39\"") != NULL,
          "a sentence split across reads is joined");

    /* Not NMEA: echo, AT replies, quotes, control bytes, overlong lines */
    cellat_nmea_init(&n);
    char bad[400];
    memset(bad, 'A', sizeof(bad));
    bad[0] = '$';
    const char junk[] = "OK\r\n+QGPS: 1\r\n$GP\"x\",1*00\r\n$GP\x01xx,1\r\n";
    cellat_nmea_feed(&n, junk, strlen(junk), &used);
    cellat_nmea_feed(&n, bad, sizeof(bad), &used);
    cellat_nmea_feed(&n, "\n", 1, &used);
    CHECK(cellat_nmea_record(&n) == NULL && n.rejected == 5, "non-NMEA lines are refused");

    /* A full batch stops the feed until it is sent */
    cellat_nmea_init(&n);
    char line[128];
    int full = 0;
    size_t total = 0;
    snprintf(line, sizeof(line), "%s\n", GGA);
    for (int i = 0; i < CELLAT_NMEA_BATCH_MAX + 5 && !full; i++) {
        full = cellat_nmea_feed(&n, line, strlen(line), &used);
        total += used;
    }
    CHECK(full && n.count == CELLAT_NMEA_BATCH_MAX, "batch fills at the limit");
    rec = cellat_nmea_record(&n);
    CHECK(rec != NULL && strlen(rec) < sizeof(n.json), "a full batch fits its buffer");

    /* The longest accepted sentences still fit */
    cellat_nmea_init(&n);
    char longest[CELLAT_NMEA_LINE_MAX + 1];
    memset(longest, 'Z', CELLAT_NMEA_LINE_MAX - 1);
    longest[0] = '$';
    longest[CELLAT_NMEA_LINE_MAX - 1] = '\n';
    for (int i = 0; i < CELLAT_NMEA_BATCH_MAX; i++)
        cellat_nmea_feed(&n, longest, CELLAT_NMEA_LINE_MAX, &used);
    rec = cellat_nmea_record(&n);
    CHECK(n.count == CELLAT_NMEA_BATCH_MAX && rec != NULL && strlen(rec) < sizeof(n.json),
          "a batch of the longest sentences fits");
}

static void test_at_replies(void) {
    CHECK(cellat_qgps_state("+QGPS: 1\nOK") == 1, "QGPS on");
    CHECK(cellat_qgps_state("+QGPS: 0\nOK") == 0, "QGPS off");
    CHECK(cellat_qgps_state("+CME ERROR: 504") == -1, "QGPS error");
    CHECK(cellat_qgps_state("+QGPS: 12") == -1, "QGPS not a state");

    char port[32];
    CHECK(cellat_qgps_outport("+QGPSCFG: \"outport\",\"usbnmea\"\nOK", port, sizeof(port)) == 0 &&
          strcmp(port, "usbnmea") == 0, "outport usbnmea");
    CHECK(cellat_qgps_outport("+QGPSCFG: \"outport\",\"none\"\nOK", port, sizeof(port)) == 0 &&
          strcmp(port, "none") == 0, "outport none");
    CHECK(cellat_qgps_outport("+QGPSCFG: \"outport\",\"us;b\"", port, sizeof(port)) == -1,
          "outport refuses odd characters");
    CHECK(cellat_qgps_outport("ERROR", port, sizeof(port)) == -1, "outport error");
    CHECK(cellat_qgps_outport("+QGPSCFG: \"outport\",\"usbnmea\"", port, 4) == -1,
          "outport too long for the buffer");
}

static void test_options(void) {
    CHECK(cellat_gnss_wanted("quectel", 7), "a name enables");
    CHECK(cellat_gnss_wanted("true", 4), "true enables");
    CHECK(!cellat_gnss_wanted("false", 5) && !cellat_gnss_wanted("OFF", 3) &&
          !cellat_gnss_wanted("0", 1) && !cellat_gnss_wanted("no", 2) &&
          !cellat_gnss_wanted("", 0) && !cellat_gnss_wanted(NULL, 0), "off values");

    char out[64];
    CHECK(cellat_gnss_wwan_nmea("/dev/wwan0at0", out, sizeof(out)) == 0 &&
          strcmp(out, "/dev/wwan0nmea0") == 0, "wwan0at0");
    CHECK(cellat_gnss_wwan_nmea("/dev/wwan3at1", out, sizeof(out)) == 0 &&
          strcmp(out, "/dev/wwan3nmea0") == 0, "wwan3at1");
    CHECK(cellat_gnss_wwan_nmea("/dev/ttyUSB2", out, sizeof(out)) == -1, "not wwan");
    CHECK(cellat_gnss_wwan_nmea("/dev/wwan0at0x", out, sizeof(out)) == -1, "trailing junk");
    CHECK(cellat_gnss_wwan_nmea("/dev/wwan0at0", out, 8) == -1, "too small");
}

/* A sentence's checksum is right: the XOR of everything between $ and * */
static int cs_ok(const char *s, size_t len) {
    if (len < 4 || s[0] != '$' || s[len - 3] != '*')
        return 0;
    unsigned int sum = 0, want = 0;
    for (size_t i = 1; i < len - 3; i++)
        sum ^= (unsigned char)s[i];
    if (sscanf(s + len - 2, "%2X", &want) != 1)
        return 0;
    return sum == want;
}

/* Sentence `idx` (0-based) of a CR LF separated block, into out */
static int nth(const char *block, int idx, char *out, size_t outsz) {
    const char *p = block;
    for (int i = 0; i < idx; i++) {
        p = strstr(p, "\r\n");
        if (p == NULL)
            return 0;
        p += 2;
    }
    size_t len = strcspn(p, "\r");
    if (len == 0 || len >= outsz || strncmp(p + len, "\r\n", 2) != 0)
        return 0;
    memcpy(out, p, len);
    out[len] = '\0';
    return 1;
}

/* Every sentence carries a right checksum and none is followed by junk */
static int all_cs_ok(const char *block, int count) {
    char s[256];
    for (int i = 0; i < count; i++) {
        if (!nth(block, i, s, sizeof(s)) || !cs_ok(s, strlen(s)))
            return 0;
    }
    return !nth(block, count, s, sizeof(s));
}

/* The body of a sentence (between $ and *) */
static const char *body_of(const char *s, char *out, size_t outsz) {
    size_t len = strlen(s);
    if (len < 4 || len - 3 >= outsz)
        return "";
    memcpy(out, s + 1, len - 4);
    out[len - 4] = '\0';
    return out;
}

static void test_qgpsloc(void) {
    char out[CELLAT_QGPSLOC_NMEA_MAX], s[256], b[256];

    /* The instrument first: the specification's GGA has a right checksum,
     * and one changed byte does not */
    CHECK(cs_ok(GGA, strlen(GGA)) && cs_ok(RMC, strlen(RMC)), "checksum of the spec examples");
    char bent[sizeof(GGA)];
    memcpy(bent, GGA, sizeof(GGA));
    bent[10] = '6';
    CHECK(!cs_ok(bent, strlen(bent)), "a changed byte fails the checksum");

    /* <mode> 2, the spec example's position: 48.1173 N, 11.516667 E */
    int n = cellat_qgpsloc_nmea(
        "\r\n+QGPSLOC: 123519.000,48.11730,11.51667,0.9,545.4,3,84.4,41.5,22.4,230394,08\r\n\r\nOK\r\n",
        out, sizeof(out));
    CHECK(n == 3, "mode 2 fix: GGA, RMC and GSA");
    CHECK(all_cs_ok(out, n), "mode 2: every checksum right");
    CHECK(nth(out, 0, s, sizeof(s)) &&
          strcmp(body_of(s, b, sizeof(b)),
                 "GNGGA,123519.000,4807.038000,N,01131.000200,E,1,08,0.9,545.4,M,,M,,") == 0,
          "mode 2 GGA: degrees to ddmm.mmmmmm, altitude, satellites, HDOP");
    CHECK(nth(out, 1, s, sizeof(s)) &&
          strcmp(body_of(s, b, sizeof(b)),
                 "GNRMC,123519.000,A,4807.038000,N,01131.000200,E,22.4,84.4,230394,,,A") == 0,
          "mode 2 RMC: knots, course and date");
    CHECK(nth(out, 2, s, sizeof(s)) && strncmp(s, "$GNGSA,A,3,", 11) == 0, "GSA says 3D");
    {
        /* The GSA layout the server reads: 18 fields, HDOP in field 16 */
        char *f[24];
        int nf = 0;
        body_of(s, b, sizeof(b));
        for (char *q = b; nf < 24; ) {
            f[nf++] = q;
            char *c = strchr(q, ',');
            if (c == NULL)
                break;
            *c = '\0';
            q = c + 1;
        }
        CHECK(nf == 18 && strcmp(f[16], "0.9") == 0 && f[15][0] == '\0' && f[17][0] == '\0',
              "GSA has 18 fields with HDOP in field 16");
    }

    /* <mode> 0 is the modem's own GGA form, passed through */
    n = cellat_qgpsloc_nmea("+QGPSLOC: 123519.00,4807.0380N,01131.0000E,0.9,545.4,2,,0.0,0.0,230394,08\r\nOK",
                            out, sizeof(out));
    CHECK(n == 3 && all_cs_ok(out, n), "mode 0 fix: three sentences, right checksums");
    CHECK(nth(out, 0, s, sizeof(s)) &&
          strcmp(body_of(s, b, sizeof(b)),
                 "GNGGA,123519.00,4807.0380,N,01131.0000,E,1,08,0.9,545.4,M,,M,,") == 0,
          "mode 0 GGA keeps the modem's digits");
    CHECK(nth(out, 2, s, sizeof(s)) && strncmp(s, "$GNGSA,A,2,", 11) == 0, "GSA says 2D");

    /* South and west, and degrees that round up into the next degree */
    n = cellat_qgpsloc_nmea("+QGPSLOC: 000000.000,-33.85678,-151.21500,1.2,10.0,3,,0.0,0.0,010100,05",
                            out, sizeof(out));
    CHECK(n == 3 && nth(out, 0, s, sizeof(s)) &&
          strstr(s, ",3351.406800,S,15112.900000,W,") != NULL, "S and W from the sign");
    n = cellat_qgpsloc_nmea("+QGPSLOC: 000000.000,0.9999999999,-0.5,1.2,10.0,3,,0.0,0.0,010100,05",
                            out, sizeof(out));
    CHECK(n == 3 && nth(out, 0, s, sizeof(s)) &&
          strstr(s, ",0100.000000,N,00030.000000,W,") != NULL,
          "a 60th minute carries into the degree");

    /* An empty <fix> (an EG18-NA with a fix leaves it empty): no GSA */
    n = cellat_qgpsloc_nmea("+QGPSLOC: 031944.000,41.00000,-111.00000,0.8,1433.1,,152.3,0.0,0.0,030826,12",
                            out, sizeof(out));
    CHECK(n == 2 && all_cs_ok(out, n) && strstr(out, "GSA") == NULL,
          "empty fix mode: GGA and RMC, no GSA");

    /* No speed: no RMC, which the server would refuse anyway */
    n = cellat_qgpsloc_nmea("+QGPSLOC: 031944.000,41.00000,-111.00000,0.8,1433.1,3,,,,030826,12",
                            out, sizeof(out));
    CHECK(n == 2 && strstr(out, "RMC") == NULL && strstr(out, "GSA") != NULL,
          "no speed: GGA and GSA, no RMC");

    /* Not fixed now: a no-fix GGA keeps the GPS connected */
    n = cellat_qgpsloc_nmea("\r\n+CME ERROR: 516\r\n", out, sizeof(out));
    CHECK(n == 1 && all_cs_ok(out, 1) && strncmp(out, "$GNGGA,,,,,,0,", 14) == 0,
          "516 is a no-fix GGA");
    n = cellat_qgpsloc_nmea("\r\n+CME ERROR: Not fixed now\r\n", out, sizeof(out));
    CHECK(n == 1 && all_cs_ok(out, 1) && strncmp(out, "$GNGGA,,,,,,0,", 14) == 0,
          "verbose not fixed now (AT+CMEE=2) is a no-fix GGA");

    /* <mode> 0 ranges: minutes under 60, nothing past 90 or 180 */
    CHECK(cellat_qgpsloc_nmea("+QGPSLOC: 123519.000,9000.0000N,18000.0000W,0.9,545.4,3,,0.0,0.0,230394,08",
                              out, sizeof(out)) == 3, "mode 0 at exactly 90 N, 180 W");
    CHECK(cellat_qgpsloc_nmea("+QGPSLOC: 123519.000,4860.0000N,01131.0000E,0.9,545.4,3,,0.0,0.0,230394,08",
                              out, sizeof(out)) == 0, "mode 0 with 60 minutes");
    CHECK(cellat_qgpsloc_nmea("+QGPSLOC: 123519.000,9000.0001N,01131.0000E,0.9,545.4,3,,0.0,0.0,230394,08",
                              out, sizeof(out)) == 0, "mode 0 latitude past 90");
    CHECK(cellat_qgpsloc_nmea("+QGPSLOC: 123519.000,4807.0380N,18100.0000E,0.9,545.4,3,,0.0,0.0,230394,08",
                              out, sizeof(out)) == 0, "mode 0 longitude past 180");

    /* A sentence that does not fit leaves nothing of itself behind */
    n = cellat_qgpsloc_nmea("+QGPSLOC: 123519.000,48.11730,11.51667,0.9,545.4,3,84.4,41.5,22.4,230394,08",
                            out, sizeof(out));
    size_t gga_len = (size_t)(strstr(out, "\r\n") + 2 - out);
    n = cellat_qgpsloc_nmea("+QGPSLOC: 123519.000,48.11730,11.51667,0.9,545.4,3,84.4,41.5,22.4,230394,08",
                            out, gga_len + 20);
    CHECK(n == 1 && strlen(out) == gga_len, "room for the GGA only: the GGA and nothing more");

    /* Everything else is nothing */
    CHECK(cellat_qgpsloc_nmea("+CME ERROR: 505", out, sizeof(out)) == 0, "505 (GNSS off)");
    CHECK(cellat_qgpsloc_nmea("+CME ERROR: 5160", out, sizeof(out)) == 0, "5160 is not 516");
    CHECK(cellat_qgpsloc_nmea("ERROR", out, sizeof(out)) == 0, "plain ERROR");
    CHECK(cellat_qgpsloc_nmea("", out, sizeof(out)) == 0 && out[0] == '\0', "no answer");
    CHECK(cellat_qgpsloc_nmea("+QGPSLOC: 123519.000,48.11730,11.51667,0.9,545.4,3,,0.0,0.0,230394",
                              out, sizeof(out)) == 0, "ten fields");
    /* A twelfth column might have been inserted anywhere, which would move
     * every column after it: refused, not read by position */
    CHECK(cellat_qgpsloc_nmea("+QGPSLOC: 123519.000,48.11730,11.51667,0.9,545.4,3,,0.0,0.0,230394,08,1",
                              out, sizeof(out)) == 0, "twelve fields");
    CHECK(cellat_qgpsloc_nmea("+QGPSLOC: 123519.000,4807.038000,N,01131.000000,E,0.9,545.4,3,,0.0,0.0,230394,08",
                              out, sizeof(out)) == 0, "mode 1 (hemisphere fields) is not decoded");
    CHECK(cellat_qgpsloc_nmea("+QGPSLOC: 123519.000,90.00001,11.51667,0.9,545.4,3,,0.0,0.0,230394,08",
                              out, sizeof(out)) == 0, "latitude beyond 90");
    CHECK(cellat_qgpsloc_nmea("+QGPSLOC: 123519.000,48.11730,180.5,0.9,545.4,3,,0.0,0.0,230394,08",
                              out, sizeof(out)) == 0, "longitude beyond 180");
    CHECK(cellat_qgpsloc_nmea("+QGPSLOC: 123519.000,48.1*730,11.51667,0.9,545.4,3,,0.0,0.0,230394,08",
                              out, sizeof(out)) == 0, "a '*' in a coordinate");
    CHECK(cellat_qgpsloc_nmea("+QGPSLOC: 123519.000,48.11730,11.51667,0.9,545.4*00,3,,0.0,0.0,230394,08",
                              out, sizeof(out)) == 0, "a '*' in the altitude");
    CHECK(cellat_qgpsloc_nmea("+QGPSLOC: 123519.000,48.11730,11.51667,0.9,,3,,0.0,0.0,230394,08",
                              out, sizeof(out)) == 0, "no altitude (the server needs it)");
    CHECK(cellat_qgpsloc_nmea("+QGPSLOC: 123519.000,48.11730,11.51667,0.9,545.4,1,,0.0,0.0,230394,08",
                              out, sizeof(out)) == 0, "fix mode 1 is not a fix");
    CHECK(cellat_qgpsloc_nmea("+QGPSLOC: 123519.000,480.7038N,01131.0000E,0.9,545.4,3,,0.0,0.0,230394,08",
                              out, sizeof(out)) == 0, "mode 0 with the point in the wrong place");
    CHECK(cellat_qgpsloc_nmea("+QGPSLOC: 123519.000,48.11730,11.51667,0.9,545.4,3,,0.0,0.0,2303945,08",
                              out, sizeof(out)) == 0, "a seven-digit date");
    CHECK(cellat_qgpsloc_nmea("+QGPSLOC: 123519.000,48.11730,11.51667,0.9,545.4,3,,0.0,0.0,230394,08",
                              out, 40) == 0, "an output buffer too small for the GGA");

    /* The sentences ride the NMEA port's batch unchanged */
    static cellat_nmea_t batch;
    size_t used;
    cellat_nmea_init(&batch);
    n = cellat_qgpsloc_nmea("+QGPSLOC: 123519.000,48.11730,11.51667,0.9,545.4,3,84.4,41.5,22.4,230394,08",
                            out, sizeof(out));
    cellat_nmea_feed(&batch, out, strlen(out), &used);
    CHECK(batch.count == 3 && batch.rejected == 0 && used == strlen(out),
          "the batch takes all three, rejecting none");
}

int main(void) {
    test_framing();
    test_at_replies();
    test_options();
    test_qgpsloc();
    if (g_fails) {
        fprintf(stderr, "test_cellat_gnss: %d failure(s)\n", g_fails);
        return 1;
    }
    printf("test_cellat_gnss: all checks passed\n");
    return 0;
}

#endif /* CELL_SELFTEST */
