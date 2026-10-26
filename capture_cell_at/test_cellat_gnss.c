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

int main(void) {
    test_framing();
    test_at_replies();
    test_options();
    if (g_fails) {
        fprintf(stderr, "test_cellat_gnss: %d failure(s)\n", g_fails);
        return 1;
    }
    printf("test_cellat_gnss: all checks passed\n");
    return 0;
}

#endif /* CELL_SELFTEST */
