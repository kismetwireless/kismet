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

    cellat_gnss -- the modem's GNSS, for a Kismet GPS.

    With gps=<name> on the source, cellat turns the modem's GNSS on over the
    AT port (Quectel AT+QGPS=1) and reads the modem's NMEA port -- a separate
    interface, so the reader runs on its own thread and its own fd and never
    waits on, or holds up, an AT exchange. Sentences go to Kismet in batches as
    CellNMEA records, which the server feeds to the cellmodem GPS of that name
    (gpscellmodem.h). A GNSS this source turned on is turned off at close.

    Pure libc: line framing, the batch record, the AT reply parsing and the
    wwan node naming, so test_cellat_gnss runs with no modem.
*/

#ifndef __CELLAT_GNSS_H__
#define __CELLAT_GNSS_H__

#include <stddef.h>

#ifdef __cplusplus
extern "C" {
#endif

#define CELLAT_GNSS_TYPE "CellNMEA"

/* The longest sentence passed on; the server's NMEA decoder limit
 * (gps_nmea::max_sentence_len) */
#define CELLAT_NMEA_LINE_MAX 128

/* A batch is sent when it holds this many sentences, or a second after its
 * first; the server drops a larger one */
#define CELLAT_NMEA_BATCH_MAX 32
#define CELLAT_NMEA_JSON_MAX (CELLAT_NMEA_BATCH_MAX * (CELLAT_NMEA_LINE_MAX + 3) + 64)

typedef struct {
    char line[CELLAT_NMEA_LINE_MAX];
    size_t len;
    int overlong;                   /* the line being read is being skipped */

    char json[CELLAT_NMEA_JSON_MAX];
    size_t json_len;
    int count;

    unsigned long rejected;         /* lines that were not NMEA */
} cellat_nmea_t;

void cellat_nmea_init(cellat_nmea_t *n);

/* Frame bytes into sentences and add them to the batch. Returns 1 when the
 * batch is full and must be sent (cellat_nmea_record) before more bytes are
 * fed; *used says how many of the bytes were consumed. */
int cellat_nmea_feed(cellat_nmea_t *n, const char *buf, size_t len, size_t *used);

/* The batch as one CellNMEA JSON record, or NULL when it is empty. The
 * pointer stays valid until cellat_nmea_clear. */
const char *cellat_nmea_record(cellat_nmea_t *n);
void cellat_nmea_clear(cellat_nmea_t *n);

/* Is the gps= value an enable: anything but empty / false / 0 / no / off */
int cellat_gnss_wanted(const char *value, size_t len);

/* AT+QGPS? -> 1 on, 0 off, -1 not understood */
int cellat_qgps_state(const char *resp);

/* AT+QGPSCFG="outport" -> the port ("usbnmea", "uartnmea", "none") into out;
 * 0, or -1 when not understood */
int cellat_qgps_outport(const char *resp, char *out, size_t outsz);

/* The NMEA node beside a wwan AT node: "/dev/wwan0at0" -> "/dev/wwan0nmea0".
 * 0, or -1 when at_path is not a wwan AT node */
int cellat_gnss_wwan_nmea(const char *at_path, char *out, size_t outsz);

#ifdef __cplusplus
}
#endif

#endif /* __CELLAT_GNSS_H__ */
