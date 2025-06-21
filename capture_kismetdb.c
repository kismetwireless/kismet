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

/* capture_kismetdb
 *
 * Basic capture binary for reading kismetdb logfiles.
 */

#include <pcap.h>
#include <getopt.h>
#include <pthread.h>
#include <fcntl.h>

/* According to POSIX.1-2001, POSIX.1-2008 */
#include <sys/select.h>

/* According to earlier standards */
#include <sys/time.h>
#include <sys/types.h>
#include <sys/stat.h>

#include <unistd.h>
#include <errno.h>

#include <arpa/inet.h>

#include <string.h>

#include "config.h"
#include "capture_framework.h"

#include <sqlite3.h>

typedef struct {
    sqlite3 *db;
    char *dbname;

    /* Optional filters for sub-sources */
    char *sub_uuid;
    int sub_dlt;

    /* Database version */
    int db_version;

    int realtime;
    struct timeval last_ts;

    unsigned int pps_throttle;
} local_pcap_t;

/* Version callback */
int sqlite_version_cb(void *ver, int argc, char **data, char **colnames) {
    if (argc != 1) {
        *((unsigned int *) ver) = 0;
        return 0;
    }

    if (sscanf(data[0], "%u", (unsigned int *) ver) != 1) {
        *((unsigned int *) ver) = 0;
    }

    return 0;
}

int probe_callback(kis_capture_handler_t *caph, uint32_t seqno, char *definition,
        char *msg, char **uuid,
        cf_params_interface_t **ret_interface,
        cf_params_spectrum_t **ret_spectrum) {
    char *placeholder = NULL;
    int placeholder_len;

    *uuid = NULL;

    char *dbname = NULL;

    struct stat sbuf;

    char errstr[4096] = "";

    sqlite3 *db;

    int sql_r;

    const char *kismet_version_sql =
        "SELECT db_version FROM KISMET";
    unsigned int dbversion = 0;
    char *sErrMsg = NULL;

    *ret_spectrum = NULL;

    *ret_interface = cf_params_interface_new();
    *ret_spectrum = NULL;

    /* kismetdb does not support channel ops */
    (*ret_interface)->chanset = NULL;
    (*ret_interface)->channels = NULL;
    (*ret_interface)->channels_len = 0;

    if ((placeholder_len = cf_parse_interface(&placeholder, definition)) <= 0) {
        snprintf(msg, STATUS_MAX, "Unable to find kismetdb file name in definition");
        return 0;
    }

    dbname = strndup(placeholder, placeholder_len);

    if (stat(dbname, &sbuf) < 0) {
        return 0;
    }

    if (!S_ISREG(sbuf.st_mode)) {
        snprintf(msg, STATUS_MAX, "Kismetdb '%s' is not a normal file", dbname);
        return 0;
    }

    sql_r = sqlite3_open(dbname, &db);
    if (sql_r) {
        snprintf(msg, STATUS_MAX, "Unable to open kismetdb file: %s", sqlite3_errmsg(db));
        return 0;
    }

    sql_r = sqlite3_exec(db, kismet_version_sql, sqlite_version_cb, &dbversion, &sErrMsg);
    if (sql_r != SQLITE_OK || dbversion == 0) {
        snprintf(msg, STATUS_MAX, "Unable to find kismetdb version in database %s: %s", dbname, sqlite3_errmsg(db));
        sqlite3_close(db);
        return 0;
    }

    if ((placeholder_len = cf_find_flag(&placeholder, "uuid", definition)) > 0) {
        *uuid = strdup(placeholder);
    } else {
        /* Kluge a UUID out of the name */
        snprintf(errstr, 4096, "%08X-0000-0000-0000-0000%08X",
                adler32_csum((unsigned char *) "kismet_cap_pcapfile",
                    strlen("kismet_cap_kismetdb")) & 0xFFFFFFFF,
                adler32_csum((unsigned char *) dbname,
                    strlen(dbname)) & 0xFFFFFFFF);
        *uuid = strdup(errstr);
    }

    sqlite3_close(db);

    return 1;
}

int open_callback(kis_capture_handler_t *caph, uint32_t seqno, char *definition,
        char *msg, uint32_t *dlt, char **uuid,
        cf_params_interface_t **ret_interface,
        cf_params_spectrum_t **ret_spectrum) {
    char *placeholder = NULL;
    int placeholder_len;

    char *dbname = NULL;

    struct stat sbuf;

    local_pcap_t *local_pcap = (local_pcap_t *) caph->userdata;

    char errstr[4096] = "";

    /* pcapfile does not support channel ops */
    *ret_interface = cf_params_interface_new();
    *ret_spectrum = NULL;

    *uuid = NULL;
    *dlt = 0;

    int sql_r;

    const char *kismet_version_sql =
        "SELECT db_version FROM KISMET";
    char *sErrMsg = NULL;

    /* Clean up any old state */
    if (local_pcap->dbname != NULL) {
        free(local_pcap->dbname);
        local_pcap->dbname = NULL;
    }

    if (local_pcap->db != NULL) {
        sqlite3_close(local_pcap->db);
        local_pcap->db = NULL;
    }

    if ((placeholder_len = cf_parse_interface(&placeholder, definition)) <= 0) {
        /* What was not an error during probe definitely is an error during open */
        snprintf(msg, STATUS_MAX, "Unable to find PCAP file name in definition");
        return -1;
    }

    dbname = strndup(placeholder, placeholder_len);

    local_pcap->dbname = dbname;

    if (stat(dbname, &sbuf) < 0) {
        snprintf(msg, STATUS_MAX, "Could not stat() file '%s', something is very odd", dbname);
        return -1;
    }

    if (!S_ISREG(sbuf.st_mode)) {
        snprintf(msg, STATUS_MAX, "Kismetdb '%s' is not a normal file", dbname);
        return -1;
    }

    sql_r = sqlite3_open(dbname, &local_pcap->db);
    if (sql_r) {
        snprintf(msg, STATUS_MAX, "Unable to open kismetdb file: %s", sqlite3_errmsg(local_pcap->db));
        return -1;
    }

    sql_r = sqlite3_exec(local_pcap->db, kismet_version_sql, sqlite_version_cb, &(local_pcap->db_version), &sErrMsg);
    if (sql_r != SQLITE_OK || local_pcap->db_version == 0) {
        snprintf(msg, STATUS_MAX, "Unable to find kismetdb version in database %s: %s", dbname, sqlite3_errmsg(local_pcap->db));
        sqlite3_close(local_pcap->db);
        local_pcap->db = NULL;
        return -1;
    }

    if ((placeholder_len = cf_find_flag(&placeholder, "uuid", definition)) > 0) {
        *uuid = strdup(placeholder);
    } else {
        /* Kluge a UUID out of the name */
        snprintf(errstr, 4096, "%08X-0000-0000-0000-0000%08X",
                adler32_csum((unsigned char *) "kismet_cap_pcapfile",
                    strlen("kismet_cap_kismetdb")) & 0xFFFFFFFF,
                adler32_csum((unsigned char *) dbname,
                    strlen(dbname)) & 0xFFFFFFFF);
        *uuid = strdup(errstr);
    }

    /* Successful open with no channel, hop, or chanset data */
    snprintf(msg, STATUS_MAX, "Opened kismetdb '%s' for playback", dbname);

    if ((placeholder_len = cf_find_flag(&placeholder, "realtime", definition)) > 0) {
        if (strncasecmp(placeholder, "true", placeholder_len) == 0) {
            snprintf(errstr, 4096,
                    "kismetdb '%s' will replay in realtime", dbname);
            cf_send_message(caph, errstr, MSGFLAG_INFO);
            local_pcap->realtime = 1;
        }
    } else if ((placeholder_len = cf_find_flag(&placeholder, "pps", definition)) > 0) {
        unsigned int pps;
        if (sscanf(placeholder, "%u", &pps) == 1) {
            snprintf(errstr, 4096,
                    "kismetdb '%s' will throttle to %u packets per second", dbname, pps);
            cf_send_message(caph, errstr,MSGFLAG_INFO);
            local_pcap->pps_throttle = pps;
        }
    }

    return 1;
}

void kismetdb_dispatch_packet_cb(u_char *user, long ts_sec, long ts_usec,
        unsigned int dlt, uint32_t original_len, uint32_t len, const u_char *data,
        double lat, double lon, double alt, double speed, double heading) {

    kis_capture_handler_t *caph = (kis_capture_handler_t *) user;
    local_pcap_t *local_pcap = (local_pcap_t *) caph->userdata;
    int ret;
    unsigned long delay_usec = 0;

    struct cf_params_gps subgps;

    /* If we're doing 'realtime' playback, delay accordingly based on the
     * previous packet.
     *
     * Because we're in our own thread, we can block as long as we want - this
     * simulates blocking IO for capturing from hardware, too.
     */
    if (local_pcap->realtime) {
        if (local_pcap->last_ts.tv_sec == 0 && local_pcap->last_ts.tv_usec == 0) {
            delay_usec = 0;
        } else {
            /* Catch packets with inconsistent times */
            if (ts_sec < local_pcap->last_ts.tv_sec) {
                delay_usec = 0;
            } else {
                delay_usec = (ts_sec - local_pcap->last_ts.tv_sec) * 1000000L;
            }

            if (ts_usec < local_pcap->last_ts.tv_usec) {
                delay_usec += (1000000L - local_pcap->last_ts.tv_usec) + ts_usec;
            } else {
                delay_usec += ts_usec - local_pcap->last_ts.tv_usec;
            }

        }

        local_pcap->last_ts.tv_sec = ts_sec;
        local_pcap->last_ts.tv_usec = ts_usec;

        if (delay_usec != 0) {
            usleep(delay_usec);
        }
    }

    /* If we're doing 'packet per second' throttling, delay accordingly */
    if (local_pcap->pps_throttle > 0) {
        delay_usec = 1000000L / local_pcap->pps_throttle;

        if (delay_usec != 0)
            usleep(delay_usec);
    }

    /* Fill in the GPS */
    subgps.lat = lat;
    subgps.lon = lon;
    subgps.alt = alt;
    subgps.heading = heading;

    if (lat == 0 || lon == 0) {
        subgps.fix = 0;
    } else if (alt != 0) {
        subgps.fix = 3;
    } else {
        subgps.fix = 2;
    }

    subgps.ts_sec = ts_sec;
    subgps.ts_usec = ts_usec;

    subgps.gps_type = strdup("kismetdb");
    subgps.gps_name = strdup("kismetdb");

    struct timeval ts;
    ts.tv_sec = ts_sec;
    ts.tv_usec = ts_usec;

    /* Try repeatedly to send the packet; go into a thread wait state if
     * the write buffer is full & we'll be woken up as soon as it flushes
     * data out in the main select() loop */
    while (1) {
        if ((ret = cf_send_data(caph, NULL, 0,
                        NULL, &subgps,
                        ts, dlt,
                        original_len, len, (uint8_t *) data)) < 0) {
            cf_send_error(caph, 0, "unable to send DATA frame");
            cf_handler_spindown(caph);
        } else if (ret == 0) {
            /* Go into a wait for the write buffer to get flushed */
            // fprintf(stderr, "debug - pcapfile - dispatch_cb - no room in write buffer - waiting for it to have more space\n");
            cf_handler_wait_ringbuffer(caph);
            continue;
        } else {
            break;
        }
    }

    if (subgps.gps_name != NULL)
        free(subgps.gps_name);
    if (subgps.gps_type != NULL)
        free(subgps.gps_type);
}

void kismetdb_dispatch_data_cb(u_char *user, long ts_sec, long ts_usec,
        char *type, char *json,
        double lat, double lon, double alt, double speed, double heading) {

    kis_capture_handler_t *caph = (kis_capture_handler_t *) user;
    local_pcap_t *local_pcap = (local_pcap_t *) caph->userdata;
    int ret;
    unsigned long delay_usec = 0;

    struct cf_params_gps subgps;

    /* If we're doing 'realtime' playback, delay accordingly based on the
     * previous packet.
     *
     * Because we're in our own thread, we can block as long as we want - this
     * simulates blocking IO for capturing from hardware, too.
     */
    if (local_pcap->realtime) {
        if (local_pcap->last_ts.tv_sec == 0 && local_pcap->last_ts.tv_usec == 0) {
            delay_usec = 0;
        } else {
            /* Catch packets with inconsistent times */
            if (ts_sec < local_pcap->last_ts.tv_sec) {
                delay_usec = 0;
            } else {
                delay_usec = (ts_sec - local_pcap->last_ts.tv_sec) * 1000000L;
            }

            if (ts_usec < local_pcap->last_ts.tv_usec) {
                delay_usec += (1000000L - local_pcap->last_ts.tv_usec) + ts_usec;
            } else {
                delay_usec += ts_usec - local_pcap->last_ts.tv_usec;
            }

        }

        local_pcap->last_ts.tv_sec = ts_sec;
        local_pcap->last_ts.tv_usec = ts_usec;

        if (delay_usec != 0) {
            usleep(delay_usec);
        }
    }

    /* If we're doing 'packet per second' throttling, delay accordingly */
    if (local_pcap->pps_throttle > 0) {
        delay_usec = 1000000L / local_pcap->pps_throttle;

        if (delay_usec != 0)
            usleep(delay_usec);
    }

    /* Fill in the GPS */
    subgps.lat = lat;
    subgps.lon = lon;
    subgps.alt = alt;
    subgps.heading = heading;

    if (alt != 0)
        subgps.fix = 3;
    else
        subgps.fix = 2;

    subgps.ts_sec = ts_sec;
    subgps.ts_usec = ts_usec;

    subgps.gps_type = strdup("kismetdb");
    subgps.gps_name = strdup("kismetdb");

    struct timeval ts;
    ts.tv_sec = ts_sec;
    ts.tv_usec = ts_usec;

    /* Try repeatedly to send the packet; go into a thread wait state if
     * the write buffer is full & we'll be woken up as soon as it flushes
     * data out in the main select() loop */
    while (1) {
        if ((ret = cf_send_json(caph, NULL, 0,
                        NULL, &subgps,
                        ts,
                        type, json)) < 0) {
            cf_send_error(caph, 0, "unable to send DATA frame");
            cf_handler_spindown(caph);
        } else if (ret == 0) {
            /* Go into a wait for the write buffer to get flushed */
            // fprintf(stderr, "debug - pcapfile - dispatch_cb - no room in write buffer - waiting for it to have more space\n");
            cf_handler_wait_ringbuffer(caph);
            continue;
        } else {
            break;
        }
    }

    if (subgps.gps_name != NULL)
        free(subgps.gps_name);
    if (subgps.gps_type != NULL)
        free(subgps.gps_type);
}

void capture_thread(kis_capture_handler_t *caph) {
    local_pcap_t *local_pcap = (local_pcap_t *) caph->userdata;

    char errstr[4096];

    int sql_r;

    sqlite3_stmt *packet_stmt = NULL;
    const char *packet_pz = NULL;

    sqlite3_stmt *data_stmt = NULL;
    const char *data_pz = NULL;

    int packet_r, data_r;

    /* Common between both packets and data */
    double lat = 0, lon = 0, alt = 0, speed = 0, heading = 0;

    /* Last packet timestamp */
    long packet_ts_sec, packet_ts_usec;

    /* Packet data */
    unsigned int packet_len, packet_fulllen;
    const void *packet_data;
    // double packet_frequency;
    int dlt;

    /* Last data timestamp */
    long data_ts_sec, data_ts_usec;

    /* Data... data... */
    char *data_type = NULL;
    char *data_json = NULL;

    /* V4 didn't have speed, heading, etc, and used the normalized encoding */
    const char *basic_packet_sql_v4 =
        "SELECT ts_sec, ts_usec, frequency, (lat / 100000.0), (lon / 100000.0), dlt, packet FROM packets ORDER BY ts_sec, ts_usec";

    const char *basic_data_sql_v4 =
        "SELECT ts_sec, ts_usec, (lat / 100000.0), (lon / 100000.0), type, json FROM data ORDER BY ts_sec, ts_usec";


    /* V5 has full GPS, and in natural doubles */
    const char *basic_packet_sql_v5 =
        "SELECT ts_sec, ts_usec, frequency, lat, lon, alt, speed, heading, dlt, packet FROM packets ORDER BY ts_sec, ts_usec";

    const char *basic_data_sql_v5 =
        "SELECT ts_sec, ts_usec, lat, lon, alt, speed, heading, type, json FROM data ORDER BY ts_sec, ts_usec";

    /* V9 has original capture length */
    const char *basic_packet_sql_v9 =
        "SELECT ts_sec, ts_usec, frequency, lat, lon, alt, speed, heading, dlt, packet, packet_full_len FROM packets ORDER BY ts_sec, ts_usec";

    const char *basic_data_sql_v9 =
        "SELECT ts_sec, ts_usec, lat, lon, alt, speed, heading, type, json FROM data ORDER BY ts_sec, ts_usec";

    int colno;

    if (local_pcap->db_version <= 4) {
        sql_r = sqlite3_prepare(local_pcap->db, basic_packet_sql_v4, strlen(basic_packet_sql_v4), &packet_stmt, &packet_pz);
    } else if (local_pcap->db_version >= 9) {
        sql_r = sqlite3_prepare(local_pcap->db, basic_packet_sql_v9, strlen(basic_packet_sql_v9), &packet_stmt, &packet_pz);
    } else if (local_pcap->db_version >= 5) {
        sql_r = sqlite3_prepare(local_pcap->db, basic_packet_sql_v5, strlen(basic_packet_sql_v5), &packet_stmt, &packet_pz);
    }  else {
        sql_r = SQLITE_ERROR;
    }

    if (sql_r != SQLITE_OK) {
        snprintf(errstr, 4096, "KismetDB '%s' could not prepare packet query: %s",
                local_pcap->dbname, sqlite3_errmsg(local_pcap->db));
        cf_send_error(caph, 0, errstr);
        return;
    }

    if (local_pcap->db_version <= 4) {
        sql_r = sqlite3_prepare(local_pcap->db, basic_data_sql_v4, strlen(basic_data_sql_v4), &data_stmt, &data_pz);
    } else if (local_pcap->db_version >= 9) {
        sql_r = sqlite3_prepare(local_pcap->db, basic_data_sql_v5, strlen(basic_data_sql_v9), &data_stmt, &data_pz);
    } else if (local_pcap->db_version >= 5) {
        sql_r = sqlite3_prepare(local_pcap->db, basic_data_sql_v5, strlen(basic_data_sql_v5), &data_stmt, &data_pz);
    }  else {
        sql_r = SQLITE_ERROR;
    }

    if (sql_r != SQLITE_OK) {
        snprintf(errstr, 4096, "KismetDB '%s' could not prepare data query: %s",
                local_pcap->dbname, sqlite3_errmsg(local_pcap->db));
        cf_send_error(caph, 0, errstr);
        return;
    }

    sql_r = sqlite3_reset(packet_stmt);
    if (sql_r != SQLITE_OK) {
        snprintf(errstr, 4096, "KismetDB '%s' could not prepare packet query: %s",
                local_pcap->dbname, sqlite3_errmsg(local_pcap->db));
        cf_send_error(caph, 0, errstr);
        return;
    }

    sql_r = sqlite3_reset(data_stmt);
    if (sql_r != SQLITE_OK) {
        snprintf(errstr, 4096, "KismetDB '%s' could not prepare data query: %s",
                local_pcap->dbname, sqlite3_errmsg(local_pcap->db));
        cf_send_error(caph, 0, errstr);
        return;
    }

    packet_r = sqlite3_step(packet_stmt);
    data_r = sqlite3_step(data_stmt);

    while (packet_r == SQLITE_ROW || data_r == SQLITE_ROW) {
        lat = 0;
        lon = 0;
        alt = 0;
        speed = 0;
        heading = 0;

        if (packet_r == SQLITE_ROW) {
            packet_ts_sec = sqlite3_column_int64(packet_stmt, 0);
            packet_ts_usec = sqlite3_column_int64(packet_stmt, 1);
        } else {
            packet_ts_sec = 0;
            packet_ts_usec = 0;
        }

        if (data_r == SQLITE_ROW) {
            data_ts_sec = sqlite3_column_int64(data_stmt, 0);
            data_ts_usec = sqlite3_column_int64(data_stmt, 1);
        } else {
            data_ts_sec = 0;
            data_ts_usec = 0;
        }

        /* Merge the timelines of the two tables; if the packet comes first process it,
         * otherwise process the data, and repeat */
        if (data_ts_sec == 0 || packet_ts_sec < data_ts_sec ||
                (packet_ts_sec == data_ts_sec && packet_ts_usec < data_ts_usec)) {
            colno = 2;

            // packet_frequency = sqlite3_column_double(packet_stmt, colno++);

            lat = sqlite3_column_double(packet_stmt, colno++);
            lon = sqlite3_column_double(packet_stmt, colno++);

            if (local_pcap->db_version >= 5) {
                alt = sqlite3_column_double(packet_stmt, colno++);
                speed = sqlite3_column_double(packet_stmt, colno++);
                heading = sqlite3_column_double(packet_stmt, colno++);
            }

            dlt = sqlite3_column_int(packet_stmt, colno++);

            packet_len = sqlite3_column_bytes(packet_stmt, colno);
            packet_data = sqlite3_column_blob(packet_stmt, colno++);
            packet_fulllen = sqlite3_column_int64(packet_stmt, colno++);

            kismetdb_dispatch_packet_cb((u_char *) caph, packet_ts_sec, packet_ts_usec, dlt,
                    packet_fulllen, packet_len, (const u_char *) packet_data,
                    lat, lon, alt, speed, heading);

            packet_r = sqlite3_step(packet_stmt);
        } else {
            colno = 2;

            lat = sqlite3_column_double(data_stmt, colno++);
            lon = sqlite3_column_double(data_stmt, colno++);

            if (local_pcap->db_version >= 5) {
                alt = sqlite3_column_double(data_stmt, colno++);
                speed = sqlite3_column_double(data_stmt, colno++);
                heading = sqlite3_column_double(data_stmt, colno++);
            }

            data_type = strdup((const char *) sqlite3_column_text(data_stmt, colno++));
            data_json = strdup((const char *) sqlite3_column_text(data_stmt, colno++));

            kismetdb_dispatch_data_cb((u_char *) caph, packet_ts_sec, packet_ts_usec,
                    data_type, data_json,
                    lat, lon, alt, speed, heading);

            free(data_type);
            free(data_json);

            data_r = sqlite3_step(data_stmt);
        }
    }

    snprintf(errstr, 4096, "KismetDB '%s' closed, all packets and data processed.",
            local_pcap->dbname);
    cf_send_message(caph, errstr, MSGFLAG_INFO);

    /* Instead of dying, spin forever in a sleep loop */
    while (1) {
        sleep(1);
    }

    /* cf_handler_spindown(caph); */
}

int main(int argc, char *argv[]) {
    local_pcap_t local_pcap = {
        .db = NULL,
        .dbname = NULL,
        .sub_uuid = NULL,
        .sub_dlt = 0,
        .realtime = 0,
        .last_ts.tv_sec = 0,
        .last_ts.tv_usec = 0,
        .pps_throttle = 0,
    };

#if 0
    /* Remap stderr so we can log debugging to a file */
    FILE *sterr;
    sterr = fopen("/tmp/capture_pcapfile.stderr", "a");
    dup2(fileno(sterr), STDERR_FILENO);
#endif

    /* fprintf(stderr, "CAPTURE_PCAPFILE launched on pid %d\n", getpid()); */

    kis_capture_handler_t *caph = cf_handler_init("kismetdb");

    if (caph == NULL) {
        fprintf(stderr, "FATAL: Could not allocate basic handler data, your system "
                "is very low on RAM or something is wrong.\n");
        return -1;
    }

    /* Set the local data ptr */
    cf_handler_set_userdata(caph, &local_pcap);

    /* Set the callback for opening a pcapfile */
    cf_handler_set_open_cb(caph, open_callback);

    /* Set the callback for probing an interface */
    cf_handler_set_probe_cb(caph, probe_callback);

    /* Set the capture thread */
    cf_handler_set_capture_cb(caph, capture_thread);

    if (cf_handler_parse_opts(caph, argc, argv) < 1) {
        cf_print_help(caph, argv[0]);
        return -1;
    }

    /* Support remote capture by launching the remote loop */
    cf_handler_remote_capture(caph);

    cf_handler_loop(caph);

    cf_handler_free(caph);

    return 1;
}

