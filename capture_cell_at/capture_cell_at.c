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

    Cell modem capture source for Kismet.

    Communicates with cellular modems via AT commands over serial ports,
    parses serving cell, neighbor cell, and network scan responses, and
    forwards cell observations as JSON to Kismet via cf_send_json()
    (type="Cell"/"CellModem"). It also emits every raw AT exchange into the
    kismetdb `data` table as type="RawAT", so a Kismet drive's .kismet carries
    the full raw AT transcript inside it, read back by kismetdb_to_cellndjson.

    It also self-anchors its clock: at capture start,
    end and every clock_anchor_sec= seconds it issues AT+CCLK? and emits a
    type="ClockAnchor" row pairing the host clock with the modem RTC, so an
    AT-only drive (no DIAG ts64, no GNSS 0x1476) can still detect host<->modem
    clock skew from a single transport. AT+CCLK? is 3GPP TS 27.007, common to
    every vendor below, so the anchor is issued once in the shared poll loop
    rather than per driver. (The raw AT+CCLK? exchange also flows into RawAT
    via the normal seam -- that raw reading is the primary dataset product;
    the ClockAnchor row is the structured layer.)

    Supported vendors and command references:

    Quectel RM500Q series (5G NR + LTE):
      "RG50xQ&RM5xxQ Series AT Commands Manual" V1.2 (2021-08-09)
      Quectel_RG50xQ_RM5xxQ_Series_AT_Commands_Manual_V1.2.pdf
      Commands: AT+QENG="servingcell", AT+QENG="neighbourcell", AT+QSCAN=3,1

    Quectel RM520N-GL series (5G NR + LTE, SDX62):
      "RG520N&RG525F&RG5x0F&RM5x0N Series AT Commands Manual" V1.1 (2025-02-20)
      Quectel_RG520NRG525FRG5x0FRM5x0N_Series_AT_Commands_Manual_V1.1.pdf
      Commands: AT+QENG="servingcell", AT+QENG="neighbourcell", AT+QSCAN=3,1
      (band config via AT+QNWPREFCFG; AT+QCFG="band" returns ERROR here)

    Quectel EG25-G series (LTE Cat 4):
      "EC2x&EG2x&EG9x&EM05 Series AT Commands Manual" V2.1 (2025-03-21)
      Quectel_EC2xEG2xEG9xEM05_Series_AT_Commands_Manual_V2.1.pdf
      Commands: AT+QENG="servingcell", AT+QENG="neighbourcell"

    Telit LM960 (LTE Cat 18):
      "LM960 Series AT Command Reference Guide" Rev.8 (2022-03-21)
      Telit_LM960_Series_AT_Command_Reference_Guide_r8.pdf
      Commands: AT#RFSTS, AT#SERVINFO, AT#MONI, AT#CSURVC

    Sierra Wireless EM9190 (5G NR + LTE):
      "EM9 Series AT Command Reference" Rev.14, 2026-01-01
      41113480 EM9 AT Command Reference r14.pdf
      Commands: AT!GSTATUS?, AT!NRINFO?, AT!NRPCI?, AT!LTEINFO?

    Orbic RC400L / Qualcomm MDM9607 (LTE Cat 4):
      Huawei-style + Qualcomm $QC commands on MDM9607 reference firmware.
      Discovered via binary analysis of atfwd_daemon.
      Commands: AT^SCELLINFO (serving cell), AT$QCRSRP? (multi-cell passive scan)

    Common 3GPP commands (all vendors, per 3GPP TS 27.007):
      AT, ATE0, AT+CGMI, AT+CGMM, AT+CGMR, AT+CGSN, AT+COPS=?
*/

#if defined(__linux__) && !defined(_GNU_SOURCE)
#define _GNU_SOURCE   /* strcasestr */
#endif

#include "../config.h"

#include <ctype.h>
#include <dirent.h>
#include <errno.h>
#include <fcntl.h>
#include <glob.h>
#include <limits.h>
#include <pthread.h>
#include <stdio.h>
#include <stdlib.h>
#include <stdbool.h>
#include <string.h>
#include <strings.h>
#include <sys/time.h>
#include <termios.h>
#include <time.h>
#include <unistd.h>

#include "../capture_framework.h"
#include "cellat_options.h"
#include "cellat_stats.h"
#include "cellat_optset.h"
#include "cellat_lock.h"
#include "cellat_gnss.h"
/* Shared with celldiag: one classifier owns both non-USB naming conventions, so
 * the DIAG source and the AT source can never disagree about a node. */
/* The non-USB AT-node admission decision. cellat_portscan.c is what
 * reaches the shared diag_wwanport classifier -- this TU does not name it
 * directly, so the classifier has exactly one call site in this binary. */
#include "cellat_portscan.h"
#include "atlog.h"
/* Shared with celldiag, for the same reason as the classifier above: both scans
 * write "AT" to every candidate tty, and both must release a port that never
 * took it without waiting out its 30 s closing_wait. */
#include "../capture_cell_diag/diag_probeclose.h"
/* The ModemIdentity record, shared with celldiag: one implementation of
 * the AT value extraction, the label and the JSON, so the two sources of one
 * modem describe it identically in the .kismet. */
#include "../capture_cell_diag/diag_modemident.h"
#include "../capture_cell_diag/cell_log.h"
#include "../capture_cell_diag/diag_identvouch.h"
#include "clockanchor.h"
#include "../capture_cell_diag/cell_safefile.h"
#include "../capture_cell_diag/cell_usbport.h"
#include "../capture_cell_diag/diag_portadmit.h"
#include <sys/wait.h>

/* Maximum AT response size (128 KB should handle even AT+COPS=? floods) */
#define AT_RESP_MAX         (128 * 1024)

/* Maximum single JSON observation */
#define JSON_BUF_MAX        4096

/* Maximum number of observations from a single AT response */
#define MAX_OBS_PER_RESP    64

/* Status/error message buffer */
#define ERRBUF_MAX          STATUS_MAX

/* -----------------------------------------------------------------------
 * Vendor identification
 * ----------------------------------------------------------------------- */

enum modem_vendor {
    VENDOR_UNKNOWN = 0,
    VENDOR_QUECTEL,
    VENDOR_TELIT,
    VENDOR_SIERRA,
    VENDOR_ORBIC,
    VENDOR_SIMCOM,
};

/* -----------------------------------------------------------------------
 * Local state for the capture source
 * ----------------------------------------------------------------------- */

typedef struct {
    int serial_fd;
    char *device_path;
    char *modem_imei;
    char *modem_firmware;
    char *modem_model;
    char *name;

    enum modem_vendor vendor;

    /* Scan intervals in milliseconds */
    unsigned long serving_interval_ms;
    unsigned long neighbor_interval_ms;
    unsigned long fullscan_interval_ms;

    /* Last-run timestamps (ms since epoch) */
    unsigned long serving_last_ms;
    unsigned long neighbor_last_ms;
    unsigned long fullscan_last_ms;

    /* Feature flags detected from modem */
    int has_qeng;
    int has_qscan;
    int has_rfsts;    /* Telit AT#RFSTS */
    int has_servinfo; /* Telit AT#SERVINFO */
    int has_moni;     /* Telit AT#MONI (cell monitor) */
    int has_csurvc;   /* Telit AT#CSURVC (network survey) */
    int has_gstatus;  /* Sierra AT!GSTATUS? */
    int has_lteinfo;  /* Sierra AT!LTEINFO? */
    int has_nrinfo;   /* Sierra AT!NRINFO? */
    int has_scellinfo; /* Orbic/QC AT^SCELLINFO */
    int has_qcrsrp;    /* Orbic/QC AT$QCRSRP? */
    int has_cpsi;      /* SIMCom AT+CPSI? */

    /* The last unrecognised +QENG neighbour RAT token reported for this
     * modem. A token normalize_rat() does not know is a firmware surprise
     * worth surfacing ONCE -- the neighbour poll runs every few seconds, so
     * reporting it per-poll would bury the signal under its own repetition.
     * Empty means nothing surprising has been seen yet. */
    char qeng_unknown_rat[24];

    /* Cached serving cell identity from AT#RFSTS / AT!GSTATUS.
     * Used to:
     *  - Supplement AT#RFSTS with PCI from AT#SERVINFO
     *  - Fix AT#CSURVC TAC=0 by substituting real TAC */
    unsigned long cached_tac;
    unsigned long cached_cell_id;
    long cached_pci;
    int cached_valid;

    /* Scan profile (strategy=), from the table in cellat_options.c.
     * Never NULL once open_callback has parsed the definition. */
    const cellat_strategy_t *strategy;

    /* Debug mode */
    int debug;

    /* enabled=false: registered but idle -- the cellat half of the cell
     * sources' lifecycle switch. No port scan, no AT I/O, no serial fd. */
    int disabled;

    /* Back-pointer to the capture handler, set once open_callback runs.
     * The AT-exchange seam at_command_t() carries only `local`, but the RawAT
     * in-db emit needs the handler for cf_send_json(). NULL until the capture
     * session opens, which is exactly the right gate: RawAT rows are emitted
     * only within a capture (never during a transient probe exec), so they land
     * in the session's .kismet and nowhere else. */
    kis_capture_handler_t *caph;

    /* The modem's own identity: AT+CGMI / +CGMM / +CGMR / +CGSN as read
     * at open, verbatim. Sent once per capture as a ModemIdentity record and
     * used as the source's hardware label. Distinct from modem_model, which
     * stays the per-vendor display string the cellat_stats `model` field
     * already carries (for Quectel it is derived from
     * the FIRMWARE, so it cannot stand in for the model). Empty imei = unset. */
    modemident_t ident;

    /* RawAT: raw AT exchanges emitted into the kismetdb `data` table as
     * type="RawAT", the emit-side counterpart of kismetdb_to_cellndjson.
     * Whenever a capture is open every exchange is sent to the server, which
     * persists it iff kismetdb logging is on. */
    uint64_t rawat_records;   /* RawAT rows successfully handed to cf_send_json */
    uint64_t rawat_dropped;   /* RawAT send/format/alloc failures (counted, not per-event logged) */
    int      rawat_oversize_said;  /* the one bus note is out */

    /* Host<->modem-RTC clock anchor (AT+CCLK?), emitted as type="ClockAnchor"
     * rows into the kismetdb so one transport alone can detect clock skew.
     * A ClockAnchor fires at capture START, at END (in the capture-thread
     * teardown), and every clock_anchor_interval_ms in between. The AT+CCLK?
     * exchange itself rides the at_command_t() seam, so the raw host-timestamped
     * reading also lands in the RawAT kismetdb row -- that
     * raw exchange is the primary dataset deliverable; the ClockAnchor row is the
     * structured metadata layer on top (see clockanchor.h). CCLK works on every
     * vendor driver (3GPP TS 27.007), so it is issued once in the shared poll loop
     * below the vendor dispatch rather than duplicated per driver. */
    unsigned long clock_anchor_interval_ms;  /* 0 = periodic off; START+END still fire */
    unsigned long clock_anchor_last_ms;      /* last periodic emit (ms since epoch) */
    uint64_t      clock_anchor_seq;          /* monotonic per-source anchor counter */
    char         *source_uuid;               /* composed datasource uuid -> ClockAnchor source_name */

    /* The cellat_stats readback (see cellat_stats.h). */
    uint64_t obs_total;           /* observations SENT to Kismet (not merely parsed) */
    time_t   last_obs_epoch;      /* 0 = none yet */
    uint64_t anchor_sent;         /* ClockAnchor rows sent */
    time_t   anchor_last_epoch;   /* 0 = none yet */
    time_t   stats_last;          /* last cellat_stats line; 0 = never */
    time_t   rate_mark_time;      /* obs_per_sec window start; 0 = unset */
    uint64_t rate_mark_obs;       /* obs_total at rate_mark_time */
    time_t   fullscan_started;    /* nonzero while a blocking full scan runs */

    /* Runtime settings arrive on the framework's command thread
     * (chancontrol), while everything they change is read by the capture
     * thread. optset_lock guards the hand-off:
     *   - strategy= and clock_anchor_sec= are QUEUED here and applied by the
     *     capture thread at the top of its next loop, because they rewrite
     *     capture-thread state (intervals, last-run stamps). */
    pthread_mutex_t optset_lock;
    const cellat_strategy_t *pending_strategy;   /* NULL = nothing queued */
    int           pending_anchor_set;
    unsigned long pending_anchor_ms;
    int           stats_now;         /* emit a stats line at the next loop top */

    /* Band/RAT lock as the source's channels (cellat_lock.h).
     * Probed at open. lock_orig is the settings AS FOUND -- or, after a crash,
     * as the state file recorded them, because the modem may still be locked.
     * lock_cur is what was last written. A channel arrives on the command
     * thread and is QUEUED (pending_lock, under optset_lock); the capture
     * thread, which owns the port, writes it. */
    int           lock_capable;
    cellat_lock_settings_t lock_orig;
    cellat_lock_settings_t lock_cur;
    char          lock_channel[CELLAT_LOCK_SET_MAX];    /* in force; "" = not capable */
    char          lock_error[384];                      /* last failure; "" = none */
    char          pending_lock[CELLAT_LOCK_SET_MAX];    /* "" = nothing queued */
    char          lock_state_path[1024];
    int           lock_state_written;   /* the state file holds lock_orig */
    int           lock_enabled;         /* bandlock=true: lock channels offered */

    /* The last at_command_t_ex exchange, as its RawAT row names it --
     * ts_mono_ns (the row's join key) and the tx/rx instants. All 0 when no
     * record was built for it (neither sink live). Read back on the same
     * thread right after the call, by the observation tagging (obs_mark) and
     * the ClockAnchor bracket. */
    uint64_t      last_x_ts_mono_ns;
    uint64_t      last_x_tx_done_ns;
    uint64_t      last_x_first_rx_ns;
    uint64_t      last_x_rx_done_ns;

    /* gps=: the modem's GNSS, read by its own thread from the NMEA port
     * (cellat_gnss.h). The thread touches only gnss_fd, the counters and
     * caph's send ring, never the AT port. */
    int           gnss_wanted;
    char          gnss_port_opt[512];     /* gpsport=; "" = find it */
    char          gnss_port[512];
    int           gnss_fd;
    int           gnss_we_enabled;        /* AT+QGPS=1 was ours: AT+QGPSEND at close */
    char          gnss_outport_orig[16];  /* outport we changed from; "" = untouched */
    pthread_t     gnss_thread;
    int           gnss_thread_live;
    int           gnss_stop;              /* __atomic: set by the capture thread */
} local_cell_t;

/* -----------------------------------------------------------------------
 * Time helpers
 * ----------------------------------------------------------------------- */

static unsigned long now_ms(void) {
    struct timeval tv;
    gettimeofday(&tv, NULL);
    return (unsigned long)(tv.tv_sec) * 1000 + (unsigned long)(tv.tv_usec) / 1000;
}

/* Host CLOCK_MONOTONIC in nanoseconds -- the RawAT record's ordering axis.
 * Monotonic, not wall-clock, so an NTP step during a drive cannot
 * reorder exchanges within the AT capture (and, as a bonus, keeps them
 * alignable to a concurrent DIAG capture should one exist). */
static uint64_t now_mono_ns(void) {
    struct timespec ts;
    clock_gettime(CLOCK_MONOTONIC, &ts);
    return (uint64_t)ts.tv_sec * 1000000000ULL + (uint64_t)ts.tv_nsec;
}

/* Wall-clock UTC as ISO 8601 with microseconds from a caller-supplied timeval.
 * The RawAT emit stamps the record's ts_utc and the cf_send_json packet
 * timestamp from the same instant. Matches
 * Python's isoformat(timespec="us"), which the correlator uses. */
static void atlog_iso8601_from_tv(char *out, size_t outsz, const struct timeval *tv) {
    struct tm tm;
    gmtime_r(&tv->tv_sec, &tm);
    snprintf(out, outsz, "%04d-%02d-%02dT%02d:%02d:%02d.%06ldZ",
             tm.tm_year + 1900, tm.tm_mon + 1, tm.tm_mday,
             tm.tm_hour, tm.tm_min, tm.tm_sec, (long)tv->tv_usec);
}

/* Build one AT-exchange JSONL record (atlog schema), returning a malloc'd
 * NUL-terminated string the caller frees, or NULL on format/alloc failure.
 * t0_mono is the monotonic-ns instant captured just BEFORE the exchange (the
 * record's ts_mono_ns); rc is at_command_log's return (<0 = no usable response,
 * so the response text is unreliable and recorded empty with a non-null err).
 * tx_done/first_rx/rx_done are the exchange's inner instants at_command_log
 * reported (0 = never reached, recorded as null).
 */
static char *atlog_build_record(uint64_t t0_mono, const char *ts_utc,
                                const char *cmd, const char *response, int rc,
                                uint64_t tx_done, uint64_t first_rx,
                                uint64_t rx_done) {
    uint64_t t1 = now_mono_ns();
    double dur_ms = (t1 > t0_mono) ? (double)(t1 - t0_mono) / 1e6 : 0.0;
    const char *err = (rc < 0) ? "no response (timeout or I/O error)" : NULL;
    const char *resp = (rc < 0) ? "" : (response ? response : "");

    size_t cap = strlen(resp) * 6 + 4096;
    char *rec = malloc(cap);
    if (rec == NULL)
        return NULL;
    if (atlog_format_record(rec, cap, t0_mono, ts_utc, cmd, resp,
                            dur_ms, err, tx_done, first_rx, rx_done) != 0) {
        free(rec);
        return NULL;
    }
    return rec;
}

/* The largest JSON payload a cellat `data` row (RawAT) may carry. Kismet
 * refuses any IPC frame over MAX_EXTERNAL_FRAME_LEN (16384, kis_external.h);
 * 4 KiB is left for the v3 header, the msgpack map, the type string and any
 * fixed-GPS block, the same budget as DIAG_RAWPKT_PAYLOAD_MAX. */
#define CELLAT_ROW_JSON_MAX 12288

/* A `data` row the server would refuse. Kismet errors the whole
 * SOURCE over a frame past MAX_EXTERNAL_FRAME_LEN and reopens it into the same
 * row, so an oversize row is dropped here instead -- the caller counts it --
 * and said once per kind, with its size, so the drop is never silent. */
static int cellat_row_oversize(local_cell_t *local, const char *type,
                               const char *counter, size_t len, int *said) {
    if (len <= CELLAT_ROW_JSON_MAX)
        return 0;
    if (!*said && local->caph != NULL) {
        char msg[ERRBUF_MAX];
        *said = 1;
        snprintf(msg, sizeof(msg),
                 "%s: dropped a %s row of %zu bytes, over the %d-byte limit of "
                 "one Kismet server frame (sending it would error the source); "
                 "counted in %s, and later ones are counted only", local->name,
                 type, len, CELLAT_ROW_JSON_MAX, counter);
        cf_send_message(local->caph, msg, MSGFLAG_ERROR);
    }
    return 1;
}

/* Emit a pre-built record into the kismetdb `data` table as type="RawAT".
 * Best-effort: a send failure degrades to a
 * counted drop, never a wedged or errored-out capture, because raw AT is a tee
 * and not the datasource's primary product. `tv` is the exchange's wall-clock
 * instant (same one the record's ts_utc was formatted from), used as the
 * cf_send_json packet timestamp. The ringbuffer-full (r==0) handling mirrors the
 * CellModem observation path: drain once and move on -- the record for THIS
 * exchange is dropped rather than blocking the AT poll loop. */
static void rawat_emit(local_cell_t *local, struct timeval tv, const char *rec) {
    if (local->caph == NULL)
        return;
    if (cellat_row_oversize(local, "RawAT", "rawat_dropped", strlen(rec),
                            &local->rawat_oversize_said)) {
        local->rawat_dropped++;
        return;
    }
    int r = cf_send_json(local->caph, NULL, 0, NULL, NULL, tv, "RawAT", rec);
    if (r < 0) {
        local->rawat_dropped++;
    } else if (r == 0) {
        cf_handler_wait_ringbuffer(local->caph);
        local->rawat_dropped++;
    } else {
        local->rawat_records++;
    }
}

/* A CellLog row (cell_log.h); best-effort, like RawAT. */
static void cellat_log_send(local_cell_t *local, const struct timeval *tv,
                            const char *rec) {
    if (local->caph == NULL)
        return;
    if (cf_send_json(local->caph, NULL, 0, NULL, NULL, *tv, CELL_LOG_TYPE, rec) == 0) {
        cf_handler_wait_ringbuffer(local->caph);
        (void)cf_send_json(local->caph, NULL, 0, NULL, NULL, *tv, CELL_LOG_TYPE, rec);
    }
}

static void cellat_log_entry(local_cell_t *local, const char *dir,
                             const char *text, size_t textlen) {
    struct timeval tv;
    char *rec;

    if (local->caph == NULL || (rec = malloc(CELL_LOG_ROW_MAX)) == NULL)
        return;
    gettimeofday(&tv, NULL);
    if (cell_log_entry_json(rec, CELL_LOG_ROW_MAX, "cellat", &tv, now_mono_ns(),
                            dir, text, textlen) == 0)
        cellat_log_send(local, &tv, rec);
    free(rec);
}

/* The AT-over-serial core -- serial_open, serial_close,
 * at_command_log, at_command -- lives in at_serial.inc so the standalone
 * cellat_serial_probe binary and the test_at_serial selftest share the exact
 * code this capture binary runs (the AT-side analogue of the DIAG side's
 * separately-compiled diag_capture.c core behind celldiag_probe). The
 * functions stay `static` via textual include -- no external linkage, no
 * symbol-collision risk against the Kismet framework library. */
#include "at_serial.inc"

/* The exchange seam for the capture thread and open callback, where
 * local_cell_t is available; each exchange becomes a RawAT row.
 * `info_idle_ms` > 0 selects at_serial.inc's info form. */
static int at_command_t_ex(local_cell_t *local, const char *cmd, char *resp_buf,
                           size_t resp_max, int timeout_ms, int info_idle_ms) {
    uint64_t t0 = 0;
    char ts_utc[40];
    struct timeval tv0;
    at_timing_t tm;

    memset(&tm, 0, sizeof(tm));

    /* The RawAT record is built only while a capture is open.  Stamp the
     * start on both clocks before the (possibly multi-second) command so
     * ts_mono_ns marks when the command left the host; when the response
     * landed is at_command_log's to report, in `tm`. */
    int want_record = (local->caph != NULL);
    if (want_record) {
        gettimeofday(&tv0, NULL);
        t0 = now_mono_ns();
        atlog_iso8601_from_tv(ts_utc, sizeof(ts_utc), &tv0);
    }

    int rc = at_command_log_ex(local->serial_fd, cmd, resp_buf, resp_max,
                               timeout_ms, want_record ? &tm : NULL, info_idle_ms);

    /* This exchange as its RawAT row will name it (tm stays zero when
     * no record is built). */
    local->last_x_ts_mono_ns  = want_record ? t0 : 0;
    local->last_x_tx_done_ns  = tm.tx_done_ns;
    local->last_x_first_rx_ns = tm.first_rx_ns;
    local->last_x_rx_done_ns  = tm.rx_done_ns;

    if (want_record) {
        char *rec = atlog_build_record(t0, ts_utc, cmd, resp_buf, rc,
                                       tm.tx_done_ns, tm.first_rx_ns,
                                       tm.rx_done_ns);
        if (rec == NULL) {
            local->rawat_dropped++;
        } else {
            rawat_emit(local, tv0, rec);
            free(rec);
        }
    }

    /* debug=true: what the exchange threw away, which its RawAT row
     * cannot show. */
    if (local->debug && want_record) {
        if (tm.late_ok_dropped) {
            char note[128 + 64];
            snprintf(note, sizeof(note),
                     "OK before the reply to %.120s: the previous exchange's, dropped",
                     cmd);
            cellat_log_entry(local, "RX-LATE", note, strlen(note));
        }
        if (tm.trail_len > 0)
            cellat_log_entry(local, "RX-DROP", tm.trail,
                             tm.trail_len < sizeof(tm.trail) ? tm.trail_len :
                                                               sizeof(tm.trail));
    }

    return rc;
}

static int at_command_t(local_cell_t *local, const char *cmd, char *resp_buf,
                        size_t resp_max, int timeout_ms) {
    return at_command_t_ex(local, cmd, resp_buf, resp_max, timeout_ms, 0);
}

/* A single-line info read on the source's own port, in the info form:
 * a modem that never terminates info replies (the T99W175) is not charged the
 * whole deadline. Its RawAT row then carries rx_done_ns null -- no terminal
 * line was read, which is what happened. */
static int at_info_command_t(local_cell_t *local, const char *cmd,
                             char *resp_buf, size_t resp_max, int timeout_ms) {
    return at_command_t_ex(local, cmd, resp_buf, resp_max, timeout_ms,
                           MODEMIDENT_INFO_IDLE_MS);
}

/* Which exchange each parsed observation came from -- the two stamps its
 * prov block carries (inject_prov_x). Tagged at PARSE time, not at emit time:
 * Telit's neighbour path sends AT#MONI=0 after its parse, so "the last
 * exchange" at emit would name the wrong command, and AT#MONI=1 / =2 each
 * contribute their own observations. */
typedef struct {
    uint64_t at_ts_mono_ns;
    uint64_t rx_done_ns;
} obs_exchange_t;

/* Tag observations [from, to) with the exchange at_command_t_ex just ran. */
static void obs_mark(const local_cell_t *local, obs_exchange_t *ref,
                     int from, int to) {
    for (int i = from; i < to; i++) {
        ref[i].at_ts_mono_ns = local->last_x_ts_mono_ns;
        ref[i].rx_done_ns    = local->last_x_rx_done_ns;
    }
}

/* True when this modem exposes no vendor engineering command --
 * neither a serving/neighbour one (QENG/RFSTS/SERVINFO/GSTATUS/SCELLINFO/CPSI)
 * nor a full-scan one (QSCAN/CSURVC). Such a modem falls back to the standard
 * 3GPP reads: parse_generic_serving() for the serving poll, AT+COPS=? for the
 * full scan. A modem with a vendor command but no full-scan command (Sierra,
 * Orbic, SIMCom) is NOT generic -- it keeps its vendor serving poll and simply
 * runs no disruptive network scan. */
static int cellat_no_vendor_cmd(const local_cell_t *local) {
    return !local->has_qeng && !local->has_rfsts && !local->has_servinfo &&
           !local->has_gstatus && !local->has_scellinfo && !local->has_cpsi &&
           !local->has_qscan && !local->has_csurvc;
}

/* Issue AT+CCLK? and emit a ClockAnchor row pairing the host clock with
 * the modem RTC, so a single transport can detect clock skew.
 *
 * `edge` is "start" | "periodic" | "end". Two products come out of one call:
 *   1. The raw AT+CCLK? exchange, via at_command_t()'s seam -> the RawAT
 *      kismetdb row. This host-timestamped raw reading is the
 *      primary dataset product and happens for every edge.
 *   2. This structured ClockAnchor `data` row (schema clock-anchor/1), the same
 *      shape the DIAG transport emits, so downstream skew analysis is
 *      transport-uniform.
 *
 * Best-effort and non-fatal: a modem that ERRORs on +CCLK, or returns no quoted
 * value, still leaves the raw exchange in the dataset and simply emits no anchor
 * row. The host clock is stamped as near the CCLK round-trip as possible (the
 * anchor's value is the host<->modem pair; +CCLK resolution is whole seconds on
 * every firmware seen, so the host stamp carries the fine cadence). */
/* Graceful-close grace, advertised to the server: see main(). */
#define CELLAT_CLOSE_GRACE_MS 8000

static void clock_anchor_emit(local_cell_t *local, const char *edge) {
    char resp[512];
    char cclk[64];
    char rec[768];
    struct timeval tv;
    char host_utc[40];

    if (local->serial_fd < 0)
        return;

    gettimeofday(&tv, NULL);
    uint64_t host_mono = now_mono_ns();
    atlog_iso8601_from_tv(host_utc, sizeof(host_utc), &tv);

    /* The raw exchange goes to RawAT here regardless of what we parse. */
    int n = at_command_t(local, "AT+CCLK?", resp, sizeof(resp), 3000);
    if (n <= 0 || cclk_extract(resp, cclk, sizeof(cclk)) != 0)
        return;

    /* Structured ClockAnchor row needs the capture handler (NULL during a probe
     * exec -- the same gate RawAT uses). */
    if (local->caph == NULL)
        return;

    /* The modem read its RTC after the command left the host (tx_done)
     * and before the first byte of its answer (first_rx) -- the exchange's own
     * instants. Stamp the midpoint of that window and carry its width as
     * host_rtt_ns, the DIAG anchor's shape. The pre-send stamp above
     * stays the reference pair and the fallback when no window was measured. */
    const char *source = local->source_uuid ? local->source_uuid :
                             (local->name ? local->name : "");
    uint64_t seq = local->clock_anchor_seq++;
    int rc;
    if (local->last_x_tx_done_ns && local->last_x_first_rx_ns) {
        struct timeval tv_mid;
        uint64_t mono_mid, rtt;
        clockanchor_bracket(&tv, host_mono, local->last_x_tx_done_ns,
                            local->last_x_first_rx_ns, &tv_mid, &mono_mid, &rtt);
        atlog_iso8601_from_tv(host_utc, sizeof(host_utc), &tv_mid);
        rc = clockanchor_format_record_rtt(rec, sizeof(rec), "at", source, seq,
                                           edge, host_utc, mono_mid,
                                           "modem_rtc_cclk", cclk, rtt);
    } else {
        rc = clockanchor_format_record(rec, sizeof(rec), "at", source, seq,
                                       edge, host_utc, host_mono,
                                       "modem_rtc_cclk", cclk);
    }
    if (rc != 0)
        return;

    int r = cf_send_json(local->caph, NULL, 0, NULL, NULL, tv, "ClockAnchor", rec);
    if (r == 0)
        cf_handler_wait_ringbuffer(local->caph);
    else if (r > 0) {
        local->anchor_sent++;
        local->anchor_last_epoch = tv.tv_sec;
    }
}

/* Send one cellat_stats line describing the source as of now.
 * `state` is "surveying", "full_scan" or "disabled".
 *
 * Best-effort like RawAT: a full ring drops this line rather than stalling the
 * AT poll loop, and the next one replaces it anyway. Routed as its own JSON
 * type so kis_datasource_cell_at intercepts it -- phy_cell must never build a
 * device from a stats object. */
static void cellat_stats_emit(local_cell_t *local, const char *state) {
    cellat_stats_t s;
    char vocab[512];
    char json[2048];
    struct timeval tv;

    if (local->caph == NULL)
        return;

    gettimeofday(&tv, NULL);
    time_t now = tv.tv_sec;

    cellat_stats_init(&s);
    s.state = state;
    s.stats_epoch = now;
    if (local->strategy != NULL) {
        s.strategy = local->strategy->name;
        s.strategy_label = local->strategy->label;
    }
    if (cellat_stats_strategies(vocab, sizeof(vocab)) > 0)
        s.strategies = vocab;

    if (strcmp(state, "disabled") != 0) {
        s.serving_interval_ms = local->serving_interval_ms;
        s.neighbor_interval_ms = local->neighbor_interval_ms;
        s.fullscan_interval_ms = local->fullscan_interval_ms;
        s.fullscan_capable = (local->has_qscan || local->has_csurvc) ? 1 : 0;
        s.fullscan_started_epoch = local->fullscan_started;

        s.obs_total = local->obs_total;
        s.last_obs_epoch = local->last_obs_epoch;
        /* Throughput over the window since the last line that measured one.
         * A line sent within a second of the previous one (a state change
         * right after a periodic tick) cannot measure a rate, so it OMITS it
         * and leaves the window open, rather than reporting 0/sec. */
        if (local->rate_mark_time == 0) {
            local->rate_mark_time = now;
            local->rate_mark_obs = local->obs_total;
        } else if (now > local->rate_mark_time) {
            s.obs_per_sec = (double)(local->obs_total - local->rate_mark_obs) /
                            (double)(now - local->rate_mark_time);
            local->rate_mark_time = now;
            local->rate_mark_obs = local->obs_total;
        }

        s.rawat_records = local->rawat_records;
        s.rawat_dropped = local->rawat_dropped;
        s.anchor_count = local->anchor_sent;
        s.anchor_last_epoch = local->anchor_last_epoch;
        s.at_port = local->device_path;
        s.model = local->modem_model;
        s.firmware = local->modem_firmware;
        /* The lock in force, read by the capture thread's own state */
        s.lock_valid = 1;
        s.lock_capable = local->lock_capable;
        if (local->lock_capable)
            s.lock_channel = local->lock_channel;
        if (local->lock_error[0])
            s.lock_error = local->lock_error;
    }

    local->stats_last = now;
    if (cellat_stats_format_json(&s, json, sizeof(json)) <= 0)
        return;
    int r = cf_send_json(local->caph, NULL, 0, NULL, NULL, tv, "cellat_stats", json);
    if (r == 0)
        cf_handler_wait_ringbuffer(local->caph);
}

/* -----------------------------------------------------------------------
 * AT response parsers — produce JSON strings for each cell observation
 *
 * Each parser writes one JSON object per observation into json_out[],
 * returning the number of observations found.
 * ----------------------------------------------------------------------- */

/* Pure decode core: parse helpers, build_cell_json, inject_prov and the
 * two AT+QENG parsers. Shared with test_cellat_qeng. */
#include "cellat_qeng.inc"
#include "cellat_cpsi.inc"
#include "cellat_rfsts.inc"
#include "cellat_tacfix.inc"
/* AT+QSCAN=3,1 full-band-scan decode core. Must follow cellat_qeng.inc:
 * parse_qscan reuses that file's split_fields/parse_int/parse_hex/plmn_field/
 * normalize_rat/lte_bw_rb_to_mhz/build_cell_json. Exercised by test_cellat_qscan. */
#include "cellat_qscan.inc"
/* Standard 3GPP decode cores (generic serving cell + AT+COPS=? PLMN scan).
 * Must follow cellat_qeng.inc: the std parsers reuse that file's
 * parse_int/parse_hex/split_fields/strip_quotes/plmn_split_mccmnc/
 * build_cell_json. Vendor-neutral fallback exercised by test_cellat_std3gpp. */
#include "cellat_std3gpp.inc"

/* -----------------------------------------------------------------------
 * Modem identification
 * ----------------------------------------------------------------------- */

/* How the last identify_modem() released its probe fd, and the scan's list of
 * ports that never took their probe. File-static: the scan runs from
 * the single open/list callback thread of this helper process. */
static diag_probeclose_how_t g_probe_close_how = DIAG_PROBECLOSE_PLAIN;
static char g_scan_stuck[256];
/* Ports the last scan skipped because another process held their claim at that
 * instant (serial_open -> EWOULDBLOCK) -- usually a sibling source's scan
 * mid-probe. Counted so open_callback can tell "busy" from "absent". */
static int g_scan_busy;

/* A lister's wait for the ports another process held during its pass.
 * The server runs the cellat and celldiag listers at once; each skips a
 * port the other is probing, so without this wait a modem with one AT port
 * (the T99W175) is dropped by whichever lister comes second. A lister's hold is
 * sub-second, so the held ports are re-tried until they are free or
 * this one shared deadline passes -- shared, because a port an open capture
 * holds is held for good and must cost a list the deadline once, not
 * once per port. 0 = off: only list_callback sets it; an open's scan already
 * rescans once. */
#define CELL_LIST_BUSY_WAIT_MS 1500
#define CELL_LIST_BUSY_STEP_MS 100
static int g_scan_list_wait;

/* Per-port cost of the last scan, for ports costing >= CELLAT_SCAN_SLOW_MS --
 * the cellat twin of celldiag's slow-port detail. Without it an open that
 * spends 30+ s in its scan says only "Command did not complete". */
#define CELLAT_SCAN_SLOW_MS 500
static char g_scan_slow[512];
/* Ports whose open() did not return within DIAG_PROBE_OPEN_DEADLINE_MS and were
 * skipped: "ttyUSB18(open-timeout)" -- a tty still in its final close
 * after a sibling's probe. Set per identify_modem() by the flag below. */
static char g_scan_openstuck[256];
static int g_probe_open_timed_out;

static long scan_elapsed_ms(const struct timespec *t0) {
    struct timespec t1;
    clock_gettime(CLOCK_MONOTONIC, &t1);
    return (long)(t1.tv_sec - t0->tv_sec) * 1000L +
           (long)(t1.tv_nsec - t0->tv_nsec) / 1000000L;
}

static void scan_slow_note(const char *port, long ms) {
    size_t off = strlen(g_scan_slow);
    if (off + 32 >= sizeof(g_scan_slow))
        return;
    const char *base = strrchr(port, '/');
    base = base ? base + 1 : port;
    snprintf(g_scan_slow + off, sizeof(g_scan_slow) - off, "%s%s:%ldms",
             off ? "," : "", base, ms);
}

/* Every close after identify_modem() has WRITTEN to the port goes through here.
 * On a tty that never reads its input -- an NMEA-only function -- a plain
 * close() blocks for the port's 30 s closing_wait, and this scan runs inside
 * open_callback: 30 s is Kismet's whole command timeout, so the source would
 * fail to launch with "Command did not complete" (see diag_probeclose.h). */
static void probe_release(int fd, const char *path) {
    g_probe_close_how = diag_probe_close(fd, path);
}

/*
 * Probe a serial port: send AT, then read firmware and IMEI.
 * Returns 1 on success (populates fw_buf, imei_buf), 0 on failure.
 */
static int identify_modem(const char *path, char *fw_buf, size_t fw_sz,
                          char *imei_buf, size_t imei_sz, modemident_t *id) {
    char resp[4096];

    modemident_clear(id);

    g_probe_close_how = DIAG_PROBECLOSE_PLAIN;
    g_probe_open_timed_out = 0;
    int fd = serial_open(path, 115200);
    if (fd < 0) {
        /* Busy is worth a rescan; an open that timed out is not -- it
         * is a tty mid-close, and never an AT port. */
        if (errno == EWOULDBLOCK)
            g_scan_busy++;
        else if (errno == ETIMEDOUT)
            g_probe_open_timed_out = 1;
        return 0;
    }

    /* Basic AT check — very short timeout since responding modems reply
     * in milliseconds.  Non-AT ports (DM, NMEA, etc.) will time out here
     * quickly, which is critical when scanning many ports at startup. */
    int n = at_command(fd, "AT", resp, sizeof(resp), 150);
    if (n < 0 || strstr(resp, "OK") == NULL) {
        probe_release(fd, path);
        return 0;
    }

    /* Firmware version.
     *
     * at_response_value() strips the `+CGMR: ` response-code prefix. Taken
     * verbatim, a SIMCom SIM8202G-M2's firmware reads
     * "+CGMR: LE13B04SIM8202M44A-M2", which matches none of the left-anchored
     * `firmware_match` globs in capture_cell_at/profiles/ -- so that modem
     * would silently get no DIAG profile at all. See cellat_qeng.inc. */
    fw_buf[0] = '\0';
    n = at_info_command(fd, "AT+CGMR", resp, sizeof(resp), 3000,
                        MODEMIDENT_INFO_IDLE_MS);
    if (n > 0)
        at_response_value(resp, fw_buf, fw_sz);

    if (!fw_buf[0]) {
        probe_release(fd, path);
        return 0;
    }

    /* IMEI. Same extraction: the SIM8202G-M2 answers +CGSN bare, but the
     * response-code form is equally legal and other firmware may use it. */
    imei_buf[0] = '\0';
    struct timespec cgsn_t0;   /* see modemident_followup_ms() */
    clock_gettime(CLOCK_MONOTONIC, &cgsn_t0);
    n = at_info_command(fd, "AT+CGSN", resp, sizeof(resp), 3000,
                        MODEMIDENT_INFO_IDLE_MS);
    long cgsn_ms = scan_elapsed_ms(&cgsn_t0);
    if (n > 0)
        at_response_value(resp, imei_buf, imei_sz);

    /* The IMEI names the source and its band-lock state file, so a read
     * that is not an IMEI's shape is re-asked once (the exchange flushes input
     * first), then dropped. A stale reply left by an earlier prober can
     * otherwise name a source "cellat-Quectel". An empty IMEI stays empty: that modem is
     * listed nowhere, exactly as one that never answered AT+CGSN. */
    if (imei_buf[0] && !modemident_imei_ok(imei_buf)) {
        char first[64];
        snprintf(first, sizeof(first), "%s", imei_buf);
        imei_buf[0] = '\0';
        n = at_info_command(fd, "AT+CGSN", resp, sizeof(resp), 3000,
                            MODEMIDENT_INFO_IDLE_MS);
        if (n > 0)
            at_response_value(resp, imei_buf, imei_sz);
        if (!modemident_imei_ok(imei_buf)) {
            fprintf(stderr, "cellat: %s: AT+CGSN answered '%s', then '%s' on "
                    "retry -- not a %d-digit IMEI, so no source is named from "
                    "this port\n", path, first, imei_buf,
                    MODEMIDENT_IMEI_DIGITS);
            imei_buf[0] = '\0';
        }
    }

    /* Make + model, only when the caller asked (`--list` does; the
     * open-time IMEI scan does not, and must not pay two round-trips on every
     * modem it passes over -- the open reads them on its own fd instead). */
    if (id != NULL) {
        /* An IMEI that arrived only by timing out marks a port that never sends
         * the final OK on info replies (the T99W175): short deadline there. */
        int follow_ms = (int)modemident_followup_ms(cgsn_ms, imei_buf[0] != '\0');

        snprintf(id->imei, sizeof(id->imei), "%s", imei_buf);
        snprintf(id->firmware, sizeof(id->firmware), "%s", fw_buf);
        n = at_info_command(fd, "AT+CGMI", resp, sizeof(resp), follow_ms,
                            MODEMIDENT_INFO_IDLE_MS);
        if (n > 0)
            modemident_value(resp, id->make, sizeof(id->make));
        n = at_info_command(fd, "AT+CGMM", resp, sizeof(resp), follow_ms,
                            MODEMIDENT_INFO_IDLE_MS);
        if (n > 0)
            modemident_value(resp, id->model, sizeof(id->model));
    }

    probe_release(fd, path);
    return 1;
}

/* Detect modem vendor from firmware string.
 *
 * Quectel firmware starts with model name: RM500Q*, EG25*, EC25*, RM502Q*, etc.
 * Telit firmware is a version number like 32.01.110 — identified by AT+CGMI.
 */
static enum modem_vendor detect_vendor(int fd, char *make_out, size_t make_sz,
                                       long *cgmi_ms) {
    char resp[4096];

    /* Try AT+CGMI (manufacturer identification). Its answer is also the
     * modem's make, verbatim, and how long it took tells the open whether this
     * port terminates info replies (modemident_followup_ms). */
    struct timespec t0;
    clock_gettime(CLOCK_MONOTONIC, &t0);
    int n = at_info_command(fd, "AT+CGMI", resp, sizeof(resp), 3000,
                            MODEMIDENT_INFO_IDLE_MS);
    if (cgmi_ms != NULL)
        *cgmi_ms = scan_elapsed_ms(&t0);
    if (make_out != NULL && make_sz > 0) {
        make_out[0] = '\0';
        if (n > 0)
            modemident_value(resp, make_out, make_sz);
    }
    if (n > 0) {
        if (strstr(resp, "Quectel") != NULL)
            return VENDOR_QUECTEL;
        if (strstr(resp, "Telit") != NULL)
            return VENDOR_TELIT;
        if (strstr(resp, "Sierra") != NULL)
            return VENDOR_SIERRA;
        /* SIMCom answers in upper case. A SIM8202G-M2 replies
         *     Manufacturer: SIMCOM INCORPORATED
         * so the vendor's own product spelling, "SIMCom", matches nothing.
         * Matched case-insensitively rather than by adding a second literal, because
         * the family also ships "SIMCOM_Ltd" and "Simcom" spellings across
         * firmware generations and a literal list would go stale silently. */
        if (strcasestr(resp, "SIMCOM") != NULL ||
            strcasestr(resp, "SIMTECH") != NULL)
            return VENDOR_SIMCOM;
        /* Orbic RC400L reports "Manufacturer" or "Reliance" or "Sino" via CGMI
         * (cheap ODM firmware quirk — varies by unit) */
        if (strstr(resp, "Reliance") != NULL || strstr(resp, "Sino") != NULL ||
            strstr(resp, "Orbic") != NULL)
            return VENDOR_ORBIC;
    }

    return VENDOR_UNKNOWN;
}

static const char *vendor_name(enum modem_vendor v) {
    switch (v) {
        case VENDOR_QUECTEL: return "Quectel";
        case VENDOR_TELIT:   return "Telit";
        case VENDOR_SIERRA:  return "Sierra";
        case VENDOR_ORBIC:   return "Orbic";
        case VENDOR_SIMCOM:  return "SIMCom";
        default:             return "Unknown";
    }
}

/* True when an AT response is a positive final result (`OK`) and not a
 * rejection (`ERROR` / `+CME ERROR`, both of which contain "ERROR").
 *
 * A vendor survey command answers a bare `OK` when it is supported but the
 * modem has nothing to report -- an unregistered modem with no serving cell
 * (garage, basement, antenna not yet connected). Treating that bare `OK` as
 * "unsupported" refuses a Telit LM960 that starts a drive without signal as
 * "no known cell survey command", and because every reopen repeats the same
 * probe it never recovers once it registers. A capability probe must key on
 * "was the command accepted", not "did it return a cell". */
static int at_response_ok(const char *resp) {
    return resp != NULL && strstr(resp, "OK") != NULL
        && strstr(resp, "ERROR") == NULL;
}

/* The survey commands the detected vendor's branch actually probes, for the
 * refusal message, so an operator is never told to audit commands the
 * vendor's branch never sent. */
static const char *vendor_probed_cmds(enum modem_vendor v) {
    switch (v) {
        case VENDOR_QUECTEL: return "AT+QENG=\"servingcell\"";
        case VENDOR_TELIT:   return "AT#RFSTS, AT#SERVINFO, AT#MONI, AT#CSURVC";
        case VENDOR_SIERRA:  return "AT!GSTATUS?";
        case VENDOR_SIMCOM:  return "AT+CPSI?";
        case VENDOR_ORBIC:   return "AT^SCELLINFO, AT$QCRSRP?";
        default:             return "AT+QENG=\"servingcell\", AT#RFSTS, "
                                    "AT!GSTATUS?, AT+CPSI?, AT^SCELLINFO, "
                                    "AT$QCRSRP?";
    }
}

/*
 * Parse Telit AT#SERVINFO response.
 *
 * Telit LM960/LM960A18:
 *   "LM960 Series AT Command Reference Guide" Rev.8, 2022-03-21, §5.6.1.27
 *
 * Format (LTE):
 *   #SERVINFO: EARFCN,RSSI,"operator","MCCMNC",cell_id(hex),TAC(hex),DRX,SD,RSRP
 *
 * Example:
 *   #SERVINFO: 66786,-62,"T-Mobile","310260",1A2B302,1A2B,1280,3,-94
 *
 * Note: field[6] is DRX (not PCI as incorrectly documented in some sources).
 * SERVINFO does NOT include PCI on LTE. PCI comes from AT#MONI or AT#CSURVC.
 * Used as fallback when AT#RFSTS is unavailable.
 */
static int parse_servinfo(const char *response, char json_out[][JSON_BUF_MAX],
                          int max_obs) {
    char *resp_copy = strdup(response);
    if (!resp_copy) return 0;

    int obs_count = 0;
    char *saveptr = NULL;
    char *line = strtok_r(resp_copy, "\n", &saveptr);

    while (line && obs_count < max_obs) {
        while (*line == ' ') line++;

        if (strncmp(line, "#SERVINFO:", 10) != 0) {
            line = strtok_r(NULL, "\n", &saveptr);
            continue;
        }

        char *body = line + 10;
        while (*body == ' ') body++;

        char *fields[32];
        char body_copy[2048];
        strncpy(body_copy, body, sizeof(body_copy) - 1);
        body_copy[sizeof(body_copy) - 1] = '\0';
        int nf = split_fields(body_copy, fields, 32);

        long earfcn = 0, rssi = 0, rsrp = 0;
        unsigned long cell_id = 0, tac = 0;
        const char *mcc = NULL, *mnc = NULL;   /* as-broadcast digit strings */
        char mcc_buf[8] = "", mnc_buf[8] = "";
        int h_earfcn = 0, h_rssi = 0, h_rsrp = 0;
        int h_cell_id = 0, h_tac = 0;
        char *operator_name = NULL;

        if (nf > 0) h_earfcn = parse_int(fields[0], &earfcn);
        if (nf > 1) h_rssi = parse_int(fields[1], &rssi);
        if (nf > 2 && fields[2][0] != '\0')
            operator_name = fields[2];
        /* fields[3] = "MCCMNC" concatenated; split preserving the digit count */
        if (nf > 3 && plmn_split_mccmnc(fields[3], mcc_buf, sizeof mcc_buf,
                                        mnc_buf, sizeof mnc_buf)) {
            mcc = mcc_buf;
            mnc = mnc_buf;
        }
        if (nf > 4) h_cell_id = parse_hex(fields[4], &cell_id);
        if (nf > 5) h_tac = parse_hex(fields[5], &tac);
        /* fields[6] = DRX (NOT PCI — confirmed against Rev.8 §5.6.1.27) */
        /* fields[7] = SD (Service Domain) */
        if (nf > 8) h_rsrp = parse_int(fields[8], &rsrp);

        build_cell_json(json_out[obs_count], JSON_BUF_MAX,
                        "LTE", NULL,
                        mcc, mnc,
                        cell_id, h_cell_id, 0, 0, /* no PCI in SERVINFO */
                        tac, h_tac, earfcn, h_earfcn,
                        0, 0, 0, 0,
                        rsrp, h_rsrp, 0, 0,
                        0, 0, rssi, h_rssi,
                        "serving", 1, operator_name);
        obs_count++;

        line = strtok_r(NULL, "\n", &saveptr);
    }

    free(resp_copy);
    return obs_count;
}

/*
 * Extract a numeric value from a "Key:Value" token in a space-delimited string.
 * Finds the key, then parses the value up to the next space or end of string.
 * Works with both decimal (e.g., "RSRP:-102") and hex (e.g., "Id:6DE11D2").
 * Returns 1 on success.
 */
static int extract_kv_int(const char *str, const char *key, long *out) {
    char *p = strstr(str, key);
    if (!p) return 0;
    p += strlen(key);
    /* Copy value to a NUL-terminated buffer */
    char val[32];
    int i = 0;
    while (p[i] && p[i] != ' ' && p[i] != '\r' && p[i] != '\n' && i < (int)sizeof(val) - 1) {
        val[i] = p[i];
        i++;
    }
    val[i] = '\0';
    return parse_int(val, out);
}

static int extract_kv_hex(const char *str, const char *key, unsigned long *out) {
    char *p = strstr(str, key);
    if (!p) return 0;
    p += strlen(key);
    char val[32];
    int i = 0;
    while (p[i] && p[i] != ' ' && p[i] != '\r' && p[i] != '\n' && i < (int)sizeof(val) - 1) {
        val[i] = p[i];
        i++;
    }
    val[i] = '\0';
    return parse_hex(val, out);
}

/* Copy the space/EOL-terminated value after `key` into `out` (NUL-terminated,
 * truncated to out_sz). Returns 1 iff the key was present. Used for PLMN
 * components whose broadcast digit count must be preserved. */
static int extract_kv_str(const char *str, const char *key, char *out, size_t out_sz) {
    char *p = strstr(str, key);
    if (!p) return 0;
    p += strlen(key);
    size_t i = 0;
    while (p[i] && p[i] != ' ' && p[i] != '\r' && p[i] != '\n' && i < out_sz - 1) {
        out[i] = p[i];
        i++;
    }
    out[i] = '\0';
    return 1;
}

/*
 * Parse Telit AT#MONI response.
 *
 * Telit LM960/LM960A18:
 *   "LM960 Series AT Command Reference Guide" Rev.8, 2022-03-21, §5.6.1.24
 *
 * Serving cell format (AT#MONI=0 then AT#MONI):
 *   #MONI: <netname> RSRP:<rsrp> RSRQ:<rsrq> TAC:<tac> Id:<id> EARFCN:<earfcn> PWR:<dBm>dbm DRX:<drx>
 *   #MONI: Cc:<cc> Nc:<nc> RSRP:<rsrp> RSRQ:<rsrq> TAC:<tac> Id:<id> EARFCN:<earfcn> PWR:<dBm>dbm DRX:<drx>
 *
 * Neighbor cell format (AT#MONI=1 or AT#MONI=2 then AT#MONI):
 *   #MONI: RSRP:<rsrp> RSRQ:<rsrq> Id:<id> EARFCN:<earfcn> PWR:<dBm>dbm
 *
 * Id is cell ID in hex for serving, PCI in hex for neighbors.
 */
static int parse_moni(const char *response, char json_out[][JSON_BUF_MAX],
                      int max_obs, int is_serving) {
    char *resp_copy = strdup(response);
    if (!resp_copy) return 0;

    int obs_count = 0;
    char *saveptr = NULL;
    char *line = strtok_r(resp_copy, "\n", &saveptr);

    while (line && obs_count < max_obs) {
        while (*line == ' ') line++;

        if (strncmp(line, "#MONI:", 6) != 0) {
            line = strtok_r(NULL, "\n", &saveptr);
            continue;
        }

        char *body = line + 6;
        while (*body == ' ') body++;

        long rsrp = 0, rsrq = 0, rssi = 0, earfcn = 0;
        const char *mcc = NULL, *mnc = NULL;   /* as-broadcast digit strings */
        char mcc_buf[8] = "", mnc_buf[8] = "";
        unsigned long tac = 0, cell_id = 0;
        long pci = 0;
        int h_rsrp = 0, h_rsrq = 0, h_rssi = 0, h_earfcn = 0;
        int h_tac = 0, h_cell_id = 0, h_pci = 0;
        char *operator_name = NULL;

        /* Extract key:value pairs from the space-delimited response.
         * Cc:/Nc: are the MCC/MNC -- keep the broadcast digit count. */
        if (extract_kv_str(body, "Cc:", mcc_buf, sizeof mcc_buf) && plmn_field(mcc_buf))
            mcc = mcc_buf;
        if (extract_kv_str(body, "Nc:", mnc_buf, sizeof mnc_buf) && plmn_field(mnc_buf))
            mnc = mnc_buf;
        h_rsrp = extract_kv_int(body, "RSRP:", &rsrp);
        h_rsrq = extract_kv_int(body, "RSRQ:", &rsrq);
        h_tac = extract_kv_hex(body, "TAC:", &tac);
        h_earfcn = extract_kv_int(body, "EARFCN:", &earfcn);
        h_rssi = extract_kv_int(body, "PWR:", &rssi);

        /* Id field: cell ID (hex) for serving, PCI (hex) for neighbors */
        unsigned long id_val = 0;
        if (extract_kv_hex(body, "Id:", &id_val)) {
            if (is_serving) {
                cell_id = id_val;
                h_cell_id = 1;
            } else {
                pci = (long)id_val;
                h_pci = 1;
            }
        }

        /* Network name: first token if it doesn't start with a known key */
        if (body[0] != '\0' && strncmp(body, "Cc:", 3) != 0 &&
            strncmp(body, "RSRP:", 5) != 0 && strncmp(body, "PSC:", 4) != 0) {
            /* Network name is the first space-delimited token */
            static char name_buf[64];
            int ni = 0;
            while (body[ni] && body[ni] != ' ' && ni < (int)sizeof(name_buf) - 1)
                name_buf[ni] = body[ni], ni++;
            name_buf[ni] = '\0';
            if (ni > 0)
                operator_name = name_buf;
        }

        const char *obs_type = is_serving ? "serving" : "observation";

        build_cell_json(json_out[obs_count], JSON_BUF_MAX,
                        "LTE", NULL,
                        mcc, mnc,
                        cell_id, h_cell_id, pci, h_pci,
                        tac, h_tac, earfcn, h_earfcn,
                        0, 0, 0, 0,
                        rsrp, h_rsrp, rsrq, h_rsrq,
                        0, 0, rssi, h_rssi,
                        obs_type, is_serving, operator_name);
        obs_count++;

        line = strtok_r(NULL, "\n", &saveptr);
    }

    free(resp_copy);
    return obs_count;
}

/*
 * Parse Telit AT#CSURVC response.
 *
 * Telit LM960/LM960A18:
 *   "LM960 Series AT Command Reference Guide" Rev.8, 2022-03-21, §5.6.9.2
 *
 * 4G serving/carrier cell format (11 fields):
 *   <earfcn>,<rxLev>,<mcc>,<mnc>,<cellId>,<tac>,<pci>,<cellStatus>,<rsrp>,<rsrq>,<bandwidth>
 *
 * 4G neighbor cell format (6 fields):
 *   <earfcn>,<rxLev>,<pci>,<cellStatus>,<rsrp>,<rsrq>
 *
 * MCC/MNC are hex. CellId and TAC are decimal by default (#CSURVF=0).
 * Lines starting with "Network survey" are status lines and should be skipped.
 *
 * The command takes 30-60 seconds to complete (max 3 minutes per manual).
 * Should only be used in stationary strategy.
 */
static int parse_csurvc(const char *response, char json_out[][JSON_BUF_MAX],
                        int max_obs) {
    char *resp_copy = strdup(response);
    if (!resp_copy) return 0;

    int obs_count = 0;
    char *saveptr = NULL;
    char *line = strtok_r(resp_copy, "\n", &saveptr);

    while (line && obs_count < max_obs) {
        while (*line == ' ') line++;

        /* Skip status lines and terminal responses */
        if (strncmp(line, "Network survey", 14) == 0 ||
            strcmp(line, "OK") == 0 || strcmp(line, "ERROR") == 0 ||
            line[0] == '\0') {
            line = strtok_r(NULL, "\n", &saveptr);
            continue;
        }

        /* Must start with a digit (EARFCN) */
        if (!isdigit((unsigned char)line[0])) {
            line = strtok_r(NULL, "\n", &saveptr);
            continue;
        }

        char *fields[32];
        char line_copy[2048];
        strncpy(line_copy, line, sizeof(line_copy) - 1);
        line_copy[sizeof(line_copy) - 1] = '\0';
        int nf = split_fields(line_copy, fields, 32);

        if (nf >= 11) {
            /* Serving/carrier cell: earfcn,rxLev,mcc,mnc,cellId,tac,pci,cellStatus,rsrp,rsrq,bandwidth */
            long earfcn = 0, rssi = 0, rsrp = 0, rsrq = 0, pci = 0, bandwidth = 0;
            const char *mcc = NULL, *mnc = NULL;   /* as-broadcast digit strings */
            long cell_id_l = 0;
            unsigned long cell_id = 0, tac = 0;
            int h_earfcn = 0, h_rssi = 0, h_rsrp = 0, h_rsrq = 0;
            int h_cell_id = 0, h_tac = 0;
            int h_pci = 0, h_bandwidth = 0;

            h_earfcn = parse_int(fields[0], &earfcn);
            h_rssi = parse_int(fields[1], &rssi);
            /* MCC/MNC: manual says hex but observed output is decimal.
             * Keep the broadcast digit count. */
            mcc = plmn_field(fields[2]);
            mnc = plmn_field(fields[3]);
            if (parse_int(fields[4], &cell_id_l)) {
                cell_id = (unsigned long)cell_id_l;
                h_cell_id = 1;
            }
            if (parse_int(fields[5], &cell_id_l)) {
                tac = (unsigned long)cell_id_l;
                h_tac = 1;
            }
            h_pci = parse_int(fields[6], &pci);
            /* fields[7] = cellStatus (skip for now) */
            h_rsrp = parse_int(fields[8], &rsrp);
            h_rsrq = parse_int(fields[9], &rsrq);
            h_bandwidth = parse_int(fields[10], &bandwidth);

            build_cell_json(json_out[obs_count], JSON_BUF_MAX,
                            "LTE", NULL,
                            mcc, mnc,
                            cell_id, h_cell_id, pci, h_pci,
                            tac, h_tac, earfcn, h_earfcn,
                            0, 0, bandwidth, h_bandwidth,
                            rsrp, h_rsrp, rsrq, h_rsrq,
                            0, 0, rssi, h_rssi,
                            "survey", 0, NULL);
            obs_count++;

        } else if (nf >= 6) {
            /* Neighbor cell: earfcn,rxLev,pci,cellStatus,rsrp,rsrq */
            long earfcn = 0, rssi = 0, rsrp = 0, rsrq = 0, pci = 0;
            int h_earfcn = 0, h_rssi = 0, h_rsrp = 0, h_rsrq = 0, h_pci = 0;

            h_earfcn = parse_int(fields[0], &earfcn);
            h_rssi = parse_int(fields[1], &rssi);
            h_pci = parse_int(fields[2], &pci);
            /* fields[3] = cellStatus (skip) */
            h_rsrp = parse_int(fields[4], &rsrp);
            h_rsrq = parse_int(fields[5], &rsrq);

            build_cell_json(json_out[obs_count], JSON_BUF_MAX,
                            "LTE", NULL,
                            NULL, NULL,   /* neighbour: PLMN not in this line */
                            0, 0, pci, h_pci,
                            0, 0, earfcn, h_earfcn,
                            0, 0, 0, 0,
                            rsrp, h_rsrp, rsrq, h_rsrq,
                            0, 0, rssi, h_rssi,
                            "observation", 0, NULL);
            obs_count++;

        } else if (nf == 3) {
            /* 3GPP TS 36.101 style WCDMA: uarfcn,rxLev,scrcode... (skip) */
        }

        line = strtok_r(NULL, "\n", &saveptr);
    }

    free(resp_copy);
    return obs_count;
}

/*
 * Parse Sierra Wireless AT!GSTATUS? response.
 *
 * Sierra EM9190/EM919x:
 *   "EM9 Series AT Command Reference" Rev.14, 2026-01-01
 *
 * The response is a multi-line key-value format with tab/space delimiters.
 * Fields vary by RAT (LTE vs NR5G). Key fields are extracted by searching
 * for known labels in the full response text.
 *
 * Also fetches PCI from AT!NRPCI? or AT!LTEINFO? as !GSTATUS lacks PCI.
 *
 * Example NR5G SA response:
 *   !GSTATUS:
 *   Current Time:  423212         Temperature: 36
 *   System mode:   NR5G           PS state:    Not attached
 *   NR5G TAC:        1a2b00       NR5G Cell ID:    1A2B9D138 (7025054008)
 *   NR5G MCC-MNC:    310-260
 *   NR5G band:       n41          NR5G Carrier ID: 0
 *   NR5G dl bw:      20 MHz
 *   NR5G Rx chan:    521232
 *   NR5G RSRP (dBm): -104        NR5G RSRQ (dB):  -15
 *   NR5G SINR (dB):   0.5
 */
/*
 * Extract a whitespace-delimited token after a label in a multiline response.
 * Copies the token to a NUL-terminated buffer for safe parsing.
 * Returns pointer to static buffer, or NULL if label not found.
 */
static const char *extract_gstatus_field(const char *response, const char *label) {
    static char field_buf[64];
    char *p = strstr(response, label);
    if (!p) return NULL;
    p += strlen(label);
    while (*p == ' ' || *p == '\t') p++;
    int i = 0;
    while (p[i] && p[i] != ' ' && p[i] != '\t' && p[i] != '\r' && p[i] != '\n'
           && i < (int)sizeof(field_buf) - 1)
        field_buf[i] = p[i], i++;
    field_buf[i] = '\0';
    return field_buf;
}

static int parse_gstatus(const char *response, int serial_fd,
                         char json_out[][JSON_BUF_MAX], int max_obs) {
    if (max_obs < 1) return 0;

    /* Detect RAT from "System mode:" */
    const char *rat = "LTE";
    const char *f = extract_gstatus_field(response, "System mode:");
    if (f) {
        if (strstr(f, "NR5G") || strcmp(f, "NR5G") == 0)
            rat = "NR";
        else if (strstr(f, "LTE") || strcmp(f, "LTE") == 0)
            rat = "LTE";
    }

    const char *mcc = NULL, *mnc = NULL;   /* as-broadcast digit strings */
    char mcc_buf[8] = "", mnc_buf[8] = "";
    long rsrp = 0, rsrq = 0, band = 0, bandwidth = 0;
    unsigned long tac = 0, cell_id = 0;
    long earfcn = 0, pci = -1;
    int h_rsrp = 0, h_rsrq = 0, h_band = 0;
    int h_tac = 0, h_cell_id = 0, h_earfcn = 0, h_pci = 0;
    int h_bandwidth = 0, h_sinr = 0;
    long sinr = 0;
    char *p;

    /* Parse MCC-MNC (format: "310-260") — same label prefix for both RATs */
    const char *mcc_mnc_label = (strcmp(rat, "NR") == 0) ? "NR5G MCC-MNC:" : "MCC-MNC:";
    f = extract_gstatus_field(response, mcc_mnc_label);
    if (f) {
        char mcc_mnc_buf[16];
        strncpy(mcc_mnc_buf, f, sizeof(mcc_mnc_buf) - 1);
        mcc_mnc_buf[sizeof(mcc_mnc_buf) - 1] = '\0';
        /* "310-260" split, preserving the broadcast digit count */
        if (plmn_split_dash(mcc_mnc_buf, mcc_buf, sizeof mcc_buf,
                            mnc_buf, sizeof mnc_buf)) {
            mcc = mcc_buf;
            mnc = mnc_buf;
        }
    }

    /* Cell ID: "... Cell ID:    1A2B9D138 (7025054008)" — use decimal in parens */
    if ((p = strstr(response, "Cell ID:")) != NULL) {
        char *paren = strchr(p, '(');
        if (paren) {
            paren++;
            char cid_buf[32];
            int bi = 0;
            while (paren[bi] && paren[bi] != ')' && bi < (int)sizeof(cid_buf) - 1)
                cid_buf[bi] = paren[bi], bi++;
            cid_buf[bi] = '\0';
            long v;
            if (parse_int(cid_buf, &v)) {
                cell_id = (unsigned long)v;
                h_cell_id = 1;
            }
        }
    }

    /* TAC (hex) */
    const char *tac_label = (strcmp(rat, "NR") == 0) ? "NR5G TAC:" : "TAC:";
    f = extract_gstatus_field(response, tac_label);
    if (f) h_tac = parse_hex(f, &tac);

    /* Band: "n41" or "B66" */
    const char *band_label = (strcmp(rat, "NR") == 0) ? "NR5G band:" : "LTE band:";
    f = extract_gstatus_field(response, band_label);
    if (f) {
        const char *bp = f;
        if (*bp == 'n' || *bp == 'N' || *bp == 'B' || *bp == 'b') bp++;
        h_band = parse_int(bp, &band);
    }

    /* DL bandwidth */
    const char *bw_label = (strcmp(rat, "NR") == 0) ? "NR5G dl bw:" : "LTE dl bw:";
    f = extract_gstatus_field(response, bw_label);
    if (f) h_bandwidth = parse_int(f, &bandwidth);

    /* Rx channel (EARFCN / NR-ARFCN) */
    const char *chan_label = (strcmp(rat, "NR") == 0) ? "NR5G Rx chan:" : "LTE Rx chan:";
    f = extract_gstatus_field(response, chan_label);
    if (f) h_earfcn = parse_int(f, &earfcn);

    /* RSRP — NR uses "NR5G RSRP (dBm):", LTE uses "PCC Rx0 RSRP:" */
    const char *rsrp_label = (strcmp(rat, "NR") == 0) ? "NR5G RSRP (dBm):" : "PCC Rx0 RSRP:";
    f = extract_gstatus_field(response, rsrp_label);
    if (f) h_rsrp = parse_int(f, &rsrp);

    /* RSRQ */
    const char *rsrq_label = (strcmp(rat, "NR") == 0) ? "NR5G RSRQ (dB):" : "RSRQ (dB):";
    f = extract_gstatus_field(response, rsrq_label);
    if (f) h_rsrq = parse_int(f, &rsrq);

    /* SINR — may be fractional (e.g. "0.5"), truncate to integer */
    const char *sinr_label = (strcmp(rat, "NR") == 0) ? "NR5G SINR (dB):" : "SINR (dB):";
    f = extract_gstatus_field(response, sinr_label);
    if (f) {
        h_sinr = parse_int(f, &sinr);
        if (!h_sinr) {
            char *end;
            double v = strtod(f, &end);
            if (end != f) { sinr = (long)v; h_sinr = 1; }
        }
    }

    /* PCI — from AT!NRPCI? (NR) or AT!LTEINFO? serving line (LTE) */
    if (serial_fd >= 0) {
        if (strcmp(rat, "NR") == 0) {
            char pci_resp[256];
            int n = at_command(serial_fd, "AT!NRPCI?", pci_resp, sizeof(pci_resp), 2000);
            if (n > 0) {
                f = extract_gstatus_field(pci_resp, "!NRPCI:");
                if (f) h_pci = parse_int(f, &pci);
            }
        } else {
            /* LTE — parse AT!LTEINFO? serving line for PCI and MCC/MNC.
             *
             * EM9 Series AT Command Reference Rev.14, 2026-01-01:
             * Serving line format (space-delimited, after header):
             *   EARFCN MCC MNC TAC CID(hex) Bd D U SNR PCI RSRQ RSRP RSSI RXLV
             *
             * Example:
             *   66786 310 260 6699 01A2B302 66 5 5 -1 236 -14.9 -103.3 -66.6 20
             */
            char lte_resp[4096];
            int n = at_command(serial_fd, "AT!LTEINFO?", lte_resp, sizeof(lte_resp), 5000);
            if (n > 0 && strstr(lte_resp, "Serving:")) {
                /* Find the data line after "Serving:" header line */
                char *serving = strstr(lte_resp, "Serving:");
                char *data_line = NULL;
                if (serving) {
                    /* Skip to next line */
                    char *nl = strchr(serving, '\n');
                    if (nl) {
                        data_line = nl + 1;
                        while (*data_line == ' ') data_line++;
                    }
                }
                if (data_line && *data_line && strncmp(data_line, "IntraFreq", 9) != 0) {
                    /* Parse space-delimited serving line */
                    char srv_copy[512];
                    strncpy(srv_copy, data_line, sizeof(srv_copy) - 1);
                    srv_copy[sizeof(srv_copy) - 1] = '\0';
                    /* Truncate at newline */
                    char *nl2 = strchr(srv_copy, '\n');
                    if (nl2) *nl2 = '\0';

                    /* Split on whitespace */
                    char *fields[20];
                    int nf = 0;
                    char *tok = strtok(srv_copy, " \t");
                    while (tok && nf < 20) {
                        fields[nf++] = tok;
                        tok = strtok(NULL, " \t");
                    }
                    /* EARFCN MCC MNC TAC CID Bd D U SNR PCI RSRQ RSRP RSSI RXLV */
                    /*   0     1   2   3   4  5  6 7  8   9   10   11   12   13  */
                    if (nf >= 10) {
                        /* fall back to the QSCAN-style columns, copying into
                         * the function-scope buffers so the pointer outlives
                         * this local field split */
                        if (!mcc && plmn_field(fields[1])) {
                            snprintf(mcc_buf, sizeof mcc_buf, "%s", fields[1]);
                            mcc = mcc_buf;
                        }
                        if (!mnc && plmn_field(fields[2])) {
                            snprintf(mnc_buf, sizeof mnc_buf, "%s", fields[2]);
                            mnc = mnc_buf;
                        }
                        h_pci = parse_int(fields[9], &pci);
                    }
                }
            }
        }
    }

    build_cell_json(json_out[0], JSON_BUF_MAX,
                    rat, NULL,
                    mcc, mnc,
                    cell_id, h_cell_id, pci, h_pci,
                    tac, h_tac, earfcn, h_earfcn,
                    band, h_band, bandwidth, h_bandwidth,
                    rsrp, h_rsrp, rsrq, h_rsrq,
                    sinr, h_sinr, 0, 0,
                    "serving", 1, NULL);
    return 1;
}

/*
 * Parse Sierra AT!LTEINFO? neighbor cells.
 *
 * Sierra EM919x:
 *   "EM9 Series AT Command Reference" Rev.14, 2026-01-01
 *
 * IntraFreq neighbors (same EARFCN as serving, derived from serving line):
 *   PCI  RSRQ   RSRP   RSSI RXLV
 *   322 -19.2 -108.3  -79.7  20
 *
 * InterFreq neighbors (different EARFCN):
 *   EARFCN ThresholdLow ThresholdHi Priority PCI  RSRQ   RSRP   RSSI RXLV
 *
 * The serving_earfcn is used to set EARFCN for IntraFreq neighbors.
 */
static int parse_lteinfo_neighbors(const char *response, long serving_earfcn,
                                   char json_out[][JSON_BUF_MAX], int max_obs) {
    char *resp_copy = strdup(response);
    if (!resp_copy) return 0;

    int obs_count = 0;
    int in_intra = 0, in_inter = 0;

    char *saveptr = NULL;
    char *line = strtok_r(resp_copy, "\n", &saveptr);

    while (line && obs_count < max_obs) {
        while (*line == ' ') line++;

        /* Detect section headers */
        if (strncmp(line, "IntraFreq:", 10) == 0) {
            in_intra = 1; in_inter = 0;
            line = strtok_r(NULL, "\n", &saveptr);
            continue;
        }
        if (strncmp(line, "InterFreq:", 10) == 0) {
            in_intra = 0; in_inter = 1;
            line = strtok_r(NULL, "\n", &saveptr);
            continue;
        }
        /* Stop at other sections */
        if (strncmp(line, "Serving:", 8) == 0 ||
            strncmp(line, "CA SCell", 8) == 0 ||
            strncmp(line, "WCDMA:", 6) == 0 ||
            strcmp(line, "OK") == 0) {
            in_intra = 0; in_inter = 0;
            line = strtok_r(NULL, "\n", &saveptr);
            continue;
        }

        /* Skip header/empty lines */
        if (!isdigit((unsigned char)line[0]) &&
            line[0] != '-') {
            line = strtok_r(NULL, "\n", &saveptr);
            continue;
        }

        /* Parse data line — split on whitespace manually (strtok conflicts
         * with outer strtok_r on some platforms) */
        char line_copy[512];
        strncpy(line_copy, line, sizeof(line_copy) - 1);
        line_copy[sizeof(line_copy) - 1] = '\0';

        char *fields[20];
        int nf = 0;
        char *wp = line_copy;
        while (*wp && nf < 20) {
            while (*wp == ' ' || *wp == '\t') wp++;
            if (!*wp || *wp == '\n' || *wp == '\r') break;
            fields[nf++] = wp;
            while (*wp && *wp != ' ' && *wp != '\t' && *wp != '\n' && *wp != '\r') wp++;
            if (*wp) { *wp = '\0'; wp++; }
        }

        if (in_intra && nf >= 3) {
            /* IntraFreq: PCI RSRQ RSRP RSSI RXLV */
            long pci = 0, rsrp = 0;
            int h_pci = parse_int(fields[0], &pci);
            /* RSRQ and RSRP may be fractional (-19.2, -108.3) — truncate */
            long rsrq = 0, rsrp_l = 0;
            char *dot;
            if (nf > 1) {
                dot = strchr(fields[1], '.');
                if (dot) *dot = '\0';
                parse_int(fields[1], &rsrq);
            }
            if (nf > 2) {
                dot = strchr(fields[2], '.');
                if (dot) *dot = '\0';
                parse_int(fields[2], &rsrp_l);
                rsrp = rsrp_l;
            }

            build_cell_json(json_out[obs_count], JSON_BUF_MAX,
                            "LTE", NULL,
                            NULL, NULL,   /* neighbour: PLMN not in this line */
                            0, 0, pci, h_pci,
                            0, 0, serving_earfcn, (serving_earfcn > 0),
                            0, 0, 0, 0,
                            rsrp, (nf > 2), rsrq, (nf > 1),
                            0, 0, 0, 0,
                            "observation", 0, NULL);
            obs_count++;

        } else if (in_inter && nf >= 7) {
            /* InterFreq: EARFCN ThresholdLow ThresholdHi Priority PCI RSRQ RSRP RSSI RXLV */
            long earfcn = 0, pci = 0, rsrp = 0, rsrq = 0;
            int h_earfcn = parse_int(fields[0], &earfcn);
            int h_pci = parse_int(fields[4], &pci);
            char *dot;
            if (nf > 5) {
                dot = strchr(fields[5], '.');
                if (dot) *dot = '\0';
                parse_int(fields[5], &rsrq);
            }
            if (nf > 6) {
                dot = strchr(fields[6], '.');
                if (dot) *dot = '\0';
                parse_int(fields[6], &rsrp);
            }

            build_cell_json(json_out[obs_count], JSON_BUF_MAX,
                            "LTE", NULL,
                            NULL, NULL,   /* neighbour: PLMN not in this line */
                            0, 0, pci, h_pci,
                            0, 0, earfcn, h_earfcn,
                            0, 0, 0, 0,
                            rsrp, (nf > 6), rsrq, (nf > 5),
                            0, 0, 0, 0,
                            "observation", 0, NULL);
            obs_count++;
        }

        line = strtok_r(NULL, "\n", &saveptr);
    }

    free(resp_copy);
    return obs_count;
}

/* -----------------------------------------------------------------------
 * Orbic RC400L / Qualcomm MDM9607 parsers
 *
 * AT^SCELLINFO — Huawei-style serving cell info (registered mode).
 *   Returns key:value pairs on separate lines.
 *
 * AT$QCRSRP? — Qualcomm multi-cell passive scan.
 *   Returns PCI,EARFCN,"RSRP" triplets.  In COPS=2 (deregistered) mode,
 *   scans ALL configured bands and returns every visible cell.
 *
 * Reference: binary analysis of atfwd_daemon on
 *   MDM9607.LE.2.0-00193-STD.PROD-1 firmware.
 * ----------------------------------------------------------------------- */

/* EARFCN → LTE band and DL frequency lookup (3GPP TS 36.101 Tables 5.7.3-1, 5.5-1).
 *
 * Each entry: N_offs_DL (low EARFCN), N_offs_DL_hi (high EARFCN), band,
 *             F_DL_low (kHz), channel widths supported (MHz, bitmask).
 *
 * Frequency: F_DL(kHz) = F_DL_low + 100 * (EARFCN - N_offs_DL)
 * Channel width bitmask: bit0=1.4 bit1=3 bit2=5 bit3=10 bit4=15 bit5=20 */
typedef struct {
    long n_offs_dl;     /* Low EARFCN */
    long n_offs_dl_hi;  /* High EARFCN */
    long band;
    long f_dl_low_khz;  /* DL low edge frequency (kHz) */
    int  bw_mask;       /* Supported channel widths bitmask */
} earfcn_band_entry_t;

#define BW_1_4  (1 << 0)
#define BW_3    (1 << 1)
#define BW_5    (1 << 2)
#define BW_10   (1 << 3)
#define BW_15   (1 << 4)
#define BW_20   (1 << 5)

static const earfcn_band_entry_t earfcn_table[] = {
    /*  N_offs_DL  hi     band  F_DL_low(kHz)  BW mask */
    {0,     599,    1,  2110000, BW_5|BW_10|BW_15|BW_20},
    {600,   1199,   2,  1930000, BW_1_4|BW_3|BW_5|BW_10|BW_15|BW_20},
    {1200,  1949,   3,  1805000, BW_1_4|BW_3|BW_5|BW_10|BW_15|BW_20},
    {1950,  2399,   4,  2110000, BW_1_4|BW_3|BW_5|BW_10|BW_15|BW_20},
    {2400,  2649,   5,  869000,  BW_1_4|BW_3|BW_5|BW_10},
    {2650,  2749,   6,  875000,  BW_5|BW_10},
    {2750,  3449,   7,  2620000, BW_5|BW_10|BW_15|BW_20},
    {3450,  3799,   8,  925000,  BW_1_4|BW_3|BW_5|BW_10},
    {3800,  4149,   9,  1844900, BW_5|BW_10|BW_15|BW_20},
    {4150,  4749,   10, 2110000, BW_5|BW_10|BW_15|BW_20},
    {4750,  4949,   11, 1475900, BW_5|BW_10},
    {5010,  5179,   12, 729000,  BW_1_4|BW_3|BW_5|BW_10},
    {5180,  5279,   13, 746000,  BW_5|BW_10},
    {5280,  5379,   14, 758000,  BW_5|BW_10},
    {5730,  5849,   17, 734000,  BW_5|BW_10},
    {5850,  5999,   18, 860000,  BW_5|BW_10|BW_15},
    {6000,  6149,   19, 875000,  BW_5|BW_10|BW_15},
    {6150,  6449,   20, 791000,  BW_5|BW_10|BW_15|BW_20},
    {6450,  6599,   21, 1495900, BW_5|BW_10|BW_15},
    {8040,  8689,   25, 1930000, BW_1_4|BW_3|BW_5|BW_10|BW_15|BW_20},
    {8690,  9039,   26, 859000,  BW_1_4|BW_3|BW_5|BW_10|BW_15},
    {9040,  9209,   27, 852000,  BW_1_4|BW_3|BW_5|BW_10},
    {9210,  9659,   28, 758000,  BW_3|BW_5|BW_10|BW_15|BW_20},
    {9770,  9869,   30, 2350000, BW_5|BW_10},
    {9870,  9919,   31, 462500,  BW_1_4|BW_3|BW_5},
    {36000, 36199,  33, 1900000, BW_5|BW_10|BW_15|BW_20},
    {36200, 36349,  34, 2010000, BW_5|BW_10|BW_15},
    {36350, 36949,  35, 1850000, BW_1_4|BW_3|BW_5|BW_10|BW_15|BW_20},
    {36950, 37549,  36, 1930000, BW_1_4|BW_3|BW_5|BW_10|BW_15|BW_20},
    {37550, 37749,  37, 1910000, BW_5|BW_10|BW_15|BW_20},
    {37750, 38249,  38, 2570000, BW_5|BW_10|BW_15|BW_20},
    {38250, 38649,  39, 1880000, BW_5|BW_10|BW_15|BW_20},
    {38650, 39649,  40, 2300000, BW_5|BW_10|BW_15|BW_20},
    {39650, 41589,  41, 2496000, BW_5|BW_10|BW_15|BW_20},
    {41590, 43589,  42, 3400000, BW_5|BW_10|BW_15|BW_20},
    {43590, 45589,  43, 3600000, BW_5|BW_10|BW_15|BW_20},
    {45590, 46589,  44, 703000,  BW_3|BW_5|BW_10|BW_15|BW_20},
    {46590, 46789,  45, 1447000, BW_5|BW_10|BW_15|BW_20},
    {46790, 54539,  46, 5150000, BW_10|BW_20},
    {54540, 55239,  47, 5855000, BW_10|BW_20},
    {55240, 56739,  48, 3550000, BW_5|BW_10|BW_15|BW_20},
    {65536, 66435,  65, 2110000, BW_1_4|BW_3|BW_5|BW_10|BW_15|BW_20},
    {66436, 67335,  66, 2110000, BW_1_4|BW_3|BW_5|BW_10|BW_15|BW_20},
    {67336, 67535,  67, 738000,  BW_5|BW_10|BW_15|BW_20},
    {67536, 67835,  68, 753000,  BW_5|BW_10|BW_15},
    {67836, 68335,  69, 2570000, BW_5|BW_10|BW_15|BW_20},
    {68336, 68585,  70, 1995000, BW_5|BW_10|BW_15|BW_20},
    {68586, 68935,  71, 617000,  BW_5|BW_10|BW_15|BW_20},
};

#define EARFCN_TABLE_SIZE (sizeof(earfcn_table) / sizeof(earfcn_table[0]))

/* Look up band from EARFCN */
static long earfcn_to_band(long earfcn) {
    for (int i = 0; i < (int)EARFCN_TABLE_SIZE; i++) {
        if (earfcn >= earfcn_table[i].n_offs_dl && earfcn <= earfcn_table[i].n_offs_dl_hi)
            return earfcn_table[i].band;
    }
    return 0;
}

/* Compute DL center frequency in kHz from EARFCN.
 * Returns 0 if EARFCN is not in a known band. */
static long earfcn_to_freq_khz(long earfcn) {
    for (int i = 0; i < (int)EARFCN_TABLE_SIZE; i++) {
        if (earfcn >= earfcn_table[i].n_offs_dl && earfcn <= earfcn_table[i].n_offs_dl_hi)
            return earfcn_table[i].f_dl_low_khz + 100 * (earfcn - earfcn_table[i].n_offs_dl);
    }
    return 0;
}

/*
 * Parse AT^SCELLINFO response (Orbic RC400L, registered mode).
 *
 * Response format — key:value pairs on separate lines:
 *   ^SCELLINFO:
 *   CELL_ID:27439874
 *   LAC_ID:6699
 *   RSSI:71
 *   RSRP:-105
 *   RSRQ:-15
 *   BAND:4
 *   CHANNEL:2300
 *   SINR:1.0
 *   CGI:310260
 *   TX_PWR:0
 *   PCI:236
 */
static int parse_scellinfo(const char *response, char json_out[][JSON_BUF_MAX],
                           int max_obs) {
    if (max_obs < 1 || !response)
        return 0;

    /* Must contain the ^SCELLINFO marker */
    if (strstr(response, "^SCELLINFO") == NULL)
        return 0;

    /* Extract key:value pairs into a simple map */
    char *resp_copy = strdup(response);
    if (!resp_copy) return 0;

    long pci = 0, earfcn = 0, band = 0, rsrp = 0, rsrq = 0, sinr = 0;
    unsigned long cell_id = 0, tac = 0;
    const char *mcc = NULL, *mnc = NULL;   /* as-broadcast digit strings */
    char mcc_buf[8] = "", mnc_buf[8] = "";
    int h_pci = 0, h_earfcn = 0, h_band = 0, h_rsrp = 0, h_rsrq = 0, h_sinr = 0;
    int h_cell_id = 0, h_tac = 0;

    char *saveptr = NULL;
    char *line = strtok_r(resp_copy, "\n", &saveptr);
    while (line) {
        while (*line == ' ' || *line == '\r') line++;

        /* Skip the header line and non-key:value lines */
        if (*line == '^' || *line == '\0' || strchr(line, ':') == NULL) {
            line = strtok_r(NULL, "\n", &saveptr);
            continue;
        }

        char *colon = strchr(line, ':');
        *colon = '\0';
        char *key = line;
        char *val = colon + 1;
        /* Trim trailing whitespace from val */
        size_t vlen = strlen(val);
        while (vlen > 0 && (val[vlen - 1] == '\r' || val[vlen - 1] == ' '))
            val[--vlen] = '\0';

        if (strcmp(key, "PCI") == 0)
            h_pci = parse_int(val, &pci);
        else if (strcmp(key, "CHANNEL") == 0)
            h_earfcn = parse_int(val, &earfcn);
        else if (strcmp(key, "BAND") == 0)
            h_band = parse_int(val, &band);
        else if (strcmp(key, "RSRP") == 0)
            h_rsrp = parse_int(val, &rsrp);
        else if (strcmp(key, "RSRQ") == 0)
            h_rsrq = parse_int(val, &rsrq);
        else if (strcmp(key, "SINR") == 0) {
            /* SINR may be fractional (e.g. "1.0") — truncate */
            char *dot = strchr(val, '.');
            if (dot) *dot = '\0';
            h_sinr = parse_int(val, &sinr);
        } else if (strcmp(key, "CELL_ID") == 0) {
            h_cell_id = parse_int(val, (long *)&cell_id);
        } else if (strcmp(key, "LAC_ID") == 0) {
            h_tac = parse_int(val, (long *)&tac);
        } else if (strcmp(key, "CGI") == 0) {
            /* CGI is PLMN as concatenated MCC+MNC, e.g. "310260";
             * split preserving the broadcast digit count */
            if (plmn_split_mccmnc(val, mcc_buf, sizeof mcc_buf,
                                  mnc_buf, sizeof mnc_buf)) {
                mcc = mcc_buf;
                mnc = mnc_buf;
            }
        }

        line = strtok_r(NULL, "\n", &saveptr);
    }

    free(resp_copy);

    if (!h_pci && !h_earfcn)
        return 0;

    /* Derive band from EARFCN if not reported */
    if (!h_band && h_earfcn) {
        band = earfcn_to_band(earfcn);
        h_band = (band > 0);
    }

    int len = build_cell_json(json_out[0], JSON_BUF_MAX,
                              "LTE", NULL,
                              mcc, mnc,
                              cell_id, h_cell_id, pci, h_pci,
                              tac, h_tac, earfcn, h_earfcn,
                              band, h_band, 0, 0,
                              rsrp, h_rsrp, rsrq, h_rsrq,
                              sinr, h_sinr, 0, 0,
                              "serving", 1, NULL);

    /* Append DL frequency derived from EARFCN */
    if (len > 0 && h_earfcn) {
        long freq = earfcn_to_freq_khz(earfcn);
        if (freq > 0 && len > 1 && json_out[0][len - 1] == '}') {
            json_out[0][len - 1] = '\0';
            snprintf(json_out[0] + len - 1, JSON_BUF_MAX - len,
                     ",\"freq_khz\":%ld}", freq);
        }
    }

    return 1;
}

/*
 * Parse AT$QCRSRP? response (Orbic RC400L, passive multi-cell scan).
 *
 * Response format — comma-separated PCI,EARFCN,"RSRP" triplets:
 *   $QCRSRP: 310,2050,"-115.80",001,2050,"-118.80",263,2050,"-125.00",
 *            001,5230,"-096.20",310,5230,"-097.00",001,975,"-113.70",
 *            007,975,"-115.50",310,975,"-110.90"
 *
 * In COPS=2 (deregistered) mode, returns ALL visible cells across ALL bands.
 * In registered mode, returns only the serving cell.
 */
static int parse_qcrsrp(const char *response, char json_out[][JSON_BUF_MAX],
                        int max_obs) {
    if (!response || max_obs < 1)
        return 0;

    /* Find the data payload after "$QCRSRP:" */
    const char *marker = strstr(response, "$QCRSRP:");
    if (!marker)
        return 0;
    marker += 8; /* skip "$QCRSRP:" */
    while (*marker == ' ') marker++;

    /* Copy payload for destructive parsing */
    char *data = strdup(marker);
    if (!data) return 0;

    /* Strip newlines and quotes */
    char *wp = data, *rp = data;
    while (*rp) {
        if (*rp != '"' && *rp != '\n' && *rp != '\r')
            *wp++ = *rp;
        rp++;
    }
    *wp = '\0';

    /* Split on commas and process in groups of 3 */
    int obs_count = 0;
    char *fields[256];
    int nf = 0;
    char *p = data;
    while (p && nf < 256) {
        while (*p == ' ') p++;
        if (!*p) break;
        fields[nf++] = p;
        char *comma = strchr(p, ',');
        if (comma) {
            *comma = '\0';
            p = comma + 1;
        } else {
            break;
        }
    }

    for (int i = 0; i + 2 < nf && obs_count < max_obs; i += 3) {
        long pci = 0, earfcn = 0, rsrp = 0;
        int h_pci = 0, h_earfcn = 0, h_rsrp = 0;

        h_pci = parse_int(fields[i], &pci);
        h_earfcn = parse_int(fields[i + 1], &earfcn);

        /* RSRP is a float string like "-115.80" — truncate to integer */
        if (fields[i + 2] && *fields[i + 2]) {
            char *dot = strchr(fields[i + 2], '.');
            if (dot) *dot = '\0';
            h_rsrp = parse_int(fields[i + 2], &rsrp);
        }

        if (!h_pci && !h_earfcn)
            continue;

        long band = earfcn_to_band(earfcn);
        long freq = earfcn_to_freq_khz(earfcn);

        int len = build_cell_json(json_out[obs_count], JSON_BUF_MAX,
                                  "LTE", NULL,
                                  NULL, NULL,   /* neighbour: PLMN not in this line */
                                  0, 0, pci, h_pci,
                                  0, 0, earfcn, h_earfcn,
                                  band, (band > 0), 0, 0,
                                  rsrp, h_rsrp, 0, 0,
                                  0, 0, 0, 0,
                                  "observation", 0, NULL);

        /* Append DL frequency derived from EARFCN */
        if (len > 0 && freq > 0 && json_out[obs_count][len - 1] == '}') {
            json_out[obs_count][len - 1] = '\0';
            snprintf(json_out[obs_count] + len - 1, JSON_BUF_MAX - len,
                     ",\"freq_khz\":%ld}", freq);
        }

        obs_count++;
    }

    free(data);
    return obs_count;
}

/* -----------------------------------------------------------------------
 * Scan serial ports for AT-responding modems
 * ----------------------------------------------------------------------- */

/* Enumerate the modem-port candidates -- the ports the scan will OPEN.
 *
 * A candidate is written to on open (115200 raw, a flush, "AT\r\n"), so
 * this list is a list of devices we are prepared to reconfigure.
 * ttyUSB/ttyACM enter it only when sysfs says "suspected cell modem"
 * (cellat_portscan.c, CELLAT_SCAN_SUSPECTED); a GNSS receiver or USB-UART
 * bridge is never opened. Operator-named paths are admitted as named.
 *
 * The decisions live in cellat_portscan.c, not here. Which patterns are
 * searched, whether a candidate is admitted, how the list is bounded, and what
 * happens to an over-long or duplicate path are all pure string logic, and this
 * function is `static` inside the capture-framework-linked TU where no test can
 * reach it. Everything below glob(3) is driven by
 * cellat_scan_sources()/cellat_scan_add(), which test_cellat_portscan
 * exercises over a synthetic candidate list on a host with no modem attached.
 * Do not re-inline a rule here: it becomes untestable the moment you do. */
/* Append every path an operator-supplied env list names: space-separated
 * literal paths or globs (space, not colon: by-id paths contain colons).
 * cellat_scan_add_named() decides admission -- a named path is trusted except
 * where it lands under /dev/mhi_* or /dev/wwan*, where the shared classifier
 * still refuses the EDL/firmware-download channels -- and refuses a duplicate. */
static void add_named_ports(const char *list, char ports[][CELLAT_PORT_PATH_MAX],
                            int *count, int max_ports) {
    glob_t g;
    char *copy = strdup(list);
    if (!copy)
        return;
    char *saveptr = NULL, *tok;
    for (tok = strtok_r(copy, " ", &saveptr);
         tok && *count < max_ports;
         tok = strtok_r(NULL, " ", &saveptr)) {
        if (glob(tok, 0, NULL, &g) != 0)
            continue;
        for (size_t i = 0; i < g.gl_pathc && *count < max_ports; i++) {
            char resolved[PATH_MAX];
            const char *r = realpath(g.gl_pathv[i], resolved) ? resolved : NULL;
            cellat_scan_add_named(ports, count, max_ports, g.gl_pathv[i], r);
        }
        globfree(&g);
    }
    free(copy);
}

static int find_modem_ports(char ports[][CELLAT_PORT_PATH_MAX], int max_ports) {
    glob_t g;
    int count = 0;
    size_t n_sources = 0;
    const cellat_scan_source_t *sources = cellat_scan_sources(&n_sources);

    /* The ttys this scan will not open -- recorded by cellat_scan_add()
     * under the SUSPECTED sources, named by open_callback. Per scan. */
    cellat_scan_refusals_reset();

    /* CELLAT_SCAN_PORTS, the twin of celldiag's CELLDIAG_SCAN_PORTS:
     * when set and non-empty, the scan's port universe is exactly these
     * paths, instead of the source table below plus CELLAT_EXTRA_PORTS. A path
     * named twice is scanned once.
     *
     * It replaces rather than adds, for the same two reasons as celldiag's:
     *   - an operator keeping the scan off a port it must not AT-probe (a
     *     non-target modem's NMEA tty) while still addressing by IMEI;
     *   - the offline harness, which drives the real scan -- its busy-port skip,
     *     the busy rescan, the open deadline, the claim wait --
     *     against PTY fake modems. CELLAT_EXTRA_PORTS adds, so a test built on
     *     it would write "AT" into every real modem on the host.
     * An operator naming one AT node wants atport=, which skips the scan. */
    const char *only = cell_getenv("CELLAT_SCAN_PORTS");
    if (only && *only) {
        add_named_ports(only, ports, &count, max_ports);
        return count;
    }

    for (size_t s = 0; s < n_sources && count < max_ports; s++) {
        if (glob(sources[s].pattern, 0, NULL, &g) == 0) {
            for (size_t i = 0; i < g.gl_pathc && count < max_ports; i++)
                cellat_scan_add(ports, &count, max_ports, sources[s].filter,
                                g.gl_pathv[i]);
        }
        globfree(&g);
    }

    /* Optional extra paths from CELLAT_EXTRA_PORTS — space-separated list of
     * literal paths or globs. Used to add modems reachable via non-USB
     * transports (e.g. AT-over-TCP exposed as a PTY via a socat shim:
     *   socat PTY,raw,echo=0,link=/tmp/cfw3212-at TCP:<host>:5555 &
     *   CELLAT_EXTRA_PORTS=/tmp/cfw3212-at kismet -c cellat-<imei>
     * ). Space-separated chosen over colon-separated because device by-id
     * paths can contain colons (cf. RC400L SN:<hex> form). */
    const char *extra = cell_getenv("CELLAT_EXTRA_PORTS");

    /* Modems with no host driver, reached over libusb (usb= option). Only their
     * AT-speaking interfaces: the DIAG and NMEA ones are never AT-probed. */
    cell_usbport_info_t usb[CELL_USBPORT_MAX];
    int n_usb = cell_usbport_scan(usb, CELL_USBPORT_MAX);
    for (int u = 0; u < n_usb && count < max_ports; u++) {
        if (strcmp(usb[u].role, "at") != 0 && strcmp(usb[u].role, "modem") != 0)
            continue;
        cellat_scan_add(ports, &count, max_ports, CELLAT_SCAN_UNFILTERED,
                        usb[u].spec);
    }

    /* The operator named these paths, so it is not the scan's business to
     * second-guess them -- except under /dev/mhi_* and /dev/wwan*, where a
     * glob would also match the EDL channel. A duplicate is refused:
     * naming a port the scan already found is the obvious operator error, and
     * the downstream USB-id de-dup cannot catch it on a non-USB node. */
    if (extra && *extra)
        add_named_ports(extra, ports, &count, max_ports);

    return count;
}

/*
 * Get the USB device path for a ttyUSB/ttyACM port via sysfs.
 * For /dev/ttyUSB0 whose sysfs device link resolves to e.g.
 *   /sys/devices/.../usb2/2-1/2-1:1.0/ttyUSB0
 * the USB device path is the grandparent: "2-1".
 * Returns 1 on success (usb_dev filled), 0 on failure.
 */
static int get_usb_device_id(const char *port_path, char *usb_dev, size_t usb_dev_sz) {
    char sysfs_path[512];
    char resolved[512];
    const char *port_name;

    /* usb:BUS-ADDR:IF -> usb:BUS-ADDR */
    if (cell_usbport_is_spec(port_path)) {
        const char *colon = strrchr(port_path, ':');
        size_t n = colon ? (size_t)(colon - port_path) : 0;
        if (cell_usbport_parse(port_path, NULL, NULL, NULL) != 0 || n >= usb_dev_sz)
            return 0;
        memcpy(usb_dev, port_path, n);
        usb_dev[n] = '\0';
        return 1;
    }

    /* Extract port name: /dev/ttyUSB0 → ttyUSB0 */
    port_name = strrchr(port_path, '/');
    if (port_name)
        port_name++;
    else
        port_name = port_path;

    snprintf(sysfs_path, sizeof(sysfs_path), "/sys/class/tty/%s/device", port_name);

    if (realpath(sysfs_path, resolved) == NULL)
        return 0;

    /* resolved is e.g. /sys/.../2-1/2-1:1.0/ttyUSB0
     * We want the component two levels up: the USB device (e.g. "2-1").
     * Walk up: strip ttyUSB0, strip 2-1:1.0, take basename. */
    char *slash1 = strrchr(resolved, '/');  /* → /ttyUSB0 */
    if (!slash1) return 0;
    *slash1 = '\0';

    char *slash2 = strrchr(resolved, '/');  /* → /2-1:1.0 */
    if (!slash2) return 0;
    *slash2 = '\0';

    char *dev_name = strrchr(resolved, '/');  /* → /2-1 */
    if (!dev_name) return 0;
    dev_name++;

    strncpy(usb_dev, dev_name, usb_dev_sz - 1);
    usb_dev[usb_dev_sz - 1] = '\0';
    return 1;
}

/*
 * Get the USB interface number for a ttyUSB port via sysfs.
 * For a sysfs config:interface like "2-1:1.4", returns 4.
 * Returns -1 on failure.
 */
static int get_usb_interface_num(const char *port_path) {
    char sysfs_path[512];
    char resolved[512];
    const char *port_name;

    if (cell_usbport_is_spec(port_path)) {
        int ifnum;
        return cell_usbport_parse(port_path, NULL, NULL, &ifnum) == 0 ? ifnum : -1;
    }

    port_name = strrchr(port_path, '/');
    if (port_name)
        port_name++;
    else
        port_name = port_path;

    snprintf(sysfs_path, sizeof(sysfs_path), "/sys/class/tty/%s/device", port_name);

    if (realpath(sysfs_path, resolved) == NULL)
        return -1;

    /* resolved: /sys/.../2-1/2-1:1.4/ttyUSB2
     * Parent dir (2-1:1.4) contains the interface number after the dot */
    char *slash = strrchr(resolved, '/');
    if (!slash) return -1;
    *slash = '\0';

    char *iface_dir = strrchr(resolved, '/');
    if (!iface_dir) return -1;
    iface_dir++;

    /* Find the dot in "2-1:1.4" */
    char *dot = strrchr(iface_dir, '.');
    if (!dot) return -1;

    return atoi(dot + 1);
}

/*
 * Scan serial ports for modems, probing only one AT-responding port per
 * physical USB device.  Uses sysfs to group ports by parent USB device,
 * then tries each port in a group until one responds to AT commands.
 * Once a port responds for a device, remaining ports in that group are
 * skipped.  Falls back to probing all ports if sysfs is unavailable.
 *
 * Calls the callback for each identified modem.  If the callback returns
 * non-zero, scanning stops immediately (early exit for find-by-IMEI).
 */
typedef int (*modem_scan_cb)(const char *port, const char *fw,
                             const char *imei, const modemident_t *id,
                             void *ctx);

/* want_ident: also read each modem's make + model and hand them to the
 * callback; otherwise the callback's `id` is NULL. */
static int scan_modems(modem_scan_cb cb, void *ctx, int want_ident) {
    char all_ports[64][CELLAT_PORT_PATH_MAX];
    char usb_devs[64][64];
    int if_nums[64];
    int n_all = find_modem_ports(all_ports, 64);
    int found = 0;

    g_scan_stuck[0] = '\0';
    g_scan_slow[0] = '\0';
    g_scan_openstuck[0] = '\0';
    g_scan_busy = 0;

    /* Resolve USB device IDs and interface numbers for grouping/sorting */
    for (int i = 0; i < n_all; i++) {
        if (!get_usb_device_id(all_ports[i], usb_devs[i], sizeof(usb_devs[i])))
            usb_devs[i][0] = '\0';  /* No sysfs — treat as unique */
        if_nums[i] = get_usb_interface_num(all_ports[i]);
    }

    /* Sort by USB device ID, then by interface number descending.
     * AT command ports tend to be higher-numbered interfaces, so trying
     * them first minimizes timeouts on non-AT ports (DM, NMEA, etc.). */
    for (int i = 0; i < n_all - 1; i++) {
        for (int j = i + 1; j < n_all; j++) {
            int swap = 0;
            int cmp = strcmp(usb_devs[i], usb_devs[j]);
            if (cmp > 0)
                swap = 1;
            else if (cmp == 0 && if_nums[i] < if_nums[j])
                swap = 1;  /* Same device, higher interface first */
            if (swap) {
                char tmp_port[256], tmp_dev[64];
                int tmp_if;
                memcpy(tmp_port, all_ports[i], 256);
                memcpy(all_ports[i], all_ports[j], 256);
                memcpy(all_ports[j], tmp_port, 256);
                memcpy(tmp_dev, usb_devs[i], 64);
                memcpy(usb_devs[i], usb_devs[j], 64);
                memcpy(usb_devs[j], tmp_dev, 64);
                tmp_if = if_nums[i]; if_nums[i] = if_nums[j]; if_nums[j] = tmp_if;
            }
        }
    }

    /* Track which USB devices we've already identified */
    char done_devs[64][64];
    int n_done = 0;
    int busy_idx[64];
    int n_busy = 0;

    for (int i = 0; i < n_all; i++) {
        /* If this port's USB device was already identified, skip it */
        if (usb_devs[i][0]) {
            int skip = 0;
            for (int j = 0; j < n_done; j++) {
                if (strcmp(done_devs[j], usb_devs[i]) == 0) { skip = 1; break; }
            }
            if (skip)
                continue;
        }

        char fw_buf[256], imei_buf[64];
        modemident_t port_ident;
        struct timespec p0;
        clock_gettime(CLOCK_MONOTONIC, &p0);
        int busy_before = g_scan_busy;
        int ident = identify_modem(all_ports[i], fw_buf, sizeof(fw_buf),
                                   imei_buf, sizeof(imei_buf),
                                   want_ident ? &port_ident : NULL);
        long port_ms = scan_elapsed_ms(&p0);
        if (port_ms >= CELLAT_SCAN_SLOW_MS)
            scan_slow_note(all_ports[i], port_ms);
        if (g_probe_close_how != DIAG_PROBECLOSE_PLAIN)
            diag_probeclose_note(g_scan_stuck, sizeof(g_scan_stuck),
                                 all_ports[i], g_probe_close_how);
        if (g_probe_open_timed_out)
            diag_probeclose_note_label(g_scan_openstuck,
                                       sizeof(g_scan_openstuck), all_ports[i],
                                       "open-timeout");
        if (!ident) {
            if (g_scan_busy > busy_before && n_busy < 64)
                busy_idx[n_busy++] = i;   /* re-tried below by a lister */
            continue;
        }

        /* This port responded — mark its USB device as done */
        if (usb_devs[i][0] && n_done < 64) {
            strncpy(done_devs[n_done], usb_devs[i], 63);
            done_devs[n_done][63] = '\0';
            n_done++;
        }

        found++;
        if (cb && cb(all_ports[i], fw_buf, imei_buf,
                     want_ident ? &port_ident : NULL, ctx))
            return found;  /* Early exit requested by callback */
    }

    /* A lister re-tries the ports it found held (see
     * CELL_LIST_BUSY_WAIT_MS). A port whose device another port has since
     * identified is settled and dropped; one still held at the deadline is
     * skipped. */
    if (g_scan_list_wait && n_busy > 0) {
        struct timespec w0;
        clock_gettime(CLOCK_MONOTONIC, &w0);
        while (n_busy > 0 && scan_elapsed_ms(&w0) < CELL_LIST_BUSY_WAIT_MS) {
            usleep(CELL_LIST_BUSY_STEP_MS * 1000);
            int kept = 0;
            for (int k = 0; k < n_busy; k++) {
                int i = busy_idx[k];
                int settled = 0;
                for (int j = 0; usb_devs[i][0] && j < n_done; j++)
                    if (strcmp(done_devs[j], usb_devs[i]) == 0) { settled = 1; break; }
                if (settled)
                    continue;
                char fw_buf[256], imei_buf[64];
                modemident_t port_ident;
                int busy_before = g_scan_busy;
                int ident = identify_modem(all_ports[i], fw_buf, sizeof(fw_buf),
                                           imei_buf, sizeof(imei_buf),
                                           want_ident ? &port_ident : NULL);
                if (!ident) {
                    if (g_scan_busy > busy_before)
                        busy_idx[kept++] = i;
                    continue;
                }
                if (usb_devs[i][0] && n_done < 64) {
                    strncpy(done_devs[n_done], usb_devs[i], 63);
                    done_devs[n_done][63] = '\0';
                    n_done++;
                }
                found++;
                if (cb && cb(all_ports[i], fw_buf, imei_buf, want_ident ? &port_ident : NULL, ctx))
                    return found;
            }
            n_busy = kept;
        }
    }

    return found;
}

/* --- Callback context types for scan_modems --- */

typedef struct {
    const char *target_imei;
    char *path_out;
    size_t path_sz;
    char *fw_out;
    size_t fw_sz;
    char *imei_out;
    size_t imei_sz;
} find_imei_ctx_t;

static int find_imei_cb(const char *port, const char *fw,
                        const char *imei, const modemident_t *id, void *ctx) {
    (void)id;
    find_imei_ctx_t *c = (find_imei_ctx_t *)ctx;
    if (strcmp(imei, c->target_imei) != 0)
        return 0;  /* Not a match, keep scanning */

    strncpy(c->path_out, port, c->path_sz - 1);
    c->path_out[c->path_sz - 1] = '\0';
    if (c->fw_out) {
        strncpy(c->fw_out, fw, c->fw_sz - 1);
        c->fw_out[c->fw_sz - 1] = '\0';
    }
    if (c->imei_out) {
        strncpy(c->imei_out, imei, c->imei_sz - 1);
        c->imei_out[c->imei_sz - 1] = '\0';
    }
    return 1;  /* Found — stop scanning */
}

/*
 * Find a serial port with a modem matching the given IMEI.
 * Uses sysfs to skip redundant ports on multi-port USB devices.
 * If fw_out/imei_out are non-NULL, copies the firmware and IMEI strings
 * from the successful probe so the caller doesn't need to re-identify.
 * Returns 1 on match (path_out filled), 0 if not found.
 */
static int find_port_by_imei(const char *imei, char *path_out, size_t path_sz,
                             char *fw_out, size_t fw_sz,
                             char *imei_out, size_t imei_sz) {
    find_imei_ctx_t ctx = {
        .target_imei = imei,
        .path_out = path_out, .path_sz = path_sz,
        .fw_out = fw_out, .fw_sz = fw_sz,
        .imei_out = imei_out, .imei_sz = imei_sz,
    };
    /* Cleared here, because "found" is read off path_out below and the
     * caller's buffer is an uninitialized stack array. Without this, a scan
     * that matched nothing would return "found" with whatever the stack held:
     * the source fails "Failed to open <garbage>: No such file or directory"
     * instead of "not found", and the busy-port rescan -- gated on "not
     * found" -- never runs. */
    if (path_sz > 0)
        path_out[0] = '\0';
    scan_modems(find_imei_cb, &ctx, 0);
    return path_out[0] != '\0' ? 1 : 0;
}

/* -----------------------------------------------------------------------
 * Capture framework callbacks
 * ----------------------------------------------------------------------- */

/* Callback context for list_callback's scan */
typedef struct {
    cf_params_list_interface_t **interfaces;
    int n_found;
} list_ctx_t;

static int list_modem_cb(const char *port, const char *fw,
                         const char *imei, const modemident_t *id, void *ctx) {
    list_ctx_t *c = (list_ctx_t *)ctx;

    /* Skip modems that don't report an IMEI — they can't be addressed */
    if (!imei[0])
        return 0;

    c->interfaces[c->n_found] = (cf_params_list_interface_t *)
        malloc(sizeof(cf_params_list_interface_t));
    memset(c->interfaces[c->n_found], 0, sizeof(cf_params_list_interface_t));

    char iface_name[512];
    snprintf(iface_name, sizeof(iface_name), "cellat-%s", imei);
    c->interfaces[c->n_found]->interface = strdup(iface_name);

    /* The modem's make/model/firmware -- what the web UI's Sources
     * panel shows for a source that is not open yet. */
    char hw_desc[512];
    if (id != NULL)
        modemident_label(id, NULL, hw_desc, sizeof(hw_desc));
    else
        snprintf(hw_desc, sizeof(hw_desc), "%s IMEI:%s", fw, imei);
    c->interfaces[c->n_found]->hardware = strdup(hw_desc);

    c->n_found++;
    return 0;  /* Keep scanning */
}

int list_callback(kis_capture_handler_t *caph, uint32_t seqno, char *msg,
                  cf_params_list_interface_t ***interfaces) {
    /* Allocate worst-case — 32 modems max */
    *interfaces = (cf_params_list_interface_t **)
        malloc(sizeof(cf_params_list_interface_t *) * 32);

    list_ctx_t ctx = { .interfaces = *interfaces, .n_found = 0 };
    g_scan_list_wait = 1;          /* wait out a sibling lister */
    scan_modems(list_modem_cb, &ctx, 1);
    g_scan_list_wait = 0;

    return ctx.n_found;
}

/*
 * Probe callback — validates that a definition looks like a cellat IMEI source.
 * Does NOT scan serial ports (that happens in open_callback) because scanning
 * all ports can take 60+ seconds with many USB devices, which exceeds Kismet's
 * 10-second probe timeout.  We only validate the format and generate a UUID.
 */
int probe_callback(kis_capture_handler_t *caph, uint32_t seqno, char *definition,
                   char *msg, char **uuid,
                   cf_params_interface_t **ret_interface,
                   cf_params_spectrum_t **ret_spectrum) {
    char *placeholder = NULL;
    int placeholder_len;
    char *interface;
    char buf[STATUS_MAX];

    *ret_spectrum = NULL;
    *ret_interface = cf_params_interface_new();

    if ((placeholder_len = cf_parse_interface(&placeholder, definition)) <= 0) {
        snprintf(msg, STATUS_MAX, "Unable to find interface in definition");
        return 0;
    }

    interface = strndup(placeholder, placeholder_len);

    /* Extract IMEI from cellat-<IMEI> */
    const char *imei = NULL;
    if (strncmp(interface, "cellat-", 7) == 0)
        imei = interface + 7;

    /* Same rule as celldiag's probe: mute for a foreign definition,
     * because Kismet probes every binary against every source and declining
     * is the normal case; loud for a near-miss on our own prefix ("you aimed
     * this at me and got it wrong"). */
    if (imei == NULL) {
        if (strncmp(interface, "cellat", 6) == 0) {
            snprintf(msg, STATUS_MAX,
                     "'%s' is not a cellat interface - expected "
                     "cellat-<15-digit IMEI> (the IMEI selects WHICH modem; "
                     "a bare 'cellat' cannot). Run "
                     "'kismet_cap_cell_at --list' for the attached modems.",
                     interface);
        }
        free(interface);
        return 0;
    }

    if (strlen(imei) != 15) {
        snprintf(msg, STATUS_MAX,
                 "Invalid cellat definition '%s' - expected "
                 "cellat-<15-digit IMEI>, but '%s' is %zu digits",
                 interface, imei, strlen(imei));
        free(interface);
        return 0;
    }

    /* Verify all digits */
    for (int i = 0; i < 15; i++) {
        if (!isdigit(imei[i])) {
            snprintf(msg, STATUS_MAX,
                     "Invalid IMEI in '%s' - must be 15 digits", interface);
            free(interface);
            return 0;
        }
    }

    /* Hardware description is unknown until open — just report the IMEI */
    char hw_desc[512];
    snprintf(hw_desc, sizeof(hw_desc), "Cell modem IMEI:%s", imei);
    (*ret_interface)->hardware = strdup(hw_desc);

    /* UUID — stable across port renumbering, based on IMEI only */
    if ((placeholder_len = cf_find_flag(&placeholder, "uuid", definition)) > 0) {
        *uuid = strndup(placeholder, placeholder_len);
    } else {
        uint32_t hash;
        snprintf(buf, STATUS_MAX, "cellat%s", imei);
        hash = adler32_csum((unsigned char *)buf, strlen(buf));
        snprintf(buf, STATUS_MAX, "%08X-0000-0000-0000-0000%08X",
                 adler32_csum((unsigned char *)"kismet_cap_cell_at",
                              strlen("kismet_cap_cell_at")) & 0xFFFFFFFF,
                 hash & 0xFFFFFFFF);
        *uuid = strdup(buf);
    }

    free(interface);
    return 1;
}

/* Warn about source-definition keys this helper does not parse.
 *
 * The scanner lives in cellat_options.c so it is reachable by
 * test_cellat_options without linking the capture framework -- same reason
 * phy_cell_decisions exists. This is only the reporting half. */
static void warn_one_unknown_option(const char *key, void *ctx) {
    kis_capture_handler_t *caph = (kis_capture_handler_t *)ctx;
    char buf[STATUS_MAX];
    snprintf(buf, STATUS_MAX,
             "cellat: source option '%s' is not recognised and is being "
             "IGNORED. Kismet accepts unknown options silently, so this would "
             "otherwise look like it worked. Known options: atport=, "
             "strategy=, debug=, clock_anchor_sec=, bandlock=, sierracnd=, "
             "usb=, gps=, gpsport=, enabled=", key);
    cf_send_warning(caph, buf);
}

static void warn_unknown_options(kis_capture_handler_t *caph,
                                 const char *definition) {
    cellat_scan_unknown_options(definition, warn_one_unknown_option, caph);
}

/* The source's UUID: an explicit uuid= if given, else the deterministic hash of
 * "cellat<imei>". Mirrors celldiag's compose_diag_uuid.
 *
 * One function, both callers: the enabled=false path returns long before the
 * tail of open_callback, and a second copy would be free to drift. A drifted
 * copy is not cosmetic: Kismet keys a source on its UUID, so a disabled source
 * minting a different uuid than the same source enabled makes
 * disable-then-re-enable look like two sources rather than one lifecycle. */
static void cellat_compose_uuid(const char *imei, char *definition, char **uuid) {
    char *placeholder = NULL;
    int placeholder_len;
    char buf[STATUS_MAX];

    if ((placeholder_len = cf_find_flag(&placeholder, "uuid", definition)) > 0) {
        *uuid = strndup(placeholder, placeholder_len);
        return;
    }

    snprintf(buf, sizeof(buf), "cellat%s", imei);
    uint32_t hash = adler32_csum((unsigned char *)buf, strlen(buf));
    snprintf(buf, sizeof(buf), "%08X-0000-0000-0000-0000%08X",
             adler32_csum((unsigned char *)"kismet_cap_cell_at",
                          strlen("kismet_cap_cell_at")) & 0xFFFFFFFF,
             hash & 0xFFFFFFFF);
    *uuid = strdup(buf);
}

/* -----------------------------------------------------------------------
 * Band/RAT lock -- the logic is cellat_lock.c; this is the
 * AT I/O and the lifecycle. Every write here lands in the modem's NV.
 * ----------------------------------------------------------------------- */

/* One lock write. OK means the modem said OK and nothing said ERROR. */
static int cellat_lock_send(local_cell_t *local, const char *cmd,
                            char *resp, size_t resp_sz) {
    int n = at_command_t(local, cmd, resp, resp_sz, 5000);
    return n > 0 && strstr(resp, "OK") != NULL && strstr(resp, "ERROR") == NULL;
}

/* Take the modem from lock_cur to `target`. On a failed write, lock_cur keeps
 * the writes that DID land -- the teardown restores from there. Returns 1 when
 * every write landed. */
static int cellat_lock_write(local_cell_t *local, const cellat_lock_settings_t *target,
                             char *why, size_t why_sz, size_t *n_out) {
    char cmds[3][CELLAT_LOCK_CMD_MAX];
    char resp[1024];
    size_t n = cellat_lock_writes(&local->lock_cur, target, cmds, 3);
    *n_out = n;
    for (size_t i = 0; i < n; i++) {
        if (!cellat_lock_send(local, cmds[i], resp, sizeof(resp))) {
            char r1[128];
            snprintf(r1, sizeof(r1), "%s", resp);
            for (char *c = r1; *c; c++)
                if (*c == '\r' || *c == '\n')
                    *c = ' ';
            snprintf(why, why_sz, "%s -> %s", cmds[i], r1[0] ? r1 : "no answer");
            return 0;
        }
        cellat_lock_note_write(&local->lock_cur, target, cmds[i]);
    }
    return 1;
}

/* At open: probe, read the settings as found, restore any a crashed session
 * left behind, and report the channels. Never fails the open: a modem without
 * lock support simply reports no channels. */
/* A boolean source option: 1 only for an explicit true / 1. */
static int cellat_flag_true(char *definition, const char *name) {
    char *placeholder = NULL;
    int len = cf_find_flag(&placeholder, name, definition);
    return (len == 4 && strncasecmp(placeholder, "true", 4) == 0) ||
           (len == 1 && placeholder[0] == '1');
}

static void cellat_lock_open(local_cell_t *local, kis_capture_handler_t *caph,
                             const char *imei, char *definition,
                             cf_params_interface_t *iface) {
    char resp[2048], buf[STATUS_MAX], err[512];
    cellat_lock_settings_t now;

    local->lock_capable = 0;
    local->lock_channel[0] = '\0';
    local->lock_error[0] = '\0';
    local->pending_lock[0] = '\0';
    local->lock_state_written = 0;
    /* A lock is written to the modem's own configuration and outlives the
     * capture, so it is offered only when asked for. A lock a crashed session
     * left behind is still undone below. */
    local->lock_enabled = cellat_flag_true(definition, "bandlock");
    memset(&now, 0, sizeof(now));

    cellat_lock_default_state_path(imei, local->lock_state_path,
                                   sizeof(local->lock_state_path));

    /* Probed, never asserted from the vendor: only a modem that answers
     * the reads with usable values gets channels. The vendor picks which
     * command family to ask (cellat_lock.h lists the families and their
     * evidence). */
    if (local->vendor == VENDOR_QUECTEL &&
        at_command_t(local, "AT+QNWPREFCFG=\"mode_pref\"", resp, sizeof(resp), 5000) > 0 &&
        cellat_lock_parse_read(resp, "mode_pref", now.mode_pref, sizeof(now.mode_pref))) {
        now.backend = CELLAT_LOCK_QNWPREF;
        if (at_command_t(local, "AT+QNWPREFCFG=\"lte_band\"", resp, sizeof(resp), 5000) > 0)
            cellat_lock_parse_read(resp, "lte_band", now.lte_band, sizeof(now.lte_band));
        if (at_command_t(local, "AT+QNWPREFCFG=\"nr5g_band\"", resp, sizeof(resp), 5000) > 0)
            cellat_lock_parse_read(resp, "nr5g_band", now.nr5g_band, sizeof(now.nr5g_band));
    } else if (local->vendor == VENDOR_QUECTEL) {
        /* The EG25-G / EC2x family: QNWPREFCFG answers ERROR there (every
         * captured build), and AT+QCFG is the documented pair. */
        memset(&now, 0, sizeof(now));
        now.backend = CELLAT_LOCK_QCFG;
        if (at_command_t(local, "AT+QCFG=\"nwscanmode\"", resp, sizeof(resp), 5000) <= 0 ||
            !cellat_lock_parse_qcfg_scanmode(resp, now.mode_pref, sizeof(now.mode_pref)))
            return;
        if (at_command_t(local, "AT+QCFG=\"band\"", resp, sizeof(resp), 5000) <= 0 ||
            !cellat_lock_parse_qcfg_band(resp, now.lte_band, sizeof(now.lte_band)))
            return;
    } else if (local->vendor == VENDOR_SIERRA) {
        /* No password (EM9 r14); the index table is read by name. */
        now.backend = CELLAT_LOCK_SELRAT;
        if (at_command_t(local, "AT!SELRAT?", resp, sizeof(resp), 5000) <= 0 ||
            !cellat_lock_parse_selrat_read(resp, now.mode_pref, sizeof(now.mode_pref)))
            return;
        if (at_command_t(local, "AT!SELRAT=?", resp, sizeof(resp), 5000) <= 0 ||
            !cellat_lock_parse_selrat_list(resp, &now))
            return;
    } else if (local->vendor == VENDOR_TELIT) {
        /* 3GPP AT+WS46 (the LM960 offers 22,28,31; NV-stored, applies at once). */
        now.backend = CELLAT_LOCK_WS46;
        if (at_command_t(local, "AT+WS46?", resp, sizeof(resp), 5000) <= 0 ||
            !cellat_lock_parse_ws46_read(resp, now.mode_pref, sizeof(now.mode_pref)))
            return;
        if (at_command_t(local, "AT+WS46=?", resp, sizeof(resp), 5000) <= 0 ||
            !cellat_lock_parse_ws46_list(resp, &now))
            return;
    } else if (local->vendor == VENDOR_SIMCOM) {
        /* AT+CNMP: applies at once, and 2 (automatic) is the every-RAT
         * mask a SIM8202G-M2 ships with. */
        now.backend = CELLAT_LOCK_CNMP;
        if (at_command_t(local, "AT+CNMP?", resp, sizeof(resp), 5000) <= 0)
            return;
        int r = cellat_lock_parse_cnmp_read(resp, now.mode_pref, sizeof(now.mode_pref));
        if (r < 0) {
            snprintf(buf, sizeof(buf), "%s: band/RAT lock not offered: AT+CNMP reads 100 "
                     "(a RAT mix with no AT+CNMP mode), which the modem will not take "
                     "back, so a lock could not be undone. After AT+CNMP=2 (automatic, "
                     "which replaces that mix) it is lockable", local->name);
            cf_send_message(caph, buf, MSGFLAG_INFO);
            return;
        }
        if (r == 0 || at_command_t(local, "AT+CNMP=?", resp, sizeof(resp), 5000) <= 0 ||
            !cellat_lock_parse_cnmp_list(resp, &now))
            return;
    } else {
        return;
    }

    local->lock_cur = now;
    local->lock_orig = now;

    /* A state file means a session ended LOCKED (a crash, a kill -9): the
     * modem may still be locked, so the FILE is the settings as found. */
    int st = cellat_lock_state_read(local->lock_state_path, imei, now.backend,
                                    &local->lock_orig, err, sizeof(err));
    if (st < 0) {
        /* Unreadable, malformed, or another modem's: never write over it, and
         * so never lock this session -- the next lock would replace it. */
        local->lock_orig = now;
        snprintf(buf, sizeof(buf), "%s: band/RAT lock DISABLED for this session: %s",
                 local->name, err);
        cf_send_message(caph, buf, MSGFLAG_ERROR);
        return;
    }
    local->lock_capable = 1;
    if (st == 1) {
        size_t n = 0;
        local->lock_state_written = 1;
        if (cellat_lock_write(local, &local->lock_orig, err, sizeof(err), &n)) {
            cell_safe_unlink(local->lock_state_path);
            local->lock_state_written = 0;
            snprintf(buf, sizeof(buf), "%s: restored the band/RAT settings a previous "
                     "session left locked (%zu write(s)) from %s", local->name, n,
                     local->lock_state_path);
            cf_send_message(caph, buf, MSGFLAG_INFO);
        } else {
            snprintf(local->lock_error, sizeof(local->lock_error),
                     "restoring the settings from %s failed: %s", local->lock_state_path, err);
            snprintf(buf, sizeof(buf), "%s: %s -- the modem may still be locked; the "
                     "state file is kept, and AUTO or a close will try again",
                     local->name, local->lock_error);
            cf_send_message(caph, buf, MSGFLAG_ERROR);
        }
    }
    snprintf(local->lock_channel, sizeof(local->lock_channel), "%s",
             memcmp(&local->lock_cur, &local->lock_orig, sizeof(local->lock_cur)) == 0 ?
             "AUTO" : "?");

    if (!local->lock_enabled)
        return;

    char chans[CELLAT_LOCK_CHANNELS_MAX][CELLAT_LOCK_CHAN_MAX];
    size_t nc = cellat_lock_channels(&local->lock_orig, chans, CELLAT_LOCK_CHANNELS_MAX);
    iface->channels = (char **) calloc(nc, sizeof(char *));
    if (iface->channels != NULL) {
        for (size_t i = 0; i < nc; i++)
            iface->channels[i] = strdup(chans[i]);
        iface->channels_len = nc;
    }
    iface->chanset = strdup("AUTO");
}

/* Capture thread: put `channel` in force (AUTO = the settings as found). */
static void cellat_lock_apply(local_cell_t *local, kis_capture_handler_t *caph,
                              const char *channel) {
    char buf[STATUS_MAX], err[512];
    cellat_lock_settings_t target;

    if (cellat_lock_target(&local->lock_orig, channel, &target, err, sizeof(err)) != 0) {
        snprintf(local->lock_error, sizeof(local->lock_error), "%s", err);
        snprintf(buf, sizeof(buf), "%s: %s", local->name, err);
        cf_send_message(caph, buf, MSGFLAG_ERROR);
        return;
    }
    int to_orig = memcmp(&target, &local->lock_orig, sizeof(target)) == 0;
    char cmds[3][CELLAT_LOCK_CMD_MAX];
    size_t pending = cellat_lock_writes(&local->lock_cur, &target, cmds, 3);

    /* The settings as found go to disk before the first write, or the lock
     * is not written at all: a lock that cannot be undone after a crash is
     * never applied. */
    if (pending > 0 && !to_orig && !local->lock_state_written) {
        if (cellat_lock_state_write(local->lock_state_path, local->modem_imei,
                                    &local->lock_orig) != 0) {
            snprintf(local->lock_error, sizeof(local->lock_error),
                     "not locking to %s: cannot save the settings as found to %s (%s)",
                     channel, local->lock_state_path, strerror(errno));
            snprintf(buf, sizeof(buf), "%s: %s", local->name, local->lock_error);
            cf_send_message(caph, buf, MSGFLAG_ERROR);
            return;
        }
        local->lock_state_written = 1;
    }

    size_t n = 0;
    if (!cellat_lock_write(local, &target, err, sizeof(err), &n)) {
        snprintf(local->lock_error, sizeof(local->lock_error), "lock to %s failed: %s",
                 channel, err);
        snprintf(buf, sizeof(buf), "%s: %s", local->name, local->lock_error);
        cf_send_message(caph, buf, MSGFLAG_ERROR);
        return;
    }
    snprintf(local->lock_channel, sizeof(local->lock_channel), "%s",
             to_orig ? "AUTO" : channel);
    local->lock_error[0] = '\0';
    if (to_orig && local->lock_state_written) {
        cell_safe_unlink(local->lock_state_path);
        local->lock_state_written = 0;
    }
    snprintf(buf, sizeof(buf), "%s: band/RAT lock now %s (%zu write(s))", local->name,
             to_orig ? "AUTO (the settings as found)" : channel, n);
    cf_send_message(caph, buf, MSGFLAG_INFO);
}

int open_callback(kis_capture_handler_t *caph, uint32_t seqno, char *definition,
                  char *msg, uint32_t *dlt, char **uuid,
                  cf_params_interface_t **ret_interface,
                  cf_params_spectrum_t **ret_spectrum) {
    local_cell_t *local = (local_cell_t *)caph->userdata;
    char *placeholder = NULL;
    int placeholder_len;
    char *interface;
    char device_path[512];
    char fw_buf[256], imei_buf[64];
    char resp[4096];
    char buf[STATUS_MAX];

    /* Record the handler so the AT-exchange seam can emit RawAT rows into the
     * kismetdb for the life of this capture. Set before any at_command_t
     * below, so every bring-up exchange (CPIN/CEREG/COPS/CIMI/ICCID/...) is
     * captured too, one RawAT row per exchange. */
    local->caph = caph;

    *ret_spectrum = NULL;
    *ret_interface = cf_params_interface_new();

    /* Before anything else: name any option we are about to ignore. */
    warn_unknown_options(caph, definition);

    if ((placeholder_len = cf_parse_interface(&placeholder, definition)) <= 0) {
        snprintf(msg, STATUS_MAX, "Unable to find interface in definition");
        return -1;
    }

    interface = strndup(placeholder, placeholder_len);

    /* Extract IMEI from cellat-<IMEI> */
    const char *imei = NULL;
    if (strncmp(interface, "cellat-", 7) == 0)
        imei = interface + 7;

    if (imei == NULL || strlen(imei) != 15) {
        snprintf(msg, STATUS_MAX, "Invalid cell modem definition '%s' — expected cellat-<15-digit IMEI>",
                 interface);
        free(interface);
        return -1;
    }

    /* Verify all digits */
    for (int i = 0; i < 15; i++) {
        if (!isdigit(imei[i])) {
            snprintf(msg, STATUS_MAX, "Invalid IMEI in '%s' — must be 15 digits", interface);
            free(interface);
            return -1;
        }
    }

    /* Save IMEI before freeing interface string */
    char imei_def[16];
    strncpy(imei_def, imei, 15);
    imei_def[15] = '\0';

    /* strategy=. Resolved here, before enabled= and before any port
     * is touched, because an unknown profile is a malformed definition and the
     * rule for those is the IMEI shape check's: refuse before I/O, rather than
     * pay for a full modem probe and then silently run the wrong survey.
     * Checked on the enabled=false path too: a disabled source
     * whose definition is broken would otherwise fail only on re-enable, far
     * from the edit that broke it. */
    local->strategy = cellat_strategy_default();
    /* `> 0` alone would let an EMPTY `strategy=` through as the default:
     * cf_find_flag reports found-but-empty as length 0 with a non-NULL value
     * pointer, and not-found as a NULL pointer. Empty is a malformed value,
     * not an absent one. */
    placeholder = NULL;
    placeholder_len = cf_find_flag(&placeholder, "strategy", definition);
    if (placeholder != NULL && placeholder_len >= 0) {
        char *strat = strndup(placeholder, placeholder_len);
        char why[STATUS_MAX];
        if (!cellat_strategy_parse(strat ? strat : "", &local->strategy,
                                   why, sizeof(why))) {
            snprintf(msg, STATUS_MAX, "cellat-%s: %s", imei_def, why);
            free(strat);
            free(interface);
            return -1;
        }
        free(strat);
    }

    /* enabled=true|false -- lifecycle parity with celldiag.
     *
     * A modem is normally captured by a paired celldiag-<imei> + cellat-<imei>,
     * so the natural operator action for "stop capturing from this modem" is
     * enabled=false on both. If only celldiag honoured it, cellat would stay
     * fully live while the operator believed the modem was disabled.
     *
     * Same semantics as celldiag: registered so the source still lists, but no
     * device I/O at all. We do not even AT-probe for model/firmware -- "does not
     * open until enabled" has to mean the port is untouched, or a disabled
     * source still contends for it against whatever else the operator is
     * running on that modem. The capture thread idles until the server reaps
     * us; runtime re-enable is a fresh open, exactly as on the DIAG side. */
    if ((placeholder_len = cf_find_flag(&placeholder, "enabled", definition)) > 0) {
        char *v = strndup(placeholder, placeholder_len);
        char why[STATUS_MAX];
        int on = 1;
        if (!cellat_bool_option_parse("enabled", v ? v : "", &on,
                                      why, sizeof(why))) {
            snprintf(msg, STATUS_MAX, "%s", why);
            free(v);
            free(interface);
            return -1;
        }
        free(v);
        local->disabled = !on;
    }

    if (local->disabled) {
        char hw_desc[512];

        local->serial_fd = -1;
        local->device_path = strdup("");
        local->modem_imei = strdup(imei_def);
        local->modem_firmware = strdup("disabled");
        local->modem_model = strdup("AT disabled");

        snprintf(hw_desc, sizeof(hw_desc), "%s IMEI:%s",
                 local->modem_model, imei_def);
        local->name = strdup(hw_desc);
        (*ret_interface)->capif = strdup("");
        (*ret_interface)->hardware = strdup(hw_desc);

        cellat_compose_uuid(imei_def, definition, uuid);

        snprintf(msg, STATUS_MAX,
                 "Cell AT source cellat-%s registered but DISABLED "
                 "(enabled=false) - no serial port opened, no AT sent; "
                 "re-enable to start capture", imei_def);
        cf_send_message(caph, msg, MSGFLAG_INFO);

        free(interface);
        return 1;
    }

    /* usb=auto|force|off -- modems reached over libusb. auto (the default)
     * scans the ones no host driver has; force also takes a modem from its host
     * driver (option, qcserial) while the source runs. */
    if ((placeholder_len = cf_find_flag(&placeholder, "usb", definition)) > 0) {
        char *v = strndup(placeholder, placeholder_len);
        int mode = cell_usbport_mode_parse(v);
        if (mode < 0) {
            snprintf(msg, STATUS_MAX, "cellat: usb=%s is not auto, force or off",
                     v ? v : "");
            free(v);
            free(interface);
            return -1;
        }
        free(v);
        cell_usbport_set_mode((cell_usb_mode_t)mode);
    }

    /* atport=<path> -- explicit AT port, skipping auto-detect. Mirrors
     * celldiag's diagport=.
     *
     * The IMEI check is not optional. Auto-detect's whole safety property is
     * that it matches on IMEI; an override that just opened the path would
     * discard it, and a typo'd port would survey the wrong modem while
     * reporting the requested one's IMEI in every observation's prov block.
     * So the override still identifies the modem on the named port and fails
     * loudly on a mismatch. */
    char atport_override[512] = "";
    if ((placeholder_len = cf_find_flag(&placeholder, "atport", definition)) > 0) {
        char *v = strndup(placeholder, placeholder_len);
        if (v) {
            strncpy(atport_override, v, sizeof(atport_override) - 1);
            free(v);
        }
    }

    if (atport_override[0]) {
        if (!identify_modem(atport_override, fw_buf, sizeof(fw_buf),
                            imei_buf, sizeof(imei_buf), NULL)) {
            snprintf(msg, STATUS_MAX,
                     "atport=%s did not respond to AT identification — it is "
                     "probably not this modem's AT port (celldiag's DIAG port "
                     "and the NMEA port both fail here)", atport_override);
            free(interface);
            return -1;
        }
        if (strcmp(imei_buf, imei_def) != 0) {
            snprintf(msg, STATUS_MAX,
                     "atport=%s is a modem with IMEI %s, but this source asked "
                     "for IMEI %s — refusing to survey the wrong modem. Drop "
                     "atport= to auto-detect by IMEI",
                     atport_override, imei_buf, imei_def);
            free(interface);
            return -1;
        }
        snprintf(device_path, sizeof(device_path), "%s", atport_override);
        snprintf(buf, STATUS_MAX, "cellat using explicit atport=%s (IMEI %s "
                 "verified); auto-detect skipped", device_path, imei_buf);
        cf_send_message(caph, buf, MSGFLAG_INFO);
    } else {
        /* Resolve IMEI to serial port — also retrieves fw/imei in one pass */
        int found_port = find_port_by_imei(imei_def, device_path, sizeof(device_path),
                                           fw_buf, sizeof(fw_buf),
                                           imei_buf, sizeof(imei_buf));
        /* The ttys the scan did not open at all: not suspected cell modems by
         * their sysfs driver / vendor id, or a modem's known DIAG /
         * NMEA interface (labelled e.g. "if01 NMEA"). Named with the evidence
         * and the escape hatch, so a modem behind a USB-UART bridge -- refused
         * as the bridge it enumerates as -- is findable from this message. */
        if (cellat_scan_refusals()[0]) {
            snprintf(buf, STATUS_MAX, "cellat AT scan: not probed (not suspected "
                     "cell modems, or a modem's known non-AT port): %s (name one "
                     "in CELLAT_EXTRA_PORTS to probe it)", cellat_scan_refusals());
            cf_send_message(caph, buf, MSGFLAG_INFO);
        }
        /* Name any port that never took its probe. Its release costs ~150 ms
         * instead of 30 s, which is exactly why nothing else would ever
         * mention it. */
        if (g_scan_stuck[0]) {
            snprintf(buf, STATUS_MAX, "cellat AT scan: port(s) never took the "
                     "probe, closed without waiting out closing_wait: %s",
                     g_scan_stuck);
            cf_send_message(caph, buf, MSGFLAG_INFO);
        }
        if (g_scan_slow[0]) {
            snprintf(buf, STATUS_MAX, "cellat AT scan slow ports: %s", g_scan_slow);
            cf_send_message(caph, buf, MSGFLAG_INFO);
        }
        /* A port still closing after a sibling's probe: its open() gave
         * up at the deadline instead of blocking ~30 s. */
        if (g_scan_openstuck[0]) {
            snprintf(buf, STATUS_MAX, "cellat AT scan: port(s) still closing "
                     "after another probe, open() gave up at %d ms and skipped "
                     "them: %s", DIAG_PROBE_OPEN_DEADLINE_MS, g_scan_openstuck);
            cf_send_message(caph, buf, MSGFLAG_INFO);
        }
        /* A concurrent multi-source open scans the same ports at the same time,
         * and a port a sibling's scan is probing is skipped -- its claim is
         * taken, and sharing it would split the reply bytes. A USB modem
         * survives that by answering on a sibling AT port; a modem with one AT
         * node (/dev/mhi_DUN on a PCIe RM520N-GL) does not: its only port is
         * the busy one, and the source would fail "not found" and wait out a
         * 5-12 s Kismet retry. So when -- and only
         * when -- the pass skipped a busy port, rescan once after a short
         * pause, jittered by pid so siblings that collided do not collide
         * again. One rescan bounds the worst case well inside Kismet's 30 s
         * command timeout. */
        if (!found_port && g_scan_busy > 0) {
            int skipped = g_scan_busy;
            usleep((useconds_t)(250 + (getpid() % 8) * 75) * 1000);
            found_port = find_port_by_imei(imei_def, device_path, sizeof(device_path),
                                           fw_buf, sizeof(fw_buf),
                                           imei_buf, sizeof(imei_buf));
            snprintf(buf, STATUS_MAX, "cellat AT scan: IMEI %s not found while "
                     "%d port(s) were held by another process; rescanned: %s",
                     imei_def, skipped, found_port ? device_path : "still not found");
            cf_send_message(caph, buf, MSGFLAG_INFO);
            if (g_scan_slow[0]) {
                snprintf(buf, STATUS_MAX, "cellat AT rescan slow ports: %s", g_scan_slow);
                cf_send_message(caph, buf, MSGFLAG_INFO);
            }
            if (g_scan_openstuck[0]) {
                snprintf(buf, STATUS_MAX, "cellat AT rescan: port(s) still "
                         "closing after another probe, open() gave up at %d ms "
                         "and skipped them: %s", DIAG_PROBE_OPEN_DEADLINE_MS,
                         g_scan_openstuck);
                cf_send_message(caph, buf, MSGFLAG_INFO);
            }
        }
        if (!found_port) {
            snprintf(msg, STATUS_MAX, "Modem IMEI %s not found on any serial port", imei_def);
            free(interface);
            return -1;
        }
    }

    free(interface);

    /* Open serial for ongoing use.
     *
     * Not a plain serial_open(). The scan above released the port it
     * identified (probe_release), and between that close and this open a
     * sibling source's scan can take the port's claim to probe it. A plain
     * open would then be refused EWOULDBLOCK and the source would fail its
     * launch with "Failed to open /dev/ttyUSB5: Resource temporarily
     * unavailable". A sibling's probe
     * holds the claim for one identify dialogue, so a busy claim is waited out
     * for a bounded time; any other open failure is immediate. A
     * claim held past the budget is a real conflict (a second source on this
     * modem) and still fails. */
    long claim_waited_ms = 0;
    local->serial_fd = serial_open_claim(device_path, 115200,
                                         SERIAL_CLAIM_WAIT_MS, &claim_waited_ms);
    if (local->serial_fd < 0) {
        int open_errno = errno;
        if (open_errno == EWOULDBLOCK)
            snprintf(msg, STATUS_MAX, "Failed to open %s: %s (held by another "
                     "process for the whole %ld ms wait)", device_path,
                     strerror(open_errno), claim_waited_ms);
        else if (open_errno == EBUSY && cell_usbport_is_spec(device_path))
            snprintf(msg, STATUS_MAX, "Failed to open %s: a host driver has "
                     "this interface (usb=force takes it from the driver)",
                     device_path);
        else
            snprintf(msg, STATUS_MAX, "Failed to open %s: %s",
                     device_path, strerror(open_errno));
        return -1;
    }
    if (claim_waited_ms > 0) {
        snprintf(buf, STATUS_MAX, "cellat: %s was held by another process when "
                 "the capture opened it (a sibling source's probe); took it "
                 "after %ld ms", device_path, claim_waited_ms);
        cf_send_message(caph, buf, MSGFLAG_INFO);
    }

    local->device_path = strdup(device_path);
    local->modem_firmware = strdup(fw_buf);
    local->modem_imei = strdup(imei_buf);

    /* Vouch at once with what the scan just verified on this port (IMEI
     * + firmware). The full record, with make and model, replaces it when the
     * identity read below completes -- but that is seconds away (vendor and
     * capability probes), and a paired celldiag opening at the same moment
     * gets one rescan 250-775 ms after meeting our claim. Publishing
     * only at the end would leave that race to Kismet's 5 s reopen. */
    {
        modemident_t early;
        modemident_clear(&early);
        snprintf(early.imei, sizeof(early.imei), "%s", imei_buf);
        snprintf(early.firmware, sizeof(early.firmware), "%s", fw_buf);
        (void)identvouch_publish(device_path, &early);
    }

    /* Detect vendor and capabilities */
    local->has_qeng = 0;
    local->has_qscan = 0;
    local->has_rfsts = 0;
    local->has_servinfo = 0;
    local->has_moni = 0;
    local->has_csurvc = 0;

    /* The identity record starts here -- detect_vendor's AT+CGMI is the
     * make, so it is kept rather than asked for twice. */
    long cgmi_ms = 0;
    modemident_clear(&local->ident);
    snprintf(local->ident.imei, sizeof(local->ident.imei), "%s", imei_buf);
    snprintf(local->ident.firmware, sizeof(local->ident.firmware), "%s", fw_buf);
    local->vendor = detect_vendor(local->serial_fd, local->ident.make,
                                  sizeof(local->ident.make), &cgmi_ms);

    if (local->vendor == VENDOR_QUECTEL) {
        /* Probed, not asserted from the vendor, like every other branch.
         * `has_qeng` is what the no-survey-command refusal below tests, so
         * assuming it for any modem that identifies as Quectel would let one
         * open, report a healthy source and sit at obs=0 forever --
         * indistinguishable from "no cells in range". `AT+QENG` is engineering
         * mode, and a carrier build or a locked unit can refuse it while
         * answering AT+CGMI "Quectel" perfectly.
         *
         * Cost: one AT round-trip at open, which every sibling branch already
         * pays. Vendor detection still earns its keep -- it picks which
         * command to try first, which keeps this to a single probe instead of
         * six. */
        int qn = at_command_t(local, "AT+QENG=\"servingcell\"",
                              resp, sizeof(resp), 5000);
        if (qn > 0 && strstr(resp, "+QENG:"))
            local->has_qeng = 1;

        /* Probed, like QENG above, rather than matched on a firmware prefix
         * (RM500Q / RM502Q), which would leave out other QSCAN-capable parts
         * such as the RM520N-GL ("+QSCAN: (1-3)"). The test form lists the
         * modes and scans nothing. */
        qn = at_command_t(local, "AT+QSCAN=?", resp, sizeof(resp), 3000);
        local->has_qscan = qscan_probe_supported(qn, resp);

        /* Build model string from firmware prefix */
        char model_buf[64];
        /* Extract model: everything before the first non-alnum after letters+digits */
        int mi = 0;
        while (fw_buf[mi] && mi < 20 &&
               (isalnum(fw_buf[mi]) || fw_buf[mi] == '-'))
            mi++;
        snprintf(model_buf, sizeof(model_buf), "Quectel %.*s", mi, fw_buf);
        local->modem_model = strdup(model_buf);

    } else if (local->vendor == VENDOR_TELIT) {
        /* Probe Telit-specific commands */
        int n = at_command_t(local,"AT#RFSTS",
                           resp, sizeof(resp), 5000);
        /* `#RFSTS:` = supported with a cell to report; a bare `OK` (no ERROR)
         * = supported but currently empty (unregistered). Both set the
         * capability -- the poll loop finds cells once the modem registers.
         * Only a real ERROR leaves it unset. */
        if (n > 0 && (strstr(resp, "#RFSTS:") || at_response_ok(resp)))
            local->has_rfsts = 1;

        n = at_command_t(local,"AT#SERVINFO",
                       resp, sizeof(resp), 5000);
        if (n > 0 && (strstr(resp, "#SERVINFO:") || at_response_ok(resp)))
            local->has_servinfo = 1;

        /* Probe AT#MONI — set to mode 0 and query */
        n = at_command_t(local,"AT#MONI=0",
                       resp, sizeof(resp), 3000);
        if (n >= 0 && strstr(resp, "OK")) {
            n = at_command_t(local,"AT#MONI",
                           resp, sizeof(resp), 3000);
            if (n > 0 && (strstr(resp, "#MONI:") || at_response_ok(resp)))
                local->has_moni = 1;
        }

        /* Probe AT#CSURVC — just check if the command is recognized
         * (don't run a full scan during probe, that takes 30-60s) */
        n = at_command_t(local,"AT#CSURVC=?",
                       resp, sizeof(resp), 3000);
        if (n >= 0 && strstr(resp, "OK"))
            local->has_csurvc = 1;

        /* Build model string from AT+CGMM if available */
        char model_resp[256];
        n = at_command_t(local,"AT+CGMM", model_resp, sizeof(model_resp), 3000);
        if (n > 0) {
            char *saveptr2 = NULL;
            char *mline = strtok_r(model_resp, "\n", &saveptr2);
            while (mline) {
                while (*mline == ' ') mline++;
                if (*mline && strcmp(mline, "OK") != 0 && strncmp(mline, "+CME", 4) != 0) {
                    char mbuf[64];
                    snprintf(mbuf, sizeof(mbuf), "Telit %s", mline);
                    local->modem_model = strdup(mbuf);
                    break;
                }
                mline = strtok_r(NULL, "\n", &saveptr2);
            }
        }
        if (!local->modem_model)
            local->modem_model = strdup("Telit");

    } else if (local->vendor == VENDOR_SIERRA) {
        /* Unlock the advanced AT commands with the default password, only
         * when asked: it changes the modem's access level, and stays changed. */
        if (cellat_flag_true(definition, "sierracnd"))
            at_command_t(local,"AT!ENTERCND=\"A710\"",
                       resp, sizeof(resp), 3000);

        /* Probe Sierra-specific commands */
        int n = at_command_t(local,"AT!GSTATUS?",
                           resp, sizeof(resp), 5000);
        if (n > 0 && strstr(resp, "!GSTATUS:"))
            local->has_gstatus = 1;

        n = at_command_t(local,"AT!LTEINFO?",
                       resp, sizeof(resp), 5000);
        if (n > 0 && strstr(resp, "!LTEINFO:") && !strstr(resp, "Not Available"))
            local->has_lteinfo = 1;

        n = at_command_t(local,"AT!NRINFO?",
                       resp, sizeof(resp), 5000);
        if (n > 0 && strstr(resp, "!NRINFO:"))
            local->has_nrinfo = 1;

        /* Build model string from AT+CGMM */
        char model_resp[256];
        n = at_command_t(local,"AT+CGMM", model_resp, sizeof(model_resp), 3000);
        if (n > 0) {
            char *saveptr2 = NULL;
            char *mline = strtok_r(model_resp, "\n", &saveptr2);
            while (mline) {
                while (*mline == ' ') mline++;
                if (*mline && strcmp(mline, "OK") != 0 && strncmp(mline, "+CME", 4) != 0) {
                    char mbuf[64];
                    snprintf(mbuf, sizeof(mbuf), "Sierra %s", mline);
                    local->modem_model = strdup(mbuf);
                    break;
                }
                mline = strtok_r(NULL, "\n", &saveptr2);
            }
        }
        if (!local->modem_model)
            local->modem_model = strdup("Sierra");

    } else if (local->vendor == VENDOR_ORBIC) {
        /* Probe Orbic/Qualcomm MDM9607 commands */
        int n = at_command_t(local,"AT^SCELLINFO",
                           resp, sizeof(resp), 5000);
        if (n > 0 && strstr(resp, "^SCELLINFO"))
            local->has_scellinfo = 1;

        n = at_command_t(local,"AT$QCRSRP?",
                       resp, sizeof(resp), 5000);
        if (n > 0 && strstr(resp, "$QCRSRP"))
            local->has_qcrsrp = 1;

        /* Build model string from AT+CGMM */
        char model_resp[256];
        n = at_command_t(local,"AT+CGMM", model_resp, sizeof(model_resp), 3000);
        if (n > 0) {
            char *saveptr2 = NULL;
            char *mline = strtok_r(model_resp, "\n", &saveptr2);
            while (mline) {
                while (*mline == ' ') mline++;
                if (*mline && strcmp(mline, "OK") != 0 && strncmp(mline, "+CME", 4) != 0) {
                    char mbuf[64];
                    snprintf(mbuf, sizeof(mbuf), "Orbic %s", mline);
                    local->modem_model = strdup(mbuf);
                    break;
                }
                mline = strtok_r(NULL, "\n", &saveptr2);
            }
        }
        if (!local->modem_model)
            local->modem_model = strdup("Orbic");

    } else if (local->vendor == VENDOR_SIMCOM) {
        /* SIMCom's serving-cell command is AT+CPSI? across the whole line —
         * SIM7070/7080/7090 (LPWA), SIM7500/7600 (LTE) and SIM82XX/83XX (5G)
         * all use it, with the same field layout per RAT.
         *
         * Probed rather than assumed: SIMCom's range includes parts this
         * driver has never seen, and a probe that costs one AT round trip is
         * cheaper than a source that opens and then reports nothing.
         *
         * `NO SERVICE` is a successful probe. The command is supported; the
         * modem simply is not camped. Requiring a decodable cell here would
         * make the capability depend on the weather. */
        int n = at_command_t(local, "AT+CPSI?", resp, sizeof(resp), 5000);
        if (n > 0 && strstr(resp, "+CPSI:"))
            local->has_cpsi = 1;

        char model_buf[64];
        snprintf(model_buf, sizeof(model_buf), "SIMCom %.40s", fw_buf);
        local->modem_model = strdup(model_buf);

    } else {
        /* Unknown vendor — try probing for common commands */
        local->modem_model = strdup(fw_buf);

        int n = at_command_t(local,"AT+QENG=\"servingcell\"",
                           resp, sizeof(resp), 5000);
        if (n > 0 && strstr(resp, "+QENG:")) {
            local->has_qeng = 1;
            local->vendor = VENDOR_QUECTEL;
        }

        if (!local->has_qeng) {
            n = at_command_t(local,"AT#RFSTS",
                           resp, sizeof(resp), 5000);
            if (n > 0 && strstr(resp, "#RFSTS:")) {
                local->has_rfsts = 1;
                local->vendor = VENDOR_TELIT;
            }
        }

        if (!local->has_qeng && !local->has_rfsts) {
            /* Try Sierra as last resort */
            n = at_command_t(local,"AT!GSTATUS?",
                           resp, sizeof(resp), 5000);
            if (n > 0 && strstr(resp, "!GSTATUS:")) {
                local->has_gstatus = 1;
                local->vendor = VENDOR_SIERRA;
            }
        }

        /* SIMCom AT+CPSI?, for a unit whose AT+CGMI answered something this
         * driver does not recognise. Placed in the unknown-vendor
         * fallback as well as behind VENDOR_SIMCOM because the two failures
         * are independent: a new SIMCom-derived ODM can miss the vendor match
         * and still speak +CPSI?. */
        if (!local->has_qeng && !local->has_rfsts && !local->has_gstatus) {
            n = at_command_t(local, "AT+CPSI?", resp, sizeof(resp), 5000);
            if (n > 0 && strstr(resp, "+CPSI:")) {
                local->has_cpsi = 1;
                local->vendor = VENDOR_SIMCOM;
            }
        }

        /* Try Orbic/Qualcomm MDM9607 commands */
        if (!local->has_qeng && !local->has_rfsts && !local->has_gstatus &&
            !local->has_cpsi) {
            n = at_command_t(local,"AT^SCELLINFO",
                           resp, sizeof(resp), 5000);
            if (n > 0 && strstr(resp, "^SCELLINFO")) {
                local->has_scellinfo = 1;
                local->vendor = VENDOR_ORBIC;
            }
            n = at_command_t(local,"AT$QCRSRP?",
                           resp, sizeof(resp), 5000);
            if (n > 0 && strstr(resp, "$QCRSRP")) {
                local->has_qcrsrp = 1;
                if (local->vendor == VENDOR_UNKNOWN)
                    local->vendor = VENDOR_ORBIC;
            }
        }
    }

    if (!local->has_qeng && !local->has_rfsts && !local->has_servinfo &&
        !local->has_gstatus && !local->has_scellinfo && !local->has_qcrsrp &&
        !local->has_cpsi) {
        /* This refusal is why a capability gap is not silent: rather than
         * open and sit at zero observations forever, open_callback fails here
         * with a named message. It names the vendor the modem gave and the
         * probes that were tried, so the operator has a next step rather than
         * a bare "no known commands". */
        snprintf(msg, STATUS_MAX,
                 "Modem on %s does not support any known cell survey command. "
                 "Vendor detected: %s. Probed: %s — all refused. "
                 "Firmware string: '%s'",
                 device_path, vendor_name(local->vendor),
                 vendor_probed_cmds(local->vendor), fw_buf);
        identvouch_withdraw(device_path);   /* no longer held */
        serial_close(&local->serial_fd);
        return -1;
    }

    /* Disable echo */
    at_command_t(local,"ATE0", resp, sizeof(resp), 2000);

    /* The model, read on the port this source holds (the make came
     * from detect_vendor above). Through at_command_t, so the exchange is also
     * a RawAT row: the container keeps the raw answer beside the record. */
    if (at_info_command_t(local, "AT+CGMM", resp, sizeof(resp),
                          (int)modemident_followup_ms(cgmi_ms, local->ident.make[0] != '\0')) > 0)
        modemident_value(resp, local->ident.model, sizeof(local->ident.model));

    /* Vouch for what was just read, on the port this source now holds
     * for its whole capture. A paired celldiag source maps IMEI -> DIAG port by
     * AT-probing this modem's ports, and our claim makes this one unprobeable;
     * on a single-AT-port modem that would make its DIAG capture impossible for
     * as long as we run. Withdrawn at teardown. Best effort: a failed write leaves
     * the sibling's scan exactly as it was. */
    (void)identvouch_publish(device_path, &local->ident);

    /* Parse debug option.
     * Default: off.  Debug mode reads the IMSI and ICCID, so it is opt-in:
     * KISMET_CELLAT_DEBUG=1 (or true) in the environment, or debug=true in the
     * source definition.  The definition overrides the environment. */
    local->debug = 0;
    const char *debug_env = cell_getenv("KISMET_CELLAT_DEBUG");
    if (debug_env && (strcmp(debug_env, "1") == 0 || strcmp(debug_env, "true") == 0))
        local->debug = 1;
    if ((placeholder_len = cf_find_flag(&placeholder, "debug", definition)) > 0) {
        char *dbg = strndup(placeholder, placeholder_len);
        if (strcmp(dbg, "false") == 0 || strcmp(dbg, "0") == 0)
            local->debug = 0;
        else if (strcmp(dbg, "true") == 0 || strcmp(dbg, "1") == 0)
            local->debug = 1;
        free(dbg);
    }

    /* gps=<name> / gpsport=<path>: read the modem's GNSS (cellat_gnss.h) */
    local->gnss_wanted = 0;
    local->gnss_port_opt[0] = '\0';
    if ((placeholder_len = cf_find_flag(&placeholder, "gps", definition)) > 0)
        local->gnss_wanted = cellat_gnss_wanted(placeholder, (size_t)placeholder_len);
    if ((placeholder_len = cf_find_flag(&placeholder, "gpsport", definition)) > 0 &&
        (size_t)placeholder_len < sizeof(local->gnss_port_opt)) {
        memcpy(local->gnss_port_opt, placeholder, (size_t)placeholder_len);
        local->gnss_port_opt[placeholder_len] = '\0';
    }

    /* Scan intervals come from the profile table (cellat_options.c), which
     * was resolved -- and validated -- at the top of open_callback. */
    local->serving_interval_ms = local->strategy->serving_ms;
    local->neighbor_interval_ms = local->strategy->neighbor_ms;
    local->fullscan_interval_ms = local->strategy->fullscan_ms;

    /* Build interface info */
    char hw_desc[512];
    snprintf(hw_desc, sizeof(hw_desc), "%s IMEI:%s", local->modem_model, imei_buf);

    local->name = strdup(hw_desc);

    /* Parse clock_anchor_sec= -- periodic cadence for the host<->modem-RTC
     * ClockAnchor. Default 30s (shared with celldiag);
     * `0` disables the periodic tick, but the mandatory start and end anchors
     * still fire. Registered in cellat_options.c so an unrecognised spelling
     * warns rather than silently doing nothing. */
    local->clock_anchor_interval_ms = 30000;
    if ((placeholder_len = cf_find_flag(&placeholder, "clock_anchor_sec", definition)) > 0) {
        char *cav = strndup(placeholder, placeholder_len);
        if (cav != NULL) {
            char *endp = NULL;
            long secs = strtol(cav, &endp, 10);
            if (endp != cav && *endp == '\0' && secs >= 0) {
                local->clock_anchor_interval_ms = (unsigned long)secs * 1000UL;
            } else {
                snprintf(buf, sizeof(buf),
                         "%s ignoring invalid clock_anchor_sec='%s' (keeping %lus)",
                         local->name ? local->name : "cellat", cav,
                         local->clock_anchor_interval_ms / 1000);
                cf_send_message(caph, buf, MSGFLAG_ERROR);
            }
            free(cav);
        }
    }

    /* Band/RAT lock presets as this source's channels. */
    cellat_lock_open(local, caph, imei_def, definition, *ret_interface);

    (*ret_interface)->capif = strdup(device_path);
    /* The hardware Kismet records for this source is the modem's own
     * make / model / firmware / IMEI. local->name keeps its "<model> IMEI:"
     * shape for the message bus. */
    {
        char ident_label[512];
        modemident_label(&local->ident, NULL, ident_label, sizeof(ident_label));
        (*ret_interface)->hardware = strdup(ident_label[0] ? ident_label : hw_desc);
    }

    /* UUID -- same function the enabled=false path uses, so the two agree. */
    cellat_compose_uuid(imei_def, definition, uuid);
    /* Keep a copy for the capture thread: the ClockAnchor source_name is this
     * datasource's uuid, and capture_thread only has `local`. */
    local->source_uuid = (*uuid != NULL) ? strdup(*uuid) : NULL;

    snprintf(buf, STATUS_MAX, "Cell modem %s opened on %s (strategy: %s)",
             local->modem_model, device_path, local->strategy->name);
    cf_send_message(caph, buf, MSGFLAG_INFO);

    /* A profile can ask for a scan this modem has no command for. The capture
     * loop already skips it (it gates on the capability, not just the
     * interval), so the source runs -- but a `strategy=stationary` that
     * silently surveys like `driving` would look like it worked when it did
     * not, so say so. A warning and not a refusal: the rest of the profile still
     * applies, and the operator may well want exactly that. */
    if (local->fullscan_interval_ms > 0 && !local->has_qscan &&
        !local->has_csurvc && !cellat_no_vendor_cmd(local)) {
        /* A vendor modem with a serving command but no full-scan command
         * (Sierra/Orbic/SIMCom). A fully-generic modem is exempt: it runs
         * AT+COPS=? as the full-scan fallback, so it is not warned. */
        snprintf(buf, STATUS_MAX,
                 "%s: strategy '%s' asks for a full band scan every %lus, but "
                 "this modem supports neither AT+QSCAN nor AT#CSURVC -- only "
                 "the serving and neighbor polls will run",
                 local->name, local->strategy->name,
                 local->fullscan_interval_ms / 1000);
        cf_send_warning(caph, buf);
    }

    /* Query modem and SIM status at startup for diagnostics */
    {
        char status_resp[1024];
        int n;

        /* SIM status */
        n = at_command_t(local, "AT+CPIN?", status_resp, sizeof(status_resp), 3000);
        if (n > 0) {
            char *cpin = strstr(status_resp, "+CPIN:");
            if (cpin) {
                char *val = cpin + 6;
                while (*val == ' ') val++;
                char *end = strchr(val, '\n');
                if (end) *end = '\0';
                snprintf(buf, STATUS_MAX, "%s SIM: %s", local->name, val);
                cf_send_message(caph, buf, MSGFLAG_INFO);
            } else if (strstr(status_resp, "ERROR")) {
                snprintf(buf, STATUS_MAX, "%s SIM: not present or not accessible",
                         local->name);
                cf_send_message(caph, buf, MSGFLAG_INFO);
            }
        }

        /* Registration status */
        n = at_command_t(local, "AT+CEREG?", status_resp, sizeof(status_resp), 3000);
        if (n > 0) {
            char *cereg = strstr(status_resp, "+CEREG:");
            if (cereg) {
                /* +CEREG: <n>,<stat>[,<tac>,<ci>,...] */
                char *body = cereg + 7;
                while (*body == ' ') body++;
                long stat = 0;
                char *comma = strchr(body, ',');
                if (comma) {
                    parse_int(comma + 1, &stat);
                }
                const char *stat_str;
                switch (stat) {
                    case 0: stat_str = "not registered, not searching"; break;
                    case 1: stat_str = "registered, home"; break;
                    case 2: stat_str = "not registered, searching"; break;
                    case 3: stat_str = "registration denied"; break;
                    case 4: stat_str = "unknown"; break;
                    case 5: stat_str = "registered, roaming"; break;
                    default: stat_str = "unknown"; break;
                }
                snprintf(buf, STATUS_MAX, "%s EPS registration: %s (%ld)",
                         local->name, stat_str, stat);
                cf_send_message(caph, buf, MSGFLAG_INFO);
            }
        }

        /* Current operator
         * +COPS: <mode>[,<format>,<oper>[,<AcT>]]
         * mode: 0=auto, 1=manual, 2=deregistered, 3=set_format, 4=manual/auto */
        n = at_command_t(local, "AT+COPS?", status_resp, sizeof(status_resp), 3000);
        if (n > 0) {
            char *cops = strstr(status_resp, "+COPS:");
            if (cops) {
                char *body = cops + 6;
                while (*body == ' ') body++;
                long cops_mode = -1;
                char *cops_end;
                long cops_val = strtol(body, &cops_end, 10);
                if (cops_end != body)
                    cops_mode = cops_val;

                const char *mode_str;
                switch (cops_mode) {
                    case 0: mode_str = "automatic"; break;
                    case 1: mode_str = "manual"; break;
                    case 2: mode_str = "deregistered"; break;
                    case 3: mode_str = "set format only"; break;
                    case 4: mode_str = "manual/automatic"; break;
                    default: mode_str = "unknown"; break;
                }

                /* Extract operator name if present (quoted string) */
                char *quote1 = strchr(body, '"');
                if (quote1) {
                    char *quote2 = strchr(quote1 + 1, '"');
                    if (quote2) {
                        *quote2 = '\0';
                        snprintf(buf, STATUS_MAX, "%s operator: %s (COPS mode %ld: %s)",
                                 local->name, quote1 + 1, cops_mode, mode_str);
                    } else {
                        snprintf(buf, STATUS_MAX, "%s operator: COPS mode %ld (%s)",
                                 local->name, cops_mode, mode_str);
                    }
                } else {
                    snprintf(buf, STATUS_MAX, "%s operator: none (COPS mode %ld: %s)",
                             local->name, cops_mode, mode_str);
                }
                cf_send_message(caph, buf, MSGFLAG_INFO);
            }
        }

        /* IMSI and ICCID — log at DEBUG (sensitive) */
        if (local->debug) {
            n = at_command_t(local, "AT+CIMI", status_resp, sizeof(status_resp), 3000);
            if (n > 0 && strstr(status_resp, "OK")) {
                char *saveptr = NULL;
                char *line = strtok_r(status_resp, "\n", &saveptr);
                while (line) {
                    while (*line == ' ') line++;
                    if (*line && strcmp(line, "OK") != 0 && strncmp(line, "+CME", 4) != 0) {
                        snprintf(buf, STATUS_MAX, "%s IMSI: %s", local->name, line);
                        cf_send_message(caph, buf, MSGFLAG_DEBUG);
                        break;
                    }
                    line = strtok_r(NULL, "\n", &saveptr);
                }
            }

            /* Try common ICCID commands */
            n = at_command_t(local, "AT+ICCID", status_resp, sizeof(status_resp), 3000);
            if (n <= 0 || strstr(status_resp, "ERROR"))
                n = at_command_t(local, "AT+QCCID", status_resp, sizeof(status_resp), 3000);
            if (n > 0 && !strstr(status_resp, "ERROR")) {
                char *iccid = strstr(status_resp, "ICCID:");
                if (!iccid) iccid = strstr(status_resp, "QCCID:");
                if (iccid) {
                    char *val = strchr(iccid, ':') + 1;
                    while (*val == ' ' || *val == '"') val++;
                    char *end = val;
                    while (*end && *end != '"' && *end != '\n' && *end != '\r') end++;
                    *end = '\0';
                    snprintf(buf, STATUS_MAX, "%s ICCID: %s", local->name, val);
                    cf_send_message(caph, buf, MSGFLAG_DEBUG);
                }
            }
        }
    }

    return 1;
}

/* Report a fatal post-open condition so the operator actually sees the reason.
 * celldiag has the same helper.
 *
 * Do not "simplify" this to a bare cf_send_error(). Under the v3
 * protocol cf_send_error() is silently discarded by the server. There is no
 * `case KIS_EXTERNAL_V3_CMD_ERROR` in either dispatcher --
 * kis_external_interface::dispatch_rx_packet_v3 falls through to
 * kis_datasource::dispatch_rx_packet_v3, which also has no case for it, so the
 * frame this helper carefully serialised is dropped on the floor. From
 * kis_datasource.cc:1084:
 *
 *   // v3 drops explicit error/warning reports and rolls them into the return
 *   // codes of the packet headers itself.  The error message is sent as a
 *   // message prior to the packet being sent.
 *
 * "Sent as a message prior" is the prescribed idiom, and that is what the
 * cf_send_message() below is. It rides KIS_EXTERNAL_V3_CMD_MESSAGE, which the
 * server does handle.
 *
 * The symptom of a lost reason is worse here than in celldiag, which replays
 * a file and exits. cellat surveys forever: every one of the sites below is
 * inside the poll loop
 * and jumps to `done:`, where the source spins down and Kismet re-opens it 5 s
 * later. Without a delivered reason the operator sees an unbounded ladder of
 * `IPC connection closed` / `SOURCEERROR ... (N failures)` with the cause --
 * "failed to send JSON to Kismet", "serial error on serving cell query" --
 * discarded on every single iteration.
 *
 * Errors raised from open_callback do not belong here: they ride out on the
 * open report's return code, which is the idiom the comment above prescribes,
 * and routing them through this would double-report. cellat has no
 * cf_send_error() call in its open path and must not gain one; the asymmetry is
 * pinned by test_open_path_errors_do_not_use_the_message_channel.
 *
 * cf_send_error() is still called after the message: it is the protocol-correct
 * thing to emit, it is what a v2 peer would consume, and it is what puts the
 * source into the error state that drives Kismet's re-open. It just cannot be
 * relied on to carry the human-readable reason. */
static void cellat_report_error(kis_capture_handler_t *caph, const char *msg) {
    cf_send_message(caph, msg, MSGFLAG_ERROR);
    cf_send_error(caph, 0, msg);
}

/* -----------------------------------------------------------------------
 * Runtime settings -- see cellat_optset.h.
 *
 * Kismet's only generic runtime setter is set_channel, which arrives here as
 * the CONFIGURE frame. The string is parsed once (translate) and applied once
 * (control); the framework frees the struct with plain free().
 * ----------------------------------------------------------------------- */
static void *cellat_chantranslate(kis_capture_handler_t *caph, const char *chanstr) {
    (void) caph;
    cellat_optset_t *o = (cellat_optset_t *) malloc(sizeof(cellat_optset_t));
    if (o != NULL)
        cellat_optset_parse(chanstr, o);
    return o;
}

/* Every non-fatal option path returns 0 -- the applied ones too -- by design.
 * (A band/RAT lock channel is the exception; see below.)
 *
 * The framework records the setting string as the source's channel only when
 * this returns > 0 (`caph->channel = strdup(channel)`), and the server then
 * reports it as kismet.datasource.channel -- and, after an error re-open,
 * replays it with set_channel(get_source_channel()) (kis_datasource.cc). So a
 * `return 1` for `strategy=walking` would (a) show "strategy=walking" as the
 * source's channel on the panel and (b) quietly re-apply it after every crash
 * recovery, while an earlier setting was forgotten because only the last
 * string is kept. Returning 0 keeps "channel" free for the band/RAT channels
 * it names and makes a runtime setting what it looks like: a
 * one-time change to a running process.
 *
 * The cost: the CONFIGRESP success bit is 1 for applied and refused alike
 * (`cbret < 0 ? 0 : 1`), as it is for celldiag's refusals -- and -1 is not an
 * option, because a negative return also tears the source down. The truth
 * travels in `msg`, the message bus, and the stats line the panel reads
 * within one interval. */
static int cellat_chancontrol(kis_capture_handler_t *caph, uint32_t seqno,
                              void *privchan, char *msg) {
    local_cell_t *local = (local_cell_t *) caph->userdata;
    cellat_optset_t *o = (cellat_optset_t *) privchan;
    (void) seqno;

    if (o == NULL) {
        snprintf(msg, STATUS_MAX, "cellat: out of memory parsing the setting");
        return -1;
    }

    /* A channel -- a band/RAT lock preset, from Lock or from
     * Kismet's hop thread. Validated here, written by the capture thread (it
     * owns the port). Returns 1, unlike every setting below: this is the
     * source's channel, so Kismet records it as kismet.datasource.channel and
     * replays it after an error re-open, exactly as it does a Wi-Fi channel.
     * The in-force lock is the readback (lock_channel), not this return. */
    if (o->status == CELLAT_OPTSET_CHANNEL) {
        cellat_lock_settings_t t;
        char err[512];
        if (local->disabled || !local->lock_capable || !local->lock_enabled) {
            snprintf(msg, STATUS_MAX,
                     "cellat: '%s' is a channel (a band/RAT lock), and %s", o->value,
                     local->disabled ? "this source is enabled=false" :
                     local->lock_capable ? "band/RAT locking is off for this source "
                     "(add bandlock=true; a lock changes the modem's saved settings)" :
                     "this modem has no band/RAT lock support in cellat "
                     "(it locks Quectel AT+QNWPREFCFG / AT+QCFG, Sierra "
                     "AT!SELRAT and 3GPP AT+WS46 modems that answer the probe)");
            cf_send_message(caph, msg, MSGFLAG_ERROR);
            return 0;
        }
        /* A band set can outgrow the in-force buffers; refuse it whole
         * rather than lock the modem to a truncated set. */
        if (strlen(o->value) >= CELLAT_LOCK_SET_MAX) {
            snprintf(msg, STATUS_MAX, "cellat: '%s' is too long for one lock "
                     "channel (%d characters at most)", o->value,
                     CELLAT_LOCK_SET_MAX - 1);
            cf_send_message(caph, msg, MSGFLAG_ERROR);
            return 0;
        }
        if (cellat_lock_target(&local->lock_orig, o->value, &t, err, sizeof(err)) != 0) {
            snprintf(msg, STATUS_MAX, "cellat: %s", err);
            cf_send_message(caph, msg, MSGFLAG_ERROR);
            return 0;
        }
        pthread_mutex_lock(&local->optset_lock);
        snprintf(local->pending_lock, sizeof(local->pending_lock), "%s", o->value);
        pthread_mutex_unlock(&local->optset_lock);
        snprintf(msg, STATUS_MAX, "cellat: band/RAT lock -> %s; applied at the next poll",
                 o->value);
        return 1;
    }

    if (o->status != CELLAT_OPTSET_OK) {
        snprintf(msg, STATUS_MAX, "cellat: %s", o->err);
        cf_send_message(caph, msg, MSGFLAG_ERROR);
        return 0;
    }

    if (local->disabled) {
        snprintf(msg, STATUS_MAX,
                 "cellat: source is enabled=false; nothing is being captured, "
                 "so '%s=%s' has nothing to change -- enable capture first",
                 o->key_str, o->value);
        cf_send_message(caph, msg, MSGFLAG_ERROR);
        return 0;
    }

    switch (o->key) {
        case CELLAT_OPTSET_KEY_STRATEGY:
            pthread_mutex_lock(&local->optset_lock);
            local->pending_strategy = o->strategy;
            pthread_mutex_unlock(&local->optset_lock);
            snprintf(msg, STATUS_MAX,
                     "cellat: scan profile -> %s (%s); applied at the next poll%s",
                     o->strategy->name, o->strategy->label,
                     local->fullscan_started ?
                        ", after the full band scan now running" : "");
            cf_send_message(caph, msg, MSGFLAG_INFO);
            return 0;

        case CELLAT_OPTSET_KEY_CLOCK_ANCHOR:
            pthread_mutex_lock(&local->optset_lock);
            local->pending_anchor_ms = o->clock_anchor_ms;
            local->pending_anchor_set = 1;
            pthread_mutex_unlock(&local->optset_lock);
            snprintf(msg, STATUS_MAX, "cellat: clock anchor cadence -> %lus%s",
                     o->clock_anchor_ms / 1000,
                     o->clock_anchor_ms ? "" : " (periodic off; START/END still fire)");
            cf_send_message(caph, msg, MSGFLAG_INFO);
            return 0;

        default:
            /* Unreachable while the keys above are the only runtime
             * ones -- here so that a key added to cellat_optset.c with no
             * apply path fails loudly instead of doing nothing. */
            snprintf(msg, STATUS_MAX,
                     "cellat: '%s' is runtime-settable but has no apply path in "
                     "this build -- this is a bug, please report it", o->key_str);
            cf_send_message(caph, msg, MSGFLAG_ERROR);
            return 0;
    }
}

/* Apply what the command thread queued. Capture thread only. */
static void cellat_apply_pending(local_cell_t *local, kis_capture_handler_t *caph) {
    char buf[STATUS_MAX];

    pthread_mutex_lock(&local->optset_lock);
    const cellat_strategy_t *ps = local->pending_strategy;
    local->pending_strategy = NULL;
    int anchor_set = local->pending_anchor_set;
    unsigned long anchor_ms = local->pending_anchor_ms;
    local->pending_anchor_set = 0;
    int stats_now = local->stats_now;
    local->stats_now = 0;
    /* CELLAT_LOCK_SET_MAX, like pending_lock itself: a shorter copy here
     * would cut e.g. "LTE-B12+13+14+66+71" to "LTE-B12+13+14+6" -- a different
     * channel -- after chancontrol had already accepted the whole set. */
    char lock_ch[CELLAT_LOCK_SET_MAX];
    snprintf(lock_ch, sizeof(lock_ch), "%s", local->pending_lock);
    local->pending_lock[0] = '\0';
    pthread_mutex_unlock(&local->optset_lock);

    if (lock_ch[0] != '\0') {
        cellat_lock_apply(local, caph, lock_ch);
        stats_now = 1;
    }

    if (ps != NULL) {
        local->strategy = ps;
        local->serving_interval_ms = ps->serving_ms;
        local->neighbor_interval_ms = ps->neighbor_ms;
        local->fullscan_interval_ms = ps->fullscan_ms;
        /* Clear the last-run stamps, so the new profile starts
         * now -- switching to stationary means "scan the bands", not "scan
         * them a minute from now". */
        local->serving_last_ms = 0;
        local->neighbor_last_ms = 0;
        local->fullscan_last_ms = 0;
        snprintf(buf, sizeof(buf), "%s now surveying as '%s'", local->name, ps->name);
        cf_send_message(caph, buf, MSGFLAG_INFO);
        if (ps->fullscan_ms > 0 && !local->has_qscan && !local->has_csurvc) {
            snprintf(buf, sizeof(buf),
                     "%s: strategy '%s' asks for a full band scan every %lus, but "
                     "this modem supports neither AT+QSCAN nor AT#CSURVC -- only "
                     "the serving and neighbor polls will run",
                     local->name, ps->name, ps->fullscan_ms / 1000);
            cf_send_warning(caph, buf);
        }
        stats_now = 1;
    }
    if (anchor_set) {
        local->clock_anchor_interval_ms = anchor_ms;
        local->clock_anchor_last_ms = now_ms();
        stats_now = 1;
    }
    if (stats_now)
        cellat_stats_emit(local, "surveying");
}

/*
 * Capture thread — runs scan loop on configured intervals.
 *
 * This runs in its own thread, isolated from the framework IO thread.
 * We can block on serial reads safely.
 */
/* One ModemIdentity record per capture (see diag_modemident.h). */
static void cellat_send_modem_identity(local_cell_t *local) {
    char label[512], rec[1024];

    if (local->caph == NULL || !local->ident.imei[0])
        return;
    modemident_label(&local->ident, NULL, label, sizeof(label));
    if (modemident_json(&local->ident, "cellat", MODEMIDENT_METHOD_AT,
                        local->device_path, label, rec, sizeof(rec)) != 0)
        return;

    struct timeval tv;
    gettimeofday(&tv, NULL);
    /* 0 == ring buffer full: wait and offer it once more (one row per capture;
     * the ClockAnchor sender's rule). */
    if (cf_send_json(local->caph, NULL, 0, NULL, NULL, tv, MODEMIDENT_TYPE, rec) == 0) {
        cf_handler_wait_ringbuffer(local->caph);
        (void)cf_send_json(local->caph, NULL, 0, NULL, NULL, tv, MODEMIDENT_TYPE, rec);
    }
}

/* -----------------------------------------------------------------------
 * GNSS (cellat_gnss.h)
 * ----------------------------------------------------------------------- */

static void cellat_gnss_send(local_cell_t *local, cellat_nmea_t *n) {
    const char *rec = cellat_nmea_record(n);
    if (rec != NULL) {
        struct timeval tv;
        gettimeofday(&tv, NULL);
        /* A full ring drops the batch: the next one is a second away, and
         * waiting here would only make this one stale */
        (void)cf_send_json(local->caph, NULL, 0, NULL, NULL, tv, CELLAT_GNSS_TYPE, rec);
    }
    cellat_nmea_clear(n);
}

static void *cellat_gnss_thread(void *arg) {
    local_cell_t *local = (local_cell_t *)arg;
    cellat_nmea_t *n = malloc(sizeof(*n));
    char rbuf[1024], msg[STATUS_MAX];
    unsigned long batch_start = 0;
    const char *why = NULL;
    int is_tty = isatty(local->gnss_fd);

    if (n == NULL)
        return NULL;
    cellat_nmea_init(n);

    while (!__atomic_load_n(&local->gnss_stop, __ATOMIC_ACQUIRE)) {
        struct pollfd pfd = { .fd = local->gnss_fd, .events = POLLIN, .revents = 0 };
        int pr = poll(&pfd, 1, 250);
        if (pr < 0 && errno != EINTR) {
            why = strerror(errno);
            break;
        }
        if (pr > 0) {
            if (pfd.revents & (POLLERR | POLLHUP | POLLNVAL)) {
                why = "the port went away";
                break;
            }
            ssize_t r = read(local->gnss_fd, rbuf, sizeof(rbuf));
            if (r < 0 && errno != EAGAIN && errno != EINTR) {
                why = strerror(errno);
                break;
            }
            if (r == 0 && !is_tty) {
                why = "end of file";
                break;
            }
            size_t off = 0;
            while (r > 0 && off < (size_t)r) {
                size_t used = 0;
                int before = n->count;
                int full = cellat_nmea_feed(n, rbuf + off, (size_t)r - off, &used);
                off += used;
                if (before == 0 && n->count > 0)
                    batch_start = now_ms();
                if (full)
                    cellat_gnss_send(local, n);
                else if (used == 0)
                    break;
            }
        }
        if (n->count > 0 && now_ms() - batch_start >= 1000)
            cellat_gnss_send(local, n);
    }

    if (why != NULL && !__atomic_load_n(&local->gnss_stop, __ATOMIC_ACQUIRE)) {
        snprintf(msg, sizeof(msg), "%s: GNSS reading stopped on %s: %s; the cell "
                 "capture continues without it", local->name ? local->name : "cellat",
                 local->gnss_port, why);
        cf_send_warning(local->caph, msg);
    }
    free(n);
    return NULL;
}

/* The NMEA port of the modem on device_path: gpsport=, the libusb
 * sibling, the wwan node, or the sysfs sibling the port table names. */
static int cellat_gnss_find_port(local_cell_t *local, char *out, size_t outsz) {
    if (local->gnss_port_opt[0]) {
        snprintf(out, outsz, "%s", local->gnss_port_opt);
        return 0;
    }

    if (cell_usbport_is_spec(local->device_path)) {
        char dev[CELL_USBPORT_SPEC_MAX];
        cell_usbport_info_t sib[16];
        const char *c = strrchr(local->device_path, ':');
        if (c == NULL || (size_t)(c - local->device_path) >= sizeof(dev))
            return -1;
        memcpy(dev, local->device_path, (size_t)(c - local->device_path));
        dev[c - local->device_path] = '\0';
        int ns = cell_usbport_siblings(dev, sib, 16);
        for (int i = 0; i < ns; i++) {
            if (strcmp(sib[i].role, "nmea") == 0) {
                snprintf(out, outsz, "%s", sib[i].spec);
                return 0;
            }
        }
        return -1;
    }

    if (cellat_gnss_wwan_nmea(local->device_path, out, outsz) == 0)
        return access(out, F_OK) == 0 ? 0 : -1;

    char real[PATH_MAX];
    if (realpath(local->device_path, real) == NULL)
        return -1;
    return diag_portadmit_find_role(DIAG_PORTADMIT_SYSFS, real, "NMEA", out, outsz) ? 0 : -1;
}

/* Turn the GNSS on if it is off, open its NMEA port and start the reader.
 * Any failure is a warning: the cell capture runs either way. */
static void cellat_gnss_start(local_cell_t *local, kis_capture_handler_t *caph) {
    char resp[512], msg[STATUS_MAX];
    const char *who = local->name ? local->name : "cellat";

    if (!local->gnss_wanted)
        return;

    if (local->vendor != VENDOR_QUECTEL) {
        snprintf(msg, sizeof(msg), "%s: gps= is supported on Quectel modems only; "
                 "this %s modem's GNSS is not used", who, vendor_name(local->vendor));
        cf_send_warning(caph, msg);
        return;
    }

    int n = at_command_t(local, "AT+QGPS?", resp, sizeof(resp), 2000);
    int state = n > 0 ? cellat_qgps_state(resp) : -1;
    if (state < 0) {
        snprintf(msg, sizeof(msg), "%s: gps=: the modem did not answer AT+QGPS? "
                 "(a model without GNSS?); its GNSS is not used", who);
        cf_send_warning(caph, msg);
        return;
    }

    if (state == 0) {
        char port[16];
        n = at_command_t(local, "AT+QGPSCFG=\"outport\"", resp, sizeof(resp), 2000);
        if (n > 0 && cellat_qgps_outport(resp, port, sizeof(port)) == 0 &&
            strcmp(port, "none") == 0) {
            n = at_command_t(local, "AT+QGPSCFG=\"outport\",\"usbnmea\"", resp,
                             sizeof(resp), 2000);
            if (n > 0 && strstr(resp, "OK") != NULL)
                snprintf(local->gnss_outport_orig, sizeof(local->gnss_outport_orig),
                         "%s", port);
        }

        n = at_command_t(local, "AT+QGPS=1", resp, sizeof(resp), 3000);
        if (n > 0 && strstr(resp, "OK") != NULL) {
            local->gnss_we_enabled = 1;
        } else if (!(n > 0 && strstr(resp, "+CME ERROR: 504") != NULL)) {
            snprintf(msg, sizeof(msg), "%s: gps=: the modem refused AT+QGPS=1 (%.80s); "
                     "its GNSS is not used", who, n > 0 ? resp : "no answer");
            cf_send_warning(caph, msg);
            return;
        }
    }

    if (cellat_gnss_find_port(local, local->gnss_port, sizeof(local->gnss_port)) != 0) {
        snprintf(msg, sizeof(msg), "%s: gps=: found no NMEA port beside %s; name it "
                 "with gpsport=<path>", who, local->device_path);
        cf_send_warning(caph, msg);
        return;
    }

    local->gnss_fd = serial_open(local->gnss_port, 115200);
    if (local->gnss_fd < 0) {
        snprintf(msg, sizeof(msg), "%s: gps=: cannot open the NMEA port %s: %s%s", who,
                 local->gnss_port, strerror(errno),
                 errno == EWOULDBLOCK ? " (held by another reader, such as gpsd)" : "");
        cf_send_warning(caph, msg);
        return;
    }

    __atomic_store_n(&local->gnss_stop, 0, __ATOMIC_RELEASE);
    if (pthread_create(&local->gnss_thread, NULL, cellat_gnss_thread, local) != 0) {
        serial_close(&local->gnss_fd);
        snprintf(msg, sizeof(msg), "%s: gps=: cannot start the GNSS reader", who);
        cf_send_warning(caph, msg);
        return;
    }
    local->gnss_thread_live = 1;

    snprintf(msg, sizeof(msg), "%s: reading the modem's GNSS from %s%s", who,
             local->gnss_port, local->gnss_we_enabled ? " (GNSS turned on; off at close)" : "");
    cf_send_message(caph, msg, MSGFLAG_INFO);
}

/* Stop the reader, then leave the GNSS as it was found. */
static void cellat_gnss_stop(local_cell_t *local) {
    char resp[256], cmd[64];

    if (local->gnss_thread_live) {
        __atomic_store_n(&local->gnss_stop, 1, __ATOMIC_RELEASE);
        pthread_join(local->gnss_thread, NULL);
        local->gnss_thread_live = 0;
    }
    serial_close(&local->gnss_fd);

    if (local->serial_fd < 0)
        return;
    if (local->gnss_we_enabled) {
        (void)at_command_t(local, "AT+QGPSEND", resp, sizeof(resp), 2000);
        local->gnss_we_enabled = 0;
    }
    if (local->gnss_outport_orig[0]) {
        snprintf(cmd, sizeof(cmd), "AT+QGPSCFG=\"outport\",\"%s\"",
                 local->gnss_outport_orig);
        (void)at_command_t(local, cmd, resp, sizeof(resp), 2000);
        local->gnss_outport_orig[0] = '\0';
    }
}

/* The session CellLog row, once per capture: the port, profile and modem. */
static void cellat_send_session_log(local_cell_t *local) {
    struct timeval tv;
    char rec[2048], anchor[24];

    snprintf(anchor, sizeof(anchor), "%lu", local->clock_anchor_interval_ms / 1000);
    cell_log_kv_t kv[] = {
        { "at_port",       local->device_path },
        { "vendor_model",  local->modem_model },
        { "imei",          local->ident.imei },
        { "make",          local->ident.make },
        { "product_model", local->ident.model },
        { "firmware",      local->ident.firmware },
        { "strategy",      local->strategy != NULL ? local->strategy->name : NULL },
        { "clock_anchor_sec", anchor },
        { "bandlock",      local->lock_enabled ? "true" : "false" },
        { "debug",         local->debug ? "true" : "false" },
    };

    gettimeofday(&tv, NULL);
    if (cell_log_session_json(rec, sizeof(rec), "cellat", &tv, now_mono_ns(),
                              kv, sizeof(kv) / sizeof(kv[0])) == 0)
        cellat_log_send(local, &tv, rec);
}

void capture_thread(kis_capture_handler_t *caph) {
    local_cell_t *local = (local_cell_t *)caph->userdata;
    char resp[AT_RESP_MAX];
    char errstr[ERRBUF_MAX];
    struct timeval tv;

    /* Static array for JSON observations */
    static char json_obs[MAX_OBS_PER_RESP][JSON_BUF_MAX];

    /* enabled=false: idle until the server closes/reaps us. Nothing was
     * opened -- serial_fd is -1 and every AT path below would write to it -- so
     * there is nothing to poll or tear down. Mirrors celldiag's disabled idle
     * loop. Runtime re-enable is a fresh open, which re-runs port resolution and
     * capability detection from scratch. */
    if (local->disabled) {
        /* Say "disabled" on the stats cadence, so the panel renders
         * an intentionally idle source as disabled -- not as a running source
         * that has gone quiet. */
        while (!caph->shutdown && !cf_handler_close_requested(caph)) {
            if (time(NULL) - local->stats_last >= CELLAT_STATS_INTERVAL_S)
                cellat_stats_emit(local, "disabled");
            struct timespec idle = { .tv_sec = 1, .tv_nsec = 0 };
            nanosleep(&idle, NULL);
        }
        return;
    }

    /* Mandatory capture start clock anchor. Fires before the poll
     * loop so an AT-only drive carries a host<->modem-RTC pair from t0. Seed the
     * periodic timer from here so the first periodic tick is a full interval
     * after start, not immediately. */
    clock_anchor_emit(local, "start");
    local->clock_anchor_last_ms = now_ms();

    /* The ModemIdentity record, once per capture, beside the start
     * anchor: the server installs its label as this source's hardware and
     * kismetdb keeps it as a data row, so the container names its modem. */
    cellat_send_modem_identity(local);
    cellat_send_session_log(local);
    cellat_gnss_start(local, caph);

    /* The first stats line goes out now, so the panel has a profile
     * and a port to show before the first poll interval has elapsed. */
    cellat_stats_emit(local, "surveying");

    /* A graceful close ends the loop the same way a clean shutdown
     * would, but with the pipe still open -- so the end anchor below reaches
     * the kismetdb instead of dying with the thread. */
    while (!caph->shutdown && !cf_handler_close_requested(caph)) {
        unsigned long now = now_ms();
        int did_work = 0;

        cellat_apply_pending(local, caph);   /* queued runtime settings */
        if (time(NULL) - local->stats_last >= CELLAT_STATS_INTERVAL_S)
            cellat_stats_emit(local, "surveying");

        /* --- Serving cell scan --- */
        if (local->serving_interval_ms > 0 &&
            (now - local->serving_last_ms) >= local->serving_interval_ms) {

            local->serving_last_ms = now;

            int n = 0;
            int obs_count = 0;
            int used_generic = 0;
            obs_exchange_t obs_ref[MAX_OBS_PER_RESP];

            if (local->has_qeng) {
                n = at_command_t(local,"AT+QENG=\"servingcell\"",
                               resp, sizeof(resp), 5000);
                if (n > 0)
                    obs_count = parse_qeng_serving(resp, json_obs, MAX_OBS_PER_RESP);
            } else if (local->has_rfsts) {
                n = at_command_t(local,"AT#RFSTS",
                               resp, sizeof(resp), 5000);
                if (n > 0)
                    obs_count = parse_rfsts(resp, json_obs, MAX_OBS_PER_RESP);

                /* Inject cached PCI from prior CSURVC/MONI observations */
                if (obs_count > 0 && local->cached_pci > 0) {
                    for (int i = 0; i < obs_count; i++) {
                        if (strstr(json_obs[i], "\"pci\"") == NULL) {
                            size_t len = strlen(json_obs[i]);
                            if (len > 1 && json_obs[i][len - 1] == '}') {
                                json_obs[i][len - 1] = '\0';
                                snprintf(json_obs[i] + len - 1,
                                         JSON_BUF_MAX - len,
                                         ",\"pci\":%ld}", local->cached_pci);
                            }
                        }
                    }
                }

                /* Cache serving cell identity for the CSURVC TAC fix
                 * and PCI enrichment */
                if (obs_count > 0) {
                    /* Extract tac and cell_id from the JSON we just built */
                    for (int i = 0; i < obs_count; i++) {
                        char *tac_p = strstr(json_obs[i], "\"tac\":");
                        char *cid_p = strstr(json_obs[i], "\"cell_id\":");
                        if (tac_p && cid_p) {
                            unsigned long t = strtoul(tac_p + 6, NULL, 10);
                            unsigned long c = strtoul(cid_p + 10, NULL, 10);
                            if (t > 0 && c > 0) {
                                local->cached_tac = t;
                                local->cached_cell_id = c;
                                local->cached_valid = 1;
                            }
                        }
                    }
                }
            } else if (local->has_servinfo) {
                n = at_command_t(local,"AT#SERVINFO",
                               resp, sizeof(resp), 5000);
                if (n > 0)
                    obs_count = parse_servinfo(resp, json_obs, MAX_OBS_PER_RESP);
            } else if (local->has_gstatus) {
                n = at_command_t(local,"AT!GSTATUS?",
                               resp, sizeof(resp), 5000);
                if (n > 0)
                    obs_count = parse_gstatus(resp, local->serial_fd,
                                              json_obs, MAX_OBS_PER_RESP);
            } else if (local->has_scellinfo) {
                n = at_command_t(local,"AT^SCELLINFO",
                               resp, sizeof(resp), 5000);
                if (n > 0)
                    obs_count = parse_scellinfo(resp, json_obs, MAX_OBS_PER_RESP);
            } else if (local->has_cpsi) {
                /* SIMCom. An EN-DC reply yields two observations from
                 * one command -- the LTE anchor and the NR secondary — which is
                 * why parse_cpsi is given the whole array rather than one slot. */
                n = at_command_t(local, "AT+CPSI?", resp, sizeof(resp), 5000);
                if (n > 0)
                    obs_count = parse_cpsi(resp, json_obs, MAX_OBS_PER_RESP);
            } else {
                /* Generic 3GPP fallback: no vendor engineering
                 * command was detected on this modem. Gather the standard
                 * TS 27.007 reads and merge them into one serving observation
                 * (identity+RAT from registration, name from COPS?, signal from
                 * CESQ/CSQ). The merge lives in the unit-tested
                 * parse_generic_serving(); this block only gathers + emits. The
                 * standard replies are small, so 512 B buffers suffice (unlike
                 * the shared 128 KB `resp`). */
                char c5[512], ce[512], cr[512], cq[512], eq[512], sq[512];
                int gerr = 0, gn;
                c5[0] = ce[0] = cr[0] = cq[0] = eq[0] = sq[0] = '\0';
                gn = at_command_t(local, "AT+C5GREG?", c5, sizeof(c5), 3000); if (gn < 0) gerr = 1; else if (gn <= 0) c5[0] = '\0';
                gn = at_command_t(local, "AT+CEREG?",  ce, sizeof(ce), 3000); if (gn < 0) gerr = 1; else if (gn <= 0) ce[0] = '\0';
                gn = at_command_t(local, "AT+CREG?",   cr, sizeof(cr), 3000); if (gn < 0) gerr = 1; else if (gn <= 0) cr[0] = '\0';
                gn = at_command_t(local, "AT+COPS?",   cq, sizeof(cq), 3000); if (gn < 0) gerr = 1; else if (gn <= 0) cq[0] = '\0';
                gn = at_command_t(local, "AT+CESQ",    eq, sizeof(eq), 3000); if (gn < 0) gerr = 1; else if (gn <= 0) eq[0] = '\0';
                gn = at_command_t(local, "AT+CSQ",     sq, sizeof(sq), 3000); if (gn < 0) gerr = 1; else if (gn <= 0) sq[0] = '\0';
                obs_count = parse_generic_serving(c5, ce, cr, cq, eq, sq,
                                                  json_obs, MAX_OBS_PER_RESP);
                n = gerr ? -1 : (obs_count > 0 ? 1 : 0);
                used_generic = 1;
            }
            /* Every branch above is one survey exchange, then its parse
             * (parse_gstatus's own follow-ups use the raw fd, not at_command_t). */
            obs_mark(local, obs_ref, 0, obs_count);

            if (local->debug && obs_count > 0) {
                snprintf(errstr, ERRBUF_MAX, "%s serving: %d observations",
                         local->name, obs_count);
                cf_send_message(caph, errstr, MSGFLAG_DEBUG);
            }

            const char *serving_origin =
                local->has_qeng      ? "AT+QENG=servingcell" :
                local->has_rfsts     ? "AT#RFSTS" :
                local->has_servinfo  ? "AT#SERVINFO" :
                local->has_gstatus   ? "AT!GSTATUS?" :
                local->has_scellinfo ? "AT^SCELLINFO" :
                local->has_cpsi      ? "AT+CPSI?" :
                used_generic         ? "3gpp-generic" : "at";

            for (int i = 0; i < obs_count; i++) {
                inject_prov_x(json_obs[i], JSON_BUF_MAX, local->modem_imei,
                              serving_origin, obs_ref[i].at_ts_mono_ns,
                              obs_ref[i].rx_done_ns);
                gettimeofday(&tv, NULL);
                int r = cf_send_json(caph, NULL, 0, NULL, NULL,
                                     tv, "CellModem", json_obs[i]);
                if (r < 0) {
                    snprintf(errstr, ERRBUF_MAX,
                             "%s failed to send JSON to Kismet", local->name);
                    cellat_report_error(caph, errstr);
                    goto done;
                }
                if (r == 0) {
                    cf_handler_wait_ringbuffer(caph);
                } else {
                    local->obs_total++;
                    local->last_obs_epoch = tv.tv_sec;
                }
            }

            if (n < 0) {
                snprintf(errstr, ERRBUF_MAX, "%s serial error on serving cell query",
                         local->name);
                cellat_report_error(caph, errstr);
                goto done;
            }

            did_work = 1;
        }

        /* A close that arrived during the serving poll is served now, not after
         * the neighbour and full scans: each block can hold this thread for
         * several AT round trips, and the close has a grace to meet. */
        if (cf_handler_close_requested(caph))
            break;

        /* --- Neighbor cell scan (Quectel QENG, Telit MONI, Sierra LTEINFO, or Orbic QCRSRP) --- */
        if ((local->has_qeng || local->has_moni || local->has_gstatus || local->has_qcrsrp) &&
            local->neighbor_interval_ms > 0 &&
            (now - local->neighbor_last_ms) >= local->neighbor_interval_ms) {

            local->neighbor_last_ms = now;

            int obs_count = 0;
            obs_exchange_t obs_ref[MAX_OBS_PER_RESP];

            /* Rows the neighbour parser saw and declined. Only the QENG
             * path fills this in; the others leave it zeroed, which renders as
             * an empty suffix in their log lines. */
            qeng_neighbor_drops_t qeng_drops;
            memset(&qeng_drops, 0, sizeof(qeng_drops));

            if (local->has_qeng) {
                int n = at_command_t(local,"AT+QENG=\"neighbourcell\"",
                                   resp, sizeof(resp), 10000);
                if (n > 0)
                    obs_count = parse_qeng_neighbor(resp, json_obs, MAX_OBS_PER_RESP,
                                                    &qeng_drops);
                obs_mark(local, obs_ref, 0, obs_count);

            } else if (local->has_moni) {
                /* AT#MONI=1 (intra-freq) + AT#MONI=2 (inter-freq) */
                for (int mode = 1; mode <= 2; mode++) {
                    char moni_cmd[16];
                    snprintf(moni_cmd, sizeof(moni_cmd), "AT#MONI=%d", mode);
                    at_command_t(local,moni_cmd, resp, sizeof(resp), 3000);

                    int n = at_command_t(local,"AT#MONI",
                                       resp, sizeof(resp), 3000);
                    if (n > 0) {
                        int cnt = parse_moni(resp, json_obs + obs_count,
                                             MAX_OBS_PER_RESP - obs_count, 0);
                        /* this AT#MONI's own rows, before =0 resets */
                        obs_mark(local, obs_ref, obs_count, obs_count + cnt);
                        obs_count += cnt;
                    }
                }
                /* Reset to mode 0 for next serving cell query */
                at_command_t(local,"AT#MONI=0", resp, sizeof(resp), 2000);

            } else if (local->has_gstatus) {
                /* Sierra AT!LTEINFO? — includes serving + intra/inter neighbors.
                 * Need the serving EARFCN for intra-freq neighbors. */
                int n = at_command_t(local,"AT!LTEINFO?",
                                   resp, sizeof(resp), 5000);
                if (n > 0 && strstr(resp, "Serving:") &&
                    !strstr(resp, "Not Available")) {
                    /* Extract serving EARFCN from the serving data line */
                    long srv_earfcn = 0;
                    char *srv = strstr(resp, "Serving:");
                    if (srv) {
                        char *nl = strchr(srv, '\n');
                        if (nl) {
                            char *dl = nl + 1;
                            while (*dl == ' ') dl++;
                            /* First token is EARFCN — copy to buffer */
                            char earfcn_buf[16];
                            int ebi = 0;
                            while (dl[ebi] && dl[ebi] != ' ' && dl[ebi] != '\t'
                                   && ebi < (int)sizeof(earfcn_buf) - 1)
                                earfcn_buf[ebi] = dl[ebi], ebi++;
                            earfcn_buf[ebi] = '\0';
                            parse_int(earfcn_buf, &srv_earfcn);
                        }
                    }
                    obs_count = parse_lteinfo_neighbors(resp, srv_earfcn,
                                                        json_obs, MAX_OBS_PER_RESP);
                }
                obs_mark(local, obs_ref, 0, obs_count);
            } else if (local->has_qcrsrp) {
                /* AT$QCRSRP? — returns all visible cells across all bands.
                 * Most useful in COPS=2 (deregistered) mode for passive scanning. */
                int n = at_command_t(local,"AT$QCRSRP?",
                                   resp, sizeof(resp), 5000);
                if (n > 0)
                    obs_count = parse_qcrsrp(resp, json_obs, MAX_OBS_PER_RESP);
                obs_mark(local, obs_ref, 0, obs_count);
            }

            /* `observation: N cells` alone is not the same fact as "N of M,
             * the rest out of scope", so the declined rows are summarised too.
             * The gate takes drops into account: an EG25-G whose entire
             * neighbour list is GSM would otherwise print no line at all for
             * the poll that saw the most rows. */
            char drop_suffix[128];
            qeng_drops_summary(&qeng_drops, drop_suffix, sizeof(drop_suffix));

            if (local->debug && (obs_count > 0 || qeng_drops.rows > 0)) {
                snprintf(errstr, ERRBUF_MAX, "%s observation: %d cells%s",
                         local->name, obs_count, drop_suffix);
                cf_send_message(caph, errstr, MSGFLAG_DEBUG);
            }

            /* An unrecognised RAT token is a different event from a declined
             * one: it means this firmware says something the parser has never
             * been taught, and it is the shape a real regression would take.
             * Report it above DEBUG, but only once per distinct token -- the
             * poll repeats every few seconds. */
            if (qeng_drops.unknown > 0 && qeng_drops.unknown_token[0] &&
                strcmp(qeng_drops.unknown_token, local->qeng_unknown_rat) != 0) {

                snprintf(local->qeng_unknown_rat, sizeof(local->qeng_unknown_rat),
                         "%s", qeng_drops.unknown_token);
                snprintf(errstr, ERRBUF_MAX,
                         "%s AT+QENG=\"neighbourcell\" reported RAT \"%s\", which this "
                         "build does not recognise; those rows are being dropped",
                         local->name, qeng_drops.unknown_token);
                cf_send_message(caph, errstr, MSGFLAG_INFO);
            }

            const char *neighbor_origin =
                local->has_qeng    ? "AT+QENG=neighbourcell" :
                local->has_moni    ? "AT#MONI" :
                local->has_gstatus ? "AT!LTEINFO?" :
                local->has_qcrsrp  ? "AT$QCRSRP?" : "at";

            for (int i = 0; i < obs_count; i++) {
                inject_prov_x(json_obs[i], JSON_BUF_MAX, local->modem_imei,
                              neighbor_origin, obs_ref[i].at_ts_mono_ns,
                              obs_ref[i].rx_done_ns);
                gettimeofday(&tv, NULL);
                int r = cf_send_json(caph, NULL, 0, NULL, NULL,
                                     tv, "CellModem", json_obs[i]);
                if (r < 0) {
                    snprintf(errstr, ERRBUF_MAX,
                             "%s failed to send JSON to Kismet", local->name);
                    cellat_report_error(caph, errstr);
                    goto done;
                }
                if (r == 0) {
                    cf_handler_wait_ringbuffer(caph);
                } else {
                    local->obs_total++;
                    local->last_obs_epoch = tv.tv_sec;
                }
            }

            did_work = 1;
        }

        if (cf_handler_close_requested(caph))
            break;

        /* --- Full band scan (AT+QSCAN, AT#CSURVC, or generic AT+COPS=?) --- */
        if ((local->has_qscan || local->has_csurvc || cellat_no_vendor_cmd(local)) &&
            local->fullscan_interval_ms > 0 &&
            (now - local->fullscan_last_ms) >= local->fullscan_interval_ms) {

            int n = 0;
            int obs_count = 0;
            obs_exchange_t obs_ref[MAX_OBS_PER_RESP];

            /* The scan blocks this thread -- and so every stats line
             * -- for up to 3 minutes. Announce it first, with its start time,
             * so the panel can tell a long scan from a hung source. */
            local->fullscan_started = time(NULL);
            cellat_stats_emit(local, "full_scan");

            if (local->has_qscan) {
                snprintf(errstr, ERRBUF_MAX, "%s starting full band scan (AT+QSCAN=3,1)",
                         local->name);
                cf_send_message(caph, errstr, MSGFLAG_INFO);
                /* QSCAN can take up to 2 minutes */
                n = at_command_t(local,"AT+QSCAN=3,1",
                               resp, sizeof(resp), 120000);
                if (n > 0)
                    obs_count = parse_qscan(resp, json_obs, MAX_OBS_PER_RESP);

            } else if (local->has_csurvc) {
                snprintf(errstr, ERRBUF_MAX, "%s starting network survey (AT#CSURVC)",
                         local->name);
                cf_send_message(caph, errstr, MSGFLAG_INFO);
                /* CSURVC can take up to 3 minutes */
                n = at_command_t(local,"AT#CSURVC",
                               resp, sizeof(resp), 180000);
                if (n > 0)
                    obs_count = parse_csurvc(resp, json_obs, MAX_OBS_PER_RESP);
            } else {
                /* Generic full scan: a modem with no vendor scan
                 * command lists the visible PLMNs via AT+COPS=?. Each operator
                 * tuple becomes an observation (mcc/mnc/operator_name/rat, no
                 * cell identity), decoded by the tested parse_cops_scan().
                 * AT+COPS=? can take up to ~3 minutes and briefly
                 * detaches the modem, hence the full-scan cadence, not the poll. */
                snprintf(errstr, ERRBUF_MAX,
                         "%s starting generic PLMN scan (AT+COPS=?)", local->name);
                cf_send_message(caph, errstr, MSGFLAG_INFO);
                n = at_command_t(local,"AT+COPS=?", resp, sizeof(resp), 180000);
                if (n > 0)
                    obs_count = parse_cops_scan(resp, json_obs, MAX_OBS_PER_RESP);
            }
            obs_mark(local, obs_ref, 0, obs_count);   /* the one scan exchange */

            /* Update timestamp AFTER scan completes — these scans block
             * for 30s-3min, so using the pre-scan 'now' would cause the
             * next iteration to immediately re-trigger */
            local->fullscan_last_ms = now_ms();
            local->fullscan_started = 0;
            cellat_stats_emit(local, "surveying");

            /* Fix CSURVC TAC=0 -- substitute cached serving TAC when a
             * survey observation has TAC=0 and a matching CellID. The
             * substitution lives in cellat_tacfix.inc so it is unit-tested
             * (test_cellat_tacfix.c), guarding against a "tac":<n>:0
             * JSON corruption from a naive in-place splice. */
            if (obs_count > 0 && local->cached_valid) {
                for (int i = 0; i < obs_count; i++)
                    cellat_apply_survey_tac(json_obs[i], JSON_BUF_MAX,
                                            local->cached_cell_id,
                                            local->cached_tac);
            }

            /* Cache PCI from CSURVC serving cell for RFSTS enrichment.
             * CSURVC 11-field lines have PCI -- extract from first observation
             * that matches the cached serving cell_id. */
            if (obs_count > 0 && local->cached_valid) {
                char cid_needle[32];
                snprintf(cid_needle, sizeof(cid_needle),
                         "\"cell_id\":%lu", local->cached_cell_id);
                for (int i = 0; i < obs_count; i++) {
                    if (strstr(json_obs[i], cid_needle)) {
                        char *pci_p = strstr(json_obs[i], "\"pci\":");
                        if (pci_p) {
                            long pv = strtol(pci_p + 6, NULL, 10);
                            if (pv > 0)
                                local->cached_pci = pv;
                        }
                        break;
                    }
                }
            }

            if (local->debug && obs_count > 0) {
                snprintf(errstr, ERRBUF_MAX, "%s full scan: %d observations",
                         local->name, obs_count);
                cf_send_message(caph, errstr, MSGFLAG_DEBUG);
            }

            /* The debug block above must close before this send loop, as the
             * serving and neighbor blocks do. A debug flag must never gate
             * data -- the whole point of AT+QSCAN / AT#CSURVC is the cells the
             * serving/neighbor queries do not report. Pinned by
             * test_fullscan_observations_are_not_gated_on_debug. */
            const char *fullscan_origin =
                local->has_qscan   ? "AT+QSCAN=3,1" :
                local->has_csurvc  ? "AT#CSURVC" : "AT+COPS=?";

            for (int i = 0; i < obs_count; i++) {
                inject_prov_x(json_obs[i], JSON_BUF_MAX, local->modem_imei,
                              fullscan_origin, obs_ref[i].at_ts_mono_ns,
                              obs_ref[i].rx_done_ns);
                gettimeofday(&tv, NULL);
                int r = cf_send_json(caph, NULL, 0, NULL, NULL,
                                     tv, "CellModem", json_obs[i]);
                if (r < 0) {
                    snprintf(errstr, ERRBUF_MAX,
                             "%s failed to send JSON to Kismet", local->name);
                    cellat_report_error(caph, errstr);
                    goto done;
                }
                if (r == 0) {
                    cf_handler_wait_ringbuffer(caph);
                } else {
                    local->obs_total++;
                    local->last_obs_epoch = tv.tv_sec;
                }
            }

            did_work = 1;
        }

        /* --- Periodic clock anchor (host<->modem-RTC via AT+CCLK?) --- */
        if (local->clock_anchor_interval_ms > 0 &&
            (now - local->clock_anchor_last_ms) >= local->clock_anchor_interval_ms) {

            local->clock_anchor_last_ms = now;
            clock_anchor_emit(local, "periodic");
            did_work = 1;
        }

        /* Avoid busy loop — sleep 250ms if no work was done */
        if (!did_work) {
            usleep(250000);
        }
    }

    /* Mandatory capture end clock anchor, emitted in the teardown
     * before the port closes so a clean stop still yields the closing
     * host<->modem-RTC pair -- the second of the >=2 anchors a single-transport
     * drive needs to compute offset+drift. Reached only on the normal shutdown
     * fall-through; the `goto done` error path (a ringbuffer-wedged capture)
     * skips it, since a wedged capture is in no state to issue another AT.
     *
     * A Kismet-driven stop reaches it through the graceful close: the
     * server's CLOSEREQ ends the loop above and waits for us to exit, so this
     * row still has a pipe to travel. */
    clock_anchor_emit(local, "end");

done:
    cellat_gnss_stop(local);

    /* Never leave a modem locked. Both exits come here -- the
     * normal teardown and the `goto done` error path -- because a wedged
     * Kismet ring buffer says nothing about the serial port, and a modem left
     * locked is the one failure here that outlives the process. */
    if (local->lock_capable && local->serial_fd >= 0 &&
        (local->lock_state_written ||
         memcmp(&local->lock_cur, &local->lock_orig, sizeof(local->lock_cur)) != 0))
        cellat_lock_apply(local, caph, "AUTO");

    if (local->device_path && local->device_path[0])
        identvouch_withdraw(local->device_path);
    serial_close(&local->serial_fd);
    cf_handler_spindown(caph);
}

/* -----------------------------------------------------------------------
 * main
 * ----------------------------------------------------------------------- */

int main(int argc, char *argv[]) {
    local_cell_t local = {
        .serial_fd = -1,
        .gnss_fd = -1,
        .device_path = NULL,
        .modem_imei = NULL,
        .modem_firmware = NULL,
        .modem_model = NULL,
        .name = NULL,
        .serving_interval_ms = 2000,
        .neighbor_interval_ms = 5000,
        .fullscan_interval_ms = 0,
        .serving_last_ms = 0,
        .neighbor_last_ms = 0,
        .fullscan_last_ms = 0,
        .vendor = VENDOR_UNKNOWN,
        .has_qeng = 0,
        .has_qscan = 0,
        .has_rfsts = 0,
        .has_servinfo = 0,
        .has_moni = 0,
        .has_csurvc = 0,
        .has_gstatus = 0,
        .has_lteinfo = 0,
        .has_nrinfo = 0,
        .has_scellinfo = 0,
        .has_qcrsrp = 0,
        .cached_tac = 0,
        .cached_cell_id = 0,
        .cached_pci = -1,
        .cached_valid = 0,
        .strategy = NULL,   /* resolved in open_callback */
        .debug = 0,
        .clock_anchor_interval_ms = 30000,  /* set for real in open_callback */
        .clock_anchor_last_ms = 0,
        .clock_anchor_seq = 0,
        .source_uuid = NULL,
        .optset_lock = PTHREAD_MUTEX_INITIALIZER,
        .pending_strategy = NULL,
    };

    kis_capture_handler_t *caph = cf_handler_init("cellat");

    if (caph == NULL) {
        fprintf(stderr, "FATAL: Could not allocate basic handler data, your system "
                "is very low on RAM or something is wrong.\n");
        return -1;
    }

    cf_handler_set_userdata(caph, &local);
    cf_handler_set_open_cb(caph, open_callback);
    cf_handler_set_probe_cb(caph, probe_callback);
    cf_handler_set_listdevices_cb(caph, list_callback);
    cf_handler_set_capture_cb(caph, capture_thread);
    /* Runtime settings via set_channel. Both callbacks, or the
     * framework answers every CONFIGURE with "does not support channel
     * configuration". */
    cf_handler_set_chantranslate_cb(caph, cellat_chantranslate);
    cf_handler_set_chancontrol_cb(caph, cellat_chancontrol);
    /* Stop on the server's CLOSEREQ with the pipe still open, so the end
     * anchor lands. The grace covers the AT command in flight when the close
     * arrives (<= 5 s, AT+CPSI?) plus the END AT+CCLK? (3 s timeout); a
     * responsive modem finishes in well under a second. */
    cf_handler_set_close_grace(caph, CELLAT_CLOSE_GRACE_MS);

    int r = cf_handler_parse_opts(caph, argc, argv);
    if (r == 0) {
        return 0;
    } else if (r < 0) {
        cf_print_help(caph, argv[0]);
        return -1;
    }

    /* Support remote capture */
    cf_handler_remote_capture(caph);

    /* Jail filesystem — serial devices need to be accessible */
    cf_jail_filesystem(caph);

    /* Drop most capabilities but keep what we need for serial */
    cf_drop_most_caps(caph);

    cf_handler_loop(caph);

    cf_handler_shutdown(caph);

    /* Withdraw the vouch here as well as at the capture thread's
     * teardown: on pipe EOF (a remote capture's server going away,
     * a graceful close) the loop returns and main exits 0
     * without that thread ever reaching `done:`, so its withdraw alone would
     * leave the record behind. SIGTERM/SIGKILL still skip both; the
     * reader refuses a dead writer's record for exactly that case. */
    if (local.device_path && local.device_path[0])
        identvouch_withdraw(local.device_path);

    /* Cleanup */
    if (local.serial_fd >= 0)
        close(local.serial_fd);
    free(local.device_path);
    free(local.modem_imei);
    free(local.modem_firmware);
    free(local.modem_model);
    free(local.name);

    return 0;
}
