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

    cellat_stats -- the "cellat_stats" control line.

    WHY THIS EXISTS. Without it a cellat source has no readback: it registers
    no datasource fields, so the web UI can say only "running" while the helper
    counts RawAT rows, atlog records and clock anchors internally. This line
    tells the operator which scan profile is armed, whether observations are
    flowing, and whether the raw AT tee is writing.
    celldiag solves the same problem with its `diag_stats` line; this
    is cellat's equivalent, routed as its own JSON type so the datasource
    intercepts it and phy_cell never builds a device from it.

    THE ONE RULE: A VALUE NEVER MEASURED IS OMITTED, NOT SENT AS ZERO. Kismet
    serialises every registered field whether or not it was set, so the web UI
    re-derives "unreported" from sentinels -- and a helper that sends
    `last_obs_epoch: 0` or `atlog_records: 0` for "no atlog= configured" hands
    it a healthy-looking zero instead. See cellat_stats_t for which fields are
    optional and what absence means for each.

    Pure libc (plus atlog.c's JSON escaper), so test_cellat_stats drives it on a
    host with no modem, no framework and no Kismet -- like diag_stats.c.
*/

#ifndef __CELLAT_STATS_H__
#define __CELLAT_STATS_H__

#include <stddef.h>
#include <stdint.h>
#include <time.h>

#ifdef __cplusplus
extern "C" {
#endif

/* Seconds between periodic stats lines. The line is ALSO sent at once when the
 * source's state changes (full scan starting or ending, a runtime setting
 * applied), so a control's readback never waits a whole interval. */
#define CELLAT_STATS_INTERVAL_S 5

typedef struct {
    /* "surveying" | "full_scan" | "disabled". Always sent. */
    const char *state;

    /* The armed scan profile: canonical name and label (cellat_options.c).
     * NULL -> omitted. */
    const char *strategy;
    const char *strategy_label;
    /* The intervals actually in force, in ms; 0 means that scan is off. Sent
     * with the profile, because after a runtime switch THESE are the
     * readback, not the name. */
    unsigned long serving_interval_ms;
    unsigned long neighbor_interval_ms;
    unsigned long fullscan_interval_ms;

    /* The profile vocabulary this binary accepts, as ';'-separated rows of
     * `name,label,fullscan_s`. The web UI's profile selector is built from
     * THIS rather than a list of its own, so the panel can never offer a
     * profile the running binary would refuse. NULL -> omitted. */
    const char *strategies;

    /* 1 if the modem has a full band scan command (AT+QSCAN / AT#CSURVC),
     * 0 if not, -1 unknown -> omitted. Unknown on a disabled source: nothing
     * was probed. */
    int fullscan_capable;
    /* When state is "full_scan": the unix time the scan started. The scan
     * blocks the AT port for up to 3 minutes, and no other line is sent until
     * it returns -- so this is how the panel tells a long scan from a hang. */
    time_t fullscan_started_epoch;

    /* Observations relayed to Kismet (sent, not merely parsed). */
    uint64_t obs_total;
    /* Throughput since the previous stats line; < 0 -> not measured yet
     * (the first line of a session) -> omitted. */
    double obs_per_sec;
    /* Unix time of the last observation; 0 -> none yet -> omitted. */
    time_t last_obs_epoch;

    /* RawAT rows into the kismetdb. Always on while capturing, so
     * always sent (a disabled source sends neither). */
    uint64_t rawat_records;
    uint64_t rawat_dropped;

    /* qmifeed= and its in-band raw QMI.
     * has_qmifeed 0 -> no feed configured -> ALL qmifeed_* and rawqmi_* keys
     * are omitted, for the atlog_* reason below. qmifeed_active is whether
     * the child is still running. */
    int has_qmifeed;
    int qmifeed_active;
    uint64_t qmifeed_sent;          /* CellModem rows relayed */
    uint64_t qmifeed_dropped;       /* send failure / full ringbuffer */
    uint64_t qmifeed_dropped_imei;  /* prov.imei is not this source's */
    uint64_t qmifeed_msgs;          /* #msg notes forwarded */
    uint64_t rawqmi_records;        /* RawQMI rows into the kismetdb */
    uint64_t rawqmi_dropped;

    /* atlog= file tee. atlog_path NULL -> no tee was configured ->
     * ALL atlog_* keys are omitted, because "0 records" would read as "the tee
     * is on and nothing is being written". */
    const char *atlog_path;
    int atlog_active;
    uint64_t atlog_records;
    uint64_t atlog_dropped;

    /* ClockAnchor rows sent. anchor_last_epoch 0 -> none yet ->
     * omitted; the count is always sent while capturing. */
    uint64_t anchor_count;
    time_t anchor_last_epoch;

    /* Band/RAT lock. lock_valid gates the group (a capturing
     * source); lock_capable is then always sent; the channel only when
     * capable, the error only when there is one. */
    int lock_valid;
    int lock_capable;
    const char *lock_channel;
    const char *lock_error;

    /* Identity. NULL or "" -> omitted. */
    const char *at_port;
    const char *model;
    const char *firmware;

    /* When this line was generated, and the periodic cadence -- together they
     * let the panel say "stale" without guessing what fresh looks like. */
    time_t stats_epoch;
    unsigned int stats_interval_s;
} cellat_stats_t;

/* Initialise to the "nothing measured" state: every optional field set to its
 * omit sentinel. Callers fill in what they know. */
void cellat_stats_init(cellat_stats_t *s);

/* Format the stats object as one JSON object (no trailing newline). Returns
 * the length written, or -1 if it does not fit in `outsz` (out is then an
 * empty string, never a truncated object: a half-object is worse than none,
 * because the server-side parser would drop it silently and the panel would
 * keep rendering the previous interval's numbers as current). */
int cellat_stats_format_json(const cellat_stats_t *s, char *out, size_t outsz);

/* Build the `strategies` vocabulary string from the profile table in
 * cellat_options.c. Returns the length, or -1 on overflow. */
int cellat_stats_strategies(char *out, size_t outsz);

#ifdef __cplusplus
}
#endif

#endif /* __CELLAT_STATS_H__ */
