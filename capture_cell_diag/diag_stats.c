/* diag_stats.c - per-source health counters for the celldiag source.
 * See diag_stats.h. Pure libc; no Kismet dependency. */

#include "diag_stats.h"

#include <stdio.h>
#include <string.h>

void diag_stats_init(diag_stats_t *s, time_t now) {
    if (!s)
        return;
    memset(s, 0, sizeof(*s));
    /* Seed the cadence baseline at open so the first status fires ~one interval
     * later rather than on the very first poll tick. */
    s->last_status_ts = now;
}

void diag_stats_on_read(diag_stats_t *s, size_t nbytes, time_t now) {
    if (!s)
        return;
    s->bytes_read += (uint64_t)nbytes;
    s->last_read_ts = now;
}

void diag_stats_on_read_error(diag_stats_t *s) {
    if (!s)
        return;
    s->read_errors++;
}

void diag_stats_on_obs_dropped(diag_stats_t *s) {
    if (!s)
        return;
    s->obs_ring_dropped++;
}

void diag_stats_on_obs(diag_stats_t *s, time_t now) {
    if (!s)
        return;
    s->obs_total++;
    s->obs_since_status++;
    s->last_obs_ts = now;

    /* Push into the rolling-rate ring. */
    s->rate_ring[s->rate_head] = now;
    s->rate_head = (s->rate_head + 1) % DIAG_STATS_RATE_SLOTS;
    if (s->rate_count < DIAG_STATS_RATE_SLOTS)
        s->rate_count++;
}

void diag_stats_set_helper_alive(diag_stats_t *s, int alive) {
    if (!s)
        return;
    s->helper_alive = alive ? 1 : 0;
}

int diag_stats_heartbeat_stale(uint64_t hb_ns, uint64_t now_ns, uint64_t bound_ns) {
    if (hb_ns == 0)
        return 0;              /* not armed: nothing was asked to beat */
    if (now_ns <= hb_ns)
        return 0;              /* beat after the caller read its clock */
    return now_ns - hb_ns > bound_ns;
}

void diag_stats_set_port_open(diag_stats_t *s, int open) {
    if (!s)
        return;
    s->port_open = open ? 1 : 0;
}

void diag_stats_set_mask_preset(diag_stats_t *s, const char *preset) {
    if (!s)
        return;
    if (!preset) {
        s->mask_preset[0] = '\0';
        return;
    }
    snprintf(s->mask_preset, sizeof(s->mask_preset), "%s", preset);
}

double diag_stats_obs_per_sec(const diag_stats_t *s, time_t now) {
    if (!s || s->rate_count == 0)
        return 0.0;
    time_t cutoff = now - DIAG_STATS_RATE_WINDOW_SEC;
    size_t in_window = 0;
    for (size_t i = 0; i < s->rate_count; i++) {
        /* Walk backwards from the most-recent write. */
        size_t idx = (s->rate_head + DIAG_STATS_RATE_SLOTS - 1 - i)
                     % DIAG_STATS_RATE_SLOTS;
        if (s->rate_ring[idx] > cutoff)
            in_window++;
        else
            break;  /* ring is time-ordered; older entries are all out of window */
    }
    return (double)in_window / (double)DIAG_STATS_RATE_WINDOW_SEC;
}

/* The producer arms come FIRST, before the recency arms.
 *
 * For a full `stall_after` window after the decoder stops, the last read and
 * the last observation are still recent. A verdict computed from recency alone
 * would read FLOWING on the same line as `port=closed ... decoder=stopped`: a
 * lagging indicator presented as a current-state verdict. The README makes
 * this word the headline health signal, so a monitor keying on the verdict
 * alone would read a dead source as healthy.
 *
 * The decoder runs on the reader thread, so the port comes first (a closed
 * port is why a finished reader stops), and a decoder that is not alive behind
 * an open port is a stuck reader: DECODER-STALLED.
 *
 * Both arms are unconditional, deliberately. `diag_stats_format` always
 * prints `port=` and `decoder=`, so any state where the word disagrees with
 * them is the defect.
 *
 * NODATA still wins over both: a source that never read a byte has nothing to
 * diagnose yet. */
const char *diag_stats_verdict(const diag_stats_t *s, time_t now,
                               time_t stall_after) {
    if (!s || s->last_read_ts == 0)
        return "NODATA";
    if (!s->port_open)
        return "PORT-CLOSED";
    if (!s->helper_alive)
        return "DECODER-STALLED";
    if (now - s->last_read_ts > stall_after)
        return "STALLED";
    if (s->last_obs_ts != 0 && now - s->last_obs_ts <= stall_after)
        return "FLOWING";
    return "RX-NO-OBS";
}

int diag_stats_due(const diag_stats_t *s, time_t interval, time_t now) {
    if (!s || interval <= 0)
        return 0;
    return (now - s->last_status_ts) >= interval;
}

/* Age in seconds since `ts`, or -1 if `ts` is 0 (never). */
static long age_or_never(time_t ts, time_t now) {
    if (ts == 0)
        return -1;
    long a = (long)(now - ts);
    return a < 0 ? 0 : a;
}

int diag_stats_format(const diag_stats_t *s, time_t now, time_t stall_after,
                      char *buf, size_t buflen) {
    if (!s || !buf || buflen == 0)
        return -1;

    long read_age = age_or_never(s->last_read_ts, now);
    long obs_age = age_or_never(s->last_obs_ts, now);
    char read_age_s[24], obs_age_s[24];
    if (read_age < 0)
        snprintf(read_age_s, sizeof(read_age_s), "never");
    else
        snprintf(read_age_s, sizeof(read_age_s), "%lds", read_age);
    if (obs_age < 0)
        snprintf(obs_age_s, sizeof(obs_age_s), "never");
    else
        snprintf(obs_age_s, sizeof(obs_age_s), "%lds", obs_age);

    /* "stopped" (port closed) is a reader that finished, not one that hung. */
    char producer_s[64];
    snprintf(producer_s, sizeof(producer_s), "decoder=%s",
             s->helper_alive ? "alive" :
             s->port_open    ? "stalled" : "stopped");

    int n = snprintf(buf, buflen,
        "celldiag stats: %s | port=%s bytes=%llu rd_err=%llu last_read=%s | "
        "obs=%llu (+%llu %.2f/s) last_obs=%s | %s | mask=%s",
        diag_stats_verdict(s, now, stall_after),
        s->port_open ? "open" : "closed",
        (unsigned long long)s->bytes_read,
        (unsigned long long)s->read_errors,
        read_age_s,
        (unsigned long long)s->obs_total,
        (unsigned long long)s->obs_since_status,
        diag_stats_obs_per_sec(s, now),
        obs_age_s,
        producer_s,
        s->mask_preset[0] ? s->mask_preset : "?");

    if (n < 0)
        return -1;
    /* snprintf returns the would-be length; clamp to what actually fit. */
    return (size_t)n >= buflen ? (int)(buflen - 1) : n;
}

/* JSON-escape `in` into `out`. Returns 0 on success, -1 if the escaped form
 * would not fit (out left unusable; callers must treat -1 as "omit the key").
 *
 * Unlike mask_preset -- a controlled label where an unsafe byte means
 * corruption and rendering it empty is right -- rawlog_path is an operator-
 * supplied filesystem path that may LEGITIMATELY contain a quote or backslash.
 * Blanking it would lie to the operator about where the tee is writing, so it
 * gets real escaping. Control bytes go to \uXXXX (the only correct JSON form;
 * a bare control byte in a string is invalid and would fail the consumer's
 * parse, taking every other field down with it). */
static int json_escape(const char *in, char *out, size_t outsz) {
    size_t o = 0;
    for (const unsigned char *p = (const unsigned char *)in; *p; p++) {
        char esc[8];
        size_t need;
        if (*p == '"' || *p == '\\') {
            esc[0] = '\\'; esc[1] = (char)*p; need = 2;
        } else if (*p < 0x20) {
            need = (size_t)snprintf(esc, sizeof(esc), "\\u%04x", *p);
        } else {
            esc[0] = (char)*p; need = 1;
        }
        if (o + need + 1 > outsz)
            return -1;
        memcpy(out + o, esc, need);
        o += need;
    }
    if (o + 1 > outsz)
        return -1;
    out[o] = '\0';
    return 0;
}

int diag_stats_format_json(const diag_stats_t *s, time_t now,
                           char *buf, size_t buflen) {
    return diag_stats_format_json_ex(s, NULL, now, buf, buflen);
}

int diag_stats_format_json_ex(const diag_stats_t *s, const diag_stats_extra_t *x,
                              time_t now, char *buf, size_t buflen) {
    if (!s || !buf || buflen == 0)
        return -1;

    /* Machine-parseable companion to diag_stats_format: one JSON object
     * whose keys are the registered kis_datasource_cell_diag field *suffixes*
     * (kismet.datasource.celldiag.<key>), so the datasource can SET each tracker
     * field by key instead of scraping the human status line. The "type" marker
     * routes it like diag_inventory / diag_f3 (a structured control line, NOT a
     * cell_observation). Only the six diag_stats-owned counters are emitted here;
     * the config-owned strings (f3_preset, rawlog_path, rawlog_bytes) and the
     * census (inventory_*) are layered in by the emit site that
     * owns them.
     *
     * mask_preset is a controlled label (wardrive/full/disabled/replay/"") so it
     * needs no JSON escaping; guard defensively anyway by refusing a preset that
     * contains a quote/backslash/control byte (renders it empty rather than
     * breaking the JSON) -- a corrupt preset must never emit an unparseable line. */
    const char *mp = s->mask_preset;
    int mp_safe = 1;
    for (const char *p = mp; *p; p++) {
        if (*p == '"' || *p == '\\' || (unsigned char)*p < 0x20) {
            mp_safe = 0;
            break;
        }
    }

    long long last_obs_epoch = (s->last_obs_ts > 0) ? (long long)s->last_obs_ts : 0;

    /* The extras are rendered into their own buffer first so the whole
     * object can be re-rendered without the unbounded rawlog_path if it does
     * not fit -- see the header's truncation contract. `drop_path` is the retry
     * flag; the loop runs at most twice. */
    for (int drop_path = 0; drop_path <= 1; drop_path++) {
        char extra[DIAG_STATS_EXTRA_MAX];
        size_t eo = 0;
        int etrunc = 0;

        /* Append helper: on overflow set etrunc rather than emitting a partial
         * key, so a clipped fragment can never reach the output object. */
#define XAPPEND(...) do {                                                     \
            int _r = snprintf(extra + eo, sizeof(extra) - eo, __VA_ARGS__);   \
            if (_r < 0 || (size_t)_r >= sizeof(extra) - eo) { etrunc = 1; }   \
            else { eo += (size_t)_r; }                                        \
        } while (0)

        if (x && !etrunc) {
            if (x->decode_mode)
                XAPPEND(",\"decode_mode\":\"%s\"", x->decode_mode);
            if (x->f3_preset) {
                char f3e[DIAG_STATS_MASK_MAX * 6];
                if (json_escape(x->f3_preset, f3e, sizeof(f3e)) == 0)
                    XAPPEND(",\"f3_preset\":\"%s\"", f3e);
            }
            if (x->rawlog_path && !drop_path) {
                char pe[DIAG_STATS_EXTRA_MAX];
                if (json_escape(x->rawlog_path, pe, sizeof(pe)) == 0)
                    XAPPEND(",\"rawlog_path\":\"%s\"", pe);
                else
                    etrunc = 1;   /* forces the drop_path retry */
            }
            /* rawlog_active ships WITH the bytes counter, not with the path:
             * the drop_path retry above discards the one unbounded field, and
             * a liveness flag that vanished with it would leave the panel
             * counting bytes for a sink it can no longer say is open. */
            if (x->rawlog_valid)
                XAPPEND(",\"rawlog_bytes\":%llu,\"rawlog_active\":%s",
                        (unsigned long long)x->rawlog_bytes,
                        x->rawlog_active ? "true" : "false");
            /* All three census keys or none -- see diag_stats_extra_t. */
            if (x->inventory_valid) {
                XAPPEND(",\"inventory_distinct_codes\":%llu,"
                        "\"inventory_unrecognized\":%llu,"
                        "\"inventory_silent\":%llu",
                        (unsigned long long)x->inventory_distinct_codes,
                        (unsigned long long)x->inventory_unrecognized,
                        (unsigned long long)x->inventory_silent);
                if (x->inventory_undecoded_valid)
                    XAPPEND(",\"inventory_undecoded_native\":%llu",
                            (unsigned long long)x->inventory_undecoded_native);
            }
            /* All seven native-tap keys or none. The denominator ships
             * with the numerator on purpose -- see diag_stats_extra_t: a
             * coverage figure is a RATIO, and half of it published alone is
             * worse than none. An unarmed tap omits the group entirely, so
             * apply_diag_stats_json leaves those fields at their defaults
             * rather than stamping zeros that read as "native decoded nothing"
             * when the truth is "native was never asked". */
            if (x->native_valid) {
                XAPPEND(",\"native_total_records\":%llu,"
                        "\"native_records\":%llu,"
                        "\"native_obs\":%llu,"
                        "\"native_declined\":%llu,"
                        "\"native_enriched\":%llu,"
                        "\"native_gps_fixes\":%llu,"
                        "\"native_fallback_records\":%llu",
                        (unsigned long long)x->native_total_records,
                        (unsigned long long)x->native_records,
                        (unsigned long long)x->native_obs,
                        (unsigned long long)x->native_declined,
                        (unsigned long long)x->native_enriched,
                        (unsigned long long)x->native_gps_fixes,
                        (unsigned long long)x->native_fallback_records);
            }
            /* The stream-switch groups, each whole or not at all. */
            if (x->rawpackets_valid)
                XAPPEND(",\"rawpackets_on\":%s,\"rawpackets_slices\":%llu,"
                        "\"rawpackets_dropped\":%llu",
                        x->rawpackets_on ? "true" : "false",
                        (unsigned long long)x->rawpackets_slices,
                        (unsigned long long)x->rawpackets_dropped);
            if (x->qsh_valid)
                XAPPEND(",\"qsh_requested\":%s,\"qsh_armed\":%s",
                        x->qsh_requested ? "true" : "false",
                        x->qsh_armed ? "true" : "false");
            /* The CRC census group, whole or not at all. */
            if (x->crc_valid)
                XAPPEND(",\"crc_checked\":%llu,\"crc_ok\":%llu,"
                        "\"crc_bad\":%llu,\"crc_damage_alerts\":%llu",
                        (unsigned long long)x->crc_checked,
                        (unsigned long long)x->crc_ok,
                        (unsigned long long)x->crc_bad,
                        (unsigned long long)x->crc_damage_alerts);
            if (x->anchor_valid) {
                XAPPEND(",\"anchor_count\":%llu,\"anchor_ring_dropped\":%llu",
                        (unsigned long long)x->anchor_count,
                        (unsigned long long)x->anchor_ring_dropped);
                if (x->anchor_last_epoch > 0)
                    XAPPEND(",\"anchor_last_epoch\":%lld", x->anchor_last_epoch);
            }
        }
#undef XAPPEND

        if (etrunc) {
            if (drop_path)
                return -1;      /* even without the path it will not fit */
            continue;           /* retry without rawlog_path */
        }

        int n = snprintf(buf, buflen,
            "{\"type\":\"diag_stats\","
            "\"bytes_read\":%llu,"
            "\"obs_total\":%llu,"
            "\"obs_ring_dropped\":%llu,"
            "\"obs_per_sec\":%.3f,"
            "\"last_obs_epoch\":%lld,"
            "\"helper_alive\":%d,"
            "\"mask_preset\":\"%s\""
            "%s}",
            (unsigned long long)s->bytes_read,
            (unsigned long long)s->obs_total,
            (unsigned long long)s->obs_ring_dropped,
            diag_stats_obs_per_sec(s, now),
            last_obs_epoch,
            s->helper_alive ? 1 : 0,
            mp_safe ? mp : "",
            extra);

        if (n < 0)
            return -1;
        if ((size_t)n >= buflen) {
            /* Would be truncated. Retry without the one unbounded field; if we
             * already did, refuse -- a clipped object does not parse, and the
             * consumer dropping it costs every field in this tick. */
            if (drop_path)
                return -1;
            continue;
        }
        return n;
    }
    return -1;
}

int diag_stats_format_bringup_json(const char *phases, long elapsed_ms,
                                   const char *error, char *buf, size_t buflen) {
    if (!buf || buflen == 0)
        return -1;
    char pe[DIAG_STATS_EXTRA_MAX];
    if (json_escape(phases ? phases : "", pe, sizeof(pe)) != 0)
        return -1;
    char ee[DIAG_STATS_EXTRA_MAX];
    if (error && json_escape(error, ee, sizeof(ee)) != 0)
        return -1;

    int n;
    if (error)
        n = snprintf(buf, buflen,
            "{\"type\":\"diag_stats\",\"bringup_ms\":%ld,"
            "\"bringup_phases\":\"%s\",\"bringup_error\":\"%s\","
            "\"helper_alive\":0,\"mask_preset\":\"failed\"}",
            elapsed_ms, pe, ee);
    else
        n = snprintf(buf, buflen,
            "{\"type\":\"diag_stats\",\"bringup_ms\":%ld,"
            "\"bringup_phases\":\"%s\"}", elapsed_ms, pe);
    if (n < 0 || (size_t)n >= buflen)
        return -1;
    return n;
}

/* Whole seconds, rounded down: "no progress for 10.9 s" reads as 10s, so the
 * figure printed is never larger than what was measured. */
int diag_stats_format_decoder_stalled(uint64_t no_progress_ms, uint64_t bound_ms,
                                      char *buf, size_t buflen) {
    if (!buf || buflen == 0)
        return -1;
    int n = snprintf(buf, buflen,
        "celldiag stats: DECODER-STALLED | decoder=stalled no_progress=%llus "
        "bound=%llus | the native DIAG reader has stopped "
        "advancing: observations have stopped",
        (unsigned long long)(no_progress_ms / 1000ULL),
        (unsigned long long)(bound_ms / 1000ULL));
    if (n < 0 || (size_t)n >= buflen)
        return -1;
    return n;
}

int diag_stats_format_liveness_json(int alive, const char *decode_mode,
                                    char *buf, size_t buflen) {
    if (!buf || buflen == 0)
        return -1;
    /* A controlled label: refuse rather than escape, as mask_preset is
     * guarded, so a corrupt label can never produce an unparseable object. */
    if (decode_mode) {
        for (const char *p = decode_mode; *p; p++)
            if (*p == '"' || *p == '\\' || (unsigned char)*p < 0x20)
                return -1;
    }
    int n;
    if (decode_mode)
        n = snprintf(buf, buflen,
                     "{\"type\":\"diag_stats\",\"helper_alive\":%d,"
                     "\"decode_mode\":\"%s\"}", alive ? 1 : 0, decode_mode);
    else
        n = snprintf(buf, buflen,
                     "{\"type\":\"diag_stats\",\"helper_alive\":%d}",
                     alive ? 1 : 0);
    if (n < 0 || (size_t)n >= buflen)
        return -1;
    return n;
}

void diag_stats_mark_status(diag_stats_t *s, time_t now) {
    if (!s)
        return;
    s->last_status_ts = now;
    s->obs_since_status = 0;
}
