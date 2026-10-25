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

    cellat_stats -- see cellat_stats.h for why.
*/

#include "cellat_stats.h"

#include <stdarg.h>
#include <stdio.h>
#include <string.h>

#include "atlog.h"
#include "cellat_options.h"

void cellat_stats_init(cellat_stats_t *s) {
    if (s == NULL)
        return;
    memset(s, 0, sizeof(*s));
    s->state = "surveying";
    s->fullscan_capable = -1;
    s->obs_per_sec = -1.0;
    s->stats_interval_s = CELLAT_STATS_INTERVAL_S;
}

/* A bounded appender. Once anything overflows, every later append is a no-op
 * and the whole format fails -- the caller never sees a truncated object. */
typedef struct {
    char *buf;
    size_t cap;
    size_t len;
    int overflow;
    int first;
} jw_t;

static void jw_raw(jw_t *w, const char *fmt, ...) {
    if (w->overflow)
        return;
    va_list ap;
    va_start(ap, fmt);
    int n = vsnprintf(w->buf + w->len, w->cap - w->len, fmt, ap);
    va_end(ap);
    if (n < 0 || (size_t)n >= w->cap - w->len) {
        w->overflow = 1;
        return;
    }
    w->len += (size_t)n;
}

static void jw_key(jw_t *w, const char *key) {
    jw_raw(w, "%s\"%s\":", w->first ? "" : ",", key);
    w->first = 0;
}

static void jw_str(jw_t *w, const char *key, const char *val) {
    char esc[1024];
    if (atlog_json_escape(val, strlen(val), esc, sizeof(esc)) < 0) {
        w->overflow = 1;
        return;
    }
    jw_key(w, key);
    jw_raw(w, "\"%s\"", esc);
}

/* Optional string: NULL and "" are both "we do not know", and are omitted. */
static void jw_str_opt(jw_t *w, const char *key, const char *val) {
    if (val != NULL && val[0] != '\0')
        jw_str(w, key, val);
}

static void jw_u64(jw_t *w, const char *key, uint64_t v) {
    jw_key(w, key);
    jw_raw(w, "%llu", (unsigned long long)v);
}

static void jw_bool(jw_t *w, const char *key, int v) {
    jw_key(w, key);
    jw_raw(w, "%s", v ? "true" : "false");
}

int cellat_stats_format_json(const cellat_stats_t *s, char *out, size_t outsz) {
    if (out == NULL || outsz == 0)
        return -1;
    out[0] = '\0';
    if (s == NULL)
        return -1;

    jw_t w = { .buf = out, .cap = outsz, .len = 0, .overflow = 0, .first = 1 };
    const int disabled = (s->state != NULL && strcmp(s->state, "disabled") == 0);

    jw_raw(&w, "{");
    jw_str(&w, "state", s->state ? s->state : "surveying");

    jw_str_opt(&w, "strategy", s->strategy);
    jw_str_opt(&w, "strategy_label", s->strategy_label);
    jw_str_opt(&w, "strategies", s->strategies);

    /* A disabled source measured nothing: no port was opened, no interval
     * is in force, and zeros here would render as "a source that is running
     * and seeing nothing", which reads as a dead helper.
     * It sends its state, its profile and its clock, and stops. */
    if (!disabled) {
        if (s->strategy != NULL) {
            jw_u64(&w, "serving_interval_ms", s->serving_interval_ms);
            jw_u64(&w, "neighbor_interval_ms", s->neighbor_interval_ms);
            jw_u64(&w, "fullscan_interval_ms", s->fullscan_interval_ms);
        }
        if (s->fullscan_capable >= 0)
            jw_bool(&w, "fullscan_capable", s->fullscan_capable);
        if (s->state != NULL && strcmp(s->state, "full_scan") == 0 &&
                s->fullscan_started_epoch > 0)
            jw_u64(&w, "fullscan_started_epoch",
                   (uint64_t)s->fullscan_started_epoch);

        jw_u64(&w, "obs_total", s->obs_total);
        if (s->obs_per_sec >= 0.0) {
            jw_key(&w, "obs_per_sec");
            jw_raw(&w, "%.3f", s->obs_per_sec);
        }
        if (s->last_obs_epoch > 0)
            jw_u64(&w, "last_obs_epoch", (uint64_t)s->last_obs_epoch);

        jw_u64(&w, "rawat_records", s->rawat_records);
        jw_u64(&w, "rawat_dropped", s->rawat_dropped);

        if (s->has_qmifeed) {
            jw_bool(&w, "qmifeed_configured", 1);
            jw_bool(&w, "qmifeed_active", s->qmifeed_active);
            jw_u64(&w, "qmifeed_sent", s->qmifeed_sent);
            jw_u64(&w, "qmifeed_dropped", s->qmifeed_dropped);
            jw_u64(&w, "qmifeed_dropped_imei", s->qmifeed_dropped_imei);
            jw_u64(&w, "qmifeed_msgs", s->qmifeed_msgs);
            jw_u64(&w, "rawqmi_records", s->rawqmi_records);
            jw_u64(&w, "rawqmi_dropped", s->rawqmi_dropped);
        }

        if (s->atlog_path != NULL && s->atlog_path[0] != '\0') {
            jw_str(&w, "atlog_path", s->atlog_path);
            jw_bool(&w, "atlog_active", s->atlog_active);
            jw_u64(&w, "atlog_records", s->atlog_records);
            jw_u64(&w, "atlog_dropped", s->atlog_dropped);
        }

        jw_u64(&w, "anchor_count", s->anchor_count);
        if (s->anchor_last_epoch > 0)
            jw_u64(&w, "anchor_last_epoch", (uint64_t)s->anchor_last_epoch);

        if (s->lock_valid) {
            jw_bool(&w, "lock_capable", s->lock_capable);
            jw_str_opt(&w, "lock_channel", s->lock_channel);
            /* ALWAYS sent while capturing, "" included: an omitted key keeps
             * the server's previous value, so a cleared error would stick. */
            jw_str(&w, "lock_error", s->lock_error ? s->lock_error : "");
        }
        jw_str_opt(&w, "at_port", s->at_port);
        jw_str_opt(&w, "model", s->model);
        jw_str_opt(&w, "firmware", s->firmware);
    }

    jw_u64(&w, "stats_epoch", (uint64_t)s->stats_epoch);
    jw_u64(&w, "stats_interval_s", s->stats_interval_s);
    jw_raw(&w, "}");

    if (w.overflow) {
        out[0] = '\0';
        return -1;
    }
    return (int)w.len;
}

int cellat_stats_strategies(char *out, size_t outsz) {
    if (out == NULL || outsz == 0)
        return -1;
    size_t off = 0;
    out[0] = '\0';
    for (size_t i = 0; i < cellat_strategy_count(); i++) {
        const cellat_strategy_t *p = cellat_strategy_at(i);
        int n = snprintf(out + off, outsz - off, "%s%s,%s,%lu",
                         i ? ";" : "", p->name, p->label,
                         p->fullscan_ms / 1000);
        if (n < 0 || (size_t)n >= outsz - off) {
            out[0] = '\0';
            return -1;
        }
        off += (size_t)n;
    }
    return (int)off;
}
