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

    cellat_optset -- see cellat_optset.h.
*/

#include "cellat_optset.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

/* Every option a cellat source definition can carry, and whether it can change
 * while the source runs. The open-time rows are here ON PURPOSE: a correctly
 * spelled `atport=` sent at runtime must be told "not while running, and why",
 * not "no such option" -- that would send the operator hunting for a typo in a
 * key that is right (diag_optset's OPEN_TIME_ONLY rule). The runtime-key list
 * in every message is generated from this table. */
static const struct {
    const char          *name;
    cellat_optset_key_t  key;
    const char          *decline;   /* NULL iff runtime-settable */
} KEYS[] = {
    { "strategy",         CELLAT_OPTSET_KEY_STRATEGY,     NULL },
    { "atlog",            CELLAT_OPTSET_KEY_ATLOG,        NULL },
    { "clock_anchor_sec", CELLAT_OPTSET_KEY_CLOCK_ANCHOR, NULL },
    { "atport",           CELLAT_OPTSET_KEY_OPEN_ONLY,
      "the AT port is found and IMEI-verified at open; close the source and "
      "reopen it with the new atport=" },
    { "enabled",          CELLAT_OPTSET_KEY_OPEN_ONLY,
      "enabled= decides whether the port is opened at all, so changing it is a "
      "re-open -- use the panel's Enable/Disable capture control, which does "
      "exactly that" },
    { "debug",            CELLAT_OPTSET_KEY_OPEN_ONLY,
      "debug= is read at open; reopen the source to change it" },
    { "transcript",       CELLAT_OPTSET_KEY_OPEN_ONLY,
      "the transcript file is opened at open; reopen the source to change it "
      "(atlog= is the runtime-switchable raw AT capture)" },
    { "uuid",             CELLAT_OPTSET_KEY_OPEN_ONLY,
      "a source's uuid is its identity in Kismet and cannot change while it "
      "exists" },
};
#define N_KEYS (sizeof(KEYS) / sizeof(KEYS[0]))

const char *cellat_optset_runtime_keys(void) {
    static char buf[128];
    if (buf[0] == '\0') {
        size_t off = 0;
        for (size_t i = 0; i < N_KEYS; i++) {
            if (KEYS[i].decline != NULL)
                continue;
            int n = snprintf(buf + off, sizeof(buf) - off, "%s%s",
                             off ? "|" : "", KEYS[i].name);
            if (n < 0 || (size_t)n >= sizeof(buf) - off)
                break;
            off += (size_t)n;
        }
    }
    return buf;
}

static void trim(char *s) {
    size_t len, i = 0;
    while (s[i] == ' ' || s[i] == '\t' || s[i] == '\r' || s[i] == '\n')
        i++;
    if (i)
        memmove(s, s + i, strlen(s + i) + 1);
    len = strlen(s);
    while (len && (s[len - 1] == ' ' || s[len - 1] == '\t' ||
                   s[len - 1] == '\r' || s[len - 1] == '\n'))
        s[--len] = '\0';
}

/* A delimiter followed by a KNOWN key and '=' -- the shape of a second
 * setting. Not "contains ',' or '='": both are legal in the path atlog= takes
 * (diag_optset.c documents the version of this that refused real paths). */
static int looks_like_a_second_setting(const char *value) {
    for (size_t i = 0; value[i] != '\0'; i++) {
        if (value[i] != ',' && value[i] != ' ' && value[i] != '\t')
            continue;
        for (size_t k = 0; k < N_KEYS; k++) {
            size_t nlen = strlen(KEYS[k].name);
            if (strncmp(value + i + 1, KEYS[k].name, nlen) == 0 &&
                    value[i + 1 + nlen] == '=')
                return 1;
        }
    }
    return 0;
}

void cellat_optset_parse(const char *spec, cellat_optset_t *out) {
    if (out == NULL)
        return;
    memset(out, 0, sizeof(*out));
    out->status = CELLAT_OPTSET_BAD_SYNTAX;

    char work[CELLAT_OPTSET_VALUE_MAX + 64];
    if (spec == NULL || strlen(spec) >= sizeof(work)) {
        snprintf(out->err, sizeof(out->err),
                 "%s runtime setting; expected <key>=<value> (%s)",
                 spec == NULL ? "empty" : "over-long",
                 cellat_optset_runtime_keys());
        return;
    }
    memcpy(work, spec, strlen(spec) + 1);
    trim(work);
    if (work[0] == '\0') {
        snprintf(out->err, sizeof(out->err),
                 "empty runtime setting; expected <key>=<value> (%s)",
                 cellat_optset_runtime_keys());
        return;
    }

    char *eq = strchr(work, '=');
    if (eq == NULL) {
        /* Classified, not rejected as malformed: see the header. */
        out->status = CELLAT_OPTSET_CHANNEL;
        snprintf(out->value, sizeof(out->value), "%s", work);
        snprintf(out->err, sizeof(out->err),
                 "'%s' is a channel (a band/RAT lock: AUTO, LTE, NR5G, "
                 "LTE-B<n>, NR-n<n>), not a setting. Runtime settings are "
                 "<key>=<value> (%s)", work, cellat_optset_runtime_keys());
        return;
    }
    if (eq == work) {
        snprintf(out->err, sizeof(out->err),
                 "'%s' has no key before '='", work);
        return;
    }

    size_t klen = (size_t)(eq - work);
    if (klen >= sizeof(out->key_str)) {
        snprintf(out->err, sizeof(out->err), "option key is too long");
        return;
    }
    memcpy(out->key_str, work, klen);
    out->key_str[klen] = '\0';
    trim(out->key_str);
    snprintf(out->value, sizeof(out->value), "%s", eq + 1);
    trim(out->value);

    if (looks_like_a_second_setting(out->value)) {
        snprintf(out->err, sizeof(out->err),
                 "'%s' carries more than one setting; send exactly one "
                 "<key>=<value> per request (there is no way to report a "
                 "half-applied pair)", work);
        return;
    }

    size_t i;
    for (i = 0; i < N_KEYS; i++)
        if (strcmp(out->key_str, KEYS[i].name) == 0)
            break;
    if (i == N_KEYS) {
        out->status = CELLAT_OPTSET_UNKNOWN_KEY;
        snprintf(out->err, sizeof(out->err),
                 "no cellat option named '%s' (runtime-settable: %s; open-time "
                 "only: atport, enabled, debug, transcript, uuid)",
                 out->key_str, cellat_optset_runtime_keys());
        return;
    }

    out->key = KEYS[i].key;
    if (KEYS[i].decline != NULL) {
        out->status = CELLAT_OPTSET_OPEN_TIME_ONLY;
        snprintf(out->err, sizeof(out->err),
                 "'%s' is not settable while the source is running: %s",
                 out->key_str, KEYS[i].decline);
        return;
    }

    if (out->value[0] == '\0') {
        out->status = CELLAT_OPTSET_BAD_VALUE;
        snprintf(out->err, sizeof(out->err), "%s= needs a value%s",
                 out->key_str,
                 out->key == CELLAT_OPTSET_KEY_ATLOG ?
                     "; use 'atlog=off' to stop the tee" : "");
        return;
    }

    switch (out->key) {
        case CELLAT_OPTSET_KEY_STRATEGY:
            /* The SAME lookup the open path uses, so the runtime and open-time
             * vocabularies cannot drift. The message is built here rather than
             * borrowed from cellat_strategy_parse(): that one says "the source
             * is NOT opened", which is false for a source that keeps running. */
            out->strategy = cellat_strategy_lookup(out->value);
            if (out->strategy == NULL) {
                char names[256] = "";
                size_t off = 0;
                for (size_t k = 0; k < cellat_strategy_count(); k++) {
                    int n = snprintf(names + off, sizeof(names) - off, "%s%s",
                                     k ? "|" : "", cellat_strategy_at(k)->name);
                    if (n < 0 || (size_t)n >= sizeof(names) - off)
                        break;
                    off += (size_t)n;
                }
                out->status = CELLAT_OPTSET_BAD_VALUE;
                snprintf(out->err, sizeof(out->err),
                         "unknown strategy '%s'; the source keeps its current "
                         "profile. Valid: %s (wardrive is accepted as driving)",
                         out->value, names);
                return;
            }
            break;
        case CELLAT_OPTSET_KEY_ATLOG:
            /* The same two "stop" spellings celldiag's rawlog= uses. */
            out->atlog_disable = (strcmp(out->value, "off") == 0 ||
                                  strcmp(out->value, "none") == 0);
            break;
        case CELLAT_OPTSET_KEY_CLOCK_ANCHOR: {
            char *endp = NULL;
            long secs = strtol(out->value, &endp, 10);
            if (endp == out->value || *endp != '\0' || secs < 0 ||
                    secs > 86400) {
                out->status = CELLAT_OPTSET_BAD_VALUE;
                snprintf(out->err, sizeof(out->err),
                         "clock_anchor_sec='%s' is not a whole number of "
                         "seconds from 0 (periodic anchors off) to 86400; the "
                         "current cadence is kept", out->value);
                return;
            }
            out->clock_anchor_ms = (unsigned long)secs * 1000UL;
            break;
        }
        default:
            break;
    }

    out->status = CELLAT_OPTSET_OK;
    out->err[0] = '\0';
}
