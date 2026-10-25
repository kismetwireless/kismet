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

    cellat source-option recognition -- see cellat_options.h for why.
*/

#include "cellat_options.h"

#include <stdio.h>
#include <string.h>

/* The accepted spellings of a boolean source option, in the order the message
 * should name them. The message is GENERATED FROM THIS ARRAY: a hand-written
 * "(expected true|false)" beside a six-value compare lets the decision and the
 * report disagree about the same rule -- and the report is the half an operator
 * reads. */
static const char *const BOOL_TRUE[]  = { "true",  "1", "yes", NULL };
static const char *const BOOL_FALSE[] = { "false", "0", "no",  NULL };

static int in_list(const char *const *list, const char *v) {
    for (int i = 0; list[i]; i++)
        if (strcmp(list[i], v) == 0)
            return 1;
    return 0;
}

static void join_list(const char *const *list, char *out, size_t outsz) {
    size_t off = 0;
    out[0] = '\0';
    for (int i = 0; list[i]; i++) {
        int n = snprintf(out + off, off < outsz ? outsz - off : 0,
                         "%s%s", i ? "|" : "", list[i]);
        if (n < 0 || (size_t)n >= (off < outsz ? outsz - off : 0))
            return;
        off += (size_t)n;
    }
}

int cellat_bool_option_parse(const char *key, const char *value, int *out,
                             char *msg, size_t msgsz) {
    if (value == NULL) {
        if (msg && msgsz)
            snprintf(msg, msgsz, "%s= needs a value", key ? key : "option");
        return 0;
    }
    if (in_list(BOOL_TRUE, value))  { if (out) *out = 1; return 1; }
    if (in_list(BOOL_FALSE, value)) { if (out) *out = 0; return 1; }

    /* The compare is CASE-SENSITIVE, and that is deliberate, not an
     * oversight: `enabled=False` -- the spelling a Python-side config generator
     * emits -- must hard-error rather than be guessed at. Guessing is how a
     * source ends up in the state the operator did not ask for while reporting
     * success. But the operator has to be TOLD that is the rule, or a rejected
     * `False` reads as a bug in the helper. */
    if (msg && msgsz) {
        char t[64], f[64];
        join_list(BOOL_TRUE, t, sizeof(t));
        join_list(BOOL_FALSE, f, sizeof(f));
        snprintf(msg, msgsz,
                 "Unknown %s value '%s' -- expected %s or %s. The compare is "
                 "case-sensitive on purpose (so '%s' is rejected rather than "
                 "guessed at); spell it lowercase.",
                 key ? key : "option", value, t, f, value);
    }
    return 0;
}

/* ── Scan profiles ──────────────────────────────────────────────────────
 *
 * The profiles are "stationary survey / walking / driving". They differ almost entirely in ONE trade: how often to run the full band
 * scan, which blocks the AT port -- and so the serving and neighbor polls --
 * for 30 s to 3 min (AT+QSCAN=3,1 is given 120 s, AT#CSURVC 180 s). The scan
 * is the only thing that finds cells on bands the modem is not camped on; the
 * blind window is its cost, and how much a blind window costs is a function
 * of speed:
 *
 *   driving     never. A 2-minute scan at 30 m/s is 3.6 km of road with no
 *               serving cell tracked. (Was `wardrive`, still accepted.)
 *   walking     every 5 min. At 1.4 m/s a
 *               5-min cadence samples every band about every 400 m -- on the
 *               order of urban cell spacing -- and a 2-min scan blinds about
 *               170 m of it, ~30% of the time worst case. Change the number
 *               here; everything else reads it.
 *   stationary  every 60 s. Nothing moves, so blind time costs nothing.
 *   serving_only  serving cell only, the lightest load on the port.
 *
 * The interval is measured from the END of the previous scan (the capture
 * loop stamps fullscan_last_ms after the scan returns), so a long scan never
 * back-to-backs into the next one.
 *
 * No PLMN (AT+COPS=?) scan appears here because the capture loop does not
 * run one. */
static const cellat_strategy_t STRATEGIES[] = {
    /* name            label                serving neighbor fullscan (ms) */
    { "driving",      "Driving",            2000,   5000,    0      },
    { "walking",      "Walking",            2000,   5000,    300000 },
    { "stationary",   "Stationary survey",  2000,   5000,    60000  },
    { "serving_only", "Serving cell only",  2000,   0,       0      },
};
#define N_STRATEGIES (sizeof(STRATEGIES) / sizeof(STRATEGIES[0]))

/* Old spellings that keep working. `wardrive` was the default's earlier name
 * and appears in existing drive commands; it is NOT the canonical
 * name any more partly because celldiag has a `wardrive` MASK preset, and one
 * word meaning two unrelated settings on the paired sources of one modem is
 * a confusion waiting to happen on the panel. */
static const struct { const char *alias; const char *canonical; } STRATEGY_ALIASES[] = {
    { "wardrive", "driving" },
};
#define N_STRATEGY_ALIASES (sizeof(STRATEGY_ALIASES) / sizeof(STRATEGY_ALIASES[0]))

const cellat_strategy_t *cellat_strategy_default(void) {
    return &STRATEGIES[0];
}

size_t cellat_strategy_count(void) {
    return N_STRATEGIES;
}

const cellat_strategy_t *cellat_strategy_at(size_t i) {
    return i < N_STRATEGIES ? &STRATEGIES[i] : NULL;
}

const cellat_strategy_t *cellat_strategy_lookup(const char *spelling) {
    if (spelling == NULL)
        return NULL;
    for (size_t i = 0; i < N_STRATEGIES; i++)
        if (strcmp(STRATEGIES[i].name, spelling) == 0)
            return &STRATEGIES[i];
    for (size_t a = 0; a < N_STRATEGY_ALIASES; a++)
        if (strcmp(STRATEGY_ALIASES[a].alias, spelling) == 0)
            return cellat_strategy_lookup(STRATEGY_ALIASES[a].canonical);
    return NULL;
}

int cellat_strategy_parse(const char *value, const cellat_strategy_t **out,
                          char *msg, size_t msgsz) {
    const cellat_strategy_t *s = cellat_strategy_lookup(value);
    if (s != NULL) {
        if (out)
            *out = s;
        return 1;
    }

    if (msg && msgsz) {
        /* Built from the tables, so a new profile or alias is named here the
         * moment it exists. */
        char names[256] = "", aliases[128] = "";
        size_t off = 0;
        for (size_t i = 0; i < N_STRATEGIES; i++) {
            int n = snprintf(names + off, sizeof(names) - off, "%s%s",
                             i ? "|" : "", STRATEGIES[i].name);
            if (n < 0 || (size_t)n >= sizeof(names) - off)
                break;
            off += (size_t)n;
        }
        off = 0;
        for (size_t a = 0; a < N_STRATEGY_ALIASES; a++) {
            int n = snprintf(aliases + off, sizeof(aliases) - off, "%s%s=%s",
                             a ? ", " : "", STRATEGY_ALIASES[a].alias,
                             STRATEGY_ALIASES[a].canonical);
            if (n < 0 || (size_t)n >= sizeof(aliases) - off)
                break;
            off += (size_t)n;
        }
        snprintf(msg, msgsz,
                 "Unknown strategy '%s' -- expected %s (also accepted: %s). "
                 "The source is NOT opened rather than silently running a "
                 "driving survey, which is not what was asked for.",
                 value ? value : "(null)", names, aliases);
    }
    return 0;
}

int cellat_option_is_known(const char *key) {
    static const char *known[] = {
        /* parsed by this helper */
        "atport", "strategy", "debug", "transcript", "uuid",
        /* JSONL corpus tee of every AT exchange (distinct from the
         * human-readable `transcript=`). Registered here so a drive command
         * using it does not draw the "unknown option, IGNORED" warning that
         * would otherwise make it look like it worked while doing nothing. */
        "atlog",
        /* Periodic cadence (seconds) for the host<->modem-RTC ClockAnchor.
         * Registered here so `clock_anchor_sec=` does not draw the "unknown
         * option, IGNORED" warning for an option that does change the anchor
         * cadence. */
        "clock_anchor_sec",
        /* Spawn a QMI cell feed (qmifeed=auto: qmifeed/kismet_qmi_feed.py) and
         * forward its NDJSON lines as CellModem records. Registered so a drive
         * command using it does not draw the "IGNORED" warning for an option
         * that works. */
        "qmifeed",
        /* Where the band/RAT settings AS FOUND are saved before a
         * lock is written (default $HOME/.kismet/cellat-lock-<imei>.state). */
        "lockstate",
        /* cellat's half of the paired-source lifecycle switch. The natural
         * operator action for "stop capturing from this modem" is enabled=false
         * on the paired celldiag-<imei> + cellat-<imei> sources, so cellat must
         * honour it too. Otherwise cellat stays fully live (port opened, AT
         * sent, observations relayed) behind an "unknown source option" warning
         * that reads as a harmless typo, and the operator has disabled half a
         * modem. */
        "enabled",
        /* injected by Kismet itself; never read here, and warning about them
         * would train the operator to ignore this check entirely. `type` is
         * Kismet's driver selector, and the web UI's Enable form always sends
         * it: without it here, every browser-enabled source would warn. */
        "type",
        "name", "informational", "channel", "channels", "channel_hop",
        "channel_hoprate", "add_channels", "block_channels", "retry",
        "timeout", "metric",
        NULL,
    };

    if (key == NULL)
        return 0;

    for (int i = 0; known[i]; i++) {
        if (strcmp(known[i], key) == 0)
            return 1;
    }

    return 0;
}

void cellat_scan_unknown_options(const char *definition,
        cellat_unknown_opt_cb cb, void *ctx) {
    if (definition == NULL || cb == NULL)
        return;

    /* Everything up to the first ':' is the interface, not an option. A
     * definition with no ':' carries no options at all. */
    const char *p = strchr(definition, ':');
    if (p == NULL)
        return;
    p++;

    while (*p) {
        while (*p == ',' || *p == ' ')
            p++;
        if (!*p)
            break;

        const char *eq = strchr(p, '=');
        const char *comma = strchr(p, ',');

        /* A bare token with no '=' before the next comma is not a key/value
         * pair. Skip it rather than warning: cf_find_flag would not read it as
         * an option either, so warning would misdescribe it. */
        if (eq == NULL || (comma != NULL && comma < eq)) {
            p = comma ? comma + 1 : p + strlen(p);
            continue;
        }

        size_t klen = (size_t)(eq - p);
        char key[64];
        if (klen >= sizeof(key))
            klen = sizeof(key) - 1;
        memcpy(key, p, klen);
        key[klen] = '\0';

        if (!cellat_option_is_known(key))
            cb(key, ctx);

        /* Advance past this pair's value. Only a comma separates pairs -- which
         * is all cf_find_flag understands either, so a value CONTAINING a comma
         * is already ambiguous at the framework level and is not this scanner's
         * problem to solve differently. */
        p = comma ? comma + 1 : p + strlen(p);
    }
}
