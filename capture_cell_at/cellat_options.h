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

    cellat source-option recognition.

    Why this exists: Kismet accepts ANY source option silently, so an option
    that does not exist is indistinguishable from one that does. A misspelled
    or invented option (say `atport=` beside a real `diagport=`) looks like it
    worked while doing nothing, and a command line that relies on it records
    a configuration that never ran. This module names every key the helper
    parses so that an unknown one is reported at open.

    Split into its own translation unit so test_cellat_options can reach the
    scanner without linking the capture framework -- the same reason
    phy_cell_decisions exists.
*/

#ifndef __CELLAT_OPTIONS_H__
#define __CELLAT_OPTIONS_H__

#include <stddef.h>

#ifdef __cplusplus
extern "C" {
#endif

/* True iff `key` is an option this helper parses, or one Kismet itself injects
 * and this helper is expected to ignore.
 *
 * The list must cover every key ANY callback parses -- probe, list and open --
 * because the scan runs once, at open. A key that IS parsed somewhere but is
 * missing here produces a warning for an option that works, and that is the
 * failure mode most likely to get the whole check ignored. */
int cellat_option_is_known(const char *key);

/* Parse a boolean source-option value into *out. Returns 1 on success; on
 * failure returns 0 and fills `msg` with an operator-facing rejection.
 *
 * The rejection message is GENERATED FROM THE ACCEPTED-VALUE LISTS, so the
 * decision and the report cannot drift apart. A hand-written message that
 * names fewer spellings than the parser accepts is harmless in the failure
 * direction, but it is still the code that decides and the code that reports
 * disagreeing about one rule.
 *
 * Accepts true|1|yes and false|0|no, CASE-SENSITIVELY on purpose -- see the
 * implementation for why `enabled=False` must hard-error rather than be
 * guessed at, and why the message has to say so.
 *
 * celldiag carries its own copy of this rule (capture_cell_diag.c). The two
 * helpers are separate link units in separate directories, so sharing this TU
 * is a build change, not an include. If you change the accepted set here,
 * change it there too -- and the message follows automatically on both sides
 * only because both generate it rather than spell it. */
int cellat_bool_option_parse(const char *key, const char *value, int *out,
                             char *msg, size_t msgsz);

/* ── Scan profiles: the `strategy=` option ──────────────────────────────
 *
 * A scan profile is cellat's equivalent of a Wi-Fi source's hop/lock mode:
 * it decides how often each kind of AT scan runs. The table in cellat_options.c
 * is the ONE place the vocabulary and the intervals live; the open path, the
 * rejection message and the stats line all read it, so the three cannot
 * disagree about which names exist.
 *
 * An unknown name is an error, not a fallback. If anything unrecognised
 * became wardrive, `strategy=stationry` would run a wardrive survey and say
 * nothing: a knob that looks like it worked while doing nothing, on the one
 * option whose whole purpose is to change what the source does. */
typedef struct {
    const char *name;           /* canonical; what fields and messages report */
    const char *label;          /* operator-facing name, for the web UI */
    unsigned long serving_ms;   /* serving-cell poll; always on */
    unsigned long neighbor_ms;  /* neighbor poll; 0 = off */
    unsigned long fullscan_ms;  /* full band scan (AT+QSCAN / AT#CSURVC); 0 = off */
} cellat_strategy_t;

/* The profile used when no strategy= is given. */
const cellat_strategy_t *cellat_strategy_default(void);

/* Canonical name or accepted alias -> profile. NULL for anything else,
 * including NULL, "" and a wrong-case spelling. */
const cellat_strategy_t *cellat_strategy_lookup(const char *spelling);

/* Parse a strategy= value. Returns 1 and sets *out on success; on failure
 * returns 0 and fills `msg` with a rejection GENERATED FROM THE TABLE (the
 * same rule as cellat_bool_option_parse), so a profile added to the
 * table is named in the error without anyone remembering to add it. */
int cellat_strategy_parse(const char *value, const cellat_strategy_t **out,
                          char *msg, size_t msgsz);

/* Iterate the canonical profiles, in display order. i >= count -> NULL. */
size_t cellat_strategy_count(void);
const cellat_strategy_t *cellat_strategy_at(size_t i);

typedef void (*cellat_unknown_opt_cb)(const char *key, void *ctx);

/* Walk a source definition ("cellat-<imei>:k=v,k=v,…") and invoke `cb` once per
 * key that cellat_option_is_known() rejects.
 *
 * Reporting, not failing, is deliberate: Kismet injects keys this helper never
 * reads, and a hard error on an unknown key would break the helper on a
 * perfectly good Kismet upgrade. A spurious warning costs a log line; a silent
 * drop costs a session. */
void cellat_scan_unknown_options(const char *definition,
        cellat_unknown_opt_cb cb, void *ctx);

#ifdef __cplusplus
}
#endif

#endif /* __CELLAT_OPTIONS_H__ */
