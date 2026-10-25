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

    cellat_optset -- runtime settings for a running cellat source.

    Kismet has exactly ONE generic runtime setter for a datasource,
    `POST /datasource/by-uuid/:uuid/set_channel`, which reaches the helper as
    the CONFIGURE frame's channel string. celldiag already multiplexes
    its runtime knob through it (diag_optset.c); this is cellat's equivalent,
    in the same `key=value` spelling the source definition uses at open:

        strategy=walking            switch the scan profile, no restart
        atlog=/captures/            start or redirect the raw AT file tee
        atlog=off                   stop it (the path is kept for the panel)
        clock_anchor_sec=60         change the ClockAnchor cadence (0 = off)

    The grammar reserves the rest of the string space for CHANNELS. A string
    with no '=' is not a malformed option -- it is a CHANNEL, the thing
    set_channel was built for, and the namespace the band/RAT locks use
    ("LTE", "LTE-B71"; see cellat_lock.h). Classifying it as a channel here
    means no band name can be mistaken for an option or vice versa.

    Same classification contract as diag_optset, for the same reason: an
    UNKNOWN key, an OPEN_TIME_ONLY key and a BAD_VALUE send an operator in three
    different directions, and collapsing any two of them misdirects one.

    Pure libc + the profile table (cellat_options.c), so test_cellat_optset runs
    with no modem and no framework.
*/

#ifndef __CELLAT_OPTSET_H__
#define __CELLAT_OPTSET_H__

#include <stddef.h>

#include "cellat_options.h"

#ifdef __cplusplus
extern "C" {
#endif

#define CELLAT_OPTSET_VALUE_MAX 1024
#define CELLAT_OPTSET_ERR_MAX   384

typedef enum {
    CELLAT_OPTSET_OK = 0,          /* recognised, validated, settable now */
    CELLAT_OPTSET_BAD_SYNTAX,      /* empty, or more than one setting */
    CELLAT_OPTSET_UNKNOWN_KEY,     /* no such cellat option at any time */
    CELLAT_OPTSET_BAD_VALUE,       /* right key, value rejected */
    CELLAT_OPTSET_OPEN_TIME_ONLY,  /* real option; changing it means a re-open */
    CELLAT_OPTSET_CHANNEL,         /* no '=': a channel -- see the header note */
} cellat_optset_status_t;

typedef enum {
    CELLAT_OPTSET_KEY_NONE = 0,
    CELLAT_OPTSET_KEY_STRATEGY,
    CELLAT_OPTSET_KEY_ATLOG,
    CELLAT_OPTSET_KEY_CLOCK_ANCHOR,
    CELLAT_OPTSET_KEY_OPEN_ONLY,   /* any open-time-only key; key_str says which */
} cellat_optset_key_t;

typedef struct {
    cellat_optset_status_t status;
    cellat_optset_key_t    key;
    char key_str[64];                        /* the key as spelled */
    char value[CELLAT_OPTSET_VALUE_MAX];     /* the value as spelled (trimmed) */
    char err[CELLAT_OPTSET_ERR_MAX];         /* operator-facing; empty iff OK */

    /* Parsed facts, so the caller never re-derives them: */
    const cellat_strategy_t *strategy;       /* KEY_STRATEGY */
    int atlog_disable;                       /* KEY_ATLOG: value was off|none */
    unsigned long clock_anchor_ms;           /* KEY_CLOCK_ANCHOR */
} cellat_optset_t;

/* Parse one runtime setting. Never fails: every outcome is a status plus a
 * populated `err`, and `out` is fully initialised on every path. */
void cellat_optset_parse(const char *spec, cellat_optset_t *out);

/* "strategy|atlog|clock_anchor_sec" -- for help text and messages. */
const char *cellat_optset_runtime_keys(void);

#ifdef __cplusplus
}
#endif

#endif /* __CELLAT_OPTSET_H__ */
