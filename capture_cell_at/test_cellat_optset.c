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

    Selftest for cellat's runtime settings.

    The anchor is the classification: six outcomes, each sending an operator
    somewhere different. The one new to cellat is CHANNEL -- a string with no
    '=' is a channel, reserved for band/RAT locks, and must never be read as a
    malformed option.
*/

#include <stdio.h>
#include <string.h>

#include "cellat_optset.h"

static int g_fails = 0;

static void expect(const char *spec, cellat_optset_status_t want,
                   const char *err_needle) {
    cellat_optset_t o;
    cellat_optset_parse(spec, &o);
    if (o.status != want) {
        fprintf(stderr, "  FAIL '%s': status %d want %d (%s)\n",
                spec ? spec : "(null)", o.status, want, o.err);
        g_fails++;
        return;
    }
    if (want == CELLAT_OPTSET_OK && o.err[0] != '\0') {
        fprintf(stderr, "  FAIL '%s': OK carries an error '%s'\n", spec, o.err);
        g_fails++;
    }
    if (want != CELLAT_OPTSET_OK && o.err[0] == '\0') {
        fprintf(stderr, "  FAIL '%s': refused with no reason\n", spec);
        g_fails++;
    }
    if (err_needle && strstr(o.err, err_needle) == NULL) {
        fprintf(stderr, "  FAIL '%s': reason lacks '%s': %s\n", spec,
                err_needle, o.err);
        g_fails++;
    }
}

int main(void) {
    cellat_optset_t o;
    printf("cellat runtime settings selftest\n");

    /* ── strategy= ──────────────────────────────────────────────────────── */
    expect("strategy=walking", CELLAT_OPTSET_OK, NULL);
    cellat_optset_parse("strategy=walking", &o);
    if (o.key != CELLAT_OPTSET_KEY_STRATEGY || o.strategy == NULL ||
            strcmp(o.strategy->name, "walking") != 0) {
        fprintf(stderr, "  FAIL strategy=walking did not resolve the profile\n");
        g_fails++;
    }
    /* The alias works at runtime too, and resolves to the canonical row. */
    cellat_optset_parse("strategy=wardrive", &o);
    if (o.status != CELLAT_OPTSET_OK || !o.strategy ||
            strcmp(o.strategy->name, "driving") != 0) {
        fprintf(stderr, "  FAIL strategy=wardrive did not alias driving\n");
        g_fails++;
    }
    /* A bad profile is a BAD_VALUE that names every real one, and says the
     * source keeps running -- NOT the open path's "the source is NOT opened". */
    expect("strategy=stationry", CELLAT_OPTSET_BAD_VALUE, "keeps its current profile");
    expect("strategy=stationry", CELLAT_OPTSET_BAD_VALUE, "serving_only");
    expect("strategy=stationry", CELLAT_OPTSET_BAD_VALUE, "walking");
    cellat_optset_parse("strategy=stationry", &o);
    if (strstr(o.err, "NOT opened")) {
        fprintf(stderr, "  FAIL runtime refusal claims the source is not "
                "opened: %s\n", o.err);
        g_fails++;
    }
    expect("strategy=", CELLAT_OPTSET_BAD_VALUE, "needs a value");

    /* ── atlog= ────────────────────────────────────────────────────────── */
    expect("atlog=/captures/", CELLAT_OPTSET_OK, NULL);
    cellat_optset_parse("atlog=off", &o);
    if (o.status != CELLAT_OPTSET_OK || !o.atlog_disable) {
        fprintf(stderr, "  FAIL atlog=off is not a stop\n");
        g_fails++;
    }
    cellat_optset_parse("atlog=none", &o);
    if (!o.atlog_disable) {
        fprintf(stderr, "  FAIL atlog=none is not a stop\n");
        g_fails++;
    }
    cellat_optset_parse("atlog=/captures/off", &o);
    if (o.atlog_disable) {
        fprintf(stderr, "  FAIL a path ending in 'off' was read as a stop\n");
        g_fails++;
    }
    /* Paths may legally contain ',' ' ' and '=' -- only a KNOWN key after a
     * delimiter is a second setting. */
    expect("atlog=/cap/my run,a=b.jsonl", CELLAT_OPTSET_OK, NULL);
    expect("atlog=/x.jsonl,strategy=walking", CELLAT_OPTSET_BAD_SYNTAX,
           "more than one setting");
    expect("atlog=", CELLAT_OPTSET_BAD_VALUE, "atlog=off");
    /* A web form's trailing newline is not part of the value. */
    cellat_optset_parse("  atlog=off\n", &o);
    if (o.status != CELLAT_OPTSET_OK || !o.atlog_disable) {
        fprintf(stderr, "  FAIL whitespace around a setting was not trimmed\n");
        g_fails++;
    }

    /* ── clock_anchor_sec= ──────────────────────────────────────────────── */
    cellat_optset_parse("clock_anchor_sec=60", &o);
    if (o.status != CELLAT_OPTSET_OK || o.clock_anchor_ms != 60000) {
        fprintf(stderr, "  FAIL clock_anchor_sec=60 -> %lu\n", o.clock_anchor_ms);
        g_fails++;
    }
    expect("clock_anchor_sec=0", CELLAT_OPTSET_OK, NULL);
    expect("clock_anchor_sec=-5", CELLAT_OPTSET_BAD_VALUE, "whole number");
    expect("clock_anchor_sec=30s", CELLAT_OPTSET_BAD_VALUE, "whole number");

    /* ── open-time only: right key, wrong moment ────────────────────────── */
    expect("atport=/dev/ttyUSB2", CELLAT_OPTSET_OPEN_TIME_ONLY, "not settable while");
    expect("enabled=true", CELLAT_OPTSET_OPEN_TIME_ONLY, "Enable/Disable capture");
    expect("debug=true", CELLAT_OPTSET_OPEN_TIME_ONLY, NULL);
    expect("transcript=/tmp/t", CELLAT_OPTSET_OPEN_TIME_ONLY, "atlog=");
    expect("uuid=X", CELLAT_OPTSET_OPEN_TIME_ONLY, NULL);

    /* ── unknown: and the message says what IS settable ─────────────────── */
    expect("strategi=walking", CELLAT_OPTSET_UNKNOWN_KEY, "strategy|atlog|clock_anchor_sec");
    expect("rawlog=/x", CELLAT_OPTSET_UNKNOWN_KEY, "no cellat option named 'rawlog'");

    /* ── no '=' is a CHANNEL, not a syntax error ───────────────────────── */
    expect("LTE-B71", CELLAT_OPTSET_CHANNEL, "band/RAT lock");
    expect("LTE", CELLAT_OPTSET_CHANNEL, "not a setting");
    cellat_optset_parse("B71", &o);
    if (strcmp(o.value, "B71") != 0) {
        fprintf(stderr, "  FAIL the channel string was not kept: '%s'\n", o.value);
        g_fails++;
    }

    /* ── syntax ────────────────────────────────────────────────────────── */
    expect("", CELLAT_OPTSET_BAD_SYNTAX, "empty");
    expect("   ", CELLAT_OPTSET_BAD_SYNTAX, "empty");
    expect(NULL, CELLAT_OPTSET_BAD_SYNTAX, NULL);
    expect("=walking", CELLAT_OPTSET_BAD_SYNTAX, "no key");

    if (strcmp(cellat_optset_runtime_keys(), "strategy|atlog|clock_anchor_sec") != 0) {
        fprintf(stderr, "  FAIL runtime keys '%s'\n", cellat_optset_runtime_keys());
        g_fails++;
    }

    printf("%s\n", g_fails == 0 ? "PASS: all cellat optset tests"
                                : "FAIL: cellat optset tests");
    return g_fails == 0 ? 0 : 1;
}
