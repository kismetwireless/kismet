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

    Selftest for cellat source-option recognition.

    Kismet accepts any source option silently, so an option capture_cell_at
    does not parse (once, `atport=`) is discarded without a word. This pins
    both halves: atport is a known option, and anything that is not known
    gets named out loud.
*/

#include <stdio.h>
#include <string.h>

#include "cellat_options.h"

static int g_fails = 0;

#define MAX_SEEN 16
typedef struct { char keys[MAX_SEEN][64]; int n; } seen_t;

static void collect(const char *key, void *ctx) {
    seen_t *s = (seen_t *)ctx;
    if (s->n < MAX_SEEN) {
        strncpy(s->keys[s->n], key, 63);
        s->keys[s->n][63] = '\0';
        s->n++;
    }
}

static void expect_unknown(const char *what, const char *definition,
                           const char *expect_csv) {
    seen_t s = { .n = 0 };
    cellat_scan_unknown_options(definition, collect, &s);

    char got[512] = "";
    for (int i = 0; i < s.n; i++) {
        if (i) strncat(got, ",", sizeof(got) - strlen(got) - 1);
        strncat(got, s.keys[i], sizeof(got) - strlen(got) - 1);
    }

    if (strcmp(got, expect_csv) != 0) {
        fprintf(stderr, "  FAIL %s\n       definition: %s\n"
                "       unknown got [%s] want [%s]\n",
                what, definition, got, expect_csv);
        g_fails++;
    }
}

int main(void) {
    printf("cellat option recognition selftest\n");

    /* ── The anchor ──────────────────────────────────────────────────────
     * An explicit port instruction. If atport were unparsed AND unreported,
     * the operator's choice of port would be discarded without a word. It
     * must be KNOWN. */
    if (!cellat_option_is_known("atport")) {
        fprintf(stderr, "  FAIL atport is not a known option -- the fix "
                "is not wired in\n");
        g_fails++;
    }
    expect_unknown("an explicit-port command has no unknown options",
            "cellat-123456789012345:atport=/dev/ttyUSB21", "");

    /* Every option the helper actually parses. */
    const char *parsed[] = { "atport", "strategy", "debug", "transcript",
                             "atlog", "clock_anchor_sec", "uuid", NULL };
    for (int i = 0; parsed[i]; i++) {
        if (!cellat_option_is_known(parsed[i])) {
            fprintf(stderr, "  FAIL '%s' is parsed by the helper but reported "
                    "as unknown -- a warning for a working option is the "
                    "fastest way to get this check ignored\n", parsed[i]);
            g_fails++;
        }
    }

    /* Keys Kismet itself injects must stay quiet, for the same reason. */
    const char *injected[] = { "name", "informational", "channel", "retry",
                               "timeout", "type", "channel_hop", NULL };
    for (int i = 0; injected[i]; i++) {
        if (!cellat_option_is_known(injected[i])) {
            fprintf(stderr, "  FAIL Kismet-injected '%s' reported as unknown\n",
                    injected[i]);
            g_fails++;
        }
    }

    /* The web UI's Enable form always sends `type=<driver>`, Kismet's own
     * driver selector. Without it on the list, every cellat source enabled
     * from the browser -- the recommended path -- would warn that 'type' was
     * IGNORED. This is the definition the web UI produces. */
    expect_unknown("the web UI Enable definition has no unknown options",
            "cellat-123456789012345:atlog=/tmp/a/,channel_hop=false,"
            "strategy=walking,type=cellat,"
            "uuid=5fe308bd-0000-0000-0000-000000000000", "");

    /* The typo case this exists for. `atprot=` is accepted silently by
     * Kismet and would open whatever auto-detect picked. */
    expect_unknown("a typo'd option is named", 
            "cellat-123456789012345:atprot=/dev/ttyUSB21", "atprot");
    /* celldiag's option name on a cellat source -- an easy mix-up given the
     * two appear on the same command line. */
    expect_unknown("diagport on a cellat source is named",
            "cellat-123456789012345:diagport=/dev/ttyUSB14", "diagport");

    /* Mixed: known and unknown together; only the unknown are reported, in
     * order. */
    expect_unknown("mixed known/unknown",
            "cellat-123456789012345:atport=/dev/ttyUSB21,bogus=1,debug=true,"
            "alsobad=x", "bogus,alsobad");

    /* Shapes that must not produce spurious warnings. */
    expect_unknown("no options at all", "cellat-123456789012345", "");
    expect_unknown("trailing colon, no options", "cellat-123456789012345:", "");
    expect_unknown("a bare token with no '=' is not an option",
            "cellat-123456789012345:someflag,debug=true", "");
    expect_unknown("spaces after commas are tolerated",
            "cellat-123456789012345:debug=true, nope=1", "nope");
    /* A path value containing a colon (the RC400L SN:<hex> by-id shape)
     * must not be mistaken for the interface separator.
     *
     * The obvious version of this case does NOT discriminate. Splitting on
     * the LAST colon instead of the first also yields "no unknown options"
     * here -- the tail after "SN:" has no '=' and is skipped. The second case
     * below puts a REAL unknown option BEFORE the colon-bearing value, which
     * a last-colon split silently swallows along with it. */
    expect_unknown("a value containing a colon does not confuse the split",
            "cellat-123456789012345:atport=/dev/serial/by-id/usb-SN:AB12-if02",
            "");
    expect_unknown("options before a colon-bearing value are still scanned",
            "cellat-123456789012345:bogus=1,"
            "atport=/dev/serial/by-id/usb-SN:AB12-if02", "bogus");

    /* ── enabled= is cellat's half of the lifecycle switch ───────────────
     *
     * celldiag-<imei> and cellat-<imei> are paired per modem, so
     * `enabled=false` on both is the natural "stop capturing from this
     * modem". If cellat did not know the option it would stay FULLY LIVE
     * while warning "unknown source option 'enabled'" -- wording that reads
     * as "typo, harmless, ignored" when the option exists on the sibling
     * source and disables it there: the operator would believe they had
     * disabled a modem when they had disabled half of one. */
    if (!cellat_option_is_known("enabled")) {
        fprintf(stderr, "  FAIL enabled= is not known -- a paired "
                "celldiag+cellat disable would warn 'unknown option' while "
                "cellat stayed live\n");
        g_fails++;
    }
    expect_unknown("a paired-disable definition has no unknown options",
            "cellat-123456789012345:enabled=false", "");

    /* The accepted-value set, both directions. Six spellings, not two. */
    {
        struct { const char *v; int want_ok; int want_on; } cases[] = {
            { "true", 1, 1 }, { "1", 1, 1 },  { "yes", 1, 1 },
            { "false", 1, 0 }, { "0", 1, 0 }, { "no", 1, 0 },
            /* Case-sensitive ON PURPOSE. `False` is what a Python-side
             * config generator emits; it must hard-error rather than be
             * guessed at, because guessing is how a source ends up in a state
             * the operator did not ask for while reporting success. */
            { "False", 0, 0 }, { "TRUE", 0, 0 }, { "yes ", 0, 0 },
            { "", 0, 0 }, { "maybe", 0, 0 },
        };
        for (size_t i = 0; i < sizeof(cases) / sizeof(cases[0]); i++) {
            int on = -1;
            char why[512] = "";
            int ok = cellat_bool_option_parse("enabled", cases[i].v, &on,
                                              why, sizeof(why));
            if (ok != cases[i].want_ok) {
                fprintf(stderr, "  FAIL enabled='%s' parse ok=%d want=%d\n",
                        cases[i].v, ok, cases[i].want_ok);
                g_fails++;
            } else if (ok && on != cases[i].want_on) {
                fprintf(stderr, "  FAIL enabled='%s' -> %d want %d\n",
                        cases[i].v, on, cases[i].want_on);
                g_fails++;
            }
            /* The report must name the rule the decision uses. A message
             * saying "(expected true|false)" while the compare accepts six
             * spellings has the decision and the report disagreeing about
             * one rule, and the report is the half an operator reads. Assert
             * on the message, not just the return code. */
            if (!ok) {
                const char *want[] = { "true|1|yes", "false|0|no",
                                       "case-sensitive", NULL };
                for (int w = 0; want[w]; w++) {
                    if (strstr(why, want[w]) == NULL) {
                        fprintf(stderr, "  FAIL enabled='%s' rejection does "
                                "not mention '%s': %s\n",
                                cases[i].v, want[w], why);
                        g_fails++;
                    }
                }
            }
        }
    }

    /* ── the scan-profile table ──────────────────────────────────────────
     *
     * An unknown strategy must refuse, never fall back to driving silently:
     * each of these would otherwise be a driving survey that reported
     * success. */
    {
        const char *bad[] = { "stationry", "Stationary", "WALKING", "drive",
                              "serving-only", "stationary ", "", NULL };
        for (int i = 0; bad[i]; i++) {
            const cellat_strategy_t *s = NULL;
            char why[512] = "";
            if (cellat_strategy_parse(bad[i], &s, why, sizeof(why))) {
                fprintf(stderr, "  FAIL strategy='%s' accepted as '%s' -- an "
                        "unknown profile must refuse, not fall back\n",
                        bad[i], s ? s->name : "(null)");
                g_fails++;
                continue;
            }
            /* The rejection names every profile, because it is generated from
             * the table -- and it names the alias, so an operator holding an
             * old drive command learns the spelling moved rather than died. */
            for (size_t k = 0; k < cellat_strategy_count(); k++) {
                if (strstr(why, cellat_strategy_at(k)->name) == NULL) {
                    fprintf(stderr, "  FAIL strategy='%s' rejection omits "
                            "profile '%s': %s\n", bad[i],
                            cellat_strategy_at(k)->name, why);
                    g_fails++;
                }
            }
            if (strstr(why, "wardrive=driving") == NULL) {
                fprintf(stderr, "  FAIL strategy='%s' rejection omits the "
                        "wardrive alias: %s\n", bad[i], why);
                g_fails++;
            }
        }
        if (cellat_strategy_parse(NULL, NULL, NULL, 0)) {
            fprintf(stderr, "  FAIL a NULL strategy parsed as valid\n");
            g_fails++;
        }
    }

    /* Every canonical name resolves to itself, and carries a label the panel
     * can show. */
    if (cellat_strategy_count() != 4) {
        fprintf(stderr, "  FAIL expected 4 profiles (driving, walking, "
                "stationary, serving_only), got %zu\n", cellat_strategy_count());
        g_fails++;
    }
    for (size_t k = 0; k < cellat_strategy_count(); k++) {
        const cellat_strategy_t *s = cellat_strategy_at(k);
        if (cellat_strategy_lookup(s->name) != s) {
            fprintf(stderr, "  FAIL profile '%s' does not resolve to itself\n",
                    s->name);
            g_fails++;
        }
        if (s->label == NULL || s->label[0] == '\0') {
            fprintf(stderr, "  FAIL profile '%s' has no label\n", s->name);
            g_fails++;
        }
        if (s->serving_ms == 0) {
            fprintf(stderr, "  FAIL profile '%s' turns the serving poll off -- "
                    "no profile may, it is the source's reason to exist\n",
                    s->name);
            g_fails++;
        }
    }
    if (cellat_strategy_at(cellat_strategy_count()) != NULL) {
        fprintf(stderr, "  FAIL cellat_strategy_at() past the end is not NULL\n");
        g_fails++;
    }

    /* The old spelling still works, and lands on the new name. Older drive
     * commands say strategy=wardrive. */
    {
        const cellat_strategy_t *d = cellat_strategy_lookup("driving");
        const cellat_strategy_t *w = cellat_strategy_lookup("wardrive");
        if (d == NULL || w != d) {
            fprintf(stderr, "  FAIL strategy=wardrive does not alias driving\n");
            g_fails++;
        }
        if (cellat_strategy_default() != d) {
            fprintf(stderr, "  FAIL the default profile is not driving\n");
            g_fails++;
        }
    }

    /* The behaviour each profile exists for. These are the numbers the
     * capture loop reads, so a swapped row is a real regression. */
    {
        const cellat_strategy_t *d = cellat_strategy_lookup("driving");
        const cellat_strategy_t *wk = cellat_strategy_lookup("walking");
        const cellat_strategy_t *st = cellat_strategy_lookup("stationary");
        const cellat_strategy_t *so = cellat_strategy_lookup("serving_only");
        if (!d || !wk || !st || !so) {
            fprintf(stderr, "  FAIL a canonical profile is missing\n");
            g_fails++;
        } else {
            /* Driving never full-scans: 2 minutes of blind port at road speed. */
            if (d->fullscan_ms != 0 || d->neighbor_ms == 0) {
                fprintf(stderr, "  FAIL driving must poll neighbors and never "
                        "full-scan\n");
                g_fails++;
            }
            /* Walking full-scans, less often than stationary. */
            if (wk->fullscan_ms == 0 || wk->fullscan_ms <= st->fullscan_ms) {
                fprintf(stderr, "  FAIL walking must full-scan, less often "
                        "than stationary (walking=%lu stationary=%lu)\n",
                        wk->fullscan_ms, st->fullscan_ms);
                g_fails++;
            }
            if (st->fullscan_ms == 0) {
                fprintf(stderr, "  FAIL stationary must full-scan\n");
                g_fails++;
            }
            if (so->neighbor_ms != 0 || so->fullscan_ms != 0) {
                fprintf(stderr, "  FAIL serving_only must poll the serving "
                        "cell and nothing else\n");
                g_fails++;
            }
        }
    }

    /* NULL-safety: the scanner runs on operator input at open time. */
    {
        int on = -1;
        char why[128] = "";
        if (cellat_bool_option_parse("enabled", NULL, &on, why, sizeof(why))) {
            fprintf(stderr, "  FAIL a NULL enabled= value parsed as valid\n");
            g_fails++;
        }
        /* out= and msg= are both optional -- must not crash. */
        (void)cellat_bool_option_parse("enabled", "true", NULL, NULL, 0);
    }

    cellat_scan_unknown_options(NULL, collect, NULL);
    if (cellat_option_is_known(NULL)) {
        fprintf(stderr, "  FAIL a NULL key reported as known\n");
        g_fails++;
    }

    if (g_fails == 0)
        printf("  ok   atport known; typos, diagport mix-up and mixed lists "
               "all named; no spurious warnings\n");
    printf("%s\n", g_fails == 0 ? "PASS: all cellat option tests"
                                : "FAIL: cellat option tests");
    return g_fails == 0 ? 0 : 1;
}
