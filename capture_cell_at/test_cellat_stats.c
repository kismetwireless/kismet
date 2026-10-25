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

    Selftest for the cellat_stats control line.

    The anchor is the omission rule: a value this source has not measured must
    be ABSENT from the line, not zero, because every registered field reaches
    the browser as 0/"" whether or not it was set -- the panel can only tell
    "unreported" from "zero" if the helper never sends a zero it did not
    measure.
*/

#include <stdio.h>
#include <string.h>

#include "cellat_options.h"
#include "cellat_stats.h"

static int g_fails = 0;

static void expect_has(const char *what, const char *json, const char *needle) {
    if (strstr(json, needle) == NULL) {
        fprintf(stderr, "  FAIL %s: missing %s\n       in %s\n", what, needle, json);
        g_fails++;
    }
}

static void expect_lacks(const char *what, const char *json, const char *needle) {
    if (strstr(json, needle) != NULL) {
        fprintf(stderr, "  FAIL %s: must NOT contain %s\n       in %s\n",
                what, needle, json);
        g_fails++;
    }
}

int main(void) {
    char out[4096];
    cellat_stats_t s;
    printf("cellat_stats selftest\n");

    /* ── A fresh source that has measured nothing ───────────────────────── */
    cellat_stats_init(&s);
    s.stats_epoch = 1760000000;
    if (cellat_stats_format_json(&s, out, sizeof(out)) <= 0) {
        fprintf(stderr, "  FAIL the empty stats object did not format\n");
        g_fails++;
    }
    expect_has("fresh", out, "\"state\":\"surveying\"");
    expect_has("fresh", out, "\"obs_total\":0");
    expect_has("fresh", out, "\"rawat_records\":0");
    expect_lacks("fresh: no feed, no qmifeed keys", out, "qmifeed_");
    expect_lacks("fresh: no feed, no rawqmi keys", out, "rawqmi_");
    expect_has("fresh", out, "\"stats_epoch\":1760000000");
    expect_has("fresh", out, "\"stats_interval_s\":5");
    /* The omission rule, one line per sentinel. */
    expect_lacks("fresh: no observation yet", out, "last_obs_epoch");
    expect_lacks("fresh: throughput not measured", out, "obs_per_sec");
    expect_lacks("fresh: no atlog= configured", out, "atlog");
    expect_lacks("fresh: no anchor yet", out, "anchor_last_epoch");
    expect_lacks("fresh: capability not probed", out, "fullscan_capable");
    expect_lacks("fresh: no port known", out, "at_port");
    expect_lacks("fresh: no profile known", out, "strategy");
    expect_lacks("fresh: not scanning", out, "fullscan_started_epoch");
    if (out[0] != '{' || out[strlen(out) - 1] != '}') {
        fprintf(stderr, "  FAIL not a single JSON object: %s\n", out);
        g_fails++;
    }

    /* ── Everything known ──────────────────────────────────────────────── */
    const cellat_strategy_t *wk = cellat_strategy_lookup("walking");
    char vocab[512];
    cellat_stats_strategies(vocab, sizeof(vocab));
    cellat_stats_init(&s);
    s.strategy = wk->name;
    s.strategy_label = wk->label;
    s.strategies = vocab;
    s.serving_interval_ms = wk->serving_ms;
    s.neighbor_interval_ms = wk->neighbor_ms;
    s.fullscan_interval_ms = wk->fullscan_ms;
    s.fullscan_capable = 0;
    s.obs_total = 42;
    s.obs_per_sec = 0.5;
    s.last_obs_epoch = 1760000099;
    s.rawat_records = 7;
    s.rawat_dropped = 1;
    /* A path that needs escaping, because the formatter is the only thing
     * between an operator-supplied path and the server's JSON parser. */
    s.atlog_path = "/cap/a\"b\\c.jsonl";
    s.atlog_active = 1;
    s.atlog_records = 6;
    s.anchor_count = 3;
    s.anchor_last_epoch = 1760000090;
    s.at_port = "/dev/ttyUSB2";
    s.model = "Quectel RM520N";
    s.firmware = "RM520NGLAAR03A03M4G";
    s.stats_epoch = 1760000100;
    if (cellat_stats_format_json(&s, out, sizeof(out)) <= 0) {
        fprintf(stderr, "  FAIL the full stats object did not format\n");
        g_fails++;
    }
    expect_has("full", out, "\"strategy\":\"walking\"");
    expect_has("full", out, "\"strategy_label\":\"Walking\"");
    expect_has("full", out, "\"fullscan_interval_ms\":300000");
    expect_has("full", out, "\"neighbor_interval_ms\":5000");
    /* capability 0 is a MEASUREMENT (the modem was probed and has no scan
     * command), so it is sent -- unlike -1, which is "not probed". */
    expect_has("full: measured incapable is sent", out, "\"fullscan_capable\":false");
    expect_has("full", out, "\"obs_total\":42");
    expect_has("full", out, "\"obs_per_sec\":0.500");
    expect_has("full", out, "\"last_obs_epoch\":1760000099");
    expect_has("full", out, "\"rawat_dropped\":1");
    expect_has("full: path escaped", out, "\"atlog_path\":\"/cap/a\\\"b\\\\c.jsonl\"");
    expect_has("full", out, "\"atlog_active\":true");
    expect_has("full", out, "\"atlog_records\":6");
    expect_has("full", out, "\"atlog_dropped\":0");
    expect_has("full", out, "\"anchor_count\":3");
    expect_has("full", out, "\"anchor_last_epoch\":1760000090");
    expect_has("full", out, "\"at_port\":\"/dev/ttyUSB2\"");
    expect_has("full", out, "\"model\":\"Quectel RM520N\"");
    expect_has("full", out, "\"strategies\":\"driving,Driving,0;walking,Walking,300;");
    /* A configured feed reports all its counters. */
    s.has_qmifeed = 1;
    s.qmifeed_active = 1;
    s.qmifeed_sent = 11;
    s.qmifeed_dropped_imei = 2;
    s.qmifeed_msgs = 4;
    s.rawqmi_records = 23;
    s.rawqmi_dropped = 5;
    cellat_stats_format_json(&s, out, sizeof(out));
    expect_has("qmifeed", out, "\"qmifeed_configured\":true");
    expect_has("qmifeed", out, "\"qmifeed_active\":true");
    expect_has("qmifeed", out, "\"qmifeed_sent\":11");
    expect_has("qmifeed", out, "\"qmifeed_dropped\":0");
    expect_has("qmifeed", out, "\"qmifeed_dropped_imei\":2");
    expect_has("qmifeed", out, "\"qmifeed_msgs\":4");
    expect_has("qmifeed", out, "\"rawqmi_records\":23");
    expect_has("qmifeed", out, "\"rawqmi_dropped\":5");
    s.qmifeed_active = 0;
    cellat_stats_format_json(&s, out, sizeof(out));
    expect_has("an exited feed says so", out, "\"qmifeed_active\":false");
    /* A stopped tee keeps its path and says so. */
    s.atlog_active = 0;
    cellat_stats_format_json(&s, out, sizeof(out));
    expect_has("stopped tee", out, "\"atlog_active\":false");
    expect_has("stopped tee keeps its path", out, "\"atlog_path\"");

    /* ── The full scan: a long blocking window, and how the panel sees it ── */
    s.state = "full_scan";
    s.fullscan_started_epoch = 1760000200;
    cellat_stats_format_json(&s, out, sizeof(out));
    expect_has("full_scan", out, "\"state\":\"full_scan\"");
    expect_has("full_scan", out, "\"fullscan_started_epoch\":1760000200");
    /* A stale start time must not leak into a surveying line. */
    s.state = "surveying";
    cellat_stats_format_json(&s, out, sizeof(out));
    expect_lacks("surveying drops the scan start", out, "fullscan_started_epoch");

    /* ── A disabled source ─────────────────────────────────────────────── */
    cellat_stats_init(&s);
    s.state = "disabled";
    s.strategy = "driving";
    s.strategy_label = "Driving";
    s.obs_total = 99;          /* must NOT appear: a disabled source measured nothing */
    s.fullscan_capable = 1;    /* nor this */
    s.at_port = "/dev/ttyUSB2";
    s.stats_epoch = 1760000300;
    cellat_stats_format_json(&s, out, sizeof(out));
    expect_has("disabled", out, "\"state\":\"disabled\"");
    expect_has("disabled keeps its profile", out, "\"strategy\":\"driving\"");
    expect_has("disabled keeps its clock", out, "\"stats_epoch\":1760000300");
    expect_lacks("disabled: no counters", out, "obs_total");
    expect_lacks("disabled: no counters", out, "rawat_records");
    expect_lacks("disabled: no intervals", out, "interval_ms");
    expect_lacks("disabled: nothing probed", out, "fullscan_capable");
    expect_lacks("disabled: no port", out, "at_port");

    /* ── Overflow is an empty string, never half an object ──────────────── */
    {
        char tiny[40];
        cellat_stats_init(&s);
        s.model = "a model name long enough to overflow a forty byte buffer";
        int r = cellat_stats_format_json(&s, tiny, sizeof(tiny));
        if (r != -1 || tiny[0] != '\0') {
            fprintf(stderr, "  FAIL overflow returned %d with '%s' -- a "
                    "truncated object would be dropped by the server and the "
                    "panel would keep showing old numbers as current\n", r, tiny);
            g_fails++;
        }
        if (cellat_stats_format_json(NULL, tiny, sizeof(tiny)) != -1) {
            fprintf(stderr, "  FAIL NULL stats accepted\n");
            g_fails++;
        }
    }

    /* ── The vocabulary string ─────────────────────────────────────────── */
    {
        int n = cellat_stats_strategies(vocab, sizeof(vocab));
        if (n <= 0) {
            fprintf(stderr, "  FAIL the strategies vocabulary did not format\n");
            g_fails++;
        }
        /* One row per profile, three cells per row. The panel splits on ';'
         * then ',', so a label containing either would shift every cell. */
        size_t rows = 1, cells = 1;
        for (const char *p = vocab; *p; p++) {
            if (*p == ';') { rows++; cells++; }
            else if (*p == ',') cells++;
        }
        if (rows != cellat_strategy_count() || cells != rows * 3) {
            fprintf(stderr, "  FAIL vocabulary has %zu rows / %zu cells, want "
                    "%zu / %zu: %s\n", rows, cells, cellat_strategy_count(),
                    cellat_strategy_count() * 3, vocab);
            g_fails++;
        }
        for (size_t i = 0; i < cellat_strategy_count(); i++) {
            const char *lbl = cellat_strategy_at(i)->label;
            if (strchr(lbl, ',') || strchr(lbl, ';') || strchr(lbl, '"')) {
                fprintf(stderr, "  FAIL label '%s' contains a delimiter\n", lbl);
                g_fails++;
            }
        }
        expect_has("vocab", vocab, "stationary,Stationary survey,60");
        expect_has("vocab", vocab, "serving_only,Serving cell only,0");
        char small[8];
        if (cellat_stats_strategies(small, sizeof(small)) != -1 || small[0]) {
            fprintf(stderr, "  FAIL vocabulary overflow not reported\n");
            g_fails++;
        }
    }

    printf("%s\n", g_fails == 0 ? "PASS: all cellat_stats tests"
                                : "FAIL: cellat_stats tests");
    return g_fails == 0 ? 0 : 1;
}
