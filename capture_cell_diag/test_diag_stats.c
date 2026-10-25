/* test_diag_stats.c - standalone unit tests for the celldiag health-stats core.
 *
 * Links only diag_stats.c (libc, no Kismet), so it runs off the capture
 * framework: `make check` in this directory. Covers the pieces with real
 * branching logic - the rolling observations/sec window, the
 * health verdict, the cadence gate, and the status-line formatting/reset - with
 * a fixed clock so every assertion is deterministic.
 */

#include "diag_stats.h"

#include <stdio.h>
#include <string.h>
#include <time.h>

/* Mirrors the emit site's buffer (capture_cell_diag.c uses STATUS_MAX), so an
 * object that fits here is one that fits in production. Hard-coded rather than
 * including config.h because this TU deliberately links nothing but libc. */
#define STATS_JSON_BUF 1024

static int failures = 0;

#define CHECK(cond, ...) do { \
    if (!(cond)) { \
        fprintf(stderr, "FAIL %s:%d: ", __FILE__, __LINE__); \
        fprintf(stderr, __VA_ARGS__); \
        fprintf(stderr, "\n"); \
        failures++; \
    } \
} while (0)

/* A fixed base instant so ages/rates are deterministic: 2026-07-17T18:19:20Z. */
static time_t base_now(void) {
    struct tm tmv;
    memset(&tmv, 0, sizeof(tmv));
    tmv.tm_year = 2026 - 1900;
    tmv.tm_mon  = 7 - 1;
    tmv.tm_mday = 17;
    tmv.tm_hour = 18;
    tmv.tm_min  = 19;
    tmv.tm_sec  = 20;
    return timegm(&tmv);
}

static void test_verdict_nodata(void) {
    diag_stats_t s;
    time_t t0 = base_now();
    diag_stats_init(&s, t0);
    /* Never read a byte -> NODATA regardless of how much time passes. */
    CHECK(strcmp(diag_stats_verdict(&s, t0 + 100, 30), "NODATA") == 0,
          "fresh source should be NODATA");
}

static void test_verdict_flowing_stalled(void) {
    diag_stats_t s;
    time_t t0 = base_now();
    diag_stats_init(&s, t0);

    /* The producer state is part of a flowing source: with port_open=0 /
     * helper_alive=0 the verdict is a producer arm, not FLOWING. Set both, so
     * this test measures the RECENCY arms it is about. */
    diag_stats_set_port_open(&s, 1);
    diag_stats_set_helper_alive(&s, 1);
    diag_stats_on_read(&s, 4096, t0);
    diag_stats_on_obs(&s, t0);
    /* 5s later, within a 30s stall window and with a recent obs -> FLOWING. */
    CHECK(strcmp(diag_stats_verdict(&s, t0 + 5, 30), "FLOWING") == 0,
          "recent read+obs should be FLOWING");
    /* 40s later, no further reads -> STALLED (reads stopped). */
    CHECK(strcmp(diag_stats_verdict(&s, t0 + 40, 30), "STALLED") == 0,
          "silent-for-40s source should be STALLED");
}

static void test_verdict_rx_no_obs(void) {
    diag_stats_t s;
    time_t t0 = base_now();
    diag_stats_init(&s, t0);

    /* Bytes keep arriving but the decoder never produced an observation. */
    diag_stats_set_port_open(&s, 1);         /* producer is up... */
    diag_stats_set_helper_alive(&s, 1);
    diag_stats_on_read(&s, 1024, t0 + 1);
    diag_stats_on_read(&s, 1024, t0 + 5);
    CHECK(strcmp(diag_stats_verdict(&s, t0 + 6, 30), "RX-NO-OBS") == 0,
          "bytes-but-no-obs should be RX-NO-OBS");
    /* A once-flowing source whose reads continue but whose observations have
     * gone stale (mask went wrong / decoder stuck): recent read, stale obs. */
    diag_stats_on_obs(&s, t0 + 5);
    diag_stats_on_read(&s, 1024, t0 + 38);
    CHECK(strcmp(diag_stats_verdict(&s, t0 + 40, 30), "RX-NO-OBS") == 0,
          "read recent but obs stale should be RX-NO-OBS");
}

/* --- The health WORD must never contradict the fields beside it ------------
 *
 * A verdict computed only from read/obs recency would print
 *
 *   celldiag stats: FLOWING | port=closed bytes=305881 rd_err=0 last_read=0s
 *     | obs=344 (+73 3.60/s) last_obs=0s | decoder=stopped | mask=wardrive
 *
 * for a full stall_after window after the source stopped: every field true,
 * and the summary computed from a subset that excludes the failure. The README
 * makes that word the headline health signal. These tests fail against a
 * recency-only verdict. */
static void test_closed_port_with_a_live_decoder_is_port_closed(void) {
    /* The port arm on its own: the decoder is fine, the DIAG fd is not. */
    diag_stats_t s;
    time_t t0 = base_now();
    diag_stats_init(&s, t0);
    diag_stats_set_port_open(&s, 1);
    diag_stats_set_helper_alive(&s, 1);
    diag_stats_on_read(&s, 4096, t0);
    diag_stats_on_obs(&s, t0);
    diag_stats_set_port_open(&s, 0);
    CHECK(strcmp(diag_stats_verdict(&s, t0 + 1, 30), "PORT-CLOSED") == 0,
          "closed port with a live decoder should be PORT-CLOSED");
}

static void test_nodata_still_outranks_the_producer_arms(void) {
    /* A source that never read a byte has nothing to diagnose yet; naming a
     * producer that was never asked to produce would be noise, and NODATA is
     * already an unambiguous "not healthy". Guards against the producer arms
     * swallowing the first state. */
    diag_stats_t s;
    time_t t0 = base_now();
    diag_stats_init(&s, t0);
    CHECK(strcmp(diag_stats_verdict(&s, t0 + 100, 30), "NODATA") == 0,
          "never-read source should still be NODATA");
}

static void test_format_word_agrees_with_the_fields_beside_it(void) {
    /* The end-to-end property, on the rendered line -- the artifact the
     * operator and any monitor actually read. */
    diag_stats_t s;
    time_t t0 = base_now();
    diag_stats_init(&s, t0);
    diag_stats_set_mask_preset(&s, "wardrive");
    diag_stats_set_port_open(&s, 1);
    diag_stats_set_helper_alive(&s, 1);
    diag_stats_on_read(&s, 305881, t0);
    diag_stats_on_obs(&s, t0);
    diag_stats_set_helper_alive(&s, 0);
    diag_stats_set_port_open(&s, 0);

    char buf[512];
    int n = diag_stats_format(&s, t0, 30, buf, sizeof(buf));
    CHECK(n > 0, "format returned %d", n);
    CHECK(strstr(buf, "decoder=stopped") != NULL, "fixture should print decoder=stopped: %s", buf);
    CHECK(strstr(buf, "port=closed") != NULL, "fixture should print port=closed: %s", buf);
    CHECK(strstr(buf, "FLOWING") == NULL,
          "the word contradicts the fields on its own line: %s", buf);
    CHECK(strstr(buf, "PORT-CLOSED") != NULL, "verdict missing: %s", buf);
}

/* ── the decoder producer ───────────────────────────────────────────────────
 * helper_alive means "the in-process decoder is alive", set from the reader
 * thread's heartbeat. */

/* A native source mid-capture: port open, decoder alive, a read and an obs
 * at t0. */
static void native_flowing(diag_stats_t *s, time_t t0) {
    diag_stats_init(s, t0);
    diag_stats_set_mask_preset(s, "wardrive");
    diag_stats_set_port_open(s, 1);
    diag_stats_set_helper_alive(s, 1);
    diag_stats_on_read(s, 249991, t0);
    diag_stats_on_obs(s, t0);
}

static void test_native_flowing_reads_flowing(void) {
    diag_stats_t s;
    time_t t0 = base_now();
    native_flowing(&s, t0);
    const char *v = diag_stats_verdict(&s, t0 + 1, 30);
    CHECK(strcmp(v, "FLOWING") == 0,
          "a live native decoder with fresh obs should be FLOWING, got %s", v);

    char buf[512];
    CHECK(diag_stats_format(&s, t0 + 1, 30, buf, sizeof(buf)) > 0, "format");
    CHECK(strncmp(buf, "celldiag stats: FLOWING |", 25) == 0, "word: %s", buf);
    CHECK(strstr(buf, "| decoder=alive |") != NULL,
          "the producer segment is missing: %s", buf);
}

static void test_native_rx_no_obs(void) {
    diag_stats_t s;
    time_t t0 = base_now();
    diag_stats_init(&s, t0);
    diag_stats_set_port_open(&s, 1);
    diag_stats_set_helper_alive(&s, 1);
    diag_stats_on_read(&s, 4096, t0);
    const char *v = diag_stats_verdict(&s, t0 + 5, 30);
    CHECK(strcmp(v, "RX-NO-OBS") == 0,
          "native, bytes but no observation, should be RX-NO-OBS, got %s", v);
}

static void test_native_quiet_port_with_a_live_decoder_is_stalled(void) {
    /* A quiet port read by a LIVE reader is the recency arm's STALLED, not a
     * stuck decoder. Conflating them would raise the DEAD alarm on every modem
     * that goes quiet. */
    diag_stats_t s;
    time_t t0 = base_now();
    native_flowing(&s, t0);
    const char *v = diag_stats_verdict(&s, t0 + 40, 30);
    CHECK(strcmp(v, "STALLED") == 0,
          "native, live decoder, reads stopped 40 s ago: want STALLED, got %s", v);
    char buf[512];
    CHECK(diag_stats_format(&s, t0 + 40, 30, buf, sizeof(buf)) > 0, "format");
    CHECK(strstr(buf, "decoder=alive") != NULL, "quiet is not stuck: %s", buf);
}

static void test_native_stuck_reader_is_decoder_stalled(void) {
    /* Every recency arm is maximally healthy (read and obs 0 s old), and the
     * decoder is not alive behind an open port: the stall must win. */
    diag_stats_t s;
    time_t t0 = base_now();
    native_flowing(&s, t0);
    diag_stats_set_helper_alive(&s, 0);
    const char *v = diag_stats_verdict(&s, t0, 30);
    CHECK(strcmp(v, "DECODER-STALLED") == 0,
          "native, port open, decoder not alive: want DECODER-STALLED, got %s", v);
    char buf[512];
    CHECK(diag_stats_format(&s, t0, 30, buf, sizeof(buf)) > 0, "format");
    CHECK(strstr(buf, "| decoder=stalled |") != NULL, "fields: %s", buf);
}

static void test_native_stuck_reader_outranks_a_stale_read(void) {
    /* The stuck reader also stops the reads, so STALLED is true too; it names
     * the symptom. Pins the producer arm ABOVE the recency arms. */
    diag_stats_t s;
    time_t t0 = base_now();
    native_flowing(&s, t0);
    diag_stats_set_helper_alive(&s, 0);
    const char *v = diag_stats_verdict(&s, t0 + 40, 30);
    CHECK(strcmp(v, "DECODER-STALLED") == 0,
          "a stuck reader must outrank the stall it caused, got %s", v);
}

static void test_native_teardown_is_port_closed_and_decoder_stopped(void) {
    /* The final line of a finished replay or a stopped source: the port
     * closed, so the reader finished and the decoder stopped with it. That is
     * PORT-CLOSED / decoder=stopped -- not a stall. */
    diag_stats_t s;
    time_t t0 = base_now();
    native_flowing(&s, t0);
    diag_stats_set_port_open(&s, 0);
    diag_stats_set_helper_alive(&s, 0);
    const char *v = diag_stats_verdict(&s, t0, 30);
    CHECK(strcmp(v, "PORT-CLOSED") == 0,
          "native teardown (port closed, decoder stopped): want PORT-CLOSED, got %s", v);
    char buf[512];
    CHECK(diag_stats_format(&s, t0, 30, buf, sizeof(buf)) > 0, "format");
    CHECK(strstr(buf, "port=closed") != NULL &&
          strstr(buf, "decoder=stopped") != NULL, "fields: %s", buf);

    /* The port arm on its own: with the decoder still marked alive the
     * closed port is still the word. */
    diag_stats_set_helper_alive(&s, 1);
    v = diag_stats_verdict(&s, t0, 30);
    CHECK(strcmp(v, "PORT-CLOSED") == 0, "native closed port: got %s", v);
}

static void test_native_nodata_still_first(void) {
    diag_stats_t s;
    time_t t0 = base_now();
    diag_stats_init(&s, t0);
    diag_stats_set_port_open(&s, 1);
    CHECK(strcmp(diag_stats_verdict(&s, t0 + 100, 30), "NODATA") == 0,
          "a native source that never read a byte is NODATA");
}

static void test_heartbeat_staleness_judgment(void) {
    const uint64_t B = 10ULL * 1000000000ULL;
    const uint64_t hb = 5000ULL * 1000000000ULL;
    CHECK(diag_stats_heartbeat_stale(0, hb + 10 * B, B) == 0,
          "an unarmed heartbeat is never stale");
    CHECK(diag_stats_heartbeat_stale(hb, hb, B) == 0, "age 0 is fresh");
    CHECK(diag_stats_heartbeat_stale(hb, hb + B, B) == 0,
          "exactly the bound is not yet past it");
    CHECK(diag_stats_heartbeat_stale(hb, hb + B + 1, B) == 1,
          "one ns past the bound is stale");
    CHECK(diag_stats_heartbeat_stale(hb, hb + 3 * B, B) == 1, "long silence is stale");
    CHECK(diag_stats_heartbeat_stale(hb + 1, hb, B) == 0,
          "a beat stamped after the caller's clock read is fresh");
}

static void test_decoder_stalled_line(void) {
    char buf[512];
    int n = diag_stats_format_decoder_stalled(12999, 10000, buf, sizeof(buf));
    CHECK(n > 0, "format returned %d", n);
    CHECK(strncmp(buf, "celldiag stats: DECODER-STALLED | ", 34) == 0,
          "the verdict word must lead, as on the regular line: %s", buf);
    CHECK(strstr(buf, "decoder=stalled no_progress=12s bound=10s") != NULL,
          "rounded-down seconds and the bound: %s", buf);
    char tiny[40];
    CHECK(diag_stats_format_decoder_stalled(12999, 10000, tiny, sizeof(tiny)) == -1,
          "a clipped stall line must not be written");
}

static void test_liveness_json(void) {
    char buf[256];
    CHECK(diag_stats_format_liveness_json(1, "native-only", buf, sizeof(buf)) > 0 &&
          strcmp(buf, "{\"type\":\"diag_stats\",\"helper_alive\":1,"
                       "\"decode_mode\":\"native-only\"}") == 0, "alive: %s", buf);
    CHECK(diag_stats_format_liveness_json(0, "native-only", buf, sizeof(buf)) > 0 &&
          strstr(buf, "\"helper_alive\":0") != NULL, "stalled: %s", buf);
    CHECK(diag_stats_format_liveness_json(7, NULL, buf, sizeof(buf)) > 0 &&
          strcmp(buf, "{\"type\":\"diag_stats\",\"helper_alive\":1}") == 0,
          "no decode_mode key when NULL; any non-zero is 1: %s", buf);
    CHECK(strstr(buf, "bytes_read") == NULL && strstr(buf, "obs_total") == NULL,
          "the liveness object must not carry counters it does not own");
    CHECK(diag_stats_format_liveness_json(1, "bad\"label", buf, sizeof(buf)) == -1,
          "an unsafe label must be refused, not emitted");
    char tiny[24];
    CHECK(diag_stats_format_liveness_json(1, "native-only", tiny, sizeof(tiny)) == -1,
          "a clipped object must not be written");
}

static void test_rate_rolling(void) {
    diag_stats_t s;
    time_t t0 = base_now();
    diag_stats_init(&s, t0);

    /* 10 observations spread over the 10s window -> ~1.0/s. */
    for (int i = 0; i < 10; i++)
        diag_stats_on_obs(&s, t0 + i);
    double r = diag_stats_obs_per_sec(&s, t0 + 9);
    CHECK(r > 0.99 && r < 1.01, "rolling rate ~1.0/s, got %.3f", r);

    /* Far in the future, all timestamps have aged out of the window -> 0. */
    double r2 = diag_stats_obs_per_sec(&s, t0 + 100);
    CHECK(r2 == 0.0, "rate should decay to 0, got %.3f", r2);
}

static void test_rate_empty(void) {
    diag_stats_t s;
    time_t t0 = base_now();
    diag_stats_init(&s, t0);
    CHECK(diag_stats_obs_per_sec(&s, t0) == 0.0, "no obs -> 0/s");
}

/* Ring saturation: the other rate tests push only 10 obs, so the ring never
 * wraps. Overfill it (> 2x SLOTS) to exercise the wrap, the rate_count cap, and
 * the modulo backward-walk crossing the wrap boundary -- a chatty modem emits
 * far more than 1024 obs inside a 10s window in the field. */
static void test_rate_ring_saturation(void) {
    diag_stats_t s;
    time_t t0 = base_now();
    diag_stats_init(&s, t0);

    int total = DIAG_STATS_RATE_SLOTS * 2 + 5;
    for (int i = 0; i < total; i++)
        diag_stats_on_obs(&s, t0);
    /* Older writes are overwritten; live entries cap at SLOTS. */
    CHECK(s.rate_count == (size_t)DIAG_STATS_RATE_SLOTS,
          "rate_count caps at SLOTS, got %zu", s.rate_count);
    /* So the in-window count is bounded by SLOTS, not `total`. */
    double r = diag_stats_obs_per_sec(&s, t0);
    double expect = (double)DIAG_STATS_RATE_SLOTS / (double)DIAG_STATS_RATE_WINDOW_SEC;
    CHECK(r == expect, "saturated rate == SLOTS/WINDOW (%.1f), got %.3f", expect, r);

    /* Past the window every entry ages out -- the break-after-wrap must still
     * terminate the walk and yield 0 with a full ring. */
    CHECK(diag_stats_obs_per_sec(&s, t0 + DIAG_STATS_RATE_WINDOW_SEC + 1) == 0.0,
          "saturated ring decays to 0 past window");
}

/* Full ring with a mix of old + recent timestamps: the time-ordered break must
 * count only the recent entries even after the head has wrapped. */
static void test_rate_full_ring_partial_window(void) {
    diag_stats_t s;
    time_t t0 = base_now();
    diag_stats_init(&s, t0);

    /* Fill the ring with stale obs, then push 3 recent ones (head has wrapped). */
    for (int i = 0; i < DIAG_STATS_RATE_SLOTS; i++)
        diag_stats_on_obs(&s, t0);
    time_t later = t0 + 100;
    for (int i = 0; i < 3; i++)
        diag_stats_on_obs(&s, later);

    /* At `later`, cutoff = later-10; only the 3 recent obs are in window. */
    double r = diag_stats_obs_per_sec(&s, later);
    double expect = 3.0 / (double)DIAG_STATS_RATE_WINDOW_SEC;
    CHECK(r == expect, "partial window counts only recent (%.2f), got %.3f",
          expect, r);
}

static void test_cadence_due(void) {
    diag_stats_t s;
    time_t t0 = base_now();
    diag_stats_init(&s, t0);

    CHECK(diag_stats_due(&s, 0, t0 + 1000) == 0, "interval 0 disables status");
    CHECK(diag_stats_due(&s, 30, t0 + 10) == 0, "10s < 30s interval, not due");
    CHECK(diag_stats_due(&s, 30, t0 + 30) == 1, "exactly 30s -> due");
    CHECK(diag_stats_due(&s, 30, t0 + 45) == 1, "45s > 30s -> due");

    /* After marking a status, the baseline advances and it is no longer due. */
    diag_stats_mark_status(&s, t0 + 45);
    CHECK(diag_stats_due(&s, 30, t0 + 50) == 0, "just emitted, not due again");
    CHECK(diag_stats_due(&s, 30, t0 + 75) == 1, "another interval later -> due");
}

static void test_mark_status_resets_since(void) {
    diag_stats_t s;
    time_t t0 = base_now();
    diag_stats_init(&s, t0);

    diag_stats_on_obs(&s, t0);
    diag_stats_on_obs(&s, t0 + 1);
    CHECK(s.obs_since_status == 2, "obs_since_status should be 2");
    CHECK(s.obs_total == 2, "obs_total should be 2");

    diag_stats_mark_status(&s, t0 + 2);
    CHECK(s.obs_since_status == 0, "mark_status clears obs_since_status");
    CHECK(s.obs_total == 2, "mark_status must NOT clear obs_total");
}

static void test_format_contains_fields(void) {
    diag_stats_t s;
    time_t t0 = base_now();
    diag_stats_init(&s, t0);
    diag_stats_set_port_open(&s, 1);
    diag_stats_set_mask_preset(&s, "wardrive");
    diag_stats_set_helper_alive(&s, 1);
    diag_stats_on_read(&s, 12345, t0);
    diag_stats_on_obs(&s, t0);

    char buf[512];
    int n = diag_stats_format(&s, t0 + 2, 30, buf, sizeof(buf));
    CHECK(n > 0, "format returned %d", n);
    CHECK(strstr(buf, "FLOWING") != NULL, "verdict missing: %s", buf);
    CHECK(strstr(buf, "bytes=12345") != NULL, "bytes missing: %s", buf);
    CHECK(strstr(buf, "obs=1") != NULL, "obs count missing: %s", buf);
    CHECK(strstr(buf, "mask=wardrive") != NULL, "mask missing: %s", buf);
    CHECK(strstr(buf, "last_obs=2s") != NULL, "obs age missing: %s", buf);
}

/* The core property: a stalled source (no bytes) must be visibly distinguishable
 * from a healthy one in the formatted line within one interval. */
static void test_format_stalled_distinguishable(void) {
    diag_stats_t healthy, stalled;
    time_t t0 = base_now();
    diag_stats_init(&healthy, t0);
    diag_stats_init(&stalled, t0);

    diag_stats_set_port_open(&healthy, 1);   /* a healthy source has */
    diag_stats_set_helper_alive(&healthy, 1);
    diag_stats_on_read(&healthy, 8192, t0 + 29);
    diag_stats_on_obs(&healthy, t0 + 29);
    /* stalled: opened, port up, but never read a byte. */
    diag_stats_set_port_open(&stalled, 1);

    char hb[512], sb[512];
    diag_stats_format(&healthy, t0 + 30, 30, hb, sizeof(hb));
    diag_stats_format(&stalled, t0 + 30, 30, sb, sizeof(sb));

    CHECK(strstr(hb, "FLOWING") != NULL, "healthy not FLOWING: %s", hb);
    CHECK(strstr(sb, "NODATA") != NULL, "stalled not NODATA: %s", sb);
    CHECK(strstr(sb, "bytes=0") != NULL, "stalled should show bytes=0: %s", sb);
    CHECK(strcmp(hb, sb) != 0, "healthy and stalled lines must differ");
}

static void test_format_overflow_clamps(void) {
    diag_stats_t s;
    time_t t0 = base_now();
    diag_stats_init(&s, t0);
    char tiny[8];
    int n = diag_stats_format(&s, t0, 30, tiny, sizeof(tiny));
    CHECK(n >= 0 && (size_t)n < sizeof(tiny), "overflow clamp got %d", n);
    CHECK(tiny[sizeof(tiny) - 1] == '\0' || n < (int)sizeof(tiny) - 1,
          "buffer must stay NUL-terminated");
}

/* The machine-parseable stats line carries the registered datasource
 * field keys with real values so the server can SET each tracker field. */
static void test_format_json_contains_field_keys(void) {
    diag_stats_t s;
    time_t t0 = base_now();
    diag_stats_init(&s, t0);
    diag_stats_set_mask_preset(&s, "wardrive");
    diag_stats_set_helper_alive(&s, 1);
    diag_stats_on_read(&s, 4096, t0);
    diag_stats_on_obs(&s, t0);

    char buf[512];
    int n = diag_stats_format_json(&s, t0 + 2, buf, sizeof(buf));
    CHECK(n > 0, "json format returned %d", n);
    CHECK(strstr(buf, "\"type\":\"diag_stats\"") != NULL, "type marker missing: %s", buf);
    CHECK(strstr(buf, "\"bytes_read\":4096") != NULL, "bytes_read missing: %s", buf);
    CHECK(strstr(buf, "\"obs_total\":1") != NULL, "obs_total missing: %s", buf);
    CHECK(strstr(buf, "\"helper_alive\":1") != NULL, "helper_alive missing: %s", buf);
    CHECK(strstr(buf, "\"mask_preset\":\"wardrive\"") != NULL, "mask_preset missing: %s", buf);
    CHECK(strstr(buf, "\"last_obs_epoch\":") != NULL, "last_obs_epoch missing: %s", buf);
    CHECK(strstr(buf, "\"obs_per_sec\":") != NULL, "obs_per_sec missing: %s", buf);
    /* Fresh source: no obs yet -> last_obs_epoch is 0, not a garbage tick. */
    diag_stats_t fresh;
    diag_stats_init(&fresh, t0);
    diag_stats_format_json(&fresh, t0, buf, sizeof(buf));
    CHECK(strstr(buf, "\"last_obs_epoch\":0") != NULL, "no-obs epoch should be 0: %s", buf);
    CHECK(strstr(buf, "\"helper_alive\":0") != NULL, "fresh helper should be dead: %s", buf);
}

/* A corrupt mask_preset with a quote must not break the JSON (renders empty). */
static void test_format_json_mask_preset_injection_guard(void) {
    diag_stats_t s;
    time_t t0 = base_now();
    diag_stats_init(&s, t0);
    diag_stats_set_mask_preset(&s, "bad\"quote");

    char buf[512];
    int n = diag_stats_format_json(&s, t0, buf, sizeof(buf));
    CHECK(n > 0, "json format returned %d", n);
    /* The unsafe preset is dropped to empty; the raw quote never reaches output. */
    CHECK(strstr(buf, "\"mask_preset\":\"\"") != NULL, "unsafe preset should be empty: %s", buf);
    CHECK(strstr(buf, "bad\"quote") == NULL, "raw quote leaked into JSON: %s", buf);
    /* Balanced braces => still a single well-formed object. */
    CHECK(buf[0] == '{' && buf[n - 1] == '}', "not a well-formed object: %s", buf);
}

/* A JSON object that does not fit is REFUSED (-1), not clamped. A clamp would
 * return a positive length for a clipped object, and the emit site's `> 0`
 * test would send it -- an unparseable line the consumer drops, taking every
 * field in that tick with it. Emitting less is a partial update; emitting a
 * fragment is no update at all, disguised as one. */
static void test_format_json_refuses_to_truncate(void) {
    diag_stats_t s;
    time_t t0 = base_now();
    diag_stats_init(&s, t0);
    char tiny[8];
    int n = diag_stats_format_json(&s, t0, tiny, sizeof(tiny));
    CHECK(n < 0, "a non-fitting object must be refused, got %d", n);
}

/* All six extras-owned keys reach the wire when their owners report. */
static void test_format_json_ex_emits_all_fields(void) {
    diag_stats_t s;
    time_t t0 = base_now();
    diag_stats_init(&s, t0);
    diag_stats_set_mask_preset(&s, "wardrive");

    diag_stats_extra_t x;
    memset(&x, 0, sizeof(x));
    x.f3_preset = "all";
    x.rawlog_path = "/tmp/celldiag-123.hdlc";
    x.rawlog_bytes = 8192;
    x.rawlog_valid = 1;
    x.inventory_distinct_codes = 12;
    x.inventory_unrecognized = 3;
    x.inventory_silent = 1;
    x.inventory_valid = 1;

    char buf[STATS_JSON_BUF];
    int n = diag_stats_format_json_ex(&s, &x, t0, buf, sizeof(buf));
    CHECK(n > 0, "ex format returned %d", n);
    CHECK(strstr(buf, "\"f3_preset\":\"all\"") != NULL, "f3_preset: %s", buf);
    CHECK(strstr(buf, "\"rawlog_path\":\"/tmp/celldiag-123.hdlc\"") != NULL,
          "rawlog_path: %s", buf);
    CHECK(strstr(buf, "\"rawlog_bytes\":8192") != NULL, "rawlog_bytes: %s", buf);
    CHECK(strstr(buf, "\"inventory_distinct_codes\":12") != NULL, "distinct: %s", buf);
    CHECK(strstr(buf, "\"inventory_unrecognized\":3") != NULL, "unrec: %s", buf);
    CHECK(strstr(buf, "\"inventory_silent\":1") != NULL, "silent: %s", buf);
    /* A census whose undecoded_native count is not valid omits the key --
     * not published as a 0 that reads as "native covers it all". */
    CHECK(strstr(buf, "inventory_undecoded_native") == NULL,
          "undecoded_native published for a census that has none: %s", buf);
    CHECK(buf[0] == '{' && buf[n - 1] == '}', "not one object: %s", buf);

    x.inventory_undecoded_native = 234;
    x.inventory_undecoded_valid = 1;
    n = diag_stats_format_json_ex(&s, &x, t0, buf, sizeof(buf));
    CHECK(strstr(buf, "\"inventory_silent\":1,\"inventory_undecoded_native\":234") != NULL,
          "undecoded_native not beside the census group: %s", buf);
}

/* The key property: a source that has not reported
 * OMITS its keys rather than sending zeros. "0 unrecognized" and "no census
 * yet" are opposite readings; a panel cannot tell them apart once they are both
 * the number 0 on the wire. */
static void test_format_json_ex_omits_unreported(void) {
    diag_stats_t s;
    time_t t0 = base_now();
    diag_stats_init(&s, t0);

    diag_stats_extra_t x;
    memset(&x, 0, sizeof(x));
    x.f3_preset = "off";        /* always known; always emitted */
    /* rawlog_valid = 0 (no rawlog= configured), inventory_valid = 0 (no census) */

    char buf[STATS_JSON_BUF];
    int n = diag_stats_format_json_ex(&s, &x, t0, buf, sizeof(buf));
    CHECK(n > 0, "ex format returned %d", n);
    CHECK(strstr(buf, "\"f3_preset\":\"off\"") != NULL, "f3_preset: %s", buf);
    CHECK(strstr(buf, "rawlog_path") == NULL, "unset path must be omitted: %s", buf);
    CHECK(strstr(buf, "rawlog_bytes") == NULL, "unset bytes must be omitted: %s", buf);
    CHECK(strstr(buf, "inventory_") == NULL, "no census => omit all three: %s", buf);
}

/* A path may legitimately contain a quote or backslash. Unlike mask_preset --
 * a controlled label where an unsafe byte means corruption -- blanking a path
 * would lie about where the tee is writing, so it is escaped, not dropped. */
static void test_format_json_ex_escapes_path(void) {
    diag_stats_t s;
    time_t t0 = base_now();
    diag_stats_init(&s, t0);

    diag_stats_extra_t x;
    memset(&x, 0, sizeof(x));
    x.rawlog_path = "/tmp/we\"ird\\path.hdlc";
    x.rawlog_valid = 1;

    char buf[STATS_JSON_BUF];
    int n = diag_stats_format_json_ex(&s, &x, t0, buf, sizeof(buf));
    CHECK(n > 0, "ex format returned %d", n);
    CHECK(strstr(buf, "\\\"ird") != NULL, "quote not escaped: %s", buf);
    CHECK(strstr(buf, "\\\\path") != NULL, "backslash not escaped: %s", buf);
    /* The path survives -- it is escaped, not blanked. */
    CHECK(strstr(buf, "\"rawlog_path\":\"\"") == NULL,
          "path must not be blanked: %s", buf);
    /* Every quote in the object is either a delimiter or escaped => the brace
     * count outside strings is balanced and the object is well-formed. */
    CHECK(buf[0] == '{' && buf[n - 1] == '}', "not one object: %s", buf);
}

/* Overflow DEGRADES: the one unbounded field (the path) is dropped so the ten
 * bounded ones still arrive. Dropping the path costs the operator one string;
 * truncating the object costs them every field in the tick. */
static void test_format_json_ex_overflow_drops_path_not_counters(void) {
    diag_stats_t s;
    time_t t0 = base_now();
    diag_stats_init(&s, t0);
    diag_stats_on_read(&s, 4096, t0);

    char longpath[DIAG_STATS_EXTRA_MAX + 64];
    memset(longpath, 'x', sizeof(longpath) - 1);
    longpath[0] = '/';
    longpath[sizeof(longpath) - 1] = '\0';

    diag_stats_extra_t x;
    memset(&x, 0, sizeof(x));
    x.rawlog_path = longpath;
    x.rawlog_bytes = 777;
    x.rawlog_valid = 1;
    x.inventory_distinct_codes = 9;
    x.inventory_valid = 1;

    char buf[STATS_JSON_BUF];
    int n = diag_stats_format_json_ex(&s, &x, t0, buf, sizeof(buf));
    CHECK(n > 0, "should degrade, not refuse; got %d", n);
    CHECK(strstr(buf, "rawlog_path") == NULL,
          "oversize path must be dropped: %s", buf);
    CHECK(strstr(buf, "\"rawlog_bytes\":777") != NULL,
          "bounded counters must survive the drop: %s", buf);
    CHECK(strstr(buf, "\"inventory_distinct_codes\":9") != NULL,
          "census must survive the drop: %s", buf);
    CHECK(strstr(buf, "\"bytes_read\":4096") != NULL,
          "base counters must survive the drop: %s", buf);
    CHECK(buf[0] == '{' && buf[n - 1] == '}', "not one object: %s", buf);
}

/* Every group at once, every counter at its u64 maximum, and a 300-char tee
 * path. The emit site's buffer is 2048 (capture_cell_diag.c `fjbuf`). The extras
 * without the path are about 1,014 B, so DIAG_STATS_EXTRA_MAX must leave room
 * for this path; a new group must be sized in by raising it, not by eating the
 * path's budget. The path is deliberately long: an 80-char one would still fit
 * at a too-small limit and could not catch that. */
static void test_format_json_ex_every_group_at_worst_case_keeps_the_path(void) {
    diag_stats_t s;
    time_t t0 = base_now();
    diag_stats_init(&s, t0);
    diag_stats_on_read(&s, 4096, t0);

    const uint64_t M = UINT64_MAX;
    char path[301];
    memset(path, 'p', 300);
    memcpy(path, "/tee/", 5);
    path[300] = '\0';
    diag_stats_extra_t x;
    memset(&x, 0, sizeof(x));
    x.f3_preset = "all";
    x.rawlog_path = path; x.rawlog_bytes = M; x.rawlog_valid = 1; x.rawlog_active = 1;
    x.inventory_distinct_codes = M; x.inventory_unrecognized = M;
    x.inventory_silent = M; x.inventory_valid = 1;
    x.inventory_undecoded_native = M; x.inventory_undecoded_valid = 1;
    x.native_total_records = M; x.native_records = M; x.native_obs = M;
    x.native_declined = M; x.native_enriched = M; x.native_gps_fixes = M;
    x.native_fallback_records = M; x.native_valid = 1;
    x.rawpackets_valid = 1; x.rawpackets_on = 1;
    x.rawpackets_slices = M; x.rawpackets_dropped = M;
    x.qsh_valid = 1; x.qsh_requested = 1; x.qsh_armed = 1;
    x.crc_valid = 1; x.crc_checked = M; x.crc_ok = M; x.crc_bad = M;
    x.crc_damage_alerts = M;
    x.anchor_valid = 1; x.anchor_count = M; x.anchor_last_epoch = 1790000000LL;

    char buf[2048];
    int n = diag_stats_format_json_ex(&s, &x, t0, buf, sizeof(buf));
    CHECK(n > 0, "worst case refused: %d", n);
    CHECK(strstr(buf, path) != NULL, "the tee path was dropped at worst case: %s", buf);
    CHECK(strstr(buf, "\"crc_damage_alerts\":18446744073709551615") != NULL,
          "crc group missing at worst case: %s", buf);
    CHECK(strstr(buf, "\"inventory_undecoded_native\":18446744073709551615") != NULL,
          "the native census's undecoded count is missing at worst case: %s", buf);
    CHECK(strstr(buf, "\"anchor_count\":18446744073709551615") != NULL,
          "the group after crc was cut: %s", buf);
    CHECK(n > 0 && buf[0] == '{' && buf[n - 1] == '}', "not one object: %s", buf);
}

/* A retained path is not a running tee.
 *
 * `rawlog=off` closes the sink and DELIBERATELY leaves `rawlog_path` set, so an
 * operator can still answer "where did the bytes I already captured go?"
 * (capture_cell_diag.c's runtime-disable arm says so in as many words). That
 * retention is right, and it means the path CANNOT carry the tee's live state:
 * after one stop, path-is-set and tee-is-running disagree forever.
 *
 * Without `rawlog_active` the only published difference between the two is
 * `rawlog_bytes` no longer rising -- a signal that requires a reader to watch
 * two consecutive ticks and to know what the number did last time. A web-UI
 * control that reads the path concludes the tee is on and offers only "Stop
 * tee"; the start input becomes unreachable for the rest of the source's life.
 * A one-way toggle.
 *
 * So the two states must be DISTINGUISHABLE IN ONE OBJECT, without history. */
static void test_format_json_ex_distinguishes_a_stopped_tee_from_a_running_one(void) {
    diag_stats_t s;
    time_t t0 = base_now();
    char running[STATS_JSON_BUF], stopped[STATS_JSON_BUF];

    diag_stats_init(&s, t0);

    diag_stats_extra_t x;
    memset(&x, 0, sizeof(x));
    x.rawlog_path = "/tmp/celldiag-123.hdlc";
    x.rawlog_bytes = 8192;
    x.rawlog_valid = 1;
    x.rawlog_active = 1;
    CHECK(diag_stats_format_json_ex(&s, &x, t0, running, sizeof(running)) > 0,
          "running format failed");

    /* The ONLY change is the sink closing. Same path, same byte total -- which
     * is exactly the state a stop leaves behind, and exactly why the other two
     * fields cannot be asked to report it. */
    x.rawlog_active = 0;
    CHECK(diag_stats_format_json_ex(&s, &x, t0, stopped, sizeof(stopped)) > 0,
          "stopped format failed");

    CHECK(strstr(running, "\"rawlog_active\":true") != NULL,
          "running tee must say so: %s", running);
    CHECK(strstr(stopped, "\"rawlog_active\":false") != NULL,
          "stopped tee must say so: %s", stopped);

    /* The control: both still report where the bytes went, identically. If a
     * future edit "fixes" this by clearing the path on stop, this fails -- and
     * it should, because that trades one lie for another. */
    CHECK(strstr(stopped, "\"rawlog_path\":\"/tmp/celldiag-123.hdlc\"") != NULL,
          "a stop must not erase where the bytes went: %s", stopped);
    CHECK(strstr(stopped, "\"rawlog_bytes\":8192") != NULL,
          "a stop must not erase the byte total: %s", stopped);
    CHECK(strcmp(running, stopped) != 0,
          "the two states rendered identically -- the object cannot express "
          "a stopped tee: %s", stopped);
}

/* `rawlog_active` rides the `rawlog_valid` gate with `rawlog_bytes`, NOT the
 * path. That is load-bearing in the one direction it can be got wrong: the
 * overflow retry drops the unbounded path and keeps the bounded counters, and
 * a state flag that vanished with the path would leave the panel unable to say
 * whether the tee it is still counting bytes for is even open. */
static void test_rawlog_active_survives_the_oversize_path_drop(void) {
    diag_stats_t s;
    time_t t0 = base_now();
    diag_stats_init(&s, t0);

    char longpath[DIAG_STATS_EXTRA_MAX + 64];
    memset(longpath, 'x', sizeof(longpath) - 1);
    longpath[0] = '/';
    longpath[sizeof(longpath) - 1] = '\0';

    diag_stats_extra_t x;
    memset(&x, 0, sizeof(x));
    x.rawlog_path = longpath;
    x.rawlog_bytes = 777;
    x.rawlog_valid = 1;
    x.rawlog_active = 1;

    char buf[STATS_JSON_BUF];
    int n = diag_stats_format_json_ex(&s, &x, t0, buf, sizeof(buf));
    CHECK(n > 0, "should degrade, not refuse; got %d", n);
    CHECK(strstr(buf, "rawlog_path") == NULL,
          "oversize path must still be dropped: %s", buf);
    CHECK(strstr(buf, "\"rawlog_active\":true") != NULL,
          "the tee's state must survive the path drop: %s", buf);
}

/* No `rawlog=` at all: the key is OMITTED, not sent as false. `false` reads as
 * "a tee exists and is stopped" and would render a Start-tee control beside a
 * path row that says "off (no rawlog= configured)". Same omission rule the rest
 * of this struct obeys, applied to the field most tempting to default. */
static void test_rawlog_active_is_omitted_when_no_tee_was_ever_configured(void) {
    diag_stats_t s;
    time_t t0 = base_now();
    diag_stats_init(&s, t0);

    diag_stats_extra_t x;
    memset(&x, 0, sizeof(x));
    x.f3_preset = "off";
    /* rawlog_valid = 0 => no rawlog= was given */

    char buf[STATS_JSON_BUF];
    int n = diag_stats_format_json_ex(&s, &x, t0, buf, sizeof(buf));
    CHECK(n > 0, "ex format returned %d", n);
    CHECK(strstr(buf, "rawlog_active") == NULL,
          "an unconfigured tee must omit the key, not publish false: %s", buf);
}

/* The switches an operator flips from the panel read back as fields.
 * Each group is emitted whole when valid -- the count without its on/off is a
 * number with no meaning -- and omitted whole when not (never a zero). */
static void test_format_json_ex_reports_the_stream_switches(void) {
    diag_stats_t s;
    time_t t0 = base_now();
    diag_stats_init(&s, t0);

    diag_stats_extra_t x;
    memset(&x, 0, sizeof(x));
    x.f3_preset = "off";
    x.rawpackets_valid = 1;
    x.rawpackets_on = 1;
    x.rawpackets_slices = 42;
    x.rawpackets_dropped = 3;
    x.qsh_valid = 1;
    x.qsh_requested = 1;
    x.qsh_armed = 0;
    x.anchor_valid = 1;
    x.anchor_count = 7;
    x.anchor_last_epoch = 1790000000LL;

    char buf[STATS_JSON_BUF];
    int n = diag_stats_format_json_ex(&s, &x, t0, buf, sizeof(buf));
    CHECK(n > 0, "ex format returned %d", n);
    CHECK(strstr(buf, "\"rawpackets_on\":true") != NULL, "rawpackets_on: %s", buf);
    CHECK(strstr(buf, "\"rawpackets_slices\":42") != NULL, "slices: %s", buf);
    CHECK(strstr(buf, "\"rawpackets_dropped\":3") != NULL, "dropped: %s", buf);
    CHECK(strstr(buf, "\"qsh_requested\":true") != NULL, "qsh_requested: %s", buf);
    CHECK(strstr(buf, "\"qsh_armed\":false") != NULL, "qsh_armed: %s", buf);
    CHECK(strstr(buf, "\"anchor_count\":7") != NULL, "anchor_count: %s", buf);
    CHECK(strstr(buf, "\"anchor_last_epoch\":1790000000") != NULL, "anchor epoch: %s", buf);
    CHECK(buf[0] == '{' && buf[n - 1] == '}', "not one object: %s", buf);

    /* rawpackets=off is a REPORTED off, not an absence. */
    x.rawpackets_on = 0;
    n = diag_stats_format_json_ex(&s, &x, t0, buf, sizeof(buf));
    CHECK(n > 0 && strstr(buf, "\"rawpackets_on\":false") != NULL, "off: %s", buf);

    /* No anchor completed yet: the count is a real 0, the epoch is ABSENT. */
    x.anchor_count = 0;
    x.anchor_last_epoch = 0;
    n = diag_stats_format_json_ex(&s, &x, t0, buf, sizeof(buf));
    CHECK(n > 0 && strstr(buf, "\"anchor_count\":0") != NULL, "count 0: %s", buf);
    CHECK(strstr(buf, "anchor_last_epoch") == NULL, "epoch must be omitted: %s", buf);
}

static void test_format_json_ex_omits_unreported_switches(void) {
    diag_stats_t s;
    time_t t0 = base_now();
    diag_stats_init(&s, t0);

    diag_stats_extra_t x;
    memset(&x, 0, sizeof(x));
    x.f3_preset = "off";

    char buf[STATS_JSON_BUF];
    int n = diag_stats_format_json_ex(&s, &x, t0, buf, sizeof(buf));
    CHECK(n > 0, "ex format returned %d", n);
    CHECK(strstr(buf, "rawpackets_") == NULL, "no rawpackets group: %s", buf);
    CHECK(strstr(buf, "qsh_") == NULL, "no qsh group: %s", buf);
    CHECK(strstr(buf, "anchor_") == NULL, "no anchor group: %s", buf);
}

/* Bring-up progress and failure, as a diag_stats object of its own. Without
 * it a failed deferred bring-up reaches only the message bus; the source then
 * reads "IPC connection closed" and the panel "Decoder DEAD". */
static void test_bringup_json_reports_progress(void) {
    char buf[STATS_JSON_BUF];
    int n = diag_stats_format_bringup_json("at_scan=12ms port_detect=3ms", 15,
                                           NULL, buf, sizeof(buf));
    CHECK(n > 0, "bringup json returned %d", n);
    CHECK(strstr(buf, "\"type\":\"diag_stats\"") != NULL, "type: %s", buf);
    CHECK(strstr(buf, "\"bringup_ms\":15") != NULL, "ms: %s", buf);
    CHECK(strstr(buf, "\"bringup_phases\":\"at_scan=12ms port_detect=3ms\"") != NULL,
          "phases: %s", buf);
    CHECK(strstr(buf, "bringup_error") == NULL, "progress carries no error: %s", buf);
    CHECK(strstr(buf, "helper_alive") == NULL,
          "progress must not claim the helper's state: %s", buf);
    CHECK(buf[0] == '{' && buf[n - 1] == '}', "not one object: %s", buf);
}

static void test_bringup_json_reports_the_failure_escaped(void) {
    char buf[STATS_JSON_BUF];
    int n = diag_stats_format_bringup_json("at_scan=2ms", 2,
        "Could not locate \"DIAG\" for C:\\x\nPass diagport=", buf, sizeof(buf));
    CHECK(n > 0, "bringup json returned %d", n);
    CHECK(strstr(buf, "\"bringup_error\":\"Could not locate \\\"DIAG\\\" for "
                      "C:\\\\x\\u000aPass diagport=\"") != NULL, "escaped: %s", buf);
    CHECK(strstr(buf, "\"helper_alive\":0") != NULL, "no helper ran: %s", buf);
    CHECK(strstr(buf, "\"mask_preset\":\"failed\"") != NULL, "mask: %s", buf);
}

static void test_bringup_json_refuses_to_truncate(void) {
    char tiny[24];
    CHECK(diag_stats_format_bringup_json("at_scan=2ms", 2, "x", tiny, sizeof(tiny)) == -1,
          "a clipped object must not be written");
}

int main(void) {
    test_verdict_nodata();
    /* The producer arms. */
    test_closed_port_with_a_live_decoder_is_port_closed();
    test_nodata_still_outranks_the_producer_arms();
    test_format_word_agrees_with_the_fields_beside_it();
    /* The decoder producer. */
    test_native_flowing_reads_flowing();
    test_native_rx_no_obs();
    test_native_quiet_port_with_a_live_decoder_is_stalled();
    test_native_stuck_reader_is_decoder_stalled();
    test_native_stuck_reader_outranks_a_stale_read();
    test_native_teardown_is_port_closed_and_decoder_stopped();
    test_native_nodata_still_first();
    test_heartbeat_staleness_judgment();
    test_decoder_stalled_line();
    test_liveness_json();
    test_verdict_flowing_stalled();
    test_verdict_rx_no_obs();
    test_rate_rolling();
    test_rate_empty();
    test_rate_ring_saturation();
    test_rate_full_ring_partial_window();
    test_cadence_due();
    test_mark_status_resets_since();
    test_format_contains_fields();
    test_format_stalled_distinguishable();
    test_format_overflow_clamps();
    test_format_json_contains_field_keys();
    test_format_json_mask_preset_injection_guard();
    test_format_json_refuses_to_truncate();
    test_format_json_ex_emits_all_fields();
    test_format_json_ex_omits_unreported();
    test_format_json_ex_distinguishes_a_stopped_tee_from_a_running_one();
    test_rawlog_active_survives_the_oversize_path_drop();
    test_rawlog_active_is_omitted_when_no_tee_was_ever_configured();
    test_format_json_ex_escapes_path();
    test_format_json_ex_overflow_drops_path_not_counters();
    test_format_json_ex_every_group_at_worst_case_keeps_the_path();
    test_format_json_ex_reports_the_stream_switches();
    test_format_json_ex_omits_unreported_switches();
    test_bringup_json_reports_progress();
    test_bringup_json_reports_the_failure_escaped();
    test_bringup_json_refuses_to_truncate();

    if (failures == 0) {
        printf("PASS: all diag_stats tests\n");
        return 0;
    }
    fprintf(stderr, "FAILED: %d diag_stats test check(s)\n", failures);
    return 1;
}
