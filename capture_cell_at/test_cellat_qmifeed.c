/*
    Selftest for cellat_qmifeed.c -- `make check` in this directory.

    Drives real child processes (/bin/sh -c ...), since the unit's whole job is
    process plumbing: line framing across reads, the overlong-line drop, EOF,
    fd hygiene, and a stop that reaches the child's whole process group.
*/

#if defined(__linux__) && !defined(_GNU_SOURCE)
#define _GNU_SOURCE   /* setresuid/setresgid: the suid-state simulation */
#endif
#include "cellat_qmifeed.h"
#include "../capture_cell_diag/diag_privdrop.h"

#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/wait.h>
#include <time.h>
#include <unistd.h>

static int failures = 0;

#define CHECK(cond, ...) do { \
    if (!(cond)) { \
        fprintf(stderr, "FAIL %s:%d: ", __FILE__, __LINE__); \
        fprintf(stderr, __VA_ARGS__); \
        fprintf(stderr, "\n"); \
        failures++; \
    } \
} while (0)

#define MAXL 16

typedef struct {
    int  n;
    char line[MAXL][QMIFEED_LINE_MAX];
} sink_t;

static void collect(const char *line, void *ctx) {
    sink_t *s = (sink_t *) ctx;
    if (s->n < MAXL)
        snprintf(s->line[s->n], QMIFEED_LINE_MAX, "%s", line);
    s->n++;
}

static void sleep_ms(int ms) {
    struct timespec ts = { .tv_sec = ms / 1000, .tv_nsec = (ms % 1000) * 1000000L };
    nanosleep(&ts, NULL);
}

/* Poll until end-of-stream (or ~5 s), collecting lines. */
static void drain(qmifeed_t *qf, sink_t *s) {
    for (int i = 0; i < 250 && !qf->eof; i++) {
        qmifeed_poll(qf, collect, s);
        if (!qf->eof)
            sleep_ms(20);
    }
}

static void test_lines_forwarded_in_order(void) {
    qmifeed_t qf; sink_t s = {0}; char err[256];
    qmifeed_init(&qf);
    CHECK(qmifeed_start(&qf, "printf '{\"a\":1}\\n{\"b\":2}\\n'", err, sizeof(err)) == 0,
          "start: %s", err);
    drain(&qf, &s);
    CHECK(s.n == 2, "want 2 lines, got %d", s.n);
    CHECK(strcmp(s.line[0], "{\"a\":1}") == 0, "line0 '%s'", s.line[0]);
    CHECK(strcmp(s.line[1], "{\"b\":2}") == 0, "line1 '%s'", s.line[1]);
    CHECK(qf.eof, "eof not seen");
    CHECK(qmifeed_stop(&qf, 500) >= 0, "stop found no child");
}

static void test_line_split_across_writes_is_reassembled(void) {
    /* The writer flushes half an object, pauses, then the rest: the reader must
     * hold the partial tail rather than forward a fragment. */
    qmifeed_t qf; sink_t s = {0}; char err[256];
    qmifeed_init(&qf);
    CHECK(qmifeed_start(&qf, "printf '{\"rat\":'; sleep 0.3; printf '\"LTE\"}\\n'",
                        err, sizeof(err)) == 0, "start: %s", err);
    sleep_ms(100);
    qmifeed_poll(&qf, collect, &s);
    CHECK(s.n == 0, "fragment forwarded early: '%s'", s.n ? s.line[0] : "");
    drain(&qf, &s);
    CHECK(s.n == 1 && strcmp(s.line[0], "{\"rat\":\"LTE\"}") == 0,
          "n=%d line='%s'", s.n, s.n ? s.line[0] : "");
    qmifeed_stop(&qf, 500);
}

static void test_non_json_and_blank_lines_dropped(void) {
    qmifeed_t qf; sink_t s = {0}; char err[256];
    qmifeed_init(&qf);
    CHECK(qmifeed_start(&qf, "printf 'banner text\\n\\n{\"ok\":1}\\r\\n{\"half\":\\n'",
                        err, sizeof(err)) == 0, "start: %s", err);
    drain(&qf, &s);
    CHECK(s.n == 1 && strcmp(s.line[0], "{\"ok\":1}") == 0,
          "n=%d line0='%s'", s.n, s.n ? s.line[0] : "");
    CHECK(qf.dropped_nonjson == 2, "dropped_nonjson=%llu",
          (unsigned long long) qf.dropped_nonjson);
    qmifeed_stop(&qf, 500);
}

static void test_overlong_line_dropped_whole(void) {
    /* 5000 'x' inside braces, then a normal line: the long one is dropped
     * entirely -- never forwarded as a truncated prefix -- and framing recovers. */
    qmifeed_t qf; sink_t s = {0}; char err[256];
    qmifeed_init(&qf);
    CHECK(qmifeed_start(&qf,
          "printf '{'; head -c 5000 /dev/zero | tr '\\0' x; printf '}\\n{\"next\":1}\\n'",
          err, sizeof(err)) == 0, "start: %s", err);
    drain(&qf, &s);
    CHECK(s.n == 1 && strcmp(s.line[0], "{\"next\":1}") == 0,
          "n=%d line0 len=%zu", s.n, s.n ? strlen(s.line[0]) : 0);
    CHECK(qf.dropped_overlong == 1, "dropped_overlong=%llu",
          (unsigned long long) qf.dropped_overlong);
    qmifeed_stop(&qf, 500);
}

static void test_overlong_tail_that_looks_like_json_is_not_forwarded(void) {
    /* The overflow lands mid-line and what follows is itself a well-formed
     * object. Forwarding it would inject a fragment the writer never meant as
     * an observation, so the rest of an overlong line is discarded to '\n'. */
    qmifeed_t qf; sink_t s = {0}; char err[256];
    qmifeed_init(&qf);
    CHECK(qmifeed_start(&qf,
          "printf '{'; head -c 4094 /dev/zero | tr '\\0' x; "
          "printf 'y{\"frag\":1}\\n{\"next\":1}\\n'",
          err, sizeof(err)) == 0, "start: %s", err);
    drain(&qf, &s);
    CHECK(s.n == 1 && strcmp(s.line[0], "{\"next\":1}") == 0,
          "n=%d line0='%.40s'", s.n, s.n ? s.line[0] : "");
    qmifeed_stop(&qf, 500);
}

static void test_unterminated_final_line_delivered_at_eof(void) {
    qmifeed_t qf; sink_t s = {0}; char err[256];
    qmifeed_init(&qf);
    CHECK(qmifeed_start(&qf, "printf '{\"last\":1}'", err, sizeof(err)) == 0,
          "start: %s", err);
    drain(&qf, &s);
    CHECK(s.n == 1 && strcmp(s.line[0], "{\"last\":1}") == 0, "n=%d", s.n);
    qmifeed_stop(&qf, 500);
}

static void test_eof_flagged_with_no_output(void) {
    qmifeed_t qf; sink_t s = {0}; char err[256];
    qmifeed_init(&qf);
    CHECK(qmifeed_start(&qf, "true", err, sizeof(err)) == 0, "start: %s", err);
    drain(&qf, &s);
    CHECK(qf.eof && qf.fd == -1, "eof=%d fd=%d", qf.eof, qf.fd);
    CHECK(qmifeed_poll(&qf, collect, &s) == 0, "a poll after EOF should return 0");
    int st = qmifeed_stop(&qf, 500);
    CHECK(WIFEXITED(st) && WEXITSTATUS(st) == 0, "status %d", st);
}

static void test_eof_flagged_when_it_arrives_with_the_last_lines(void) {
    /* The shape every real feed has: print, then exit. Lines and EOF land in
     * one read(); the call must deliver the lines AND flag the EOF. */
    qmifeed_t qf; sink_t s = {0}; char err[256];
    qmifeed_init(&qf);
    CHECK(qmifeed_start(&qf, "printf '{\"a\":1}\\n'; exit 3", err, sizeof(err)) == 0,
          "start: %s", err);
    sleep_ms(300);          /* let it print AND exit before the first poll */
    int n = qmifeed_poll(&qf, collect, &s);
    CHECK(n == 1 && s.n == 1, "n=%d s.n=%d", n, s.n);
    CHECK(qf.eof, "EOF not flagged on the read that delivered the last line");
    int st = qmifeed_stop(&qf, 500);
    CHECK(WIFEXITED(st) && WEXITSTATUS(st) == 3, "status %d", st);
}

static void test_empty_command_rejected(void) {
    qmifeed_t qf; char err[256] = "";
    qmifeed_init(&qf);
    CHECK(qmifeed_start(&qf, "", err, sizeof(err)) == -1, "empty cmd accepted");
    CHECK(strstr(err, "qmifeed=") != NULL, "err '%s'", err);
    CHECK(qmifeed_stop(&qf, 100) == -1, "stop with no child should be -1");
}

static void test_inherited_fds_closed_in_child(void) {
    /* Stand-in for the KDS IPC pipe: a non-CLOEXEC fd open in the parent. The
     * child must not see it, or the server never gets EOF from a dead source. */
    int fds[2];
    CHECK(pipe(fds) == 0, "pipe");
    char cmd[128];
    snprintf(cmd, sizeof(cmd),
             "if [ -e /proc/self/fd/%d ] || [ -e /dev/fd/%d ]; then "
             "echo '{\"leak\":1}'; else echo '{\"leak\":0}'; fi", fds[1], fds[1]);
    qmifeed_t qf; sink_t s = {0}; char err[256];
    qmifeed_init(&qf);
    CHECK(qmifeed_start(&qf, cmd, err, sizeof(err)) == 0, "start: %s", err);
    drain(&qf, &s);
    CHECK(s.n == 1 && strcmp(s.line[0], "{\"leak\":0}") == 0,
          "child inherited fd %d: '%s'", fds[1], s.n ? s.line[0] : "(none)");
    qmifeed_stop(&qf, 500);
    close(fds[0]);
    close(fds[1]);
}

static void test_stop_kills_the_whole_group(void) {
    /* sh backgrounds a grandchild that ignores nothing and would outlive sh;
     * the stop must reach it through the process group. It reports its pid. */
    qmifeed_t qf; sink_t s = {0}; char err[256];
    qmifeed_init(&qf);
    CHECK(qmifeed_start(&qf, "sleep 60 & echo \"{\\\"gc\\\":$!}\"; wait",
                        err, sizeof(err)) == 0, "start: %s", err);
    for (int i = 0; i < 250 && s.n == 0; i++) {
        qmifeed_poll(&qf, collect, &s);
        if (s.n == 0) sleep_ms(20);
    }
    CHECK(s.n == 1, "no grandchild pid line");
    int gc = 0;
    if (s.n == 1)
        sscanf(s.line[0], "{\"gc\":%d}", &gc);
    CHECK(gc > 0, "bad grandchild pid in '%s'", s.n ? s.line[0] : "");
    qmifeed_stop(&qf, 1000);
    int alive = 0;
    for (int i = 0; i < 50; i++) {
        alive = (gc > 0 && kill(gc, 0) == 0);
        if (!alive) break;
        sleep_ms(20);
    }
    CHECK(!alive, "grandchild %d survived qmifeed_stop", gc);
    CHECK(qf.pid == -1 && qf.fd == -1, "stop left pid=%d fd=%d", (int) qf.pid, qf.fd);
    CHECK(qmifeed_stop(&qf, 100) == -1, "second stop should be a no-op");
}

static void test_child_starts_with_no_blocked_signals(void) {
#ifdef __linux__
    /* The capture thread blocks SIGPIPE (and more); the mask survives exec.
     * Model it here, then read the child's own mask from /proc. */
    sigset_t blk, old;
    sigemptyset(&blk);
    sigaddset(&blk, SIGPIPE);
    sigaddset(&blk, SIGCHLD);
    sigprocmask(SIG_BLOCK, &blk, &old);
    qmifeed_t qf; sink_t s = {0}; char err[256];
    qmifeed_init(&qf);
    CHECK(qmifeed_start(&qf,
          "printf '{\"blk\":\"%s\"}\\n' \"$(awk '/^SigBlk/{print $2}' /proc/self/status)\"",
          err, sizeof(err)) == 0, "start: %s", err);
    sigprocmask(SIG_SETMASK, &old, NULL);
    drain(&qf, &s);
    CHECK(s.n == 1 && strcmp(s.line[0], "{\"blk\":\"0000000000000000\"}") == 0,
          "child mask: '%s'", s.n ? s.line[0] : "(none)");
    qmifeed_stop(&qf, 500);
#endif
}

static void test_stop_escalates_to_sigkill(void) {
    /* A child that ignores SIGTERM must still be gone within the grace. */
    qmifeed_t qf; sink_t s = {0}; char err[256];
    qmifeed_init(&qf);
    CHECK(qmifeed_start(&qf, "trap '' TERM; echo '{\"up\":1}'; while :; do sleep 1; done",
                        err, sizeof(err)) == 0, "start: %s", err);
    for (int i = 0; i < 250 && s.n == 0; i++) {
        qmifeed_poll(&qf, collect, &s);
        if (s.n == 0) sleep_ms(20);
    }
    int st = qmifeed_stop(&qf, 200);
    CHECK(WIFSIGNALED(st) && WTERMSIG(st) == SIGKILL, "status %d", st);
}

/* ---- the IMEI cross-check --------------------------------------------- */

#define SRC_IMEI "351234567890123"

static void test_line_imei_extracted_from_prov(void) {
    char imei[32];
    CHECK(qmifeed_line_imei("{\"rat\":\"LTE\",\"prov\":{\"src\":\"qmi\",\"imei\":\"352222222222222\"}}",
                            imei, sizeof(imei)) == 1 && strcmp(imei, "352222222222222") == 0,
          "prov.imei not found: '%s'", imei);
    /* A top-level "imei" (or one in some other object) is not prov.imei. */
    CHECK(qmifeed_line_imei("{\"imei\":\"111111111111111\",\"x\":{\"imei\":\"2\"},\"prov\":{\"src\":\"qmi\"}}",
                            imei, sizeof(imei)) == 0, "a non-prov imei was read as prov.imei");
    /* Strings that merely CONTAIN the key text do not fool the scanner. */
    CHECK(qmifeed_line_imei("{\"note\":\"\\\"prov\\\":{\\\"imei\\\":\\\"9\\\"}\",\"prov\":{\"imei\":\"352222222222222\"}}",
                            imei, sizeof(imei)) == 1 && strcmp(imei, "352222222222222") == 0,
          "string contents confused the scanner: '%s'", imei);
    /* Nested values before the key are skipped whole. */
    CHECK(qmifeed_line_imei("{\"prov\":{\"a\":[1,{\"imei\":\"9\"}],\"imei\":\"352222222222222\"}}",
                            imei, sizeof(imei)) == 1 && strcmp(imei, "352222222222222") == 0,
          "nested value not skipped: '%s'", imei);
    CHECK(qmifeed_line_imei("{\"prov\":{\"src\":\"qmi\"}}", imei, sizeof(imei)) == 0,
          "absent prov.imei not reported as absent");
    CHECK(qmifeed_line_imei("{\"rat\":\"LTE\"}", imei, sizeof(imei)) == 0,
          "absent prov not reported as absent");
    CHECK(qmifeed_line_imei("{\"prov\":\"qmi\"}", imei, sizeof(imei)) == -1,
          "a non-object prov is malformed");
    CHECK(qmifeed_line_imei("{\"prov\":{\"imei\":352222222222222}}", imei, sizeof(imei)) == -1,
          "a numeric imei is malformed");
    CHECK(qmifeed_line_imei("{\"prov\":{\"imei\":\"352222222222222", imei, sizeof(imei)) == -1,
          "an unterminated string is malformed");
}

static void test_imei_verdicts(void) {
    const char *ok  = "{\"prov\":{\"src\":\"qmi\",\"imei\":\"" SRC_IMEI "\"}}";
    const char *bad = "{\"prov\":{\"src\":\"qmi\",\"imei\":\"352222222222222\"}}";
    const char *empty = "{\"prov\":{\"src\":\"qmi\",\"imei\":\"\"}}";
    const char *none  = "{\"prov\":{\"src\":\"qmi\"}}";
    char got[32];
    CHECK(qmifeed_imei_check(ok, SRC_IMEI, got, sizeof(got)) == QMIFEED_IMEI_MATCH, "match");
    CHECK(qmifeed_imei_check(bad, SRC_IMEI, got, sizeof(got)) == QMIFEED_IMEI_MISMATCH
          && strcmp(got, "352222222222222") == 0, "mismatch (got '%s')", got);
    /* No stamp = no attribution anyone checked: fail closed. */
    CHECK(qmifeed_imei_check(empty, SRC_IMEI, got, sizeof(got)) == QMIFEED_IMEI_UNSTAMPED,
          "empty prov.imei must be UNSTAMPED");
    CHECK(qmifeed_imei_check(none, SRC_IMEI, got, sizeof(got)) == QMIFEED_IMEI_UNSTAMPED,
          "absent prov.imei must be UNSTAMPED");
    CHECK(qmifeed_imei_check("{\"prov\":7}", SRC_IMEI, got, sizeof(got)) == QMIFEED_IMEI_UNSTAMPED,
          "malformed prov must be UNSTAMPED");
    /* A source that could not learn its own IMEI has nothing to compare to. */
    CHECK(qmifeed_imei_check(bad, "", got, sizeof(got)) == QMIFEED_IMEI_UNCHECKED, "empty source");
    CHECK(qmifeed_imei_check(bad, NULL, got, sizeof(got)) == QMIFEED_IMEI_UNCHECKED, "NULL source");
    CHECK(qmifeed_imei_check(bad, "000000000000000", got, sizeof(got)) == QMIFEED_IMEI_UNCHECKED,
          "this tree's unknown-IMEI sentinel is not an identity");
}

static void test_child_env_carries_the_verified_imei(void) {
    /* The feed learns which modem it must be on from CELLAT_IMEI. */
    qmifeed_t qf; sink_t s = {0}; char err[256];
    qmifeed_init(&qf);
    qmifeed_set_expect_imei(&qf, SRC_IMEI);
    CHECK(qmifeed_start(&qf, "echo \"{\\\"env\\\":\\\"$CELLAT_IMEI\\\"}\"",
                        err, sizeof(err)) == 0, "start: %s", err);
    drain(&qf, &s);
    CHECK(s.n == 1 && strcmp(s.line[0], "{\"env\":\"" SRC_IMEI "\"}") == 0,
          "CELLAT_IMEI in child: '%s'", s.n ? s.line[0] : "(none)");
    qmifeed_stop(&qf, 500);
}

static void test_inherited_cellat_imei_is_replaced_not_duplicated(void) {
    /* A stale CELLAT_IMEI in the capture child's own environment must not win,
     * and a source with no verified IMEI must not pass one along. */
    setenv("CELLAT_IMEI", "999999999999999", 1);
    qmifeed_t qf; sink_t s = {0}; char err[256];
    qmifeed_init(&qf);
    qmifeed_set_expect_imei(&qf, SRC_IMEI);
    /* /proc/$$/environ, not `env`: see test_child_env_announces_the_line_protocol. */
    CHECK(qmifeed_start(&qf, "{ if [ -r /proc/$$/environ ]; then tr '\\0' '\\n' < /proc/$$/environ; "
                             "else env; fi; } | grep -c '^CELLAT_IMEI=' | sed 's/.*/{\"n\":&}/'; "
                             "echo \"{\\\"env\\\":\\\"$CELLAT_IMEI\\\"}\"",
                        err, sizeof(err)) == 0, "start: %s", err);
    drain(&qf, &s);
    CHECK(s.n == 2 && strcmp(s.line[0], "{\"n\":1}") == 0
          && strcmp(s.line[1], "{\"env\":\"" SRC_IMEI "\"}") == 0,
          "stale env: '%s' '%s'", s.n > 0 ? s.line[0] : "", s.n > 1 ? s.line[1] : "");
    qmifeed_stop(&qf, 500);

    sink_t s2 = {0};
    qmifeed_init(&qf);
    qmifeed_set_expect_imei(&qf, "000000000000000");
    CHECK(qmifeed_start(&qf, "echo \"{\\\"env\\\":\\\"${CELLAT_IMEI-unset}\\\"}\"",
                        err, sizeof(err)) == 0, "start: %s", err);
    drain(&qf, &s2);
    CHECK(s2.n == 1 && strcmp(s2.line[0], "{\"env\":\"unset\"}") == 0,
          "sentinel IMEI exported: '%s'", s2.n ? s2.line[0] : "(none)");
    qmifeed_stop(&qf, 500);
    unsetenv("CELLAT_IMEI");
}

/* ---- the tagged second line type -------------------------------------- */

typedef struct {
    int    n;
    int    tag[MAXL];
    size_t len[MAXL];
    char   payload[MAXL][256];   /* first 255 bytes: enough to identify */
} tagsink_t;

typedef struct { sink_t obs; tagsink_t tags; } both_t;

static void collect_obs(const char *line, void *ctx) {
    collect(line, &((both_t *) ctx)->obs);
}

static void collect_tag(qmifeed_tag_t tag, const char *payload, void *ctx) {
    tagsink_t *s = &((both_t *) ctx)->tags;
    if (s->n < MAXL) {
        s->tag[s->n] = (int) tag;
        s->len[s->n] = strlen(payload);
        snprintf(s->payload[s->n], sizeof(s->payload[0]), "%s", payload);
    }
    s->n++;
}

static void drain_both(qmifeed_t *qf, both_t *b) {
    for (int i = 0; i < 250 && !qf->eof; i++) {
        qmifeed_poll(qf, collect_obs, b);
        if (!qf->eof)
            sleep_ms(20);
    }
}

static void test_tagged_lines_are_routed_beside_observations(void) {
    qmifeed_t qf; both_t b; char err[256];
    memset(&b, 0, sizeof(b));
    qmifeed_init(&qf);
    qmifeed_set_tag_cb(&qf, collect_tag);
    CHECK(qmifeed_start(&qf,
          "printf '#rawqmi {\"argv\":[\"qmicli\"],\"rc\":0}\\n{\"obs\":1}\\n"
          "#msg info polling /dev/cdc-wdm3 instead\\n#msg error no QMI device\\n'",
          err, sizeof(err)) == 0, "start: %s", err);
    drain_both(&qf, &b);
    CHECK(b.obs.n == 1 && strcmp(b.obs.line[0], "{\"obs\":1}") == 0,
          "observations n=%d", b.obs.n);
    CHECK(b.tags.n == 3, "want 3 tagged, got %d", b.tags.n);
    CHECK(b.tags.tag[0] == QMIFEED_TAG_RAWQMI &&
          strcmp(b.tags.payload[0], "{\"argv\":[\"qmicli\"],\"rc\":0}") == 0,
          "raw: tag=%d '%s'", b.tags.tag[0], b.tags.payload[0]);
    CHECK(b.tags.tag[1] == QMIFEED_TAG_MSG_INFO &&
          strcmp(b.tags.payload[1], "polling /dev/cdc-wdm3 instead") == 0,
          "info: tag=%d '%s'", b.tags.tag[1], b.tags.payload[1]);
    CHECK(b.tags.tag[2] == QMIFEED_TAG_MSG_ERROR &&
          strcmp(b.tags.payload[2], "no QMI device") == 0,
          "error: tag=%d '%s'", b.tags.tag[2], b.tags.payload[2]);
    CHECK(qf.tagged == 3 && qf.lines == 1 && qf.dropped_nonjson == 0,
          "tagged=%llu lines=%llu nonjson=%llu", (unsigned long long) qf.tagged,
          (unsigned long long) qf.lines, (unsigned long long) qf.dropped_nonjson);
    qmifeed_stop(&qf, 500);
}

static void test_tagged_lines_without_a_callback_are_non_json(void) {
    /* A capture path that never sets a tag callback treats tagged lines as
     * non-JSON. */
    qmifeed_t qf; sink_t s = {0}; char err[256];
    qmifeed_init(&qf);
    CHECK(qmifeed_start(&qf, "printf '#rawqmi {\"a\":1}\\n#msg info hi\\n{\"ok\":1}\\n'",
                        err, sizeof(err)) == 0, "start: %s", err);
    drain(&qf, &s);
    CHECK(s.n == 1 && qf.dropped_nonjson == 2 && qf.tagged == 0,
          "n=%d nonjson=%llu tagged=%llu", s.n,
          (unsigned long long) qf.dropped_nonjson, (unsigned long long) qf.tagged);
    qmifeed_stop(&qf, 500);
}

static void test_malformed_tags_are_counted_not_forwarded(void) {
    qmifeed_t qf; both_t b; char err[256];
    memset(&b, 0, sizeof(b));
    qmifeed_init(&qf);
    qmifeed_set_tag_cb(&qf, collect_tag);
    CHECK(qmifeed_start(&qf,
          "printf '#bogus x\\n#rawqmi not-json\\n#rawqmi {\"open\":1\\n"
          "#msg warn x\\n#msg info \\n#rawqmi\\n'",
          err, sizeof(err)) == 0, "start: %s", err);
    drain_both(&qf, &b);
    CHECK(b.tags.n == 0, "forwarded %d malformed tagged line(s), first '%s'",
          b.tags.n, b.tags.payload[0]);
    CHECK(qf.dropped_badtag == 6, "dropped_badtag=%llu",
          (unsigned long long) qf.dropped_badtag);
    qmifeed_stop(&qf, 500);
}

static void test_a_raw_line_may_exceed_the_observation_cap(void) {
    /* A --qmilog-wire record is ~10 KB: it must arrive whole, while an
     * observation of the same size is still dropped whole. */
    qmifeed_t qf; both_t b; char err[256];
    memset(&b, 0, sizeof(b));
    qmifeed_init(&qf);
    qmifeed_set_tag_cb(&qf, collect_tag);
    CHECK(qmifeed_start(&qf,
          "printf '#rawqmi {\"x\":\"'; head -c 10000 /dev/zero | tr '\\0' x; printf '\"}\\n';"
          "printf '{\"y\":\"'; head -c 10000 /dev/zero | tr '\\0' y; printf '\"}\\n{\"next\":1}\\n'",
          err, sizeof(err)) == 0, "start: %s", err);
    drain_both(&qf, &b);
    CHECK(b.tags.n == 1 && b.tags.len[0] == 10000 + 8,
          "raw n=%d len=%zu", b.tags.n, b.tags.n ? b.tags.len[0] : (size_t) 0);
    CHECK(b.obs.n == 1 && strcmp(b.obs.line[0], "{\"next\":1}") == 0 &&
          qf.dropped_overlong == 1, "obs n=%d overlong=%llu", b.obs.n,
          (unsigned long long) qf.dropped_overlong);
    qmifeed_stop(&qf, 500);
}

static void test_child_env_announces_the_line_protocol(void) {
    /* The feed may write tagged lines only when told this binary reads them;
     * an inherited value must not survive (or be duplicated). */
    setenv(QMIFEED_PROTO_ENV, "99", 1);
    qmifeed_t qf; sink_t s = {0}; char err[256];
    qmifeed_init(&qf);
    /* Count in /proc/$$/environ, the block exec() actually received: `env`
     * cannot see a duplicate, because sh rebuilds its environment from its own
     * (deduplicated) variable table -- and a duplicate is a real defect, since
     * C getenv() takes the FIRST entry and Python os.environ the LAST. Where
     * there is no /proc (Darwin) the count falls back to `env`'s. */
    CHECK(qmifeed_start(&qf, "{ if [ -r /proc/$$/environ ]; then tr '\\0' '\\n' < /proc/$$/environ; "
                             "else env; fi; } | grep -c '^" QMIFEED_PROTO_ENV "=' | sed 's/.*/{\"n\":&}/'; "
                             "echo \"{\\\"p\\\":\\\"$" QMIFEED_PROTO_ENV "\\\"}\"",
                        err, sizeof(err)) == 0, "start: %s", err);
    drain(&qf, &s);
    CHECK(s.n == 2 && strcmp(s.line[0], "{\"n\":1}") == 0
          && strcmp(s.line[1], "{\"p\":\"2\"}") == 0,
          "proto env: '%s' '%s'", s.n > 0 ? s.line[0] : "", s.n > 1 ? s.line[1] : "");
    qmifeed_stop(&qf, 500);
    unsetenv(QMIFEED_PROTO_ENV);
}

/* ---- qmifeed=auto finds the feed that ships in this tree ---- */

static char tree[256];

/* A throwaway tree: <tree>/capture_cell_at/qmifeed/kismet_qmi_feed.py. */
static void make_tree(const char *leaf_dir) {
    snprintf(tree, sizeof(tree), "/tmp/qmifeed_auto_XXXXXX");
    if (mkdtemp(tree) == NULL) {
        perror("mkdtemp");
        exit(2);
    }
    char cmd[1024];
    snprintf(cmd, sizeof(cmd),
             "mkdir -p '%s/capture_cell_at/qmifeed' '%s/%s' && "
             "touch '%s/capture_cell_at/qmifeed/kismet_qmi_feed.py'",
             tree, tree, leaf_dir, tree);
    if (system(cmd) != 0) {
        fprintf(stderr, "make_tree failed\n");
        exit(2);
    }
}

static void rm_tree(void) {
    char cmd[512];
    snprintf(cmd, sizeof(cmd), "rm -rf '%s'", tree);
    if (system(cmd) != 0)
        fprintf(stderr, "rm_tree: could not remove %s\n", tree);
}

static void test_a_command_is_used_verbatim(void) {
    char out[512], err[256];
    const char *cmd = "/usr/bin/python3 /opt/feed.py --interval 2";
    CHECK(qmifeed_resolve_command(cmd, "/nonexistent", out, sizeof(out),
                                  err, sizeof(err)) == 0, "verbatim refused: %s", err);
    CHECK(strcmp(out, cmd) == 0, "verbatim changed: %s", out);
    /* "autox" is a command named autox, not the keyword. */
    CHECK(qmifeed_resolve_command("autox", "/nonexistent", out, sizeof(out),
                                  err, sizeof(err)) == 0 && strcmp(out, "autox") == 0,
          "autox read as auto: %s", out);
}

static void test_auto_finds_the_feed_beside_the_binary(void) {
    make_tree("capture_cell_at");
    char self[512], out[1024], err[256], want[1024];
    snprintf(self, sizeof(self), "%s/capture_cell_at", tree);
    CHECK(qmifeed_resolve_command("auto", self, out, sizeof(out), err, sizeof(err)) == 0,
          "auto refused beside the binary: %s", err);
    snprintf(want, sizeof(want),
             "exec python3 '%s/capture_cell_at/qmifeed/kismet_qmi_feed.py'", tree);
    CHECK(strcmp(out, want) == 0, "auto -> %s", out);
    /* `1` is the same keyword. */
    CHECK(qmifeed_resolve_command("1", self, out, sizeof(out), err, sizeof(err)) == 0
          && strcmp(out, want) == 0, "1 -> %s", out);
    rm_tree();
}

static void test_auto_finds_the_feed_from_the_tree_root_and_below(void) {
    make_tree("build/sub");
    char self[512], out[1024], err[256], want[1024];
    snprintf(want, sizeof(want),
             "exec python3 '%s/capture_cell_at/qmifeed/kismet_qmi_feed.py'", tree);
    /* A binary at the tree root finds capture_cell_at/qmifeed/. */
    CHECK(qmifeed_resolve_command("auto", tree, out, sizeof(out), err, sizeof(err)) == 0
          && strcmp(out, want) == 0, "root: %s / %s", out, err);
    /* Two levels down still walks up to it. */
    snprintf(self, sizeof(self), "%s/build/sub", tree);
    CHECK(qmifeed_resolve_command("auto", self, out, sizeof(out), err, sizeof(err)) == 0
          && strcmp(out, want) == 0, "below: %s / %s", out, err);
    rm_tree();
}

static void test_auto_passes_its_arguments_to_the_feed(void) {
    make_tree("capture_cell_at");
    char self[512], out[1024], err[256], want[1024];
    snprintf(self, sizeof(self), "%s/capture_cell_at", tree);
    CHECK(qmifeed_resolve_command("auto -d /dev/cdc-wdm0 --interval 2", self,
                                  out, sizeof(out), err, sizeof(err)) == 0,
          "auto+args refused: %s", err);
    snprintf(want, sizeof(want),
             "exec python3 '%s/capture_cell_at/qmifeed/kismet_qmi_feed.py'"
             " -d /dev/cdc-wdm0 --interval 2", tree);
    CHECK(strcmp(out, want) == 0, "auto+args -> %s", out);
    rm_tree();
}

static void test_auto_without_a_feed_refuses_and_says_what_to_do(void) {
    char self[256], out[1024], err[512];
    snprintf(self, sizeof(self), "/tmp/qmifeed_none_XXXXXX");
    CHECK(mkdtemp(self) != NULL, "mkdtemp");
    out[0] = '\0';
    CHECK(qmifeed_resolve_command("auto", self, out, sizeof(out), err, sizeof(err)) == -1,
          "auto resolved with no feed: %s", out);
    CHECK(strstr(err, QMIFEED_AUTO_SCRIPT) && strstr(err, self)
          && strstr(err, "qmifeed=<command>"), "refusal lacks the fix: %s", err);
    rmdir(self);
    CHECK(qmifeed_resolve_command("auto", NULL, out, sizeof(out), err, sizeof(err)) == -1
          && strstr(err, "qmifeed=<command>"), "NULL self_dir: %s", err);
    CHECK(qmifeed_resolve_command("", "/tmp", out, sizeof(out), err, sizeof(err)) == -1,
          "empty value accepted");
}

static void test_auto_quotes_the_path_for_the_shell(void) {
    make_tree("capture_cell_at");
    /* Rename the tree to one with a space and a single quote in it. */
    char odd[512], cmd[1200], self[600], out[2048], err[256];
    snprintf(odd, sizeof(odd), "%s it's", tree);
    snprintf(cmd, sizeof(cmd), "mv '%s' \"%s\"", tree, odd);
    CHECK(system(cmd) == 0, "rename");
    snprintf(self, sizeof(self), "%s/capture_cell_at", odd);
    CHECK(qmifeed_resolve_command("auto", self, out, sizeof(out), err, sizeof(err)) == 0,
          "auto refused: %s", err);
    /* Let the shell itself parse it: `exec python3` swapped for printf. */
    const char *rest = out + strlen("exec python3 ");
    char sh[2400];
    snprintf(sh, sizeof(sh), "printf %%s %s", rest);
    FILE *f = popen(sh, "r");
    char got[1024] = "";
    if (f) {
        if (fgets(got, sizeof(got), f) == NULL)
            got[0] = '\0';
        pclose(f);
    }
    char want[1024];
    snprintf(want, sizeof(want), "%s/capture_cell_at/qmifeed/kismet_qmi_feed.py", odd);
    CHECK(strcmp(got, want) == 0, "shell read %s as [%s]", out, got);
    snprintf(cmd, sizeof(cmd), "rm -rf \"%s\"", odd);
    if (system(cmd) != 0)
        fprintf(stderr, "could not remove %s\n", odd);
}

/* An installed binary sits in $(BINDIR) with no qmifeed/ beside it;
 * `make install` puts the feed in the data dir, the last candidate. */
static void test_auto_falls_back_to_the_data_dir(void) {
    make_tree("usr/bin");
    char bin[512], data[512], out[1024], err[512], want[1024];
    snprintf(bin, sizeof(bin), "%s/usr/bin", tree);
    /* The data dir IS <tree>/capture_cell_at: it holds qmifeed/. */
    snprintf(data, sizeof(data), "%s/capture_cell_at", tree);
    snprintf(want, sizeof(want),
             "exec python3 '%s/capture_cell_at/qmifeed/kismet_qmi_feed.py' -d x", tree);
    /* The walk from usr/bin reaches <tree> in 2 steps and finds
     * capture_cell_at/qmifeed/ there, so move the binary out of range first. */
    char far[512];
    snprintf(far, sizeof(far), "%s/usr/bin/a/b/c/d", tree);
    char cmd[1200];
    snprintf(cmd, sizeof(cmd), "mkdir -p '%s'", far);
    CHECK(system(cmd) == 0, "mkdir far");
    out[0] = '\0';
    CHECK(qmifeed_resolve_command_in("auto", far, NULL, out, sizeof(out),
                                     err, sizeof(err)) == -1,
          "no data dir, out of walk range, still resolved: %s", out);
    CHECK(qmifeed_resolve_command_in("auto -d x", far, data, out, sizeof(out),
                                     err, sizeof(err)) == 0,
          "data dir not tried: %s", err);
    CHECK(strcmp(out, want) == 0, "data dir -> %s", out);
    /* A binary that cannot name its own directory still finds the data dir. */
    CHECK(qmifeed_resolve_command_in("auto -d x", NULL, data, out, sizeof(out),
                                     err, sizeof(err)) == 0 && strcmp(out, want) == 0,
          "NULL self_dir + data dir: %s / %s", out, err);
    /* The walk wins over the data dir: a build tree runs its own feed. */
    char other[512];
    snprintf(other, sizeof(other), "%s/usr", tree);
    snprintf(want, sizeof(want),
             "exec python3 '%s/capture_cell_at/qmifeed/kismet_qmi_feed.py'", tree);
    CHECK(qmifeed_resolve_command_in("auto", bin, other, out, sizeof(out),
                                     err, sizeof(err)) == 0 && strcmp(out, want) == 0,
          "walk did not win: %s / %s", out, err);
    /* A data dir without the feed: refused, naming the data dir too. */
    CHECK(qmifeed_resolve_command_in("auto", far, other, out, sizeof(out),
                                     err, sizeof(err)) == -1,
          "empty data dir resolved: %s", out);
    CHECK(strstr(err, other) && strstr(err, "qmifeed=<command>"),
          "refusal does not name the data dir: %s", err);
    rm_tree();
}

static void test_exe_dir_is_this_binarys_directory(void) {
    const char *d = qmifeed_exe_dir();
    CHECK(d != NULL, "qmifeed_exe_dir() is NULL");
    if (d) {
        char probe[1024];
        snprintf(probe, sizeof(probe), "%s/test_cellat_qmifeed", d);
        CHECK(access(probe, X_OK) == 0, "exe dir %s has no test_cellat_qmifeed", d);
    }
}

/* Not suid, nothing to drop -- the drop must be a no-op that succeeds,
 * or every ordinary (non-suid) install would refuse to start its feed. */
static void test_privdrop_is_a_noop_when_not_suid(void) {
    uid_t u = getuid(); gid_t g = getgid();
    if (geteuid() != u || getegid() != g) {
        printf("  SKIP privdrop no-op: this selftest itself runs with elevated ids\n");
        return;
    }
    pid_t pid = fork();
    if (pid == 0) {
        char err[160] = "";
        int r = diag_child_drop_privs(err, sizeof(err));
        _exit(r == 0 && getuid() == u && geteuid() == u && getgid() == g ? 0 : 1);
    }
    int st = 0;
    waitpid(pid, &st, 0);
    CHECK(WIFEXITED(st) && WEXITSTATUS(st) == 0,
          "a non-suid drop failed or changed an id (status %d)", st);
}

#ifdef __linux__
/* Read "Uid:" or "Gid:" from /proc/self/status as "real eff saved fs". */
static void read_ids(const char *key, char *out, size_t outsz) {
    out[0] = '\0';
    FILE *f = fopen("/proc/self/status", "r");
    if (f == NULL)
        return;
    char line[256];
    size_t kl = strlen(key);
    while (fgets(line, sizeof(line), f)) {
        if (strncmp(line, key, kl) != 0)
            continue;
        unsigned long a, b, c, d;
        if (sscanf(line + kl, "%lu %lu %lu %lu", &a, &b, &c, &d) == 4)
            snprintf(out, outsz, "%lu %lu %lu %lu", a, b, c, d);
        break;
    }
    fclose(f);
}

/* The real claim: under a suid-root install the qmifeed= command runs
 * as the CALLER. Simulated exactly: real ids `nobody`, effective and saved 0 --
 * the kernel's state after a suid-root exec by nobody. The child reports the
 * ids it really holds, read from /proc, not from what the code meant to do.
 * Root-only (only root can build that state); a sub-process, so this selftest's
 * own ids are never touched.
 *
 * This pins the OUTCOME, not the attribution. qmifeed= always runs through
 * `/bin/sh -c`, and bash and dash drop privileges by themselves when started
 * with euid != ruid (no -p) -- so on Debian this passes even with the drop in
 * qmifeed_start() deleted. The drop there is for a /bin/sh that does
 * not do that; test_privdrop_cannot_be_undone() below exercises the drop itself,
 * and celltools/tests/test_celldiag_suid_privdrop.py measures celldiag's
 * execv(python), where no shell stands in between. */
static void test_qmifeed_child_runs_as_the_caller_under_suid(void) {
    if (geteuid() != 0) {
        printf("  SKIP qmifeed suid drop: needs root to simulate a suid install\n");
        return;
    }
    const unsigned long NOBODY = 65534;
    pid_t pid = fork();
    if (pid == 0) {
        if (setresgid(NOBODY, 0, 0) != 0 || setresuid(NOBODY, 0, 0) != 0) {
            fprintf(stderr, "FAIL: could not build the suid state\n");
            _exit(2);
        }
        /* Positive control: the gauge must SEE the elevated state first, or a
         * pass below would be vacuous. */
        char uids[64], gids[64];
        read_ids("Uid:", uids, sizeof(uids));
        read_ids("Gid:", gids, sizeof(gids));
        if (strcmp(uids, "65534 0 0 0") != 0 || strcmp(gids, "65534 0 0 0") != 0) {
            fprintf(stderr, "FAIL: simulated suid state reads uid '%s' gid '%s'\n",
                    uids, gids);
            _exit(2);
        }
        qmifeed_t qf; sink_t s = {0}; char err[256];
        qmifeed_init(&qf);
        if (qmifeed_start(&qf,
                "u=$(grep '^Uid:' /proc/self/status | tr -s '\\t ' '  ' | cut -d' ' -f2-5); "
                "g=$(grep '^Gid:' /proc/self/status | tr -s '\\t ' '  ' | cut -d' ' -f2-5); "
                "echo \"{\\\"u\\\":\\\"$u\\\",\\\"g\\\":\\\"$g\\\"}\"",
                err, sizeof(err)) != 0) {
            fprintf(stderr, "FAIL: start: %s\n", err);
            _exit(1);
        }
        drain(&qf, &s);
        qmifeed_stop(&qf, 500);
        const char *want = "{\"u\":\"65534 65534 65534 65534\",\"g\":\"65534 65534 65534 65534\"}";
        if (s.n != 1 || strcmp(s.line[0], want) != 0) {
            fprintf(stderr, "FAIL: qmifeed child ids: got %d line(s), '%s', want '%s'\n",
                    s.n, s.n ? s.line[0] : "", want);
            _exit(1);
        }
        _exit(0);
    }
    int st = 0;
    waitpid(pid, &st, 0);
    CHECK(WIFEXITED(st) && WEXITSTATUS(st) == 0,
          "qmifeed child kept a suid install's elevated ids (status %d)", st);
}

/* And the drop is final: no id the suid bit granted can be taken back. */
static void test_privdrop_cannot_be_undone(void) {
    if (geteuid() != 0) {
        printf("  SKIP privdrop finality: needs root to simulate a suid install\n");
        return;
    }
    pid_t pid = fork();
    if (pid == 0) {
        if (setresgid(65534, 0, 0) != 0 || setresuid(65534, 0, 0) != 0)
            _exit(2);
        char err[160] = "";
        if (diag_child_drop_privs(err, sizeof(err)) != 0) {
            fprintf(stderr, "FAIL: drop: %s\n", err);
            _exit(1);
        }
        uid_t r, e, sv;
        gid_t gr, ge, gs;
        getresuid(&r, &e, &sv);
        getresgid(&gr, &ge, &gs);
        if (sv != 65534 || gs != 65534) {
            fprintf(stderr, "FAIL: saved ids kept: uid %ld gid %ld\n", (long) sv, (long) gs);
            _exit(1);
        }
        _exit(setuid(0) == 0 || seteuid(0) == 0 ? 1 : 0);
    }
    int st = 0;
    waitpid(pid, &st, 0);
    CHECK(WIFEXITED(st) && WEXITSTATUS(st) == 0,
          "after the drop, root could be regained (status %d)", st);
}
#endif

int main(void) {
    test_lines_forwarded_in_order();
    test_line_split_across_writes_is_reassembled();
    test_non_json_and_blank_lines_dropped();
    test_overlong_line_dropped_whole();
    test_overlong_tail_that_looks_like_json_is_not_forwarded();
    test_unterminated_final_line_delivered_at_eof();
    test_eof_flagged_with_no_output();
    test_eof_flagged_when_it_arrives_with_the_last_lines();
    test_empty_command_rejected();
    test_inherited_fds_closed_in_child();
    test_stop_kills_the_whole_group();
    test_stop_escalates_to_sigkill();
    test_child_starts_with_no_blocked_signals();
    test_line_imei_extracted_from_prov();
    test_imei_verdicts();
    test_child_env_carries_the_verified_imei();
    test_inherited_cellat_imei_is_replaced_not_duplicated();
    test_tagged_lines_are_routed_beside_observations();
    test_tagged_lines_without_a_callback_are_non_json();
    test_malformed_tags_are_counted_not_forwarded();
    test_a_raw_line_may_exceed_the_observation_cap();
    test_child_env_announces_the_line_protocol();
    test_a_command_is_used_verbatim();
    test_auto_finds_the_feed_beside_the_binary();
    test_auto_finds_the_feed_from_the_tree_root_and_below();
    test_auto_passes_its_arguments_to_the_feed();
    test_auto_without_a_feed_refuses_and_says_what_to_do();
    test_auto_quotes_the_path_for_the_shell();
    test_auto_falls_back_to_the_data_dir();
    test_exe_dir_is_this_binarys_directory();
    test_privdrop_is_a_noop_when_not_suid();
#ifdef __linux__
    test_qmifeed_child_runs_as_the_caller_under_suid();
    test_privdrop_cannot_be_undone();
#endif

    if (failures) {
        fprintf(stderr, "test_cellat_qmifeed: %d FAILED\n", failures);
        return 1;
    }
    printf("test_cellat_qmifeed: all passed\n");
    return 0;
}
