/* test_diag_rawlog.c - standalone unit tests for the rawlog sink core.
 *
 * Links only diag_rawlog.c (libc, no Kismet), so it runs off the capture
 * framework: `make check` in this directory. Covers the two pieces of the
 * rawlog= feature with real branching logic - path templating
 * (diag_rawlog_resolve) and the whole-buffer tee write (diag_rawlog_write) -
 * plus a byte-fidelity round-trip that is the property rawlog= exists for.
 */

#include "diag_rawlog.h"

#include <errno.h>
#include <fcntl.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
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

/* A fixed, known instant so %t is deterministic: 2026-07-17T18:19:20Z. */
static time_t fixed_now(void) {
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

static void test_resolve_literal(void) {
    char out[256];
    int r = diag_rawlog_resolve("/tmp/celldiag.hdlc", "123456789012345",
                                "RM520N-GL", fixed_now(), out, sizeof(out));
    CHECK(r == 0, "literal resolve returned %d", r);
    CHECK(strcmp(out, "/tmp/celldiag.hdlc") == 0, "literal got '%s'", out);
}

static void test_resolve_tokens(void) {
    char out[256];
    int r = diag_rawlog_resolve("/cap/%i-%t.hdlc", "123456789012345",
                                "RM520N-GL", fixed_now(), out, sizeof(out));
    CHECK(r == 0, "token resolve returned %d", r);
    CHECK(strcmp(out, "/cap/123456789012345-20260717T181920Z.hdlc") == 0,
          "tokens got '%s'", out);
}

static void test_resolve_model_sanitized(void) {
    char out[256];
    /* spaces and slash in a firmware string must not leak into the path */
    int r = diag_rawlog_resolve("/cap/%m.hdlc", "123456789012345",
                                "RM520N-GL R03A04 M/N", fixed_now(),
                                out, sizeof(out));
    CHECK(r == 0, "model resolve returned %d", r);
    CHECK(strcmp(out, "/cap/RM520N-GL_R03A04_M_N.hdlc") == 0,
          "sanitized model got '%s'", out);
}

static void test_resolve_imei_sanitized(void) {
    char out[256];
    /* A garbled/hostile IMEI must not inject a path separator. The resolver
     * sanitizes the model string for exactly this reason and cannot trust its
     * caller, so the IMEI (also used as a path component) gets the same guard. */
    int r = diag_rawlog_resolve("/cap/%i.hdlc", "12/34..56", "m",
                                fixed_now(), out, sizeof(out));
    CHECK(r == 0, "imei resolve returned %d", r);
    CHECK(strcmp(out, "/cap/12_34..56.hdlc") == 0, "sanitized imei got '%s'", out);
    /* No '/' may appear past the literal "/cap/" prefix (index 5 onward). */
    CHECK(strchr(out + 5, '/') == NULL, "no injected separator: '%s'", out);
}

static void test_resolve_dir_imei_sanitized(void) {
    char out[256];
    /* The dir-mode auto-filename also embeds the IMEI (celldiag-<imei>-<ts>). */
    int r = diag_rawlog_resolve("/cap/", "aa/bb", "m", fixed_now(),
                                out, sizeof(out));
    CHECK(r == 0, "dir imei resolve returned %d", r);
    CHECK(strcmp(out, "/cap/celldiag-aa_bb-20260717T181920Z.hdlc") == 0,
          "dir sanitized imei got '%s'", out);
}

static void test_resolve_dotdot_component_neutralized(void) {
    char out[256];
    /* A wholly-dot IMEI/model (".." = parent dir) used as a directory component
     * via %i/ or %m/ would climb out of the intended tree even though '/' is
     * blocked - the '/' comes from the operator's spec, not the token. Blocking
     * '/' alone (test_resolve_imei_sanitized) does not stop this; the resolver
     * must collapse an all-dots component to '_'. */
    int r = diag_rawlog_resolve("/cap/%i/run.hdlc", "..", "m",
                                fixed_now(), out, sizeof(out));
    CHECK(r == 0, "dotdot imei resolve returned %d", r);
    CHECK(strcmp(out, "/cap/_/run.hdlc") == 0, "dotdot imei got '%s'", out);
    /* Same for the model token. */
    r = diag_rawlog_resolve("/cap/%m/run.hdlc", "123456789012345", "..",
                            fixed_now(), out, sizeof(out));
    CHECK(r == 0, "dotdot model resolve returned %d", r);
    CHECK(strcmp(out, "/cap/_/run.hdlc") == 0, "dotdot model got '%s'", out);
    /* A single "." (self dir) collapses too. */
    r = diag_rawlog_resolve("/cap/%i/run.hdlc", ".", "m",
                            fixed_now(), out, sizeof(out));
    CHECK(r == 0, "dot imei resolve returned %d", r);
    CHECK(strcmp(out, "/cap/_/run.hdlc") == 0, "dot imei got '%s'", out);
    /* But a name that merely CONTAINS dots (real firmware "A0.300", or "a..b")
     * is not all-dots and must pass through unchanged. */
    r = diag_rawlog_resolve("/cap/%m.hdlc", "123456789012345", "A0.300",
                            fixed_now(), out, sizeof(out));
    CHECK(r == 0, "dotted-model resolve returned %d", r);
    CHECK(strcmp(out, "/cap/A0.300.hdlc") == 0, "dotted model got '%s'", out);
}

static void test_resolve_percent_literal(void) {
    char out[256];
    int r = diag_rawlog_resolve("/cap/100%%.hdlc", "123456789012345",
                                "m", fixed_now(), out, sizeof(out));
    CHECK(r == 0, "%%%% resolve returned %d", r);
    CHECK(strcmp(out, "/cap/100%.hdlc") == 0, "%%%% got '%s'", out);
}

static void test_resolve_trailing_slash_dir(void) {
    char out[256];
    int r = diag_rawlog_resolve("/cap/", "123456789012345", "m",
                                fixed_now(), out, sizeof(out));
    CHECK(r == 0, "dir resolve returned %d", r);
    CHECK(strcmp(out, "/cap/celldiag-123456789012345-20260717T181920Z.hdlc") == 0,
          "trailing-slash dir got '%s'", out);
}

static void test_resolve_existing_dir(void) {
    char tmpl[] = "/tmp/celldiag_rawlog_XXXXXX";
    char *dir = mkdtemp(tmpl);
    CHECK(dir != NULL, "mkdtemp failed");
    if (!dir)
        return;

    char out[256];
    int r = diag_rawlog_resolve(dir, "123456789012345", "m",
                                fixed_now(), out, sizeof(out));
    CHECK(r == 0, "existing-dir resolve returned %d", r);

    char expect[256];
    snprintf(expect, sizeof(expect),
             "%s/celldiag-123456789012345-20260717T181920Z.hdlc", dir);
    CHECK(strcmp(out, expect) == 0, "existing dir got '%s' want '%s'", out, expect);

    rmdir(dir);
}

static void test_resolve_overflow(void) {
    char out[16];
    int r = diag_rawlog_resolve("/some/long/path/that/does/not/fit.hdlc",
                                "1", "m", fixed_now(), out, sizeof(out));
    CHECK(r == -1, "overflow should return -1, got %d", r);
}

/* Dir-mode has its OWN overflow guard (auto-filename append), distinct from the
 * file-mode path in test_resolve_overflow. A trailing-slash dir whose composed
 * celldiag-<imei>-<ts>.hdlc won't fit must also return -1, not truncate. */
static void test_resolve_dir_overflow(void) {
    char out[20]; /* "/cap/" + celldiag-… far exceeds 20 */
    int r = diag_rawlog_resolve("/cap/", "123456789012345", "m",
                                fixed_now(), out, sizeof(out));
    CHECK(r == -1, "dir-mode overflow should return -1, got %d", r);
}

/* A NULL model defaults to the literal "modem" (never an empty component). */
static void test_resolve_null_model_default(void) {
    char out[256];
    int r = diag_rawlog_resolve("/cap/%m.hdlc", "123456789012345", NULL,
                                fixed_now(), out, sizeof(out));
    CHECK(r == 0, "null-model resolve returned %d", r);
    CHECK(strcmp(out, "/cap/modem.hdlc") == 0, "null model got '%s'", out);
}

/* expand_tokens: an unknown token (%z) emits the '%' literally and processes the
 * following char normally; a trailing lone '%' is emitted literally. */
static void test_resolve_unknown_and_trailing_token(void) {
    char out[256];
    int r = diag_rawlog_resolve("/cap/%z.hdlc", "123456789012345", "m",
                                fixed_now(), out, sizeof(out));
    CHECK(r == 0, "unknown-token resolve returned %d", r);
    CHECK(strcmp(out, "/cap/%z.hdlc") == 0, "unknown token got '%s'", out);
    /* Trailing '%' with nothing after it. */
    r = diag_rawlog_resolve("/cap/x%", "123456789012345", "m",
                            fixed_now(), out, sizeof(out));
    CHECK(r == 0, "trailing-%% resolve returned %d", r);
    CHECK(strcmp(out, "/cap/x%") == 0, "trailing %% got '%s'", out);
}

/* Byte-fidelity round trip: the tee write must reproduce the exact input bytes,
 * chunked arbitrarily (the capture loop tees per read()). This is the property
 * that makes a rawlog file replay identically to what was decoded. */
static void test_write_roundtrip(void) {
    char tmpl[] = "/tmp/celldiag_rawlog_out_XXXXXX";
    int fd = mkstemp(tmpl);
    CHECK(fd >= 0, "mkstemp failed");
    if (fd < 0)
        return;

    /* A stand-in raw-HDLC-ish stream with embedded 0x7e frame delims + NULs. */
    static const unsigned char stream[] = {
        0x7e, 0x10, 0x00, 0x00, 0x7e, 0x99, 0x00, 0x46,
        0x00, 0x26, 0xbe, 0xcc, 0x09, 0x97, 0x0f, 0x00,
        0x7e, 0xff, 0x00, 0x7e,
    };
    /* Tee in three uneven chunks, mimicking successive read() sizes. */
    CHECK(diag_rawlog_write(fd, stream, 5) == 0, "write chunk 1");
    CHECK(diag_rawlog_write(fd, stream + 5, 9) == 0, "write chunk 2");
    CHECK(diag_rawlog_write(fd, stream + 14, sizeof(stream) - 14) == 0,
          "write chunk 3");
    close(fd);

    int rfd = open(tmpl, O_RDONLY);
    CHECK(rfd >= 0, "reopen failed");
    unsigned char back[64];
    ssize_t n = read(rfd, back, sizeof(back));
    close(rfd);
    CHECK(n == (ssize_t)sizeof(stream), "size back=%zd want=%zu",
          n, sizeof(stream));
    CHECK(n > 0 && memcmp(back, stream, sizeof(stream)) == 0,
          "round-trip bytes differ");

    unlink(tmpl);
}

/* ---- one tee per capture session, never truncated ----------------------- */

static char *mk_tmpdir(void) {
    static char dir[64];
    snprintf(dir, sizeof(dir), "/tmp/celldiag_rawlog_sess_XXXXXX");
    return mkdtemp(dir);
}

static void put_file(const char *path, const char *bytes) {
    int fd = open(path, O_WRONLY | O_CREAT | O_TRUNC, 0644);
    if (fd >= 0) {
        if (bytes[0])
            (void)!write(fd, bytes, strlen(bytes));
        close(fd);
    }
}

static long file_size(const char *path) {
    struct stat st;
    return stat(path, &st) == 0 ? (long)st.st_size : -1;
}

static void rm_tree(const char *dir) {
    char cmd[256];
    snprintf(cmd, sizeof(cmd), "rm -rf '%s'", dir);
    (void)!system(cmd);
}

/* A path that does not exist yet is opened as given -- the first open of a
 * source is unaffected by session diversion. */
static void test_session_fresh_path_as_given(void) {
    char *d = mk_tmpdir(), path[256], out[256];
    CHECK(d != NULL, "mkdtemp");
    if (!d) return;
    snprintf(path, sizeof(path), "%s/cap.hdlc", d);
    int div = -1;
    int fd = diag_rawlog_open_session(path, fixed_now(), out, sizeof(out), &div);
    CHECK(fd >= 0, "fresh open failed");
    CHECK(div == 0, "fresh path diverted");
    CHECK(strcmp(out, path) == 0, "fresh out=%s want=%s", out, path);
    if (fd >= 0) close(fd);
    rm_tree(d);
}

/* An EMPTY existing file holds no session's bytes: reuse it, no sibling. */
static void test_session_empty_file_reused(void) {
    char *d = mk_tmpdir(), path[256], out[256];
    if (!d) return;
    snprintf(path, sizeof(path), "%s/cap.hdlc", d);
    put_file(path, "");
    int div = -1;
    int fd = diag_rawlog_open_session(path, fixed_now(), out, sizeof(out), &div);
    CHECK(fd >= 0 && div == 0 && strcmp(out, path) == 0,
          "empty file: fd=%d div=%d out=%s", fd, div, out);
    if (fd >= 0) close(fd);
    rm_tree(d);
}

/* THE defect: a non-empty file is an earlier session's tee. It must survive
 * byte for byte, and this session gets a stamped sibling. */
static void test_session_nonempty_diverts_and_keeps_bytes(void) {
    char *d = mk_tmpdir(), path[256], out[256], want[256];
    if (!d) return;
    snprintf(path, sizeof(path), "%s/cap.hdlc", d);
    put_file(path, "SESSION-ONE");
    int div = -1;
    int fd = diag_rawlog_open_session(path, fixed_now(), out, sizeof(out), &div);
    CHECK(fd >= 0, "divert open failed");
    CHECK(div == 1, "non-empty file not diverted");
    snprintf(want, sizeof(want), "%s/cap-20260717T181920Z.hdlc", d);
    CHECK(strcmp(out, want) == 0, "divert out=%s want=%s", out, want);
    if (fd >= 0) {
        CHECK(diag_rawlog_write(fd, (const uint8_t *)"TWO", 3) == 0, "write");
        close(fd);
    }
    CHECK(file_size(path) == 11, "earlier session shrank to %ld", file_size(path));
    CHECK(file_size(want) == 3, "new session size %ld", file_size(want));
    rm_tree(d);
}

/* Two reopens inside one second (a restart-to-apply toggle can) must still
 * land in two files: the second collides on the stamp and counts. */
static void test_session_same_second_counts(void) {
    char *d = mk_tmpdir(), path[256], out[256], want[256];
    if (!d) return;
    snprintf(path, sizeof(path), "%s/cap.hdlc", d);
    put_file(path, "ONE");
    snprintf(want, sizeof(want), "%s/cap-20260717T181920Z.hdlc", d);
    put_file(want, "TWO");
    int div = -1;
    int fd = diag_rawlog_open_session(path, fixed_now(), out, sizeof(out), &div);
    snprintf(want, sizeof(want), "%s/cap-20260717T181920Z-2.hdlc", d);
    CHECK(fd >= 0 && div == 1 && strcmp(out, want) == 0,
          "same-second: fd=%d div=%d out=%s want=%s", fd, div, out, want);
    if (fd >= 0) close(fd);
    rm_tree(d);
}

/* A %t spec already carries this second's stamp in its stem: count rather
 * than stamp it twice. */
static void test_session_stamped_stem_counts(void) {
    char *d = mk_tmpdir(), path[256], out[256], want[256];
    if (!d) return;
    snprintf(path, sizeof(path), "%s/cap-20260717T181920Z.hdlc", d);
    put_file(path, "ONE");
    int div = -1;
    int fd = diag_rawlog_open_session(path, fixed_now(), out, sizeof(out), &div);
    snprintf(want, sizeof(want), "%s/cap-20260717T181920Z-2.hdlc", d);
    CHECK(fd >= 0 && div == 1 && strcmp(out, want) == 0,
          "stamped stem: out=%s want=%s", out, want);
    if (fd >= 0) close(fd);
    rm_tree(d);
}

/* The extension is the LAST component's: a dotted directory with a dotless
 * file name gets the stamp at the end, not inside the directory name. */
static void test_session_ext_from_basename_only(void) {
    char *d = mk_tmpdir(), dir[128], path[256], out[256], want[256];
    if (!d) return;
    snprintf(dir, sizeof(dir), "%.100s/run.v2", d);
    mkdir(dir, 0755);
    snprintf(path, sizeof(path), "%s/capture", dir);
    put_file(path, "ONE");
    int div = -1;
    int fd = diag_rawlog_open_session(path, fixed_now(), out, sizeof(out), &div);
    snprintf(want, sizeof(want), "%s/capture-20260717T181920Z", dir);
    CHECK(fd >= 0 && strcmp(out, want) == 0, "dotted dir: out=%s want=%s",
          out, want);
    if (fd >= 0) close(fd);
    rm_tree(d);
}

/* Not a regular file (a tee to /dev/null, a FIFO): never diverted. */
static void test_session_char_device_as_given(void) {
    char out[64];
    int div = -1;
    int fd = diag_rawlog_open_session("/dev/null", fixed_now(), out, sizeof(out),
                                      &div);
    CHECK(fd >= 0 && div == 0 && strcmp(out, "/dev/null") == 0,
          "/dev/null: fd=%d div=%d out=%s", fd, div, out);
    if (fd >= 0) close(fd);
}

/* A diverted name that no longer fits `out` is an error, not a truncated
 * path silently opened. */
static void test_session_divert_overflow(void) {
    char *d = mk_tmpdir(), path[256], out[64];
    if (!d) return;
    snprintf(path, sizeof(path), "%s/cap.hdlc", d);
    put_file(path, "ONE");
    size_t need = strlen(path) + 1;
    int div = -1;
    /* room for the path itself, not for "-<16-char stamp>" */
    CHECK(need <= sizeof(out), "test setup: tmpdir too long");
    int fd = diag_rawlog_open_session(path, fixed_now(), out, need, &div);
    CHECK(fd < 0 && errno == ENAMETOOLONG, "overflow: fd=%d errno=%d", fd, errno);
    if (fd >= 0) close(fd);
    CHECK(file_size(path) == 3, "overflow touched the original");
    rm_tree(d);
}

int main(void) {
    test_resolve_literal();
    test_resolve_tokens();
    test_resolve_model_sanitized();
    test_resolve_imei_sanitized();
    test_resolve_dir_imei_sanitized();
    test_resolve_dotdot_component_neutralized();
    test_resolve_percent_literal();
    test_resolve_trailing_slash_dir();
    test_resolve_existing_dir();
    test_resolve_overflow();
    test_resolve_dir_overflow();
    test_resolve_null_model_default();
    test_resolve_unknown_and_trailing_token();
    test_write_roundtrip();
    test_session_fresh_path_as_given();
    test_session_empty_file_reused();
    test_session_nonempty_diverts_and_keeps_bytes();
    test_session_same_second_counts();
    test_session_stamped_stem_counts();
    test_session_ext_from_basename_only();
    test_session_char_device_as_given();
    test_session_divert_overflow();

    if (failures == 0) {
        printf("PASS: all diag_rawlog tests\n");
        return 0;
    }
    fprintf(stderr, "FAILED: %d diag_rawlog test check(s)\n", failures);
    return 1;
}
