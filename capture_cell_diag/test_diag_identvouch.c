/* test_diag_identvouch.c - standalone tests for the holder's identity vouch.
 *
 * Links diag_identvouch.c + diag_modemident.c (libc, no Kismet): `make check`
 * here, and the cellat directory's `make check` runs it too, because both
 * helpers link it.
 *
 * The "port" is a regular file in a private temp directory: every rule the
 * module enforces is about the node's identity (rdev / inode / ctime) and the
 * writer's liveness, and a regular file exercises all of them without a modem.
 */

#include "diag_identvouch.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <sys/wait.h>
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

static char g_root[256];
static char g_port[512];
static char g_vdir[512];

/* An RM500Q-AE-shaped identity (real make/model/build spellings) under a
 * Luhn-INVALID fake IMEI: a real unit's IMEI must never appear in a test. */
static modemident_t rm500q(void) {
    modemident_t id;
    modemident_clear(&id);
    snprintf(id.make, sizeof(id.make), "Quectel");
    snprintf(id.model, sizeof(id.model), "RM500Q-AE");
    snprintf(id.firmware, sizeof(id.firmware), "RM500QAEAAR11A03M4G");
    snprintf(id.imei, sizeof(id.imei), "351234567890123");
    return id;
}

static void make_port(void) {
    FILE *f = fopen(g_port, "w");
    if (f) { fputs("tty stand-in\n", f); fclose(f); }
}

static void record_file(char *out, size_t out_sz) {
    char name[512];
    identvouch_filename(g_port, name, sizeof(name));
    snprintf(out, out_sz, "%s/%s", g_vdir, name);
}

static void test_filename(void) {
    char out[64];
    CHECK(identvouch_filename("/dev/ttyUSB8", out, sizeof(out)) == 0 &&
          strcmp(out, "_dev_ttyUSB8.vouch") == 0, "filename: %s", out);
    CHECK(identvouch_filename("/dev/mhi_DUN", out, sizeof(out)) == 0 &&
          strcmp(out, "_dev_mhi_DUN.vouch") == 0, "mhi filename: %s", out);
    char tiny[8];
    CHECK(identvouch_filename("/dev/ttyUSB8", tiny, sizeof(tiny)) == -1,
          "a short buffer is refused, not truncated into another port's name");
}

static void test_round_trip(void) {
    modemident_t id = rm500q(), got;
    pid_t who = 0;
    CHECK(identvouch_publish(g_port, &id) == 0, "publish");
    CHECK(identvouch_lookup(g_port, &got, &who) == 1, "lookup of a fresh vouch");
    CHECK(strcmp(got.imei, id.imei) == 0, "imei %s", got.imei);
    CHECK(strcmp(got.firmware, id.firmware) == 0, "firmware %s", got.firmware);
    CHECK(strcmp(got.make, "Quectel") == 0 && strcmp(got.model, "RM500Q-AE") == 0,
          "make/model %s/%s", got.make, got.model);
    CHECK(who == getpid(), "writer pid %ld", (long) who);

    char other[600];
    snprintf(other, sizeof(other), "%s/other-port", g_root);
    CHECK(identvouch_lookup(other, &got, NULL) == 0 && got.imei[0] == '\0',
          "no record for another port, and the output is cleared");
}

static void test_reenumerated_node_is_refused(void) {
    modemident_t id = rm500q(), got;
    CHECK(identvouch_publish(g_port, &id) == 0, "publish");
    /* A USB re-enumeration re-creates the node: same NAME, new instance. The
     * old record must not vouch for whatever modem now answers to the name.
     * Holding the old file open keeps its inode number from being reused. */
    FILE *keep = fopen(g_port, "r");
    unlink(g_port);
    make_port();
    CHECK(identvouch_lookup(g_port, &got, NULL) == 0,
          "a record for the previous node instance is refused");
    if (keep) fclose(keep);
}

static void test_dead_writer_is_refused(void) {
    modemident_t id = rm500q(), got;
    pid_t child = fork();
    if (child == 0) {
        _exit(identvouch_publish(g_port, &id) == 0 ? 0 : 1);
    }
    int st = 0;
    waitpid(child, &st, 0);
    CHECK(WIFEXITED(st) && WEXITSTATUS(st) == 0, "child published");
    CHECK(identvouch_lookup(g_port, &got, NULL) == 0,
          "a record whose writer has exited is refused");
}

static void test_withdraw_is_own_record_only(void) {
    modemident_t id = rm500q(), got;
    char rec[1100];
    record_file(rec, sizeof(rec));

    CHECK(identvouch_publish(g_port, &id) == 0, "publish");
    identvouch_withdraw(g_port);
    CHECK(access(rec, F_OK) != 0, "withdraw removes this process's record");

    /* A newer holder's record (another pid) must survive our withdraw. */
    pid_t child = fork();
    if (child == 0) {
        _exit(identvouch_publish(g_port, &id) == 0 ? 0 : 1);
    }
    waitpid(child, NULL, 0);
    identvouch_withdraw(g_port);
    CHECK(access(rec, F_OK) == 0, "withdraw leaves another writer's record");
    unlink(rec);
    (void) got;
}

static void test_bad_input_is_refused(void) {
    modemident_t id = rm500q(), got;
    snprintf(id.imei, sizeof(id.imei), "35123456789012");   /* 14 digits */
    CHECK(identvouch_publish(g_port, &id) == -1, "a short IMEI is not published");
    snprintf(id.imei, sizeof(id.imei), "35123456789012X");
    CHECK(identvouch_publish(g_port, &id) == -1, "a non-digit IMEI is not published");

    char missing[600];
    snprintf(missing, sizeof(missing), "%s/no-such-port", g_root);
    id = rm500q();
    CHECK(identvouch_publish(missing, &id) == -1, "a missing port is not published");

    /* A hand-edited record naming a DIFFERENT port under this port's file. */
    char rec[1100];
    record_file(rec, sizeof(rec));
    struct stat pst;
    stat(g_port, &pst);
    FILE *f = fopen(rec, "w");
    if (f) {
        fprintf(f, "v=1\nport=/dev/ttyUSB99\nrdev=%llu\nino=%llu\nctime=%lld\n"
                   "pid=%ld\nimei=351234567890123\n",
                (unsigned long long) pst.st_rdev, (unsigned long long) pst.st_ino,
                (long long) pst.st_ctime, (long) getpid());
        fclose(f);
    }
    CHECK(identvouch_lookup(g_port, &got, NULL) == 0,
          "a record naming another port is refused");

    f = fopen(rec, "w");
    if (f) {
        fprintf(f, "v=2\nport=%s\nrdev=%llu\nino=%llu\nctime=%lld\npid=%ld\n"
                   "imei=351234567890123\n", g_port,
                (unsigned long long) pst.st_rdev, (unsigned long long) pst.st_ino,
                (long long) pst.st_ctime, (long) getpid());
        fclose(f);
    }
    CHECK(identvouch_lookup(g_port, &got, NULL) == 0,
          "an unknown schema is refused");
    unlink(rec);
}

static void test_unsafe_directory_is_refused(void) {
    char open_dir[600];
    snprintf(open_dir, sizeof(open_dir), "%s/group-readable", g_root);
    mkdir(open_dir, 0700);
    chmod(open_dir, 0750);
    setenv(IDENTVOUCH_ENV_DIR, open_dir, 1);
    CHECK(identvouch_dir() == NULL, "a directory others can read is refused");

    char link[600];
    snprintf(link, sizeof(link), "%s/a-symlink", g_root);
    CHECK(symlink(g_vdir, link) == 0, "symlink setup");
    setenv(IDENTVOUCH_ENV_DIR, link, 1);
    CHECK(identvouch_dir() == NULL, "a symlink in place of the directory is refused");

    modemident_t id = rm500q();
    CHECK(identvouch_publish(g_port, &id) == -1,
          "nothing is published without a safe directory");
    setenv(IDENTVOUCH_ENV_DIR, g_vdir, 1);
}

int main(void) {
    snprintf(g_root, sizeof(g_root), "/tmp/test_identvouch.XXXXXX");
    if (mkdtemp(g_root) == NULL) {
        perror("mkdtemp");
        return 2;
    }
    snprintf(g_port, sizeof(g_port), "%s/ttyFAKE0", g_root);
    snprintf(g_vdir, sizeof(g_vdir), "%s/vouch", g_root);
    make_port();
    setenv(IDENTVOUCH_ENV_DIR, g_vdir, 1);

    test_filename();
    test_round_trip();
    test_reenumerated_node_is_refused();
    test_dead_writer_is_refused();
    test_withdraw_is_own_record_only();
    test_bad_input_is_refused();
    test_unsafe_directory_is_refused();

    char cmd[600];
    snprintf(cmd, sizeof(cmd), "rm -rf '%s'", g_root);
    if (system(cmd) != 0)
        fprintf(stderr, "note: could not clean %s\n", g_root);

    if (failures) {
        fprintf(stderr, "test_diag_identvouch: %d failure(s)\n", failures);
        return 1;
    }
    printf("test_diag_identvouch: all checks passed\n");
    return 0;
}
