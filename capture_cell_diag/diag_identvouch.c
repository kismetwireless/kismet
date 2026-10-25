/* diag_identvouch.c - a port's holder vouches for the modem identity it read.
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 *
 * See diag_identvouch.h for the contract and why it exists.
 */
#include "diag_identvouch.h"

#include <ctype.h>
#include <errno.h>
#include <fcntl.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <unistd.h>

#ifndef O_CLOEXEC
#define O_CLOEXEC 0
#endif
#ifndef O_NOFOLLOW
#define O_NOFOLLOW 0
#endif

#define IDENTVOUCH_REC_MAX 2048

static int imei_ok(const char *s) {
    if (s == NULL)
        return 0;
    for (int i = 0; i < 15; i++)
        if (!isdigit((unsigned char) s[i]))
            return 0;
    return s[15] == '\0';
}

static int is_dir(const char *p) {
    struct stat st;
    return stat(p, &st) == 0 && S_ISDIR(st.st_mode);
}

const char *identvouch_dir(void) {
    static char dir[512];
    const char *env = getenv(IDENTVOUCH_ENV_DIR);
    uid_t eu = geteuid();

    if (env != NULL && *env)
        snprintf(dir, sizeof(dir), "%s", env);
    else if (eu == 0 && is_dir("/run"))
        snprintf(dir, sizeof(dir), "/run/kismet-cell");
    else
        snprintf(dir, sizeof(dir), "/tmp/kismet-cell-%lu", (unsigned long) eu);

    if (mkdir(dir, 0700) != 0 && errno != EEXIST)
        return NULL;

    /* lstat, not stat: a symlink planted where the directory should be is
     * refused, not followed. A record here steers which device a capture
     * opens, so only this euid may be able to write one. */
    struct stat st;
    if (lstat(dir, &st) != 0 || !S_ISDIR(st.st_mode) || st.st_uid != eu ||
        (st.st_mode & 077) != 0)
        return NULL;
    return dir;
}

int identvouch_filename(const char *port, char *out, size_t out_sz) {
    if (port == NULL || out == NULL || out_sz == 0)
        return -1;
    size_t n = 0;
    for (const char *p = port; *p; p++) {
        if (n + 1 >= out_sz)
            return -1;
        out[n++] = (*p == '/') ? '_' : *p;
    }
    static const char ext[] = ".vouch";
    if (n + sizeof(ext) > out_sz)
        return -1;
    memcpy(out + n, ext, sizeof(ext));
    return 0;
}

static int record_path(const char *port, char *out, size_t out_sz) {
    const char *dir = identvouch_dir();
    char name[512];
    if (dir == NULL || identvouch_filename(port, name, sizeof(name)) != 0)
        return -1;
    int w = snprintf(out, out_sz, "%s/%s", dir, name);
    return (w < 0 || (size_t) w >= out_sz) ? -1 : 0;
}

/* One value, with anything that would break the line format flattened. AT
 * values are single lines already; this is defence, not normalisation. */
static void put_value(char *dst, size_t dst_sz, size_t *off, const char *key,
                      const char *val) {
    if (*off >= dst_sz)
        return;
    int w = snprintf(dst + *off, dst_sz - *off, "%s=", key);
    if (w < 0 || (size_t) w >= dst_sz - *off) {
        *off = dst_sz;
        return;
    }
    *off += (size_t) w;
    for (const char *p = val ? val : ""; *p && *off + 1 < dst_sz; p++)
        dst[(*off)++] = (*p == '\n' || *p == '\r') ? ' ' : *p;
    if (*off + 1 < dst_sz)
        dst[(*off)++] = '\n';
    else
        *off = dst_sz;
    if (*off < dst_sz)
        dst[*off] = '\0';
}

int identvouch_publish(const char *port, const modemident_t *id) {
    if (port == NULL || !*port || id == NULL || !imei_ok(id->imei))
        return -1;

    struct stat pst;
    if (stat(port, &pst) != 0)
        return -1;

    char path[1024], tmp[1100];
    if (record_path(port, path, sizeof(path)) != 0)
        return -1;
    snprintf(tmp, sizeof(tmp), "%s.%ld.tmp", path, (long) getpid());

    char rec[IDENTVOUCH_REC_MAX];
    int w = snprintf(rec, sizeof(rec),
                     "v=%d\nport=%s\nrdev=%llu\nino=%llu\nctime=%lld\npid=%ld\n",
                     IDENTVOUCH_SCHEMA, port,
                     (unsigned long long) pst.st_rdev,
                     (unsigned long long) pst.st_ino,
                     (long long) pst.st_ctime, (long) getpid());
    if (w < 0 || (size_t) w >= sizeof(rec))
        return -1;
    size_t off = (size_t) w;
    put_value(rec, sizeof(rec), &off, "imei", id->imei);
    put_value(rec, sizeof(rec), &off, "make", id->make);
    put_value(rec, sizeof(rec), &off, "model", id->model);
    put_value(rec, sizeof(rec), &off, "firmware", id->firmware);
    if (off >= sizeof(rec))
        return -1;

    /* O_CLOEXEC: cellat forks a QMI feeder, which must not inherit this. */
    int fd = open(tmp, O_WRONLY | O_CREAT | O_TRUNC | O_NOFOLLOW | O_CLOEXEC,
                  0600);
    if (fd < 0)
        return -1;
    size_t done = 0;
    while (done < off) {
        ssize_t n = write(fd, rec + done, off - done);
        if (n < 0) {
            if (errno == EINTR)
                continue;
            close(fd);
            unlink(tmp);
            return -1;
        }
        done += (size_t) n;
    }
    if (close(fd) != 0 || rename(tmp, path) != 0) {
        unlink(tmp);
        return -1;
    }
    return 0;
}

typedef struct {
    int v;
    char port[512];
    unsigned long long rdev, ino;
    long long ctime;
    long pid;
    modemident_t id;
} vouch_rec_t;

static void copy_field(char *dst, size_t dst_sz, const char *src) {
    snprintf(dst, dst_sz, "%s", src);
}

/* Read and parse the record for `port`. 0 on a well-formed read, -1 otherwise. */
static int read_record(const char *port, vouch_rec_t *r) {
    memset(r, 0, sizeof(*r));
    char path[1024];
    if (record_path(port, path, sizeof(path)) != 0)
        return -1;
    int fd = open(path, O_RDONLY | O_NOFOLLOW | O_CLOEXEC);
    if (fd < 0)
        return -1;
    struct stat fst;
    if (fstat(fd, &fst) != 0 || !S_ISREG(fst.st_mode) || fst.st_uid != geteuid()) {
        close(fd);
        return -1;
    }
    char buf[IDENTVOUCH_REC_MAX + 1];
    size_t used = 0;
    ssize_t n;
    while (used < IDENTVOUCH_REC_MAX &&
           (n = read(fd, buf + used, IDENTVOUCH_REC_MAX - used)) != 0) {
        if (n < 0) {
            if (errno == EINTR)
                continue;
            close(fd);
            return -1;
        }
        used += (size_t) n;
    }
    close(fd);
    buf[used] = '\0';

    char *save = NULL;
    for (char *line = strtok_r(buf, "\n", &save); line != NULL;
         line = strtok_r(NULL, "\n", &save)) {
        char *eq = strchr(line, '=');
        if (eq == NULL)
            continue;
        *eq = '\0';
        const char *k = line, *v = eq + 1;
        if (strcmp(k, "v") == 0)
            r->v = atoi(v);
        else if (strcmp(k, "port") == 0)
            copy_field(r->port, sizeof(r->port), v);
        else if (strcmp(k, "rdev") == 0)
            r->rdev = strtoull(v, NULL, 10);
        else if (strcmp(k, "ino") == 0)
            r->ino = strtoull(v, NULL, 10);
        else if (strcmp(k, "ctime") == 0)
            r->ctime = strtoll(v, NULL, 10);
        else if (strcmp(k, "pid") == 0)
            r->pid = strtol(v, NULL, 10);
        else if (strcmp(k, "imei") == 0)
            copy_field(r->id.imei, sizeof(r->id.imei), v);
        else if (strcmp(k, "make") == 0)
            copy_field(r->id.make, sizeof(r->id.make), v);
        else if (strcmp(k, "model") == 0)
            copy_field(r->id.model, sizeof(r->id.model), v);
        else if (strcmp(k, "firmware") == 0)
            copy_field(r->id.firmware, sizeof(r->id.firmware), v);
    }
    return 0;
}

void identvouch_withdraw(const char *port) {
    if (port == NULL || !*port)
        return;
    vouch_rec_t r;
    if (read_record(port, &r) != 0 || r.pid != (long) getpid())
        return;
    char path[1024];
    if (record_path(port, path, sizeof(path)) == 0)
        unlink(path);
}

int identvouch_lookup(const char *port, modemident_t *id_out, pid_t *writer_pid) {
    if (id_out != NULL)
        modemident_clear(id_out);
    if (writer_pid != NULL)
        *writer_pid = 0;
    if (port == NULL || !*port || id_out == NULL)
        return 0;

    vouch_rec_t r;
    if (read_record(port, &r) != 0)
        return 0;
    if (r.v != IDENTVOUCH_SCHEMA || strcmp(r.port, port) != 0 ||
        !imei_ok(r.id.imei) || r.pid <= 0)
        return 0;

    /* The same node INSTANCE the holder read -- not merely the same name. */
    struct stat pst;
    if (stat(port, &pst) != 0 ||
        (unsigned long long) pst.st_rdev != r.rdev ||
        (unsigned long long) pst.st_ino != r.ino ||
        (long long) pst.st_ctime != r.ctime)
        return 0;

    if (kill((pid_t) r.pid, 0) != 0 && errno != EPERM)
        return 0;

    *id_out = r.id;
    if (writer_pid != NULL)
        *writer_pid = (pid_t) r.pid;
    return 1;
}
