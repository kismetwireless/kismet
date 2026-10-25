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

    cellat QMI feed -- see cellat_qmifeed.h for the why.
*/

#include "cellat_qmifeed.h"
#include "../capture_cell_diag/diag_privdrop.h"

#include <errno.h>
#include <fcntl.h>
#include <signal.h>
#include <stdio.h>
#include <string.h>
#include <sys/wait.h>
#include <time.h>
#include <stdlib.h>
#include <unistd.h>

#include <limits.h>
#include <sys/stat.h>
#ifdef __APPLE__
#include <mach-o/dyld.h>   /* _NSGetExecutablePath -- qmifeed_exe_dir() */
#endif

#ifdef __linux__
#include <sys/prctl.h>
#endif

void qmifeed_init(qmifeed_t *qf) {
    memset(qf, 0, sizeof(*qf));
    qf->pid = -1;
    qf->fd = -1;
}

void qmifeed_set_tag_cb(qmifeed_t *qf, qmifeed_tag_cb cb) {
    qf->tag_cb = cb;
}

/* In the forked child only: close everything but 0/1/2. See the header's
 * FD HYGIENE note -- the KDS IPC pipe must not outlive the capture child. */
static void close_inherited_fds(void) {
    long maxfd = sysconf(_SC_OPEN_MAX);
    if (maxfd < 0 || maxfd > 65536)
        maxfd = 65536;
    for (int fd = 3; fd < maxfd; fd++)
        close(fd);
}

extern char **environ;

/* "" for anything that is not a real identity: NULL, empty, all zeros. */
static int imei_is_real(const char *imei) {
    if (imei == NULL || imei[0] == '\0')
        return 0;
    for (const char *p = imei; *p; p++)
        if (*p != '0')
            return 1;
    return 0;
}

void qmifeed_set_expect_imei(qmifeed_t *qf, const char *imei) {
    if (imei_is_real(imei))
        snprintf(qf->expect_imei, sizeof(qf->expect_imei), "%s", imei);
    else
        qf->expect_imei[0] = '\0';
}

#define QMIFEED_STR_(x) #x
#define QMIFEED_STR(x) QMIFEED_STR_(x)

/* The child's environment, built BEFORE fork: the capture child is threaded,
 * so between fork and exec only async-signal-safe calls are allowed, and
 * setenv() allocates. Every inherited CELLAT_IMEI is dropped; the verified one
 * (if any) is appended from `slot`. The pointer array is malloc'd; the strings
 * are environ's own or `slot`. */
static char **build_child_env(const char *imei, char *slot, size_t slotsz) {
    size_t n = 0;
    for (char **e = environ; e && *e; e++)
        n++;
    char **env = malloc((n + 4) * sizeof(*env));
    if (env == NULL)
        return NULL;
    size_t k = 0;
    for (char **e = environ; e && *e; e++)
        if (strncmp(*e, "CELLAT_IMEI=", 12) != 0 &&
            strncmp(*e, QMIFEED_PROTO_ENV "=", sizeof(QMIFEED_PROTO_ENV)) != 0 &&
            strncmp(*e, QMIFEED_RAWQMI_MAX_ENV "=", sizeof(QMIFEED_RAWQMI_MAX_ENV)) != 0)
            env[k++] = *e;
    /* The line protocol this binary reads. A string
     * literal, so it outlives the exec without a slot of its own. */
    env[k++] = (char *) QMIFEED_PROTO_ENV "=2";
    /* The largest #rawqmi payload this binary forwards. */
    env[k++] = (char *) QMIFEED_RAWQMI_MAX_ENV "=" QMIFEED_STR(CELLAT_ROW_JSON_MAX);
    if (imei != NULL && imei[0] != '\0') {
        snprintf(slot, slotsz, "CELLAT_IMEI=%s", imei);
        env[k++] = slot;
    }
    env[k] = NULL;
    return env;
}

/* ---- a minimal JSON walker, enough to find prov.imei ---------- */

static const char *skip_ws(const char *p) {
    while (*p == ' ' || *p == '\t' || *p == '\r' || *p == '\n')
        p++;
    return p;
}

/* p at '"'; returns just past the closing quote, or NULL if unterminated. */
static const char *skip_string(const char *p) {
    for (p++; *p; p++) {
        if (*p == '\\') {
            if (p[1] == '\0')
                return NULL;
            p++;
        } else if (*p == '"') {
            return p + 1;
        }
    }
    return NULL;
}

/* p at a value; returns just past it, or NULL if malformed. */
static const char *skip_value(const char *p) {
    if (*p == '"')
        return skip_string(p);
    if (*p == '{' || *p == '[') {
        int depth = 0;
        while (*p) {
            if (*p == '"') {
                if ((p = skip_string(p)) == NULL)
                    return NULL;
                continue;
            }
            if (*p == '{' || *p == '[')
                depth++;
            else if ((*p == '}' || *p == ']') && --depth == 0)
                return p + 1;
            p++;
        }
        return NULL;
    }
    const char *s = p;
    while (*p && *p != ',' && *p != '}' && *p != ']' &&
           *p != ' ' && *p != '\t' && *p != '\r' && *p != '\n')
        p++;
    return p == s ? NULL : p;
}

/* p at '{'; returns the start of `key`'s value among the object's OWN members
 * (never a nested object's), or NULL if absent or malformed. */
static const char *find_member(const char *p, const char *key) {
    size_t klen = strlen(key);
    p = skip_ws(p);
    if (*p != '{')
        return NULL;
    p = skip_ws(p + 1);
    if (*p == '}')
        return NULL;
    for (;;) {
        if (*p != '"')
            return NULL;
        const char *k = p + 1;
        const char *kend = skip_string(p);
        if (kend == NULL)
            return NULL;
        int match = (size_t)(kend - 1 - k) == klen && memcmp(k, key, klen) == 0;
        p = skip_ws(kend);
        if (*p != ':')
            return NULL;
        p = skip_ws(p + 1);
        if (match)
            return p;
        if ((p = skip_value(p)) == NULL)
            return NULL;
        p = skip_ws(p);
        if (*p != ',')
            return NULL;     /* '}' (end of object) or junk: not here */
        p = skip_ws(p + 1);
    }
}

int qmifeed_line_imei(const char *line, char *out, size_t outsz) {
    if (outsz > 0)
        out[0] = '\0';
    const char *prov = find_member(line, "prov");
    if (prov == NULL)
        return 0;
    if (*prov != '{')
        return -1;
    const char *v = find_member(prov, "imei");
    if (v == NULL) {
        /* Absent, or the walk hit something malformed inside prov. */
        return skip_value(prov) == NULL ? -1 : 0;
    }
    if (*v != '"')
        return -1;
    const char *end = skip_string(v);
    if (end == NULL)
        return -1;
    size_t n = (size_t)(end - 1 - (v + 1));
    if (n + 1 > outsz || memchr(v + 1, '\\', n) != NULL)
        return -1;           /* an IMEI has no escapes; do not unescape guesses */
    memcpy(out, v + 1, n);
    out[n] = '\0';
    return 1;
}

qmifeed_imei_verdict_t qmifeed_imei_check(const char *line, const char *source_imei,
                                          char *got, size_t gotsz) {
    char tmp[64];
    if (got == NULL || gotsz == 0) {
        got = tmp;
        gotsz = sizeof(tmp);
    }
    int r = qmifeed_line_imei(line, got, gotsz);
    if (!imei_is_real(source_imei))
        return QMIFEED_IMEI_UNCHECKED;
    if (r != 1 || got[0] == '\0')
        return QMIFEED_IMEI_UNSTAMPED;
    return strcmp(got, source_imei) == 0 ? QMIFEED_IMEI_MATCH : QMIFEED_IMEI_MISMATCH;
}

int qmifeed_start(qmifeed_t *qf, const char *cmd, char *err, size_t errsz) {
    int p[2];

    if (cmd == NULL || cmd[0] == '\0') {
        snprintf(err, errsz, "qmifeed= needs a command");
        return -1;
    }
    char env_slot[64];
    char **env = build_child_env(qf->expect_imei, env_slot, sizeof(env_slot));
    if (env == NULL) {
        snprintf(err, errsz, "qmifeed: out of memory building the child environment");
        return -1;
    }
    if (pipe(p) < 0) {
        snprintf(err, errsz, "qmifeed pipe() failed: %s", strerror(errno));
        free(env);
        return -1;
    }

    pid_t pid = fork();
    if (pid < 0) {
        snprintf(err, errsz, "qmifeed fork() failed: %s", strerror(errno));
        close(p[0]);
        close(p[1]);
        free(env);
        return -1;
    }

    if (pid == 0) {
        /* `cmd` is the caller's. Under `make suidinstall` it must run as
         * the caller, never at this binary's effective uid. Before anything
         * else, so nothing below runs elevated either. */
        char perr[160];
        if (diag_child_drop_privs(perr, sizeof(perr)) != 0) {
            dprintf(STDERR_FILENO, "qmifeed: refusing to exec: %s\n", perr);
            _exit(126);
        }
        /* Own process group, so qmifeed_stop() reaches sh, python and qmicli. */
        setpgid(0, 0);
#ifdef __linux__
        /* A SIGKILLed capture child gets no chance to stop us; the kernel does.
         * PDEATHSIG reaches this process only -- it is not inherited across
         * fork, and a shell killed by it does not pass it on. For `sh -c` plus a
         * pipeline, it kills sh and orphans the rest. The deeper layers are the
         * feed's own: kismet_qmi_feed.py exits when its parent changes, and any
         * writer dies of SIGPIPE on its next line. */
        prctl(PR_SET_PDEATHSIG, SIGTERM);
#endif
        int devnull = open("/dev/null", O_RDONLY);
        if (devnull >= 0) {
            dup2(devnull, STDIN_FILENO);
            if (devnull != STDIN_FILENO)
                close(devnull);
        }
        dup2(p[1], STDOUT_FILENO);
        close_inherited_fds();   /* also closes p[0] / p[1] */
        /* The capture thread runs with SIGPIPE/SIGCHLD/SIGALRM/SIGQUIT blocked
         * (capture_framework.c's signal-thread mask), and a blocked mask
         * SURVIVES exec. A feed that could not take SIGPIPE would never die of
         * a write to a dead reader. Give it a clean slate. */
        sigset_t none;
        sigemptyset(&none);
        sigprocmask(SIG_SETMASK, &none, NULL);
        signal(SIGPIPE, SIG_DFL);
        signal(SIGCHLD, SIG_DFL);
        signal(SIGTERM, SIG_DFL);
        char *const argv[] = { "sh", "-c", (char *) cmd, NULL };
        execve("/bin/sh", argv, env);
        _exit(127);
    }

    free(env);
    close(p[1]);
    /* Mirror the child's own setpgid so a stop racing the exec still hits it. */
    setpgid(pid, pid);
    int fl = fcntl(p[0], F_GETFL);
    fcntl(p[0], F_SETFL, fl | O_NONBLOCK);
    fcntl(p[0], F_SETFD, FD_CLOEXEC);

    qf->pid = pid;
    qf->fd = p[0];
    qf->len = 0;
    qf->discarding = 0;
    qf->eof = 0;
    return 0;
}

/* One terminated line in qf->buf[0..len). Forward it if it is a JSON object. */
/* `#rawqmi {json}` or `#msg info|error <text>`. Anything
 * else starting with '#' -- an unknown tag, a raw payload that is not an
 * object, an empty note -- is counted, never forwarded. */
static void deliver_tagged(qmifeed_t *qf, size_t n, void *ctx) {
    static const struct { const char *pfx; qmifeed_tag_t tag; } tags[] = {
        { "#rawqmi ",    QMIFEED_TAG_RAWQMI },
        { "#msg info ",  QMIFEED_TAG_MSG_INFO },
        { "#msg error ", QMIFEED_TAG_MSG_ERROR },
    };
    for (size_t i = 0; i < sizeof(tags) / sizeof(tags[0]); i++) {
        size_t pl = strlen(tags[i].pfx);
        if (n <= pl || strncmp(qf->buf, tags[i].pfx, pl) != 0)
            continue;
        const char *payload = qf->buf + pl;
        if (tags[i].tag == QMIFEED_TAG_RAWQMI &&
            (payload[0] != '{' || qf->buf[n - 1] != '}'))
            break;
        qf->tagged++;
        qf->tag_cb(tags[i].tag, payload, ctx);
        return;
    }
    qf->dropped_badtag++;
}

static int deliver(qmifeed_t *qf, qmifeed_line_cb cb, void *ctx) {
    size_t n = qf->len;
    qf->len = 0;

    while (n > 0 && (qf->buf[n - 1] == '\r' || qf->buf[n - 1] == ' ' ||
                     qf->buf[n - 1] == '\t'))
        n--;
    if (n == 0)
        return 0;            /* blank line: not an observation, not an error */

    qf->buf[n] = '\0';
    if (qf->buf[0] == '#' && qf->tag_cb != NULL) {
        deliver_tagged(qf, n, ctx);
        return 0;
    }
    if (qf->buf[0] != '{' || qf->buf[n - 1] != '}') {
        qf->dropped_nonjson++;
        return 0;
    }
    if (n + 1 > QMIFEED_LINE_MAX) {
        /* An observation must fit capture_cell_at's JSON buffer; only tagged
         * raw lines may use the rest of QMIFEED_RAW_MAX. Dropped whole. */
        qf->dropped_overlong++;
        return 0;
    }
    qf->lines++;
    cb(qf->buf, ctx);
    return 1;
}

int qmifeed_poll(qmifeed_t *qf, qmifeed_line_cb cb, void *ctx) {
    char chunk[1024];
    int delivered = 0;

    if (qf->fd < 0)
        return 0;

    for (;;) {
        ssize_t r = read(qf->fd, chunk, sizeof(chunk));
        if (r < 0) {
            if (errno == EINTR)
                continue;
            if (errno == EAGAIN || errno == EWOULDBLOCK)
                return delivered;
            r = 0;           /* any other error: treat as end of stream */
        }
        if (r == 0) {
            /* A final line with no newline is still a whole line once the
             * writer is gone -- but only if it was not being discarded. */
            if (qf->len > 0 && !qf->discarding)
                delivered += deliver(qf, cb, ctx);
            qf->len = 0;
            close(qf->fd);
            qf->fd = -1;
            qf->eof = 1;
            return delivered;
        }

        for (ssize_t i = 0; i < r; i++) {
            char c = chunk[i];
            if (c == '\n') {
                if (qf->discarding) {
                    qf->discarding = 0;
                    qf->len = 0;
                } else {
                    delivered += deliver(qf, cb, ctx);
                }
                continue;
            }
            if (qf->discarding)
                continue;
            if (qf->len + 1 >= QMIFEED_RAW_MAX) {
                /* Too long for any line: drop the WHOLE line, never a
                 * truncated prefix of it. (An observation's own, smaller cap
                 * is applied in deliver(), on the complete line.) */
                qf->dropped_overlong++;
                qf->discarding = 1;
                qf->len = 0;
                continue;
            }
            qf->buf[qf->len++] = c;
        }
    }
}

int qmifeed_stop(qmifeed_t *qf, int grace_ms) {
    int status = -1;

    if (qf->fd >= 0) {
        close(qf->fd);
        qf->fd = -1;
    }
    if (qf->pid <= 0)
        return -1;

    /* Wait with WNOWAIT: the leader stays an unreaped zombie, so its pid --
     * which is also the group id -- cannot be recycled while we sweep the
     * group below. Only then is it reaped. */
    kill(-qf->pid, SIGTERM);
    for (int waited = 0; ; waited += 20) {
        siginfo_t si;
        memset(&si, 0, sizeof(si));
        int w = waitid(P_PID, (id_t) qf->pid, &si, WEXITED | WNOHANG | WNOWAIT);
        if (w < 0 && errno == EINTR)
            continue;
        if (w < 0 || si.si_pid == qf->pid)
            break;
        if (waited >= grace_ms) {
            kill(-qf->pid, SIGKILL);
            waited = -1000000;   /* SIGKILL cannot be ignored: wait it out */
        }
        struct timespec ts = { .tv_sec = 0, .tv_nsec = 20 * 1000000L };
        nanosleep(&ts, NULL);
    }
    /* sh may be gone while its pipeline lingers: sweep the group, then reap. */
    kill(-qf->pid, SIGKILL);
    while (waitpid(qf->pid, &status, 0) < 0 && errno == EINTR)
        ;
    qf->pid = -1;
    return status;
}

const char *qmifeed_exe_dir(void) {
    static char dir[PATH_MAX];
    static int tried = 0;

    if (!tried) {
        tried = 1;
        ssize_t n = -1;
#ifdef __APPLE__
        char raw[PATH_MAX];
        uint32_t rawsz = sizeof(raw);
        if (_NSGetExecutablePath(raw, &rawsz) == 0 && realpath(raw, dir) != NULL)
            n = (ssize_t) strlen(dir);
#else
        n = readlink("/proc/self/exe", dir, sizeof(dir) - 1);
#endif
        if (n <= 0) {
            dir[0] = '\0';
        } else {
            dir[n] = '\0';
            char *slash = strrchr(dir, '/');
            if (slash && slash != dir)
                *slash = '\0';
            else
                dir[0] = '\0';
        }
    }
    return dir[0] ? dir : NULL;
}

/* `auto`, `1`, or `auto <args>`: 1 and the argument tail (maybe ""), else 0. */
static int qmifeed_is_auto(const char *value, const char **tail) {
    if (strcmp(value, "1") == 0) {
        *tail = "";
        return 1;
    }
    if (strncmp(value, "auto", 4) != 0)
        return 0;
    if (value[4] == '\0' || value[4] == ' ') {
        *tail = value + 4;
        return 1;
    }
    return 0;
}

static int qmifeed_is_file(const char *path) {
    struct stat st;
    return stat(path, &st) == 0 && S_ISREG(st.st_mode) && access(path, R_OK) == 0;
}

/* Single-quote `s` for /bin/sh into out+*len. -1 if it does not fit. */
static int qmifeed_sh_quote(const char *s, char *out, size_t outsz, size_t *len) {
    if (*len + 1 >= outsz)
        return -1;
    out[(*len)++] = '\'';
    for (; *s; s++) {
        const char *piece = (*s == '\'') ? "'\\''" : NULL;
        size_t need = piece ? strlen(piece) : 1;
        if (*len + need + 1 >= outsz)
            return -1;
        if (piece) {
            memcpy(out + *len, piece, need);
            *len += need;
        } else {
            out[(*len)++] = *s;
        }
    }
    if (*len + 1 >= outsz)
        return -1;
    out[(*len)++] = '\'';
    out[*len] = '\0';
    return 0;
}

/* The feed at `probe` as `exec python3 '<probe>'<tail>` into out. */
static int qmifeed_auto_command(const char *probe, const char *tail,
                                char *out, size_t outsz, char *err, size_t errsz) {
    /* exec: the shell becomes python, so the direct child that
     * PR_SET_PDEATHSIG and the group kill reach IS the feed. */
    size_t len = (size_t) snprintf(out, outsz, "exec python3 ");
    if (len >= outsz || qmifeed_sh_quote(probe, out, outsz, &len) != 0
            || len + strlen(tail) >= outsz) {
        snprintf(err, errsz, "qmifeed=auto: the command for %s is too long",
                 probe);
        return -1;
    }
    memcpy(out + len, tail, strlen(tail) + 1);
    return 0;
}

int qmifeed_resolve_command(const char *value, const char *self_dir,
                            char *out, size_t outsz, char *err, size_t errsz) {
    return qmifeed_resolve_command_in(value, self_dir, QMIFEED_DATADIR,
                                      out, outsz, err, errsz);
}

int qmifeed_resolve_command_in(const char *value, const char *self_dir,
                               const char *data_dir,
                               char *out, size_t outsz, char *err, size_t errsz) {
    const char *tail = NULL;

    if (value == NULL || value[0] == '\0') {
        snprintf(err, errsz, "qmifeed= needs a command, or auto");
        return -1;
    }
    if (!qmifeed_is_auto(value, &tail)) {
        if (strlen(value) >= outsz) {
            snprintf(err, errsz, "qmifeed= command is too long");
            return -1;
        }
        snprintf(out, outsz, "%s", value);
        return 0;
    }
    int have_data = data_dir != NULL && data_dir[0] != '\0';
    if ((self_dir == NULL || self_dir[0] == '\0') && !have_data) {
        snprintf(err, errsz, "qmifeed=auto: this binary cannot find its own "
                 "directory, so it cannot find the feed that ships beside it; "
                 "pass qmifeed=<command> instead");
        return -1;
    }

    /* The walk: <root>/qmifeed/ is the helper's own directory (the binary is
     * built in capture_cell_at/); <root>/capture_cell_at/qmifeed/ is a binary
     * run from the source tree's root. */
    static const char *const rel[] = {
        QMIFEED_AUTO_SCRIPT,
        "capture_cell_at/" QMIFEED_AUTO_SCRIPT,
    };
    char root[PATH_MAX];
    char probe[PATH_MAX];
    snprintf(root, sizeof(root), "%s", self_dir ? self_dir : "");
    for (int up = 0; root[0] && up <= QMIFEED_AUTO_MAX_UP; up++) {
        for (size_t i = 0; i < sizeof(rel) / sizeof(rel[0]); i++) {
            if (snprintf(probe, sizeof(probe), "%s/%s", root, rel[i])
                    >= (int) sizeof(probe))
                continue;
            if (!qmifeed_is_file(probe))
                continue;
            return qmifeed_auto_command(probe, tail, out, outsz, err, errsz);
        }
        char *slash = strrchr(root, '/');
        if (!slash || slash == root)
            break;
        *slash = '\0';
    }
    /* The installed layout: the binary in $(BINDIR), the feed in the data dir. */
    if (have_data
            && snprintf(probe, sizeof(probe), "%s/%s", data_dir,
                        QMIFEED_AUTO_SCRIPT) < (int) sizeof(probe)
            && qmifeed_is_file(probe))
        return qmifeed_auto_command(probe, tail, out, outsz, err, errsz);
    if (have_data)
        snprintf(err, errsz, "qmifeed=auto: no %s beside this binary (%s), up to "
                 "%d parents, or in %s; pass qmifeed=<command> instead",
                 QMIFEED_AUTO_SCRIPT, self_dir ? self_dir : "?",
                 QMIFEED_AUTO_MAX_UP, data_dir);
    else
        snprintf(err, errsz, "qmifeed=auto: no %s beside this binary (%s) or up to "
                 "%d parents; pass qmifeed=<command> instead",
                 QMIFEED_AUTO_SCRIPT, self_dir, QMIFEED_AUTO_MAX_UP);
    return -1;
}
