/* cell_safefile.h - open, rename and remove the files a source definition
 * names.
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 *
 * Both cell captures write files at paths from the source definition or its
 * defaults (transcript=, atlog=, rawlog=, capmeta, the clock anchor sidecar,
 * lockstate=). `make suidinstall` installs them setuid root, so under a suid
 * install each of these operations runs in a forked child at the caller's own
 * ids (diag_child_drop_privs), and the opened fd is passed back: a path the
 * caller cannot write as themselves cannot be written through the capture.
 *
 * Every open refuses a final symlink (O_NOFOLLOW) and anything that is not a
 * regular file, suid or not. The open is non-blocking, so a FIFO or device
 * named as a log cannot hang the capture before it is refused.
 *
 * Header-only (static inline), like diag_privdrop.h, so both captures share
 * one implementation with no new object in either build.
 */

#ifndef __CELL_SAFEFILE_H__
#define __CELL_SAFEFILE_H__

#include "diag_privdrop.h"

#include <errno.h>
#include <fcntl.h>
#include <stdio.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <sys/uio.h>
#include <sys/wait.h>
#include <unistd.h>

#ifndef O_CLOEXEC
#define O_CLOEXEC 0
#endif

static inline int cell_is_elevated(void) {
    return getuid() != geteuid() || getgid() != getegid();
}

enum { CELL_SAFE_OPEN = 0, CELL_SAFE_RENAME = 1, CELL_SAFE_UNLINK = 2 };

/* The operation itself, at whatever ids this process holds. must_own: an
 * existing file has to belong to the effective uid (a shared directory like
 * /tmp, where someone else could have made it first). */
static inline int cell_safe_op_direct(int op, const char *a, const char *b,
                                      int flags, mode_t mode, int must_own) {
    if (op == CELL_SAFE_RENAME)
        return rename(a, b);
    if (op == CELL_SAFE_UNLINK)
        return unlink(a);

    int fd = open(a, flags | O_NOFOLLOW | O_CLOEXEC | O_NOCTTY | O_NONBLOCK, mode);
    if (fd < 0)
        return -1;
    struct stat st;
    if (fstat(fd, &st) != 0 || !S_ISREG(st.st_mode) ||
            (must_own && st.st_uid != geteuid())) {
        close(fd);
        errno = EPERM;
        return -1;
    }
    int fl = fcntl(fd, F_GETFL);
    if (fl >= 0)
        fcntl(fd, F_SETFL, fl & ~O_NONBLOCK);
    return fd;
}

/* Under suid: the operation in a child at the caller's ids; the result, errno
 * and (for an open) the fd come back over a socketpair. Only async-signal-safe
 * calls run in the child -- the captures are threaded. */
static inline int cell_safe_op(int op, const char *a, const char *b,
                               int flags, mode_t mode, int must_own) {
    if (a == NULL || (op == CELL_SAFE_RENAME && b == NULL)) {
        errno = EINVAL;
        return -1;
    }
    if (!cell_is_elevated())
        return cell_safe_op_direct(op, a, b, flags, mode, must_own);

    int sv[2];
    if (socketpair(AF_UNIX, SOCK_STREAM, 0, sv) != 0)
        return -1;
    fcntl(sv[0], F_SETFD, FD_CLOEXEC);
    fcntl(sv[1], F_SETFD, FD_CLOEXEC);

    pid_t pid = fork();
    if (pid < 0) {
        int e = errno;
        close(sv[0]);
        close(sv[1]);
        errno = e;
        return -1;
    }

    if (pid == 0) {
        char perr[160];
        int res[2] = { -1, EPERM };
        int fd = -1;
        close(sv[0]);
        if (diag_child_drop_privs(perr, sizeof(perr)) == 0) {
            fd = cell_safe_op_direct(op, a, b, flags, mode, must_own);
            res[0] = fd >= 0 ? 0 : -1;
            res[1] = fd >= 0 ? 0 : errno;
        }

        struct iovec iov = { .iov_base = res, .iov_len = sizeof(res) };
        union {
            struct cmsghdr h;
            char buf[CMSG_SPACE(sizeof(int))];
        } cm;
        struct msghdr m;
        memset(&m, 0, sizeof(m));
        m.msg_iov = &iov;
        m.msg_iovlen = 1;
        if (op == CELL_SAFE_OPEN && fd >= 0) {
            memset(&cm, 0, sizeof(cm));
            m.msg_control = cm.buf;
            m.msg_controllen = sizeof(cm.buf);
            struct cmsghdr *c = CMSG_FIRSTHDR(&m);
            c->cmsg_level = SOL_SOCKET;
            c->cmsg_type = SCM_RIGHTS;
            c->cmsg_len = CMSG_LEN(sizeof(int));
            memcpy(CMSG_DATA(c), &fd, sizeof(int));
        }
        _exit(sendmsg(sv[1], &m, 0) == (ssize_t) sizeof(res) ? 0 : 1);
    }

    close(sv[1]);
    int res[2] = { -1, EIO };
    int fd = -1;
    struct iovec iov = { .iov_base = res, .iov_len = sizeof(res) };
    union {
        struct cmsghdr h;
        char buf[CMSG_SPACE(sizeof(int))];
    } cm;
    struct msghdr m;
    memset(&m, 0, sizeof(m));
    m.msg_iov = &iov;
    m.msg_iovlen = 1;
    m.msg_control = cm.buf;
    m.msg_controllen = sizeof(cm.buf);

    ssize_t n;
    do {
        n = recvmsg(sv[0], &m, 0);
    } while (n < 0 && errno == EINTR);

    if (n == (ssize_t) sizeof(res) && !(m.msg_flags & MSG_CTRUNC)) {
        for (struct cmsghdr *c = CMSG_FIRSTHDR(&m); c != NULL; c = CMSG_NXTHDR(&m, c))
            if (c->cmsg_level == SOL_SOCKET && c->cmsg_type == SCM_RIGHTS &&
                    c->cmsg_len == CMSG_LEN(sizeof(int)))
                memcpy(&fd, CMSG_DATA(c), sizeof(int));
    } else {
        res[0] = -1;
        res[1] = EIO;
    }
    close(sv[0]);

    /* The framework may reap children itself; the answer came over the
     * socket either way. */
    while (waitpid(pid, NULL, 0) < 0 && errno == EINTR)
        ;

    if (op == CELL_SAFE_OPEN) {
        if (res[0] == 0 && fd >= 0) {
            fcntl(fd, F_SETFD, FD_CLOEXEC);
            return fd;
        }
        if (fd >= 0)
            close(fd);
        errno = res[1] ? res[1] : EIO;
        return -1;
    }
    if (res[0] != 0) {
        errno = res[1] ? res[1] : EIO;
        return -1;
    }
    return 0;
}

static inline int cell_safe_open(const char *path, int flags, mode_t mode) {
    return cell_safe_op(CELL_SAFE_OPEN, path, NULL, flags, mode, 0);
}

/* For a fixed name in a shared directory: an existing file must be ours. */
static inline int cell_safe_open_owned(const char *path, int flags, mode_t mode) {
    return cell_safe_op(CELL_SAFE_OPEN, path, NULL, flags, mode, 1);
}

static inline int cell_safe_rename(const char *from, const char *to) {
    return cell_safe_op(CELL_SAFE_RENAME, from, to, 0, 0, 0);
}

static inline int cell_safe_unlink(const char *path) {
    return cell_safe_op(CELL_SAFE_UNLINK, path, NULL, 0, 0, 0);
}

/* fopen() through cell_safe_op(); mode is "r" or "w". */
static inline FILE *cell_safe_fopen(const char *path, const char *mode, mode_t perm,
                                    int must_own) {
    int write = mode != NULL && mode[0] == 'w';
    int fd = cell_safe_op(CELL_SAFE_OPEN, path, NULL,
                          write ? (O_WRONLY | O_CREAT | O_TRUNC) : O_RDONLY, perm, must_own);
    if (fd < 0)
        return NULL;
    FILE *f = fdopen(fd, write ? "w" : "r");
    if (f == NULL) {
        int e = errno;
        close(fd);
        errno = e;
    }
    return f;
}

#endif
