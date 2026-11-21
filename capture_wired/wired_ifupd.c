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
*/

/* dirfd */
#define _GNU_SOURCE

#include "wired_ifupd.h"
#include "wired_priv.h"
#include "wired_sysfs.h"

#include <dirent.h>
#include <errno.h>
#include <fcntl.h>
#include <limits.h>
#include <poll.h>
#include <signal.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#include <sys/ioctl.h>
#include <sys/prctl.h>
#include <sys/random.h>
#include <sys/socket.h>
#include <sys/syscall.h>

#include <net/if.h>

#include <linux/capability.h>
#include <linux/nsfs.h>

#ifndef PR_SET_NO_NEW_PRIVS
#define PR_SET_NO_NEW_PRIVS     38
#endif

#ifndef PR_CAP_AMBIENT
#define PR_CAP_AMBIENT              47
#define PR_CAP_AMBIENT_CLEAR_ALL    4
#endif

#define WIRED_CAP_ADMIN         (1ULL << CAP_NET_ADMIN)

/* The child's one descriptor */
#define WIRED_IFUPD_FD          3

/* capget and capset without libcap */
static int wired_caps_get(uint64_t *eff, uint64_t *prm, uint64_t *inh) {
    struct __user_cap_header_struct hdr;
    struct __user_cap_data_struct data[_LINUX_CAPABILITY_U32S_3];

    memset(&hdr, 0, sizeof(hdr));
    memset(data, 0, sizeof(data));
    hdr.version = _LINUX_CAPABILITY_VERSION_3;

    if (syscall(SYS_capget, &hdr, data) < 0)
        return -1;

    *eff = (uint64_t) data[0].effective | ((uint64_t) data[1].effective << 32);
    *prm = (uint64_t) data[0].permitted | ((uint64_t) data[1].permitted << 32);
    *inh = (uint64_t) data[0].inheritable | ((uint64_t) data[1].inheritable << 32);
    return 1;
}

static int wired_caps_set(uint64_t eff, uint64_t prm, uint64_t inh) {
    struct __user_cap_header_struct hdr;
    struct __user_cap_data_struct data[_LINUX_CAPABILITY_U32S_3];

    memset(&hdr, 0, sizeof(hdr));
    memset(data, 0, sizeof(data));
    hdr.version = _LINUX_CAPABILITY_VERSION_3;

    data[0].effective = (uint32_t) eff;
    data[1].effective = (uint32_t) (eff >> 32);
    data[0].permitted = (uint32_t) prm;
    data[1].permitted = (uint32_t) (prm >> 32);
    data[0].inheritable = (uint32_t) inh;
    data[1].inheritable = (uint32_t) (inh >> 32);

    return syscall(SYS_capset, &hdr, data) < 0 ? -1 : 1;
}

int wired_ifupd_drop_admin(void) {
    uint64_t eff, prm, inh;

    if (wired_caps_get(&eff, &prm, &inh) < 0)
        return -1;

    if (((eff | prm | inh) & WIRED_CAP_ADMIN) == 0)
        return 1;

    /* Gone from the permitted set, it goes from the ambient one too */
    if (wired_caps_set(eff & ~WIRED_CAP_ADMIN, prm & ~WIRED_CAP_ADMIN, inh & ~WIRED_CAP_ADMIN) < 0 ||
            wired_caps_get(&eff, &prm, &inh) < 0 || ((eff | prm | inh) & WIRED_CAP_ADMIN) != 0)
        return -1;

    return 1;
}

int wired_netns_foreign(void) {
#ifdef NS_GET_USERNS
    int nfd, ufd, e;

    if ((nfd = open("/proc/self/ns/net", O_RDONLY | O_CLOEXEC)) < 0)
        return -1;

    ufd = ioctl(nfd, NS_GET_USERNS);
    e = errno;
    close(nfd);

    /* EPERM only for an owner outside this user namespace; one owned by this
     * namespace or a child of it is changed by CAP_NET_ADMIN here */
    if (ufd < 0)
        return e == EPERM ? 1 : -1;

    close(ufd);
    return 0;
#else
    return -1;
#endif
}

wired_ifupd_state_t wired_ifupd_decide(int admin_permitted, int root_ids) {
    if (!admin_permitted)
        return WIRED_IFUPD_NO_CAP;

    /* A child here would keep the ids the capture process leaves (wired_priv.h) */
    if (root_ids != 0)
        return WIRED_IFUPD_ROOT;

    return WIRED_IFUPD_RUNNING;
}

static int wired_ifupd_errno(int e) {
    return e > 0 && e <= WIRED_ERRNO_MAX ? e : EIO;
}

void wired_ifupd_answer(const uint8_t *buf, size_t len, const wired_ifupd_ops_t *ops,
        wired_ifup_reply_t *reply) {
    char ifname[WIRED_IFNAMSIZ];
    wired_nl_link_t link, after;
    uint64_t seq = 0;
    int e;

    if (wired_ifup_req_parse(buf, len, &seq, ifname) < 0) {
        wired_ifup_reply_build(seq, WIRED_IFUP_FAILED, EINVAL, reply);
        return;
    }

    /* Checked here again in this process's own network namespace, whatever the
     * capture process checked, and pinned to the index found */
    if (ops->getlink(ifname, 0, &link) < 0) {
        e = errno;
        wired_ifup_reply_build(seq, WIRED_IFUP_FAILED, wired_ifupd_errno(e), reply);
        return;
    }

    switch (wired_classify_link(ops->sysfs_root, &link)) {
        case WIRED_IF_OK:
            break;
        case WIRED_IF_UNVERIFIED:
            wired_ifup_reply_build(seq, WIRED_IFUP_FAILED, EXDEV, reply);
            return;
        default:
            wired_ifup_reply_build(seq, WIRED_IFUP_FAILED, EOPNOTSUPP, reply);
            return;
    }

    if (link.flags & IFF_UP) {
        wired_ifup_reply_build(seq, WIRED_IFUP_ALREADY, 0, reply);
        return;
    }

    if (ops->set_up(link.index) < 0) {
        e = errno;
        wired_ifup_reply_build(seq, WIRED_IFUP_FAILED, wired_ifupd_errno(e), reply);
        return;
    }

    /* The index was brought up whatever it's called; the asker gets told when
     * it isn't the name asked for any more */
    if (ops->getlink(NULL, link.index, &after) < 0 || after.index != link.index ||
            strcmp(after.name, ifname) != 0) {
        wired_ifup_reply_build(seq, WIRED_IFUP_FAILED, ESTALE, reply);
        return;
    }

    wired_ifup_reply_build(seq, WIRED_IFUP_DONE, 0, reply);
}

/* Closes every descriptor but WIRED_IFUPD_FD, as /proc/self/fd lists them */
static int wired_ifupd_close_listed(void) {
    struct dirent *de;
    char *end;
    long v;
    DIR *d;
    int dfd;

    if ((d = opendir("/proc/self/fd")) == NULL)
        return -1;

    dfd = dirfd(d);

    while ((de = readdir(d)) != NULL) {
        if (de->d_name[0] < '0' || de->d_name[0] > '9')
            continue;

        errno = 0;
        v = strtol(de->d_name, &end, 10);

        if (errno != 0 || *end != 0 || v < 0 || v > INT_MAX)
            continue;

        if ((int) v != WIRED_IFUPD_FD && (int) v != dfd)
            close((int) v);
    }

    closedir(d);
    return 1;
}

/* Moves fd to WIRED_IFUPD_FD and closes every other descriptor */
static int wired_ifupd_keep_only(int fd) {
    if (fd != WIRED_IFUPD_FD && dup2(fd, WIRED_IFUPD_FD) < 0)
        return -1;

#ifdef SYS_close_range
    if (syscall(SYS_close_range, 0U, (unsigned int) WIRED_IFUPD_FD - 1, 0U) == 0 &&
            syscall(SYS_close_range, (unsigned int) WIRED_IFUPD_FD + 1, ~0U, 0U) == 0)
        return WIRED_IFUPD_FD;
#endif

    /* Kernels before 5.9 */
    if (wired_ifupd_close_listed() < 0)
        return -1;

    return WIRED_IFUPD_FD;
}

static void wired_ifupd_child(int fd, pid_t parent) {
    const wired_ifupd_ops_t ops = { WIRED_SYSFS_NET, wired_nl_getlink, wired_set_up };
    uint8_t buf[sizeof(wired_ifup_req_t)];
    wired_ifup_reply_t reply;
    uint64_t eff, prm, inh;
    sigset_t none;
    ssize_t r;
    int s;

    /* Gone with its parent, whichever way the parent goes */
    if (prctl(PR_SET_PDEATHSIG, SIGKILL) < 0 || getppid() != parent)
        _exit(1);

    for (s = 1; s < NSIG; s++)
        signal(s, SIG_DFL);

    signal(SIGPIPE, SIG_IGN);
    sigemptyset(&none);
    sigprocmask(SIG_SETMASK, &none, NULL);

    if ((fd = wired_ifupd_keep_only(fd)) < 0)
        _exit(1);

    /* stdio on /dev/null so no later socket or sysfs file lands on 0-2 */
    if ((s = open("/dev/null", O_RDWR | O_CLOEXEC)) != 0 || dup2(0, 1) != 1 || dup2(0, 2) != 2)
        _exit(1);

    /* CAP_NET_ADMIN and nothing else; EINVAL is a kernel without the setting */
    if (prctl(PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0) < 0 && errno != EINVAL)
        _exit(1);

    if (prctl(PR_CAP_AMBIENT, PR_CAP_AMBIENT_CLEAR_ALL, 0, 0, 0) < 0 && errno != EINVAL)
        _exit(1);

    if (wired_caps_set(WIRED_CAP_ADMIN, WIRED_CAP_ADMIN, 0) < 0 ||
            wired_caps_get(&eff, &prm, &inh) < 0 ||
            eff != WIRED_CAP_ADMIN || prm != WIRED_CAP_ADMIN || inh != 0)
        _exit(1);

    for (;;) {
        r = recv(fd, buf, sizeof(buf), MSG_TRUNC);

        if (r < 0 && errno == EINTR)
            continue;

        /* EOF: every capture process, and a --retry monitor, has gone */
        if (r <= 0)
            _exit(0);

        wired_ifupd_answer(buf, (size_t) r, &ops, &reply);

        if (send(fd, &reply, sizeof(reply), MSG_NOSIGNAL) != (ssize_t) sizeof(reply))
            _exit(0);
    }
}

int wired_ifupd_spawn(wired_ifupd_t *d) {
    pid_t parent = getpid(), pid;
    int sv[2], e;

    if (socketpair(AF_UNIX, SOCK_SEQPACKET | SOCK_CLOEXEC, 0, sv) < 0)
        return -1;

    if ((pid = fork()) < 0) {
        e = errno;
        close(sv[0]);
        close(sv[1]);
        errno = e;
        return -1;
    }

    if (pid == 0) {
        close(sv[0]);
        wired_ifupd_child(sv[1], parent);
        _exit(1);
    }

    close(sv[1]);
    d->fd = sv[0];
    d->pid = pid;
    d->state = WIRED_IFUPD_RUNNING;
    d->busy = 0;

    if (d->timeout_ms <= 0)
        d->timeout_ms = WIRED_IFUPD_TIMEOUT_MS;

    if (d->stall_ms <= 0)
        d->stall_ms = WIRED_IFUPD_STALL_MS;

    return 1;
}

int wired_ifupd_start(wired_ifupd_t *d) {
    uint64_t eff, prm, inh;

    memset(d, 0, sizeof(*d));
    d->fd = -1;
    d->pid = -1;
    d->timeout_ms = WIRED_IFUPD_TIMEOUT_MS;
    d->stall_ms = WIRED_IFUPD_STALL_MS;
    d->netns_foreign = wired_netns_foreign() == 1;

    if (wired_caps_get(&eff, &prm, &inh) < 0 || (d->root_ids = wired_root_ids()) < 0)
        return -1;

    d->state = wired_ifupd_decide((prm & WIRED_CAP_ADMIN) != 0, d->root_ids);

    if (d->state == WIRED_IFUPD_RUNNING && wired_ifupd_spawn(d) < 0)
        d->state = WIRED_IFUPD_GONE;

    return wired_ifupd_drop_admin();
}

static void wired_ifupd_gone(wired_ifupd_t *d) {
    close(d->fd);
    d->fd = -1;
    d->state = WIRED_IFUPD_GONE;
    d->busy = 0;
}

static void wired_ifupd_set_busy(wired_ifupd_t *d, uint64_t seq) {
    d->busy = 1;
    d->busy_seq = seq;
    d->busy_since_ms = wired_mono_ms();
}

/* A process forked with a copy numbers its own requests and waits on none of
 * the copy's.  The count starts anywhere, so a later process given a dead one's
 * pid doesn't take that one's late answers for its own */
static void wired_ifupd_own(wired_ifupd_t *d) {
    pid_t self = getpid();
    uint32_t start;

    if (d->seq_owner == self)
        return;

    if (getrandom(&start, sizeof(start), GRND_NONBLOCK) != (ssize_t) sizeof(start))
        start = (uint32_t) wired_mono_ms();

    d->seq_owner = self;
    d->seq = start;
    d->busy = 0;
}

void wired_ifupd_collect(wired_ifupd_t *d) {
    uint8_t buf[sizeof(wired_ifup_reply_t)];
    wired_ifup_status_t status;
    uint64_t seq;
    ssize_t r;
    int e;

    wired_ifupd_own(d);

    while (d->busy && d->fd >= 0) {
        r = recv(d->fd, buf, sizeof(buf), MSG_DONTWAIT | MSG_TRUNC);

        if (r < 0 && errno == EINTR)
            continue;

        if (r < 0 && (errno == EAGAIN || errno == EWOULDBLOCK))
            break;

        if (r <= 0) {
            wired_ifupd_gone(d);
            return;
        }

        /* Skipped: other processes' answers, and ones already given up on.  After
         * a full socket (busy_seq 0) any answer shows the child reading again */
        if (wired_ifup_reply_read(buf, (size_t) r, &seq, &status, &e) < 0 ||
                (d->busy_seq != 0 && seq != d->busy_seq))
            continue;

        d->busy = 0;
    }

    if (d->busy && wired_mono_ms() - d->busy_since_ms >=
            (uint64_t) (d->stall_ms > 0 ? d->stall_ms : WIRED_IFUPD_STALL_MS))
        d->busy = 0;
}

int wired_ifupd_request(wired_ifupd_t *d, const char *ifname, int *err) {
    uint8_t buf[sizeof(wired_ifup_reply_t)];
    wired_ifup_req_t req;
    wired_ifup_status_t status;
    struct pollfd pfd;
    uint64_t deadline, now, seq;
    ssize_t r;
    int e;

    if (d->fd < 0) {
        *err = ENOTCONN;
        return -1;
    }

    wired_ifupd_collect(d);

    if (d->fd < 0) {
        *err = EPIPE;
        return -1;
    }

    /* One request at a time: the child answers in order, so a new one would only
     * queue behind the one it's still working on */
    if (d->busy) {
        *err = EBUSY;
        return -1;
    }

    seq = wired_ifup_seq((uint32_t) d->seq_owner, d->seq + 1);

    if (wired_ifup_req_build(ifname, seq, &req) < 0) {
        *err = EINVAL;
        return -1;
    }

    d->seq++;

    do {
        r = send(d->fd, &req, sizeof(req), MSG_NOSIGNAL | MSG_DONTWAIT);
    } while (r < 0 && errno == EINTR);

    /* A full socket is a child which stopped reading */
    if (r < 0 && (errno == EAGAIN || errno == EWOULDBLOCK)) {
        wired_ifupd_set_busy(d, 0);
        *err = EBUSY;
        return -1;
    }

    if (r != (ssize_t) sizeof(req)) {
        *err = r < 0 ? errno : EIO;
        wired_ifupd_gone(d);
        return -1;
    }

    deadline = wired_mono_ms() + (uint64_t) (d->timeout_ms > 0 ? d->timeout_ms :
            WIRED_IFUPD_TIMEOUT_MS);

    /* Answers to requests which timed out, or whose asker died waiting, are
     * skipped by their seq */
    for (;;) {
        if ((now = wired_mono_ms()) >= deadline) {
            wired_ifupd_set_busy(d, seq);
            *err = ETIMEDOUT;
            return -1;
        }

        pfd.fd = d->fd;
        pfd.events = POLLIN;
        pfd.revents = 0;

        if ((r = poll(&pfd, 1, (int) (deadline - now))) < 0 && errno == EINTR)
            continue;

        /* Not left busy: the answer, if one comes, is skipped by its seq and the
         * next request waits behind it at most */
        if (r < 0) {
            *err = errno;
            return -1;
        }

        if (r == 0)
            continue;

        r = recv(d->fd, buf, sizeof(buf), MSG_DONTWAIT | MSG_TRUNC);

        if (r < 0 && (errno == EINTR || errno == EAGAIN || errno == EWOULDBLOCK))
            continue;

        if (r <= 0) {
            *err = r < 0 ? errno : EPIPE;
            wired_ifupd_gone(d);
            return -1;
        }

        switch (wired_ifup_reply_parse(buf, (size_t) r, seq, &status, &e)) {
            case 1:
                *err = e;
                return (int) status;
            case 0:
                continue;
            default:
                /* The child answered, if wrongly, so it's reading */
                *err = EPROTO;
                return -1;
        }
    }
}
