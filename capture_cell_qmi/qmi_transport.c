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

#define _GNU_SOURCE

#include <errno.h>
#include <fcntl.h>
#include <poll.h>
#include <stdarg.h>
#include <stddef.h>
#include <stdio.h>
#include <string.h>
#include <sys/file.h>
#include <sys/ioctl.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <sys/un.h>
#include <time.h>
#include <unistd.h>

#ifdef __linux__
#include <linux/usb/cdc-wdm.h>
#endif

#include "../capture_cell_diag/cell_safefile.h"
#include "qmi_transport.h"

/* CTL transaction id 0xFF and the top MBIM ids are kept for the prebuilt
 * release, so it can never collide with a request in flight */
#define CTL_TID_RELEASE   0xFF
#define MBIM_TID_RELEASE  0xFFFFFFFEu
#define MBIM_TID_CLOSE    0xFFFFFFFFu
#define MBIM_TID_WRAP     0xFFFFFF00u

/* MBIM function error: the function has not been opened */
#define MBIM_ERROR_NOT_OPENED 5

#define MBIM_MAX_CONTROL_TRANSFER 4096
/* MBIM 1.0: a function's control transfer is never under 64 bytes */
#define MBIM_MIN_CONTROL_TRANSFER 64
#define MBIM_PROXY_TIMEOUT_S 10
/* How long a direct MBIM node gets to show it is already open */
#define MBIM_PROBE_MS 1500

/* mbim_exchange: the device answered with a function error */
#define XFER_FUNCTION_ERROR (-2)

/* How often an open's waits check whether it was cancelled */
#define OPEN_CANCEL_POLL_MS 100

static int (*g_open_cancel)(void *) = NULL;
static void *g_open_cancel_arg = NULL;

void qmi_transport_set_open_cancel(int (*cancelled)(void *), void *arg) {
    g_open_cancel = cancelled;
    g_open_cancel_arg = arg;
}

static int open_cancelled(qmi_transport_t *t) {
    if (t->opening && g_open_cancel != NULL && g_open_cancel(g_open_cancel_arg))
        t->cancelled = 1;
    return t->opening && t->cancelled;
}

/* How long a release or MBIM_CLOSE waits once the open was cancelled: with
 * the held wait it all fits the helper's 3 s close grace */
#define CANCELLED_CLOSE_MS 400

/* A wait of `left` ms, cut into slices during an open so a cancel is seen */
static int wait_slice(const qmi_transport_t *t, long left) {
    if (t->opening && left > OPEN_CANCEL_POLL_MS)
        return OPEN_CANCEL_POLL_MS;
    return (int) left;
}

/* The uid a proxy must run as.  The real ones run as root; a listener run by
 * anyone else is refused, never used, and never a reason to open the node
 * directly instead (open=direct does that, when asked). */
#ifdef QMI_TRANSPORT_SELFTEST
static uid_t proxy_uid = 0;
static char proxy_prefix[64] = "";

void qmi_transport_selftest_proxy(const char *prefix, uid_t uid) {
    snprintf(proxy_prefix, sizeof(proxy_prefix), "%s", prefix != NULL ? prefix : "");
    proxy_uid = uid;
}
#else
static const uid_t proxy_uid = 0;
static const char proxy_prefix[] = "";
#endif

const char *qmi_transport_kind_name(qmi_transport_kind_t kind) {
    switch (kind) {
        case QMI_T_DIRECT_QMUX: return "QMI";
        case QMI_T_DIRECT_MBIM: return "QMI over MBIM";
        case QMI_T_PROXY_QMUX: return "QMI via qmi-proxy";
        case QMI_T_PROXY_MBIM: return "QMI over MBIM via mbim-proxy";
        default: return "none";
    }
}

static long now_ms(void) {
    struct timespec ts;
    clock_gettime(CLOCK_MONOTONIC, &ts);
    return (long) ts.tv_sec * 1000L + ts.tv_nsec / 1000000L;
}

static int is_mbim(const qmi_transport_t *t) {
    return t->kind == QMI_T_DIRECT_MBIM || t->kind == QMI_T_PROXY_MBIM;
}

static void seterr(char *err, size_t errsz, const char *fmt, ...)
    __attribute__((format(printf, 3, 4)));

static void seterr(char *err, size_t errsz, const char *fmt, ...) {
    va_list ap;

    if (err == NULL || errsz == 0)
        return;
    va_start(ap, fmt);
    vsnprintf(err, errsz, fmt, ap);
    va_end(ap);
}

static ssize_t raw_write(int fd, int is_socket, const uint8_t *b, size_t n) {
    return is_socket ? send(fd, b, n, MSG_NOSIGNAL) : write(fd, b, n);
}

/* A node takes each write() as one whole message, so a message is written
 * in one call; a socket may take it in pieces. */
static int write_all(qmi_transport_t *t, const uint8_t *b, size_t n,
                     int timeout_ms, char *err, size_t errsz) {
    const long deadline = now_ms() + timeout_ms;
    const size_t total = n;

    while (n > 0) {
        /* Once part of a message is out, all of it goes */
        if (n == total && open_cancelled(t)) {
            seterr(err, errsz, "the open was cancelled");
            return 0;
        }

        const ssize_t w = raw_write(t->fd, t->is_socket, b, n);

        if (w > 0) {
            b += w;
            n -= (size_t) w;
            continue;
        }

        if (w < 0 && errno == EINTR)
            continue;

        if (w < 0 && (errno == EAGAIN || errno == EWOULDBLOCK)) {
            const long left = deadline - now_ms();
            struct pollfd p = { .fd = t->fd, .events = POLLOUT };
            if (left <= 0) {
                seterr(err, errsz, "write timed out");
                return 0;
            }
            if (poll(&p, 1, wait_slice(t, left)) < 0 && errno != EINTR) {
                seterr(err, errsz, "poll failed: %s", strerror(errno));
                return 0;
            }
            continue;
        }

        seterr(err, errsz, "write failed: %s", w < 0 ? strerror(errno) : "short write");
        return 0;
    }

    t->sent++;
    return 1;
}

/* The next whole message in the receive buffer: 1 got one, 0 need more,
 * -1 the stream is out of sync */
static int rx_pop(qmi_transport_t *t, uint8_t *out, size_t cap, size_t *outlen) {
    int bad = 0;
    const size_t n = is_mbim(t) ? mbim_frame_len(t->rx, t->rxlen, &bad) :
        qmux_frame_len(t->rx, t->rxlen, &bad);

    if (bad) {
        /* A node hands over one message per read, so junk is dropped whole;
         * a proxy's stream has no boundary left to find */
        if (!t->is_socket) {
            t->rxlen = 0;
            return 0;
        }
        return -1;
    }

    if (n == 0)
        return 0;

    if (n <= cap) {
        memcpy(out, t->rx, n);
        *outlen = n;
    } else {
        *outlen = 0;
    }

    memmove(t->rx, t->rx + n, t->rxlen - n);
    t->rxlen -= n;

    return *outlen > 0 ? 1 : 0;
}

/* One message, waiting until `deadline`: 1 got one, 0 timed out, -1 failed */
static int rx_next(qmi_transport_t *t, uint8_t *out, size_t cap, size_t *outlen,
                   long deadline, char *err, size_t errsz) {
    for (;;) {
        const int r = rx_pop(t, out, cap, outlen);
        if (r == 1)
            return 1;
        if (r < 0) {
            seterr(err, errsz, "lost message framing on the proxy connection");
            return -1;
        }

        if (open_cancelled(t)) {
            if (!t->hold_cancel) {
                seterr(err, errsz, "the open was cancelled");
                return -1;
            }
            /* A client id request is out: its grant must be read to be
             * released, so wait a little longer for it */
            if (t->cancel_by == 0)
                t->cancel_by = now_ms() + QMI_CANCEL_HOLD_MS;
            if (deadline > t->cancel_by)
                deadline = t->cancel_by;
        }

        const long left = deadline - now_ms();
        if (left <= 0)
            return 0;

        struct pollfd p = { .fd = t->fd, .events = POLLIN };
        const int pr = poll(&p, 1, wait_slice(t, left));
        if (pr < 0) {
            if (errno == EINTR)
                continue;
            seterr(err, errsz, "poll failed: %s", strerror(errno));
            return -1;
        }
        if (pr == 0)
            continue;
        if (p.revents & POLLNVAL) {
            seterr(err, errsz, "the control node was closed");
            return -1;
        }

        if (t->rxlen == sizeof(t->rx))
            t->rxlen = 0;

        const ssize_t n = read(t->fd, t->rx + t->rxlen, sizeof(t->rx) - t->rxlen);
        if (n == 0) {
            seterr(err, errsz, t->is_socket ? "the proxy closed the connection" :
                   "the control node went away");
            return -1;
        }
        if (n < 0) {
            if (errno == EINTR || errno == EAGAIN || errno == EWOULDBLOCK)
                continue;
            if (errno == ECONNRESET)
                seterr(err, errsz, "the proxy reset the connection (it accepts "
                       "only clients running as root)");
            else
                seterr(err, errsz, "read failed: %s", strerror(errno));
            return -1;
        }

        t->rxlen += (size_t) n;
    }
}

/* Remember a NAS client id grant found where another reply was expected
 * (whole message `msg`, in the transport's framing): it may answer a request
 * that timed out, whose id must still be released */
static void note_alloc_reply(qmi_transport_t *t, const uint8_t *msg, size_t n) {
    qmux_msg_t m;
    uint8_t cid;

    if (is_mbim(t)) {
        mbim_msg_t mm;
        if (!mbim_parse(msg, n, &mm) || mm.type != MBIM_COMMAND_DONE || mm.status != 0 ||
            memcmp(mm.uuid, mbim_uuid_qmi, 16) != 0 || mm.cid != MBIM_CID_QMI_MSG ||
            !qmux_parse(mm.info, mm.info_len, &m))
            return;
    } else if (!qmux_parse(msg, n, &m)) {
        return;
    }

    if (m.service != QMI_SVC_CTL || m.msg_id != QMI_CTL_GET_CLIENT_ID ||
        !m.is_response || m.is_indication || m.tid == 0 || m.tid > 0xFF ||
        !qmi_ctl_alloc_parse(&m, QMI_SVC_NAS, &cid) || cid == 0)
        return;

    for (int i = 0; i < t->nlate; i++)
        if (t->late[i].tid == (uint8_t) m.tid)
            return;
    if (t->nlate < QMI_REC_SLOTS) {
        t->late[t->nlate].tid = (uint8_t) m.tid;
        t->late[t->nlate].cid = cid;
        t->nlate++;
    }
}

/* Discard what a node held before this open: old replies, and indications
 * for clients nobody released, which the modem queues while the node is
 * closed and can be hundreds deep.  Client id grants among them are noted. */
static void drain(qmi_transport_t *t) {
    uint8_t junk[QMI_MSG_MAX];
    const long deadline = now_ms() + 2000;

    while (now_ms() < deadline && !open_cancelled(t)) {
        struct pollfd p = { .fd = t->fd, .events = POLLIN };
        if (poll(&p, 1, 150) <= 0)
            break;
        const ssize_t n = read(t->fd, junk, sizeof(junk));
        if (n <= 0)
            break;

        /* A node hands over one message per read, a pty can join several */
        for (size_t off = 0; off < (size_t) n;) {
            int bad = 0;
            const size_t left = (size_t) n - off;
            const size_t fl = is_mbim(t) ? mbim_frame_len(junk + off, left, &bad) :
                qmux_frame_len(junk + off, left, &bad);
            if (bad || fl == 0 || fl > left)
                break;
            note_alloc_reply(t, junk + off, fl);
            off += fl;
        }
    }

    t->rxlen = 0;
}

static uint32_t next_mbim_tid(qmi_transport_t *t) {
    t->mbim_tid++;
    if (t->mbim_tid == 0 || t->mbim_tid >= MBIM_TID_WRAP)
        t->mbim_tid = 1;
    return t->mbim_tid;
}

/* Send a prebuilt MBIM message and wait for the COMMAND_DONE (or OPEN_DONE,
 * CLOSE_DONE) carrying transaction `tid`.  `uuid` NULL accepts any service. */
static int mbim_exchange(qmi_transport_t *t, const uint8_t *msg, size_t len,
                         uint32_t tid, uint32_t want_type, const uint8_t *uuid,
                         uint32_t cid, uint8_t *buf, size_t cap, mbim_msg_t *done,
                         int timeout_ms, char *err, size_t errsz) {
    const long deadline = now_ms() + timeout_ms;
    size_t n;

    if (!write_all(t, msg, len, timeout_ms, err, errsz))
        return -1;

    for (;;) {
        const int r = rx_next(t, buf, cap, &n, deadline, err, errsz);
        if (r <= 0)
            return r;

        /* A reply larger than the function's maximum control transfer comes
         * in fragments: join them, then read the whole message */
        if (mbim_is_fragment(buf, n)) {
            const int a = mbim_reasm_add(&t->reasm, buf, n);
            if (a != 1 || t->reasm.len > cap)
                continue;
            memcpy(buf, t->reasm.buf, t->reasm.len);
            n = t->reasm.len;
            mbim_reasm_reset(&t->reasm);
        }

        mbim_msg_t m;
        if (!mbim_parse(buf, n, &m))
            continue;
        if (m.tid != tid) {
            note_alloc_reply(t, buf, n);
            continue;
        }

        if (m.type == MBIM_FUNCTION_ERROR_MSG) {
            *done = m;
            seterr(err, errsz, "MBIM function error %u", (unsigned int) m.status);
            return XFER_FUNCTION_ERROR;
        }

        if (m.type != want_type)
            continue;
        if (want_type == MBIM_COMMAND_DONE &&
            (memcmp(m.uuid, uuid, 16) != 0 || m.cid != cid))
            continue;

        *done = m;
        return 1;
    }
}

uint32_t mbim_open_max_transfer(int have_node_max, uint32_t node_max) {
    if (!have_node_max)
        return MBIM_MAX_CONTROL_TRANSFER;
    if (node_max < MBIM_MIN_CONTROL_TRANSFER)
        return MBIM_MIN_CONTROL_TRANSFER;
    return node_max < MBIM_MAX_CONTROL_TRANSFER ? node_max : MBIM_MAX_CONTROL_TRANSFER;
}

/* The largest control transfer to ask for in MBIM_OPEN: no more than the
 * node's own buffer (mbim_open_max_transfer) */
static uint32_t mbim_max_transfer(const qmi_transport_t *t) {
#if defined(__linux__) && defined(IOCTL_WDM_MAX_COMMAND)
    uint16_t node_max = 0;

    if (!t->is_socket && ioctl(t->fd, IOCTL_WDM_MAX_COMMAND, &node_max) == 0)
        return mbim_open_max_transfer(1, node_max);
#else
    (void) t;
#endif
    return mbim_open_max_transfer(0, 0);
}

static int mbim_open_function(qmi_transport_t *t, int timeout_ms, char *err,
                              size_t errsz) {
    uint8_t msg[32], buf[QMI_MSG_MAX];
    mbim_msg_t done;
    const uint32_t tid = next_mbim_tid(t);
    const size_t len = mbim_open_build(msg, sizeof(msg), tid, mbim_max_transfer(t));

    const int r = mbim_exchange(t, msg, len, tid, MBIM_OPEN_DONE, NULL, 0, buf,
                                sizeof(buf), &done, timeout_ms, err, errsz);
    if (r == 0)
        seterr(err, errsz, "no answer to MBIM_OPEN");
    if (r != 1)
        return 0;
    if (done.status != 0) {
        seterr(err, errsz, "MBIM_OPEN failed, status %u", (unsigned int) done.status);
        return 0;
    }

    t->mbim_opened = 1;
    t->mbim_ready = 1;
    return 1;
}

/* Does the QMUX response `m` answer request `q`? */
static int qmux_answers(const qmux_msg_t *q, const qmux_msg_t *m) {
    if (m->is_indication || !m->is_response)
        return 0;
    if (m->service != q->service || m->msg_id != q->msg_id)
        return 0;
    if (q->service != QMI_SVC_CTL && m->client != q->client)
        return 0;
    /* Some firmware answers CTL with transaction id 0 */
    return m->tid == q->tid || (q->service == QMI_SVC_CTL && m->tid == 0);
}

static int xfer_mbim_once(qmi_transport_t *t, const qmux_msg_t *q,
                          const uint8_t *req, size_t reqlen, uint8_t *rsp,
                          size_t cap, size_t *rsplen, int timeout_ms, char *err,
                          size_t errsz) {
    uint8_t msg[QMI_MSG_MAX], buf[QMI_MSG_MAX];
    mbim_msg_t done;
    const uint32_t tid = next_mbim_tid(t);
    const size_t len = mbim_command_build(msg, sizeof(msg), tid, mbim_uuid_qmi,
                                          MBIM_CID_QMI_MSG, MBIM_COMMAND_TYPE_SET,
                                          req, reqlen);
    if (len == 0) {
        seterr(err, errsz, "request too large for MBIM");
        return -1;
    }

    const int r = mbim_exchange(t, msg, len, tid, MBIM_COMMAND_DONE, mbim_uuid_qmi,
                                MBIM_CID_QMI_MSG, buf, sizeof(buf), &done,
                                timeout_ms, err, errsz);
    if (r == XFER_FUNCTION_ERROR && done.status == MBIM_ERROR_NOT_OPENED)
        return XFER_FUNCTION_ERROR;
    if (r != 1)
        return r == XFER_FUNCTION_ERROR ? -1 : r;

    if (done.status != 0) {
        seterr(err, errsz, "the modem does not carry QMI over MBIM (status %u); "
               "it needs a native MBIM source", (unsigned int) done.status);
        return -1;
    }

    qmux_msg_t m;
    if (done.info_len > cap || !qmux_parse(done.info, done.info_len, &m) ||
        !qmux_answers(q, &m)) {
        seterr(err, errsz, "the MBIM reply did not carry the QMI response");
        return -1;
    }

    memcpy(rsp, done.info, done.info_len);
    *rsplen = done.info_len;
    return 1;
}

/* Send one QMUX request, wait for its response: 1, 0 timeout, -1 failure.
 *
 * With `backlog_max_ms` 0 the wait ends `timeout_ms` after the request.
 * Otherwise `timeout_ms` is how long the node may stay quiet: each message
 * that is not the reply moves the deadline to `timeout_ms` after it, up to
 * `backlog_max_ms` after the request.  A cold cdc-wdm node delivers what it
 * queued for unreleased clients first, one message per interrupt poll
 * (32 ms on qmi_wwan), so the reply can arrive many seconds late on a node
 * that is busy the whole time, while a node that says nothing still fails
 * after `timeout_ms`. */
static int xfer(qmi_transport_t *t, const uint8_t *req, size_t reqlen,
                uint8_t *rsp, size_t cap, size_t *rsplen, int timeout_ms,
                int backlog_max_ms, char *err, size_t errsz) {
    qmux_msg_t q;

    if (!qmux_parse(req, reqlen, &q)) {
        seterr(err, errsz, "malformed request");
        return -1;
    }

    if ((t->kind == QMI_T_PROXY_QMUX || t->kind == QMI_T_PROXY_MBIM) &&
        qmux_is_ctl_sync(req, reqlen)) {
        seterr(err, errsz, "refusing to send CTL Sync through a proxy");
        return -1;
    }

    if (is_mbim(t)) {
        if (t->kind == QMI_T_DIRECT_MBIM && !t->mbim_ready) {
            /* Ask before opening: an open function answers, and opening it
             * again would reset it under whoever opened it */
            const int r = xfer_mbim_once(t, &q, req, reqlen, rsp, cap, rsplen,
                                         MBIM_PROBE_MS, err, errsz);
            if (r == 1) {
                t->mbim_ready = 1;
                return 1;
            }
            if (r != 0 && r != XFER_FUNCTION_ERROR)
                return r;
            if (!mbim_open_function(t, timeout_ms, err, errsz))
                return -1;
        }

        const int r = xfer_mbim_once(t, &q, req, reqlen, rsp, cap, rsplen,
                                     timeout_ms, err, errsz);
        return r == XFER_FUNCTION_ERROR ? -1 : r;
    }

    if (!write_all(t, req, reqlen, timeout_ms, err, errsz))
        return -1;

    const long start = now_ms();
    const long hard = start + (backlog_max_ms > timeout_ms ? backlog_max_ms : timeout_ms);
    long deadline = start + timeout_ms;
    for (;;) {
        size_t n;
        const int r = rx_next(t, rsp, cap, &n, deadline, err, errsz);
        if (r <= 0)
            return r;

        qmux_msg_t m;
        if (!qmux_parse(rsp, n, &m) || !qmux_answers(&q, &m)) {
            note_alloc_reply(t, rsp, n);
            if (backlog_max_ms > 0) {
                const long quiet = now_ms() + timeout_ms;
                deadline = quiet < hard ? quiet : hard;
            }
            continue;
        }

        *rsplen = n;
        return 1;
    }
}

/* 1 if the listener on `fd` runs as proxy_uid */
static int proxy_peer_ok(int fd, const char *name, char *err, size_t errsz) {
    /* Linux's struct ucred; OpenBSD has SO_PEERCRED with another struct, and
     * every BSD and macOS has getpeereid() */
#if defined(__linux__)
    struct ucred cred;
    socklen_t cl = sizeof(cred);

    memset(&cred, 0, sizeof(cred));
    const int r = getsockopt(fd, SOL_SOCKET, SO_PEERCRED, &cred, &cl);
    if (r != 0 || cl != sizeof(cred)) {
        seterr(err, errsz, "@%s: cannot tell who runs it (%s); refusing it", name,
               r != 0 ? strerror(errno) : "short credentials");
        return 0;
    }
    const uid_t uid = cred.uid;
    const int pid = (int) cred.pid;
#else
    uid_t uid;
    gid_t gid;

    if (getpeereid(fd, &uid, &gid) != 0) {
        seterr(err, errsz, "@%s: cannot tell who runs it (%s); refusing it", name,
               strerror(errno));
        return 0;
    }
    const int pid = 0;
#endif

    if (uid == proxy_uid)
        return 1;

    seterr(err, errsz, "@%s is run by uid %u (pid %d), but the real proxy runs as "
           "root; refusing it.  Stop that process, or set open=direct", name,
           (unsigned int) uid, pid);
    return 0;
}

static int proxy_connect(qmi_transport_t *t, const char *proxy, char *err,
                         size_t errsz) {
    struct sockaddr_un a;
    char name[sizeof(a.sun_path) - 1];
    const int nl = snprintf(name, sizeof(name), "%s%s", proxy_prefix, proxy);

    if (nl < 0 || (size_t) nl >= sizeof(name)) {
        seterr(err, errsz, "proxy name too long");
        return 0;
    }

#ifdef SOCK_CLOEXEC
    const int fd = socket(AF_UNIX, SOCK_STREAM | SOCK_CLOEXEC, 0);
#else
    /* macOS has no SOCK_CLOEXEC; set the flag right after */
    const int fd = socket(AF_UNIX, SOCK_STREAM, 0);
    if (fd >= 0)
        fcntl(fd, F_SETFD, FD_CLOEXEC);
#endif
    if (fd < 0) {
        seterr(err, errsz, "socket: %s", strerror(errno));
        return 0;
    }

    /* Non-blocking first: a listener that never accepts would otherwise hold
     * connect() once its backlog is full */
    fcntl(fd, F_SETFL, fcntl(fd, F_GETFL) | O_NONBLOCK);

    memset(&a, 0, sizeof(a));
    a.sun_family = AF_UNIX;
    memcpy(a.sun_path + 1, name, (size_t) nl);     /* abstract: leading NUL */
    const socklen_t alen = (socklen_t) (offsetof(struct sockaddr_un, sun_path) + 1 +
                                        (size_t) nl);

    if (connect(fd, (struct sockaddr *) &a, alen) < 0) {
        if (errno == EAGAIN || errno == EWOULDBLOCK || errno == EINPROGRESS)
            seterr(err, errsz, "@%s is not accepting connections", name);
        else
            seterr(err, errsz, "@%s: %s (this source never starts a proxy)", name,
                   strerror(errno));
        close(fd);
        return 0;
    }

    /* Before anything is sent: not even the node's path goes to a listener
     * that is not the proxy */
    if (!proxy_peer_ok(fd, name, err, errsz)) {
        close(fd);
        return 0;
    }

    t->fd = fd;
    t->is_socket = 1;
    return 1;
}

static int proxy_qmux_open(qmi_transport_t *t, const char *dev, int timeout_ms,
                           char *err, size_t errsz) {
    uint8_t req[300], rsp[QMI_MSG_MAX];
    const size_t len = qmi_ctl_proxy_open_build(req, sizeof(req), 1, dev);

    if (len == 0) {
        seterr(err, errsz, "device path too long");
        return 0;
    }

    if (!write_all(t, req, len, timeout_ms, err, errsz))
        return 0;

    const long deadline = now_ms() + timeout_ms;
    for (;;) {
        size_t n;
        const int r = rx_next(t, rsp, sizeof(rsp), &n, deadline, err, errsz);
        if (r == 0) {
            seterr(err, errsz, "@qmi-proxy did not answer the open of %s", dev);
            return 0;
        }
        if (r < 0) {
            /* The proxy hangs up on a node it cannot open */
            seterr(err, errsz, "@qmi-proxy could not open %s", dev);
            return 0;
        }

        qmux_msg_t m;
        uint16_t code = 0;
        if (!qmux_parse(rsp, n, &m) || m.service != QMI_SVC_CTL ||
            m.msg_id != QMI_CTL_PROXY_OPEN || !m.is_response)
            continue;     /* unsolicited frames may come first */

        if (qmi_result(&m, &code) != 1) {
            seterr(err, errsz, "@qmi-proxy refused %s (QMI error %u)", dev,
                   (unsigned int) code);
            return 0;
        }
        return 1;
    }
}

static int proxy_mbim_open(qmi_transport_t *t, const char *dev, int timeout_ms,
                           char *err, size_t errsz) {
    uint8_t msg[700], buf[QMI_MSG_MAX];
    mbim_msg_t done;
    const uint32_t tid = next_mbim_tid(t);
    const size_t len = mbim_proxy_config_build(msg, sizeof(msg), tid, dev,
                                               MBIM_PROXY_TIMEOUT_S);
    if (len == 0) {
        seterr(err, errsz, "device path too long");
        return 0;
    }

    /* The proxy opens the node itself on its first client, which takes a
     * moment longer than a command */
    const int r = mbim_exchange(t, msg, len, tid, MBIM_COMMAND_DONE,
                                mbim_uuid_proxy_control, MBIM_CID_PROXY_CONFIG,
                                buf, sizeof(buf), &done,
                                timeout_ms + MBIM_PROXY_TIMEOUT_S * 1000, err, errsz);
    if (r == 0) {
        seterr(err, errsz, "@mbim-proxy did not answer the open of %s", dev);
        return 0;
    }
    if (r < 0) {
        seterr(err, errsz, "@mbim-proxy could not open %s", dev);
        return 0;
    }
    if (done.status != 0) {
        seterr(err, errsz, "@mbim-proxy refused %s (status %u)", dev,
               (unsigned int) done.status);
        return 0;
    }
    return 1;
}

static int transport_open(qmi_transport_t *t, const char *dev,
                          qmi_transport_kind_t kind, int timeout_ms, const dev_t *rdev,
                          char *err, size_t errsz) {
    struct stat st;

    memset(t, 0, sizeof(*t));
    t->fd = -1;
    t->kind = kind;
    t->opening = 1;

    if (kind == QMI_T_PROXY_QMUX) {
        if (!proxy_connect(t, "qmi-proxy", err, errsz))
            return 0;
        if (!proxy_qmux_open(t, dev, timeout_ms, err, errsz)) {
            close(t->fd);
            t->fd = -1;
            return 0;
        }
        return 1;
    }

    if (kind == QMI_T_PROXY_MBIM) {
        if (!proxy_connect(t, "mbim-proxy", err, errsz))
            return 0;
        if (!proxy_mbim_open(t, dev, timeout_ms, err, errsz)) {
            close(t->fd);
            t->fd = -1;
            return 0;
        }
        return 1;
    }

    t->fd = open(dev, O_RDWR | O_NONBLOCK | O_NOCTTY | O_CLOEXEC | O_NOFOLLOW);
    if (t->fd < 0) {
        seterr(err, errsz, "open %s: %s", dev, strerror(errno));
        return 0;
    }

    /* Nothing is written to a node that changed since it was checked */
    if (fstat(t->fd, &st) != 0 || !S_ISCHR(st.st_mode) ||
        (rdev != NULL && st.st_rdev != *rdev)) {
        seterr(err, errsz, "%s is no longer the control node that was checked", dev);
        close(t->fd);
        t->fd = -1;
        return 0;
    }

    /* The Kismet cell sources keep apart by flock() */
    if (flock(t->fd, LOCK_EX | LOCK_NB) < 0) {
        seterr(err, errsz, "%s is in use by another Kismet cell source", dev);
        close(t->fd);
        t->fd = -1;
        return 0;
    }

    drain(t);
    return 1;
}

static int slot_has(const uint8_t *slots, uint8_t v) {
    for (int i = 0; i < QMI_REC_SLOTS; i++)
        if (slots[i] == v)
            return 1;
    return 0;
}

/* Add `v` (non-zero); with every slot taken, the oldest is forgotten */
static void slot_add(uint8_t *slots, uint8_t v) {
    if (slot_has(slots, v))
        return;
    for (int i = 0; i < QMI_REC_SLOTS; i++) {
        if (slots[i] == 0) {
            slots[i] = v;
            return;
        }
    }
    memmove(slots, slots + 1, QMI_REC_SLOTS - 1);
    slots[QMI_REC_SLOTS - 1] = v;
}

static void slot_del(uint8_t *slots, uint8_t v) {
    for (int i = 0; i < QMI_REC_SLOTS; i++)
        if (slots[i] == v)
            slots[i] = 0;
}

/* Never the id of a request still waited for, whose late answer would be
 * taken for this one's */
static uint8_t next_ctl_tid(qmi_session_t *s) {
    do {
        s->ctl_tid++;
        if (s->ctl_tid == 0 || s->ctl_tid >= CTL_TID_RELEASE)
            s->ctl_tid = 1;
    } while (slot_has(s->wait, s->ctl_tid));
    return s->ctl_tid;
}

static void record_save(qmi_session_t *s);

/* Grants noted while waiting for other replies: those answering a request
 * in `wait` move to `held`, to be released.  `answered`: a later client id
 * request was just answered, and as the modem answers in order, a request
 * still waited for never will be. */
static void settle_late(qmi_session_t *s, int answered) {
    for (int i = 0; i < s->t.nlate; i++) {
        if (slot_has(s->wait, s->t.late[i].tid)) {
            slot_del(s->wait, s->t.late[i].tid);
            slot_add(s->held, s->t.late[i].cid);
        }
    }
    s->t.nlate = 0;

    if (answered) {
        for (int i = 0; i < QMI_REC_SLOTS; i++)
            s->waits_dropped += s->wait[i] != 0;
        memset(s->wait, 0, sizeof(s->wait));
    }
    record_save(s);
}

/* Release every id in `held`.  One whose release was never sent (a cancel,
 * or a write that timed out) stays held, and recorded. */
static void release_held(qmi_session_t *s, int timeout_ms, int backlog_max_ms,
                         int late) {
    char err[128];

    for (int i = 0; i < QMI_REC_SLOTS; i++) {
        uint8_t req[32], rsp[QMI_MSG_MAX];
        size_t rl = 0;
        qmux_msg_t m;
        uint16_t code = 0;
        const uint8_t cid = s->held[i];

        if (cid == 0 || (s->have_cid && cid == s->nas_cid))
            continue;

        const size_t len = qmi_ctl_release_build(req, sizeof(req), next_ctl_tid(s),
                                                 QMI_SVC_NAS, cid);
        const uint32_t sent = s->t.sent;
        const int r = xfer(&s->t, req, len, rsp, sizeof(rsp), &rl, timeout_ms,
                           backlog_max_ms, err, sizeof(err));
        if (s->t.sent == sent)
            continue;

        /* Whatever the modem answers, it is not released again: an id that
         * was already free may since have gone to someone else */
        s->held[i] = 0;
        if (late) {
            s->late_released++;
        } else {
            s->stale_released = 1;
            s->stale_cid = cid;
            s->stale_answered = r == 1 && qmux_parse(rsp, rl, &m) &&
                qmi_result(&m, &code) == 1;
        }
        record_save(s);
    }
}

static uint16_t next_nas_tid(qmi_session_t *s) {
    s->nas_tid++;
    if (s->nas_tid == 0)
        s->nas_tid = 1;
    return s->nas_tid;
}

/* 1 allocated, 0 refused or timed out, -1 transport failure */
static int alloc_nas(qmi_session_t *s, int timeout_ms, char *err, size_t errsz) {
    uint8_t req[32], rsp[QMI_MSG_MAX];
    size_t rl = 0;
    qmux_msg_t m;
    uint16_t code = 0;

    /* Recorded before it goes out, until answered: a grant nobody reads
     * would leave the id allocated */
    const uint8_t tid = next_ctl_tid(s);
    const size_t len = qmi_ctl_alloc_build(req, sizeof(req), tid, QMI_SVC_NAS);
    slot_add(s->wait, tid);
    record_save(s);

    /* The first request on a cold node: its reply can sit behind a backlog.
     * Once it is sent, a cancel waits for the answer (QMI_CANCEL_HOLD_MS). */
    const uint32_t sent = s->t.sent;
    s->t.hold_cancel = 1;
    const int r = xfer(&s->t, req, len, rsp, sizeof(rsp), &rl, timeout_ms,
                       QMI_OPEN_BACKLOG_MAX_MS, err, errsz);
    s->t.hold_cancel = 0;

    if (s->t.sent == sent) {
        slot_del(s->wait, tid);
        record_save(s);
    }
    if (r == 0) {
        settle_late(s, 0);
        seterr(err, errsz, "no answer to the NAS client id request");
        return 0;
    }
    if (r < 0) {
        settle_late(s, 0);
        return -1;
    }

    slot_del(s->wait, tid);
    if (qmux_parse(rsp, rl, &m) && qmi_ctl_alloc_parse(&m, QMI_SVC_NAS, &s->nas_cid) &&
        s->nas_cid != 0) {
        s->have_cid = 1;
        slot_del(s->held, s->nas_cid);
        settle_late(s, 1);
        return 1;
    }
    settle_late(s, 1);

    qmux_parse(rsp, rl, &m);
    qmi_result(&m, &code);
    seterr(err, errsz, "the modem refused a NAS client id (QMI error %u)",
           (unsigned int) code);
    return 0;
}

/* What qmi_session_release_now() writes: built once, while it is safe to */
static void prebuild_release(qmi_session_t *s) {
    uint8_t qmux[32];
    const size_t ql = qmi_ctl_release_build(qmux, sizeof(qmux), CTL_TID_RELEASE,
                                            QMI_SVC_NAS, s->nas_cid);

    s->release_len = 0;
    s->close_len = 0;

    if (is_mbim(&s->t)) {
        s->release_len = mbim_command_build(s->release_bytes, sizeof(s->release_bytes),
                                            MBIM_TID_RELEASE, mbim_uuid_qmi,
                                            MBIM_CID_QMI_MSG, MBIM_COMMAND_TYPE_SET,
                                            qmux, ql);
        if (s->t.mbim_opened)
            s->close_len = mbim_close_build(s->close_bytes, sizeof(s->close_bytes),
                                            MBIM_TID_CLOSE);
    } else if (ql <= sizeof(s->release_bytes)) {
        memcpy(s->release_bytes, qmux, ql);
        s->release_len = ql;
    }
}

/* The client id record: one line naming the node, the session's own id, the
 * ids still to release and the CTL transaction ids of client id requests
 * not yet answered (0 empty).  An empty file holds nothing.  Version 1 held
 * only the one id. */
#define CID_RECORD_V1 "cellqmi-cid 1 %llu %llu %lld %ld %u %u\n"
#define CID_RECORD_V2 "cellqmi-cid 2 %llu %llu %lld %ld %u %u %u %u %u %u %u %u %u %u\n"
/* Read back as %llu, which saturates where %u wraps (2^32 + 9 would read as 9) */
#define CID_SCAN_V1 "cellqmi-cid 1 %llu %llu %lld %ld %llu %llu\n"
#define CID_SCAN_V2 "cellqmi-cid 2 %llu %llu %lld %ld %llu %llu %llu %llu %llu %llu %llu %llu %llu %llu\n"

#ifdef __APPLE__
#define ST_CTIME_SEC(st)  ((st)->st_ctimespec.tv_sec)
#define ST_CTIME_NSEC(st) ((st)->st_ctimespec.tv_nsec)
#else
#define ST_CTIME_SEC(st)  ((st)->st_ctim.tv_sec)
#define ST_CTIME_NSEC(st) ((st)->st_ctim.tv_nsec)
#endif

/* Load what the record holds for this very node (s->rec_*) into `held` and
 * `wait`: 1 if it named the node and held something valid */
static int cid_record_read(qmi_session_t *s) {
    char buf[192];
    const ssize_t n = pread(s->state_fd, buf, sizeof(buf) - 1, 0);
    unsigned long long rdev, ino;
    long long csec;
    long cnsec;
    unsigned long long svc, own, h[QMI_REC_SLOTS] = { 0 }, w[QMI_REC_SLOTS] = { 0 };

    if (n <= 0)
        return 0;
    buf[n] = '\0';

    if (sscanf(buf, CID_SCAN_V2, &rdev, &ino, &csec, &cnsec, &svc, &own, &h[0], &h[1],
               &h[2], &h[3], &w[0], &w[1], &w[2], &w[3]) != 14 &&
        sscanf(buf, CID_SCAN_V1, &rdev, &ino, &csec, &cnsec, &svc, &own) != 6)
        return 0;
    if (rdev != s->rec_rdev || ino != s->rec_ino || csec != s->rec_csec ||
        cnsec != s->rec_cnsec || svc != QMI_SVC_NAS || own > 0xFF)
        return 0;
    for (int i = 0; i < QMI_REC_SLOTS; i++)
        if (h[i] > 0xFF || w[i] >= CTL_TID_RELEASE)
            return 0;

    if (own != 0)
        slot_add(s->held, (uint8_t) own);
    for (int i = 0; i < QMI_REC_SLOTS; i++) {
        if (h[i] != 0)
            slot_add(s->held, (uint8_t) h[i]);
        if (w[i] != 0)
            slot_add(s->wait, (uint8_t) w[i]);
    }
    return 1;
}

/* The record line, with or without the session's own id: its length, 0
 * when it holds nothing */
static size_t record_format(const qmi_session_t *s, int with_own, char *buf,
                            size_t cap) {
    const unsigned int own = with_own && s->have_cid ? s->nas_cid : 0;
    int any = own != 0;

    for (int i = 0; i < QMI_REC_SLOTS; i++)
        any |= s->held[i] != 0 || s->wait[i] != 0;
    if (!any)
        return 0;

    const int n = snprintf(buf, cap, CID_RECORD_V2, s->rec_rdev, s->rec_ino, s->rec_csec,
                           s->rec_cnsec, (unsigned int) QMI_SVC_NAS, own,
                           (unsigned int) s->held[0], (unsigned int) s->held[1],
                           (unsigned int) s->held[2], (unsigned int) s->held[3],
                           (unsigned int) s->wait[0], (unsigned int) s->wait[1],
                           (unsigned int) s->wait[2], (unsigned int) s->wait[3]);
    return n > 0 && (size_t) n < cap ? (size_t) n : 0;
}

/* Async-signal-safe */
static void cid_record_clear(int fd) {
    if (fd < 0 || ftruncate(fd, 0) == 0)
        return;
    /* Not emptied: spoil it, so it is never read as a record */
    const ssize_t w = pwrite(fd, "-", 1, 0);
    (void) w;
}

/* Write the record as the session now stands, and keep the line without the
 * session's own id ready for qmi_session_release_now() */
static void record_save(qmi_session_t *s) {
    char buf[sizeof(s->rec_after)];

    if (s->state_fd < 0)
        return;

    s->rec_after_len = record_format(s, 0, s->rec_after, sizeof(s->rec_after));

    const size_t n = record_format(s, 1, buf, sizeof(buf));
    if (n == 0) {
        cid_record_clear(s->state_fd);
        return;
    }
    /* Not truncated, an older and longer record leaves bytes after the line,
     * which are never read */
    if (pwrite(s->state_fd, buf, n, 0) == (ssize_t) n) {
        const int tr = ftruncate(s->state_fd, (off_t) n);
        (void) tr;
    }
    (void) fsync(s->state_fd);
}

static int session_start(qmi_session_t *s, int via_proxy, int timeout_ms,
                         const char *state_path, char *err, size_t errsz);

int qmi_session_open(qmi_session_t *s, const char *dev, qmi_framing_t framing,
                     int via_proxy, int timeout_ms, char *err, size_t errsz) {
    return qmi_session_open_tracked(s, dev, framing, via_proxy, timeout_ms, NULL,
                                    NULL, err, errsz);
}

int qmi_session_open_tracked(qmi_session_t *s, const char *dev,
                             qmi_framing_t framing, int via_proxy, int timeout_ms,
                             const char *state_path, const dev_t *rdev, char *err,
                             size_t errsz) {
    qmi_transport_kind_t kind;

    memset(s, 0, sizeof(*s));
    s->t.fd = -1;
    s->state_fd = -1;

    if (framing == QMI_FRAMING_QMUX)
        kind = via_proxy ? QMI_T_PROXY_QMUX : QMI_T_DIRECT_QMUX;
    else if (framing == QMI_FRAMING_MBIM)
        kind = via_proxy ? QMI_T_PROXY_MBIM : QMI_T_DIRECT_MBIM;
    else {
        seterr(err, errsz, "unknown framing");
        return 0;
    }

    if (!transport_open(&s->t, dev, kind, timeout_ms, rdev, err, errsz))
        return 0;

    return session_start(s, via_proxy, timeout_ms, state_path, err, errsz);
}

/* The open after the transport: the client id record, then the NAS client */
static int session_start(qmi_session_t *s, int via_proxy, int timeout_ms,
                         const char *state_path, char *err, size_t errsz) {
    struct stat node;

    memset(&node, 0, sizeof(node));

    /* Only a direct open holds the node alone, so only it keeps a record */
    if (state_path != NULL && !via_proxy && fstat(s->t.fd, &node) == 0 &&
        S_ISCHR(node.st_mode)) {
        s->state_fd = cell_safe_op(CELL_SAFE_OPEN, state_path, NULL, O_RDWR | O_CREAT,
                                   0600, CELL_SAFE_MUST_OWN);
        s->rec_rdev = (unsigned long long) node.st_rdev;
        s->rec_ino = (unsigned long long) node.st_ino;
        s->rec_csec = (long long) ST_CTIME_SEC(&node);
        s->rec_cnsec = (long) ST_CTIME_NSEC(&node);
        if (s->state_fd >= 0 && !cid_record_read(s))
            cid_record_clear(s->state_fd);
    }

    /* Ids a dead session left, then grants the drain found for its requests,
     * go back before asking for one of our own */
    release_held(s, timeout_ms, QMI_OPEN_BACKLOG_MAX_MS, 0);
    settle_late(s, 0);
    release_held(s, timeout_ms, QMI_OPEN_BACKLOG_MAX_MS, 1);

    /* A modem just out of reset can refuse the first client id request */
    int r = alloc_nas(s, timeout_ms, err, errsz);
    if (r == 0 && !s->t.cancelled) {
        usleep(500 * 1000);
        r = alloc_nas(s, timeout_ms, err, errsz);
    }

    /* Grants that came late, to this open's requests or a dead session's */
    if (r == 1 && !s->t.cancelled)
        release_held(s, timeout_ms, 0, 1);

    if (s->t.cancelled) {
        /* An id granted after all is released by the close */
        seterr(err, errsz, "the open was cancelled");
        r = 0;
    }

    if (r != 1) {
        qmi_session_close(s);
        return 0;
    }

    prebuild_release(s);
    record_save(s);
    s->t.opening = 0;
    return 1;
}

int qmi_session_nas(qmi_session_t *s, uint16_t msg_id, uint8_t *buf, size_t cap,
                    qmux_msg_t *out, int timeout_ms, char *err, size_t errsz) {
    uint8_t req[32];
    size_t rl = 0;

    if (s->t.fd < 0 || !s->have_cid) {
        seterr(err, errsz, "session not open");
        return -1;
    }

    const size_t len = qmux_build(req, sizeof(req), QMI_SVC_NAS, s->nas_cid,
                                  next_nas_tid(s), msg_id, NULL, 0);
    const int r = xfer(&s->t, req, len, buf, cap, &rl, timeout_ms, 0, err, errsz);
    if (r != 1)
        return r;

    if (!qmux_parse(buf, rl, out)) {
        seterr(err, errsz, "malformed reply");
        return -1;
    }
    return 1;
}

void qmi_session_close(qmi_session_t *s) {
    char err[128];
    /* After a cancel the close fits what is left of the close grace */
    const int wait_ms = s->t.cancelled ? CANCELLED_CLOSE_MS : 1000;

    /* A close is never cancelled: the release must go out */
    s->t.opening = 0;

    if (s->t.fd < 0)
        return;

    if (s->have_cid) {
        uint8_t req[32], rsp[QMI_MSG_MAX];
        size_t rl = 0;
        const size_t len = qmi_ctl_release_build(req, sizeof(req), next_ctl_tid(s),
                                                 QMI_SVC_NAS, s->nas_cid);
        (void) xfer(&s->t, req, len, rsp, sizeof(rsp), &rl, wait_ms, 0, err, sizeof(err));
        s->have_cid = 0;
    }

    /* Ids still held after the open; after a cancel they wait in the
     * record for the next open */
    if (!s->t.cancelled)
        release_held(s, wait_ms, 0, 1);

    /* The session's own id leaves the record even when its release went
     * unanswered: a record of an id that was in fact released could later
     * free someone else's */
    if (s->state_fd >= 0) {
        record_save(s);
        close(s->state_fd);
        s->state_fd = -1;
    }

    if (s->t.kind == QMI_T_DIRECT_MBIM && s->t.mbim_opened) {
        uint8_t msg[16], buf[QMI_MSG_MAX];
        mbim_msg_t done;
        const uint32_t tid = next_mbim_tid(&s->t);
        const size_t len = mbim_close_build(msg, sizeof(msg), tid);
        (void) mbim_exchange(&s->t, msg, len, tid, MBIM_CLOSE_DONE, NULL, 0, buf,
                             sizeof(buf), &done, wait_ms, err, sizeof(err));
        s->t.mbim_opened = 0;
    }

    close(s->t.fd);
    s->t.fd = -1;
}

void qmi_session_release_now(const qmi_session_t *s) {
    if (s->t.fd < 0 || !s->have_cid)
        return;

    if (s->release_len > 0)
        (void) raw_write(s->t.fd, s->t.is_socket, s->release_bytes, s->release_len);
    if (s->close_len > 0)
        (void) raw_write(s->t.fd, s->t.is_socket, s->close_bytes, s->close_len);

    /* The record keeps whatever else it held */
    if (s->state_fd < 0)
        return;
    if (s->rec_after_len == 0) {
        cid_record_clear(s->state_fd);
    } else if (pwrite(s->state_fd, s->rec_after, s->rec_after_len, 0) ==
               (ssize_t) s->rec_after_len) {
        const int tr = ftruncate(s->state_fd, (off_t) s->rec_after_len);
        (void) tr;
    } else {
        cid_record_clear(s->state_fd);
    }
}

/* ------------------------------------------------------------ native MBIM */

static int devsvc_query(qmi_transport_t *t, uint8_t *buf, size_t cap, mbim_msg_t *done,
                        int timeout_ms, char *err, size_t errsz) {
    uint8_t msg[64];
    const uint32_t tid = next_mbim_tid(t);
    const size_t len = mbim_command_build(msg, sizeof(msg), tid, mbim_uuid_basic_connect,
                                          MBIM_CID_DEVICE_SERVICES,
                                          MBIM_COMMAND_TYPE_QUERY, NULL, 0);

    return mbim_exchange(t, msg, len, tid, MBIM_COMMAND_DONE, mbim_uuid_basic_connect,
                         MBIM_CID_DEVICE_SERVICES, buf, cap, done, timeout_ms, err, errsz);
}

int mbim_session_open(mbim_session_t *s, const char *dev, int via_proxy, int timeout_ms,
                      const dev_t *rdev, char *err, size_t errsz) {
    uint8_t buf[QMI_MSG_MAX];
    mbim_msg_t done;
    int r;

    memset(s, 0, sizeof(*s));
    s->t.fd = -1;

    if (!transport_open(&s->t, dev, via_proxy ? QMI_T_PROXY_MBIM : QMI_T_DIRECT_MBIM,
                        timeout_ms, rdev, err, errsz))
        return 0;

    if (via_proxy) {
        r = devsvc_query(&s->t, buf, sizeof(buf), &done, timeout_ms, err, errsz);
    } else {
        /* Ask before opening: an open function answers, and opening it again
         * would reset it under whoever opened it */
        r = devsvc_query(&s->t, buf, sizeof(buf), &done, MBIM_PROBE_MS, err, errsz);
        if (r == 0 || (r == XFER_FUNCTION_ERROR && done.status == MBIM_ERROR_NOT_OPENED)) {
            if (!mbim_open_function(&s->t, timeout_ms, err, errsz)) {
                mbim_session_close(s);
                return 0;
            }
            s->close_len = mbim_close_build(s->close_bytes, sizeof(s->close_bytes),
                                            MBIM_TID_CLOSE);
            r = devsvc_query(&s->t, buf, sizeof(buf), &done, timeout_ms, err, errsz);
        } else if (r == 1) {
            s->t.mbim_ready = 1;
        }
    }

    if (r == 0)
        seterr(err, errsz, "no answer to MBIM DEVICE_SERVICES");
    if (r != 1) {
        mbim_session_close(s);
        return 0;
    }
    if (done.status != 0 || !mbim_device_services_parse(done.info, done.info_len,
                                                        &s->caps)) {
        seterr(err, errsz, "MBIM DEVICE_SERVICES unreadable (status %u)",
               (unsigned int) done.status);
        mbim_session_close(s);
        return 0;
    }

    s->t.opening = 0;
    return 1;
}

int mbim_session_query(mbim_session_t *s, const uint8_t uuid[16], uint32_t cid,
                       const uint8_t *info, size_t info_len, uint8_t *buf, size_t cap,
                       mbim_msg_t *done, int timeout_ms, char *err, size_t errsz) {
    uint8_t msg[256];

    if (s->t.fd < 0) {
        seterr(err, errsz, "session not open");
        return -1;
    }

    const uint32_t tid = next_mbim_tid(&s->t);
    const size_t len = mbim_command_build(msg, sizeof(msg), tid, uuid, cid,
                                          MBIM_COMMAND_TYPE_QUERY, info, info_len);
    if (len == 0) {
        seterr(err, errsz, "request too large");
        return -1;
    }

    const int r = mbim_exchange(&s->t, msg, len, tid, MBIM_COMMAND_DONE, uuid, cid, buf,
                                cap, done, timeout_ms, err, errsz);
    return r == XFER_FUNCTION_ERROR ? -1 : r;
}

void mbim_session_close(mbim_session_t *s) {
    char err[128];
    const int wait_ms = s->t.cancelled ? CANCELLED_CLOSE_MS : 1000;

    s->t.opening = 0;

    if (s->t.fd < 0)
        return;

    if (s->t.kind == QMI_T_DIRECT_MBIM && s->t.mbim_opened) {
        uint8_t msg[16], buf[QMI_MSG_MAX];
        mbim_msg_t done;
        const uint32_t tid = next_mbim_tid(&s->t);
        const size_t len = mbim_close_build(msg, sizeof(msg), tid);
        (void) mbim_exchange(&s->t, msg, len, tid, MBIM_CLOSE_DONE, NULL, 0, buf,
                             sizeof(buf), &done, wait_ms, err, sizeof(err));
        s->t.mbim_opened = 0;
    }

    close(s->t.fd);
    s->t.fd = -1;
}

void mbim_session_close_now(const mbim_session_t *s) {
    if (s->t.fd < 0 || !s->t.mbim_opened || s->close_len == 0)
        return;
    (void) raw_write(s->t.fd, s->t.is_socket, s->close_bytes, s->close_len);
}

int qmi_session_adopt(qmi_session_t *s, mbim_session_t *m, int timeout_ms,
                      const char *state_path, char *err, size_t errsz) {
    if (m->t.fd < 0) {
        seterr(err, errsz, "MBIM session not open");
        return 0;
    }

    memset(s, 0, sizeof(*s));
    s->state_fd = -1;
    s->t = m->t;
    s->t.mbim_ready = 1;
    s->t.opening = 1;
    m->t.fd = -1;

    return session_start(s, s->t.kind == QMI_T_PROXY_MBIM, timeout_ms, state_path, err,
                         errsz);
}
