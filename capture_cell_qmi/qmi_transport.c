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
#include <sys/socket.h>
#include <sys/un.h>
#include <time.h>
#include <unistd.h>

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
#define MBIM_PROXY_TIMEOUT_S 10
/* How long a direct MBIM node gets to show it is already open */
#define MBIM_PROBE_MS 1500

/* mbim_exchange: the device answered with a function error */
#define XFER_FUNCTION_ERROR (-2)

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

    while (n > 0) {
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
            if (left <= 0 || poll(&p, 1, (int) left) <= 0) {
                seterr(err, errsz, "write timed out");
                return 0;
            }
            continue;
        }

        seterr(err, errsz, "write failed: %s", w < 0 ? strerror(errno) : "short write");
        return 0;
    }

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

        const long left = deadline - now_ms();
        if (left <= 0)
            return 0;

        struct pollfd p = { .fd = t->fd, .events = POLLIN };
        const int pr = poll(&p, 1, (int) left);
        if (pr < 0) {
            if (errno == EINTR)
                continue;
            seterr(err, errsz, "poll failed: %s", strerror(errno));
            return -1;
        }
        if (pr == 0)
            return 0;
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

/* Discard what a node held before this open: old replies, and indications
 * for clients nobody released, which the modem queues while the node is
 * closed and can be hundreds deep */
static void drain(qmi_transport_t *t) {
    uint8_t junk[QMI_MSG_MAX];
    const long deadline = now_ms() + 2000;

    while (now_ms() < deadline) {
        struct pollfd p = { .fd = t->fd, .events = POLLIN };
        if (poll(&p, 1, 150) <= 0)
            break;
        if (read(t->fd, junk, sizeof(junk)) <= 0)
            break;
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

        mbim_msg_t m;
        if (!mbim_parse(buf, n, &m) || m.tid != tid)
            continue;

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

static int mbim_open_function(qmi_transport_t *t, int timeout_ms, char *err,
                              size_t errsz) {
    uint8_t msg[32], buf[QMI_MSG_MAX];
    mbim_msg_t done;
    const uint32_t tid = next_mbim_tid(t);
    const size_t len = mbim_open_build(msg, sizeof(msg), tid, MBIM_MAX_CONTROL_TRANSFER);

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

static int proxy_connect(qmi_transport_t *t, const char *name, char *err,
                         size_t errsz) {
    struct sockaddr_un a;
    const size_t nl = strlen(name);

    if (nl + 1 > sizeof(a.sun_path)) {
        seterr(err, errsz, "proxy name too long");
        return 0;
    }

    const int fd = socket(AF_UNIX, SOCK_STREAM | SOCK_CLOEXEC, 0);
    if (fd < 0) {
        seterr(err, errsz, "socket: %s", strerror(errno));
        return 0;
    }

    memset(&a, 0, sizeof(a));
    a.sun_family = AF_UNIX;
    memcpy(a.sun_path + 1, name, nl);     /* abstract: leading NUL */
    const socklen_t alen = (socklen_t) (offsetof(struct sockaddr_un, sun_path) + 1 + nl);

    if (connect(fd, (struct sockaddr *) &a, alen) < 0) {
        seterr(err, errsz, "@%s: %s (this source never starts a proxy)", name,
               strerror(errno));
        close(fd);
        return 0;
    }

    fcntl(fd, F_SETFL, fcntl(fd, F_GETFL) | O_NONBLOCK);
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
                          qmi_transport_kind_t kind, int timeout_ms, char *err,
                          size_t errsz) {
    memset(t, 0, sizeof(*t));
    t->fd = -1;
    t->kind = kind;

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

    t->fd = open(dev, O_RDWR | O_NONBLOCK | O_NOCTTY | O_CLOEXEC);
    if (t->fd < 0) {
        seterr(err, errsz, "open %s: %s", dev, strerror(errno));
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

static uint8_t next_ctl_tid(qmi_session_t *s) {
    s->ctl_tid++;
    if (s->ctl_tid == 0 || s->ctl_tid >= CTL_TID_RELEASE)
        s->ctl_tid = 1;
    return s->ctl_tid;
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

    /* The first request on a cold node: its reply can sit behind a backlog */
    const size_t len = qmi_ctl_alloc_build(req, sizeof(req), next_ctl_tid(s), QMI_SVC_NAS);
    const int r = xfer(&s->t, req, len, rsp, sizeof(rsp), &rl, timeout_ms,
                       QMI_OPEN_BACKLOG_MAX_MS, err, errsz);
    if (r == 0) {
        seterr(err, errsz, "no answer to the NAS client id request");
        return 0;
    }
    if (r < 0)
        return -1;

    if (qmux_parse(rsp, rl, &m) && qmi_ctl_alloc_parse(&m, QMI_SVC_NAS, &s->nas_cid)) {
        s->have_cid = 1;
        return 1;
    }

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

int qmi_session_open(qmi_session_t *s, const char *dev, qmi_framing_t framing,
                     int via_proxy, int timeout_ms, char *err, size_t errsz) {
    qmi_transport_kind_t kind;

    memset(s, 0, sizeof(*s));
    s->t.fd = -1;

    if (framing == QMI_FRAMING_QMUX)
        kind = via_proxy ? QMI_T_PROXY_QMUX : QMI_T_DIRECT_QMUX;
    else if (framing == QMI_FRAMING_MBIM)
        kind = via_proxy ? QMI_T_PROXY_MBIM : QMI_T_DIRECT_MBIM;
    else {
        seterr(err, errsz, "unknown framing");
        return 0;
    }

    if (!transport_open(&s->t, dev, kind, timeout_ms, err, errsz))
        return 0;

    /* A modem just out of reset can refuse the first client id request */
    int r = alloc_nas(s, timeout_ms, err, errsz);
    if (r == 0) {
        usleep(500 * 1000);
        r = alloc_nas(s, timeout_ms, err, errsz);
    }

    if (r != 1) {
        qmi_session_close(s);
        return 0;
    }

    prebuild_release(s);
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

    if (s->t.fd < 0)
        return;

    if (s->have_cid) {
        uint8_t req[32], rsp[QMI_MSG_MAX];
        size_t rl = 0;
        const size_t len = qmi_ctl_release_build(req, sizeof(req), next_ctl_tid(s),
                                                 QMI_SVC_NAS, s->nas_cid);
        (void) xfer(&s->t, req, len, rsp, sizeof(rsp), &rl, 1000, 0, err, sizeof(err));
        s->have_cid = 0;
    }

    if (s->t.kind == QMI_T_DIRECT_MBIM && s->t.mbim_opened) {
        uint8_t msg[16], buf[QMI_MSG_MAX];
        mbim_msg_t done;
        const uint32_t tid = next_mbim_tid(&s->t);
        const size_t len = mbim_close_build(msg, sizeof(msg), tid);
        (void) mbim_exchange(&s->t, msg, len, tid, MBIM_CLOSE_DONE, NULL, 0, buf,
                             sizeof(buf), &done, 1000, err, sizeof(err));
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
}
