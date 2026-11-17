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

    A QMI session on one control node: the transport (the node itself, or a
    proxy daemon's socket; bare QMUX, or QMUX inside MBIM) and one NAS client
    id on it.

    Proxies:
      @qmi-proxy   takes a CTL 0xFF00 request naming the node, then carries
                   bare QMUX.  It rewrites CTL transaction ids and maps the
                   replies back.
      @mbim-proxy  takes an MBIM command on its control service naming the
                   node, then carries MBIM.  It answers MBIM_OPEN and
                   MBIM_CLOSE itself, so neither is sent through it.
    Both stream their messages: reads are split on the message length, not
    taken one per read().  Both accept only clients whose effective uid is 0.

    Client ids: neither a proxy nor the modem frees a client id when its
    holder dies, and each service has only a few.  The session releases its
    id on close, and keeps the release ready-built so a signal handler can
    send it with one write().

    Direct MBIM: MBIM_OPEN resets the function, which ends any data session
    another program set up on it.  The session asks first and opens the
    function only if the device answers that it is not open, and closes it
    afterwards only if it opened it.
*/

#ifndef __QMI_TRANSPORT_H__
#define __QMI_TRANSPORT_H__

#include <stddef.h>
#include <stdint.h>

#include "qmi_node.h"
#include "qmi_wire.h"

#ifdef __cplusplus
extern "C" {
#endif

typedef enum {
    QMI_T_NONE = 0,
    QMI_T_DIRECT_QMUX,
    QMI_T_DIRECT_MBIM,
    QMI_T_PROXY_QMUX,
    QMI_T_PROXY_MBIM,
} qmi_transport_kind_t;

typedef struct {
    int fd;
    int is_socket;
    qmi_transport_kind_t kind;
    uint8_t rx[2 * QMI_MSG_MAX];
    size_t rxlen;
    uint32_t mbim_tid;
    int mbim_ready;         /* direct MBIM: the function is known to be open */
    int mbim_opened;        /* direct MBIM: this session sent the MBIM_OPEN */
} qmi_transport_t;

typedef struct {
    qmi_transport_t t;
    uint8_t ctl_tid;
    uint16_t nas_tid;
    int have_cid;
    uint8_t nas_cid;
    /* Prebuilt for qmi_session_release_now(): the release, wrapped for the
     * transport, and the MBIM_CLOSE when the session opened the function */
    uint8_t release_bytes[128];
    size_t release_len;
    uint8_t close_bytes[16];
    size_t close_len;
} qmi_session_t;

/* Open `dev` (through its proxy when `via_proxy`) and allocate a NAS client
 * id.  1 on success; 0 with a reason in `err`. */
int qmi_session_open(qmi_session_t *s, const char *dev, qmi_framing_t framing,
                     int via_proxy, int timeout_ms, char *err, size_t errsz);

/* Send NAS request `msg_id` (no TLVs) and wait for its reply, which is parsed
 * into `out` and points into `buf`.  1 on a reply, 0 on a timeout, -1 if the
 * transport failed (`err` says how). */
int qmi_session_nas(qmi_session_t *s, uint16_t msg_id, uint8_t *buf, size_t cap,
                    qmux_msg_t *out, int timeout_ms, char *err, size_t errsz);

/* Release the client id, close the MBIM function if this session opened it,
 * and close the transport.  Safe to call twice. */
void qmi_session_close(qmi_session_t *s);

/* Async-signal-safe: write the prebuilt release (and MBIM_CLOSE) without
 * waiting for replies.  For a signal handler on the way out. */
void qmi_session_release_now(const qmi_session_t *s);

const char *qmi_transport_kind_name(qmi_transport_kind_t kind);

#ifdef __cplusplus
}
#endif

#endif
