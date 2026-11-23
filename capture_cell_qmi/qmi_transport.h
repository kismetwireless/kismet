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

#include "mbim_wire.h"
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
    mbim_reasm_t reasm;     /* MBIM: a reply arriving in fragments */
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
    /* The client id record (qmi_session_open_tracked), or -1 */
    int state_fd;
    /* The open released a client id an earlier session left behind */
    int stale_released;
    uint8_t stale_cid;
    int stale_answered;     /* the modem answered that release */
} qmi_session_t;

/* How long a cold open's client id request may wait while the node keeps
 * delivering other messages ahead of the reply.  Indications queued for
 * clients nobody released arrive first, one per 32 ms interrupt poll on
 * qmi_wwan: about 400 of them, 13 s, were measured on one modem.  A quiet
 * node still fails after the caller's timeout. */
#ifndef QMI_OPEN_BACKLOG_MAX_MS
#define QMI_OPEN_BACKLOG_MAX_MS 20000
#endif

/* Open `dev` (through its proxy when `via_proxy`) and allocate a NAS client
 * id.  1 on success; 0 with a reason in `err`.  `timeout_ms` is how long the
 * node may stay silent; a backlog ahead of the reply can stretch the open to
 * QMI_OPEN_BACKLOG_MAX_MS (QMUX framing). */
int qmi_session_open(qmi_session_t *s, const char *dev, qmi_framing_t framing,
                     int via_proxy, int timeout_ms, char *err, size_t errsz);

/* qmi_session_open(), and on a direct open also keep a record of the client
 * id in `state_path`, so a session that dies without releasing it (SIGKILL,
 * where no handler runs) does not leak it for good: the next direct open of
 * the same node finds the record, releases that id, then allocates its own.
 *
 * The record names the node by device number, inode and change time, so a
 * modem that re-enumerated (its node was made again, and its ids were freed
 * by the reset) never has a number released that it may since have given to
 * someone else.  A direct open happens only when no other program holds the
 * node (the open order refuses otherwise), so the recorded id has no live
 * holder.  Through a proxy, other clients share the modem's ids, and nothing
 * is recorded.  The record is emptied whenever the id is released: on close,
 * and by qmi_session_release_now().  A NULL `state_path`, or a record that
 * cannot be opened, tracks nothing. */
int qmi_session_open_tracked(qmi_session_t *s, const char *dev,
                             qmi_framing_t framing, int via_proxy, int timeout_ms,
                             const char *state_path, char *err, size_t errsz);

/* Send NAS request `msg_id` (no TLVs) and wait for its reply, which is parsed
 * into `out` and points into `buf`.  1 on a reply, 0 on a timeout, -1 if the
 * transport failed (`err` says how). */
int qmi_session_nas(qmi_session_t *s, uint16_t msg_id, uint8_t *buf, size_t cap,
                    qmux_msg_t *out, int timeout_ms, char *err, size_t errsz);

/* Release the client id, close the MBIM function if this session opened it,
 * and close the transport.  Safe to call twice. */
void qmi_session_close(qmi_session_t *s);

/* Async-signal-safe: write the prebuilt release (and MBIM_CLOSE) without
 * waiting for replies, and empty the client id record.  For a signal handler
 * on the way out. */
void qmi_session_release_now(const qmi_session_t *s);

const char *qmi_transport_kind_name(qmi_transport_kind_t kind);

/* The control transfer MBIM_OPEN asks for: the node's own buffer
 * (`have_node_max`: cdc-wdm's IOCTL_WDM_MAX_COMMAND answered), never more
 * than 4096 nor under MBIM's 64.  Asking for more than the node holds is not
 * harmless: an XMM7360 with a 512-byte buffer, opened at 4096, sent a 1 KB
 * reply as one transfer the node could not hold, and its MBIM function then
 * answered nobody until the modem was reset.  Without the ioctl (a proxy
 * socket, or not Linux) the default stands. */
uint32_t mbim_open_max_transfer(int have_node_max, uint32_t node_max);

/* ------------------------------------------------------------ native MBIM */

/* An MBIM function read with MBIM's own services, for modems whose MBIM
 * function carries no QMI.  The open follows the QMI session's MBIM rules:
 * through @mbim-proxy nothing is opened or closed; directly, MBIM_OPEN is
 * sent only if the function answers that it is not open, and MBIM_CLOSE on
 * close only if this session opened it.  DEVICE_SERVICES is read at open. */
typedef struct {
    qmi_transport_t t;
    mbim_caps_t caps;
    uint8_t close_bytes[16];
    size_t close_len;
} mbim_session_t;

int mbim_session_open(mbim_session_t *s, const char *dev, int via_proxy, int timeout_ms,
                      char *err, size_t errsz);

/* A query: 1 with the reply in `done` (whose status may be an error), 0 on
 * a timeout, -1 if the transport failed */
int mbim_session_query(mbim_session_t *s, const uint8_t uuid[16], uint32_t cid,
                       const uint8_t *info, size_t info_len, uint8_t *buf, size_t cap,
                       mbim_msg_t *done, int timeout_ms, char *err, size_t errsz);

void mbim_session_close(mbim_session_t *s);

/* Async-signal-safe: the prebuilt MBIM_CLOSE, when this session opened it */
void mbim_session_close_now(const mbim_session_t *s);

/* Carry on as a QMI session (QMI over MBIM) on the MBIM transport `m` opened,
 * which the QMI session then owns: `m` is left closed.  As
 * qmi_session_open_tracked() after its transport open. */
int qmi_session_adopt(qmi_session_t *s, mbim_session_t *m, int timeout_ms,
                      const char *state_path, char *err, size_t errsz);

#ifdef __cplusplus
}
#endif

#endif
