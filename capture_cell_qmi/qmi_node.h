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

    Which framing a control node speaks, and how to reach it.

    Framing comes from the node: a cdc-wdm node speaks what its USB driver
    speaks (qmi_wwan: QMUX, cdc_mbim: MBIM), and the wwan / MHI nodes say it
    in their names (wwan0qmi0, wwan0mbim0, mhi_QMI0, mhi_MBIM0).

    How to reach it is a separate question, answered in this order:
      1. proxy:  the framing's proxy daemon is listening (@qmi-proxy for
                 QMUX, @mbim-proxy for MBIM, also for QMI carried in MBIM)
                 and nothing else holds the node.  The source becomes one
                 more proxy client, beside ModemManager or anything else.
      2. refuse: another program holds the node (uqmi, a vendor connection
                 manager, a stale proxy of the other framing).  Opening it
                 too would steal that program's replies, so the source names
                 it and stops.
      3. direct: no proxy and no holder: open the node.

    A proxy is detected by reading /proc/net/unix, never by connecting, and
    is never started: a started mbim-proxy outlives its client and holds the
    node from then on.
*/

#ifndef __QMI_NODE_H__
#define __QMI_NODE_H__

#include <stddef.h>
#include <sys/types.h>

#ifdef __cplusplus
extern "C" {
#endif

typedef enum {
    QMI_FRAMING_NONE = 0,
    QMI_FRAMING_QMUX,
    QMI_FRAMING_MBIM,
} qmi_framing_t;

/* 1 if `name` (no /dev/) is a control node name this source opens:
 * cdc-wdmN, wwanNqmiM, wwanNmbimM, mhi_QMIN, mhi_MBIMN. */
int qmi_node_name_ok(const char *name);

/* The framing of node `dev`.  `driver` gets what decided it (the USB driver,
 * or "wwan" / "mhi" for a node named by its framing).  QMI_FRAMING_NONE for a
 * cdc-wdm node whose driver is unknown or speaks neither. */
qmi_framing_t qmi_node_framing(const char *dev, char *driver, size_t driversz);

/* 1 if an abstract AF_UNIX socket `@name` is listening (/proc/net/unix). */
int qmi_abstract_listening(const char *name);

/* The proxy that serves a framing. */
const char *qmi_proxy_name(qmi_framing_t framing);

typedef enum {
    QMI_OPEN_AUTO = 0,     /* the order above */
    QMI_OPEN_PROXY_ONLY,   /* proxy, or refuse: never a direct open */
    QMI_OPEN_DIRECT_ONLY,  /* direct, or refuse: never through a proxy */
} qmi_open_req_t;

typedef enum {
    QMI_PLAN_REFUSE = 0,
    QMI_PLAN_DIRECT,
    QMI_PLAN_PROXY,
} qmi_plan_mode_t;

typedef struct {
    qmi_plan_mode_t mode;
    const char *proxy;       /* the proxy's name when mode is PROXY */
    char reason[320];
} qmi_open_plan_t;

/* What the plan is decided from, gathered by qmi_open_plan or given by the
 * selftest. */
typedef struct {
    int proxy_listening;
    int held;                 /* any process holds the node */
    pid_t held_pid;
    char held_comm[32];
    int held_by_other;        /* a process other than the proxy holds it */
    pid_t other_pid;
    char other_comm[32];
} qmi_open_facts_t;

void qmi_open_decide(const char *dev, qmi_framing_t framing, qmi_open_req_t req,
                     const qmi_open_facts_t *facts, qmi_open_plan_t *out);

/* Gather the facts for `dev` and decide. */
void qmi_open_plan(const char *dev, qmi_framing_t framing, qmi_open_req_t req,
                   qmi_open_plan_t *out);

/* Selftest hook: prefix /proc and /sys reads with `root` ("" = real). */
void qmi_node_set_root(const char *root);

#ifdef __cplusplus
}
#endif

#endif
