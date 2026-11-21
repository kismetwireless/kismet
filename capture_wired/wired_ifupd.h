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

#ifndef __WIRED_IFUPD_H__
#define __WIRED_IFUPD_H__

#include <stdint.h>
#include <sys/types.h>

#include "wired_util.h"

/* The only holder of CAP_NET_ADMIN: a child forked in main before any thread or
 * connection exists, which can do one thing, set IFF_UP on an Ethernet interface
 * the capture process names.  The capture process and a --retry monitor never
 * hold CAP_NET_ADMIN themselves */

typedef enum {
    WIRED_IFUPD_RUNNING = 0,
    /* No CAP_NET_ADMIN was held */
    WIRED_IFUPD_NO_CAP,
    /* Started with a uid, gid or supplementary group 0, which it leaves later; no
     * child */
    WIRED_IFUPD_ROOT,
    /* It couldn't be started, or it has exited */
    WIRED_IFUPD_GONE,
} wired_ifupd_state_t;

/* How long the capture process waits for an answer, well inside the server's
 * open timeout */
#define WIRED_IFUPD_TIMEOUT_MS  5000

/* When the capture process gives up waiting on an answer and sends the next
 * request regardless, past what one answer takes the child at most when it works
 * (three rtnetlink requests, each up to 8 reads of 1 s in wired_sysfs.c) */
#define WIRED_IFUPD_STALL_MS    25000

typedef struct {
    int fd;
    pid_t pid;
    /* Requests are numbered per process (wired_ifup_seq), the pid in the high 32
     * bits and a count from a random start in the low, so a --retry capture
     * process never takes an answer meant for the one before it */
    pid_t seq_owner;
    uint32_t seq;
    wired_ifupd_state_t state;
    /* The WIRED_ROOT_* ids (wired_priv.h) held at start */
    int root_ids;
    int timeout_ms;
    int stall_ms;
    /* A request which timed out, or a socket the child had stopped reading, at
     * busy_since_ms; no other request is sent until the child answers busy_seq
     * (0 for none) or stall_ms passes */
    int busy;
    uint64_t busy_seq;
    uint64_t busy_since_ms;
    /* The network namespace belongs to a user namespace other than this one, so
     * CAP_NET_ADMIN here can't change its interfaces */
    int netns_foreign;
} wired_ifupd_t;

/* Whether start forks the child: NO_CAP without CAP_NET_ADMIN permitted, ROOT
 * with any WIRED_ROOT_* id, otherwise RUNNING */
wired_ifupd_state_t wired_ifupd_decide(int admin_permitted, int root_ids);

/* Called once in main, after cf_handler_daemonize and before
 * cf_handler_remote_capture: with CAP_NET_ADMIN and no id 0 it forks the child,
 * and in every case drops CAP_NET_ADMIN from this process.  Returns 1, or -1 when
 * the ids can't be read or CAP_NET_ADMIN couldn't be dropped (then the helper has
 * to exit) */
int wired_ifupd_start(wired_ifupd_t *d);

/* The fork alone, without start's checks; tests use it.  Returns 1 or -1 */
int wired_ifupd_spawn(wired_ifupd_t *d);

/* Clears CAP_NET_ADMIN from this process's effective, permitted and inheritable
 * sets (and so the ambient one), and confirms it's gone.  Returns 1 or -1 */
int wired_ifupd_drop_admin(void);

/* Asks the child to bring ifname up and waits up to timeout_ms for the answer,
 * never blocking to send.  Returns the wired_ifup_status_t, with *err the errno
 * for WIRED_IFUP_FAILED, or -1 with *err set: ENOTCONN no child, ETIMEDOUT no
 * answer in time, EBUSY still busy with an earlier request (nothing sent),
 * EPROTO a malformed answer, poll's error, or the socket's error when the child
 * has gone.  Only a timeout, or a socket the child has stopped reading, leaves it
 * busy; the socket stays open */
int wired_ifupd_request(wired_ifupd_t *d, const char *ifname, int *err);

/* Reads the answers that came after their request timed out, without waiting,
 * and ends busy when the child has answered or stall_ms has passed */
void wired_ifupd_collect(wired_ifupd_t *d);

/* What the child answers with; the tests replace them */
typedef struct {
    const char *sysfs_root;
    int (*getlink)(const char *ifname, int ifindex, wired_nl_link_t *link);
    int (*set_up)(int ifindex);
} wired_ifupd_ops_t;

/* The child's answer to one request of len bytes.  The name is looked up once in
 * the child's own network namespace (getlink), and that link must be Ethernet,
 * neither loopback nor wireless (wired_classify_link under sysfs_root); set_up
 * then gets its index alone, and the link of that index must still have the name
 * afterwards.  Errors: EINVAL a malformed request, ENODEV no such interface,
 * EOPNOTSUPP not a wired Ethernet interface, EXDEV sysfs_root isn't this network
 * namespace's, ESTALE renamed or removed while it was brought up */
void wired_ifupd_answer(const uint8_t *buf, size_t len, const wired_ifupd_ops_t *ops,
        wired_ifup_reply_t *reply);

/* 1 when the network namespace belongs to a user namespace outside this
 * process's (NS_GET_USERNS refuses with EPERM), 0 when it doesn't, -1 when it
 * can't be told */
int wired_netns_foreign(void);

#endif
