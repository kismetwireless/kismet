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

/* kismet_cap_wired
 *
 * Captures Ethernet frames from a Linux interface with libpcap and sends every
 * frame (or 1 in N with sample=N) to Kismet as DLT_EN10MB.  libpcap puts back
 * the VLAN tags the kernel strips, 802.1ad outer tags included.
 *
 * Needs CAP_NET_RAW only; install it with the file capability
 * cap_net_raw+ep rather than setuid.  Once the filesystem is jailed it keeps
 * CAP_NET_RAW and drops every other capability, ambient ones too, whoever runs
 * it, and exits if it can't.  Started with any uid 0 (root, or setuid root) it
 * also leaves root for the invoking user, or nobody, and gids 0 likewise, and
 * exits if it can't, or if it was built without libcap; see wired_priv.h.
 *
 * Installed with cap_net_raw,cap_net_admin+ep and run as a user, it can also
 * bring a down interface up (ifup=, default true): CAP_NET_ADMIN then lives only
 * in a child forked first thing, which can do nothing but that; see
 * wired_ifupd.h.
 *
 * Built with -DWIRED_REPLAY (make -C capture_wired replay, never installed) it
 * reads a pcap file named by replay= instead of an interface, so the server
 * paths can be tested without privileges.
 */

#include "../config.h"

#include <errno.h>
#include <poll.h>
#include <pthread.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <unistd.h>

#include <sys/socket.h>
#include <sys/time.h>

#include <pcap.h>

#include "../capture_framework.h"

#include "wired_ifupd.h"
#include "wired_priv.h"
#include "wired_sysfs.h"
#include "wired_util.h"

/* Libpcap ring timeout: how long a partly filled TPACKET_V3 block waits */
#define WIRED_PCAP_TIMEOUT_MS       100
#define WIRED_POLL_MS               500
#define WIRED_DISPATCH_BATCH        256
#define WIRED_STATUS_INTERVAL_MS    5000
#define WIRED_DROP_MSG_INTERVAL_S   60

typedef struct {
    pcap_t *pd;
    char ifname[WIRED_IFNAMSIZ];
    wired_opts_t opts;
    wired_sampler_t sampler;
    wired_status_t status;

    /* Most bytes of a frame sent, under the server's IPC frame limit */
    unsigned int caplen_max;

    /* In remote capture, the server's TCP checked again on every frame as sent:
     * the kernel filter sees a frame before libpcap puts its VLAN tag back, and
     * libpcap runs the filter in userspace on frames queued before it was set */
    struct bpf_program selfprog;
    int has_selfprog;

    /* Where that connection runs, and the interface it leaves through */
    wired_path_t remote_path;
    char remote_via[WIRED_IFNAMSIZ];

    /* pcap_stats counters are 32 bit and wrap; these are the last values read */
    unsigned int last_ps_recv;
    unsigned int last_ps_drop;
    unsigned int last_ps_ifdrop;

    uint64_t drops_at_last_msg;
    time_t last_drop_msg;

    int replay_eof;

    /* What the privilege drop in main left */
    wired_priv_t priv;

    /* The bring-up child, and whether this open brought the interface up */
    wired_ifupd_t ifupd;
    int brought_up;
    /* The interface of a bring-up which timed out, reported as brought up when
     * it's found up at the next open */
    char late_ifname[WIRED_IFNAMSIZ];
} local_wired_t;

static uint64_t wired_mono_ms(void) {
    struct timespec ts;

    clock_gettime(CLOCK_MONOTONIC, &ts);
    return (uint64_t) ts.tv_sec * 1000 + (uint64_t) ts.tv_nsec / 1000000;
}

/* The interface name from a definition, checked against the allowlist */
static int wired_definition_ifname(char *definition, char *ifname, char *msg) {
    char *placeholder = NULL;
    int len;

    if ((len = cf_parse_interface(&placeholder, definition)) <= 0) {
        snprintf(msg, STATUS_MAX, "Unable to find an interface in the source definition");
        return -1;
    }

    if (!wired_ifname_valid(placeholder, (size_t) len)) {
        snprintf(msg, STATUS_MAX, "Not a valid interface name");
        return -1;
    }

    memcpy(ifname, placeholder, (size_t) len);
    ifname[len] = 0;

    return 1;
}

static char *wired_make_uuid(const char *ifname, const wired_opts_t *opts) {
    char buf[WIRED_UUID_LEN + 1];
    uint8_t mac[6];
    const uint8_t *macp = NULL;

    if (opts->has_uuid)
        return strdup(opts->uuid);

#ifndef WIRED_REPLAY
    if (wired_read_mac(WIRED_SYSFS_NET, ifname, mac) > 0)
        macp = mac;
#else
    (void) mac;
#endif

    if (wired_format_uuid(ifname, macp, buf, sizeof(buf)) < 0)
        return NULL;

    return strdup(buf);
}

static char *wired_hardware(const char *ifname) {
    char driver[WIRED_DRIVER_MAX] = "";

#ifndef WIRED_REPLAY
    wired_read_driver(WIRED_SYSFS_NET, ifname, driver, sizeof(driver));
#else
    (void) ifname;
#endif

    return strdup(driver[0] != 0 ? driver : "ethernet");
}

int probe_callback(kis_capture_handler_t *caph, uint32_t seqno, char *definition,
        char *msg, char **uuid,
        cf_params_interface_t **ret_interface,
        cf_params_spectrum_t **ret_spectrum) {
    char ifname[WIRED_IFNAMSIZ];
    char errstr[STATUS_MAX];
    wired_opts_t opts;

    *uuid = NULL;
    *ret_spectrum = NULL;
    *ret_interface = cf_params_interface_new();

    if (*ret_interface == NULL)
        return -1;

    if (wired_definition_ifname(definition, ifname, msg) < 0)
        return 0;

#ifndef WIRED_REPLAY
    {
        wired_if_class_t c = wired_classify(WIRED_SYSFS_NET, ifname);

        if (c != WIRED_IF_OK) {
            snprintf(msg, STATUS_MAX, "Interface '%s' is %s", ifname, wired_class_reason(c));
            return 0;
        }
    }
#endif

    if (wired_parse_opts(definition, &opts, errstr, sizeof(errstr)) < 0) {
        snprintf(msg, STATUS_MAX, "Interface '%s': %s", ifname, errstr);
        return -1;
    }

    (*ret_interface)->capif = strdup(ifname);
    (*ret_interface)->hardware = wired_hardware(ifname);
    *uuid = wired_make_uuid(ifname, &opts);

    if ((*ret_interface)->capif == NULL || (*ret_interface)->hardware == NULL || *uuid == NULL) {
        snprintf(msg, STATUS_MAX, "Out of memory probing '%s'", ifname);
        return -1;
    }

    return 1;
}

int list_callback(kis_capture_handler_t *caph, uint32_t seqno,
        char *msg, cf_params_list_interface_t ***interfaces) {
#ifdef WIRED_REPLAY
    *interfaces = NULL;
    return 0;
#else
    char names[WIRED_LIST_MAX][WIRED_IFNAMSIZ];
    size_t n, i, out = 0;

    *interfaces = NULL;

    n = wired_list_interfaces(WIRED_SYSFS_NET, wired_if_kind, names, WIRED_LIST_MAX);

    if (n == 0)
        return 0;

    *interfaces = (cf_params_list_interface_t **) calloc(n, sizeof(cf_params_list_interface_t *));

    if (*interfaces == NULL) {
        snprintf(msg, STATUS_MAX, "Out of memory listing interfaces");
        return -1;
    }

    /* The list response reads every entry it's given, so only count complete ones */
    for (i = 0; i < n; i++) {
        cf_params_list_interface_t *li = calloc(1, sizeof(cf_params_list_interface_t));

        if (li == NULL)
            break;

        li->interface = strdup(names[i]);
        li->hardware = wired_hardware(names[i]);

        if (li->interface == NULL || li->hardware == NULL) {
            free(li->interface);
            free(li->hardware);
            free(li);
            break;
        }

        (*interfaces)[out++] = li;
    }

    if (out == 0) {
        free(*interfaces);
        *interfaces = NULL;
    }

    return (int) out;
#endif
}

/* In remote capture, the expression that keeps all TCP to and from the server
 * out of the capture, and where the connection runs (lw->remote_path).  Returns
 * 0 when not remote, the length, or -1 when remote but the connection can't be
 * described; a sensor capturing the link its uplink runs on would otherwise feed
 * its own traffic, and its sibling helpers', back.  The exclusion only matches
 * the connection as the helper sees it: when that is a loopback forward or runs
 * over a tunnel, its real carrier isn't matched. */
static int wired_remote_selfexcl(kis_capture_handler_t *caph, local_wired_t *lw,
        char *out, size_t out_len) {
    struct sockaddr_storage peer, local;
    socklen_t peer_len = sizeof(peer);
    socklen_t local_len = sizeof(local);
    const char *local_if = NULL;
    char peer_if[WIRED_IFNAMSIZ];
    int fd = -1, peer_local;

    out[0] = 0;
    lw->remote_path = WIRED_PATH_UNKNOWN;
    lw->remote_via[0] = 0;

    if (caph->use_ipc)
        return 0;

    if (caph->tcp_fd >= 0) {
        fd = caph->tcp_fd;
#ifdef HAVE_LIBWEBSOCKETS
    } else if (caph->lwsclientwsi != NULL) {
        fd = (int) lws_get_socket_fd(caph->lwsclientwsi);
#endif
    }

    if (fd < 0)
        return caph->remote_host != NULL ? -1 : 0;

    memset(&peer, 0, sizeof(peer));

    if (getpeername(fd, (struct sockaddr *) &peer, &peer_len) < 0)
        return -1;

    memset(&local, 0, sizeof(local));

    if (getsockname(fd, (struct sockaddr *) &local, &local_len) == 0 &&
            wired_addr_ifname((struct sockaddr *) &local, lw->remote_via,
                sizeof(lw->remote_via)) > 0)
        local_if = lw->remote_via;

    peer_local = wired_addr_ifname((struct sockaddr *) &peer, peer_if, sizeof(peer_if)) > 0;

    lw->remote_path = wired_remote_path(WIRED_SYSFS_NET, wired_if_kind, lw->ifname,
            (struct sockaddr *) &peer, peer_local, local_if);

    return wired_build_selfexcl((struct sockaddr *) &peer, out, out_len);
}

/* The exclusion can't vouch for a connection it may not see on the wire; say
 * how the carrier gets left out instead.  A second uplink is the usual reason
 * for another interface, so that one is only information */
static void wired_remote_path_warning(kis_capture_handler_t *caph, local_wired_t *lw) {
    char msg[STATUS_MAX];
    unsigned int flags = MSGFLAG_ERROR;

    switch (lw->remote_path) {
        case WIRED_PATH_CAPTURED:
            return;
        case WIRED_PATH_LOOPBACK:
            snprintf(msg, sizeof(msg), "Interface '%s': the connection to the Kismet server goes "
                    "to a loopback address or one of this host's: the server runs here, or an "
                    "SSH forward, proxy or tunnel carries the connection.  If that runs over "
                    "'%s', its frames are captured and sent to the server again, feeding back "
                    "on themselves; leave them out with filter= (such as filter=\"not port 22\" "
                    "for an SSH forward)", lw->ifname, lw->ifname);
            break;
        case WIRED_PATH_OTHER:
            flags = MSGFLAG_INFO;
            snprintf(msg, sizeof(msg), "Interface '%s': the connection to the Kismet server is "
                    "from an address of '%s', not of this interface.  A separate uplink needs "
                    "nothing, nor does a route with a src address sending it out over '%s', "
                    "which is still left out.  If '%s' is a tunnel or VPN carried over '%s', "
                    "or policy-based IPsec encrypts the connection, its frames are captured and "
                    "sent to the server again, feeding back on themselves; leave them out with "
                    "filter=", lw->ifname, lw->remote_via, lw->ifname, lw->remote_via,
                    lw->ifname);
            break;
        case WIRED_PATH_UNMATCHED:
            snprintf(msg, sizeof(msg), "Interface '%s': the connection to the Kismet server runs "
                    "over '%s', which is carried over this interface in a form the exclusion "
                    "can't match (more than %d VLAN tags, or encrypted or encapsulated, such as "
                    "MACsec or VXLAN).  Its frames are captured and sent to the server again, "
                    "feeding back on themselves; leave them out with filter=, or capture "
                    "another interface", lw->ifname, lw->remote_via, WIRED_SELFEXCL_TAGS);
            break;
        case WIRED_PATH_UNKNOWN:
        default:
            snprintf(msg, sizeof(msg), "Interface '%s': could not tell which interface the "
                    "connection to the Kismet server leaves through: its address is on no "
                    "interface, is a service address on a loopback, dummy or VRF interface, sent "
                    "wherever the routes say, or is on an interface with more stacked under it "
                    "than the helper follows.  If a tunnel, VPN, SSH forward or policy-based "
                    "IPsec carries it over '%s', its frames are captured and sent to the "
                    "server again, feeding back on themselves; leave them out with filter=",
                    lw->ifname, lw->ifname);
            break;
    }

    cf_send_message(caph, msg, flags);
}

static void wired_close(local_wired_t *lw) {
    if (lw->pd != NULL) {
        pcap_close(lw->pd);
        lw->pd = NULL;
    }

    if (lw->has_selfprog) {
        pcap_freecode(&lw->selfprog);
        lw->has_selfprog = 0;
    }
}

/* The exclusion alone, for frames as libpcap hands them over: tags inline */
static int wired_compile_selfprog(local_wired_t *lw, const char *selfexcl, char *msg) {
    pcap_t *dead = pcap_open_dead(DLT_EN10MB, (int) WIRED_SNAPLEN_MAX);
    int r;

    if (dead == NULL) {
        snprintf(msg, STATUS_MAX, "Out of memory filtering '%s'", lw->ifname);
        return -1;
    }

    r = pcap_compile(dead, &lw->selfprog, selfexcl, 1, PCAP_NETMASK_UNKNOWN);

    if (r < 0)
        snprintf(msg, STATUS_MAX, "Could not compile the server exclusion for '%s': %s",
                lw->ifname, pcap_geterr(dead));
    else
        lw->has_selfprog = 1;

    pcap_close(dead);

    return r < 0 ? -1 : 1;
}

#ifndef WIRED_REPLAY
/* The handle and its settings, which don't need the interface up */
static int wired_create(local_wired_t *lw, char *msg) {
    char errstr[PCAP_ERRBUF_SIZE] = "";

    if ((lw->pd = pcap_create(lw->ifname, errstr)) == NULL) {
        snprintf(msg, STATUS_MAX, "Could not open '%s': %s", lw->ifname, errstr);
        return -1;
    }

    if (pcap_set_snaplen(lw->pd, (int) lw->caplen_max) != 0 ||
            pcap_set_promisc(lw->pd, lw->opts.promisc) != 0 ||
            pcap_set_timeout(lw->pd, WIRED_PCAP_TIMEOUT_MS) != 0 ||
            pcap_set_buffer_size(lw->pd, (int) (lw->opts.buffer_mb * 1024U * 1024U)) != 0) {
        snprintf(msg, STATUS_MAX, "Could not configure '%s': %s", lw->ifname,
                pcap_geterr(lw->pd));
        return -1;
    }

    return 1;
}

static int wired_activate(local_wired_t *lw, char *msg) {
    int r;

    r = pcap_activate(lw->pd);

    if (r < 0) {
        if (r == PCAP_ERROR || r == PCAP_ERROR_NO_SUCH_DEVICE || r == PCAP_ERROR_PERM_DENIED)
            snprintf(msg, STATUS_MAX, "Could not open '%s': %s%s", lw->ifname,
                    pcap_geterr(lw->pd),
                    r == PCAP_ERROR_PERM_DENIED ?
                    " (kismet_cap_wired needs CAP_NET_RAW, set with "
                    "'setcap cap_net_raw+ep kismet_cap_wired')" : "");
        else
            snprintf(msg, STATUS_MAX, "Could not open '%s': %s", lw->ifname,
                    pcap_statustostr(r));
        return -1;
    }

    /* Promiscuous mode can't be had on some interfaces; capture anyway */
    if (r > 0 && lw->opts.promisc)
        lw->opts.promisc = r != PCAP_WARNING_PROMISC_NOTSUP;

    return 1;
}
#endif

/* The whole filter into filter (WIRED_FULL_FILTER_MAX), and *netmask for it,
 * compiled once for Ethernet without the interface, so a mistake in it fails the
 * open before the interface is brought up */
static int wired_prepare_filter(kis_capture_handler_t *caph, local_wired_t *lw, char *filter,
        bpf_u_int32 *netmask, char *msg) {
    char selfexcl[WIRED_SELFEXCL_MAX];
    struct bpf_program prog;
    pcap_t *dead;
    int r;

    *netmask = PCAP_NETMASK_UNKNOWN;

    if ((r = wired_remote_selfexcl(caph, lw, selfexcl, sizeof(selfexcl))) < 0) {
        snprintf(msg, STATUS_MAX, "Could not find the connection to the Kismet server to "
                "leave it out of the capture of '%s'", lw->ifname);
        return -1;
    }

    /* Applied either way; claimed only when the connection is known to cross this
     * interface as the helper sees it */
    lw->status.remote_excluded = r > 0 && lw->remote_path == WIRED_PATH_CAPTURED;

    if (r > 0 && wired_compile_selfprog(lw, selfexcl, msg) < 0)
        return -1;

    if (wired_build_filter(lw->opts.has_filter ? lw->opts.filter : NULL, selfexcl,
                filter, WIRED_FULL_FILTER_MAX) < 0) {
        snprintf(msg, STATUS_MAX, "Filter for '%s' is too long", lw->ifname);
        return -1;
    }

    if (filter[0] == 0)
        return 1;

#ifndef WIRED_REPLAY
    /* 'ip broadcast' needs the netmask; an interface without IPv4 has none */
    {
        char errstr[PCAP_ERRBUF_SIZE] = "";
        bpf_u_int32 net = 0, mask = 0;

        if (pcap_lookupnet(lw->ifname, &net, &mask, errstr) == 0 && mask != 0)
            *netmask = mask;
    }
#endif

    if ((dead = pcap_open_dead(DLT_EN10MB, (int) WIRED_SNAPLEN_MAX)) == NULL) {
        snprintf(msg, STATUS_MAX, "Out of memory filtering '%s'", lw->ifname);
        return -1;
    }

    r = pcap_compile(dead, &prog, filter, 1, *netmask);

    if (r < 0)
        snprintf(msg, STATUS_MAX, "Could not compile the filter for '%s': %s", lw->ifname,
                pcap_geterr(dead));
    else
        pcap_freecode(&prog);

    pcap_close(dead);

    return r < 0 ? -1 : 1;
}

/* The filter wired_prepare_filter made, on the open handle */
static int wired_set_filter(local_wired_t *lw, const char *filter, bpf_u_int32 netmask,
        char *msg) {
    struct bpf_program prog;
    int r;

    if (filter[0] == 0)
        return 1;

    if (pcap_compile(lw->pd, &prog, filter, 1, netmask) < 0) {
        snprintf(msg, STATUS_MAX, "Could not compile the filter for '%s': %s", lw->ifname,
                pcap_geterr(lw->pd));
        return -1;
    }

    r = pcap_setfilter(lw->pd, &prog);
    pcap_freecode(&prog);

    if (r < 0) {
        snprintf(msg, STATUS_MAX, "Could not set the filter for '%s': %s", lw->ifname,
                pcap_geterr(lw->pd));
        return -1;
    }

    return 1;
}

#ifndef WIRED_REPLAY
/* A down interface is brought up, never taken down again: it stays up when the
 * source closes, as linuxwifi leaves its interfaces.  Returns 1 when it was
 * brought up, 0 when it was left alone, or -1 with msg set */
static int wired_bring_up(local_wired_t *lw, char *msg) {
    const char *n = lw->ifname;
    int r, e = 0, up;

    if ((up = wired_nl_read_up(n)) < 0) {
        snprintf(msg, STATUS_MAX, "Couldn't read whether interface '%s' is up", n);
        return -1;
    }

    switch (wired_ifup_action(up, lw->opts.ifup)) {
        case WIRED_IFUP_KEEP:
            /* A request which timed out may have brought it up after all */
            if (lw->late_ifname[0] != 0 && strcmp(lw->late_ifname, n) == 0) {
                lw->late_ifname[0] = 0;
                return 1;
            }

            return 0;
        case WIRED_IFUP_REFUSE:
            snprintf(msg, STATUS_MAX, "Interface '%s' is down, and ifup=false; bring it up with "
                    "'ip link set %s up'", n, n);
            return -1;
        case WIRED_IFUP_BRING:
        default:
            break;
    }

    r = lw->ifupd.fd >= 0 ? wired_ifupd_request(&lw->ifupd, n, &e) : -1;

    if (r == WIRED_IFUP_ALREADY)
        return 0;

    if (r == WIRED_IFUP_DONE) {
        if (wired_nl_read_up(n) != 1) {
            snprintf(msg, STATUS_MAX, "Interface '%s' did not come up", n);
            return -1;
        }

        return 1;
    }

    if (r < 0 && lw->ifupd.timed_out)
        snprintf(lw->late_ifname, sizeof(lw->late_ifname), "%s", n);

    if (lw->ifupd.netns_foreign && r == WIRED_IFUP_FAILED && e == EPERM)
        snprintf(msg, STATUS_MAX, "Interface '%s' is down, and its network namespace belongs to "
                "another user namespace, so kismet_cap_wired can't bring it up from here; bring "
                "it up with 'ip link set %s up' outside this user namespace", n, n);
    else if (r == WIRED_IFUP_FAILED && e == ESTALE)
        snprintf(msg, STATUS_MAX, "Interface '%s' was renamed or removed while kismet_cap_wired "
                "brought it up; check 'ip link' and open it by its name now", n);
    else if (r == WIRED_IFUP_FAILED && e == EXDEV)
        snprintf(msg, STATUS_MAX, "Interface '%s' is down, and the /sys kismet_cap_wired sees "
                "isn't its network namespace's, so it can't be told from Wi-Fi and isn't brought "
                "up; bring it up with 'ip link set %s up'", n, n);
    else if (r == WIRED_IFUP_FAILED)
        snprintf(msg, STATUS_MAX, "Could not bring up '%s': %s", n, strerror(e));
    else if (lw->ifupd.state == WIRED_IFUPD_NO_CAP)
        snprintf(msg, STATUS_MAX, "Interface '%s' is down, and kismet_cap_wired can't bring it "
                "up without CAP_NET_ADMIN; bring it up with 'ip link set %s up', or install the "
                "helper with 'setcap cap_net_raw,cap_net_admin+ep kismet_cap_wired'", n, n);
    else if (lw->ifupd.state == WIRED_IFUPD_ROOT)
        snprintf(msg, STATUS_MAX, "Interface '%s' is down; kismet_cap_wired started with %s "
                "doesn't bring interfaces up; bring it up with 'ip link set %s up'", n,
                (lw->ifupd.root_ids & WIRED_ROOT_UID) ? "root's uid" :
                "root's group (a gid or supplementary group 0)", n);
    else if (lw->ifupd.timed_out)
        snprintf(msg, STATUS_MAX, "Interface '%s' is down, and kismet_cap_wired's bring-up "
                "process isn't responding; bring it up with 'ip link set %s up'", n, n);
    else
        snprintf(msg, STATUS_MAX, "Interface '%s' is down, and kismet_cap_wired's bring-up "
                "process didn't answer (%s); bring it up with 'ip link set %s up'", n,
                strerror(e != 0 ? e : EPIPE), n);

    return -1;
}
#endif

static int wired_open(kis_capture_handler_t *caph, char *definition,
        char *msg, uint32_t *dlt, char **uuid,
        cf_params_interface_t **ret_interface,
        cf_params_spectrum_t **ret_spectrum) {
    local_wired_t *lw = (local_wired_t *) caph->userdata;
    char errstr[STATUS_MAX];
    char offloads[256] = "";
    char unknown[256] = "";
    char filter[WIRED_FULL_FILTER_MAX] = "";
    bpf_u_int32 netmask = PCAP_NETMASK_UNKNOWN;

    lw->brought_up = 0;
    *uuid = NULL;
    *dlt = 0;
    *ret_spectrum = NULL;
    *ret_interface = cf_params_interface_new();

    if (*ret_interface == NULL)
        return -1;

    /* The framework refuses an open while the capture thread runs, so the old
     * handle is unused here */
    wired_close(lw);
    memset(&lw->status, 0, sizeof(lw->status));
    lw->last_ps_recv = lw->last_ps_drop = lw->last_ps_ifdrop = 0;
    lw->drops_at_last_msg = 0;
    lw->last_drop_msg = 0;
    lw->replay_eof = 0;

    if (wired_definition_ifname(definition, lw->ifname, msg) < 0)
        return -1;

    if (wired_parse_opts(definition, &lw->opts, errstr, sizeof(errstr)) < 0) {
        snprintf(msg, STATUS_MAX, "Interface '%s': %s", lw->ifname, errstr);
        return -1;
    }

    /* A fixed GPS adds its name to every report */
    lw->caplen_max = wired_caplen_limit(lw->opts.snaplen,
            caph->gps_fixed_lat != 0 && caph->gps_name != NULL ? strlen(caph->gps_name) : 0);

    if (lw->caplen_max == 0) {
        snprintf(msg, STATUS_MAX, "Interface '%s': the fixed GPS name is too long to send "
                "with each frame", lw->ifname);
        return -1;
    }

#ifndef WIRED_REPLAY
    {
        wired_if_class_t c = wired_classify(WIRED_SYSFS_NET, lw->ifname);

        if (c != WIRED_IF_OK) {
            snprintf(msg, STATUS_MAX, "Interface '%s' is %s", lw->ifname, wired_class_reason(c));
            return -1;
        }
    }

    /* Root without CAP_NET_RAW (a container's --cap-drop) gains nothing by running
     * as root */
    if (lw->priv.no_net_raw) {
        snprintf(msg, STATUS_MAX, "Could not open '%s': kismet_cap_wired holds no CAP_NET_RAW; "
                "%s", lw->ifname, lw->priv.was_root ?
                "grant it CAP_NET_RAW, or run it as a user with 'setcap cap_net_raw+ep "
                "kismet_cap_wired'" :
                "set it with 'setcap cap_net_raw+ep kismet_cap_wired', or run it as root");
        return -1;
    }

    /* Everything a mistake in the options can fail goes before the bring-up */
    if (wired_create(lw, msg) < 0 ||
            wired_prepare_filter(caph, lw, filter, &netmask, msg) < 0) {
        wired_close(lw);
        return -1;
    }

    if ((lw->brought_up = wired_bring_up(lw, msg)) < 0) {
        lw->brought_up = 0;
        wired_close(lw);
        return -1;
    }

    if (wired_activate(lw, msg) < 0) {
        wired_close(lw);
        return -1;
    }

    if (wired_query_offloads(lw->ifname, &lw->status.offloads) < 0)
        lw->status.offloads = 0;

    lw->status.carrier = wired_read_carrier(WIRED_SYSFS_NET, lw->ifname);
#else
    lw->status.carrier = -1;

    {
        char pcaperr[PCAP_ERRBUF_SIZE] = "";

        if ((lw->pd = pcap_open_offline(lw->opts.replay, pcaperr)) == NULL) {
            snprintf(msg, STATUS_MAX, "Could not open replay file: %s", pcaperr);
            return -1;
        }
    }

    if (wired_prepare_filter(caph, lw, filter, &netmask, msg) < 0) {
        wired_close(lw);
        return -1;
    }
#endif

    if (pcap_datalink(lw->pd) != DLT_EN10MB) {
        snprintf(msg, STATUS_MAX, "Interface '%s' is not Ethernet (link type %d)",
                lw->ifname, pcap_datalink(lw->pd));
        wired_close(lw);
        return -1;
    }

    if (wired_set_filter(lw, filter, netmask, msg) < 0) {
        wired_close(lw);
        return -1;
    }

#ifndef WIRED_REPLAY
    if (pcap_setnonblock(lw->pd, 1, errstr) < 0) {
        snprintf(msg, STATUS_MAX, "Could not set '%s' non-blocking: %s", lw->ifname, errstr);
        wired_close(lw);
        return -1;
    }
#endif

    wired_sampler_init(&lw->sampler, lw->opts.sample);
    lw->status.sample = lw->opts.sample;
    lw->status.snaplen = lw->caplen_max;
    lw->status.buffer_mb = lw->opts.buffer_mb;
    lw->status.promisc = lw->opts.promisc;

    (*ret_interface)->capif = strdup(lw->ifname);
    (*ret_interface)->hardware = wired_hardware(lw->ifname);
    *uuid = wired_make_uuid(lw->ifname, &lw->opts);

    if ((*ret_interface)->capif == NULL || (*ret_interface)->hardware == NULL || *uuid == NULL) {
        snprintf(msg, STATUS_MAX, "Out of memory opening '%s'", lw->ifname);
        wired_close(lw);
        return -1;
    }

    *dlt = DLT_EN10MB;

    if (lw->status.offloads != 0 &&
            wired_offloads_describe(lw->status.offloads, offloads, sizeof(offloads)) > 0) {
        snprintf(errstr, sizeof(errstr), "Interface '%s' has offloads on (%s): merged frames "
                "are captured as one, and rx-vlan-filter can hide VLANs; turn them off with "
                "'ethtool -K %s <feature> off'", lw->ifname, offloads, lw->ifname);
        cf_send_message(caph, errstr, MSGFLAG_INFO);
    }

    if (lw->brought_up) {
        snprintf(errstr, sizeof(errstr), "Interface '%s' was down; kismet_cap_wired brought it "
                "up, and it stays up when the source closes", lw->ifname);
        cf_send_message(caph, errstr, MSGFLAG_INFO);
    }

    if (lw->has_selfprog)
        wired_remote_path_warning(caph, lw);

    if (lw->priv.userns_root) {
        const char *id = lw->priv.was_root ? "uid" : "gid";

        snprintf(errstr, sizeof(errstr), "Interface '%s': kismet_cap_wired stays %s 0 of its "
                "user namespace, which isn't %s 0 outside it, with only CAP_NET_RAW, as it %s; %s",
                lw->ifname, id, id, lw->priv.why,
                lw->priv.proc_sys_ro ? "/proc/sys is read-only to it" :
                "the net.* sysctls of a network namespace it owns stay writable to it");
        cf_send_message(caph, errstr, MSGFLAG_INFO);
    }

    if (wired_unknown_options(definition, unknown, sizeof(unknown)) > 0) {
        snprintf(errstr, sizeof(errstr), "Interface '%s': ignoring unknown source options (%s)",
                lw->ifname, unknown);
        cf_send_message(caph, errstr, MSGFLAG_ERROR);
    }

    snprintf(msg, STATUS_MAX, "Opened Ethernet interface '%s' (snaplen %u%s%s%s%s)", lw->ifname,
            lw->caplen_max, lw->brought_up ? ", brought up" : "",
            lw->opts.promisc ? ", promiscuous" : "",
            lw->opts.sample > 1 ? ", sampled" : "",
            lw->status.remote_excluded ? ", without the connection to the server" : "");

    return 1;
}

int open_callback(kis_capture_handler_t *caph, uint32_t seqno, char *definition,
        char *msg, uint32_t *dlt, char **uuid,
        cf_params_interface_t **ret_interface,
        cf_params_spectrum_t **ret_spectrum) {
    local_wired_t *lw = (local_wired_t *) caph->userdata;
    char failed[STATUS_MAX];
    int r = wired_open(caph, definition, msg, dlt, uuid, ret_interface, ret_spectrum);

    /* A failure after the bring-up says the interface was left up */
    if (r < 0 && lw->brought_up) {
        snprintf(failed, sizeof(failed), "%s; kismet_cap_wired brought '%s' up, and it stays up",
                msg, lw->ifname);
        snprintf(msg, STATUS_MAX, "%s", failed);
    }

    return r;
}

static void wired_dispatch_cb(u_char *user, const struct pcap_pkthdr *header,
        const u_char *data) {
    kis_capture_handler_t *caph = (kis_capture_handler_t *) user;
    local_wired_t *lw = (local_wired_t *) caph->userdata;
    uint32_t caplen, len;
    int ret;

    /* A frame cut before the fields the check reads fails closed; snaplen keeps
     * live frames longer than that */
    if (lw->has_selfprog && (wired_selfexcl_undecided(header->caplen, header->len) ||
                pcap_offline_filter(&lw->selfprog, header, data) != 0))
        return;

    lw->status.frames++;

    if (!wired_sampler_take(&lw->sampler))
        return;

    /* The kernel keeps to snaplen, a replayed file might not */
    caplen = header->caplen < lw->caplen_max ? header->caplen : lw->caplen_max;
    len = header->len < caplen ? caplen : header->len;

    /* A full ring waits for the server; the kernel ring drops meanwhile, and
     * those drops are reported */
    while (1) {
        ret = cf_send_data(caph, NULL, MSGFLAG_INFO, NULL, NULL, header->ts, DLT_EN10MB,
                len, caplen, (uint8_t *) data);

        if (ret < 0) {
            pcap_breakloop(lw->pd);
            cf_send_error(caph, 0, "unable to send DATA frame");
            cf_handler_spindown(caph);
            return;
        }

        if (ret > 0)
            break;

        if (caph->spindown || caph->shutdown) {
            pcap_breakloop(lw->pd);
            return;
        }

        cf_handler_wait_ringbuffer(caph);
    }

    lw->status.forwarded++;
}

/* The unsigned difference of 32 bit counters survives one wrap between reads */
static void wired_update_stats(kis_capture_handler_t *caph, local_wired_t *lw) {
#ifndef WIRED_REPLAY
    struct pcap_stat ps;
    char msg[STATUS_MAX];
    unsigned int offloads;
    time_t now;

    if (pcap_stats(lw->pd, &ps) < 0)
        return;

    lw->status.kernel_received += (unsigned int) (ps.ps_recv - lw->last_ps_recv);
    lw->status.kernel_drops += (unsigned int) (ps.ps_drop - lw->last_ps_drop);
    lw->status.if_drops += (unsigned int) (ps.ps_ifdrop - lw->last_ps_ifdrop);
    lw->last_ps_recv = ps.ps_recv;
    lw->last_ps_drop = ps.ps_drop;
    lw->last_ps_ifdrop = ps.ps_ifdrop;

    lw->status.carrier = wired_read_carrier(WIRED_SYSFS_NET, lw->ifname);

    /* Three unprivileged ethtool reads per status, so the server's warning follows
     * an 'ethtool -K'; a failed read keeps what was last seen */
    if (wired_query_offloads(lw->ifname, &offloads) > 0)
        lw->status.offloads = offloads;

    now = time(NULL);

    if (lw->status.kernel_drops > lw->drops_at_last_msg &&
            (lw->last_drop_msg == 0 || now - lw->last_drop_msg >= WIRED_DROP_MSG_INTERVAL_S)) {
        snprintf(msg, sizeof(msg), "Interface '%s': the kernel dropped %llu frames the capture "
                "couldn't keep up with; raise buffer_mb, use sample=, or filter=",
                lw->ifname, (unsigned long long) (lw->status.kernel_drops - lw->drops_at_last_msg));
        cf_send_message(caph, msg, MSGFLAG_ERROR);
        lw->drops_at_last_msg = lw->status.kernel_drops;
        lw->last_drop_msg = now;
    }
#else
    (void) caph;
    (void) lw;
#endif
}

static void wired_send_status(kis_capture_handler_t *caph, local_wired_t *lw) {
    char json[WIRED_STATUS_JSON_MAX];
    struct timeval tv;

    if (wired_status_json(&lw->status, json, sizeof(json)) < 0)
        return;

    gettimeofday(&tv, NULL);

    /* A full ring skips one; the next has the same counters, only newer */
    cf_send_json(caph, NULL, 0, NULL, NULL, tv, "wiredstatus", json);
}

/* Interface administratively down or gone: report it, and the server reopens
 * the source once it's back.  A cable pull with the interface up isn't an
 * error; frames just stop. */
static int wired_socket_error(local_wired_t *lw, short revents, char *msg, size_t msg_len) {
    int err = 0;
    socklen_t err_len = sizeof(err);

    if (!(revents & (POLLERR | POLLHUP | POLLNVAL)))
        return 0;

    if (getsockopt(pcap_get_selectable_fd(lw->pd), SOL_SOCKET, SO_ERROR, &err, &err_len) < 0)
        err = errno;

    snprintf(msg, msg_len, "Capture on '%s' failed: %s", lw->ifname,
            err != 0 ? strerror(err) : "the interface went down or was removed");

    return 1;
}

void capture_thread(kis_capture_handler_t *caph) {
    local_wired_t *lw = (local_wired_t *) caph->userdata;
    char msg[STATUS_MAX];
    uint64_t next_status;
    int fd = pcap_get_selectable_fd(lw->pd);
    int r;

    wired_send_status(caph, lw);
    next_status = wired_mono_ms() + WIRED_STATUS_INTERVAL_MS;

    while (!caph->spindown && !caph->shutdown) {
        short revents = 0;

#ifndef WIRED_REPLAY
        struct pollfd pfd;

        pfd.fd = fd;
        pfd.events = POLLIN;
        pfd.revents = 0;

        r = poll(&pfd, 1, WIRED_POLL_MS);

        if (r < 0 && errno != EINTR) {
            snprintf(msg, sizeof(msg), "Capture on '%s' failed waiting for frames: %s",
                    lw->ifname, strerror(errno));
            cf_send_error(caph, 0, msg);
            cf_handler_spindown(caph);
            break;
        }

        if (r > 0)
            revents = pfd.revents;
#else
        (void) fd;
#endif

        if (!lw->replay_eof) {
            r = pcap_dispatch(lw->pd, WIRED_DISPATCH_BATCH, wired_dispatch_cb, (u_char *) caph);

            if (r == PCAP_ERROR_BREAK)
                break;

            if (r < 0) {
                snprintf(msg, sizeof(msg), "Capture on '%s' failed: %s", lw->ifname,
                        pcap_geterr(lw->pd));
                cf_send_error(caph, 0, msg);
                cf_handler_spindown(caph);
                break;
            }

#ifdef WIRED_REPLAY
            /* A finished replay idles like pcapfile does, so the source doesn't error */
            if (r == 0) {
                lw->replay_eof = 1;
                next_status = 0;
            }
#endif
        } else {
            usleep(WIRED_POLL_MS * 1000);
        }

        if (wired_socket_error(lw, revents, msg, sizeof(msg))) {
            cf_send_error(caph, 0, msg);
            cf_handler_spindown(caph);
            break;
        }

        if (wired_mono_ms() >= next_status) {
            wired_update_stats(caph, lw);
            wired_send_status(caph, lw);
            next_status = wired_mono_ms() + WIRED_STATUS_INTERVAL_MS;
        }
    }
}

int main(int argc, char *argv[]) {
    local_wired_t local_wired;
    char drop_msg[STATUS_MAX];
    int r;

    memset(&local_wired, 0, sizeof(local_wired));

    kis_capture_handler_t *caph = cf_handler_init("wired");

    if (caph == NULL) {
        fprintf(stderr, "FATAL: Could not allocate basic handler data, your system "
                "is very low on RAM or something is wrong.\n");
        return -1;
    }

    cf_handler_set_userdata(caph, &local_wired);
    cf_handler_set_open_cb(caph, open_callback);
    cf_handler_set_probe_cb(caph, probe_callback);
    cf_handler_set_listdevices_cb(caph, list_callback);
    cf_handler_set_capture_cb(caph, capture_thread);

    r = cf_handler_parse_opts(caph, argc, argv);
    if (r == 0) {
        return 0;
    } else if (r < 0) {
        cf_print_help(caph, argv[0]);
        return -1;
    }

    /* The daemon fork would leave the bring-up child behind its exiting parent, so
     * it goes first */
    cf_handler_daemonize(caph);

    /* Before any thread or connection: from here on only the bring-up child holds
     * CAP_NET_ADMIN, and no --retry monitor or capture process does */
    if (wired_ifupd_start(&local_wired.ifupd) < 0) {
        fprintf(stderr, "FATAL: kismet_cap_wired could not drop CAP_NET_ADMIN: %s\n",
                strerror(errno));
        cf_handler_free(caph);
        return -1;
    }

    cf_handler_remote_capture(caph);

    /* Never capture as root, nor with more than CAP_NET_RAW: a failed drop or
     * switch, or root or more than CAP_NET_RAW in a build without libcap, stops the
     * helper.  Unprivileged, the sets are still cut to CAP_NET_RAW, so a broader
     * file capability or an inherited ambient set doesn't stay */
    if (wired_drop_privileges(caph, &local_wired.priv) < 0) {
        fprintf(stderr, "FATAL: kismet_cap_wired %s\n", local_wired.priv.why);

        /* The server shows messages but not error frames.  Spun down, the loop
         * sends what is queued and stops without reading a request.  A websocket
         * isn't connected until the loop runs, and connecting resets spindown, so
         * that one just exits */
        if (caph->use_ipc || caph->tcp_fd >= 0) {
            snprintf(drop_msg, sizeof(drop_msg), "kismet_cap_wired %s", local_wired.priv.why);
            cf_send_message(caph, drop_msg, MSGFLAG_ERROR);
            cf_send_error(caph, 0, drop_msg);
            cf_handler_spindown(caph);
            cf_handler_loop(caph);
        }

        cf_handler_shutdown(caph);
        cf_handler_free(caph);
        return -1;
    }

    cf_handler_loop(caph);

    cf_handler_shutdown(caph);

    wired_close(&local_wired);

    cf_handler_free(caph);

    return 1;
}
