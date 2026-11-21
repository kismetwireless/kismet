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

#ifndef __WIRED_SYSFS_H__
#define __WIRED_SYSFS_H__

#include "../config.h"

#include <stddef.h>
#include <stdint.h>

#include "wired_util.h"

/* Linux interface inspection for kismet_cap_wired.  The sysfs root is a
 * parameter so the tests can point it at a made-up tree. */

#define WIRED_SYSFS_NET         "/sys/class/net"

/* Most interfaces --list offers */
#define WIRED_LIST_MAX          256

#define WIRED_DRIVER_MAX        32

typedef enum {
    WIRED_IF_OK = 0,
    WIRED_IF_BADNAME,
    WIRED_IF_MISSING,
    WIRED_IF_NOT_ETHERNET,
    WIRED_IF_LOOPBACK,
    WIRED_IF_WIRELESS,
    /* Its /sys entry isn't this network namespace's (wired_classify_link) */
    WIRED_IF_UNVERIFIED,
} wired_if_class_t;

/* Whether ifname is an Ethernet interface the helper captures from: ARPHRD_ETHER,
 * not loopback, and not a Wi-Fi interface in managed mode (also ARPHRD_ETHER) */
wired_if_class_t wired_classify(const char *sysfs_root, const char *ifname);

/* Why an interface isn't captured from, for the probe and open messages */
const char *wired_class_reason(wired_if_class_t c);

/* The interface's MAC address.  Returns 1, or -1 if it can't be read or isn't
 * 6 colon-separated hex bytes */
int wired_read_mac(const char *sysfs_root, const char *ifname, uint8_t mac[6]);

/* The kernel driver's name, or "" for a virtual interface or a name outside
 * [A-Za-z0-9._-] */
void wired_read_driver(const char *sysfs_root, const char *ifname, char *out, size_t out_len);

/* 1 with a link, 0 without, -1 unknown (the kernel refuses the read while the
 * interface is down) */
int wired_read_carrier(const char *sysfs_root, const char *ifname);

/* 1 when the interface is administratively up (IFF_UP), 0 when down, -1 unknown */
int wired_read_up(const char *sysfs_root, const char *ifname);

/* Sets IFF_UP and nothing else on the link with index ifindex, with an RTM_NEWLINK
 * naming no interface; needs CAP_NET_ADMIN.  Returns 1, or -1 with errno set (EPERM
 * without the capability) */
int wired_set_up(int ifindex);

/* The link named ifname, or with ifname NULL the one with index ifindex, as
 * rtnetlink in this process's network namespace shows it.  Returns 1, or -1 with
 * errno set (ENODEV when there's no such link) */
int wired_nl_getlink(const char *ifname, int ifindex, wired_nl_link_t *link);

/* 1 when ifname is up (IFF_UP) in this network namespace, 0 when down, -1 unknown */
int wired_nl_read_up(const char *ifname);

/* wired_classify for a link rtnetlink showed: its type and flags decide, and
 * WIRED_IF_UNVERIFIED when sysfs_root has no directory of its name with its index
 * (a /sys mounted for another network namespace), so the Wi-Fi checks can't be
 * made there */
wired_if_class_t wired_classify_link(const char *sysfs_root, const wired_nl_link_t *link);

/* Interfaces stacked between an address's interface and the captured one, the
 * kernel's own nesting limit (MAX_NEST_DEV): a bridge on a bond on a VLAN on the
 * NIC is three */
#define WIRED_STACK_DEPTH       8

/* An interface's rtnetlink link kind ("vlan", "bridge"...).  Returns 1 with kind
 * set, 0 for an interface without one, or -1 if it can't be told */
typedef int (*wired_kind_fn)(const char *ifname, char *kind, size_t kind_len);

/* The kind from the kernel, an unprivileged RTM_GETLINK; sysfs names only some
 * kinds (macvlan, ipvlan and team have no DEVTYPE) */
int wired_if_kind(const char *ifname, char *kind, size_t kind_len);

/* Most sysfs entries --list looks at */
#define WIRED_LIST_SCAN_MAX     16384

/* Names of the interfaces wired_classify accepts, at most max: NICs first, then
 * other virtual interfaces, then veth and tun/tap (one per container or VM, by
 * kind), each sorted by name, so a container host's NICs aren't crowded out.
 * Returns how many */
size_t wired_list_interfaces(const char *sysfs_root, wired_kind_fn kind,
        char names[][WIRED_IFNAMSIZ], size_t max);

typedef enum {
    /* lower isn't under upper */
    WIRED_STACK_NONE = 0,
    /* Every way down from upper to lower passes frames the exclusion matches */
    WIRED_STACK_MATCHED,
    /* Some way down tags them more than WIRED_SELFEXCL_TAGS times, or goes through
     * an interface which isn't known to pass them through unchanged */
    WIRED_STACK_UNMATCHED,
    /* Not found, but the walk ran out of its directory budget before it had looked
     * everywhere */
    WIRED_STACK_UNKNOWN,
} wired_stack_t;

/* How frames of upper reach lower: the same interface, or lower found under upper
 * through sysfs lower_* links, at most WIRED_STACK_DEPTH deep (the kernel's own
 * limit) and 256 directories read.  Each interface on the way is looked
 * up with kind: VLANs add a tag, and a bridge does when it has vlan_filtering on
 * (or it can't be read) */
wired_stack_t wired_if_stacked_on(const char *sysfs_root, wired_kind_fn kind, const char *upper,
        const char *lower);

/* The interface holding a local address, from getifaddrs.  Returns 1, or -1 if
 * no interface has it */
int wired_addr_ifname(const struct sockaddr *local, char *ifname, size_t ifname_len);

/* Where the server connection runs, from the server's address, whether this host
 * has that address (peer_local), and the interface holding the connection's local
 * address (NULL when none has it) */
wired_path_t wired_remote_path(const char *sysfs_root, wired_kind_fn kind, const char *capif,
        const struct sockaddr *peer, int peer_local, const char *local_if);

/* The offloads from wired_util.h which are on, through the unprivileged
 * ETHTOOL_GSSET_INFO, ETHTOOL_GSTRINGS and ETHTOOL_GFEATURES.  Returns 1, or -1
 * if the driver doesn't say */
int wired_query_offloads(const char *ifname, unsigned int *offloads);

#endif
