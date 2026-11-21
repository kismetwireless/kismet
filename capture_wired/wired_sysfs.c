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

#include "wired_sysfs.h"

#include <dirent.h>
#include <errno.h>
#include <fcntl.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#include <ifaddrs.h>
#include <netinet/in.h>

#include <sys/ioctl.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <sys/time.h>

#include <net/if.h>
#include <linux/ethtool.h>
#include <linux/if_link.h>
#include <linux/netlink.h>
#include <linux/rtnetlink.h>
#include <linux/sockios.h>

/* if_arp.h ARPHRD_ETHER and ARPHRD_LOOPBACK, if.h IFF_LOOPBACK */
#define WIRED_ARPHRD_ETHER      1
#define WIRED_ARPHRD_LOOPBACK   772
#define WIRED_IFF_LOOPBACK      0x8

/* Far more feature strings than any kernel has (about 70 in 6.x) */
#define WIRED_FEATURES_MAX      1024

#define WIRED_SYSFS_PATH_MAX    512

static int wired_path(char *out, size_t out_len, const char *root, const char *ifname,
        const char *leaf) {
    int r;

    if (leaf == NULL)
        r = snprintf(out, out_len, "%s/%s", root, ifname);
    else
        r = snprintf(out, out_len, "%s/%s/%s", root, ifname, leaf);

    if (r < 0 || (size_t) r >= out_len)
        return -1;

    return 1;
}

/* A small sysfs attribute, NUL terminated, trailing newline removed */
static ssize_t wired_read_attr(const char *root, const char *ifname, const char *leaf,
        char *out, size_t out_len) {
    char path[WIRED_SYSFS_PATH_MAX];
    ssize_t r;
    int fd;

    if (out_len < 2 || wired_path(path, sizeof(path), root, ifname, leaf) < 0)
        return -1;

    if ((fd = open(path, O_RDONLY | O_CLOEXEC)) < 0)
        return -1;

    do {
        r = read(fd, out, out_len - 1);
    } while (r < 0 && errno == EINTR);

    close(fd);

    if (r < 0)
        return -1;

    out[r] = 0;

    while (r > 0 && (out[r - 1] == '\n' || out[r - 1] == '\r'))
        out[--r] = 0;

    return r;
}

static int wired_exists(const char *root, const char *ifname, const char *leaf) {
    char path[WIRED_SYSFS_PATH_MAX];
    struct stat sb;

    if (wired_path(path, sizeof(path), root, ifname, leaf) < 0)
        return 0;

    return lstat(path, &sb) == 0;
}

static int wired_parse_long(const char *s, int base, long *ret) {
    char *end = NULL;
    long v;

    if (s == NULL || s[0] == 0)
        return -1;

    errno = 0;
    v = strtol(s, &end, base);

    if (errno != 0 || end == s || *end != 0)
        return -1;

    *ret = v;
    return 1;
}

static int wired_uevent_is_wlan(const char *root, const char *ifname) {
    char buf[1024];
    char *line, *save = NULL;

    if (wired_read_attr(root, ifname, "uevent", buf, sizeof(buf)) < 0)
        return 0;

    for (line = strtok_r(buf, "\n", &save); line != NULL; line = strtok_r(NULL, "\n", &save)) {
        if (strcmp(line, "DEVTYPE=wlan") == 0)
            return 1;
    }

    return 0;
}

wired_if_class_t wired_classify(const char *sysfs_root, const char *ifname) {
    char buf[32];
    long v;

    if (ifname == NULL || !wired_ifname_valid(ifname, strlen(ifname)))
        return WIRED_IF_BADNAME;

    if (!wired_exists(sysfs_root, ifname, NULL))
        return WIRED_IF_MISSING;

    if (wired_read_attr(sysfs_root, ifname, "type", buf, sizeof(buf)) < 0 ||
            wired_parse_long(buf, 10, &v) < 0)
        return WIRED_IF_MISSING;

    if (v == WIRED_ARPHRD_LOOPBACK)
        return WIRED_IF_LOOPBACK;

    if (v != WIRED_ARPHRD_ETHER)
        return WIRED_IF_NOT_ETHERNET;

    if (wired_read_attr(sysfs_root, ifname, "flags", buf, sizeof(buf)) >= 0 &&
            wired_parse_long(buf, 16, &v) >= 0 && (v & WIRED_IFF_LOOPBACK))
        return WIRED_IF_LOOPBACK;

    /* A managed-mode Wi-Fi interface is ARPHRD_ETHER too */
    if (wired_exists(sysfs_root, ifname, "wireless") ||
            wired_exists(sysfs_root, ifname, "phy80211") ||
            wired_uevent_is_wlan(sysfs_root, ifname))
        return WIRED_IF_WIRELESS;

    return WIRED_IF_OK;
}

const char *wired_class_reason(wired_if_class_t c) {
    switch (c) {
        case WIRED_IF_OK:
            return "Ethernet interface";
        case WIRED_IF_BADNAME:
            return "not a valid interface name";
        case WIRED_IF_MISSING:
            return "no such interface";
        case WIRED_IF_NOT_ETHERNET:
            return "not an Ethernet interface";
        case WIRED_IF_LOOPBACK:
            return "a loopback interface";
        case WIRED_IF_WIRELESS:
            return "a Wi-Fi interface, use the linuxwifi source";
    }

    return "unknown";
}

static int wired_hexval(char c) {
    if (c >= '0' && c <= '9')
        return c - '0';
    if (c >= 'a' && c <= 'f')
        return c - 'a' + 10;
    if (c >= 'A' && c <= 'F')
        return c - 'A' + 10;
    return -1;
}

int wired_read_mac(const char *sysfs_root, const char *ifname, uint8_t mac[6]) {
    char buf[32];
    int i;

    if (!wired_ifname_valid(ifname, strlen(ifname)))
        return -1;

    if (wired_read_attr(sysfs_root, ifname, "address", buf, sizeof(buf)) != 17)
        return -1;

    for (i = 0; i < 6; i++) {
        int hi = wired_hexval(buf[i * 3]);
        int lo = wired_hexval(buf[i * 3 + 1]);

        if (hi < 0 || lo < 0 || (i < 5 && buf[i * 3 + 2] != ':'))
            return -1;

        mac[i] = (uint8_t) ((hi << 4) | lo);
    }

    return 1;
}

void wired_read_driver(const char *sysfs_root, const char *ifname, char *out, size_t out_len) {
    char path[WIRED_SYSFS_PATH_MAX];
    char link[WIRED_SYSFS_PATH_MAX];
    const char *base;
    ssize_t r;
    size_t i, l;

    if (out == NULL || out_len == 0)
        return;

    out[0] = 0;

    if (!wired_ifname_valid(ifname, strlen(ifname)) ||
            wired_path(path, sizeof(path), sysfs_root, ifname, "device/driver") < 0)
        return;

    if ((r = readlink(path, link, sizeof(link) - 1)) <= 0)
        return;

    link[r] = 0;

    base = strrchr(link, '/');
    base = base == NULL ? link : base + 1;
    l = strlen(base);

    if (l == 0 || l >= out_len || l >= WIRED_DRIVER_MAX)
        return;

    for (i = 0; i < l; i++) {
        char c = base[i];

        if (!((c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z') || (c >= '0' && c <= '9') ||
                    c == '.' || c == '_' || c == '-'))
            return;
    }

    memcpy(out, base, l + 1);
}

int wired_read_carrier(const char *sysfs_root, const char *ifname) {
    char buf[8];

    if (!wired_ifname_valid(ifname, strlen(ifname)) ||
            wired_read_attr(sysfs_root, ifname, "carrier", buf, sizeof(buf)) != 1)
        return -1;

    if (buf[0] == '1')
        return 1;
    if (buf[0] == '0')
        return 0;

    return -1;
}

/* A NIC (it has a device), any other virtual interface, then the kinds a host makes
 * one of per container or VM */
static int wired_list_rank(const char *sysfs_root, wired_kind_fn kind, const char *ifname) {
    char k[WIRED_KIND_MAX];

    if (wired_exists(sysfs_root, ifname, "device"))
        return 0;

    if (kind != NULL && kind(ifname, k, sizeof(k)) > 0 &&
            (strcmp(k, "veth") == 0 || strcmp(k, "tun") == 0))
        return 2;

    return 1;
}

size_t wired_list_interfaces(const char *sysfs_root, wired_kind_fn kind,
        char names[][WIRED_IFNAMSIZ], size_t max) {
    DIR *d;
    struct dirent *de;
    int *ranks;
    size_t n = 0, scanned = 0, i;

    if (max == 0 || (ranks = calloc(max, sizeof(*ranks))) == NULL)
        return 0;

    if ((d = opendir(sysfs_root)) == NULL) {
        free(ranks);
        return 0;
    }

    /* The best max by rank, then name, kept sorted; each entry costs sysfs reads
     * and maybe a netlink request, so a huge host is only read so far */
    while (scanned < WIRED_LIST_SCAN_MAX && (de = readdir(d)) != NULL) {
        size_t l = strlen(de->d_name);
        int rank;

        scanned++;

        if (!wired_ifname_valid(de->d_name, l) ||
                wired_classify(sysfs_root, de->d_name) != WIRED_IF_OK)
            continue;

        /* A full list of NICs can't take a virtual one */
        if (n == max && ranks[n - 1] == 0 && !wired_exists(sysfs_root, de->d_name, "device"))
            continue;

        rank = wired_list_rank(sysfs_root, kind, de->d_name);

        for (i = n; i > 0; i--) {
            if (ranks[i - 1] < rank || (ranks[i - 1] == rank && strcmp(names[i - 1], de->d_name) < 0))
                break;
        }

        if (i == max)
            continue;

        if (n < max)
            n++;

        /* Full, the last one falls off */
        if (i + 1 < n) {
            memmove(names[i + 1], names[i], (n - 1 - i) * WIRED_IFNAMSIZ);
            memmove(&ranks[i + 1], &ranks[i], (n - 1 - i) * sizeof(*ranks));
        }

        memcpy(names[i], de->d_name, l + 1);
        ranks[i] = rank;
    }

    closedir(d);
    free(ranks);

    return n;
}

/* One link's RTM_NEWLINK without VF lists is a few KB */
#define WIRED_NL_REPLY_MAX      32768
#define WIRED_NL_READS          8
#define WIRED_NL_SEQ            0x4b57

typedef struct {
    struct nlmsghdr nh;
    struct ifinfomsg ifi;
    uint8_t attrs[RTA_SPACE(WIRED_IFNAMSIZ)];
} wired_nl_getlink_t;

int wired_if_kind(const char *ifname, char *kind, size_t kind_len) {
    wired_nl_getlink_t req;
    struct sockaddr_nl kernel, from;
    struct rtattr rta;
    struct timeval tv = { 1, 0 };
    socklen_t from_len;
    uint8_t *buf = NULL;
    ssize_t r;
    size_t l;
    int fd, i, ret = -1;

    if (kind == NULL || kind_len == 0)
        return -1;

    kind[0] = 0;

    if (ifname == NULL || !wired_ifname_valid(ifname, (l = strlen(ifname))))
        return -1;

    memset(&req, 0, sizeof(req));
    req.nh.nlmsg_type = RTM_GETLINK;
    req.nh.nlmsg_flags = NLM_F_REQUEST;
    req.nh.nlmsg_seq = WIRED_NL_SEQ;
    req.ifi.ifi_family = AF_UNSPEC;

    /* Asked by name, so there's no index to go stale between lookups */
    rta.rta_type = IFLA_IFNAME;
    rta.rta_len = (unsigned short) RTA_LENGTH(l + 1);
    memcpy(req.attrs, &rta, sizeof(rta));
    memcpy(req.attrs + RTA_LENGTH(0), ifname, l + 1);
    req.nh.nlmsg_len = (uint32_t) (offsetof(wired_nl_getlink_t, attrs) + RTA_SPACE(l + 1));

    if ((fd = socket(AF_NETLINK, SOCK_RAW | SOCK_CLOEXEC, NETLINK_ROUTE)) < 0)
        return -1;

    memset(&kernel, 0, sizeof(kernel));
    kernel.nl_family = AF_NETLINK;

    if (setsockopt(fd, SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof(tv)) < 0 ||
            sendto(fd, &req, req.nh.nlmsg_len, 0, (struct sockaddr *) &kernel,
                sizeof(kernel)) != (ssize_t) req.nh.nlmsg_len ||
            (buf = malloc(WIRED_NL_REPLY_MAX)) == NULL)
        goto out;

    for (i = 0; i < WIRED_NL_READS; i++) {
        memset(&from, 0, sizeof(from));
        from_len = sizeof(from);

        r = recvfrom(fd, buf, WIRED_NL_REPLY_MAX, MSG_TRUNC, (struct sockaddr *) &from, &from_len);

        if (r < 0 && errno == EINTR)
            continue;

        if (r < 0 || (size_t) r > WIRED_NL_REPLY_MAX)
            break;

        /* Another process can write to this socket too; only the kernel answers */
        if (from_len < sizeof(from) || from.nl_family != AF_NETLINK || from.nl_pid != 0)
            continue;

        ret = wired_nl_link_kind(buf, (size_t) r, WIRED_NL_SEQ, kind, kind_len);
        break;
    }

out:
    free(buf);
    close(fd);

    return ret;
}

/* Directories read in one stacking check, so a wide bridge of bonds stays cheap */
#define WIRED_STACK_VISITS      256

typedef struct {
    const char *root;
    wired_kind_fn kind;
    const char *lower;
    unsigned int visits;
    int unmatched;
    /* An interface left unread for the budget */
    int cut;
} wired_walk_t;

/* Tags upper adds to what it sends down, or -1 when the exclusion can't follow it */
static int wired_hop_tags(const wired_walk_t *w, const char *upper) {
    char kind[WIRED_KIND_MAX];
    char buf[8];

    if (w->kind(upper, kind, sizeof(kind)) <= 0)
        return -1;

    switch (wired_kind_hop(kind)) {
        case WIRED_HOP_TAG:
            return 1;
        case WIRED_HOP_PASS:
            /* A VLAN-aware bridge can tag frames on their way out a port */
            if (strcmp(kind, "bridge") == 0 &&
                    (wired_read_attr(w->root, upper, "bridge/vlan_filtering", buf, sizeof(buf)) != 1 ||
                     buf[0] != '0'))
                return 1;
            return 0;
        case WIRED_HOP_OPAQUE:
        default:
            return -1;
    }
}

/* 1 when a way down from upper reaches w->lower with frames the exclusion matches;
 * one which doesn't sets w->unmatched, and ends the walk */
static int wired_walk(wired_walk_t *w, const char *upper, unsigned int depth, unsigned int tags,
        int opaque) {
    char path[WIRED_SYSFS_PATH_MAX];
    struct dirent *de;
    DIR *d;
    int found = 0, hop = 0, hop_known = 0;

    if (strcmp(upper, w->lower) == 0) {
        if (opaque || tags > WIRED_SELFEXCL_TAGS) {
            w->unmatched = 1;
            return 0;
        }

        return 1;
    }

    if (depth == 0)
        return 0;

    if (w->visits >= WIRED_STACK_VISITS) {
        w->cut = 1;
        return 0;
    }

    w->visits++;

    if (wired_path(path, sizeof(path), w->root, upper, NULL) < 0 || (d = opendir(path)) == NULL)
        return 0;

    while (!w->unmatched && (de = readdir(d)) != NULL) {
        if (strncmp(de->d_name, "lower_", 6) != 0 ||
                !wired_ifname_valid(de->d_name + 6, strlen(de->d_name + 6)))
            continue;

        /* Looked up once, and only for an interface with something under it */
        if (!hop_known) {
            hop = wired_hop_tags(w, upper);
            hop_known = 1;
        }

        if (wired_walk(w, de->d_name + 6, depth - 1, hop < 0 ? tags : tags + (unsigned int) hop,
                    opaque || hop < 0))
            found = 1;
    }

    closedir(d);

    return found;
}

wired_stack_t wired_if_stacked_on(const char *sysfs_root, wired_kind_fn kind, const char *upper,
        const char *lower) {
    wired_walk_t w;
    int found;

    if (kind == NULL || upper == NULL || lower == NULL ||
            !wired_ifname_valid(upper, strlen(upper)) || !wired_ifname_valid(lower, strlen(lower)))
        return WIRED_STACK_NONE;

    memset(&w, 0, sizeof(w));
    w.root = sysfs_root;
    w.kind = kind;
    w.lower = lower;

    found = wired_walk(&w, upper, WIRED_STACK_DEPTH, 0, 0);

    if (w.unmatched)
        return WIRED_STACK_UNMATCHED;

    if (found)
        return WIRED_STACK_MATCHED;

    return w.cut ? WIRED_STACK_UNKNOWN : WIRED_STACK_NONE;
}

int wired_addr_ifname(const struct sockaddr *local, char *ifname, size_t ifname_len) {
    struct ifaddrs *ifa_list = NULL, *ifa;
    int r = -1;

    if (local == NULL || ifname == NULL || ifname_len == 0 || getifaddrs(&ifa_list) < 0)
        return -1;

    for (ifa = ifa_list; ifa != NULL; ifa = ifa->ifa_next) {
        size_t l;

        if (ifa->ifa_addr == NULL || ifa->ifa_name == NULL ||
                (ifa->ifa_addr->sa_family != AF_INET && ifa->ifa_addr->sa_family != AF_INET6) ||
                !wired_addr_same(local, ifa->ifa_addr))
            continue;

        /* A link-local address names its interface by scope */
        if (local->sa_family == AF_INET6 && ifa->ifa_addr->sa_family == AF_INET6) {
            const struct sockaddr_in6 *l6 = (const struct sockaddr_in6 *) local;
            const struct sockaddr_in6 *i6 = (const struct sockaddr_in6 *) ifa->ifa_addr;

            if (IN6_IS_ADDR_LINKLOCAL(&l6->sin6_addr) && l6->sin6_scope_id != 0 &&
                    l6->sin6_scope_id != i6->sin6_scope_id)
                continue;
        }

        /* An IPv4 alias is labelled "eth0:1" */
        l = strcspn(ifa->ifa_name, ":");

        if (l >= ifname_len || !wired_ifname_valid(ifa->ifa_name, l))
            continue;

        memcpy(ifname, ifa->ifa_name, l);
        ifname[l] = 0;
        r = 1;
        break;
    }

    freeifaddrs(ifa_list);

    return r;
}

wired_path_t wired_remote_path(const char *sysfs_root, wired_kind_fn kind, const char *capif,
        const struct sockaddr *peer, int peer_local, const char *local_if) {
    char k[WIRED_KIND_MAX];

    /* A connection to this host's own address runs over loopback too */
    if (peer_local || wired_addr_loopback(peer))
        return WIRED_PATH_LOOPBACK;

    if (local_if == NULL)
        return WIRED_PATH_UNKNOWN;

    /* A service address on lo, a dummy or a VRF leaves through whatever the route
     * says, not the interface holding it; a VRF's ports are under it, but it adds
     * nothing to their frames */
    if ((capif == NULL || strcmp(local_if, capif) != 0) &&
            (wired_classify(sysfs_root, local_if) == WIRED_IF_LOOPBACK ||
             (kind != NULL && kind(local_if, k, sizeof(k)) > 0 &&
              (strcmp(k, "dummy") == 0 || strcmp(k, "vrf") == 0))))
        return WIRED_PATH_UNKNOWN;

    switch (wired_if_stacked_on(sysfs_root, kind, local_if, capif)) {
        case WIRED_STACK_MATCHED:
            return WIRED_PATH_CAPTURED;
        case WIRED_STACK_UNMATCHED:
            return WIRED_PATH_UNMATCHED;
        case WIRED_STACK_UNKNOWN:
            return WIRED_PATH_UNKNOWN;
        case WIRED_STACK_NONE:
        default:
            break;
    }

    return WIRED_PATH_OTHER;
}

int wired_query_offloads(const char *ifname, unsigned int *offloads) {
    struct ifreq ifr;
    struct ethtool_sset_info *sset = NULL;
    struct ethtool_gstrings *strs = NULL;
    struct ethtool_gfeatures *feats = NULL;
    uint32_t active[(WIRED_FEATURES_MAX + 31) / 32];
    size_t n, blocks, i;
    int fd, ret = -1;

    *offloads = 0;

    if (!wired_ifname_valid(ifname, strlen(ifname)))
        return -1;

    if ((fd = socket(AF_INET, SOCK_DGRAM | SOCK_CLOEXEC, 0)) < 0)
        return -1;

    memset(&ifr, 0, sizeof(ifr));
    memcpy(ifr.ifr_name, ifname, strlen(ifname));

    sset = calloc(1, sizeof(*sset) + sizeof(uint32_t));
    if (sset == NULL)
        goto out;

    sset->cmd = ETHTOOL_GSSET_INFO;
    sset->sset_mask = 1ULL << ETH_SS_FEATURES;
    ifr.ifr_data = (void *) sset;

    if (ioctl(fd, SIOCETHTOOL, &ifr) < 0 || !(sset->sset_mask & (1ULL << ETH_SS_FEATURES)))
        goto out;

    n = sset->data[0];

    if (n == 0 || n > WIRED_FEATURES_MAX)
        goto out;

    strs = calloc(1, sizeof(*strs) + n * ETH_GSTRING_LEN);
    if (strs == NULL)
        goto out;

    strs->cmd = ETHTOOL_GSTRINGS;
    strs->string_set = ETH_SS_FEATURES;
    strs->len = (uint32_t) n;
    ifr.ifr_data = (void *) strs;

    if (ioctl(fd, SIOCETHTOOL, &ifr) < 0)
        goto out;

    if (strs->len < n)
        n = strs->len;

    blocks = (n + 31) / 32;

    feats = calloc(1, sizeof(*feats) + blocks * sizeof(struct ethtool_get_features_block));
    if (feats == NULL)
        goto out;

    feats->cmd = ETHTOOL_GFEATURES;
    feats->size = (uint32_t) blocks;
    ifr.ifr_data = (void *) feats;

    if (ioctl(fd, SIOCETHTOOL, &ifr) < 0)
        goto out;

    /* The kernel answers with how many blocks it has; only read what was allocated */
    if (feats->size < blocks)
        blocks = feats->size;

    for (i = 0; i < blocks; i++)
        active[i] = feats->features[i].active;

    *offloads = wired_offloads_from_features((const char *) strs->data, ETH_GSTRING_LEN,
            n, active, blocks);
    ret = 1;

out:
    free(sset);
    free(strs);
    free(feats);
    close(fd);

    return ret;
}
