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

#ifndef __WIRED_UTIL_H__
#define __WIRED_UTIL_H__

#include "../config.h"

#include <stddef.h>
#include <stdint.h>

#include <sys/socket.h>
#include <sys/types.h>

/* Option parsing, filter building, sampling and status formatting for
 * kismet_cap_wired; nothing here touches an interface, so the tests link it
 * without privileges */

/* Linux IFNAMSIZ, including the NUL */
#define WIRED_IFNAMSIZ          16

/* The server's MAX_EXTERNAL_FRAME_LEN (kis_external.h).  It errors the whole
 * source over a larger IPC frame, and the reopened source sends the same frame
 * again, so no frame may get near it */
#define WIRED_IPC_FRAME_MAX     16384U

/* The v3 frame header, the report map, the packet block and a fixed-GPS block
 * without its name take under 200 bytes; the rest is margin */
#define WIRED_IPC_OVERHEAD      512U

#define WIRED_SNAPLEN_DEFAULT   1600U
/* At least WIRED_SELFEXCL_DEPTH, so the per-frame server re-check always sees
 * every field it reads in a cut frame */
#define WIRED_SNAPLEN_MIN       96U
#define WIRED_SNAPLEN_MAX       (WIRED_IPC_FRAME_MAX - WIRED_IPC_OVERHEAD)

#define WIRED_BUFFER_MB_DEFAULT 64U
#define WIRED_BUFFER_MB_MIN     1U
#define WIRED_BUFFER_MB_MAX     1024U

#define WIRED_SAMPLE_MAX        1000000U

#define WIRED_FILTER_MAX        1024U

/* VLAN tags in front of the server connection's frames which the exclusion
 * still matches; libpcap puts back a tag the kernel stripped, so a frame can
 * show one more tag than the kernel filter saw */
#define WIRED_SELFEXCL_TAGS     3

/* The deepest byte the exclusion reads: an IPv4 destination port behind
 * WIRED_SELFEXCL_TAGS tags and a 60 byte IP header with options */
#define WIRED_SELFEXCL_DEPTH    (14U + 4U * WIRED_SELFEXCL_TAGS + 60U + 4U)

#if WIRED_SNAPLEN_MIN < WIRED_SELFEXCL_DEPTH
#error "WIRED_SNAPLEN_MIN must cover WIRED_SELFEXCL_DEPTH"
#endif

/* An IPv6 server matched behind 0 to WIRED_SELFEXCL_TAGS tags */
#define WIRED_SELFEXCL_MAX      2560

/* Room for the user filter, the self-exclusion and the glue between them */
#define WIRED_FULL_FILTER_MAX   (WIRED_FILTER_MAX + WIRED_SELFEXCL_MAX + 64)

#define WIRED_STATUS_JSON_MAX   512

#define WIRED_UUID_LEN          36

/* Offloads which change what a capture sees */
#define WIRED_OFFLOAD_GRO           (1U << 0)
#define WIRED_OFFLOAD_GRO_HW        (1U << 1)
#define WIRED_OFFLOAD_LRO           (1U << 2)
#define WIRED_OFFLOAD_RX_VLAN_FILT  (1U << 3)
#define WIRED_OFFLOAD_TSO           (1U << 4)
#define WIRED_OFFLOAD_TSO6          (1U << 5)
#define WIRED_OFFLOAD_GSO           (1U << 6)
#define WIRED_OFFLOAD_COUNT         7

/* Kernel feature names, ETH_SS_FEATURES strings */
extern const char *const wired_offload_names[WIRED_OFFLOAD_COUNT];

typedef struct {
    unsigned int snaplen;
    unsigned int buffer_mb;
    unsigned int sample;
    int promisc;
    /* Bring a down interface up at open */
    int ifup;
    int has_filter;
    char filter[WIRED_FILTER_MAX + 1];
    int has_uuid;
    char uuid[WIRED_UUID_LEN + 1];
#ifdef WIRED_REPLAY
    char replay[4096];
#endif
} wired_opts_t;

/* 1 for an interface name Linux could have: 1 to IFNAMSIZ-1 characters of
 * [A-Za-z0-9._@-], not starting with a dot, so it can't walk out of a sysfs
 * directory */
int wired_ifname_valid(const char *name, size_t len);

/* Parse the source options in a definition into opts, with defaults for the
 * ones missing.  Returns 1, or -1 with errstr filled */
int wired_parse_opts(char *definition, wired_opts_t *opts, char *errstr, size_t errstr_len);

/* 1 when every ')' closes an earlier '(' and none is left open.  The filter is
 * put inside parentheses next to the self-exclusion, which an unbalanced one
 * could climb out of */
int wired_filter_balanced(const char *filter, size_t len);

/* The option names in a definition which neither the helper nor the server
 * reads, comma separated, each cut to 32 characters and anything outside
 * [A-Za-z0-9_-] shown as '?'.  Returns how many, writing as many as fit */
int wired_unknown_options(const char *definition, char *out, size_t out_len);

/* The most bytes of a frame to send: snaplen, less what a fixed-GPS name adds
 * to every report.  0 when the name leaves less than WIRED_SNAPLEN_MIN */
unsigned int wired_caplen_limit(unsigned int snaplen, size_t gps_name_len);

/* Decimal digits only, no sign or spaces, in [min, max].  Returns 1 or -1 */
int wired_parse_uint(const char *str, size_t len, unsigned long min, unsigned long max,
        unsigned long *ret);

/* true or false, any case.  Returns 1 or -1 */
int wired_parse_bool(const char *str, size_t len, int *ret);

/* 8-4-4-4-12 hex.  Returns 1 or -1 */
int wired_uuid_valid(const char *str, size_t len);

/* The source UUID for an interface: a fixed prefix, a hash of the name, and
 * the MAC when there is one.  VLAN interfaces, bridges and bonds share their
 * parent's MAC, so the name keeps their sources apart.  out holds at least
 * WIRED_UUID_LEN + 1.  Returns 1, or -1 */
int wired_format_uuid(const char *ifname, const uint8_t *mac, char *out, size_t out_len);

/* The BPF expression which matches every TCP segment to or from the server's
 * address and port, so neither this helper's connection nor a sibling helper's
 * on the same sensor is captured.  IPv4 (and IPv4-mapped IPv6) or IPv6, behind
 * 0 to WIRED_SELFEXCL_TAGS 802.1Q/802.1ad tags.
 *
 * Written only with ether[] loads at fixed offsets from the frame start, and
 * no keyword which moves the link offsets ('vlan', 'pppoes', 'geneve', 'mpls'),
 * so it reads the same fields whatever is compiled with it.
 * Returns the length, or -1 */
int wired_build_selfexcl(const struct sockaddr *server, char *out, size_t out_len);

/* 1 for 127/8, ::1, or 127/8 mapped into IPv6: a server reached through an SSH
 * forward or a local proxy, whose real carrier the exclusion can't see */
int wired_addr_loopback(const struct sockaddr *sa);

/* 1 when both name the same IP address, ports ignored; an IPv4-mapped IPv6
 * address matches its IPv4 form */
int wired_addr_same(const struct sockaddr *a, const struct sockaddr *b);

/* Where the connection to the server runs, as far as the helper can tell */
typedef enum {
    /* From an address on the captured interface, or one stacked on it in a way
     * the exclusion still matches */
    WIRED_PATH_CAPTURED = 0,
    /* To a loopback address or one of this host's: carried by something else,
     * maybe over the capture */
    WIRED_PATH_LOOPBACK,
    /* From an address on another interface: a second NIC, or a tunnel or VPN */
    WIRED_PATH_OTHER,
    /* From an address no interface has, one on a loopback, dummy or VRF interface,
     * or one whose stack is too wide to follow */
    WIRED_PATH_UNKNOWN,
    /* From an interface carried over the captured one in a form the exclusion
     * doesn't match: more than WIRED_SELFEXCL_TAGS tags, or encapsulated */
    WIRED_PATH_UNMATCHED,
} wired_path_t;

/* What a stacked interface does to the frames it sends through its lower one */
typedef enum {
    /* Unknown, encrypted or encapsulated (macsec, vxlan...): never matched */
    WIRED_HOP_OPAQUE = 0,
    /* Sent unchanged: bond, team, bridge, macvlan, ipvlan and their taps */
    WIRED_HOP_PASS,
    /* One more VLAN tag, 802.1Q or 802.1ad */
    WIRED_HOP_TAG,
} wired_hop_t;

/* Longest IFLA_INFO_KIND kept, including the NUL; longer ones are unknown */
#define WIRED_KIND_MAX          24

/* The hop for an rtnetlink link kind ("vlan", "bridge"...); NULL or anything not
 * known to pass frames through unchanged is opaque */
wired_hop_t wired_kind_hop(const char *kind);

/* The IFLA_INFO_KIND in the kernel's answer to an RTM_GETLINK request with
 * sequence number seq.  Returns 1 with kind set, 0 for a link without a kind
 * (a NIC, loopback), or -1 for an error answer, another message, a malformed
 * one, or a kind outside [A-Za-z0-9._-] or longer than kind_len - 1 */
int wired_nl_link_kind(const uint8_t *buf, size_t len, uint32_t seq, char *kind,
        size_t kind_len);

/* One link as rtnetlink shows it, in the asking process's network namespace */
typedef struct {
    int32_t index;
    uint16_t type;
    uint32_t flags;
    /* IFLA_WIRELESS was there (wext); cfg80211 interfaces may leave it out */
    int wireless;
    char name[WIRED_IFNAMSIZ];
    /* Empty for a link without a kind */
    char kind[WIRED_KIND_MAX];
} wired_nl_link_t;

/* The kernel's RTM_NEWLINK answer to an RTM_GETLINK request with sequence number
 * seq.  Returns 1 with link set, or -1 for another message, a malformed one, an
 * index below 1, a missing or invalid IFLA_IFNAME, or an invalid kind */
int wired_nl_link_parse(const uint8_t *buf, size_t len, uint32_t seq, wired_nl_link_t *link);

/* The kernel's NLMSG_ERROR answer to a request with sequence number seq sent with
 * NLM_F_ACK.  Returns 1 with *err 0 for success or the errno it failed with, or -1
 * for another message, a malformed one, or an error outside 0 to -4095 */
int wired_nl_ack(const uint8_t *buf, size_t len, uint32_t seq, int *err);

typedef enum {
    /* Up, or its flags can't be read; libpcap reports a down one itself */
    WIRED_IFUP_KEEP = 0,
    WIRED_IFUP_BRING,
    /* Down, and ifup=false */
    WIRED_IFUP_REFUSE,
} wired_ifup_t;

/* What open does with an interface: up is 1 up, 0 down, -1 unknown
 * (wired_nl_read_up), ifup the source option */
wired_ifup_t wired_ifup_action(int up, int ifup);

/* The bring-up child's protocol (wired_ifupd.h), one fixed-size message each way
 * over a SOCK_SEQPACKET socketpair */
#define WIRED_IFUP_MAGIC        0x4b574955

/* MAX_ERRNO in linux/err.h */
#define WIRED_ERRNO_MAX         4095

/* A request's 64-bit number travels as owner (the high 32 bits, the asking
 * process's pid) and seq (the low 32, its own count), so capture processes
 * sharing the child never number two requests alike */
typedef struct {
    uint32_t magic;
    uint32_t owner;
    uint32_t seq;
    /* NUL-terminated, zero after the NUL */
    char ifname[WIRED_IFNAMSIZ];
} wired_ifup_req_t;

typedef enum {
    WIRED_IFUP_DONE = 0,
    WIRED_IFUP_ALREADY,
    /* err is the errno, 1 to 4095 */
    WIRED_IFUP_FAILED,
} wired_ifup_status_t;

typedef struct {
    uint32_t magic;
    uint32_t owner;
    uint32_t seq;
    uint32_t status;
    int32_t err;
} wired_ifup_reply_t;

/* A request's 64-bit number from its owner and seq */
uint64_t wired_ifup_seq(uint32_t owner, uint32_t seq);

/* Returns 1, or -1 for an invalid name */
int wired_ifup_req_build(const char *ifname, uint64_t seq, wired_ifup_req_t *req);

/* A request of exactly len bytes.  Returns 1 with seq and a valid ifname, or -1 */
int wired_ifup_req_parse(const uint8_t *buf, size_t len, uint64_t *seq,
        char ifname[WIRED_IFNAMSIZ]);

void wired_ifup_reply_build(uint64_t seq, wired_ifup_status_t status, int err,
        wired_ifup_reply_t *reply);

/* A reply of exactly len bytes, whichever request it answers.  Returns 1 with
 * *seq, *status and *err set, or -1 for a malformed one */
int wired_ifup_reply_read(const uint8_t *buf, size_t len, uint64_t *seq,
        wired_ifup_status_t *status, int *err);

/* A reply of exactly len bytes.  Returns 1 for the answer to seq, 0 for a valid
 * answer to another request, -1 for a malformed one */
int wired_ifup_reply_parse(const uint8_t *buf, size_t len, uint64_t seq,
        wired_ifup_status_t *status, int *err);

/* CLOCK_MONOTONIC in milliseconds */
uint64_t wired_mono_ms(void);

/* The user's filter and the self-exclusion together, "not (exclusion) and
 * (user)"; either may be NULL or empty.  The exclusion goes first: 'vlan',
 * 'pppoes', 'geneve' and 'mpls' in the user's filter move the link offsets of
 * everything compiled after them, and would shift it off its fields.
 * Returns the length (0 for no filter), or -1 if it doesn't fit */
int wired_build_filter(const char *user, const char *selfexcl, char *out, size_t out_len);

/* A frame cut short of WIRED_SELFEXCL_DEPTH, which the re-check can't rule out
 * as server traffic; the helper drops it.  The snaplen minimum keeps live frames
 * from ever being cut that short.  Returns 1 or 0 */
int wired_selfexcl_undecided(uint32_t caplen, uint32_t len);

/* 1 in N frames forwarded, the first of each N; N of 0 or 1 forwards everything */
typedef struct {
    unsigned int sample;
    unsigned int count;
} wired_sampler_t;

void wired_sampler_init(wired_sampler_t *s, unsigned int sample);
int wired_sampler_take(wired_sampler_t *s);

/* Offload bits from the ETH_SS_FEATURES names and the active feature blocks
 * of ETHTOOL_GFEATURES, each block 32 features */
unsigned int wired_offloads_from_features(const char *names, size_t name_len, size_t n_names,
        const uint32_t *active, size_t n_blocks);

/* Comma-separated kernel names of the offloads, "" for none.  Returns the length,
 * or -1 if it doesn't fit */
int wired_offloads_describe(unsigned int offloads, char *out, size_t out_len);

typedef struct {
    uint64_t kernel_received;
    uint64_t kernel_drops;
    uint64_t if_drops;
    uint64_t frames;
    uint64_t forwarded;
    unsigned int sample;
    unsigned int snaplen;
    unsigned int buffer_mb;
    int promisc;
    int remote_excluded;
    unsigned int offloads;
    /* 1 link, 0 no link, -1 unknown and left out */
    int carrier;
} wired_status_t;

/* nobody / nogroup on Linux, the kernel's overflow id */
#define WIRED_NOBODY_ID         65534

/* The uid and gid a helper with euid 0 switches to: the invoking user's, from the
 * real ids of a setuid-root start, or nobody when the real uid is root too.  A real
 * gid of 0 (root's group) becomes nobody's as well */
void wired_unpriv_ids(uid_t ruid, gid_t rgid, uid_t *uid, gid_t *gid);

/* Room for /proc/self/status, or a uid_map or gid_map at the kernel's 340 lines */
#define WIRED_PROC_TEXT_MAX     16384U

/* The whole of a small file (a /proc one) into buf, NUL terminated, its length in
 * *len.  Returns 0, or -1 when it can't be read or doesn't fit */
int wired_read_text(const char *path, char *buf, size_t buf_len, size_t *len);

/* The id outside a user namespace which id maps to, from the text of a uid_map or
 * gid_map: lines of three space-separated decimal numbers.  Returns 1 with *outer
 * set, 0 when id isn't mapped, -1 for text which isn't such a map */
int wired_id_map_outer(const char *map, size_t len, uint32_t id, uint32_t *outer);

/* What a helper holds in a user namespace other than the initial one, with its real
 * and saved ids already set to the effective ones (the kernel takes only ids mapped
 * there), and what the kernel shows of the initial namespace's root */
typedef struct {
    const char *uid_map;
    size_t uid_map_len;
    const char *gid_map;
    size_t gid_map_len;
    uid_t uid;
    gid_t gid;
    const gid_t *groups;
    size_t n_groups;
    /* The kernel's overflow gid, which a group not mapped here shows as */
    gid_t overflow_gid;
    /* The group of a file of the initial root's: what root's group is here, or
     * overflow_gid when it isn't mapped */
    gid_t root_gid;
    /* The uid passed a check only the initial namespace's uid 0 passes */
    int uid_is_root;
} wired_userns_ids_t;

/* Whether those ids are root outside the namespace: the uid or gid isn't mapped or
 * maps to 0 of the parent namespace, a group is 0 there or shows as overflow_gid
 * (a group from outside, maybe root's), an id is root_gid, or uid_is_root.
 * Returns 1 when none is, or -1 with why set */
int wired_userns_ids_check(const wired_userns_ids_t *ids, char *why, size_t why_len);

/* CapPrm and CapEff from the text of /proc/<pid>/status.  Returns 0, or -1 when
 * either is missing, given twice or isn't 1 to 16 hex digits */
int wired_status_caps(const char *status, size_t len, uint64_t *prm, uint64_t *eff);

/* The status record the server shows on the source.  Numbers and fixed names
 * only, nothing from the wire, so there's nothing to escape.  Returns the
 * length, or -1 if it doesn't fit */
int wired_status_json(const wired_status_t *st, char *out, size_t out_len);

#endif
