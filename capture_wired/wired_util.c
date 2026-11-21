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

#include "wired_util.h"

#include <errno.h>
#include <fcntl.h>
#include <inttypes.h>
#include <stdarg.h>
#include <stdio.h>
#include <string.h>
#include <strings.h>
#include <time.h>
#include <unistd.h>

#include <arpa/inet.h>
#include <netinet/in.h>

#include <linux/if_link.h>
#include <linux/netlink.h>
#include <linux/rtnetlink.h>

#include "../capture_framework.h"

const char *const wired_offload_names[WIRED_OFFLOAD_COUNT] = {
    "rx-gro",
    "rx-gro-hw",
    "rx-lro",
    "rx-vlan-filter",
    "tx-tcp-segmentation",
    "tx-tcp6-segmentation",
    "tx-generic-segmentation",
};

int wired_ifname_valid(const char *name, size_t len) {
    size_t i;

    if (name == NULL || len == 0 || len >= WIRED_IFNAMSIZ)
        return 0;

    if (name[0] == '.')
        return 0;

    for (i = 0; i < len; i++) {
        char c = name[i];

        if ((c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z') || (c >= '0' && c <= '9') ||
                c == '.' || c == '_' || c == '@' || c == '-')
            continue;

        return 0;
    }

    return 1;
}

int wired_parse_uint(const char *str, size_t len, unsigned long min, unsigned long max,
        unsigned long *ret) {
    unsigned long v = 0;
    size_t i;

    if (str == NULL || len == 0 || len > 10)
        return -1;

    for (i = 0; i < len; i++) {
        unsigned long d;

        if (str[i] < '0' || str[i] > '9')
            return -1;

        d = (unsigned long) (str[i] - '0');

        /* Stops before v * 10 + d can pass max, so it can't wrap a 32 bit long */
        if (d > max || v > (max - d) / 10)
            return -1;

        v = v * 10 + d;
    }

    if (v < min || v > max)
        return -1;

    *ret = v;
    return 1;
}

int wired_parse_bool(const char *str, size_t len, int *ret) {
    if (str == NULL)
        return -1;

    if (len == 4 && strncasecmp(str, "true", 4) == 0) {
        *ret = 1;
        return 1;
    }

    if (len == 5 && strncasecmp(str, "false", 5) == 0) {
        *ret = 0;
        return 1;
    }

    return -1;
}

int wired_uuid_valid(const char *str, size_t len) {
    size_t i;

    if (str == NULL || len != WIRED_UUID_LEN)
        return -1;

    for (i = 0; i < len; i++) {
        char c = str[i];

        if (i == 8 || i == 13 || i == 18 || i == 23) {
            if (c != '-')
                return -1;
            continue;
        }

        if (!((c >= '0' && c <= '9') || (c >= 'a' && c <= 'f') || (c >= 'A' && c <= 'F')))
            return -1;
    }

    return 1;
}

/* adler32_csum returns 0 under 4 bytes and reads 32 bits at a time, so hash
 * from an aligned copy, prefixed to be long enough for any interface name */
static uint32_t wired_hash(const char *s) {
    union {
        uint32_t align;
        char key[64];
    } k;
    int kl = snprintf(k.key, sizeof(k.key), "kismet_cap_wired%s%s", s[0] != 0 ? ":" : "", s);

    if (kl < 0 || (size_t) kl >= sizeof(k.key))
        return 0;

    return adler32_csum((uint8_t *) k.key, (size_t) kl) & 0xFFFFFFFF;
}

/* FNV-1a for the interface name: adler32's position weights collide across
 * names like eth0.12 and eth0.21, thousands of times over eth0.1 to eth0.4094 */
static uint32_t wired_name_hash(const char *s) {
    uint32_t h = 2166136261U;

    for (; *s != 0; s++) {
        h ^= (uint8_t) *s;
        h *= 16777619U;
    }

    return h;
}

int wired_format_uuid(const char *ifname, const uint8_t *mac, char *out, size_t out_len) {
    uint32_t h;
    int r;

    if (ifname == NULL || out == NULL)
        return -1;

    h = wired_name_hash(ifname);

    if (mac != NULL)
        r = snprintf(out, out_len, "%08X-%04X-%04X-0000-%02X%02X%02X%02X%02X%02X",
                wired_hash(""), (unsigned int) (h >> 16), (unsigned int) (h & 0xFFFF),
                mac[0], mac[1], mac[2], mac[3], mac[4], mac[5]);
    else
        r = snprintf(out, out_len, "%08X-0000-0000-0000-0000%08X", wired_hash(""), h);

    if (r != WIRED_UUID_LEN || (size_t) r >= out_len)
        return -1;

    return 1;
}

int wired_filter_balanced(const char *filter, size_t len) {
    size_t depth = 0;
    size_t i;

    if (filter == NULL)
        return 0;

    for (i = 0; i < len; i++) {
        if (filter[i] == '(') {
            depth++;
        } else if (filter[i] == ')') {
            if (depth == 0)
                return 0;
            depth--;
        }
    }

    return depth == 0;
}

/* Read by the helper, then by the server (kis_datasource.cc) for every source */
static const char *const wired_known_options[] = {
    "mode", "snaplen", "buffer_mb", "sample", "promisc", "ifup", "filter", "uuid",
#ifdef WIRED_REPLAY
    "replay",
#endif
    "type", "name", "retry", "timestamp", "metagps", "hopgroup", "hopsync",
    "channel", "channels", "channel_hop", "channel_hoprate", "add_channels",
    "block_channels", "info_antenna_type", "info_antenna_gain",
    "info_antenna_orientation", "info_antenna_beamwidth", "info_amp_type",
    "info_amp_gain",
};

#define WIRED_OPTNAME_SHOWN     32

static int wired_option_known(const char *key, size_t len) {
    size_t i;

    for (i = 0; i < sizeof(wired_known_options) / sizeof(wired_known_options[0]); i++) {
        if (strlen(wired_known_options[i]) == len &&
                strncasecmp(wired_known_options[i], key, len) == 0)
            return 1;
    }

    return 0;
}

/* Appends a name to out, cut short and with anything outside the allowlist
 * replaced, since it goes into a message; stops quietly when out is full */
static void wired_append_optname(const char *key, size_t len, char *out, size_t out_len,
        size_t *pos) {
    size_t i;

    if (len > WIRED_OPTNAME_SHOWN)
        len = WIRED_OPTNAME_SHOWN;

    if (*pos != 0) {
        if (*pos + 1 >= out_len)
            return;
        out[(*pos)++] = ',';
    }

    for (i = 0; i < len && *pos + 1 < out_len; i++) {
        char c = key[i];

        if (!((c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z') || (c >= '0' && c <= '9') ||
                    c == '_' || c == '-'))
            c = '?';

        out[(*pos)++] = c;
    }

    out[*pos] = 0;
}

int wired_unknown_options(const char *definition, char *out, size_t out_len) {
    const char *p;
    size_t pos = 0;
    int n = 0;

    if (out != NULL && out_len > 0)
        out[0] = 0;

    if (definition == NULL || (p = strchr(definition, ':')) == NULL)
        return 0;

    p++;

    /* Pairs split as cf_find_flag splits them: a quote after the '=' and before
     * the next comma runs to the closing quote */
    while (*p != 0) {
        const char *eq = strchr(p, '=');
        const char *comma = strchr(p, ',');
        const char *quote;

        if (eq == NULL || (comma != NULL && comma < eq)) {
            if (comma == NULL)
                break;
            p = comma + 1;
            continue;
        }

        if (eq > p && !wired_option_known(p, (size_t) (eq - p))) {
            n++;
            if (out != NULL && out_len > 0)
                wired_append_optname(p, (size_t) (eq - p), out, out_len, &pos);
        }

        quote = strchr(eq, '"');

        if (quote != NULL && (comma == NULL || quote < comma)) {
            const char *equote = strchr(quote + 1, '"');

            if (equote == NULL)
                break;

            comma = strchr(equote, ',');
        }

        if (comma == NULL)
            break;

        p = comma + 1;
    }

    return n;
}

unsigned int wired_caplen_limit(unsigned int snaplen, size_t gps_name_len) {
    size_t limit;

    if (gps_name_len > WIRED_SNAPLEN_MAX - WIRED_SNAPLEN_MIN)
        return 0;

    limit = WIRED_SNAPLEN_MAX - gps_name_len;

    if (snaplen < limit)
        limit = snaplen;

    return (unsigned int) limit;
}

/* cf_find_flag returns 0 for a missing flag, -1 for a malformed definition */
static int wired_find(char *definition, const char *flag, char **value, char *errstr,
        size_t errstr_len) {
    int len = cf_find_flag(value, flag, definition);

    if (len < 0) {
        snprintf(errstr, errstr_len, "could not parse the source options near '%s'", flag);
        return -1;
    }

    return len;
}

int wired_parse_opts(char *definition, wired_opts_t *opts, char *errstr, size_t errstr_len) {
    char *v = NULL;
    int len;
    unsigned long u;
    size_t i;

    memset(opts, 0, sizeof(*opts));
    opts->snaplen = WIRED_SNAPLEN_DEFAULT;
    opts->buffer_mb = WIRED_BUFFER_MB_DEFAULT;
    opts->sample = 1;
    opts->promisc = 1;
    opts->ifup = 1;

    if ((len = wired_find(definition, "mode", &v, errstr, errstr_len)) < 0)
        return -1;
    if (len > 0) {
        if (len == 7 && strncasecmp(v, "summary", 7) == 0) {
            snprintf(errstr, errstr_len, "mode=summary is not supported by this version of "
                    "kismet_cap_wired, use mode=full");
            return -1;
        }

        if (!(len == 4 && strncasecmp(v, "full", 4) == 0)) {
            snprintf(errstr, errstr_len, "unknown mode, expected mode=full");
            return -1;
        }
    }

    if ((len = wired_find(definition, "snaplen", &v, errstr, errstr_len)) < 0)
        return -1;
    if (len > 0) {
        if (wired_parse_uint(v, (size_t) len, WIRED_SNAPLEN_MIN, WIRED_SNAPLEN_MAX, &u) < 0) {
            snprintf(errstr, errstr_len, "snaplen must be a number from %u to %u",
                    WIRED_SNAPLEN_MIN, WIRED_SNAPLEN_MAX);
            return -1;
        }
        opts->snaplen = (unsigned int) u;
    }

    if ((len = wired_find(definition, "buffer_mb", &v, errstr, errstr_len)) < 0)
        return -1;
    if (len > 0) {
        if (wired_parse_uint(v, (size_t) len, WIRED_BUFFER_MB_MIN, WIRED_BUFFER_MB_MAX, &u) < 0) {
            snprintf(errstr, errstr_len, "buffer_mb must be a number from %u to %u",
                    WIRED_BUFFER_MB_MIN, WIRED_BUFFER_MB_MAX);
            return -1;
        }
        opts->buffer_mb = (unsigned int) u;
    }

    if ((len = wired_find(definition, "sample", &v, errstr, errstr_len)) < 0)
        return -1;
    if (len > 0) {
        if (wired_parse_uint(v, (size_t) len, 1, WIRED_SAMPLE_MAX, &u) < 0) {
            snprintf(errstr, errstr_len, "sample must be a number from 1 to %u",
                    WIRED_SAMPLE_MAX);
            return -1;
        }
        opts->sample = (unsigned int) u;
    }

    if ((len = wired_find(definition, "promisc", &v, errstr, errstr_len)) < 0)
        return -1;
    if (len > 0 && wired_parse_bool(v, (size_t) len, &opts->promisc) < 0) {
        snprintf(errstr, errstr_len, "promisc must be true or false");
        return -1;
    }

    if ((len = wired_find(definition, "ifup", &v, errstr, errstr_len)) < 0)
        return -1;
    if (len > 0 && wired_parse_bool(v, (size_t) len, &opts->ifup) < 0) {
        snprintf(errstr, errstr_len, "ifup must be true or false");
        return -1;
    }

    if ((len = wired_find(definition, "filter", &v, errstr, errstr_len)) < 0)
        return -1;
    if (len > 0) {
        if ((size_t) len > WIRED_FILTER_MAX) {
            snprintf(errstr, errstr_len, "filter is longer than %u characters", WIRED_FILTER_MAX);
            return -1;
        }

        /* Only ever handed to pcap_compile, but keep it to text pcap can parse */
        for (i = 0; i < (size_t) len; i++) {
            if ((unsigned char) v[i] < 0x20 || (unsigned char) v[i] > 0x7e) {
                snprintf(errstr, errstr_len, "filter may only contain printable ASCII");
                return -1;
            }
        }

        if (!wired_filter_balanced(v, (size_t) len)) {
            snprintf(errstr, errstr_len, "filter has unbalanced parentheses");
            return -1;
        }

        /* A blank filter matches everything alone, but '( )' next to the
         * exclusion doesn't compile */
        for (i = 0; i < (size_t) len && v[i] == ' '; i++)
            ;

        if (i < (size_t) len) {
            memcpy(opts->filter, v, (size_t) len);
            opts->filter[len] = 0;
            opts->has_filter = 1;
        }
    }

    if ((len = wired_find(definition, "uuid", &v, errstr, errstr_len)) < 0)
        return -1;
    if (len > 0) {
        if (wired_uuid_valid(v, (size_t) len) < 0) {
            snprintf(errstr, errstr_len, "uuid must be in the form "
                    "XXXXXXXX-XXXX-XXXX-XXXX-XXXXXXXXXXXX");
            return -1;
        }

        memcpy(opts->uuid, v, WIRED_UUID_LEN);
        opts->uuid[WIRED_UUID_LEN] = 0;
        opts->has_uuid = 1;
    }

#ifdef WIRED_REPLAY
    if ((len = wired_find(definition, "replay", &v, errstr, errstr_len)) < 0)
        return -1;
    if (len <= 0 || (size_t) len >= sizeof(opts->replay)) {
        snprintf(errstr, errstr_len, "the replay build needs replay=<pcap file>");
        return -1;
    }
    memcpy(opts->replay, v, (size_t) len);
    opts->replay[len] = 0;
#endif

    return 1;
}

/* The server's address as network-order bytes (IPv4-mapped IPv6 as IPv4, since
 * that's what goes on the wire) and its port */
static int wired_server_endpoint(const struct sockaddr *sa, int *family, uint8_t addr[16],
        unsigned int *port) {
    if (sa->sa_family == AF_INET) {
        const struct sockaddr_in *in4 = (const struct sockaddr_in *) sa;

        memcpy(addr, &in4->sin_addr, 4);
        *family = AF_INET;
        *port = ntohs(in4->sin_port);
        return 1;
    }

    if (sa->sa_family == AF_INET6) {
        const struct sockaddr_in6 *in6 = (const struct sockaddr_in6 *) sa;

        if (IN6_IS_ADDR_V4MAPPED(&in6->sin6_addr)) {
            memcpy(addr, &in6->sin6_addr.s6_addr[12], 4);
            *family = AF_INET;
        } else {
            memcpy(addr, &in6->sin6_addr, 16);
            *family = AF_INET6;
        }

        *port = ntohs(in6->sin6_port);
        return 1;
    }

    return -1;
}

static int wired_append(char *out, size_t out_len, size_t *pos, const char *fmt, ...)
    __attribute__((format(printf, 4, 5)));

static int wired_append(char *out, size_t out_len, size_t *pos, const char *fmt, ...) {
    va_list ap;
    int r;

    if (*pos >= out_len)
        return -1;

    va_start(ap, fmt);
    r = vsnprintf(out + *pos, out_len - *pos, fmt, ap);
    va_end(ap);

    if (r < 0 || (size_t) r >= out_len - *pos)
        return -1;

    *pos += (size_t) r;
    return 1;
}

static uint32_t wired_be32(const uint8_t *b) {
    return ((uint32_t) b[0] << 24) | ((uint32_t) b[1] << 16) | ((uint32_t) b[2] << 8) | b[3];
}

/* One branch of the exclusion: the server's TCP behind 'tags' tags, the IP
 * header at ether[base] */
static int wired_selfexcl_branch(int family, const uint8_t *addr, unsigned int port,
        unsigned int tags, char *out, size_t out_len, size_t *pos) {
    unsigned int base = 14 + 4 * tags;
    unsigned int t;

    if (wired_append(out, out_len, pos, "(") < 0)
        return -1;

    for (t = 0; t < tags; t++) {
        unsigned int o = 12 + 4 * t;

        if (wired_append(out, out_len, pos, "(ether[%u:2] = 0x8100 or ether[%u:2] = 0x88a8 or "
                    "ether[%u:2] = 0x9100) and ", o, o, o) < 0)
            return -1;
    }

    if (family == AF_INET) {
        uint32_t a = wired_be32(addr);

        /* Ports from the header length in the IP header; first fragments only, as
         * the tcp keyword does */
        return wired_append(out, out_len, pos,
                "ether[%u:2] = 0x0800 and ether[%u] = 6 and ether[%u:2] & 0x1fff = 0 and "
                "((ether[%u:4] = 0x%08" PRIx32 " and ether[%u + ((ether[%u] & 0xf) << 2):2] = %u) or "
                "(ether[%u:4] = 0x%08" PRIx32 " and ether[%u + ((ether[%u] & 0xf) << 2):2] = %u)))",
                base - 2, base + 9, base + 6,
                base + 12, a, base, base, port,
                base + 16, a, base + 2, base, port);
    }

    /* IPv6 with TCP as the first next header, which is all the helper's own
     * connections send */
    return wired_append(out, out_len, pos,
            "ether[%u:2] = 0x86dd and ether[%u] = 6 and "
            "((ether[%u:4] = 0x%08" PRIx32 " and ether[%u:4] = 0x%08" PRIx32 " and "
            "ether[%u:4] = 0x%08" PRIx32 " and ether[%u:4] = 0x%08" PRIx32 " and ether[%u:2] = %u) or "
            "(ether[%u:4] = 0x%08" PRIx32 " and ether[%u:4] = 0x%08" PRIx32 " and "
            "ether[%u:4] = 0x%08" PRIx32 " and ether[%u:4] = 0x%08" PRIx32 " and ether[%u:2] = %u)))",
            base - 2, base + 6,
            base + 8, wired_be32(addr), base + 12, wired_be32(addr + 4),
            base + 16, wired_be32(addr + 8), base + 20, wired_be32(addr + 12), base + 40, port,
            base + 24, wired_be32(addr), base + 28, wired_be32(addr + 4),
            base + 32, wired_be32(addr + 8), base + 36, wired_be32(addr + 12), base + 42, port);
}

int wired_build_selfexcl(const struct sockaddr *server, char *out, size_t out_len) {
    uint8_t addr[16];
    unsigned int port;
    unsigned int tags;
    size_t pos = 0;
    int family;

    if (server == NULL || out == NULL || out_len == 0)
        return -1;

    out[0] = 0;

    if (wired_server_endpoint(server, &family, addr, &port) < 0 || port == 0)
        return -1;

    for (tags = 0; tags <= WIRED_SELFEXCL_TAGS; tags++) {
        if (tags > 0 && wired_append(out, out_len, &pos, " or ") < 0)
            return -1;

        if (wired_selfexcl_branch(family, addr, port, tags, out, out_len, &pos) < 0)
            return -1;
    }

    if (pos > INT32_MAX)
        return -1;

    return (int) pos;
}

int wired_addr_loopback(const struct sockaddr *sa) {
    static const uint8_t v6_loopback[16] = { [15] = 1 };
    uint8_t addr[16];
    unsigned int port;
    int family;

    if (sa == NULL || wired_server_endpoint(sa, &family, addr, &port) < 0)
        return 0;

    if (family == AF_INET)
        return addr[0] == 127;

    return memcmp(addr, v6_loopback, sizeof(v6_loopback)) == 0;
}

int wired_addr_same(const struct sockaddr *a, const struct sockaddr *b) {
    uint8_t aa[16], ba[16];
    unsigned int ap, bp;
    int af, bf;

    if (a == NULL || b == NULL ||
            wired_server_endpoint(a, &af, aa, &ap) < 0 ||
            wired_server_endpoint(b, &bf, ba, &bp) < 0 || af != bf)
        return 0;

    return memcmp(aa, ba, af == AF_INET ? 4 : 16) == 0;
}

wired_hop_t wired_kind_hop(const char *kind) {
    static const char *const pass[] = {
        "bond", "team", "bridge", "macvlan", "macvtap", "ipvlan", "ipvtap",
    };
    size_t i;

    if (kind == NULL)
        return WIRED_HOP_OPAQUE;

    if (strcmp(kind, "vlan") == 0)
        return WIRED_HOP_TAG;

    for (i = 0; i < sizeof(pass) / sizeof(pass[0]); i++) {
        if (strcmp(kind, pass[i]) == 0)
            return WIRED_HOP_PASS;
    }

    return WIRED_HOP_OPAQUE;
}

/* The next attribute at *off in an attribute run of len bytes.  Returns 1, 0 at the
 * end, or -1 for an attribute running past it */
static int wired_rta_next(const uint8_t *buf, size_t len, size_t *off, unsigned int *type,
        const uint8_t **data, size_t *data_len) {
    struct rtattr rta;
    size_t step;

    if (*off >= len || len - *off < sizeof(rta))
        return 0;

    memcpy(&rta, buf + *off, sizeof(rta));

    if (rta.rta_len < sizeof(rta) || rta.rta_len > len - *off)
        return -1;

    *type = (unsigned int) rta.rta_type & (unsigned int) NLA_TYPE_MASK;
    *data = buf + *off + sizeof(rta);
    *data_len = rta.rta_len - sizeof(rta);

    /* The padding after the last attribute may be left off */
    step = RTA_ALIGN((size_t) rta.rta_len);
    *off = step > len - *off ? len : *off + step;

    return 1;
}

static int wired_kind_char(uint8_t c) {
    return (c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z') || (c >= '0' && c <= '9') ||
        c == '.' || c == '_' || c == '-';
}

/* IFLA_INFO_KIND inside IFLA_LINKINFO */
static int wired_linkinfo_kind(const uint8_t *buf, size_t len, char *kind, size_t kind_len) {
    const uint8_t *data;
    size_t off = 0, dlen, l;
    unsigned int type;
    int r;

    while ((r = wired_rta_next(buf, len, &off, &type, &data, &dlen)) > 0) {
        if (type != IFLA_INFO_KIND)
            continue;

        for (l = 0; l < dlen && data[l] != 0; l++) {
            if (!wired_kind_char(data[l]))
                return -1;
        }

        if (l == 0 || l >= kind_len)
            return -1;

        memcpy(kind, data, l);
        kind[l] = 0;
        return 1;
    }

    return r < 0 ? -1 : 0;
}

int wired_nl_link_kind(const uint8_t *buf, size_t len, uint32_t seq, char *kind,
        size_t kind_len) {
    struct nlmsghdr nh;
    const uint8_t *data;
    size_t off, dlen;
    unsigned int type;
    int r;

    if (kind == NULL || kind_len == 0)
        return -1;

    kind[0] = 0;

    if (buf == NULL || len < sizeof(nh))
        return -1;

    memcpy(&nh, buf, sizeof(nh));

    if (nh.nlmsg_len < sizeof(nh) || nh.nlmsg_len > len || nh.nlmsg_seq != seq ||
            nh.nlmsg_type != RTM_NEWLINK)
        return -1;

    off = NLMSG_HDRLEN + NLMSG_ALIGN(sizeof(struct ifinfomsg));

    if (off > nh.nlmsg_len)
        return -1;

    buf += off;
    len = nh.nlmsg_len - off;
    off = 0;

    while ((r = wired_rta_next(buf, len, &off, &type, &data, &dlen)) > 0) {
        if (type == IFLA_LINKINFO)
            return wired_linkinfo_kind(data, dlen, kind, kind_len);
    }

    return r < 0 ? -1 : 0;
}

int wired_nl_link_parse(const uint8_t *buf, size_t len, uint32_t seq, wired_nl_link_t *link) {
    struct nlmsghdr nh;
    struct ifinfomsg ifi;
    const uint8_t *data;
    size_t off, dlen, l;
    unsigned int type;
    int r, named = 0;

    if (link == NULL)
        return -1;

    memset(link, 0, sizeof(*link));

    if (buf == NULL || len < sizeof(nh))
        return -1;

    memcpy(&nh, buf, sizeof(nh));

    off = NLMSG_HDRLEN + NLMSG_ALIGN(sizeof(ifi));

    if (nh.nlmsg_len < off || nh.nlmsg_len > len || nh.nlmsg_seq != seq ||
            nh.nlmsg_type != RTM_NEWLINK)
        return -1;

    memcpy(&ifi, buf + NLMSG_HDRLEN, sizeof(ifi));

    if (ifi.ifi_index < 1)
        return -1;

    link->index = ifi.ifi_index;
    link->type = ifi.ifi_type;
    link->flags = ifi.ifi_flags;

    buf += off;
    len = nh.nlmsg_len - off;
    off = 0;

    while ((r = wired_rta_next(buf, len, &off, &type, &data, &dlen)) > 0) {
        if (type == IFLA_IFNAME) {
            for (l = 0; l < dlen && data[l] != 0; l++)
                ;

            if (l == dlen || l >= sizeof(link->name) || !wired_ifname_valid((const char *) data, l))
                return -1;

            memcpy(link->name, data, l);
            link->name[l] = 0;
            named = 1;
        } else if (type == IFLA_WIRELESS) {
            link->wireless = 1;
        } else if (type == IFLA_LINKINFO) {
            if (wired_linkinfo_kind(data, dlen, link->kind, sizeof(link->kind)) < 0)
                return -1;
        }
    }

    return r < 0 || !named ? -1 : 1;
}

int wired_nl_ack(const uint8_t *buf, size_t len, uint32_t seq, int *err) {
    struct nlmsghdr nh;
    int32_t e;

    if (buf == NULL || err == NULL || len < NLMSG_HDRLEN + sizeof(e))
        return -1;

    memcpy(&nh, buf, sizeof(nh));

    /* Only the error is read; the request echoed after it may be cut */
    if (nh.nlmsg_len < NLMSG_HDRLEN + sizeof(e) || nh.nlmsg_len > len || nh.nlmsg_seq != seq ||
            nh.nlmsg_type != NLMSG_ERROR)
        return -1;

    memcpy(&e, buf + NLMSG_HDRLEN, sizeof(e));

    if (e > 0 || e < -WIRED_ERRNO_MAX)
        return -1;

    *err = -e;
    return 1;
}

wired_ifup_t wired_ifup_action(int up, int ifup) {
    if (up != 0)
        return WIRED_IFUP_KEEP;

    return ifup ? WIRED_IFUP_BRING : WIRED_IFUP_REFUSE;
}

uint64_t wired_mono_ms(void) {
    struct timespec ts;

    clock_gettime(CLOCK_MONOTONIC, &ts);
    return (uint64_t) ts.tv_sec * 1000 + (uint64_t) ts.tv_nsec / 1000000;
}

uint64_t wired_ifup_seq(uint32_t owner, uint32_t seq) {
    return (uint64_t) owner << 32 | seq;
}

int wired_ifup_req_build(const char *ifname, uint64_t seq, wired_ifup_req_t *req) {
    size_t l;

    if (req == NULL || ifname == NULL || !wired_ifname_valid(ifname, (l = strlen(ifname))))
        return -1;

    memset(req, 0, sizeof(*req));
    req->magic = WIRED_IFUP_MAGIC;
    req->owner = (uint32_t) (seq >> 32);
    req->seq = (uint32_t) seq;
    memcpy(req->ifname, ifname, l);

    return 1;
}

int wired_ifup_req_parse(const uint8_t *buf, size_t len, uint64_t *seq,
        char ifname[WIRED_IFNAMSIZ]) {
    wired_ifup_req_t req;
    size_t l, i;

    if (buf == NULL || seq == NULL || ifname == NULL || len != sizeof(req))
        return -1;

    memcpy(&req, buf, sizeof(req));

    if (req.magic != WIRED_IFUP_MAGIC)
        return -1;

    *seq = wired_ifup_seq(req.owner, req.seq);

    /* NUL-terminated inside the field, and nothing after the NUL */
    for (l = 0; l < sizeof(req.ifname) && req.ifname[l] != 0; l++)
        ;

    if (l == sizeof(req.ifname))
        return -1;

    for (i = l; i < sizeof(req.ifname); i++) {
        if (req.ifname[i] != 0)
            return -1;
    }

    if (!wired_ifname_valid(req.ifname, l))
        return -1;

    memcpy(ifname, req.ifname, l + 1);
    return 1;
}

void wired_ifup_reply_build(uint64_t seq, wired_ifup_status_t status, int err,
        wired_ifup_reply_t *reply) {
    memset(reply, 0, sizeof(*reply));
    reply->magic = WIRED_IFUP_MAGIC;
    reply->owner = (uint32_t) (seq >> 32);
    reply->seq = (uint32_t) seq;
    reply->status = (uint32_t) status;
    reply->err = status == WIRED_IFUP_FAILED ? err : 0;
}

int wired_ifup_reply_read(const uint8_t *buf, size_t len, uint64_t *seq,
        wired_ifup_status_t *status, int *err) {
    wired_ifup_reply_t reply;

    if (buf == NULL || seq == NULL || status == NULL || err == NULL || len != sizeof(reply))
        return -1;

    memcpy(&reply, buf, sizeof(reply));

    if (reply.magic != WIRED_IFUP_MAGIC || reply.status > WIRED_IFUP_FAILED)
        return -1;

    if (reply.status == WIRED_IFUP_FAILED ? (reply.err <= 0 || reply.err > WIRED_ERRNO_MAX) :
            reply.err != 0)
        return -1;

    *seq = wired_ifup_seq(reply.owner, reply.seq);
    *status = (wired_ifup_status_t) reply.status;
    *err = reply.err;
    return 1;
}

int wired_ifup_reply_parse(const uint8_t *buf, size_t len, uint64_t seq,
        wired_ifup_status_t *status, int *err) {
    wired_ifup_status_t st;
    uint64_t got;
    int e;

    if (status == NULL || err == NULL || wired_ifup_reply_read(buf, len, &got, &st, &e) < 0)
        return -1;

    /* An answer to an earlier request: one which timed out, or whose asker died
     * waiting */
    if (got != seq)
        return 0;

    *status = st;
    *err = e;
    return 1;
}

int wired_build_filter(const char *user, const char *selfexcl, char *out, size_t out_len) {
    int has_user = user != NULL && user[0] != 0;
    int has_self = selfexcl != NULL && selfexcl[0] != 0;
    int r;

    if (out == NULL || out_len == 0)
        return -1;

    /* The exclusion first: vlan, pppoes, geneve and mpls in the user's filter move
     * the link offsets of everything compiled after them */
    if (has_user && has_self)
        r = snprintf(out, out_len, "not (%s) and (%s)", selfexcl, user);
    else if (has_user)
        r = snprintf(out, out_len, "%s", user);
    else if (has_self)
        r = snprintf(out, out_len, "not (%s)", selfexcl);
    else
        r = snprintf(out, out_len, "%s", "");

    if (r < 0 || (size_t) r >= out_len)
        return -1;

    return r;
}

int wired_selfexcl_undecided(uint32_t caplen, uint32_t len) {
    return caplen < len && caplen < WIRED_SELFEXCL_DEPTH;
}

void wired_sampler_init(wired_sampler_t *s, unsigned int sample) {
    s->sample = sample == 0 ? 1 : sample;
    s->count = 0;
}

int wired_sampler_take(wired_sampler_t *s) {
    int take = s->count == 0;

    if (++s->count >= s->sample)
        s->count = 0;

    return take;
}

unsigned int wired_offloads_from_features(const char *names, size_t name_len, size_t n_names,
        const uint32_t *active, size_t n_blocks) {
    unsigned int offloads = 0;
    size_t i, o;

    if (names == NULL || active == NULL || name_len == 0)
        return 0;

    for (i = 0; i < n_names && i / 32 < n_blocks; i++) {
        const char *name = names + i * name_len;

        if (!(active[i / 32] & (1U << (i % 32))))
            continue;

        for (o = 0; o < WIRED_OFFLOAD_COUNT; o++) {
            size_t l = strlen(wired_offload_names[o]);

            /* Kernel strings are NUL-padded to name_len, but don't trust that */
            if (l < name_len && memcmp(name, wired_offload_names[o], l) == 0 && name[l] == 0)
                offloads |= 1U << o;
        }
    }

    return offloads;
}

int wired_offloads_describe(unsigned int offloads, char *out, size_t out_len) {
    size_t pos = 0;
    size_t o;

    if (out == NULL || out_len == 0)
        return -1;

    out[0] = 0;

    for (o = 0; o < WIRED_OFFLOAD_COUNT; o++) {
        int r;

        if (!(offloads & (1U << o)))
            continue;

        r = snprintf(out + pos, out_len - pos, "%s%s", pos == 0 ? "" : ",",
                wired_offload_names[o]);

        if (r < 0 || (size_t) r >= out_len - pos)
            return -1;

        pos += (size_t) r;
    }

    return (int) pos;
}

void wired_unpriv_ids(uid_t ruid, gid_t rgid, uid_t *uid, gid_t *gid) {
    *uid = ruid != 0 ? ruid : WIRED_NOBODY_ID;
    *gid = ruid != 0 && rgid != 0 ? rgid : WIRED_NOBODY_ID;
}

int wired_read_text(const char *path, char *buf, size_t buf_len, size_t *len) {
    size_t pos = 0;
    ssize_t r;
    char extra;
    int fd, e;

    if (path == NULL || buf == NULL || buf_len == 0 || len == NULL)
        return -1;

    if ((fd = open(path, O_RDONLY | O_CLOEXEC | O_NOCTTY)) < 0)
        return -1;

    /* /proc text can come in pieces; a byte past what fits makes it too big */
    for (;;) {
        if (pos < buf_len - 1)
            r = read(fd, buf + pos, buf_len - 1 - pos);
        else
            r = read(fd, &extra, 1);

        if (r < 0 && errno == EINTR)
            continue;

        if (r <= 0)
            break;

        if (pos >= buf_len - 1) {
            errno = EFBIG;
            r = -1;
            break;
        }

        pos += (size_t) r;
    }

    e = errno;
    close(fd);
    errno = e;

    if (r < 0)
        return -1;

    buf[pos] = 0;
    *len = pos;
    return 0;
}

/* Spaces, then 1 to 10 decimal digits which fit 32 bits */
static int wired_map_number(const char **p, const char *end, uint32_t *v) {
    uint64_t n = 0;
    size_t digits = 0;

    while (*p < end && **p == ' ')
        (*p)++;

    while (*p < end && **p >= '0' && **p <= '9') {
        if (++digits > 10)
            return -1;

        n = n * 10 + (uint64_t) (**p - '0');
        (*p)++;
    }

    if (digits == 0 || n > UINT32_MAX)
        return -1;

    *v = (uint32_t) n;
    return 0;
}

int wired_id_map_outer(const char *map, size_t len, uint32_t id, uint32_t *outer) {
    const char *p = map;
    const char *end;
    int found = 0;

    if (map == NULL || outer == NULL)
        return -1;

    end = map + len;

    while (p < end) {
        const char *eol = memchr(p, '\n', (size_t) (end - p));
        uint32_t inside, start, count;
        uint64_t o;

        if (eol == NULL)
            return -1;

        if (wired_map_number(&p, eol, &inside) < 0 || p == eol || *p != ' ' ||
                wired_map_number(&p, eol, &start) < 0 || p == eol || *p != ' ' ||
                wired_map_number(&p, eol, &count) < 0 || count == 0)
            return -1;

        while (p < eol && *p == ' ')
            p++;

        if (p != eol)
            return -1;

        if (id >= inside && (uint64_t) id < (uint64_t) inside + count) {
            o = (uint64_t) start + (id - inside);

            /* The kernel never writes overlapping ranges */
            if (found || o > UINT32_MAX)
                return -1;

            *outer = (uint32_t) o;
            found = 1;
        }

        p = eol + 1;
    }

    return found;
}

/* 1 when id maps to a non-zero id of the parent namespace, else -1 with why set */
static int wired_id_outside(const char *map, size_t map_len, const char *kind, uint32_t id,
        char *why, size_t why_len) {
    uint32_t outer;
    int r = wired_id_map_outer(map, map_len, id, &outer);

    if (r < 0) {
        snprintf(why, why_len, "could not read the %s map of its user namespace", kind);
        return -1;
    }

    if (r == 0) {
        snprintf(why, why_len, "its %s %u isn't mapped in its user namespace, so what it is "
                "outside can't be told", kind, (unsigned int) id);
        return -1;
    }

    if (outer == 0) {
        snprintf(why, why_len, "%s %u of its user namespace maps to %s 0 of the parent "
                "namespace, which may be root's (as under 'unshare -r' run by root); run it as "
                "a user with 'setcap cap_net_raw+ep kismet_cap_wired'", kind,
                (unsigned int) id, kind);
        return -1;
    }

    return 1;
}

int wired_userns_ids_check(const wired_userns_ids_t *ids, char *why, size_t why_len) {
    size_t i;

    if (ids == NULL || why == NULL || why_len == 0 || (ids->n_groups != 0 && ids->groups == NULL))
        return -1;

    why[0] = 0;

    if (wired_id_outside(ids->uid_map, ids->uid_map_len, "uid", ids->uid, why, why_len) < 0)
        return -1;

    /* Each map shows only the parent namespace; one further up can still end at root */
    if (ids->uid_is_root) {
        snprintf(why, why_len, "uid %u of its user namespace is the host's uid 0 through the "
                "namespaces above it, so it would capture as root", (unsigned int) ids->uid);
        return -1;
    }

    if (wired_id_outside(ids->gid_map, ids->gid_map_len, "gid", ids->gid, why, why_len) < 0)
        return -1;

    for (i = 0; i < ids->n_groups; i++) {
        if (ids->groups[i] == ids->overflow_gid) {
            snprintf(why, why_len, "holds supplementary groups from outside its user namespace, "
                    "which show as %u and may be root's; start it from an account with no "
                    "supplementary groups, or in a namespace made with newuidmap and newgidmap "
                    "('unshare --map-auto', rootless podman), where as root of the namespace it "
                    "clears them itself",
                    (unsigned int) ids->overflow_gid);
            return -1;
        }

        if (wired_id_outside(ids->gid_map, ids->gid_map_len, "gid", ids->groups[i], why,
                    why_len) < 0)
            return -1;
    }

    /* Root's group shows as itself only when it's mapped somewhere in the chain;
     * overflow_gid also stands for it not being mapped at all */
    if (ids->root_gid == ids->overflow_gid)
        return 1;

    for (i = 0; i <= ids->n_groups; i++) {
        gid_t g = i < ids->n_groups ? ids->groups[i] : ids->gid;

        if (g == ids->root_gid) {
            snprintf(why, why_len, "gid %u of its user namespace is the host's gid 0 (root's "
                    "group) through the namespaces above it", (unsigned int) g);
            return -1;
        }
    }

    return 1;
}

/* Tabs or spaces, then 1 to 16 hex digits up to the end of the line */
static int wired_status_hex(const char *p, const char *eol, uint64_t *v) {
    uint64_t n = 0;
    size_t digits = 0;

    while (p < eol && (*p == '\t' || *p == ' '))
        p++;

    for (; p < eol; p++) {
        unsigned int h;

        if (*p >= '0' && *p <= '9')
            h = (unsigned int) (*p - '0');
        else if (*p >= 'a' && *p <= 'f')
            h = (unsigned int) (*p - 'a') + 10;
        else if (*p >= 'A' && *p <= 'F')
            h = (unsigned int) (*p - 'A') + 10;
        else
            return -1;

        if (++digits > 16)
            return -1;

        n = (n << 4) | h;
    }

    if (digits == 0)
        return -1;

    *v = n;
    return 0;
}

int wired_status_caps(const char *status, size_t len, uint64_t *prm, uint64_t *eff) {
    static const char prm_key[] = "CapPrm:";
    static const char eff_key[] = "CapEff:";
    const size_t key_len = sizeof(prm_key) - 1;
    const char *p = status;
    const char *end;
    int have_prm = 0, have_eff = 0;

    if (status == NULL || prm == NULL || eff == NULL)
        return -1;

    end = status + len;

    while (p < end) {
        const char *eol = memchr(p, '\n', (size_t) (end - p));

        if (eol == NULL)
            eol = end;

        if ((size_t) (eol - p) >= key_len && memcmp(p, prm_key, key_len) == 0) {
            if (have_prm || wired_status_hex(p + key_len, eol, prm) < 0)
                return -1;
            have_prm = 1;
        } else if ((size_t) (eol - p) >= key_len && memcmp(p, eff_key, key_len) == 0) {
            if (have_eff || wired_status_hex(p + key_len, eol, eff) < 0)
                return -1;
            have_eff = 1;
        }

        p = eol < end ? eol + 1 : end;
    }

    return have_prm && have_eff ? 0 : -1;
}

int wired_status_json(const wired_status_t *st, char *out, size_t out_len) {
    char offloads[256];
    size_t pos = 0;
    size_t o;
    int r;

    if (st == NULL || out == NULL)
        return -1;

    /* Kernel names are plain lowercase text; quote each one */
    for (o = 0; o < WIRED_OFFLOAD_COUNT; o++) {
        if (!(st->offloads & (1U << o)))
            continue;

        r = snprintf(offloads + pos, sizeof(offloads) - pos, "%s\"%s\"", pos == 0 ? "" : ",",
                wired_offload_names[o]);

        if (r < 0 || (size_t) r >= sizeof(offloads) - pos)
            return -1;

        pos += (size_t) r;
    }
    offloads[pos] = 0;

    r = snprintf(out, out_len,
            "{\"kernel_received\":%" PRIu64 ",\"kernel_drops\":%" PRIu64 ","
            "\"if_drops\":%" PRIu64 ",\"frames\":%" PRIu64 ",\"forwarded\":%" PRIu64 ","
            "\"sample\":%u,\"snaplen\":%u,\"buffer_mb\":%u,\"promisc\":%s,"
            "\"remote_excluded\":%s,\"offloads\":[%s]%s}",
            st->kernel_received, st->kernel_drops, st->if_drops, st->frames, st->forwarded,
            st->sample, st->snaplen, st->buffer_mb, st->promisc ? "true" : "false",
            st->remote_excluded ? "true" : "false", offloads,
            st->carrier < 0 ? "" : (st->carrier ? ",\"carrier\":true" : ",\"carrier\":false"));

    if (r < 0 || (size_t) r >= out_len)
        return -1;

    return r;
}
