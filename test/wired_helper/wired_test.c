/* Tests for kismet_cap_wired's option parsing, interface filter, server
 * exclusion filter, sampling, offload decoding, source UUID, status record and
 * where the server connection runs, with the rtnetlink link kind parser, the
 * ids root switches to, and the uid_map and /proc status readers and the user
 * namespace id check the privilege drop uses (capture_wired/wired_util.c, wired_sysfs.c); priv_test
 * covers the privilege drop itself.  The interface checks run against
 * a made-up sysfs tree, removed again at the end; the ethtool and rtnetlink
 * requests only read, so nothing here needs privileges.
 *
 *   make -C capture_wired test && test/wired_helper/wired_test
 *
 * With an argument, the status records are also written to that file, one per
 * line, for a strict JSON parse.
 */

/* nftw */
#define _GNU_SOURCE

#include <errno.h>
#include <ftw.h>
#include <stddef.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#include <arpa/inet.h>
#include <netinet/in.h>
#include <sys/stat.h>

#include <linux/if_link.h>
#include <linux/netlink.h>
#include <linux/rtnetlink.h>

#include <pcap.h>

#include "../../capture_wired/wired_sysfs.h"
#include "../../capture_wired/wired_util.h"

static int failures = 0;
static int checks = 0;

#define CHECK(cond, ...) do { \
    checks++; \
    if (!(cond)) { \
        failures++; \
        printf("FAIL %s:%d: ", __FILE__, __LINE__); \
        printf(__VA_ARGS__); \
        printf("\n"); \
    } \
} while (0)

static void test_ifname(void) {
    static const struct {
        const char *name;
        int valid;
    } cases[] = {
        { "eth0", 1 }, { "enp4s0", 1 }, { "br-lan", 1 }, { "eth0.100", 1 },
        { "bond_0", 1 }, { "x@y", 1 }, { "a", 1 }, { "abcdefghijklmno", 1 },
        { "abcdefghijklmnop", 0 }, { "", 0 }, { ".", 0 }, { "..", 0 }, { ".eth0", 0 },
        { "eth/0", 0 }, { "../lo", 0 }, { "eth0:1", 0 }, { "eth 0", 0 }, { "eth\t0", 0 },
        { "eth0\n", 0 }, { "\xc3\xa9th0", 0 }, { "eth$0", 0 }, { "eth\"0", 0 },
    };
    size_t i;

    for (i = 0; i < sizeof(cases) / sizeof(cases[0]); i++)
        CHECK(wired_ifname_valid(cases[i].name, strlen(cases[i].name)) == cases[i].valid,
                "ifname '%s' valid=%d", cases[i].name, cases[i].valid);

    /* An embedded NUL is past what the caller passed as the name */
    CHECK(!wired_ifname_valid("eth\0x", 5), "embedded NUL");
    CHECK(!wired_ifname_valid(NULL, 4), "NULL name");
}

static void test_parse_uint(void) {
    unsigned long v = 0;

    CHECK(wired_parse_uint("1600", 4, 64, 65535, &v) == 1 && v == 1600, "1600");
    CHECK(wired_parse_uint("65535", 5, 64, 65535, &v) == 1 && v == 65535, "max");
    CHECK(wired_parse_uint("64", 2, 64, 65535, &v) == 1 && v == 64, "min");
    CHECK(wired_parse_uint("65536", 5, 64, 65535, &v) < 0, "over max");
    CHECK(wired_parse_uint("63", 2, 64, 65535, &v) < 0, "under min");
    CHECK(wired_parse_uint("-1", 2, 0, 65535, &v) < 0, "negative");
    CHECK(wired_parse_uint("+1", 2, 0, 65535, &v) < 0, "plus sign");
    CHECK(wired_parse_uint(" 1", 2, 0, 65535, &v) < 0, "space");
    CHECK(wired_parse_uint("1a", 2, 0, 65535, &v) < 0, "trailing letter");
    CHECK(wired_parse_uint("0x10", 4, 0, 65535, &v) < 0, "hex");
    CHECK(wired_parse_uint("", 0, 0, 65535, &v) < 0, "empty");
    CHECK(wired_parse_uint("00000000100", 11, 0, 65535, &v) < 0, "too many digits");
    /* Would wrap a 32 bit long without the overflow guard */
    CHECK(wired_parse_uint("9999999999", 10, 0, 4294967295UL, &v) < 0, "wrap");
    CHECK(wired_parse_uint("4294967295", 10, 0, 4294967295UL, &v) == 1 && v == 4294967295UL,
            "32 bit max");
    /* A digit above a one-digit max, which max - d would wrap */
    CHECK(wired_parse_uint("5", 1, 0, 3, &v) < 0, "digit over max");
    CHECK(wired_parse_uint("15", 2, 0, 3, &v) < 0, "digits over max");
    CHECK(wired_parse_uint("3", 1, 0, 3, &v) == 1 && v == 3, "digit at max");
    CHECK(wired_parse_uint("0", 1, 0, 0, &v) == 1 && v == 0, "max 0");
    CHECK(wired_parse_uint("1", 1, 0, 0, &v) < 0, "over max 0");
    /* Length bounds the read, not a NUL */
    CHECK(wired_parse_uint("12,snaplen", 2, 0, 65535, &v) == 1 && v == 12, "length bound");
}

static int parse(const char *def, wired_opts_t *opts, char *err, size_t err_len) {
    char buf[4096];

    snprintf(buf, sizeof(buf), "%s", def);
    err[0] = 0;
    return wired_parse_opts(buf, opts, err, err_len);
}

static void test_parse_opts(void) {
    wired_opts_t o;
    char err[256];
    char def[2048];

    CHECK(parse("eth0", &o, err, sizeof(err)) == 1, "no options: %s", err);
    CHECK(o.snaplen == WIRED_SNAPLEN_DEFAULT && o.buffer_mb == WIRED_BUFFER_MB_DEFAULT &&
            o.sample == 1 && o.promisc == 1 && !o.has_filter && !o.has_uuid, "defaults");

    CHECK(parse("eth0:name=foo,mode=full,snaplen=128,buffer_mb=8,sample=10,promisc=false",
                &o, err, sizeof(err)) == 1, "all options: %s", err);
    CHECK(o.snaplen == 128 && o.buffer_mb == 8 && o.sample == 10 && o.promisc == 0, "values");

    CHECK(parse("eth0:promisc=TRUE", &o, err, sizeof(err)) == 1 && o.promisc == 1, "TRUE");
    CHECK(parse("eth0:mode=summary", &o, err, sizeof(err)) < 0 && strstr(err, "summary"),
            "summary refused");
    CHECK(parse("eth0:mode=fast", &o, err, sizeof(err)) < 0, "unknown mode");
    CHECK(parse("eth0:snaplen=95", &o, err, sizeof(err)) < 0, "snaplen low");
    CHECK(parse("eth0:snaplen=96", &o, err, sizeof(err)) == 1 && o.snaplen == 96, "snaplen min");
    CHECK(WIRED_SNAPLEN_MIN >= WIRED_SELFEXCL_DEPTH, "snaplen min covers the exclusion");
    CHECK(parse("eth0:snaplen=1e3", &o, err, sizeof(err)) < 0, "snaplen float");

    /* snaplen stays under the server's IPC frame limit */
    CHECK(WIRED_SNAPLEN_MAX + WIRED_IPC_OVERHEAD <= WIRED_IPC_FRAME_MAX, "snaplen max in frame");
    snprintf(def, sizeof(def), "eth0:snaplen=%u", WIRED_SNAPLEN_MAX);
    CHECK(parse(def, &o, err, sizeof(err)) == 1 && o.snaplen == WIRED_SNAPLEN_MAX,
            "snaplen max: %s", err);
    snprintf(def, sizeof(def), "eth0:snaplen=%u", WIRED_SNAPLEN_MAX + 1);
    CHECK(parse(def, &o, err, sizeof(err)) < 0 && strstr(err, "snaplen") != NULL,
            "snaplen over max");
    CHECK(parse("eth0:snaplen=16384", &o, err, sizeof(err)) < 0, "snaplen 16384");
    CHECK(parse("eth0:snaplen=65535", &o, err, sizeof(err)) < 0, "snaplen 65535");

    CHECK(parse("eth0:buffer_mb=0", &o, err, sizeof(err)) < 0, "buffer 0");
    CHECK(parse("eth0:buffer_mb=1025", &o, err, sizeof(err)) < 0, "buffer high");
    CHECK(parse("eth0:buffer_mb=1024", &o, err, sizeof(err)) == 1 && o.buffer_mb == 1024,
            "buffer max");
    CHECK(parse("eth0:sample=0", &o, err, sizeof(err)) < 0, "sample 0");
    CHECK(parse("eth0:sample=1000001", &o, err, sizeof(err)) < 0, "sample high");
    CHECK(parse("eth0:promisc=yes", &o, err, sizeof(err)) < 0, "promisc yes");
    CHECK(parse("eth0:snaplen", &o, err, sizeof(err)) < 0, "flag without value");
    CHECK(parse("eth0:filter=\"unterminated", &o, err, sizeof(err)) < 0, "open quote");

    CHECK(parse("eth0:filter=\"not port 22 and (tcp or udp)\",snaplen=200", &o, err,
                sizeof(err)) == 1, "quoted filter: %s", err);
    CHECK(o.has_filter && strcmp(o.filter, "not port 22 and (tcp or udp)") == 0 &&
            o.snaplen == 200, "quoted filter value '%s'", o.filter);
    CHECK(parse("eth0:filter=arp", &o, err, sizeof(err)) == 1 && strcmp(o.filter, "arp") == 0,
            "bare filter");
    CHECK(parse("eth0:filter=\"arp\ttcp\"", &o, err, sizeof(err)) < 0, "control char");
    CHECK(parse("eth0:filter=\"arp\x7f\"", &o, err, sizeof(err)) < 0, "DEL");
    CHECK(parse("eth0:filter=\"arp \xc3\xa9\"", &o, err, sizeof(err)) < 0, "non-ASCII");

    /* A filter which could climb out of its parentheses next to the exclusion */
    CHECK(parse("eth0:filter=\"tcp) or (ip\"", &o, err, sizeof(err)) < 0 &&
            strstr(err, "parenthes") != NULL, "close before open: %s", err);
    CHECK(parse("eth0:filter=\"(tcp\"", &o, err, sizeof(err)) < 0, "left open");
    CHECK(parse("eth0:filter=\"tcp)\"", &o, err, sizeof(err)) < 0, "extra close");
    CHECK(parse("eth0:filter=\"((tcp) or (vlan and (tcp)))\"", &o, err, sizeof(err)) == 1,
            "nested balanced: %s", err);
    CHECK(parse("eth0:filter=\"   \"", &o, err, sizeof(err)) == 1 && !o.has_filter,
            "blank filter is no filter");
    CHECK(parse("eth0:filter=\"\"", &o, err, sizeof(err)) == 1 && !o.has_filter,
            "empty filter is no filter");

    memset(def, 0, sizeof(def));
    snprintf(def, sizeof(def), "eth0:filter=\"");
    memset(def + strlen(def), 'a', WIRED_FILTER_MAX);
    strcat(def, "\"");
    CHECK(parse(def, &o, err, sizeof(err)) == 1 && strlen(o.filter) == WIRED_FILTER_MAX,
            "filter at max: %s", err);

    memset(def, 0, sizeof(def));
    snprintf(def, sizeof(def), "eth0:filter=\"");
    memset(def + strlen(def), 'a', WIRED_FILTER_MAX + 1);
    strcat(def, "\"");
    CHECK(parse(def, &o, err, sizeof(err)) < 0, "filter over max");

    CHECK(parse("eth0:uuid=0123ABCD-0000-4000-8000-00000000abcd", &o, err, sizeof(err)) == 1 &&
            o.has_uuid && strcmp(o.uuid, "0123ABCD-0000-4000-8000-00000000abcd") == 0, "uuid");
    CHECK(parse("eth0:uuid=0123ABCD-0000-4000-8000-00000000abc", &o, err, sizeof(err)) < 0,
            "uuid short");
    CHECK(parse("eth0:uuid=0123ABCD-0000-4000-8000-00000000abcde", &o, err, sizeof(err)) < 0,
            "uuid long");
    CHECK(parse("eth0:uuid=0123ABCD00000-4000-8000-00000000abcd", &o, err, sizeof(err)) < 0,
            "uuid dash");
    CHECK(parse("eth0:uuid=0123ABCG-0000-4000-8000-00000000abcd", &o, err, sizeof(err)) < 0,
            "uuid hex");
}

static void test_balanced(void) {
    CHECK(wired_filter_balanced("", 0), "empty");
    CHECK(wired_filter_balanced("tcp", 3), "none");
    CHECK(wired_filter_balanced("(a (b) c)", 9), "nested");
    CHECK(!wired_filter_balanced(")(", 2), "close first");
    CHECK(!wired_filter_balanced("((a)", 4), "open left");
    /* Only the given length counts */
    CHECK(wired_filter_balanced("(a))", 3), "length bound");
    CHECK(!wired_filter_balanced(NULL, 0), "NULL");
}

static void test_unknown_options(void) {
    char out[256];

    CHECK(wired_unknown_options("eth0", out, sizeof(out)) == 0 && out[0] == 0, "no options");
    CHECK(wired_unknown_options("eth0:type=wired,name=x,snaplen=128,filter=\"a,b=c\","
                "uuid=0123ABCD-0000-4000-8000-00000000abcd,retry=true", out, sizeof(out)) == 0,
            "all known, quoted comma: '%s'", out);
    CHECK(wired_unknown_options("eth0:NAME=x,SnapLen=128,channel_hop=false,"
                "info_antenna_type=omni", out, sizeof(out)) == 0, "case and server options '%s'", out);
    CHECK(wired_unknown_options("eth0:snaplem=128,name=x,promiscuous=true", out, sizeof(out)) == 2 &&
            strcmp(out, "snaplem,promiscuous") == 0, "two unknown '%s'", out);
    /* Echoed into a message: allowlisted and cut */
    CHECK(wired_unknown_options("eth0:a<b>%s\x01=1", out, sizeof(out)) == 1 &&
            strcmp(out, "a?b??s?") == 0, "allowlist '%s'", out);
    CHECK(wired_unknown_options("eth0:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa=1", out,
                sizeof(out)) == 1 && strlen(out) == 32, "cut to 32 '%s'", out);
    CHECK(wired_unknown_options("eth0:bogus1=1,bogus2=2", out, 9) == 2 && strcmp(out, "bogus1,b") == 0,
            "output bounded '%s'", out);
    CHECK(wired_unknown_options("eth0:filter=\"x,bogus=1", out, sizeof(out)) == 0,
            "unterminated quote stops");
    CHECK(wired_unknown_options("eth0:,=1,novalue,x=1", out, sizeof(out)) == 1 &&
            strcmp(out, "x") == 0, "empty key and bare token '%s'", out);
#ifdef WIRED_REPLAY
    CHECK(wired_unknown_options("eth0:replay=/x", out, sizeof(out)) == 0, "replay known");
#else
    CHECK(wired_unknown_options("eth0:replay=/x", out, sizeof(out)) == 1, "replay unknown");
#endif
    CHECK(wired_unknown_options(NULL, out, sizeof(out)) == 0, "NULL");
}

static void test_unpriv_ids(void) {
    uid_t u = 1;
    gid_t g = 1;

    wired_unpriv_ids(0, 0, &u, &g);
    CHECK(u == WIRED_NOBODY_ID && g == WIRED_NOBODY_ID, "root started it: nobody");
    wired_unpriv_ids(1000, 1000, &u, &g);
    CHECK(u == 1000 && g == 1000, "setuid root, the invoking user");
    wired_unpriv_ids(1000, 0, &u, &g);
    CHECK(u == 1000 && g == WIRED_NOBODY_ID, "the invoking user, never root's group");
    wired_unpriv_ids(0, 1000, &u, &g);
    CHECK(u == WIRED_NOBODY_ID && g == WIRED_NOBODY_ID, "root with another group: nobody");
    wired_unpriv_ids(WIRED_NOBODY_ID, 100, &u, &g);
    CHECK(u == WIRED_NOBODY_ID && g == 100, "started by nobody");
}

static void test_id_map(void) {
    static const struct {
        const char *map;
        uint32_t id;
        int r;
        uint32_t outer;
    } cases[] = {
        /* The kernel's own layout, %10u fields */
        { "         0       1000          1\n", 0, 1, 1000 },
        { "         0          0 4294967295\n", 0, 1, 0 },
        { "         0          0 4294967295\n", 4294967294U, 1, 4294967294U },
        { "0 0 1\n", 0, 1, 0 },
        { "0 100000 65536\n", 65535, 1, 165535 },
        { "0 100000 65536\n", 65536, 0, 0 },
        { "1 1000 5\n", 0, 0, 0 },
        { "1 100001 65535\n0 0 1\n", 0, 1, 0 },
        { "0 1000 1   \n", 0, 1, 1000 },
        { "", 0, 0, 0 },
        /* Not a map */
        { "0 1000 1", 0, -1, 0 },
        { "0 1000\n", 0, -1, 0 },
        { "0 1000 1 7\n", 0, -1, 0 },
        { "0\t1000\t1\n", 0, -1, 0 },
        { "0 1000 0\n", 0, -1, 0 },
        { "-1 1000 1\n", 0, -1, 0 },
        { "0 +1000 1\n", 0, -1, 0 },
        { "0 4294967296 1\n", 0, -1, 0 },
        { "0 00000000001 1\n", 0, -1, 0 },
        { "0 4294967295 2\n", 1, -1, 0 },
        { "0 1000 1\n\n", 0, -1, 0 },
        { "0 1000 5\n2 2000 1\n", 2, -1, 0 },
        { "0 1000 5\n2 2000 1\n", 1, 1, 1001 },
        { "2 2000 1\n0 1000 2\n", 0, 1, 1000 },
        { "0x0 1000 1\n", 0, -1, 0 },
    };
    uint32_t outer;
    size_t i;
    int r;

    for (i = 0; i < sizeof(cases) / sizeof(cases[0]); i++) {
        outer = 77;
        r = wired_id_map_outer(cases[i].map, strlen(cases[i].map), cases[i].id, &outer);
        CHECK(r == cases[i].r && (r != 1 || outer == cases[i].outer), "id map %zu: r=%d outer=%u", i, r,
                (unsigned int) outer);
    }

    /* Overlapping ranges, whichever comes first */
    CHECK(wired_id_map_outer("5 10 1\n0 1000 10\n", strlen("5 10 1\n0 1000 10\n"), 5, &outer) == -1, "overlap");

    /* A NUL inside the length, and only the length is read */
    CHECK(wired_id_map_outer("0 10\0000 1\n", 9, 0, &outer) == -1, "NUL in a field");
    CHECK(wired_id_map_outer("0 1000 1\nGARBAGE", 9, 0, &outer) == 1 && outer == 1000, "length bounds it");
    CHECK(wired_id_map_outer(NULL, 0, 0, &outer) == -1, "NULL map");
}

static wired_userns_ids_t userns_ids(const char *uid_map, const char *gid_map, uid_t uid, gid_t gid,
        const gid_t *groups, size_t n_groups) {
    wired_userns_ids_t ids;

    memset(&ids, 0, sizeof(ids));
    ids.uid_map = uid_map;
    ids.uid_map_len = strlen(uid_map);
    ids.gid_map = gid_map;
    ids.gid_map_len = strlen(gid_map);
    ids.uid = uid;
    ids.gid = gid;
    ids.groups = groups;
    ids.n_groups = n_groups;
    ids.overflow_gid = 65534;
    ids.root_gid = 65534;
    return ids;
}

static void test_userns_ids(void) {
    /* A rootless container: 0 is the user outside, the rest subordinate ids */
    const char *sub = "         0       1000          1\n         1     100000      65536\n";
    const gid_t mapped[] = { 4, 27 };
    const gid_t outside[] = { 0, 65534 };
    const gid_t to_root[] = { 0, 7 };
    wired_userns_ids_t ids;
    char why[512];

    ids = userns_ids(sub, sub, 0, 0, NULL, 0);
    CHECK(wired_userns_ids_check(&ids, why, sizeof(why)) == 1 && why[0] == 0, "container root: %s", why);
    ids = userns_ids(sub, sub, 65534, 65534, NULL, 0);
    CHECK(wired_userns_ids_check(&ids, why, sizeof(why)) == 1, "nobody, mapped and set by the helper: %s", why);
    ids = userns_ids(sub, sub, 5, 5, mapped, 2);
    CHECK(wired_userns_ids_check(&ids, why, sizeof(why)) == 1, "mapped groups: %s", why);

    /* The direct parent: root's own 'unshare -r', and a non-zero id mapped to 0 */
    ids = userns_ids("0 0 1\n", sub, 0, 0, NULL, 0);
    CHECK(wired_userns_ids_check(&ids, why, sizeof(why)) == -1 && strstr(why, "uid 0 of its user namespace maps to uid 0 of the parent") != NULL,
            "uid 0 -> 0: %s", why);
    ids = userns_ids("5 0 1\n", "5 0 1\n", 5, 5, NULL, 0);
    CHECK(wired_userns_ids_check(&ids, why, sizeof(why)) == -1 && strstr(why, "uid 5 of its user namespace maps to uid 0 of the parent") != NULL,
            "uid 5 -> 0: %s", why);
    ids = userns_ids(sub, "0 0 1\n", 0, 0, NULL, 0);
    CHECK(wired_userns_ids_check(&ids, why, sizeof(why)) == -1 && strstr(why, "gid 0 of its user namespace maps to gid 0 of the parent") != NULL,
            "gid 0 -> 0: %s", why);
    ids = userns_ids(sub, "0 1000 1\n7 0 1\n", 0, 0, to_root, 2);
    CHECK(wired_userns_ids_check(&ids, why, sizeof(why)) == -1 && strstr(why, "gid 7 of its") != NULL, "group 7 -> 0: %s", why);

    /* Not mapped, or no map to read */
    ids = userns_ids("1 1000 5\n", sub, 0, 0, NULL, 0);
    CHECK(wired_userns_ids_check(&ids, why, sizeof(why)) == -1 && strstr(why, "isn't mapped") != NULL, "uid unmapped: %s", why);
    ids = userns_ids(sub, sub, 0, 70000, NULL, 0);
    CHECK(wired_userns_ids_check(&ids, why, sizeof(why)) == -1 && strstr(why, "gid 70000 isn't mapped") != NULL, "gid unmapped: %s", why);
    ids = userns_ids("", sub, 0, 0, NULL, 0);
    CHECK(wired_userns_ids_check(&ids, why, sizeof(why)) == -1, "empty uid map");
    ids = userns_ids("0 1000", sub, 0, 0, NULL, 0);
    CHECK(wired_userns_ids_check(&ids, why, sizeof(why)) == -1 && strstr(why, "could not read the uid map") != NULL,
            "malformed uid map: %s", why);
    ids = userns_ids(sub, "0 1000 1\n0 2000 1\n", 0, 0, NULL, 0);
    CHECK(wired_userns_ids_check(&ids, why, sizeof(why)) == -1 && strstr(why, "gid map") != NULL, "overlapping gid map: %s", why);

    /* Groups from outside the namespace show as the overflow gid, mapped or not */
    ids = userns_ids("0 1000 1\n", "0 1000 1\n", 0, 0, outside, 2);
    CHECK(wired_userns_ids_check(&ids, why, sizeof(why)) == -1 && strstr(why, "supplementary groups from outside") != NULL &&
            strstr(why, "'unshare --map-auto'") != NULL && strstr(why, "setpriv") == NULL, "unshare -r groups: %s", why);
    ids = userns_ids(sub, sub, 0, 0, outside, 2);
    CHECK(wired_userns_ids_check(&ids, why, sizeof(why)) == -1 && strstr(why, "supplementary groups from outside") != NULL,
            "overflow gid mapped: %s", why);
    ids = userns_ids(sub, sub, 0, 0, outside, 2);
    ids.overflow_gid = 4000;
    ids.root_gid = 4000;
    CHECK(wired_userns_ids_check(&ids, why, sizeof(why)) == 1, "overflowgid set elsewhere: %s", why);
    ids = userns_ids(sub, sub, 0, 0, outside, 1);
    CHECK(wired_userns_ids_check(&ids, why, sizeof(why)) == 1, "only mapped groups: %s", why);

    /* Root further up: the probe opened, or root's group shows as an id held */
    ids = userns_ids("5 7 1\n", "5 7 1\n", 5, 5, NULL, 0);
    ids.uid_is_root = 1;
    CHECK(wired_userns_ids_check(&ids, why, sizeof(why)) == -1 && strstr(why, "host's uid 0 through") != NULL,
            "uid root further up: %s", why);
    ids = userns_ids("5 7 1\n", "5 7 1\n", 5, 5, NULL, 0);
    ids.root_gid = 5;
    CHECK(wired_userns_ids_check(&ids, why, sizeof(why)) == -1 && strstr(why, "gid 5 of its user namespace is the host's gid 0") != NULL,
            "gid root further up: %s", why);
    ids = userns_ids(sub, sub, 0, 0, mapped, 2);
    ids.root_gid = 27;
    CHECK(wired_userns_ids_check(&ids, why, sizeof(why)) == -1 && strstr(why, "gid 27 of its") != NULL, "group root further up: %s", why);
    ids = userns_ids(sub, sub, 0, 0, mapped, 2);
    ids.root_gid = 99;
    CHECK(wired_userns_ids_check(&ids, why, sizeof(why)) == 1, "root's group mapped, not held: %s", why);

    /* Bad arguments; a short why is cut, never overrun */
    ids = userns_ids(sub, sub, 0, 0, NULL, 2);
    CHECK(wired_userns_ids_check(&ids, why, sizeof(why)) == -1, "groups NULL with a count");
    CHECK(wired_userns_ids_check(NULL, why, sizeof(why)) == -1, "NULL ids");
    ids = userns_ids("0 0 1\n", sub, 0, 0, NULL, 0);
    memset(why, 'x', sizeof(why));
    CHECK(wired_userns_ids_check(&ids, why, 8) == -1 && strlen(why) == 7 && why[8] == 'x', "short why");
}

static void test_status_caps(void) {
    static const char status[] =
        "Name:\tkismet_cap_wire\nUmask:\t0022\nState:\tS (sleeping)\nUid:\t1000\t1000\t1000\t1000\n"
        "CapInh:\t0000000000000000\nCapPrm:\t0000000000002000\nCapEff:\t0000000000002000\n"
        "CapBnd:\t000001ffffffffff\nCapAmb:\t0000000000000000\nNoNewPrivs:\t0\n";
    static const struct {
        const char *text;
        int r;
        uint64_t prm, eff;
    } cases[] = {
        { "CapPrm:\t000001ffffffffff\nCapEff:\t000001FFFFFFFFFF\n", 0, 0x1ffffffffffULL, 0x1ffffffffffULL },
        { "CapEff:\t0\nCapPrm:\tffffffffffffffff", 0, UINT64_MAX, 0 },
        { "CapPrm: 3000\nCapEff:   2000\n", 0, 0x3000, 0x2000 },
        { "CapPrm:\t0000000000002000\n", -1, 0, 0 },
        { "CapPrm:\t1\nCapEff:\t1\nCapPrm:\t0\n", -1, 0, 0 },
        { "CapPrm:\t10000000000000000\nCapEff:\t0\n", -1, 0, 0 },
        { "CapPrm:\t\nCapEff:\t0\n", -1, 0, 0 },
        { "CapPrm:\t2000 \nCapEff:\t0\n", -1, 0, 0 },
        { "CapPrm:\t0x2000\nCapEff:\t0\n", -1, 0, 0 },
        { "CapPrm:\t-1\nCapEff:\t0\n", -1, 0, 0 },
        { " CapPrm:\t1\nCapEff:\t1\n", -1, 0, 0 },
        { "capprm:\t1\nCapEff:\t1\n", -1, 0, 0 },
        { "", -1, 0, 0 },
    };
    uint64_t prm = 1, eff = 1;
    size_t i;
    int r;

    CHECK(wired_status_caps(status, sizeof(status) - 1, &prm, &eff) == 0 && prm == 0x2000 && eff == 0x2000,
            "kernel layout");

    for (i = 0; i < sizeof(cases) / sizeof(cases[0]); i++) {
        prm = eff = 1;
        r = wired_status_caps(cases[i].text, strlen(cases[i].text), &prm, &eff);
        CHECK(r == cases[i].r && (r != 0 || (prm == cases[i].prm && eff == cases[i].eff)),
                "status caps %zu: r=%d", i, r);
    }

    /* Cut inside the CapEff value: the digits left still parse, cut before it fails */
    CHECK(wired_status_caps("CapPrm:\t1\nCapEff:\t2000", 20, &prm, &eff) == 0 && eff == 0x20, "cut value");
    CHECK(wired_status_caps("CapPrm:\t1\nCapEff:\t2000", 17, &prm, &eff) == -1, "cut before the value");
    CHECK(wired_status_caps("CapPrm:\t1\nCapEff:\t2\0003", 20, &prm, &eff) == -1, "NUL in a value");
}

static void test_read_text(const char *root) {
    char path[1100], buf[16];
    size_t len = 99;
    FILE *f;

    snprintf(path, sizeof(path), "%s/text", root);

    CHECK(wired_read_text(path, buf, sizeof(buf), &len) == -1, "missing file");

    if ((f = fopen(path, "w")) == NULL) {
        CHECK(0, "fopen %s: %s", path, strerror(errno));
        return;
    }
    fputs("0123456789abcde", f);
    fclose(f);

    CHECK(wired_read_text(path, buf, sizeof(buf), &len) == 0 && len == 15 && strcmp(buf, "0123456789abcde") == 0,
            "exactly fits");
    CHECK(wired_read_text(path, buf, 15, &len) == -1, "a byte too big");
    CHECK(wired_read_text(path, buf, 1, &len) == -1, "only room for the NUL");
    CHECK(wired_read_text(path, buf, 0, &len) == -1, "no room");

    if ((f = fopen(path, "w")) != NULL)
        fclose(f);

    CHECK(wired_read_text(path, buf, sizeof(buf), &len) == 0 && len == 0 && buf[0] == 0, "empty file");
    CHECK(remove(path) == 0, "remove %s", path);

    CHECK(wired_read_text("/proc/self/status", buf, sizeof(buf), &len) == -1, "/proc text too big");
}

static void test_caplen_limit(void) {
    CHECK(wired_caplen_limit(1600, 0) == 1600, "snaplen under limit");
    CHECK(wired_caplen_limit(WIRED_SNAPLEN_MAX, 0) == WIRED_SNAPLEN_MAX, "max");
    CHECK(wired_caplen_limit(65535, 0) == WIRED_SNAPLEN_MAX, "over max clamped");
    CHECK(wired_caplen_limit(WIRED_SNAPLEN_MAX, 100) == WIRED_SNAPLEN_MAX - 100, "gps name");
    CHECK(wired_caplen_limit(1600, 100) == 1600, "gps name, small snaplen");
    CHECK(wired_caplen_limit(WIRED_SNAPLEN_MIN, WIRED_SNAPLEN_MAX - WIRED_SNAPLEN_MIN) ==
            WIRED_SNAPLEN_MIN, "gps name at the edge");
    CHECK(wired_caplen_limit(WIRED_SNAPLEN_MAX, WIRED_SNAPLEN_MAX - WIRED_SNAPLEN_MIN) ==
            WIRED_SNAPLEN_MIN, "gps name at the edge, largest snaplen");
    CHECK(wired_caplen_limit(WIRED_SNAPLEN_MIN, WIRED_SNAPLEN_MAX - WIRED_SNAPLEN_MIN + 1) == 0,
            "gps name too long");
    CHECK(wired_caplen_limit(WIRED_SNAPLEN_MIN, SIZE_MAX) == 0, "huge gps name");
}

static void sa4(struct sockaddr_storage *ss, const char *addr, unsigned int port) {
    struct sockaddr_in *in4 = (struct sockaddr_in *) ss;

    memset(ss, 0, sizeof(*ss));
    in4->sin_family = AF_INET;
    in4->sin_port = htons((uint16_t) port);
    inet_pton(AF_INET, addr, &in4->sin_addr);
}

static void sa6(struct sockaddr_storage *ss, const char *addr, unsigned int port) {
    struct sockaddr_in6 *in6 = (struct sockaddr_in6 *) ss;

    memset(ss, 0, sizeof(*ss));
    in6->sin6_family = AF_INET6;
    in6->sin6_port = htons((uint16_t) port);
    in6->sin6_scope_id = 3;
    inet_pton(AF_INET6, addr, &in6->sin6_addr);
}

#define FRAME_MAX 160

/* Ethernet with ntags VLAN tags of the given TPIDs, then the ethertype */
static size_t build_eth(uint8_t *f, const uint16_t *tpids, size_t ntags, uint16_t et) {
    size_t p, t;

    memset(f, 0, FRAME_MAX);
    memcpy(f, "\x02\x00\x00\x00\x00\x01\x02\x00\x00\x00\x00\x02", 12);
    p = 12;

    for (t = 0; t < ntags; t++) {
        f[p++] = (uint8_t) (tpids[t] >> 8);
        f[p++] = (uint8_t) tpids[t];
        f[p++] = 0x00;
        f[p++] = (uint8_t) (100 + t);
    }

    f[p++] = (uint8_t) (et >> 8);
    f[p++] = (uint8_t) et;

    return p;
}

/* IPv4 with ihl 32-bit words of header (5 to 15), TCP or another protocol */
static size_t build_ip4(uint8_t *f, const uint16_t *tpids, size_t ntags, unsigned int ihl,
        uint8_t proto, uint16_t frag, const char *src, unsigned int sport, const char *dst,
        unsigned int dport) {
    size_t p = build_eth(f, tpids, ntags, 0x0800);
    struct in_addr a;

    f[p] = (uint8_t) (0x40 | ihl);
    f[p + 3] = (uint8_t) (ihl * 4 + 20);
    f[p + 6] = (uint8_t) (frag >> 8);
    f[p + 7] = (uint8_t) frag;
    f[p + 8] = 64;
    f[p + 9] = proto;
    inet_pton(AF_INET, src, &a);
    memcpy(f + p + 12, &a, 4);
    inet_pton(AF_INET, dst, &a);
    memcpy(f + p + 16, &a, 4);
    p += ihl * 4;

    f[p] = (uint8_t) (sport >> 8);
    f[p + 1] = (uint8_t) sport;
    f[p + 2] = (uint8_t) (dport >> 8);
    f[p + 3] = (uint8_t) dport;
    f[p + 12] = 0x50;
    f[p + 13] = 0x10;

    return p + 20;
}

static size_t build_tcp4(uint8_t *f, const uint16_t *tpids, size_t ntags, const char *src,
        unsigned int sport, const char *dst, unsigned int dport) {
    return build_ip4(f, tpids, ntags, 5, 6, 0, src, sport, dst, dport);
}

static size_t build_tcp6(uint8_t *f, const uint16_t *tpids, size_t ntags, const char *src,
        unsigned int sport, const char *dst, unsigned int dport) {
    size_t p = build_eth(f, tpids, ntags, 0x86dd);

    f[p] = 0x60;
    f[p + 5] = 20;
    f[p + 6] = 6;
    f[p + 7] = 64;
    inet_pton(AF_INET6, src, f + p + 8);
    inet_pton(AF_INET6, dst, f + p + 24);
    p += 40;

    f[p] = (uint8_t) (sport >> 8);
    f[p + 1] = (uint8_t) sport;
    f[p + 2] = (uint8_t) (dport >> 8);
    f[p + 3] = (uint8_t) dport;
    f[p + 12] = 0x50;

    return p + 20;
}

static int filter_accepts(pcap_t *dead, const char *expr, const uint8_t *f, size_t len) {
    struct bpf_program prog;
    struct pcap_pkthdr h;
    int r;

    if (pcap_compile(dead, &prog, expr, 1, PCAP_NETMASK_UNKNOWN) < 0)
        return -1;

    memset(&h, 0, sizeof(h));
    h.caplen = h.len = (bpf_u_int32) len;
    r = pcap_offline_filter(&prog, &h, f) != 0;
    pcap_freecode(&prog);

    return r;
}

#define SRV4 "198.51.100.20"
#define SRV6 "2001:db8::20"
#define SRV_PORT 2502
#define LOCAL4 "192.0.2.10"
#define LOCAL6 "2001:db8::10"

typedef struct {
    const char *name;
    int server;
    uint8_t f[FRAME_MAX];
    size_t len;
} sx_frame_t;

static size_t sx_frames(sx_frame_t *fr) {
    static const uint16_t q1[1] = { 0x8100 };
    static const uint16_t ad1[1] = { 0x88a8 };
    static const uint16_t qinq[2] = { 0x88a8, 0x8100 };
    static const uint16_t q3[3] = { 0x9100, 0x88a8, 0x8100 };
    static const uint16_t q4[4] = { 0x8100, 0x8100, 0x8100, 0x8100 };
    size_t n = 0;

#define SX(nm, srv, expr) do { fr[n].name = nm; fr[n].server = srv; fr[n].len = expr; n++; } while (0)
    SX("to server untagged", 1, build_tcp4(fr[n].f, NULL, 0, LOCAL4, 40000, SRV4, SRV_PORT));
    SX("from server untagged", 1, build_tcp4(fr[n].f, NULL, 0, SRV4, SRV_PORT, LOCAL4, 40000));
    SX("to server 802.1Q", 1, build_tcp4(fr[n].f, q1, 1, LOCAL4, 40000, SRV4, SRV_PORT));
    SX("from server 802.1ad", 1, build_tcp4(fr[n].f, ad1, 1, SRV4, SRV_PORT, LOCAL4, 40000));
    SX("to server QinQ", 1, build_tcp4(fr[n].f, qinq, 2, LOCAL4, 40000, SRV4, SRV_PORT));
    SX("from server 3 tags", 1, build_tcp4(fr[n].f, q3, 3, SRV4, SRV_PORT, LOCAL4, 40000));
    SX("sibling helper to server", 1, build_tcp4(fr[n].f, NULL, 0, LOCAL4, 40007, SRV4, SRV_PORT));
    SX("other sensor to server", 1, build_tcp4(fr[n].f, q1, 1, "192.0.2.99", 51000, SRV4, SRV_PORT));
    SX("to server, IP options", 1, build_ip4(fr[n].f, NULL, 0, 7, 6, 0, LOCAL4, 40000, SRV4, SRV_PORT));
    SX("from server, IP options", 1, build_ip4(fr[n].f, q1, 1, 15, 6, 0x4000, SRV4, SRV_PORT, LOCAL4, 40000));

    SX("4 tags (past the exclusion)", 0, build_tcp4(fr[n].f, q4, 4, LOCAL4, 40000, SRV4, SRV_PORT));
    SX("other server port", 0, build_tcp4(fr[n].f, NULL, 0, LOCAL4, 40000, SRV4, SRV_PORT + 1));
    SX("server address, swapped ports", 0, build_tcp4(fr[n].f, NULL, 0, SRV4, 40000, LOCAL4, SRV_PORT));
    SX("udp to server port", 0, build_ip4(fr[n].f, NULL, 0, 5, 17, 0, LOCAL4, 40000, SRV4, SRV_PORT));
    SX("non-first fragment", 0, build_ip4(fr[n].f, NULL, 0, 5, 6, 0x0010, LOCAL4, 40000, SRV4, SRV_PORT));
    SX("other tcp untagged", 0, build_tcp4(fr[n].f, NULL, 0, "198.51.100.1", 80, "198.51.100.2", 1234));
    SX("other tcp 802.1Q", 0, build_tcp4(fr[n].f, q1, 1, "198.51.100.1", 80, "198.51.100.2", SRV_PORT));
    SX("v6 to server port", 0, build_tcp6(fr[n].f, NULL, 0, LOCAL6, 40000, SRV6, SRV_PORT));
    SX("v6 other tcp", 0, build_tcp6(fr[n].f, NULL, 0, LOCAL6, 40000, "2001:db8::21", 443));
#undef SX

    return n;
}

static size_t sx_frames6(sx_frame_t *fr) {
    static const uint16_t q1[1] = { 0x8100 };
    static const uint16_t qinq[2] = { 0x88a8, 0x8100 };
    static const uint16_t q3[3] = { 0x9100, 0x88a8, 0x8100 };
    size_t n = 0;

#define SX(nm, srv, expr) do { fr[n].name = nm; fr[n].server = srv; fr[n].len = expr; n++; } while (0)
    SX("v6 to server untagged", 1, build_tcp6(fr[n].f, NULL, 0, LOCAL6, 40000, SRV6, SRV_PORT));
    SX("v6 from server 802.1Q", 1, build_tcp6(fr[n].f, q1, 1, SRV6, SRV_PORT, LOCAL6, 40000));
    SX("v6 to server QinQ", 1, build_tcp6(fr[n].f, qinq, 2, LOCAL6, 40000, SRV6, SRV_PORT));
    SX("v6 from server 3 tags", 1, build_tcp6(fr[n].f, q3, 3, SRV6, SRV_PORT, LOCAL6, 40000));

    SX("v6 other host, server port", 0, build_tcp6(fr[n].f, q1, 1, LOCAL6, 40000, "2001:db8::21", SRV_PORT));
    SX("v6 swapped ports", 0, build_tcp6(fr[n].f, NULL, 0, SRV6, 40000, LOCAL6, SRV_PORT));
    SX("v6 other tcp", 0, build_tcp6(fr[n].f, NULL, 0, LOCAL6, 40000, "2001:db8::21", 443));
    SX("v4 tcp to the server port", 0, build_tcp4(fr[n].f, NULL, 0, LOCAL4, 40000, SRV4, SRV_PORT));
#undef SX

    return n;
}

/* pppoes and geneve move the link offsets of everything compiled after them, as
 * vlan does; the exclusion is compiled first so none of them can shift it */
static const char *sx_users[] = {
    NULL, "not port 22", "tcp", "tcp or (vlan and tcp)", "vlan", "vlan 100",
    "arp or (vlan and arp)", "ip or (vlan and ip)", "tcp or (vlan and tcp) or vlan",
    "vlan and vlan and tcp", "(vlan and tcp) or tcp", "not vlan",
    "pppoes", "tcp or pppoes", "pppoes or tcp", "tcp or pppoes 7", "vlan and pppoes",
    "geneve", "tcp or geneve", "geneve or tcp", "ip6 or geneve", "tcp or mpls",
};

static void test_selfexcl_family(pcap_t *dead, int v6) {
    sx_frame_t fr[24];
    size_t nf = v6 ? sx_frames6(fr) : sx_frames(fr);
    const char *fam = v6 ? "v6" : "v4";
    struct sockaddr_storage srv;
    struct bpf_program self, full, user;
    char se[WIRED_SELFEXCL_MAX];
    char expr[WIRED_FULL_FILTER_MAX];
    size_t u, i;

    if (v6)
        sa6(&srv, SRV6, SRV_PORT);
    else
        sa4(&srv, SRV4, SRV_PORT);

    CHECK(wired_build_selfexcl((struct sockaddr *) &srv, se, sizeof(se)) > 0, "%s selfexcl", fam);
    CHECK(strstr(se, "vlan") == NULL, "no vlan keyword in the exclusion");

    /* The userspace check: the exclusion alone, on frames with their tags inline */
    if (pcap_compile(dead, &self, se, 1, PCAP_NETMASK_UNKNOWN) < 0) {
        CHECK(0, "%s selfexcl compiles: %s", fam, pcap_geterr(dead));
        return;
    }

    for (i = 0; i < nf; i++) {
        struct pcap_pkthdr h;

        memset(&h, 0, sizeof(h));
        h.caplen = h.len = (bpf_u_int32) fr[i].len;
        CHECK((pcap_offline_filter(&self, &h, fr[i].f) != 0) == fr[i].server,
                "userspace exclusion, %s", fr[i].name);
    }

    pcap_freecode(&self);

    /* The kernel filter: the user's filter and the exclusion together.  Server
     * frames are dropped whatever the user wrote; every other frame gets the
     * user filter's verdict */
    for (u = 0; u < sizeof(sx_users) / sizeof(sx_users[0]); u++) {
        const char *un = sx_users[u] != NULL ? sx_users[u] : "(none)";
        int have_user = 0;

        if (wired_build_filter(sx_users[u], se, expr, sizeof(expr)) <= 0 ||
                pcap_compile(dead, &full, expr, 1, PCAP_NETMASK_UNKNOWN) < 0) {
            CHECK(0, "[%s] %s composed filter compiles: %s", un, fam, pcap_geterr(dead));
            continue;
        }

        if (sx_users[u] != NULL) {
            if (pcap_compile(dead, &user, sx_users[u], 1, PCAP_NETMASK_UNKNOWN) < 0) {
                CHECK(0, "[%s] user filter compiles", un);
                pcap_freecode(&full);
                continue;
            }
            have_user = 1;
        }

        for (i = 0; i < nf; i++) {
            struct pcap_pkthdr h;
            int pass, upass;

            memset(&h, 0, sizeof(h));
            h.caplen = h.len = (bpf_u_int32) fr[i].len;
            pass = pcap_offline_filter(&full, &h, fr[i].f) != 0;
            upass = have_user ? pcap_offline_filter(&user, &h, fr[i].f) != 0 : 1;

            if (fr[i].server)
                CHECK(!pass, "[%s] %s server, %s leaked", un, fam, fr[i].name);
            else
                CHECK(pass == upass, "[%s] %s server, %s pass=%d, user filter alone=%d", un, fam,
                        fr[i].name, pass, upass);
        }

        pcap_freecode(&full);
        if (have_user)
            pcap_freecode(&user);
    }
}

static void test_selfexcl(void) {
    struct sockaddr_storage srv;
    char se[WIRED_SELFEXCL_MAX];
    char full[WIRED_FULL_FILTER_MAX];
    char user[WIRED_FILTER_MAX + 1];
    uint8_t f[FRAME_MAX];
    size_t len;
    pcap_t *dead = pcap_open_dead(DLT_EN10MB, 65535);
    const uint16_t q1[1] = { 0x8100 };
    const uint16_t qinq[2] = { 0x88a8, 0x8100 };
    struct bpf_program prog;
    int r;

    CHECK(dead != NULL, "pcap_open_dead");
    if (dead == NULL)
        return;

    test_selfexcl_family(dead, 0);
    test_selfexcl_family(dead, 1);

    /* The exclusion first, at the offsets it was written for, then the user filter */
    sa4(&srv, SRV4, SRV_PORT);
    CHECK(wired_build_selfexcl((struct sockaddr *) &srv, se, sizeof(se)) > 0, "v4 selfexcl");
    r = wired_build_filter("tcp", se, full, sizeof(full));
    CHECK(r > 0 && strncmp(full, "not (", 5) == 0 && strncmp(full + 5, se, strlen(se)) == 0 &&
            strcmp(full + 5 + strlen(se), ") and (tcp)") == 0, "order '%s'", full);
    CHECK(wired_build_filter("arp", NULL, full, sizeof(full)) == 3 && strcmp(full, "arp") == 0,
            "user only");
    CHECK(wired_build_filter(NULL, NULL, full, sizeof(full)) == 0 && full[0] == 0, "none");
    CHECK(wired_build_filter("", "", full, sizeof(full)) == 0, "empty strings");
    CHECK(wired_build_filter("arp", NULL, full, 3) < 0, "doesn't fit");
    CHECK(wired_build_selfexcl((struct sockaddr *) &srv, se, 100) < 0, "exclusion doesn't fit");

    /* IPv6, any tag depth up to the limit, and other servers' traffic kept */
    sa6(&srv, "2001:db8::20", SRV_PORT);
    r = wired_build_selfexcl((struct sockaddr *) &srv, se, sizeof(se));
    CHECK(r > 0 && strchr(se, '%') == NULL, "v6 selfexcl");
    CHECK(wired_build_filter(NULL, se, full, sizeof(full)) > 0, "v6 filter");
    len = build_tcp6(f, NULL, 0, "2001:db8::10", 40000, "2001:db8::20", SRV_PORT);
    CHECK(filter_accepts(dead, full, f, len) == 0, "v6 to server dropped");
    len = build_tcp6(f, qinq, 2, "2001:db8::20", SRV_PORT, "2001:db8::11", 41000);
    CHECK(filter_accepts(dead, full, f, len) == 0, "v6 QinQ from server dropped");
    len = build_tcp6(f, q1, 1, "2001:db8::10", 40000, "2001:db8::21", SRV_PORT);
    CHECK(filter_accepts(dead, full, f, len) == 1, "v6 other host kept");
    len = build_tcp6(f, NULL, 0, "2001:db8::20", 40000, "2001:db8::10", SRV_PORT);
    CHECK(filter_accepts(dead, full, f, len) == 1, "v6 swapped ports kept");
    CHECK(wired_build_filter("tcp or (vlan and tcp)", se, full, sizeof(full)) > 0, "v6 + vlan user");
    len = build_tcp6(f, NULL, 0, "2001:db8::10", 40000, "2001:db8::20", SRV_PORT);
    CHECK(filter_accepts(dead, full, f, len) == 0, "v6 untagged dropped behind a vlan user filter");

    /* IPv4-mapped IPv6 goes on the wire as IPv4 */
    sa6(&srv, "::ffff:" SRV4, SRV_PORT);
    CHECK(wired_build_selfexcl((struct sockaddr *) &srv, se, sizeof(se)) > 0 &&
            wired_build_filter(NULL, se, full, sizeof(full)) > 0, "mapped v6");
    len = build_tcp4(f, NULL, 0, LOCAL4, 40000, SRV4, SRV_PORT);
    CHECK(filter_accepts(dead, full, f, len) == 0, "mapped v6 matches IPv4 frames");

    sa4(&srv, SRV4, 0);
    CHECK(wired_build_selfexcl((struct sockaddr *) &srv, se, sizeof(se)) < 0, "port 0 refused");
    CHECK(wired_build_selfexcl(NULL, se, sizeof(se)) < 0, "NULL server");
    memset(&srv, 0, sizeof(srv));
    srv.ss_family = AF_UNIX;
    CHECK(wired_build_selfexcl((struct sockaddr *) &srv, se, sizeof(se)) < 0, "AF_UNIX refused");

    /* The longest exclusion and the longest user filter still fit and compile */
    sa6(&srv, "ffff:ffff:ffff:ffff:ffff:ffff:ffff:fffe", 65535);
    r = wired_build_selfexcl((struct sockaddr *) &srv, se, sizeof(se));
    CHECK(r > 0 && r < WIRED_SELFEXCL_MAX, "longest selfexcl fits (%d of %d)", r, WIRED_SELFEXCL_MAX);
    memset(user, 0, sizeof(user));
    for (len = 0; len + 8 <= WIRED_FILTER_MAX; len += 8)
        memcpy(user + len, "tcp or  ", 8);
    memcpy(user + len - 8, "tcp     ", 8);
    CHECK(strlen(user) <= WIRED_FILTER_MAX, "user filter length");
    CHECK(wired_build_filter(user, se, full, sizeof(full)) > 0, "longest filter fits");
    CHECK(pcap_compile(dead, &prog, full, 1, PCAP_NETMASK_UNKNOWN) == 0,
            "longest filter compiles: %s", pcap_geterr(dead));
    pcap_freecode(&prog);

    pcap_close(dead);
}

/* The re-check reads up to WIRED_SELFEXCL_DEPTH bytes; a frame cut shorter can't
 * be ruled out and is dropped, a whole short frame is judged as it is */
static void test_selfexcl_undecided(void) {
    pcap_t *dead = pcap_open_dead(DLT_EN10MB, 65535);
    const uint16_t q3[3] = { 0x9100, 0x88a8, 0x8100 };
    struct sockaddr_storage srv;
    struct bpf_program self;
    struct pcap_pkthdr h;
    char se[WIRED_SELFEXCL_MAX];
    uint8_t f[FRAME_MAX];
    size_t len, cut;
    int missed = 0;

    CHECK(WIRED_SELFEXCL_DEPTH == 90, "exclusion depth %u", WIRED_SELFEXCL_DEPTH);
    CHECK(wired_selfexcl_undecided(64, 1500) == 1, "cut at 64");
    CHECK(wired_selfexcl_undecided(WIRED_SELFEXCL_DEPTH - 1, 1500) == 1, "cut one short");
    CHECK(wired_selfexcl_undecided(WIRED_SELFEXCL_DEPTH, 1500) == 0, "cut at the depth");
    CHECK(wired_selfexcl_undecided(60, 60) == 0, "whole short frame");
    CHECK(wired_selfexcl_undecided(0, 0) == 0, "empty");
    CHECK(wired_selfexcl_undecided(0, 1) == 1, "cut to nothing");
    CHECK(wired_selfexcl_undecided(1600, 1600) == 0, "whole frame");

    CHECK(dead != NULL, "pcap_open_dead");
    if (dead == NULL)
        return;

    /* The deepest server frame: 3 tags and IPv4 options, ports at the end of the
     * depth.  Every cut either still matches or is undecided */
    sa4(&srv, SRV4, SRV_PORT);
    if (wired_build_selfexcl((struct sockaddr *) &srv, se, sizeof(se)) <= 0 ||
            pcap_compile(dead, &self, se, 1, PCAP_NETMASK_UNKNOWN) < 0) {
        CHECK(0, "selfexcl compiles");
        pcap_close(dead);
        return;
    }

    len = build_ip4(f, q3, 3, 15, 6, 0, LOCAL4, 40000, SRV4, SRV_PORT);
    memset(&h, 0, sizeof(h));
    h.caplen = h.len = (bpf_u_int32) len;
    CHECK(pcap_offline_filter(&self, &h, f) != 0, "deepest server frame matches whole");
    h.caplen = WIRED_SELFEXCL_DEPTH - 1;
    CHECK(pcap_offline_filter(&self, &h, f) == 0, "the re-check alone misses it cut one short");

    for (cut = 0; cut <= len; cut++) {
        memset(&h, 0, sizeof(h));
        h.caplen = (bpf_u_int32) cut;
        h.len = (bpf_u_int32) len;

        if (!wired_selfexcl_undecided(h.caplen, h.len) && pcap_offline_filter(&self, &h, f) == 0)
            missed++;
    }
    CHECK(missed == 0, "deepest server frame kept at %d cut lengths", missed);

    pcap_freecode(&self);
    pcap_close(dead);
}

static void test_sampler(void) {
    wired_sampler_t s;
    int taken = 0, i;

    wired_sampler_init(&s, 1);
    for (i = 0; i < 10; i++)
        taken += wired_sampler_take(&s);
    CHECK(taken == 10, "sample 1 takes all: %d", taken);

    wired_sampler_init(&s, 0);
    taken = 0;
    for (i = 0; i < 10; i++)
        taken += wired_sampler_take(&s);
    CHECK(taken == 10, "sample 0 takes all: %d", taken);

    wired_sampler_init(&s, 3);
    CHECK(wired_sampler_take(&s) == 1, "first of 3");
    CHECK(wired_sampler_take(&s) == 0, "second of 3");
    CHECK(wired_sampler_take(&s) == 0, "third of 3");
    CHECK(wired_sampler_take(&s) == 1, "fourth");

    wired_sampler_init(&s, WIRED_SAMPLE_MAX);
    taken = 0;
    for (i = 0; i < 3 * (int) WIRED_SAMPLE_MAX; i++)
        taken += wired_sampler_take(&s);
    CHECK(taken == 3, "sample max: %d", taken);
}

static void test_offloads(void) {
    char names[80 * 32];
    uint32_t active[3] = { 0, 0, 0 };
    char desc[256];

    memset(names, 0, sizeof(names));
    strcpy(names + 3 * 32, "rx-gro");
    strcpy(names + 4 * 32, "rx-gro-hw");
    strcpy(names + 40 * 32, "rx-lro");
    strcpy(names + 41 * 32, "rx-vlan-filter");
    strcpy(names + 70 * 32, "tx-generic-segmentation");
    strcpy(names + 5 * 32, "rx-gro-list");
    /* 32 bytes with no NUL must neither match nor be read past */
    memcpy(names + 6 * 32, "rx-groAAAAAAAAAAAAAAAAAAAAAAAAAA", 32);

    active[0] = (1U << 3) | (1U << 5) | (1U << 6);
    active[1] = (1U << (41 - 32));
    active[2] = (1U << (70 - 64));

    CHECK(wired_offloads_from_features(names, 32, 80, active, 3) ==
            (WIRED_OFFLOAD_GRO | WIRED_OFFLOAD_RX_VLAN_FILT | WIRED_OFFLOAD_GSO),
            "offload bits %x", wired_offloads_from_features(names, 32, 80, active, 3));

    /* Fewer blocks than names: later names aren't read */
    CHECK(wired_offloads_from_features(names, 32, 80, active, 1) == WIRED_OFFLOAD_GRO,
            "short blocks");
    CHECK(wired_offloads_from_features(names, 32, 0, active, 3) == 0, "no names");
    CHECK(wired_offloads_from_features(NULL, 32, 80, active, 3) == 0, "NULL names");

    CHECK(wired_offloads_describe(0, desc, sizeof(desc)) == 0 && desc[0] == 0, "none");
    CHECK(wired_offloads_describe(WIRED_OFFLOAD_GRO | WIRED_OFFLOAD_TSO, desc, sizeof(desc)) > 0 &&
            strcmp(desc, "rx-gro,tx-tcp-segmentation") == 0, "describe '%s'", desc);
    CHECK(wired_offloads_describe(WIRED_OFFLOAD_GRO | WIRED_OFFLOAD_TSO, desc, 10) < 0,
            "describe doesn't fit");
    CHECK(wired_offloads_describe(0xffffffff, desc, sizeof(desc)) > 0, "all bits");
}

static void test_status(FILE *jout) {
    wired_status_t st;
    char json[WIRED_STATUS_JSON_MAX];
    int r;

    memset(&st, 0, sizeof(st));
    st.kernel_received = 10;
    st.kernel_drops = 2;
    st.if_drops = 1;
    st.frames = 8;
    st.forwarded = 4;
    st.sample = 2;
    st.snaplen = 1600;
    st.buffer_mb = 64;
    st.promisc = 1;
    st.remote_excluded = 0;
    st.offloads = WIRED_OFFLOAD_GRO | WIRED_OFFLOAD_RX_VLAN_FILT;
    st.carrier = 1;

    r = wired_status_json(&st, json, sizeof(json));
    CHECK(r > 0 && strcmp(json, "{\"kernel_received\":10,\"kernel_drops\":2,\"if_drops\":1,"
                "\"frames\":8,\"forwarded\":4,\"sample\":2,\"snaplen\":1600,\"buffer_mb\":64,"
                "\"promisc\":true,\"remote_excluded\":false,"
                "\"offloads\":[\"rx-gro\",\"rx-vlan-filter\"],\"carrier\":true}") == 0,
            "status '%s'", json);
    if (jout != NULL)
        fprintf(jout, "%s\n", json);

    st.carrier = -1;
    st.offloads = 0;
    r = wired_status_json(&st, json, sizeof(json));
    CHECK(r > 0 && strstr(json, "carrier") == NULL && strstr(json, "\"offloads\":[]}") != NULL,
            "unknown carrier left out '%s'", json);
    if (jout != NULL)
        fprintf(jout, "%s\n", json);

    st.kernel_received = st.kernel_drops = st.if_drops = st.frames = st.forwarded = UINT64_MAX;
    st.sample = st.snaplen = st.buffer_mb = 0xffffffffU;
    st.offloads = 0xffffffffU;
    st.carrier = 0;
    st.remote_excluded = 1;
    r = wired_status_json(&st, json, sizeof(json));
    CHECK(r > 0 && (size_t) r < sizeof(json), "largest status fits (%d)", r);
    if (jout != NULL)
        fprintf(jout, "%s\n", json);

    CHECK(wired_status_json(&st, json, 100) < 0, "status doesn't fit");
}

static int mkfile(const char *dir, const char *name, const char *content) {
    char path[1024];
    FILE *f;

    snprintf(path, sizeof(path), "%s/%s", dir, name);
    if ((f = fopen(path, "w")) == NULL)
        return -1;
    fputs(content, f);
    fclose(f);
    return 0;
}

static void mkiface(const char *root, const char *ifname, const char *type, const char *flags,
        const char *addr) {
    char dir[1024];

    snprintf(dir, sizeof(dir), "%s/%s", root, ifname);
    mkdir(dir, 0700);
    if (type != NULL)
        mkfile(dir, "type", type);
    if (flags != NULL)
        mkfile(dir, "flags", flags);
    if (addr != NULL)
        mkfile(dir, "address", addr);
}

static void test_sysfs(const char *root) {
    char path[1024];
    char names[WIRED_LIST_MAX][WIRED_IFNAMSIZ];
    char drv[WIRED_DRIVER_MAX];
    uint8_t mac[6];
    size_t n;

    mkiface(root, "eth0", "1\n", "0x1003\n", "02:00:00:00:53:01\n");
    mkiface(root, "eth1", "1\n", "0x1002\n", "02:00:00:00:53:0A\n");
    mkiface(root, "lo", "772\n", "0x9\n", "00:00:00:00:00:00\n");
    mkiface(root, "loflag", "1\n", "0x9\n", NULL);
    mkiface(root, "tun0", "65534\n", "0x1091\n", NULL);
    mkiface(root, "wlan0", "1\n", "0x1003\n", NULL);
    mkiface(root, "wlan1", "1\n", "0x1003\n", NULL);
    mkiface(root, "wlan2", "1\n", "0x1003\n", NULL);
    mkiface(root, "badtype", "one\n", "0x1003\n", NULL);
    mkiface(root, "notype", NULL, NULL, NULL);
    mkiface(root, "badmac", "1\n", "0x1003\n", "zz:00:00:00:53:01\n");
    mkiface(root, "shortmac", "1\n", "0x1003\n", "02:00:00:00:53\n");

    snprintf(path, sizeof(path), "%s/wlan0/wireless", root);
    mkdir(path, 0700);
    snprintf(path, sizeof(path), "%s/wlan1/phy80211", root);
    if (symlink("../../ieee80211/phy0", path) < 0)
        printf("symlink: %s\n", strerror(errno));
    snprintf(path, sizeof(path), "%s/wlan2", root);
    mkfile(path, "uevent", "INTERFACE=wlan2\nIFINDEX=7\nDEVTYPE=wlan\n");
    snprintf(path, sizeof(path), "%s/eth0", root);
    mkfile(path, "uevent", "INTERFACE=eth0\nIFINDEX=2\n");
    mkfile(path, "carrier", "1\n");
    snprintf(path, sizeof(path), "%s/eth1", root);
    mkfile(path, "carrier", "0\n");
    mkfile(root, "bonding_masters", "\n");

    snprintf(path, sizeof(path), "%s/eth0/device", root);
    mkdir(path, 0700);
    snprintf(path, sizeof(path), "%s/eth0/device/driver", root);
    if (symlink("../../../bus/pci/drivers/e1000e", path) < 0)
        printf("symlink: %s\n", strerror(errno));
    snprintf(path, sizeof(path), "%s/eth1/device", root);
    mkdir(path, 0700);
    snprintf(path, sizeof(path), "%s/eth1/device/driver", root);
    if (symlink("../../../bus/pci/drivers/bad driver", path) < 0)
        printf("symlink: %s\n", strerror(errno));

    CHECK(wired_classify(root, "eth0") == WIRED_IF_OK, "eth0");
    CHECK(wired_classify(root, "eth1") == WIRED_IF_OK, "eth1");
    CHECK(wired_classify(root, "lo") == WIRED_IF_LOOPBACK, "lo");
    CHECK(wired_classify(root, "loflag") == WIRED_IF_LOOPBACK, "IFF_LOOPBACK");
    CHECK(wired_classify(root, "tun0") == WIRED_IF_NOT_ETHERNET, "tun0");
    CHECK(wired_classify(root, "wlan0") == WIRED_IF_WIRELESS, "wireless dir");
    CHECK(wired_classify(root, "wlan1") == WIRED_IF_WIRELESS, "phy80211 link");
    CHECK(wired_classify(root, "wlan2") == WIRED_IF_WIRELESS, "DEVTYPE=wlan");
    CHECK(wired_classify(root, "badtype") == WIRED_IF_MISSING, "bad type");
    CHECK(wired_classify(root, "notype") == WIRED_IF_MISSING, "no type");
    CHECK(wired_classify(root, "nosuch") == WIRED_IF_MISSING, "missing");
    CHECK(wired_classify(root, "bonding_masters") == WIRED_IF_MISSING, "a file, not an interface");
    CHECK(wired_classify(root, "../eth0") == WIRED_IF_BADNAME, "traversal");
    CHECK(wired_classify(root, "..") == WIRED_IF_BADNAME, "dotdot");
    CHECK(wired_classify(root, NULL) == WIRED_IF_BADNAME, "NULL");

    /* NICs (with a device) before the rest */
    n = wired_list_interfaces(root, NULL, names, WIRED_LIST_MAX);
    CHECK(n == 4, "list count %zu", n);
    if (n == 4)
        CHECK(strcmp(names[0], "eth0") == 0 && strcmp(names[1], "eth1") == 0 &&
                strcmp(names[2], "badmac") == 0 && strcmp(names[3], "shortmac") == 0,
                "list order %s %s %s %s", names[0], names[1], names[2], names[3]);
    CHECK(wired_list_interfaces(root, NULL, names, 1) == 1 && strcmp(names[0], "eth0") == 0, "list max");
    CHECK(wired_list_interfaces(root, NULL, names, 0) == 0, "list max 0");
    CHECK(wired_list_interfaces("/nonexistent-wired-test", NULL, names, WIRED_LIST_MAX) == 0,
            "list missing root");

    CHECK(wired_read_mac(root, "eth0", mac) == 1 && mac[0] == 0x02 && mac[5] == 0x01, "mac");
    CHECK(wired_read_mac(root, "eth1", mac) == 1 && mac[5] == 0x0a, "uppercase mac");
    CHECK(wired_read_mac(root, "badmac", mac) < 0, "bad mac");
    CHECK(wired_read_mac(root, "shortmac", mac) < 0, "short mac");
    CHECK(wired_read_mac(root, "tun0", mac) < 0, "no mac");

    wired_read_driver(root, "eth0", drv, sizeof(drv));
    CHECK(strcmp(drv, "e1000e") == 0, "driver '%s'", drv);
    wired_read_driver(root, "eth1", drv, sizeof(drv));
    CHECK(drv[0] == 0, "bad driver name '%s'", drv);
    wired_read_driver(root, "lo", drv, sizeof(drv));
    CHECK(drv[0] == 0, "virtual '%s'", drv);
    wired_read_driver(root, "eth0", drv, 4);
    CHECK(drv[0] == 0, "driver doesn't fit '%s'", drv);

    CHECK(wired_read_carrier(root, "eth0") == 1, "carrier up");
    CHECK(wired_read_carrier(root, "eth1") == 0, "carrier down");
    CHECK(wired_read_carrier(root, "lo") == -1, "carrier unknown");

    CHECK(strlen(wired_class_reason(WIRED_IF_WIRELESS)) > 0, "reason");
}

/* Interfaces sharing a MAC, as VLAN interfaces, a bridge and its first port, and
 * a bond and its slaves do, get different source UUIDs */
static void test_uuid(const char *root) {
    static const char *shared[] = {
        "eth0", "eth0.100", "eth0.200", "eth0.100.10", "br0", "bond0", "eth2", "eth3",
        "vlan100", "enp3s0", "enp3s0.4094",
    };
    char uuids[sizeof(shared) / sizeof(shared[0])][WIRED_UUID_LEN + 1];
    static char vlans[4094][WIRED_UUID_LEN + 1];
    uint8_t mac[6];
    char name[WIRED_IFNAMSIZ];
    size_t i, j;
    int dups = 0;

    for (i = 0; i < sizeof(shared) / sizeof(shared[0]); i++) {
        if (strcmp(shared[i], "eth0") != 0)
            mkiface(root, shared[i], "1\n", "0x1003\n", "02:00:00:00:53:01\n");

        CHECK(wired_read_mac(root, shared[i], mac) == 1 && mac[5] == 0x01, "%s shares the MAC",
                shared[i]);
        CHECK(wired_format_uuid(shared[i], mac, uuids[i], sizeof(uuids[i])) == 1 &&
                wired_uuid_valid(uuids[i], strlen(uuids[i])) == 1, "%s uuid '%s'", shared[i],
                uuids[i]);
        CHECK(strstr(uuids[i], "-0000-020000005301") != NULL, "%s uuid keeps the MAC '%s'",
                shared[i], uuids[i]);
    }

    for (i = 0; i < sizeof(shared) / sizeof(shared[0]); i++)
        for (j = i + 1; j < sizeof(shared) / sizeof(shared[0]); j++)
            CHECK(strcmp(uuids[i], uuids[j]) != 0, "%s and %s collide: %s", shared[i],
                    shared[j], uuids[i]);

    /* Every VLAN interface of one parent */
    for (i = 0; i < 4094; i++) {
        snprintf(name, sizeof(name), "eth0.%zu", i + 1);
        if (wired_format_uuid(name, mac, vlans[i], sizeof(vlans[i])) != 1)
            dups++;
    }

    for (i = 0; i < 4094; i++)
        for (j = i + 1; j < 4094; j++)
            if (strcmp(vlans[i], vlans[j]) == 0)
                dups++;

    CHECK(dups == 0, "eth0.1 to eth0.4094: %d collisions", dups);

    /* Stable, and different without a MAC */
    CHECK(wired_format_uuid("eth0", mac, name, sizeof(name)) < 0, "doesn't fit");
    CHECK(wired_format_uuid("eth0", NULL, uuids[0], sizeof(uuids[0])) == 1 &&
            wired_uuid_valid(uuids[0], strlen(uuids[0])) == 1 &&
            strstr(uuids[0], "-0000-0000-0000-0000") != NULL, "no MAC '%s'", uuids[0]);
    CHECK(wired_format_uuid("eth0", NULL, uuids[1], sizeof(uuids[1])) == 1 &&
            strcmp(uuids[0], uuids[1]) == 0, "stable");
    CHECK(wired_format_uuid("eth1", NULL, uuids[1], sizeof(uuids[1])) == 1 &&
            strcmp(uuids[0], uuids[1]) != 0, "no MAC, names differ");
    CHECK(wired_format_uuid(NULL, mac, uuids[1], sizeof(uuids[1])) < 0, "NULL name");
}

static void set4(struct sockaddr_in *s, const char *a, unsigned int port) {
    memset(s, 0, sizeof(*s));
    s->sin_family = AF_INET;
    s->sin_port = htons((uint16_t) port);
    inet_pton(AF_INET, a, &s->sin_addr);
}

static void set6(struct sockaddr_in6 *s, const char *a, unsigned int port) {
    memset(s, 0, sizeof(*s));
    s->sin6_family = AF_INET6;
    s->sin6_port = htons((uint16_t) port);
    inet_pton(AF_INET6, a, &s->sin6_addr);
}

/* The server's address and the connection's local one, as getpeername and
 * getsockname give them */
static void test_addr(void) {
    struct sockaddr_in a4, b4;
    struct sockaddr_in6 a6, b6;
    struct sockaddr_storage un;

    set4(&a4, "127.0.0.1", 2501);
    CHECK(wired_addr_loopback((struct sockaddr *) &a4) == 1, "127.0.0.1 loopback");
    set4(&a4, "127.255.0.9", 2501);
    CHECK(wired_addr_loopback((struct sockaddr *) &a4) == 1, "127/8 loopback");
    set4(&a4, "198.51.100.20", 2501);
    CHECK(wired_addr_loopback((struct sockaddr *) &a4) == 0, "198.51.100.20 not loopback");
    set4(&a4, "128.0.0.1", 2501);
    CHECK(wired_addr_loopback((struct sockaddr *) &a4) == 0, "128.0.0.1 not loopback");
    set6(&a6, "::1", 2501);
    CHECK(wired_addr_loopback((struct sockaddr *) &a6) == 1, "::1 loopback");
    set6(&a6, "::ffff:127.0.0.2", 2501);
    CHECK(wired_addr_loopback((struct sockaddr *) &a6) == 1, "mapped 127/8 loopback");
    set6(&a6, "::ffff:192.0.2.1", 2501);
    CHECK(wired_addr_loopback((struct sockaddr *) &a6) == 0, "mapped 192.0.2.1 not loopback");
    set6(&a6, "2001:db8::1", 2501);
    CHECK(wired_addr_loopback((struct sockaddr *) &a6) == 0, "2001:db8::1 not loopback");
    set6(&a6, "::", 2501);
    CHECK(wired_addr_loopback((struct sockaddr *) &a6) == 0, ":: not loopback");
    set6(&a6, "::2", 2501);
    CHECK(wired_addr_loopback((struct sockaddr *) &a6) == 0, "::2 not loopback");
    memset(&un, 0, sizeof(un));
    un.ss_family = AF_UNIX;
    CHECK(wired_addr_loopback((struct sockaddr *) &un) == 0, "AF_UNIX not loopback");
    CHECK(wired_addr_loopback(NULL) == 0, "NULL not loopback");

    set4(&a4, "192.0.2.10", 40000);
    set4(&b4, "192.0.2.10", 0);
    CHECK(wired_addr_same((struct sockaddr *) &a4, (struct sockaddr *) &b4) == 1, "same v4, ports ignored");
    set4(&b4, "192.0.2.11", 40000);
    CHECK(wired_addr_same((struct sockaddr *) &a4, (struct sockaddr *) &b4) == 0, "different v4");
    set6(&a6, "::ffff:192.0.2.10", 40000);
    CHECK(wired_addr_same((struct sockaddr *) &a6, (struct sockaddr *) &a4) == 1, "mapped matches v4");
    set6(&a6, "2001:db8::10", 40000);
    set6(&b6, "2001:db8::10", 0);
    CHECK(wired_addr_same((struct sockaddr *) &a6, (struct sockaddr *) &b6) == 1, "same v6");
    set6(&b6, "2001:db8::11", 0);
    CHECK(wired_addr_same((struct sockaddr *) &a6, (struct sockaddr *) &b6) == 0, "different v6");
    CHECK(wired_addr_same((struct sockaddr *) &a6, (struct sockaddr *) &a4) == 0, "v6 vs v4");
    CHECK(wired_addr_same((struct sockaddr *) &un, (struct sockaddr *) &un) == 0, "AF_UNIX");
    CHECK(wired_addr_same(NULL, (struct sockaddr *) &a4) == 0, "NULL");

    /* Every host has 127.0.0.1 on its loopback, containers too */
    {
        char ifn[WIRED_IFNAMSIZ];

        set4(&a4, "127.0.0.1", 40000);
        CHECK(wired_addr_ifname((struct sockaddr *) &a4, ifn, sizeof(ifn)) == 1 &&
                strcmp(ifn, "lo") == 0, "127.0.0.1 on lo");
        CHECK(wired_addr_ifname((struct sockaddr *) &a4, ifn, 2) < 0, "name doesn't fit");
        set4(&a4, "192.0.2.254", 40000);
        CHECK(wired_addr_ifname((struct sockaddr *) &a4, ifn, sizeof(ifn)) < 0, "no interface has it");
        CHECK(wired_addr_ifname(NULL, ifn, sizeof(ifn)) < 0, "NULL address");
    }
}

static void mklower(const char *root, const char *upper, const char *lower) {
    char path[1024], target[64];

    snprintf(path, sizeof(path), "%s/%s/lower_%s", root, upper, lower);
    snprintf(target, sizeof(target), "../%s", lower);
    if (symlink(target, path) < 0)
        printf("symlink %s: %s\n", path, strerror(errno));
}

/* The kinds RTM_GETLINK would give the made-up interfaces; any other is a NIC */
static const struct {
    const char *name;
    const char *kind;
    int ret;
} test_kinds[] = {
    { "snic0.12", "vlan", 1 }, { "sbond0", "bond", 1 }, { "sbr0", "bridge", 1 },
    { "smv0", "macvlan", 1 }, { "smvt0", "macvtap", 1 }, { "sipv0", "ipvlan", 1 },
    { "sipvt0", "ipvtap", 1 }, { "steam0", "team", 1 }, { "stun0", "tun", 1 },
    { "sloop0", "bond", 1 }, { "swide0", "bridge", 1 },
    { "sv1", "vlan", 1 }, { "sv2", "vlan", 1 }, { "sv3", "vlan", 1 }, { "sv4", "vlan", 1 },
    { "sbrv0", "bridge", 1 }, { "sbrv1", "bridge", 1 }, { "sbrx0", "bridge", 1 },
    { "sms0", "macsec", 1 }, { "svx0", "vxlan", 1 }, { "sdsa0", "dsa", 1 },
    { "snok0", "", 0 }, { "sfail0", "", -1 }, { "sbrm0", "bridge", 1 },
    { "smix0", "bond", 1 }, { "sms4", "macsec", 1 }, { "sdum0", "dummy", 1 },
    { "svrf0", "vrf", 1 },
};

static int test_kind(const char *ifname, char *kind, size_t kind_len) {
    size_t i;

    kind[0] = 0;

    for (i = 0; i < sizeof(test_kinds) / sizeof(test_kinds[0]); i++) {
        if (strcmp(ifname, test_kinds[i].name) != 0)
            continue;

        if (test_kinds[i].ret > 0)
            snprintf(kind, kind_len, "%s", test_kinds[i].kind);

        return test_kinds[i].ret;
    }

    if (strncmp(ifname, "sd", 2) == 0)
        return snprintf(kind, kind_len, "bond") > 0;

    return 0;
}

static int list_kind_nic_calls = 0;

static int list_kind(const char *ifname, char *kind, size_t kind_len) {
    kind[0] = 0;

    if (strstr(ifname, "nic") != NULL)
        list_kind_nic_calls++;

    if (strncmp(ifname, "aveth", 5) == 0)
        return snprintf(kind, kind_len, "veth") > 0;
    if (strncmp(ifname, "atap", 4) == 0)
        return snprintf(kind, kind_len, "tun") > 0;
    if (strncmp(ifname, "br", 2) == 0)
        return snprintf(kind, kind_len, "bridge") > 0;

    return -1;
}

/* A container host: veths sorting before its NICs, past the cap */
static void test_list(const char *root) {
    static const char *const order[] = {
        "ynic1", "znic0", "br0", "fail0", "atap0", "aveth00", "aveth01", "aveth02", "aveth03",
        "aveth04", "aveth05", "aveth06", "aveth07", "aveth08", "aveth09",
    };
    const size_t n_order = sizeof(order) / sizeof(order[0]);
    char names[WIRED_LIST_MAX][WIRED_IFNAMSIZ];
    char dir[1024], path[1100];
    size_t i, n, max;
    int same;

    snprintf(dir, sizeof(dir), "%s/list", root);
    mkdir(dir, 0700);

    for (i = 0; i < n_order; i++) {
        mkiface(dir, order[i], "1\n", "0x1003\n", NULL);

        if (strstr(order[i], "nic") != NULL) {
            snprintf(path, sizeof(path), "%s/%s/device", dir, order[i]);
            mkdir(path, 0700);
        }
    }

    mkiface(dir, "lo", "772\n", "0x9\n", NULL);

    for (max = 1; max <= n_order + 1; max++) {
        n = wired_list_interfaces(dir, list_kind, names, max);
        same = n == (max < n_order ? max : n_order);

        for (i = 0; same && i < n; i++)
            same = strcmp(names[i], order[i]) == 0;

        CHECK(same, "list of %zu: %zu, first %s, last %s", max, n, n > 0 ? names[0] : "-",
                n > 0 ? names[n - 1] : "-");
    }

    CHECK(list_kind_nic_calls == 0, "kind looked up for a NIC");

    /* Without kinds the veths are just virtual, by name */
    n = wired_list_interfaces(dir, NULL, names, 4);
    CHECK(n == 4 && strcmp(names[0], "ynic1") == 0 && strcmp(names[1], "znic0") == 0 &&
            strcmp(names[2], "atap0") == 0 && strcmp(names[3], "aveth00") == 0, "no kind fn: %s %s",
            names[2], names[3]);
}

static void mkbridge(const char *root, const char *ifname, const char *vlan_filtering) {
    char path[1024];

    snprintf(path, sizeof(path), "%s/%s/bridge", root, ifname);
    mkdir(path, 0700);

    if (vlan_filtering != NULL)
        mkfile(path, "vlan_filtering", vlan_filtering);
}

/* Stacks as the kernel links them, lower_ links, with the kind of each from the
 * table: a bridge on a bond on a VLAN on a NIC, and the kinds the exclusion can't
 * follow */
static void test_stacked(const char *root) {
    static const char *ifs[] = {
        "snic0", "snic1", "snic2", "snic3", "snic4", "snic0.12", "sbond0", "sbr0", "smv0",
        "smvt0", "sipv0", "sipvt0", "steam0", "stun0", "sloop0", "swide0",
        "sv1", "sv2", "sv3", "sv4", "sbrv0", "sbrv1", "sbrx0", "sms0", "svx0", "sdsa0",
        "snok0", "sfail0", "sbrm0", "smix0", "sms4", "sdum0", "svrf0",
    };
    struct sockaddr_in p4;
    char name[WIRED_IFNAMSIZ];
    size_t i;

    for (i = 0; i < sizeof(ifs) / sizeof(ifs[0]); i++)
        mkiface(root, ifs[i], "1\n", "0x1003\n", NULL);

    for (i = 0; i <= 9; i++) {
        snprintf(name, sizeof(name), "sd%zu", i);
        mkiface(root, name, "1\n", "0x1003\n", NULL);
    }

    mklower(root, "snic0.12", "snic0");
    mklower(root, "sbond0", "snic0.12");
    mklower(root, "sbond0", "snic1");
    mklower(root, "sbr0", "sbond0");
    mkbridge(root, "sbr0", "0\n");
    mklower(root, "smv0", "snic1");
    mklower(root, "smvt0", "snic1");
    mklower(root, "sipv0", "snic3");
    mklower(root, "sipvt0", "snic3");
    mklower(root, "steam0", "snic3");
    for (i = 0; i < 9; i++) {
        char upper[WIRED_IFNAMSIZ];

        snprintf(upper, sizeof(upper), "sd%zu", i);
        snprintf(name, sizeof(name), "sd%zu", i + 1);
        mklower(root, upper, name);
    }
    mklower(root, "sloop0", "sloop0");
    mklower(root, "sbr0", ".hidden");
    mkbridge(root, "swide0", "0\n");

    for (i = 0; i < 300; i++) {
        snprintf(name, sizeof(name), "sw%zu", i);
        mklower(root, "swide0", name);
    }

    /* Q-in-Q-in-Q-in-Q, and VLAN-aware bridges over them */
    mklower(root, "sv1", "snic2");
    mklower(root, "sv2", "sv1");
    mklower(root, "sv3", "sv2");
    mklower(root, "sv4", "sv3");
    mklower(root, "sbrv0", "sv2");
    mkbridge(root, "sbrv0", "1\n");
    mklower(root, "sbrv1", "sv3");
    mkbridge(root, "sbrv1", "1\n");
    mklower(root, "sbrx0", "sv3");
    mkbridge(root, "sbrx0", NULL);

    mklower(root, "sms0", "snic3");
    mklower(root, "svx0", "snic3");
    mklower(root, "sdsa0", "snic3");
    mklower(root, "snok0", "snic3");
    mklower(root, "sfail0", "snic3");
    mklower(root, "sbrm0", "sms0");
    mkbridge(root, "sbrm0", "0\n");
    mklower(root, "sms4", "snic4");
    mklower(root, "smix0", "snic4");
    mklower(root, "smix0", "sms4");
    mklower(root, "svrf0", "snic0");

    CHECK(wired_if_stacked_on(root, test_kind, "snic0", "snic0") == WIRED_STACK_MATCHED,
            "same interface");
    CHECK(wired_if_stacked_on(root, test_kind, "snic0.12", "snic0") == WIRED_STACK_MATCHED,
            "VLAN on its NIC");
    CHECK(wired_if_stacked_on(root, test_kind, "snic0", "snic0.12") == WIRED_STACK_NONE,
            "NIC isn't on its VLAN");
    CHECK(wired_if_stacked_on(root, test_kind, "sbr0", "snic0") == WIRED_STACK_MATCHED,
            "bridge, bond, VLAN, NIC");
    CHECK(wired_if_stacked_on(root, test_kind, "sbr0", "snic1") == WIRED_STACK_MATCHED,
            "bridge, bond, NIC");
    CHECK(wired_if_stacked_on(root, test_kind, "sbond0", "snic1") == WIRED_STACK_MATCHED,
            "bond port");
    CHECK(wired_if_stacked_on(root, test_kind, "smv0", "snic1") == WIRED_STACK_MATCHED, "macvlan");
    CHECK(wired_if_stacked_on(root, test_kind, "smvt0", "snic1") == WIRED_STACK_MATCHED, "macvtap");
    CHECK(wired_if_stacked_on(root, test_kind, "sipv0", "snic3") == WIRED_STACK_MATCHED, "ipvlan");
    CHECK(wired_if_stacked_on(root, test_kind, "sipvt0", "snic3") == WIRED_STACK_MATCHED, "ipvtap");
    CHECK(wired_if_stacked_on(root, test_kind, "steam0", "snic3") == WIRED_STACK_MATCHED, "team");
    CHECK(wired_if_stacked_on(root, test_kind, "smv0", "snic0") == WIRED_STACK_NONE,
            "macvlan on the other NIC");
    CHECK(wired_if_stacked_on(root, test_kind, "stun0", "snic0") == WIRED_STACK_NONE, "tunnel");

    CHECK(wired_if_stacked_on(root, test_kind, "sd1", "sd9") == WIRED_STACK_MATCHED,
            "eight deep, the kernel's limit");
    CHECK(wired_if_stacked_on(root, test_kind, "sd0", "sd9") == WIRED_STACK_NONE,
            "nine deep is past the limit");
    CHECK(wired_if_stacked_on(root, test_kind, "sloop0", "snic0") == WIRED_STACK_NONE,
            "self loop ends");
    CHECK(wired_if_stacked_on(root, test_kind, "swide0", "snic0") == WIRED_STACK_UNKNOWN,
            "wide, nothing found but cut short");
    {
        int found = 0;

        /* Past the directory budget, ports are still compared, just not descended */
        for (i = 0; i < 300; i++) {
            snprintf(name, sizeof(name), "sw%zu", i);
            found += wired_if_stacked_on(root, test_kind, "swide0", name) == WIRED_STACK_MATCHED;
        }

        CHECK(found == 300, "wide, every port found (%d)", found);
    }

    CHECK(wired_if_stacked_on(root, test_kind, "sv3", "snic2") == WIRED_STACK_MATCHED,
            "three tags");
    CHECK(wired_if_stacked_on(root, test_kind, "sv4", "snic2") == WIRED_STACK_UNMATCHED,
            "four tags");
    CHECK(wired_if_stacked_on(root, test_kind, "sv4", "sv1") == WIRED_STACK_MATCHED,
            "four deep, captured below the first tag");
    CHECK(wired_if_stacked_on(root, test_kind, "sbrv0", "snic2") == WIRED_STACK_MATCHED,
            "VLAN-aware bridge on two tags");
    CHECK(wired_if_stacked_on(root, test_kind, "sbrv1", "snic2") == WIRED_STACK_UNMATCHED,
            "VLAN-aware bridge on three tags");
    CHECK(wired_if_stacked_on(root, test_kind, "sbrx0", "snic2") == WIRED_STACK_UNMATCHED,
            "bridge without vlan_filtering counts it on");
    CHECK(wired_if_stacked_on(root, test_kind, "sbrx0", "sv1") == WIRED_STACK_MATCHED,
            "bridge without vlan_filtering, room for its tag");

    CHECK(wired_if_stacked_on(root, test_kind, "sms0", "snic3") == WIRED_STACK_UNMATCHED, "MACsec");
    CHECK(wired_if_stacked_on(root, test_kind, "svx0", "snic3") == WIRED_STACK_UNMATCHED, "VXLAN");
    CHECK(wired_if_stacked_on(root, test_kind, "sdsa0", "snic3") == WIRED_STACK_UNMATCHED,
            "unknown kind");
    CHECK(wired_if_stacked_on(root, test_kind, "snok0", "snic3") == WIRED_STACK_UNMATCHED,
            "no kind, but stacked");
    CHECK(wired_if_stacked_on(root, test_kind, "sfail0", "snic3") == WIRED_STACK_UNMATCHED,
            "kind unknown");
    CHECK(wired_if_stacked_on(root, test_kind, "sbrm0", "snic3") == WIRED_STACK_UNMATCHED,
            "bridge on MACsec");
    CHECK(wired_if_stacked_on(root, test_kind, "sbrm0", "sms0") == WIRED_STACK_MATCHED,
            "bridge on MACsec, MACsec captured");
    CHECK(wired_if_stacked_on(root, test_kind, "smix0", "snic4") == WIRED_STACK_UNMATCHED,
            "bond with a plain and a MACsec way down");
    CHECK(wired_if_stacked_on(root, test_kind, "sms0", "snic0") == WIRED_STACK_NONE,
            "MACsec on the other NIC");

    CHECK(wired_if_stacked_on(root, test_kind, "sbr0", "snic9") == WIRED_STACK_NONE,
            "past a bad lower_ name, not found");
    CHECK(wired_if_stacked_on(root, test_kind, "nosuch", "snic0") == WIRED_STACK_NONE,
            "missing upper");
    CHECK(wired_if_stacked_on(root, test_kind, "../sbr0", "snic0") == WIRED_STACK_NONE,
            "bad upper name");
    CHECK(wired_if_stacked_on(root, test_kind, "sbr0", NULL) == WIRED_STACK_NONE, "NULL lower");
    CHECK(wired_if_stacked_on(root, NULL, "sbr0", "snic0") == WIRED_STACK_NONE, "no kind lookup");

    set4(&p4, "127.0.0.1", 2501);
    CHECK(wired_remote_path(root, test_kind, "snic0", (struct sockaddr *) &p4, 0, "lo") ==
            WIRED_PATH_LOOPBACK, "SSH forward");
    CHECK(wired_remote_path(root, test_kind, "snic0", (struct sockaddr *) &p4, 0, "snic0") ==
            WIRED_PATH_LOOPBACK, "loopback peer wins");
    set4(&p4, "198.51.100.20", 2501);
    CHECK(wired_remote_path(root, test_kind, "snic0", (struct sockaddr *) &p4, 1, "snic0") ==
            WIRED_PATH_LOOPBACK, "server on one of this host's addresses");
    CHECK(wired_remote_path(root, test_kind, "snic0", (struct sockaddr *) &p4, 0, "snic0") ==
            WIRED_PATH_CAPTURED, "connection on the capture");
    CHECK(wired_remote_path(root, test_kind, "snic0", (struct sockaddr *) &p4, 0, "sbr0") ==
            WIRED_PATH_CAPTURED, "connection on a bridge over the capture");
    CHECK(wired_remote_path(root, test_kind, "snic0", (struct sockaddr *) &p4, 0, "stun0") ==
            WIRED_PATH_OTHER, "VPN");
    CHECK(wired_remote_path(root, test_kind, "snic0.12", (struct sockaddr *) &p4, 0, "snic0") ==
            WIRED_PATH_OTHER, "untagged uplink, VLAN captured");
    CHECK(wired_remote_path(root, test_kind, "snic3", (struct sockaddr *) &p4, 0, "sms0") ==
            WIRED_PATH_UNMATCHED, "MACsec over the capture");
    CHECK(wired_remote_path(root, test_kind, "snic2", (struct sockaddr *) &p4, 0, "sv4") ==
            WIRED_PATH_UNMATCHED, "four tags over the capture");
    CHECK(wired_remote_path(root, test_kind, "snic0", (struct sockaddr *) &p4, 0, "lo") ==
            WIRED_PATH_UNKNOWN, "service address on lo");
    CHECK(wired_remote_path(root, test_kind, "snic0", (struct sockaddr *) &p4, 0, "sdum0") ==
            WIRED_PATH_UNKNOWN, "service address on a dummy");
    CHECK(wired_remote_path(root, test_kind, "snic0", (struct sockaddr *) &p4, 0, "svrf0") ==
            WIRED_PATH_UNKNOWN, "service address on a VRF over the capture");
    CHECK(wired_remote_path(root, test_kind, "svrf0", (struct sockaddr *) &p4, 0, "svrf0") ==
            WIRED_PATH_CAPTURED, "VRF captured, its own address");
    CHECK(wired_remote_path(root, test_kind, "snic0", (struct sockaddr *) &p4, 0, "swide0") ==
            WIRED_PATH_UNKNOWN, "walk cut short by its budget, nothing found");
    CHECK(wired_remote_path(root, test_kind, "snic0", (struct sockaddr *) &p4, 0, NULL) ==
            WIRED_PATH_UNKNOWN, "local address on no interface");
}

static void test_kind_hop(void) {
    static const char *pass[] = {
        "bond", "team", "bridge", "macvlan", "macvtap", "ipvlan", "ipvtap",
    };
    static const char *opaque[] = {
        "macsec", "vxlan", "geneve", "gretap", "dsa", "hsr", "veth", "dummy", "", "VLAN",
        "vlan ", "bond0", "bridg",
    };
    size_t i;

    CHECK(wired_kind_hop("vlan") == WIRED_HOP_TAG, "vlan tags");

    for (i = 0; i < sizeof(pass) / sizeof(pass[0]); i++)
        CHECK(wired_kind_hop(pass[i]) == WIRED_HOP_PASS, "%s passes", pass[i]);

    for (i = 0; i < sizeof(opaque) / sizeof(opaque[0]); i++)
        CHECK(wired_kind_hop(opaque[i]) == WIRED_HOP_OPAQUE, "'%s' is opaque", opaque[i]);

    CHECK(wired_kind_hop(NULL) == WIRED_HOP_OPAQUE, "NULL is opaque");
}

/* An RTM_NEWLINK as the kernel sends it: header, ifinfomsg, IFLA_IFNAME and, with
 * kind set, IFLA_LINKINFO holding IFLA_INFO_DATA (data_first) and IFLA_INFO_KIND */
static size_t nl_attr(uint8_t *buf, size_t off, unsigned int type, const void *data, size_t len) {
    struct rtattr rta;

    rta.rta_type = (unsigned short) type;
    rta.rta_len = (unsigned short) RTA_LENGTH(len);
    memcpy(buf + off, &rta, sizeof(rta));
    if (len > 0)
        memcpy(buf + off + RTA_LENGTH(0), data, len);
    memset(buf + off + RTA_LENGTH(len), 0, RTA_SPACE(len) - RTA_LENGTH(len));

    return off + RTA_SPACE(len);
}

static size_t nl_link(uint8_t *buf, uint32_t seq, const uint8_t *kind, size_t kind_len,
        int data_first, unsigned int linkinfo_flags) {
    static const uint8_t vlan_id[] = { 12, 0 };
    struct nlmsghdr nh;
    struct ifinfomsg ifi;
    uint8_t info[256];
    size_t off, ioff = 0;

    memset(buf, 0, 1024);
    memset(&ifi, 0, sizeof(ifi));
    ifi.ifi_index = 9;
    memcpy(buf + NLMSG_HDRLEN, &ifi, sizeof(ifi));
    off = NLMSG_HDRLEN + NLMSG_ALIGN(sizeof(ifi));
    off = nl_attr(buf, off, IFLA_IFNAME, "snic0.12", 9);

    if (kind != NULL) {
        if (data_first)
            ioff = nl_attr(info, ioff, IFLA_INFO_DATA | NLA_F_NESTED, vlan_id, sizeof(vlan_id));
        ioff = nl_attr(info, ioff, IFLA_INFO_KIND, kind, kind_len);
        off = nl_attr(buf, off, IFLA_LINKINFO | linkinfo_flags, info, ioff);
    }

    memset(&nh, 0, sizeof(nh));
    nh.nlmsg_len = (uint32_t) off;
    nh.nlmsg_type = RTM_NEWLINK;
    nh.nlmsg_seq = seq;
    memcpy(buf, &nh, sizeof(nh));

    return off;
}

static void nl_set_len(uint8_t *buf, uint32_t len) {
    memcpy(buf + offsetof(struct nlmsghdr, nlmsg_len), &len, sizeof(len));
}

static void nl_set_rta_len(uint8_t *buf, size_t off, unsigned short len) {
    memcpy(buf + off + offsetof(struct rtattr, rta_len), &len, sizeof(len));
}

/* Where nl_link puts IFLA_IFNAME and IFLA_LINKINFO */
#define NL_FIRST_ATTR   (NLMSG_HDRLEN + NLMSG_ALIGN(sizeof(struct ifinfomsg)))
#define NL_LINKINFO     (NL_FIRST_ATTR + RTA_SPACE(9))

static void test_nl_kind(void) {
    uint8_t buf[1024];
    char kind[WIRED_KIND_MAX];
    struct nlmsghdr nh;
    size_t l;

    l = nl_link(buf, 7, (const uint8_t *) "vlan", 5, 0, 0);
    CHECK(wired_nl_link_kind(buf, l, 7, kind, sizeof(kind)) == 1 && strcmp(kind, "vlan") == 0,
            "vlan '%s'", kind);
    CHECK(wired_nl_link_kind(buf, l, 8, kind, sizeof(kind)) < 0 && kind[0] == 0, "another seq");
    CHECK(wired_nl_link_kind(buf, l, 7, kind, 5) == 1, "kind just fits");
    CHECK(wired_nl_link_kind(buf, l, 7, kind, 4) < 0, "kind doesn't fit");
    CHECK(wired_nl_link_kind(buf, l - 1, 7, kind, sizeof(kind)) < 0, "message longer than read");
    CHECK(wired_nl_link_kind(buf, l + 64, 7, kind, sizeof(kind)) == 1, "read longer than message");

    l = nl_link(buf, 7, (const uint8_t *) "macvlan", 8, 1, 0);
    CHECK(wired_nl_link_kind(buf, l, 7, kind, sizeof(kind)) == 1 && strcmp(kind, "macvlan") == 0,
            "kind after data '%s'", kind);
    l = nl_link(buf, 7, (const uint8_t *) "bond", 5, 0, NLA_F_NESTED);
    CHECK(wired_nl_link_kind(buf, l, 7, kind, sizeof(kind)) == 1 && strcmp(kind, "bond") == 0,
            "nested flag '%s'", kind);
    l = nl_link(buf, 7, (const uint8_t *) "team", 4, 0, 0);
    CHECK(wired_nl_link_kind(buf, l, 7, kind, sizeof(kind)) == 1 && strcmp(kind, "team") == 0,
            "kind without its NUL '%s'", kind);
    l = nl_link(buf, 7, (const uint8_t *) "ab\0", 3, 0, 0);
    nl_set_rta_len(buf, NL_LINKINFO, (unsigned short) RTA_LENGTH(RTA_LENGTH(3)));
    nl_set_len(buf, (uint32_t) (l - 1));
    CHECK(wired_nl_link_kind(buf, l - 1, 7, kind, sizeof(kind)) == 1 && strcmp(kind, "ab") == 0,
            "last attributes without their padding '%s'", kind);

    l = nl_link(buf, 7, NULL, 0, 0, 0);
    CHECK(wired_nl_link_kind(buf, l, 7, kind, sizeof(kind)) == 0 && kind[0] == 0, "no kind");
    l = nl_link(buf, 7, (const uint8_t *) "", 1, 0, 0);
    CHECK(wired_nl_link_kind(buf, l, 7, kind, sizeof(kind)) < 0, "empty kind");
    l = nl_link(buf, 7, (const uint8_t *) "vl/n", 5, 0, 0);
    CHECK(wired_nl_link_kind(buf, l, 7, kind, sizeof(kind)) < 0, "kind with a slash");
    l = nl_link(buf, 7, (const uint8_t *) "vl\x1bn", 5, 0, 0);
    CHECK(wired_nl_link_kind(buf, l, 7, kind, sizeof(kind)) < 0, "kind with an escape");
    l = nl_link(buf, 7, (const uint8_t *) "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa", 37, 0, 0);
    CHECK(wired_nl_link_kind(buf, l, 7, kind, sizeof(kind)) < 0, "long kind");

    /* An attribute claiming more than is there, or less than its own header */
    l = nl_link(buf, 7, (const uint8_t *) "vlan", 5, 0, 0);
    nl_set_rta_len(buf, NL_FIRST_ATTR, 0xff);
    CHECK(wired_nl_link_kind(buf, l, 7, kind, sizeof(kind)) < 0, "attribute past the end");
    l = nl_link(buf, 7, (const uint8_t *) "vlan", 5, 0, 0);
    nl_set_rta_len(buf, NL_FIRST_ATTR, 2);
    CHECK(wired_nl_link_kind(buf, l, 7, kind, sizeof(kind)) < 0, "attribute shorter than its header");
    l = nl_link(buf, 7, (const uint8_t *) "vlan", 5, 0, 0);
    nl_set_rta_len(buf, NL_LINKINFO + RTA_LENGTH(0), 0x7f);
    CHECK(wired_nl_link_kind(buf, l, 7, kind, sizeof(kind)) < 0, "nested attribute past its parent");

    l = nl_link(buf, 7, (const uint8_t *) "vlan", 5, 0, 0);
    nl_set_len(buf, (uint32_t) (NLMSG_HDRLEN + 4));
    CHECK(wired_nl_link_kind(buf, l, 7, kind, sizeof(kind)) < 0, "cut inside ifinfomsg");
    nl_set_len(buf, 8);
    CHECK(wired_nl_link_kind(buf, l, 7, kind, sizeof(kind)) < 0, "length under the header");
    CHECK(wired_nl_link_kind(buf, 8, 7, kind, sizeof(kind)) < 0, "read under the header");

    /* ENODEV for a name no interface has */
    memset(buf, 0, sizeof(buf));
    memset(&nh, 0, sizeof(nh));
    nh.nlmsg_len = NLMSG_LENGTH(sizeof(struct nlmsgerr));
    nh.nlmsg_type = NLMSG_ERROR;
    nh.nlmsg_seq = 7;
    memcpy(buf, &nh, sizeof(nh));
    CHECK(wired_nl_link_kind(buf, nh.nlmsg_len, 7, kind, sizeof(kind)) < 0, "error answer");

    CHECK(wired_nl_link_kind(NULL, 64, 7, kind, sizeof(kind)) < 0, "NULL message");
    CHECK(wired_nl_link_kind(buf, 64, 7, NULL, 8) < 0, "NULL kind");
    CHECK(wired_nl_link_kind(buf, 64, 7, kind, 0) < 0, "no room for a kind");

    /* The kernel's own answers: loopback has no kind */
    CHECK(wired_if_kind("lo", kind, sizeof(kind)) == 0 && kind[0] == 0, "lo has no kind '%s'", kind);
    CHECK(wired_if_kind("nosuch-wired0", kind, sizeof(kind)) < 0, "missing interface");
    CHECK(wired_if_kind("../lo", kind, sizeof(kind)) < 0, "bad name");
    CHECK(wired_if_kind(NULL, kind, sizeof(kind)) < 0, "NULL name");
}

static void test_ethtool(void) {
    unsigned int off = 0xdead;

    /* Read-only ethtool requests work unprivileged, on loopback too */
    CHECK(wired_query_offloads("lo", &off) == 1, "lo offloads");
    CHECK(wired_query_offloads("nosuch-wired0", &off) < 0 && off == 0, "missing interface");
    CHECK(wired_query_offloads("../lo", &off) < 0, "bad name");
}

static int rm_entry(const char *path, const struct stat *sb, int flag, struct FTW *ftw) {
    (void) sb;
    (void) flag;
    (void) ftw;

    return remove(path);
}

/* The made-up sysfs tree: files, directories and dangling symlinks, never followed */
static int rm_tree(const char *root) {
    return nftw(root, rm_entry, 16, FTW_DEPTH | FTW_PHYS);
}

int main(int argc, char *argv[]) {
    const char *tmp = getenv("TMPDIR");
    char root[1024];
    FILE *jout = NULL;
    int cleaned;

    snprintf(root, sizeof(root), "%s/wired_test.XXXXXX", tmp != NULL && tmp[0] != 0 ? tmp : "/tmp");

    if (mkdtemp(root) == NULL) {
        printf("mkdtemp: %s\n", strerror(errno));
        return 1;
    }

    if (argc > 1 && (jout = fopen(argv[1], "w")) == NULL) {
        printf("could not open %s: %s\n", argv[1], strerror(errno));
        rm_tree(root);
        return 1;
    }

    test_ifname();
    test_parse_uint();
    test_parse_opts();
    test_balanced();
    test_unknown_options();
    test_unpriv_ids();
    test_id_map();
    test_userns_ids();
    test_status_caps();
    test_read_text(root);
    test_caplen_limit();
    test_selfexcl();
    test_selfexcl_undecided();
    test_sampler();
    test_offloads();
    test_status(jout);
    test_sysfs(root);
    test_list(root);
    test_uuid(root);
    test_addr();
    test_stacked(root);
    test_kind_hop();
    test_nl_kind();
    test_ethtool();

    if (jout != NULL)
        fclose(jout);

    cleaned = rm_tree(root) == 0;
    CHECK(cleaned, "removing %s: %s", root, strerror(errno));

    printf("%s: %d checks, %d failed\n", failures ? "FAIL" : "ok", checks, failures);

    return failures != 0;
}
