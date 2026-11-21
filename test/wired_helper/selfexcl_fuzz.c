/* libFuzzer harness for the wired helper's server exclusion (wired_build_selfexcl,
 * wired_build_filter, wired_selfexcl_undecided), differential against a reference
 * matcher written from the description in wired_util.h: TCP to or from the
 * server's address and port, IPv4 first fragments or IPv6 with TCP as the first
 * next header, behind 0 to WIRED_SELFEXCL_TAGS tags of 0x8100, 0x88a8 or 0x9100.
 *
 *   SAN="-g -O1 -fsanitize=address,undefined -fno-sanitize-recover=all"
 *   clang $SAN -fsanitize=fuzzer -I. -Icapture_wired test/wired_helper/selfexcl_fuzz.c \
 *       capture_wired/wired_util.c libkismetdatasource.a -lpcap -lcap -lwebsockets -lpthread -lm \
 *       -o <scratch>/selfexcl_fuzz
 *   <scratch>/selfexcl_fuzz <corpus dir>
 *
 * Input: [0] the server (IPv4, IPv6, IPv4-mapped IPv6), [1] a user filter from
 * the list below, [2..3] the captured length (0 for all of it), then the frame.
 *
 * Checked on every input:
 *   - the re-check (the exclusion alone, on the frame cut to the captured length)
 *     matches exactly when the reference does, or both can't tell because the
 *     frame is cut short of a field; such a frame, when cut, is one the
 *     fail-closed check drops
 *   - the composed kernel filter on the whole frame never passes a server frame,
 *     and gives every other frame the user filter's verdict (but for geneve
 *     filters, whose verdict alone libpcap can't give reliably)
 *
 * Synthetic addresses only: 192.0.2/24, 198.51.100/24, 2001:db8::/32.
 */

#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include <arpa/inet.h>
#include <netinet/in.h>

#include <pcap.h>

#include "wired_util.h"

#define SRV_PORT 2502

/* pppoes, geneve, vlan and mpls move the link offsets of what's compiled after them */
static const char *users[] = {
    NULL, "tcp", "not port 22", "vlan", "tcp or (vlan and tcp)", "vlan and vlan and tcp",
    "pppoes", "tcp or pppoes", "pppoes or tcp", "vlan and pppoes", "geneve", "tcp or geneve",
    "geneve or tcp", "ip6 or geneve", "tcp or mpls", "mpls or tcp", "port 2502",
};

#define N_USERS (sizeof(users) / sizeof(users[0]))

static struct bpf_program self[3];
static struct bpf_program full[3][N_USERS];
static struct bpf_program user[N_USERS];
static uint8_t srv4[4], srv6[16];
static int ready;

static void compile_or_die(pcap_t *dead, struct bpf_program *p, const char *expr) {
    if (pcap_compile(dead, p, expr, 1, PCAP_NETMASK_UNKNOWN) < 0) {
        fprintf(stderr, "compile '%s': %s\n", expr, pcap_geterr(dead));
        abort();
    }
}

static void setup(void) {
    pcap_t *dead = pcap_open_dead(DLT_EN10MB, (int) WIRED_SNAPLEN_MAX);
    struct sockaddr_storage ss[3];
    struct sockaddr_in *s4 = (struct sockaddr_in *) &ss[0];
    struct sockaddr_in6 *s6 = (struct sockaddr_in6 *) &ss[1];
    struct sockaddr_in6 *m6 = (struct sockaddr_in6 *) &ss[2];
    char se[WIRED_SELFEXCL_MAX];
    char expr[WIRED_FULL_FILTER_MAX];
    size_t s, u;

    if (dead == NULL)
        abort();

    memset(ss, 0, sizeof(ss));
    s4->sin_family = AF_INET;
    s4->sin_port = htons(SRV_PORT);
    inet_pton(AF_INET, "198.51.100.20", &s4->sin_addr);
    memcpy(srv4, &s4->sin_addr, 4);
    s6->sin6_family = AF_INET6;
    s6->sin6_port = htons(SRV_PORT);
    inet_pton(AF_INET6, "2001:db8::20", &s6->sin6_addr);
    memcpy(srv6, &s6->sin6_addr, 16);
    m6->sin6_family = AF_INET6;
    m6->sin6_port = htons(SRV_PORT);
    inet_pton(AF_INET6, "::ffff:198.51.100.20", &m6->sin6_addr);

    for (u = 0; u < N_USERS; u++)
        if (users[u] != NULL)
            compile_or_die(dead, &user[u], users[u]);

    for (s = 0; s < 3; s++) {
        if (wired_build_selfexcl((struct sockaddr *) &ss[s], se, sizeof(se)) <= 0)
            abort();

        compile_or_die(dead, &self[s], se);

        for (u = 0; u < N_USERS; u++) {
            if (wired_build_filter(users[u], se, expr, sizeof(expr)) <= 0)
                abort();
            compile_or_die(dead, &full[s][u], expr);
        }
    }

    pcap_close(dead);
    ready = 1;
}

static unsigned int be16(const uint8_t *b) {
    return ((unsigned int) b[0] << 8) | b[1];
}

static int is_tpid(unsigned int v) {
    return v == 0x8100 || v == 0x88a8 || v == 0x9100;
}

/* 1 match, 0 no match, -1 a field it needs is past cl */
static int ref_branch(const uint8_t *f, size_t cl, int v6, unsigned int tags) {
    size_t base = 14 + 4 * tags;
    size_t ports;
    unsigned int t;

#define NEED(n) do { if ((size_t) (n) > cl) return -1; } while (0)
    for (t = 0; t < tags; t++) {
        NEED(12 + 4 * t + 2);
        if (!is_tpid(be16(f + 12 + 4 * t)))
            return 0;
    }

    NEED(base);

    if (!v6) {
        if (be16(f + base - 2) != 0x0800)
            return 0;
        NEED(base + 10);
        if (f[base + 9] != 6 || (be16(f + base + 6) & 0x1fff) != 0)
            return 0;
        NEED(base + 16);
        if (memcmp(f + base + 12, srv4, 4) == 0) {
            ports = base + (size_t) ((f[base] & 0xf) << 2);
            NEED(ports + 2);
            if (be16(f + ports) == SRV_PORT)
                return 1;
        }
        NEED(base + 20);
        if (memcmp(f + base + 16, srv4, 4) == 0) {
            ports = base + 2 + (size_t) ((f[base] & 0xf) << 2);
            NEED(ports + 2);
            if (be16(f + ports) == SRV_PORT)
                return 1;
        }
        return 0;
    }

    if (be16(f + base - 2) != 0x86dd)
        return 0;
    NEED(base + 7);
    if (f[base + 6] != 6)
        return 0;
    NEED(base + 24);
    if (memcmp(f + base + 8, srv6, 16) == 0) {
        NEED(base + 42);
        if (be16(f + base + 40) == SRV_PORT)
            return 1;
    }
    NEED(base + 40);
    if (memcmp(f + base + 24, srv6, 16) == 0) {
        NEED(base + 44);
        if (be16(f + base + 42) == SRV_PORT)
            return 1;
    }
    return 0;
#undef NEED
}

/* 1 match, 0 no match, -1 undecided (a field past cl on a path that could match) */
static int ref_match(const uint8_t *f, size_t cl, int v6) {
    unsigned int t;
    int short_read = 0;

    for (t = 0; t <= WIRED_SELFEXCL_TAGS; t++) {
        int r = ref_branch(f, cl, v6, t);

        if (r == 1)
            return 1;
        if (r < 0)
            short_read = 1;
    }

    return short_read ? -1 : 0;
}

int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {
    struct pcap_pkthdr h;
    uint8_t *frame;
    size_t which, u, cl, len;
    int bpf, ref, ref_full, pass, upass;

    if (!ready)
        setup();

    if (size < 4)
        return 0;

    which = data[0] % 3;
    u = data[1] % N_USERS;
    cl = be16(data + 2);
    len = size - 4;

    if (cl == 0 || cl > len)
        cl = len;

    /* Exactly the captured bytes, so ASan sees any read past them */
    frame = malloc(len > 0 ? len : 1);
    if (frame == NULL)
        return 0;
    memcpy(frame, data + 4, len);

    /* The userspace re-check sees only the captured bytes */
    memset(&h, 0, sizeof(h));
    h.caplen = (bpf_u_int32) cl;
    h.len = (bpf_u_int32) len;
    bpf = pcap_offline_filter(&self[which], &h, frame) != 0;
    ref = ref_match(frame, cl, which == 1);

    if ((ref == 1) != bpf && !(ref < 0 && !bpf)) {
        fprintf(stderr, "re-check mismatch: server %zu caplen %zu len %zu bpf %d ref %d\n",
                which, cl, len, bpf, ref);
        abort();
    }

    /* A cut frame the re-check can't decide is dropped */
    if (ref < 0 && cl < len && !wired_selfexcl_undecided((uint32_t) cl, (uint32_t) len)) {
        fprintf(stderr, "undecided frame kept: caplen %zu len %zu\n", cl, len);
        abort();
    }

    /* The kernel filter sees the whole frame */
    h.caplen = (bpf_u_int32) len;
    ref_full = ref_match(frame, len, which == 1);
    pass = pcap_offline_filter(&full[which][u], &h, frame) != 0;
    upass = users[u] == NULL ? 1 : pcap_offline_filter(&user[u], &h, frame) != 0;

    if (ref_full == 1 && pass) {
        fprintf(stderr, "kernel filter passed a server frame: server %zu user '%s'\n", which,
                users[u] != NULL ? users[u] : "");
        abort();
    }

    /* A runt the exclusion can't read is rejected by BPF whatever the user filter
     * says, as any libpcap filter reading past the frame is.  Geneve filters are
     * left out: what follows 'geneve' takes its offset from scratch memory only
     * the Geneve branch writes, so on other frames libpcap's own verdict for the
     * user filter alone is unreliable (1.10.1 passes a tagged non-TCP frame for
     * 'geneve or tcp'); the composed filter is checked against server frames above */
    if (ref_full == 0 && pass != upass && strstr(users[u] != NULL ? users[u] : "", "geneve") == NULL) {
        fprintf(stderr, "kernel filter changed a verdict: server %zu user '%s' pass %d user %d\n",
                which, users[u] != NULL ? users[u] : "", pass, upass);
        abort();
    }

    free(frame);
    return 0;
}
