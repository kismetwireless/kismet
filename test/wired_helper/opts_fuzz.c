/* libFuzzer harness for the wired helper's source definition paths:
 * wired_parse_opts, wired_unknown_options (at several output sizes),
 * wired_filter_balanced, wired_format_uuid, wired_build_selfexcl and the address
 * checks on arbitrary socket addresses, and the filter composed from the user's
 * and the exclusion.
 * The input is a source definition, "eth0:snaplen=128,filter=\"tcp\"" and so on.
 *
 *   SAN="-g -O1 -fsanitize=address,undefined -fno-sanitize-recover=all"
 *   clang $SAN -fsanitize=fuzzer -I. -Icapture_wired test/wired_helper/opts_fuzz.c \
 *       capture_wired/wired_util.c libkismetdatasource.a -lpcap -lcap -lwebsockets -lpthread -lm \
 *       -o <scratch>/opts_fuzz
 *   <scratch>/opts_fuzz <corpus dir>
 *
 * Under MSan, libpcap isn't instrumented, so -DNO_PCAP leaves out the filter
 * compilation checks and libpcap, and the framework is built instrumented
 * instead of taken from libkismetdatasource.a (add -lwebsockets when the tree
 * is configured with it):
 *
 *   clang -g -O1 -fsanitize=memory,fuzzer -fsanitize-memory-track-origins=2 -DNO_PCAP \
 *       -I. -Icapture_wired test/wired_helper/opts_fuzz.c capture_wired/wired_util.c \
 *       capture_framework.c simple_ringbuf_c.c mpack/mpack.c version.c firmware_file.c \
 *       -lcap -llzma -lpthread -lm -o <scratch>/opts_fuzz_msan
 *
 * Checked on every input:
 *   - unknown-option text is NUL-terminated inside out_len, only [A-Za-z0-9_?,-]
 *   - an accepted filter is balanced, not blank, within WIRED_FILTER_MAX
 *   - a user filter which compiles alone compiles composed with an IPv4 and an
 *     IPv6 exclusion; the composed filter drops the server frames whatever the
 *     user wrote, and gives every other frame the user filter's verdict (but for
 *     geneve filters, whose verdict alone libpcap can't give reliably)
 *   - the exclusion builder fails cleanly on small buffers and odd addresses
 *   - the uuid formatter gives a valid 8-4-4-4-12 or -1
 *
 * Synthetic addresses only: 192.0.2/24, 198.51.100/24, 2001:db8::/32.
 */

#define _GNU_SOURCE
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include <arpa/inet.h>
#include <netinet/in.h>

#include <pcap.h>

#include "wired_util.h"

#define SRV_PORT 2502
#define FRAME_MAX 128
#define N_FRAMES 8

typedef struct {
    int server;
    int v6;
    uint8_t f[FRAME_MAX];
    size_t len;
} of_frame_t;

static int ready;
#ifndef NO_PCAP
static pcap_t *dead;
#endif
static char se4[WIRED_SELFEXCL_MAX], se6[WIRED_SELFEXCL_MAX];
static of_frame_t frames[N_FRAMES];

static size_t of_eth(uint8_t *f, size_t ntags, uint16_t et) {
    size_t p = 12, t;

    memset(f, 0, FRAME_MAX);
    memcpy(f, "\x02\x00\x00\x00\x00\x01\x02\x00\x00\x00\x00\x02", 12);

    for (t = 0; t < ntags; t++) {
        f[p++] = t == 0 && ntags > 1 ? 0x88 : 0x81;
        f[p++] = t == 0 && ntags > 1 ? 0xa8 : 0x00;
        f[p++] = 0;
        f[p++] = (uint8_t) (100 + t);
    }

    f[p++] = (uint8_t) (et >> 8);
    f[p++] = (uint8_t) et;

    return p;
}

static size_t of_tcp4(uint8_t *f, size_t ntags, const char *src, unsigned int sport,
        const char *dst, unsigned int dport) {
    size_t p = of_eth(f, ntags, 0x0800);

    f[p] = 0x45;
    f[p + 3] = 40;
    f[p + 8] = 64;
    f[p + 9] = 6;
    inet_pton(AF_INET, src, f + p + 12);
    inet_pton(AF_INET, dst, f + p + 16);
    p += 20;
    f[p] = (uint8_t) (sport >> 8);
    f[p + 1] = (uint8_t) sport;
    f[p + 2] = (uint8_t) (dport >> 8);
    f[p + 3] = (uint8_t) dport;
    f[p + 12] = 0x50;

    return p + 20;
}

static size_t of_tcp6(uint8_t *f, size_t ntags, const char *src, unsigned int sport,
        const char *dst, unsigned int dport) {
    size_t p = of_eth(f, ntags, 0x86dd);

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

static void setup(void) {
    struct sockaddr_in s4;
    struct sockaddr_in6 s6;
    size_t n = 0;

#ifndef NO_PCAP
    dead = pcap_open_dead(DLT_EN10MB, 65535);
    if (dead == NULL)
        abort();
#endif

    memset(&s4, 0, sizeof(s4));
    s4.sin_family = AF_INET;
    s4.sin_port = htons(SRV_PORT);
    inet_pton(AF_INET, "198.51.100.20", &s4.sin_addr);
    memset(&s6, 0, sizeof(s6));
    s6.sin6_family = AF_INET6;
    s6.sin6_port = htons(SRV_PORT);
    inet_pton(AF_INET6, "2001:db8::20", &s6.sin6_addr);

    if (wired_build_selfexcl((struct sockaddr *) &s4, se4, sizeof(se4)) <= 0 ||
            wired_build_selfexcl((struct sockaddr *) &s6, se6, sizeof(se6)) <= 0)
        abort();

#define OF(srv, six, expr) do { frames[n].server = srv; frames[n].v6 = six; frames[n].len = expr; n++; } while (0)
    OF(1, 0, of_tcp4(frames[n].f, 0, "192.0.2.10", 40000, "198.51.100.20", SRV_PORT));
    OF(1, 0, of_tcp4(frames[n].f, 2, "198.51.100.20", SRV_PORT, "192.0.2.10", 40000));
    OF(1, 1, of_tcp6(frames[n].f, 0, "2001:db8::10", 40000, "2001:db8::20", SRV_PORT));
    OF(1, 1, of_tcp6(frames[n].f, 1, "2001:db8::20", SRV_PORT, "2001:db8::10", 40000));
    OF(0, 0, of_tcp4(frames[n].f, 0, "192.0.2.10", 40000, "198.51.100.21", SRV_PORT));
    OF(0, 0, of_tcp4(frames[n].f, 1, "192.0.2.10", 22, "198.51.100.21", 80));
    OF(0, 1, of_tcp6(frames[n].f, 0, "2001:db8::10", 40000, "2001:db8::21", 443));
    OF(0, 1, of_tcp6(frames[n].f, 2, "2001:db8::10", 40000, "2001:db8::21", SRV_PORT));
#undef OF
}

static void check_unknown(const char *def) {
    static const size_t sizes[] = { 1, 2, 9, 33, 256 };
    char out[256];
    size_t s;

    for (s = 0; s < sizeof(sizes) / sizeof(sizes[0]); s++) {
        size_t n = sizes[s], l, i;

        memset(out, 0x55, sizeof(out));
        if (wired_unknown_options(def, out, n) < 0)
            abort();

        l = strnlen(out, n);
        if (l >= n)
            abort();

        for (i = 0; i < l; i++) {
            char c = out[i];

            if (!((c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z') || (c >= '0' && c <= '9') ||
                        c == '_' || c == '-' || c == '?' || c == ','))
                abort();
        }

        if (n < sizeof(out) && out[n] != 0x55)
            abort();
    }

    (void) wired_unknown_options(def, NULL, 0);
}

static void check_filter(const char *filter) {
#ifdef NO_PCAP
    (void) filter;
#else
    char expr[WIRED_FULL_FILTER_MAX];
    struct bpf_program u, c;
    struct pcap_pkthdr h;
    int v;
    size_t i;

    if (pcap_compile(dead, &u, filter, 1, PCAP_NETMASK_UNKNOWN) < 0)
        return;

    for (v = 0; v < 2; v++) {
        if (wired_build_filter(filter, v ? se6 : se4, expr, sizeof(expr)) <= 0) {
            fprintf(stderr, "composed doesn't fit for a filter that parsed: '%s'\n", filter);
            abort();
        }

        if (pcap_compile(dead, &c, expr, 1, PCAP_NETMASK_UNKNOWN) < 0) {
            fprintf(stderr, "user filter compiles alone, composed doesn't: '%s': %s\n", filter,
                    pcap_geterr(dead));
            abort();
        }

        for (i = 0; i < N_FRAMES; i++) {
            int pass, upass;

            memset(&h, 0, sizeof(h));
            h.caplen = h.len = (bpf_u_int32) frames[i].len;
            pass = pcap_offline_filter(&c, &h, frames[i].f) != 0;
            upass = pcap_offline_filter(&u, &h, frames[i].f) != 0;

            if (frames[i].server && frames[i].v6 == v && pass) {
                fprintf(stderr, "composed filter passes a server frame: '%s' (frame %zu)\n", filter, i);
                abort();
            }

            /* Geneve filters read scratch memory only the Geneve branch writes,
             * so libpcap's verdict for them alone can't serve as the reference */
            if (!frames[i].server && pass != upass && strcasestr(filter, "geneve") == NULL) {
                fprintf(stderr, "composed filter changes a verdict: '%s' (frame %zu) %d %d\n", filter, i,
                        pass, upass);
                abort();
            }
        }

        pcap_freecode(&c);
    }

    pcap_freecode(&u);
#endif
}

static void check_selfexcl(const uint8_t *data, size_t size, const char *filter) {
    struct sockaddr_storage ss;
    char se[WIRED_SELFEXCL_MAX], full[WIRED_FULL_FILTER_MAX];
    size_t n, small;
    int sr;

    if (size < 2)
        return;

    n = size - 1 < sizeof(ss) ? size - 1 : sizeof(ss);
    memset(&ss, 0, sizeof(ss));
    memcpy(&ss, data + 1, n);
    ss.ss_family = data[0] % 3 == 0 ? AF_INET : data[0] % 3 == 1 ? AF_INET6 : (sa_family_t) data[0];

    sr = wired_build_selfexcl((struct sockaddr *) &ss, se, sizeof(se));
    if (sr > 0) {
        if ((size_t) sr != strlen(se) || (size_t) sr >= sizeof(se))
            abort();
        if (wired_build_filter(filter, se, full, sizeof(full)) <= 0)
            abort();
    }

    (void) wired_addr_loopback((struct sockaddr *) &ss);
    if (wired_addr_same((struct sockaddr *) &ss, (struct sockaddr *) &ss) !=
            (ss.ss_family == AF_INET || ss.ss_family == AF_INET6))
        abort();

    small = (size_t) (data[0] % 64) + 1;
    sr = wired_build_selfexcl((struct sockaddr *) &ss, se, small);
    if (sr > 0 && (size_t) sr >= small)
        abort();
}

static void check_uuid(const char *def) {
    static const uint8_t mac[6] = { 0x02, 0x00, 0x00, 0x00, 0x53, 0x01 };
    char name[WIRED_IFNAMSIZ];
    char uuid[WIRED_UUID_LEN + 1];
    size_t nl = strcspn(def, ":");
    int m;

    if (nl >= sizeof(name))
        nl = sizeof(name) - 1;
    memcpy(name, def, nl);
    name[nl] = 0;

    for (m = 0; m < 2; m++) {
        if (wired_format_uuid(name, m ? mac : NULL, uuid, sizeof(uuid)) != 1 ||
                wired_uuid_valid(uuid, strlen(uuid)) != 1)
            abort();
    }

    if (wired_format_uuid(name, mac, uuid, WIRED_UUID_LEN) != -1)
        abort();
}

int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {
    char def[4200];
    char err[256];
    wired_opts_t o;
    int r;

    if (!ready) {
        setup();
        ready = 1;
    }

    if (size >= sizeof(def))
        size = sizeof(def) - 1;
    memcpy(def, data, size);
    def[size] = 0;

    (void) wired_filter_balanced(def, size);

    check_unknown(def);

    memset(&o, 0x5a, sizeof(o));
    r = wired_parse_opts(def, &o, err, sizeof(err));

    if (r == 1 && o.has_filter) {
        size_t fl = strnlen(o.filter, sizeof(o.filter));
        size_t i;

        if (fl == 0 || fl > WIRED_FILTER_MAX || !wired_filter_balanced(o.filter, fl))
            abort();

        for (i = 0; i < fl && o.filter[i] == ' '; i++)
            ;
        if (i == fl)
            abort();

        check_filter(o.filter);
    }

    if (r == 1 && (o.snaplen < WIRED_SNAPLEN_MIN || o.snaplen > WIRED_SNAPLEN_MAX))
        abort();

    check_selfexcl(data, size, r == 1 && o.has_filter ? o.filter : NULL);
    check_uuid(def);

    (void) wired_caplen_limit((unsigned int) size * 7U, size);

    return 0;
}
