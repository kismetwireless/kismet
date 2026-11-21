/* libFuzzer harness for the wired helper's rtnetlink answer parser,
 * wired_nl_link_kind, and the kind table it feeds (wired_kind_hop).
 *
 *   SAN="-g -O1 -fsanitize=address,undefined -fno-sanitize-recover=all"
 *   clang $SAN -fsanitize=fuzzer -I. -Icapture_wired test/wired_helper/linkkind_fuzz.c \
 *       capture_wired/wired_util.c libkismetdatasource.a -lpcap -lcap -lwebsockets -lpthread -lm \
 *       -o <scratch>/linkkind_fuzz
 *   <scratch>/linkkind_fuzz <corpus dir>
 *
 * Input: [0] the kind buffer size (1 to 32) in the low five bits, and bit 7 set
 * to have the harness put a matching nlmsghdr and ifinfomsg in front of the rest,
 * so the attributes are fuzzed directly; otherwise the whole input is the answer,
 * read with sequence number 7.  The answer is copied to a buffer of exactly its
 * length, so a read past it is caught.
 *
 * Checked on every input:
 *   - the result is -1, 0 or 1, and kind is NUL-terminated inside its size
 *   - 1 gives a kind of 1 to size - 1 characters of [A-Za-z0-9._-], found in the
 *     answer; anything else leaves kind empty
 *   - wired_kind_hop gives a defined hop for whatever was found
 *   - wired_nl_link_parse gives -1, or 1 with a valid name, index above 0 and a
 *     NUL-terminated kind
 *   - wired_nl_ack, on the same answer, gives -1 or 1 with an errno of 0 to 4095
 */

/* memmem */
#define _GNU_SOURCE
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include <linux/netlink.h>
#include <linux/rtnetlink.h>

#include "wired_util.h"

#define LK_SEQ          7
#define LK_KIND_MAX     32

static int lk_kind_char(char c) {
    return (c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z') || (c >= '0' && c <= '9') ||
        c == '.' || c == '_' || c == '-';
}

int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {
    char kind[LK_KIND_MAX + 1];
    size_t kind_len, hdr, len, l, i;
    uint8_t *msg;
    wired_hop_t hop;
    int r, ack_err;

    if (size < 1)
        return 0;

    kind_len = (size_t) (data[0] & 0x1f) + 1;
    hdr = (data[0] & 0x80) ? NLMSG_HDRLEN + NLMSG_ALIGN(sizeof(struct ifinfomsg)) : 0;
    len = hdr + size - 1;

    if ((msg = malloc(len > 0 ? len : 1)) == NULL)
        return 0;

    if (hdr > 0) {
        struct nlmsghdr nh;

        memset(msg, 0, hdr);
        memset(&nh, 0, sizeof(nh));
        nh.nlmsg_len = (uint32_t) len;
        nh.nlmsg_type = RTM_NEWLINK;
        nh.nlmsg_seq = LK_SEQ;
        memcpy(msg, &nh, sizeof(nh));
    }

    memcpy(msg + hdr, data + 1, size - 1);

    /* A canary past the size given, which must survive */
    memset(kind, 'Z', sizeof(kind));

    r = wired_nl_link_kind(msg, len, LK_SEQ, kind, kind_len);

    if (r < -1 || r > 1)
        abort();

    if (kind[kind_len] != 'Z')
        abort();

    l = strnlen(kind, kind_len);

    if (l >= kind_len)
        abort();

    if (r == 1) {
        if (l == 0)
            abort();

        for (i = 0; i < l; i++) {
            if (!lk_kind_char(kind[i]))
                abort();
        }

        if (memmem(msg, len, kind, l) == NULL)
            abort();

        hop = wired_kind_hop(kind);

        if (hop != WIRED_HOP_OPAQUE && hop != WIRED_HOP_PASS && hop != WIRED_HOP_TAG)
            abort();
    } else if (l != 0) {
        abort();
    }

    /* The bring-up child's link parser too: a name that's valid, a kind that's
     * NUL-terminated, an index above 0 */
    {
        wired_nl_link_t link;

        r = wired_nl_link_parse(msg, len, LK_SEQ, &link);

        if (r != -1 && r != 1)
            abort();

        if (r == 1) {
            l = strnlen(link.name, sizeof(link.name));

            if (l == 0 || l >= sizeof(link.name) || !wired_ifname_valid(link.name, l) ||
                    link.index < 1 || strnlen(link.kind, sizeof(link.kind)) >= sizeof(link.kind))
                abort();
        }
    }

    /* The bring-up's ack parser reads the same answers */
    ack_err = -1;
    r = wired_nl_ack(msg, len, LK_SEQ, &ack_err);

    if (r != -1 && r != 1)
        abort();

    if (r == 1 && (ack_err < 0 || ack_err > 4095))
        abort();

    free(msg);

    return 0;
}
