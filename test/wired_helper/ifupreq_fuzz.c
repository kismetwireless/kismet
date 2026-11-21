/* libFuzzer harness for the wired bring-up child's request and reply parsers,
 * wired_ifup_req_parse and wired_ifup_reply_parse.
 *
 *   SAN="-g -O1 -fsanitize=address,undefined -fno-sanitize-recover=all"
 *   clang $SAN -fsanitize=fuzzer -I. -Icapture_wired test/wired_helper/ifupreq_fuzz.c \
 *       capture_wired/wired_util.c libkismetdatasource.a -lpcap -lcap -lwebsockets -lpthread -lm \
 *       -o <scratch>/ifupreq_fuzz
 *   <scratch>/ifupreq_fuzz <corpus dir>
 *
 * The input is copied to a buffer of exactly its length, so a read past it is
 * caught.  Checked on every input:
 *   - a request parses only at its exact size, and then gives a valid interface
 *     name which builds back into the same bytes
 *   - a reply parses only at its exact size, with a known status and an errno of
 *     1 to 4095 for a failure, 0 otherwise; it builds back into the same bytes,
 *     is never taken for another owner's request numbered alike, and
 *     wired_ifup_reply_read agrees with it
 */

#include <stdint.h>
#include <stdlib.h>
#include <string.h>

#include "wired_util.h"

int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {
    char name[WIRED_IFNAMSIZ];
    wired_ifup_req_t req;
    wired_ifup_status_t st;
    uint8_t *buf;
    wired_ifup_reply_t rep;
    uint64_t seq, got;
    uint32_t owner, low;
    int err, r;

    if ((buf = malloc(size > 0 ? size : 1)) == NULL)
        return 0;

    memcpy(buf, data, size);

    if (wired_ifup_req_parse(buf, size, &seq, name) == 1) {
        if (size != sizeof(req) || !wired_ifname_valid(name, strlen(name)) ||
                wired_ifup_req_build(name, seq, &req) != 1 || memcmp(&req, buf, sizeof(req)) != 0)
            abort();
    }

    /* The owner and seq as they sit in a reply */
    owner = size >= 8 ? (uint32_t) buf[4] | (uint32_t) buf[5] << 8 |
        (uint32_t) buf[6] << 16 | (uint32_t) buf[7] << 24 : 0;
    low = size >= 12 ? (uint32_t) buf[8] | (uint32_t) buf[9] << 8 |
        (uint32_t) buf[10] << 16 | (uint32_t) buf[11] << 24 : 0;
    seq = wired_ifup_seq(owner, low);

    if ((r = wired_ifup_reply_parse(buf, size, seq, &st, &err)) == 1) {
        if (size != sizeof(wired_ifup_reply_t) || st > WIRED_IFUP_FAILED ||
                (st == WIRED_IFUP_FAILED ? (err < 1 || err > WIRED_ERRNO_MAX) : err != 0))
            abort();

        /* It builds back into the same bytes, and no other owner takes it */
        wired_ifup_reply_build(seq, st, err, &rep);

        if (memcmp(&rep, buf, sizeof(rep)) != 0 ||
                wired_ifup_reply_parse(buf, size, seq ^ ((uint64_t) 1 << 32), &st, &err) != 0 ||
                wired_ifup_reply_read(buf, size, &got, &st, &err) != 1 || got != seq)
            abort();
    } else if (r != 0 && r != -1) {
        abort();
    } else if (r == 0 || wired_ifup_reply_read(buf, size, &got, &st, &err) == 1) {
        /* Valid but unmatched can only be a seq mismatch, never with the true seq */
        abort();
    }

    free(buf);
    return 0;
}
