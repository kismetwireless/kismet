/* Partial legacy v2 frames from the server must not stall the helper's input.
 *
 *   tools/unit.sh <tree> test/capture_framework/rx_v2_partial_test.c --set framework \
 *       --libs "-llzma -lwebsockets" --flavor asan
 *
 * The server's v2 probe PING is 48 bytes; over TCP or websockets it can arrive
 * in pieces.  A piece shorter than the v2 header used to leave the input ring
 * mid-peek, so every later frame was refused and the helper stopped reading;
 * when the piece crossed the end of the ring its copy leaked too.  Each case
 * feeds a partial v2 frame, then the rest, then a v3 PING, and every PING must
 * be answered with its own seqno.  A v2 PING's payload must arrive in full
 * before it is consumed, and an impossible payload size fails the helper
 * instead of draining frames that follow it.  A v2 or v3 frame that exactly
 * fills the ring is still accepted.
 */

#include <arpa/inet.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "capture_framework.h"

static int failures = 0;

#define CHECK(c) do { if (!(c)) { fprintf(stderr, "FAIL %s:%d: %s\n", __FILE__, __LINE__, #c); failures++; } } while (0)

static size_t v2_ping(uint8_t *buf, uint32_t seqno, uint32_t data_sz) {
    kismet_external_frame_v2_t *f = (kismet_external_frame_v2_t *) buf;

    memset(buf, 0, sizeof(kismet_external_frame_v2_t) + data_sz);
    f->signature = htonl(KIS_EXTERNAL_PROTO_SIG);
    f->v2_sentinel = htons(KIS_EXTERNAL_V2_SIG);
    f->frame_version = htons(2);
    f->data_sz = htonl(data_sz);
    strncpy(f->command, "PING", sizeof(f->command) - 1);
    f->seqno = htonl(seqno);

    return sizeof(kismet_external_frame_v2_t) + data_sz;
}

static size_t v3_ping(uint8_t *buf, uint32_t seqno) {
    kismet_external_frame_v3_t *f = (kismet_external_frame_v3_t *) buf;

    memset(buf, 0, sizeof(kismet_external_frame_v3_t));
    f->signature = htonl(KIS_EXTERNAL_PROTO_SIG);
    f->v3_sentinel = htons(KIS_EXTERNAL_V3_SIG);
    f->v3_version = htons(3);
    f->length = 0;
    f->pkt_type = htons(KIS_EXTERNAL_V3_CMD_PING);
    f->seqno = htonl(seqno);

    return sizeof(kismet_external_frame_v3_t);
}

/* Process everything buffered, as the service loop does; returns the last result */
static int service(kis_capture_handler_t *caph) {
    int ret;

    do {
        ret = cf_handle_rb_rx_data(caph);
    } while (ret > 0);

    return ret;
}

/* Drain the out ring; returns the number of PONGs, and the last seqno in *seqno */
static int pongs(kis_capture_handler_t *caph, uint32_t *seqno) {
    kismet_external_frame_v3_t f;
    int n = 0;

    while (kis_simple_ringbuf_used(caph->out_ringbuf) >= sizeof(f)) {
        kis_simple_ringbuf_peek(caph->out_ringbuf, &f, sizeof(f));
        if (ntohs(f.pkt_type) == KIS_EXTERNAL_V3_CMD_PONG) {
            n++;
            *seqno = ntohl(f.seqno);
        }
        kis_simple_ringbuf_read(caph->out_ringbuf, NULL, sizeof(f) + ntohl(f.length));
    }

    return n;
}

/* A new, empty input ring with its read position off bytes before the end, so
 * one stuck case doesn't fail the rest */
static void position(kis_capture_handler_t *caph, size_t off) {
    static uint8_t junk[CAP_FRAMEWORK_RINGBUF_IN_SZ];
    size_t sz;

    kis_simple_ringbuf_free(caph->in_ringbuf);
    caph->in_ringbuf = kis_simple_ringbuf_create(CAP_FRAMEWORK_RINGBUF_IN_SZ);
    if (caph->in_ringbuf == NULL)
        abort();

    sz = kis_simple_ringbuf_size(caph->in_ringbuf);
    kis_simple_ringbuf_write(caph->in_ringbuf, junk, sz - off);
    kis_simple_ringbuf_read(caph->in_ringbuf, NULL, sz - off);
}

/* A v2 PING split at cut, then a v3 PING; both must be answered */
static void split_ping(kis_capture_handler_t *caph, const char *name, size_t ring_off, size_t cut, uint32_t data_sz) {
    uint8_t frame[256];
    size_t len;
    uint32_t seq = 0;
    int ret;

    position(caph, ring_off);

    len = v2_ping(frame, 100 + (uint32_t) cut, data_sz);

    kis_simple_ringbuf_write(caph->in_ringbuf, frame, cut);
    ret = service(caph);
    if (ret != 0 || caph->in_ringbuf->mid_peek || kis_simple_ringbuf_used(caph->in_ringbuf) != cut)
        fprintf(stderr, "FAIL %s: after %zu of %zu bytes: ret %d, mid_peek %d, %zu buffered\n", name, cut, len,
                ret, caph->in_ringbuf->mid_peek, kis_simple_ringbuf_used(caph->in_ringbuf));
    CHECK(ret == 0);
    CHECK(caph->in_ringbuf->mid_peek == 0);
    CHECK(kis_simple_ringbuf_used(caph->in_ringbuf) == cut);
    CHECK(pongs(caph, &seq) == 0);

    kis_simple_ringbuf_write(caph->in_ringbuf, frame + cut, len - cut);
    len = v3_ping(frame, 7);
    kis_simple_ringbuf_write(caph->in_ringbuf, frame, len);

    ret = service(caph);
    CHECK(ret == 0);
    CHECK(kis_simple_ringbuf_used(caph->in_ringbuf) == 0);

    seq = 0;
    ret = pongs(caph, &seq);
    if (ret != 2 || seq != 7)
        fprintf(stderr, "FAIL %s: cut %zu: %d pongs, last seqno %u\n", name, cut, ret, seq);
    CHECK(ret == 2);
    CHECK(seq == 7);
}

/* A PING whose header plus payload is exactly the ring size, at ring_off; then
 * the same header with one more payload byte, which must fail */
static void exact_fit(kis_capture_handler_t *caph, const char *name, int version, size_t ring_off) {
    static uint8_t big[CAP_FRAMEWORK_RINGBUF_IN_SZ];
    size_t ring_sz = CAP_FRAMEWORK_RINGBUF_IN_SZ, hdr_sz;
    uint32_t seq = 0;
    int ret;

    for (int over = 0; over < 2; over++) {
        position(caph, ring_off);
        memset(big, 0, sizeof(big));

        if (version == 2) {
            hdr_sz = sizeof(kismet_external_frame_v2_t);
            v2_ping(big, 300, 0);
            ((kismet_external_frame_v2_t *) big)->data_sz = htonl((uint32_t) (ring_sz - hdr_sz + over));
        } else {
            hdr_sz = sizeof(kismet_external_frame_v3_t);
            v3_ping(big, 300);
            ((kismet_external_frame_v3_t *) big)->length = htonl((uint32_t) (ring_sz - hdr_sz + over));
        }

        CHECK(kis_simple_ringbuf_write(caph->in_ringbuf, big, over ? hdr_sz : ring_sz) == (over ? hdr_sz : ring_sz));

        ret = service(caph);
        seq = 0;

        if (!over) {
            if (ret != 0 || kis_simple_ringbuf_used(caph->in_ringbuf) != 0)
                fprintf(stderr, "FAIL %s: exact fit: ret %d, %zu buffered\n", name, ret,
                        kis_simple_ringbuf_used(caph->in_ringbuf));
            CHECK(ret == 0);
            CHECK(kis_simple_ringbuf_used(caph->in_ringbuf) == 0);
            CHECK(pongs(caph, &seq) == 1);
            CHECK(seq == 300);
        } else {
            CHECK(ret < 0);
            CHECK(pongs(caph, &seq) == 0);
        }

        CHECK(caph->in_ringbuf->mid_peek == 0);
    }
}

int main(void) {
    kis_capture_handler_t *caph = cf_handler_init("rxv2");
    uint8_t frame[256];
    size_t cut, len;
    uint32_t seq = 0;

    if (caph == NULL)
        return 1;

    caph->use_ipc = 1;
    caph->verbose = 0;
    caph->in_ringbuf = kis_simple_ringbuf_create(CAP_FRAMEWORK_RINGBUF_IN_SZ);
    caph->out_ringbuf = kis_simple_ringbuf_create(CAP_FRAMEWORK_RINGBUF_OUT_SZ);
    if (caph->in_ringbuf == NULL || caph->out_ringbuf == NULL)
        return 1;

    /* Every cut of the probe PING header, in the middle of the ring and across its end */
    for (cut = sizeof(kismet_external_frame_t); cut < sizeof(kismet_external_frame_v2_t); cut++) {
        split_ping(caph, "contiguous", 4096, cut, 0);
        split_ping(caph, "wrapped", sizeof(kismet_external_frame_t) + 2, cut, 0);
    }

    /* A v2 PING with a payload, cut inside the payload */
    for (cut = sizeof(kismet_external_frame_v2_t); cut < sizeof(kismet_external_frame_v2_t) + 16; cut++) {
        split_ping(caph, "payload", 4096, cut, 16);
        split_ping(caph, "payload-wrapped", sizeof(kismet_external_frame_v2_t) + 4, cut, 16);
    }

    /* A payload size that can't fit the ring fails, rather than eating the next frame */
    position(caph, 4096);
    len = v2_ping(frame, 1, 0);
    ((kismet_external_frame_v2_t *) frame)->data_sz = htonl(0xFFFFFFF0);
    kis_simple_ringbuf_write(caph->in_ringbuf, frame, len);
    len = v3_ping(frame, 2);
    kis_simple_ringbuf_write(caph->in_ringbuf, frame, len);
    CHECK(service(caph) < 0);
    CHECK(caph->in_ringbuf->mid_peek == 0);
    CHECK(pongs(caph, &seq) == 0);

    /* A frame that exactly fills the ring is accepted, one byte more is not */
    exact_fit(caph, "v2-contiguous", 2, CAP_FRAMEWORK_RINGBUF_IN_SZ);
    exact_fit(caph, "v2-wrapped", 2, 4096);
    exact_fit(caph, "v3-contiguous", 3, CAP_FRAMEWORK_RINGBUF_IN_SZ);
    exact_fit(caph, "v3-wrapped", 3, 4096);

    printf("%s: %d failed\n", failures ? "FAIL" : "ok", failures);

    cf_handler_free(caph);
    free(caph);

    return failures != 0;
}
