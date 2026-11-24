/* libFuzzer harness: a stream of valid v2/v3 frames, split at fuzzer-chosen points and
 * optionally followed by random bytes, through cf_handle_rb_rx_data.
 *
 *   tools/unit.sh <tree> test/capture_framework/rx_split_fuzz.c --set framework \
 *       --libs "-llzma -lwebsockets" --flavor fuzz [--time 60] [--corpus DIR]
 *
 * Invariants: the ring is never left mid-peek after any return; while the stream is
 * valid no call fails; every complete PING is answered exactly once, in order, as soon
 * as its last byte is buffered and not before; only whole frames are consumed,
 * including one that fills the ring exactly.  Each input gets a new handler.
 *
 * Input: [0] ring offset, [1] flags (bit 0 garbage tail) + frame count, [2] chunk count k,
 * then frame records [kind][plen] x n, then k chunk sizes, then the garbage tail.
 */

#include <arpa/inet.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "capture_framework.h"

#define MAXF 24
#define STREAM_MAX (MAXF * (65536 + 64))

static kis_capture_handler_t *caph;
static uint8_t stream[STREAM_MAX];
static uint8_t junk[CAP_FRAMEWORK_RINGBUF_IN_SZ];

static void position(size_t off) {
    size_t sz;

    kis_simple_ringbuf_free(caph->in_ringbuf);
    caph->in_ringbuf = kis_simple_ringbuf_create(CAP_FRAMEWORK_RINGBUF_IN_SZ);
    if (caph->in_ringbuf == NULL)
        abort();
    sz = kis_simple_ringbuf_size(caph->in_ringbuf);
    off %= sz;
    kis_simple_ringbuf_write(caph->in_ringbuf, junk, sz - off);
    kis_simple_ringbuf_read(caph->in_ringbuf, NULL, sz - off);
}

/* Drain PONGs, checking each against the expected seqno order */
static size_t got;
static void drain_pongs(const uint32_t *exp, size_t nexp, int strict) {
    kismet_external_frame_v3_t f;

    while (kis_simple_ringbuf_used(caph->out_ringbuf) >= sizeof(f)) {
        kis_simple_ringbuf_peek(caph->out_ringbuf, &f, sizeof(f));
        if (ntohs(f.pkt_type) == KIS_EXTERNAL_V3_CMD_PONG) {
            if (got < nexp) {
                if (ntohl(f.seqno) != exp[got]) {
                    fprintf(stderr, "pong %zu seqno %u, want %u\n", got, ntohl(f.seqno), exp[got]);
                    abort();
                }
            } else if (strict) {
                fprintf(stderr, "extra pong %u\n", ntohl(f.seqno));
                abort();
            }
            got++;
        }
        kis_simple_ringbuf_read(caph->out_ringbuf, NULL, sizeof(f) + ntohl(f.length));
    }
}

int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {
    size_t ends[MAXF];          /* stream offset after each frame */
    int isping[MAXF];
    uint32_t exp[MAXF];
    size_t nexp = 0, nf, k, i, slen = 0, pos = 0, ci = 0, gpos, glen;
    int garbage, ret = 0, failed = 0;

    if (size < 3)
        return 0;

    /* A fresh handler per input, so commands in an earlier garbage tail
     * (CLOSEREQ, LISTREQ, ...) leave nothing behind */
    if (caph != NULL) {
        cf_handler_free(caph);
        free(caph);
    }

    caph = cf_handler_init("rxsplit");
    if (caph == NULL)
        abort();
    caph->use_ipc = 1;
    caph->verbose = 0;
    caph->in_ringbuf = kis_simple_ringbuf_create(CAP_FRAMEWORK_RINGBUF_IN_SZ);
    caph->out_ringbuf = kis_simple_ringbuf_create(CAP_FRAMEWORK_RINGBUF_OUT_SZ);
    if (caph->in_ringbuf == NULL || caph->out_ringbuf == NULL)
        abort();

    position((size_t) data[0] * 263);
    got = 0;

    garbage = data[1] & 1;
    nf = ((data[1] >> 1) % MAXF) + 1;
    k = data[2];
    i = 3;

    for (size_t f = 0; f < nf; f++) {
        unsigned int kind = i < size ? data[i] : 0;
        uint32_t plen = i + 1 < size ? data[i + 1] : 0;
        uint32_t seq = 1000 + (uint32_t) f;
        i += 2;

        switch (kind % 5) {
            case 3:
                /* big v2 PING payload, near the ring bound or filling it exactly */
                plen = plen == 255 ? CAP_FRAMEWORK_RINGBUF_IN_SZ - sizeof(kismet_external_frame_v2_t) : plen * 256;
                /* fallthrough */
            case 0: {
                kismet_external_frame_v2_t *h = (kismet_external_frame_v2_t *) (stream + slen);
                memset(h, 0, sizeof(*h));
                h->signature = htonl(KIS_EXTERNAL_PROTO_SIG);
                h->v2_sentinel = htons(KIS_EXTERNAL_V2_SIG);
                h->frame_version = htons(2);
                h->data_sz = htonl(plen);
                memcpy(h->command, (kind & 0x40) ? "ping" : "PING", 4);
                h->seqno = htonl(seq);
                slen += sizeof(*h);
                memset(stream + slen, 0xA5, plen);
                slen += plen;
                isping[f] = 1;
                break;
            }
            case 1:
            case 2:
            case 4: {
                kismet_external_frame_v3_t *h = (kismet_external_frame_v3_t *) (stream + slen);
                memset(h, 0, sizeof(*h));
                h->signature = htonl(KIS_EXTERNAL_PROTO_SIG);
                h->v3_sentinel = htons(KIS_EXTERNAL_V3_SIG);
                h->v3_version = htons(3);
                h->length = htonl(plen);
                h->pkt_type = htons((kind % 5) == 2 ? KIS_EXTERNAL_V3_CMD_PONG : KIS_EXTERNAL_V3_CMD_PING);
                h->seqno = htonl(seq);
                slen += sizeof(*h);
                /* payload bytes may themselves look like a frame header */
                for (uint32_t b = 0; b < plen; b++)
                    stream[slen + b] = data[(i + b) % size];
                slen += plen;
                isping[f] = (kind % 5) != 2;
                break;
            }
        }
        ends[f] = slen;
        if (isping[f])
            exp[nexp++] = seq;
    }

    const uint8_t *chunks = data + (i < size ? i : size);
    size_t nchunks = i < size ? (size - i < k ? size - i : k) : 0;
    gpos = i + nchunks;
    glen = (garbage && gpos < size) ? size - gpos : 0;

    /* Feed the valid stream in chunks */
    size_t done_frames = 0, done_pings = 0, consumed = 0;
    while (pos < slen) {
        size_t c = nchunks ? (size_t) chunks[ci++ % nchunks] + 1 : slen - pos;
        size_t avail = kis_simple_ringbuf_available(caph->in_ringbuf);

        if (c > slen - pos)
            c = slen - pos;
        if (c > avail)
            c = avail;
        if (c == 0) {
            fprintf(stderr, "stall: ring full at %zu/%zu, %zu buffered\n", pos, slen,
                    kis_simple_ringbuf_used(caph->in_ringbuf));
            abort();
        }
        if (kis_simple_ringbuf_write(caph->in_ringbuf, stream + pos, c) != c)
            abort();
        pos += c;

        do {
            ret = cf_handle_rb_rx_data(caph);
            if (caph->in_ringbuf->mid_peek) {
                fprintf(stderr, "left mid-peek, ret %d\n", ret);
                abort();
            }
        } while (ret > 0);

        if (ret < 0) {
            fprintf(stderr, "valid stream failed at %zu/%zu\n", pos, slen);
            abort();
        }

        while (done_frames < nf && ends[done_frames] <= pos) {
            if (isping[done_frames])
                done_pings++;
            consumed = ends[done_frames];
            done_frames++;
        }

        drain_pongs(exp, nexp, 1);
        if (got != done_pings) {
            fprintf(stderr, "at %zu: %zu pongs, %zu complete pings\n", pos, got, done_pings);
            abort();
        }
        if (kis_simple_ringbuf_used(caph->in_ringbuf) != pos - consumed) {
            fprintf(stderr, "at %zu: %zu buffered, want %zu\n", pos,
                    kis_simple_ringbuf_used(caph->in_ringbuf), pos - consumed);
            abort();
        }
    }

    if (kis_simple_ringbuf_used(caph->in_ringbuf) != 0 || got != nexp)
        abort();

    /* Random tail: anything may happen but a crash, a stuck peek or lost earlier answers */
    pos = 0;
    while (pos < glen && !failed) {
        size_t c = glen - pos;
        size_t avail = kis_simple_ringbuf_available(caph->in_ringbuf);
        if (c > 97)
            c = 97;
        if (c > avail)
            c = avail;
        if (c == 0)
            break;
        kis_simple_ringbuf_write(caph->in_ringbuf, (void *) (data + gpos + pos), c);
        pos += c;
        do {
            ret = cf_handle_rb_rx_data(caph);
            if (caph->in_ringbuf->mid_peek) {
                fprintf(stderr, "garbage: left mid-peek, ret %d\n", ret);
                abort();
            }
        } while (ret > 0);
        if (ret < 0)
            failed = 1;
        drain_pongs(exp, nexp, 0);
    }

    return 0;
}
