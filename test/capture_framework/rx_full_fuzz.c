/* libFuzzer harness for server frames handled while the outbound queue is full.
 *
 *   tools/unit.sh <tree> test/capture_framework/rx_full_fuzz.c --set framework \
 *       --libs "-llzma -lwebsockets" --flavor fuzz [--time 60] [--corpus DIR]
 *
 * PING, PONG, TIMESYNCREPORT, LISTREQ, PROBEREQ and unknown frames go to
 * cf_handle_rx_content with the queue at a chosen fill level.  After each input the
 * queue is drained and its frame stream checked, and the drop counters must stay
 * consistent.  Byte 0: transport (bit 0: ws) and fill level (bits 1-2), then records
 * of [cmd selector][seqno][payload len][payload].
 */

#include <arpa/inet.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "capture_framework.h"

static kis_capture_handler_t *rb_h, *ws_h;

static void frame_header(uint8_t *buf, unsigned int type, uint32_t seqno, uint32_t len) {
    kismet_external_frame_v3_t *f = (kismet_external_frame_v3_t *) buf;
    memset(buf, 0, sizeof(kismet_external_frame_v3_t));
    f->signature = htonl(KIS_EXTERNAL_PROTO_SIG);
    f->v3_sentinel = htons(KIS_EXTERNAL_V3_SIG);
    f->v3_version = htons(3);
    f->length = htonl(len);
    f->pkt_type = htons(type);
    f->seqno = htonl(seqno);
}

static void fill(kis_capture_handler_t *caph, int ws, int level) {
    static uint8_t pkt[60000];
    struct timeval tv = { 0, 0 };
    int i;

    if (level == 0)
        return;

    if (ws) {
        while (cf_send_data(caph, NULL, 0, NULL, NULL, tv, 1, 100, 100, pkt) > 0)
            ;
    } else {
        while (cf_send_data(caph, NULL, 0, NULL, NULL, tv, 1, sizeof(pkt), sizeof(pkt), pkt) > 0)
            ;
        while (cf_send_data(caph, NULL, 0, NULL, NULL, tv, 1, 500, 500, pkt) > 0)
            ;
    }

    if (level >= 2) {
        for (i = 0; i < 100000; i++)
            if (cf_send_message(caph, "filler", MSGFLAG_INFO) <= 0)
                break;
    }

    if (level >= 3) {
        for (i = 0; i < 100000; i++)
            if (cf_send_pong(caph, 1) <= 0)
                break;
    }
}

static void drain(kis_capture_handler_t *caph, int ws) {
#ifdef HAVE_LIBWEBSOCKETS
    if (ws) {
        struct cf_ws_msg *m;
        if (caph->lwsring == NULL)
            return;
        while ((m =(struct cf_ws_msg *) lws_ring_get_element(caph->lwsring, &caph->lwstail)) != NULL) {
            kismet_external_frame_v3_t *f = (kismet_external_frame_v3_t *) (m->payload + LWS_PRE);
            if (m->len < sizeof(*f) || ntohl(f->length) + sizeof(*f) != m->len)
                abort();
            lws_ring_consume_single_tail(caph->lwsring, &caph->lwstail, 1);
        }
        return;
    }
#endif
    (void) ws;
    while (caph->out_ringbuf != NULL && kis_simple_ringbuf_used(caph->out_ringbuf) > 0) {
        kismet_external_frame_v3_t hdr;
        uint32_t len;
        if (kis_simple_ringbuf_read(caph->out_ringbuf, &hdr, sizeof(hdr)) != sizeof(hdr))
            abort();
        if (ntohl(hdr.signature) != KIS_EXTERNAL_PROTO_SIG || ntohs(hdr.v3_sentinel) != KIS_EXTERNAL_V3_SIG)
            abort();
        len = ntohl(hdr.length);
        if (kis_simple_ringbuf_read(caph->out_ringbuf, NULL, len) != len)
            abort();
    }
}

static const unsigned int cmds[] = {
    KIS_EXTERNAL_V3_CMD_PING, KIS_EXTERNAL_V3_CMD_PING, KIS_EXTERNAL_V3_CMD_PING,
    KIS_EXTERNAL_V3_CMD_PONG, KIS_EXTERNAL_V3_KDS_TIMESYNCREPORT,
    KIS_EXTERNAL_V3_KDS_LISTREQ, KIS_EXTERNAL_V3_KDS_PROBEREQ, 99, 0
};

int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {
    static uint8_t buf[sizeof(kismet_external_frame_v3_t) + 300];
    kis_capture_handler_t *caph;
    int ws, level;
    size_t off = 1;

    if (rb_h == NULL) {
        rb_h = cf_handler_init("rxfuzz");
        ws_h = cf_handler_init("rxfuzzws");
        if (rb_h == NULL || ws_h == NULL)
            abort();
        rb_h->use_ipc = 1;
        rb_h->verbose = 0;
        ws_h->use_ws = 1;
        ws_h->verbose = 0;
    }

    if (size < 1)
        return 0;

#ifdef HAVE_LIBWEBSOCKETS
    ws = data[0] & 1;
#else
    ws = 0;
#endif
    level = (data[0] >> 1) & 3;
    caph = ws ? ws_h : rb_h;

    fill(caph, ws, level);

    while (off + 3 <= size) {
        unsigned int cmd = cmds[data[off] % (sizeof(cmds) / sizeof(cmds[0]))];
        uint32_t seq = data[off + 1];
        size_t plen = data[off + 2];
        off += 3;
        if (plen > size - off)
            plen = size - off;
        if (plen > 300)
            plen = 300;
        frame_header(buf, cmd, seq, (uint32_t) plen);
        memcpy(buf + sizeof(kismet_external_frame_v3_t), data + off, plen);
        off += plen;
        cf_handle_rx_content(caph, buf, sizeof(kismet_external_frame_v3_t) + plen);
        caph->spindown = 0;
    }

    pthread_mutex_lock(&caph->out_ringbuf_lock);
    if (caph->out_ctl_dropped_reported > caph->out_ctl_dropped)
        abort();
    pthread_mutex_unlock(&caph->out_ringbuf_lock);

    drain(caph, ws);
    return 0;
}
