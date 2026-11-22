/* Control frames still reach the server while data keeps the outbound queue full.
 *
 *   tools/unit.sh <tree> test/capture_framework/out_reserve_test.c --set framework \
 *       --libs "-llzma -lwebsockets" --flavor asan [-- rb | ws]
 *
 * Without an argument both transports run: "rb", the byte ring IPC and TCP remotes
 * write from, and "ws", the websocket message ring (skipped without libwebsockets).
 *
 * Each fills the queue with PACKET frames as a busy capture thread does, sending until
 * refused and then topping off with frames of any size that still fit, then hands
 * cf_handle_rx_content a v3 PING as the service loop does.  The PONG must be queued,
 * behind the data, nothing lost.  Then messages until refused: a PING still gets its
 * PONG.  Then replies until even they are refused: that PING's PONG is dropped and
 * counted, and once the queue drains the next PING's PONG comes with a warning about
 * the drop.
 */

#include <arpa/inet.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/time.h>

#include "capture_framework.h"

static int failures = 0;

#define CHECK(c) do { if (!(c)) { fprintf(stderr, "FAIL %s:%d: %s\n", __FILE__, __LINE__, #c); failures++; } } while (0)

#define MAX_FRAMES 100000
#define DATA_SZ 1000

struct frame_rec {
    unsigned int type;
    uint32_t seqno;
};

static struct frame_rec frames[MAX_FRAMES];
static size_t n_frames;

static int is_ws = 0;

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

static size_t queue_free(kis_capture_handler_t *caph) {
#ifdef HAVE_LIBWEBSOCKETS
    if (is_ws)
        return caph->lwsring == NULL ? 0 : lws_ring_get_count_free_elements(caph->lwsring);
#endif
    return caph->out_ringbuf == NULL ? 0 : kis_simple_ringbuf_available(caph->out_ringbuf);
}

/* Data until refused, then whole PACKET frames of whatever size still fits, so the
 * queue is as full as data can make it */
static size_t fill_data(kis_capture_handler_t *caph) {
    uint8_t pkt[DATA_SZ];
    struct timeval tv = { 0, 0 };
    size_t n = 0;
    int r;

    memset(pkt, 0x5a, sizeof(pkt));

    while (n < MAX_FRAMES) {
        r = cf_send_data(caph, NULL, 0, NULL, NULL, tv, 1, DATA_SZ, DATA_SZ, pkt);
        CHECK(r >= 0);
        if (r <= 0)
            break;
        n++;
    }

    if (!is_ws) {
        size_t len = queue_free(caph);
        uint8_t *buf = calloc(1, len + 1);

        CHECK(buf != NULL);
        if (buf == NULL)
            return n;

        while (len >= sizeof(kismet_external_frame_v3_t) && n < MAX_FRAMES) {
            frame_header(buf, KIS_EXTERNAL_V3_KDS_PACKET, 0, len - sizeof(kismet_external_frame_v3_t));
            if (cf_send_raw_bytes(caph, buf, len) > 0) {
                n++;
                len = queue_free(caph);
            } else {
                len /= 2;
            }
        }

        free(buf);
    }

    return n;
}

/* Take every queued frame off, in the order it would go out */
static void drain(kis_capture_handler_t *caph) {
    n_frames = 0;

#ifdef HAVE_LIBWEBSOCKETS
    if (is_ws) {
        struct cf_ws_msg *m;

        while ((m = (struct cf_ws_msg *) lws_ring_get_element(caph->lwsring, &caph->lwstail)) != NULL) {
            kismet_external_frame_v3_t *f = (kismet_external_frame_v3_t *) (m->payload + LWS_PRE);

            CHECK(m->len >= sizeof(kismet_external_frame_v3_t));
            CHECK(ntohl(f->length) + sizeof(kismet_external_frame_v3_t) == m->len);
            if (n_frames < MAX_FRAMES) {
                frames[n_frames].type = ntohs(f->pkt_type);
                frames[n_frames].seqno = ntohl(f->seqno);
                n_frames++;
            }
            lws_ring_consume_single_tail(caph->lwsring, &caph->lwstail, 1);
        }
        return;
    }
#endif

    while (kis_simple_ringbuf_used(caph->out_ringbuf) > 0) {
        kismet_external_frame_v3_t hdr;
        uint32_t len;

        if (kis_simple_ringbuf_read(caph->out_ringbuf, &hdr, sizeof(hdr)) != sizeof(hdr)) {
            CHECK(!"short frame header in ring");
            return;
        }

        CHECK(ntohl(hdr.signature) == KIS_EXTERNAL_PROTO_SIG);
        CHECK(ntohs(hdr.v3_sentinel) == KIS_EXTERNAL_V3_SIG);

        len = ntohl(hdr.length);
        if (kis_simple_ringbuf_read(caph->out_ringbuf, NULL, len) != len) {
            CHECK(!"short frame body in ring");
            return;
        }

        if (n_frames < MAX_FRAMES) {
            frames[n_frames].type = ntohs(hdr.pkt_type);
            frames[n_frames].seqno = ntohl(hdr.seqno);
            n_frames++;
        }
    }
}

static int ping(kis_capture_handler_t *caph, uint32_t seqno) {
    uint8_t buf[sizeof(kismet_external_frame_v3_t) + 1];

    frame_header(buf, KIS_EXTERNAL_V3_CMD_PING, seqno, 1);
    buf[sizeof(kismet_external_frame_v3_t)] = 0x80;

    return cf_handle_rx_content(caph, buf, sizeof(buf));
}

static size_t count_type(unsigned int type) {
    size_t i, c = 0;

    for (i = 0; i < n_frames; i++)
        if (frames[i].type == type)
            c++;

    return c;
}

/* Index of the PONG answering seqno, or -1 */
static long find_pong(uint32_t seqno) {
    size_t i;

    for (i = 0; i < n_frames; i++)
        if (frames[i].type == KIS_EXTERNAL_V3_CMD_PONG && frames[i].seqno == seqno)
            return (long) i;

    return -1;
}

static void run(const char *name) {
    kis_capture_handler_t *caph = cf_handler_init("outreserve");
    size_t n_data, n_msg, n_reply, i;
    long p;

    CHECK(caph != NULL);
    if (caph == NULL)
        return;

    if (is_ws)
        caph->use_ws = 1;
    else
        caph->use_ipc = 1;

    /* 1: a PING behind a queue full of data */
    n_data = fill_data(caph);
    CHECK(n_data > 0);
    CHECK(ping(caph, 7001) > 0);
    drain(caph);
    p = find_pong(7001);
    CHECK(p >= 0);
    CHECK(count_type(KIS_EXTERNAL_V3_KDS_PACKET) == n_data);
    /* Order is kept: the PONG goes out behind everything queued before it */
    CHECK(p == (long) n_frames - 1);
    fprintf(stderr, "%s: data %zu, pong at %ld of %zu\n", name, n_data, p, n_frames);

    /* 2: data, then messages until refused, then a PING */
    n_data = fill_data(caph);
    for (n_msg = 0; n_msg < MAX_FRAMES; n_msg++)
        if (cf_send_message(caph, "filler message", MSGFLAG_INFO) <= 0)
            break;
    CHECK(n_msg > 0);
    CHECK(ping(caph, 7002) > 0);
    drain(caph);
    CHECK(find_pong(7002) == (long) n_frames - 1);
    CHECK(count_type(KIS_EXTERNAL_V3_CMD_MESSAGE) == n_msg);
    fprintf(stderr, "%s: data %zu, messages %zu, pong at %ld of %zu\n", name, n_data, n_msg,
            find_pong(7002), n_frames);

    /* 3: replies until nothing fits; that PING's PONG is dropped and counted, and the
     * next one, with room, carries a warning about it */
    fill_data(caph);
    for (i = 0; i < MAX_FRAMES; i++)
        if (cf_send_message(caph, "filler message", MSGFLAG_INFO) <= 0)
            break;
    for (n_reply = 0; n_reply < MAX_FRAMES; n_reply++)
        if (cf_send_pong(caph, 100) <= 0)
            break;
    CHECK(n_reply > 0);
    /* Data is refused when only reserved space remains */
    CHECK(cf_send_data(caph, NULL, 0, NULL, NULL, (struct timeval) { 0, 0 }, 1, 1, 1,
                (uint8_t *) "x") == 0);
    CHECK(ping(caph, 7003) > 0);
    drain(caph);
    CHECK(find_pong(7003) < 0);
#ifdef CAP_FRAMEWORK_WS_CTL_RESERVE
    CHECK(caph->out_ctl_dropped >= 1);
#endif

    CHECK(ping(caph, 7004) > 0);
    drain(caph);
    CHECK(n_frames == 2);
    CHECK(find_pong(7004) == 0);
    CHECK(n_frames == 2 && frames[1].type == KIS_EXTERNAL_V3_CMD_MESSAGE);
#ifdef CAP_FRAMEWORK_WS_CTL_RESERVE
    CHECK(caph->out_ctl_dropped_reported == caph->out_ctl_dropped);
#endif

    /* Reported once */
    CHECK(ping(caph, 7005) > 0);
    drain(caph);
    CHECK(n_frames == 1 && find_pong(7005) == 0);

#ifdef HAVE_LIBWEBSOCKETS
    if (caph->lwsring != NULL) {
        lws_ring_destroy(caph->lwsring);
        caph->lwsring = NULL;
    }
#endif

    cf_handler_free(caph);
    free(caph);
}

int main(int argc, char *argv[]) {
    const char *which = argc > 1 ? argv[1] : "all";

    if (strcmp(which, "all") == 0 || strcmp(which, "rb") == 0) {
        is_ws = 0;
        run("rb");
    }

    if (strcmp(which, "all") == 0 || strcmp(which, "ws") == 0) {
#ifdef HAVE_LIBWEBSOCKETS
        is_ws = 1;
        run("ws");
#else
        fprintf(stderr, "ws: skipped, no libwebsockets\n");
#endif
    }

    if (failures) {
        fprintf(stderr, "FAILED: %d\n", failures);
        return 1;
    }

    fprintf(stderr, "PASS\n");
    return 0;
}
