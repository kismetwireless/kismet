/* The outbound reserves under concurrent capture, notice, service and writer threads.
 *
 *   tools/unit.sh <tree> test/capture_framework/out_reserve_mt_test.c --set framework \
 *       --libs "-llzma -lwebsockets" --flavor tsan [-- rb | ws [seconds]]
 *
 * Two data threads retry cf_send_data like a busy helper, a notice thread floods
 * messages, a service thread pings, and a slow writer drains the queue in partial
 * chunks (rb) or one message at a time (ws) under out_ringbuf_lock.  The frame stream
 * must stay intact, every ping get its pong in order, and the drop reports add up to
 * the refused notices, not counting a refused report.  Default rb for 3 seconds.
 */

#include <arpa/inet.h>
#include <pthread.h>
#include <stdatomic.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <unistd.h>

#include "capture_framework.h"

static int failures = 0;
#define CHECK(c) do { if (!(c)) { fprintf(stderr, "FAIL %s:%d: %s\n", __FILE__, __LINE__, #c); failures++; } } while (0)

static kis_capture_handler_t *caph;
static int is_ws;
static atomic_int stop_prod;
static atomic_int stop_drain;

static atomic_uint_fast64_t data_ok, data_retry, msg_ok, msg_fail, ping_sent;

#define MAXPING 2000000
static uint32_t *pong_seen;
static size_t n_pong;
static uint64_t reported_sum;
static size_t n_report, n_msgframes, n_data_frames;
static uint32_t last_pong_seq;
static int pong_order_ok = 1;

static uint8_t *stream;
static size_t stream_len, stream_cap;

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

static void on_frame(const uint8_t *f, size_t len) {
    const kismet_external_frame_v3_t *h = (const kismet_external_frame_v3_t *) f;
    unsigned int type = ntohs(h->pkt_type);
    uint32_t seq = ntohl(h->seqno);

    if (type == KIS_EXTERNAL_V3_CMD_PONG) {
        if (n_pong > 0 && seq <= last_pong_seq)
            pong_order_ok = 0;
        last_pong_seq = seq;
        if (n_pong < MAXPING)
            pong_seen[n_pong++] = seq;
    } else if (type == KIS_EXTERNAL_V3_CMD_MESSAGE) {
        const char *needle = "buffer was full; ";
        size_t i, nl = strlen(needle);
        n_msgframes++;
        for (i = 0; i + nl < len; i++) {
            if (memcmp(f + i, needle, nl) == 0) {
                char tmp[32];
                size_t k = 0;
                i += nl;
                while (i < len && k < sizeof(tmp) - 1 && f[i] >= '0' && f[i] <= '9')
                    tmp[k++] = (char) f[i++];
                tmp[k] = 0;
                reported_sum += strtoull(tmp, NULL, 10);
                n_report++;
                break;
            }
        }
    } else if (type == KIS_EXTERNAL_V3_KDS_PACKET) {
        n_data_frames++;
    }
}

static void parse_stream(void) {
    size_t off = 0;
    while (stream_len - off >= sizeof(kismet_external_frame_v3_t)) {
        const kismet_external_frame_v3_t *h = (const kismet_external_frame_v3_t *) (stream + off);
        size_t flen;
        if (ntohl(h->signature) != KIS_EXTERNAL_PROTO_SIG || ntohs(h->v3_sentinel) != KIS_EXTERNAL_V3_SIG) {
            CHECK(!"bad frame signature in stream");
            stream_len = 0;
            return;
        }
        flen = ntohl(h->length) + sizeof(kismet_external_frame_v3_t);
        if (stream_len - off < flen)
            break;
        on_frame(stream + off, flen);
        off += flen;
    }
    memmove(stream, stream + off, stream_len - off);
    stream_len -= off;
}

/* One drain step; returns bytes or messages taken */
static size_t drain_step(size_t maxchunk) {
    size_t got = 0;
    pthread_mutex_lock(&caph->out_ringbuf_lock);
#ifdef HAVE_LIBWEBSOCKETS
    if (is_ws) {
        struct cf_ws_msg *m;
        if (caph->lwsring != NULL &&
                (m = (struct cf_ws_msg *) lws_ring_get_element(caph->lwsring, &caph->lwstail)) != NULL) {
            const kismet_external_frame_v3_t *f = (const kismet_external_frame_v3_t *) (m->payload + LWS_PRE);
            CHECK(ntohl(f->length) + sizeof(kismet_external_frame_v3_t) == m->len);
            on_frame((const uint8_t *) f, m->len);
            lws_ring_consume_single_tail(caph->lwsring, &caph->lwstail, 1);
            got = 1;
        }
        pthread_mutex_unlock(&caph->out_ringbuf_lock);
        return got;
    }
#endif
    if (caph->out_ringbuf != NULL) {
        uint8_t *peek = NULL;
        size_t sz = kis_simple_ringbuf_peek_zc(caph->out_ringbuf, (void **) &peek, 0);
        if (sz > 0) {
            if (sz > maxchunk)
                sz = maxchunk;
            if (stream_len + sz > stream_cap) {
                stream_cap = (stream_len + sz) * 2;
                stream = realloc(stream, stream_cap);
                if (stream == NULL)
                    abort();
            }
            memcpy(stream + stream_len, peek, sz);
            stream_len += sz;
            kis_simple_ringbuf_read(caph->out_ringbuf, NULL, sz);
            got = sz;
        }
        kis_simple_ringbuf_peek_free(caph->out_ringbuf, peek);
    }
    pthread_mutex_unlock(&caph->out_ringbuf_lock);
    if (got)
        parse_stream();
    return got;
}

static void *drain_thread(void *a) {
    unsigned int r = 12345;
    unsigned int n = 0;
    (void) a;
    while (!atomic_load(&stop_drain)) {
        r = r * 1103515245 + 12345;
        drain_step(1 + (r >> 8) % 9000);
        /* A stalled link now and then, so the notices overrun their share of the
         * byte ring; the few-slot ws ring overruns without, and a stall this long
         * would run it out of reply slots too */
        if (!is_ws && ++n % 500 == 0)
            usleep(100000);
        else
            usleep(100);
    }
    return NULL;
}

static void *data_thread(void *a) {
    uint8_t pkt[1400];
    struct timeval tv = { 0, 0 };
    (void) a;
    memset(pkt, 0x5a, sizeof(pkt));
    while (!atomic_load(&stop_prod)) {
        int r = cf_send_data(caph, NULL, 0, NULL, NULL, tv, 1, sizeof(pkt), sizeof(pkt), pkt);
        CHECK(r >= 0);
        if (r > 0)
            atomic_fetch_add(&data_ok, 1);
        else {
            atomic_fetch_add(&data_retry, 1);
            sched_yield();
        }
    }
    return NULL;
}

static void *notice_thread(void *a) {
    (void) a;
    while (!atomic_load(&stop_prod)) {
        int i;
        for (i = 0; i < 5000; i++) {
            if (cf_send_message(caph, "notice flood message", MSGFLAG_INFO) > 0)
                atomic_fetch_add(&msg_ok, 1);
            else
                atomic_fetch_add(&msg_fail, 1);
        }
        usleep(20000);
    }
    return NULL;
}

static void *service_thread(void *a) {
    uint8_t buf[sizeof(kismet_external_frame_v3_t) + 1];
    uint32_t seq = 1;
    (void) a;
    while (!atomic_load(&stop_prod)) {
        frame_header(buf, KIS_EXTERNAL_V3_CMD_PING, seq, 1);
        buf[sizeof(kismet_external_frame_v3_t)] = 0x80;
        CHECK(cf_handle_rx_content(caph, buf, sizeof(buf)) > 0);
        atomic_fetch_add(&ping_sent, 1);
        seq++;
        usleep(500);
    }
    return NULL;
}

int main(int argc, char *argv[]) {
    pthread_t d1, d2, nt, st, dr;
    int secs = argc > 2 ? atoi(argv[2]) : 3;
    uint64_t sent, dropped, rep;
    uint8_t pbuf[sizeof(kismet_external_frame_v3_t) + 1];

    is_ws = argc > 1 && strcmp(argv[1], "ws") == 0;
#ifndef HAVE_LIBWEBSOCKETS
    if (is_ws) {
        fprintf(stderr, "ws: skipped\n");
        return 0;
    }
#endif

    pong_seen = calloc(MAXPING, sizeof(uint32_t));
    caph = cf_handler_init("outreservemt");
    CHECK(caph != NULL);
    if (is_ws)
        caph->use_ws = 1;
    else
        caph->use_ipc = 1;

    /* First a single send so the ring exists before threads race on it */
    {
        struct timeval tv = { 0, 0 };
        cf_send_data(caph, NULL, 0, NULL, NULL, tv, 1, 1, 1, (uint8_t *) "x");
    }

    pthread_create(&dr, NULL, drain_thread, NULL);
    pthread_create(&d1, NULL, data_thread, NULL);
    pthread_create(&d2, NULL, data_thread, NULL);
    pthread_create(&nt, NULL, notice_thread, NULL);
    pthread_create(&st, NULL, service_thread, NULL);

    sleep(secs);
    atomic_store(&stop_prod, 1);
    pthread_join(d1, NULL);
    pthread_join(d2, NULL);
    pthread_join(nt, NULL);
    pthread_join(st, NULL);

    /* Writer thread off, then drain all and a ping with room for the final report */
    atomic_store(&stop_drain, 1);
    pthread_join(dr, NULL);
    while (drain_step(1 << 20) > 0)
        ;
    frame_header(pbuf, KIS_EXTERNAL_V3_CMD_PING, 0x7fffffff, 1);
    pbuf[sizeof(kismet_external_frame_v3_t)] = 0x80;
    CHECK(cf_handle_rx_content(caph, pbuf, sizeof(pbuf)) > 0);
    while (drain_step(1 << 20) > 0)
        ;

    sent = atomic_load(&ping_sent);
    pthread_mutex_lock(&caph->out_ringbuf_lock);
    dropped = caph->out_ctl_dropped;
    rep = caph->out_ctl_dropped_reported;
    pthread_mutex_unlock(&caph->out_ringbuf_lock);

    fprintf(stderr, "%s: data ok %llu retry %llu, msg ok %llu fail %llu, pings %llu pongs %zu, "
            "dropped %llu reported %llu, report msgs %zu sum %llu, data frames %zu, stream left %zu\n",
            is_ws ? "ws" : "rb",
            (unsigned long long) atomic_load(&data_ok), (unsigned long long) atomic_load(&data_retry),
            (unsigned long long) atomic_load(&msg_ok), (unsigned long long) atomic_load(&msg_fail),
            (unsigned long long) sent, n_pong, (unsigned long long) dropped,
            (unsigned long long) rep, n_report, (unsigned long long) reported_sum,
            n_data_frames, stream_len);

    CHECK(stream_len == 0);
    CHECK(pong_order_ok);
    /* Pings are bounded and data can't take their share: every one answered */
    CHECK(n_pong == sent + 1);
    CHECK(n_data_frames == atomic_load(&data_ok) + 1);
    CHECK(atomic_load(&data_retry) > 0);
    /* The queue really was under pressure from notices */
    CHECK(atomic_load(&msg_fail) > 0);
    /* Every refused notice counted, a refused report not; reports add up and come once */
    CHECK(dropped == atomic_load(&msg_fail));
    CHECK(rep == reported_sum);
    CHECK(rep == dropped);

#ifdef HAVE_LIBWEBSOCKETS
    if (caph->lwsring != NULL) {
        lws_ring_destroy(caph->lwsring);
        caph->lwsring = NULL;
    }
#endif
    cf_handler_free(caph);
    free(caph);
    free(pong_seen);
    free(stream);

    if (failures) {
        fprintf(stderr, "FAILED: %d\n", failures);
        return 1;
    }
    fprintf(stderr, "PASS\n");
    return 0;
}
