/* libFuzzer harness for configure requests (set-channel and hop lists).
 *
 *   tools/unit.sh <tree> test/capture_framework/cfgreq_fuzz.c --set framework \
 *       --libs "-llzma -lwebsockets" --flavor fuzz [--time 60] [--corpus DIR]
 *
 * Requests go to cf_handle_rx_content with the hop thread running, a
 * chantranslate that refuses some names and a chanfree that counts.  After each
 * input every translated channel must be owned by the hop list (none leaked, none
 * freed twice, never a NULL free), channel control never gets NULL, a list on
 * its own timer has no NULL slot, every NULL slot of a synced list is marked
 * failed, there are no more failures than channels, the offset lies in the
 * list, and the stored rate is finite and >= 0.
 *
 * Byte 0 low 2 bits: 0/1 structured hop list, 2 set-channel, 3 raw body.
 */

#include <arpa/inet.h>
#include <math.h>
#include <pthread.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "capture_framework.h"
#include "mpack/mpack.h"

static kis_capture_handler_t *caph;
static int live_priv;

static void *translate_cb(kis_capture_handler_t *h, const char *s) {
    char *r;

    (void) h;

    if (strcmp(s, "bad") == 0 || strcmp(s, "worse") == 0 || strcmp(s, "") == 0)
        return NULL;

    r = strdup(s);
    if (r != NULL)
        __atomic_add_fetch(&live_priv, 1, __ATOMIC_ACQ_REL);

    return r;
}

static void chanfree_cb(void *p) {
    if (p == NULL)
        abort();

    __atomic_sub_fetch(&live_priv, 1, __ATOMIC_ACQ_REL);
    free(p);
}

static int control_cb(kis_capture_handler_t *h, uint32_t seqno, void *p, char *msg) {
    (void) h;
    (void) seqno;
    (void) msg;

    if (p == NULL)
        abort();

    if (strcmp((const char *) p, "fail") == 0)
        return 0;

    return 1;
}

static void drain(void) {
    static char buf[65536];

    pthread_mutex_lock(&caph->out_ringbuf_lock);

    while (caph->out_ringbuf != NULL &&
            kis_simple_ringbuf_used(caph->out_ringbuf) >= sizeof(kismet_external_frame_v3_t)) {
        kismet_external_frame_v3_t hdr;
        uint32_t len;

        if (kis_simple_ringbuf_read(caph->out_ringbuf, &hdr, sizeof(hdr)) != sizeof(hdr))
            abort();

        len = ntohl(hdr.length);

        if (len > sizeof(buf) || kis_simple_ringbuf_read(caph->out_ringbuf, buf, len) != len)
            abort();
    }

    pthread_mutex_unlock(&caph->out_ringbuf_lock);
}

static void send_body(const uint8_t *body, size_t len) {
    static uint8_t buf[sizeof(kismet_external_frame_v3_t) + 4096];
    kismet_external_frame_v3_t *f = (kismet_external_frame_v3_t *) buf;

    if (len > 4096)
        len = 4096;

    memset(buf, 0, sizeof(kismet_external_frame_v3_t));
    f->signature = htonl(KIS_EXTERNAL_PROTO_SIG);
    f->v3_sentinel = htons(KIS_EXTERNAL_V3_SIG);
    f->v3_version = htons(3);
    f->length = htonl((uint32_t) len);
    f->pkt_type = htons(KIS_EXTERNAL_V3_KDS_CONFIGREQ);
    f->seqno = htonl(7);
    memcpy(buf + sizeof(kismet_external_frame_v3_t), body, len);

    cf_handle_rx_content(caph, buf, sizeof(kismet_external_frame_v3_t) + len);
}

static const char *names[] = { "1", "6", "bad", "worse", "fail", "11", "x=1", "" };

static uint8_t get(const uint8_t **d, size_t *n) {
    uint8_t v;

    if (*n == 0)
        return 0;

    v = **d;
    (*d)++;
    (*n)--;

    return v;
}

static float rate_for(uint8_t sel) {
    switch (sel & 7) {
        case 0: return 0.5f;
        case 1: return 10.0f;
        case 2: return 200.0f;
        case 3: return 2000.0f;
        case 4: return 0.0f;
        case 5: return -5.0f;
        case 6: return NAN;
        default: return INFINITY;
    }
}

static int failed_at(size_t pos) {
    struct cf_channel_error *e;

    for (e = (struct cf_channel_error *) caph->channel_hop_failure_list; e != NULL; e = e->next) {
        if (e->channel_pos == pos)
            return 1;
    }

    return 0;
}

/* Hop state invariants; under handler_lock */
static void check_hop_state(void) {
    size_t k;

    /* A bad rate is refused, never stored */
    if (!isfinite(caph->channel_hop_rate) || caph->channel_hop_rate < 0) {
        fprintf(stderr, "stored hop rate %f\n", caph->channel_hop_rate);
        abort();
    }

    if (caph->channel_hop_list_sz == 0)
        return;

    for (k = 0; k < caph->channel_hop_list_sz; k++) {
        if (caph->custom_channel_hop_list[k] != NULL)
            continue;

        if (!caph->hop_sync) {
            fprintf(stderr, "NULL slot %zu in a non-synced list\n", k);
            abort();
        }

        if (!failed_at(k)) {
            fprintf(stderr, "NULL slot %zu of a synced list not marked\n", k);
            abort();
        }
    }

    if (caph->channel_hop_failure_list_sz > caph->channel_hop_list_sz) {
        fprintf(stderr, "%zu failures in a list of %zu\n", caph->channel_hop_failure_list_sz,
                caph->channel_hop_list_sz);
        abort();
    }

    if (caph->channel_hop_offset < 0 ||
            (size_t) caph->channel_hop_offset >= caph->channel_hop_list_sz) {
        fprintf(stderr, "offset %d in a list of %zu\n", caph->channel_hop_offset,
                caph->channel_hop_list_sz);
        abort();
    }
}

int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {
    char body[2048];
    mpack_writer_t w;
    uint8_t mode, b, cnt, i, fl;
    size_t k;
    int owned;

    if (caph == NULL) {
        caph = cf_handler_init("cfgreqfuzz");
        if (caph == NULL)
            abort();

        caph->use_ipc = 1;
        caph->verbose = 0;
        cf_handler_set_chantranslate_cb(caph, translate_cb);
        cf_handler_set_chancontrol_cb(caph, control_cb);
        cf_handler_set_chanfree_cb(caph, chanfree_cb);

        if (caph->out_ringbuf == NULL)
            caph->out_ringbuf = kis_simple_ringbuf_create(CAP_FRAMEWORK_RINGBUF_OUT_SZ);
    }

    mode = get(&data, &size) & 3;

    if (mode == 3) {
        send_body(data, size);
    } else if (mode == 2) {
        b = get(&data, &size);
        mpack_writer_init(&w, body, sizeof(body));
        mpack_build_map(&w);
        mpack_write_uint(&w, KIS_EXTERNAL_V3_KDS_CONFIGREQ_FIELD_CHANNEL);
        mpack_write_cstr(&w, names[b & 7]);
        mpack_complete_map(&w);
        if (mpack_writer_error(&w) == mpack_ok)
            send_body((const uint8_t *) body, mpack_writer_buffer_used(&w));
    } else {
        cnt = get(&data, &size);
        fl = get(&data, &size);
        mpack_writer_init(&w, body, sizeof(body));
        mpack_build_map(&w);
        mpack_write_uint(&w, KIS_EXTERNAL_V3_KDS_CONFIGREQ_FIELD_CHANHOPBLOCK);
        mpack_build_map(&w);
        mpack_write_uint(&w, KIS_EXTERNAL_V3_KDS_SUB_CHANHOP_FIELD_CHAN_LIST);
        mpack_start_array(&w, (uint32_t) (cnt % 12));
        for (i = 0; i < cnt % 12; i++) {
            b = get(&data, &size);
            if ((b & 0xf0) == 0xf0)
                mpack_write_uint(&w, b);
            else
                mpack_write_cstr(&w, names[b & 7]);
        }
        mpack_finish_array(&w);
        mpack_write_uint(&w, KIS_EXTERNAL_V3_KDS_SUB_CHANHOP_FIELD_RATE);
        if (fl & 0x80)
            mpack_write_cstr(&w, "fast");
        else
            mpack_write_float(&w, rate_for(fl));
        if (fl & 0x08) {
            mpack_write_uint(&w, KIS_EXTERNAL_V3_KDS_SUB_CHANHOP_FIELD_SHUFFLE);
            mpack_write_bool(&w, 1);
            mpack_write_uint(&w, KIS_EXTERNAL_V3_KDS_SUB_CHANHOP_FIELD_SKIP);
            mpack_write_u16(&w, get(&data, &size));
        }
        if (fl & 0x10) {
            uint8_t lo = get(&data, &size);
            uint8_t hi = get(&data, &size);

            mpack_write_uint(&w, KIS_EXTERNAL_V3_KDS_SUB_CHANHOP_FIELD_OFFSET);
            mpack_write_u16(&w, (uint16_t) (lo | (hi << 8)));
        }
        if (fl & 0x20) {
            mpack_write_uint(&w, KIS_EXTERNAL_V3_KDS_SUB_CHANHOP_FIELD_SYNC_EPOCH);
            mpack_write_u64(&w, (uint64_t) 1700000000ULL * 1000000000ULL);
        }
        mpack_complete_map(&w);
        mpack_complete_map(&w);
        if (mpack_writer_error(&w) == mpack_ok)
            send_body((const uint8_t *) body, mpack_writer_buffer_used(&w));
    }

    drain();

    pthread_mutex_lock(&caph->handler_lock);

    owned = 0;
    for (k = 0; k < caph->channel_hop_list_sz; k++) {
        if (caph->custom_channel_hop_list[k] != NULL)
            owned++;
    }

    if (owned != __atomic_load_n(&live_priv, __ATOMIC_ACQUIRE)) {
        fprintf(stderr, "priv mismatch: owned %d live %d\n", owned, live_priv);
        abort();
    }

    check_hop_state();

    pthread_mutex_unlock(&caph->handler_lock);

    return 0;
}
