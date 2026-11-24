/* Channels the source refuses in a configure request.
 *
 *   tools/unit.sh <tree> test/capture_framework/chan_refuse_test.c --set framework \
 *       --libs "-llzma -lwebsockets" --flavor asan
 *
 * chantranslate returns NULL for a channel it can't use.  A set-channel to one
 * gets a successful CONFIGREPORT with a warning (a failed one makes the server
 * close the source); it must not stop the hopping in progress or reach channel
 * control.  Synced, refused entries of a hop list stay in the list marked failed
 * from the start, so the source keeps the shared schedule and sits their slots
 * out, and closes only when every usable channel failed to tune; on its own
 * timer they're dropped at once, with no dwell and no prune report, and the
 * server's offset moves to the channel it meant in the compacted list.  NULL
 * slots of a helper's own list are dropped by the prune, and failure entries
 * outside the list are ignored, by the prune and by the "every channel failed"
 * checks.  A shorter list keeps the configured shuffle spacing for the next
 * list.  A hop list with nothing usable, or with a NaN, infinite or negative
 * rate, gets the warning and leaves the current hop list running.  Each
 * refusal goes out as exactly one MESSAGE naming
 * the source (name=, else the interface, else the UUID; none for a remote
 * source, which the server names), after the CONFIGREPORT, since the report's
 * text reaches no log or UI.  A new hop list forgets the old list's failed
 * positions, malformed requests free what they parsed and translated, a
 * request with nothing to configure succeeds (also on a source without
 * channel control), and a NaN rate set directly never reaches a float to
 * integer conversion.
 *
 * Requests whose report is checked for messages run with handler_lock held, so
 * the hop thread can't queue a warning of its own first.
 */

#include <arpa/inet.h>
#include <math.h>
#include <pthread.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <unistd.h>

#include "capture_framework.h"
#include "mpack/mpack.h"

static int failures = 0;

#define CHECK(c) do { if (!(c)) { fprintf(stderr, "FAIL %s:%d: %s\n", __FILE__, __LINE__, #c); failures++; } } while (0)

static int null_calls = 0;
static int chan_calls = 0;
static int live_priv = 0;
static int null_frees = 0;

/* Channel "1" fails to tune this many more times */
static int fail_1 = 0;

/* Shuffle spacing for set_hop_full; 0 sends no shuffle */
static unsigned int hop_spacing = 0;

/* Channel control calls while recording, with the realtime clock (which is the
 * server's clock for a source that never synced) */
#define MAX_RECS 256
static pthread_mutex_t rec_lock = PTHREAD_MUTEX_INITIALIZER;
static int recording = 0;
static int n_recs = 0;
static char rec_chan[MAX_RECS][16];
static uint64_t rec_ns[MAX_RECS];

static uint64_t realtime_ns(void) {
    struct timespec ts;
    clock_gettime(CLOCK_REALTIME, &ts);
    return (uint64_t) ts.tv_sec * 1000000000ULL + (uint64_t) ts.tv_nsec;
}

static void *translate_cb(kis_capture_handler_t *caph, const char *chanstr) {
    char *r;

    (void) caph;

    if (strcmp(chanstr, "bad") == 0 || strcmp(chanstr, "worse") == 0 ||
            strcmp(chanstr, "oom=1") == 0)
        return NULL;

    r = strdup(chanstr);
    if (r != NULL)
        __atomic_add_fetch(&live_priv, 1, __ATOMIC_ACQ_REL);

    return r;
}

static void chanfree_cb(void *privchan) {
    if (privchan == NULL) {
        __atomic_add_fetch(&null_frees, 1, __ATOMIC_ACQ_REL);
        return;
    }

    __atomic_sub_fetch(&live_priv, 1, __ATOMIC_ACQ_REL);
    free(privchan);
}

static int control_cb(kis_capture_handler_t *caph, uint32_t seqno, void *privchan, char *msg) {
    (void) caph;
    (void) seqno;
    (void) msg;

    if (privchan == NULL) {
        __atomic_add_fetch(&null_calls, 1, __ATOMIC_ACQ_REL);
        return 0;
    }

    /* A channel the hardware fails to tune, unlike one the source refuses */
    if (strcmp((const char *) privchan, "fail") == 0)
        return 0;

    if (strcmp((const char *) privchan, "1") == 0 &&
            __atomic_load_n(&fail_1, __ATOMIC_ACQUIRE) > 0) {
        __atomic_sub_fetch(&fail_1, 1, __ATOMIC_ACQ_REL);
        return 0;
    }

    pthread_mutex_lock(&rec_lock);
    if (recording && n_recs < MAX_RECS) {
        snprintf(rec_chan[n_recs], sizeof(rec_chan[n_recs]), "%s", (const char *) privchan);
        rec_ns[n_recs] = realtime_ns();
        n_recs++;
    }
    pthread_mutex_unlock(&rec_lock);

    __atomic_add_fetch(&chan_calls, 1, __ATOMIC_ACQ_REL);
    return 1;
}

static void record_start(void) {
    pthread_mutex_lock(&rec_lock);
    recording = 1;
    n_recs = 0;
    pthread_mutex_unlock(&rec_lock);
}

static int record_count(void) {
    int n;

    pthread_mutex_lock(&rec_lock);
    n = n_recs;
    pthread_mutex_unlock(&rec_lock);

    return n;
}

static void record_stop(void) {
    pthread_mutex_lock(&rec_lock);
    recording = 0;
    pthread_mutex_unlock(&rec_lock);
}

static void capture_cb(kis_capture_handler_t *caph) {
    int stop = 0;

    while (!stop) {
        usleep(5000);

        pthread_mutex_lock(&caph->handler_lock);
        stop = caph->spindown || caph->shutdown;
        pthread_mutex_unlock(&caph->handler_lock);
    }
}

static int open_cb(kis_capture_handler_t *caph, uint32_t seqno, char *definition, char *msg,
        uint32_t *dlt, char **uuid, cf_params_interface_t **ret_interface,
        cf_params_spectrum_t **ret_spectrum) {
    (void) caph;
    (void) seqno;
    (void) definition;
    (void) msg;
    (void) ret_interface;
    (void) ret_spectrum;

    *dlt = 0;
    *uuid = strdup("5FE308BD-0000-0000-0000-000000000001");

    return 1;
}

/* The label is set from any open; a failed one starts no capture thread, whose
 * short life TSan can't follow to the handler's free */
static int open_fail_cb(kis_capture_handler_t *caph, uint32_t seqno, char *definition, char *msg,
        uint32_t *dlt, char **uuid, cf_params_interface_t **ret_interface,
        cf_params_spectrum_t **ret_spectrum) {
    open_cb(caph, seqno, definition, msg, dlt, uuid, ret_interface, ret_spectrum);
    return -1;
}

/* The hop state, read the way the hop thread writes it */
struct hop_state {
    int running;
    unsigned int gen;
    size_t sz;
    size_t fails;
    int have_channel;
    char list[8][16];
};

static void get_state(kis_capture_handler_t *caph, struct hop_state *s) {
    size_t i;

    memset(s, 0, sizeof(*s));

    pthread_mutex_lock(&caph->handler_lock);
    s->running = caph->hopping_running;
    s->gen = caph->hop_generation;
    s->sz = caph->channel_hop_list_sz;
    s->fails = caph->channel_hop_failure_list_sz;
    s->have_channel = caph->channel != NULL;
    for (i = 0; i < s->sz && i < 8; i++)
        snprintf(s->list[i], sizeof(s->list[i]), "%s",
                caph->channel_hop_list[i] != NULL ? caph->channel_hop_list[i] : "(null)");
    pthread_mutex_unlock(&caph->handler_lock);
}

struct report {
    int found;
    unsigned int code;
    int hop_chans;
    int hop_offset;
    int hop_skip;
    char msg[256];
    int messages;
    unsigned int msg_flags;
    char message[256];
    int errors;
    char error[256];
    /* Frame order in the queue; -1 when absent */
    int report_pos;
    int first_msg_pos;
};

/* Find the CONFIGREPORT for seqno in the outbound queue, dropping every frame */
static void take_report(kis_capture_handler_t *caph, uint32_t seqno, struct report *r) {
    static char buf[65536];
    mpack_tree_t tree;
    mpack_node_t root, n;

    int pos = 0;

    memset(r, 0, sizeof(*r));
    r->hop_chans = -1;
    r->hop_offset = -1;
    r->hop_skip = -1;
    r->report_pos = -1;
    r->first_msg_pos = -1;

    pthread_mutex_lock(&caph->out_ringbuf_lock);

    if (caph->out_ringbuf == NULL) {
        pthread_mutex_unlock(&caph->out_ringbuf_lock);
        CHECK(!"no outbound ring");
        return;
    }

    while (kis_simple_ringbuf_used(caph->out_ringbuf) >= sizeof(kismet_external_frame_v3_t)) {
        kismet_external_frame_v3_t hdr;
        uint32_t len;

        if (kis_simple_ringbuf_read(caph->out_ringbuf, &hdr, sizeof(hdr)) != sizeof(hdr))
            break;

        len = ntohl(hdr.length);

        if (len > sizeof(buf) || kis_simple_ringbuf_read(caph->out_ringbuf, buf, len) != len) {
            CHECK(!"short frame");
            break;
        }

        pos++;

        if (ntohs(hdr.pkt_type) == KIS_EXTERNAL_V3_CMD_MESSAGE) {
            r->messages++;
            if (r->first_msg_pos < 0)
                r->first_msg_pos = pos;

            mpack_tree_init_data(&tree, buf, len);
            mpack_tree_parse(&tree);
            root = mpack_tree_root(&tree);
            r->msg_flags = mpack_node_u8(mpack_node_map_uint(root, KIS_EXTERNAL_V3_MESSAGE_FIELD_TYPE));
            mpack_node_copy_cstr(mpack_node_map_uint(root, KIS_EXTERNAL_V3_MESSAGE_FIELD_STRING),
                    r->message, sizeof(r->message));
            CHECK(mpack_tree_destroy(&tree) == mpack_ok);
            continue;
        }

        if (ntohs(hdr.pkt_type) == KIS_EXTERNAL_V3_CMD_ERROR) {
            r->errors++;

            mpack_tree_init_data(&tree, buf, len);
            mpack_tree_parse(&tree);
            root = mpack_tree_root(&tree);
            n = mpack_node_map_uint_optional(root, KIS_EXTERNAL_V3_ERROR_FIELD_STRING);
            if (!mpack_node_is_missing(n))
                mpack_node_copy_cstr(n, r->error, sizeof(r->error));
            CHECK(mpack_tree_destroy(&tree) == mpack_ok);
            continue;
        }

        if (ntohs(hdr.pkt_type) != KIS_EXTERNAL_V3_KDS_CONFIGREPORT || ntohl(hdr.seqno) != seqno)
            continue;

        r->found = 1;
        r->code = ntohs(hdr.code);
        r->report_pos = pos;

        mpack_tree_init_data(&tree, buf, len);
        mpack_tree_parse(&tree);
        root = mpack_tree_root(&tree);

        n = mpack_node_map_uint_optional(root, KIS_EXTERNAL_V3_KDS_CONFIGREPORT_FIELD_MSG);
        if (!mpack_node_is_missing(n))
            mpack_node_copy_cstr(n, r->msg, sizeof(r->msg));

        n = mpack_node_map_uint_optional(root, KIS_EXTERNAL_V3_KDS_CONFIGREPORT_FIELD_CHANHOPBLOCK);
        if (!mpack_node_is_missing(n)) {
            mpack_node_t o = mpack_node_map_uint_optional(n, KIS_EXTERNAL_V3_KDS_SUB_CHANHOP_FIELD_OFFSET);

            if (!mpack_node_is_missing(o))
                r->hop_offset = (int) mpack_node_uint(o);

            o = mpack_node_map_uint_optional(n, KIS_EXTERNAL_V3_KDS_SUB_CHANHOP_FIELD_SKIP);
            if (!mpack_node_is_missing(o))
                r->hop_skip = (int) mpack_node_uint(o);

            n = mpack_node_map_uint_optional(n, KIS_EXTERNAL_V3_KDS_SUB_CHANHOP_FIELD_CHAN_LIST);
            if (!mpack_node_is_missing(n))
                r->hop_chans = (int) mpack_node_array_length(n);
        }

        CHECK(mpack_tree_destroy(&tree) == mpack_ok);
    }

    pthread_mutex_unlock(&caph->out_ringbuf_lock);
}

/* A v3 request, handled as the service loop hands it over */
static int send_frame(kis_capture_handler_t *caph, unsigned int type, uint32_t seqno,
        const char *body, size_t len) {
    static uint8_t buf[sizeof(kismet_external_frame_v3_t) + 1024];
    kismet_external_frame_v3_t *f = (kismet_external_frame_v3_t *) buf;

    if (len > 1024)
        return -1;

    memset(buf, 0, sizeof(kismet_external_frame_v3_t));
    f->signature = htonl(KIS_EXTERNAL_PROTO_SIG);
    f->v3_sentinel = htons(KIS_EXTERNAL_V3_SIG);
    f->v3_version = htons(3);
    f->length = htonl((uint32_t) len);
    f->pkt_type = htons(type);
    f->seqno = htonl(seqno);
    memcpy(buf + sizeof(kismet_external_frame_v3_t), body, len);

    return cf_handle_rx_content(caph, buf, sizeof(kismet_external_frame_v3_t) + len);
}

static int open_source(kis_capture_handler_t *caph, uint32_t seqno, const char *definition) {
    char body[256];
    mpack_writer_t w;

    mpack_writer_init(&w, body, sizeof(body));
    mpack_build_map(&w);
    mpack_write_uint(&w, KIS_EXTERNAL_V3_KDS_OPENREQ_FIELD_DEFINITION);
    mpack_write_cstr(&w, definition);
    mpack_complete_map(&w);

    return send_frame(caph, KIS_EXTERNAL_V3_KDS_OPENREQ, seqno, body, mpack_writer_buffer_used(&w));
}

static int set_channel(kis_capture_handler_t *caph, uint32_t seqno, const char *chan) {
    char body[256];
    mpack_writer_t w;

    mpack_writer_init(&w, body, sizeof(body));
    mpack_build_map(&w);
    mpack_write_uint(&w, KIS_EXTERNAL_V3_KDS_CONFIGREQ_FIELD_CHANNEL);
    mpack_write_cstr(&w, chan);
    mpack_complete_map(&w);

    return send_frame(caph, KIS_EXTERNAL_V3_KDS_CONFIGREQ, seqno, body, mpack_writer_buffer_used(&w));
}

/* Malformed requests for the error paths, and requests leaving out the rate, or
 * the spacing while shuffling */
enum hop_kind { HOP_OK, HOP_BAD_ELEMENT, HOP_BAD_RATE, HOP_NO_RATE, HOP_NO_SKIP };

static int set_hop_full(kis_capture_handler_t *caph, uint32_t seqno, const char **chans, size_t n,
        double rate, int sync, uint64_t epoch_ns, unsigned int offset, enum hop_kind kind) {
    char body[512];
    mpack_writer_t w;
    size_t i;

    mpack_writer_init(&w, body, sizeof(body));
    mpack_build_map(&w);
    mpack_write_uint(&w, KIS_EXTERNAL_V3_KDS_CONFIGREQ_FIELD_CHANHOPBLOCK);
    mpack_build_map(&w);
    mpack_write_uint(&w, KIS_EXTERNAL_V3_KDS_SUB_CHANHOP_FIELD_CHAN_LIST);
    mpack_start_array(&w, (uint32_t) n);
    for (i = 0; i < n; i++) {
        if (kind == HOP_BAD_ELEMENT && i == n - 1)
            mpack_write_uint(&w, 7);
        else
            mpack_write_cstr(&w, chans[i]);
    }
    mpack_finish_array(&w);
    if (kind != HOP_NO_RATE) {
        mpack_write_uint(&w, KIS_EXTERNAL_V3_KDS_SUB_CHANHOP_FIELD_RATE);
        if (kind == HOP_BAD_RATE)
            mpack_write_cstr(&w, "fast");
        else
            mpack_write_float(&w, (float) rate);
    }
    if (offset != 0) {
        mpack_write_uint(&w, KIS_EXTERNAL_V3_KDS_SUB_CHANHOP_FIELD_OFFSET);
        mpack_write_u16(&w, (uint16_t) offset);
    }
    /* Always sent: an absent shuffle keeps the previous list's */
    mpack_write_uint(&w, KIS_EXTERNAL_V3_KDS_SUB_CHANHOP_FIELD_SHUFFLE);
    mpack_write_bool(&w, hop_spacing != 0 || kind == HOP_NO_SKIP);
    if (hop_spacing != 0 && kind != HOP_NO_SKIP) {
        mpack_write_uint(&w, KIS_EXTERNAL_V3_KDS_SUB_CHANHOP_FIELD_SKIP);
        mpack_write_u16(&w, (uint16_t) hop_spacing);
    }
    if (sync) {
        mpack_write_uint(&w, KIS_EXTERNAL_V3_KDS_SUB_CHANHOP_FIELD_SYNC_EPOCH);
        mpack_write_u64(&w, epoch_ns);
    }
    mpack_complete_map(&w);
    mpack_complete_map(&w);

    return send_frame(caph, KIS_EXTERNAL_V3_KDS_CONFIGREQ, seqno, body, mpack_writer_buffer_used(&w));
}

static int set_hop(kis_capture_handler_t *caph, uint32_t seqno, const char **chans, size_t n) {
    return set_hop_full(caph, seqno, chans, n, 50.0, 0, 0, 0, HOP_OK);
}

/* Lets the hop thread step through its list a few times */
static void hop_a_while(void) {
    int start = __atomic_load_n(&chan_calls, __ATOMIC_ACQUIRE);
    int i;

    for (i = 0; i < 2000 && __atomic_load_n(&chan_calls, __ATOMIC_ACQUIRE) < start + 6; i++)
        usleep(1000);
}

/* Synced: the slot the hop thread switched into for a call at srv_ns.  A switch
 * may start up to lead_ns before its slot, or run late into it */
static int synced_match(const char *chan, uint64_t srv_ns, uint64_t epoch_ns, uint64_t dwell_ns,
        unsigned int offset, const char **list, size_t n) {
    static const uint64_t lead_ns = 5000000;
    uint64_t rel = srv_ns - epoch_ns;
    uint64_t s1 = rel / dwell_ns, s2 = (rel + lead_ns) / dwell_ns;

    return strcmp(chan, list[(s1 + offset) % n]) == 0 || strcmp(chan, list[(s2 + offset) % n]) == 0;
}

/* A hop list, its report and the hop state, with the hop thread held off */
static int set_hop_locked(kis_capture_handler_t *caph, uint32_t seqno, const char **chans, size_t n,
        double rate, int sync, uint64_t epoch_ns, unsigned int offset, struct report *r,
        struct hop_state *s) {
    int ret;

    pthread_mutex_lock(&caph->handler_lock);
    ret = set_hop_full(caph, seqno, chans, n, rate, sync, epoch_ns, offset, HOP_OK);
    take_report(caph, seqno, r);
    get_state(caph, s);
    pthread_mutex_unlock(&caph->handler_lock);

    return ret;
}

/* Requests which fail to parse fail and free their parse tree (LeakSanitizer
 * checks at exit) */
static void parse_failures(void) {
    static const char not_map[] = { 0x02 };
    static const char truncated[] = { (char) 0x82, 0x01 };
    kis_capture_handler_t *h = cf_handler_init("chanrefuse");
    char body[64];
    mpack_writer_t w;
    struct report r;

    CHECK(h != NULL);
    if (h == NULL)
        return;

    h->use_ipc = 1;
    h->verbose = 0;
    cf_handler_set_open_cb(h, open_cb);
    cf_handler_set_capture_cb(h, capture_cb);
    cf_handler_set_chantranslate_cb(h, translate_cb);
    cf_handler_set_chancontrol_cb(h, control_cb);
    cf_handler_set_chanfree_cb(h, chanfree_cb);

    CHECK(send_frame(h, KIS_EXTERNAL_V3_KDS_OPENREQ, 1, truncated, sizeof(truncated)) < 0);
    CHECK(send_frame(h, KIS_EXTERNAL_V3_KDS_OPENREQ, 2, not_map, sizeof(not_map)) < 0);
    CHECK(send_frame(h, KIS_EXTERNAL_V3_KDS_CONFIGREQ, 3, truncated, sizeof(truncated)) < 0);
    CHECK(send_frame(h, KIS_EXTERNAL_V3_KDS_CONFIGREQ, 4, not_map, sizeof(not_map)) < 0);

    /* Only a report interval, or only a field this framework doesn't know:
     * applied and answered with success, so a newer server keeps the source */
    mpack_writer_init(&w, body, sizeof(body));
    mpack_build_map(&w);
    mpack_write_uint(&w, KIS_EXTERNAL_V3_KDS_CONFIGREQ_FIELD_REPORT_MS);
    mpack_write_u32(&w, 2000);
    mpack_complete_map(&w);
    CHECK(send_frame(h, KIS_EXTERNAL_V3_KDS_CONFIGREQ, 5, body, mpack_writer_buffer_used(&w)) > 0);
    take_report(h, 5, &r);
    CHECK(r.found && r.code == 1 && r.messages == 0);
    pthread_mutex_lock(&h->handler_lock);
    CHECK(h->hop_report_ms == 2000);
    pthread_mutex_unlock(&h->handler_lock);

    mpack_writer_init(&w, body, sizeof(body));
    mpack_build_map(&w);
    mpack_write_uint(&w, 200);
    mpack_write_cstr(&w, "from a newer server");
    mpack_complete_map(&w);
    CHECK(send_frame(h, KIS_EXTERNAL_V3_KDS_CONFIGREQ, 6, body, mpack_writer_buffer_used(&w)) > 0);
    take_report(h, 6, &r);
    CHECK(r.found && r.code == 1 && r.messages == 0);

    cf_handler_shutdown(h);
    cf_handler_free(h);
    free(h);
}

/* A non-synced 6 channel list with offset 3: its report, and the first channel
 * the hop thread tunes */
static void offset_case(kis_capture_handler_t *caph, uint32_t seqno, const char **chans,
        unsigned int spacing, size_t want_sz, int want_offset, const char *want_first) {
    struct report r;
    struct hop_state s;
    char first[16];
    int i, n;

    /* Under the lock, so the previous hop thread records nothing */
    pthread_mutex_lock(&caph->handler_lock);
    record_start();
    hop_spacing = spacing;
    CHECK(set_hop_locked(caph, seqno, chans, 6, 50.0, 0, 0, 3, &r, &s) > 0);
    hop_spacing = 0;
    pthread_mutex_unlock(&caph->handler_lock);

    CHECK(r.found && r.code == 1);
    CHECK(r.hop_chans == (int) want_sz);
    CHECK(r.hop_offset == want_offset);
    CHECK(s.sz == want_sz);
    CHECK(s.fails == 0);

    for (i = 0; i < 2000 && record_count() < 1; i++)
        usleep(1000);
    record_stop();

    pthread_mutex_lock(&rec_lock);
    n = n_recs;
    snprintf(first, sizeof(first), "%s", n > 0 ? rec_chan[0] : "");
    pthread_mutex_unlock(&rec_lock);

    CHECK(n >= 1);
    if (strcmp(first, want_first) != 0) {
        fprintf(stderr, "offset case %u: started on '%s', want '%s' (offset %d)\n",
                (unsigned int) seqno, first, want_first, r.hop_offset);
        CHECK(!"start channel");
    }
}

static kis_capture_handler_t *new_handler(void) {
    kis_capture_handler_t *h = cf_handler_init("chanrefuse");

    CHECK(h != NULL);
    if (h == NULL)
        return NULL;

    h->use_ipc = 1;
    h->verbose = 0;
    cf_handler_set_chantranslate_cb(h, translate_cb);
    cf_handler_set_chancontrol_cb(h, control_cb);
    cf_handler_set_chanfree_cb(h, chanfree_cb);

    /* Made by an open otherwise */
    if (h->out_ringbuf == NULL)
        h->out_ringbuf = kis_simple_ringbuf_create(CAP_FRAMEWORK_RINGBUF_OUT_SZ);
    CHECK(h->out_ringbuf != NULL);

    return h;
}

static void free_handler(kis_capture_handler_t *h) {
    cf_handler_shutdown(h);
    cf_handler_free(h);
    free(h);
}

/* Synced, "1" fails to tune once; the refused slot is never usable */
static void synced_failure_case(const char **chans, size_t n, int expect_close) {
    kis_capture_handler_t *h = new_handler();
    uint64_t epoch_ns = (realtime_ns() / 1000000000ULL - 100) * 1000000000ULL;
    struct report r, all;
    struct hop_state s;
    int i, j, seen6 = 0, closed = 0;

    if (h == NULL)
        return;

    memset(&all, 0, sizeof(all));
    __atomic_store_n(&fail_1, 1, __ATOMIC_RELEASE);

    CHECK(set_hop_full(h, 40, chans, n, 20.0, 1, epoch_ns, 0, HOP_OK) > 0);
    take_report(h, 40, &r);
    CHECK(r.found && r.code == 1);

    record_start();
    for (i = 0; i < 300; i++) {
        usleep(10000);

        take_report(h, 0, &r);
        all.errors += r.errors;
        all.messages += r.messages;
        if (r.errors > 0)
            snprintf(all.error, sizeof(all.error), "%s", r.error);
        if (r.messages > 0)
            snprintf(all.message, sizeof(all.message), "%s", r.message);

        pthread_mutex_lock(&h->handler_lock);
        closed = !h->hopping_running && h->spindown;
        pthread_mutex_unlock(&h->handler_lock);

        pthread_mutex_lock(&rec_lock);
        for (seen6 = 0, j = 0; j < n_recs; j++)
            seen6 += strcmp(rec_chan[j], "6") == 0;
        pthread_mutex_unlock(&rec_lock);

        if (expect_close && closed)
            break;
        if (!expect_close && __atomic_load_n(&fail_1, __ATOMIC_ACQUIRE) == 0 && seen6 >= 2)
            break;
    }
    record_stop();

    get_state(h, &s);
    CHECK(__atomic_load_n(&fail_1, __ATOMIC_ACQUIRE) == 0);
    CHECK(strstr(all.message, "Could not tune to channel 1") != NULL);

    if (expect_close) {
        CHECK(closed);
        CHECK(all.errors >= 1);
        CHECK(strcmp(all.error, "All configured channels are in error state!") == 0);
    } else {
        CHECK(!closed && s.running);
        CHECK(all.errors == 0);
        CHECK(seen6 >= 2);
        CHECK(s.sz == 3 && s.fails == 2);
    }

    __atomic_store_n(&fail_1, 0, __ATOMIC_RELEASE);
    free_handler(h);
}

/* A list a helper assigns itself, with a NULL slot, hopping on its own timer:
 * the slot is never tuned and the prune drops it */
static void null_slot_case(void) {
    kis_capture_handler_t *h = new_handler();
    char **chans;
    void **privs;
    struct report r;
    struct hop_state s;
    int i, pruned = 0;

    if (h == NULL)
        return;

    chans = (char **) calloc(3, sizeof(char *));
    privs = (void **) calloc(3, sizeof(void *));
    CHECK(chans != NULL && privs != NULL);
    if (chans == NULL || privs == NULL) {
        free(chans);
        free(privs);
        free_handler(h);
        return;
    }

    chans[0] = strdup("1");
    chans[1] = strdup("gone");
    chans[2] = strdup("6");
    privs[0] = translate_cb(h, "1");
    privs[2] = translate_cb(h, "6");

    cf_handler_assign_hop_channels(h, chans, privs, 3, 50.0, 0, 0, 0);

    for (i = 0; i < 200; i++) {
        usleep(10000);
        take_report(h, 0, &r);
        if (r.found && r.hop_chans == 2)
            pruned = 1;
        get_state(h, &s);
        if (pruned && s.sz == 2)
            break;
    }

    get_state(h, &s);
    CHECK(pruned);
    CHECK(s.running);
    CHECK(s.sz == 2 && strcmp(s.list[0], "1") == 0 && strcmp(s.list[1], "6") == 0);
    CHECK(__atomic_load_n(&null_calls, __ATOMIC_ACQUIRE) == 0);

    free_handler(h);
}

/* Adds a failure entry no list position has; under handler_lock */
static void add_stray_failure(kis_capture_handler_t *h) {
    struct cf_channel_error *e = (struct cf_channel_error *) malloc(sizeof(*e));

    CHECK(e != NULL);
    if (e == NULL)
        return;

    e->channel_pos = 99;
    e->next = (struct cf_channel_error *) h->channel_hop_failure_list;
    h->channel_hop_failure_list = e;
    h->channel_hop_failure_list_sz++;
}

/* On its own timer, a failure entry outside the list gets one warning at the
 * prune, which still drops the channels that failed and keeps hopping */
static void stray_failure_case(void) {
    static const char *with_fail[] = { "1", "fail", "6" };
    static const char *clean[] = { "1", "6" };
    kis_capture_handler_t *h = new_handler();
    struct report r, all;
    struct hop_state s;
    int i, pruned;

    if (h == NULL)
        return;

    /* With a channel which fails: pruned to {1, 6} */
    pthread_mutex_lock(&h->handler_lock);
    CHECK(set_hop_full(h, 50, with_fail, 3, 50.0, 0, 0, 0, HOP_OK) > 0);
    take_report(h, 50, &r);
    add_stray_failure(h);
    pthread_mutex_unlock(&h->handler_lock);

    memset(&all, 0, sizeof(all));
    for (i = 0, pruned = 0; i < 200 && !pruned; i++) {
        usleep(10000);
        take_report(h, 0, &r);
        all.messages += r.messages;
        all.errors += r.errors;
        if (r.messages > 0)
            snprintf(all.message, sizeof(all.message), "%s", r.message);
        pruned = r.found && r.hop_chans == 2;
    }

    get_state(h, &s);
    CHECK(pruned);
    CHECK(s.running);
    CHECK(s.sz == 2 && strcmp(s.list[0], "1") == 0 && strcmp(s.list[1], "6") == 0);
    CHECK(s.fails == 0);
    CHECK(all.errors == 0);
    CHECK(all.messages == 1);
    CHECK(strstr(all.message, "Ignoring 1 of the 2 channel errors") != NULL);

    /* With nothing failing: one warning, no prune report, list kept */
    pthread_mutex_lock(&h->handler_lock);
    CHECK(set_hop_full(h, 51, clean, 2, 50.0, 0, 0, 0, HOP_OK) > 0);
    take_report(h, 51, &r);
    add_stray_failure(h);
    pthread_mutex_unlock(&h->handler_lock);

    memset(&all, 0, sizeof(all));
    for (i = 0; i < 200; i++) {
        usleep(10000);
        take_report(h, 0, &r);
        all.found += r.found;
        all.messages += r.messages;
        all.errors += r.errors;
        if (r.messages > 0)
            snprintf(all.message, sizeof(all.message), "%s", r.message);
        get_state(h, &s);
        if (s.fails == 0 && all.messages > 0)
            break;
    }
    usleep(100000);
    take_report(h, 0, &r);
    all.found += r.found;
    all.messages += r.messages;

    get_state(h, &s);
    CHECK(s.running);
    CHECK(s.sz == 2 && s.fails == 0);
    CHECK(!all.found);
    CHECK(all.errors == 0);
    CHECK(all.messages == 1);
    CHECK(strstr(all.message, "Ignoring 1 of the 1 channel errors") != NULL);

    free_handler(h);
}

enum stray_mode { STRAY_OWN_TIMER, STRAY_NULL_SLOT, STRAY_SYNCED };

/* 3 of 4 channels fail and one failure entry lies outside the list: that isn't
 * every channel failing, so the source keeps hopping on the 4th.  On its own
 * timer through the tune failure check and through the NULL slot check (a
 * helper's own list), where the prune then leaves the 4th; synced, it sits the
 * failed slots out */
static void stray_all_case(enum stray_mode mode) {
    static const char *chans4[] = { "fail", "fail", "fail", "6" };
    kis_capture_handler_t *h = new_handler();
    uint64_t epoch_ns = (realtime_ns() / 1000000000ULL - 100) * 1000000000ULL;
    struct report r, all;
    struct hop_state s;
    char **chans;
    void **privs;
    int i, j, seen6 = 0, pruned = 0;

    if (h == NULL)
        return;

    memset(&all, 0, sizeof(all));
    record_start();

    /* The hop thread waits on handler_lock until the stray entry is in */
    pthread_mutex_lock(&h->handler_lock);

    if (mode == STRAY_NULL_SLOT) {
        chans = (char **) calloc(4, sizeof(char *));
        privs = (void **) calloc(4, sizeof(void *));
        CHECK(chans != NULL && privs != NULL);
        if (chans == NULL || privs == NULL) {
            pthread_mutex_unlock(&h->handler_lock);
            free(chans);
            free(privs);
            free_handler(h);
            return;
        }

        chans[0] = strdup("fail");
        chans[1] = strdup("fail");
        chans[2] = strdup("gone");
        chans[3] = strdup("6");
        privs[0] = translate_cb(h, "fail");
        privs[1] = translate_cb(h, "fail");
        privs[3] = translate_cb(h, "6");

        cf_handler_assign_hop_channels(h, chans, privs, 4, 50.0, 0, 0, 0);
    } else {
        CHECK(set_hop_full(h, 80, chans4, 4, mode == STRAY_SYNCED ? 20.0 : 50.0,
                    mode == STRAY_SYNCED, epoch_ns, 0, HOP_OK) > 0);
        take_report(h, 80, &r);
    }

    add_stray_failure(h);
    pthread_mutex_unlock(&h->handler_lock);

    for (i = 0; i < 300; i++) {
        usleep(10000);

        take_report(h, 0, &r);
        all.errors += r.errors;
        all.messages += r.messages;
        if (r.errors > 0)
            snprintf(all.error, sizeof(all.error), "%s", r.error);
        if (r.found && r.hop_chans == 1)
            pruned = 1;

        pthread_mutex_lock(&rec_lock);
        for (seen6 = 0, j = 0; j < n_recs; j++)
            seen6 += strcmp(rec_chan[j], "6") == 0;
        pthread_mutex_unlock(&rec_lock);

        get_state(h, &s);
        if (!s.running || (seen6 >= 3 && (mode == STRAY_SYNCED || pruned)))
            break;
    }
    record_stop();

    get_state(h, &s);
    if (all.errors > 0)
        fprintf(stderr, "stray mode %d: error '%s'\n", (int) mode, all.error);
    CHECK(s.running);
    CHECK(all.errors == 0);
    CHECK(seen6 >= 3);

    if (mode == STRAY_SYNCED) {
        CHECK(s.sz == 4 && s.fails == 4);
    } else {
        CHECK(pruned);
        CHECK(s.sz == 1 && strcmp(s.list[0], "6") == 0 && s.fails == 0);
    }

    CHECK(__atomic_load_n(&null_calls, __ATOMIC_ACQUIRE) == 0);

    free_handler(h);
}

/* Hops recorded since record_start match want, in order */
static int record_matches(const char **want, int n) {
    int i, ok;

    pthread_mutex_lock(&rec_lock);
    ok = n_recs >= n;
    for (i = 0; ok && i < n; i++)
        ok = strcmp(rec_chan[i], want[i]) == 0;
    if (!ok) {
        fprintf(stderr, "hop order:");
        for (i = 0; i < n_recs && i < n; i++)
            fprintf(stderr, " %s", rec_chan[i]);
        fprintf(stderr, "\n");
    }
    pthread_mutex_unlock(&rec_lock);

    return ok;
}

/* Shuffle spacing 4 on 5 channels, 2 of them refused (or pruned after failing
 * to tune): the 3 left hop in order and report spacing 1, but the configured 4
 * is kept, so the full list sent again without a spacing (the server never
 * sends one) still shuffles with 4 */
static void spacing_case(int prune) {
    static const char *refused5[] = { "a0", "bad", "a2", "worse", "a4" };
    static const char *failing5[] = { "a0", "fail", "a2", "fail", "a4" };
    static const char *full5[] = { "b0", "b1", "b2", "b3", "b4" };
    static const char *order5[] = { "b0", "b4", "b1", "b2", "b3" };
    kis_capture_handler_t *h = new_handler();
    struct report r;
    struct hop_state s;
    unsigned int spacing;
    int i, shuffle, skip = -1;

    if (h == NULL)
        return;

    hop_spacing = 4;
    CHECK(set_hop_full(h, 90, prune ? failing5 : refused5, 5, 50.0, 0, 0, 0, HOP_OK) > 0);
    hop_spacing = 0;
    take_report(h, 90, &r);
    CHECK(r.found && r.code == 1);

    if (prune) {
        CHECK(r.hop_chans == 5 && r.hop_skip == 4);

        for (i = 0; i < 300 && skip < 0; i++) {
            usleep(10000);
            take_report(h, 0, &r);
            if (r.found && r.hop_chans == 3)
                skip = r.hop_skip;
        }
    } else {
        CHECK(r.hop_chans == 3);
        skip = r.hop_skip;
    }

    pthread_mutex_lock(&h->handler_lock);
    spacing = h->channel_hop_shuffle_spacing;
    shuffle = h->channel_hop_shuffle;
    pthread_mutex_unlock(&h->handler_lock);

    get_state(h, &s);
    CHECK(s.running && s.sz == 3);
    CHECK(skip == 1);
    CHECK(shuffle && spacing == 4);

    /* Under the lock, so the previous hop thread records nothing */
    pthread_mutex_lock(&h->handler_lock);
    record_start();
    CHECK(set_hop_full(h, 91, full5, 5, 50.0, 0, 0, 0, HOP_NO_SKIP) > 0);
    take_report(h, 91, &r);
    pthread_mutex_unlock(&h->handler_lock);

    CHECK(r.found && r.code == 1 && r.hop_chans == 5);
    CHECK(r.hop_skip == 4);

    for (i = 0; i < 300 && record_count() < 5; i++)
        usleep(10000);
    record_stop();

    if (!record_matches(order5, 5))
        CHECK(!"shuffle order after a shorter list");

    free_handler(h);
}

/* A source without channel control: a request with only a report interval
 * succeeds; one with a channel or a hop list is refused as before */
static void no_chancontrol_case(void) {
    static const char *two[] = { "1", "6" };
    kis_capture_handler_t *h = new_handler();
    char body[64];
    mpack_writer_t w;
    struct report r;
    int live;

    if (h == NULL)
        return;

    cf_handler_set_chancontrol_cb(h, NULL);
    live = __atomic_load_n(&live_priv, __ATOMIC_ACQUIRE);

    mpack_writer_init(&w, body, sizeof(body));
    mpack_build_map(&w);
    mpack_write_uint(&w, KIS_EXTERNAL_V3_KDS_CONFIGREQ_FIELD_REPORT_MS);
    mpack_write_u32(&w, 3000);
    mpack_complete_map(&w);
    CHECK(send_frame(h, KIS_EXTERNAL_V3_KDS_CONFIGREQ, 100, body, mpack_writer_buffer_used(&w)) > 0);
    take_report(h, 100, &r);
    CHECK(r.found && r.code == 1 && r.messages == 0);
    pthread_mutex_lock(&h->handler_lock);
    CHECK(h->hop_report_ms == 3000);
    pthread_mutex_unlock(&h->handler_lock);

    CHECK(set_channel(h, 101, "6") < 0);
    take_report(h, 101, &r);
    CHECK(r.found && r.code == 0);
    CHECK(strstr(r.msg, "does not support channel configuration") != NULL);

    CHECK(set_hop(h, 102, two, 2) < 0);
    take_report(h, 102, &r);
    CHECK(r.found && r.code == 0);
    CHECK(__atomic_load_n(&live_priv, __ATOMIC_ACQUIRE) == live);

    free_handler(h);
}

/* A hop list with a rate the source refuses, on a source opened as srcA with
 * {1, 6} hopping; under handler_lock so the hop thread queues nothing between */
static void bad_rate_case(kis_capture_handler_t *caph, uint32_t seqno, const char **chans,
        double rate, int sync, uint64_t epoch_ns) {
    struct report r;
    struct hop_state s;

    pthread_mutex_lock(&caph->handler_lock);
    CHECK(set_hop_full(caph, seqno, chans, 3, rate, sync, epoch_ns, 0, HOP_OK) > 0);
    take_report(caph, seqno, &r);
    get_state(caph, &s);
    pthread_mutex_unlock(&caph->handler_lock);

    CHECK(r.found && r.code == 1);
    CHECK(strstr(r.msg, "srcA could not use the requested hop rate; keeping the current") != NULL);
    CHECK(r.messages == 1);
    CHECK(strcmp(r.message, r.msg) == 0);
    CHECK(r.report_pos > 0 && r.report_pos < r.first_msg_pos);
    CHECK(r.hop_chans == 2);
    CHECK(s.running);
    CHECK(s.sz == 2 && strcmp(s.list[0], "1") == 0 && strcmp(s.list[1], "6") == 0);
}

static void rate_guard_one(double rate) {
    static const char *again[] = { "1", "6", "11" };
    kis_capture_handler_t *h = new_handler();
    char **chans;
    void **privs;
    struct hop_state s;
    struct report r;

    if (h == NULL)
        return;

    chans = (char **) calloc(2, sizeof(char *));
    privs = (void **) calloc(2, sizeof(void *));
    CHECK(chans != NULL && privs != NULL);
    if (chans == NULL || privs == NULL) {
        free(chans);
        free(privs);
        free_handler(h);
        return;
    }

    chans[0] = strdup("1");
    chans[1] = strdup("6");
    privs[0] = translate_cb(h, "1");
    privs[1] = translate_cb(h, "6");

    cf_handler_assign_hop_channels(h, chans, privs, 2, rate, 0, 0, 0);
    usleep(50000);

    get_state(h, &s);
    CHECK(s.running);

    /* A request without a rate keeps the stored one, which is only checked
     * where it's used: the source stays open and takes the new list */
    pthread_mutex_lock(&h->handler_lock);
    CHECK(set_hop_full(h, 70, again, 3, 0, 0, 0, 0, HOP_NO_RATE) > 0);
    take_report(h, 70, &r);
    get_state(h, &s);
    pthread_mutex_unlock(&h->handler_lock);

    CHECK(r.found && r.code == 1 && r.hop_chans == 3);
    CHECK(s.running && s.sz == 3);

    free_handler(h);
}

static void rate_guard_case(void) {
    rate_guard_one(NAN);
    rate_guard_one(INFINITY);
    rate_guard_one(-5.0);
}

/* A fresh source opened with a definition, refusing a channel: the warning
 * starts with the expected label */
static void label_case(const char *definition, int remote, const char *expect) {
    kis_capture_handler_t *h = cf_handler_init("chanrefuse");
    struct report r;
    char want[256];

    CHECK(h != NULL);
    if (h == NULL)
        return;

    h->use_ipc = 1;
    h->verbose = 0;
    cf_handler_set_open_cb(h, open_fail_cb);
    cf_handler_set_capture_cb(h, capture_cb);
    cf_handler_set_chantranslate_cb(h, translate_cb);
    cf_handler_set_chancontrol_cb(h, control_cb);
    cf_handler_set_chanfree_cb(h, chanfree_cb);

    if (remote)
        h->remote_host = strdup("192.0.2.1");

    CHECK(open_source(h, 1, definition) < 0);
    take_report(h, 1, &r);

    CHECK(set_channel(h, 2, "bad") > 0);
    take_report(h, 2, &r);

    snprintf(want, sizeof(want), "%s could not use the requested channel; ", expect);
    CHECK(r.messages == 1);
    if (strncmp(r.message, want, strlen(want)) != 0) {
        fprintf(stderr, "label for '%s': got '%s'\n", definition, r.message);
        CHECK(!"label");
    }

    cf_handler_shutdown(h);
    cf_handler_free(h);
    free(h);
}

int main(void) {
    kis_capture_handler_t *caph = cf_handler_init("chanrefuse");
    static const char *mixed[] = { "1", "bad", "6", "worse" };
    static const char *refused[] = { "bad", "worse" };
    static const char *synced[] = { "1", "bad", "6", "11" };
    static const char *failing[] = { "fail", "1" };
    static const char *fresh[] = { "1", "6" };
    static const char *synced_two[] = { "1", "bad", "6" };
    static const char *synced_one[] = { "1", "bad" };
    static const char *split_refused[] = { "1", "2", "bad", "worse", "5", "13" };
    static const char *split_kept[] = { "bad", "1", "worse", "6", "11", "12" };
    static const char *split_shuffle[] = { "a0", "bad", "a2", "a3", "worse", "a5" };
    static const char *other[] = { "2", "3", "4" };
    const uint64_t dwell_ns = 100000000;
    uint64_t epoch_ns;
    struct report r;
    struct hop_state s;
    unsigned int gen;
    int ret, i, n, mismatch, seen1, seen6, seen11, live;

    CHECK(caph != NULL);
    if (caph == NULL)
        return 1;

    caph->use_ipc = 1;
    caph->verbose = 0;
    cf_handler_set_open_cb(caph, open_cb);
    cf_handler_set_capture_cb(caph, capture_cb);
    cf_handler_set_chantranslate_cb(caph, translate_cb);
    cf_handler_set_chancontrol_cb(caph, control_cb);
    cf_handler_set_chanfree_cb(caph, chanfree_cb);

    /* 0: the refusals name the source by its definition's name= */
    ret = open_source(caph, 9, "chanrefuse:name=srcA");
    take_report(caph, 9, &r);
    CHECK(ret >= 0);

    /* 1: not synced, refused entries leave the list at once, so they cost no
     * dwell; the report comes before its one warning, which names the source */
    ret = set_hop_locked(caph, 10, mixed, 4, 50.0, 0, 0, 0, &r, &s);
    CHECK(ret > 0);
    CHECK(r.found && r.code == 1);
    CHECK(r.hop_chans == 2);
    CHECK(strstr(r.msg, "srcA could not use 2 of the 4 channels in the hop list") != NULL);
    CHECK(r.messages == 1);
    CHECK(r.msg_flags == MSGFLAG_ERROR);
    CHECK(strcmp(r.message, r.msg) == 0);
    CHECK(r.report_pos > 0 && r.report_pos < r.first_msg_pos);
    CHECK(s.sz == 2 && strcmp(s.list[0], "1") == 0 && strcmp(s.list[1], "6") == 0);
    CHECK(s.fails == 0);

    /* A pass over the list sends no prune report and no warning for them */
    hop_a_while();
    take_report(caph, 0, &r);
    get_state(caph, &s);
    CHECK(__atomic_load_n(&null_calls, __ATOMIC_ACQUIRE) == 0);
    CHECK(!r.found);
    CHECK(r.messages == 0);
    CHECK(s.running);
    CHECK(s.sz == 2 && strcmp(s.list[0], "1") == 0 && strcmp(s.list[1], "6") == 0);
    CHECK(s.fails == 0);

    /* 2: a refused set-channel succeeds with a warning and leaves the hopping running */
    gen = s.gen;

    ret = set_channel(caph, 11, "bad");
    take_report(caph, 11, &r);
    get_state(caph, &s);
    CHECK(ret > 0);
    CHECK(r.found && r.code == 1);
    CHECK(strstr(r.msg, "srcA could not use the requested channel; keeping the current") != NULL);
    CHECK(r.messages == 1);
    CHECK(r.msg_flags == MSGFLAG_ERROR);
    CHECK(strcmp(r.message, r.msg) == 0);
    CHECK(r.report_pos > 0 && r.report_pos < r.first_msg_pos);
    CHECK(r.hop_chans == 2);
    CHECK(s.running);
    CHECK(s.gen == gen);
    CHECK(s.sz == 2);
    CHECK(!s.have_channel);
    CHECK(__atomic_load_n(&null_calls, __ATOMIC_ACQUIRE) == 0);

    hop_a_while();
    CHECK(__atomic_load_n(&null_calls, __ATOMIC_ACQUIRE) == 0);

    /* 3: a hop list of refused channels only keeps the current one */
    ret = set_hop(caph, 12, refused, 2);
    take_report(caph, 12, &r);
    get_state(caph, &s);
    CHECK(ret > 0);
    CHECK(r.found && r.code == 1);
    CHECK(strstr(r.msg, "srcA could not use any channel in the hop list; keeping the current") != NULL);
    CHECK(r.messages == 1);
    CHECK(r.msg_flags == MSGFLAG_ERROR);
    CHECK(strcmp(r.message, r.msg) == 0);
    CHECK(r.report_pos > 0 && r.report_pos < r.first_msg_pos);
    CHECK(r.hop_chans == 2);
    CHECK(s.running);
    CHECK(s.gen == gen);
    CHECK(s.sz == 2 && strcmp(s.list[0], "1") == 0 && strcmp(s.list[1], "6") == 0);

    hop_a_while();
    CHECK(__atomic_load_n(&null_calls, __ATOMIC_ACQUIRE) == 0);

    /* 4: a setting the source can't process isn't reported as a channel, and
     * keeps the hopping running */
    ret = set_channel(caph, 14, "oom=1");
    take_report(caph, 14, &r);
    get_state(caph, &s);
    CHECK(ret > 0);
    CHECK(r.found && r.code == 1);
    CHECK(strstr(r.msg, "srcA could not process the requested setting; keeping the current") != NULL);
    CHECK(r.messages == 1);
    CHECK(strcmp(r.message, r.msg) == 0);
    CHECK(r.report_pos > 0 && r.report_pos < r.first_msg_pos);
    CHECK(s.running);
    CHECK(s.gen == gen);

    /* 5: a usable set-channel still ends the hopping, without a warning */
    ret = set_channel(caph, 13, "6");
    take_report(caph, 13, &r);
    get_state(caph, &s);
    CHECK(ret > 0);
    CHECK(r.found && r.code == 1);
    CHECK(r.messages == 0);
    CHECK(!s.running);
    CHECK(s.have_channel);

    /* 5b: not synced and split (offset 3 of 6), with 2 refused: the source
     * starts on the server's channel, or the next usable one in the hop cycle,
     * and reports the offset of that channel in the compacted list */
    offset_case(caph, 30, split_refused, 0, 4, 2, "5");
    offset_case(caph, 31, split_kept, 0, 4, 1, "6");
    offset_case(caph, 32, split_shuffle, 2, 4, 1, "a3");

    /* 6: synced, with an offset and a refused channel in the middle: the list
     * keeps its size with the refused slot already failed, the slot is sat out,
     * and every other slot gets its channel from the shared schedule */
    epoch_ns = (realtime_ns() / 1000000000ULL - 100) * 1000000000ULL;

    ret = set_hop_locked(caph, 15, synced, 4, 10.0, 1, epoch_ns, 1, &r, &s);
    CHECK(ret > 0);
    CHECK(r.found && r.code == 1);
    CHECK(r.hop_chans == 4);
    CHECK(strstr(r.msg, "srcA could not use 1 of the 4 channels in the hop list") != NULL);
    CHECK(r.messages == 1);
    CHECK(r.report_pos > 0 && r.report_pos < r.first_msg_pos);
    CHECK(s.sz == 4 && s.fails == 1);

    record_start();
    for (i = 0; i < 400 && record_count() < 9; i++)
        usleep(10000);
    record_stop();

    get_state(caph, &s);
    CHECK(s.running);
    CHECK(s.sz == 4 && strcmp(s.list[1], "bad") == 0);
    CHECK(s.fails == 1);
    CHECK(__atomic_load_n(&null_calls, __ATOMIC_ACQUIRE) == 0);

    pthread_mutex_lock(&rec_lock);
    n = n_recs;
    mismatch = seen1 = seen6 = seen11 = 0;
    for (i = 0; i < n; i++) {
        if (!synced_match(rec_chan[i], rec_ns[i], epoch_ns, dwell_ns, 1, synced, 4)) {
            fprintf(stderr, "synced call %d: %s at slot %llu\n", i, rec_chan[i],
                    (unsigned long long) ((rec_ns[i] - epoch_ns) / dwell_ns));
            mismatch++;
        }
        seen1 += strcmp(rec_chan[i], "1") == 0;
        seen6 += strcmp(rec_chan[i], "6") == 0;
        seen11 += strcmp(rec_chan[i], "11") == 0;
    }
    pthread_mutex_unlock(&rec_lock);

    CHECK(n >= 9);
    CHECK(mismatch == 0);
    CHECK(seen1 > 0 && seen6 > 0 && seen11 > 0);

    /* 7: a new hop list forgets the old list's failed positions.  "fail" is a
     * tune failure, which the hop thread warns about once it gets the lock */
    ret = set_hop_locked(caph, 16, failing, 2, 20.0, 1, epoch_ns, 0, &r, &s);
    CHECK(ret > 0);
    CHECK(r.messages == 0);
    CHECK(s.fails == 0);

    for (i = 0; i < 200; i++) {
        get_state(caph, &s);
        if (s.fails > 0)
            break;
        usleep(10000);
    }
    CHECK(s.fails == 1);

    ret = set_hop_full(caph, 17, fresh, 2, 20.0, 1, epoch_ns, 0, HOP_OK);
    take_report(caph, 17, &r);
    get_state(caph, &s);
    CHECK(ret > 0);
    CHECK(s.fails == 0);

    record_start();
    for (i = 0; i < 300 && record_count() < 6; i++)
        usleep(10000);
    record_stop();

    pthread_mutex_lock(&rec_lock);
    n = n_recs;
    seen1 = 0;
    for (i = 0; i < n; i++)
        seen1 += strcmp(rec_chan[i], "1") == 0;
    pthread_mutex_unlock(&rec_lock);

    CHECK(n >= 6);
    CHECK(seen1 > 0);

    /* 8: malformed hop lists free the channels they translated, through the
     * source's chanfree */
    live = __atomic_load_n(&live_priv, __ATOMIC_ACQUIRE);

    ret = set_hop_full(caph, 18, fresh, 2, 20.0, 0, 0, 0, HOP_BAD_ELEMENT);
    CHECK(ret < 0);
    CHECK(__atomic_load_n(&live_priv, __ATOMIC_ACQUIRE) == live);

    ret = set_hop_full(caph, 19, fresh, 2, 20.0, 0, 0, 0, HOP_BAD_RATE);
    CHECK(ret < 0);
    CHECK(__atomic_load_n(&live_priv, __ATOMIC_ACQUIRE) == live);

    get_state(caph, &s);
    CHECK(s.running);
    CHECK(s.sz == 2 && strcmp(s.list[0], "1") == 0 && strcmp(s.list[1], "6") == 0);

    /* 9: NaN, infinite and negative rates are refused like a channel: a
     * successful report and one warning, what they translated is freed, and
     * the hopping stays as it was */
    live = __atomic_load_n(&live_priv, __ATOMIC_ACQUIRE);

    bad_rate_case(caph, 20, other, NAN, 0, 0);
    bad_rate_case(caph, 21, other, INFINITY, 1, epoch_ns);
    bad_rate_case(caph, 23, other, -5.0, 0, 0);
    CHECK(__atomic_load_n(&live_priv, __ATOMIC_ACQUIRE) == live);

    get_state(caph, &s);
    CHECK(s.running);
    CHECK(s.sz == 2 && strcmp(s.list[0], "1") == 0 && strcmp(s.list[1], "6") == 0);

    ret = set_hop_full(caph, 22, fresh, 2, 20.0, 0, 0, 0, HOP_OK);
    take_report(caph, 22, &r);
    CHECK(ret > 0);

    take_report(caph, 0, &r);

    cf_handler_shutdown(caph);
    cf_handler_free(caph);
    free(caph);

    /* 10: requests which fail to parse, and requests with nothing to configure */
    parse_failures();

    /* 12: synced, one tune failure on "1" keeps a source with another usable
     * channel hopping; with none left it closes */
    synced_failure_case(synced_two, 3, 0);
    synced_failure_case(synced_one, 2, 1);

    /* 13: NULL slots from a helper's own list are dropped by the prune */
    null_slot_case();

    /* 14: failure entries outside the list are ignored and hopping goes on */
    stray_failure_case();

    /* 15: rates the configure request refuses, set by a helper directly, hop at
     * the longest dwell; UBSan with float-cast-overflow catches a conversion.
     * A later request without a rate keeps the source open */
    rate_guard_case();

    /* 16: failure entries outside the list don't make every channel failed */
    stray_all_case(STRAY_OWN_TIMER);
    stray_all_case(STRAY_NULL_SLOT);
    stray_all_case(STRAY_SYNCED);

    /* 17: a shorter list keeps the configured shuffle spacing for the next one */
    spacing_case(0);
    spacing_case(1);

    /* 18: a source without channel control takes a report interval */
    no_chancontrol_case();

    /* 11: labels; serial paths are names, a bad name falls back to the interface
     * and a bad interface to the UUID, and a remote source gets none */
    label_case("/dev/ttyUSB0", 0, "/dev/ttyUSB0");
    label_case("/dev/ttyUSB1:name=srcB", 0, "srcB");
    label_case("ttyX1:name=bad$name", 0, "ttyX1");
    label_case("ttyX2:name=0123456789012345678901234567890123456789012345678901234567890123456789", 0,
            "ttyX2");
    label_case("bad$if:name=bad name", 0, "5FE308BD-0000-0000-0000-000000000001");
    label_case("ttyX3:name=remoteA", 1, "Source");

    /* Every translated channel went back through chanfree, and never a NULL one */
    CHECK(__atomic_load_n(&live_priv, __ATOMIC_ACQUIRE) == 0);
    CHECK(__atomic_load_n(&null_frees, __ATOMIC_ACQUIRE) == 0);

    if (failures) {
        fprintf(stderr, "chan_refuse_test: %d failure(s)\n", failures);
        return 1;
    }

    printf("chan_refuse_test: ok\n");
    return 0;
}
