/* test_diag_rawpkt.c - standalone unit tests for the raw-stream slicer.
 *
 * Links diag_rawpkt.c and nothing else: `make -f standalone.mk check`. Covers
 * the slice header's exact bytes, whole-frame slicing, a partial frame held
 * across reads, the cut at the payload cap, the no-terminator FRAGMENT, a dropped slice
 * leaving an exact offset gap, the end-of-stream flush, the END slice and the
 * first-drop record, the parser's rejections -- and the invariant
 * everything else serves: slices sorted by
 * offset and concatenated ARE the stream, under every read chunking.
 */

#include "diag_rawpkt.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

static int failures = 0;

#define CHECK(cond, ...) do { \
    if (!(cond)) { \
        fprintf(stderr, "FAIL %s:%d: ", __FILE__, __LINE__); \
        fprintf(stderr, __VA_ARGS__); \
        fprintf(stderr, "\n"); \
        failures++; \
    } \
} while (0)

/* ---- a collecting emit sink ---- */

#define MAX_SLICES 4096

typedef struct {
    size_t   n;
    uint8_t *pkt[MAX_SLICES];
    size_t   len[MAX_SLICES];
    int      drop_index;          /* 0-based slice to refuse, or -1 */
    size_t   calls;
} sink_t;

static void sink_init(sink_t *k) {
    memset(k, 0, sizeof(*k));
    k->drop_index = -1;
}

static void sink_free(sink_t *k) {
    for (size_t i = 0; i < k->n; i++)
        free(k->pkt[i]);
    k->n = 0;
}

/* Keeps a copy of every packet OFFERED (delivered or not), so a test can see
 * the dropped slice's header too. */
static int sink_emit(void *ctx, const uint8_t *pkt, size_t len) {
    sink_t *k = (sink_t *)ctx;
    size_t idx = k->calls++;
    if (k->n < MAX_SLICES) {
        k->pkt[k->n] = (uint8_t *)malloc(len);
        memcpy(k->pkt[k->n], pkt, len);
        k->len[k->n] = len;
        k->n++;
    }
    return (int)idx != k->drop_index;
}

static diag_rawpkt_hdr_t parsed(const sink_t *k, size_t i) {
    diag_rawpkt_hdr_t h;
    memset(&h, 0, sizeof(h));
    int r = diag_rawpkt_parse(k->pkt[i], k->len[i], &h);
    CHECK(r == 0, "slice %zu did not parse", i);
    return h;
}

/* ---- a deterministic stream of HDLC-shaped frames ---- */

static uint64_t rng = 0x9E3779B97F4A7C15ULL;
static uint32_t rnd(void) {
    rng ^= rng << 13; rng ^= rng >> 7; rng ^= rng << 17;
    return (uint32_t)(rng >> 16);
}

/* Frames of 2..`maxframe` bytes: body bytes never 0x7E (HDLC stuffs it), with
 * some 0x7D escapes in the mix, each ending in 0x7E. Returns the length. */
static size_t build_stream(uint8_t *out, size_t cap, size_t maxframe) {
    size_t n = 0;
    while (n + maxframe + 1 < cap) {
        size_t body = 1 + rnd() % maxframe;
        for (size_t i = 0; i < body; i++) {
            uint8_t b = (uint8_t)rnd();
            if (b == 0x7E) b = 0x7D;          /* an escape, as stuffing makes */
            out[n++] = b;
        }
        out[n++] = 0x7E;
    }
    return n;
}

/* ---- header ---- */

/* Catches: any change to the published slice-header layout (field order,
 * endianness, magic, version, header_len). Offline readers are written against
 * these exact bytes. */
static void test_header_bytes_are_the_published_layout(void) {
    static diag_rawpkt_t s;
    sink_t k;
    const uint8_t frame[] = { 0x01, 0x02, 0x7E };
    sink_init(&k);
    diag_rawpkt_init(&s, 0x1122334455667788ULL);
    diag_rawpkt_feed(&s, frame, sizeof(frame), sink_emit, &k);

    CHECK(k.n == 1, "want 1 slice, got %zu", k.n);
    if (k.n != 1) { sink_free(&k); return; }
    const uint8_t *p = k.pkt[0];
    const uint8_t want_hdr[24] = {
        'C', 'D', 'R', 'H', 0x01, 0x00, 24, 0x00,
        0x88, 0x77, 0x66, 0x55, 0x44, 0x33, 0x22, 0x11,   /* session, LE */
        0, 0, 0, 0, 0, 0, 0, 0,                           /* offset 0, LE */
    };
    CHECK(k.len[0] == 24 + sizeof(frame), "packet length %zu", k.len[0]);
    CHECK(memcmp(p, want_hdr, 24) == 0, "header bytes differ from the contract");
    CHECK(memcmp(p + 24, frame, sizeof(frame)) == 0, "payload is not the input bytes");
    sink_free(&k);
}

/* Catches: an offset written big-endian or truncated to 32 bits. */
static void test_offset_is_64_bit_little_endian(void) {
    static diag_rawpkt_t s;
    sink_t k;
    const uint8_t frame[] = { 0xAA, 0x7E };
    sink_init(&k);
    diag_rawpkt_init(&s, 1);
    s.offset = 0x0102030405060708ULL;     /* a stream already this far along */
    diag_rawpkt_feed(&s, frame, sizeof(frame), sink_emit, &k);
    CHECK(k.n == 1, "want 1 slice, got %zu", k.n);
    if (k.n == 1) {
        const uint8_t want[8] = { 8, 7, 6, 5, 4, 3, 2, 1 };
        CHECK(memcmp(k.pkt[0] + 16, want, 8) == 0, "offset bytes wrong");
        diag_rawpkt_hdr_t h = parsed(&k, 0);
        CHECK(h.offset == 0x0102030405060708ULL, "parsed offset 0x%llx",
              (unsigned long long)h.offset);
    }
    sink_free(&k);
}

/* ---- slicing ---- */

/* Catches: one packet per frame (the 2-8x row-overhead shape), or emitting
 * before the read's frames are all in. */
static void test_whole_frames_of_one_read_are_one_slice(void) {
    static diag_rawpkt_t s;
    sink_t k;
    const uint8_t buf[] = { 0x10, 0x7E, 0x20, 0x21, 0x7E, 0x30, 0x7E };
    sink_init(&k);
    diag_rawpkt_init(&s, 7);
    diag_rawpkt_feed(&s, buf, sizeof(buf), sink_emit, &k);
    CHECK(k.n == 1, "three whole frames in one read should be ONE slice, got %zu", k.n);
    if (k.n == 1) {
        diag_rawpkt_hdr_t h = parsed(&k, 0);
        CHECK(h.payload_len == sizeof(buf), "payload %zu", h.payload_len);
        CHECK(h.flags == 0, "flags 0x%02x", h.flags);
    }
    CHECK(s.len == 0, "accumulator should be empty, holds %zu", s.len);
    sink_free(&k);
}

/* Catches: a slice cut mid-frame at a read boundary (corrupts the frame on
 * both sides of a later drop), or the held tail's offset miscounted. */
static void test_a_partial_frame_waits_for_its_terminator(void) {
    static diag_rawpkt_t s;
    sink_t k;
    const uint8_t a[] = { 0xAA, 0xBB, 0x7E, 0xCC, 0xDD };
    const uint8_t b[] = { 0xEE, 0x7E };
    sink_init(&k);
    diag_rawpkt_init(&s, 7);
    diag_rawpkt_feed(&s, a, sizeof(a), sink_emit, &k);
    CHECK(k.n == 1, "first read: want 1 slice, got %zu", k.n);
    CHECK(s.len == 2, "the partial frame (2 bytes) should be held, holds %zu", s.len);
    diag_rawpkt_feed(&s, b, sizeof(b), sink_emit, &k);
    CHECK(k.n == 2, "second read: want 2 slices, got %zu", k.n);
    if (k.n == 2) {
        diag_rawpkt_hdr_t h0 = parsed(&k, 0), h1 = parsed(&k, 1);
        const uint8_t want1[] = { 0xCC, 0xDD, 0xEE, 0x7E };
        CHECK(h0.payload_len == 3 && h0.payload[2] == 0x7E, "slice 0 is not the first frame");
        CHECK(h1.offset == 3, "slice 1 offset %llu, want 3", (unsigned long long)h1.offset);
        CHECK(h1.payload_len == 4 && memcmp(h1.payload, want1, 4) == 0,
              "slice 1 is not the reassembled frame");
    }
    sink_free(&k);
}

/* Catches: a feed with no terminator emitting a slice (a mid-frame cut). */
static void test_no_terminator_emits_nothing_until_flush(void) {
    static diag_rawpkt_t s;
    sink_t k;
    const uint8_t a[] = { 0x11, 0x22, 0x33 };
    sink_init(&k);
    diag_rawpkt_init(&s, 7);
    diag_rawpkt_feed(&s, a, sizeof(a), sink_emit, &k);
    CHECK(k.n == 0, "no 0x7E yet, but %zu slice(s) went out", k.n);
    diag_rawpkt_flush(&s, sink_emit, &k);
    CHECK(k.n == 1, "flush should emit the residual, got %zu", k.n);
    if (k.n == 1) {
        diag_rawpkt_hdr_t h = parsed(&k, 0);
        CHECK(h.flags & DIAG_RAWPKT_FLAG_FRAGMENT, "an end-of-stream residual must be FRAGMENT");
        CHECK(h.payload_len == 3, "payload %zu", h.payload_len);
    }
    CHECK(s.fragments == 1, "fragments %llu", (unsigned long long)s.fragments);
    sink_free(&k);
}

/* Catches: a flush that emits an empty slice, or a zero-length feed that does. */
static void test_empty_feed_and_empty_flush_emit_nothing(void) {
    static diag_rawpkt_t s;
    sink_t k;
    sink_init(&k);
    diag_rawpkt_init(&s, 7);
    diag_rawpkt_feed(&s, (const uint8_t *)"", 0, sink_emit, &k);
    diag_rawpkt_flush(&s, sink_emit, &k);
    CHECK(k.n == 0, "nothing was fed, %zu slice(s) went out", k.n);
    CHECK(s.fragments == 0, "fragments %llu", (unsigned long long)s.fragments);
    sink_free(&k);
}

/* Catches: a read larger than the cap going out as one oversize packet, or
 * the cut landing anywhere but just after a 0x7E. */
static void test_a_large_read_is_cut_at_a_terminator(void) {
    static diag_rawpkt_t s;
    static uint8_t buf[70000];
    sink_t k;
    for (size_t i = 0; i < sizeof(buf); i++)
        buf[i] = (i % 100 == 99) ? 0x7E : 0x42;     /* 700 frames of 100 bytes */
    /* Derived from the cap, not hardcoded to one value of it: each full slice
     * is the whole 100-byte frames that fit, the last is the remainder. */
    const size_t first = (DIAG_RAWPKT_PAYLOAD_MAX / 100) * 100;
    const size_t want_n = sizeof(buf) / first + (sizeof(buf) % first ? 1 : 0);
    sink_init(&k);
    diag_rawpkt_init(&s, 7);
    diag_rawpkt_feed(&s, buf, sizeof(buf), sink_emit, &k);
    CHECK(k.n == want_n, "want %zu slices of <= %zu, got %zu", want_n, first, k.n);
    for (size_t i = 0; i < k.n; i++) {
        diag_rawpkt_hdr_t h = parsed(&k, i);
        CHECK(h.payload_len <= DIAG_RAWPKT_PAYLOAD_MAX, "slice %zu is %zu bytes", i, h.payload_len);
        CHECK(h.payload_len > 0 && h.payload[h.payload_len - 1] == 0x7E,
              "slice %zu does not end on a terminator", i);
        CHECK(h.flags == 0, "slice %zu flagged 0x%02x", i, h.flags);
    }
    if (k.n >= 1)
        CHECK(parsed(&k, 0).payload_len == first, "first cut at %zu, want %zu",
              parsed(&k, 0).payload_len, first);
    CHECK(s.len == 0, "accumulator holds %zu", s.len);
    sink_free(&k);
}

/* Catches: a no-terminator run longer than the cap wedging the slicer, going
 * out unflagged, or overflowing the accumulator. */
static void test_a_run_longer_than_the_cap_is_a_fragment(void) {
    static diag_rawpkt_t s;
    /* A no-terminator run one cap long plus 7232 bytes, then a 0x7E. */
    static uint8_t buf[DIAG_RAWPKT_PAYLOAD_MAX + 7233];
    sink_t k;
    memset(buf, 0x11, sizeof(buf) - 1);
    buf[sizeof(buf) - 1] = 0x7E;
    sink_init(&k);
    diag_rawpkt_init(&s, 7);
    diag_rawpkt_feed(&s, buf, sizeof(buf), sink_emit, &k);
    CHECK(k.n == 2, "want 2 slices, got %zu", k.n);
    if (k.n == 2) {
        diag_rawpkt_hdr_t h0 = parsed(&k, 0), h1 = parsed(&k, 1);
        CHECK(h0.payload_len == DIAG_RAWPKT_PAYLOAD_MAX, "fragment is %zu", h0.payload_len);
        CHECK(h0.flags & DIAG_RAWPKT_FLAG_FRAGMENT, "the cap-length run must be FRAGMENT");
        CHECK(h1.offset == DIAG_RAWPKT_PAYLOAD_MAX, "second offset %llu",
              (unsigned long long)h1.offset);
        CHECK(h1.payload_len == 7233, "tail %zu", h1.payload_len);
        CHECK(!(h1.flags & DIAG_RAWPKT_FLAG_FRAGMENT), "the tail ends on 0x7E: not a fragment");
    }
    CHECK(s.fragments == 1, "fragments %llu", (unsigned long long)s.fragments);
    sink_free(&k);
}

/* Catches: a drop that advances nothing (the next slice reuses the offset, so
 * the hole is invisible) or that stalls the slicer. */
static void test_a_dropped_slice_is_an_exact_offset_gap(void) {
    static diag_rawpkt_t s;
    sink_t k;
    const uint8_t f0[] = { 0x01, 0x7E };
    const uint8_t f1[] = { 0x02, 0x03, 0x04, 0x7E };
    const uint8_t f2[] = { 0x05, 0x7E };
    sink_init(&k);
    k.drop_index = 1;
    diag_rawpkt_init(&s, 7);
    diag_rawpkt_feed(&s, f0, sizeof(f0), sink_emit, &k);
    diag_rawpkt_feed(&s, f1, sizeof(f1), sink_emit, &k);
    diag_rawpkt_feed(&s, f2, sizeof(f2), sink_emit, &k);
    CHECK(k.n == 3, "want 3 offered, got %zu", k.n);
    CHECK(s.slices == 2 && s.dropped_slices == 1, "delivered %llu dropped %llu",
          (unsigned long long)s.slices, (unsigned long long)s.dropped_slices);
    CHECK(s.bytes == 4 && s.dropped_bytes == 4, "bytes %llu dropped_bytes %llu",
          (unsigned long long)s.bytes, (unsigned long long)s.dropped_bytes);
    if (k.n == 3) {
        diag_rawpkt_hdr_t h2 = parsed(&k, 2);
        CHECK(h2.offset == 6, "after the drop the offset is %llu, want 6 (2 + 4)",
              (unsigned long long)h2.offset);
    }
    sink_free(&k);
}

/* ---- END and the first-drop record ---- */

/* Catches: END sent before the residual (so its offset is not the final
 * length), END carrying a payload or the FRAGMENT flag, END counted as a data
 * slice, or a second END from a second call. */
static void test_end_closes_the_stream_at_its_final_length(void) {
    static diag_rawpkt_t s;
    sink_t k;
    const uint8_t buf[] = { 0x01, 0x7E, 0xAA, 0xBB };      /* a frame + a partial */
    sink_init(&k);
    diag_rawpkt_init(&s, 9);
    diag_rawpkt_feed(&s, buf, sizeof(buf), sink_emit, &k);
    diag_rawpkt_end(&s, sink_emit, &k);
    CHECK(k.n == 3, "want frame + residual + END, got %zu packet(s)", k.n);
    if (k.n == 3) {
        diag_rawpkt_hdr_t r = parsed(&k, 1), e = parsed(&k, 2);
        CHECK(r.flags == DIAG_RAWPKT_FLAG_FRAGMENT && r.offset == 2 && r.payload_len == 2,
              "the residual must precede END, as a 2-byte FRAGMENT at 2");
        CHECK(e.flags == DIAG_RAWPKT_FLAG_END, "END flags 0x%02x", e.flags);
        CHECK(e.payload_len == 0, "END carries %zu payload byte(s)", e.payload_len);
        CHECK(e.offset == sizeof(buf), "END offset %llu, want the final length %zu",
              (unsigned long long)e.offset, sizeof(buf));
        CHECK(e.session_id == 9, "END session %llu", (unsigned long long)e.session_id);
    }
    CHECK(s.slices == 2 && s.bytes == sizeof(buf),
          "END must not count as data: slices %llu bytes %llu",
          (unsigned long long)s.slices, (unsigned long long)s.bytes);
    CHECK(s.end_sent == 1, "end_sent %d", s.end_sent);
    diag_rawpkt_end(&s, sink_emit, &k);
    CHECK(k.n == 3, "a second end() sent %zu more packet(s)", k.n - 3);
    sink_free(&k);
}

/* Catches: an empty stream that ends with no END (a reader would then call a
 * source that read nothing "unconfirmed" rather than "ended, empty"). */
static void test_an_empty_stream_still_ends(void) {
    static diag_rawpkt_t s;
    sink_t k;
    sink_init(&k);
    diag_rawpkt_init(&s, 9);
    diag_rawpkt_end(&s, sink_emit, &k);
    CHECK(k.n == 1, "want END alone, got %zu packet(s)", k.n);
    if (k.n == 1) {
        diag_rawpkt_hdr_t e = parsed(&k, 0);
        CHECK(e.flags == DIAG_RAWPKT_FLAG_END && e.offset == 0 && e.payload_len == 0,
              "END of an empty stream: flags 0x%02x offset %llu", e.flags,
              (unsigned long long)e.offset);
    }
    sink_free(&k);
}

/* The END case. Catches: tail loss that stays invisible. The LAST data
 * slice is dropped, so no later slice shows the hole -- only END's offset,
 * which counts dropped bytes, puts it back between the delivered end and END. */
static void test_a_dropped_tail_is_a_gap_before_end(void) {
    static diag_rawpkt_t s;
    sink_t k;
    const uint8_t f0[] = { 0x01, 0x7E };
    const uint8_t f1[] = { 0x02, 0x03, 0x04, 0x7E };
    sink_init(&k);
    k.drop_index = 1;                     /* the stream's last data slice */
    diag_rawpkt_init(&s, 9);
    diag_rawpkt_feed(&s, f0, sizeof(f0), sink_emit, &k);
    diag_rawpkt_feed(&s, f1, sizeof(f1), sink_emit, &k);
    diag_rawpkt_end(&s, sink_emit, &k);
    CHECK(k.n == 3, "want 2 data + END offered, got %zu", k.n);
    if (k.n == 3) {
        diag_rawpkt_hdr_t d0 = parsed(&k, 0), e = parsed(&k, 2);
        uint64_t delivered_end = d0.offset + d0.payload_len;
        CHECK(e.flags == DIAG_RAWPKT_FLAG_END, "packet 2 is not END (0x%02x)", e.flags);
        CHECK(e.offset - delivered_end == sizeof(f1),
              "tail gap %llu, want the dropped %zu bytes",
              (unsigned long long)(e.offset - delivered_end), sizeof(f1));
    }
    CHECK(s.end_sent == 1, "END was offered to an accepting sink: end_sent %d", s.end_sent);
    CHECK(s.first_drop_offset == sizeof(f0) && s.first_drop_len == sizeof(f1),
          "first drop at %llu len %llu", (unsigned long long)s.first_drop_offset,
          (unsigned long long)s.first_drop_len);
    sink_free(&k);
}

/* Catches: a refused END recorded as sent. */
static void test_a_refused_end_is_recorded(void) {
    static diag_rawpkt_t s;
    sink_t k;
    const uint8_t f0[] = { 0x01, 0x7E };
    sink_init(&k);
    k.drop_index = 1;                     /* END itself */
    diag_rawpkt_init(&s, 9);
    diag_rawpkt_feed(&s, f0, sizeof(f0), sink_emit, &k);
    diag_rawpkt_end(&s, sink_emit, &k);
    CHECK(s.end_sent == -1, "end_sent %d, want -1", s.end_sent);
    CHECK(s.dropped_slices == 0, "a dropped END counted as a dropped data slice");
    sink_free(&k);
}

/* Catches: the record naming a LATER drop, a malformed JSON shape, a record
 * for a stream that never dropped, or a silent truncation into a small buffer. */
static void test_drop_json_names_the_first_drop(void) {
    static diag_rawpkt_t s;
    sink_t k;
    char buf[256];
    const uint8_t f0[] = { 0x01, 0x7E };
    const uint8_t f1[] = { 0x02, 0x03, 0x7E };
    const uint8_t f2[] = { 0x04, 0x05, 0x06, 0x7E };
    sink_init(&k);
    diag_rawpkt_init(&s, 1790028000123456789ULL);
    CHECK(diag_rawpkt_drop_json(&s, buf, sizeof(buf)) == -1,
          "a record for a stream with no drop");
    k.drop_index = 1;
    diag_rawpkt_feed(&s, f0, sizeof(f0), sink_emit, &k);
    diag_rawpkt_feed(&s, f1, sizeof(f1), sink_emit, &k);
    k.drop_index = 2;
    diag_rawpkt_feed(&s, f2, sizeof(f2), sink_emit, &k);
    CHECK(s.dropped_slices == 2, "setup: want 2 drops, got %llu",
          (unsigned long long)s.dropped_slices);
    CHECK(diag_rawpkt_drop_json(&s, buf, sizeof(buf)) == 0, "no record after a drop");
    const char *want = "{\"schema\":\"raw-diag-drop/1\",\"session_id\":1790028000123456789,"
                       "\"first_drop_offset\":2,\"first_drop_len\":3}";
    CHECK(strcmp(buf, want) == 0, "record\n  got  %s\n  want %s", buf, want);
    CHECK(diag_rawpkt_drop_json(&s, buf, 20) == -1, "a truncated record reported success");
    sink_free(&k);
}

/* The invariant (.hdlc equivalence). Catches ANY slicing defect that loses,
 * duplicates, or reorders a byte: sorted by offset and concatenated, the
 * slices must be the stream, under chunkings from 1 byte to larger than the
 * cap, with frames up to 9000 bytes (the largest observed is 8,050). */
static void test_slices_concatenate_to_the_stream_under_every_chunking(void) {
    static uint8_t stream[400000];
    static uint8_t rebuilt[400000];
    static diag_rawpkt_t s;
    size_t total = build_stream(stream, sizeof(stream), 9000);
    const size_t chunkings[] = { 0 /* random */, 1, 7, 4096, 32768, 65536, 100000 };

    for (size_t c = 0; c < sizeof(chunkings) / sizeof(chunkings[0]); c++) {
        sink_t k;
        size_t fed = 0, rlen = 0;
        uint64_t expect_off = 0;
        int ok = 1;
        /* byte-at-a-time over the whole 400 KB would be slow and adds nothing
         * over 7; cap the 1-byte case to the frames within the first 20 KB --
         * cut AFTER a 0x7E, or the flushed residual is (rightly) a fragment. */
        size_t limit = total;
        if (chunkings[c] == 1) {
            limit = 20000;
            while (limit > 0 && stream[limit - 1] != 0x7E)
                limit--;
        }

        sink_init(&k);
        diag_rawpkt_init(&s, 42);
        while (fed < limit) {
            size_t n = chunkings[c] ? chunkings[c] : 1 + rnd() % 70000;
            if (n > limit - fed) n = limit - fed;
            diag_rawpkt_feed(&s, stream + fed, n, sink_emit, &k);
            fed += n;
        }
        diag_rawpkt_flush(&s, sink_emit, &k);

        for (size_t i = 0; i < k.n; i++) {
            diag_rawpkt_hdr_t h = parsed(&k, i);
            if (h.offset != expect_off) { ok = 0; break; }
            if (h.payload_len == 0 || h.payload_len > DIAG_RAWPKT_PAYLOAD_MAX) { ok = 0; break; }
            if (!(h.flags & DIAG_RAWPKT_FLAG_FRAGMENT) &&
                h.payload[h.payload_len - 1] != 0x7E) { ok = 0; break; }
            memcpy(rebuilt + rlen, h.payload, h.payload_len);
            rlen += h.payload_len;
            expect_off += h.payload_len;
        }
        CHECK(ok, "chunking %zu: a slice broke contiguity, the cap, or its terminator",
              chunkings[c]);
        CHECK(rlen == limit && memcmp(rebuilt, stream, limit) == 0,
              "chunking %zu: concatenated slices (%zu B) are not the %zu-byte stream",
              chunkings[c], rlen, limit);
        CHECK(s.bytes == limit, "chunking %zu: delivered-bytes counter %llu, want %zu",
              chunkings[c], (unsigned long long)s.bytes, limit);
        CHECK(s.fragments == 0, "chunking %zu: a well-formed stream produced %llu fragment(s)",
              chunkings[c], (unsigned long long)s.fragments);
        sink_free(&k);
    }
}

/* ---- parser ---- */

/* Catches: a parser that accepts foreign or truncated bytes as a slice. */
static void test_parse_rejects_what_is_not_a_slice(void) {
    static diag_rawpkt_t s;
    sink_t k;
    diag_rawpkt_hdr_t h;
    const uint8_t frame[] = { 0x01, 0x7E };
    uint8_t p[64];
    sink_init(&k);
    diag_rawpkt_init(&s, 7);
    diag_rawpkt_feed(&s, frame, sizeof(frame), sink_emit, &k);
    CHECK(k.n == 1, "setup: want 1 slice, got %zu", k.n);
    if (k.n != 1) { sink_free(&k); return; }
    size_t n = k.len[0];
    CHECK(diag_rawpkt_parse(k.pkt[0], n, &h) == 0, "a real slice must parse");
    CHECK(h.session_id == 7 && h.payload_len == 2 && h.header_len == 24,
          "parsed fields wrong");

    memcpy(p, k.pkt[0], n); p[0] = 'X';
    CHECK(diag_rawpkt_parse(p, n, &h) == -1, "bad magic accepted");
    memcpy(p, k.pkt[0], n); p[4] = 2;
    CHECK(diag_rawpkt_parse(p, n, &h) == -1, "unknown version accepted");
    CHECK(diag_rawpkt_parse(k.pkt[0], 23, &h) == -1, "a packet shorter than the header accepted");
    memcpy(p, k.pkt[0], n); p[6] = 60;
    CHECK(diag_rawpkt_parse(p, n, &h) == -1, "header_len past the packet end accepted");
    memcpy(p, k.pkt[0], n); p[6] = 16;
    CHECK(diag_rawpkt_parse(p, n, &h) == -1, "header_len shorter than v1's accepted");
    memcpy(p, k.pkt[0], n); p[5] = DIAG_RAWPKT_FLAG_END;
    CHECK(diag_rawpkt_parse(p, n, &h) == -1, "an END slice with a payload accepted");
    CHECK(diag_rawpkt_parse(p, 24, &h) == 0 && h.flags == DIAG_RAWPKT_FLAG_END &&
          h.payload_len == 0, "an empty END slice must parse");
    sink_free(&k);
}

/* Catches: a reader that hard-codes 24 instead of honouring header_len -- a
 * v1 reader must skip fields a later v1 writer appends. */
static void test_parse_honours_a_longer_header_len(void) {
    uint8_t p[40];
    diag_rawpkt_hdr_t h;
    memset(p, 0, sizeof(p));
    memcpy(p, "CDRH", 4);
    p[4] = 1; p[6] = 32;                  /* 8 bytes of future fields */
    p[32] = 0xAB; p[33] = 0x7E;
    CHECK(diag_rawpkt_parse(p, 34, &h) == 0, "a longer header_len must parse");
    CHECK(h.payload_len == 2 && h.payload == p + 32 && h.payload[0] == 0xAB,
          "payload must start at header_len, not at 24");
}

int main(void) {
    test_header_bytes_are_the_published_layout();
    test_offset_is_64_bit_little_endian();
    test_whole_frames_of_one_read_are_one_slice();
    test_a_partial_frame_waits_for_its_terminator();
    test_no_terminator_emits_nothing_until_flush();
    test_empty_feed_and_empty_flush_emit_nothing();
    test_a_large_read_is_cut_at_a_terminator();
    test_a_run_longer_than_the_cap_is_a_fragment();
    test_a_dropped_slice_is_an_exact_offset_gap();
    test_end_closes_the_stream_at_its_final_length();
    test_an_empty_stream_still_ends();
    test_a_dropped_tail_is_a_gap_before_end();
    test_a_refused_end_is_recorded();
    test_drop_json_names_the_first_drop();
    test_slices_concatenate_to_the_stream_under_every_chunking();
    test_parse_rejects_what_is_not_a_slice();
    test_parse_honours_a_longer_header_len();

    if (failures) {
        fprintf(stderr, "test_diag_rawpkt: %d FAILURE(S)\n", failures);
        return 1;
    }
    printf("test_diag_rawpkt: all 17 cases passed\n");
    return 0;
}
