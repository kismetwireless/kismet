/* diag_rawpkt.c - the raw DIAG byte stream as Kismet packets.
 *
 * The contract a reader relies on is in diag_rawpkt.h. This file is the
 * slicer (feed / flush / end), the header codec and the RawDiagDrop record,
 * libc-only.
 */
#include "diag_rawpkt.h"

#include <inttypes.h>
#include <stdio.h>
#include <string.h>

#define PAYLOAD(s) ((s)->pkt + DIAG_RAWPKT_HDR_LEN)

static void put_le16(uint8_t *p, uint16_t v) {
    p[0] = (uint8_t)v;
    p[1] = (uint8_t)(v >> 8);
}

static void put_le64(uint8_t *p, uint64_t v) {
    for (int i = 0; i < 8; i++)
        p[i] = (uint8_t)(v >> (8 * i));
}

static uint64_t get_le64(const uint8_t *p) {
    uint64_t v = 0;
    for (int i = 7; i >= 0; i--)
        v = (v << 8) | p[i];
    return v;
}

void diag_rawpkt_init(diag_rawpkt_t *s, uint64_t session_id) {
    memset(s, 0, sizeof(*s));
    s->session_id = session_id;
}

static void put_header(diag_rawpkt_t *s, uint8_t flags) {
    memcpy(s->pkt, DIAG_RAWPKT_MAGIC, 4);
    s->pkt[4] = (uint8_t)DIAG_RAWPKT_VERSION;
    s->pkt[5] = flags;
    put_le16(s->pkt + 6, (uint16_t)DIAG_RAWPKT_HDR_LEN);
    put_le64(s->pkt + 8, s->session_id);
    put_le64(s->pkt + 16, s->offset);
}

/* Send the first `n` accumulated payload bytes as one slice, then slide the
 * rest (the partial frame after the cut) to the front. The offset advances
 * whether or not the slice was delivered: that is what makes a drop an exact,
 * visible gap rather than a silent splice. */
static void emit_slice(diag_rawpkt_t *s, size_t n, uint8_t flags,
                       diag_rawpkt_emit_fn emit, void *ctx) {
    put_header(s, flags);

    if (flags & DIAG_RAWPKT_FLAG_FRAGMENT)
        s->fragments++;
    if (emit(ctx, s->pkt, DIAG_RAWPKT_HDR_LEN + n)) {
        s->slices++;
        s->bytes += n;
    } else {
        /* The first drop is what a RawDiagDrop row reports. */
        if (s->dropped_slices == 0) {
            s->first_drop_offset = s->offset;
            s->first_drop_len = n;
        }
        s->dropped_slices++;
        s->dropped_bytes += n;
    }

    s->offset += n;
    s->len -= n;
    if (s->len > 0)
        memmove(PAYLOAD(s), PAYLOAD(s) + n, s->len);
    /* The cut was at the LAST 0x7E (or took everything), so what is left
     * holds no terminator. */
    s->commit = 0;
}

void diag_rawpkt_feed(diag_rawpkt_t *s, const uint8_t *buf, size_t len,
                      diag_rawpkt_emit_fn emit, void *ctx) {
    while (len > 0) {
        size_t n = DIAG_RAWPKT_PAYLOAD_MAX - s->len;
        if (n > len)
            n = len;
        memcpy(PAYLOAD(s) + s->len, buf, n);
        for (size_t i = n; i > 0; i--) {
            if (buf[i - 1] == 0x7E) {
                s->commit = s->len + i;
                break;
            }
        }
        s->len += n;
        buf += n;
        len -= n;

        if (s->len == DIAG_RAWPKT_PAYLOAD_MAX) {
            if (s->commit > 0)
                emit_slice(s, s->commit, 0, emit, ctx);
            else
                emit_slice(s, s->len, DIAG_RAWPKT_FLAG_FRAGMENT, emit, ctx);
        }
    }
    /* End of this read: every frame it completed goes out now, so a slice's
     * packet timestamp is the host receipt time of all of its frames. */
    if (s->commit > 0)
        emit_slice(s, s->commit, 0, emit, ctx);
}

void diag_rawpkt_flush(diag_rawpkt_t *s, diag_rawpkt_emit_fn emit, void *ctx) {
    if (s->len > 0)
        emit_slice(s, s->len, DIAG_RAWPKT_FLAG_FRAGMENT, emit, ctx);
}

/* After the flush the accumulator is empty, so s->offset IS the final length:
 * every byte fed, whether its slice was delivered or dropped. */
void diag_rawpkt_end(diag_rawpkt_t *s, diag_rawpkt_emit_fn emit, void *ctx) {
    if (s->end_sent != 0)
        return;
    diag_rawpkt_flush(s, emit, ctx);
    put_header(s, DIAG_RAWPKT_FLAG_END);
    s->end_sent = emit(ctx, s->pkt, DIAG_RAWPKT_HDR_LEN) ? 1 : -1;
}

int diag_rawpkt_drop_json(const diag_rawpkt_t *s, char *buf, size_t cap) {
    if (s->dropped_slices == 0)
        return -1;
    int n = snprintf(buf, cap,
                     "{\"schema\":\"" DIAG_RAWPKT_DROP_SCHEMA "\",\"session_id\":%" PRIu64
                     ",\"first_drop_offset\":%" PRIu64 ",\"first_drop_len\":%" PRIu64 "}",
                     s->session_id, s->first_drop_offset, s->first_drop_len);
    return (n < 0 || (size_t)n >= cap) ? -1 : 0;
}

int diag_rawpkt_parse(const uint8_t *pkt, size_t len, diag_rawpkt_hdr_t *out) {
    if (len < DIAG_RAWPKT_HDR_LEN || memcmp(pkt, DIAG_RAWPKT_MAGIC, 4) != 0 ||
        pkt[4] != DIAG_RAWPKT_VERSION)
        return -1;
    uint16_t hl = (uint16_t)(pkt[6] | (pkt[7] << 8));
    if (hl < DIAG_RAWPKT_HDR_LEN || hl > len)
        return -1;
    if ((pkt[5] & DIAG_RAWPKT_FLAG_END) && len != hl)
        return -1;                  /* END carries no stream bytes */
    out->version = pkt[4];
    out->flags = pkt[5];
    out->header_len = hl;
    out->session_id = get_le64(pkt + 8);
    out->offset = get_le64(pkt + 16);
    out->payload = pkt + hl;
    out->payload_len = len - hl;
    return 0;
}
