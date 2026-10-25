/*
    This file is part of Kismet

    Kismet is free software; you can redistribute it and/or modify
    it under the terms of the GNU General Public License as published by
    the Free Software Foundation; either version 2 of the License, or
    (at your option) any later version.

    Kismet is distributed in the hope that it will be useful,
    but WITHOUT ANY WARRANTY; without even the implied warranty of
    MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
    GNU General Public License for more details.

    You should have received a copy of the GNU General Public License
    along with Kismet; if not, write to the Free Software
    Foundation, Inc., 59 Temple Place, Suite 330, Boston, MA  02111-1307  USA

    See diag_logstream.h for what this is and why. Three layers:

        diag_logstream_feed()   the byte stream -> raw frames
        process_frame()         one frame -> at most one record
        extract_log_f()         one LOG_F body -> the record's fields

    Selftest: build with -DDIAG_LOGSTREAM_SELFTEST (see the check target).
*/

#include <string.h>

#include "diag_logstream.h"
#include "diag_hdlc.h"

#define HDLC_FLAG 0x7E

/* DIAG_LOG_F. */
#define OPCODE_LOG_F 0x10
/* DIAG_MULTI_RADIO_CMD_F: [0]=0x98 [1]=radio_id [2:4]=pad [4:8]=tx_mask
 * [8:]=a COMPLETE inner frame. On SDX72-class parts EVERY record arrives this
 * way, so an extractor that only handles a top-level 0x10 sees nothing at all
 * on those modems. */
#define OPCODE_MULTI_RADIO 0x98
#define MULTI_RADIO_WRAPPER_OFFSET 8

/* cmd(1) pending(1) outer_len(2) inner_len(2) log_code(2) ts64(8) = 16 */
#define LOG_F_MIN_LEN 16
#define LOG_F_CODE_OFFSET 6
#define LOG_F_TS64_OFFSET 8

static uint16_t rd_u16le(const uint8_t *p) {
    return (uint16_t)(p[0] | ((uint16_t)p[1] << 8));
}

static uint64_t rd_u64le(const uint8_t *p) {
    uint64_t v = 0;
    for (int i = 7; i >= 0; i--)
        v = (v << 8) | p[i];
    return v;
}

/* Parse a CRC-stripped LOG_F frame body. Returns 1 and
 * fills *out on success, 0 if the body is too short or is not a 0x10. */
static int extract_log_f(const uint8_t *body, size_t len, bool from_wrapper,
                         diag_log_record_t *out) {
    if (len < LOG_F_MIN_LEN || body[0] != OPCODE_LOG_F)
        return 0;

    out->log_code = rd_u16le(body + LOG_F_CODE_OFFSET);
    out->ts64 = rd_u64le(body + LOG_F_TS64_OFFSET);
    out->payload = body + LOG_F_MIN_LEN;
    out->payload_len = len - LOG_F_MIN_LEN;
    out->from_wrapper = from_wrapper;
    return 1;
}

/* Decode ONE raw (still-escaped, delimiter-stripped) frame, emitting at most
 * one record.
 *
 * CRC is always verified here: this runs on a live modem port where a bad
 * frame is a corrupt read, and a corrupt LOG_F would be handed to a decode leg
 * as if it were real. */
static void process_frame(diag_logstream_t *s, const uint8_t *raw, size_t rawlen,
                          diag_logstream_cb cb, void *user) {
    diag_log_record_t rec;

    s->stats.frames_seen++;

    /* opcode + at least 1 byte + 2 CRC. Python returns before touching stats. */
    if (rawlen < 4)
        return;

    size_t flen = diag_hdlc_unescape(raw, rawlen, s->frame, sizeof(s->frame));
    if (flen < 3) {
        s->stats.skipped_short++;
        return;
    }

    if (!diag_hdlc_check_crc(s->frame, &flen)) {
        s->stats.crc_bad++;
        return;
    }
    s->stats.crc_ok++;

    /* A NULL callback makes this a CRC census -- every frame is
     * unescaped, checked and counted, and nothing is extracted. The helper runs
     * one on builds and modes that have no native tap, so a damaged stream is
     * counted everywhere, not only where nativedecode= happens to be armed. */
    if (cb == NULL)
        return;

    /* diag_hdlc_check_crc already stripped the trailing CRC, so `flen` is the
     * Python's `body = frame[:-2]`. */
    const uint8_t *body = s->frame;
    size_t blen = flen;
    if (blen == 0)
        return;

    if (body[0] == OPCODE_LOG_F) {
        if (extract_log_f(body, blen, false, &rec)) {
            s->stats.log_records++;
            cb(&rec, user);
        }
        return;
    }

    if (body[0] == OPCODE_MULTI_RADIO && blen > MULTI_RADIO_WRAPPER_OFFSET) {
        /* The wrapper carries ONE outer CRC and no inner CRC, so the inner frame
         * is the envelope body from the wrapper offset on, un-stripped. */
        const uint8_t *inner = body + MULTI_RADIO_WRAPPER_OFFSET;
        size_t ilen = blen - MULTI_RADIO_WRAPPER_OFFSET;
        if (extract_log_f(inner, ilen, true, &rec)) {
            s->stats.log_records++;
            s->stats.log_records_from_wrapper++;
            cb(&rec, user);
        }
        return;
    }

    /* Every other opcode (0x79/0x99 F3, 0x80 QShrink4, 0x9E secure log, command
     * responses) is not a LOG record: counted, and nothing yielded. The raw
     * stream (rawlog=, the kismetdb raw packets) still carries them for an
     * offline reader -- this extractor is a TAP on the byte stream, not a
     * filter in front of it. */
}

void diag_logstream_init(diag_logstream_t *s) {
    memset(s, 0, sizeof(*s));
}

void diag_logstream_feed(diag_logstream_t *s, const uint8_t *buf, size_t len,
                         diag_logstream_cb cb, void *user) {
    size_t i = 0;

    while (i < len) {
        const uint8_t *flag = (const uint8_t *)memchr(buf + i, HDLC_FLAG, len - i);
        size_t seglen = flag ? (size_t)(flag - (buf + i)) : (len - i);

        if (s->residual_len + seglen <= sizeof(s->residual)) {
            memcpy(s->residual + s->residual_len, buf + i, seglen);
            s->residual_len += seglen;
        } else {
            /* This frame will not fit. Mark it and stop accumulating; the bytes
             * up to its delimiter are discarded, and the NEXT delimiter starts a
             * clean frame -- so a single oversize/desynced frame costs one
             * frame, not the rest of the stream. */
            s->residual_overflow = true;
        }

        if (!flag) {
            /* Chunk ended mid-frame; hold what we have for the next feed. */
            return;
        }

        if (s->residual_overflow) {
            s->stats.oversize_dropped++;
            s->residual_overflow = false;
        } else if (s->residual_len > 0) {
            process_frame(s, s->residual, s->residual_len, cb, user);
        }
        /* An empty segment is a back-to-back 0x7E (idle fill / frame padding);
         * the Python's split() yields b"" there and _process_frame returns on
         * the len<4 guard without counting. Skipping it here is the same
         * outcome without inflating frames_seen. */
        s->residual_len = 0;
        i += seglen + 1;   /* consume the segment and its delimiter */
    }
}

void diag_logstream_flush(diag_logstream_t *s, diag_logstream_cb cb, void *user) {
    if (s->residual_overflow) {
        s->stats.oversize_dropped++;
        s->residual_overflow = false;
        s->residual_len = 0;
        return;
    }
    if (s->residual_len == 0)
        return;
    process_frame(s, s->residual, s->residual_len, cb, user);
    s->residual_len = 0;
}

/* -----------------------------------------------------------------------
 * Selftest
 * ----------------------------------------------------------------------- */
#ifdef DIAG_LOGSTREAM_SELFTEST

#include <stdio.h>
#include <stdlib.h>

static int failures = 0;

static void check(int cond, const char *what) {
    if (!cond) {
        fprintf(stderr, "FAIL: %s\n", what);
        failures++;
    } else {
        printf("PASS: %s\n", what);
    }
}

#define MAX_COLLECT 64

typedef struct {
    size_t n;
    uint16_t code[MAX_COLLECT];
    uint64_t ts[MAX_COLLECT];
    size_t plen[MAX_COLLECT];
    uint8_t p0[MAX_COLLECT];      /* first payload byte, so a wrong offset shows */
    bool wrapped[MAX_COLLECT];
} collect_t;

static void collect_cb(const diag_log_record_t *rec, void *user) {
    collect_t *c = (collect_t *)user;
    if (c->n >= MAX_COLLECT)
        return;
    c->code[c->n] = rec->log_code;
    c->ts[c->n] = rec->ts64;
    c->plen[c->n] = rec->payload_len;
    c->p0[c->n] = rec->payload_len ? rec->payload[0] : 0;
    c->wrapped[c->n] = rec->from_wrapper;
    c->n++;
}

/* Build a complete on-wire frame: escape(body || crc16(body)) || 0x7E.
 * Returns the wire length. `body` starts with the opcode. */
static size_t build_frame(const uint8_t *body, size_t blen, uint8_t *out, size_t outcap) {
    return diag_hdlc_build(body[0], body + 1, blen - 1, out, outcap);
}

/* A minimal but REAL-SHAPED LOG_F body: cmd, pending, outer_len, inner_len,
 * log_code, ts64, payload. outer_len == total - 4 keeps it well-formed. */
static size_t make_log_f(uint16_t code, uint64_t ts, const uint8_t *payload,
                         size_t plen, uint8_t *out) {
    size_t total = LOG_F_MIN_LEN + plen;
    memset(out, 0, total);
    out[0] = OPCODE_LOG_F;
    out[1] = 0x00;
    out[2] = (uint8_t)((total - 4) & 0xFF);
    out[3] = (uint8_t)(((total - 4) >> 8) & 0xFF);
    out[4] = out[2];
    out[5] = out[3];
    out[6] = (uint8_t)(code & 0xFF);
    out[7] = (uint8_t)(code >> 8);
    for (int i = 0; i < 8; i++)
        out[LOG_F_TS64_OFFSET + i] = (uint8_t)((ts >> (8 * i)) & 0xFF);
    if (plen)
        memcpy(out + LOG_F_MIN_LEN, payload, plen);
    return total;
}

/* Wrap a complete inner LOG_F body in a 0x98 multi-radio envelope. */
static size_t make_wrapped(const uint8_t *inner, size_t ilen, uint8_t *out) {
    memset(out, 0, MULTI_RADIO_WRAPPER_OFFSET);
    out[0] = OPCODE_MULTI_RADIO;
    out[1] = 0x01;                 /* radio_id */
    memcpy(out + MULTI_RADIO_WRAPPER_OFFSET, inner, ilen);
    return MULTI_RADIO_WRAPPER_OFFSET + ilen;
}

int main(void) {
    uint8_t body[512], wire[4096];
    size_t wirelen = 0;

    /* ---- Frame 1: bare 0x10 LOG_F, log code 0xB192, payload with a 0x7E and a
     * 0x7D in it so the escape path is exercised on real content (not just on
     * the CRC bytes). */
    {
        const uint8_t payload[] = {0x7E, 0x7D, 0xAB, 0x01};
        size_t blen = make_log_f(0xB192, 0x0102030405060708ULL, payload, sizeof(payload), body);
        wirelen += build_frame(body, blen, wire + wirelen, sizeof(wire) - wirelen);
    }
    /* ---- Frame 2: a NON-LOG opcode (0x79 F3). Must be counted, never emitted. */
    {
        const uint8_t f3[] = {0x79, 0x01, 0x02, 0x03, 0x04};
        wirelen += build_frame(f3, sizeof(f3), wire + wirelen, sizeof(wire) - wirelen);
    }
    /* ---- Frame 3: 0x98-wrapped inner 0x10, log code 0xB97F. */
    {
        uint8_t inner[256], env[300];
        const uint8_t payload[] = {0x0A, 0x00, 0xEE};
        size_t ilen = make_log_f(0xB97F, 0x00000000DEADBEEFULL, payload, sizeof(payload), inner);
        size_t elen = make_wrapped(inner, ilen, env);
        wirelen += build_frame(env, elen, wire + wirelen, sizeof(wire) - wirelen);
    }

    const size_t total_wire = wirelen;

    /* 1. Whole-buffer decode. */
    collect_t c;
    diag_logstream_t s;
    memset(&c, 0, sizeof(c));
    diag_logstream_init(&s);
    diag_logstream_feed(&s, wire, total_wire, collect_cb, &c);
    diag_logstream_flush(&s, collect_cb, &c);

    check(c.n == 2, "two LOG records extracted (the 0x79 F3 frame is not one)");
    check(c.n == 2 && c.code[0] == 0xB192 && c.code[1] == 0xB97F, "log codes in stream order");
    check(c.n == 2 && c.ts[0] == 0x0102030405060708ULL, "ts64 read little-endian from offset 8");
    check(c.n == 2 && c.plen[0] == 4 && c.p0[0] == 0x7E,
          "payload starts at offset 16 and survives the escape round trip");
    check(c.n == 2 && c.wrapped[0] == false && c.wrapped[1] == true,
          "from_wrapper distinguishes the 0x98-enveloped record");
    check(s.stats.crc_ok == 3 && s.stats.crc_bad == 0, "all three frames CRC-verified");
    check(s.stats.log_records == 2 && s.stats.log_records_from_wrapper == 1,
          "stats count the wrapper-sourced record separately");

    /* 2. THE chunking-invariance property. A live read() splits wherever the
     * kernel says, including mid-frame and mid-escape-pair, so the record
     * sequence must not depend on it. Test EVERY single split point, then a
     * byte-at-a-time feed. */
    int chunk_ok = 1;
    for (size_t cut = 0; cut <= total_wire; cut++) {
        collect_t cc;
        diag_logstream_t ss;
        memset(&cc, 0, sizeof(cc));
        diag_logstream_init(&ss);
        diag_logstream_feed(&ss, wire, cut, collect_cb, &cc);
        diag_logstream_feed(&ss, wire + cut, total_wire - cut, collect_cb, &cc);
        diag_logstream_flush(&ss, collect_cb, &cc);
        if (cc.n != c.n || memcmp(cc.code, c.code, sizeof(uint16_t) * c.n) != 0 ||
                memcmp(cc.ts, c.ts, sizeof(uint64_t) * c.n) != 0 ||
                memcmp(cc.plen, c.plen, sizeof(size_t) * c.n) != 0) {
            fprintf(stderr, "  chunking divergence at cut=%zu (n=%zu vs %zu)\n",
                    cut, cc.n, c.n);
            chunk_ok = 0;
            break;
        }
    }
    check(chunk_ok, "record sequence is identical for every 2-way chunk split");

    {
        collect_t cc;
        diag_logstream_t ss;
        memset(&cc, 0, sizeof(cc));
        diag_logstream_init(&ss);
        for (size_t i = 0; i < total_wire; i++)
            diag_logstream_feed(&ss, wire + i, 1, collect_cb, &cc);
        diag_logstream_flush(&ss, collect_cb, &cc);
        check(cc.n == c.n && memcmp(cc.code, c.code, sizeof(uint16_t) * c.n) == 0,
              "byte-at-a-time feed yields the same records");
    }

    /* 3. Mid-stream join. A live DIAG port is almost always opened mid-frame, so
     * the first partial frame must be discarded without eating the next one. */
    {
        collect_t cc;
        diag_logstream_t ss;
        memset(&cc, 0, sizeof(cc));
        diag_logstream_init(&ss);
        /* Start 5 bytes into frame 1: its delimiter terminates a garbage frame. */
        diag_logstream_feed(&ss, wire + 5, total_wire - 5, collect_cb, &cc);
        diag_logstream_flush(&ss, collect_cb, &cc);
        check(cc.n == 1 && cc.code[0] == 0xB97F,
              "joining mid-frame drops only the partial frame, not the ones after it");
    }

    /* 4. A corrupt frame must be REJECTED, not decoded. This is the difference
     * that matters most on a live port: without the CRC gate a flipped byte in
     * a LOG_F header reaches a decode leg as a real record. */
    {
        collect_t cc;
        diag_logstream_t ss;
        uint8_t bad[4096];
        memcpy(bad, wire, total_wire);
        /* Corrupt one byte of frame 1, choosing a flip that cannot itself change
         * the FRAMING -- introducing a 0x7E or 0x7D would test the wrong thing
         * (a re-split stream, not a bad CRC). Scan for a byte whose flipped form
         * is neither, staying inside frame 1 (before its 0x7E delimiter). */
        size_t corrupt_at = 0;
        for (size_t i = 1; i < total_wire; i++) {
            if (bad[i] == HDLC_FLAG)
                break;                          /* end of frame 1 */
            uint8_t f = bad[i] ^ 0x40;
            if (bad[i] != 0x7D && f != HDLC_FLAG && f != 0x7D) {
                corrupt_at = i;
                break;
            }
        }
        check(corrupt_at != 0, "found a framing-neutral byte to corrupt");
        bad[corrupt_at] ^= 0x40;
        memset(&cc, 0, sizeof(cc));
        diag_logstream_init(&ss);
        diag_logstream_feed(&ss, bad, total_wire, collect_cb, &cc);
        diag_logstream_flush(&ss, collect_cb, &cc);
        check(ss.stats.crc_bad == 1, "a bit-flipped frame fails CRC");
        check(cc.n == 1 && cc.code[0] == 0xB97F,
              "the corrupt frame yields no record; later frames still decode");
    }

    /* 5. A LOG_F too short to hold its own header is declined, not read past.
     * Guards the extract_log_f length gate -- reading log_code at offset 6 from
     * a 5-byte frame would be an out-of-bounds read of attacker-adjacent data. */
    {
        collect_t cc;
        diag_logstream_t ss;
        uint8_t shortw[64];
        const uint8_t stub[] = {0x10, 0x00, 0x02, 0x00, 0x02, 0x00};  /* 6 B, < 16 */
        size_t n = build_frame(stub, sizeof(stub), shortw, sizeof(shortw));
        memset(&cc, 0, sizeof(cc));
        diag_logstream_init(&ss);
        diag_logstream_feed(&ss, shortw, n, collect_cb, &cc);
        diag_logstream_flush(&ss, collect_cb, &cc);
        check(ss.stats.crc_ok == 1 && cc.n == 0,
              "a CRC-valid but under-length LOG_F yields no record");
    }

    /* 6. Oversize frame: dropped and counted, and the stream RESYNCS. This is
     * the one deliberate divergence from the Python (which has no frame ceiling),
     * so it is pinned rather than left to chance. */
    {
        collect_t cc;
        diag_logstream_t ss;
        static uint8_t big[DIAG_LOGSTREAM_FRAME_MAX + 4096];
        memset(big, 0xAA, sizeof(big));       /* no 0x7E, no 0x7D inside */
        big[sizeof(big) - 1] = HDLC_FLAG;     /* terminate the oversize frame */
        memset(&cc, 0, sizeof(cc));
        diag_logstream_init(&ss);
        diag_logstream_feed(&ss, big, sizeof(big), collect_cb, &cc);
        diag_logstream_feed(&ss, wire, total_wire, collect_cb, &cc);
        diag_logstream_flush(&ss, collect_cb, &cc);
        check(ss.stats.oversize_dropped == 1, "the oversize frame is dropped and counted");
        check(cc.n == 2 && cc.code[0] == 0xB192,
              "the stream resyncs: frames after an oversize frame decode normally");
    }

    /* 7. Back-to-back delimiters (idle fill) produce nothing and do not desync. */
    {
        collect_t cc;
        diag_logstream_t ss;
        uint8_t pad[4096];
        size_t n = 0;
        for (int i = 0; i < 4; i++)
            pad[n++] = HDLC_FLAG;
        memcpy(pad + n, wire, total_wire);
        n += total_wire;
        memset(&cc, 0, sizeof(cc));
        diag_logstream_init(&ss);
        diag_logstream_feed(&ss, pad, n, collect_cb, &cc);
        diag_logstream_flush(&ss, collect_cb, &cc);
        check(cc.n == 2, "leading idle-fill delimiters are ignored");
    }

    if (failures) {
        fprintf(stderr, "\n%d check(s) FAILED\n", failures);
        return 1;
    }
    printf("\nRESULT: all diag_logstream checks passed\n");
    return 0;
}

#endif /* DIAG_LOGSTREAM_SELFTEST */

/* -----------------------------------------------------------------------
 * Cross-check dump driver
 * -----------------------------------------------------------------------
 * Build with -DDIAG_LOGSTREAM_DUMP. Reads a raw-HDLC capture and prints one
 * line per extracted record, in stream order:
 *
 *     <log_code:04X> <ts64> <payload_len> <first-8-payload-bytes hex> <T|W>
 *
 * The synthetic selftest above proves the extractor is self-consistent; it
 * cannot prove it agrees with another extractor on a real capture. This driver
 * is the vehicle for that comparison: diff its output line-for-line against any
 * other (log_code, ts64, payload) extractor run over the same capture.
 *
 * Reads in 64 KiB chunks -- the same size diag_reader_t uses -- so the
 * comparison exercises the streaming residual path, not a whole-buffer decode.
 */
#ifdef DIAG_LOGSTREAM_DUMP

#include <stdio.h>

static void dump_cb(const diag_log_record_t *rec, void *user) {
    (void)user;
    printf("%04X %llu %zu ", rec->log_code,
           (unsigned long long)rec->ts64, rec->payload_len);
    size_t n = rec->payload_len < 8 ? rec->payload_len : 8;
    for (size_t i = 0; i < n; i++)
        printf("%02x", rec->payload[i]);
    if (n == 0)
        printf("-");
    printf(" %c\n", rec->from_wrapper ? 'W' : 'T');
}

int main(int argc, char **argv) {
    if (argc != 2) {
        fprintf(stderr, "usage: %s <raw-hdlc-capture>\n", argv[0]);
        return 2;
    }
    FILE *fp = fopen(argv[1], "rb");
    if (!fp) {
        perror(argv[1]);
        return 2;
    }

    static diag_logstream_t s;
    static uint8_t buf[65536];
    diag_logstream_init(&s);

    size_t n;
    while ((n = fread(buf, 1, sizeof(buf), fp)) > 0)
        diag_logstream_feed(&s, buf, n, dump_cb, NULL);
    diag_logstream_flush(&s, dump_cb, NULL);
    fclose(fp);

    fprintf(stderr,
            "frames=%llu crc_ok=%llu crc_bad=%llu short=%llu "
            "records=%llu from_wrapper=%llu oversize=%llu\n",
            (unsigned long long)s.stats.frames_seen,
            (unsigned long long)s.stats.crc_ok,
            (unsigned long long)s.stats.crc_bad,
            (unsigned long long)s.stats.skipped_short,
            (unsigned long long)s.stats.log_records,
            (unsigned long long)s.stats.log_records_from_wrapper,
            (unsigned long long)s.stats.oversize_dropped);
    return 0;
}

#endif /* DIAG_LOGSTREAM_DUMP */
