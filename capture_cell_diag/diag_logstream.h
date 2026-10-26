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

    Streaming raw-HDLC -> DIAG LOG record extractor.

    WHY THIS EXISTS. diag_native_decode.{h,cpp} makes the diagspec
    cell_observation legs callable from THIS process (the helper), but a leg
    takes a log-code-stripped LOG_F payload, and the helper reads a raw HDLC
    byte stream off the DIAG port:

        raw HDLC bytes  ->  (log_code, ts64, payload)

    diag_capture.c returns whole HDLC frames of any opcode and does not unwrap
    the QShrink4 / QSR envelopes (0x98 / 0x99 / 0x92) that SDX55/62/72
    basebands pack LOG_F records into.

    This module does the framing, CRC check and unwrapping in C.

    THE STREAMING CONTRACT (and why splitting on a raw 0x7E is safe). HDLC
    byte-stuffs any 0x7E occurring inside a frame as 0x7D 0x5E, so a literal 0x7E
    in the stream is ALWAYS a frame delimiter, never frame content. We accumulate
    a `residual` of the bytes after the last delimiter seen; a frame spanning two
    reads simply stays there until its delimiter arrives. The residual is bounded
    by one in-flight frame, so memory does not grow with stream length.

    The equivalence property the selftest pins is that the emitted record
    sequence is INDEPENDENT OF CHUNKING:

        feed(a); feed(b); flush()   ==   feed(a || b); flush()

    for any split. A live read() boundary lands wherever the kernel says, so a
    chunking-sensitive extractor would decode differently on every run.

    NOT a decoder: this produces (log_code, ts64, payload) and nothing more. What
    the payload MEANS is diag_native_decode()'s business.
*/

#ifndef __DIAG_LOGSTREAM_H__
#define __DIAG_LOGSTREAM_H__

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

/* Largest HDLC frame we will reassemble. Qualcomm DIAG bounds a frame well under
 * this (the largest real-capture LOG_F in the corpus is ~2 KB; 0x80 QShrink4
 * bulk batches run to ~4 KB), so a frame that exceeds it is a desynced or
 * corrupt stream, not a legitimate record. Such a frame is DROPPED and counted
 * (oversize_dropped) rather than truncated: a truncated frame would fail CRC
 * anyway, but counting it separately keeps "the stream is garbage" visibly
 * distinct from "this modem emits bad CRCs". */
#define DIAG_LOGSTREAM_FRAME_MAX 32768

/* One extracted DIAG LOG record. `payload` points INTO the extractor's internal
 * frame buffer and is valid only for the duration of the callback -- copy it if
 * you need it to outlive the call. This mirrors the Python's yield-per-record
 * shape without allocating. */
typedef struct {
    uint16_t log_code;
    uint64_t ts64;              /* raw since-boot 1.25 ms tick; NOT a wall clock */
    const uint8_t *payload;     /* log-code-stripped LOG_F payload (offset 16 on) */
    size_t payload_len;
    bool from_wrapper;          /* true iff unwrapped from a 0x98 multi-radio envelope */
} diag_log_record_t;

/* Invoked once per extracted record, in stream order. */
typedef void (*diag_logstream_cb)(const diag_log_record_t *rec, void *user);

/* Running counters. Exposed so a caller can report "how much of the stream did the
 * native path actually see" instead of asserting it saw all of it. */
typedef struct {
    uint64_t frames_seen;               /* delimiter-terminated frames examined */
    uint64_t crc_ok;
    uint64_t crc_bad;
    uint64_t skipped_short;             /* unescaped to < 3 bytes */
    uint64_t log_records;               /* records handed to the callback */
    uint64_t log_records_from_wrapper;  /* subset that came out of a 0x98 envelope */
    uint64_t oversize_dropped;          /* frames exceeding DIAG_LOGSTREAM_FRAME_MAX */
} diag_logstream_stats_t;

typedef struct {
    uint8_t residual[DIAG_LOGSTREAM_FRAME_MAX];
    size_t residual_len;
    /* Set when the in-flight frame overflowed the residual buffer. The rest of
     * that frame is discarded up to its delimiter, so one oversize frame cannot
     * desync every frame after it. */
    bool residual_overflow;
    uint8_t frame[DIAG_LOGSTREAM_FRAME_MAX];   /* unescape scratch */
    diag_logstream_stats_t stats;
} diag_logstream_t;

/* Zero the extractor. Must be called before the first feed. */
void diag_logstream_init(diag_logstream_t *s);

/* Consume `len` bytes of raw HDLC, invoking `cb` for every complete LOG record
 * whose terminating 0x7E arrived in (or before) this chunk. `cb` may be NULL:
 * the frames are then CRC-checked and counted in `stats` and nothing is
 * extracted -- a CRC census. A zero-length feed
 * is a no-op, NOT an EOF signal -- matching the Python, where an empty chunk is
 * skipped and only the iterable ending means EOF. */
void diag_logstream_feed(diag_logstream_t *s, const uint8_t *buf, size_t len,
                         diag_logstream_cb cb, void *user);

/* Process whatever is left in the residual as a final frame (the Python's
 * flush_tail=True). Call at end-of-stream; it is what makes the streaming path
 * byte-equivalent to a whole-buffer decode of the same bytes. Idempotent. */
void diag_logstream_flush(diag_logstream_t *s, diag_logstream_cb cb, void *user);

#ifdef __cplusplus
}
#endif

#endif /* __DIAG_LOGSTREAM_H__ */
