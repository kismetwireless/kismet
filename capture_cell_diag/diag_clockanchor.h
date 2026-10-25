/* diag_clockanchor.h - host<->modem-ts64 clock anchor for the celldiag source
 * (the DIAG instance of the shared ClockAnchor record format).
 *
 * A DIAG frame's only timestamp is the modem's own ts64 (Q16 1.25 ms ticks).
 * Without an anchor, absolute host UTC is reachable only through a GNSS 0x1476
 * in the same stream, which an LTE-only / GNSS-off drive does not carry. So the
 * running capture periodically asks the modem "what time is it?" with DIAG_TS_F
 * (opcode 0x1D, empty body; reply = 0x1D + 8-byte LE ts64) and pairs the answer
 * with the host clock. Each pair is a "ClockAnchor" record:
 *
 *   {"schema": "clock-anchor/1", "transport": "diag", "source_name": "<uuid>",
 *    "seq": 0, "edge": "start", "host_utc": "2026-09-22T12:00:00.123456Z",
 *    "host_mono_ns": 123, "source_clock_kind": "modem_ts64",
 *    "source_clock_value": "<ts64 as decimal digits>", "host_rtt_ns": 3500000}
 *
 * The first nine fields are exactly cellat's (capture_cell_at/clockanchor.h)
 * in the same order and spelling, so skew analysis is transport-uniform.
 * DIAG adds `host_rtt_ns`, because unlike AT+CCLK? (whole seconds) the ts64
 * resolves ~19 ns and the round trip IS the error bar:
 *
 *   - host_utc / host_mono_ns are the MIDPOINT of [request written, reply read].
 *     The modem read its clock somewhere in that window, so the midpoint is
 *     wrong by at most host_rtt_ns / 2. Under a log flood the reply queues
 *     behind log frames and the window stretches asymmetrically -- that is
 *     visible in host_rtt_ns, and a consumer can weight or drop wide anchors.
 *   - source_clock_value is a decimal STRING, not a JSON number: a GPS-epoch
 *     ts64 is ~7.7e16, past 2^53, so any double-based JSON reader would round
 *     it. cellat's value is a string too, so the field has one type across
 *     transports.
 *   - The raw ts64 is carried un-interpreted. Whether it is GPS-absolute or
 *     device uptime (an undisciplined time-of-day) is decided by the
 *     consumer, which also owns the 18 s leap handling -- this layer does not
 *     guess.
 *
 * WHERE THE RECORDS GO. Every anchor is a type="ClockAnchor" kismetdb `data`
 * row (cf_send_json) AND a line appended to `<rawlog>.clock_anchor.jsonl` next
 * to the .hdlc tee -- the same bytes -- so a forked-out .hdlc can be
 * wall-clocked without the kismetdb.
 *
 * This file is libc-only, like diag_capmeta.c and diag_rawlog.c: the request
 * builder, the reply scanner, the record formatter and the sidecar helpers are
 * unit-tested standalone in test_diag_clockanchor.c
 * (`make -f standalone.mk check` in this directory).
 */
#ifndef DIAG_CLOCKANCHOR_H
#define DIAG_CLOCKANCHOR_H

#include <stddef.h>
#include <stdint.h>
#include <sys/time.h>

#define DIAG_TS_F_OPCODE 0x1D

/* Build the complete wire frame for a DIAG_TS_F request (opcode, no body, CRC,
 * 0x7E terminator). Returns the frame length, or 0 if it does not fit. */
size_t diag_clockanchor_build_request(uint8_t *out, size_t cap);

typedef enum {
    DIAG_TSF_NONE = 0,       /* no reply in these bytes (yet) */
    DIAG_TSF_RESPONSE = 1,   /* a CRC-valid 0x1D reply; *ts64_out is set */
    DIAG_TSF_REJECTED = 2,   /* 0x13/0x14/0x15 echoing 0x1D: the modem refuses */
} diag_tsf_result_t;

/* Longest escaped frame the scanner buffers. A TS_F reply is 9 bytes + 2 CRC,
 * at most 22 once every byte is stuffed; anything longer is a LOG/F3 frame and
 * is skipped to its terminator without being buffered. */
#define DIAG_TSF_SCAN_MAX 32

/* Incremental DIAG_TS_F reply scanner over the raw (still-escaped) HDLC byte
 * stream. Zero-initialise, or diag_tsf_scan_reset(), before the first feed.
 *
 * It needs no frame sync: a frame already in flight when the request went out
 * contributes a partial prefix that fails its CRC (or overruns the buffer) and
 * is discarded at its 0x7E, so the reply is recognised whether it is the first
 * byte after the request or buried in a flood. */
typedef struct {
    uint8_t buf[DIAG_TSF_SCAN_MAX];
    size_t  len;
    int     overlong;   /* current frame outgrew buf; skip to the next 0x7E */
} diag_tsf_scan_t;

void diag_tsf_scan_reset(diag_tsf_scan_t *s);

/* Feed buf[0..len). Returns the FIRST reply (or rejection) completed inside
 * these bytes; bytes after it are consumed and ignored -- one request is
 * outstanding at a time, and the caller resets the scanner for the next.
 * On DIAG_TSF_RESPONSE, *ts64_out receives the 8-byte little-endian value. */
diag_tsf_result_t diag_tsf_scan_feed(diag_tsf_scan_t *s, const uint8_t *buf,
                                     size_t len, uint64_t *ts64_out);

/* Midpoint of a request/reply window: the wall clock at send plus half the
 * MONOTONIC elapsed time, so a wall-clock step (NTP) between send and receive
 * cannot skew it. mono_recv < mono_send is treated as a zero-length window. */
void diag_clockanchor_midpoint(const struct timeval *tv_send, uint64_t mono_send,
                               uint64_t mono_recv, struct timeval *tv_mid,
                               uint64_t *mono_mid);

/* ISO-8601 UTC with microseconds ("YYYY-MM-DDTHH:MM:SS.uuuuuuZ") -- the exact
 * format cellat's ClockAnchor host_utc uses (atlog_iso8601_from_tv). */
void diag_clockanchor_iso8601(char *out, size_t outsz, const struct timeval *tv);

/* Format ONE ClockAnchor record (with trailing '\n') into out. transport and
 * source_clock_kind are fixed ("diag", "modem_ts64"); source_name and edge are
 * JSON-escaped, NULL -> "". Returns 0, or -1 on overflow (record dropped). */
int diag_clockanchor_format_record(char *out, size_t outsz,
                                   const char *source_name, uint64_t seq,
                                   const char *edge, const char *host_utc,
                                   uint64_t host_mono_ns, uint64_t ts64,
                                   uint64_t host_rtt_ns);

/* `<rawlog_path>.clock_anchor.jsonl`. Returns 0, or -1 on NULL / overflow. */
int diag_clockanchor_sidecar_path(const char *rawlog_path, char *out,
                                  size_t outsz);

/* Append buf to path (O_APPEND|O_CREAT, 0644), open-write-close per record:
 * anchors are rare (one per clock_anchor_sec=), and reopening by NAME is what
 * makes the sidecar follow a runtime rawlog= redirect. Returns 0, -1 on error. */
int diag_clockanchor_append(const char *path, const char *buf, size_t len);

#endif /* DIAG_CLOCKANCHOR_H */
