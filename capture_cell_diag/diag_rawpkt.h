/* diag_rawpkt.h - the raw DIAG byte stream as Kismet packets.
 *
 * celldiag emits the raw DIAG stream INTO Kismet as ordinary packets
 * (cf_send_data) with a private link type, so the server's kismetdb `packets`
 * table -- and a pcapng log, if one is enabled -- carries the stream itself, not
 * only the decoded observations. `rawlog=` stays as the debug-outside file tee;
 * this is the in-db copy (raw AT goes to `data`/RawAT, raw DIAG to
 * `packets`/DLT).
 *
 * ---------------------------------------------------------------------------
 * THE CONTRACT (what a reader of the `packets` table may rely on)
 * ---------------------------------------------------------------------------
 *
 * dlt      DIAG_RAWPKT_DLT = 147, LINKTYPE_USER0 (the private-use range). No
 *          registered link type carries raw HDLC-framed Qualcomm DIAG, and the
 *          GSMTAP QC_DIAG subtype carries a DEFRAMED message -- which cannot
 *          preserve the byte-identical .hdlc equivalence this exists for.
 *
 * packet   a 24-byte slice header, then a slice of the raw stream:
 *
 *     off len  field
 *       0   4  magic        "CDRH" (celldiag raw HDLC)
 *       4   1  version      1
 *       5   1  flags        bit0 DIAG_RAWPKT_FLAG_FRAGMENT, bit1 DIAG_RAWPKT_FLAG_END,
 *                           others 0
 *       6   2  header_len   24, little-endian -- skip this many bytes to reach
 *                           the payload, so a later version may append fields
 *       8   8  session_id   LE; host CLOCK_REALTIME ns when this stream began
 *      16   8  offset       LE; byte offset of payload[0] within the stream
 *      24   -  payload      the bytes exactly as read from the DIAG port:
 *                           HDLC-escaped, CRC and 0x7E terminators included
 *
 * The invariant: for one (datasource, session_id), sorting the slices by
 * `offset` and concatenating their payloads reproduces the stream byte for
 * byte -- the same bytes a `rawlog=` tee opened at the start of the capture
 * writes. A gap between one slice's (offset + payload length) and the next
 * slice's offset is EXACTLY the bytes that were not delivered.
 *
 * END. A gap needs a delivered slice AFTER it, so without a marker a
 * slice dropped after the last delivered one leaves no trace in the offsets: a
 * stream that lost its tail reads as whole. So a stream that ends closes with
 * one END slice: flags DIAG_RAWPKT_FLAG_END, an EMPTY payload, and `offset` =
 * the stream's final length -- every byte read, delivered or dropped. It is sent
 * after the flushed residual, so tail loss becomes an ordinary gap, the one
 * between the last delivered slice and END. A reader:
 *   END offset == delivered end   the stream is whole (bar any interior gap)
 *   END offset >  delivered end   exactly that many trailing bytes were lost
 *   END offset <  delivered end   inconsistent; the END is not believable
 *   no END                        the end is UNCONFIRMED
 * END is only sent where the capture reaches its teardown: replay EOF, a dead
 * port or helper, and a Kismet-driven stop under the graceful close, which asks
 * the source to close and waits for its teardown. REST close_source, a server
 * SIGTERM, and a SIGINT to the whole process group (a terminal Ctrl-C) all leave
 * each stream byte-identical to its tee, ending in a confirmed END.
 * Without the graceful close (a close out of its grace,
 * datasource_graceful_close=false) a stop sends no END, and the tail is
 * short by at most the read(s) in flight when the pipe closes: the capture
 * framework wakes its I/O loop on every commit, so a slice reaches the
 * server ~0.1 ms after the read. Those reads are not dropped, so no RawDiagDrop
 * row records them: "no END" means "unconfirmed: whole, or short by the reads
 * at the close". A source that DIED is not this case: see RawDiagAbort below.
 *
 * RawDiagDrop. The first time a slice is dropped, the source also sends
 * one `data`-table row, type "RawDiagDrop", retried until it lands -- the same
 * policy as its "slice DROPPED" ERROR message, which goes out only after it.
 * The message lands in the kismetdb `messages` table, which records no
 * datasource; this row does, so a reader can attribute the loss:
 *     {"schema":"raw-diag-drop/1","session_id":N,
 *      "first_drop_offset":X,"first_drop_len":L}
 * X and L are the first dropped slice's offset and payload length. A reader that
 * finds the row knows the stream is holed even when no gap shows -- a RING-FULL
 * drop at the tail of a live stream. What stays invisible: the reads in flight
 * at a Kismet-driven stop (above; not a drop), and a first drop in the last
 * moments before one, when neither the row nor END can land.
 *
 * RawDiagAbort. A source that DIES mid-stream reaches no teardown: its
 * helper killed by the capture framework's 15 s PING watchdog while the server
 * stalled, a crash, an OOM kill. So there is no END, and the helper's out-ring
 * (up to 4 MiB) dies with it -- queued, not dropped, so no RawDiagDrop row
 * either: megabytes of a stream can be lost that way with no gap, no END and no
 * row, and a reader would pass it under --strict. The helper cannot write that loss down -- the server is, by
 * definition, not reading it -- so the SERVER does. The celldiag datasource
 * follows each raw session from its slice headers, and when the source fails
 * mid-session (its IPC errors while the server is not stopping) after data but
 * before END, it writes one `data`-table row for that datasource:
 *     {"schema":"raw-diag-abort/1","session_id":N,"delivered_end":X,
 *      "slices":K,"reason":"..."}
 * N is the session, X one past the highest stream byte the server received for
 * it, K its data slices, and reason the source's error ("IPC connection
 * closed", ...). A reader treats a session with this row and no END as having
 * lost an unknown tail after X, and refuses it under --strict. It is written
 * ONLY on that error path: a stop the server asked for is not a death (with the
 * graceful close it ends in END), and a close that ran out of its grace
 * or ran with graceful close off stays the plain "no END" case.
 *
 * Order comes from `offset`, never from row order or timestamps. Kismet
 * hands packets to one of >= 4 worker threads at random and each inserts its
 * own rows, a remote source's timestamps are overwritten on arrival
 * (override_remote_timestamp=true), and kismetdb_to_pcap selects with no ORDER
 * BY. Nothing between here and the file preserves stream order, so the slice
 * carries its own.
 *
 * Do not feed a packet's bytes to a DIAG deframer as they are. The header is
 * binary and may contain 0x7E; a reader that skips it by accident merges it
 * into the slice's first frame, which then fails its CRC -- one lost frame per
 * packet, silently. Strip header_len bytes first.
 *
 * Slice boundaries. Every slice ends immediately after a 0x7E, i.e. holds whole
 * HDLC frames only, EXCEPT one flagged FRAGMENT: a run of more than
 * DIAG_RAWPKT_PAYLOAD_MAX bytes containing no 0x7E (not DIAG), or the partial
 * frame left over when a stream ends. So a dropped slice costs whole frames and
 * never corrupts the deframing of its neighbours. A slice holds the whole
 * frames completed by ONE host read (a read larger than the cap is cut, still
 * at a 0x7E), which bounds the per-row overhead -- a kismetdb row carries
 * ~150-200 bytes of fixed columns, and the median DIAG frame is 26-107 bytes,
 * so one row per frame would store the stream 2-8x over.
 *
 * DIAG_RAWPKT_PAYLOAD_MAX is bounded by the SERVER, not by pcap. Kismet
 * refuses any IPC frame over MAX_EXTERNAL_FRAME_LEN (16384, kis_external.h) --
 * and refuses it by erroring the whole SOURCE, not by dropping the frame. A
 * slice rides one frame with the v3 header, the msgpack packet block, this
 * 24-byte header and, if the capture runs with a fixed GPS, a GPS block. 12 KiB
 * leaves 4 KiB for all of that and is still larger than the largest DIAG frame
 * observed (8,050 B), so real frames are never fragmented. Do not size it to
 * pcapng's 65535-byte snaplen: offline tests pass, and a real server kills the
 * source on the first slice. celltools/tests/test_celldiag_raw_packets.py pins
 * the budget against kis_external.h.
 *
 * libc-only (no Kismet dependency): unit-tested standalone in test_diag_rawpkt.c.
 */
#ifndef DIAG_RAWPKT_H
#define DIAG_RAWPKT_H

#include <stddef.h>
#include <stdint.h>

#define DIAG_RAWPKT_DLT           147u   /* LINKTYPE_USER0 */
#define DIAG_RAWPKT_MAGIC         "CDRH"
#define DIAG_RAWPKT_VERSION       1u
#define DIAG_RAWPKT_HDR_LEN       24u
#define DIAG_RAWPKT_FLAG_FRAGMENT 0x01u
#define DIAG_RAWPKT_FLAG_END      0x02u  /* empty payload; offset = final length */
#define DIAG_RAWPKT_DROP_TYPE     "RawDiagDrop"
#define DIAG_RAWPKT_DROP_SCHEMA   "raw-diag-drop/1"
#define DIAG_RAWPKT_ABORT_TYPE    "RawDiagAbort"       /* written by the SERVER */
#define DIAG_RAWPKT_ABORT_SCHEMA  "raw-diag-abort/1"
#define DIAG_RAWPKT_PAYLOAD_MAX   12288u /* see the server-frame note above */
#define DIAG_RAWPKT_PACKET_MAX    (DIAG_RAWPKT_HDR_LEN + DIAG_RAWPKT_PAYLOAD_MAX)

/* Deliver one finished packet (header + payload, `len` bytes). Return nonzero
 * if it was delivered, 0 if it was dropped: the slicer counts both and moves
 * on either way, so a drop is a gap in `offset`, never a stall. The buffer is
 * only valid for the duration of the call. */
typedef int (*diag_rawpkt_emit_fn)(void *ctx, const uint8_t *pkt, size_t len);

typedef struct {
    /* The packet being assembled: header space, then the payload
     * accumulator, so a finished slice goes out without a copy. */
    uint8_t  pkt[DIAG_RAWPKT_PACKET_MAX];
    size_t   len;             /* payload bytes accumulated */
    size_t   commit;          /* payload length through the last 0x7E; 0 = none */
    uint64_t session_id;
    uint64_t offset;          /* stream offset of the accumulator's first byte */

    uint64_t slices;          /* delivered */
    uint64_t bytes;           /* payload bytes delivered */
    uint64_t dropped_slices;
    uint64_t dropped_bytes;
    uint64_t fragments;       /* delivered or not, slices flagged FRAGMENT */
    uint64_t first_drop_offset;  /* valid once dropped_slices > 0 */
    uint64_t first_drop_len;
    int      end_sent;        /* 0 not yet, 1 END delivered, -1 END dropped */
} diag_rawpkt_t;

typedef struct {
    uint8_t  version;
    uint8_t  flags;
    uint16_t header_len;
    uint64_t session_id;
    uint64_t offset;
    const uint8_t *payload;
    size_t   payload_len;
} diag_rawpkt_hdr_t;

void diag_rawpkt_init(diag_rawpkt_t *s, uint64_t session_id);

/* Append bytes read from the DIAG port, emitting every slice they complete.
 * On return the accumulator holds at most the one partial frame after the
 * last 0x7E seen. */
void diag_rawpkt_feed(diag_rawpkt_t *s, const uint8_t *buf, size_t len,
                      diag_rawpkt_emit_fn emit, void *ctx);

/* Emit whatever partial frame is left, flagged FRAGMENT. No-op when nothing
 * is pending. */
void diag_rawpkt_flush(diag_rawpkt_t *s, diag_rawpkt_emit_fn emit, void *ctx);

/* End of stream: flush, then send the END slice (empty payload, offset = the
 * final stream length). Once only; a second call does nothing. END is not
 * counted in `slices` / `bytes` -- those stay data -- and its fate is recorded
 * in `end_sent`. */
void diag_rawpkt_end(diag_rawpkt_t *s, diag_rawpkt_emit_fn emit, void *ctx);

/* The RawDiagDrop record (schema above) for this stream's first drop, into
 * `buf`. Returns 0, or -1 if nothing has been dropped or `cap` is too small. */
int diag_rawpkt_drop_json(const diag_rawpkt_t *s, char *buf, size_t cap);

/* Decode a packet built by this module. Returns 0 and fills `out` (payload
 * points into `pkt`), or -1 for a wrong magic, an unknown version, a length
 * that does not fit, or an END slice that carries a payload. */
int diag_rawpkt_parse(const uint8_t *pkt, size_t len, diag_rawpkt_hdr_t *out);

#endif /* DIAG_RAWPKT_H */
