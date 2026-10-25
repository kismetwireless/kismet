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
*/

/* kismetdb_to_hdlc — reconstruct a celldiag source's raw DIAG HDLC byte stream
 * (the `rawlog=` tee) from the kismetdb `packets` table: the parse side of the
 * celldiag raw-packet emitter.
 *
 * Sibling of kismetdb_to_atlog. That tool rebuilds the AT lane's sidecar from
 * `data` rows; this one rebuilds the DIAG lane's from `packets` rows, so a
 * drive whose raw DIAG lives only in the .kismet can be processed exactly like
 * a drive that also wrote a rawlog= .hdlc sidecar.
 *
 * The input contract is capture_cell_diag/diag_rawpkt.h, and its constants are
 * included from there rather than restated. Each DLT-147 packet is a 24-byte
 * "CDRH" slice header (version, flags, header_len, session_id, offset), then a
 * slice of the stream exactly as read from the port. For one (datasource,
 * session_id), the slices sorted by `offset` and concatenated ARE the stream.
 * The header parse below repeats diag_rawpkt_parse()'s checks, but the tool
 * does not link diag_rawpkt.c: that object belongs to capture_cell_diag's own
 * sub-make, and building it here as well would put one object path under two
 * makefiles with different flags. The celltools test that replays through the
 * real emitter pins that the two agree.
 *
 * Order comes from `offset` only, never from rowid, packetid or the
 * timestamps. Kismet hands every celldiag packet to a random worker thread
 * (assignment_id 0), packetid is assigned inside that worker, and a remote
 * source's timestamps are overwritten on arrival. None of those follow the
 * order the source sent the packets in.
 *
 * What is selected: `packets` rows with dlt == DIAG_RAWPKT_DLT (--dlt) whose
 * datasource has `datasources.typestring == "celldiag"` (--type).
 *
 * What is written: one .hdlc per (source, session), the payloads concatenated
 * in offset order, with each header stripped (a header left in the stream
 * would glue itself onto the slice's first frame and cost that frame its CRC).
 * No deframing, no CRC check, no re-escaping: that is the DIAG decoder's
 * job (e.g. kismet_cap_cell_diag's replay=).
 *
 * Integrity, from the offsets alone, per stream:
 *   gap       the next slice starts past the end of the last one. That many
 *             bytes were never delivered. Slices end on a 0x7E, so the missing
 *             bytes are whole frames and the frames around them still deframe.
 *   overlap   the next slice starts before the end of the last one. The slice
 *             is skipped; this should never happen.
 *   malformed a DLT-147 row that is not a valid v1 slice. The row is skipped.
 *   truncated a row stored shorter than packet_full_len.
 *   unaligned a slice not flagged FRAGMENT whose payload does not end in 0x7E
 *             (the contract says every such slice does).
 *   tail gap  the stream's END slice sits past the last delivered byte: that
 *             many trailing bytes were never delivered.
 *   bad END   END before the delivered data, or more than one END.
 *   drop row  a RawDiagDrop `data` row from the source for this session: it
 *             dropped slices, even if no gap shows them.
 *   abort row a RawDiagAbort `data` row the SERVER wrote for this session: the
 *             source died mid-stream (the helper's PING watchdog during a
 *             server stall, a crash), after data and before END, so an unknown
 *             tail -- up to its whole out-ring -- was lost with it.
 * Each is reported on stderr every time, not only with -v. --strict makes any
 * of them a failure (exit 3) before anything is written, which is what an
 * automated ingest wants. A replayed capture is lossless by design; a
 * live one can drop slices when the ring is full, and says so in a RawDiagDrop
 * row, in the source's messages and as a gap here.
 *
 * A gap needs a delivered slice AFTER it, so the offsets alone cannot show
 * slices dropped after the last delivered one: under a flood on a slow host,
 * the delivered slices can run contiguously from offset 0 while the tee holds
 * more than twice as many bytes, and an offsets-only reader would pass it under
 * --strict. Two witnesses close that (contract in diag_rawpkt.h):
 *   - END: a stream that reaches its teardown closes with an empty slice at its
 *     final length, so tail loss is an ordinary gap before it.
 *   - RawDiagDrop: the first drop is recorded as a `data` row, which is how a
 *     live drive stopped from Kismet without END (see below) still shows it
 *     lost its tail.
 * A stream with no END gets a NOTE that its end is unconfirmed -- and it may be
 * short: the read(s) in flight when the server closes the pipe are lost,
 * neither dropped (no RawDiagDrop row) nor ended. From an older helper without
 * the out-ring wakeup it is ~0.4-1 s short, stranded in the out-ring. With the
 * graceful close a Kismet-driven stop DOES end in END; none comes from a drive
 * recorded before it, a close that ran out of its grace, or
 * datasource_graceful_close=false. That is NOT a --strict failure -- it would
 * fail every older drive, and a gate that fails every drive gets switched off;
 * --require-end makes it one. A source that DIED mid-stream is different: the
 * server writes a RawDiagAbort row for it, and that IS refused.
 *
 * Exit status: 0 ok, 1 usage / input / ambiguity error, 2 no DIAG packets
 * (e.g. a drive from before the emitter existed, or rawpackets=off),
 * 3 --strict integrity failure.
 *
 * Deliberately opens the db READONLY and never VACUUMs/mutates it: a captured
 * .kismet is an artifact of record.
 */

#include "config.h"

#include <algorithm>
#include <map>
#include <string>
#include <vector>

#include <inttypes.h>
#include <string.h>
#include <stdio.h>
#include <errno.h>
#include <time.h>
#include <unistd.h>
#include <stdbool.h>
#include <stdlib.h>
#include <sys/types.h>
#include <sys/stat.h>

#include <sqlite3.h>

#include "getopt.h"
#include "nlohmann/json.hpp"
#include "capture_cell_diag/diag_rawpkt.h"

enum {
    EXIT_OK = 0,
    EXIT_ERR = 1,
    EXIT_NODATA = 2,
    EXIT_STRICT = 3,
};

void print_help(char *argv) {
    printf("Kismetdb to raw DIAG HDLC\n");
    printf("Reconstruct a celldiag source's raw DIAG HDLC byte stream (the\n"
           "`rawlog=` tee) from a KismetDB log's `packets` table: the DLT %u\n"
           "\"CDRH\" slices of each celldiag datasource, ordered by their stream\n"
           "offset, headers stripped, payloads concatenated. The output is a\n"
           "plain .hdlc capture for a DIAG decoder (e.g. kismet_cap_cell_diag's\n"
           "replay= option).\n"
           "\n"
           "One .hdlc is one stream: one modem, one session (a source that\n"
           "reopens starts a new session). Use -o for a single stream (pick it\n"
           "with --source / --session when there are several), -O to write\n"
           "<source name>-<session start UTC>.hdlc per stream, or -l to list them.\n",
           DIAG_RAWPKT_DLT);
    printf("usage: %s [OPTION]\n", argv);
    printf(" -i, --in [filename]          Input kismetdb file\n"
           " -o, --out [filename]         Output .hdlc file ('-' for stdout); needs\n"
           "                              exactly one stream\n"
           " -O, --out-dir [dir]          Write one .hdlc per stream into dir\n"
           " -l, --list                   List the streams: slices, bytes, gaps, END\n"
           "                              and reported drops, and the source's rawlog=\n"
           "                              spec (as configured: %%m/%%i/%%t are not\n"
           "                              expanded)\n"
           " -s, --source [uuid|name]     Only this datasource\n"
           " -S, --session [id]           Only this session (from --list)\n"
           " -t, --type [typestring]      Datasource type to read (default: celldiag)\n"
           " -d, --dlt [n]                Packet DLT to read (default: %u)\n"
           "     --strict                 Fail (exit 3, nothing written) on any gap,\n"
           "                              overlap, malformed, truncated or unaligned slice,\n"
           "                              tail gap, bad END, or drop the source reported\n"
           "     --require-end            Also fail --strict when a stream has no END\n"
           "                              slice (a Kismet-driven stop never sends one yet)\n"
           " -f, --force                  Overwrite existing output file(s)\n"
           " -v, --verbose                Verbose output\n"
           "\n"
           "exit: 0 ok, 1 error, 2 no DIAG packets, 3 --strict integrity failure\n",
           DIAG_RAWPKT_DLT);
}

struct source_t {
    std::string uuid;
    std::string name;
    std::string rawlog;         /* rawlog= spec from the source definition, if any */

    /* Per-row problems that belong to no session (the header is unreadable). */
    uint64_t malformed = 0;
    uint64_t truncated = 0;
    uint64_t bad_drop_rows = 0; /* RawDiagDrop rows that do not parse */
    uint64_t bad_abort_rows = 0; /* RawDiagAbort rows that do not parse */
    std::map<int64_t, uint64_t> other_dlts;  /* dlt -> rows, not read */
};

/* One slice as the index pass sees it: enough to order it and fetch it. */
struct slice_t {
    uint64_t offset;
    int64_t rowid;
    uint32_t header_len;
    uint32_t payload_len;
};

/* One (source, session) stream, after ordering. */
struct stream_t {
    size_t src;                 /* index into the sources vector */
    uint64_t session_id;
    std::vector<slice_t> take;  /* the slices to write, in offset order */
    uint64_t slices = 0;        /* valid slices seen, taken or not */
    uint64_t bytes = 0;         /* payload bytes taken */
    uint64_t gaps = 0;
    uint64_t gap_bytes = 0;
    uint64_t overlaps = 0;
    uint64_t fragments = 0;
    uint64_t unaligned = 0;
    uint64_t delivered_end = 0; /* one past the last byte taken */

    /* END. */
    uint64_t ends = 0;          /* END slices seen; exactly 1 is well-formed */
    uint64_t end_offset = 0;    /* the stream's final length, per END */
    uint64_t tail_gap = 0;      /* end_offset - delivered_end, when positive */
    bool end_bad = false;       /* END before the data, or more than one */

    /* The source's own RawDiagDrop row for this session. */
    uint64_t drop_rows = 0;
    uint64_t drop_offset = 0;   /* first dropped slice, per the first row */
    uint64_t drop_len = 0;

    /* The server's RawDiagAbort row for this session: the source died
     * after data and before END. */
    uint64_t abort_rows = 0;
    uint64_t abort_delivered_end = 0; /* what the server received, per the row */
    uint64_t abort_slices = 0;
    std::string abort_reason;

    std::string path;
};

static uint64_t get_le64(const uint8_t *p) {
    uint64_t v = 0;
    for (int i = 7; i >= 0; i--)
        v = (v << 8) | p[i];
    return v;
}

/* The `rawlog=` value from a source definition "name:k=v,k=v", for --list, so
 * the operator can see which sidecar to diff the output against. It is the spec
 * as configured, so %m/%i/%t tokens are still unexpanded (the resolved name is
 * in the sidecar's .capture_meta.json). Kismet lets a value be double-quoted;
 * a bare value ends at the next ','. */
static std::string rawlog_from_definition(const std::string& def) {
    auto colon = def.find(':');
    if (colon == std::string::npos)
        return "";
    auto opts = def.substr(colon + 1);
    size_t pos = 0;
    while (pos < opts.size()) {
        auto end = opts.find(',', pos);
        if (end == std::string::npos)
            end = opts.size();
        auto kv = opts.substr(pos, end - pos);
        if (kv.compare(0, 7, "rawlog=") == 0) {
            auto v = kv.substr(7);
            if (v.size() >= 2 && v.front() == '"' && v.back() == '"')
                v = v.substr(1, v.size() - 2);
            return v;
        }
        pos = end + 1;
    }
    return "";
}

static std::string sanitize_filename(const std::string& in) {
    std::string out;
    for (char c : in) {
        if ((c >= 'A' && c <= 'Z') || (c >= 'a' && c <= 'z') ||
                (c >= '0' && c <= '9') || c == '.' || c == '_' || c == '-')
            out += c;
        else
            out += '_';
    }
    if (out.empty() || out == "." || out == "..")
        out = "source";
    return out;
}

/* A session id is host CLOCK_REALTIME ns at stream start; render it the way
 * rawlog='s %t does, so an extracted file names itself like a tee. */
static std::string session_utc(uint64_t session_id) {
    time_t t = (time_t) (session_id / 1000000000ULL);
    struct tm tm;
    char buf[32];
    if (gmtime_r(&t, &tm) == nullptr ||
            strftime(buf, sizeof(buf), "%Y%m%dT%H%M%SZ", &tm) == 0)
        return std::to_string(session_id);
    return buf;
}

/* Index pass for one source: read every candidate row's header (never the
 * whole blob), validate it, and group the valid slices by session. Returns 0,
 * or -1 on a db error (message already printed). */
static int index_source(sqlite3 *db, source_t& src, size_t src_idx, int64_t dlt,
                        std::vector<stream_t>& streams) {
    sqlite3_stmt *stmt = nullptr;

    if (sqlite3_prepare_v2(db,
                "SELECT dlt, count(*) FROM packets WHERE datasource = ?1 AND dlt != ?2 "
                "GROUP BY dlt", -1, &stmt, nullptr) != SQLITE_OK) {
        fprintf(stderr, "ERROR:  Unable to query packets: %s\n", sqlite3_errmsg(db));
        return -1;
    }
    sqlite3_bind_text(stmt, 1, src.uuid.c_str(), -1, SQLITE_TRANSIENT);
    sqlite3_bind_int64(stmt, 2, dlt);
    while (sqlite3_step(stmt) == SQLITE_ROW)
        src.other_dlts[sqlite3_column_int64(stmt, 0)] =
            (uint64_t) sqlite3_column_int64(stmt, 1);
    sqlite3_finalize(stmt);

    /* substr() on a BLOB counts bytes; the last byte is for the alignment
     * check. packet_full_len may be NULL; that reads as 0, meaning unknown. */
    if (sqlite3_prepare_v2(db,
                "SELECT rowid, substr(packet, 1, ?3), length(packet), packet_full_len, "
                "substr(packet, -1, 1) "
                "FROM packets WHERE datasource = ?1 AND dlt = ?2",
                -1, &stmt, nullptr) != SQLITE_OK) {
        fprintf(stderr, "ERROR:  Unable to query packets: %s\n", sqlite3_errmsg(db));
        return -1;
    }
    sqlite3_bind_text(stmt, 1, src.uuid.c_str(), -1, SQLITE_TRANSIENT);
    sqlite3_bind_int64(stmt, 2, dlt);
    sqlite3_bind_int(stmt, 3, (int) DIAG_RAWPKT_HDR_LEN);

    std::map<uint64_t, std::vector<std::pair<slice_t, uint8_t>>> by_session;
    std::map<uint64_t, uint64_t> frags;
    std::map<uint64_t, std::vector<uint64_t>> ends;     /* session -> END offsets */
    int r;

    while ((r = sqlite3_step(stmt)) == SQLITE_ROW) {
        int64_t rowid = sqlite3_column_int64(stmt, 0);
        const uint8_t *h = (const uint8_t *) sqlite3_column_blob(stmt, 1);
        int hn = sqlite3_column_bytes(stmt, 1);
        int64_t len = sqlite3_column_int64(stmt, 2);
        int64_t full_len = sqlite3_column_int64(stmt, 3);
        const uint8_t *last = (const uint8_t *) sqlite3_column_blob(stmt, 4);
        int lastn = sqlite3_column_bytes(stmt, 4);

        if (full_len > len)
            src.truncated++;

        /* The same checks as diag_rawpkt_parse(). */
        if (h == nullptr || hn < (int) DIAG_RAWPKT_HDR_LEN ||
                memcmp(h, DIAG_RAWPKT_MAGIC, 4) != 0 ||
                h[4] != DIAG_RAWPKT_VERSION) {
            src.malformed++;
            continue;
        }
        uint16_t hl = (uint16_t) (h[6] | (h[7] << 8));
        if (hl < DIAG_RAWPKT_HDR_LEN || (int64_t) hl > len) {
            src.malformed++;
            continue;
        }

        slice_t s;
        s.offset = get_le64(h + 16);
        s.rowid = rowid;
        s.header_len = hl;
        s.payload_len = (uint32_t) (len - hl);
        uint64_t session = get_le64(h + 8);
        uint8_t flags = h[5];

        /* END carries no stream bytes, only where the stream ended; one with a
         * payload is not a valid slice (diag_rawpkt_parse() refuses it too).
         * by_session gets an entry either way, so a session whose every data
         * slice was dropped still exists to be reported. */
        if (flags & DIAG_RAWPKT_FLAG_END) {
            if (s.payload_len != 0) {
                src.malformed++;
                continue;
            }
            ends[session].push_back(s.offset);
            by_session[session];
            continue;
        }

        if (flags & DIAG_RAWPKT_FLAG_FRAGMENT)
            frags[session]++;

        /* Remember whether this slice honours the boundary rule; an empty
         * payload has no last byte to check. */
        uint8_t aligned = (flags & DIAG_RAWPKT_FLAG_FRAGMENT) ||
            (s.payload_len > 0 && last != nullptr && lastn == 1 && last[0] == 0x7E);
        by_session[session].push_back({s, aligned});
    }

    if (r != SQLITE_DONE) {
        fprintf(stderr, "ERROR:  Failed reading packets for source %s: %s\n",
                src.uuid.c_str(), sqlite3_errmsg(db));
        sqlite3_finalize(stmt);
        return -1;
    }
    sqlite3_finalize(stmt);

    for (auto& kv : by_session) {
        auto& v = kv.second;
        std::sort(v.begin(), v.end(), [](const auto& a, const auto& b) {
            if (a.first.offset != b.first.offset)
                return a.first.offset < b.first.offset;
            return a.first.rowid < b.first.rowid;
        });

        stream_t st;
        st.src = src_idx;
        st.session_id = kv.first;
        st.fragments = frags[kv.first];

        uint64_t at = 0;        /* a stream starts at offset 0 */
        for (const auto& e : v) {
            const slice_t& s = e.first;
            st.slices++;
            if (s.offset < at) {
                st.overlaps++;
                continue;
            }
            if (s.offset > at) {
                st.gaps++;
                st.gap_bytes += s.offset - at;
            }
            if (!e.second)
                st.unaligned++;
            st.take.push_back(s);
            st.bytes += s.payload_len;
            at = s.offset + s.payload_len;
        }
        st.delivered_end = at;

        /* END against what was delivered: the same arithmetic as a gap, so
         * tail loss is measured exactly, not merely flagged. */
        auto ei = ends.find(kv.first);
        if (ei != ends.end()) {
            const auto& e = ei->second;
            st.ends = e.size();
            st.end_offset = *std::max_element(e.begin(), e.end());
            if (st.ends > 1 || st.end_offset < at)
                st.end_bad = true;
            else if (st.end_offset > at)
                st.tail_gap = st.end_offset - at;
        }
        streams.push_back(std::move(st));
    }
    return 0;
}

/* The source's RawDiagDrop rows, attached to its streams by
 * session_id. A row for a session with no slices at all -- every one dropped --
 * becomes an empty stream, so the loss is still reported. Returns 0, or -1 on a
 * db error (message already printed). */
static int read_drop_rows(sqlite3 *db, source_t& src, size_t src_idx,
                          std::vector<stream_t>& streams) {
    sqlite3_stmt *stmt = nullptr;
    if (sqlite3_prepare_v2(db, "SELECT json FROM data WHERE datasource = ?1 AND type = ?2",
                -1, &stmt, nullptr) != SQLITE_OK) {
        fprintf(stderr, "ERROR:  Unable to query data: %s\n", sqlite3_errmsg(db));
        return -1;
    }
    sqlite3_bind_text(stmt, 1, src.uuid.c_str(), -1, SQLITE_TRANSIENT);
    sqlite3_bind_text(stmt, 2, DIAG_RAWPKT_DROP_TYPE, -1, SQLITE_STATIC);

    int r;
    while ((r = sqlite3_step(stmt)) == SQLITE_ROW) {
        const char *b = (const char *) sqlite3_column_blob(stmt, 0);
        std::string text = b ? std::string(b, sqlite3_column_bytes(stmt, 0)) : std::string();
        /* No exceptions anywhere: parse(…, false) marks bad JSON discarded, and
         * every field is type-checked before get<>(), which would throw on a
         * mismatch -- a corrupt row is a counted bad row, never a crash. */
        auto j = nlohmann::json::parse(text, nullptr, false);
        auto u64 = [&](const char *k) -> const nlohmann::json * {
            auto it = j.find(k);
            return (it != j.end() && it->is_number_unsigned()) ? &*it : nullptr;
        };
        auto schema_ok = [&]() {
            auto it = j.find("schema");
            return it != j.end() && it->is_string() &&
                it->get<std::string>() == DIAG_RAWPKT_DROP_SCHEMA;
        };
        if (j.is_discarded() || !j.is_object() || !schema_ok() ||
                !u64("session_id") || !u64("first_drop_offset") || !u64("first_drop_len")) {
            src.bad_drop_rows++;
            continue;
        }
        uint64_t session = u64("session_id")->get<uint64_t>();

        stream_t *st = nullptr;
        for (auto& x : streams)
            if (x.src == src_idx && x.session_id == session)
                st = &x;
        if (st == nullptr) {
            stream_t fresh;
            fresh.src = src_idx;
            fresh.session_id = session;
            streams.push_back(std::move(fresh));
            st = &streams.back();
        }
        if (st->drop_rows++ == 0) {
            st->drop_offset = u64("first_drop_offset")->get<uint64_t>();
            st->drop_len = u64("first_drop_len")->get<uint64_t>();
        }
    }
    if (r != SQLITE_DONE) {
        fprintf(stderr, "ERROR:  Failed reading data for source %s: %s\n",
                src.uuid.c_str(), sqlite3_errmsg(db));
        sqlite3_finalize(stmt);
        return -1;
    }
    sqlite3_finalize(stmt);
    return 0;
}

/* The server's RawDiagAbort rows, attached to their streams by
 * session_id exactly like the drop rows above: a source that died mid-session.
 * A row naming a session with no slices becomes an empty stream, so the death
 * is still reported. Returns 0, or -1 on a db error (message already printed). */
static int read_abort_rows(sqlite3 *db, source_t& src, size_t src_idx,
                           std::vector<stream_t>& streams) {
    sqlite3_stmt *stmt = nullptr;
    if (sqlite3_prepare_v2(db, "SELECT json FROM data WHERE datasource = ?1 AND type = ?2",
                -1, &stmt, nullptr) != SQLITE_OK) {
        fprintf(stderr, "ERROR:  Unable to query data: %s\n", sqlite3_errmsg(db));
        return -1;
    }
    sqlite3_bind_text(stmt, 1, src.uuid.c_str(), -1, SQLITE_TRANSIENT);
    sqlite3_bind_text(stmt, 2, DIAG_RAWPKT_ABORT_TYPE, -1, SQLITE_STATIC);

    int r;
    while ((r = sqlite3_step(stmt)) == SQLITE_ROW) {
        const char *b = (const char *) sqlite3_column_blob(stmt, 0);
        std::string text = b ? std::string(b, sqlite3_column_bytes(stmt, 0)) : std::string();
        /* Type-checked before every get<>(), as in read_drop_rows: a corrupt
         * row is a counted bad row, never a throw. */
        auto j = nlohmann::json::parse(text, nullptr, false);
        auto u64 = [&](const char *k) -> const nlohmann::json * {
            auto it = j.find(k);
            return (it != j.end() && it->is_number_unsigned()) ? &*it : nullptr;
        };
        auto str = [&](const char *k) -> const nlohmann::json * {
            auto it = j.find(k);
            return (it != j.end() && it->is_string()) ? &*it : nullptr;
        };
        if (j.is_discarded() || !j.is_object() || !str("schema") ||
                str("schema")->get<std::string>() != DIAG_RAWPKT_ABORT_SCHEMA ||
                !u64("session_id") || !u64("delivered_end") || !u64("slices") ||
                !str("reason")) {
            src.bad_abort_rows++;
            continue;
        }
        uint64_t session = u64("session_id")->get<uint64_t>();

        stream_t *st = nullptr;
        for (auto& x : streams)
            if (x.src == src_idx && x.session_id == session)
                st = &x;
        if (st == nullptr) {
            stream_t fresh;
            fresh.src = src_idx;
            fresh.session_id = session;
            streams.push_back(std::move(fresh));
            st = &streams.back();
        }
        if (st->abort_rows++ == 0) {
            st->abort_delivered_end = u64("delivered_end")->get<uint64_t>();
            st->abort_slices = u64("slices")->get<uint64_t>();
            st->abort_reason = str("reason")->get<std::string>();
        }
    }
    if (r != SQLITE_DONE) {
        fprintf(stderr, "ERROR:  Failed reading data for source %s: %s\n",
                src.uuid.c_str(), sqlite3_errmsg(db));
        sqlite3_finalize(stmt);
        return -1;
    }
    sqlite3_finalize(stmt);
    return 0;
}

/* Integrity warnings are always printed: a reconstruction that is not the
 * whole stream must never pass as one because nobody asked for -v. Returns
 * true if there was anything to warn about. */
static bool warn_source(const source_t& src) {
    bool any = false;
    if (src.malformed) {
        fprintf(stderr, "WARNING: %s (%s): %" PRIu64 " DLT-%u row(s) are not valid "
                "slices (bad magic, version or header length) and were skipped.\n",
                src.name.c_str(), src.uuid.c_str(), src.malformed, DIAG_RAWPKT_DLT);
        any = true;
    }
    if (src.truncated) {
        fprintf(stderr, "WARNING: %s (%s): %" PRIu64 " truncated packet(s) (stored "
                "shorter than captured).\n",
                src.name.c_str(), src.uuid.c_str(), src.truncated);
        any = true;
    }
    if (src.bad_drop_rows) {
        fprintf(stderr, "WARNING: %s (%s): %" PRIu64 " %s row(s) do not parse: the "
                "source reported a drop this tool cannot place.\n",
                src.name.c_str(), src.uuid.c_str(), src.bad_drop_rows,
                DIAG_RAWPKT_DROP_TYPE);
        any = true;
    }
    if (src.bad_abort_rows) {
        fprintf(stderr, "WARNING: %s (%s): %" PRIu64 " %s row(s) do not parse: the "
                "server recorded a mid-stream death this tool cannot place.\n",
                src.name.c_str(), src.uuid.c_str(), src.bad_abort_rows,
                DIAG_RAWPKT_ABORT_TYPE);
        any = true;
    }
    return any;
}

/* `have_drop_rows`: the db has a `data` table, so a RawDiagDrop row COULD have
 * been written; without one, "no drop reported" means nothing. */
static bool warn_stream(const source_t& src, const stream_t& st, bool require_end,
                        bool have_drop_rows) {
    bool any = false;
    if (st.tail_gap) {
        fprintf(stderr, "WARNING: %s session %" PRIu64 ": the stream's last %" PRIu64
                " byte(s) were never delivered (END at offset %" PRIu64 ", delivered "
                "through %" PRIu64 ").\n", src.name.c_str(), st.session_id,
                st.tail_gap, st.end_offset, st.delivered_end);
        any = true;
    }
    if (st.end_bad) {
        fprintf(stderr, "WARNING: %s session %" PRIu64 ": %" PRIu64 " END slice(s), the "
                "last at offset %" PRIu64 ", against data delivered through %" PRIu64
                "; the stream's end is not believable.\n", src.name.c_str(),
                st.session_id, st.ends, st.end_offset, st.delivered_end);
        any = true;
    }
    if (st.drop_rows) {
        bool unseen = st.drop_offset >= st.delivered_end && st.tail_gap == 0;
        fprintf(stderr, "WARNING: %s session %" PRIu64 ": the source reported dropping "
                "slices (first at offset %" PRIu64 ", %" PRIu64 " byte(s))%s.\n",
                src.name.c_str(), st.session_id, st.drop_offset, st.drop_len,
                unseen ? ", after the last delivered byte: tail loss no gap shows" : "");
        any = true;
    }
    /* The server saw this source die after data and before END. The
     * stream is short by an unknown tail -- whatever the helper had read but
     * not yet delivered, up to its whole out-ring -- and no offset can show it.
     * With END in, the stream reached its teardown and is confirmed anyway;
     * the server never writes the row then, so this is a contradiction to
     * note, not a loss. */
    if (st.abort_rows && st.ends == 0) {
        fprintf(stderr, "WARNING: %s session %" PRIu64 ": the source DIED mid-stream "
                "(%s): the server received it through offset %" PRIu64 " (%" PRIu64
                " slice(s)) and no END, so an unknown tail -- up to the capture "
                "helper's whole out-ring -- was lost with it (RawDiagAbort).\n",
                src.name.c_str(), st.session_id, st.abort_reason.c_str(),
                st.abort_delivered_end, st.abort_slices);
        any = true;
    } else if (st.abort_rows) {
        fprintf(stderr, "NOTE: %s session %" PRIu64 ": a RawDiagAbort row names this "
                "session, but its END arrived, so the stream is confirmed.\n",
                src.name.c_str(), st.session_id);
    }
    /* Not "complete, probably": a stop without END loses the read(s) in
     * flight at the close -- not dropped, so no RawDiagDrop row either. With
     * the out-ring wakeup that is at most a frame or so, and most stopped
     * streams are whole; an older helper without it strands ~0.4-1 s. The reader cannot tell which built the drive, so the note must
     * not read as a clean bill. A death has its own warning above. */
    if (st.ends == 0 && !st.abort_rows) {
        fprintf(stderr, "%s: %s session %" PRIu64 ": no END slice, so the stream's end "
                "is unconfirmed. A Kismet-driven stop sends END only since the "
                "graceful close -- none from an older drive, a close out of "
                "its grace, or datasource_graceful_close=false -- and without it the "
                "read(s) in flight at the close are lost (up to ~1 s from an older "
                "helper without the out-ring wakeup), so the tail may be short%s.\n",
                require_end ? "WARNING" : "NOTE", src.name.c_str(), st.session_id,
                st.drop_rows ? "" : have_drop_rows ?
                    "; no ring-full drop was reported" :
                    "; this kismetdb has no data table, so a drop could not be recorded");
        any |= require_end;
    }
    if (st.gaps) {
        fprintf(stderr, "WARNING: %s session %" PRIu64 ": %" PRIu64 " gap(s), %" PRIu64
                " byte(s) never delivered (whole frames; the rest still deframes).\n",
                src.name.c_str(), st.session_id, st.gaps, st.gap_bytes);
        any = true;
    }
    if (st.overlaps) {
        fprintf(stderr, "WARNING: %s session %" PRIu64 ": %" PRIu64 " overlapping "
                "slice(s) skipped.\n", src.name.c_str(), st.session_id, st.overlaps);
        any = true;
    }
    if (st.unaligned) {
        fprintf(stderr, "WARNING: %s session %" PRIu64 ": %" PRIu64 " slice(s) not "
                "flagged FRAGMENT do not end in 0x7E.\n",
                src.name.c_str(), st.session_id, st.unaligned);
        any = true;
    }
    return any;
}

static bool file_exists(const std::string& path) {
    struct stat sb;
    return stat(path.c_str(), &sb) == 0;
}

/* Write one stream to `path` ('-' = stdout). A file is written to
 * "<path>.partial" and renamed only once complete, so an interrupted run
 * never leaves a plausible-looking truncated .hdlc behind. */
static int write_stream(sqlite3 *db, const stream_t& st, const std::string& path) {
    sqlite3_stmt *stmt = nullptr;
    if (sqlite3_prepare_v2(db, "SELECT packet FROM packets WHERE rowid = ?1", -1,
                &stmt, nullptr) != SQLITE_OK) {
        fprintf(stderr, "ERROR:  Unable to query packets: %s\n", sqlite3_errmsg(db));
        return -1;
    }

    std::string tmp = path == "-" ? path : path + ".partial";
    FILE *f = path == "-" ? stdout : fopen(tmp.c_str(), "wb");
    if (f == nullptr) {
        fprintf(stderr, "ERROR:  Unable to open '%s' for writing: %s\n",
                tmp.c_str(), strerror(errno));
        sqlite3_finalize(stmt);
        return -1;
    }

    int ret = 0;
    for (const auto& s : st.take) {
        sqlite3_reset(stmt);
        sqlite3_bind_int64(stmt, 1, s.rowid);
        if (sqlite3_step(stmt) != SQLITE_ROW) {
            fprintf(stderr, "ERROR:  Packet row %" PRId64 " vanished: %s\n",
                    s.rowid, sqlite3_errmsg(db));
            ret = -1;
            break;
        }
        const uint8_t *blob = (const uint8_t *) sqlite3_column_blob(stmt, 0);
        int len = sqlite3_column_bytes(stmt, 0);
        if (blob == nullptr || len != (int) (s.header_len + s.payload_len)) {
            fprintf(stderr, "ERROR:  Packet row %" PRId64 " changed length while "
                    "reading.\n", s.rowid);
            ret = -1;
            break;
        }
        if (s.payload_len &&
                fwrite(blob + s.header_len, 1, s.payload_len, f) != s.payload_len) {
            fprintf(stderr, "ERROR:  Write to '%s' failed: %s\n", tmp.c_str(),
                    strerror(errno));
            ret = -1;
            break;
        }
    }
    sqlite3_finalize(stmt);

    if (path == "-")
        return (ret == 0 && fflush(stdout) == 0) ? 0 : -1;

    if (fclose(f) != 0 && ret == 0) {
        fprintf(stderr, "ERROR:  Unable to close '%s': %s\n", tmp.c_str(), strerror(errno));
        ret = -1;
    }
    if (ret != 0) {
        unlink(tmp.c_str());
        return -1;
    }
    if (rename(tmp.c_str(), path.c_str()) != 0) {
        fprintf(stderr, "ERROR:  Unable to rename '%s' to '%s': %s\n",
                tmp.c_str(), path.c_str(), strerror(errno));
        unlink(tmp.c_str());
        return -1;
    }
    return 0;
}

static bool parse_u64(const char *s, uint64_t& out) {
    char *end = nullptr;
    errno = 0;
    unsigned long long v = strtoull(s, &end, 10);
    if (errno != 0 || end == s || *end != '\0' || *s == '-')
        return false;
    out = (uint64_t) v;
    return true;
}

int main(int argc, char *argv[]) {
    enum { OPT_STRICT = 1000, OPT_REQUIRE_END };

    static struct option longopt[] = {
        { "in", required_argument, 0, 'i' },
        { "out", required_argument, 0, 'o' },
        { "out-dir", required_argument, 0, 'O' },
        { "list", no_argument, 0, 'l' },
        { "source", required_argument, 0, 's' },
        { "session", required_argument, 0, 'S' },
        { "type", required_argument, 0, 't' },
        { "dlt", required_argument, 0, 'd' },
        { "strict", no_argument, 0, OPT_STRICT },
        { "require-end", no_argument, 0, OPT_REQUIRE_END },
        { "verbose", no_argument, 0, 'v' },
        { "force", no_argument, 0, 'f' },
        { "help", no_argument, 0, 'h' },
        { 0, 0, 0, 0 }
    };

    int option_idx = 0;
    optind = 0;
    opterr = 0;

    std::string in_fname, out_fname, out_dir, source_filter;
    std::string type_filter = "celldiag";
    bool list_mode = false;
    bool session_set = false;
    uint64_t session_filter = 0;
    int64_t dlt = DIAG_RAWPKT_DLT;
    bool strict = false;
    bool require_end = false;
    bool verbose = false;
    bool force = false;

    while (1) {
        int r = getopt_long(argc, argv,
                            "-hi:o:O:ls:S:t:d:vf",
                            longopt, &option_idx);
        if (r < 0) break;

        if (r == 'h') {
            print_help(argv[0]);
            exit(EXIT_ERR);
        } else if (r == 'i') {
            in_fname = std::string(optarg);
        } else if (r == 'o') {
            out_fname = std::string(optarg);
        } else if (r == 'O') {
            out_dir = std::string(optarg);
        } else if (r == 'l') {
            list_mode = true;
        } else if (r == 's') {
            source_filter = std::string(optarg);
        } else if (r == 'S') {
            if (!parse_u64(optarg, session_filter)) {
                fprintf(stderr, "ERROR:  --session expects a session id, got '%s'\n", optarg);
                exit(EXIT_ERR);
            }
            session_set = true;
        } else if (r == 't') {
            type_filter = std::string(optarg);
        } else if (r == 'd') {
            uint64_t v;
            if (!parse_u64(optarg, v)) {
                fprintf(stderr, "ERROR:  --dlt expects an integer, got '%s'\n", optarg);
                exit(EXIT_ERR);
            }
            dlt = (int64_t) v;
        } else if (r == OPT_STRICT) {
            strict = true;
        } else if (r == OPT_REQUIRE_END) {
            require_end = true;
        } else if (r == 'v') {
            verbose = true;
        } else if (r == 'f') {
            force = true;
        }
    }

    int n_modes = (out_fname != "") + (out_dir != "") + (list_mode ? 1 : 0);
    if (in_fname == "" || n_modes != 1) {
        fprintf(stderr, "ERROR: Expected --in [kismetdb file] and exactly one of "
                "--out [file], --out-dir [dir] or --list\n");
        exit(EXIT_ERR);
    }

    struct stat statbuf;
    if (stat(in_fname.c_str(), &statbuf) < 0) {
        if (errno == ENOENT)
            fprintf(stderr, "ERROR:  Input file '%s' does not exist.\n", in_fname.c_str());
        else
            fprintf(stderr, "ERROR:  Unexpected problem checking input "
                    "file '%s': %s\n", in_fname.c_str(), strerror(errno));
        exit(EXIT_ERR);
    }

    if (out_dir != "") {
        if (stat(out_dir.c_str(), &statbuf) < 0 || !S_ISDIR(statbuf.st_mode)) {
            fprintf(stderr, "ERROR:  Output directory '%s' does not exist.\n",
                    out_dir.c_str());
            exit(EXIT_ERR);
        }
    }

    sqlite3 *db = nullptr;
    if (sqlite3_open_v2(in_fname.c_str(), &db, SQLITE_OPEN_READONLY, nullptr) != SQLITE_OK) {
        fprintf(stderr, "ERROR:  Unable to open '%s': %s\n",
                in_fname.c_str(), sqlite3_errmsg(db));
        sqlite3_close(db);
        exit(EXIT_ERR);
    }

    int db_version = 0;
    {
        sqlite3_stmt *stmt = nullptr;
        if (sqlite3_prepare_v2(db, "SELECT db_version FROM KISMET", -1, &stmt,
                    nullptr) != SQLITE_OK || sqlite3_step(stmt) != SQLITE_ROW) {
            fprintf(stderr, "ERROR:  '%s' is not a kismetdb (no KISMET table): %s\n",
                    in_fname.c_str(), sqlite3_errmsg(db));
            sqlite3_finalize(stmt);
            sqlite3_close(db);
            exit(EXIT_ERR);
        }
        db_version = sqlite3_column_int(stmt, 0);
        sqlite3_finalize(stmt);
    }

    /* Every kismetdb Kismet writes has a `data` table; a hand-built one may
     * not, and then no RawDiagDrop row can exist to be read. */
    bool have_data = false;
    {
        sqlite3_stmt *stmt = nullptr;
        if (sqlite3_prepare_v2(db, "SELECT 1 FROM sqlite_master WHERE type = 'table' "
                    "AND name = 'data'", -1, &stmt, nullptr) == SQLITE_OK)
            have_data = sqlite3_step(stmt) == SQLITE_ROW;
        sqlite3_finalize(stmt);
    }

    /* The sources to read: type match, then the --source filter by uuid or
     * name. Sorted by uuid so output order does not depend on the db. */
    std::vector<source_t> sources;
    {
        sqlite3_stmt *stmt = nullptr;
        if (sqlite3_prepare_v2(db, "SELECT uuid, name, definition FROM datasources "
                    "WHERE typestring = ?1 ORDER BY uuid", -1, &stmt, nullptr) != SQLITE_OK) {
            fprintf(stderr, "ERROR:  Unable to read datasources: %s\n", sqlite3_errmsg(db));
            sqlite3_close(db);
            exit(EXIT_ERR);
        }
        sqlite3_bind_text(stmt, 1, type_filter.c_str(), -1, SQLITE_TRANSIENT);
        while (sqlite3_step(stmt) == SQLITE_ROW) {
            source_t s;
            auto col = [&](int i) -> std::string {
                auto t = sqlite3_column_text(stmt, i);
                return t ? std::string((const char *) t) : std::string();
            };
            s.uuid = col(0);
            s.name = col(1);
            s.rawlog = rawlog_from_definition(col(2));
            if (!source_filter.empty() && s.uuid != source_filter && s.name != source_filter)
                continue;
            sources.push_back(s);
        }
        sqlite3_finalize(stmt);
    }

    if (sources.empty()) {
        if (!source_filter.empty())
            fprintf(stderr, "ERROR:  No '%s' datasource matches '%s' in '%s'.\n",
                    type_filter.c_str(), source_filter.c_str(), in_fname.c_str());
        else
            fprintf(stderr, "ERROR:  No '%s' datasources in '%s'; no DIAG packets "
                    "to extract.\n", type_filter.c_str(), in_fname.c_str());
        sqlite3_close(db);
        exit(source_filter.empty() ? EXIT_NODATA : EXIT_ERR);
    }

    /* Index pass: headers only. Nothing is written until every decision
     * below is made. */
    std::vector<stream_t> streams;
    for (size_t i = 0; i < sources.size(); i++) {
        if (index_source(db, sources[i], i, dlt, streams) != 0 ||
                (have_data && (read_drop_rows(db, sources[i], i, streams) != 0 ||
                               read_abort_rows(db, sources[i], i, streams) != 0))) {
            sqlite3_close(db);
            exit(EXIT_ERR);
        }
    }

    if (session_set) {
        streams.erase(std::remove_if(streams.begin(), streams.end(),
                    [&](const stream_t& s) { return s.session_id != session_filter; }),
                streams.end());
    }

    if (list_mode) {
        for (size_t i = 0; i < sources.size(); i++) {
            const auto& s = sources[i];
            std::string tail;
            if (s.malformed)
                tail += " malformed=" + std::to_string(s.malformed);
            if (s.truncated)
                tail += " truncated=" + std::to_string(s.truncated);
            if (s.bad_drop_rows)
                tail += " bad_drop_rows=" + std::to_string(s.bad_drop_rows);
            if (s.bad_abort_rows)
                tail += " bad_abort_rows=" + std::to_string(s.bad_abort_rows);
            for (const auto& d : s.other_dlts)
                tail += " dlt" + std::to_string(d.first) + "_rows=" +
                    std::to_string(d.second);
            if (!s.rawlog.empty())
                tail += " rawlog=" + s.rawlog;

            bool any = false;
            for (const auto& st : streams) {
                if (st.src != i)
                    continue;
                any = true;
                /* END and reported drops: end=none is the common case
                 * on a Kismet-stopped drive, and says the end is unconfirmed. */
                std::string end = st.ends ? " end=" + std::to_string(st.end_offset)
                                          : std::string(" end=none");
                if (st.tail_gap)
                    end += " tail_gap_bytes=" + std::to_string(st.tail_gap);
                if (st.end_bad)
                    end += " end_bad=" + std::to_string(st.ends);
                if (st.drop_rows)
                    end += " drop_reported_at=" + std::to_string(st.drop_offset);
                if (st.abort_rows)
                    end += " died_after=" + std::to_string(st.abort_delivered_end);
                printf("%s  %s  session=%" PRIu64 " (%s) slices=%" PRIu64 " bytes=%"
                       PRIu64 " gaps=%" PRIu64 " gap_bytes=%" PRIu64 " overlaps=%"
                       PRIu64 " fragments=%" PRIu64 " unaligned=%" PRIu64 "%s%s\n",
                       s.uuid.c_str(), s.name.c_str(), st.session_id,
                       session_utc(st.session_id).c_str(), st.slices, st.bytes,
                       st.gaps, st.gap_bytes, st.overlaps, st.fragments, st.unaligned,
                       end.c_str(), tail.c_str());
            }
            if (!any)
                printf("%s  %s  sessions=0%s\n", s.uuid.c_str(), s.name.c_str(),
                       tail.c_str());
        }
        sqlite3_close(db);
        return EXIT_OK;
    }

    /* A source with valid-looking rows but no stream is still worth hearing
     * about, and so is one with no DIAG packets at all. */
    bool hazard = false;
    for (size_t i = 0; i < sources.size(); i++)
        hazard |= warn_source(sources[i]);

    /* Before the empty streams are dropped below: a session whose every data
     * slice was lost has nothing to write, but its END, RawDiagDrop or
     * RawDiagAbort row is still a loss to report. */
    for (const auto& st : streams)
        hazard |= warn_stream(sources[st.src], st, require_end, have_data);

    streams.erase(std::remove_if(streams.begin(), streams.end(),
                [](const stream_t& s) { return s.take.empty(); }), streams.end());

    if (streams.empty()) {
        fprintf(stderr, "ERROR:  No DIAG packets (DLT %" PRId64 ") for any '%s' source in "
                "'%s'%s (a drive from before the celldiag packets emitter, rawpackets=off, "
                "or kis_log_packets=false?).\n", dlt, type_filter.c_str(),
                in_fname.c_str(), session_set ? " in that session" : "");
        sqlite3_close(db);
        exit(EXIT_NODATA);
    }

    if (out_fname != "" && streams.size() > 1) {
        fprintf(stderr, "ERROR:  %zu DIAG streams, and one .hdlc is one stream. Pick "
                "one with --source / --session, or use --out-dir:\n", streams.size());
        for (const auto& st : streams)
            fprintf(stderr, "    %s  %s  session=%" PRIu64 " (%s)  bytes=%" PRIu64 "\n",
                    sources[st.src].uuid.c_str(), sources[st.src].name.c_str(),
                    st.session_id, session_utc(st.session_id).c_str(), st.bytes);
        sqlite3_close(db);
        exit(EXIT_ERR);
    }

    if (strict && hazard) {
        fprintf(stderr, "ERROR:  --strict: the reconstruction is not the whole, "
                "well-formed stream; nothing written.\n");
        sqlite3_close(db);
        exit(EXIT_STRICT);
    }

    /* Output paths, all checked before any is written, so a refusal never
     * leaves half a set behind. <name>-<session UTC>.hdlc mirrors the name a
     * rawlog= tee synthesizes (celldiag-<imei>-<ts>.hdlc); two sessions in the
     * same second fall back to the full session id. */
    if (out_fname != "") {
        streams[0].path = out_fname;
    } else {
        std::map<std::string, int> base_count;
        std::vector<std::string> bases;
        for (const auto& st : streams) {
            bases.push_back(sanitize_filename(sources[st.src].name) + "-" +
                    session_utc(st.session_id));
            base_count[bases.back()]++;
        }
        for (size_t k = 0; k < streams.size(); k++) {
            auto base = bases[k];
            if (base_count[base] > 1)
                base = sanitize_filename(sources[streams[k].src].name) + "-" +
                    std::to_string(streams[k].session_id);
            streams[k].path = out_dir + "/" + base + ".hdlc";
        }
    }

    for (const auto& st : streams) {
        if (st.path != "-" && file_exists(st.path) && !force) {
            fprintf(stderr, "ERROR:  Output file '%s' exists already; use --force to "
                    "clobber it.\n", st.path.c_str());
            sqlite3_close(db);
            exit(EXIT_ERR);
        }
    }

    for (const auto& st : streams) {
        if (write_stream(db, st, st.path) != 0) {
            sqlite3_close(db);
            exit(EXIT_ERR);
        }
        if (verbose)
            fprintf(stderr, "* %s (%s) session %" PRIu64 ": %zu slices, %" PRIu64
                    " bytes -> %s\n", sources[st.src].name.c_str(),
                    sources[st.src].uuid.c_str(), st.session_id, st.take.size(),
                    st.bytes, st.path.c_str());
    }

    sqlite3_close(db);

    if (verbose)
        fprintf(stderr, "* KismetDB version %d\n* Done!\n", db_version);

    return EXIT_OK;
}
