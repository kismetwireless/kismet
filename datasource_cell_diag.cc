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

#include "config.h"

#include <sys/time.h>

#include <algorithm>
#include <cstring>

#include "kis_datasource.h"
#include "kis_databaselogfile.h"
#include "datasource_cell_diag.h"
#include "capture_cell_diag/diag_rawpkt.h"

// No diagspec leg headers here; see the decode-seam note in
// datasource_cell_diag.h.  The decode->frame chain lives in the capture helper
// (capture_cell_diag/diag_native_decode.cpp), which is the process that holds
// the raw DIAG bytes; this one only ever sees decoded JSON.

kis_datasource_cell_diag::kis_datasource_cell_diag(shared_datasource_builder in_builder) :
    kis_datasource(in_builder) {

    std::string devpath = munge_to_printable(get_definition_opt("device"));
    if (devpath != "") {
        set_int_source_cap_interface("celldiag#" + devpath);
    } else {
        set_int_source_cap_interface("celldiag");
    }

    set_int_source_hardware("celldiag");
    set_int_source_ipc_binary("kismet_cap_cell_diag");

    // Base construction is complete (kis_datasource ctor has returned into
    // this frame), so `this` is now a fully-formed kis_datasource_cell_diag and
    // insert() targets this source's own field map. Register the runtime counters.
    register_celldiag_fields();
    modemident.register_into(this);
}

void kis_datasource_cell_diag::register_celldiag_fields() {
    auto et = Globalreg::globalreg->entrytracker;

    diag_bytes_read =
        std::make_shared<tracker_element_uint64>(
            et->register_field("kismet.datasource.celldiag.bytes_read",
                tracker_element_factory<tracker_element_uint64>(),
                "raw DIAG bytes read from the modem port"));
    insert(diag_bytes_read);

    diag_obs_total =
        std::make_shared<tracker_element_uint64>(
            et->register_field("kismet.datasource.celldiag.obs_total",
                tracker_element_factory<tracker_element_uint64>(),
                "total cell_observation records relayed"));
    insert(diag_obs_total);

    diag_obs_per_sec =
        std::make_shared<tracker_element_double>(
            et->register_field("kismet.datasource.celldiag.obs_per_sec",
                tracker_element_factory<tracker_element_double>(),
                "recent cell_observation throughput (obs/sec)"));
    insert(diag_obs_per_sec);

    diag_last_obs_epoch =
        std::make_shared<tracker_element_uint64>(
            et->register_field("kismet.datasource.celldiag.last_obs_epoch",
                tracker_element_factory<tracker_element_uint64>(),
                "unix epoch of the most recent cell_observation"));
    insert(diag_last_obs_epoch);

    diag_helper_alive =
        std::make_shared<tracker_element_uint8>(
            et->register_field("kismet.datasource.celldiag.helper_alive",
                tracker_element_factory<tracker_element_uint8>(),
                "1 if the decoder is alive: the capture helper's in-process "
                "decoder, whose DIAG reader heartbeat is fresh"));
    insert(diag_helper_alive);

    diag_mask_preset =
        std::make_shared<tracker_element_string>(
            et->register_field("kismet.datasource.celldiag.mask_preset",
                tracker_element_factory<tracker_element_string>(),
                "active DIAG log-mask preset"));
    insert(diag_mask_preset);

    diag_decode_mode =
        std::make_shared<tracker_element_string>(
            et->register_field("kismet.datasource.celldiag.decode_mode",
                tracker_element_factory<tracker_element_string>(),
                "which decoder renders observations: native-only (the "
                "capture helper's in-process native decode legs)"));
    insert(diag_decode_mode);

    diag_f3_preset =
        std::make_shared<tracker_element_string>(
            et->register_field("kismet.datasource.celldiag.f3_preset",
                tracker_element_factory<tracker_element_string>(),
                "active F3 debug-log preset"));
    insert(diag_f3_preset);

    diag_rawlog_path =
        std::make_shared<tracker_element_string>(
            et->register_field("kismet.datasource.celldiag.rawlog_path",
                tracker_element_factory<tracker_element_string>(),
                "raw DIAG tee-to-disk path, empty if disabled"));
    insert(diag_rawlog_path);

    diag_rawlog_bytes =
        std::make_shared<tracker_element_uint64>(
            et->register_field("kismet.datasource.celldiag.rawlog_bytes",
                tracker_element_factory<tracker_element_uint64>(),
                "bytes written to the raw DIAG tee file"));
    insert(diag_rawlog_bytes);

    /* Not inferable from rawlog_path.  A runtime `rawlog=off` closes
     * the sink and keeps the path, deliberately, so that a source which has
     * stopped teeing can still tell the operator where the bytes it already
     * wrote went. Liveness therefore needs its own field, or every consumer
     * re-derives it from the path and gets it wrong the same way. */
    diag_rawlog_active =
        std::make_shared<tracker_element_uint8>(
            et->register_field("kismet.datasource.celldiag.rawlog_active",
                tracker_element_factory<tracker_element_uint8>(),
                "1 if the raw DIAG tee sink is open right now; a retained "
                "rawlog_path with rawlog_active=0 is a stopped tee"));
    insert(diag_rawlog_active);

    diag_inv_distinct =
        std::make_shared<tracker_element_uint32>(
            et->register_field("kismet.datasource.celldiag.inventory_distinct_codes",
                tracker_element_factory<tracker_element_uint32>(),
                "distinct (code,version) pairs seen this session"));
    insert(diag_inv_distinct);

    diag_inv_unrecognized =
        std::make_shared<tracker_element_uint32>(
            et->register_field("kismet.datasource.celldiag.inventory_unrecognized",
                tracker_element_factory<tracker_element_uint32>(),
                // The census reports unrecognized (code,version) keys, not
                // records.  Worded so a web UI renders "3" as three firmware
                // variants rather than three lost records.
                "distinct (code,version) keys with no known record layout"));
    insert(diag_inv_unrecognized);

    // `silent` is a stronger signal than `unrecognized`: a contract code that
    // parses fine and emits nothing is indistinguishable from "no cells in
    // range", whereas an unrecognized key is usually just new firmware.
    diag_inv_silent =
        std::make_shared<tracker_element_uint32>(
            et->register_field("kismet.datasource.celldiag.inventory_silent",
                tracker_element_factory<tracker_element_uint32>(),
                "distinct emit-contract (code,version) keys that parsed but "
                "produced no observation"));
    insert(diag_inv_silent);

    // The census's third state.  Not a finding about the stream, so it sits
    // apart from unrecognized/silent: it counts log CODES (not keys) whose
    // record layout is known and that no native leg reads yet -- the
    // native-coverage to-do list, with the codes named on the census status
    // line.
    diag_inv_undecoded_native =
        std::make_shared<tracker_element_uint32>(
            et->register_field("kismet.datasource.celldiag.inventory_undecoded_native",
                tracker_element_factory<tracker_element_uint32>(),
                "log codes with a known record layout that no native leg "
                "reads yet"));
    insert(diag_inv_undecoded_native);

    // The census table, which turns the three counters above from a verdict
    // into something an operator can act on.  "3 silent" says a problem
    // exists; only the table says which (code,version).
    diag_inv_table =
        std::make_shared<tracker_element_string>(
            et->register_field("kismet.datasource.celldiag.inventory_table",
                tracker_element_factory<tracker_element_string>(),
                "per-(code,version) census rows, ';'-separated, each "
                "`code/vN,count,decoded,dropped,emitted,enrich_failed,flags`"));
    insert(diag_inv_table);

    // The native decoder's counters.  The server keeps a machine-readable copy
    // for the celldiag panel to bind to.
    //
    // total_records is registered first and is not optional.  Coverage is a
    // ratio; a UI given `native_records` alone can render a numerator as if it
    // were a percentage. See diag_stats_extra_t for the all-or-none contract on
    // the emit side.
    diag_native_total_records =
        std::make_shared<tracker_element_uint64>(
            et->register_field("kismet.datasource.celldiag.native_total_records",
                tracker_element_factory<tracker_element_uint64>(),
                "DIAG LOG records the native extractor recovered -- the "
                "DENOMINATOR of native coverage"));
    insert(diag_native_total_records);

    diag_native_records =
        std::make_shared<tracker_element_uint64>(
            et->register_field("kismet.datasource.celldiag.native_records",
                tracker_element_factory<tracker_element_uint64>(),
                "records claimed by any native C++ decode leg, cell or GNSS"));
    insert(diag_native_records);

    diag_native_obs =
        std::make_shared<tracker_element_uint64>(
            et->register_field("kismet.datasource.celldiag.native_obs",
                tracker_element_factory<tracker_element_uint64>(),
                "cell observations the native legs produced"));
    insert(diag_native_obs);

    diag_native_declined =
        std::make_shared<tracker_element_uint64>(
            et->register_field("kismet.datasource.celldiag.native_declined",
                tracker_element_factory<tracker_element_uint64>(),
                "records where a native cell leg ran and legitimately found "
                "nothing -- a decline is not a failure"));
    insert(diag_native_declined);

    // Deliberately worded so a panel cannot render it as a throughput
    // number: enrichment changes no observation COUNT, only which FIELDS an
    // observation carries, which is exactly why native_obs alone cannot see it.
    diag_native_enriched =
        std::make_shared<tracker_element_uint64>(
            et->register_field("kismet.datasource.celldiag.native_enriched",
                tracker_element_factory<tracker_element_uint64>(),
                "observations that gained MCC/MNC/TAC/CellID from a SIB1 seen "
                "EARLIER in the stream; the only counter that moves when "
                "identity is gained or lost"));
    insert(diag_native_enriched);

    diag_native_gps_fixes =
        std::make_shared<tracker_element_uint64>(
            et->register_field("kismet.datasource.celldiag.native_gps_fixes",
                tracker_element_factory<tracker_element_uint64>(),
                "usable position fixes from the native GNSS leg -- counted in "
                "its OWN units, never folded into native_obs"));
    insert(diag_native_gps_fixes);

    diag_native_fallback_records =
        std::make_shared<tracker_element_uint64>(
            et->register_field("kismet.datasource.celldiag.native_fallback_records",
                tracker_element_factory<tracker_element_uint64>(),
                "records no native leg claimed: the native-coverage gap, by "
                "record"));
    insert(diag_native_fallback_records);

    // Stream switches, CRC census, decoder queue and bring-up; see the
    // header.  Registered through one small helper
    // each so the field name stays a literal a grep (and the panel contract
    // test) can find.
    auto reg_u8 = [&](const char *name, const char *desc) {
        auto f = std::make_shared<tracker_element_uint8>(
            et->register_field(name, tracker_element_factory<tracker_element_uint8>(), desc));
        insert(f);
        return f;
    };
    auto reg_u64 = [&](const char *name, const char *desc) {
        auto f = std::make_shared<tracker_element_uint64>(
            et->register_field(name, tracker_element_factory<tracker_element_uint64>(), desc));
        insert(f);
        return f;
    };
    auto reg_str = [&](const char *name, const char *desc) {
        auto f = std::make_shared<tracker_element_string>(
            et->register_field(name, tracker_element_factory<tracker_element_string>(), desc));
        insert(f);
        return f;
    };
    diag_switches_reported = reg_u8("kismet.datasource.celldiag.switches_reported",
        "1 once the helper has reported its stream switches; the "
        "rawpackets_* / qsh_* / anchor_* fields mean nothing while this is 0");
    diag_rawpackets_on = reg_u8("kismet.datasource.celldiag.rawpackets_on",
        "1 if the raw DIAG stream goes into the kismetdb as DLT 147 packets");
    diag_rawpackets_slices = reg_u64("kismet.datasource.celldiag.rawpackets_slices",
        "raw DIAG slices delivered to the kismetdb this session");
    diag_rawpackets_dropped = reg_u64("kismet.datasource.celldiag.rawpackets_dropped",
        "raw DIAG slices lost to a full ring");
    diag_qsh_requested = reg_u8("kismet.datasource.celldiag.qsh_requested",
        "1 if qsh=on (the full F3 surface) was asked for; live sources only");
    diag_qsh_armed = reg_u8("kismet.datasource.celldiag.qsh_armed",
        "1 if the QSH arm was sent this session");
    diag_anchor_count = reg_u64("kismet.datasource.celldiag.anchor_count",
        "ClockAnchor rows completed this session");
    diag_anchor_ring_dropped = reg_u64("kismet.datasource.celldiag.anchor_ring_dropped",
        "ClockAnchor rows a full output ring would not take (still in the sidecar)");
    diag_obs_ring_dropped = reg_u64("kismet.datasource.celldiag.obs_ring_dropped",
        "cell observations dropped because the output ring was full; a live "
        "source drops rather than stop reading the DIAG port");
    diag_anchor_last_epoch = reg_u64("kismet.datasource.celldiag.anchor_last_epoch",
        "host time of the last ClockAnchor; 0 = none yet");
    diag_crc_reported = reg_u8("kismet.datasource.celldiag.crc_reported",
        "1 once the helper has reported its CRC census; the crc_* "
        "fields mean nothing while this is 0");
    diag_crc_checked = reg_u64("kismet.datasource.celldiag.crc_checked",
        "DIAG frames that reached the CRC check this session");
    diag_crc_ok = reg_u64("kismet.datasource.celldiag.crc_ok",
        "DIAG frames that passed the CRC check");
    diag_crc_bad = reg_u64("kismet.datasource.celldiag.crc_bad",
        "DIAG frames that FAILED the CRC check: bytes the modem sent that did "
        "not all reach the capture (a tty overflow drops them silently)");
    diag_crc_damage_alerts = reg_u64("kismet.datasource.celldiag.crc_damage_alerts",
        "check windows whose CRC-bad count crossed the damage floor; > 0 means "
        "this stream lost bytes, and the source warning says so");
    diag_bringup_ms = reg_u64("kismet.datasource.celldiag.bringup_ms",
        "deferred bring-up time so far / in total (ms)");
    diag_bringup_phases = reg_str("kismet.datasource.celldiag.bringup_phases",
        "bring-up phases completed, e.g. \"at_scan=1204ms port_detect=3ms\"; "
        "empty = none reported this open");
    diag_bringup_error = reg_str("kismet.datasource.celldiag.bringup_error",
        "why the deferred bring-up failed; empty = it has not failed this open");
}

kis_datasource_cell_diag::~kis_datasource_cell_diag() {

}

// Standard Adler-32 (portable, no external lib) used to derive a deterministic,
// collision-resistant UUID from the IMEI. NOTE: this is textbook Adler-32, which
// differs from capture_framework's non-standard adler32_csum, so the value is
// NOT the same one the capture helper's compose_diag_uuid() reports at
// probe/--list time. That is fine: uniqueness (not cross-layer parity) is the
// requirement, and at runtime the datasource UUID set here is authoritative
// (local_uuid pre-empts the open-report UUID on both success and failure).
static uint32_t celldiag_adler32(const char *buf) {
    uint32_t s1 = 1, s2 = 0;
    for (const char *p = buf; *p; p++) {
        s1 = (s1 + (uint8_t)*p) % 65521;
        s2 = (s2 + s1) % 65521;
    }
    return (s2 << 16) | s1;
}

// True if the definition carries an explicit `uuid=` SOURCE OPTION. Options in a
// Kismet source definition are `interface:k=v,k=v`, so a real option token is
// always preceded by ':' or ','. A plain substring search would also fire on a
// value that happens to contain "uuid=" (e.g. rawlog=/cap/uuid=x.hdlc) and would
// then skip the injection, leaving the source back on the all-zeros UUID the
// injection exists to prevent.
static bool celldiag_definition_has_uuid_opt(const std::string& def) {
    for (size_t p = def.find("uuid="); p != std::string::npos;
            p = def.find("uuid=", p + 1)) {
        if (p > 0 && (def[p - 1] == ':' || def[p - 1] == ','))
            return true;
    }
    return false;
}

// The deterministic celldiag UUID for an IMEI: adler32 of the source-type +
// adler32 of "celldiag"+IMEI. Format: %08X-0000-0000-0000-0000%08X. Stable
// across port renumbering; unique per (IMEI, source-type).
static std::string celldiag_uuid_for_imei(const std::string& imei) {
    std::string seed = "celldiag" + imei;
    char out[40];
    snprintf(out, sizeof(out), "%08X-0000-0000-0000-0000%08X",
            celldiag_adler32("kismet_cap_cell_diag"),
            celldiag_adler32(seed.c_str()));
    return std::string(out);
}

void kis_datasource_cell_diag::open_interface(std::string in_definition, unsigned int in_transaction,
        open_callback_t in_cb) {
    // Give this source a unique, port-stable UUID BEFORE the IPC open, by
    // injecting a deterministic uuid= into the definition when the operator did
    // not supply one. This is required (not just nice) because Kismet merges a
    // datasource into the tracker even when its open FAILS (datasourcetracker.cc
    // "Always merge it so it gets scheduled for re-opening"), and on a failed
    // open the core open-report handler returns before adopting the report's
    // UUID -- so a source that is still scanning / mid-handshake would otherwise
    // register the all-zeros UUID and collide with every other not-yet-open
    // celldiag source. Setting uuid= up front (the same path an operator-supplied
    // uuid= takes) makes get_source_uuid() unique from construction. The
    // value is NOT byte-identical to the capture helper's compose_diag_uuid()
    // (see the celldiag_adler32 note above -- the helper uses capture_framework's
    // non-standard adler32_csum); that is cosmetic, because the datasource UUID
    // set here is the authoritative runtime value and uniqueness is the contract.
    if (!celldiag_definition_has_uuid_opt(in_definition)) {
        // interface token is everything before the first ':'; strip celldiag-.
        std::string iface = in_definition.substr(0, in_definition.find(':'));
        std::string imei;
        if (iface.rfind("celldiag-", 0) == 0)
            imei = iface.substr(9);

        bool imei_ok = (imei.length() == 15);
        for (char c : imei)
            if (!isdigit((unsigned char)c)) { imei_ok = false; break; }

        if (imei_ok) {
            std::string u = celldiag_uuid_for_imei(imei);
            in_definition +=
                (in_definition.find(':') == std::string::npos ? ":" : ",");
            in_definition += "uuid=" + u;
        }
    }

    // This open's bring-up reports from scratch. Without the clear a
    // retry that SUCCEEDS would keep showing the previous attempt's failure,
    // and handle_source_error would pin a stale reason on a later, unrelated
    // exit.
    diag_bringup_ms->set(0);
    diag_bringup_phases->set("");
    diag_bringup_error->set("");

    kis_datasource::open_interface(in_definition, in_transaction, in_cb);
}

namespace {

uint64_t rawpkt_le64(const uint8_t *p) {
    uint64_t v = 0;
    for (int i = 7; i >= 0; i--)
        v = (v << 8) | p[i];
    return v;
}

// A JSON string literal. The reason is the source's error text; quote it
// rather than trust it to hold no '"' or '\'.
std::string json_quoted(const std::string& s) {
    std::string out = "\"";
    for (unsigned char c : s) {
        switch (c) {
            case '"':  out += "\\\""; break;
            case '\\': out += "\\\\"; break;
            case '\n': out += "\\n"; break;
            case '\r': out += "\\r"; break;
            case '\t': out += "\\t"; break;
            default:
                if (c < 0x20) {
                    char esc[8];
                    snprintf(esc, sizeof(esc), "\\u%04x", c);
                    out += esc;
                } else {
                    out += (char) c;
                }
        }
    }
    out += "\"";
    return out;
}

} // namespace

void kis_datasource_cell_diag::adopt_sibling_identity() {
    const auto rec = modemident.adopt_sibling("celldiag", " DIAG");
    if (rec.empty())
        return;

    std::string label;
    try {
        label = nlohmann::json::parse(rec).value("label", "");
    } catch (const std::exception&) { }
    if (!label.empty())
        set_int_source_hardware(label);

    // The same two persistence steps the helper's own record gets: the
    // `datasources` row now, and a timestamped ModemIdentity data row, written
    // the way the RawDiagAbort row is, under this source.
    auto dbf = Globalreg::fetch_global_as<kis_database_logfile>("DATABASELOG");
    if (dbf != nullptr)
        dbf->log_datasource(std::static_pointer_cast<kis_datasource>(shared_from_this()));

    auto packet = packetchain->generate_packet();
    gettimeofday(&(packet->ts), nullptr);
    packet->suppress_gps = true;
    auto jsoninfo = packetchain->new_packet_component<kis_json_packinfo>();
    jsoninfo->type = MODEMIDENT_TYPE;
    jsoninfo->json_string = rec;
    packet->insert(pack_comp_json, jsoninfo);
    auto datasrcinfo = packetchain->new_packet_component<packetchain_comp_datasource>();
    datasrcinfo->ref_source = this;
    packet->insert(pack_comp_datasrc, datasrcinfo);
    packetchain->process_packet(packet);

    _MSG_INFO("Data source '{}' opened without AT identity (its AT node was held); "
            "adopted '{}' as read over AT by a same-IMEI source of this server",
            get_source_name(), label);
}

kis_datasource::rx_content kis_datasource_cell_diag::handle_rx_data_content(kis_packet *packet,
        kis_datachunk *datachunk, const uint8_t *content, size_t content_sz) {
    adopt_sibling_identity();
    if (datachunk != nullptr && datachunk->dlt == DIAG_RAWPKT_DLT) {
        // A slice carries its stream offset, so no two are ever the same frame
        // heard twice, and the packetchain's duplicate test (a CRC32 match
        // within its 1024-packet window AND identical frame bytes) should
        // never fire on one.  The exemption makes that a contract instead of
        // a consequence of the header layout: a slice marked duplicate would
        // take the earlier packet's number and decoded components, and with
        // kis_log_duplicate_packets=false would not be logged at all -- one
        // DIAG frame lost, with no drop row to say so.
        packet->dedupe_exempt = true;
    }

    return kis_datasource::handle_rx_data_content(packet, datachunk, content, content_sz);
}

void kis_datasource_cell_diag::handle_rx_packet(std::shared_ptr<kis_packet> packet) {
    auto chunk = packet->fetch<kis_datachunk>(pack_comp_linkframe);
    if (chunk == nullptr || chunk->dlt != DIAG_RAWPKT_DLT) {
        kis_datasource::handle_rx_packet(packet);
        return;
    }

    // The slice is counted here, as it enters the packetchain, and not in
    // handle_rx_data_content(): the base rx path returns on `cancelled` after
    // that point, and trigger_error() sets it from the IPC reaper's timer
    // thread before it waits on ext_mutex and runs handle_source_error().
    // Counting earlier could leave one slice counted and abandoned: a
    // RawDiagAbort row naming a slice, and its bytes, the kismetdb never got.
    // Counting and handing over under the lock the witness snapshots under
    // makes "counted" mean "logged".
    std::lock_guard<std::mutex> lk(raw_session_mutex);
    if (!note_raw_slice((const uint8_t *) chunk->data(), chunk->length()))
        return;

    kis_datasource::handle_rx_packet(packet);
}

bool kis_datasource_cell_diag::note_raw_slice(const uint8_t *p, size_t n) {
    // The checks diag_rawpkt_parse() makes, restated: the server does not link
    // diag_rawpkt.c, which belongs to the helper's own sub-make (kismetdb_to_hdlc
    // restates them for the same reason). A slice failing them is left alone
    // here; the readers count it as malformed.
    if (n < DIAG_RAWPKT_HDR_LEN || memcmp(p, DIAG_RAWPKT_MAGIC, 4) != 0 ||
            p[4] != DIAG_RAWPKT_VERSION)
        return true;

    size_t header_len = (size_t) p[6] | ((size_t) p[7] << 8);
    if (header_len < DIAG_RAWPKT_HDR_LEN || header_len > n)
        return true;

    bool is_end = (p[5] & DIAG_RAWPKT_FLAG_END) != 0;
    size_t payload_len = n - header_len;
    if (is_end && payload_len != 0)
        return true;

    uint64_t session = rawpkt_le64(p + 8);
    uint64_t offset = rawpkt_le64(p + 16);

    // One helper process per session: a new id means the source was reopened.
    if (!raw_session.active || raw_session.session_id != session) {
        raw_session = raw_session_state{};
        raw_session.active = true;
        raw_session.session_id = session;
    }

    // The row is the session's last word: a slice logged after it would sit past
    // the delivered_end it names.
    if (raw_session.witnessed)
        return false;

    if (is_end) {
        raw_session.end_seen = true;
        return true;
    }

    raw_session.slices++;
    raw_session.delivered_end = std::max(raw_session.delivered_end, offset + payload_len);
    return true;
}

void kis_datasource_cell_diag::handle_source_error() {
    // A helper whose deferred bring-up failed exits right after
    // saying why, and the transport then reports the generic "IPC connection
    // closed". The bring-up's own reason is the one an operator can act on
    // ("Pass diagport=/dev/ttyUSBx explicitly"), so it wins -- only over that
    // generic text, never over a specific error the transport raised.
    {
        auto why = diag_bringup_error->get();
        if (!why.empty() && get_source_error_reason() == "IPC connection closed")
            set_int_source_error_reason("bring-up failed: " + why);
    }

    // Before the base, which may schedule the retry that starts the next
    // session. The error reason is already set (kis_datasource::handle_error).
    witness_raw_abort(get_source_error_reason());

    kis_datasource::handle_source_error();
}

bool kis_datasource_cell_diag::witness_raw_abort(const std::string& reason) {
    raw_session_state s;
    {
        std::lock_guard<std::mutex> lk(raw_session_mutex);
        s = raw_session;
        raw_session = raw_session_state{};

        // Nothing to witness: no raw stream (rawpackets=off, a bring-up that failed
        // before its first slice), or one that reached its teardown. With END in,
        // the stream is confirmed whole, whatever ended the helper after it.
        if (!s.active || s.end_seen || s.witnessed || s.slices == 0)
            return false;

        // A source dying while the SERVER stops is a stop, not a mid-drive death:
        // the stream ends there anyway, and the readers' plain "no END" note is
        // the honest verdict for it.
        if (Globalreg::globalreg->spindown)
            return false;

        // Decided in the critical section handle_rx_packet() counts in:
        // every slice the row counts is already in the packetchain, and a late
        // slice of this session is dropped rather than logged past the row.
        raw_session.active = true;
        raw_session.session_id = s.session_id;
        raw_session.witnessed = true;
    }

    auto json = fmt::format("{{\"schema\":\"{}\",\"session_id\":{},\"delivered_end\":{},"
            "\"slices\":{},\"reason\":{}}}", DIAG_RAWPKT_ABORT_SCHEMA, s.session_id,
            s.delivered_end, s.slices, json_quoted(reason));

    // The same route a helper's RawDiagDrop row takes (handle_rx_jsonlayer_v3 ->
    // handle_rx_packet): a JSON component plus this datasource, which the
    // kismetdb logger writes to the `data` table under this source's uuid.
    auto packet = packetchain->generate_packet();
    gettimeofday(&(packet->ts), nullptr);
    // A loss record, not an observation: no position lookup.
    packet->suppress_gps = true;

    auto jsoninfo = packetchain->new_packet_component<kis_json_packinfo>();
    jsoninfo->type = DIAG_RAWPKT_ABORT_TYPE;
    jsoninfo->json_string = json;
    packet->insert(pack_comp_json, jsoninfo);

    auto datasrcinfo = packetchain->new_packet_component<packetchain_comp_datasource>();
    datasrcinfo->ref_source = this;
    packet->insert(pack_comp_datasrc, datasrcinfo);

    packetchain->process_packet(packet);

    _MSG_ERROR("Data source '{}' failed in the middle of raw DIAG session {} ({}): the "
            "server received the stream through offset {} ({} slices) and no END, so the "
            "rest died with the capture helper; recorded as a {} row",
            get_source_name(), s.session_id, reason, s.delivered_end, s.slices,
            DIAG_RAWPKT_ABORT_TYPE);

    return true;
}

void kis_datasource_cell_diag::handle_rx_jsonlayer_v3(std::shared_ptr<kis_packet> packet,
        mpack_node_t& root, mpack_tree_t *tree) {
    // First, in case a sibling published since this source's last rx --
    // the intercepted types below return without reaching the end.
    adopt_sibling_identity();

    // Peek the mpack json-block's routing type. The capture
    // helper emits its structured runtime counters as their own type
    // ("diag_stats"), distinct from the "CellModem" cell_observations, so we can
    // intercept them here purely on the type field -- no risk of building a
    // bogus device from a stats object. Navigation mirrors the base handler.
    if (mpack_node_map_contains_uint(root, KIS_EXTERNAL_V3_KDS_DATAREPORT_FIELD_JSONBLOCK)) {
        auto jsonmap = mpack_node_map_uint(root, KIS_EXTERNAL_V3_KDS_DATAREPORT_FIELD_JSONBLOCK);

        if (mpack_tree_error(tree) == mpack_ok) {
            auto type_n = mpack_node_map_uint_optional(jsonmap,
                    KIS_EXTERNAL_V3_KDS_SUB_JSON_FIELD_TYPE);

            if (!mpack_node_is_missing(type_n)) {
                auto type_s = mpack_node_str(type_n);
                auto type_sz = mpack_node_data_len(type_n);

                // There are two intercepted types.  Both are handled by one
                // test against a small set rather than a chain of `== "..."`
                // comparisons: the interception and the do-not-delegate below
                // are one decision, and splitting them into per-type branches is
                // how a new control line ends up intercepted but not applied, or
                // applied and then ALSO devicified by the base handler.
                const std::string type_str =
                    type_s != nullptr ? std::string(type_s, type_sz) : std::string();

                // The helper's ModemIdentity record. Applied to this
                // source's modem fields and hardware label, then deliberately
                // NOT swallowed -- it falls through to the base handler so
                // kismetdb keeps it as a `ModemIdentity` data row. phy_cell
                // devicifies only CellModem/Cellular, so no device results.
                if (type_str == MODEMIDENT_TYPE) {
                    auto json_n = mpack_node_map_uint_optional(jsonmap,
                            KIS_EXTERNAL_V3_KDS_SUB_JSON_FIELD_JSON);
                    if (!mpack_node_is_missing(json_n)) {
                        auto json_s = mpack_node_str(json_n);
                        auto json_sz = mpack_node_data_len(json_n);
                        if (json_s != nullptr) {
                            auto label = modemident.apply_json(
                                    std::string(json_s, json_sz));
                            if (!label.empty())
                                set_int_source_hardware(label);
                            // Rewrite this source's kismetdb `datasources` row
                            // now.  It is otherwise rewritten only every
                            // kis_log_datasource_rate (30 s), and the shutdown
                            // rewrite does not land, so a shorter session would
                            // persist "DIAG opening" with empty modem fields.
                            auto dbf = Globalreg::fetch_global_as<kis_database_logfile>(
                                    "DATABASELOG");
                            if (dbf != nullptr)
                                dbf->log_datasource(std::static_pointer_cast<kis_datasource>(
                                        shared_from_this()));
                        }
                    }
                }

                if (type_str == "diag_stats" || type_str == "diag_census") {
                    auto json_n = mpack_node_map_uint_optional(jsonmap,
                            KIS_EXTERNAL_V3_KDS_SUB_JSON_FIELD_JSON);

                    if (!mpack_node_is_missing(json_n)) {
                        auto json_s = mpack_node_str(json_n);
                        auto json_sz = mpack_node_data_len(json_n);
                        if (json_s != nullptr) {
                            if (type_str == "diag_census")
                                apply_diag_census_json(
                                        std::string(json_s, json_sz));
                            else
                                apply_diag_stats_json(
                                        std::string(json_s, json_sz));
                        }
                    }

                    // Intercepted: do NOT delegate. Leaving the base handler
                    // un-called means no kis_json_packinfo is inserted, so
                    // phy_cell never sees (and never tries to devicify) a stats
                    // object -- it is a datasource-field update only.
                    return;
                }
            }
        }
    }

    // Anything else (CellModem cell_observations, gps, ...) -> base behavior.
    kis_datasource::handle_rx_jsonlayer_v3(packet, root, tree);

    // And last, after the base handler has logged this message -- which
    // may be this source's own "definition" ModemIdentity row, so the adopted
    // row always follows it.
    adopt_sibling_identity();
}

void kis_datasource_cell_diag::apply_diag_census_json(const std::string& json_str) {
    // Same defensive contract as apply_diag_stats_json: a corrupt
    // or partial line must never disrupt capture, and a missing key leaves the
    // prior value intact rather than blanking a table that was correct.
    nlohmann::json j;
    try {
        j = nlohmann::json::parse(json_str);
    } catch (const std::exception&) {
        return;
    }

    if (!j.is_object())
        return;

    // An empty string is a legitimate value here and is set, not skipped: a
    // census that has arrived and has no rows to show is a different state from
    // no census at all, and the panel distinguishes them using
    // inventory_distinct_codes (which is > 0 the moment any record is counted).
    // Skipping the empty case would leave a stale table from an earlier census
    // rendered beside a current count -- the two disagreeing, with nothing
    // saying which is live.
    if (j.contains("table") && j["table"].is_string())
        diag_inv_table->set(j["table"].get<std::string>());
}

void kis_datasource_cell_diag::apply_diag_stats_json(const std::string& json_str) {
    // A corrupt/partial stats line must never disrupt capture -- parse defensively
    // and drop silently on any error. Each key is optional and type-checked; a
    // missing or mistyped key leaves the field's prior value intact.
    nlohmann::json j;
    try {
        j = nlohmann::json::parse(json_str);
    } catch (const std::exception&) {
        return;
    }

    if (!j.is_object())
        return;

    if (j.contains("bytes_read") && j["bytes_read"].is_number_unsigned())
        diag_bytes_read->set(j["bytes_read"].get<uint64_t>());
    if (j.contains("obs_total") && j["obs_total"].is_number_unsigned())
        diag_obs_total->set(j["obs_total"].get<uint64_t>());
    if (j.contains("obs_per_sec") && j["obs_per_sec"].is_number())
        diag_obs_per_sec->set(j["obs_per_sec"].get<double>());
    if (j.contains("last_obs_epoch") && j["last_obs_epoch"].is_number())
        diag_last_obs_epoch->set(j["last_obs_epoch"].get<uint64_t>());
    if (j.contains("helper_alive") && j["helper_alive"].is_number())
        diag_helper_alive->set((uint8_t)(j["helper_alive"].get<int>() ? 1 : 0));
    if (j.contains("mask_preset") && j["mask_preset"].is_string())
        diag_mask_preset->set(j["mask_preset"].get<std::string>());
    if (j.contains("decode_mode") && j["decode_mode"].is_string())
        diag_decode_mode->set(j["decode_mode"].get<std::string>());

    // Each key is optional, and that is load-bearing rather than just
    // defensive: the emit site omits a key whose source has not reported (no
    // rawlog= configured, no census received yet). "Missing key leaves the prior
    // value intact" is therefore the correct behavior -- it keeps a
    // never-reported field at its default instead of stamping a zero that reads
    // as a healthy measurement.
    if (j.contains("f3_preset") && j["f3_preset"].is_string())
        diag_f3_preset->set(j["f3_preset"].get<std::string>());
    if (j.contains("rawlog_path") && j["rawlog_path"].is_string())
        diag_rawlog_path->set(j["rawlog_path"].get<std::string>());
    if (j.contains("rawlog_bytes") && j["rawlog_bytes"].is_number_unsigned())
        diag_rawlog_bytes->set(j["rawlog_bytes"].get<uint64_t>());
    // Boolean on the wire, so is_boolean() -- NOT is_number_unsigned(), which
    // would silently skip every emit and leave this at the default 0 while
    // rawlog_path arrived normally, presenting as a tee that always reads
    // stopped.
    if (j.contains("rawlog_active") && j["rawlog_active"].is_boolean())
        diag_rawlog_active->set(j["rawlog_active"].get<bool>() ? 1 : 0);
    if (j.contains("inventory_distinct_codes") &&
            j["inventory_distinct_codes"].is_number_unsigned())
        diag_inv_distinct->set(
            (uint32_t)j["inventory_distinct_codes"].get<uint64_t>());
    if (j.contains("inventory_unrecognized") &&
            j["inventory_unrecognized"].is_number_unsigned())
        diag_inv_unrecognized->set(
            (uint32_t)j["inventory_unrecognized"].get<uint64_t>());
    if (j.contains("inventory_silent") &&
            j["inventory_silent"].is_number_unsigned())
        diag_inv_silent->set((uint32_t)j["inventory_silent"].get<uint64_t>());
    if (j.contains("inventory_undecoded_native") &&
            j["inventory_undecoded_native"].is_number_unsigned())
        diag_inv_undecoded_native->set(
            (uint32_t)j["inventory_undecoded_native"].get<uint64_t>());

    // The native decoder's counters.  Same optional-key contract as the rest:
    // an unarmed decoder omits the whole group, and these fields must then stay
    // at their defaults.  Stamping zeros would read as a confident
    // `native_records=0` that was never measured.
    if (j.contains("native_total_records") &&
            j["native_total_records"].is_number_unsigned())
        diag_native_total_records->set(j["native_total_records"].get<uint64_t>());
    if (j.contains("native_records") && j["native_records"].is_number_unsigned())
        diag_native_records->set(j["native_records"].get<uint64_t>());
    if (j.contains("native_obs") && j["native_obs"].is_number_unsigned())
        diag_native_obs->set(j["native_obs"].get<uint64_t>());
    if (j.contains("native_declined") && j["native_declined"].is_number_unsigned())
        diag_native_declined->set(j["native_declined"].get<uint64_t>());
    if (j.contains("native_enriched") && j["native_enriched"].is_number_unsigned())
        diag_native_enriched->set(j["native_enriched"].get<uint64_t>());
    if (j.contains("native_gps_fixes") && j["native_gps_fixes"].is_number_unsigned())
        diag_native_gps_fixes->set(j["native_gps_fixes"].get<uint64_t>());
    if (j.contains("native_fallback_records") &&
            j["native_fallback_records"].is_number_unsigned())
        diag_native_fallback_records->set(
            j["native_fallback_records"].get<uint64_t>());

    // The stream switches (each group sent whole or not at all).
    if (j.contains("rawpackets_on") && j["rawpackets_on"].is_boolean()) {
        diag_switches_reported->set(1);
        diag_rawpackets_on->set(j["rawpackets_on"].get<bool>() ? 1 : 0);
    }
    if (j.contains("rawpackets_slices") && j["rawpackets_slices"].is_number_unsigned())
        diag_rawpackets_slices->set(j["rawpackets_slices"].get<uint64_t>());
    if (j.contains("rawpackets_dropped") && j["rawpackets_dropped"].is_number_unsigned())
        diag_rawpackets_dropped->set(j["rawpackets_dropped"].get<uint64_t>());
    if (j.contains("qsh_requested") && j["qsh_requested"].is_boolean())
        diag_qsh_requested->set(j["qsh_requested"].get<bool>() ? 1 : 0);
    if (j.contains("qsh_armed") && j["qsh_armed"].is_boolean())
        diag_qsh_armed->set(j["qsh_armed"].get<bool>() ? 1 : 0);
    if (j.contains("anchor_count") && j["anchor_count"].is_number_unsigned())
        diag_anchor_count->set(j["anchor_count"].get<uint64_t>());
    if (j.contains("anchor_ring_dropped") && j["anchor_ring_dropped"].is_number_unsigned())
        diag_anchor_ring_dropped->set(j["anchor_ring_dropped"].get<uint64_t>());
    if (j.contains("obs_ring_dropped") && j["obs_ring_dropped"].is_number_unsigned())
        diag_obs_ring_dropped->set(j["obs_ring_dropped"].get<uint64_t>());
    if (j.contains("anchor_last_epoch") && j["anchor_last_epoch"].is_number_unsigned())
        diag_anchor_last_epoch->set(j["anchor_last_epoch"].get<uint64_t>());

    // The CRC census (the helper sends the group whole or not at all).
    if (j.contains("crc_checked") && j["crc_checked"].is_number_unsigned()) {
        diag_crc_reported->set(1);
        diag_crc_checked->set(j["crc_checked"].get<uint64_t>());
    }
    if (j.contains("crc_ok") && j["crc_ok"].is_number_unsigned())
        diag_crc_ok->set(j["crc_ok"].get<uint64_t>());
    if (j.contains("crc_bad") && j["crc_bad"].is_number_unsigned())
        diag_crc_bad->set(j["crc_bad"].get<uint64_t>());
    if (j.contains("crc_damage_alerts") && j["crc_damage_alerts"].is_number_unsigned()) {
        auto alerts = j["crc_damage_alerts"].get<uint64_t>();
        // A new damage window: the source's standing warning says so, in the
        // panel, until the source is reopened. The helper's ERROR line is on the
        // bus once; this is what an operator glancing at Data Sources sees.
        if (alerts > diag_crc_damage_alerts->get())
            set_int_source_warning(fmt::format(
                "DIAG stream losing bytes: {} of {} frames failed CRC ({} damaged "
                "window(s)). Bytes the modem sent are not reaching the capture -- "
                "the read loop fell behind a DIAG burst",
                diag_crc_bad->get(), diag_crc_checked->get(), alerts));
        diag_crc_damage_alerts->set(alerts);
    }

    // Bring-up progress / failure.
    if (j.contains("bringup_ms") && j["bringup_ms"].is_number_unsigned())
        diag_bringup_ms->set(j["bringup_ms"].get<uint64_t>());
    if (j.contains("bringup_phases") && j["bringup_phases"].is_string())
        diag_bringup_phases->set(j["bringup_phases"].get<std::string>());
    if (j.contains("bringup_error") && j["bringup_error"].is_string())
        diag_bringup_error->set(j["bringup_error"].get<std::string>());
}
