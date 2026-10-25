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

#ifndef __DATASOURCE_CELL_DIAG_H__
#define __DATASOURCE_CELL_DIAG_H__

#include "config.h"

#include <cstdint>
#include <vector>
#include <cstdint>
#include <mutex>

#include "kis_datasource.h"
#include "datasource_cell_modemident.h"

// Do not #include a diagspec leg header here.  This translation unit is on the
// server side of the capture fork, and no decodable DIAG record ever reaches
// it.  (Raw stream slices do arrive, as DLT 147 packets, but only for the
// loggers; see the decode-seam note in the protected section below.)
// diagspec/check_binary_symbols.sh's `server` role fails the kismet link if a
// leg symbol reappears in the binary.

class kis_datasource_cell_diag;
typedef std::shared_ptr<kis_datasource_cell_diag> shared_datasource_cell_diag;

class kis_datasource_cell_diag : public kis_datasource {
public:
    kis_datasource_cell_diag(shared_datasource_builder in_builder);
    virtual ~kis_datasource_cell_diag();

protected:
    virtual void open_interface(std::string in_definition, unsigned int in_transaction,
            open_callback_t in_cb) override;

    // The DIAG decode seam is not in this class, and cannot be.
    //
    //   * DIAG is decoded inside the capture helper (capture_cell_diag/), not
    //     in the server.
    //   * The helper's decoded upstream is cf_send_json(): observations,
    //     diag_stats, ClockAnchor rows.
    //   * This class's only JSON rx override, handle_rx_jsonlayer_v3() below,
    //     peeks an mpack JSON block.
    //
    // So the server receives already-decoded JSON by design, and a decode leg
    // linked here would be unreachable.  There is exactly one implementation per
    // log code, in diagspec/enrichment/cpp/, reached from
    // capture_cell_diag/diag_native_decode.cpp where the raw bytes are.
    //
    // Raw bytes do reach this process, and that changes none of the above.  The
    // helper also sends the raw DIAG stream via cf_send_data(), as DLT 147
    // packets (offset-stamped slices, contract in capture_cell_diag/diag_rawpkt.h).
    // They take the base class's handle_rx_datalayer_v3() -> LINKFRAME path, and
    // the only consumers are the loggers: kis_databaselogfile writes them to the
    // kismetdb `packets` table (and a pcapng log, if enabled, writes them too).
    // That is a logging path, not a decode seam: a slice is a cut of the byte
    // stream, not a record, and decoding one here would be a second decoder
    // racing the helper's.
    //
    // If server-side decode is ever designed, re-add the seam here and flip
    // check_binary_symbols.sh's `server` role back to a presence assertion.
    // Re-adding one without the other fails the kismet link.
    //
    // A leg takes the code-specific bytes after the DIAG log-container header,
    // starting at the version byte, not the whole record.  Handing it the
    // container is a silent wrong answer, not a parse failure.
    //
    // Entry points formerly declared here, and the symbols they forwarded to:
    //   decode_0xb0c0_gsmtap         -> diagspec::celldiag::diag_0xb0c0_to_gsmtap
    //   decode_0xb821_exported_pdu   -> diagspec::celldiag::diag_0xb821_to_exported_pdu
    //   decode_0xb808_exported_pdu   -> diagspec::celldiag::diag_0xb808_to_exported_pdu
    //   decode_0xb192_observations   -> diag_0xb192_observation::observations
    //   decode_0xb195_observations   -> diag_0xb195_observation::observations
    //   decode_0xb0c0_observations   -> diag_0xb0c0_observation::observations
    //   decode_0xb97f_observations   -> diag_0xb97f_observation::observations
    // The right-hand symbols still exist and are linked into the capture
    // helper.

    // Intercept the capture helper's structured
    // "diag_stats" JSON object and SET the registered runtime-counter fields from
    // it, so /datasource/all_sources.json reports live counters. Any other json
    // type (notably "CellModem" cell_observations) is delegated to the base so it
    // still builds `Cellular` devices.
    virtual void handle_rx_jsonlayer_v3(std::shared_ptr<kis_packet> packet,
            mpack_node_t& root, mpack_tree_t *tree) override;

    // The witness for a raw DIAG stream whose helper died mid-session.
    //
    // A helper killed by the capture framework's 15 s PING watchdog (a stalled
    // server), a crash or an OOM kill reaches no teardown: no END slice, and its
    // out-ring (up to 4 MiB, queued, not dropped) dies with it, so no
    // RawDiagDrop row either.  Without a witness, the readers would pass such a
    // truncated stream under --strict.  The helper cannot write that down,
    // because the server is not reading it.  This class can: it follows each
    // raw session from the slice headers alone, and when the source fails
    // mid-session it writes one RawDiagAbort data row (the contract is in
    // capture_cell_diag/diag_rawpkt.h).
    //
    // It reads the 24-byte CDRH slice header (stream framing, not DIAG).  No
    // DIAG record is looked at, so the decode-seam note above stands.
    virtual rx_content handle_rx_data_content(kis_packet *packet, kis_datachunk *datachunk,
            const uint8_t *content, size_t content_sz) override;
    virtual void handle_source_error() override;
    // A raw slice is counted where it enters the packetchain, not in
    // handle_rx_data_content(): see the .cc.
    virtual void handle_rx_packet(std::shared_ptr<kis_packet> packet) override;

    struct raw_session_state {
        bool active = false;         // a slice of this session has arrived
        bool end_seen = false;       // ...and so has its END
        uint64_t session_id = 0;
        uint64_t delivered_end = 0;  // one past the highest stream byte received
        uint64_t slices = 0;         // data slices received
        bool witnessed = false;      // its RawDiagAbort row is sent: no slice after it
    };

    // The rx path runs under ext_mutex and the error path does not, so the
    // session carries its own lock.  handle_rx_packet() holds it from the count
    // through the hand-off to the packetchain, and witness_raw_abort() takes its
    // snapshot under it, so the row never counts a slice the kismetdb lacks.
    std::mutex raw_session_mutex;
    raw_session_state raw_session;

    // Count one slice into its session.  Caller holds raw_session_mutex.  Returns
    // false for a slice of a session already witnessed, which is not to be logged.
    bool note_raw_slice(const uint8_t *content, size_t content_sz);

    // Write the RawDiagAbort row if the current session earned one: data
    // arrived, END did not, and the server is not stopping. A session is
    // witnessed at most once. Returns true if a row was sent.
    bool witness_raw_abort(const std::string& reason);

    // Parse one diag_stats JSON payload and SET the counter fields. Split out so
    // it is unit-testable without a live mpack tree.
    void apply_diag_stats_json(const std::string& json_str);

    // Parse one diag_census JSON payload.  It has its own control line and its
    // own applier rather than a key on diag_stats because of size: 24 rows of a
    // realistic 241-key census render to 619 bytes against a
    // DIAG_STATS_EXTRA_MAX of 768, and the worst case is 2,880.  Adding it to
    // the extras would blow the budget on every emit and trip diag_stats'
    // drop_path retry, which degrades by silently dropping rawlog_path: valid
    // JSON, all counters present, one registered field permanently dead.
    void apply_diag_census_json(const std::string& json_str);

    // Register the celldiag runtime-counter fields (the schema the web UI's
    // celldiag panel renders) so they serialize into /datasource/all_sources.json.
    //
    // This is done imperatively from the ctor, NOT via a register_fields()
    // override: kis_datasource's base ctor calls register_fields()/reserve_fields()
    // during base construction, when this object's dynamic type is still
    // kis_datasource — so a subclass override never fires (the derived vtable
    // isn't installed until the base ctor returns). Instead we register each
    // field with the entrytracker and insert() it directly into this source's
    // tracker_element_map once base construction has completed.
    void register_celldiag_fields();

    // The modem's own identity (make/model/firmware/IMEI), set from the
    // helper's ModemIdentity record. Shared with cellat.
    cell_modemident_fields modemident;

    // A source that opened without AT identity ("definition") adopts
    // the identity a same-IMEI sibling source of this server read over AT --
    // on a PCIe modem, the cellat source holding the only AT node. Called on
    // every rx (a string compare once resolved): whichever of the two records
    // lands first, the adoption happens on this source's next message, on its
    // own rx path, so no other datasource's lock is ever taken.
    void adopt_sibling_identity();

    // Counter fields, every one of them SET from the helper's "diag_stats"
    // control line by apply_diag_stats_json().
    //
    // If you add a field here, add its emit site in the helper in the same
    // change.  A registered field with no emitter sits at a permanent zero/""
    // that is indistinguishable from a real reading ("rawlog_bytes: 0" reads as
    // "tee on, nothing written yet"; "inventory_unrecognized: 0" reads as "every
    // code recognized"), and registration coverage stays green the whole time.
    //
    // Fields whose source has not reported yet are OMITTED from the JSON rather
    // than sent as zeros, so a never-reported field keeps its default instead of
    // asserting a healthy-looking measurement. See diag_stats_extra_t.
    std::shared_ptr<tracker_element_uint64> diag_bytes_read;
    std::shared_ptr<tracker_element_uint64> diag_obs_total;
    std::shared_ptr<tracker_element_double> diag_obs_per_sec;
    std::shared_ptr<tracker_element_uint64> diag_last_obs_epoch;
    std::shared_ptr<tracker_element_uint8>  diag_helper_alive;
    std::shared_ptr<tracker_element_string> diag_mask_preset;
    std::shared_ptr<tracker_element_string> diag_decode_mode;
    std::shared_ptr<tracker_element_string> diag_f3_preset;
    std::shared_ptr<tracker_element_string> diag_rawlog_path;
    std::shared_ptr<tracker_element_uint64> diag_rawlog_bytes;
    std::shared_ptr<tracker_element_uint8>  diag_rawlog_active;
    std::shared_ptr<tracker_element_uint32> diag_inv_distinct;
    std::shared_ptr<tracker_element_uint32> diag_inv_unrecognized;
    std::shared_ptr<tracker_element_uint32> diag_inv_silent;
    // Log codes whose record layout is known and that no native leg reads
    // yet: the native-coverage to-do list.
    std::shared_ptr<tracker_element_uint32> diag_inv_undecoded_native;

    // The per-(code,version) census table, as one delimited string:
    // rows ';'-separated, `code/vN,count,decoded,dropped,emitted,enrich_failed,flags`.
    //
    // A STRING and not a nested tracker vector, because the only consumer
    // between the helper and this field is a C relay that does not parse JSON --
    // it lifts named string fields with diag_profile_json_string(), the same way
    // status, mask_preset and rawlog_path already travel. Every character is a
    // hex digit, a decimal digit, or from `x/v,;-` plus the flag alphabet, so it
    // needs no JSON escaping and cannot put the relay's string reader out of
    // phase.
    //
    // Bounded, and the bound is reported: inventory_distinct_codes rides the
    // stats line, so the panel renders "showing N of M".  A bounded table that
    // looks complete is worse than no table, and the rows worth a slot (a
    // silent contract code, an unhandled version) are by definition rare, so the
    // producer selects flagged-first and only then by count. A plain
    // top-N-by-count cut drops exactly them and leaves a
    // busiest-and-healthiest table, which reads as a clean bill of health for a
    // source with a live problem.
    std::shared_ptr<tracker_element_string> diag_inv_table;

    // Native decoder counters, so native coverage is visible to the server and
    // the celldiag panel rather than only in a human-readable status line.
    //
    // uint64 across the board (not uint32 like the census): these count records
    // on a wardrive, and a long session passes 2^32. The census counts distinct
    // (code,version) KEYS, which is bounded by the code space.
    std::shared_ptr<tracker_element_uint64> diag_native_total_records;
    std::shared_ptr<tracker_element_uint64> diag_native_records;
    std::shared_ptr<tracker_element_uint64> diag_native_obs;
    std::shared_ptr<tracker_element_uint64> diag_native_declined;
    std::shared_ptr<tracker_element_uint64> diag_native_enriched;
    std::shared_ptr<tracker_element_uint64> diag_native_gps_fixes;
    std::shared_ptr<tracker_element_uint64> diag_native_fallback_records;

    // The stream switches, read back. `switches_reported` is the
    // gate: 0 until a helper that reports them has sent its first stats line,
    // so an older helper's source never shows "rawpackets off, 0 slices".
    std::shared_ptr<tracker_element_uint8> diag_switches_reported;
    std::shared_ptr<tracker_element_uint8> diag_rawpackets_on;
    std::shared_ptr<tracker_element_uint64> diag_rawpackets_slices;
    std::shared_ptr<tracker_element_uint64> diag_rawpackets_dropped;
    std::shared_ptr<tracker_element_uint8> diag_qsh_requested;
    std::shared_ptr<tracker_element_uint8> diag_qsh_armed;
    std::shared_ptr<tracker_element_uint64> diag_anchor_count;
    std::shared_ptr<tracker_element_uint64> diag_anchor_ring_dropped;
    std::shared_ptr<tracker_element_uint64> diag_obs_ring_dropped;
    std::shared_ptr<tracker_element_uint64> diag_anchor_last_epoch;

    // The helper's CRC census.  crc_bad is the one trace of bytes lost between
    // the modem and the capture (a tty overflow logs nothing; a typical cause is
    // the read loop blocking on the decoder's pipe).  Gated like the switches:
    // the counters mean nothing while crc_reported is 0, so an older helper
    // never shows "0 bad".
    std::shared_ptr<tracker_element_uint8> diag_crc_reported;
    std::shared_ptr<tracker_element_uint64> diag_crc_checked;
    std::shared_ptr<tracker_element_uint64> diag_crc_ok;
    std::shared_ptr<tracker_element_uint64> diag_crc_bad;
    std::shared_ptr<tracker_element_uint64> diag_crc_damage_alerts;

    // The deferred bring-up's progress and failure. Cleared at every
    // open, so a retry that succeeds does not keep the last attempt's error.
    std::shared_ptr<tracker_element_uint64> diag_bringup_ms;
    std::shared_ptr<tracker_element_string> diag_bringup_phases;
    std::shared_ptr<tracker_element_string> diag_bringup_error;

};

class datasource_cell_diag_builder : public kis_datasource_builder {
public:
    datasource_cell_diag_builder() :
        kis_datasource_builder() {
        register_fields();
        reserve_fields(NULL);
        initialize();
    }

    datasource_cell_diag_builder(int in_id) :
        kis_datasource_builder(in_id) {
        register_fields();
        reserve_fields(NULL);
        initialize();
    }

    datasource_cell_diag_builder(int in_id, std::shared_ptr<tracker_element_map> e) :
        kis_datasource_builder(in_id, e) {

        register_fields();
        reserve_fields(e);
        initialize();
    }

    virtual ~datasource_cell_diag_builder() { }

    virtual shared_datasource build_datasource(shared_datasource_builder in_sh_this) override {
        return shared_datasource_cell_diag(new kis_datasource_cell_diag(in_sh_this));
    }

    virtual void initialize() override {
        set_source_type("celldiag");
        set_source_description("Cellular modem DIAG passive tap (per-measurement cell signal)");

        set_probe_capable(true);
        set_list_capable(true);
        set_local_capable(true);
        set_remote_capable(true);
        set_passive_capable(false);

        /* True, and it is not a claim that celldiag has channels.
         *
         * `set_channel()` in kis_datasource.cc short-circuits on exactly this
         * flag and answers "Driver not capable of changing channel", and
         * `set_channel` is the only generic runtime setter Kismet ships for a
         * datasource.  So the flag does double duty: "this source has
         * channels" and "this source accepts a runtime setting".  celldiag needs
         * the second and has none of the first, and there is no third flag.
         *
         * The consequence is accepted deliberately: the generic datasource UI
         * keys on this to render channel affordances on the source row, so a
         * source with no channels gets a channel control.  Hiding it in
         * kismet.ui.datasources.js would hide the only surface through which
         * the runtime knob (`rawlog=<path>` / `rawlog=off`) can be driven until
         * the celldiag panel grows a purpose-built control.  Once it does, the
         * generic one becomes redundant and can be suppressed. */
        set_tune_capable(true);
        set_hop_capable(false);
    }
};

#endif
