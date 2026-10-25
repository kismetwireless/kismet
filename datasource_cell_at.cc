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
#include "kis_datasource.h"
#include "kis_databaselogfile.h"
#include "datasource_cell_at.h"

kis_datasource_cell_at::kis_datasource_cell_at(shared_datasource_builder in_builder) :
    kis_datasource(in_builder) {

    std::string devpath = munge_to_printable(get_definition_opt("device"));
    if (devpath != "") {
        set_int_source_cap_interface("cellat#" + devpath);
    } else {
        set_int_source_cap_interface("cellat");
    }

    set_int_source_hardware("cellat");
    set_int_source_ipc_binary("kismet_cap_cell_at");

    // Base construction is complete, so insert() targets this source's own map.
    register_cellat_fields();
    modemident.register_into(this);
}

// ── The cellat_stats fields ─────────────────────────────────────────────────
//
// One row per field. The row's full field name is spelled as a literal so a
// grep (and the panel contract test) can find it; the JSON key the helper sends
// is the part after the prefix. Registration and parsing both walk this
// table; see the note on cellat_fields in the header for why that matters.
//
// Wire types: `str` is a JSON string, `u64` an unsigned integer, `flag` a JSON
// BOOLEAN (stored as uint8 0/1), `dbl` any number. A key that arrives with the
// wrong JSON type is ignored and the field keeps its previous value -- the same
// defensive contract as diag_stats, and the one the omit-not-zero rule needs:
// the helper OMITS what it has not measured (capture_cell_at/cellat_stats.h),
// so "missing key -> keep prior value" is what keeps an unmeasured field at its
// default instead of stamping a healthy-looking zero.
namespace {

enum class cellat_ft { str, u64, flag, dbl };

struct cellat_field_spec {
    const char *field;
    cellat_ft type;
    const char *desc;
};

const char CELLAT_FIELD_PREFIX[] = "kismet.datasource.cellat.";

const cellat_field_spec CELLAT_FIELDS[] = {
    { "kismet.datasource.cellat.state", cellat_ft::str,
        "surveying | full_scan | disabled; empty until the first stats line" },
    { "kismet.datasource.cellat.strategy", cellat_ft::str,
        "armed scan profile, canonical name (driving/walking/stationary/serving_only)" },
    { "kismet.datasource.cellat.strategy_label", cellat_ft::str,
        "armed scan profile, operator-facing label" },
    { "kismet.datasource.cellat.strategies", cellat_ft::str,
        "profiles this binary accepts, ';'-separated `name,label,fullscan_s` rows" },
    { "kismet.datasource.cellat.serving_interval_ms", cellat_ft::u64,
        "serving-cell poll interval in force (ms)" },
    { "kismet.datasource.cellat.neighbor_interval_ms", cellat_ft::u64,
        "neighbor poll interval in force (ms); 0 = off" },
    { "kismet.datasource.cellat.fullscan_interval_ms", cellat_ft::u64,
        "full band scan interval in force (ms); 0 = off" },
    { "kismet.datasource.cellat.fullscan_capable", cellat_ft::flag,
        "1 if the modem has AT+QSCAN or AT#CSURVC; meaningful only once stats_epoch > 0" },
    { "kismet.datasource.cellat.fullscan_started_epoch", cellat_ft::u64,
        "unix time the running full scan started; read only when state == full_scan" },
    { "kismet.datasource.cellat.obs_total", cellat_ft::u64,
        "cell observations sent to Kismet" },
    { "kismet.datasource.cellat.obs_per_sec", cellat_ft::dbl,
        "observation throughput over the last stats window" },
    { "kismet.datasource.cellat.last_obs_epoch", cellat_ft::u64,
        "unix time of the last observation; 0 = none yet" },
    { "kismet.datasource.cellat.rawat_records", cellat_ft::u64,
        "raw AT exchanges written to the kismetdb as RawAT rows" },
    { "kismet.datasource.cellat.rawat_dropped", cellat_ft::u64,
        "RawAT rows dropped (send/format failure or full ring)" },
    { "kismet.datasource.cellat.qmifeed_configured", cellat_ft::flag,
        "1 if a qmifeed= command was configured; every qmifeed_* / "
        "rawqmi_* field is meaningful only when this is 1" },
    { "kismet.datasource.cellat.qmifeed_active", cellat_ft::flag,
        "1 while the qmifeed child is running; 0 with qmifeed_configured = it exited" },
    { "kismet.datasource.cellat.qmifeed_sent", cellat_ft::u64,
        "QMI cell observations relayed as CellModem rows" },
    { "kismet.datasource.cellat.qmifeed_dropped", cellat_ft::u64,
        "QMI observations lost to a send failure or full ring" },
    { "kismet.datasource.cellat.qmifeed_dropped_imei", cellat_ft::u64,
        "QMI observations dropped for another/no IMEI" },
    { "kismet.datasource.cellat.qmifeed_msgs", cellat_ft::u64,
        "feed notes forwarded to the message bus (capped)" },
    { "kismet.datasource.cellat.rawqmi_records", cellat_ft::u64,
        "raw qmicli exchanges written to the kismetdb as RawQMI rows" },
    { "kismet.datasource.cellat.rawqmi_dropped", cellat_ft::u64,
        "RawQMI rows dropped (send failure or full ring)" },
    { "kismet.datasource.cellat.atlog_path", cellat_ft::str,
        "atlog= JSONL tee path; empty if no tee was ever configured" },
    { "kismet.datasource.cellat.atlog_active", cellat_ft::flag,
        "1 if the atlog= tee is open now; a retained path with 0 is a stopped tee" },
    { "kismet.datasource.cellat.atlog_records", cellat_ft::u64,
        "records written to the atlog= tee" },
    { "kismet.datasource.cellat.atlog_dropped", cellat_ft::u64,
        "atlog= records lost to a write/format failure" },
    { "kismet.datasource.cellat.anchor_count", cellat_ft::u64,
        "ClockAnchor rows sent" },
    { "kismet.datasource.cellat.anchor_last_epoch", cellat_ft::u64,
        "unix time of the last ClockAnchor; 0 = none yet" },
    { "kismet.datasource.cellat.lock_capable", cellat_ft::flag,
        "1 if this modem answered the band/RAT lock probe; its "
        "channels are then the lock presets" },
    { "kismet.datasource.cellat.lock_channel", cellat_ft::str,
        "the band/RAT lock IN FORCE, as the helper wrote it: AUTO = the "
        "settings as found; empty = not capable" },
    { "kismet.datasource.cellat.lock_error", cellat_ft::str,
        "why the last lock or restore failed; empty = none" },
    { "kismet.datasource.cellat.at_port", cellat_ft::str,
        "the AT port this source opened" },
    { "kismet.datasource.cellat.model", cellat_ft::str,
        "modem model as identified at open" },
    { "kismet.datasource.cellat.firmware", cellat_ft::str,
        "modem firmware revision as identified at open" },
    { "kismet.datasource.cellat.stats_epoch", cellat_ft::u64,
        "unix time of the last stats line; 0 = none received yet" },
    { "kismet.datasource.cellat.stats_interval_s", cellat_ft::u64,
        "periodic stats cadence (s); a line older than ~3x this is stale" },
};

} // namespace

void kis_datasource_cell_at::register_cellat_fields() {
    auto et = Globalreg::globalreg->entrytracker;

    for (const auto& spec : CELLAT_FIELDS) {
        std::shared_ptr<tracker_element> el;
        switch (spec.type) {
            case cellat_ft::str:
                el = std::make_shared<tracker_element_string>(
                        et->register_field(spec.field,
                            tracker_element_factory<tracker_element_string>(),
                            spec.desc));
                break;
            case cellat_ft::u64:
                el = std::make_shared<tracker_element_uint64>(
                        et->register_field(spec.field,
                            tracker_element_factory<tracker_element_uint64>(),
                            spec.desc));
                break;
            case cellat_ft::flag:
                el = std::make_shared<tracker_element_uint8>(
                        et->register_field(spec.field,
                            tracker_element_factory<tracker_element_uint8>(),
                            spec.desc));
                break;
            case cellat_ft::dbl:
                el = std::make_shared<tracker_element_double>(
                        et->register_field(spec.field,
                            tracker_element_factory<tracker_element_double>(),
                            spec.desc));
                break;
        }
        insert(el);
        cellat_fields[spec.field + (sizeof(CELLAT_FIELD_PREFIX) - 1)] = el;
    }
}

void kis_datasource_cell_at::apply_cellat_stats_json(const std::string& json_str) {
    // A corrupt line must never disrupt capture: parse defensively, drop on error.
    nlohmann::json j;
    try {
        j = nlohmann::json::parse(json_str);
    } catch (const std::exception&) {
        return;
    }
    if (!j.is_object())
        return;

    for (const auto& spec : CELLAT_FIELDS) {
        const char *key = spec.field + (sizeof(CELLAT_FIELD_PREFIX) - 1);
        auto it = j.find(key);
        if (it == j.end())
            continue;
        auto fi = cellat_fields.find(key);
        if (fi == cellat_fields.end())
            continue;

        switch (spec.type) {
            case cellat_ft::str:
                if (it->is_string())
                    std::static_pointer_cast<tracker_element_string>(fi->second)
                        ->set(it->get<std::string>());
                break;
            case cellat_ft::u64:
                if (it->is_number_unsigned())
                    std::static_pointer_cast<tracker_element_uint64>(fi->second)
                        ->set(it->get<uint64_t>());
                break;
            case cellat_ft::flag:
                // Boolean on the wire -- is_boolean(), NOT is_number().  As
                // with celldiag's rawlog_active, the wrong type test silently
                // skips every emit and pins the field at 0.
                if (it->is_boolean())
                    std::static_pointer_cast<tracker_element_uint8>(fi->second)
                        ->set(it->get<bool>() ? 1 : 0);
                break;
            case cellat_ft::dbl:
                if (it->is_number())
                    std::static_pointer_cast<tracker_element_double>(fi->second)
                        ->set(it->get<double>());
                break;
        }
    }

    // Remember what a CAPTURING session ran. Only a surveying/full-scan
    // line counts: the whole-modem switch's "off" is itself a session (an
    // enabled=false reopen that reports stats too), and letting it update the
    // record would erase the very choices it is meant to carry across.
    auto st = j.find("state");
    if (st != j.end() && st->is_string() &&
            (*st == "surveying" || *st == "full_scan")) {
        std::lock_guard<std::mutex> lk(runtime_mutex);
        auto s = j.find("strategy");
        if (s != j.end() && s->is_string())
            runtime.strategy = s->get<std::string>();
        auto ap = j.find("atlog_path");
        if (ap != j.end() && ap->is_string())
            runtime.atlog_path = ap->get<std::string>();
        auto aa = j.find("atlog_active");
        if (aa != j.end() && aa->is_boolean())
            runtime.atlog_active = aa->get<bool>();
        auto lc = j.find("lock_channel");
        if (lc != j.end() && lc->is_string())
            runtime.lock_channel = lc->get<std::string>();
        runtime.valid = true;
    }
}

void kis_datasource_cell_at::set_channel(std::string in_channel,
        unsigned int in_transaction, configure_callback_t in_cb) {
    // Which runtime keys the operator touched. The VALUE is not kept:
    // the success bit is 1 for applied and refused settings alike, so
    // what gets restored is the helper's readback of what actually ran.
    {
        std::lock_guard<std::mutex> lk(runtime_mutex);
        if (in_channel.rfind("strategy=", 0) == 0)
            runtime.touched_strategy = true;
        else if (in_channel.rfind("atlog=", 0) == 0)
            runtime.touched_atlog = true;
    }
    kis_datasource::set_channel(in_channel, in_transaction, in_cb);
}

void kis_datasource_cell_at::stop_source() {
    {
        std::lock_guard<std::mutex> lk(runtime_mutex);
        explicit_close = true;
    }
    kis_datasource::stop_source();
}

void kis_datasource_cell_at::disable_source() {
    {
        std::lock_guard<std::mutex> lk(runtime_mutex);
        explicit_close = true;
    }
    kis_datasource::disable_source();
}

void kis_datasource_cell_at::handle_rx_jsonlayer_v3(std::shared_ptr<kis_packet> packet,
        mpack_node_t& root, mpack_tree_t *tree) {
    // Same navigation as kis_datasource_cell_diag's diag_stats intercept.
    if (mpack_node_map_contains_uint(root, KIS_EXTERNAL_V3_KDS_DATAREPORT_FIELD_JSONBLOCK)) {
        auto jsonmap = mpack_node_map_uint(root, KIS_EXTERNAL_V3_KDS_DATAREPORT_FIELD_JSONBLOCK);

        if (mpack_tree_error(tree) == mpack_ok) {
            auto type_n = mpack_node_map_uint_optional(jsonmap,
                    KIS_EXTERNAL_V3_KDS_SUB_JSON_FIELD_TYPE);

            if (!mpack_node_is_missing(type_n)) {
                auto type_s = mpack_node_str(type_n);
                auto type_sz = mpack_node_data_len(type_n);

                // The ModemIdentity record -- applied to the modem
                // fields and the hardware label, then NOT swallowed: it falls
                // through to the base handler so kismetdb keeps it as a data
                // row. Same handling as kis_datasource_cell_diag's.
                if (type_s != nullptr &&
                        std::string(type_s, type_sz) == MODEMIDENT_TYPE) {
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
                            // persist empty modem fields.
                            auto dbf = Globalreg::fetch_global_as<kis_database_logfile>(
                                    "DATABASELOG");
                            if (dbf != nullptr)
                                dbf->log_datasource(std::static_pointer_cast<kis_datasource>(
                                        shared_from_this()));
                        }
                    }
                }

                if (type_s != nullptr &&
                        std::string(type_s, type_sz) == "cellat_stats") {
                    auto json_n = mpack_node_map_uint_optional(jsonmap,
                            KIS_EXTERNAL_V3_KDS_SUB_JSON_FIELD_JSON);
                    if (!mpack_node_is_missing(json_n)) {
                        auto json_s = mpack_node_str(json_n);
                        auto json_sz = mpack_node_data_len(json_n);
                        if (json_s != nullptr)
                            apply_cellat_stats_json(std::string(json_s, json_sz));
                    }
                    // Intercepted: never delegated, so no kis_json_packinfo is
                    // inserted and phy_cell never tries to devicify a stats line.
                    return;
                }
            }
        }
    }

    kis_datasource::handle_rx_jsonlayer_v3(packet, root, tree);
}

kis_datasource_cell_at::~kis_datasource_cell_at() {

}

// Standard Adler-32 (portable) used to derive a deterministic, unique UUID from
// the IMEI. Textbook Adler-32, which differs from capture_framework's
// non-standard adler32_csum -- so this is NOT the same value the cellat helper
// reports at probe/--list time. Uniqueness is the requirement, and the
// datasource UUID set here is authoritative at runtime (local_uuid pre-empts the
// open-report UUID).
static uint32_t cellat_adler32(const char *buf) {
    uint32_t s1 = 1, s2 = 0;
    for (const char *p = buf; *p; p++) {
        s1 = (s1 + (uint8_t)*p) % 65521;
        s2 = (s2 + s1) % 65521;
    }
    return (s2 << 16) | s1;
}

// True if the definition carries an explicit `uuid=` SOURCE OPTION -- an option
// token is always preceded by ':' or ',' in `interface:k=v,k=v`. A bare substring
// search would also fire on a value containing "uuid=" and skip the injection,
// re-opening the all-zeros UUID collision. Mirrors the celldiag helper.
static bool cellat_definition_has_uuid_opt(const std::string& def) {
    for (size_t p = def.find("uuid="); p != std::string::npos;
            p = def.find("uuid=", p + 1)) {
        if (p > 0 && (def[p - 1] == ':' || def[p - 1] == ','))
            return true;
    }
    return false;
}

// Deterministic cellat UUID for an IMEI: adler32 of "kismet_cap_cell_at" +
// adler32 of "cellat"+IMEI.
static std::string cellat_uuid_for_imei(const std::string& imei) {
    std::string seed = "cellat" + imei;
    char out[40];
    snprintf(out, sizeof(out), "%08X-0000-0000-0000-0000%08X",
            cellat_adler32("kismet_cap_cell_at"),
            cellat_adler32(seed.c_str()));
    return std::string(out);
}

void kis_datasource_cell_at::open_interface(std::string in_definition, unsigned int in_transaction,
        open_callback_t in_cb) {
    // Set a unique, port-stable UUID BEFORE the IPC open (see the detailed
    // rationale in datasource_cell_diag.cc). Kismet merges a datasource into the
    // tracker even when its open fails, and the failed-open report path does not
    // adopt the report UUID -- so a cellat source that is still scanning / failing
    // would register the all-zeros UUID and collide with the other cellat/celldiag
    // sources. Inject a deterministic uuid= up front when the operator gave none.
    if (!cellat_definition_has_uuid_opt(in_definition)) {
        std::string iface = in_definition.substr(0, in_definition.find(':'));
        std::string imei;
        if (iface.rfind("cellat-", 0) == 0)
            imei = iface.substr(7);

        bool imei_ok = (imei.length() == 15);
        for (char c : imei)
            if (!isdigit((unsigned char)c)) { imei_ok = false; break; }

        if (imei_ok) {
            std::string u = cellat_uuid_for_imei(imei);
            in_definition +=
                (in_definition.find(':') == std::string::npos ? ":" : ",");
            in_definition += "uuid=" + u;
        }
    }

    // Never auto-hop a cell modem (see the builder). An operator
    // who asks for channel_hop= gets what they asked for.
    {
        bool has_hop = false;
        for (size_t p = in_definition.find("channel_hop="); p != std::string::npos;
                p = in_definition.find("channel_hop=", p + 1)) {
            if (p > 0 && (in_definition[p - 1] == ':' || in_definition[p - 1] == ','))
                has_hop = true;
        }
        if (!has_hop) {
            in_definition +=
                (in_definition.find(':') == std::string::npos ? ":" : ",");
            in_definition += "channel_hop=false";
        }
    }

    // Re-apply the operator's runtime choices after a reopen.
    //   - profile and AT log: after every successful open of an enabled
    //     definition, unless the definition itself changed that key since the
    //     last open (an update_definition is the operator re-specifying it);
    //   - the band/RAT lock: after an error reopen only.  An explicit Capture
    //     or whole-modem off/on comes back AUTO, the modem as found.  Kismet's
    //     own error-retry callback does not do this for cellat, although it
    //     looks like it: it replays get_source_channel(), which the new
    //     helper's open report has already reset to AUTO by the time the
    //     callback runs.
    //
    // Everything is decided at success time, never here.  An open that meets
    // a graceful close still in flight is parked in pending_open and re-enters
    // this virtual later with the callback built here.  Deciding at entry
    // would consume explicit_close on the first pass and make the second pass
    // an "error reopen" that re-locks an explicitly reopened modem, but only
    // when the close had not finished yet.
    // The generation makes only the OUTERMOST wrapper of a re-entered open
    // act; the definition is read after the base parsed it, so overrides from
    // update_definition count (they are folded in there, not in the string).
    uint64_t gen;
    {
        std::lock_guard<std::mutex> lk(runtime_mutex);
        gen = ++open_generation;
    }
    auto user_cb = in_cb;
    in_cb = [this, user_cb, gen](unsigned int in_t, bool in_success, std::string in_msg) {
        // The caller's callback FIRST: Kismet's error-retry callback sends its
        // own (stale) channel, and a re-applied lock must land after it.
        if (user_cb != nullptr)
            user_cb(in_t, in_success, in_msg);
        if (!in_success)
            return;

        std::string en = get_definition_opt("enabled");
        bool enabled = !(en == "false" || en == "0" || en == "no" || en == "off");
        std::string def_strategy = get_definition_opt("strategy");
        std::string def_atlog = get_definition_opt("atlog");

        std::vector<std::string> restore;
        bool error_reopen;
        {
            std::lock_guard<std::mutex> lk(runtime_mutex);
            if (gen != open_generation)
                return;          // an inner wrapper of a re-entered open
            error_reopen = opened_before && !explicit_close;
            explicit_close = false;
            if (opened_before) {
                if (def_strategy != last_open_strategy)
                    runtime.touched_strategy = false;
                if (def_atlog != last_open_atlog)
                    runtime.touched_atlog = false;
            }
            last_open_strategy = def_strategy;
            last_open_atlog = def_atlog;
            opened_before = true;

            if (enabled && runtime.valid) {
                if (runtime.touched_strategy && !runtime.strategy.empty())
                    restore.push_back("strategy=" + runtime.strategy);
                if (runtime.touched_atlog && !runtime.atlog_path.empty())
                    restore.push_back(runtime.atlog_active ?
                            "atlog=" + runtime.atlog_path : std::string("atlog=off"));
                if (error_reopen && !runtime.lock_channel.empty() &&
                        runtime.lock_channel != "AUTO")
                    restore.push_back(runtime.lock_channel);
            }
        }
        if (restore.empty())
            return;

        std::string list;
        for (const auto& s : restore)
            list += (list.empty() ? "" : ", ") + s;
        _MSG_INFO("Data source '{}' re-opened ({}); re-applying its runtime "
                "choices: {}", get_source_name(),
                error_reopen ? "after an error" : "on request", list);
        for (const auto& s : restore)
            kis_datasource::set_channel(s, 0, nullptr);
    };

    kis_datasource::open_interface(in_definition, in_transaction, in_cb);
}
