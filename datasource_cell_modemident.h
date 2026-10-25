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

#ifndef __DATASOURCE_CELL_MODEMIDENT_H__
#define __DATASOURCE_CELL_MODEMIDENT_H__

// The server half of the ModemIdentity record, shared by the two cell
// datasources (celldiag and cellat).
//
// Each capture helper reads its modem's own AT+CGMI / +CGMM / +CGMR / +CGSN at
// startup and sends one `ModemIdentity` JSON record per open; the record's
// contract is capture_cell_diag/diag_modemident.h. On receipt a datasource:
//
//   1. sets the `kismet.datasource.cell.modem_*` fields below, so
//      /datasource/all_sources.json and the kismetdb `datasources` row name the
//      modem -- the datasource re-logs that row the moment the record lands,
//      since the periodic rewrite (30 s) and the shutdown one miss a short
//      session;
//   2. installs the record's `label` as the source's hardware -- which is the
//      only post-open hardware update a cell source has. OPENREPORT sets it
//      once, and for a deferred celldiag bring-up that is the placeholder
//      "DIAG opening IMEI:<imei> DIAG", which would otherwise be frozen into
//      the .kismet log;
//   3. passes the record on to the base handler, so kismetdb also keeps it as a
//      timestamped `ModemIdentity` row in `data` (phy_cell devicifies only
//      CellModem / Cellular, so it builds no device).
//
// The values are the modem's answers, verbatim. This file sets them; it does
// not interpret, normalise or correct them.

#include "config.h"

#include <cstdint>
#include <ctime>
#include <map>
#include <memory>
#include <mutex>
#include <string>

#include "entrytracker.h"
#include "globalregistry.h"
#include "nlohmann/json.hpp"
#include "trackedelement.h"
#include "capture_cell_diag/diag_modemident.h"

// Every identity a cell source of this server READ over AT, by IMEI.
//
// A PCIe modem (the RM520N-GL over MHI) has one AT node, /dev/mhi_DUN. A drive
// opens a cellat and a celldiag source for it, and the cellat source holds that
// node for its whole capture -- so when cellat reaches it first, celldiag's
// identity read can never succeed, however long it retries, and the source
// opens as "definition": `hardware` "unknown IMEI:...", no model or firmware
// in all_sources.json, the kismetdb `datasources` row or its ModemIdentity row.
// The server holds both sources and cellat DID read the modem, so the celldiag
// source adopts that reading (adopt_sibling below).
//
// Lock-free across sources by construction: a source only ever PUBLISHES here
// and READS here under this mutex, and only changes its OWN fields, from its
// own rx path. Nothing takes another datasource's lock.
class cell_modemident_registry {
public:
    static void publish(const std::string& imei, const nlohmann::json& rec) {
        std::lock_guard<std::mutex> lk(mtx());
        table()[imei] = rec;
    }

    static bool lookup(const std::string& imei, nlohmann::json& out) {
        std::lock_guard<std::mutex> lk(mtx());
        auto it = table().find(imei);
        if (it == table().end())
            return false;
        out = it->second;
        return true;
    }

private:
    static std::mutex& mtx() {
        static std::mutex m;
        return m;
    }
    static std::map<std::string, nlohmann::json>& table() {
        static std::map<std::string, nlohmann::json> t;
        return t;
    }
};

class cell_modemident_fields {
public:
    // Registered into `map` -- the datasource itself -- from its constructor.
    // Both cell datasources register the same names; the entry tracker hands
    // back the existing id for a name already registered with the same type.
    template <class Map>
    void register_into(Map *map) {
        auto et = Globalreg::globalreg->entrytracker;

        make = reg_str(et, "kismet.datasource.cell.modem_make",
                "modem make, as the modem answered AT+CGMI");
        model = reg_str(et, "kismet.datasource.cell.modem_model",
                "modem model, as the modem answered AT+CGMM");
        firmware = reg_str(et, "kismet.datasource.cell.modem_firmware",
                "modem firmware, as the modem answered AT+CGMR");
        imei = reg_str(et, "kismet.datasource.cell.modem_imei",
                "modem IMEI; read over AT+CGSN when modem_identity_method is "
                "'at', else the IMEI the source was addressed by");
        at_port = reg_str(et, "kismet.datasource.cell.modem_at_port",
                "the AT node the identity was read on");
        method = reg_str(et, "kismet.datasource.cell.modem_identity_method",
                "'at' = read from the modem; 'definition' = no AT identity was "
                "possible, only the addressed IMEI is known; 'sibling' = read "
                "over AT by another source of this server on the same IMEI, "
                "e.g. the paired cellat; 'vouched' = read over AT by the "
                "process holding the AT port, which published it for this "
                "helper's scan; '' = none yet");
        epoch = std::make_shared<tracker_element_uint64>(
                et->register_field("kismet.datasource.cell.modem_identity_epoch",
                    tracker_element_factory<tracker_element_uint64>(),
                    "unix epoch the current identity was received"));

        for (const auto& f : {make, model, firmware, imei, at_port, method})
            map->insert(f);
        map->insert(epoch);
    }

    // Apply one ModemIdentity JSON object. Returns the display label to install
    // as the source's hardware, or "" when the record is unusable (then nothing
    // was changed). A key the record omits CLEARS its field: a record describes
    // one open completely, and a stale model from a previous open must not
    // survive into a reopen against a different unit.
    std::string apply_json(const std::string& json_str) {
        nlohmann::json j;
        try {
            j = nlohmann::json::parse(json_str);
        } catch (const std::exception&) {
            return "";
        }
        if (!j.is_object() || !j.contains("v") || !j["v"].is_number_integer())
            return "";
        if (!str_of(j, "imei").size() && !str_of(j, "label").size())
            return "";

        make->set(str_of(j, "make"));
        model->set(str_of(j, "model"));
        firmware->set(str_of(j, "firmware"));
        imei->set(str_of(j, "imei"));
        at_port->set(str_of(j, "at_port"));
        method->set(str_of(j, "method"));
        epoch->set(static_cast<uint64_t>(time(nullptr)));
        // A reading, not an address -- offer it to same-IMEI siblings.
        if (str_of(j, "method") == MODEMIDENT_METHOD_AT && !str_of(j, "imei").empty())
            cell_modemident_registry::publish(str_of(j, "imei"), j);
        return str_of(j, "label");
    }

    // While this source's identity is only the IMEI it was addressed by,
    // adopt what a same-IMEI source of this server read over AT. Cheap to call
    // on every rx: it is a string compare until the source is unresolved.
    // Returns the ModemIdentity record now applied -- the caller installs its
    // label and logs it -- or "" when nothing changed.
    std::string adopt_sibling(const char *source_type, const char *label_suffix) {
        if (method->get() != MODEMIDENT_METHOD_DEFINITION)
            return "";
        const auto want = imei->get();
        nlohmann::json sib;
        if (want.empty() || !cell_modemident_registry::lookup(want, sib))
            return "";

        // The record contract (diag_modemident.h): unread keys are OMITTED.
        nlohmann::json rec = {{"v", MODEMIDENT_SCHEMA}, {"source_type", source_type},
                              {"method", MODEMIDENT_METHOD_SIBLING}, {"imei", want}};
        std::string label;
        for (const char *k : {"make", "model", "firmware", "at_port"}) {
            auto v = str_of(sib, k);
            if (!v.empty())
                rec[k] = v;
        }
        // modemident_label's shape: "<make> <model> (<firmware>) IMEI:<imei><suffix>".
        auto mk = str_of(sib, "make"), md = str_of(sib, "model"), fw = str_of(sib, "firmware");
        label = mk;
        if (!md.empty())
            label += (label.empty() ? "" : " ") + md;
        if (!fw.empty())
            label += label.empty() ? fw : " (" + fw + ")";
        label += (label.empty() ? "IMEI:" : " IMEI:") + want;
        if (label_suffix != nullptr)
            label += label_suffix;
        rec["label"] = label;

        const auto out = rec.dump();
        apply_json(out);
        return out;
    }

private:
    static std::shared_ptr<tracker_element_string> reg_str(
            entry_tracker *et, const char *name,
            const char *desc) {
        return std::make_shared<tracker_element_string>(
                et->register_field(name,
                    tracker_element_factory<tracker_element_string>(), desc));
    }

    static std::string str_of(const nlohmann::json& j, const char *key) {
        if (j.contains(key) && j[key].is_string())
            return j[key].get<std::string>();
        return "";
    }

    std::shared_ptr<tracker_element_string> make, model, firmware, imei,
        at_port, method;
    std::shared_ptr<tracker_element_uint64> epoch;
};

#endif
