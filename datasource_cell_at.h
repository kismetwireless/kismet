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

#ifndef __DATASOURCE_CELL_AT_H__
#define __DATASOURCE_CELL_AT_H__

#include "config.h"

#include <map>
#include <mutex>
#include <string>

#include "kis_datasource.h"
#include "datasource_cell_modemident.h"

class kis_datasource_cell_at;
typedef std::shared_ptr<kis_datasource_cell_at> shared_datasource_cell_at;

class kis_datasource_cell_at : public kis_datasource {
public:
    kis_datasource_cell_at(shared_datasource_builder in_builder);
    virtual ~kis_datasource_cell_at();

    // Parse one cellat_stats JSON payload and SET the fields it carries.
    // Public so the contract test can drive it without an mpack tree.
    void apply_cellat_stats_json(const std::string& json_str);

protected:
    virtual void open_interface(std::string in_definition, unsigned int in_transaction,
            open_callback_t in_cb) override;

    // Intercept the helper's "cellat_stats" control line and SET the
    // registered fields from it; everything else (CellModem observations,
    // RawAT, ClockAnchor) goes to the base handler unchanged. Mirrors
    // kis_datasource_cell_diag's diag_stats interception.
    virtual void handle_rx_jsonlayer_v3(std::shared_ptr<kis_packet> packet,
            mpack_node_t& root, mpack_tree_t *tree) override;

    // Registered imperatively from the ctor, not via a register_fields()
    // override -- the base ctor calls register_fields() while this object's
    // dynamic type is still kis_datasource, so an override never runs. Same
    // constraint, and same fix, as datasource_cell_diag.h documents.
    void register_cellat_fields();

    // The modem's own identity, set from the helper's ModemIdentity
    // record. Shared with celldiag (datasource_cell_modemident.h).
    cell_modemident_fields modemident;

    // One table drives both registration and parsing (datasource_cell_at.cc,
    // CELLAT_FIELDS).  Registering and parsing field by field risks a field
    // that is registered but never set, reading as a confident zero.  Here a
    // field cannot be registered without a parse rule, because the row that
    // registers it is the parse rule.
    std::map<std::string, std::shared_ptr<tracker_element>> cellat_fields;

public:
    // A runtime choice survives a reopen (UI choices last until Kismet
    // restarts).  set_channel records WHICH runtime key the
    // operator touched; the helper's stats readback records WHAT actually ran.
    virtual void set_channel(std::string in_channel, unsigned int in_transaction,
            configure_callback_t in_cb) override;

    // The panel's Capture and whole-modem switches close through the
    // close_source route (stop_source()) or the disable_source route
    // (disable_source()); Kismet's error re-open calls neither.  That is how an
    // explicit reopen is told from an error one: a lock is re-applied after an
    // error reopen only.  Both overrides mark the close explicit.
    virtual void stop_source() override;
    virtual void disable_source() override;

protected:
    struct cellat_runtime_t {
        bool touched_strategy = false;   // set_channel("strategy=...") was sent
        bool touched_atlog = false;      // set_channel("atlog=...") was sent
        bool valid = false;              // a capturing stats line has arrived
        std::string strategy;            // readback: the profile in force
        std::string atlog_path;          // readback: the tee path
        bool atlog_active = false;       // readback: the tee is open
        std::string lock_channel;        // readback: the band/RAT lock in force
    };
    std::mutex runtime_mutex;
    cellat_runtime_t runtime;
    std::string last_open_strategy, last_open_atlog;
    bool opened_before = false;
    bool explicit_close = false;
    uint64_t open_generation = 0;
};

class datasource_cell_at_builder : public kis_datasource_builder {
public:
    datasource_cell_at_builder() :
        kis_datasource_builder() {
        register_fields();
        reserve_fields(NULL);
        initialize();
    }

    datasource_cell_at_builder(int in_id) :
        kis_datasource_builder(in_id) {
        register_fields();
        reserve_fields(NULL);
        initialize();
    }

    datasource_cell_at_builder(int in_id, std::shared_ptr<tracker_element_map> e) :
        kis_datasource_builder(in_id, e) {

        register_fields();
        reserve_fields(e);
        initialize();
    }

    virtual ~datasource_cell_at_builder() { }

    virtual shared_datasource build_datasource(shared_datasource_builder in_sh_this) override {
        return shared_datasource_cell_at(new kis_datasource_cell_at(in_sh_this));
    }

    virtual void initialize() override {
        set_source_type("cellat");
        set_source_description("Cellular modem AT command survey");

        set_probe_capable(true);
        set_list_capable(true);
        set_local_capable(true);
        set_remote_capable(true);
        set_passive_capable(false);

        /* Tune-capable, for the reason celldiag's builder spells out:
         * set_channel is Kismet's only generic runtime setter, and
         * kis_datasource::set_channel() refuses a source whose builder is not
         * tune-capable before anything reaches the helper.  cellat needs it for
         * the runtime scan-profile switch and the atlog= toggle.
         *
         * A lock-capable modem also has channels: its band/RAT lock presets
         * (capture_cell_at/cellat_lock.h).  A key=value setting still never
         * becomes the source's channel (cellat_chancontrol).
         *
         * Hop-capable too, because kis_datasource::set_channel_hop() refuses a
         * builder that is not, and Hop is the operator's synthetic slow scan.
         * But a hop-capable source is auto-hopped at open at the global
         * channel_hop_speed (several per second), and every step re-locks the
         * modem and writes its NV.  So the datasource opens with
         * channel_hop=false unless the operator set it (open_interface), and
         * hops only when asked. */
        set_tune_capable(true);
        set_hop_capable(true);
    }
};

#endif
