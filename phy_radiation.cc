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

#include "datasourcetracker.h"
#include "devicetracker.h"
#include "kis_databaselogfile.h"
#include "kis_httpd_registry.h"
#include "macaddr.h"
#include "phy_radiation.h"

kis_radiation_phy::kis_radiation_phy(int in_phyid) :
    kis_phy_handler(in_phyid) {

    set_phy_name("RADIATION");
    indexed = false;

    geiger_device_id = 
        Globalreg::globalreg->entrytracker->register_field("radiation.geiger",
                tracker_element_factory<geiger_device>(), "Geiger counter");

    packetchain =
        Globalreg::fetch_mandatory_global_as<packet_chain>();
    devicetracker =
        Globalreg::fetch_mandatory_global_as<device_tracker>();
    datasourcetracker =
        Globalreg::fetch_mandatory_global_as<datasource_tracker>();
    eventbus = 
        Globalreg::fetch_mandatory_global_as<event_bus>();

	pack_comp_common = 
		packetchain->register_packet_component("COMMON");
    pack_comp_json = 
        packetchain->register_packet_component("JSON");
    pack_comp_meta =
        packetchain->register_packet_component("METABLOB");
    pack_comp_datasrc =
        packetchain->register_packet_component("KISDATASRC");

	packetchain->register_handler(&packet_handler, this, CHAINPOS_CLASSIFIER, -100);

    geiger_counters = 
        std::make_shared<tracker_element_uuid_map>();

    auto httpd = 
        Globalreg::fetch_mandatory_global_as<kis_net_beast_httpd>();

    auto httpregistry =
        Globalreg::fetch_mandatory_global_as<kis_httpd_registry>();
    httpregistry->register_js_module("kismet_ui_radiation", "js/kismet.ui.radiation.js");

    httpd->register_route("/radiation/sensors/all_sensors", {"GET", "POST"},
            httpd->RO_ROLE, {},
            std::make_shared<kis_net_web_tracked_endpoint>(geiger_counters, rad_mutex));

    auto timetracker = Globalreg::fetch_mandatory_global_as<time_tracker>();
    event_timer =
        timetracker->register_timer(SERVER_TIMESLICES_SEC * 3, nullptr, 1, 
                [this](int) -> int {
                    auto kismetdb = Globalreg::fetch_global_as<kis_database_logfile>();
                    auto lg = kis_lock_guard<kis_mutex>(rad_mutex);
                    if (kismetdb != nullptr) {
                        struct timeval tv;
                        gettimeofday(&tv, nullptr);

                        std::stringstream js;

                        Globalreg::globalreg->entrytracker->serialize("json", js, geiger_counters, NULL);

                        kismetdb->log_snapshot(nullptr, tv, "RADIATION", js.str());
                    }

                    auto evt = eventbus->get_eventbus_event(event_radiation());
                    evt->get_event_content()->insert(event_radiation(), geiger_counters);
                    eventbus->publish(evt);

                    return 1;

                });
}

kis_radiation_phy::~kis_radiation_phy() {
    packetchain->remove_handler(&packet_handler, CHAINPOS_CLASSIFIER);
}

int kis_radiation_phy::packet_handler(CHAINCALL_PARMS) {
    kis_radiation_phy *radphy = (kis_radiation_phy *) auxdata;

    if (in_pack->error || in_pack->filtered || in_pack->duplicate) {
        return 0;
    }

    auto json = in_pack->fetch<kis_json_packinfo>(radphy->pack_comp_json);

    if (json == nullptr) {
        return 0;
    }

    auto datasrc = in_pack->fetch<packetchain_comp_datasource>(radphy->pack_comp_datasrc);

    if (datasrc == nullptr) {
        return 0;
    }

    // Radview arduino code emits the CPS and spectrum data
    if (json->type == "radview") {

        nlohmann::json json_;
        std::vector<double> spectrum;
        double cps;

        try {
            std::stringstream ss(json->json_string);
            ss >> json_;

            cps = json_["cps"].get<double>();
            spectrum = json_["spectrum"].get<std::vector<double>>();

        } catch (const std::exception& e) {
            _MSG_DEBUG("JSON parsing error: {}", e.what());
            return 0;
        }

        // _MSG_DEBUG("Radview JSON: {}", json->json_string);

        auto lk = kis_lock_guard<kis_mutex>(radphy->rad_mutex, "radphy update");
        std::shared_ptr<geiger_device> rv;
        auto gk = radphy->geiger_counters->find(datasrc->ref_source->get_source_uuid());
        if (gk == radphy->geiger_counters->end()) {
            rv = std::make_shared<geiger_device>(radphy->geiger_device_id);

            // Minor hoops to jump through; the packet source ref is a raw pointer not a shared
            // pointer, so we need to get the shared from the DST.
            rv->set_src_alias(radphy->datasourcetracker->find_datasource(datasrc->ref_source->get_source_uuid()));

            rv->set_detector_type("Radview");
            radphy->geiger_counters->insert(datasrc->ref_source->get_source_uuid(), rv);
        } else {
            rv = std::static_pointer_cast<geiger_device>(gk->second);
        }

        rv->insert_cps_record(in_pack->ts.tv_sec, cps, spectrum);

        return 1;
    }

    // Radiacode gives dosage information as well as cps.  Once written it 
    // should also provide spectrum.
    if (json->type == "radiacode") {

        nlohmann::json json_;
        std::vector<double> spectrum;
        double cps;
        double sv;

        try {
            std::stringstream ss(json->json_string);
            ss >> json_;

            cps = json_["cps"].get<double>();
            sv = json_["sv"].get<double>();

        } catch (const std::exception& e) {
            _MSG_DEBUG("JSON parsing error: {}", e.what());
            return 0;
        }

        // _MSG_DEBUG("Radiacode JSON: {}", json->json_string);

        auto lk = kis_lock_guard<kis_mutex>(radphy->rad_mutex, "radphy update");

        std::shared_ptr<geiger_device> rv;
        auto gk = radphy->geiger_counters->find(datasrc->ref_source->get_source_uuid());
        if (gk == radphy->geiger_counters->end()) {
            rv = std::make_shared<geiger_device>(radphy->geiger_device_id);

            rv->set_src_alias(radphy->datasourcetracker->find_datasource(datasrc->ref_source->get_source_uuid()));

            rv->set_detector_type("Radiacode");
            radphy->geiger_counters->insert(datasrc->ref_source->get_source_uuid(), rv);
        } else {
            rv = std::static_pointer_cast<geiger_device>(gk->second);
        }

        // Radiacode reports sv in 1/10000ths
        rv->insert_cps_usv(in_pack->ts.tv_sec, cps, sv * 10000);

        return 1;
    }

    /*
    if (json->type != "radiation")
        return 0;

    auto rdata = in_pack->fetch_or_add<packet_metablob>(radphy->pack_comp_meta);
    rdata->set_data("radiation", json->json_string);
    */



    return 1;
}

