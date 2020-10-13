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

#include "configfile.h"
#include "datasourcetracker.h"
#include "datasource_virtual.h"
#include "datasource_tzsp.h"

tzsp_source::tzsp_source() :
    lifetime_global() {

    packetchain =
        Globalreg::fetch_mandatory_global_as<packet_chain>();
    datasourcetracker =
        Globalreg::fetch_mandatory_global_as<datasource_tracker>();
    pollabletracker =
        Globalreg::fetch_mandatory_global_as<pollable_tracker>();

	pack_comp_common = packetchain->register_packet_component("COMMON");
	pack_comp_linkframe = packetchain->register_packet_component("LINKFRAME");
    pack_comp_l1info = packetchain->register_packet_component("RADIODATA");
	pack_comp_datasrc = packetchain->register_packet_component("KISDATASRC");

    auto enable_tzsp = 
        Globalreg::globalreg->kismet_config->fetch_opt_bool("tzsp_enable", false);

    if (enable_tzsp) {
        auto tzsp_listen =
            Globalreg::globalreg->kismet_config->fetch_opt_dfl("tzsp_listen", "127.0.0.1");

        auto tzsp_port =
            Globalreg::globalreg->kismet_config->fetch_opt_as<unsigned int>("tzsp_listen_port", 37008);

        auto tzsp_filter =
            Globalreg::globalreg->kismet_config->fetch_opt_vec("tzsp_allowed");

        auto tzsp_buffer_sz =
            Globalreg::globalreg->kismet_config->fetch_opt_as<unsigned int>("tzsp_buffer_kb", 64);

        tzsp_listener = std::make_shared<udp_dgram_server>();

        tzsp_listener->configure_server(tzsp_port, tzsp_listen, tzsp_filter, std::chrono::seconds(60), 
                4096, tzsp_buffer_sz);

        pollabletracker->register_pollable(tzsp_listener);

    } else {
        _MSG_INFO("TZSP datasource / listener disabled, set tzsp_enable=true in your config to turn it on.");
        return;
    }

}

tzsp_source::~tzsp_source() {
    pollabletracker->remove_pollable(tzsp_listener);

    Globalreg::globalreg->remove_global(global_name());

    if (tzsp_io_thread.joinable())
        tzsp_io_thread.join();
}

void tzsp_source::tzsp_io() {
    bool first = true;

}

