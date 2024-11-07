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

#include <memory>

#include <stdio.h>
#include <time.h>
#include <list>
#include <map>
#include <vector>

#include "kismet_algorithm.h"

#include <string>
#include <sstream>
#include <pthread.h>

#include "globalregistry.h"
#include "util.h"
#include "configfile.h"
#include "messagebus.h"
#include "packetchain.h"
#include "devicetracker.h"
#include "packet.h"
#include "gpstracker.h"
#include "alertracker.h"
#include "manuf.h"
#include "entrytracker.h"
#include "devicetracker_component.h"
#include "json_adapter.h"
#include "base64.h"

std::shared_ptr<tracker_element> device_tracker::multimac_endp_handler(shared_con con) {
    auto ret_devices = std::make_shared<tracker_element_vector>();
    auto macs = std::vector<mac_addr>{};

    if (con->json()["devices"].is_null())
        throw std::runtime_error("Missing 'devices' key in command dictionary");

    for (const auto& m : con->json()["devices"]) {
        mac_addr ma{m.get<std::string>()};

        if (ma.state.error) {
            const auto e = fmt::format("Invalid MAC address '{}' in 'devices' list",
                        con->escape_html(m.get<std::string>()));
            throw std::runtime_error(e);
        }

        macs.push_back(ma);
    }

    // Duplicate the mac index so that we're 'immune' to things changing it under us; because we
    // may have quite a number of devices in our query list, this is safest.
    kis_unique_lock<kis_mutex> devlist_locker(get_devicelist_mutex(), std::defer_lock, "multimac_endp_handler");
    devlist_locker.lock();
    auto immutable_copy = 
        std::multimap<mac_addr, std::shared_ptr<kis_tracked_device_base>>{tracked_mac_multimap};
    devlist_locker.unlock();

    // Pull all the devices out of the list
    for (auto m : macs) {
        const auto& mi = immutable_copy.equal_range(m);
        for (auto msi = mi.first; msi != mi.second; ++msi)
            ret_devices->push_back(msi->second);
    }

    return ret_devices;
}

std::shared_ptr<tracker_element> device_tracker::all_phys_endp_handler(shared_con con) {
    kis_lock_guard<kis_mutex> lg(get_devicelist_mutex(), "all_phys_endp_handler");

    auto ret_vec = std::make_shared<tracker_element_vector>();

    for (auto i : phy_handler_map) {
        auto tracked_phy =
            std::make_shared<tracker_element_map>(phy_phyentry_id);

        auto tracked_name =
            std::make_shared<tracker_element_string>(phy_phyname_id, i.second->fetch_phy_name());
        auto tracked_id =
            std::make_shared<tracker_element_uint32>(phy_phyid_id, i.second->fetch_phy_id());
        auto tracked_dev_count =
            std::make_shared<tracker_element_uint64>(phy_devices_count_id);
        auto tracked_packet_count =
            std::make_shared<tracker_element_uint64>(phy_packets_count_id, phy_packets[i.second->fetch_phy_id()]);

        auto pv_key = phy_view_map.find(i.second->fetch_phy_id());
        if (pv_key != phy_view_map.end())
            tracked_dev_count->set(pv_key->second->get_list_sz());

        tracked_phy->insert(tracked_name);
        tracked_phy->insert(tracked_id);
        tracked_phy->insert(tracked_dev_count);
        tracked_phy->insert(tracked_packet_count);
        ret_vec->push_back(tracked_phy);
    }

    return ret_vec;
}

std::shared_ptr<tracker_element> device_tracker::multikey_endp_handler(shared_con con, bool as_object) {
    auto ret_devices_obj = std::make_shared<tracker_element_device_key_map>();
    auto ret_devices_vec = std::make_shared<tracker_element_vector>();
    auto keys = std::vector<device_key>{};

    if (con->json()["devices"].is_null())
        throw std::runtime_error("Missing 'devices' key in command dictionary");

    for (const auto& k : con->json()["devices"]) {
        device_key ka{k.get<std::string>()};

        if (ka.get_error())  {
            const auto e = fmt::format("Invalid device key '{}' in 'devices' list", con->escape_html(k));
            throw std::runtime_error(e);
        }

        keys.push_back(ka);
    }

    for (auto k : keys) { 
        auto d = fetch_device(k);

        if (d == nullptr)
            continue;

        if (as_object)
            ret_devices_obj->insert(k, d);
        else
            ret_devices_vec->push_back(d);
    }

    if (as_object)
        return ret_devices_obj;

    return ret_devices_vec;
}

