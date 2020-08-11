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

#include "phy_80211_ssidtracker.h"

#include "boost_like_hash.h"
#include "timetracker.h"
#include "trackedelement_workers.h"

void dot11_tracked_ssid_group::register_fields() {
    tracker_component::register_fields();

    register_field("dot11.ssidgroup.hash", "unique hash of ssid and encryption options", &ssid_hash);
    register_field("dot11.ssidgroup.ssid", "SSID", &ssid);
    register_field("dot11.ssidgroup.ssid_len", "Length of SSID", &ssid_len);
    register_field("dot11.ssidgroup.crypt_set", "Advertised encryption set", &crypt_set);
    register_field("dot11.ssidgroup.first_time", "First time seen (unix timestamp)", &first_time);
    register_field("dot11.ssidgroup.last_time", "Last time seen (unix timestamp)", &last_time);

    register_field("dot11.ssidgroup.probing_devices", "Probing device keys", &probing_device_map);
    register_field("dot11.ssidgroup.responding_devices", "Responding device keys", &responding_device_map);
    register_field("dot11.ssidgroup.advertising_devices", "Advertising device keys", &advertising_device_map);

    register_field("dot11.ssidgroup.probing_devices_len", "Number of probing devices", &probing_device_len);
    register_field("dot11.ssidgroup.responding_devices_len", "Number of responding devices", &responding_device_len);
    register_field("dot11.ssidgroup.advertising_devices_len", "Number of advertising devices", &advertising_device_len);

}

void dot11_tracked_ssid_group::reserve_fields(std::shared_ptr<tracker_element_map> e) {
    tracker_component::reserve_fields(e);

    // Treat all of these as key vectors; we serialize out the key values as a list instead of a map,
    // we just use it as a map to make lookups more efficient.
    advertising_device_map->set_as_key_vector(true);
    responding_device_map->set_as_key_vector(true);
    probing_device_map->set_as_key_vector(true);

}

uint64_t dot11_tracked_ssid_group::generate_hash(const std::string& ssid, unsigned int ssid_len, uint64_t crypt_set) {
    auto hash = xx_hash_cpp{};

    boost_like::hash_combine(hash, ssid);
    boost_like::hash_combine(hash, ssid_len);
    boost_like::hash_combine(hash, crypt_set);

    return hash.hash();
}

void dot11_tracked_ssid_group::add_advertising_device(std::shared_ptr<kis_tracked_device_base> device) {
    local_locker l(&mutex);
    advertising_device_map->insert(device->get_key(), nullptr);

    if (device->get_first_time() < get_first_time() || get_first_time() == 0)
        set_first_time(device->get_first_time());

    if (device->get_last_time() > get_last_time())
        set_last_time(device->get_last_time());
}

void dot11_tracked_ssid_group::add_probing_device(std::shared_ptr<kis_tracked_device_base> device) {
    local_locker l(&mutex);
    probing_device_map->insert(device->get_key(), nullptr);

    if (device->get_first_time() < get_first_time() || get_first_time() == 0)
        set_first_time(device->get_first_time());

    if (device->get_last_time() > get_last_time())
        set_last_time(device->get_last_time());
}

void dot11_tracked_ssid_group::add_responding_device(std::shared_ptr<kis_tracked_device_base> device) {
    local_locker l(&mutex);
    responding_device_map->insert(device->get_key(), nullptr);

    if (device->get_first_time() < get_first_time() || get_first_time() == 0)
        set_first_time(device->get_first_time());

    if (device->get_last_time() > get_last_time())
        set_last_time(device->get_last_time());
}

phy_80211_ssid_tracker::phy_80211_ssid_tracker() {
    mutex.set_name("phy_80211_ssid_tracker");

    auto timetracker = Globalreg::fetch_mandatory_global_as<time_tracker>();

    cleanup_timer_id = -1;

    tracked_ssid_id = 
        Globalreg::globalreg->entrytracker->register_field("dot11.ssidtracker.ssid",
                tracker_element_factory<dot11_tracked_ssid_group>(),
                "Tracked SSID grouping");

    ssid_vector = std::make_shared<tracker_element_vector>();

    ssid_tracking_enabled = true;

    if (!Globalreg::globalreg->kismet_config->fetch_opt_bool("dot11_view_ssids", true)) {
        _MSG_INFO("Disabling 802.11 SSID view (dot11_view_ssids=false in configuration)");
        ssid_tracking_enabled = false;
    }

    // Always register the endpoint so we don't get a 404, it'll just return nothing if 
    // ssid tracking is disabled since we'll never populate our SSID table
    ssid_endp = 
        std::make_shared<kis_net_httpd_simple_post_endpoint>("/phy/phy80211/ssids/views/ssids",
                [this](std::ostream& stream, const std::string& uri, const Json::Value& json,
                    kis_net_httpd_connection::variable_cache_map& variable_cache) -> unsigned int {
                return ssid_endpoint_handler(stream, uri, json, variable_cache);
                });

    detail_endp =
        std::make_shared<kis_net_httpd_path_tracked_endpoint>(
                [this](const std::vector<std::string>& path) -> bool {
                    return detail_endpoint_path(path);
                },
                [this](const std::vector<std::string>& path) -> std::shared_ptr<tracker_element> {
                    return detail_endpoint_handler(path);
                });
}

phy_80211_ssid_tracker::~phy_80211_ssid_tracker() {
    auto timetracker = Globalreg::fetch_mandatory_global_as<time_tracker>();

    timetracker->remove_timer(cleanup_timer_id);

}

unsigned int phy_80211_ssid_tracker::ssid_endpoint_handler(std::ostream& stream,
        const std::string& uri, const Json::Value& json,
        kis_net_httpd_connection::variable_cache_map& postvars) {
    auto summary_vec = std::vector<SharedElementSummary>{};
    auto rename_map = std::make_shared<tracker_element_serializer::rename_map>();

    time_t timestamp_min = 0;

    auto search_term = std::string{};

    auto search_paths = std::vector<std::vector<int>>{};

    auto order_field = std::vector<int>{};

    auto regex = json["regex"];

    std::shared_ptr<tracker_element_string_map> wrapper_elem;

    std::shared_ptr<tracker_element> transmit;

    auto length_elem = std::make_shared<tracker_element_uint64>();
    auto start_elem = std::make_shared<tracker_element_uint64>();

    auto total_sz_elem = std::make_shared<tracker_element_uint64>();
    auto filtered_sz_elem = std::make_shared<tracker_element_uint64>();

    auto output_ssids_elem = std::make_shared<tracker_element_vector>();

    auto dt_draw_elem = std::make_shared<tracker_element_uint64>();

    try {
        // If the structured component has a 'fields' record, derive the fields simplification; we need this to
        // compute the search path so we have to implement our own copy of the code
        auto fields = json.get("fields", Json::Value(Json::arrayValue));

        for (const auto& i : fields) {
            if (i.isString()) {
                summary_vec.push_back(std::make_shared<tracker_element_summary>(i.asString()));
            } else if (i.isArray()) {
                if (i.size() != 2) 
                    throw std::runtime_error("Invalid field map, expected [field, rename]");

                summary_vec.push_back(std::make_shared<tracker_element_summary>(i[0].asString(), i[1].asString()));
            } else {
                throw std::runtime_error("Invalid field map, exected field or [field, rename]");
            }
        }

        // Capture timestamp and negative-offset timestamp
        auto raw_ts = json.get("last_time", 0).asInt64();
        if (raw_ts < 0)
            timestamp_min = time(0) + raw_ts;
        else
            timestamp_min = raw_ts;
    } catch (const std::runtime_error& e) {
        stream << "Invalid request: " << e.what() << "\n";
        return 400;
    }

    // Input fields from variables
    unsigned int in_window_start = 0;
    unsigned int in_window_len = 0;
    unsigned int in_dt_draw = 0;
    std::string in_order_column_num = "0";
    unsigned int in_order_direction = 0;

    // Parse datatables sub-data for windowing, etc
    try {
        // Extract the column number -> column fieldpath data
        auto column_number_map = json["colmap"];

        if (json.get("datatable", false).asBool()) {
            // Extract from the raw postvars 
            if (postvars.find("start") != postvars.end())
                *(postvars["start"]) >> in_window_start;

            if (postvars.find("length") != postvars.end())
                *(postvars["length"]) >> in_window_len;

            if (postvars.find("draw") != postvars.end())
                *(postvars["draw"]) >> in_dt_draw;

            if (postvars.find("search[value]") != postvars.end())
                *(postvars["search[value]"]) >> search_term;

            // Search every field we return
            if (search_term.length() != 0) 
                for (const auto& svi : summary_vec)
                    search_paths.push_back(svi->resolved_path);

            // We only allow ordering by a single column, we don't do sub-ordering;
            // look for that single column
            if (postvars.find("order[0][column]") != postvars.end())
                *(postvars["order[0][column]"]) >> in_order_column_num;

            auto column_index = column_number_map[in_order_column_num];
            if (!column_index.isNull() && postvars.find("order[0][dir]") != postvars.end()) {
                auto order = postvars.find("order[0][dir]")->second->str();

                if (order == "asc")
                    in_order_direction = 1;
                else
                    in_order_direction = 0;

                // Resolve the path, we only allow the first one
                if (column_index.isArray() && column_index.size() > 0) {
                    if (column_index[0].isArray()) {
                        // We only allow the first field, but make sure we're not a nested array
                        if (column_index[0].size() > 0) {
                            order_field = tracker_element_summary(column_index[0][0].asString()).resolved_path;
                        }
                    } else {
                        // Otherwise get the first array
                        if (column_index.size() >= 1) {
                            order_field = tracker_element_summary(column_index[0].asString()).resolved_path;
                        }
                    }
                }
            }

            if (in_window_len > 500) 
                in_window_len = 500;

            // Set the window elements for datatables
            length_elem->set(in_window_len);
            start_elem->set(in_window_start);
            dt_draw_elem->set(in_dt_draw);

            // Set up the datatables wrapper
            wrapper_elem = std::make_shared<tracker_element_string_map>();
            transmit = wrapper_elem;

            wrapper_elem->insert("draw", dt_draw_elem);
            wrapper_elem->insert("data", output_ssids_elem);
            wrapper_elem->insert("recordsTotal", total_sz_elem);
            wrapper_elem->insert("recordsFiltered", filtered_sz_elem);

            // We transmit the wrapper elem
            transmit = wrapper_elem;
        }
    } catch (const std::exception& e) {
        stream << "Invalid request: " << e.what() << "\n";
        return 400;
    }

    // Next vector we do work on
    auto next_work_vec = std::make_shared<tracker_element_vector>();

    // Copy the entire vector list, under lock, to the next work vector; this makes it an independent copy
    // which is protected from the main vector being grown/shrank.  While we're in there, log the total
    // size of the original vector for windowed ops.
    {
        local_shared_locker l(&mutex);

        next_work_vec->set(ssid_vector->begin(), ssid_vector->end());
        total_sz_elem->set(next_work_vec->size());
    }

    // If we have a time filter, apply that first, it's the fastest.
    if (timestamp_min > 0) {
        auto worker = 
            tracker_element_function_worker([timestamp_min](std::shared_ptr<tracker_element> e) -> bool {
            auto si = std::static_pointer_cast<dot11_tracked_ssid_group>(e);

            return (si->get_last_time() >= timestamp_min);
            });

        next_work_vec = worker.do_work(next_work_vec);
    }

    // Apply a string filter
    if (search_term.length() > 0 && search_paths.size() > 0) {
        auto worker = 
            tracker_element_icasestringmatch_worker(search_term, search_paths);
        next_work_vec = worker.do_work(next_work_vec);
    }

    // Apply a regex filter
    if (!regex.isNull()) {
        try {
            auto worker = 
                tracker_element_regex_worker(regex);
            next_work_vec = worker.do_work(next_work_vec);
        } catch (const std::exception& e) {
            stream << "Invalid regex: " << e.what() << "\n";
            return 400;
        }
    }

    // Apply the filtered length
    filtered_sz_elem->set(next_work_vec->size());

    // Slice from the beginning of the list
    if (in_window_start >= next_work_vec->size()) 
        in_window_start = 0;

    // Update the start
    start_elem->set(in_window_start);

    tracker_element_vector::iterator si = std::next(next_work_vec->begin(), in_window_start);
    tracker_element_vector::iterator ei;

    if (in_window_len + in_window_start >= next_work_vec->size() || in_window_len == 0)
        ei = next_work_vec->end();
    else
        ei = std::next(next_work_vec->begin(), in_window_start + in_window_len);

    // Update the end
    length_elem->set(ei - si);

    // Unfortunately we need to do a stable sort to get a consistent display
    if (in_order_column_num.length() && order_field.size() > 0) {
        std::stable_sort(next_work_vec->begin(), next_work_vec->end(),
                [&](shared_tracker_element a, shared_tracker_element b) -> bool {
                shared_tracker_element fa;
                shared_tracker_element fb;

                fa = get_tracker_element_path(order_field, a);
                fb = get_tracker_element_path(order_field, b);

                if (fa == nullptr) 
                    return in_order_direction == 0;

                if (fb == nullptr)
                    return in_order_direction != 0;

                if (in_order_direction == 0)
                    return fast_sort_tracker_element_less(fa, fb);

                return fast_sort_tracker_element_less(fb, fa);
            });
    }

    // Summarize into the output element
    for (auto i = si; i != ei; ++i) {
        output_ssids_elem->push_back(summarize_single_tracker_element(*i, summary_vec, rename_map));
    }

    // If the transmit wasn't assigned to a wrapper...
    if (transmit == nullptr)
        transmit = output_ssids_elem;

    // serialize
    Globalreg::globalreg->entrytracker->serialize(kishttpd::get_suffix(uri), stream, transmit, rename_map);

    // And done
    return 200;
}

bool phy_80211_ssid_tracker::detail_endpoint_path(const std::vector<std::string>& path) {
    // /phy/phy80211/ssids/by-hash/[hash]/ssid

    if (path.size() < 6)
        return false;

    if (path[0] != "phy" || path[1] != "phy80211" || path[2] != "ssids" || path[3] != "by-hash" || path[5] != "ssid")
        return false;

    local_locker l(&mutex, "phy_80211_ssid_tracker::detail_endpoint_path");

    try {
        auto h = string_to_n<size_t>(path[4]);
        auto k = ssid_map.find(h);

        if (k == ssid_map.end())
            return false;
    } catch (const std::exception& e) {
        return false;
    }

    return true;
}

std::shared_ptr<tracker_element> phy_80211_ssid_tracker::detail_endpoint_handler(const std::vector<std::string>& path) {
    if (path.size() < 6)
        return nullptr;

    local_locker l(&mutex, "phy_80211_ssid_tracker::detail_endpoint_handler");

    try {
        auto h = string_to_n<size_t>(path[4]);
        auto k = ssid_map.find(h);

        if (k == ssid_map.end())
            return nullptr;

        return k->second;
    } catch (const std::exception& e) {
        return nullptr;
    }

    return nullptr;
}


void phy_80211_ssid_tracker::handle_broadcast_ssid(const std::string& ssid, unsigned int ssid_len, 
        uint64_t crypt_set, std::shared_ptr<kis_tracked_device_base> device) {

    if (!ssid_tracking_enabled)
        return;

    if (ssid_len == 0)
        return;

    auto key = dot11_tracked_ssid_group::generate_hash(ssid, ssid_len, crypt_set);

    local_locker l(&mutex);

    auto mapdev = ssid_map.find(key);

    if (mapdev == ssid_map.end()) {
        auto tssid = std::make_shared<dot11_tracked_ssid_group>(tracked_ssid_id, ssid, ssid_len, crypt_set);
        tssid->add_advertising_device(device);
        ssid_map[key] = tssid;
        ssid_vector->push_back(tssid);
    } else {
        auto tssid = std::static_pointer_cast<dot11_tracked_ssid_group>(mapdev->second);
        tssid->add_advertising_device(device);
    }
}

void phy_80211_ssid_tracker::handle_response_ssid(const std::string& ssid, unsigned int ssid_len, 
        uint64_t crypt_set, std::shared_ptr<kis_tracked_device_base> device) {

    if (!ssid_tracking_enabled)
        return;

    if (ssid_len == 0)
        return;

    auto key = dot11_tracked_ssid_group::generate_hash(ssid, ssid_len, crypt_set);

    local_locker l(&mutex);

    auto mapdev = ssid_map.find(key);

    if (mapdev == ssid_map.end()) {
        auto tssid = std::make_shared<dot11_tracked_ssid_group>(tracked_ssid_id, ssid, ssid_len, crypt_set);
        tssid->add_responding_device(device);
        ssid_map[key] = tssid;
        ssid_vector->push_back(tssid);
    } else {
        auto tssid = std::static_pointer_cast<dot11_tracked_ssid_group>(mapdev->second);
        tssid->add_responding_device(device);
    }

}

void phy_80211_ssid_tracker::handle_probe_ssid(const std::string& ssid, unsigned int ssid_len, 
        uint64_t crypt_set, std::shared_ptr<kis_tracked_device_base> device) {

    if (!ssid_tracking_enabled)
        return;

    if (ssid_len == 0)
        return;

    auto key = dot11_tracked_ssid_group::generate_hash(ssid, ssid_len, crypt_set);

    local_locker l(&mutex);

    auto mapdev = ssid_map.find(key);

    if (mapdev == ssid_map.end()) {
        auto tssid = std::make_shared<dot11_tracked_ssid_group>(tracked_ssid_id, ssid, ssid_len, crypt_set);
        tssid->add_probing_device(device);
        ssid_map[key] = tssid;
        ssid_vector->push_back(tssid);
    } else {
        auto tssid = std::static_pointer_cast<dot11_tracked_ssid_group>(mapdev->second);
        tssid->add_probing_device(device);
    }

}

