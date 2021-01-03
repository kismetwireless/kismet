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

#include "devicetracker_view.h"
#include "devicetracker.h"
#include "devicetracker_component.h"
#include "util.h"

#include "kis_mutex.h"
#include "kismet_algorithm.h"

device_tracker_view::device_tracker_view(const std::string& in_id, const std::string& in_description, 
        new_device_cb in_new_cb, updated_device_cb in_update_cb) :
    tracker_component{},
    new_cb {in_new_cb},
    update_cb {in_update_cb} {

    mutex.set_name(fmt::format("devicetracker_view({})", in_id));

    devicetracker = Globalreg::fetch_mandatory_global_as<device_tracker>();

    register_fields();
    reserve_fields(nullptr);

    view_id->set(in_id);
    view_description->set(in_description);

    device_list = std::make_shared<tracker_element_vector>();

    auto httpd = Globalreg::fetch_mandatory_global_as<kis_net_beast_httpd>();

    auto uri = fmt::format("/devices/views/{}/devices", in_id);
    httpd->register_route(uri, {"GET", "POST"}, httpd->RO_ROLE, {},
            std::make_shared<kis_net_web_function_endpoint>(
                [this](std::shared_ptr<kis_net_beast_httpd_connection> con) {
                    return device_endpoint_handler(con);
                }));

    uri = fmt::format("/device/views/{}/last-time/:timestamp/devices", in_id);
    httpd->register_route(uri, {"GET", "POST"}, httpd->RO_ROLE, {},
            std::make_shared<kis_net_web_tracked_endpoint>(
                [this](std::shared_ptr<kis_net_beast_httpd_connection> con) {
                    return device_time_endpoint(con);
                }));
}

device_tracker_view::device_tracker_view(const std::string& in_id, const std::string& in_description,
        const std::vector<std::string>& in_aux_path, 
        new_device_cb in_new_cb, updated_device_cb in_update_cb) :
    tracker_component{},
    new_cb {in_new_cb},
    update_cb {in_update_cb} {

    mutex.set_name(fmt::format("devicetracker_view({})", in_id));

    devicetracker = Globalreg::fetch_mandatory_global_as<device_tracker>();

    register_fields();
    reserve_fields(nullptr);

    view_id->set(in_id);
    view_description->set(in_description);

    device_list = std::make_shared<tracker_element_vector>();

    auto httpd = Globalreg::fetch_mandatory_global_as<kis_net_beast_httpd>();

    auto uri = fmt::format("/devices/views/{}/devices", in_id);
    httpd->register_route(uri, {"GET", "POST"}, httpd->RO_ROLE, {},
            std::make_shared<kis_net_web_function_endpoint>(
                [this](std::shared_ptr<kis_net_beast_httpd_connection> con) {
                    return device_endpoint_handler(con);
                }));

    uri = fmt::format("/device/views/{}/last-time/:timestamp/devices", in_id);
    httpd->register_route(uri, {"GET", "POST"}, httpd->RO_ROLE, {},
            std::make_shared<kis_net_web_tracked_endpoint>(
                [this](std::shared_ptr<kis_net_beast_httpd_connection> con) {
                    return device_time_endpoint(con);
                }));


    if (in_aux_path.size() == 0)
        return;

    // Concatenate the alternate endpoints and register the same endpoint handlers
    std::stringstream ss;
    for (const auto& i : in_aux_path)
        ss << i << "/";

    uri = fmt::format("/devices/views/{}devices", ss.str());
    httpd->register_route(uri, {"GET", "POST"}, httpd->RO_ROLE, {},
            std::make_shared<kis_net_web_function_endpoint>(
                [this](std::shared_ptr<kis_net_beast_httpd_connection> con) {
                    return device_endpoint_handler(con);
                }));

    uri = fmt::format("/device/views/{}last-time/:timestamp/devices", ss.str());
    httpd->register_route(uri, {"GET", "POST"}, httpd->RO_ROLE, {},
            std::make_shared<kis_net_web_tracked_endpoint>(
                [this](std::shared_ptr<kis_net_beast_httpd_connection> con) {
                    return device_time_endpoint(con);
                }));
}

std::shared_ptr<tracker_element_vector> device_tracker_view::do_device_work(device_tracker_view_worker& worker) {
    // Make a copy of the vector
    std::shared_ptr<tracker_element_vector> immutable_copy;
    {
        kis_lock_guard<kis_mutex> lk(mutex);
        immutable_copy = std::make_shared<tracker_element_vector>(device_list);
    }

    return do_device_work(worker, immutable_copy);
}

std::shared_ptr<tracker_element_vector> device_tracker_view::do_readonly_device_work(device_tracker_view_worker& worker) {
    // Make a copy of the vector
    std::shared_ptr<tracker_element_vector> immutable_copy;
    {
        kis_lock_guard<kis_mutex> lk(mutex);
        immutable_copy = std::make_shared<tracker_element_vector>(device_list);
    }

    return do_readonly_device_work(worker, immutable_copy);
}

std::shared_ptr<tracker_element_vector> device_tracker_view::do_device_work(device_tracker_view_worker& worker,
        std::shared_ptr<tracker_element_vector> devices) {
    auto ret = std::make_shared<tracker_element_vector>();
    ret->reserve(devices->size());

    // Lock the whole device list for the duration
    auto dev_lg = 
        std::lock_guard<kis_tristate_mutex_view>(devicetracker->get_devicelist_write());

    std::for_each(devices->begin(), devices->end(),
            [&](shared_tracker_element val) {

            if (val == nullptr)
                return;

            auto dev = std::static_pointer_cast<kis_tracked_device_base>(val);

            bool m;
            {
                // Lock each device within the overall devicelist write state
                dev->device_mutex.lock();
                m = worker.match_device(dev);
                dev->device_mutex.unlock();
            }

            if (m) 
                ret->push_back(dev);

        });

    worker.set_matched_devices(ret);

    worker.finalize();

    return ret;
}

std::shared_ptr<tracker_element_vector> device_tracker_view::do_readonly_device_work(device_tracker_view_worker& worker,
        std::shared_ptr<tracker_element_vector> devices) {
    auto ret = std::make_shared<tracker_element_vector>();
    ret->reserve(devices->size());

    auto ul_devlist =
        std::lock_guard<kis_tristate_mutex_view>(devicetracker->get_devicelist_share());

    std::for_each(devices->begin(), devices->end(),
            [&](shared_tracker_element val) {

            if (val == nullptr)
                return;

            auto dev = std::static_pointer_cast<kis_tracked_device_base>(val);

            auto m = worker.match_device(dev);

            if (m) 
                ret->push_back(dev);

        });

    worker.set_matched_devices(ret);

    worker.finalize();

    return ret;
}

void device_tracker_view::new_device(std::shared_ptr<kis_tracked_device_base> device) {
    if (new_cb != nullptr) {
        kis_lock_guard<kis_mutex> lk(mutex);

        if (new_cb(device)) {
            auto dpmi = device_presence_map.find(device->get_key());

            if (dpmi == device_presence_map.end()) {
                device_presence_map[device->get_key()] = true;
                device_list->push_back(device);
            }

            list_sz->set(device_list->size());
        }
    }
}

void device_tracker_view::update_device(std::shared_ptr<kis_tracked_device_base> device) {

    if (update_cb == nullptr)
        return;

    {
        kis_lock_guard<kis_mutex> lk(mutex);
        bool retain = update_cb(device);

        auto dpmi = device_presence_map.find(device->get_key());

        // If we're adding the device (or keeping it) and we don't have it tracked,
        // add it and record it in the presence map
        if (retain && dpmi == device_presence_map.end()) {
            device_list->push_back(device);
            device_presence_map[device->get_key()] = true;
            list_sz->set(device_list->size());
            return;
        }

        // if we're removing the device, find it in the vector and remove it, and remove
        // it from the presence map; this is expensive
        if (!retain && dpmi != device_presence_map.end()) {
            for (auto di = device_list->begin(); di != device_list->end(); ++di) {
                if (*di == device) {
                    device_list->erase(di);
                    break;
                }
            }
            device_presence_map.erase(dpmi);
            list_sz->set(device_list->size());
            return;
        }
    }
}

void device_tracker_view::remove_device(std::shared_ptr<kis_tracked_device_base> device) {
    kis_lock_guard<kis_mutex> lk(mutex);

    auto di = device_presence_map.find(device->get_key());

    if (di != device_presence_map.end()) {
        device_presence_map.erase(di);

        for (auto vi = device_list->begin(); vi != device_list->end(); ++vi) {
            if (*vi == device) {
                device_list->erase(vi);
                break;
            }
        }
        
        list_sz->set(device_list->size());
    }
}

void device_tracker_view::add_device_direct(std::shared_ptr<kis_tracked_device_base> device) {
    kis_lock_guard<kis_mutex> lk(mutex);

    auto di = device_presence_map.find(device->get_key());

    if (di != device_presence_map.end())
        return;

    device_presence_map[device->get_key()] = true;
    device_list->push_back(device);

    list_sz->set(device_list->size());
}

void device_tracker_view::remove_device_direct(std::shared_ptr<kis_tracked_device_base> device) {
    kis_lock_guard<kis_mutex> lk(mutex);

    auto di = device_presence_map.find(device->get_key());

    if (di != device_presence_map.end()) {
        device_presence_map.erase(di);

        for (auto vi = device_list->begin(); vi != device_list->end(); ++vi) {
            if (*vi == device) {
                device_list->erase(vi);
                break;
            }
        }
        
        list_sz->set(device_list->size());
    }
}

std::shared_ptr<tracker_element> 
device_tracker_view::device_time_endpoint(std::shared_ptr<kis_net_beast_httpd_connection> con) {
    // The device worker creates an immutable copy of the device list under its own RO mutex,
    // so we don't have to lock here.
    
    auto ret = std::make_shared<tracker_element_vector>();

    auto tv_k = con->uri_params().find(":timestamp");
    auto tv = string_to_n_dfl<int64_t>(tv_k->second, 0);
    time_t ts;

    if (tv < 0) {
        ts = time(0) + tv;
    } else {
        ts = tv;
    }

    auto worker = 
        device_tracker_view_function_worker([&](std::shared_ptr<kis_tracked_device_base> dev) -> bool {
                if (dev->get_last_time() < ts)
                    return false;

                return true;
                });

    return do_readonly_device_work(worker);
}

void device_tracker_view::device_endpoint_handler(std::shared_ptr<kis_net_beast_httpd_connection> con) {
    std::ostream os(&con->response_stream());

    // Summarization vector based on simplification part of shared data
    auto summary_vec = std::vector<SharedElementSummary>{};

    // Rename cache generated by summarization
    auto rename_map = std::make_shared<tracker_element_serializer::rename_map>();

    // Timestamp limitation
    time_t timestamp_min = 0;

    // String search term, if any
    auto search_term = std::string{};

    // Search paths, if any
    auto search_paths = std::vector<std::vector<int>>{};

    // Order path
    auto order_field = std::vector<int>{};

    // Regular expression terms, if any
    auto regex = con->json()["regex"];

    // Wrapper, if any, we insert under
    std::shared_ptr<tracker_element_string_map> wrapper_elem;

    // Field we transmit in the final stage (derived array, or map)
    std::shared_ptr<tracker_element> transmit;

    // Windowed response elements, used in datatables and others
    auto length_elem = std::make_shared<tracker_element_uint64>();
    auto start_elem = std::make_shared<tracker_element_uint64>();

    // Total and filtered output sizes
    auto total_sz_elem = std::make_shared<tracker_element_uint64>();
    auto filtered_sz_elem = std::make_shared<tracker_element_uint64>();

    // Output device list, should be copied into for final output
    auto output_devices_elem = std::make_shared<tracker_element_vector>();

    // Datatables specific draw element
    auto dt_draw_elem = std::make_shared<tracker_element_uint64>();

    try {
        // If the json has a 'fields' record, derive the fields simplification
        auto fields = con->json().get("fields", Json::Value(Json::arrayValue));

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
        auto raw_ts = con->json().get("last_time", 0).asInt64();
        if (raw_ts < 0)
            timestamp_min = time(0) + raw_ts;
        else
            timestamp_min = raw_ts;
    } catch (const std::runtime_error& e) {
        con->set_status(400);
        os << "Invalid request: " << e.what() << "\n";
    }

    // Input fields from variables
    unsigned int in_window_start = 0;
    unsigned int in_window_len = 0;
    unsigned int in_dt_draw = 0;
    std::string in_order_column_num;
    unsigned int in_order_direction = 0;

    // Parse datatables sub-data for windowing, etc
    try {
        // Extract the column number -> column fieldpath data
        auto column_number_map = con->json()["colmap"];

        if (con->json().get("datatable", false).asBool()) {
            // Extract from the raw postvars 
            auto start_k = con->http_variables().find("start");
            if (start_k != con->http_variables().end())
                in_window_start = string_to_n<unsigned int>(start_k->second);

            auto length_k = con->http_variables().find("length");
            if (length_k != con->http_variables().end())
                in_window_len = string_to_n<unsigned int>(length_k->second);

            auto draw_k = con->http_variables().find("draw");
            if (draw_k != con->http_variables().end())
                in_dt_draw = string_to_n<unsigned int>(draw_k->second);

            auto search_k = con->http_variables().find("search[value]");
            if (search_k != con->http_variables().end())
                search_term = search_k->second;

            // Search every field we return
            if (search_term.length() != 0) 
                for (const auto& svi : summary_vec)
                    search_paths.push_back(svi->resolved_path);

            // We only allow ordering by a single column, we don't do sub-ordering;
            // look for that single column
            auto order_k = con->http_variables().find("order[0][column]");
            if (order_k != con->http_variables().end())
                in_order_column_num = order_k->second;

            // We can only sort by a column that makes sense
            auto column_index = column_number_map[in_order_column_num];
            auto orderdir_k = con->http_variables().find("order[0][dir]");
            if (!column_index.isNull() && orderdir_k != con->http_variables().end()) {
                if (orderdir_k->second == "asc")
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
            wrapper_elem->insert("data", output_devices_elem);
            wrapper_elem->insert("recordsTotal", total_sz_elem);
            wrapper_elem->insert("recordsFiltered", filtered_sz_elem);

            // We transmit the wrapper elem
            transmit = wrapper_elem;
        }
    } catch (const std::exception& e) {
        con->set_status(400);
        os << "Invalid request: " << e.what() << "\n";
    }

    // Next vector we do work on
    auto next_work_vec = std::make_shared<tracker_element_vector>();

    // Copy the entire vector list, under lock, to the next work vector; this makes it an independent copy
    // which is protected from the main vector being grown/shrank.  While we're in there, log the total
    // size of the original vector for windowed ops.
    {
        kis_lock_guard<kis_mutex> lk(mutex);

        next_work_vec->set(device_list->begin(), device_list->end());
        total_sz_elem->set(next_work_vec->size());
    }

    // If we have a time filter, apply that first, it's the fastest.
    if (timestamp_min > 0) {
        auto worker = 
            device_tracker_view_function_worker([timestamp_min] (std::shared_ptr<kis_tracked_device_base> dev) -> bool {
                    if (dev->get_last_time() < timestamp_min)
                        return false;
                    return true;
                    });

        // Do the work and copy the vector
        auto ts_vec = do_readonly_device_work(worker, next_work_vec);
        next_work_vec->set(ts_vec->begin(), ts_vec->end());
    }

    // Apply a string filter
    if (search_term.length() > 0 && search_paths.size() > 0) {
        auto worker =
            device_tracker_view_icasestringmatch_worker(search_term, search_paths);
        auto s_vec = do_readonly_device_work(worker, next_work_vec);
        next_work_vec->set(s_vec->begin(), s_vec->end());
    }

    // Apply a regex filter
    if (!regex.isNull()) {
        try {
            auto worker = 
                device_tracker_view_regex_worker(regex);
            auto r_vec = do_readonly_device_work(worker, next_work_vec);
            next_work_vec = r_vec;
            // next_work_vec->set(r_vec->begin(), r_vec->end());
        } catch (const std::exception& e) {
            con->set_status(400);
            os << "Invalid regex: " << e.what() << "\n";
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
    auto final_devices_vec = std::make_shared<tracker_element_vector>();

    for (auto i = si; i != ei; ++i) {
        final_devices_vec->push_back(*i);
        output_devices_elem->push_back(summarize_tracker_element(*i, summary_vec, rename_map));
    }

    // If the transmit wasn't assigned to a wrapper...
    if (transmit == nullptr)
        transmit = output_devices_elem;

    // Lock shared access to serialize
    auto lg_list =
        std::lock_guard<kis_tristate_mutex_view>(devicetracker->get_devicelist_share());
    Globalreg::globalreg->entrytracker->serialize(static_cast<std::string>(con->uri()), os, transmit, rename_map);
}


