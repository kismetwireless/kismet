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

#ifdef HAVE_CPP17_PARALLEL
#include <execution>
#endif

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

    devicetracker = Globalreg::fetch_mandatory_global_as<device_tracker>();

    register_fields();
    reserve_fields(nullptr);

    view_id->set(in_id);
    view_description->set(in_description);
    view_indexed->set(true);

    device_list = std::make_shared<tracker_element_vector>();

    register_urls(in_id);
}

device_tracker_view::device_tracker_view(const std::string& in_id, const std::string& in_description,
        const std::vector<std::string>& in_aux_path, 
        new_device_cb in_new_cb, updated_device_cb in_update_cb) :
    tracker_component{},
    new_cb {in_new_cb},
    update_cb {in_update_cb} {

    devicetracker = Globalreg::fetch_mandatory_global_as<device_tracker>();

    register_fields();
    reserve_fields(nullptr);

    view_id->set(in_id);
    view_description->set(in_description);
    view_indexed->set(true);

    device_list = std::make_shared<tracker_element_vector>();

    register_urls(in_id);

    if (in_aux_path.size() == 0)
        return;

    // Concatenate the alternate endpoints and register the same endpoint handlers
    std::stringstream ss;
    for (const auto& i : in_aux_path)
        ss << i << "/";

    register_urls(ss.str());
}

void device_tracker_view::register_urls(const std::string& in_id) { 
    auto httpd = Globalreg::fetch_mandatory_global_as<kis_net_beast_httpd>();

    auto uri = fmt::format("/devices/views/{}/devices", in_id);
    httpd->register_route(uri, {"GET", "POST"}, httpd->RO_ROLE, {},
            std::make_shared<kis_net_web_function_endpoint>(
                [this](std::shared_ptr<kis_net_beast_httpd_connection> con) {
                    return device_endpoint_handler(con);
                }, devicetracker->get_devicelist_mutex()));

    uri = fmt::format("/devices/views/{}/last-time/:timestamp/devices", in_id);
    httpd->register_route(uri, {"GET", "POST"}, httpd->RO_ROLE, {},
            std::make_shared<kis_net_web_tracked_endpoint>(
                [this](std::shared_ptr<kis_net_beast_httpd_connection> con) {
                    return device_time_endpoint(con);
                }, devicetracker->get_devicelist_mutex()));

    uri = fmt::format("/devices/views/{}/monitor", in_id);
    httpd->register_websocket_route(uri, httpd->RO_ROLE, {"ws"},
            std::make_shared<kis_net_web_function_endpoint>(
                [this](std::shared_ptr<kis_net_beast_httpd_connection> con) {

                std::unordered_map<unsigned int, int> key_timer_map;
                auto timetracker = Globalreg::fetch_mandatory_global_as<time_tracker>();

                auto ws =
                    std::make_shared<kis_net_web_websocket_endpoint>(con,
                        [this, timetracker, &key_timer_map, con](std::shared_ptr<kis_net_web_websocket_endpoint> ws,
                            std::shared_ptr<boost::asio::streambuf> buf, bool text) {

                        if (!text) {
                            ws->close();
                            return;
                        }

                        std::stringstream ss(boost::beast::buffers_to_string(buf->data()));
                        nlohmann::json json;

                        unsigned int req_id;

                        try {
                            ss >> json;

                            auto cancel_j = json["cancel"];
                            if (cancel_j.is_number()) {
                                auto kt_v = key_timer_map.find(cancel_j);
                                if (kt_v != key_timer_map.end()) {
                                    timetracker->remove_timer(kt_v->second);
                                    key_timer_map.erase(kt_v);
                                }
                            }

                            auto monitor_j = json["monitor"];
                            if (!monitor_j.is_null()) {
                                req_id = json["request"];

                                std::string format_t = json.value("format", "json");

                                std::string dev_r = json["monitor"];
                                auto dev_k = device_key(json["monitor"]);
                                auto dev_m = mac_addr(json["monitor"].get<std::string>());
                                
                                if (dev_r != "*" && dev_k.get_error() && dev_m.error())
                                    throw std::runtime_error("invalid device reference");

                                unsigned int rate = json["rate"];

                                // Remove any existing request under this ID
                                auto kt_v = key_timer_map.find(req_id);
                                if (kt_v != key_timer_map.end())
                                    timetracker->remove_timer(kt_v->second);

                                auto rename_map = Globalreg::new_from_pool<tracker_element_serializer::rename_map>();

                                time_t last_tm = 0;

                                // Generate a timer event that goes and looks for the devices and
                                // serializes them with the fields record
                                auto tid = 
                                    timetracker->register_timer(std::chrono::seconds(rate), true,
                                            [this, con, dev_r, dev_k, dev_m, json, ws, &last_tm, rename_map, format_t](int) -> int {
                                                if (dev_r == "*") {
                                                    auto worker = device_tracker_view_function_worker([json, last_tm, format_t, ws](std::shared_ptr<kis_tracked_device_base> dev) -> bool {
                                                        if (dev->get_mod_time() > last_tm) {
                                                            std::stringstream ss;
                                                            Globalreg::globalreg->entrytracker->serialize_with_json_summary(format_t, ss, dev, json);
                                                            ws->write(ss.str());
                                                        }

                                                        return false;
                                                    });

                                                    do_device_work(worker);
                                                } else if (!dev_k.get_error()) {
                                                    kis_lock_guard<kis_mutex> lk(devicetracker->get_devicelist_mutex(), "view ws monitor timer serialize lambda");

                                                    auto dev = fetch_device(dev_k);
                                                    if (dev != nullptr) {
                                                        if (dev->get_mod_time() > last_tm) {
                                                            std::stringstream ss;
                                                            Globalreg::globalreg->entrytracker->serialize_with_json_summary(format_t, ss, dev, json);
                                                            ws->write(ss.str());
                                                        }
                                                    }
                                                } else if (!dev_m.error()) {
                                                    kis_lock_guard<kis_mutex> lk(devicetracker->get_devicelist_mutex(), "view ws monitor timer serialize lambda");

                                                    auto mvec = devicetracker->fetch_devices(dev_m);

                                                    for (const auto& i : mvec) {
                                                        auto pk = device_presence_map.find(i->get_key());
                                                        if (pk == device_presence_map.end() || pk->second == false)
                                                            continue;

                                                        if (i->get_mod_time() > last_tm) {
                                                            std::stringstream ss;
                                                            Globalreg::globalreg->entrytracker->serialize_with_json_summary(format_t, ss, i, json);
                                                            ws->write(ss.str());
                                                        }
                                                    }
                                                }

                                                last_tm = time(0);

                                                return 1;
                                            });

                                key_timer_map[req_id] = tid;
                            }

                        } catch (const std::exception& e) {
                            _MSG_ERROR("Invalid device monitor request: {}", e.what());
                            return;
                        }

                    });

                ws->text();

                try {
                    ws->handle_request(con);
                } catch (const std::exception& e) {
                    ;
                }

                for (const auto &t : key_timer_map)
                    timetracker->remove_timer(t.second);

                }));
}

void device_tracker_view::pre_serialize() {
    kis_lock_guard<kis_mutex> lk(devicetracker->get_devicelist_mutex(), kismet::retain_lock, "devicetracker_view serialize");
}

void device_tracker_view::post_serialize() {
    kis_lock_guard<kis_mutex> lk(devicetracker->get_devicelist_mutex(), std::adopt_lock, "devicetracker_view post_serialize");
}

std::shared_ptr<tracker_element_vector> device_tracker_view::do_device_work(device_tracker_view_worker& worker) {
    // Make a copy of the vector in case the worker manipulates the original
    std::shared_ptr<tracker_element_vector> immutable_copy;
    {
        kis_lock_guard<kis_mutex> lk(devicetracker->get_devicelist_mutex());
        immutable_copy = std::make_shared<tracker_element_vector>(device_list);
    }

    return do_device_work(worker, immutable_copy);
}

std::shared_ptr<tracker_element_vector> device_tracker_view::do_readonly_device_work(device_tracker_view_worker& worker) {
    // Make a copy of the vector in case the worker manipulates the original
    std::shared_ptr<tracker_element_vector> immutable_copy;
    {
        kis_lock_guard<kis_mutex> lk(devicetracker->get_devicelist_mutex());
        immutable_copy = std::make_shared<tracker_element_vector>(device_list);
    }

    return do_readonly_device_work(worker, immutable_copy);
}

std::shared_ptr<tracker_element_vector> device_tracker_view::do_device_work(device_tracker_view_worker& worker,
        std::shared_ptr<tracker_element_vector> devices) {
    auto ret = std::make_shared<tracker_element_vector>();
    ret->reserve(devices->size());

    // Lock the whole device list for the duration; we may already hold this lock if we're inside the webserver
    // but that's OK
    kis_lock_guard<kis_mutex> dev_lg(devicetracker->get_devicelist_mutex(), 
            "device_tracker_view do_device_work");

    std::for_each(devices->begin(), devices->end(),
            [&](shared_tracker_element val) {

            if (val == nullptr)
                return;

            auto dev = std::static_pointer_cast<kis_tracked_device_base>(val);

            bool m;
            m = worker.match_device(dev);

            if (m) 
                ret->push_back(dev);

        });

    worker.set_matched_devices(ret);

    worker.finalize();

    return ret;
}

std::shared_ptr<tracker_element_vector> device_tracker_view::do_readonly_device_work(device_tracker_view_worker& worker,
        std::shared_ptr<tracker_element_vector> devices) {

    // read-only workers are currently disabled because it may not be reasonable to solve conflicts
    // at the per-device level, use the locked worker.

    return do_device_work(worker, devices);

#if 0
    auto ret = std::make_shared<tracker_element_vector>();
    ret->reserve(devices->size());

    kis_lock_guard<kis_mutex> ul_devlist(devicetracker->get_devicelist_mutex(), 
            "device_tracker_view do_readonly_device_work");

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
#endif
}

std::shared_ptr<kis_tracked_device_base> device_tracker_view::fetch_device(device_key in_key) {
    kis_lock_guard<kis_mutex> lk(devicetracker->get_devicelist_mutex(), "device_tracker_view fetch_device");

    auto present_itr = device_presence_map.find(in_key);

    if (present_itr == device_presence_map.end() || present_itr->second == false)
        return nullptr;

    return devicetracker->fetch_device(in_key);
}

void device_tracker_view::new_device(std::shared_ptr<kis_tracked_device_base> device) {
    if (new_cb != nullptr) {
        // Only called under guard from devicetracker
        // kis_lock_guard<kis_mutex> lk(devicetracker->get_devicelist_mutex());

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

    // Only called under guard from devicetracker already
    // kis_lock_guard<kis_mutex> lk(devicetracker->get_devicelist_mutex());
    
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

void device_tracker_view::remove_device(std::shared_ptr<kis_tracked_device_base> device) {
    // Only called under guard from devicetracker
    // kis_lock_guard<kis_mutex> lk(devicetracker->get_devicelist_mutex());

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
    kis_lock_guard<kis_mutex> lk(devicetracker->get_devicelist_mutex());

    auto di = device_presence_map.find(device->get_key());

    if (di != device_presence_map.end())
        return;

    device_presence_map[device->get_key()] = true;
    device_list->push_back(device);

    list_sz->set(device_list->size());
}

void device_tracker_view::remove_device_direct(std::shared_ptr<kis_tracked_device_base> device) {
    kis_lock_guard<kis_mutex> lk(devicetracker->get_devicelist_mutex());

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
    auto ret = Globalreg::new_from_pool<tracker_element_vector>();
    std::ostream os(&con->response_stream());

    auto tv_k = con->uri_params().find(":timestamp");
    auto tv = string_to_n_dfl<int64_t>(tv_k->second, 0);
    time_t ts;

    if (tv < 0) {
        ts = time(0) + tv;
    } else {
        ts = tv;
    }

    // Regular expression terms, if any
    auto regex = con->json()["regex"];

    auto worker = 
        device_tracker_view_function_worker([&](std::shared_ptr<kis_tracked_device_base> dev) -> bool {
                if (dev->get_last_time() < ts)
                    return false;

                return true;
                });

    auto next_work_vec = do_device_work(worker);

    // Apply a regex filter
    if (!regex.is_null()) {
        try {
            auto worker = 
                device_tracker_view_regex_worker(regex);
            auto r_vec = do_readonly_device_work(worker, next_work_vec);
            next_work_vec = r_vec;
        } catch (const std::exception& e) {
            con->set_status(400);
            os << "Invalid regex: " << e.what() << "\n";
            return nullptr;
        }
    }

    return next_work_vec;
}

void device_tracker_view::device_endpoint_handler(std::shared_ptr<kis_net_beast_httpd_connection> con) {
    std::ostream os(&con->response_stream());

    // Summarization vector based on simplification part of shared data
    auto summary_vec = std::vector<SharedElementSummary>{};

    // Rename cache generated by summarization
    auto rename_map = Globalreg::new_from_pool<tracker_element_serializer::rename_map>();

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

    auto max_page_elem = std::make_shared<tracker_element_uint64>();

    // Output device list, should be copied into for final output
    auto output_devices_elem = std::make_shared<tracker_element_vector>();

    // Datatables specific draw element
    auto dt_draw_elem = std::make_shared<tracker_element_uint64>();

    try {
        // If the json has a 'fields' record, derive the fields simplification
        auto fields = con->json().value("fields", nlohmann::json::array_t{});

        for (const auto& i : fields) {
            if (i.is_string()) {
                summary_vec.push_back(std::make_shared<tracker_element_summary>(i.get<std::string>()));
            } else if (i.is_array()) {
                if (i.size() != 2) 
                    throw std::runtime_error("Invalid field map, expected [field, rename]");

                summary_vec.push_back(std::make_shared<tracker_element_summary>(i[0].get<std::string>(), i[1].get<std::string>()));
            } else {
                throw std::runtime_error("Invalid field map, exected field or [field, rename]");
            }
        }

        // Capture timestamp and negative-offset timestamp
        uint64_t raw_ts = con->json().value("last_time", 0);
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

        // Generic pagination
        auto start_k = con->http_variables().find("page");
        if (start_k != con->http_variables().end()) {
            in_window_start = string_to_n<unsigned int>(start_k->second);

            auto length_k = con->http_variables().find("length");
            if (length_k != con->http_variables().end()) {
                in_window_len = string_to_n<unsigned int>(length_k->second);

                in_window_start *= in_window_len;
            } else {
                length_k = con->http_variables().find("size");
                if (length_k != con->http_variables().end())
                    in_window_len = string_to_n<unsigned int>(length_k->second);

                in_window_start *= in_window_len;
            }

            // Set the window elements for datatables
            start_elem->set(in_window_start);
            dt_draw_elem->set(in_dt_draw);

            // Set up the datatables wrapper
            wrapper_elem = std::make_shared<tracker_element_string_map>();
            transmit = wrapper_elem;

            wrapper_elem->insert("data", output_devices_elem);
            wrapper_elem->insert("last_page", max_page_elem);
            wrapper_elem->insert("last_row", filtered_sz_elem);
            wrapper_elem->insert("total_row", total_sz_elem);

            // We transmit the wrapper elem
            transmit = wrapper_elem;
        } 

        // Handle legacy datatable otpions, if datatable=true
        if (con->json().value("datatable", false)) {
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
            if (!column_index.is_null() && orderdir_k != con->http_variables().end()) {
                if (orderdir_k->second == "asc")
                    in_order_direction = 1;
                else
                    in_order_direction = 0;

                // Resolve the path, we only allow the first one
                if (column_index.is_array() && column_index.size() > 0) {
                    if (column_index[0].is_array()) {
                        // We only allow the first field, but make sure we're not a nested array
                        if (column_index[0].size() > 0) {
                            order_field = tracker_element_summary(column_index[0][0].get<std::string>()).resolved_path;
                        }
                    } else {
                        // Otherwise get the first array
                        if (column_index.size() >= 1) {
                            order_field = tracker_element_summary(column_index[0].get<std::string>()).resolved_path;
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
        } else {
            // Otherwise handle generic sort options
            auto sort_k = con->http_variables().find("sort");
            if (sort_k != con->http_variables().end()) {
                order_field = tracker_element_summary(sort_k->second).resolved_path;

                auto dir_k = con->http_variables().find("sort_dir");
                if (dir_k != con->http_variables().end() && dir_k->second == "asc")
                    in_order_direction = 1;
                else
                    in_order_direction = 0;
            }

            auto search_k = con->http_variables().find("search");
            if (search_k != con->http_variables().end())
                search_term = search_k->second;

            // Search every field we return
            if (search_term.length() != 0) 
                for (const auto& svi : summary_vec)
                    search_paths.push_back(svi->resolved_path);

        }
    } catch (const std::exception& e) {
        con->set_status(400);
        os << "Invalid request: " << e.what() << "\n";
        return;
    }

    // Next vector we do work on
    auto next_work_vec = std::make_shared<tracker_element_vector>();

    // Copy the entire vector list, under lock, to the next work vector; this makes it an independent copy
    // we can sort and manipulate
    next_work_vec->set(device_list->begin(), device_list->end());
    total_sz_elem->set(next_work_vec->size());

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
    if (!regex.is_null()) {
        try {
            auto worker = 
                device_tracker_view_regex_worker(regex);
            auto r_vec = do_readonly_device_work(worker, next_work_vec);
            next_work_vec = r_vec;
            // next_work_vec->set(r_vec->begin(), r_vec->end());
        } catch (const std::exception& e) {
            con->set_status(400);
            os << "Invalid regex: " << e.what() << "\n";
            return;
        }
    }

    // Apply the filtered length
    filtered_sz_elem->set(next_work_vec->size());

    if (in_window_len > 0) {
        max_page_elem->set(ceil(((float) next_work_vec->size()) / in_window_len));
    }

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

    // if (in_order_column_num.length() && order_field.size() > 0) {
    
    if (order_field.size() > 0) {
        std::stable_sort(
#if defined(HAVE_CPP17_PARALLEL)
            std::execution::par_unseq,
#endif
            next_work_vec->begin(), next_work_vec->end(),
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

    // Done
    Globalreg::globalreg->entrytracker->serialize(static_cast<std::string>(con->uri()), os, transmit, rename_map);
}


