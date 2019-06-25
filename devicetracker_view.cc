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
#include "devicetracker_component.h"
#include "util.h"

#include "kis_mutex.h"
#include "kismet_algorithm.h"

DevicetrackerView::DevicetrackerView(const std::string& in_id, const std::string& in_description, 
        new_device_cb in_new_cb, updated_device_cb in_update_cb) :
    tracker_component{},
    new_cb {in_new_cb},
    update_cb {in_update_cb} {

    using namespace std::placeholders;

    register_fields();
    reserve_fields(nullptr);

    view_id->set(in_id);
    view_description->set(in_description);

    device_list = std::make_shared<TrackerElementVector>();

    auto uri = fmt::format("/devices/views/{}/devices", in_id);
    device_endp =
        std::make_shared<Kis_Net_Httpd_Simple_Post_Endpoint>(uri, 
                [this](std::ostream& stream, const std::string& uri, SharedStructured post_structured,
                    Kis_Net_Httpd_Connection::variable_cache_map& variable_cache) -> unsigned int {
                    return device_endpoint_handler(stream, uri, post_structured, variable_cache);
                });

    time_endp =
        std::make_shared<Kis_Net_Httpd_Path_Tracked_Endpoint>(
                [this](const std::vector<std::string>& path) -> bool {
                    return device_time_endpoint_path(path);
                }, 
                [this](const std::vector<std::string>& path) -> std::shared_ptr<TrackerElement> {
                    return device_time_endpoint(path);
                });
}

DevicetrackerView::DevicetrackerView(const std::string& in_id, const std::string& in_description,
        const std::vector<std::string>& in_aux_path, 
        new_device_cb in_new_cb, updated_device_cb in_update_cb) :
    tracker_component{},
    new_cb {in_new_cb},
    update_cb {in_update_cb},
    uri_extras {in_aux_path} {

    using namespace std::placeholders;

    register_fields();
    reserve_fields(nullptr);

    view_id->set(in_id);
    view_description->set(in_description);

    device_list = std::make_shared<TrackerElementVector>();

    // Because we can't lock the device view and acquire locks on devices while the caller
    // might also hold locks on devices, we need to specially handle the mutex ourselves;
    // all our endpoints are registered w/ no mutex, accordingly.
    auto uri = fmt::format("/devices/views/{}/devices", in_id);
    device_endp =
        std::make_shared<Kis_Net_Httpd_Simple_Post_Endpoint>(uri, 
                [this](std::ostream& stream, const std::string& uri, SharedStructured post_structured,
                    Kis_Net_Httpd_Connection::variable_cache_map& variable_cache) -> unsigned int {
                    return device_endpoint_handler(stream, uri, post_structured, variable_cache);
                });

    time_endp =
        std::make_shared<Kis_Net_Httpd_Path_Tracked_Endpoint>(
                [this](const std::vector<std::string>& path) -> bool {
                    return device_time_endpoint_path(path);
                }, 
                [this](const std::vector<std::string>& path) -> std::shared_ptr<TrackerElement> {
                    return device_time_endpoint(path);
                });

    if (in_aux_path.size() == 0)
        return;

    // Concatenate the alternate endpoints and register the same endpoint handlers
    std::stringstream ss;
    for (auto i : in_aux_path)
        ss << i << "/";

    uri = fmt::format("/devices/views/{}devices", ss.str());
    device_uri_endp =
        std::make_shared<Kis_Net_Httpd_Simple_Post_Endpoint>(uri, 
                [this](std::ostream& stream, const std::string& uri, SharedStructured post_structured,
                    Kis_Net_Httpd_Connection::variable_cache_map& variable_cache) -> unsigned int {
                    return device_endpoint_handler(stream, uri, post_structured, variable_cache);
                });

    time_uri_endp =
        std::make_shared<Kis_Net_Httpd_Path_Tracked_Endpoint>(
                [this](const std::vector<std::string>& path) -> bool {
                    return device_time_uri_endpoint_path(path);
                }, 
                [this](const std::vector<std::string>& path) -> std::shared_ptr<TrackerElement> {
                    return device_time_uri_endpoint(path);
                });
    
}

std::shared_ptr<TrackerElementVector> DevicetrackerView::doDeviceWork(DevicetrackerViewWorker& worker) {
    // Make a copy of the vector
    std::shared_ptr<TrackerElementVector> immutable_copy;
    {
        local_shared_locker dl(&mutex);
        immutable_copy = std::make_shared<TrackerElementVector>(device_list);
    }

    return doDeviceWork(worker, immutable_copy);
}

std::shared_ptr<TrackerElementVector> DevicetrackerView::doReadonlyDeviceWork(DevicetrackerViewWorker& worker) {
    // Make a copy of the vector
    std::shared_ptr<TrackerElementVector> immutable_copy;
    {
        local_shared_locker dl(&mutex);
        immutable_copy = std::make_shared<TrackerElementVector>(device_list);
    }

    return doReadonlyDeviceWork(worker, immutable_copy);
}

std::shared_ptr<TrackerElementVector> DevicetrackerView::doDeviceWork(DevicetrackerViewWorker& worker,
        std::shared_ptr<TrackerElementVector> devices) {
    auto ret = std::make_shared<TrackerElementVector>();
    kis_recursive_timed_mutex ret_mutex;

    kismet__for_each(devices->begin(), devices->end(),
            [&](SharedTrackerElement val) {

            if (val == nullptr)
                return;

            auto dev = std::static_pointer_cast<kis_tracked_device_base>(val);

            bool m;
            {
                local_locker devlocker(&dev->device_mutex);
                m = worker.matchDevice(dev);
            }

            if (m) {
                local_locker retl(&ret_mutex);
                ret->push_back(dev);
            }

        });

    worker.setMatchedDevices(ret);

    return ret;
}

std::shared_ptr<TrackerElementVector> DevicetrackerView::doReadonlyDeviceWork(DevicetrackerViewWorker& worker,
        std::shared_ptr<TrackerElementVector> devices) {
    auto ret = std::make_shared<TrackerElementVector>();
    kis_recursive_timed_mutex ret_mutex;

    kismet__for_each(devices->begin(), devices->end(),
            [&](SharedTrackerElement val) {

            if (val == nullptr)
                return;

            auto dev = std::static_pointer_cast<kis_tracked_device_base>(val);

            bool m;
            {
                local_shared_locker devlocker(&dev->device_mutex);
                m = worker.matchDevice(dev);
            }

            if (m) {
                local_locker retl(&ret_mutex);
                ret->push_back(dev);
            }

        });

    worker.setMatchedDevices(ret);

    return ret;
}

void DevicetrackerView::newDevice(std::shared_ptr<kis_tracked_device_base> device) {
    if (new_cb != nullptr) {
        local_locker l(&mutex);

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

void DevicetrackerView::updateDevice(std::shared_ptr<kis_tracked_device_base> device) {

    if (update_cb == nullptr)
        return;

    {
        local_locker l(&mutex);
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

void DevicetrackerView::removeDevice(std::shared_ptr<kis_tracked_device_base> device) {
    local_locker l(&mutex);

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

void DevicetrackerView::addDeviceDirect(std::shared_ptr<kis_tracked_device_base> device) {
    local_locker l(&mutex);

    auto di = device_presence_map.find(device->get_key());

    if (di != device_presence_map.end())
        return;

    device_presence_map[device->get_key()] = true;
    device_list->push_back(device);

    list_sz->set(device_list->size());
}

void DevicetrackerView::removeDeviceDirect(std::shared_ptr<kis_tracked_device_base> device) {
    local_locker l(&mutex);

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

bool DevicetrackerView::device_time_endpoint_path(const std::vector<std::string>& path) {
    // /devices/views/[id]/last-time/[time]/devices

    if (path.size() < 6)
        return false;

    if (path[0] != "devices" || path[1] != "views" || path[3] != "last-time" || path[5] != "devices")
        return false;

    if (path[2] != get_view_id())
        return false;

    try {
       StringTo<int64_t>(path[4]);
    } catch (const std::exception& e) {
        return false;
    }

    return true;
}

std::shared_ptr<TrackerElement> DevicetrackerView::device_time_endpoint(const std::vector<std::string>& path) {
    // The device worker creates an immutable copy of the device list under its own RO mutex,
    // so we don't have to lock here.
    
    auto ret = std::make_shared<TrackerElementVector>();

    if (path.size() < 6)
        return ret;

    auto tv = StringTo<int64_t>(path[4], 0);
    time_t ts;

    // Don't allow 'all' devices b/c it's really expensive
    if (tv == 0)
        return ret;

    if (tv < 0)
        ts = time(0) - tv;
    else
        ts = tv;

    auto worker = 
        DevicetrackerViewFunctionWorker([&](std::shared_ptr<kis_tracked_device_base> dev) -> bool {
                if (dev->get_last_time() < ts)
                    return false;

                return true;
                });

    return doReadonlyDeviceWork(worker);
}

bool DevicetrackerView::device_time_uri_endpoint_path(const std::vector<std::string>& path) {
    // /devices/views/[extrasN]/last-time/[time]/devices
    
    auto extras_sz = uri_extras.size();

    if (extras_sz == 0)
        return false;

    if (path.size() < (5 + extras_sz))
        return false;

    if (path[0] != "devices" || path[1] != "views" || path[extras_sz + 2] != "last-time" || 
            path[extras_sz + 4] != "devices")
        return false;

    for (size_t s = 0; s < extras_sz; s++) {
        if (path[2 + s] != uri_extras[s]) {
            return false;
        }
    }

    try {
        StringTo<int64_t>(path[3 + extras_sz]);
    } catch (const std::exception& e) {
        return false;
    }

    return true;
}

std::shared_ptr<TrackerElement> DevicetrackerView::device_time_uri_endpoint(const std::vector<std::string>& path) {
    // The device worker creates an immutable copy of the device list under its own RO mutex,
    // so we don't have to lock here.
    auto ret = std::make_shared<TrackerElementVector>();

    auto extras_sz = uri_extras.size();

    if (extras_sz == 0)
        return ret;

    if (path.size() < (5 + extras_sz))
        return ret;

    auto tv = StringTo<int64_t>(path[3 + extras_sz], 0);
    time_t ts;

    // Don't allow 'all' devices b/c it's really expensive
    if (tv == 0)
        return ret;

    if (tv < 0)
        ts = time(0) + tv;
    else
        ts = tv;

    auto worker = 
        DevicetrackerViewFunctionWorker([&](std::shared_ptr<kis_tracked_device_base> dev) -> bool {
                if (dev->get_last_time() < ts)
                    return false;

                return true;
                });

    return doReadonlyDeviceWork(worker);
}

unsigned int DevicetrackerView::device_endpoint_handler(std::ostream& stream, 
        const std::string& uri, SharedStructured structured,
        std::map<std::string, std::shared_ptr<std::stringstream>>& postvars) {
    // The device worker creates an immutable copy of the device list under its own RO mutex,
    // so we don't have to lock here.

    // Summarization vector based on simplification part of shared data
    auto summary_vec = std::vector<SharedElementSummary>{};

    // Rename cache generated by summarization
    auto rename_map = std::make_shared<TrackerElementSerializer::rename_map>();

    // Timestamp limitation
    time_t timestamp_min = 0;

    // String search term, if any
    auto search_term = std::string{};

    // Search paths, if any
    auto search_paths = std::vector<std::vector<int>>{};

    // Order path
    auto order_field = std::vector<int>{};

    // Regular expression terms, if any
    auto regex = SharedStructured{};

    // Wrapper, if any, we insert under
    std::shared_ptr<TrackerElementStringMap> wrapper_elem;

    // Field we transmit in the final stage (dervied array, or map)
    std::shared_ptr<TrackerElement> transmit;

    // Windowed response elements, used in datatables and others
    auto length_elem = std::make_shared<TrackerElementUInt64>();
    auto start_elem = std::make_shared<TrackerElementUInt64>();

    // Total and filtered output sizes
    auto total_sz_elem = std::make_shared<TrackerElementUInt64>();
    auto filtered_sz_elem = std::make_shared<TrackerElementUInt64>();

    // Output device list, should be copied into for final output
    auto output_devices_elem = std::make_shared<TrackerElementVector>();

    // Datatables specific draw element
    auto dt_draw_elem = std::make_shared<TrackerElementUInt64>();

    try {
        // If the structured component has a 'fields' record, derive the fields
        // simplification
        if (structured->hasKey("fields")) {
            auto fields = structured->getStructuredByKey("fields");
            auto fvec = fields->getStructuredArray();

            for (const auto& i : fvec) {
                if (i->isString()) {
                    auto s = std::make_shared<TrackerElementSummary>(i->getString());
                    summary_vec.push_back(s);
                } else if (i->isArray()) {
                    auto mapvec = i->getStringVec();

                    if (mapvec.size() != 2)
                        throw StructuredDataException("Invalid field mapping, expected "
                                "[field, rename]");

                    auto s = std::make_shared<TrackerElementSummary>(mapvec[0], mapvec[1]);
                    summary_vec.push_back(s);
                } else {
                    throw StructuredDataException("Invalid field mapping, expected "
                            "field or [field,rename]");
                }
            }
        }

        // Capture timestamp and negative-offset timestamp
        int64_t raw_ts = structured->getKeyAsNumber("last_time", 0);
        if (raw_ts < 0)
            timestamp_min = time(0) + raw_ts;
        else
            timestamp_min = raw_ts;

        // Regex
        if (structured->hasKey("regex"))
            regex = structured->getStructuredByKey("regex");

    } catch (const StructuredDataException& e) {
        stream << "Invalid request: " << e.what() << "\n";
        return 400;
    }

    // Input fields from variables
    unsigned int in_window_start = 0;
    unsigned int in_window_len = 0;
    unsigned int in_dt_draw = 0;
    int in_order_column_num = 0;
    unsigned int in_order_direction = 0;

    // Column number->path field mapping
    auto column_number_map = StructuredData::structured_num_map{};

    // Parse datatables sub-data for windowing, etc
    try {
        // Extract the column number -> column fieldpath data
        if (structured->hasKey("colmap")) 
            column_number_map = structured->getStructuredByKey("colmap")->getStructuredNumMap();

        if (structured->getKeyAsBool("datatable", false)) {
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

            // We can only sort by a column that makes sense
            auto column_index = column_number_map.find(in_order_column_num);
            if (column_index == column_number_map.end())
                in_order_column_num = -1;

            // What direction do we sort in
            if (in_order_column_num >= 0 &&
                    postvars.find("order[0][dir]") != postvars.end()) {
                auto order = postvars.find("order[0][dir]")->second->str();

                if (order == "asc")
                    in_order_direction = 1;
                else
                    in_order_direction = 0;

                // Resolve the path, we only allow the first one
                auto column_index_vec = column_index->second->getStringVec();
                if (column_index_vec.size() >= 1) {
                    auto summary = TrackerElementSummary{column_index_vec[0]};
                    order_field = summary.resolved_path;
                }
            }

            if (in_window_len > 200) 
                in_window_len = 200;

            // Set the window elements for datatables
            length_elem->set(in_window_len);
            start_elem->set(in_window_start);
            dt_draw_elem->set(in_dt_draw);

            // Set up the datatables wrapper
            wrapper_elem = std::make_shared<TrackerElementStringMap>();
            transmit = wrapper_elem;

            wrapper_elem->insert("draw", dt_draw_elem);
            wrapper_elem->insert("data", output_devices_elem);
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
    auto next_work_vec = std::make_shared<TrackerElementVector>();

    // Copy the entire vector list, under lock, to the next work vector; this makes it an independent copy
    // which is protected from the main vector being grown/shrank.  While we're in there, log the total
    // size of the original vector for windowed ops.
    {
        local_locker l(&mutex);
        next_work_vec->set(device_list->begin(), device_list->end());
        total_sz_elem->set(next_work_vec->size());
    }

    // If we have a time filter, apply that first, it's the fastest.
    if (timestamp_min > 0) {
        auto worker = 
            DevicetrackerViewFunctionWorker([timestamp_min] (std::shared_ptr<kis_tracked_device_base> dev) -> bool {
                    if (dev->get_last_time() < timestamp_min)
                        return false;
                    return true;
                    });

        // Do the work and copy the vector
        auto ts_vec = doReadonlyDeviceWork(worker, next_work_vec);
        next_work_vec->set(ts_vec->begin(), ts_vec->end());
    }

    // Apply a string filter
    if (search_term.length() > 0 && search_paths.size() > 0) {
        auto worker =
            DevicetrackerViewStringmatchWorker(search_term, search_paths);
        auto s_vec = doReadonlyDeviceWork(worker, next_work_vec);
        next_work_vec->set(s_vec->begin(), s_vec->end());
    }

    // Apply a regex filter
    if (regex != nullptr) {
        try {
            auto worker = 
                DevicetrackerViewRegexWorker(regex);
            auto r_vec = doReadonlyDeviceWork(worker, next_work_vec);
            next_work_vec->set(r_vec->begin(), r_vec->end());
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

    auto si = next_work_vec->begin() + in_window_start;
    auto ei = next_work_vec->begin();

    if (in_window_len + in_window_start >= next_work_vec->size() || in_window_len == 0)
        ei = next_work_vec->end();
    else
        ei = ei + in_window_len;

    // Update the end
    length_elem->set(ei - si);

    // Do a partial fast-sort
    if (in_order_column_num >= 0 && order_field.size() > 0) {
        kismet__partial_sort(si, ei, next_work_vec->end(),
                [&](SharedTrackerElement a, SharedTrackerElement b) -> bool {
                SharedTrackerElement fa;
                SharedTrackerElement fb;

                fa = GetTrackerElementPath(order_field, a);
                fb = GetTrackerElementPath(order_field, b);

                if (fa == nullptr) 
                    return in_order_direction == 0;

                if (fb == nullptr)
                    return in_order_direction != 0;

                if (in_order_direction == 0)
                    return FastSortTrackerElementLess(fa, fb);

                return FastSortTrackerElementLess(fb, fa);
            });
    }

    // Summarize into the output element
    for (auto i = si; i != ei; ++i) {
        output_devices_elem->push_back(SummarizeSingleTrackerElement(*i, summary_vec, rename_map));
    }

    // If the transmit wasn't assigned to a wrapper...
    if (transmit == nullptr)
        transmit = output_devices_elem;

    // Serialize
    Globalreg::globalreg->entrytracker->Serialize(kishttpd::GetSuffix(uri), stream, transmit, rename_map);

    // And done
    return 200;
}


