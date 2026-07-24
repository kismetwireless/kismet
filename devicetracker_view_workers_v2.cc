/*
    this file is part of kismet

    kismet is free software; you can redistribute it and/or modify
    it under the terms of the gnu general public license as published by
    the free software foundation; either version 2 of the license, or
    (at your option) any later version.

    kismet is distributed in the hope that it will be useful,
    but without any warranty; without even the implied warranty of
    merchantability or fitness for a particular purpose.  see the
    gnu general public license for more details.

    you should have received a copy of the gnu general public license
    along with kismet; if not, write to the free software
    foundation, inc., 59 temple place, suite 330, boston, ma  02111-1307  usa
*/

#include "device_tracker_view_workers_v2.h"

device_tracker_view_regex_worker_v2::device_tracker_view_regex_worker_v2(const std::string& re,
        const std::string& fn) {

    json_adapter_v2::field_group_map gm;
    json_adapter_v2::group_fields(json_adapter_v2::raw_field_list{{fn, ""}}, gm);

    regex_field_list_.push_back({std::make_unique<kis_regex::regex>(re), gm});

    match_any_ = true;
}

device_tracker_view_regex_worker_v2::device_tracker_view_regex_worker_v2(const std::list<std::pair<std::string, std::list<std::string>>>& matchset,
        bool match_any) {

    for (const auto& mi : matchset) {
        json_adapter_v2::field_group_map fgm;
        json_adapter_v2::group_fields(std::get<1>(mi), fgm);
        regex_field_list_.push_back({std::make_unique<kis_regex::regex>(std::get<0>(mi)), fgm});
    }

    match_any_ = match_any;
}

bool device_tracker_view_regex_worker_v2::match_device(kis_tracked_device_base_v2 *d) {
    for (const auto& re : regex_field_list_) {
        // remember to make a copy of the fields before we potentially descend down the
        // field tree mutably
        auto m = d->match_regex(*std::get<0>(re), std::get<1>(re));
        if (m && match_any_) {
            matched_.push_back(d);
            return true;
        } else if (!m) {
            return false;
        }
    }

    matched_.push_back(d);
    return true;
}

device_tracker_view_string_worker_v2::device_tracker_view_string_worker_v2(const std::string& str,
        const std::string& fn, bool match_icase, bool match_full) {

    json_adapter_v2::field_group_map gm;
    json_adapter_v2::group_fields(json_adapter_v2::raw_field_list{{fn, ""}}, gm);

    string_field_list_ = {{str, gm}};

    match_any_ = true;
    match_icase_ = match_icase;
    match_full_ = match_full;
}

device_tracker_view_string_worker_v2::device_tracker_view_string_worker_v2(const std::list<std::pair<std::string, std::list<std::string>>>& matchset,
        bool match_any, bool match_icase, bool match_full) {

    for (const auto& mi : matchset) {
        json_adapter_v2::field_group_map fgm;
        json_adapter_v2::group_fields(std::get<1>(mi), fgm);
        string_field_list_.push_back({std::get<0>(mi), fgm});
    }

    match_any_ = match_any;
    match_icase_ = match_icase;
    match_full_ = match_full;
}

bool device_tracker_view_string_worker_v2::match_device(kis_tracked_device_base_v2 *d) {
    for (const auto& re : string_field_list_) {
        // remember to make a copy of the fields before we potentially descend down the
        // field tree mutably
        auto m = d->match_string(std::get<0>(re), match_icase_, match_full_, std::get<1>(re));
        if (m && match_any_) {
            matched_.push_back(d);
            return true;
        } else if (!m) {
            return false;
        }
    }

    matched_.push_back(d);
    return true;
}
