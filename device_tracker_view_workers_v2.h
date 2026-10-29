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

#ifndef __DEVICE_TRACKER_VIEW_WORKERS_V2_H__
#define __DEVICE_TRACKER_VIEW_WORKERS_V2_H__

#include "config.h"

#include <functional>
#include <vector>

#include "devicetracker_component_v2.h"

#include "regex_adapter.h"

class device_tracker_view_worker_v2 {
public:
    device_tracker_view_worker_v2() { }
    virtual ~device_tracker_view_worker_v2() { }

    virtual bool match_device(kis_tracked_device_base_v2 *d) = 0;
    virtual void finalize() { }

    const auto& get_matched() { return matched_; }

protected:
    std::vector<kis_tracked_device_base_v2 *> matched_;
};

template<typename Mftor>
class device_tracker_view_ftor_worker : public device_tracker_view_worker_v2 {
public:
    device_tracker_view_ftor_worker(const device_tracker_view_ftor_worker& w) {
        matched_ = w.matched_;
    }

    device_tracker_view_ftor_worker(const device_tracker_view_ftor_worker&& w) {
        matched_ = std::move(w.matched_);
    }

    virtual ~device_tracker_view_ftor_worker() { }

    virtual bool match_device(kis_tracked_device_base_v2 *d) {
        if (Mftor{}(d)) {
            matched_.push_back(d);
            return true;
        }

        return false;
    }
};


class device_tracker_view_regex_worker_v2 : public device_tracker_view_worker_v2 {
public:
    // match a single regex/field
    device_tracker_view_regex_worker_v2(const std::string& re, const std::string& fn);

    // match N regex:[fields] pairs
    device_tracker_view_regex_worker_v2(const std::list<std::pair<std::string, std::list<std::string>>>& matchset,
            bool match_any);

    device_tracker_view_regex_worker_v2(const device_tracker_view_regex_worker_v2&) = delete;
    device_tracker_view_regex_worker_v2(const device_tracker_view_regex_worker_v2&& w) = delete;

    virtual ~device_tracker_view_regex_worker_v2() { }

    virtual bool match_device(kis_tracked_device_base_v2 *d) override;

protected:
    std::list<std::pair<std::unique_ptr<kis_regex::regex>, json_adapter_v2::field_group_map>> regex_field_list_;
    bool match_any_;
};

class device_tracker_view_string_worker_v2 : public device_tracker_view_worker_v2 {
public:
    // match a single string/field
    device_tracker_view_string_worker_v2(const std::string& str, const std::string& fn,
            bool match_icase, bool match_full);

    // match N string:[fields] pairs
    device_tracker_view_string_worker_v2(const std::list<std::pair<std::string, std::list<std::string>>>& matchset,
            bool match_any, bool match_icase, bool match_full);

    device_tracker_view_string_worker_v2(const device_tracker_view_string_worker_v2&) = delete;
    device_tracker_view_string_worker_v2(const device_tracker_view_string_worker_v2&& w) = delete;

    virtual ~device_tracker_view_string_worker_v2() { }

    virtual bool match_device(kis_tracked_device_base_v2 *d) override;

protected:
    std::list<std::pair<std::string, json_adapter_v2::field_group_map>> string_field_list_;
    bool match_any_;
    bool match_icase_;
    bool match_full_;
};


#endif /* __DEVICE_TRACKER_VIEW_WORKERS_V2_H__ */
