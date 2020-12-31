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

#include "devicetracker_view_workers.h"
#include "devicetracker_component.h"
#include "util.h"

#include "kis_mutex.h"
#include "kismet_algorithm.h"

void device_tracker_view_worker::set_matched_devices(std::shared_ptr<tracker_element_vector> devs) {
    kis_lock_guard<kis_shared_mutex> lk(mutex);
    matched = devs;
}

device_tracker_view_function_worker::device_tracker_view_function_worker(filter_cb cb) :
    filter {cb} { }

bool device_tracker_view_function_worker::match_device(std::shared_ptr<kis_tracked_device_base> device) {
    return filter(device);
}

#ifdef HAVE_LIBPCRE
device_tracker_view_regex_worker::pcre_filter::pcre_filter(const std::string& in_target,
        const std::string& in_regex) {

    const char *compile_error, *study_error;
    int err_offt;

    target = in_target;

    re = pcre_compile(in_regex.c_str(), 0, &compile_error, &err_offt, NULL);

    if (re == nullptr)
        throw std::runtime_error(fmt::format("Could not parse PCRE Regex: {} at {}",
                    compile_error, err_offt));

    study = pcre_study(re, 0, &study_error);
    if (study_error != nullptr) {
        pcre_free(re);
        throw std::runtime_error(fmt::format("Could not parse PCRE Regex, optimization failed: {}",
                    study_error));
    }
}

device_tracker_view_regex_worker::pcre_filter::~pcre_filter() {
    if (re != NULL)
        pcre_free(re);
    if (study != NULL)
        pcre_free(study);
}

#endif

device_tracker_view_regex_worker::device_tracker_view_regex_worker(const std::vector<std::shared_ptr<device_tracker_view_regex_worker::pcre_filter>>& in_filter_vec) {
#ifdef HAVE_LIBPCRE
    filter_vec = in_filter_vec;
#else
    throw std::runtime_error("Kismet was not compiled with PCRE support");
#endif
}

device_tracker_view_regex_worker::device_tracker_view_regex_worker(const Json::Value& json) {
#ifdef HAVE_LIBPCRE
    for (const auto& i : json) {
        if (!i.isArray())
            throw std::runtime_error("expected array of [field, regex] pairs for regex filter");

        if (i.size() != 2)
            throw std::runtime_error("expected array of [field, regex] pairs for regex filter");

        auto worker_filter = 
            std::make_shared<device_tracker_view_regex_worker::pcre_filter>(i[0].asString(), i[1].asString());

        filter_vec.push_back(worker_filter);
    }
#else
    throw std::runtime_error("Kismet was not compiled with PCRE support");
#endif
}

device_tracker_view_regex_worker::device_tracker_view_regex_worker(const std::vector<std::pair<std::string, std::string>>& str_pcre_vec) {
#ifdef HAVE_LIBPCRE
    for (const auto& i : str_pcre_vec) {
        auto field = std::get<0>(i);
        auto regex = std::get<1>(i);

        auto worker_filter = std::make_shared<device_tracker_view_regex_worker::pcre_filter>(field, regex);

        filter_vec.push_back(worker_filter);
    }
#else
    throw std::runtime_error("Kismet was not compiled with PCRE support");
#endif
}

bool device_tracker_view_regex_worker::match_device(std::shared_ptr<kis_tracked_device_base> device) {
#ifdef HAVE_LIBPCRE
    bool matched = false;

    for (const auto& i : filter_vec) {
        auto fields = get_tracker_element_multi_path(i->target, device);

        for (const auto& fi : fields) {
            std::string val;

            switch (fi->get_type()) {
                case tracker_type::tracker_string:
                    val = get_tracker_value<std::string>(fi);
                    break;
                case tracker_type::tracker_mac_addr:
                    val = get_tracker_value<mac_addr>(fi).mac_to_string();
                    break;
                case tracker_type::tracker_uuid:
                    val = get_tracker_value<uuid>(fi).uuid_to_string();
                    break;
                case tracker_type::tracker_byte_array:
                    val = std::static_pointer_cast<tracker_element_byte_array>(fi)->get();
                    break;
                default:
                    continue;
            }

            int rc;
            int ovector[128];

            rc = pcre_exec(i->re, i->study, val.c_str(), val.length(), 0, 0, ovector, 128);

            // Stop matching as soon as we find a hit
            if (rc >= 0) {
                matched = true;
                break;
            }

        }

        if (matched)
            return true;
    }
#endif
    return false;
}

device_tracker_view_stringmatch_worker::device_tracker_view_stringmatch_worker(const std::string& in_query,
        const std::vector<std::vector<int>>& in_paths) :
    query { in_query },
    fieldpaths { in_paths } {

    // Generate cached match for mac addresses
    mac_addr::prepare_search_term(query, mac_query_term, mac_query_term_len);
}

bool device_tracker_view_stringmatch_worker::match_device(std::shared_ptr<kis_tracked_device_base> device) {
    bool matched = false;

    for (const auto& i : fieldpaths) {
        auto field = get_tracker_element_path(i, device);

        if (field == nullptr)
            continue;

        switch (field->get_type()) {
            case tracker_type::tracker_string:
                // We can only do a straight string match against string fields
                matched = get_tracker_value<std::string>(field).find(query) != std::string::npos;
                break;
            case tracker_type::tracker_byte_array:
                // Try a raw string match against a binary field
                matched = 
                    std::static_pointer_cast<tracker_element_byte_array>(field)->get().find(query) != 
                    std::string::npos;
                break;
            case tracker_type::tracker_mac_addr:
                if (mac_query_term_len != 0) {
                    // If we were able to interpret the query term as a partial
                    // mac address, do a mac compare
                    matched =
                        std::static_pointer_cast<tracker_element_mac_addr>(field)->get().partial_search(mac_query_term, mac_query_term_len);
                }
                break;
            default:
                ;
        }

        if (matched)
            return true;
    }

    return false;
}

device_tracker_view_icasestringmatch_worker::device_tracker_view_icasestringmatch_worker(const std::string& in_query,
        const std::vector<std::vector<int>>& in_paths) :
    query { in_query },
    fieldpaths { in_paths } {

    // Generate cached match for mac addresses
    mac_addr::prepare_search_term(query, mac_query_term, mac_query_term_len);
}

bool device_tracker_view_icasestringmatch_worker::match_device(std::shared_ptr<kis_tracked_device_base> device) {
    bool matched = false;

    auto icasesearch = [](const std::string& haystack, const std::string& needle) -> bool {
        auto pos = std::search(haystack.begin(), haystack.end(), needle.begin(), needle.end(),
                [](char ch1, char ch2) -> bool { 
                    return std::toupper(ch1) == std::toupper(ch2);
                });
        return (pos != haystack.end());
    };

    for (const auto& i : fieldpaths) {
        auto field = get_tracker_element_path(i, device);

        if (field == nullptr)
            continue;

        switch (field->get_type()) {
            case tracker_type::tracker_string:
                // We can only do a straight string match against string fields
                matched = icasesearch(get_tracker_value<std::string>(field), query);
                break;
            case tracker_type::tracker_byte_array:
                // Try a raw string match against a binary field
                matched = icasesearch(std::static_pointer_cast<tracker_element_byte_array>(field)->get(), query);
                break;
            case tracker_type::tracker_mac_addr:
                if (mac_query_term_len != 0) {
                    // If we were able to interpret the query term as a partial
                    // mac address, do a mac compare
                    matched =
                        std::static_pointer_cast<tracker_element_mac_addr>(field)->get().partial_search(mac_query_term, mac_query_term_len);
                }
                break;
            default:
                ;
        }

        if (matched)
            return true;
    }

    return false;
}


