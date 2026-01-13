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
    kis_lock_guard<kis_mutex> lk(mutex);
    matched = devs;
}

device_tracker_view_function_worker::device_tracker_view_function_worker(filter_cb cb) :
    filter {cb} { }

bool device_tracker_view_function_worker::match_device(std::shared_ptr<kis_tracked_device_base> device) {
    return filter(device);
}

#if defined(HAVE_LIBPCRE1)
device_tracker_view_regex_worker::pcre_filter::pcre_filter(const std::string& in_target,
        const std::string& in_regex) {

    const char *compile_error, *study_error;
    int err_offt;

    target = in_target;

    re = pcre_compile(in_regex.c_str(), 0, &compile_error, &err_offt, NULL);

    if (re == nullptr) {
        const auto e = fmt::format("Could not parse PCRE Regex: {} at {}",
                compile_error, err_offt);
        throw std::runtime_error(e);
    }

    study = pcre_study(re, 0, &study_error);
    if (study_error != nullptr) {
        pcre_free(re);
        
        const auto e = fmt::format("Could not parse PCRE Regex, optimization failed: {}", study_error);
        throw std::runtime_error(e);
    }
}

device_tracker_view_regex_worker::pcre_filter::~pcre_filter() {
    if (re != NULL)
        pcre_free(re);
    if (study != NULL)
        pcre_free(study);
}

#elif defined(HAVE_LIBPCRE2)

device_tracker_view_regex_worker::pcre_filter::pcre_filter(const std::string& in_target,
        const std::string& in_regex) {

    PCRE2_SIZE erroroffset;
    int errornumber;

    re = NULL;
    match_data = NULL;

    target = in_target;

    re = pcre2_compile((PCRE2_SPTR8) in_regex.c_str(),
       PCRE2_ZERO_TERMINATED, 0, &errornumber, &erroroffset, NULL);

    if (re == nullptr) {
        PCRE2_UCHAR buffer[256];
        pcre2_get_error_message(errornumber, buffer, sizeof(buffer));

        const auto e = fmt::format("Could not parse PCRE regex: {} at {}",
                (int) erroroffset, (char *) buffer);
        throw std::runtime_error(e);
    }

	match_data = pcre2_match_data_create_from_pattern(re, NULL);
}

device_tracker_view_regex_worker::pcre_filter::~pcre_filter() {
    if (match_data != nullptr)
        pcre2_match_data_free(match_data);
    if (re != nullptr)
        pcre2_code_free(re);
}

#endif

device_tracker_view_regex_worker::device_tracker_view_regex_worker(const std::vector<std::shared_ptr<device_tracker_view_regex_worker::pcre_filter>>& in_filter_vec) {
#if defined(HAVE_LIBPCRE1) || defined(HAVE_LIBPCRE2)
    filter_vec = in_filter_vec;
#else
    throw std::runtime_error("Kismet was not compiled with PCRE support");
#endif
}

device_tracker_view_regex_worker::device_tracker_view_regex_worker(nlohmann::json& json) {
#if defined(HAVE_LIBPCRE1) || defined(HAVE_LIBPCRE2)
    for (const auto& i : json) {
        if (!i.is_array())
            throw std::runtime_error("expected array of [field, regex] pairs for regex filter");

        if (i.size() != 2)
            throw std::runtime_error("expected array of [field, regex] pairs for regex filter");

        auto worker_filter = 
            std::make_shared<device_tracker_view_regex_worker::pcre_filter>(i[0].get<std::string>(), i[1].get<std::string>());

        filter_vec.push_back(worker_filter);
    }
#else
    throw std::runtime_error("Kismet was not compiled with PCRE support");
#endif
}

device_tracker_view_regex_worker::device_tracker_view_regex_worker(const std::vector<std::pair<std::string, std::string>>& str_pcre_vec) {
#if defined(HAVE_LIBPCRE1) || defined(HAVE_LIBPCRE2)
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
#if defined(HAVE_LIBPCRE1) || defined(HAVE_LIBPCRE2)
    bool matched = false;

    for (const auto& i : filter_vec) {
        auto fields = get_tracker_element_multi_path(i->target, device);

        for (const auto& fi : fields) {
            std::string val;

            switch (fi->get_type()) {
                case tracker_type::tracker_string:
                case tracker_type::tracker_string_pointer:
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
                    if (!Globalreg::globalreg->entrytracker->search_xform(fi, val)) {
                        continue;
                    }
                    break;
            }

            int rc;

#if defined(HAVE_LIBPCRE1)
            int ovector[128];

            rc = pcre_exec(i->re, i->study, val.c_str(), val.length(), 0, 0, ovector, 128);

#else
            rc = pcre2_match(i->re, (PCRE2_SPTR8) val.c_str(), val.length(), 
                    0, 0, i->match_data, NULL);
#endif

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
        std::string val;

        if (field == nullptr)
            continue;

        switch (field->get_type()) {
            case tracker_type::tracker_string:
            case tracker_type::tracker_string_pointer:
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
                if (Globalreg::globalreg->entrytracker->search_xform(field, val)) {
                    matched = val.find(query) != std::string::npos;
                }
                break;
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
        std::string val;

        if (field == nullptr)
            continue;

        switch (field->get_type()) {
            case tracker_type::tracker_string:
            case tracker_type::tracker_string_pointer:
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
                if (Globalreg::globalreg->entrytracker->search_xform(field, val)) {
                    matched = icasesearch(val, query);
                }
                break;
        }

        if (matched)
            return true;
    }

    return false;
}


