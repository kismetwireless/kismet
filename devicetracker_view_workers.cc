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

void DevicetrackerViewWorker::setMatchedDevices(std::shared_ptr<TrackerElementVector> devs) {
    local_locker l(&mutex);
    matched = devs;
}

DevicetrackerViewFunctionWorker::DevicetrackerViewFunctionWorker(filter_cb cb) :
    filter {cb} { }

bool DevicetrackerViewFunctionWorker::matchDevice(std::shared_ptr<kis_tracked_device_base> device) {
    return filter(device);
}

#ifdef HAVE_LIBPCRE
DevicetrackerViewRegexWorker::pcre_filter::pcre_filter(const std::string& in_target,
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

DevicetrackerViewRegexWorker::pcre_filter::~pcre_filter() {
    if (re != NULL)
        pcre_free(re);
    if (study != NULL)
        pcre_free(study);
}

#endif

DevicetrackerViewRegexWorker::DevicetrackerViewRegexWorker(const std::vector<std::shared_ptr<DevicetrackerViewRegexWorker::pcre_filter>>& in_filter_vec) {
#ifdef HAVE_LIBPCRE
    filter_vec = in_filter_vec;
#else
    throw std::runtime_error("Kismet was not compiled with PCRE support");
#endif
}

DevicetrackerViewRegexWorker::DevicetrackerViewRegexWorker(SharedStructured shared_pcre_vec) {
#ifdef HAVE_LIBPCRE
    auto vec = shared_pcre_vec->getStructuredArray();

    for (auto i : vec) {
        auto rpair = i->getStructuredArray();

        if (rpair.size() != 2)
            throw std::runtime_error("expected [field, regex] pair from incoming filter");

        auto field = rpair[0]->getString();
        auto regex = rpair[1]->getString();

        auto worker_filter = std::make_shared<DevicetrackerViewRegexWorker::pcre_filter>(field, regex);

        filter_vec.push_back(worker_filter);
    }
#else
    throw std::runtime_error("Kismet was not compiled with PCRE support");
#endif
}

DevicetrackerViewRegexWorker::DevicetrackerViewRegexWorker(const std::vector<std::pair<std::string, std::string>>& str_pcre_vec) {
#ifdef HAVE_LIBPCRE
    for (auto i : str_pcre_vec) {
        auto field = std::get<0>(i);
        auto regex = std::get<1>(i);

        auto worker_filter = std::make_shared<DevicetrackerViewRegexWorker::pcre_filter>(field, regex);

        filter_vec.push_back(worker_filter);
    }
#else
    throw std::runtime_error("Kismet was ot compiled with PCRE support");
#endif
}

bool DevicetrackerViewRegexWorker::matchDevice(std::shared_ptr<kis_tracked_device_base> device) {
#ifdef HAVE_LIBPCRE
    bool matched = false;

    for (auto i : filter_vec) {
        auto fields = GetTrackerElementMultiPath(i->target, device);

        for (auto fi : fields) {
            std::string val;

            if (fi->get_type() == TrackerType::TrackerString)
                val = GetTrackerValue<std::string>(fi);
            else if (fi->get_type() == TrackerType::TrackerMac)
                val = GetTrackerValue<mac_addr>(fi).Mac2String();
            else if (fi->get_type() == TrackerType::TrackerUuid)
                val = GetTrackerValue<uuid>(fi).UUID2String();
            else if (fi->get_type() == TrackerType::TrackerByteArray) 
                val = std::static_pointer_cast<TrackerElementByteArray>(fi)->get();
            else
                continue;

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

DevicetrackerViewStringmatchWorker::DevicetrackerViewStringmatchWorker(const std::string& in_query,
        const std::vector<std::vector<int>>& in_paths) :
    query { in_query },
    fieldpaths { in_paths } {

    // Generate cached match for mac addresses
    mac_addr::PrepareSearchTerm(query, mac_query_term, mac_query_term_len);
}

bool DevicetrackerViewStringmatchWorker::matchDevice(std::shared_ptr<kis_tracked_device_base> device) {
    bool matched = false;

    for (auto i : fieldpaths) {
        auto field = GetTrackerElementPath(i, device);

        if (field == nullptr)
            continue;

        if (field->get_type() == TrackerType::TrackerString) {
            // We can only do a straight string match against string fields
            matched = GetTrackerValue<std::string>(field).find(query) != std::string::npos;
        } else if (field->get_type() == TrackerType::TrackerByteArray) {
            // Try a raw string match against a binary field
            matched = 
                std::static_pointer_cast<TrackerElementByteArray>(field)->get().find(query) != 
                std::string::npos;
        } else if (field->get_type() == TrackerType::TrackerMac && mac_query_term_len != 0) {
            // If we were able to interpret the query term as a partial
            // mac address, do a mac compare
            matched =
                std::static_pointer_cast<TrackerElementMacAddr>(field)->get().PartialSearch(mac_query_term, mac_query_term_len);
        }

        if (matched)
            return true;
    }

    return false;
}

DevicetrackerViewICaseStringmatchWorker::DevicetrackerViewICaseStringmatchWorker(const std::string& in_query,
        const std::vector<std::vector<int>>& in_paths) :
    query { in_query },
    fieldpaths { in_paths } {

    // Generate cached match for mac addresses
    mac_addr::PrepareSearchTerm(query, mac_query_term, mac_query_term_len);
}

bool DevicetrackerViewICaseStringmatchWorker::matchDevice(std::shared_ptr<kis_tracked_device_base> device) {
    bool matched = false;

    auto icasesearch = [](const std::string& haystack, const std::string& needle) -> bool {
        auto pos = std::search(haystack.begin(), haystack.end(), needle.begin(), needle.end(),
                [](char ch1, char ch2) -> bool { 
                    return std::toupper(ch1) == std::toupper(ch2);
                });
        return (pos != haystack.end());
    };

    for (auto i : fieldpaths) {
        auto field = GetTrackerElementPath(i, device);

        if (field == nullptr)
            continue;

        if (field->get_type() == TrackerType::TrackerString) {
            // We can only do a straight string match against string fields
            matched = icasesearch(GetTrackerValue<std::string>(field), query);
        } else if (field->get_type() == TrackerType::TrackerByteArray) {
            // Try a raw string match against a binary field
            matched = icasesearch(std::static_pointer_cast<TrackerElementByteArray>(field)->get(), query);
        } else if (field->get_type() == TrackerType::TrackerMac && mac_query_term_len != 0) {
            // If we were able to interpret the query term as a partial
            // mac address, do a mac compare
            matched =
                std::static_pointer_cast<TrackerElementMacAddr>(field)->get().PartialSearch(mac_query_term, mac_query_term_len);
        }

        if (matched)
            return true;
    }

    return false;
}


