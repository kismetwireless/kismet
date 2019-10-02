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
#include <iterator>

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
#include "devicetracker_workers.h"
#include "json_adapter.h"
#include "structured.h"
#include "kismet_json.h"
#include "base64.h"

devicetracker_function_worker::devicetracker_function_worker(
        const std::function<bool (device_tracker *, std::shared_ptr<kis_tracked_device_base>)>& in_mcb,
        const std::function<void (device_tracker *)>& in_fcb) {

    mcb = in_mcb;
    fcb = in_fcb;
}

devicetracker_function_worker::~devicetracker_function_worker() {
}

bool devicetracker_function_worker::match_device(device_tracker *devicetracker,
        std::shared_ptr<kis_tracked_device_base> device) {

    if (mcb == NULL)
        return false;

    return mcb(devicetracker, device);
}

void devicetracker_function_worker::finalize(device_tracker *devicetracker) {
    if (fcb != NULL) {
        fcb(devicetracker);
    }
}


devicetracker_stringmatch_worker::devicetracker_stringmatch_worker(const std::string& in_query,
        const std::vector<std::vector<int>> & in_paths) {

    query = in_query;
    fieldpaths = in_paths;

    // Preemptively try to compute a mac address partial search term
    mac_addr::prepare_search_term(query, mac_query_term, mac_query_term_len);
}

devicetracker_stringmatch_worker::~devicetracker_stringmatch_worker() {
}

bool devicetracker_stringmatch_worker::match_device(device_tracker *devicetracker __attribute__((unused)),
        std::shared_ptr<kis_tracked_device_base> device) {
    bool matched = false;

    // Go through the fields
    for (auto i = fieldpaths.begin(); i != fieldpaths.end(); ++i) {
        // We should never have to search nested vectors so we don't use
        // multipath
        shared_tracker_element field = get_tracker_element_path(*i, device);

        if (field == NULL)
            continue;

        if (field->get_type() == tracker_type::tracker_string) {
            // We can only do a straight string match against string fields
            matched = get_tracker_value<std::string>(field).find(query) != std::string::npos;
        } else if (field->get_type() == tracker_type::tracker_byte_array) {
            // Try a raw string match against a binary field
            matched = 
                std::static_pointer_cast<tracker_element_byte_array>(field)->get().find(query) != std::string::npos;
        } else if (field->get_type() == tracker_type::tracker_mac_addr && mac_query_term_len != 0) {
            // If we were able to interpret the query term as a partial
            // mac address, do a mac compare
            matched =
                std::static_pointer_cast<tracker_element_mac_addr>(field)->get().partial_search(mac_query_term, mac_query_term_len);
        } else if (field->get_type() == tracker_type::tracker_uuid) {
            matched =
                tracker_element::safe_cast_as<tracker_element_uuid>(field)->get().as_string().find(query) != std::string::npos;
        }

        if (matched)
            return true;
    }

    return false;
}

void devicetracker_stringmatch_worker::finalize(device_tracker *devicetracker __attribute__((unused))) {

}

#ifdef HAVE_LIBPCRE

devicetracker_pcre_worker::devicetracker_pcre_worker(
        const std::vector<std::shared_ptr<devicetracker_pcre_worker::pcre_filter>>& in_filter_vec) {

    filter_vec = in_filter_vec;
    error = false;
}

devicetracker_pcre_worker::devicetracker_pcre_worker(shared_structured raw_pcre_vec) {
    error = false;

    // Process a structuredarray of sub-arrays of [target, filter]; throw any 
    // exceptions we encounter

    structured_data::structured_vec rawvec = raw_pcre_vec->as_vector();
    for (auto i : rawvec) {
        structured_data::structured_vec rpair = i->as_vector();

        if (rpair.size() != 2)
            throw structured_data_exception("expected [field, regex] pair");

        std::string field = rpair[0]->as_string();
        std::string regex = rpair[1]->as_string();

        std::shared_ptr<pcre_filter> filter(new pcre_filter());
        filter->target = field;

        const char *compile_error, *study_error;
        int erroroffset;

        filter->re =
            pcre_compile(regex.c_str(), 0, &compile_error, &erroroffset, NULL);

        if (filter->re == NULL) {
            throw std::runtime_error(fmt::format("Could not parse pcre expression: {} at {}",
                        compile_error, erroroffset));
        }

        filter->study = pcre_study(filter->re, 0, &study_error);
        if (study_error != NULL) {
            throw std::runtime_error(fmt::format("Could not parse PCRE expression, optimization failure {}",
                        study_error));
        }

        filter_vec.push_back(filter);
    }
}

devicetracker_pcre_worker::devicetracker_pcre_worker(const std::vector<std::pair<std::string, std::string>>& str_pcre_vec) {
    error = false;

    // Process a structuredarray of sub-arrays of [target, filter]; throw any 
    // exceptions we encounter

    for (auto i : str_pcre_vec) {
        std::shared_ptr<pcre_filter> filter(new pcre_filter());
        filter->target = i.first;

        const char *compile_error, *study_error;
        int erroroffset;

        filter->re =
            pcre_compile(i.second.c_str(), 0, &compile_error, &erroroffset, NULL);

        if (filter->re == NULL) {
            throw std::runtime_error(fmt::format("Could not parse pcre expression: {} at {}",
                        compile_error, erroroffset));
        }

        filter->study = pcre_study(filter->re, 0, &study_error);
        if (study_error != NULL) {
            throw std::runtime_error(fmt::format("Could not parse PCRE expression, optimization failure {}",
                        study_error));
        }

        filter_vec.push_back(filter);
    }
}

devicetracker_pcre_worker::devicetracker_pcre_worker(const std::string& in_target,
        shared_structured raw_pcre_vec) {

    error = false;

    // Process a structuredarray of sub-arrays of [target, filter]; throw any 
    // exceptions we encounter

    structured_data::structured_vec rawvec = raw_pcre_vec->as_vector();
    for (auto i : rawvec) {
        std::string regex = i->as_string();

        std::shared_ptr<pcre_filter> filter(new pcre_filter());
        filter->target = in_target; 

        const char *compile_error, *study_error;
        int erroroffset;
        std::ostringstream errordesc;

        filter->re =
            pcre_compile(regex.c_str(), 0, &compile_error, &erroroffset, NULL);

        if (filter->re == NULL) {
            errordesc << "Could not parse PCRE expression: " << compile_error <<
                " at character " << erroroffset;
            throw std::runtime_error(errordesc.str());
        }

        filter->study = pcre_study(filter->re, 0, &study_error);
        if (study_error != NULL) {
            errordesc << "Could not parse PCRE expression, study/optimization "
                "failure: " << study_error;
            throw std::runtime_error(errordesc.str());
        }

        filter_vec.push_back(filter);
    }
}

devicetracker_pcre_worker::~devicetracker_pcre_worker() {
}

bool devicetracker_pcre_worker::match_device(device_tracker *devicetracker __attribute__((unused)),
        std::shared_ptr<kis_tracked_device_base> device) {
    bool matched = false;

    // Go through all the filters until we find one that hits
    for (auto i : filter_vec) {
        // Get complex fields - this lets us search nested vectors
        // or strings or whatnot
        std::vector<shared_tracker_element> fields = 
            get_tracker_element_multi_path(i->target, device);

        for (auto fi : fields) {
            std::string val;

            // Process a few different types
            if (fi->get_type() == tracker_type::tracker_string)
                val = get_tracker_value<std::string>(fi);
            else if (fi->get_type() == tracker_type::tracker_mac_addr)
                val = get_tracker_value<mac_addr>(fi).mac_to_string();
            else if (fi->get_type() == tracker_type::tracker_uuid)
                val = get_tracker_value<uuid>(fi).uuid_to_string();
            else if (fi->get_type() == tracker_type::tracker_byte_array) 
                val = std::static_pointer_cast<tracker_element_byte_array>(fi)->get();
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

    return false;
}

void devicetracker_pcre_worker::finalize(device_tracker *devicetracker __attribute__((unused))) {

}

#endif

