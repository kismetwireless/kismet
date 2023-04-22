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

#ifndef __DEVICE_VIEW_WORKERS_H__
#define __DEVICE_VIEW_WORKERS_H__

#include "config.h"

#include <functional>

#include "kis_mutex.h"
#include "uuid.h"
#include "trackedelement.h"
#include "trackedcomponent.h"
#include "devicetracker_component.h"

#ifdef HAVE_LIBPCRE1
#include <pcre.h>
#endif

#ifdef HAVE_LIBPCRE2
#define PCRE2_CODE_UNIT_WIDTH 8
#include <pcre2.h>
#endif

class device_tracker_view_worker {
public:
    device_tracker_view_worker() {
        mutex.set_name("device_tracker_view_worker");
    }
    virtual ~device_tracker_view_worker() { }

    virtual bool match_device(std::shared_ptr<kis_tracked_device_base> device) = 0;
    virtual std::shared_ptr<tracker_element_vector> getMatchedDevices() {
        return matched;
    }

    virtual void finalize() { }

protected:
    friend class device_tracker_view;

    virtual void set_matched_devices(std::shared_ptr<tracker_element_vector> devices);

    kis_mutex mutex;
    std::shared_ptr<tracker_element_vector> matched;
};

class device_tracker_view_function_worker : public device_tracker_view_worker {
public:
    using filter_cb = std::function<bool (std::shared_ptr<kis_tracked_device_base>)>;

    device_tracker_view_function_worker(filter_cb cb);
    device_tracker_view_function_worker(const device_tracker_view_function_worker& w) {
        filter = w.filter;
        matched = w.matched;
    }

    virtual ~device_tracker_view_function_worker() { }

    virtual bool match_device(std::shared_ptr<kis_tracked_device_base> device) override;

protected:
    filter_cb filter;
};

// Field:Regex matcher
class device_tracker_view_regex_worker : public device_tracker_view_worker {
public:
    struct pcre_filter {
#if defined(HAVE_LIBPCRE1)
        pcre_filter(const std::string& target, const std::string& in_regex);
        ~pcre_filter();

        std::string target;
        pcre *re;
        pcre_extra *study;
#elif defined(HAVE_LIBPCRE2)
        pcre_filter(const std::string& target, const std::string& in_regex);
        ~pcre_filter();

        std::string target;

        pcre2_code *re;
        pcre2_match_data *match_data;
#endif
    };

    // Filter baed on a prepared vector
    device_tracker_view_regex_worker(const std::vector<std::shared_ptr<device_tracker_view_regex_worker::pcre_filter>>& filter_vec);

    // Build a PCRE from a standard regex description on a POST.
    // The JSON object is expected to be a vector of [field, regex] pairs.
    // std::runtime_error may be thrown if there is a parsing failure
    device_tracker_view_regex_worker(nlohmann::json& json_pcre_vec);

    // Build a PCRE from a vector of field:pcre pairs
    // std::runtime_error may be thrown if there is a parsing failure
    device_tracker_view_regex_worker(const std::vector<std::pair<std::string, std::string>>& str_pcre_vec);

    device_tracker_view_regex_worker(const device_tracker_view_regex_worker& w) {
        filter_vec = w.filter_vec;
        matched = w.matched;
    }

    virtual ~device_tracker_view_regex_worker() { }

    virtual bool match_device(std::shared_ptr<kis_tracked_device_base> device) override;

protected:
    std::vector<std::shared_ptr<device_tracker_view_regex_worker::pcre_filter>> filter_vec;

};

// Generic string search for any string-like value (and a few more complex values, like MAC addresses).
// Searches multiple fields for a given string
class device_tracker_view_stringmatch_worker : public device_tracker_view_worker {
public:
    // Match a given string against a list of resovled field paths
    device_tracker_view_stringmatch_worker(const std::string& in_query,
            const std::vector<std::vector<int>>& in_paths);
    device_tracker_view_stringmatch_worker(const device_tracker_view_stringmatch_worker& w) {
        query = w.query;
        fieldpaths = w.fieldpaths;
        mac_query_term = w.mac_query_term;
        mac_query_term_len = w.mac_query_term_len;
        matched = w.matched;
    }

    virtual ~device_tracker_view_stringmatch_worker() { }

    virtual bool match_device(std::shared_ptr<kis_tracked_device_base> device) override;

protected:
    std::string query;
    std::vector<std::vector<int>> fieldpaths;

    uint64_t mac_query_term;
    unsigned int mac_query_term_len;
};

// Generic string search for any string-like value (and a few more complex values, like MAC addresses).
// Searches multiple fields for a given string
class device_tracker_view_icasestringmatch_worker : public device_tracker_view_worker {
public:
    // Match a given string against a list of resovled field paths
    device_tracker_view_icasestringmatch_worker(const std::string& in_query,
            const std::vector<std::vector<int>>& in_paths);
    device_tracker_view_icasestringmatch_worker(const device_tracker_view_icasestringmatch_worker& w) {
        query = w.query;
        fieldpaths = w.fieldpaths;
        mac_query_term = w.mac_query_term;
        mac_query_term_len = w.mac_query_term_len;
        matched = w.matched;
    }

    virtual ~device_tracker_view_icasestringmatch_worker() { }

    virtual bool match_device(std::shared_ptr<kis_tracked_device_base> device) override;

protected:
    std::string query;
    std::vector<std::vector<int>> fieldpaths;

    uint64_t mac_query_term;
    unsigned int mac_query_term_len;
};

#endif
