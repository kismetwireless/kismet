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

#ifdef HAVE_LIBPCRE
#include <pcre.h>
#endif

class DevicetrackerViewWorker {
public:
    DevicetrackerViewWorker() { }
    virtual ~DevicetrackerViewWorker() { }

    virtual bool matchDevice(std::shared_ptr<kis_tracked_device_base> device) = 0;
    virtual std::shared_ptr<TrackerElementVector> getMatchedDevices() {
        return matched;
    }

protected:
    friend class DevicetrackerView;

    virtual void setMatchedDevices(std::shared_ptr<TrackerElementVector> devices);

    kis_recursive_timed_mutex mutex;
    std::shared_ptr<TrackerElementVector> matched;
};

class DevicetrackerViewFunctionWorker : public DevicetrackerViewWorker {
public:
    using filter_cb = std::function<bool (std::shared_ptr<kis_tracked_device_base>)>;

    DevicetrackerViewFunctionWorker(filter_cb cb);
    DevicetrackerViewFunctionWorker(const DevicetrackerViewFunctionWorker& w) {
        filter = w.filter;
        matched = w.matched;
    }

    virtual ~DevicetrackerViewFunctionWorker() { }

    virtual bool matchDevice(std::shared_ptr<kis_tracked_device_base> device) override;

protected:
    filter_cb filter;
};

// Field:Regex matcher
class DevicetrackerViewRegexWorker : public DevicetrackerViewWorker {
public:
    struct pcre_filter {
#ifdef HAVE_LIBPCRE
        pcre_filter(const std::string& target, const std::string& in_regex);
        ~pcre_filter();

        std::string target;
        pcre *re;
        pcre_extra *study;
#endif
    };

    // Filter baed on a prepared vector
    DevicetrackerViewRegexWorker(const std::vector<std::shared_ptr<DevicetrackerViewRegexWorker::pcre_filter>>& filter_vec);

    // Build a PCRE from a standard regex description on a POST.
    // The SharedStructured objeect is expected to be a vector of [field, regex] pairs.
    // std::runtime_error may be thrown if there is a parsing failure
    DevicetrackerViewRegexWorker(SharedStructured shared_pcre_vec);

    // Build a PCRE from a vector of field:pcre pairs
    // std::runtime_error may be thrown if there is a parsing failure
    DevicetrackerViewRegexWorker(const std::vector<std::pair<std::string, std::string>>& str_pcre_vec);

    DevicetrackerViewRegexWorker(const DevicetrackerViewRegexWorker& w) {
        filter_vec = w.filter_vec;
        matched = w.matched;
    }

    virtual ~DevicetrackerViewRegexWorker() { }

    virtual bool matchDevice(std::shared_ptr<kis_tracked_device_base> device) override;

protected:
    std::vector<std::shared_ptr<DevicetrackerViewRegexWorker::pcre_filter>> filter_vec;

};

// Generic string search for any string-like value (and a few more complex values, like MAC addresses).
// Searches multiple fields for a given string
class DevicetrackerViewStringmatchWorker : public DevicetrackerViewWorker {
public:
    // Match a given string against a list of resovled field paths
    DevicetrackerViewStringmatchWorker(const std::string& in_query,
            const std::vector<std::vector<int>>& in_paths);
    DevicetrackerViewStringmatchWorker(const DevicetrackerViewStringmatchWorker& w) {
        query = w.query;
        fieldpaths = w.fieldpaths;
        mac_query_term = w.mac_query_term;
        mac_query_term_len = w.mac_query_term_len;
        matched = w.matched;
    }

    virtual ~DevicetrackerViewStringmatchWorker() { }

    virtual bool matchDevice(std::shared_ptr<kis_tracked_device_base> device) override;

protected:
    std::string query;
    std::vector<std::vector<int>> fieldpaths;

    uint64_t mac_query_term;
    unsigned int mac_query_term_len;
};

// Generic string search for any string-like value (and a few more complex values, like MAC addresses).
// Searches multiple fields for a given string
class DevicetrackerViewICaseStringmatchWorker : public DevicetrackerViewWorker {
public:
    // Match a given string against a list of resovled field paths
    DevicetrackerViewICaseStringmatchWorker(const std::string& in_query,
            const std::vector<std::vector<int>>& in_paths);
    DevicetrackerViewICaseStringmatchWorker(const DevicetrackerViewICaseStringmatchWorker& w) {
        query = w.query;
        fieldpaths = w.fieldpaths;
        mac_query_term = w.mac_query_term;
        mac_query_term_len = w.mac_query_term_len;
        matched = w.matched;
    }

    virtual ~DevicetrackerViewICaseStringmatchWorker() { }

    virtual bool matchDevice(std::shared_ptr<kis_tracked_device_base> device) override;

protected:
    std::string query;
    std::vector<std::vector<int>> fieldpaths;

    uint64_t mac_query_term;
    unsigned int mac_query_term_len;
};

#endif
