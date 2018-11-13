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

#ifndef __DEVICE_TRACKER_WORKERS_H__
#define __DEVICE_TRACKER_WORKERS_H__

#include "config.h"

#ifdef HAVE_LIBPCRE
#include <pcre.h>
#endif

#include "trackedelement.h"
#include "trackedcomponent.h"

class kis_tracked_device_base;

// Filter-handler class.  Subclassed by a filter supplicant to be passed to the
// device filter functions.
class DevicetrackerFilterWorker {
    friend class Devicetracker;

public:
    DevicetrackerFilterWorker() {
        matched_devices = std::make_shared<TrackerElementVector>();
    };
    virtual ~DevicetrackerFilterWorker() { };

    // Perform a match on a device
    virtual bool MatchDevice(Devicetracker *devicetracker,
            std::shared_ptr<kis_tracked_device_base> base) = 0;

    // Finalize operations
    virtual void Finalize(Devicetracker *devicetracker __attribute__((unused))) { }

    virtual std::shared_ptr<TrackerElementVector> GetMatchedDevices() {
        return matched_devices;
    }

protected:
    virtual void MatchedDevice(SharedTrackerElement d) {
        local_locker lock(&worker_mutex);
        matched_devices->push_back(d);
    }

    kis_recursive_timed_mutex worker_mutex;
    std::shared_ptr<TrackerElementVector> matched_devices;
};

// C++ lambda matcher
class devicetracker_function_worker : public DevicetrackerFilterWorker {
public:
    devicetracker_function_worker(
            const std::function<bool (Devicetracker *, 
                std::shared_ptr<kis_tracked_device_base>)>& in_mcb,
            const std::function<void (Devicetracker *)>& in_fcb);
    virtual ~devicetracker_function_worker();

    virtual bool MatchDevice(Devicetracker *devicetracker,
            std::shared_ptr<kis_tracked_device_base> device);

    virtual void Finalize(Devicetracker *devicetracker);

protected:
    GlobalRegistry *globalreg;

    std::function<bool (Devicetracker *, 
            std::shared_ptr<kis_tracked_device_base>)> mcb;
    std::function<void (Devicetracker *)> fcb;
};

// Matching worker to match fields against a string search term

class devicetracker_stringmatch_worker : public DevicetrackerFilterWorker {
public:
    // Prepare the worker with the query and the vector of paths we
    // query against.  The vector of paths is equivalent to a field
    // summary/request field path, and can be extracted directly from 
    // that object.
    // in_devvec_object is the object the responses are placed into.
    // in_devvec_object must be a vector object.
    devicetracker_stringmatch_worker(const std::string& in_query,
            const std::vector<std::vector<int>>& in_paths);

    virtual ~devicetracker_stringmatch_worker();

    virtual bool MatchDevice(Devicetracker *devicetracker,
            std::shared_ptr<kis_tracked_device_base> device);

    virtual void Finalize(Devicetracker *devicetracker);

protected:
    std::string query;
    std::vector<std::vector<int> > fieldpaths;

    // Make a macaddr query out of it, too
    uint64_t mac_query_term;
    unsigned int mac_query_term_len;
};

#ifdef HAVE_LIBPCRE
// Retrieve a list of devices based on complex field paths and
// return them in a vector sharedtrackerelement
class devicetracker_pcre_worker : public DevicetrackerFilterWorker {
public:
    class pcre_filter {
    public:
        pcre_filter() {
            re = NULL;
            study = NULL;
        }

        ~pcre_filter() {
            if (re != NULL)
                pcre_free(re);
            if (study != NULL)
                pcre_free(study);
        }

        std::string target;
        pcre *re;
        pcre_extra *study;
    };

    // Prepare the worker with a set of filters and the object we fill our
    // results into.  in_devvec_object must be a vector object.
    devicetracker_pcre_worker(const std::vector<std::shared_ptr<devicetracker_pcre_worker::pcre_filter>>& in_filter_vec);

    // Shortcut function for building a PCRE from an incoming standard filter
    // description on a POST event:
    // Prepare the worker with a set of filters contained in a raw Structured 
    // object, which is expected to be a vector of [field, regex] pairs.
    // Results are filled into in_devvec_object which is expected to be a vector object
    // This MAY THROW EXCEPTIONS from structured parsing or the PCRE parsing!
    devicetracker_pcre_worker(SharedStructured raw_pcre_vec);

    // Shortcut function for building a PCRE from an incoming vector of filters
    // as a string.
    // THIS MAY THROW EXCEPTIONS from PCRE parsing failures
    devicetracker_pcre_worker(const std::vector<std::pair<std::string, std::string>>& str_pcre_vec);

    // Shortcut function for building a PCRE worker from an incoming list of
    // filters, targeting a single field (such as a SSID match):
    // Prepare the worker with a set of filters referencing a single field
    // target.  The filters should be contained in a raw Structured object, which
    // is expected to be a vector of filter strings.  Results are filled into
    // in_devvec_object which is expected to be a vector object.
    // This MAY THROW EXCEPTIONS from structured parsing or the PCRE parsing!
    devicetracker_pcre_worker(const std::string& in_target, SharedStructured raw_pcre_vec);

    virtual ~devicetracker_pcre_worker();

    bool get_error() { return error; }

    virtual bool MatchDevice(Devicetracker *devicetracker,
            std::shared_ptr<kis_tracked_device_base> device);

    virtual void Finalize(Devicetracker *devicetracker);

protected:
    int pcre_match_id;

    std::vector<std::shared_ptr<devicetracker_pcre_worker::pcre_filter> > filter_vec;
    bool error;
};
#else
class devicetracker_pcre_worker : public DevicetrackerFilterWorker {
public:
    class pcre_filter {
    public:
        pcre_filter() { }
    };

    // Prepare the worker with a set of filters and the object we fill our
    // results into.  in_devvec_object must be a vector object.
    devicetracker_pcre_worker(const std::vector<std::shared_ptr<devicetracker_pcre_worker::pcre_filter>>& in_filter_vec) {
        throw(std::runtime_error("Kismet not compiled with PCRE support"));
    }

    devicetracker_pcre_worker(SharedStructured raw_pcre_vec) {
        throw(std::runtime_error("Kismet not compiled with PCRE support"));
    }

    devicetracker_pcre_worker(const std::string& in_target, SharedStructured raw_pcre_vec) {
        throw(std::runtime_error("Kismet not compiled with PCRE support"));
    }

    virtual ~devicetracker_pcre_worker() { };

    bool get_error() { return true; }

    virtual bool MatchDevice(Devicetracker *devicetracker,
            std::shared_ptr<kis_tracked_device_base> device) { return false; };

    virtual void Finalize(Devicetracker *devicetracker) { };
};


#endif

#endif

