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
#include "gps_manager.h"
#include "alertracker.h"
#include "manuf.h"
#include "packetsourcetracker.h"
#include "packetsource.h"
#include "dumpfile_devicetracker.h"
#include "entrytracker.h"
#include "devicetracker_component.h"
#include "msgpack_adapter.h"
#include "xmlserialize_adapter.h"
#include "json_adapter.h"
#include "structured.h"
#include "kismet_json.h"
#include "base64.h"


devicetracker_stringmatch_worker::devicetracker_stringmatch_worker(GlobalRegistry *in_globalreg,
        string in_query,
        vector<vector<int> > in_paths,
        SharedTrackerElement in_devvec_object) {

    globalreg = in_globalreg;

    entrytracker =
        static_pointer_cast<EntryTracker>(globalreg->FetchGlobal("ENTRY_TRACKER"));

    query = in_query;
    fieldpaths = in_paths;

    // Preemptively try to compute a mac address partial search term
    mac_addr::PrepareSearchTerm(query, mac_query_term, mac_query_term_len);

    return_dev_vec = in_devvec_object;

    pthread_mutex_init(&worker_mutex, NULL);
}

devicetracker_stringmatch_worker::~devicetracker_stringmatch_worker() {
    pthread_mutex_destroy(&worker_mutex);
}

void devicetracker_stringmatch_worker::MatchDevice(Devicetracker *devicetracker __attribute__((unused)),
        shared_ptr<kis_tracked_device_base> device) {
    vector<vector<int> >::iterator i;

    bool matched = false;

    // Go through the fields
    for (i = fieldpaths.begin(); i != fieldpaths.end(); ++i) {
        // We should never have to search nested vectors so we don't use
        // multipath
        SharedTrackerElement field = GetTrackerElementPath(*i, device);

        if (field->get_type() == TrackerString) {
            // We can only do a straight string match against string fields
            matched = GetTrackerValue<string>(field).find(query) != std::string::npos;
        } else if (field->get_type() == TrackerMac && mac_query_term_len != 0) {
            // If we were able to interpret the query term as a partial
            // mac address, do a mac compare
            matched = 
                GetTrackerValue<mac_addr>(field).PartialSearch(mac_query_term,
                        mac_query_term_len);
        }

        if (matched) {
            local_locker lock(&worker_mutex);
            return_dev_vec->add_vector(device);
            break;
        }
    }

}

void devicetracker_stringmatch_worker::Finalize(Devicetracker *devicetracker __attribute__((unused))) {

}

#ifdef HAVE_LIBPCRE

devicetracker_pcre_worker::devicetracker_pcre_worker(GlobalRegistry *in_globalreg,
        vector<shared_ptr<devicetracker_pcre_worker::pcre_filter> > in_filter_vec,
        SharedTrackerElement in_devvec_object) {

    globalreg = in_globalreg;

    entrytracker =
        static_pointer_cast<EntryTracker>(globalreg->FetchGlobal("ENTRY_TRACKER"));

    filter_vec = in_filter_vec;
    error = false;

    return_dev_vec = in_devvec_object;

    pthread_mutex_init(&worker_mutex, NULL);
}

devicetracker_pcre_worker::devicetracker_pcre_worker(GlobalRegistry *in_globalreg,
        SharedStructured raw_pcre_vec,
        SharedTrackerElement in_devvec_object) {

    globalreg = in_globalreg;

    entrytracker =
        static_pointer_cast<EntryTracker>(globalreg->FetchGlobal("ENTRY_TRACKER"));

    error = false;

    return_dev_vec = in_devvec_object;

    // Process a structuredarray of sub-arrays of [target, filter]; throw any 
    // exceptions we encounter

    StructuredData::structured_vec rawvec = raw_pcre_vec->getStructuredArray();
    for (StructuredData::structured_vec::iterator i = rawvec.begin(); 
            i != rawvec.end(); ++i) {
        StructuredData::structured_vec rpair = (*i)->getStructuredArray();

        if (rpair.size() != 2)
            throw StructuredDataException("expected [field, regex] pair");

        string field = rpair[0]->getString();
        string regex = rpair[1]->getString();

        shared_ptr<pcre_filter> filter(new pcre_filter());
        filter->target = field;

        const char *compile_error, *study_error;
        int erroroffset;
        ostringstream errordesc;

        filter->re =
            pcre_compile(regex.c_str(), 0, &compile_error, &erroroffset, NULL);

        if (filter->re == NULL) {
            errordesc << "Could not parse PCRE expression: " << compile_error <<
                " at character " << erroroffset;
            throw std::runtime_error(errordesc.str());
        }

        filter->study = pcre_study(filter->re, 0, &study_error);
        if (filter->study == NULL) {
            errordesc << "Could not parse PCRE expression, study/optimization "
                "failure: " << study_error;
            throw std::runtime_error(errordesc.str());
        }

        filter_vec.push_back(filter);
    }

    pthread_mutex_init(&worker_mutex, NULL);
}

devicetracker_pcre_worker::devicetracker_pcre_worker(GlobalRegistry *in_globalreg,
        string in_target,
        SharedStructured raw_pcre_vec,
        SharedTrackerElement in_devvec_object) {

    globalreg = in_globalreg;

    entrytracker =
        static_pointer_cast<EntryTracker>(globalreg->FetchGlobal("ENTRY_TRACKER"));

    error = false;

    return_dev_vec = in_devvec_object;

    // Process a structuredarray of sub-arrays of [target, filter]; throw any 
    // exceptions we encounter

    StructuredData::structured_vec rawvec = raw_pcre_vec->getStructuredArray();
    for (StructuredData::structured_vec::iterator i = rawvec.begin(); 
            i != rawvec.end(); ++i) {

        string regex = (*i)->getString();

        shared_ptr<pcre_filter> filter(new pcre_filter());
        filter->target = in_target; 

        const char *compile_error, *study_error;
        int erroroffset;
        ostringstream errordesc;

        filter->re =
            pcre_compile(regex.c_str(), 0, &compile_error, &erroroffset, NULL);

        if (filter->re == NULL) {
            errordesc << "Could not parse PCRE expression: " << compile_error <<
                " at character " << erroroffset;
            throw std::runtime_error(errordesc.str());
        }

        filter->study = pcre_study(filter->re, 0, &study_error);
        if (filter->study == NULL) {
            errordesc << "Could not parse PCRE expression, study/optimization "
                "failure: " << study_error;
            throw std::runtime_error(errordesc.str());
        }

        filter_vec.push_back(filter);
    }

    pthread_mutex_init(&worker_mutex, NULL);
}

devicetracker_pcre_worker::~devicetracker_pcre_worker() {
    pthread_mutex_destroy(&worker_mutex);
}

void devicetracker_pcre_worker::MatchDevice(Devicetracker *devicetracker __attribute__((unused)),
        shared_ptr<kis_tracked_device_base> device) {
    vector<shared_ptr<devicetracker_pcre_worker::pcre_filter> >::iterator i;

    bool matched = false;

    // Go through all the filters until we find one that hits
    for (i = filter_vec.begin(); i != filter_vec.end(); ++i) {

        // Get complex fields - this lets us search nested vectors
        // or strings or whatnot
        vector<SharedTrackerElement> fields = 
            GetTrackerElementMultiPath((*i)->target, device, entrytracker);

        for (vector<SharedTrackerElement>::iterator fi = fields.begin();
                fi != fields.end(); ++fi) {
            // We can only regex strings
            if ((*fi)->get_type() != TrackerString)
                continue;

            int rc;
            int ovector[128];

            rc = pcre_exec((*i)->re, (*i)->study,
                    GetTrackerValue<string>(*fi).c_str(),
                    GetTrackerValue<string>(*fi).length(),
                    0, 0, ovector, 128);

            // Stop matching as soon as we find a hit
            if (rc >= 0) {
                matched = true;
                break;
            }

        }

        if (matched) {
            local_locker lock(&worker_mutex);
            return_dev_vec->add_vector(device);
        }
    }

}

void devicetracker_pcre_worker::Finalize(Devicetracker *devicetracker __attribute__((unused))) {

}

#endif

