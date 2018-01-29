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
#include "gpstracker.h"
#include "alertracker.h"
#include "manuf.h"
#include "entrytracker.h"
#include "devicetracker_component.h"
#include "msgpack_adapter.h"
#include "json_adapter.h"
#include "structured.h"
#include "kismet_json.h"
#include "base64.h"

// HTTP interfaces
bool Devicetracker::Httpd_VerifyPath(const char *path, const char *method) {
    if (strcmp(method, "GET") == 0) {
        // Simple fixed URLS

        string stripped = Httpd_StripSuffix(path);
        bool can_serialize = Httpd_CanSerialize(path);

        // Explicit compare for .ekjson because it doesn't serialize the 
        // same way
        if (strcmp(path, "/devices/all_devices.ekjson") == 0)
            return true;

        if (stripped == "/phy/all_phys" && can_serialize)
            return true;

        if (stripped == "/phy/all_phys_dt" && can_serialize)
            return true;

        // Split URL and process
        vector<string> tokenurl = StrTokenize(path, "/");
        if (tokenurl.size() < 2)
            return false;

        if (tokenurl[1] == "devices") {
            if (tokenurl.size() < 3)
                return false;

            // Do a by-key lookup and return the device or the device path
            if (tokenurl[2] == "by-key") {
                if (tokenurl.size() < 5) {
                    return false;
                }

                TrackedDeviceKey key(tokenurl[3]);

                if (key.get_error())
                    return false;

                if (!Httpd_CanSerialize(tokenurl[4]))
                    return false;

                auto tmi = FetchDevice(key);

                if (tmi == NULL)
                    return false;

                string target = Httpd_StripSuffix(tokenurl[4]);

                if (target == "device") {
                    // Try to find the exact field
                    if (tokenurl.size() > 5) {
                        vector<string>::const_iterator first = tokenurl.begin() + 5;
                        vector<string>::const_iterator last = tokenurl.end();
                        vector<string> fpath(first, last);

                        if (tmi->get_child_path(fpath) == NULL) {
                            return false;
                        }
                    }

                    return true;
                }

                return false;
            } else if (tokenurl[2] == "by-mac") {
                if (tokenurl.size() < 5)
                    return false;

                if (!Httpd_CanSerialize(tokenurl[4]))
                    return false;

                mac_addr mac = mac_addr(tokenurl[3]);

                if (mac.error) {
                    return false;
                }

                { 
                    local_locker devlock(&devicelist_mutex);

                    if (tracked_mac_multimap.count(mac) > 0)
                        return true;
                }

                return false;
            } else if (tokenurl[2] == "last-time") {
                if (tokenurl.size() < 5) {
                    return false;
                }

                long lastts;
                if (sscanf(tokenurl[3].c_str(), "%ld", &lastts) != 1) {
                    return false;
                }

                // Explicit catch of ekjson
                if (tokenurl[4] == "devices.ekjson")
                    return true;

                return Httpd_CanSerialize(tokenurl[4]);
            }
        }
    } else if (strcmp(method, "POST") == 0) {
        // Split URL and process
        vector<string> tokenurl = StrTokenize(path, "/");
        if (tokenurl.size() < 2)
            return false;

        if (tokenurl[1] == "devices") {
            if (tokenurl.size() < 4) {
                return false;

            } else if (tokenurl[2] == "summary") {
                return Httpd_CanSerialize(tokenurl[3]);
            } else if (tokenurl[2] == "last-time") {
                if (tokenurl.size() < 5) {
                    return false;
                }

                long lastts;
                if (sscanf(tokenurl[3].c_str(), "%ld", &lastts) != 1) {
                    fprintf(stderr, "debug - unable to parse ts\n");
                    return false;
                }

                return Httpd_CanSerialize(tokenurl[4]);
            } else if (tokenurl[2] == "by-key") {
                if (tokenurl.size() < 5) {
                    return false;
                }

                TrackedDeviceKey key(tokenurl[3]);

                if (key.get_error())
                    return false;

                if (!Httpd_CanSerialize(tokenurl[4]))
                    return false;

                if (FetchDevice(key) == NULL)
                    return false;

                string target = Httpd_StripSuffix(tokenurl[4]);

                if (target == "device") {
                    return true;
                }

                if (target == "set_name") {
                    return true;
                }

                if (target == "set_tag") {
                    return true;
                }
            } else if (tokenurl[2] == "by-mac") {
                if (tokenurl.size() < 5)
                    return false;

                if (!Httpd_CanSerialize(tokenurl[4]))
                    return false;

                mac_addr mac = mac_addr(tokenurl[3]);

                if (mac.error) {
                    return false;
                }

                {
                    local_locker listlocker(&devicelist_mutex);
                    if (tracked_mac_multimap.count(mac) > 0)
                        return true;
                }

                return false;
            } else if (tokenurl[2] == "by-phy") {
                if (tokenurl.size() < 5)
                    return false;

                if (!Httpd_CanSerialize(tokenurl[4]))
                    return false;

                auto p = FetchPhyHandlerByName(tokenurl[3]);
                if (p != NULL)
                    return true;

                return false;
            }
        }
    }

    return false;
}

void Devicetracker::httpd_all_phys(string path, std::ostream &stream,
        string in_wrapper_key) {

    SharedTrackerElement phyvec =
        globalreg->entrytracker->GetTrackedInstance(phy_base_id);

    SharedTrackerElement wrapper = NULL;

    if (in_wrapper_key != "") {
        wrapper.reset(new TrackerElement(TrackerMap));
        wrapper->add_map(phyvec);
        phyvec->set_local_name(in_wrapper_key);
    } else {
        wrapper = phyvec;
    }

    shared_ptr<kis_tracked_phy> anyphy(new kis_tracked_phy(globalreg, phy_base_id));
    anyphy->set_from_phy(this, KIS_PHY_ANY);
    phyvec->add_vector(anyphy);

    map<int, Kis_Phy_Handler *>::iterator mi;
    for (mi = phy_handler_map.begin(); mi != phy_handler_map.end(); ++mi) {
        shared_ptr<kis_tracked_phy> p(new kis_tracked_phy(globalreg, phy_base_id));
        p->set_from_phy(this, mi->first);
        phyvec->add_vector(p);
    }

    entrytracker->Serialize(httpd->GetSuffix(path), stream, wrapper, NULL);
}

int Devicetracker::Httpd_CreateStreamResponse(
        Kis_Net_Httpd *httpd __attribute__((unused)),
        Kis_Net_Httpd_Connection *connection,
        const char *path, const char *method, const char *upload_data,
        size_t *upload_data_size) {

    if (strcmp(method, "GET") != 0) {
        return MHD_YES;
    }

    // Allocate our buffer aux
    Kis_Net_Httpd_Buffer_Stream_Aux *saux = 
        (Kis_Net_Httpd_Buffer_Stream_Aux *) connection->custom_extension;

    BufferHandlerOStringStreambuf *streambuf = 
        new BufferHandlerOStringStreambuf(saux->get_rbhandler());
    std::ostream stream(streambuf);

    // Set our cleanup function
    saux->set_aux(streambuf, 
            [](Kis_Net_Httpd_Buffer_Stream_Aux *aux) {
                if (aux->aux != NULL)
                    delete((BufferHandlerOStreambuf *) (aux->aux));
            });

    // Set our sync function which is called by the webserver side before we
    // clean up...
    saux->set_sync([streambuf](Kis_Net_Httpd_Buffer_Stream_Aux *aux) {
            if (aux->aux != NULL) {
                ((BufferHandlerOStringStreambuf *) aux->aux)->pubsync();
                }
            });


    if (strcmp(path, "/devices/all_devices.ekjson") == 0) {
        // Instantiate a manual serializer
        JsonAdapter::Serializer serial(globalreg); 

        devicetracker_function_worker fw(globalreg, 
                [this, &stream, &serial](Devicetracker *, shared_ptr<kis_tracked_device_base> d) -> bool {
                    serial.serialize(d, stream);
                    stream << "\n";

                    // Return false because we're not building a list, we're serializing
                    // per element
                    return false;
                }, NULL);

        MatchOnDevices(&fw);
        return MHD_YES;
    }

    string stripped = Httpd_StripSuffix(path);

    if (stripped == "/phy/all_phys") {
        httpd_all_phys(path, stream);
        return MHD_YES;
    }

    if (stripped == "/phy/all_phys_dt") {
        httpd_all_phys(path, stream, "aaData");
        return MHD_YES;
    }

    vector<string> tokenurl = StrTokenize(path, "/");

    if (tokenurl.size() < 2)
        return MHD_YES;

    if (tokenurl[1] == "devices") {
        if (tokenurl.size() < 5)
            return MHD_YES;

        if (tokenurl[2] == "by-key") {
            if (tokenurl.size() < 5) {
                return MHD_YES;
            }

            if (!Httpd_CanSerialize(tokenurl[4]))
                return MHD_YES;

            TrackedDeviceKey key(tokenurl[3]);
            auto dev = FetchDevice(key);

            if (dev == NULL) {
                stream << "Invalid device key";
                return MHD_YES;
            }

            string target = Httpd_StripSuffix(tokenurl[4]);

            if (target == "device") {
                // Try to find the exact field
                if (tokenurl.size() > 5) {
                    vector<string>::const_iterator first = tokenurl.begin() + 5;
                    vector<string>::const_iterator last = tokenurl.end();
                    vector<string> fpath(first, last);

                    local_locker devlocker(&(dev->device_mutex));

                    SharedTrackerElement sub = dev->get_child_path(fpath);

                    if (sub == NULL) {
                        return MHD_YES;
                    } 

                    entrytracker->Serialize(httpd->GetSuffix(tokenurl[4]), stream, sub, NULL);

                    return MHD_YES;
                }

                entrytracker->Serialize(httpd->GetSuffix(tokenurl[4]), stream, dev, NULL);

                return MHD_YES;
            } else {
                return MHD_YES;
            }
        } else if (tokenurl[2] == "by-mac") {
            if (tokenurl.size() < 5)
                return MHD_YES;

            if (!Httpd_CanSerialize(tokenurl[4]))
                return MHD_YES;

            local_locker lock(&devicelist_mutex);

            mac_addr mac = mac_addr(tokenurl[3]);

            if (mac.error) {
                return MHD_YES;
            }

            SharedTrackerElement devvec(new TrackerElement(TrackerVector));

            auto mmp = tracked_mac_multimap.equal_range(mac);
            for (auto mmpi = mmp.first; mmpi != mmp.second; ++mmpi) {
                devvec->add_vector(mmpi->second);
            }

            entrytracker->Serialize(httpd->GetSuffix(tokenurl[4]), stream, devvec, NULL);

            return MHD_YES;
        } else if (tokenurl[2] == "last-time") {
            if (tokenurl.size() < 5)
                return MHD_YES;

            // Is the timestamp an int?
            long lastts;
            if (sscanf(tokenurl[3].c_str(), "%ld", &lastts) != 1)
                return MHD_YES;

            // If it's negative, subtract from the current ts
            if (lastts < 0) {
                time_t now = time(0);
                lastts = now + lastts;
            }

            if (!Httpd_CanSerialize(tokenurl[4]))
                return MHD_YES;

            SharedTrackerElement devvec;

            devicetracker_function_worker fw(globalreg, 
                    [this, &stream, devvec, lastts](Devicetracker *, 
                        shared_ptr<kis_tracked_device_base> d) -> bool {
                        if (d->get_last_time() <= lastts)
                            return false;

                        return true;
                    }, NULL);
            MatchOnDevices(&fw);
            devvec = fw.GetMatchedDevices();

            entrytracker->Serialize(httpd->GetSuffix(tokenurl[4]), stream, devvec, NULL);

            return MHD_YES;
        }

    }

    return MHD_YES;
}

int Devicetracker::Httpd_PostComplete(Kis_Net_Httpd_Connection *concls) {
    // Split URL and process
    vector<string> tokenurl = StrTokenize(concls->url, "/");

    Kis_Net_Httpd_Buffer_Stream_Aux *saux = 
        (Kis_Net_Httpd_Buffer_Stream_Aux *) concls->custom_extension;

    BufferHandlerOStreambuf *streambuf = 
        new BufferHandlerOStreambuf(saux->get_rbhandler());
    std::ostream stream(streambuf);

    saux->set_aux(streambuf, 
            [streambuf](Kis_Net_Httpd_Buffer_Stream_Aux *aux) {
                if (aux->aux != NULL)
                    delete((BufferHandlerOStreambuf *) (aux->aux));
            });

    // Set our sync function which is called by the webserver side before we
    // clean up...
    saux->set_sync([streambuf](Kis_Net_Httpd_Buffer_Stream_Aux *aux) {
            if (aux->aux != NULL) {
                ((BufferHandlerOStringStreambuf *) aux->aux)->pubsync();
                }
            });

    // All URLs are at least /devices/summary/x or /devices/by-foo/y/x
    if (tokenurl.size() < 4) {
        stream << "Invalid request";
        concls->httpcode = 400;
        return MHD_YES;
    }

    // Common structured API data
    SharedStructured structdata;

    // Summarization vector
    vector<SharedElementSummary> summary_vec;

    // Wrapper, if any
    string wrapper_name;

    // Rename cache generated during simplification
    TrackerElementSerializer::rename_map rename_map;

    SharedStructured regexdata;

    time_t post_ts = 0;

    try {
        // Decode the base64 msgpack and parse it, or parse the json
        if (concls->variable_cache.find("msgpack") != concls->variable_cache.end()) {
            structdata.reset(new StructuredMsgpack(Base64::decode(concls->variable_cache["msgpack"]->str())));
        } else if (concls->variable_cache.find("json") != 
                concls->variable_cache.end()) {
            structdata.reset(new StructuredJson(concls->variable_cache["json"]->str()));
        } else {
            // fprintf(stderr, "debug - missing data\n");
            throw StructuredDataException("Missing data");
        }
    } catch(const StructuredDataException e) {
        stream << "Invalid request: ";
        stream << e.what();
        concls->httpcode = 400;
        return MHD_YES;
    }

    try {
        if (structdata->hasKey("fields")) {
            SharedStructured fields = structdata->getStructuredByKey("fields");
            StructuredData::structured_vec fvec = fields->getStructuredArray();

            for (StructuredData::structured_vec::iterator i = fvec.begin(); 
                    i != fvec.end(); ++i) {
                if ((*i)->isString()) {
                    SharedElementSummary s(new TrackerElementSummary((*i)->getString(), 
                                entrytracker));
                    summary_vec.push_back(s);
                } else if ((*i)->isArray()) {
                    StructuredData::string_vec mapvec = (*i)->getStringVec();

                    if (mapvec.size() != 2) {
                        // fprintf(stderr, "debug - malformed rename pair\n");
                        stream << "Invalid request: Expected field, rename";
                        concls->httpcode = 400;
                        return MHD_YES;
                    }

                    SharedElementSummary s(new TrackerElementSummary(mapvec[0], 
                                mapvec[1], entrytracker));
                    summary_vec.push_back(s);
                }
            }
        }

        // Get the wrapper, if one exists, default to empty if it doesn't
        wrapper_name = structdata->getKeyAsString("wrapper", "");

        if (structdata->hasKey("regex")) {
            regexdata = structdata->getStructuredByKey("regex");
        }

        if (structdata->hasKey("last_time")) {
            int64_t rawt = structdata->getKeyAsNumber("last_time");

            if (rawt < 0)
                post_ts = time(0) + rawt;
            else
                post_ts = rawt;
        }
    } catch(const StructuredDataException e) {
        stream << "Invalid request: ";
        stream << e.what();
        concls->httpcode = 400;
        return MHD_YES;
    }

    try {
        if (tokenurl[1] == "devices") {
            if (tokenurl[2] == "by-mac") {
                if (tokenurl.size() < 5) {
                    stream << "Invalid request";
                    concls->httpcode = 400;
                    return MHD_YES;
                }

                if (!Httpd_CanSerialize(tokenurl[4])) {
                    stream << "Invalid request";
                    concls->httpcode = 400;
                    return MHD_YES;
                }

                local_demand_locker lock(&devicelist_mutex);

                if (!Httpd_CanSerialize(tokenurl[4])) {
                    stream << "Invalid request";
                    concls->httpcode = 400;
                    return MHD_YES;
                }

                mac_addr mac = mac_addr(tokenurl[3]);

                if (mac.error) {
                    stream << "Invalid request";
                    concls->httpcode = 400;
                    return MHD_YES;
                }

                lock.lock();
                if (tracked_mac_multimap.count(mac) == 0) {
                    stream << "Invalid request";
                    concls->httpcode = 400;
                    return MHD_YES;
                }
                lock.unlock();

                string target = Httpd_StripSuffix(tokenurl[4]);

                if (target == "devices") {
                    SharedTrackerElement devvec(new TrackerElement(TrackerVector));

                    lock.lock();
                    auto mmp = tracked_mac_multimap.equal_range(mac);
                    lock.unlock();

                    for (auto mmpi = mmp.first; mmpi != mmp.second; ++mmpi) {
                        SharedTrackerElement simple;

                        SummarizeTrackerElement(entrytracker, mmpi->second, summary_vec,
                                simple, rename_map);

                        devvec->add_vector(simple);
                    }

                    entrytracker->Serialize(httpd->GetSuffix(tokenurl[4]), stream, 
                            devvec, &rename_map);

                    return MHD_YES;
                }

                stream << "Invalid request";
                concls->httpcode = 400;
                return MHD_YES;
            } else if (tokenurl[2] == "by-key") {
                if (tokenurl.size() < 5) {
                    stream << "Invalid request";
                    concls->httpcode = 400;
                    return MHD_YES;
                }

                if (!Httpd_CanSerialize(tokenurl[4])) {
                    stream << "Invalid request";
                    concls->httpcode = 400;
                    return MHD_YES;
                }

                TrackedDeviceKey key(tokenurl[3]);

                auto dev = FetchDevice(key);

                if (dev == NULL) {
                    stream << "Invalid request";
                    concls->httpcode = 400;
                    return MHD_YES;
                }

                string target = Httpd_StripSuffix(tokenurl[4]);

                if (target == "device") {
                    SharedTrackerElement simple;

                    local_locker devlock(&(dev->device_mutex));

                    SummarizeTrackerElement(entrytracker, dev, summary_vec, simple, rename_map);

                    entrytracker->Serialize(httpd->GetSuffix(tokenurl[4]), stream, simple, &rename_map);

                    return MHD_YES;
                }

                if (target == "set_name") {
                    std::string name;

                    // Must have a session to set the name
                    if (!httpd->HasValidSession(concls)) 
                        throw std::runtime_error("login required");

                    if (!structdata->hasKey("username")) 
                        throw std::runtime_error("expected username in command dictionary");

                    name = structdata->getKeyAsString("username");

                    SetDeviceUserName(dev, name);

                    stream << "OK";
                    return MHD_YES;
                }

                if (target == "set_tag") {
                    std::string tag, content;

                    if (!httpd->HasValidSession(concls))
                        throw std::runtime_error("login required");

                    if (!structdata->hasKey("tagname"))
                        throw std::runtime_error("expected tagname in command dictionary");

                    if (!structdata->hasKey("tagvalue"))
                        throw std::runtime_error("expected tagvalue in command dictionary");

                    tag = structdata->getKeyAsString("tagname");
                    content = structdata->getKeyAsString("tagvalue");

                    SetDeviceTag(dev, tag, content);

                    stream << "OK";
                    return MHD_YES;
                }

            } else if (tokenurl[2] == "summary") {
                // We don't lock device list up here because we use workers since it
                // can be a multi-device return
                
                SharedStructured colmapdata;
                StructuredData::structured_num_map colmap;
                if (structdata->hasKey("colmap")) {
                    colmapdata = structdata->getStructuredByKey("colmap");
                    colmap = colmapdata->getStructuredNumMap();
                }

                // Wrapper we insert under
                SharedTrackerElement wrapper = NULL;

                // DT fields
                SharedTrackerElement dt_length_elem = NULL;
                SharedTrackerElement dt_filter_elem = NULL;

                SharedTrackerElement outdevs =
                    globalreg->entrytracker->GetTrackedInstance(device_list_base_id);

                unsigned int dt_start = 0;
                unsigned int dt_length = 0;
                int dt_draw = 0;

                int in_dt_length = 0, in_dt_start = 0;

                // Search string
                string dt_search;

                // Resolved paths to fields we search
                std::vector<std::vector<int> > dt_search_paths;

                int dt_order_col = -1;
                int dt_order_dir = 0;

                // Fields we search
                std::vector<std::vector<int> > dt_order_fields;

                if (structdata->getKeyAsBool("datatable", false)) {
                    // fprintf(stderr, "debug - we think we're doing a server-side datatable\n");
                    if (concls->variable_cache.find("start") != 
                            concls->variable_cache.end()) {
                        *(concls->variable_cache["start"]) >> in_dt_start;
                    }

                    if (concls->variable_cache.find("length") != 
                            concls->variable_cache.end()) {
                        *(concls->variable_cache["length"]) >> in_dt_length;
                    }

                    if (concls->variable_cache.find("draw") != 
                            concls->variable_cache.end()) {
                        *(concls->variable_cache["draw"]) >> dt_draw;
                    }

                    if (concls->variable_cache.find("search[value]") !=
                            concls->variable_cache.end()) {
                        dt_search = concls->variable_cache["search[value]"]->str();
                    }

                    // Search every field; we could make this more controlled by using
                    // the new colmap code but we don't really need to
                    if (dt_search.length() != 0) {
                        for (auto svi : summary_vec) 
                            dt_search_paths.push_back(svi->resolved_path);
                    }

                    // We only handle sorting by the first column in the sort list; we
                    // don't support cascading sorts
                    if (concls->variable_cache.find("order[0][column]") !=
                            concls->variable_cache.end()) {
                        *(concls->variable_cache["order[0][column]"]) >> dt_order_col;
                    }

                    // Don't allow ordering by a column that doesn't make sense
                    auto colmap_index = colmap.find(dt_order_col);
                    if (colmap_index == colmap.end())
                        dt_order_col = -1;

                    if (dt_order_col >= 0 &&
                            concls->variable_cache.find("order[0][dir]") !=
                            concls->variable_cache.end()) {
                        string ord = concls->variable_cache["order[0][dir]"]->str();

                        if (ord == "asc")
                            dt_order_dir = 1;

                        // Resolve the paths
                        StructuredData::string_vec col_field_vec = 
                            colmap_index->second->getStringVec();

                        for (auto fn : col_field_vec) {
                            TrackerElementSummary s(fn, entrytracker);
                            dt_order_fields.push_back(s.resolved_path);
                        }
                    }

                    // Force a length if we think we're doing a smart position and
                    // something has gone wonky
                    if (in_dt_length <= 0 || in_dt_length > 200) {
                        dt_length = 50;
                    } else {
                        dt_length = in_dt_length;
                    }

                    if (in_dt_start < 0)
                        dt_start = 0;
                    else
                        dt_start = in_dt_start;

                    // DT always has to wrap in an object
                    wrapper.reset(new TrackerElement(TrackerMap));

                    // wrap in 'data' for DT
                    wrapper->add_map(outdevs);
                    outdevs->set_local_name("data");

                    // Set the DT draw
                    SharedTrackerElement 
                        draw_elem(new TrackerElement(TrackerUInt64, dt_draw_id));
                    draw_elem->set((uint64_t) dt_draw);
                    draw_elem->set_local_name("draw");
                    wrapper->add_map(draw_elem);

                    // Make the length and filter elements
                    dt_length_elem.reset(new TrackerElement(TrackerUInt64, dt_length_id));
                    dt_length_elem->set_local_name("recordsTotal");
                    dt_length_elem->set((uint64_t) tracked_vec.size());
                    wrapper->add_map(dt_length_elem);

                    dt_filter_elem.reset(new TrackerElement(TrackerUInt64, dt_filter_id));
                    dt_filter_elem->set_local_name("recordsFiltered");
                    wrapper->add_map(dt_filter_elem);
                }

                if (regexdata != NULL) {
                    // If we're doing a basic regex outside of devicetables
                    // shenanigans...
                    devicetracker_pcre_worker worker(globalreg, regexdata);
                    MatchOnDevices(&worker);

                    SharedTrackerElement pcredevs = worker.GetMatchedDevices();
                    TrackerElementVector pcrevec(pcredevs);

                    // Check DT ranges
                    if (dt_start >= pcrevec.size())
                        dt_start = 0;

                    if (dt_filter_elem != NULL)
                        dt_filter_elem->set((uint64_t) pcrevec.size());

                    // Sort the list by the selected column
                    if (dt_order_col >= 0 && dt_order_fields.size() > 0) {
                        kismet__stable_sort(pcrevec.begin(), pcrevec.end(), 
                                [&](SharedTrackerElement a, SharedTrackerElement b) {
                                SharedTrackerElement fa;
                                SharedTrackerElement fb;
                                bool passfa = false, passfb = false;

                                for (auto ofi : dt_order_fields) {
                                    if (fa == NULL || (fa != NULL && 
                                        fa->get_type() == TrackerString &&
                                        GetTrackerValue<std::string>(fa) == "")) {
                                        fa = 
                                            GetTrackerElementPath(ofi, a);
                                    } else {
                                        passfa = true;
                                    }

                                    if (fb == NULL || (fb != NULL && 
                                        fb->get_type() == TrackerString &&
                                        GetTrackerValue<std::string>(fb) == "")) {
                                        fb = 
                                            GetTrackerElementPath(ofi, b);
                                    } else {
                                        passfb = true;
                                    }

                                    if (passfa && passfb)
                                        break;
                                }

                                if (dt_order_dir == 0)
                                    return fa < fb;

                                return fb < fa;
                                });
                    }

                    // If we filtered, that's our list
                    TrackerElementVector::iterator vi;
                    // Set the iterator endpoint for our length
                    TrackerElementVector::iterator ei;
                    if (dt_length == 0 ||
                            dt_length + dt_start >= pcrevec.size())
                        ei = pcrevec.end();
                    else
                        ei = pcrevec.begin() + dt_start + dt_length;

                    for (vi = pcrevec.begin() + dt_start; vi != ei; ++vi) {
                        SharedTrackerElement simple;

                        SummarizeTrackerElement(entrytracker, (*vi), summary_vec, simple, rename_map);

                        outdevs->add_vector(simple);
                    }
                } else if (dt_search_paths.size() != 0) {
                    // Otherwise, we're doing a search inside a datatables query,
                    // so go through every device and do a search on every element
                    // which we have flagged as searchable, and which is a string or
                    // mac which we can treat as a string.

                    devicetracker_stringmatch_worker worker(globalreg, dt_search, 
                            dt_search_paths);
                    MatchOnDevices(&worker);

                    SharedTrackerElement matchdevs = worker.GetMatchedDevices();
                    TrackerElementVector matchvec(matchdevs);

                    if (dt_order_col >= 0 && dt_order_fields.size() > 0) {
                        kismet__stable_sort(matchvec.begin(), matchvec.end(), 
                                [&](SharedTrackerElement a, SharedTrackerElement b) {
                                SharedTrackerElement fa;
                                SharedTrackerElement fb;
                                bool passfa = false, passfb = false;

                                for (auto ofi : dt_order_fields) {
                                    if (fa == NULL || (fa != NULL && 
                                        fa->get_type() == TrackerString &&
                                        GetTrackerValue<std::string>(fa) == "")) {
                                        fa = 
                                            GetTrackerElementPath(ofi, a);
                                    } else {
                                        passfa = true;
                                    }

                                    if (fb == NULL || (fb != NULL && 
                                        fb->get_type() == TrackerString &&
                                        GetTrackerValue<std::string>(fb) == "")) {
                                        fb = 
                                            GetTrackerElementPath(ofi, b);
                                    } else {
                                        passfb = true;
                                    }

                                    if (passfa && passfb)
                                        break;
                                }

                                if (dt_order_dir == 0)
                                    return fa < fb;

                                return fb < fa;
                                });
                    }

                    // Check DT ranges
                    if (dt_start >= matchvec.size())
                        dt_start = 0;

                    if (dt_filter_elem != NULL)
                        dt_filter_elem->set((uint64_t) matchvec.size());

                    // Set the iterator endpoint for our length
                    TrackerElementVector::iterator ei;
                    if (dt_length == 0 ||
                            dt_length + dt_start >= matchvec.size())
                        ei = matchvec.end();
                    else
                        ei = matchvec.begin() + dt_start + dt_length;

                    // If we filtered, that's our list
                    TrackerElementVector::iterator vi;
                    for (vi = matchvec.begin() + dt_start; vi != ei; ++vi) {
                        SharedTrackerElement simple;

                        SummarizeTrackerElement(entrytracker, (*vi), summary_vec, simple, rename_map);

                        outdevs->add_vector(simple);
                    }
                } else {
                    local_locker listlock(&devicelist_mutex);

                    // Check DT ranges
                    if (dt_start >= tracked_vec.size())
                        dt_start = 0;

                    if (dt_filter_elem != NULL)
                        dt_filter_elem->set((uint64_t) tracked_vec.size());

                    if (dt_order_col >= 0 && dt_order_fields.size() > 0) {
                        kismet__stable_sort(tracked_vec.begin(), tracked_vec.end(), 
                                [&](SharedTrackerElement a, SharedTrackerElement b) {
                                SharedTrackerElement fa;
                                SharedTrackerElement fb;
                                bool passfa = false, passfb = false;

                                for (auto ofi : dt_order_fields) {
                                    if (fa == NULL || (fa != NULL && 
                                        fa->get_type() == TrackerString &&
                                        GetTrackerValue<std::string>(fa) == "")) {
                                        fa = 
                                            GetTrackerElementPath(ofi, a);
                                    } else {
                                        passfa = true;
                                    }

                                    if (fb == NULL || (fb != NULL && 
                                        fb->get_type() == TrackerString &&
                                        GetTrackerValue<std::string>(fb) == "")) {
                                        fb = 
                                            GetTrackerElementPath(ofi, b);
                                    } else {
                                        passfb = true;
                                    }

                                    if (passfa && passfb)
                                        break;
                                }

                                if (dt_order_dir == 0)
                                    return fa < fb;

                                return fb < fa;
                                });
                    }

                    vector<shared_ptr<kis_tracked_device_base> >::iterator vi;
                    vector<shared_ptr<kis_tracked_device_base> >::iterator ei;

                    // Set the iterator endpoint for our length
                    if (dt_length == 0 ||
                            dt_length + dt_start >= tracked_vec.size())
                        ei = tracked_vec.end();
                    else
                        ei = tracked_vec.begin() + dt_start + dt_length;

                    for (vi = tracked_vec.begin() + dt_start; vi != ei; ++vi) {
                        SharedTrackerElement simple;

                        SummarizeTrackerElement(entrytracker,
                                (*vi), summary_vec,
                                simple, rename_map);

                        outdevs->add_vector(simple);
                    }
                }

                // Apply wrapper if we haven't applied it already
                if (wrapper_name != "" && wrapper == NULL) {
                    wrapper.reset(new TrackerElement(TrackerMap));
                    wrapper->add_map(outdevs);
                    outdevs->set_local_name(wrapper_name);
                } else if (wrapper == NULL) {
                    wrapper = outdevs;
                }

                entrytracker->Serialize(httpd->GetSuffix(tokenurl[3]), stream, 
                        wrapper, &rename_map);
                return MHD_YES;

            } else if (tokenurl[2] == "last-time") {
                // We don't lock the device list since we use workers

                if (tokenurl.size() < 5) {
                    stream << "Invalid request";
                    concls->httpcode = 400;
                    return MHD_YES;
                }

                // Is the timestamp an int?
                long lastts;
                if (sscanf(tokenurl[3].c_str(), "%ld", &lastts) != 1 ||
                        !Httpd_CanSerialize(tokenurl[4])) {
                    stream << "Invalid request";
                    concls->httpcode = 400;
                    return MHD_YES;
                }

                // If it's negative, subtract from the current ts
                if (lastts < 0) {
                    time_t now = time(0);
                    lastts = now + lastts;
                }

                // Rename cache generated during simplification
                TrackerElementSerializer::rename_map rename_map;

                // List of devices that pass the timestamp filter
                SharedTrackerElement timedevs;

                //  List of devices that pass the regex filter
                SharedTrackerElement regexdevs(new TrackerElement(TrackerVector));

                devicetracker_function_worker tw(globalreg, 
                        [this, &stream, lastts](Devicetracker *, shared_ptr<kis_tracked_device_base> d) -> bool {

                        if (d->get_last_time() <= lastts)
                        return false;

                        return true;
                        }, NULL);
                MatchOnDevices(&tw);
                timedevs = tw.GetMatchedDevices();

                if (regexdata != NULL) {
                    devicetracker_pcre_worker worker(globalreg, regexdata);
                    MatchOnDevices(&worker, timedevs);
                    regexdevs = worker.GetMatchedDevices();
                } else {
                    regexdevs = timedevs;
                }

                // Final devices being simplified and sent out
                SharedTrackerElement outdevs(new TrackerElement(TrackerVector));

                TrackerElementVector regexdevs_vec(regexdevs);
                for (auto rei : regexdevs_vec) {
                    std::shared_ptr<kis_tracked_device_base> rd = 
                        std::static_pointer_cast<kis_tracked_device_base>(rei);

                    local_locker lock(&rd->device_mutex);

                    SharedTrackerElement simple;

                    SummarizeTrackerElement(entrytracker, rd, summary_vec, simple, rename_map);

                    outdevs->add_vector(simple);
                }

                entrytracker->Serialize(httpd->GetSuffix(tokenurl[4]), stream, outdevs, &rename_map);
                return MHD_YES;
            } else if (tokenurl[2] == "by-phy") {
                // We don't lock the device list since we use workers
                if (tokenurl.size() < 5) {
                    stream << "Invalid request";
                    concls->httpcode = 400;
                    return MHD_YES;
                }

                auto phy = FetchPhyHandlerByName(tokenurl[3]);

                if (phy == NULL) {
                    stream << "Invalid request";
                    concls->httpcode = 400;
                    return MHD_YES;
                }

                // Rename cache generated during simplification
                TrackerElementSerializer::rename_map rename_map;

                // List of devices that pass the timestamp filter
                SharedTrackerElement timedevs;

                // Devices that pass the phy filter
                SharedTrackerElement phydevs;

                //  List of devices that pass the regex filter
                SharedTrackerElement regexdevs;


                // Filter by time first, it's fast
                devicetracker_function_worker tw(globalreg, 
                        [this, &stream, post_ts](Devicetracker *, shared_ptr<kis_tracked_device_base> d) -> bool {

                        if (d->get_last_time() <= post_ts)
                        return false;

                        return true;
                        }, NULL);

                devicetracker_function_worker pw(globalreg, 
                        [this, &stream, phydevs, phy](Devicetracker *, shared_ptr<kis_tracked_device_base> d) -> bool {
                        if (d->get_phyname() != phy->FetchPhyName())
                        return false;

                        return true;
                        }, NULL);

                if (post_ts != 0) {
                    // time-match then phy-match then pass to regex
                    MatchOnDevices(&tw);
                    timedevs = tw.GetMatchedDevices();
                    MatchOnDevices(&pw, timedevs);
                    phydevs = pw.GetMatchedDevices();
                }  else {
                    // Phy match only
                    MatchOnDevices(&pw);
                    phydevs = pw.GetMatchedDevices();
                }

                if (regexdata != NULL) {
                    devicetracker_pcre_worker worker(globalreg, regexdata);
                    MatchOnDevices(&worker, phydevs);
                    regexdevs = worker.GetMatchedDevices();
                } else {
                    regexdevs = phydevs;
                }

                // Final devices being simplified and sent out
                SharedTrackerElement outdevs(new TrackerElement(TrackerVector));

                TrackerElementVector regexdevs_vec(regexdevs);
                for (auto rei : regexdevs_vec) {
                    std::shared_ptr<kis_tracked_device_base> rd = 
                        std::static_pointer_cast<kis_tracked_device_base>(rei);

                    local_locker lock(&rd->device_mutex);

                    SharedTrackerElement simple;

                    SummarizeTrackerElement(entrytracker, rd, summary_vec, simple, rename_map);

                    outdevs->add_vector(simple);
                }

                entrytracker->Serialize(httpd->GetSuffix(tokenurl[4]), stream, outdevs, &rename_map);
                return MHD_YES;
            }
        }
    } catch(const std::exception& e) {
        stream << "Invalid request: ";
        stream << e.what();
        concls->httpcode = 400;
        return MHD_YES;
    }

    stream << "OK";

    return MHD_YES;
}

