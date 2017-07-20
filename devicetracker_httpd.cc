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
#include "dumpfile_devicetracker.h"
#include "entrytracker.h"
#include "devicetracker_component.h"
#include "msgpack_adapter.h"
#include "xmlserialize_adapter.h"
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

        if (stripped == "/devices/all_devices" && can_serialize)
            return true;

        if (stripped == "/devices/all_devices_dt" && can_serialize)
            return true;

        if (strcmp(path, "/devices/all_devices.xml") == 0)
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

                local_locker lock(&devicelist_mutex);

                uint64_t key = 0;
                std::stringstream ss(tokenurl[3]);
                ss >> key;

                if (!Httpd_CanSerialize(tokenurl[4]))
                    return false;

                map<uint64_t, shared_ptr<kis_tracked_device_base> >::iterator tmi =
                    tracked_map.find(key);

                if (tmi == tracked_map.end())
                    return false;

                string target = Httpd_StripSuffix(tokenurl[4]);

                if (target == "device") {
                    // Try to find the exact field
                    if (tokenurl.size() > 5) {
                        vector<string>::const_iterator first = tokenurl.begin() + 5;
                        vector<string>::const_iterator last = tokenurl.end();
                        vector<string> fpath(first, last);

                        if (tmi->second->get_child_path(fpath) == NULL) {
                            return false;
                        }
                    }

                    return true;
                }

                return false;
            } else if (tokenurl[2] == "by-mac") {
                if (tokenurl.size() < 5)
                    return false;

                local_locker lock(&devicelist_mutex);

                if (!Httpd_CanSerialize(tokenurl[4]))
                    return false;

                mac_addr mac = mac_addr(tokenurl[3]);

                if (mac.error) {
                    return false;
                }

                // Try to find the actual mac
                vector<shared_ptr<kis_tracked_device_base> >::iterator vi;
                for (vi = tracked_vec.begin(); vi != tracked_vec.end(); ++vi) {
                    if ((*vi)->get_macaddr() == mac) {
                        return true;
                    }
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
                    return false;
                }

                return Httpd_CanSerialize(tokenurl[4]);
            } else if (tokenurl[2] == "by-key") {
                if (tokenurl.size() < 5) {
                    return false;
                }

                local_locker lock(&devicelist_mutex);

                uint64_t key = 0;
                std::stringstream ss(tokenurl[3]);
                ss >> key;

                if (!Httpd_CanSerialize(tokenurl[4]))
                    return false;

                map<uint64_t, shared_ptr<kis_tracked_device_base> >::iterator tmi =
                    tracked_map.find(key);

                if (tmi == tracked_map.end())
                    return false;

                string target = Httpd_StripSuffix(tokenurl[4]);

                if (target == "set_name") {
                    return true;
                }
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

void Devicetracker::httpd_device_summary(string url, std::ostream &stream, 
        shared_ptr<TrackerElementVector> subvec, 
        vector<SharedElementSummary> summary_vec,
        string in_wrapper_key) {

    local_locker lock(&devicelist_mutex);

    SharedTrackerElement devvec =
        globalreg->entrytracker->GetTrackedInstance(device_summary_base_id);

    TrackerElementSerializer::rename_map rename_map;

    // Wrap the dev vec in a dictionary and change its name
    SharedTrackerElement wrapper = NULL;

    if (in_wrapper_key != "") {
        wrapper.reset(new TrackerElement(TrackerMap));
        wrapper->add_map(devvec);
        devvec->set_local_name(in_wrapper_key);
    } else {
        wrapper = devvec;
    }

    if (subvec == NULL) {
        for (unsigned int x = 0; x < tracked_vec.size(); x++) {
            if (summary_vec.size() == 0) {
                devvec->add_vector(tracked_vec[x]);
            } else {
                SharedTrackerElement simple;

                SummarizeTrackerElement(entrytracker, tracked_vec[x], 
                        summary_vec, simple, rename_map);

                devvec->add_vector(simple);
            }
        }
    } else {
        for (TrackerElementVector::const_iterator x = subvec->begin();
                x != subvec->end(); ++x) {
            if (summary_vec.size() == 0) {
                devvec->add_vector(*x);
            } else {
                SharedTrackerElement simple;

                SummarizeTrackerElement(entrytracker, *x, 
                        summary_vec, simple, rename_map);

                devvec->add_vector(simple);
            }
        }
    }

    entrytracker->Serialize(httpd->GetSuffix(url), stream, wrapper, &rename_map);
}

void Devicetracker::httpd_xml_device_summary(std::ostream &stream) {
    local_locker lock(&devicelist_mutex);

    SharedTrackerElement devvec =
        globalreg->entrytracker->GetTrackedInstance(device_summary_base_id);

    for (unsigned int x = 0; x < tracked_vec.size(); x++) {
        devvec->add_vector(tracked_vec[x]);
    }

    XmlserializeAdapter *xml = new XmlserializeAdapter(globalreg);

    xml->RegisterField("kismet.device.list", "SummaryDevices");
    xml->RegisterFieldNamespace("kismet.device.list",
            "k",
            "http://www.kismetwireless.net/xml/summary",
            "http://www.kismetwireless.net/xml/summary.xsd");
    xml->RegisterFieldSchema("kismet.device.list",
            "common",
            "http://www.kismetwireless.net/xml/common",
            "http://www.kismetwireless.net/xml/common.xsd");
    xml->RegisterFieldSchema("kismet.device.list",
            "gps",
            "http://www.kismetwireless.net/xml/gps",
            "http://www.kismetwireless.net/xml/gps.xsd");


    xml->RegisterField("kismet.device.summary", "summary");

    xml->RegisterField("kismet.device.base.name", "name");
    xml->RegisterField("kismet.device.base.phyname", "phyname");
    xml->RegisterField("kismet.device.base.signal", "signal");
    xml->RegisterField("kismet.device.base.channel", "channel");
    xml->RegisterField("kismet.device.base.frequency", "frequency");
    xml->RegisterField("kismet.device.base.manuf", "manufacturer");
    xml->RegisterField("kismet.device.base.key", "key");
    xml->RegisterField("kismet.device.base.macaddr", "macaddress");
    xml->RegisterField("kismet.device.base.type", "type");
    xml->RegisterField("kismet.device.base.first_time", "firstseen");
    xml->RegisterField("kismet.device.base.last_time", "lastseen");
    xml->RegisterField("kismet.device.base.packets.total", "packetstotal");

    xml->RegisterField("kismet.common.signal.last_signal_dbm", "lastsignaldbm");
    xml->RegisterField("kismet.common.signal.min_signal_dbm", "minsignaldbm");
    xml->RegisterField("kismet.common.signal.max_signal_dbm", "maxsignaldbm");
    xml->RegisterField("kismet.common.signal.last_noise_dbm", "lastnoisedbm");
    xml->RegisterField("kismet.common.signal.min_noise_dbm", "minnoisedbm");
    xml->RegisterField("kismet.common.signal.max_noise_dbm", "maxnoisedbm");
    xml->RegisterField("kismet.common.signal.last_signal_rssi", "lastsignalrssi");
    xml->RegisterField("kismet.common.signal.min_signal_rssi", "minsignalrssi");
    xml->RegisterField("kismet.common.signal.max_signal_rssi", "maxsignalrssi");
    xml->RegisterField("kismet.common.signal.last_noise_rssi", "lastnoiserssi");
    xml->RegisterField("kismet.common.signal.min_noise_rssi", "minnoiserssi");
    xml->RegisterField("kismet.common.signal.max_noise_rssi", "maxnoiserssi");

    xml->RegisterField("kismet.common.signal.peak_loc", "peaklocation");
    xml->RegisterFieldXsitype("kismet.common.signal.peak_loc", "kismet:location");

    xml->RegisterField("kismet.common.location.lat", "lat");
    xml->RegisterField("kismet.common.location.lon", "lon");
    xml->RegisterField("kismet.common.location.alt", "alt");
    xml->RegisterField("kismet.common.location.speed", "speed");

    stream << "<?xml version=\"1.0\"?>";

    xml->XmlSerialize(devvec, stream);

    delete(xml);
}

void Devicetracker::Httpd_CreateStreamResponse(
        Kis_Net_Httpd *httpd __attribute__((unused)),
        Kis_Net_Httpd_Connection *connection,
        const char *path, const char *method, const char *upload_data,
        size_t *upload_data_size) {

    if (strcmp(method, "GET") != 0) {
        return;
    }

    Kis_Net_Httpd_Buffer_Stream_Aux *saux = 
        (Kis_Net_Httpd_Buffer_Stream_Aux *) connection->custom_extension;
   
    BufferHandlerOStreambuf streambuf(saux->get_rbhandler());
    std::ostream stream(&streambuf);

    // Set us immediately in error so the webserver will flush us out
    saux->in_error = true;

    // fprintf(stderr, "debug - making ostream pointing to buffer\n");

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
        return;
    }

    string stripped = Httpd_StripSuffix(path);

    if (stripped == "/devices/all_devices") {
        httpd_device_summary(path, stream, NULL, vector<SharedElementSummary>());
        return;
    }

    if (stripped == "/devices/all_devices_dt") {
        httpd_device_summary(path, stream, NULL, 
                vector<SharedElementSummary>(), "aaData");
        return;
    }

    // XML is special right now
    if (strcmp(path, "/devices/all_devices.xml") == 0) {
        httpd_xml_device_summary(stream);
        return;
    }

    if (stripped == "/phy/all_phys") {
        httpd_all_phys(path, stream);
    }

    if (stripped == "/phy/all_phys_dt") {
        httpd_all_phys(path, stream, "aaData");
    }

    vector<string> tokenurl = StrTokenize(path, "/");

    if (tokenurl.size() < 2)
        return;

    if (tokenurl[1] == "devices") {
        if (tokenurl.size() < 5)
            return;

        if (tokenurl[2] == "by-key") {
            if (tokenurl.size() < 5) {
                return;
            }

            if (!Httpd_CanSerialize(tokenurl[4]))
                return;

            local_locker lock(&devicelist_mutex);

            uint64_t key = 0;
            std::stringstream ss(tokenurl[3]);

            ss >> key;

            /*
			if (sscanf(tokenurl[3].c_str(), "%lu", &key) != 1) {
				return;
            }
            */

            map<uint64_t, shared_ptr<kis_tracked_device_base> >::iterator tmi =
                tracked_map.find(key);

            if (tmi == tracked_map.end()) {
                stream << "Invalid device key";
                return;
            }

            string target = Httpd_StripSuffix(tokenurl[4]);

            if (target == "device") {
                // Try to find the exact field
                if (tokenurl.size() > 5) {
                    vector<string>::const_iterator first = tokenurl.begin() + 5;
                    vector<string>::const_iterator last = tokenurl.end();
                    vector<string> fpath(first, last);

                    SharedTrackerElement sub = tmi->second->get_child_path(fpath);

                    if (sub == NULL) {
                        return;
                    } 

                    entrytracker->Serialize(httpd->GetSuffix(tokenurl[4]), stream, sub, NULL);

                    return;
                }

                entrytracker->Serialize(httpd->GetSuffix(tokenurl[4]), stream, 
                        tmi->second, NULL);

                return;
            } else {
                return;
            }
        } else if (tokenurl[2] == "by-mac") {
            if (tokenurl.size() < 5)
                return;

            if (!Httpd_CanSerialize(tokenurl[4]))
                return;

            local_locker lock(&devicelist_mutex);

            mac_addr mac = mac_addr(tokenurl[3]);

            if (mac.error) {
                return;
            }

            SharedTrackerElement devvec =
                globalreg->entrytracker->GetTrackedInstance(device_list_base_id);

            vector<shared_ptr<kis_tracked_device_base> >::iterator vi;
            for (vi = tracked_vec.begin(); vi != tracked_vec.end(); ++vi) {
                if ((*vi)->get_macaddr() == mac) {
                    devvec->add_vector((*vi));
                }
            }

            entrytracker->Serialize(httpd->GetSuffix(tokenurl[4]), stream, devvec, NULL);

            return;
        } else if (tokenurl[2] == "last-time") {
            if (tokenurl.size() < 5)
                return;

            // Is the timestamp an int?
            long lastts;
            if (sscanf(tokenurl[3].c_str(), "%ld", &lastts) != 1)
                return;

            // Special handling of the ekjson
            if (tokenurl[4] == "devices.ekjson") {
                // Instantiate a manual serializer
                JsonAdapter::Serializer serial(globalreg); 

                devicetracker_function_worker fw(globalreg, 
                        [this, &stream, &serial, lastts](Devicetracker *, shared_ptr<kis_tracked_device_base> d) -> bool {
                            if (d->get_last_time() <= lastts)
                                return false;
                            serial.serialize(d, stream);
                            stream << "\n";

                            // Return false because we're not building a list, we're serializing
                            // per element
                            return false;
                        }, NULL);
                MatchOnDevices(&fw);

            }

            if (!Httpd_CanSerialize(tokenurl[4]))
                return;

            local_locker lock(&devicelist_mutex);

            SharedTrackerElement wrapper(new TrackerElement(TrackerMap));

            SharedTrackerElement refresh =
                globalreg->entrytracker->GetTrackedInstance(device_update_required_id);

            // If we've changed the list more recently, we have to do a refresh
            if (lastts < full_refresh_time) {
                refresh->set((uint8_t) 1);
            } else {
                refresh->set((uint8_t) 0);
            }

            wrapper->add_map(refresh);

            SharedTrackerElement updatets =
                globalreg->entrytracker->GetTrackedInstance(device_update_timestamp_id);
            updatets->set((int64_t) globalreg->timestamp.tv_sec);

            wrapper->add_map(updatets);

            SharedTrackerElement devvec =
                globalreg->entrytracker->GetTrackedInstance(device_list_base_id);

            wrapper->add_map(devvec);

            vector<shared_ptr<kis_tracked_device_base> >::iterator vi;
            for (vi = tracked_vec.begin(); vi != tracked_vec.end(); ++vi) {
                if ((*vi)->get_last_time() > lastts)
                    devvec->add_vector((*vi));
            }

            entrytracker->Serialize(httpd->GetSuffix(tokenurl[4]), stream, wrapper, NULL);

            return;
        }

    }
}

int Devicetracker::Httpd_PostComplete(Kis_Net_Httpd_Connection *concls) {
    local_locker lock(&devicelist_mutex);

    // Split URL and process
    vector<string> tokenurl = StrTokenize(concls->url, "/");

    // All URLs are at least /devices/summary/x or /devices/last-time/ts/x
    if (tokenurl.size() < 4) {
        concls->response_stream << "Invalid request";
        concls->httpcode = 400;
        return 1;
    }

    // Common structured API data
    SharedStructured structdata;

    // Summarization vector
    vector<SharedElementSummary> summary_vec;

    // Wrapper, if any
    string wrapper_name;

    SharedStructured regexdata;

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

        // fprintf(stderr, "debug - parsed structured data\n");

    } catch(const StructuredDataException e) {
        // fprintf(stderr, "debug - missing data key %s data %s\n", key, data);
        concls->response_stream << "Invalid request: ";
        concls->response_stream << e.what();
        concls->httpcode = 400;
        return 1;
    }

    if (tokenurl[1] == "devices") {
        if (tokenurl[2] == "by-key") {
            if (tokenurl.size() < 5) {
                concls->response_stream << "Invalid request";
                concls->httpcode = 400;
                return 1;
            }

            if (!Httpd_CanSerialize(tokenurl[4])) {
                concls->response_stream << "Invalid request";
                concls->httpcode = 400;
                return 1;
            }

            uint64_t key = 0;
            std::stringstream ss(tokenurl[3]);
            ss >> key;

            map<uint64_t, shared_ptr<kis_tracked_device_base> >::iterator tmi =
                tracked_map.find(key);

            if (tmi == tracked_map.end()) {
                concls->response_stream << "Invalid request";
                concls->httpcode = 400;
                return 1;
            }

            string target = Httpd_StripSuffix(tokenurl[4]);

            if (target == "set_name") {
                // Must have a session to set the name
                if (!httpd->HasValidSession(concls)) {
                    return 1;
                }

            }

        } else if (tokenurl[2] == "summary") {
            try {
                SharedStructured fields = structdata->getStructuredByKey("fields");
                StructuredData::structured_vec fvec = fields->getStructuredArray();

                for (StructuredData::structured_vec::iterator i = fvec.begin(); 
                        i != fvec.end(); ++i) {
                    if ((*i)->isString()) {
                        SharedElementSummary s(new TrackerElementSummary((*i)->getString(), entrytracker));
                        summary_vec.push_back(s);
                    } else if ((*i)->isArray()) {
                        StructuredData::string_vec mapvec = (*i)->getStringVec();

                        if (mapvec.size() != 2) {
                            // fprintf(stderr, "debug - malformed rename pair\n");
                            concls->response_stream << "Invalid request: "
                                "Expected field, rename";
                            concls->httpcode = 400;
                            return 1;
                        }

                        SharedElementSummary s(new TrackerElementSummary(mapvec[0], 
                                    mapvec[1], entrytracker));
                        summary_vec.push_back(s);
                    }
                }

                // Get the wrapper, if one exists, default to empty if it doesn't
                wrapper_name = structdata->getKeyAsString("wrapper", "");

                if (structdata->hasKey("regex")) {
                    regexdata = structdata->getStructuredByKey("regex");
                }
            } catch(const StructuredDataException e) {
                concls->response_stream << "Invalid request: ";
                concls->response_stream << e.what();
                concls->httpcode = 400;
                return 1;
            }

            // Wrapper we insert under
            SharedTrackerElement wrapper = NULL;

            // DT fields
            SharedTrackerElement dt_length_elem = NULL;
            SharedTrackerElement dt_filter_elem = NULL;

            // Rename cache generated during simplification
            TrackerElementSerializer::rename_map rename_map;

            SharedTrackerElement outdevs =
                globalreg->entrytracker->GetTrackedInstance(device_list_base_id);

            unsigned int dt_start = 0;
            unsigned int dt_length = 0;
            int dt_draw = 0;

            int in_dt_length, in_dt_start;

            // Search string
            string dt_search;

            // Resolved paths to fields we search
            vector<vector<int> > dt_search_paths;
            
            unsigned int dt_order_col = -1;
            int dt_order_dir = 0;
            vector<int> dt_order_field;

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

                // If we're searching, we need to figure out what columns are
                // searchable.  Because of how we have to map names into datatables,
                // we don't get a usable field definition from the dt js plugin,
                // BUT we DO get a usable fieldspec from our fields list that
                // we already processed... so we have to make a slightly funky
                // assumption that columns[x] is equivalent to summary_vec[x],
                // and then we just pull the parsed-int field path in for our
                // searching mechanism
                if (dt_search.length() != 0) {
                    // fprintf(stderr, "debug - searching for '%s'\n", dt_search.c_str());
                    std::stringstream sstr;

                    // We have to act like an array and iterate through the
                    // column fields...  We use the summary vec length as a 
                    // quick cheat
                    for (unsigned int ci = 0; ci < summary_vec.size(); ci++) {
                        sstr.str("");
                        sstr << "columns[" << ci << "][searchable]";
                        map<string, std::unique_ptr<std::stringstream> >::iterator mi;
                        if ((mi = concls->variable_cache.find(sstr.str())) !=
                                concls->variable_cache.end()) {
                            if (mi->second->str() == "true") {
                                // We can blindly trust the offset b/c we're 
                                // iterating from our summary vec size, not the
                                // form data
                                dt_search_paths.push_back(summary_vec[ci]->resolved_path);
                            }
                        } else {
                            // If we've run out of columns to look at for some
                            // reason just bail instead of doing more string 
                            // construction
                            break;
                        }
                    }

                }
                
                // We only handle sorting by the first column
                if (concls->variable_cache.find("order[0][column]") !=
                        concls->variable_cache.end()) {
                    *(concls->variable_cache["order[0][column]"]) >> dt_order_col;
                }

                // Don't allow ordering by a column that doesn't make sense
                if (dt_order_col >= summary_vec.size())
                    dt_order_col = -1;

                if (dt_order_col >= 0 &&
                        concls->variable_cache.find("order[0][dir]") !=
                        concls->variable_cache.end()) {
                    string ord = concls->variable_cache["order[0][dir]"]->str();

                    if (ord == "asc")
                        dt_order_dir = 1;

                    dt_order_field = summary_vec[dt_order_col]->resolved_path;
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
                SharedTrackerElement pcredevs =
                    globalreg->entrytracker->GetTrackedInstance(device_list_base_id);
                TrackerElementVector pcrevec(pcredevs);

                devicetracker_pcre_worker worker(globalreg, regexdata, pcredevs);
                MatchOnDevices(&worker);
                
                // Check DT ranges
                if (dt_start >= pcrevec.size())
                    dt_start = 0;

                if (dt_filter_elem != NULL)
                    dt_filter_elem->set((uint64_t) pcrevec.size());

                // Sort the list by the selected column
                if (dt_order_col >= 0) {
                    kismet__stable_sort(pcrevec.begin(), pcrevec.end(), 
                            [&](SharedTrackerElement a, SharedTrackerElement b) {
                            SharedTrackerElement fa =
                                GetTrackerElementPath(dt_order_field, a);
                            SharedTrackerElement fb =
                                GetTrackerElementPath(dt_order_field, b);

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

                    SummarizeTrackerElement(entrytracker,
                            (*vi), summary_vec,
                            simple, rename_map);

                    outdevs->add_vector(simple);
                }
            } else if (dt_search_paths.size() != 0) {
                // Otherwise, we're doing a search inside a datatables query,
                // so go through every device and do a search on every element
                // which we have flagged as searchable, and which is a string or
                // mac which we can treat as a string.
                SharedTrackerElement matchdevs =
                    globalreg->entrytracker->GetTrackedInstance(device_list_base_id);
                TrackerElementVector matchvec(matchdevs);

                devicetracker_stringmatch_worker worker(globalreg, dt_search, 
                        dt_search_paths, matchdevs);
                MatchOnDevices(&worker);
                
                if (dt_order_col >= 0) {
                    kismet__stable_sort(matchvec.begin(), matchvec.end(), 
                            [&](SharedTrackerElement a, SharedTrackerElement b) {
                            SharedTrackerElement fa =
                                GetTrackerElementPath(dt_order_field, a);
                            SharedTrackerElement fb =
                                GetTrackerElementPath(dt_order_field, b);

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

                    SummarizeTrackerElement(entrytracker,
                            (*vi), summary_vec,
                            simple, rename_map);

                    outdevs->add_vector(simple);
                }
            } else {
                // Otherwise we use the complete list
                //
                // Check DT ranges
                if (dt_start >= tracked_vec.size())
                    dt_start = 0;

                if (dt_filter_elem != NULL)
                    dt_filter_elem->set((uint64_t) tracked_vec.size());

                if (dt_order_col >= 0) {
                    kismet__stable_sort(tracked_vec.begin(), tracked_vec.end(), 
                            [&](SharedTrackerElement a, SharedTrackerElement b) {
                            SharedTrackerElement fa =
                                GetTrackerElementPath(dt_order_field, a);
                            SharedTrackerElement fb =
                                GetTrackerElementPath(dt_order_field, b);

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

            entrytracker->Serialize(httpd->GetSuffix(tokenurl[3]), concls->response_stream, 
                    wrapper, &rename_map);
            return 1;

        } else if (tokenurl[2] == "last-time") {
            if (tokenurl.size() < 5) {
                // fprintf(stderr, "debug - couldn't parse ts\n");
                concls->response_stream << "Invalid request";
                concls->httpcode = 400;
                return 1;
            }

            // Is the timestamp an int?
            long lastts;
            if (sscanf(tokenurl[3].c_str(), "%ld", &lastts) != 1 ||
                    !Httpd_CanSerialize(tokenurl[4])) {
                // fprintf(stderr, "debug - couldn't parse/deserialize\n");
                concls->response_stream << "Invalid request";
                concls->httpcode = 400;
                return 1;
            }

            // We always wrap in a map
            SharedTrackerElement wrapper(new TrackerElement(TrackerMap));

            SharedTrackerElement refresh =
                globalreg->entrytracker->GetTrackedInstance(device_update_required_id);

            // If we've changed the list more recently, we have to do a refresh
            if (lastts < full_refresh_time) {
                refresh->set((uint8_t) 1);
            } else {
                refresh->set((uint8_t) 0);
            }

            wrapper->add_map(refresh);

            SharedTrackerElement updatets =
                globalreg->entrytracker->GetTrackedInstance(device_update_timestamp_id);
            updatets->set((int64_t) globalreg->timestamp.tv_sec);

            wrapper->add_map(updatets);

            // Rename cache generated during simplification
            TrackerElementSerializer::rename_map rename_map;

            // Create the device vector of all devices, and simplify it
            SharedTrackerElement sourcedevs =
                globalreg->entrytracker->GetTrackedInstance(device_list_base_id);
            TrackerElementVector sourcevec(sourcedevs);

            if (regexdata != NULL) {
                devicetracker_pcre_worker worker(globalreg, regexdata, sourcedevs);
                MatchOnDevices(&worker);
            }

            SharedTrackerElement outdevs =
                globalreg->entrytracker->GetTrackedInstance(device_list_base_id);

            if (regexdata != NULL) {
                // If we filtered, that's our list
                TrackerElementVector::iterator vi;
                for (vi = sourcevec.begin(); vi != sourcevec.end(); ++vi) {
                    shared_ptr<kis_tracked_device_base> vid =
                        static_pointer_cast<kis_tracked_device_base>(*vi);

                    if (vid->get_last_time() > lastts) {
                        SharedTrackerElement simple;

                        SummarizeTrackerElement(entrytracker,
                                (*vi), summary_vec,
                                simple, rename_map);

                        outdevs->add_vector(simple);
                    }
                }
            } else {
                // Otherwise we use the complete list
                vector<shared_ptr<kis_tracked_device_base> >::iterator vi;
                for (vi = tracked_vec.begin(); vi != tracked_vec.end(); ++vi) {
                    if ((*vi)->get_last_time() > lastts) {
                        SharedTrackerElement simple;

                        SummarizeTrackerElement(entrytracker,
                                (*vi), summary_vec,
                                simple, rename_map);

                        outdevs->add_vector(simple);
                    }
                }
            }

            // Put the simplified map in the vector
            wrapper->add_map(outdevs);

            entrytracker->Serialize(httpd->GetSuffix(tokenurl[4]), 
                    concls->response_stream, wrapper, &rename_map);
            return MHD_YES;
        }
    }

    concls->response_stream << "OK";

    return MHD_YES;
}

