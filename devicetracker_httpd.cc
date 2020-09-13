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
#include "json_adapter.h"
#include "base64.h"

// HTTP interfaces
bool device_tracker::httpd_verify_path(const char *path, const char *method) {
    if (strcmp(method, "GET") == 0) {
        // Simple fixed URLS

        std::string stripped = httpd_strip_suffix(path);

        // Explicit compare for .ekjson because it doesn't serialize the 
        // same way
        if (strcmp(path, "/devices/all_devices.ekjson") == 0)
            return true;

        // Split URL and process
        std::vector<std::string> tokenurl = str_tokenize(path, "/");
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

                device_key key(tokenurl[3]);

                if (key.get_error())
                    return false;

                if (!httpd_can_serialize(tokenurl[4]))
                    return false;

                auto tmi = fetch_device(key);

                if (tmi == NULL)
                    return false;

                std::string target = httpd_strip_suffix(tokenurl[4]);

                if (target == "device") {
                    // Try to find the exact field
                    if (tokenurl.size() > 5) {
                        std::vector<std::string>::const_iterator first = tokenurl.begin() + 5;
                        std::vector<std::string>::const_iterator last = tokenurl.end();
                        std::vector<std::string> fpath(first, last);

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

                if (!httpd_can_serialize(tokenurl[4]))
                    return false;

                mac_addr mac = mac_addr(tokenurl[3]);

                if (mac.state.error) {
                    return false;
                }

                { 
                    local_shared_locker devlock(&devicelist_mutex);

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

                // Explicit catch of ekjson and itjson
                if (tokenurl[4] == "devices.ekjson" || tokenurl[4] == "devices.itjson")
                    return true;

                return httpd_can_serialize(tokenurl[4]);
            }
        }
    } else if (strcmp(method, "POST") == 0) {
        // Split URL and process
        std::vector<std::string> tokenurl = str_tokenize(path, "/");
        if (tokenurl.size() < 2)
            return false;

        if (tokenurl[1] == "devices") {
            if (tokenurl.size() < 4) {
                return false;
            } else if (tokenurl[2] == "last-time") {
                if (tokenurl.size() < 5) {
                    return false;
                }

                long lastts;
                if (sscanf(tokenurl[3].c_str(), "%ld", &lastts) != 1) {
                    fprintf(stderr, "debug - unable to parse ts\n");
                    return false;
                }

                return httpd_can_serialize(tokenurl[4]);
            } else if (tokenurl[2] == "by-key") {
                if (tokenurl.size() < 5) {
                    return false;
                }

                device_key key(tokenurl[3]);

                if (key.get_error())
                    return false;

                if (!httpd_can_serialize(tokenurl[4]))
                    return false;

                if (fetch_device(key) == NULL)
                    return false;

                std::string target = httpd_strip_suffix(tokenurl[4]);

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

                if (!httpd_can_serialize(tokenurl[4]))
                    return false;

                mac_addr mac = mac_addr(tokenurl[3]);

                if (mac.state.error) {
                    return false;
                }

                {
                    local_shared_locker listlocker(&devicelist_mutex);
                    if (tracked_mac_multimap.count(mac) > 0)
                        return true;
                }

                return false;
            }
        }
    }

    return false;
}

KIS_MHD_RETURN device_tracker::httpd_create_stream_response(
        kis_net_httpd *httpd __attribute__((unused)),
        kis_net_httpd_connection *connection,
        const char *path, const char *method, const char *upload_data,
        size_t *upload_data_size) {

    // fmt::print(stderr, "createstreamresponse path {}\n", path);

    if (strcmp(method, "GET") != 0) {
        return MHD_YES;
    }

    // Allocate our buffer aux
    kis_net_httpd_buffer_stream_aux *saux = 
        (kis_net_httpd_buffer_stream_aux *) connection->custom_extension;

    buffer_handler_ostringstream_buf *streambuf = 
        new buffer_handler_ostringstream_buf(saux->get_rbhandler());
    std::ostream stream(streambuf);

    // Set our cleanup function
    saux->set_aux(streambuf, 
            [](kis_net_httpd_buffer_stream_aux *aux) {
                if (aux->aux != NULL)
                    delete((buffer_handler_ostringstream_buf *) (aux->aux));
            });

    // Set our sync function which is called by the webserver side before we
    // clean up...
    saux->set_sync([](kis_net_httpd_buffer_stream_aux *aux) {
            if (aux->aux != NULL) {
                ((buffer_handler_ostringstream_buf *) aux->aux)->pubsync();
                }
            });


    if (strcmp(path, "/devices/all_devices.ekjson") == 0) {
        // Instantiate a manual serializer
        ek_json_adapter::serializer serial; 

        // Copy the vector of devices for stability
        std::shared_ptr<tracker_element_vector> device_ro = std::make_shared<tracker_element_vector>();

        {
            local_locker l(&devicelist_mutex);
            device_ro->set(immutable_tracked_vec->begin(), immutable_tracked_vec->end());
        }

        serial.serialize(device_ro, stream);
        return MHD_YES;
    }

    std::string stripped = httpd_strip_suffix(path);

    // fmt::print(stderr, "tokenizing path {}\n", path);

    std::vector<std::string> tokenurl = str_tokenize(path, "/");

    // fmt::print(stderr, "path {} tokenized to size {}\n", path, tokenurl.size());

    if (tokenurl.size() < 2) {
        return MHD_YES;
    }

    if (tokenurl[1] == "devices") {
        if (tokenurl.size() < 5)
            return MHD_YES;

        if (tokenurl[2] == "by-key") {
            if (tokenurl.size() < 5) {
                _MSG_ERROR("HTTP request for {}; invalid by-key URI", path);
                stream << "Invalid by-key URI\n";
                connection->httpcode = 500;
                return MHD_YES;
            }

            if (!httpd_can_serialize(tokenurl[4])) {
                _MSG_ERROR("HTTP request for {}; can't actually serialize.", path);
                connection->httpcode = 500;
                return MHD_YES;
            }

            device_key key(tokenurl[3]);
            auto dev = fetch_device(key);

            if (dev == nullptr) {
                _MSG_ERROR("HTTP request for {}; invalid device key {}", path, tokenurl[3]);
                stream << "Invalid device key\n";
                connection->httpcode = 500;
                return MHD_YES;
            }

            std::string target = httpd_strip_suffix(tokenurl[4]);

            if (target == "device") {
                // Try to find the exact field
                if (tokenurl.size() > 5) {
                    std::vector<std::string>::const_iterator first = tokenurl.begin() + 5;
                    std::vector<std::string>::const_iterator last = tokenurl.end();
                    std::vector<std::string> fpath(first, last);

                    local_shared_locker devlocker(&(dev->device_mutex));

                    shared_tracker_element sub = dev->get_child_path(fpath);

                    if (sub == nullptr) {
                        _MSG_ERROR("HTTP request for {}; could not map child path to a device record node.", path);
                        stream << "Invalid sub-key path\n";
                        connection->httpcode = 500;
                        return MHD_YES;
                    } 

                    // Set the mime component of the url
                    connection->mime_url = tokenurl[4];

                    Globalreg::globalreg->entrytracker->serialize(httpd->get_suffix(tokenurl[4]), stream, sub, NULL);
                    return MHD_YES;
                }

                Globalreg::globalreg->entrytracker->serialize(httpd->get_suffix(tokenurl[4]), stream, dev, NULL);
                // fmt::print(stderr, "Wrote data for key {}", key);

                return MHD_YES;
            } else {
                stream << "<h1>Server error</h1>Unhandled by-key target.";
                connection->httpcode = 500;
                return MHD_YES;
            }
        } else if (tokenurl[2] == "by-mac") {
            if (tokenurl.size() < 5)
                return MHD_YES;

            if (!httpd_can_serialize(tokenurl[4]))
                return MHD_YES;

            local_shared_locker lock(&devicelist_mutex);

            mac_addr mac = mac_addr(tokenurl[3]);

            if (mac.state.error) {
                return MHD_YES;
            }

            auto devvec = std::make_shared<tracker_element_vector>();

            const auto& mmp = tracked_mac_multimap.equal_range(mac);
            for (auto mmpi = mmp.first; mmpi != mmp.second; ++mmpi) {
                devvec->push_back(mmpi->second);
            }

            Globalreg::globalreg->entrytracker->serialize(httpd->get_suffix(tokenurl[4]), stream, devvec, NULL);

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

            if (!httpd_can_serialize(tokenurl[4]))
                return MHD_YES;

            std::shared_ptr<tracker_element_vector> devvec;

            device_tracker_view_function_worker fw(
                    [devvec, lastts](std::shared_ptr<kis_tracked_device_base> d) -> bool {
                        if (d->get_last_time() <= lastts)
                            return false;

                        return true;
                    });
            devvec = do_readonly_device_work(fw);

            Globalreg::globalreg->entrytracker->serialize(httpd->get_suffix(tokenurl[4]), stream, devvec, NULL);

            return MHD_YES;
        }

    }

    return MHD_YES;
}

KIS_MHD_RETURN device_tracker::httpd_post_complete(kis_net_httpd_connection *concls) {
    // Split URL and process
    std::vector<std::string> tokenurl = str_tokenize(concls->url, "/");

    auto saux = (kis_net_httpd_buffer_stream_aux *) concls->custom_extension;
    auto streambuf = new buffer_handler_ostringstream_buf(saux->get_rbhandler());

    std::ostream stream(streambuf);

    saux->set_aux(streambuf, 
            [](kis_net_httpd_buffer_stream_aux *aux) {
                if (aux->aux != NULL)
                    delete((buffer_handler_ostringstream_buf *) (aux->aux));
            });

    // Set our sync function which is called by the webserver side before we
    // clean up...
    saux->set_sync([](kis_net_httpd_buffer_stream_aux *aux) {
            if (aux->aux != NULL) {
                ((buffer_handler_ostringstream_buf *) aux->aux)->pubsync();
                }
            });

    // All URLs are at least /devices/by-foo/y/x
    if (tokenurl.size() < 4) {
        stream << "Invalid request";
        concls->httpcode = 400;
        return MHD_YES;
    }

    // Common structured API data
    Json::Value json;

    // Wrapper, if any
    std::string wrapper_name;

    // Rename cache generated during simplification
    auto rename_map = std::make_shared<tracker_element_serializer::rename_map>();

    Json::Value regexdata;

    try {
        if (concls->variable_cache.find("json") != 
                concls->variable_cache.end()) {
            
            json = concls->variable_cache_as<Json::Value>("json");
        } else {
            throw std::runtime_error("Missing data; expected command dictionary in json= POST variable");
        }
    } catch(const std::exception& e) {
        stream << "Invalid request: " << e.what();
        concls->httpcode = 400;
        return MHD_YES;
    }

    try {
        // Get the wrapper, if one exists, default to empty if it doesn't
        wrapper_name = json.get("wrapper", "").asString();

        regexdata = json["regex"];
    } catch(const std::exception& e) {
        stream << "Invalid request: Malformed command dictionary, " << e.what();
        concls->httpcode = 400;
        return MHD_YES;
    }

    try {
        if (tokenurl[1] == "devices") {
            if (tokenurl[2] == "by-mac") {
                if (tokenurl.size() < 5) {
                    stream << "Invalid request: Invalid URI\n";
                    concls->httpcode = 400;
                    return MHD_YES;
                }

                local_demand_locker lock(&devicelist_mutex);

                if (!httpd_can_serialize(tokenurl[4])) {
                    stream << "Invalid request: Cannot find serializer for file type\n";
                    concls->httpcode = 400;
                    return MHD_YES;
                }

                mac_addr mac = mac_addr(tokenurl[3]);

                
                if (mac.state.error) {
                    stream << "Invalid request: Invalid MAC address\n";
                    concls->httpcode = 400;
                    return MHD_YES;
                }

                lock.lock();
                if (tracked_mac_multimap.count(mac) == 0) {
                    stream << "Invalid request: Could not find device by MAC\n";
                    concls->httpcode = 400;
                    return MHD_YES;
                }
                lock.unlock();

                std::string target = httpd_strip_suffix(tokenurl[4]);

                if (target == "devices") {
                    auto devvec = std::make_shared<tracker_element_vector>();

                    lock.lock();
                    auto mmp = tracked_mac_multimap.equal_range(mac);
                    lock.unlock();

                    for (auto mmpi = mmp.first; mmpi != mmp.second; ++mmpi) 
                        devvec->push_back(kishttpd::summarize_with_json(mmpi->second, json, rename_map));

                    Globalreg::globalreg->entrytracker->serialize(httpd->get_suffix(tokenurl[4]), stream, 
                            devvec, rename_map);

                    return MHD_YES;
                }

                stream << "Invalid request\n";
                concls->httpcode = 400;
                return MHD_YES;
            } else if (tokenurl[2] == "by-key") {
                if (tokenurl.size() < 5) {
                    stream << "Invalid request: Invalid URI\n";
                    concls->httpcode = 400;
                    return MHD_YES;
                }

                if (!httpd_can_serialize(tokenurl[4])) {
                    stream << "Invalid request: Cannot serialize field type\n";
                    concls->httpcode = 400;
                    return MHD_YES;
                }

                device_key key(tokenurl[3]);

                auto dev = fetch_device(key);

                if (dev == NULL) {
                    stream << "Invalid request: No device with that key\n";
                    concls->httpcode = 400;
                    return MHD_YES;
                }

                std::string target = httpd_strip_suffix(tokenurl[4]);

                if (target == "device") {
                    local_shared_locker devlock(&(dev->device_mutex));

                    auto simple = 
                        kishttpd::summarize_with_json(dev, json, rename_map);

                    Globalreg::globalreg->entrytracker->serialize(httpd->get_suffix(tokenurl[4]), 
                            stream, simple, rename_map);

                    return MHD_YES;
                }

                if (target == "set_name") {
                    auto name = json["username"].asString();

                    set_device_user_name(dev, name);

                    stream << "OK\n";
                    return MHD_YES;
                }

                if (target == "set_tag") {
                    auto tag = json["tagname"].asString();
                    auto content = json["tagvalue"].asString();

                    set_device_tag(dev, tag, content);

                    stream << "OK\n";
                    return MHD_YES;
                }

            } else if (tokenurl[2] == "last-time") {
                // We don't lock the device list since we use workers

                if (tokenurl.size() < 5) {
                    stream << "Invalid request\n";
                    concls->httpcode = 400;
                    return MHD_YES;
                }

                // Is the timestamp an int?
                long lastts;
                if (sscanf(tokenurl[3].c_str(), "%ld", &lastts) != 1 ||
                        !httpd_can_serialize(tokenurl[4])) {
                    stream << "Invalid request\n";
                    concls->httpcode = 400;
                    return MHD_YES;
                }

                // If it's negative, subtract from the current ts
                if (lastts < 0) {
                    time_t now = time(0);
                    lastts = now + lastts;
                }

                // Rename cache generated during simplification
                auto rename_map = std::make_shared<tracker_element_serializer::rename_map>();

                // List of devices that pass the timestamp filter
                std::shared_ptr<tracker_element_vector> timedevs;

                //  List of devices that pass the regex filter
                auto regexdevs = std::make_shared<tracker_element_vector>();

                device_tracker_view_function_worker tw(
                        [lastts](std::shared_ptr<kis_tracked_device_base> d) -> bool {

                        if (d->get_last_time() <= lastts)
                            return false;

                        return true;
                        });
                timedevs = do_readonly_device_work(tw);

                if (!regexdata.isNull()) {
                    device_tracker_view_regex_worker worker(regexdata);
                    regexdevs = do_readonly_device_work(worker, timedevs);
                } else {
                    regexdevs = timedevs;
                }

                // Final devices being simplified and sent out
                auto outdevs = std::make_shared<tracker_element_vector>();

                for (const auto& rei : *regexdevs) {
                    auto rd = std::static_pointer_cast<kis_tracked_device_base>(rei);
                    local_shared_locker lock(&rd->device_mutex);

                    outdevs->push_back(kishttpd::summarize_with_json(rd, json, rename_map));
                }

                Globalreg::globalreg->entrytracker->serialize(httpd->get_suffix(tokenurl[4]), stream, 
                        outdevs, rename_map);
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

unsigned int device_tracker::multimac_endp_handler(std::ostream& stream, const std::string& uri,
        const Json::Value& json, kis_net_httpd_connection::variable_cache_map& variable_cache) {

    try {
        auto ret_devices = std::make_shared<tracker_element_vector>();
        auto macs = std::vector<mac_addr>{};

        if (json["devices"].isNull())
            throw std::runtime_error("Missing 'devices' key in command dictionary");
        
        for (auto m : json["devices"]) {
            mac_addr ma{m.asString()};

            if (ma.state.error) 
                throw std::runtime_error(fmt::format("Invalid MAC address '{}' in 'devices' list",
                            kishttpd::escape_html(m.asString())));

            macs.push_back(ma);
        }

        // Duplicate the mac index so that we're 'immune' to things changing it under us; because we
        // may have quite a number of devices in our query list, this is safest.
        local_demand_locker l(&devicelist_mutex);
        l.lock();
        auto immutable_copy = 
            std::multimap<mac_addr, std::shared_ptr<kis_tracked_device_base>>{tracked_mac_multimap};
        l.unlock();

        // Pull all the devices out of the list
        for (auto m : macs) {
            const auto& mi = immutable_copy.equal_range(m);
            for (auto msi = mi.first; msi != mi.second; ++msi)
                ret_devices->push_back(msi->second);
        }

        // Summarize it all at once
        auto rename_map = std::make_shared<tracker_element_serializer::rename_map>();

        auto output = 
            kishttpd::summarize_with_json(ret_devices, json, rename_map);

        Globalreg::globalreg->entrytracker->serialize(kishttpd::get_suffix(uri), stream, output, rename_map);

        return 200;

    } catch (const std::exception& e) {
        stream << "Invalid request: " << e.what() << "\n";
        return 500;
    }

    stream << "Unhandled request\n";
    return 500;
}

std::shared_ptr<tracker_element> device_tracker::all_phys_endp_handler() {
    auto ret_vec = 
        std::make_shared<tracker_element_vector>();

    for (auto i : phy_handler_map) {
        auto tracked_phy =
            std::make_shared<tracker_element_map>(phy_phyentry_id);

        auto tracked_name =
            std::make_shared<tracker_element_string>(phy_phyname_id, i.second->fetch_phy_name());
        auto tracked_id =
            std::make_shared<tracker_element_uint32>(phy_phyid_id, i.second->fetch_phy_id());
        auto tracked_dev_count =
            std::make_shared<tracker_element_uint64>(phy_devices_count_id);
        auto tracked_packet_count =
            std::make_shared<tracker_element_uint64>(phy_packets_count_id, phy_packets[i.second->fetch_phy_id()]);

        auto pv_key = phy_view_map.find(i.second->fetch_phy_id());
        if (pv_key != phy_view_map.end())
            tracked_dev_count->set(pv_key->second->get_list_sz());

        tracked_phy->insert(tracked_name);
        tracked_phy->insert(tracked_id);
        tracked_phy->insert(tracked_dev_count);
        tracked_phy->insert(tracked_packet_count);

        ret_vec->push_back(tracked_phy);

    }

    return ret_vec;
}

unsigned int device_tracker::multikey_endp_handler(std::ostream& stream, const std::string& uri,
        const Json::Value& json, kis_net_httpd_connection::variable_cache_map& variable_cache) {

    try {
        auto ret_devices = std::make_shared<tracker_element_vector>();
        auto keys = std::vector<device_key>{};

        if (json["devices"].isNull())
            throw std::runtime_error("Missing 'devices' key in command dictionary");
       
        for (auto k : json["devices"]) {
            device_key ka{k.asString()};

            if (ka.get_error()) 
                throw std::runtime_error(fmt::format("Invalid device key '{}' in 'devices' list",
                            kishttpd::escape_html(k.asString())));

            keys.push_back(ka);
        }

        for (auto k : keys) { 
            auto d = fetch_device(k);

            if (d == nullptr)
                continue;

            ret_devices->push_back(d);
        }

        for (auto d : *ret_devices)
            std::static_pointer_cast<kis_tracked_device_base>(d)->lock();

        auto rename_map = std::make_shared<tracker_element_serializer::rename_map>();

        auto output = 
            kishttpd::summarize_with_json(ret_devices, json, rename_map);

        Globalreg::globalreg->entrytracker->serialize(kishttpd::get_suffix(uri), stream, output, rename_map);

        for (auto d : *ret_devices)
            std::static_pointer_cast<kis_tracked_device_base>(d)->unlock();

        return 200;

    } catch (const std::exception& e) {
        stream << "Invalid request: " << e.what() << "\n";
        return 500;
    }

    stream << "Unhandled request\n";
    return 500;
}

unsigned int device_tracker::multikey_dict_endp_handler(std::ostream& stream, const std::string& uri,
        const Json::Value& json, kis_net_httpd_connection::variable_cache_map& variable_cache) {

    try {
        auto ret_devices = std::make_shared<tracker_element_device_key_map>();
        auto keys = std::vector<device_key>{};

        if (json["devices"].isNull())
            throw std::runtime_error("Missing 'devices' key in command dictionary");
       
        for (auto k : json["devices"]) {
            device_key ka{k.asString()};

            if (ka.get_error()) 
                throw std::runtime_error(fmt::format("Invalid device key '{}' in 'devices' list",
                            kishttpd::escape_html(k.asString())));

            keys.push_back(ka);
        }

        for (auto k : keys) { 
            auto d = fetch_device(k);

            if (d == nullptr)
                continue;

            ret_devices->insert(k, d);
        }

        // Explicitly lock all devices during serialziation
        for (auto d : *ret_devices)
            std::static_pointer_cast<kis_tracked_device_base>(d.second)->lock();

        auto rename_map = std::make_shared<tracker_element_serializer::rename_map>();

        auto output = 
            kishttpd::summarize_with_json(ret_devices, json, rename_map);

        Globalreg::globalreg->entrytracker->serialize(kishttpd::get_suffix(uri), stream, output, rename_map);

        for (auto d : *ret_devices)
            std::static_pointer_cast<kis_tracked_device_base>(d.second)->unlock();

        return 200;

    } catch (const std::exception& e) {
        stream << "Invalid request: " << e.what() << "\n";
        return 500;
    }

    stream << "Unhandled request\n";
    return 500;
}

