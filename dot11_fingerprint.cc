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

#include "dot11_fingerprint.h"
#include "configfile.h"
#include "fmt.h"

dot11_fingerprint_tracker::dot11_fingerprint_tracker(const std::string& in_uri) {
    mutex.set_name("dot11_fingerprint_tracker");

    using namespace std::placeholders;

    base_uri = str_tokenize(in_uri, "/");

    // Tokenized paths begin with / which yields a blank [0] element, so trim that
    if (base_uri.size())
        base_uri = std::vector<std::string>(base_uri.begin() + 1, base_uri.end());

    fingerprint_endp =
        std::make_shared<kis_net_httpd_simple_tracked_endpoint>(in_uri + "/all_fingerprints", 
                fingerprint_map, &mutex);

    update_endp =
        std::make_shared<kis_net_httpd_path_post_endpoint>(
                [this](const std::vector<std::string>& path, const std::string& uri) -> bool {
                    return std::get<0>(post_path(path)) != uri_endpoint::endp_unknown;
                }, 
                [this](std::ostream& stream, const std::vector<std::string>& path,
                    const std::string& uri, const Json::Value& json,
                    kis_net_httpd_connection::variable_cache_map& variable_cache) -> unsigned int {
                    return mod_dispatch(stream, path, json);
                }, &mutex);
}

dot11_fingerprint_tracker::dot11_fingerprint_tracker(const std::string& in_uri,
    const std::string& in_config, const std::string& in_confvalue) {
    using namespace std::placeholders;

    base_uri = str_tokenize(in_uri, "/");

    // Tokenized paths begin with / which yields a blank [0] element, so trim that
    if (base_uri.size())
        base_uri = std::vector<std::string>(base_uri.begin() + 1, base_uri.end());

    fingerprint_endp =
        std::make_shared<kis_net_httpd_simple_tracked_endpoint>(in_uri + "/all_fingerprints", 
                fingerprint_map, &mutex);

    update_endp =
        std::make_shared<kis_net_httpd_path_post_endpoint>(
                [this](const std::vector<std::string>& path, const std::string& uri) -> bool {
                    return std::get<0>(post_path(path)) != uri_endpoint::endp_unknown;
                }, 
                [this](std::ostream& stream, const std::vector<std::string>& path,
                    const std::string& uri, const Json::Value& json,
                    kis_net_httpd_connection::variable_cache_map& variable_cache) -> unsigned int {
                    return mod_dispatch(stream, path, json);
                }, &mutex);

    configfile = std::make_shared<config_file>();
    configpath = configfile->expand_log_path(in_config);
    configvalue = in_confvalue;
    configfile->parse_config(in_config);
}

dot11_fingerprint_tracker::~dot11_fingerprint_tracker() {
    if (configfile != nullptr)
        configfile->save_config(configpath);
}

std::tuple<dot11_fingerprint_tracker::uri_endpoint, mac_addr>
dot11_fingerprint_tracker::post_path(const std::vector<std::string>& path) {
    // Match against the base URI path
    if (path.size() <= base_uri.size())
        return std::make_tuple(uri_endpoint::endp_unknown, mac_addr {0});

    if (!std::equal(base_uri.begin(), base_uri.end(), path.begin()))
        return std::make_tuple(uri_endpoint::endp_unknown, mac_addr {0});

    // Compare against the sub-paths
    unsigned int path_offt = base_uri.size();

    // .../new/insert.cmd
    // .../bulk/insert.cmd
    // .../bulk/delete.cmd

    if (path.size() < path_offt + 2)
        return std::make_tuple(uri_endpoint::endp_unknown, mac_addr {0});

    if (path[path_offt] == "new") 
        if (path[path_offt + 1] == "insert") 
            return std::make_tuple(uri_endpoint::endp_insert, mac_addr {0});

    if (path[path_offt] == "bulk") {
        if (path[path_offt + 1] == "insert")
            return std::make_tuple(uri_endpoint::endp_bulk_insert, mac_addr {0});

        if (path[path_offt + 1] == "delete")
            return std::make_tuple(uri_endpoint::endp_bulk_delete, mac_addr {0});
    }

    // .../by-mac/[mac]/update.cmd
    // .../by-mac/[mac]/delete.cmd

    if (path.size() < path_offt + 3)
        return std::make_tuple(uri_endpoint::endp_unknown, mac_addr {0});

    if (path[path_offt] == "by-mac") {
        mac_addr m {path[path_offt + 1]};

        if (m.state.error)
            return std::make_tuple(uri_endpoint::endp_unknown, mac_addr {0});

        if (fingerprint_map->find(m) == fingerprint_map->end())
            return std::make_tuple(uri_endpoint::endp_unknown, mac_addr {0});

        if (path[path_offt + 2] == "update")
            return std::make_tuple(uri_endpoint::endp_update, mac_addr {0});

        if (path[path_offt + 2] == "delete")
            return std::make_tuple(uri_endpoint::endp_delete, mac_addr {0});
    }

    return std::make_tuple(uri_endpoint::endp_unknown, mac_addr {0});
}

unsigned int dot11_fingerprint_tracker::mod_dispatch(std::ostream& stream,
        const std::vector<std::string>& path, const Json::Value& json) {

    auto path_extract = post_path(path);

    switch (std::get<0>(path_extract)) {
        case uri_endpoint::endp_unknown:
            stream << "Unhandled endpoint\n";
            return 401;
        case uri_endpoint::endp_update:
            return update_fingerprint(stream, std::get<1>(path_extract), json);
        case uri_endpoint::endp_insert:
            return insert_fingerprint(stream, json);
        case uri_endpoint::endp_delete:
            return delete_fingerprint(stream, std::get<1>(path_extract), json);
        case uri_endpoint::endp_bulk_insert:
            return bulk_insert_fingerprint(stream, json);
        case uri_endpoint::endp_bulk_delete:
            return bulk_delete_fingerprint(stream, json);
        default:
            stream << "Unknown endpoint\n";
            return 401;
    }

    return 401;
}

unsigned int dot11_fingerprint_tracker::update_fingerprint(std::ostream &stream, mac_addr mac, 
        const Json::Value& json) {

    auto fpi = fingerprint_map->find(mac);

    if (fpi == fingerprint_map->end()) {
        stream << "Could not find fingerprint to update\n";
        return 500;
    }

    auto fp = std::static_pointer_cast<tracked_dot11_fingerprint>(fpi->second);

    try {
        if (!json["beacon_hash"].isNull())
            fp->set_beacon_hash(json["beacon_hash"].asUInt());

        if (!json["response_hash"].isNull())
            fp->set_response_hash(json["response_hash"].asUInt());

        if (!json["probe_hash"].isNull())
            fp->set_response_hash(json["probe_hash"].asUInt());

        rebuild_config();

        stream << "Fingerprint updated\n";
        return 200;

    } catch (const std::exception& e) {
        stream << "Malformed update: " << e.what() << "\n";
        return 500;
    }

    stream << "Unhandled command\n";
    return 500;
}

unsigned int dot11_fingerprint_tracker::insert_fingerprint(std::ostream& stream, const Json::Value& json) {
    try {
        auto mac = mac_addr(json["macaddr"].asString());

        if (mac.state.error)
            throw std::runtime_error("Invalid 'macaddr' field in insert command");

        auto fpi = fingerprint_map->find(mac);

        if (fpi != fingerprint_map->end())
            throw std::runtime_error("Fingerprint MAC address already exists, delete or edit "
                    "it instead.");

        auto fp = std::make_shared<tracked_dot11_fingerprint>();

        fp->set_probe_hash(json.get("beacon_hash", 0).asUInt());
        fp->set_response_hash(json.get("response_hash", 0).asUInt());
        fp->set_probe_hash(json.get("probe_hash", 0).asUInt());

        fingerprint_map->insert(std::make_pair(mac, fp));

        rebuild_config();

        stream << "Fingerprint added\n";
        return 200;

    } catch (const std::exception& e) {
        stream << "Malformed insert: " << e.what() << "\n";
        return 500;
    }

    stream << "Unhandled command\n";
    return 500;
}

unsigned int dot11_fingerprint_tracker::delete_fingerprint(std::ostream& stream, mac_addr mac,
        const Json::Value& json) {

    auto fpi = fingerprint_map->find(mac);

    if (fpi == fingerprint_map->end()) {
        stream << "Could not find target MAC to delete\n";
        return 500;
    }

    fingerprint_map->erase(fpi);

    rebuild_config();

    stream << "Fingerprint deleted\n";
    return 200;
}

unsigned int dot11_fingerprint_tracker::bulk_delete_fingerprint(std::ostream& stream, const Json::Value& json) {

    try {
        int num_erased = 0;

        if (!json["fingerprints"].isArray())
            throw std::runtime_error("Expected fingerprints as array");

        for (auto fpi : json["fingerprints"]) {
            mac_addr mac { fpi.asString() };

            if (mac.state.error)
                throw std::runtime_error(fmt::format("Invalid MAC address: {}",
                            kishttpd::escape_html(fpi.asString())));

            auto fmi = fingerprint_map->find(mac);

            if (fmi == fingerprint_map->end())
                continue;

            fingerprint_map->erase(fmi);

            num_erased++;
        }

        rebuild_config();

        stream << "Erased " << num_erased << " fingerprints\n";
        return 200;
    } catch (const std::exception& e) {
        stream << "Erasing fingerprints failed: " << e.what() << "\n";
        return 500;
    }

    stream << "Unhandled command\n";
    return 500;
}

unsigned int dot11_fingerprint_tracker::bulk_insert_fingerprint(std::ostream& stream, const Json::Value& json) {

    try {
        int num_added = 0;

        if (!json["fingerprints"].isArray())
            throw std::runtime_error("Expected fingerprints as array");

        for (auto fpi : json["fingerprints"]) {
            // Get the sub-dictionarys from the vector
            mac_addr mac { fpi.asString() };

            if (mac.state.error)
                throw std::runtime_error(fmt::format("Invalid MAC address: {}",
                            kishttpd::escape_html(fpi.asString())));

            // Make sure it doesn't exist
            auto fmi = fingerprint_map->find(mac);
            if (fmi != fingerprint_map->end())
                throw std::runtime_error(fmt::format("MAC address {} already present in "
                            "fingerprint list", kishttpd::escape_html(mac.as_string())));

            auto fp = std::make_shared<tracked_dot11_fingerprint>();

            fp->set_probe_hash(fpi.get("beacon_hash", 0).asUInt());
            fp->set_response_hash(fpi.get("response_hash", 0).asUInt());
            fp->set_probe_hash(fpi.get("probe_hash", 0).asUInt());

            fingerprint_map->insert(std::make_pair(mac, fp));
            num_added++;
        }

        rebuild_config();

        stream << "Inserted " << num_added << " fingerprints\n";
        return 200;
    } catch (const std::runtime_error& e) {
        stream << "Error: " << e.what() << "\n";
        return 500;
    }

    stream << "Unhandled command\n";
    return 500;
}

std::shared_ptr<tracked_dot11_fingerprint> dot11_fingerprint_tracker::get_fingerprint(const mac_addr& mac) {
    auto fmi = fingerprint_map->find(mac);

    if (fmi == fingerprint_map->end())
        return nullptr;

    return std::static_pointer_cast<tracked_dot11_fingerprint>(fmi->second);
}

void dot11_fingerprint_tracker::rebuild_config() {
    local_locker l(&mutex);

    if (configfile == nullptr)
        return;

    auto v = std::vector<std::string>{};

    for (auto fpi : *fingerprint_map) {
        auto fp = std::static_pointer_cast<tracked_dot11_fingerprint>(fpi.second);
        v.push_back(fp->as_config_complex(fpi.first).to_string());
    }

    configfile->set_opt_vec(configvalue, v, true);
    configfile->save_config(configpath);
}


