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

Dot11FingerprintTracker::Dot11FingerprintTracker(const std::string& in_uri) {
    using namespace std::placeholders;

    base_uri = StrTokenize(in_uri, "/");

    // Tokenized paths begin with / which yields a blank [0] element, so trim that
    if (base_uri.size())
        base_uri = std::vector<std::string>(base_uri.begin() + 1, base_uri.end());

    fingerprint_endp =
        std::make_shared<Kis_Net_Httpd_Simple_Tracked_Endpoint>(in_uri + "/all_fingerprints", 
                fingerprint_map, &mutex);

    update_endp =
        std::make_shared<Kis_Net_Httpd_Path_Post_Endpoint>(
                [this](const std::vector<std::string>& path, const std::string& uri) -> bool {
                    return std::get<0>(post_path(path)) != uri_endpoint::endp_unknown;
                }, 
                [this](std::ostream& stream, const std::vector<std::string>& path,
                    const std::string& uri, SharedStructured post_structured,
                    Kis_Net_Httpd_Connection::variable_cache_map& variable_cache) -> unsigned int {
                    return mod_dispatch(stream, path, post_structured);
                }, &mutex);
}

Dot11FingerprintTracker::Dot11FingerprintTracker(const std::string& in_uri,
    const std::string& in_config, const std::string& in_confvalue) {
    using namespace std::placeholders;

    base_uri = StrTokenize(in_uri, "/");

    // Tokenized paths begin with / which yields a blank [0] element, so trim that
    if (base_uri.size())
        base_uri = std::vector<std::string>(base_uri.begin() + 1, base_uri.end());

    fingerprint_endp =
        std::make_shared<Kis_Net_Httpd_Simple_Tracked_Endpoint>(in_uri + "/all_fingerprints", 
                fingerprint_map, &mutex);

    update_endp =
        std::make_shared<Kis_Net_Httpd_Path_Post_Endpoint>(
                [this](const std::vector<std::string>& path, const std::string& uri) -> bool {
                    return std::get<0>(post_path(path)) != uri_endpoint::endp_unknown;
                }, 
                [this](std::ostream& stream, const std::vector<std::string>& path,
                    const std::string& uri, SharedStructured post_structured,
                    Kis_Net_Httpd_Connection::variable_cache_map& variable_cache) -> unsigned int {
                    return mod_dispatch(stream, path, post_structured);
                }, &mutex);

    configfile = std::make_shared<ConfigFile>();
    configpath = configfile->ExpandLogPath(in_config);
    configvalue = in_confvalue;
    configfile->ParseConfig(in_config);
}

Dot11FingerprintTracker::~Dot11FingerprintTracker() {
    if (configfile != nullptr)
        configfile->SaveConfig(configpath);
}

std::tuple<Dot11FingerprintTracker::uri_endpoint, mac_addr>
Dot11FingerprintTracker::post_path(const std::vector<std::string>& path) {
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

        if (m.error)
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

unsigned int Dot11FingerprintTracker::mod_dispatch(std::ostream& stream,
        const std::vector<std::string>& path, SharedStructured structured) {

    auto path_extract = post_path(path);

    switch (std::get<0>(path_extract)) {
        case uri_endpoint::endp_unknown:
            stream << "Unhandled endpoint\n";
            return 401;
        case uri_endpoint::endp_update:
            return update_fingerprint(stream, std::get<1>(path_extract), structured);
        case uri_endpoint::endp_insert:
            return insert_fingerprint(stream, structured);
        case uri_endpoint::endp_delete:
            return delete_fingerprint(stream, std::get<1>(path_extract), structured);
        case uri_endpoint::endp_bulk_insert:
            return bulk_insert_fingerprint(stream, structured);
        case uri_endpoint::endp_bulk_delete:
            return bulk_delete_fingerprint(stream, structured);
        default:
            stream << "Unknown endpoint\n";
            return 401;
    }

    return 401;
}

unsigned int Dot11FingerprintTracker::update_fingerprint(std::ostream &stream,
        mac_addr mac, SharedStructured structured) {

    auto fpi = fingerprint_map->find(mac);

    if (fpi == fingerprint_map->end()) {
        stream << "Could not find fingerprint to update\n";
        return 500;
    }

    auto fp = std::static_pointer_cast<tracked_dot11_fingerprint>(fpi->second);

    try {
        if (structured->hasKey("beacon_hash"))
            fp->set_beacon_hash(structured->getKeyAsNumber("beacon_hash"));

        if (structured->hasKey("response_hash"))
            fp->set_response_hash(structured->getKeyAsNumber("response_hash"));

        if (structured->hasKey("probe_hash"))
            fp->set_probe_hash(structured->getKeyAsNumber("probe_hash"));

        rebuild_config();

        stream << "Fingerprint updated\n";
        return 200;

    } catch (const StructuredDataException& e) {
        stream << "Malformed update: " << e.what() << "\n";
        return 500;
    }

    stream << "Unhandled command\n";
    return 500;
}

unsigned int Dot11FingerprintTracker::insert_fingerprint(std::ostream& stream, 
        SharedStructured structured) {
    try {
        if (!structured->hasKey("macaddr"))
            throw StructuredDataException("Missing 'macaddr' field in insert command");

        auto mac = mac_addr { structured->getKeyAsString("macaddr") };
        if (mac.error)
            throw StructuredDataException("Invalid 'macaddr' field in insert command");

        auto fpi = fingerprint_map->find(mac);

        if (fpi != fingerprint_map->end())
            throw StructuredDataException("Fingerprint MAC address already exists, delete or edit "
                    "it instead.");

        auto fp = std::make_shared<tracked_dot11_fingerprint>();

        fp->set_probe_hash(structured->getKeyAsNumber("beacon_hash", 0));
        fp->set_response_hash(structured->getKeyAsNumber("response_hash", 0));
        fp->set_probe_hash(structured->getKeyAsNumber("probe_hash", 0));

        fingerprint_map->insert(std::make_pair(mac, fp));

        rebuild_config();

        stream << "Fingerprint added\n";
        return 200;

    } catch (const StructuredDataException& e) {
        stream << "Malformed insert: " << e.what() << "\n";
        return 500;
    }

    stream << "Unhandled command\n";
    return 500;
}

unsigned int Dot11FingerprintTracker::delete_fingerprint(std::ostream& stream, mac_addr mac,
        SharedStructured structured) {

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

unsigned int Dot11FingerprintTracker::bulk_delete_fingerprint(std::ostream& stream, 
        SharedStructured structured) {

    try {
        auto fpv = structured->getStructuredByKey("fingerprints");
        auto fingerprints = fpv->getStringVec();

        int num_erased = 0;

        for (auto fpi : fingerprints) {
            mac_addr mac { fpi };

            if (mac.error)
                throw StructuredDataException("Invalid MAC address");

            auto fmi = fingerprint_map->find(mac);

            if (fmi == fingerprint_map->end())
                continue;

            fingerprint_map->erase(fmi);

            num_erased++;
        }

        rebuild_config();

        stream << "Erased " << num_erased << " fingerprints\n";
        return 200;
    } catch (const StructuredDataException& e) {
        stream << "Erasing fingerprints failed: " << e.what() << "\n";
        return 500;
    }

    stream << "Unhandled command\n";
    return 500;
}

unsigned int Dot11FingerprintTracker::bulk_insert_fingerprint(std::ostream& stream,
        SharedStructured structured) {

    try {
        auto fpv = structured->getStructuredByKey("fingerprints");
        auto fingerprints = fpv->getStructuredArray();

        int num_added = 0;

        for (auto fpi : fingerprints) {
            // Get the sub-dictionarys from the vector
            if (!fpi->hasKey("macaddr"))
                throw StructuredDataException("Fingerprint dictionary missing 'macaddr'");

            auto mac = mac_addr { fpi->getKeyAsString("macaddr") };
            if (mac.error)
                throw StructuredDataException("Invalid MAC address in 'macaddr'");

            // Make sure it doesn't exist
            auto fmi = fingerprint_map->find(mac);
            if (fmi != fingerprint_map->end())
                throw StructuredDataException(fmt::format("MAC address {} already present in "
                            "fingerprint list", mac));

            auto fp = std::make_shared<tracked_dot11_fingerprint>();

            fp->set_probe_hash(fpi->getKeyAsNumber("beacon_hash", 0));
            fp->set_response_hash(fpi->getKeyAsNumber("response_hash", 0));
            fp->set_probe_hash(fpi->getKeyAsNumber("probe_hash", 0));

            fingerprint_map->insert(std::make_pair(mac, fp));
            num_added++;
        }

        rebuild_config();

        stream << "Inserted " << num_added << " fingerprints\n";
        return 200;
    } catch (const StructuredDataException& e) {
        stream << "Error: " << e.what() << "\n";
        return 500;
    }

    stream << "Unhandled command\n";
    return 500;
}

std::shared_ptr<tracked_dot11_fingerprint> Dot11FingerprintTracker::get_fingerprint(const mac_addr& mac) {
    auto fmi = fingerprint_map->find(mac);

    if (fmi == fingerprint_map->end())
        return nullptr;

    return std::static_pointer_cast<tracked_dot11_fingerprint>(fmi->second);
}

void Dot11FingerprintTracker::rebuild_config() {
    local_locker l(&mutex);

    if (configfile == nullptr)
        return;

    auto v = std::vector<std::string>{};

    for (auto fpi : *fingerprint_map) {
        auto fp = std::static_pointer_cast<tracked_dot11_fingerprint>(fpi.second);
        v.push_back(fp->asConfigComplex(fpi.first).toString());
    }

    configfile->SetOptVec(configvalue, v, true);
    configfile->SaveConfig(configpath);
}


