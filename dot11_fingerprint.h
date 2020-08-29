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

#ifndef __DOT11_FINGERPRINT_H__
#define __DOT11_FINGERPRINT_H__

#include "config.h"

#include "configfile.h"
#include "kis_mutex.h"
#include "trackedelement.h"
#include "trackedcomponent.h"
#include "kis_net_microhttpd.h"

class tracked_dot11_fingerprint : public tracker_component {
public:
    tracked_dot11_fingerprint() :
        tracker_component{} {
        register_fields();
        reserve_fields(nullptr);
    }

    tracked_dot11_fingerprint(int in_id) :
        tracker_component{in_id} {
        register_fields();
        reserve_fields(nullptr);
    }

    tracked_dot11_fingerprint(int in_id, std::shared_ptr<tracker_element_map> e) :
        tracker_component{in_id} {
        register_fields();
        reserve_fields(e);
    }

    tracked_dot11_fingerprint(const tracked_dot11_fingerprint *p) :
        tracker_component{p} {

        __ImportField(beacon_hash, p);
        __ImportField(response_hash, p);
        __ImportField(probe_hash, p);

        reserve_fields(nullptr);
    }

    virtual std::unique_ptr<tracker_element> clone_type() override {
        using this_t = std::remove_pointer<decltype(this)>::type;
        auto dup = std::unique_ptr<this_t>(new this_t(this));
        return std::move(dup);
    }

    virtual ~tracked_dot11_fingerprint() { }

    __Proxy(beacon_hash, uint32_t, uint32_t, uint32_t, beacon_hash);
    __Proxy(response_hash, uint32_t, uint32_t, uint32_t, response_hash);
    __Proxy(probe_hash, uint32_t, uint32_t, uint32_t, probe_hash);

    // Turn it into a complex config line
    header_value_config as_config_complex(mac_addr m) {
        header_value_config hc;
        hc.set_header(m.as_string());
        hc.set_value("beacon_hash", get_beacon_hash());
        hc.set_value("response_hash", get_response_hash());

        return hc;
    };

    // Quick compare; a 0-hash indicates a do-not-compare op
    bool match(uint32_t beacon, uint32_t response, uint32_t probe) const {
        if (beacon != 0)
            if (get_beacon_hash() != beacon)
                return false;

        if (response != 0)
            if (get_response_hash() != response)
                return false;

        if (probe != 0)
            if (get_probe_hash() != probe)
                return false;

        return true;
    }

protected:
    virtual void register_fields() override {
        tracker_component::register_fields();

        register_field("kismet.dot11.fingerprint.beacon_hash", "Beacon hash", &beacon_hash);
        register_field("kismet.dot11.fingerprint.response_hash", "Response hash", &response_hash);
        register_field("ksimet.dot11.fingerprint.probe_hash", "Probe hash", &probe_hash);
    }

    std::shared_ptr<tracker_element_uint32> beacon_hash;
    std::shared_ptr<tracker_element_uint32> response_hash;
    std::shared_ptr<tracker_element_uint32> probe_hash;
};


// Generate a dot11 fingerprint tracker on a provided endpoint and with a provided backing file for
// storage.  This allows multiple fingerprint instances to be generated eg for alerts, whitelisting,
// and other types.
// The URI directory should be a non-slash-terminated full path, such as:
// /phy/phy80211/whitelist
class dot11_fingerprint_tracker {
public:
    // Simple list of endpoints the post_path can return
    enum class uri_endpoint {
        endp_unknown,
        endp_update, endp_insert, endp_delete, endp_bulk_insert, endp_bulk_delete
    };

    dot11_fingerprint_tracker(const std::string& uri_dir);
    dot11_fingerprint_tracker(const std::string& uri_dir, const std::string& config_file, 
            const std::string& config_value);
    virtual ~dot11_fingerprint_tracker();

    // Process the post path and return the type and target, or a tuple of uri_endpoint::endp_unknown
    // if it doesn't exist
    std::tuple<uri_endpoint, mac_addr> post_path(const std::vector<std::string>& path);
  
    // Dispatch function based on URI
    unsigned int mod_dispatch(std::ostream& stream, const std::vector<std::string>& path, const Json::Value& json);

    // Fingerprint manipulation; all of these are called w/in the mutex lock held by 
    // the simple tracked and simple post endpoints
    unsigned int update_fingerprint(std::ostream& stream, mac_addr mac, const Json::Value& json);
    unsigned int insert_fingerprint(std::ostream& stream, const Json::Value& json);
    unsigned int delete_fingerprint(std::ostream& stream, mac_addr mac, const Json::Value& json);
    unsigned int bulk_delete_fingerprint(std::ostream& stream, const Json::Value& json);
    unsigned int bulk_insert_fingerprint(std::ostream& stream, const Json::Value& json);

    // Fetch a fingerprint, return nullptr if fingerprint not found
    std::shared_ptr<tracked_dot11_fingerprint> get_fingerprint(const mac_addr& mac);

protected:
    void rebuild_config();

    kis_recursive_timed_mutex mutex;

    std::string configpath;
    std::string configvalue;
    std::shared_ptr<config_file> configfile;

    std::vector<std::string> base_uri;

    std::shared_ptr<tracker_element_mac_map> fingerprint_map;

    std::shared_ptr<kis_net_httpd_simple_tracked_endpoint> fingerprint_endp;
    std::shared_ptr<kis_net_httpd_path_post_endpoint> update_endp;

};

#endif

