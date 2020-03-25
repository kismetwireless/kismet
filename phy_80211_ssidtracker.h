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

#ifndef __PHY_80211_SSIDTRACKER__
#define __PHY_80211_SSIDTRACKER__ 

#include "config.h"

#include <functional>
#include <unordered_map>

#include "devicetracker.h"
#include "devicetracker_component.h"

#include "globalregistry.h"

#include "kis_mutex.h"
#include "kis_net_microhttpd.h"


// Tracked SSID group; a ssid, who has beaconed, probed, and responded for it,
// as well as the last time anything tried to talk to it
class dot11_tracked_ssid_group : public tracker_component {
public:
    dot11_tracked_ssid_group() :
        tracker_component() {
        register_fields();
        reserve_fields(NULL);
    }

    dot11_tracked_ssid_group(int in_id) : 
        tracker_component(in_id) { 
            register_fields();
            reserve_fields(NULL);
        } 

    dot11_tracked_ssid_group(int in_id, std::shared_ptr<tracker_element_map> e) : 
        tracker_component(in_id) {
            register_fields();
            reserve_fields(e);
        }

    virtual uint32_t get_signature() const override {
        return adler32_checksum("dot11_tracked_ssid_group");
    }

    virtual std::unique_ptr<tracker_element> clone_type() override {
        using this_t = std::remove_pointer<decltype(this)>::type;
        auto dup = std::unique_ptr<this_t>(new this_t());
        return std::move(dup);
    }

    virtual std::unique_ptr<tracker_element> clone_type(int in_id) override {
        using this_t = std::remove_pointer<decltype(this)>::type;
        auto dup = std::unique_ptr<this_t>(new this_t(in_id));
        return std::move(dup);
    }

    __Proxy(ssid_hash, size_t, uint64_t, uint64_t, ssid_hash);
    __Proxy(ssid, std::string, std::string, std::string, ssid);
    __Proxy(ssid_len, uint32_t, unsigned int, unsigned int, ssid_len);
    __Proxy(crypt_set, uint64_t, uint64_t, uint64_t, crypt_set);

    __Proxy(first_seen, uint64_t, time_t, time_t, first_seen);
    __Proxy(last_seen, uint64_t, time_t, time_t, last_seen);

protected:
    virtual void register_fields() override;

    std::shared_ptr<tracker_element_uint64> ssid_hash;

    std::shared_ptr<tracker_element_string> ssid;
    std::shared_ptr<tracker_element_uint32> ssid_len;

    std::shared_ptr<tracker_element_uint64> crypt_set;

    std::shared_ptr<tracker_element_device_key_map> advertising_device_map;
    std::shared_ptr<tracker_element_device_key_map> responding_device_map;
    std::shared_ptr<tracker_element_device_key_map> probing_device_map;

    std::shared_ptr<tracker_element_uint64> first_seen;
    std::shared_ptr<tracker_element_uint64> last_seen;
};

class phy_80211_ssid_tracker : public lifetime_global {
public:
    static std::string global_name() { return "DOT11_SSID_TRACKER"; }

    static std::shared_ptr<phy_80211_ssid_tracker> create_dot11_ssidtracker() {
        std::shared_ptr<phy_80211_ssid_tracker> mon(new phy_80211_ssid_tracker());
        Globalreg::globalreg->register_lifetime_global(mon);
        Globalreg::globalreg->insert_global(global_name(), mon);
        return mon;
    }

private:
    phy_80211_ssid_tracker();

public:
    virtual ~phy_80211_ssid_tracker();

protected:
    kis_recursive_timed_mutex mutex;

    std::unordered_map<size_t, std::shared_ptr<dot11_tracked_ssid_group>> ssid_map;
    std::shared_ptr<tracker_element_vector> ssid_vector;

    int tracked_ssid_id;

    std::shared_ptr<kis_net_httpd_simple_post_endpoint> ssid_endp;

    unsigned int ssid_endpoint_handler(std::ostream& stream, const std::string& uri,
            shared_structured structured,
            kis_net_httpd_connection::variable_cache_map& postvars);

    int cleanup_timer_id;

    bool ssid_tracking_enabled;

};

#endif /* ifndef PHY_80211_SSIDTRACKER */
