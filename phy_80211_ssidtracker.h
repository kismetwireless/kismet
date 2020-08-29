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
        mutex.set_name("dot11_tracked_ssid_group internal");
        register_fields();
        reserve_fields(NULL);
    }

    dot11_tracked_ssid_group(int in_id) : 
        tracker_component(in_id) { 
        mutex.set_name("dot11_tracked_ssid_group internal");
        register_fields();
        reserve_fields(NULL);
    } 

    dot11_tracked_ssid_group(int in_id, std::shared_ptr<tracker_element_map> e) : 
        tracker_component(in_id) {
        mutex.set_name("dot11_tracked_ssid_group internal");
        register_fields();
        reserve_fields(e);
    }

    dot11_tracked_ssid_group(const dot11_tracked_ssid_group *p) :
        tracker_component{p} {

        ssid_hash = tracker_element_clone_adaptor(p->ssid_hash);
        ssid = tracker_element_clone_adaptor(p->ssid);
        ssid_len = tracker_element_clone_adaptor(p->ssid_len);
        crypt_set = tracker_element_clone_adaptor(p->crypt_set);
        advertising_device_map = tracker_element_clone_adaptor(p->advertising_device_map);
        responding_device_map = tracker_element_clone_adaptor(p->responding_device_map);
        probing_device_map = tracker_element_clone_adaptor(p->probing_device_map);
        advertising_device_len = tracker_element_clone_adaptor(p->advertising_device_len);
        responding_device_len = tracker_element_clone_adaptor(p->responding_device_len);
        probing_device_len = tracker_element_clone_adaptor(p->probing_device_len);
        first_time = tracker_element_clone_adaptor(p->first_time);
        last_time = tracker_element_clone_adaptor(p->last_time);

        reserve_fields(nullptr);
    }

    dot11_tracked_ssid_group(int in_id, const std::string& in_ssid, unsigned int in_ssid_len,
            unsigned int in_crypt_set);

    virtual uint32_t get_signature() const override {
        return adler32_checksum("dot11_tracked_ssid_group");
    }

    virtual std::unique_ptr<tracker_element> clone_type() override {
        using this_t = std::remove_pointer<decltype(this)>::type;
        auto dup = std::unique_ptr<this_t>(new this_t(this));
        return std::move(dup);
    }

    __Proxy(ssid_hash, uint64_t, uint64_t, uint64_t, ssid_hash);
    __Proxy(ssid, std::string, std::string, std::string, ssid);
    __Proxy(ssid_len, uint32_t, uint32_t, uint32_t, ssid_len);
    __Proxy(crypt_set, uint64_t, uint64_t, uint64_t, crypt_set);

    __Proxy(first_time, uint64_t, time_t, time_t, first_time);
    __Proxy(last_time, uint64_t, time_t, time_t, last_time);

    __Proxy(advertising_device_len, uint64_t, uint64_t, uint64_t, advertising_device_len);
    __Proxy(probing_device_len, uint64_t, uint64_t, uint64_t, probing_device_len);
    __Proxy(responding_device_len, uint64_t, uint64_t, uint64_t, responding_device_len);

    void add_advertising_device(std::shared_ptr<kis_tracked_device_base> device);
    void add_probing_device(std::shared_ptr<kis_tracked_device_base> device);
    void add_responding_device(std::shared_ptr<kis_tracked_device_base> device);

    virtual void pre_serialize() override {
        // We have to protect our maps so we lock around them
        local_eol_locker el(&mutex);

        set_advertising_device_len(advertising_device_map->size());
        set_probing_device_len(probing_device_map->size());
        set_responding_device_len(responding_device_map->size());
    }

    virtual void post_serialize() override {
        local_unlocker ul(&mutex);
    }

protected:
    kis_recursive_timed_mutex mutex;

    virtual void register_fields() override;
    virtual void reserve_fields(std::shared_ptr<tracker_element_map> e) override;

    std::shared_ptr<tracker_element_uint64> ssid_hash;

    std::shared_ptr<tracker_element_string> ssid;
    std::shared_ptr<tracker_element_uint32> ssid_len;

    std::shared_ptr<tracker_element_uint64> crypt_set;

    // Maps contain nullptr values, and are used only as a fast way to indicate which device keys are
    // present.  We don't need to actually track a full link to the dependent device, and we'd rather avoid
    // it because then that would add more dependencies for timing out devices and whatnot.
    std::shared_ptr<tracker_element_device_key_map> advertising_device_map;
    std::shared_ptr<tracker_element_device_key_map> responding_device_map;
    std::shared_ptr<tracker_element_device_key_map> probing_device_map;

    std::shared_ptr<tracker_element_uint64> advertising_device_len;
    std::shared_ptr<tracker_element_uint64> responding_device_len;
    std::shared_ptr<tracker_element_uint64> probing_device_len;

    std::shared_ptr<tracker_element_uint64> first_time;
    std::shared_ptr<tracker_element_uint64> last_time;
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

    void handle_broadcast_ssid(const std::string& ssid, unsigned int ssid_len, uint64_t crypt_set, 
            std::shared_ptr<kis_tracked_device_base> device);
    void handle_response_ssid(const std::string& ssid, unsigned int ssid_len, uint64_t crypt_set, 
            std::shared_ptr<kis_tracked_device_base> device);
    void handle_probe_ssid(const std::string& ssid, unsigned int ssid_len, uint64_t crypt_set, 
            std::shared_ptr<kis_tracked_device_base> device);

protected:
    kis_recursive_timed_mutex mutex;

    std::unordered_map<size_t, std::shared_ptr<dot11_tracked_ssid_group>> ssid_map;
    std::shared_ptr<tracker_element_vector> ssid_vector;

    int tracked_ssid_id;

    std::shared_ptr<kis_net_httpd_simple_post_endpoint> ssid_endp;
    unsigned int ssid_endpoint_handler(std::ostream& stream, const std::string& uri,
            const Json::Value& json, kis_net_httpd_connection::variable_cache_map& postvars);

    std::shared_ptr<kis_net_httpd_path_tracked_endpoint> detail_endp;
    bool detail_endpoint_path(const std::vector<std::string>& path);
    std::shared_ptr<tracker_element> detail_endpoint_handler(const std::vector<std::string>& path);

    int cleanup_timer_id;

    bool ssid_tracking_enabled;

};

#endif /* ifndef PHY_80211_SSIDTRACKER */
