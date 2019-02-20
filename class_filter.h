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

#include "packetchain.h"
#include "packet.h"

#include "trackedcomponent.h"

// Common class-based filter mechanism which can be used in multiple locations;
// implements basic default behavior and REST endpoints.
//
// Filters act on 'true' results:  Default behavior of 'true' defaults to BLOCKING
// the action, behavior of 'false' defaults to PASSING actions.

class Classfilter : public tracker_component {
public:
    Classfilter(const std::string& in_id, const std::string& in_description,
            const std::string& in_type);

    virtual ~Classfilter() {
        local_locker l(&mutex);
    }

    __ProxyGet(filter_id, std::string, std::string, filter_id);
    __ProxyGet(filter_description, std::string, std::string, filter_description);
    __ProxyGet(filter_type, std::string, std::string, filter_type);
    __Proxy(filter_default, uint8_t, bool, bool, filter_default);

    // Filtering actions are custom per subclass

protected:
    bool filterstring_to_bool(const std::string& str);

    __ProxySet(filter_id, std::string, std::string, filter_id);
    __ProxySet(filter_description, std::string, std::string, filter_description);
    __ProxySet(filter_type, std::string, std::string, filter_type);

    virtual void register_fields() override {
        tracker_component::register_fields();

        RegisterField("kismet.classfilter.id", "Filter ID/Endpoint", &filter_id);
        RegisterField("kismet.classfilter.description", "Filter description", &filter_description);
        RegisterField("kismet.classfilter.type", "Filter mechanism", &filter_type);
        RegisterField("kismet.classfilter.default", "Default filter (pass/reject)", &filter_default);
    }

    kis_recursive_timed_mutex mutex;

    std::string base_uri;

    std::shared_ptr<TrackerElementString> filter_id;
    std::shared_ptr<TrackerElementString> filter_description;
    std::shared_ptr<TrackerElementString> filter_type;
    std::shared_ptr<TrackerElementUInt8> filter_default;

    // Default endpoint
    std::shared_ptr<Kis_Net_Httpd_Simple_Post_Endpoint> default_endp;
    int default_set_endp_handler(std::ostream& stream, SharedStructured post_structured);

    // Default display endpoint
    std::shared_ptr<Kis_Net_Httpd_Simple_Tracked_Endpoint> self_endp;
    // Build the return object; subfilters must implement this to bypass class hierarchy & call
    // build_self_content
    virtual std::shared_ptr<TrackerElementMap> self_endp_handler() = 0;
    // Cascading build
    virtual void build_self_content(std::shared_ptr<TrackerElementMap> content);
};

// MAC based filter
class ClassfilterMacaddr : public Classfilter {
public:
    ClassfilterMacaddr(const std::string& in_id, const std::string& in_descripton);
    virtual ~ClassfilterMacaddr() {}

    virtual bool filter(mac_addr in_mac);

    virtual void set_filter(mac_addr in_mac, const std::string& in_phy, bool value);
    virtual void remove_filter(mac_addr in_mac, const std::string& in_phy);

protected:
    virtual void register_fields() override {
        Classfilter::register_fields();

        RegisterField("kismet.classfilter.macaddr.addresses",
                "MAC address filters", &filter_block);

        filter_sub_phy_id = 
            RegisterField("kismet.classfilter.macaddr.phyname",
                    TrackerElementFactory<TrackerElementString>(),
                    "Applied PHY name for MAC");
        filter_sub_value_id =
            RegisterField("kismet.classfilter.macaddr.value",
                    TrackerElementFactory<TrackerElementUInt8>(),
                    "Filter value");
    }

    std::shared_ptr<TrackerElementMacMap> filter_block;

    int filter_sub_phy_id, filter_sub_value_id;

    // Address management endpoint keyed on path
    std::shared_ptr<Kis_Net_Httpd_Path_Post_Endpoint> macaddr_edit_endp;
    unsigned int edit_endp_handler(std::ostream& stream, const std::vector<std::string>& path, 
            SharedStructured structured);

    std::shared_ptr<Kis_Net_Httpd_Path_Post_Endpoint> macaddr_remove_endp;
    unsigned int remove_endp_handler(std::ostream& stream, const std::vector<std::string> &path,
            SharedStructured structured);

    virtual std::shared_ptr<TrackerElementMap> self_endp_handler() override;
    virtual void build_self_content(std::shared_ptr<TrackerElementMap> content) override;

};

