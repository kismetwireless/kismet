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
#include "eventbus.h"
#include "kis_net_beast_httpd.h"

// Common class-based filter mechanism which can be used in multiple locations;
// implements basic default behavior and REST endpoints.
//
// Filters act on 'true' results:  Default behavior of 'true' defaults to BLOCKING
// the action, behavior of 'false' defaults to PASSING actions.

class class_filter : public tracker_component {
public:
    class_filter(const std::string& in_id, const std::string& in_description,
            const std::string& in_type);

    virtual ~class_filter() { }

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

        register_field("kismet.classfilter.id", "Filter ID/Endpoint", &filter_id);
        register_field("kismet.classfilter.description", "Filter description", &filter_description);
        register_field("kismet.classfilter.type", "Filter mechanism", &filter_type);
        register_field("kismet.classfilter.default", "Default filter (pass/reject)", &filter_default);
    }

    kis_mutex mutex;

    std::string base_uri;

    std::shared_ptr<tracker_element_string> filter_id;
    std::shared_ptr<tracker_element_string> filter_description;
    std::shared_ptr<tracker_element_string> filter_type;
    std::shared_ptr<tracker_element_uint8> filter_default;

    // Default endpoint
    void default_set_endp_handler(std::shared_ptr<kis_net_beast_httpd_connection> con);

    // Build the return object; subfilters must implement this to bypass class hierarchy & call
    // build_self_content
    virtual std::shared_ptr<tracker_element_map> self_endp_handler() = 0;
    // Cascading build
    virtual void build_self_content(std::shared_ptr<tracker_element_map> content);
};

// MAC based filter
class class_filter_mac_addr : public class_filter {
public:
    class_filter_mac_addr(const std::string& in_id, const std::string& in_descripton);
    virtual ~class_filter_mac_addr();

    virtual bool filter(mac_addr in_mac, unsigned int in_phy);

    virtual void set_filter(mac_addr in_mac, const std::string& in_phy, bool value);
    virtual void remove_filter(mac_addr in_mac, const std::string& in_phy);

protected:
	std::shared_ptr<device_tracker> devicetracker;
	std::shared_ptr<event_bus> eventbus;
	unsigned long eb_id;

	void update_phy_map(std::shared_ptr<eventbus_event> evt);

	// Filters are stored in integer-indexed local form, but also a constructed tiered
	// map for presentation out the rest interface:
	// map[string, phy] -> map[mac, boolean].

    virtual void register_fields() override {
        class_filter::register_fields();

		// Phy-based map
        register_field("kismet.classfilter.macaddr.address_by_phy",
                "MAC address filters", &filter_phy_block);

        // Mac based map filter_sub_mac_id =
        register_field("kismet.classfilter.macaddr.filter_block",
                tracker_element_factory<tracker_element_macfilter_map>(),
                "MAC address filters");

		// Filter value
        filter_sub_value_id =
            register_field("kismet.classfilter.macaddr.value",
                    tracker_element_factory<tracker_element_uint8>(),
                    "Filter value");
    }

	std::shared_ptr<tracker_element_string_map> filter_phy_block;

	// Nested phy types
    int filter_sub_mac_id, filter_sub_value_id;

	// Internal fast lookup tables per-phy we use for actual filtering
	std::map<int, std::map<mac_addr, bool>> phy_mac_filter_map;

	// Internal unknown phy map for filters registered before we had a phy ID
	std::map<std::string, std::map<mac_addr, bool>> unknown_phy_mac_filter_map;

    // Address management endpoint keyed on path
    void edit_endp_handler(std::shared_ptr<kis_net_beast_httpd_connection> con);
    void remove_endp_handler(std::shared_ptr<kis_net_beast_httpd_connection> con);

    virtual std::shared_ptr<tracker_element_map> self_endp_handler() override;
    virtual void build_self_content(std::shared_ptr<tracker_element_map> content) override;

};

