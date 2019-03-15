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

// Common packet filter mechanism which can be used in multiple locations;
// implements basic default behavior, filtering by address, and REST endpoints.
//
// Filters act on 'true' results:  Default behavior of 'true' defaults to BLOCKING packets.
// Default behavior of 'false' defaults to PASSING packets.

class Packetfilter : public tracker_component {
public:
    Packetfilter(const std::string& in_id, const std::string& in_description,
            const std::string& in_type);

    virtual ~Packetfilter() {
        local_locker l(&mutex);
    }

    __ProxyGet(filter_id, std::string, std::string, filter_id);
    __ProxyGet(filter_description, std::string, std::string, filter_description);
    __ProxyGet(filter_type, std::string, std::string, filter_type);
    __Proxy(filter_default, uint8_t, bool, bool, filter_default);

    virtual bool filter_packet(kis_packet *packet) = 0;

protected:
    bool filterstring_to_bool(const std::string& str);

    __ProxySet(filter_id, std::string, std::string, filter_id);
    __ProxySet(filter_description, std::string, std::string, filter_description);
    __ProxySet(filter_type, std::string, std::string, filter_type);

    virtual void register_fields() override {
        tracker_component::register_fields();

        RegisterField("kismet.packetfilter.id", "Filter ID/Endpoint", &filter_id);
        RegisterField("kismet.packetfilter.description", "Filter description", &filter_description);
        RegisterField("kismet.packetfilter.type", "Filter mechanism", &filter_type);
        RegisterField("kismet.packetfilter.default", "Default filter (pass/reject)", &filter_default);
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
    // Build the return object; subfilters must implement this to bypass class heirarchy & call
    // build_self_content
    virtual std::shared_ptr<TrackerElementMap> self_endp_handler() = 0;
    // Cascading build
    virtual void build_self_content(std::shared_ptr<TrackerElementMap> content);
};

// Mac-address based filter.
// Filters can be applied to 'ANY', source, destination, network, or transmitter
// (in wifi terms, source, dest, bssid, or 4mac transmitter for wds).
// Filters are true (filter/reject packet), or false (pass packet).  Packets not matched
// by any filter are passed to the default filter term.
class PacketfilterMacaddr : public Packetfilter {
public:
    PacketfilterMacaddr(const std::string& in_id, const std::string& in_description);
    virtual ~PacketfilterMacaddr();

    virtual bool filter_packet(kis_packet *packet) override;

    // We use strings for blocks here for maximum flexibility in the future since
    // *adding* a filter should be a relatively non-realtime task
    virtual void set_filter(mac_addr in_mac, const std::string& in_phy,
            const std::string& in_block, bool value);
    virtual void remove_filter(mac_addr in_mac, const std::string &in_phy,
            const std::string& in_block);

protected:
    virtual void register_fields() override {
        Packetfilter::register_fields();

		// Phy-based map
        RegisterField("kismet.packetfilter.macaddr.blocks_by_phy",
                "MAC address filters", &filter_phy_blocks);

        filter_sub_value_id =
            RegisterField("kismet.packetfilter.macaddr.value",
                    TrackerElementFactory<TrackerElementUInt8>(),
                    "Filter value");

        filter_source_id =
            RegisterField("kismet.packetfilter.macaddr.source", 
                    TrackerElementFactory<TrackerElementMacMap>(),
                    "Source address filters");

        filter_dest_id =
            RegisterField("kismet.packetfilter.macaddr.destination", 
                    TrackerElementFactory<TrackerElementMacMap>(),
                    "Destination address filters");

        filter_network_id =
            RegisterField("kismet.packetfilter.macaddr.network", 
                    TrackerElementFactory<TrackerElementMacMap>(),
                    "Network/BSSID address filters");

        filter_other_id =
            RegisterField("kismet.packetfilter.macaddr.other", 
                    TrackerElementFactory<TrackerElementMacMap>(),
                    "Other address filters");

        filter_any_id =
            RegisterField("kismet.packetfilter.macaddr.any", 
                    TrackerElementFactory<TrackerElementMacMap>(),
                    "Any matching address type");
    }

    std::shared_ptr<Devicetracker> devicetracker;
	std::shared_ptr<Eventbus> eventbus;
	unsigned long eb_id;

	void update_phy_map(std::shared_ptr<EventbusEvent> evt);

    unsigned int pack_comp_common;

    int filter_sub_value_id, filter_source_id, filter_dest_id, 
        filter_network_id, filter_other_id, filter_any_id;

    // Externally exposed tracked table
    std::shared_ptr<TrackerElementStringMap> filter_phy_blocks;

    struct phy_filter_group {
        std::map<mac_addr, bool> filter_source;
        std::map<mac_addr, bool> filter_dest;
        std::map<mac_addr, bool> filter_network;
        std::map<mac_addr, bool> filter_other;
        std::map<mac_addr, bool> filter_any;
    };

	// Internal fast lookup tables per-phy we use for actual filtering
	std::map<int, struct phy_filter_group> phy_mac_filter_map;
	// Internal unknown phy map for filters registered before we had a phy ID
	std::map<std::string, struct phy_filter_group> unknown_phy_mac_filter_map;

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

