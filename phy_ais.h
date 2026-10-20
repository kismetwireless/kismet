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

#ifndef __PHY_AIS_H__
#define __PHY_AIS_H__

#include "config.h"

#include "datasourcetracker.h"
#include "devicetracker_component.h"
#include "globalregistry.h"
#include "kis_net_beast_httpd.h"
#include "phyhandler.h"
#include "trackedelement.h"

// Bit-level reader for AIS payloads; AIS fields are packed MSB-first, which
// is the order the capture source delivers the payload bytes in.  Reads past
// the end of the payload return zero; callers check has() for fields which
// are optional or which may be truncated.
class ais_bitreader {
public:
    ais_bitreader(const std::string& in_data) :
        data{in_data} { }

    // Holds a reference to the payload; never bind to a temporary
    ais_bitreader(std::string&&) = delete;

    size_t size_bits() const {
        return data.size() * 8;
    }

    bool has(size_t start, size_t len) const {
        return start + len <= size_bits();
    }

    uint32_t get_uint(size_t start, size_t len) const;
    int32_t get_int(size_t start, size_t len) const;

    // 6-bit AIS text, trimmed of '@' padding and trailing spaces
    std::string get_string(size_t start, size_t len) const;

protected:
    const std::string& data;
};

// AIS station (vessel, base station, aid to navigation, SAR aircraft)
class ais_tracked_vessel : public tracker_component {
public:
    ais_tracked_vessel() :
        tracker_component() {
        register_fields();
        reserve_fields(NULL);
    }

    ais_tracked_vessel(int in_id) :
       tracker_component(in_id) {
        register_fields();
        reserve_fields(NULL);
    }

    ais_tracked_vessel(int in_id, std::shared_ptr<tracker_element_map> e) :
        tracker_component(in_id) {
        register_fields();
        reserve_fields(e);
    }

    virtual uint32_t get_signature() const override {
        return adler32_checksum("ais_tracked_vessel");
    }

    virtual std::shared_ptr<tracker_element> clone_type() noexcept override {
        using this_t = typename std::remove_pointer<decltype(this)>::type;
        auto r = std::make_shared<this_t>();
        r->set_id(this->get_id());
        return r;
    }

    __Proxy(mmsi, uint32_t, uint32_t, uint32_t, mmsi);
    __Proxy(mid, uint16_t, uint16_t, uint16_t, mid);
    __Proxy(country, std::string, std::string, std::string, country);
    __Proxy(station_class, std::string, std::string, std::string, station_class);

    __Proxy(shipname, std::string, std::string, std::string, shipname);
    __Proxy(callsign, std::string, std::string, std::string, callsign);
    __Proxy(imo, uint32_t, uint32_t, uint32_t, imo);
    __Proxy(vendor, std::string, std::string, std::string, vendor);

    __Proxy(ship_type, uint8_t, uint8_t, uint8_t, ship_type);
    __Proxy(ship_type_str, std::string, std::string, std::string, ship_type_str);
    __Proxy(nav_status, uint8_t, uint8_t, uint8_t, nav_status);
    __Proxy(nav_status_str, std::string, std::string, std::string, nav_status_str);
    __Proxy(aton_type, uint8_t, uint8_t, uint8_t, aton_type);
    __Proxy(aton_type_str, std::string, std::string, std::string, aton_type_str);
    __Proxy(aton_virtual, uint8_t, bool, bool, aton_virtual);
    __Proxy(aton_off_position, uint8_t, bool, bool, aton_off_position);

    __Proxy(dim_bow, uint16_t, uint16_t, uint16_t, dim_bow);
    __Proxy(dim_stern, uint16_t, uint16_t, uint16_t, dim_stern);
    __Proxy(dim_port, uint16_t, uint16_t, uint16_t, dim_port);
    __Proxy(dim_starboard, uint16_t, uint16_t, uint16_t, dim_starboard);
    __Proxy(draught, double, double, double, draught);
    __Proxy(destination, std::string, std::string, std::string, destination);
    __Proxy(eta, std::string, std::string, std::string, eta);

    __Proxy(last_msg_type, uint8_t, uint8_t, uint8_t, last_msg_type);
    __Proxy(sog, double, double, double, sog);
    __Proxy(cog, double, double, double, cog);
    __Proxy(heading, double, double, double, heading);
    __Proxy(rot, double, double, double, rot);
    __Proxy(altitude, double, double, double, altitude);
    __Proxy(utc_time, std::string, std::string, std::string, utc_time);

protected:
    virtual void register_fields() override {
        register_field("ais.device.mmsi", "MMSI", &mmsi);
        register_field("ais.device.mid", "Maritime identification digits", &mid);
        register_field("ais.device.country", "Country of registration (from MID)", &country);
        register_field("ais.device.class", "AIS station class", &station_class);

        register_field("ais.device.name", "Vessel / station name", &shipname);
        register_field("ais.device.callsign", "Callsign", &callsign);
        register_field("ais.device.imo", "IMO number", &imo);
        register_field("ais.device.vendor", "Transponder vendor ID", &vendor);

        register_field("ais.device.ship_type", "Ship type code", &ship_type);
        register_field("ais.device.ship_type_str", "Ship type", &ship_type_str);
        register_field("ais.device.nav_status", "Navigation status code", &nav_status);
        register_field("ais.device.nav_status_str", "Navigation status", &nav_status_str);
        register_field("ais.device.aton_type", "Aid to navigation type code", &aton_type);
        register_field("ais.device.aton_type_str", "Aid to navigation type", &aton_type_str);
        register_field("ais.device.aton_virtual", "Virtual aid to navigation", &aton_virtual);
        register_field("ais.device.aton_off_position", "Aid to navigation off position",
                &aton_off_position);

        register_field("ais.device.dim_bow", "Distance from reference to bow (m)", &dim_bow);
        register_field("ais.device.dim_stern", "Distance from reference to stern (m)", &dim_stern);
        register_field("ais.device.dim_port", "Distance from reference to port (m)", &dim_port);
        register_field("ais.device.dim_starboard", "Distance from reference to starboard (m)",
                &dim_starboard);
        register_field("ais.device.draught", "Draught (m)", &draught);
        register_field("ais.device.destination", "Destination", &destination);
        register_field("ais.device.eta", "ETA (MM-DD HH:MM UTC)", &eta);

        register_field("ais.device.last_msg_type", "Last AIS message type", &last_msg_type);
        register_field("ais.device.sog", "Speed over ground (knots)", &sog);
        register_field("ais.device.cog", "Course over ground (degrees)", &cog);
        register_field("ais.device.heading", "True heading (degrees)", &heading);
        register_field("ais.device.rot", "Rate of turn (degrees/minute)", &rot);
        register_field("ais.device.altitude", "SAR aircraft altitude (m)", &altitude);
        register_field("ais.device.utc_time", "Base station UTC time", &utc_time);
    }

    std::shared_ptr<tracker_element_uint32> mmsi;
    std::shared_ptr<tracker_element_uint16> mid;
    std::shared_ptr<tracker_element_string> country;
    std::shared_ptr<tracker_element_string> station_class;

    std::shared_ptr<tracker_element_string> shipname;
    std::shared_ptr<tracker_element_string> callsign;
    std::shared_ptr<tracker_element_uint32> imo;
    std::shared_ptr<tracker_element_string> vendor;

    std::shared_ptr<tracker_element_uint8> ship_type;
    std::shared_ptr<tracker_element_string> ship_type_str;
    std::shared_ptr<tracker_element_uint8> nav_status;
    std::shared_ptr<tracker_element_string> nav_status_str;
    std::shared_ptr<tracker_element_uint8> aton_type;
    std::shared_ptr<tracker_element_string> aton_type_str;
    std::shared_ptr<tracker_element_uint8> aton_virtual;
    std::shared_ptr<tracker_element_uint8> aton_off_position;

    std::shared_ptr<tracker_element_uint16> dim_bow;
    std::shared_ptr<tracker_element_uint16> dim_stern;
    std::shared_ptr<tracker_element_uint16> dim_port;
    std::shared_ptr<tracker_element_uint16> dim_starboard;
    std::shared_ptr<tracker_element_double> draught;
    std::shared_ptr<tracker_element_string> destination;
    std::shared_ptr<tracker_element_string> eta;

    std::shared_ptr<tracker_element_uint8> last_msg_type;
    std::shared_ptr<tracker_element_double> sog;
    std::shared_ptr<tracker_element_double> cog;
    std::shared_ptr<tracker_element_double> heading;
    std::shared_ptr<tracker_element_double> rot;
    std::shared_ptr<tracker_element_double> altitude;
    std::shared_ptr<tracker_element_string> utc_time;
};

class kis_ais_phy : public kis_phy_handler {
public:
    virtual ~kis_ais_phy();

    kis_ais_phy() :
        kis_phy_handler() { };

	// Build a strong version of ourselves
	virtual kis_phy_handler *create_phy_handler(int in_phyid) override {
		return new kis_ais_phy(in_phyid);
	}

    kis_ais_phy(int in_phyid);

    static int packet_handler(CHAINCALL_PARMS);

    // Encode a binary AIS payload as one or more NMEA AIVDM sentences
    static std::vector<std::string> payload_to_aivdm(const std::string& payload,
            char channel, unsigned int seq_id);

    static const char *ship_type_to_string(unsigned int type);
    static const char *nav_status_to_string(unsigned int status);
    static const char *aton_type_to_string(unsigned int type);
    static const char *mid_to_country(unsigned int mid);

    // Extract the maritime identification digits from an MMSI, accounting for
    // the coast station, aid to navigation, and SAR aircraft formats
    static unsigned int mmsi_to_mid(uint32_t mmsi);

protected:
    std::shared_ptr<packet_chain> packetchain;
    std::shared_ptr<entry_tracker> entrytracker;
    std::shared_ptr<device_tracker> devicetracker;

    int ais_vessel_id;

    int pack_comp_json, pack_comp_meta, pack_comp_datasource;

    std::shared_ptr<tracker_element_string> ais_manuf;

    mac_addr mmsi_to_mac(uint32_t mmsi);

    bool process_ais_json(nlohmann::json& in_json, const std::shared_ptr<kis_packet>& packet);

    // Decode an AIS payload as a JSON record suitable for websocket feeds
    bool extract_ais_json(const nlohmann::json& in_json, std::string& payload, char& channel);

    std::shared_ptr<tracker_element> ais_map_endp_handler(std::shared_ptr<kis_net_beast_httpd_connection> con);

    void register_aivdm_websocket(const std::string& uri, bool by_uuid);

    int map_min_lat_id, map_max_lat_id, map_min_lon_id, map_max_lon_id, map_recent_devs_id;
};

#endif

