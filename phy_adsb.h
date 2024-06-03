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

#ifndef __PHY_ADSB_H__
#define __PHY_ADSB_H__

#include "config.h"


#include "adsb_icao.h"
#include "datasourcetracker.h"
#include "devicetracker_component.h"
#include "globalregistry.h"
#include "kis_net_beast_httpd.h"
#include "phyhandler.h"
#include "trackedelement.h"

/* ADSB BEAST binary frame
 * https://wiki.jetvision.de/wiki/Mode-S_Beast:Data_Output_Formats
 */
typedef struct adsb_beast_frame {
    char esc;
    char frametype;
    // We use the top 28 bits as the lower part of a unix timestamp, 
    // and the bottom 20 bits as the uS.
    char mlat_ts[6];
    char signal;
    char modes[0];
} __attribute__((packed)) adsb_beast_frame_t;

// ADSB plane data
class adsb_tracked_adsb : public tracker_component {
public:
    adsb_tracked_adsb() :
        tracker_component() {
        register_fields();
        reserve_fields(NULL);

        lat = lon = alt = heading = speed = 0;
        update_location = false;
    }

    adsb_tracked_adsb(int in_id) :
       tracker_component(in_id) {
        register_fields();
        reserve_fields(NULL);

        lat = lon = alt = heading = speed = 0;
        update_location = false;
        }

    adsb_tracked_adsb(int in_id, std::shared_ptr<tracker_element_map> e) :
        tracker_component(in_id) {
        register_fields();
        reserve_fields(e);

        lat = lon = alt = heading = speed = 0;
        update_location = false;
    }

    virtual uint32_t get_signature() const override {
        return adler32_checksum("adsb_tracked_adsb");
    }

    virtual std::shared_ptr<tracker_element> clone_type() noexcept override {
        using this_t = typename std::remove_pointer<decltype(this)>::type;
        auto r = std::make_shared<this_t>();
        r->set_id(this->get_id());
        return r;
    }

    __Proxy(icao, std::string, std::string, std::string, icao);
    __ProxyTrackable(icao_record, tracked_adsb_icao, icao_record);
    __Proxy(callsign, std::string, std::string, std::string, callsign);
    __Proxy(gsas, std::string, std::string, std::string, gsas);

    __Proxy(odd_raw_lat, double, double, double, odd_raw_lat);
    __Proxy(odd_raw_lon, double, double, double, odd_raw_lon);
    __Proxy(odd_ts, uint64_t, time_t, time_t, odd_ts);
    __Proxy(even_raw_lat, double, double, double, even_raw_lat);
    __Proxy(even_raw_lon, double, double, double, even_raw_lon);
    __Proxy(even_ts, uint64_t, time_t, time_t, even_ts);

protected:
    virtual void register_fields() override {
        register_field("adsb.device.icao", "ICAO", &icao);
        register_field("adsb.device.icao_record", "ICAO record", &icao_record);
        register_field("adsb.device.gsas", "GSAS", &gsas);
        register_field("adsb.device.callsign", "Callsign", &callsign);
        register_field("adsb.device.odd_raw_lat", "Odd-packet raw latitude", &odd_raw_lat);
        register_field("adsb.device.odd_raw_lon", "Odd-packet raw longitude", &odd_raw_lon);
        register_field("adsb.device.odd_ts", "Timestamp of last odd-packet", &odd_ts);
        register_field("adsb.device.even_raw_lat", "even-packet raw latitude", &even_raw_lat);
        register_field("adsb.device.even_raw_lon", "even-packet raw longitude", &even_raw_lon);
        register_field("adsb.device.even_ts", "Timestamp of last even-packet", &even_ts);
    }

    std::shared_ptr<tracker_element_string> icao;
    std::shared_ptr<tracked_adsb_icao> icao_record;
    std::shared_ptr<tracker_element_string> callsign;
    std::shared_ptr<tracker_element_string> gsas;


    // Aggregate location records from multiple packets to derive the actual
    // location.  These are raw adsb locations.
    std::shared_ptr<tracker_element_double> odd_raw_lat;
    std::shared_ptr<tracker_element_double> odd_raw_lon;
    std::shared_ptr<tracker_element_uint64> odd_ts;
    std::shared_ptr<tracker_element_double> even_raw_lat;
    std::shared_ptr<tracker_element_double> even_raw_lon;
    std::shared_ptr<tracker_element_uint64> even_ts;

    // Aggregated location turned into a packet location later
    double lat, lon, alt, heading, speed;
    bool update_location;

    friend class kis_adsb_phy;
};

class kis_adsb_phy : public kis_phy_handler {
public:
    virtual ~kis_adsb_phy();

    kis_adsb_phy() :
        kis_phy_handler() { };

	// Build a strong version of ourselves
	virtual kis_phy_handler *create_phy_handler(int in_phyid) override {
		return new kis_adsb_phy(in_phyid);
	}

    kis_adsb_phy(int in_phyid);

    static int packet_handler(CHAINCALL_PARMS);

protected:
    std::shared_ptr<datasource_tracker> datasourcetracker;

    std::shared_ptr<kis_adsb_icao> icaodb;

    int pack_comp_gps;

    // Convert a JSON record to a RTL-based device key
    mac_addr icao_to_mac(uint32_t icao);

    // convert to a device record & push into device tracker, return false
    // if we can't do anything with it
    bool json_to_rtl(nlohmann::json& in_json, const std::shared_ptr<kis_packet>& packet);
    bool process_adsb_hex(nlohmann::json& in_json, const std::shared_ptr<kis_packet>& packet);

    bool is_adsb(nlohmann::json json);

    std::shared_ptr<adsb_tracked_adsb> add_adsb(const std::shared_ptr<kis_packet>& packet,
            nlohmann::json json, const std::shared_ptr<kis_tracked_device_base>& rtlholder);

    static uint32_t modes_checksum_table[];

    double f_to_c(double f);

    int cpr_mod(int a, int b);
    int cpr_nl(double lat);
    int cpr_n(double lat, int odd);
    double cpr_dlon(double lat, int odd);
    void decode_cpr(const std::shared_ptr<adsb_tracked_adsb>& adsb,
        const std::shared_ptr<kis_packet>& packet);

    std::shared_ptr<packet_chain> packetchain;
    std::shared_ptr<entry_tracker> entrytracker;
    std::shared_ptr<device_tracker> devicetracker;

    int adsb_adsb_id;

    int pack_comp_common, pack_comp_json, pack_comp_meta, pack_comp_datasource;

    std::shared_ptr<tracker_element_string> rtl_manuf;

    std::shared_ptr<tracker_element> adsb_map_endp_handler(std::shared_ptr<kis_net_beast_httpd_connection> con);

    int map_min_lat_id, map_max_lat_id, map_min_lon_id, map_max_lon_id, map_recent_devs_id;

    // Calculate checksum
    uint32_t modes_checksum(const std::string& u8_buf); 

    // Get the expected length of a message based on the type 
    size_t adsb_msg_len_by_type(uint8_t type);

    // Extract checksum
    uint32_t adsb_msg_get_crc(const std::string& u8_buf);

    uint8_t adsb_msg_get_type(const std::string& u8_buf) const;
    uint32_t adsb_msg_get_icao(const std::string& u8_buf) const;
    uint8_t adsb_msg_get_fs(const std::string& u8_buf) const;
    uint8_t adsb_msg_get_me_type(const std::string& u8_buf) const;
    uint8_t adsb_msg_get_me_subtype(const std::string& u8_buf) const;

    int adsb_msg_get_ac13_altitude(const std::string& u8_buf) const;
    int adsb_msg_get_ac12_altitude(const std::string& u8_buf) const;

    std::string adsb_msg_get_flight(const std::string& u8_buf) const;

    typedef struct adsb_location {
        unsigned int lat;
        unsigned int lon;
        bool even;

        adsb_location() {
            lat = 0;
            lon = 0;
            even = false;
        }
    } adsb_location_t;

    void adsb_msg_get_airborne_position(const std::string& u8_buf, adsb_location_t &ret) const;

    double adsb_msg_get_airborne_velocity(const std::string& u8_buf) const;
    double adsb_msg_get_airborne_heading(const std::string& u8_buf) const;
    bool adsb_msg_get_airborne_heading_valid(const std::string& u8_buf) const;
    double adsb_msg_get_sub3_heading(const std::string& u8_buf) const;

};

#endif

