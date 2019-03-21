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

#ifndef __PHY_RTLADSB_H__
#define __PHY_RTLADSB_H__

#include "config.h"
#include "globalregistry.h"
#include "kis_net_microhttpd.h"
#include "trackedelement.h"
#include "devicetracker_component.h"
#include "phyhandler.h"
#include "kismet_json.h"

/* Similar to the extreme aggregator, a consumption aggregator which ignores empty
 * slots while aggregating and otherwise selects the most extreme value when a 
 * slot overlaps.  This fits a lot of generic situations in RTLADSB sensors which
 * only report a few times a second (if that).
 */
class rtladsb_empty_aggregator {
public:
    // Select the most extreme value
    static int64_t combine_element(const int64_t a, const int64_t b) {
        if (a == default_val())
            return b;

        if (b == default_val())
            return a;

        if (a < 0 && b < 0) {
            if (a < b)
                return a;

            return b;
        } else if (a > 0 && b > 0) {
            if (a > b)
                return a;

            return b;
        } else if (a == 0) {
            return b;
        } else if (b == 0) {
            return a;
        } else if (a < b) {
            return a;
        }

        return b;
    }

    // Simple average
    static int64_t combine_vector(std::shared_ptr<TrackerElementVectorDouble> e) {
        int64_t avg = 0;
        int64_t avg_c = 0;

        for (auto i : *e) {
            if (i != default_val()) {
                avg += i;
                avg_c++;
            }
        }

        if (avg_c == 0)
            return default_val();

        return avg / avg_c;
    }

    // Default 'empty' value, no legit signal would be 0
    static int64_t default_val() {
        return (int64_t) -9999;
    }

    static std::string name() {
        return "rtladsb_empty";
    }
};


// Base rtl device record
class rtladsb_tracked_common : public tracker_component {
public:
    rtladsb_tracked_common() :
        tracker_component() {
        register_fields();
        reserve_fields(NULL);
    }

    rtladsb_tracked_common(int in_id) :
        tracker_component(in_id) {
            register_fields();
            reserve_fields(NULL);
        }

    rtladsb_tracked_common(int in_id, 
            std::shared_ptr<TrackerElementMap> e) :
        tracker_component(in_id) {
        register_fields();
        reserve_fields(e);
    }

    virtual uint32_t get_signature() const override {
        return Adler32Checksum("rtladsb_tracked_common");
    }

    virtual std::unique_ptr<TrackerElement> clone_type() override {
        using this_t = std::remove_pointer<decltype(this)>::type;
        auto dup = std::unique_ptr<this_t>(new this_t());
        return std::move(dup);
    }

    virtual std::unique_ptr<TrackerElement> clone_type(int in_id) override {
        using this_t = std::remove_pointer<decltype(this)>::type;
        auto dup = std::unique_ptr<this_t>(new this_t(in_id));
        return std::move(dup);
    }

    __Proxy(model, std::string, std::string, std::string, model);
    __Proxy(rtlid, std::string, std::string, std::string, rtlid);
    __Proxy(rtlchannel, std::string, std::string, std::string, rtlchannel);

protected:
    virtual void register_fields() override {
        tracker_component::register_fields();

        RegisterField("rtladsb.device.model", "Sensor model", &model);
        RegisterField("rtladsb.device.id", "Sensor ID", &rtlid);
        RegisterField("rtladsb.device.rtlchannel", "Sensor sub-channel", &rtlchannel);
    }

    std::shared_ptr<TrackerElementString> model;

    // Device id, could be from the "id" or the "device" record
    std::shared_ptr<TrackerElementString> rtlid;

    // RTL subchannel, if one is available (many adsb messages report one)
    std::shared_ptr<TrackerElementString> rtlchannel;

    // Battery as a string
    //std::shared_ptr<TrackerElementString> battery;
};

// Thermometer type rtl data, derived from the rtl device.  This adds new
// fields for adsb but uses the same base IDs
class rtladsb_tracked_adsb : public tracker_component {
public:
    rtladsb_tracked_adsb() :
        tracker_component() {
        register_fields();
        reserve_fields(NULL);
    }

    rtladsb_tracked_adsb(int in_id) :
       tracker_component(in_id) {
            register_fields();
            reserve_fields(NULL);
        }

    rtladsb_tracked_adsb(int in_id, std::shared_ptr<TrackerElementMap> e) :
        tracker_component(in_id) {
        register_fields();
        reserve_fields(e);
    }

    virtual uint32_t get_signature() const override {
        return Adler32Checksum("rtladsb_tracked_adsb");
    }

    virtual std::unique_ptr<TrackerElement> clone_type() override {
        using this_t = std::remove_pointer<decltype(this)>::type;
        auto dup = std::unique_ptr<this_t>(new this_t());
        return std::move(dup);
    }

    virtual std::unique_ptr<TrackerElement> clone_type(int in_id) override {
        using this_t = std::remove_pointer<decltype(this)>::type;
        auto dup = std::unique_ptr<this_t>(new this_t(in_id));
        return std::move(dup);
    }

    __Proxy(icao, std::string, std::string, std::string, icao);
    __Proxy(regid, std::string, std::string, std::string, regid);
    __Proxy(mdl, std::string, std::string, std::string, mdl);
    __Proxy(atype, std::string, std::string, std::string, atype);
    __Proxy(aoperator, std::string, std::string, std::string, aoperator);
    __Proxy(callsign, std::string, std::string, std::string, callsign);
    __Proxy(altitude, double, double, double, altitude);
    __Proxy(speed, double, double, double, speed);
    __Proxy(heading, double, double, double, heading);
    __Proxy(gsas, std::string, std::string, std::string, gsas);
    //__Proxy(icao, double, double, double, icao);

    //typedef kis_tracked_rrd<rtladsb_empty_aggregator> rrdt;
    //__ProxyTrackable(consumption_rrd, rrdt, consumption_rrd);

protected:
    virtual void register_fields() override {
        RegisterField("rtladsb.device.icao", "ICAO", &icao);
        RegisterField("rtladsb.device.regid", "REGID", &regid);
        RegisterField("rtladsb.device.mdl", "MDL", &mdl);
        RegisterField("rtladsb.device.atype", "Type", &atype);
        RegisterField("rtladsb.device.aoperator", "Operator", &aoperator);
        RegisterField("rtladsb.device.callsign", "Callsign", &callsign);
        RegisterField("rtladsb.device.altitude", "Altitude", &altitude);
        RegisterField("rtladsb.device.speed", "Speed", &speed);
        RegisterField("rtladsb.device.heading", "Heading", &heading);
        RegisterField("rtladsb.device.gsas", "GSAS", &gsas);

        //RegisterField("rtladsb.device.consumption_rrd", "Consumption history RRD", &consumption_rrd);
    }

    // Basic temp in C, from multiple sensors; we might have to convert to C
    // for some types of sensors
    std::shared_ptr<TrackerElementString> icao;
    std::shared_ptr<TrackerElementString> regid;
    std::shared_ptr<TrackerElementString> mdl;
    std::shared_ptr<TrackerElementString> atype;
    std::shared_ptr<TrackerElementString> aoperator;
    std::shared_ptr<TrackerElementString> callsign;
    std::shared_ptr<TrackerElementDouble> altitude; 
    std::shared_ptr<TrackerElementDouble> speed;
    std::shared_ptr<TrackerElementDouble> heading;
    std::shared_ptr<TrackerElementString> gsas;

    //std::shared_ptr<kis_tracked_rrd<rtladsb_empty_aggregator>> consumption_rrd;

};

class Kis_RTLADSB_Phy : public Kis_Phy_Handler {
public:
    virtual ~Kis_RTLADSB_Phy();

    Kis_RTLADSB_Phy(GlobalRegistry *in_globalreg) :
        Kis_Phy_Handler(in_globalreg) { };

	// Build a strong version of ourselves
	virtual Kis_Phy_Handler *CreatePhyHandler(GlobalRegistry *in_globalreg, int in_phyid) override {
		return new Kis_RTLADSB_Phy(in_globalreg, in_phyid);
	}

    Kis_RTLADSB_Phy(GlobalRegistry *in_globalreg, int in_phyid);

    static int PacketHandler(CHAINCALL_PARMS);

protected:
    // Convert a JSON record to a RTL-based device key
    mac_addr json_to_mac(Json::Value in_json);

    // convert to a device record & push into device tracker, return false
    // if we can't do anything with it
    bool json_to_rtl(Json::Value in_json, kis_packet *packet);

    bool is_adsb(Json::Value json);

    void add_adsb(Json::Value json, std::shared_ptr<TrackerElementMap> rtlholder);

    double f_to_c(double f);


protected:
    std::shared_ptr<Packetchain> packetchain;
    std::shared_ptr<EntryTracker> entrytracker;
    std::shared_ptr<Devicetracker> devicetracker;

    int rtladsb_holder_id, rtladsb_common_id, rtladsb_adsb_id;
    //std::string rtladsb_icao_id;
    //FIX HERE, rtladsb_powermeter_id;

    int pack_comp_common, pack_comp_json, pack_comp_meta;

    std::shared_ptr<TrackerElementString> rtl_manuf;

};

#endif

