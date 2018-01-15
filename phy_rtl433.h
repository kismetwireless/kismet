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

#ifndef __PHY_RTL433_H__
#define __PHY_RTL433_H__

#include "config.h"
#include "globalregistry.h"
#include "kis_net_microhttpd.h"
#include "trackedelement.h"
#include "devicetracker_component.h"
#include "phyhandler.h"
#include "kismet_json.h"

/* phy-rtl433
 *
 * A simple phy handler which creates a REST endpoint for posting json-encoded
 * data from the rtl_433 sensor reading program.
 *
 * This serves as a relatively simple example of an alternate data capture
 * method: 
 *
 * 1. For very low-rate data (such as capturing sensor information), 
 *    we can implement a simple REST POST api which allows an external data
 *    gathering program to send us the information.
 *
 * 2. This serves as a simple demonstration of how to handle non-packetized 
 *    information from an external capture system.  The rtl433 sensor data is a 
 *    complete record.  We'll simulate a data frame to increment some counters,
 *    and then rely on the display frontend to make sense of it from there.
 *
 * RTL433 has an option to export as JSON; with the help of an external script
 * we simply convert the JSON from stdout and post it to Kismet, then decode it into
 * a tracked record and derive a device key for it.
 *
 */

/* Similar to the extreme aggregator, a temperature aggregator which ignores empty
 * slots while aggregating and otherwise selects the most extreme value when a 
 * slot overlaps.  This fits a lot of generic situations in RTL433 sensors which
 * only report a few times a second (if that).
 */
class rtl433_empty_aggregator {
public:
    // Select the most extreme value
    static int64_t combine_element(const int64_t a, const int64_t b) {
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
    static int64_t combine_vector(SharedTrackerElement e) {
        TrackerElementVector v(e);

        int64_t avg = 0;
        int64_t avg_c = 0;

        for (TrackerElementVector::iterator i = v.begin(); i != v.end(); ++i)  {
            int64_t v = GetTrackerValue<int64_t>(*i);

            if (v != default_val()) {
                avg += GetTrackerValue<int64_t>(*i);
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

    static string name() {
        return "rtl433_empty";
    }
};


// Base rtl device record
class rtl433_tracked_common : public tracker_component {
public:
    rtl433_tracked_common(GlobalRegistry *in_globalreg, int in_id) :
        tracker_component(in_globalreg, in_id) {
            register_fields();
            reserve_fields(NULL);
        }

    virtual SharedTrackerElement clone_type() {
        return SharedTrackerElement(new rtl433_tracked_common(globalreg, get_id()));
    }

    rtl433_tracked_common(GlobalRegistry *in_globalreg, int in_id, 
            SharedTrackerElement e) :
        tracker_component(in_globalreg, in_id) {
        register_fields();
        reserve_fields(e);
    }

    __Proxy(model, string, string, string, model);
    __Proxy(rtlid, uint64_t, uint64_t, uint64_t, rtlid);
    __Proxy(rtlchannel, string, string, string, rtlchannel);
    __Proxy(battery, string, string, string, battery);

protected:
    virtual void register_fields() {
        tracker_component::register_fields();

        model_id =
            RegisterField("rtl433.device.model", TrackerString,
                    "Sensor model", &model);

        rtlid_id =
            RegisterField("rtl433.device.id", TrackerUInt64,
                    "Sensor ID", &rtlid);

        rtlchannel_id =
            RegisterField("rtl433.device.rtlchannel", TrackerString,
                    "Sensor sub-channel", &rtlchannel);

        battery_id =
            RegisterField("rtl433.device.battery", TrackerString,
                    "Sensor battery level", &battery);
    }

    int model_id;
    SharedTrackerElement model;

    // Device id, could be from the "id" or the "device" record
    int rtlid_id;
    SharedTrackerElement rtlid;

    // RTL subchannel, if one is available (many thermometers report one)
    int rtlchannel_id;
    SharedTrackerElement rtlchannel;

    // Battery as a string
    int battery_id;
    SharedTrackerElement battery;
};

// Thermometer type rtl data, derived from the rtl device.  This adds new
// fields for thermometers but uses the same base IDs
class rtl433_tracked_thermometer : public tracker_component {
public:
    rtl433_tracked_thermometer(GlobalRegistry *in_globalreg, int in_id) :
       tracker_component(in_globalreg, in_id) {
            register_fields();
            reserve_fields(NULL);
        }

    virtual SharedTrackerElement clone_type() {
        return SharedTrackerElement(new rtl433_tracked_thermometer(globalreg, get_id()));
    }

    rtl433_tracked_thermometer(GlobalRegistry *in_globalreg, int in_id, 
            SharedTrackerElement e) :
        tracker_component(in_globalreg, in_id) {
        register_fields();
        reserve_fields(e);
    }

    __Proxy(temperature, double, double, double, temperature);
    __Proxy(humidity, int32_t, int32_t, int32_t, humidity);

    typedef kis_tracked_rrd<rtl433_empty_aggregator> rrdt;
    __ProxyTrackable(temperature_rrd, rrdt, temperature_rrd);
    __ProxyTrackable(humidity_rrd, rrdt, humidity_rrd);

protected:
    virtual void register_fields() {
        temperature_id =
            RegisterField("rtl433.device.temperature", TrackerDouble,
                    "Temperature in degrees Celsius", &temperature);

        shared_ptr<kis_tracked_rrd<rtl433_empty_aggregator> > rrd_builder(new kis_tracked_rrd<rtl433_empty_aggregator>(globalreg, 0));
        temperature_rrd_id =
            RegisterComplexField("rtl433.device.temperature_rrd", rrd_builder,
                    "Temperature RRD");

        humidity_id =
            RegisterField("rtl433.device.humidity", TrackerInt32,
                    "Humidity", &humidity);

        rrd_builder.reset(new kis_tracked_rrd<rtl433_empty_aggregator>(globalreg, 0));
        humidity_rrd_id =
            RegisterComplexField("rtl433.device.humidity_rrd", rrd_builder,
                    "Humidity RRD");
    }

    virtual void reserve_fields(SharedTrackerElement e) {
        tracker_component::reserve_fields(e);

        if (e != NULL) {
            temperature_rrd.reset(new kis_tracked_rrd<rtl433_empty_aggregator>(globalreg, temperature_rrd_id, e->get_map_value(temperature_rrd_id)));
            add_map(temperature_rrd);

            humidity_rrd.reset(new kis_tracked_rrd<rtl433_empty_aggregator>(globalreg, humidity_rrd_id, e->get_map_value(humidity_rrd_id)));
            add_map(humidity_rrd);
        } else {
            temperature_rrd.reset(new kis_tracked_rrd<rtl433_empty_aggregator>(globalreg, temperature_rrd_id));
            add_map(temperature_rrd);

            humidity_rrd.reset(new kis_tracked_rrd<rtl433_empty_aggregator>(globalreg, humidity_rrd_id));
            add_map(humidity_rrd);
        }
    }

    // Basic temp in C, from multiple sensors; we might have to convert to C
    // for some types of sensors
    int temperature_id;
    SharedTrackerElement temperature;

    int temperature_rrd_id;
    shared_ptr<kis_tracked_rrd<rtl433_empty_aggregator> > temperature_rrd;

    // Basic humidity in percentage, from multiple sensors
    int humidity_id;
    SharedTrackerElement humidity;

    int humidity_rrd_id;
    shared_ptr<kis_tracked_rrd<rtl433_empty_aggregator> > humidity_rrd;
};

// Weather station type data
class rtl433_tracked_weatherstation : public tracker_component {
public:
    rtl433_tracked_weatherstation(GlobalRegistry *in_globalreg, int in_id) :
        tracker_component(in_globalreg, in_id) {
            register_fields();
            reserve_fields(NULL);
        }

    virtual SharedTrackerElement clone_type() {
        return SharedTrackerElement(new rtl433_tracked_weatherstation(globalreg, get_id()));
    }

    rtl433_tracked_weatherstation(GlobalRegistry *in_globalreg, int in_id, 
            SharedTrackerElement e) :
        tracker_component(in_globalreg, in_id) {
        register_fields();
        reserve_fields(e);
    }

    __Proxy(wind_dir, int32_t, int32_t, int32_t, wind_dir);
    __Proxy(wind_speed, int32_t, int32_t, int32_t, wind_speed);
    __Proxy(wind_gust, int32_t, int32_t, int32_t, wind_gust);
    __Proxy(rain, int32_t, int32_t, int32_t, rain);

    typedef kis_tracked_rrd<rtl433_empty_aggregator> rrdt;
    __ProxyTrackable(wind_dir_rrd, rrdt, wind_dir_rrd);
    __ProxyTrackable(wind_speed_rrd, rrdt, wind_speed_rrd);
    __ProxyTrackable(wind_gust_rrd, rrdt, wind_gust_rrd);
    __ProxyTrackable(rain_rrd, rrdt, rain_rrd);

protected:
    virtual void register_fields() {
        wind_dir_id =
            RegisterField("rtl433.device.wind_dir", TrackerInt32,
                    "Wind direction in degrees", &wind_dir);

        shared_ptr<kis_tracked_rrd<rtl433_empty_aggregator> > rrd_builder(new kis_tracked_rrd<rtl433_empty_aggregator>(globalreg, 0));
        wind_dir_rrd_id =
            RegisterComplexField("rtl433.device.wind_dir_rrd", rrd_builder,
                    "Wind direction RRD");

        wind_speed_id =
            RegisterField("rtl433.device.wind_speed", TrackerInt32,
                    "Wind speed in Kph", &wind_speed);

        rrd_builder.reset(new kis_tracked_rrd<rtl433_empty_aggregator>(globalreg, 0));
        wind_speed_rrd_id =
            RegisterComplexField("rtl433.device.wind_speed_rrd", rrd_builder,
                    "Wind speed RRD");

        wind_gust_id =
            RegisterField("rtl433.device.wind_gust", TrackerInt32,
                    "Wind gust in Kph", &wind_gust);

        rrd_builder.reset(new kis_tracked_rrd<rtl433_empty_aggregator>(globalreg, 0));
        wind_gust_rrd_id =
            RegisterComplexField("rtl433.device.wind_gust_rrd", rrd_builder,
                    "Wind gust RRD");

        rain_id =
            RegisterField("rtl433.device.rain", TrackerInt32,
                    "Measured rain", &rain);

        rrd_builder.reset(new kis_tracked_rrd<rtl433_empty_aggregator>(globalreg, 0));
        rain_rrd_id =
            RegisterComplexField("rtl433.device.rain_rrd", rrd_builder,
                    "Rain RRD");

    }

    virtual void reserve_fields(SharedTrackerElement e) {
        tracker_component::reserve_fields(e);

        if (e != NULL) {
            wind_dir_rrd.reset(new kis_tracked_rrd<rtl433_empty_aggregator>(globalreg, wind_dir_rrd_id, e->get_map_value(wind_dir_rrd_id)));
            add_map(wind_dir_rrd);

            wind_speed_rrd.reset(new kis_tracked_rrd<rtl433_empty_aggregator>(globalreg, wind_speed_rrd_id, e->get_map_value(wind_speed_rrd_id)));
            add_map(wind_speed_rrd);

            wind_gust_rrd.reset(new kis_tracked_rrd<rtl433_empty_aggregator>(globalreg, wind_gust_rrd_id, e->get_map_value(wind_gust_rrd_id)));
            add_map(wind_gust_rrd);

            rain_rrd.reset(new kis_tracked_rrd<rtl433_empty_aggregator>(globalreg, rain_rrd_id, e->get_map_value(rain_rrd_id)));
            add_map(rain_rrd);
        } else {
            wind_dir_rrd.reset(new kis_tracked_rrd<rtl433_empty_aggregator>(globalreg, wind_dir_rrd_id));
            add_map(wind_dir_rrd);

            wind_speed_rrd.reset(new kis_tracked_rrd<rtl433_empty_aggregator>(globalreg, wind_speed_rrd_id));
            add_map(wind_speed_rrd);

            wind_gust_rrd.reset(new kis_tracked_rrd<rtl433_empty_aggregator>(globalreg, wind_gust_rrd_id));
            add_map(wind_gust_rrd);

            rain_rrd.reset(new kis_tracked_rrd<rtl433_empty_aggregator>(globalreg, rain_rrd_id));
            add_map(rain_rrd);
        }
    }

    // Wind direction in degrees
    int wind_dir_id;
    SharedTrackerElement wind_dir;

    int wind_dir_rrd_id;
    shared_ptr<kis_tracked_rrd<rtl433_empty_aggregator> > wind_dir_rrd;

    // Wind speed in kph (might have to convert for some sensors)
    int wind_speed_id;
    SharedTrackerElement wind_speed;

    int wind_speed_rrd_id;
    shared_ptr<kis_tracked_rrd<rtl433_empty_aggregator> > wind_speed_rrd;

    // Wind gust in kph (might have to convert for some sensors)
    int wind_gust_id;
    SharedTrackerElement wind_gust;

    int wind_gust_rrd_id;
    shared_ptr<kis_tracked_rrd<rtl433_empty_aggregator> > wind_gust_rrd;

    // Rain (in whatever the sensor reports it in)
    int rain_id;
    SharedTrackerElement rain;

    int rain_rrd_id;
    shared_ptr<kis_tracked_rrd<rtl433_empty_aggregator> > rain_rrd;
};

class Kis_RTL433_Phy : public Kis_Phy_Handler, public Kis_Net_Httpd_CPPStream_Handler {
public:
    virtual ~Kis_RTL433_Phy();

    Kis_RTL433_Phy(GlobalRegistry *in_globalreg) :
        Kis_Phy_Handler(in_globalreg) { };

	// Build a strong version of ourselves
	virtual Kis_Phy_Handler *CreatePhyHandler(GlobalRegistry *in_globalreg,
											  Devicetracker *in_tracker,
											  int in_phyid) {
		return new Kis_RTL433_Phy(in_globalreg, in_tracker, in_phyid);
	}

    Kis_RTL433_Phy(GlobalRegistry *in_globalreg, Devicetracker *in_tracker,
            int in_phyid);

    // HTTPD API
    virtual bool Httpd_VerifyPath(const char *path, const char *method);

    virtual void Httpd_CreateStreamResponse(Kis_Net_Httpd *httpd,
            Kis_Net_Httpd_Connection *connection,
            const char *url, const char *method, const char *upload_data,
            size_t *upload_data_size, std::stringstream &stream);

    virtual int Httpd_PostComplete(Kis_Net_Httpd_Connection *concls);

protected:
    shared_ptr<Packetchain> packetchain;
    shared_ptr<EntryTracker> entrytracker;

    int rtl433_holder_id, rtl433_common_id, rtl433_thermometer_id, 
        rtl433_weatherstation_id;

    int pack_comp_common;

    // Convert a JSON record to a RTL-based device key
    mac_addr json_to_mac(cppjson::json in_json);

    // convert to a device record & push into device tracker, return false
    // if we can't do anything with it
    bool json_to_rtl(cppjson::json in_json);

    double f_to_c(double f);

};

#endif

