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


// Base rtl device record
class rtl433_tracked_device : public tracker_component {
public:
    rtl433_tracked_device(GlobalRegistry *in_globalreg, int in_id) :
        tracker_component(in_globalreg, in_id) {
            register_fields();
            reserve_fields(NULL);
        }

    virtual TrackerElement *clone_type() {
        return new rtl433_tracked_device(globalreg, get_id());
    }

    rtl433_tracked_device(GlobalRegistry *in_globalreg, int in_id, TrackerElement *e) :
        tracker_component(in_globalreg, in_id) {
        register_fields();
        reserve_fields(e);
    }

    __Proxy(model, string, string, string, model);
    __Proxy(rtlid, string, string, string, rtlid);
    __Proxy(rtlchannel, string, string, string, rtlchannel);
    __Proxy(battery, string, string, string, battery);

protected:
    virtual void register_fields() {
        model_id =
            RegisterField("rtl433.device.model", TrackerString,
                    "Sensor model", (void **) &model);

        rtlid_id =
            RegisterField("rtl433.device.id", TrackerString,
                    "Sensor ID", (void **) &rtlid);

        rtlchannel_id =
            RegisterField("rtl433.device.rtlchannel", TrackerString,
                    "Sensor sub-channel", (void **) &rtlchannel);

        battery_id =
            RegisterField("rtl433.device.battery", TrackerString,
                    "Sensor battery level", (void **) &rtlchannel);
    }

    int model_id;
    TrackerElement *model;

    // Device id, could be from the "id" or the "device" record
    int rtlid_id;
    TrackerElement *rtlid;

    // RTL subchannel, if one is available (many thermometers report one)
    int rtlchannel_id;
    TrackerElement *rtlchannel;

    // Battery as a string
    int battery_id;
    TrackerElement *battery;
};

// Thermometer type rtl data, derived from the rtl device.  This adds new
// fields for thermometers but uses the same base IDs
class rtl433_tracked_thermometer : public rtl433_tracked_device {
public:
    rtl433_tracked_thermometer(GlobalRegistry *in_globalreg, int in_id) :
        rtl433_tracked_device(in_globalreg, in_id) {
            register_fields();
            reserve_fields(NULL);
        }

    virtual TrackerElement *clone_type() {
        return new rtl433_tracked_thermometer(globalreg, get_id());
    }

    rtl433_tracked_thermometer(GlobalRegistry *in_globalreg, int in_id, 
            TrackerElement *e) :
        rtl433_tracked_device(in_globalreg, in_id) {
        register_fields();
        reserve_fields(e);
    }

    __Proxy(temperature, int32_t, int32_t, int32_t, temperature);
    __Proxy(humidity, int32_t, int32_t, int32_t, humidity);

    typedef kis_tracked_rrd<> rrdt;
    __ProxyTrackable(temperature_rrd, rrdt, temperature_rrd);
    __ProxyTrackable(humidity_rrd, rrdt, humidity_rrd);

protected:
    virtual void register_fields() {
        temperature_id =
            RegisterField("rtl433.device.temperature", TrackerInt32,
                    "Temperature in degrees Celsius", (void **) &temperature);

        kis_tracked_rrd<> *rrd_builder = new kis_tracked_rrd<>(globalreg, 0);
        temperature_rrd_id =
            RegisterComplexField("rtl433.device.temperature_rrd", rrd_builder,
                    "Temperature RRD");
        delete(rrd_builder);

        humidity_id =
            RegisterField("rtl433.device.humidity", TrackerInt32,
                    "Humidity", (void **) &humidity);

        rrd_builder = new kis_tracked_rrd<>(globalreg, 0);
        humidity_rrd_id =
            RegisterComplexField("rtl433.device.humidity_rrd", rrd_builder,
                    "Humidity RRD");
    }

    virtual void reserve_fields(TrackerElement *e) {
        rtl433_tracked_device::reserve_fields(e);

        if (e != NULL) {
            temperature_rrd = new kis_tracked_rrd<>(globalreg, 
                    temperature_rrd_id, e->get_map_value(temperature_rrd_id));
            add_map(temperature_rrd);

            humidity_rrd = new kis_tracked_rrd<>(globalreg,
                    humidity_rrd_id, e->get_map_value(humidity_rrd_id));
            add_map(humidity_rrd);
        } else {
            temperature_rrd = new kis_tracked_rrd<>(globalreg, temperature_rrd_id);
            add_map(temperature_rrd);

            humidity_rrd = new kis_tracked_rrd<>(globalreg, humidity_rrd_id);
            add_map(humidity_rrd);
        }
    }

    // Basic temp in C, from multiple sensors; we might have to convert to C
    // for some types of sensors
    int temperature_id;
    TrackerElement *temperature;

    int temperature_rrd_id;
    kis_tracked_rrd<> *temperature_rrd;

    // Basic humidity in percentage, from multiple sensors
    int humidity_id;
    TrackerElement *humidity;

    int humidity_rrd_id;
    kis_tracked_rrd<> *humidity_rrd;
};

// Weather station type data
class rtl433_tracked_weatherstation : public rtl433_tracked_thermometer {
public:
    rtl433_tracked_weatherstation(GlobalRegistry *in_globalreg, int in_id) :
        rtl433_tracked_thermometer(in_globalreg, in_id) {
            register_fields();
            reserve_fields(NULL);
        }

    virtual TrackerElement *clone_type() {
        return new rtl433_tracked_weatherstation(globalreg, get_id());
    }

    rtl433_tracked_weatherstation(GlobalRegistry *in_globalreg, int in_id, 
            TrackerElement *e) :
        rtl433_tracked_thermometer(in_globalreg, in_id) {
        register_fields();
        reserve_fields(e);
    }

protected:
    virtual void register_fields() {
        wind_dir_id =
            RegisterField("rtl433.device.wind_dir", TrackerInt32,
                    "Wind direction in degrees", (void **) &wind_dir);

        kis_tracked_rrd<> *rrd_builder = new kis_tracked_rrd<>(globalreg, 0);
        wind_dir_rrd_id =
            RegisterComplexField("rtl433.device.wind_dir_rrd", rrd_builder,
                    "Wind direction RRD");
        delete(rrd_builder);

        wind_speed_id =
            RegisterField("rtl433.device.wind_speed", TrackerInt32,
                    "Wind speed in Kph", (void **) &wind_speed);

        rrd_builder = new kis_tracked_rrd<>(globalreg, 0);
        wind_speed_rrd_id =
            RegisterComplexField("rtl433.device.wind_speed_rrd", rrd_builder,
                    "Wind speed RRD");
        delete(rrd_builder);

        wind_gust_id =
            RegisterField("rtl433.device.wind_gust", TrackerInt32,
                    "Wind gust in Kph", (void **) &wind_gust);

        rrd_builder = new kis_tracked_rrd<>(globalreg, 0);
        wind_gust_rrd_id =
            RegisterComplexField("rtl433.device.wind_gust_rrd", rrd_builder,
                    "Wind gust RRD");
        delete(rrd_builder);

        rain_id =
            RegisterField("rtl433.device.rain", TrackerInt32,
                    "Measured rain", (void **) &rain);

        rrd_builder = new kis_tracked_rrd<>(globalreg, 0);
        rain_rrd_id =
            RegisterComplexField("rtl433.device.rain", rrd_builder,
                    "Rain RRD");
        delete(rrd_builder);

    }

    virtual void reserve_fields(TrackerElement *e) {
        rtl433_tracked_device::reserve_fields(e);

        if (e != NULL) {
            wind_dir_rrd = new kis_tracked_rrd<>(globalreg, 
                    wind_dir_rrd_id, e->get_map_value(wind_dir_rrd_id));
            add_map(wind_dir_rrd);

            wind_speed_rrd = new kis_tracked_rrd<>(globalreg, 
                    wind_speed_rrd_id, e->get_map_value(wind_speed_rrd_id));
            add_map(wind_speed_rrd);

            wind_gust_rrd = new kis_tracked_rrd<>(globalreg, 
                    wind_gust_rrd_id, e->get_map_value(wind_gust_rrd_id));
            add_map(wind_gust_rrd);

            rain_rrd = new kis_tracked_rrd<>(globalreg, 
                    rain_rrd_id, e->get_map_value(rain_rrd_id));
            add_map(rain_rrd);
        } else {
            wind_dir_rrd = new kis_tracked_rrd<>(globalreg, wind_dir_rrd_id);
            add_map(wind_dir_rrd);

            wind_speed_rrd = new kis_tracked_rrd<>(globalreg, wind_speed_rrd_id);
            add_map(wind_speed_rrd);

            wind_gust_rrd = new kis_tracked_rrd<>(globalreg, wind_gust_rrd_id);
            add_map(wind_gust_rrd);

            rain_rrd = new kis_tracked_rrd<>(globalreg, rain_rrd_id);
            add_map(rain_rrd);
        }
    }

    // Wind direction in degrees
    int wind_dir_id;
    TrackerElement *wind_dir;

    int wind_dir_rrd_id;
    kis_tracked_rrd<> *wind_dir_rrd;

    // Wind speed in kph (might have to convert for some sensors)
    int wind_speed_id;
    TrackerElement *wind_speed;

    int wind_speed_rrd_id;
    kis_tracked_rrd<> *wind_speed_rrd;

    // Wind gust in kph (might have to convert for some sensors)
    int wind_gust_id;
    TrackerElement *wind_gust;

    int wind_gust_rrd_id;
    kis_tracked_rrd<> *wind_gust_rrd;

    // Rain (in whatever the sensor reports it in)
    int rain_id;
    TrackerElement *rain;

    int rain_rrd_id;
    kis_tracked_rrd<> *rain_rrd;
};

class Kis_RTL433_Phy : public Kis_Phy_Handler, public Kis_Net_Httpd_Stream_Handler {
public:
    Kis_RTL433_Phy() { }

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

    // Log stub
	virtual void ExportLogRecord(kis_tracked_device_base *in_device, string in_logtype, 
								 FILE *in_logfile, int in_lineindent) { }

    // HTTPD API
    virtual bool Httpd_VerifyPath(const char *path, const char *method);

    virtual void Httpd_CreateStreamResponse(Kis_Net_Httpd *httpd,
            struct MHD_Connection *connection,
            const char *url, const char *method, const char *upload_data,
            size_t *upload_data_size, std::stringstream &stream);

    virtual int Httpd_PostIterator(void *coninfo_cls, enum MHD_ValueKind kind, 
            const char *key, const char *filename, const char *content_type,
            const char *transfer_encoding, const char *data, 
            uint64_t off, size_t size);
protected:

};

#endif

