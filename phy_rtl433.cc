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

#include "phy_rtl433.h"
#include "devicetracker.h"
#include "kismet_json.h"
#include "endian_magic.h"
#include "macaddr.h"

Kis_RTL433_Phy::Kis_RTL433_Phy(GlobalRegistry *in_globalreg,
        Devicetracker *in_tracker, int in_phyid) :
    Kis_Phy_Handler(in_globalreg, in_tracker, in_phyid),
    Kis_Net_Httpd_Stream_Handler(in_globalreg) {

    globalreg->InsertGlobal("PHY_RTL433", this);

    phyname = "RTL433";

	pack_comp_common = 
		globalreg->packetchain->RegisterPacketComponent("COMMON");

    /* Test device/weatherstation inheritance */
#if 0
    rtl433_tracked_device *dev_builder = new rtl433_tracked_device(globalreg, 0);
    rtl433_device_id = 
        globalreg->entrytracker->RegisterField("rtl433.device", dev_builder,
                "RTL433 device");
    delete(dev_builder);

    rtl433_tracked_thermometer *therm_builder = 
        new rtl433_tracked_thermometer(globalreg, 0);
    rtl433_thermometer_id =
        globalreg->entrytracker->RegisterField("rtl433.thermometer", therm_builder,
                "RTL433 thermometer");
    delete(therm_builder);

    rtl433_tracked_weatherstation *weather_builder = 
        new rtl433_tracked_weatherstation(globalreg, 0);
    rtl433_weatherstation_id =
        globalreg->entrytracker->RegisterField("rtl433.weatherstation", weather_builder,
                "RTL433 weather station");
    delete(weather_builder);

    rtl433_tracked_device *dev = 
        new rtl433_tracked_device(globalreg, rtl433_device_id);
    dev->link();
    dev->set_model("test model");

    rtl433_tracked_thermometer *therm =
        new rtl433_tracked_thermometer(globalreg, rtl433_thermometer_id, dev);

    therm->link();
    dev->unlink();

    fprintf(stderr, "debug - therm model %s\n", therm->get_model().c_str());

    therm->get_temperature_rrd()->add_sample(200, 1);
    therm->get_temperature_rrd()->add_sample(300, 2);

    fprintf(stderr, "debug - therm rrd last time %ld\n", therm->get_temperature_rrd()->get_last_time());

    rtl433_tracked_weatherstation *weather =
        new rtl433_tracked_weatherstation(globalreg, rtl433_weatherstation_id, therm);

    weather->link();
    therm->unlink();

    fprintf(stderr, "debug - weather model %s\n", weather->get_model().c_str());

    fprintf(stderr, "debug - weather temp rrd last time %ld\n", weather->get_temperature_rrd()->get_last_time());
#endif

}

Kis_RTL433_Phy::~Kis_RTL433_Phy() {
    globalreg->RemoveGlobal("PHY_RTL433");
}

bool Kis_RTL433_Phy::Httpd_VerifyPath(const char *path, const char *method) {
    if (strcmp(method, "POST") == 0) {
        if (strcmp(path, "/phy/phyRTL433/post_sensor_json.cmd") == 0)
            return true;
    }

    return false;
}

mac_addr Kis_RTL433_Phy::json_to_mac(struct JSON_value *json) {
    // Derive a mac addr from the model and device id data
    //
    // We turn the model string into 4 bytes using the adler32 checksum,
    // then we use the model as a (potentially) 16bit int
    //
    // Finally we set the locally assigned bit on the first octet

    string err;

    union {
        uint8_t bytes[6];
        struct {
            uint16_t model;
            uint32_t checksum;
        } breakout;
    } synth_mac;

    string model = JSON_dict_get_string(json, "model", err);
    synth_mac.breakout.checksum = Adler32Checksum(model.c_str(), model.length());

    // See what we can scrape up...
    if (JSON_dict_has_key(json, "id")) {
        synth_mac.breakout.model = 
            kis_hton16((uint16_t) JSON_dict_get_number(json, "id", err));
    } else if (JSON_dict_has_key(json, "device")) {
        synth_mac.breakout.model =
            kis_hton16((uint16_t) JSON_dict_get_number(json, "device", err));
    } else {
        synth_mac.breakout.model = 0x0000;
    }

    // Set the local bit
    synth_mac.bytes[0] |= 0x2;

    return mac_addr(synth_mac.bytes, 6);
}

bool Kis_RTL433_Phy::json_to_rtl(struct JSON_value *json) {
    string err;

    if (json == NULL)
        return false;

    // synth a mac out of it
    mac_addr rtlmac = json_to_mac(json);

    if (rtlmac.error) {
        fprintf(stderr, "debug - could not synth rtl mac\n");
        return false;
    }

    // To interact with devicetracker we (currently) need to turn this into
    // something that looks vaguely like a packet
    kis_packet *pack = new kis_packet(globalreg);

    pack->ts.tv_sec = globalreg->timestamp.tv_sec;
    pack->ts.tv_usec = globalreg->timestamp.tv_usec;

    kis_common_info *common = new kis_common_info();

    common->type = packet_basic_data;
    common->phyid = FetchPhyId();
    common->datasize = 0;

    // If this json record has a channel
    if (JSON_dict_has_key(json, "channel")) {
        int c = JSON_dict_get_number(json, "channel", err);

        if (err.length() == 0) {
            common->channel = IntToString(c);
        }
    }

    common->freq_khz = 433920;
    common->source = rtlmac;
    common->device = rtlmac;

    pack->insert(pack_comp_common, common);

    kis_tracked_device_base *basedev =
        devicetracker->UpdateCommonDevice(common->device, 
                common->phyid, pack,
                (UCD_UPDATE_FREQUENCIES | UCD_UPDATE_PACKETS | UCD_UPDATE_LOCATION |
                 UCD_UPDATE_SEENBY));

    // Get rid of our pseudopacket
    delete(pack);

    TrackerElementScopeLocker((TrackerElement *) basedev);

    string dn = "Sensor";
    if (JSON_dict_has_key(json, "model")) {
        string mdn;
        mdn = JSON_dict_get_string(json, "model", err);
        if (err.length() == 0) {
            dn = MungeToPrintable(mdn);
        }
    }

    basedev->set_manuf("RTL433");

    basedev->set_type_string("RTL433 Sensor");
    basedev->set_devicename(dn);

    return true;
}

void Kis_RTL433_Phy::Httpd_CreateStreamResponse(Kis_Net_Httpd *httpd,
        struct MHD_Connection *connection,
        const char *url, const char *method, const char *upload_data,
        size_t *upload_data_size, std::stringstream &stream) {

    return;
}

int Kis_RTL433_Phy::Httpd_PostIterator(void *coninfo_cls, enum MHD_ValueKind kind, 
        const char *key, const char *filename, const char *content_type,
        const char *transfer_encoding, const char *data, 
        uint64_t off, size_t size) {

    Kis_Net_Httpd_Connection *concls = (Kis_Net_Httpd_Connection *) coninfo_cls;

    // Anything involving POST here requires a login
    if (!httpd->HasValidSession(concls)) {
        fprintf(stderr, "debug - no valid session\n");
        concls->response_stream << "Login required";
        concls->httpcode = 401;
        return 1;
    }

    bool handled = false;

    if (concls->url == "/phy/phyRTL433/post_sensor_json.cmd" &&
            strcmp(key, "obj") == 0 && size > 0) {
        struct JSON_value *json;
        string err;

        json = JSON_parse(data, err);

        if (err.length() != 0 || json == NULL) {
            fprintf(stderr, "Could not parse json? %s\n", err.c_str());
            concls->response_stream << "Invalid request: could not parse JSON";
            concls->httpcode = 400;

            if (json != NULL)
                JSON_delete(json);

            return 1;
        }

        // If we can't make sense of it, blow up
        if (!json_to_rtl(json)) {
            fprintf(stderr, "debug - could not ocnvert to rtl\n");
            concls->response_stream << 
                "Invalid request:  could not convert to RTL device";
            concls->httpcode = 400;
            handled = false;
        } else {
            handled = true;
        }

        JSON_delete(json);
    }

    // If we didn't handle it and got here, we don't know what it is, throw an
    // error.
    if (!handled) {
        concls->response_stream << "Invalid request";
        concls->httpcode = 400;
    } else {
        // Return a generic OK.  msgpack returns shouldn't get to here.
        concls->response_stream << "OK";
    }

    return 1;
}

