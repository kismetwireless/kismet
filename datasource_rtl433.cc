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
#include "kis_datasource.h"
#include "datasource_rtl433.h"
#include "kismet_json.h"
#include "phy_rtl433.h"

KisDatasourceRtl433::KisDatasourceRtl433(GlobalRegistry *in_globalreg,
        SharedDatasourceBuilder in_builder) :
    KisDatasource(in_globalreg, in_builder),
    Kis_Net_Httpd_CPPStream_Handler(in_globalreg) {

    pack_comp_rtl433 = packetchain->RegisterPacketComponent("RTL433JSON");

    std::string devnum = MungeToPrintable(get_definition_opt("device"));
    if (devnum != "") {
        set_int_source_cap_interface("rtl433usb#" + devnum);
    } else {
        set_int_source_cap_interface("rtl433usb");
    }

    set_int_source_retry(false);
    set_int_source_passive(true);

    set_int_source_hardware("rtlsdr");

    _MSG("Created RTL433 datasource.  This data source receives events from a helper tool, "
            "kismet_cap_sdr_rtl433; make sure this tool is running.", MSGFLAG_INFO);
}

KisDatasourceRtl433::~KisDatasourceRtl433() {

}

bool KisDatasourceRtl433::Httpd_VerifyPath(const char *path, const char *method) {
    if (strcmp(method, "POST") == 0) {
        if (!Httpd_CanSerialize(path))
            return false;

        std::string stripped = Httpd_StripSuffix(path);
        std::vector<std::string> tokenurl = StrTokenize(stripped, "/");

        if (tokenurl.size() < 5)
            return false;

        if (tokenurl[1] != "datasource")
            return false;

        if (tokenurl[2] != "by-uuid")
            return false;

        if (tokenurl[3] != get_source_uuid().UUID2String())
            return false;

        if (tokenurl[4] == "update")
            return true;
    }

    return false;
}

void KisDatasourceRtl433::Httpd_CreateStreamResponse(Kis_Net_Httpd *httpd,
        Kis_Net_Httpd_Connection *connection,
        const char *url, const char *method, const char *upload_data,
        size_t *upload_data_size, std::stringstream &stream) {

}

int KisDatasourceRtl433::Httpd_PostComplete(Kis_Net_Httpd_Connection *concls) {
    std::string stripped = Httpd_StripSuffix(concls->url);
    std::vector<std::string> tokenurl = StrTokenize(stripped, "/");

    // Anything involving POST here requires a login
    if (!httpd->HasValidSession(concls, true)) {
        return 1;
    }

    if (tokenurl.size() < 5)
        return MHD_NO;

    if (tokenurl[1] != "datasource")
        return MHD_NO;

    if (tokenurl[2] != "by-uuid")
        return MHD_NO;

    if (tokenurl[3] != get_source_uuid().UUID2String())
        return MHD_NO;

    if (tokenurl[4] == "update") {
        Json::Value device_json;
        Json::Value gps_json;
        Json::Value meta_json;

        try {
            std::stringstream ss;
            
            ss.str(concls->variable_cache["device"]->str());
            ss >> device_json;

            ss.str(concls->variable_cache["meta"]->str());
            ss >> meta_json;

            if (concls->variable_cache.find("gps") != concls->variable_cache.end()) {
                ss.str(concls->variable_cache["gps"]->str());
                ss >> gps_json;
            }
        } catch (std::exception& e) {
            concls->response_stream << "Invalid request:  could not parse JSON: " << e.what();
            concls->httpcode = 400;
            return MHD_YES;
        }

        kis_packet *packet = packetchain->GeneratePacket();

        try {
            if (clobber_timestamp) {
                gettimeofday(&(packet->ts), NULL);
            } else {
                auto tv_sec_j = meta_json["tv_sec"];
                auto tv_usec_j = meta_json["tv_usec"];

                packet->ts.tv_sec = tv_sec_j.asUInt64();
                packet->ts.tv_usec = tv_usec_j.asUInt64();
            }

            if (gps_json.isObject()) {
                auto lat_j = gps_json["lat"];
                auto lon_j = gps_json["lon"];
                auto alt_j = gps_json["alt"];
                auto spd_j = gps_json["speed"];
                auto head_j = gps_json["heading"];
                auto prec_j = gps_json["precision"];
                auto time_j = gps_json["time"];
                auto fix_j = gps_json["fix"];

                if (lat_j.isNumeric() && lon_j.isNumeric()) {
                    kis_gps_packinfo *gpsinfo = new kis_gps_packinfo();

                    gpsinfo->lat = lat_j.asDouble();
                    gpsinfo->lon = lon_j.asDouble();

                    gpsinfo->fix = 2;

                    if (alt_j.isNumeric()) {
                        gpsinfo->alt = alt_j.asDouble();
                        gpsinfo->fix = 3;
                    }

                    if (fix_j.isNumeric()) 
                        gpsinfo->fix = fix_j.asUInt();

                    if (spd_j.isNumeric())
                        gpsinfo->speed = spd_j.asDouble();

                    if (head_j.isNumeric()) 
                        gpsinfo->heading = head_j.asDouble();

                    if (prec_j.isNumeric())
                        gpsinfo->precision = prec_j.asDouble();

                    if (time_j.isNumeric()) {
                        gpsinfo->tv.tv_sec = time_j.asUInt64();
                        gpsinfo->tv.tv_usec = 0;
                    }

                    packet->insert(pack_comp_gps, gpsinfo);
                }
            }
        } catch (std::exception& e) {
            packetchain->DestroyPacket(packet);
            packet = NULL;

            concls->response_stream << "Invalid request:  could not process packet: " << e.what();
            concls->httpcode = 400;
            return MHD_YES;
        }

        packet_info_rtl433 *r433info = new packet_info_rtl433(device_json);
        packet->insert(pack_comp_rtl433, r433info);

        packetchain_comp_datasource *datasrcinfo = new packetchain_comp_datasource();
        datasrcinfo->ref_source = this;
        packet->insert(pack_comp_datasrc, datasrcinfo);

        inc_source_num_packets(1);
        get_source_packet_rrd()->add_sample(1, time(0));

        packetchain->ProcessPacket(packet);
    }

    return MHD_NO;
}


