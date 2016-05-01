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

#include "gpsweb.h"
#include "gps_manager.h"
#include "messagebus.h"

// Don't bind to the http server until we're created, so pass a null to
// the stream_handler init
GPSWeb::GPSWeb(GlobalRegistry *in_globalreg) : 
    Kis_Gps(in_globalreg),
    Kis_Net_Httpd_Stream_Handler(NULL) {

    globalreg = in_globalreg;

    last_heading_time = 0;
}

GPSWeb::~GPSWeb() {

}

Kis_Gps *GPSWeb::BuildGps(string in_opts) {
    local_locker lock(&gps_locker);

    GPSWeb *new_gps = new GPSWeb(globalreg);

    if (new_gps->OpenGps(in_opts) < 0) {
        delete new_gps;
        return NULL;
    }

    return new_gps;
}

int GPSWeb::OpenGps(string in_opts) {
    local_locker lock(&gps_locker);

    if (Kis_Gps::OpenGps(in_opts) < 0) {
        return -1;
    }

    // Call the http stream handler init to bind to the webserver
    Bind_Httpd_Server(globalreg);

    return 1;
}

string GPSWeb::FetchGpsDescription() {
    local_locker lock(&gps_locker);

    return "Web GPS";
}

bool GPSWeb::FetchGpsLocationValid() {
    local_locker lock(&gps_locker);

    if (gps_location == NULL) {
        return false;
    }

    if (gps_location->fix < 2) {
        return false;
    }

    if (globalreg->timestamp.tv_sec - gps_location->time > 30) {
        return false;
    }

    return true;
}

bool GPSWeb::FetchGpsConnected() {
    return true;
}

kis_gps_packinfo *GPSWeb::FetchGpsLocation() {
    local_locker lock(&gps_locker);

    return gps_location;
}

bool GPSWeb::Httpd_VerifyPath(const char *path, const char *method) {
    if (strcmp(method, "POST") == 0 &&
            strcmp(path, "/gps/web/update.cmd") == 0) {
        return true;
    }

    return false;
}

void GPSWeb::Httpd_CreateStreamResponse(Kis_Net_Httpd *httpd,
        struct MHD_Connection *connection,
        const char *url, const char *method, const char *upload_data,
        size_t *upload_data_size, std::stringstream &stream) {
    return;
}

int GPSWeb::Httpd_PostIterator(void *coninfo_cls, enum MHD_ValueKind kind, 
        const char *key, const char *filename, const char *content_type,
        const char *transfer_encoding, const char *data, 
        uint64_t off, size_t size) {

    Kis_Net_Httpd_Connection *concls = (Kis_Net_Httpd_Connection *) coninfo_cls;

    bool handled = false;

    // Anything involving POST here requires a login
    if (!httpd->HasValidSession(concls)) {
        concls->response_stream << "Login required";
        concls->httpcode = 401;
        return 1;
    }

    double lat = 0, lon = 0, alt = 0, spd = 0;
    bool set_alt = false, set_spd = false;

    if (concls->url == "/gps/web/update.cmd") {
        if (strcmp(key, "msgpack") == 0 && size > 0) {
            // Get the dictionary
            MsgpackAdapter::MsgpackStrMap params = Httpd_Post_Get_Msgpack(data, size);
            MsgpackAdapter::MsgpackStrMap::iterator obj_iter;

            try {
                // Lat and lon are required
                obj_iter = params.find("lat");
                if (obj_iter == params.end())
                    throw std::runtime_error("expected 'lat' entry");
                lat = obj_iter->second.as<double>();

                obj_iter = params.find("lon");
                if (obj_iter == params.end())
                    throw std::runtime_error("expected 'lon' entry");
                lon = obj_iter->second.as<double>();

                // Alt and speed are optional, but if one is provided,
                // it needs to be a double
                obj_iter = params.find("alt");
                if (obj_iter != params.end()) {
                    alt = obj_iter->second.as<double>();
                    set_alt = true;
                }

                obj_iter = params.find("spd");
                if (obj_iter != params.end()) {
                    spd = obj_iter->second.as<double>();
                    set_spd = true;
                }

                handled = true;
            } catch (const std::exception& e) {
                concls->response_stream << "Invalid request " << e.what();
                concls->httpcode = 400;
                return 1;
            }
        }
    }

    // If we didn't handle it and got here, we don't know what it is, throw an
    // error.
    if (!handled) {
        concls->response_stream << "Invalid request";
        concls->httpcode = 400;
    } else {
        concls->response_stream << "OK";
    }

    if (handled) {
        // Set up our local gps record
        if (gps_last_location != NULL) 
            delete gps_last_location;

        gps_last_location = new kis_gps_packinfo(gps_location);

        gps_location = new kis_gps_packinfo();

        gps_location->lat = lat;
        gps_location->lon = lon;
        gps_location->fix = 2;

        if (set_alt) {
            gps_location->alt = alt;
            gps_location->fix = 3;
        }

        if (set_spd) 
            gps_location->speed = spd;

        gps_location->time = globalreg->timestamp.tv_sec;

        // printf("debug - gps %f,%f alt %f spd %f\n", gps_location->lat, gps_location->lon, gps_location->alt, gps_location->speed);

        if (globalreg->timestamp.tv_sec - last_heading_time > 5 &&
                gps_last_location != NULL &&
                gps_last_location->fix >= 2) {
            gps_location->heading = 
                GpsCalcHeading(gps_location->lat, gps_location->lon, 
                        gps_last_location->lat, gps_last_location->lon);
            last_heading_time = gps_location->time;
        }
    }

    return 1;
}


