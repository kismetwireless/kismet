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

#include "base64.h"
#include "gpsweb.h"
#include "gpstracker.h"
#include "messagebus.h"

// Don't bind to the http server until we're created, so pass a null to
// the stream_handler init
kis_gps_web::kis_gps_web(shared_gps_builder in_builder) : 
    kis_gps(in_builder),
    kis_net_httpd_cppstream_handler() {

    last_heading_time = 0;
}

kis_gps_web::~kis_gps_web() {

}

bool kis_gps_web::open_gps(std::string in_opts) {
    local_locker lock(gps_mutex);

    if (!kis_gps::open_gps(in_opts)) {
        return false;
    }

    set_int_gps_description("web-based GPS using location from browser");

    bind_httpd_server();

    return true;
}

bool kis_gps_web::get_location_valid() {
    local_locker lock(gps_mutex);

    if (gps_location == NULL) {
        return false;
    }

    if (gps_location->fix < 2) {
        return false;
    }

    // Allow a wider location window
    if (time(0) - gps_location->tv.tv_sec > 30) {
        return false;
    }

    return true;
}

bool kis_gps_web::get_device_connected() {
    if (gps_location == NULL)
        return false;

    // If we've seen a GPS update w/in the past 2 minutes, we count as 'connected' to a gps
    if (time(0) - gps_location->tv.tv_sec > 120) {
        return false;
    }

    return true;
}

bool kis_gps_web::httpd_verify_path(const char *path, const char *method) {
    if (strcmp(method, "POST") == 0 &&
            strcmp(path, "/gps/web/update.cmd") == 0) {
        return true;
    }

    return false;
}

void kis_gps_web::httpd_create_stream_response(kis_net_httpd *httpd,
        kis_net_httpd_connection *connection,
        const char *url, const char *method, const char *upload_data,
        size_t *upload_data_size, std::stringstream &stream) {
    return;
}

int kis_gps_web::httpd_post_iterator(void *coninfo_cls, enum MHD_ValueKind kind, 
        const char *key, const char *filename, const char *content_type,
        const char *transfer_encoding, const char *data, 
        uint64_t off, size_t size) {

    kis_net_httpd_connection *concls = (kis_net_httpd_connection *) coninfo_cls;

    bool handled = false;

    // Anything involving POST here requires a login
    if (!httpd->has_valid_session(concls)) {
        concls->response_stream << "Login required";
        concls->httpcode = 401;
        return 1;
    }

    double lat = 0, lon = 0, alt = 0, spd = 0;
    bool set_alt = false, set_spd = false;

    if (concls->url == "/gps/web/update.cmd") {
#if 0
        if (strcmp(key, "msgpack") == 0 && size > 0) {
            std::string decode = base64::decode(std::string(data));

            // Get the dictionary
            MsgpackAdapter::MsgpackStrMap params;
            MsgpackAdapter::MsgpackStrMap::iterator obj_iter;
            msgpack::unpacked result;

            try {
                msgpack::unpack(result, decode.data(), decode.size());
                msgpack::object deserialized = result.get();
                params = deserialized.as<MsgpackAdapter::MsgpackStrMap>();

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
#endif
        concls->response_stream << "Being rewritten";
        concls->httpcode = 400;
        return 1;
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

        gettimeofday(&(gps_location->tv), NULL);

        if (time(0) - last_heading_time > 5 && gps_last_location != NULL &&
                gps_last_location->fix >= 2) {
            gps_location->heading = 
                gps_calc_heading(gps_location->lat, gps_location->lon, 
                        gps_last_location->lat, gps_last_location->lon);
            last_heading_time = gps_location->tv.tv_sec;
        }
    }

    update_locations();

    return 1;
}


