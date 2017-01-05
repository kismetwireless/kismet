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

Kis_RTL433_Phy::Kis_RTL433_Phy(GlobalRegistry *in_globalreg,
        Devicetracker *in_tracker, int in_phyid) :
    Kis_Phy_Handler(in_globalreg, in_tracker, in_phyid),
    Kis_Net_Httpd_Stream_Handler(in_globalreg) {

    globalreg->InsertGlobal("PHY_RTL433", this);

    phyname = "RTL433";

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
        concls->response_stream << "Login required";
        concls->httpcode = 401;
        return 1;
    }

    bool handled = false;

    if (concls->url == "/phy/phyRTL433/post_sensor_json.cmd" &&
            strcmp(key, "obj") == 0 && size > 0) {
        fprintf(stderr, "debug - obj %s\n", data);
        struct JSON_value *json;
        string err;

        json = JSON_parse(data, err);

        if (err.length() != 0 || json == NULL) {
            concls->response_stream << "Invalid request: could not parse JSON";
            concls->httpcode = 400;

            if (json != NULL)
                JSON_delete(json);

            return 1;
        }

        if (json != NULL)
            JSON_delete(json);

        handled = true;
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

