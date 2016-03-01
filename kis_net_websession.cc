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
#include "kis_net_websession.h"


Kis_Net_Websession::Kis_Net_Websession(GlobalRegistry *in_globalreg) {
    globalreg = in_globalreg;

    globalreg->httpd_server->RegisterHandler(this);
}

Kis_Net_Websession::~Kis_Net_Websession() {
    globalreg->httpd_server->RemoveHandler(this);
}


bool Kis_Net_Websession::Httpd_VerifyPath(const char *path, const char *method) {
    if (strcmp(method, "GET") != 0)
        return false;

    if (strcmp(path, "/session/create_session") == 0)
        return true;

    if (strcmp(path, "/session/check_session") == 0)
        return true;

    return false;
}



int Kis_Net_Websession::Httpd_HandleRequest(Kis_Net_Httpd *httpd, 
            struct MHD_Connection *connection,
            const char *url, const char *method, const char *upload_data,
            size_t *upload_data_size) {

    if (strcmp(method, "GET") != 0) {
        return 0;
    }

    std::stringstream stream;

    if (strcmp(url, "/session/create_session") == 0) {
        bool make_session = false;

        if (httpd->HasValidSession(connection)) {
            stream << "Already have a valid session";
        } else {
            stream << "Will create a session";
            make_session = true;
        }

        struct MHD_Response *response = 
            MHD_create_response_from_buffer(stream.str().length(),
                    (void *) stream.str().c_str(), MHD_RESPMEM_MUST_COPY);

        char lastmod[31];
        struct tm tmstruct;
        time_t now;
        time(&now);
        localtime_r(&now, &tmstruct);
        strftime(lastmod, 31, "%a, %d %b %Y %H:%M:%S %Z", &tmstruct);
        MHD_add_response_header(response, "Last-Modified", lastmod);

        if (make_session) {
            httpd->CreateSession(response, 0);
        }

        int ret = MHD_queue_response(connection, MHD_HTTP_OK, response);

        MHD_destroy_response(response);

        return ret;
    }

    return 1;
}

