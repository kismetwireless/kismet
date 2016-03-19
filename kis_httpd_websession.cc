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

#include <sstream>

#include "configfile.h"
#include "messagebus.h"
#include "kis_httpd_websession.h"

Kis_Httpd_Websession::Kis_Httpd_Websession(GlobalRegistry *in_globalreg) {
    globalreg = in_globalreg;

    globalreg->httpd_server->RegisterHandler(this);

    string userpair = globalreg->kismet_config->FetchOpt("httpd_user");
    vector<string> up = StrTokenize(userpair, ":");

    if (up.size() != 2) {
        _MSG("Expected user:password in httpd_user config variable.  Without a "
                "valid user, it is not possible to configure Kismet via the web.",
                MSGFLAG_FATAL);
        globalreg->fatal_condition = 1;
    }

    conf_username = up[0];
    conf_password = up[1];
    
}

Kis_Httpd_Websession::~Kis_Httpd_Websession() {
    globalreg->httpd_server->RemoveHandler(this);
}

void Kis_Httpd_Websession::SetLogin(string in_username, string in_password) {
    stringstream str;

    conf_username = in_username;
    conf_password = in_password;

    str << in_username << ":" << in_password;

    globalreg->kismet_config->SetOpt("httpd_user", str.str(), true);

}

bool Kis_Httpd_Websession::Httpd_VerifyPath(const char *path, const char *method) {
    if (strcmp(method, "GET") != 0)
        return false;

    if (strcmp(path, "/session/create_session") == 0)
        return true;

    if (strcmp(path, "/session/check_session") == 0)
        return true;

    return false;
}

int Kis_Httpd_Websession::Httpd_HandleRequest(Kis_Net_Httpd *httpd, 
            struct MHD_Connection *connection,
            const char *url, const char *method, 
            const char *upload_data __attribute__((unused)),
            size_t *upload_data_size __attribute__((unused))) {

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

        int ret;

        char *user;
        char *pass = NULL;

        struct MHD_Response *response = 
            MHD_create_response_from_buffer(stream.str().length(),
                    (void *) stream.str().c_str(), MHD_RESPMEM_MUST_COPY);

        if (make_session) {
            user = MHD_basic_auth_get_username_password(connection, &pass);
            if (user == NULL || conf_username != user || conf_password != pass) {
                stream.str("");
                stream << "Login required";

                ret = MHD_queue_basic_auth_fail_response(connection,
                        "Kismet Admin", response);

                MHD_destroy_response(response);

                return ret;
            }

            httpd->CreateSession(response, 0);

        }

        ret = MHD_queue_response(connection, MHD_HTTP_OK, response);

        MHD_destroy_response(response);

        return ret;
    }

    return 1;
}

