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

#include "config.hpp"

#include <sstream>

#include "configfile.h"
#include "messagebus.h"
#include "kis_net_microhttpd.h"
#include "kis_httpd_websession.h"

Kis_Httpd_Websession::Kis_Httpd_Websession(GlobalRegistry *in_globalreg) :
    Kis_Net_Httpd_CPPStream_Handler(in_globalreg) {
    globalreg = in_globalreg;

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

}

void Kis_Httpd_Websession::SetLogin(string in_username, string in_password) {
    stringstream str;

    conf_username = in_username;
    conf_password = in_password;

    str << in_username << ":" << in_password;

    globalreg->kismet_config->SetOpt("httpd_user", str.str(), true);

}

bool Kis_Httpd_Websession::CompareLogin(struct MHD_Connection *connection) {
    char *user;
    char *pass = NULL;

    user = MHD_basic_auth_get_username_password(connection, &pass);
    if (user == NULL || conf_username != user || conf_password != pass) {
        return false;
    }

    return true;
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

void Kis_Httpd_Websession::Httpd_CreateStreamResponse(Kis_Net_Httpd *httpd,
        Kis_Net_Httpd_Connection *connection,
        const char *url, const char *method, const char *upload_data,
        size_t *upload_data_size, std::stringstream &stream) {

    if (strcmp(method, "GET") != 0) {
        return;
    }

    if (strcmp(url, "/session/check_session") == 0) {
        if (httpd->HasValidSession(connection)) {
            stream << "Valid session";
        }
    }

    return;
}

