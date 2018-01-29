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
#include "kis_net_microhttpd.h"
#include "kis_httpd_websession.h"
#include "alertracker.h"

Kis_Httpd_Websession::Kis_Httpd_Websession(GlobalRegistry *in_globalreg) :
    Kis_Net_Httpd_CPPStream_Handler(in_globalreg) {
    globalreg = in_globalreg;

    activated = false;

}

void Kis_Httpd_Websession::Deferred_Startup() {
    string olduser = globalreg->kismet_config->FetchOpt("httpd_user");

    shared_ptr<Alertracker> alertracker = 
        Globalreg::FetchGlobalAs<Alertracker>(globalreg, "ALERTTRACKER");

    if (olduser != "") {
        int oldref;

        alertracker->DefineAlert("OLDHTTPDUSER", sat_second, 1, sat_second, 1);
        oldref = alertracker->ActivateConfiguredAlert("OLDHTTPDUSER", 
                "Found httpd_user= in global Kismet configs (kismet.conf or "
                "kismet_http.conf).  This config has been replaced with a "
                "per-user config in ~/.kismet/kismet_http.conf.  Make sure "
                "to update your config files!");
        alertracker->RaiseAlert(oldref, NULL, mac_addr(), mac_addr(),
                mac_addr(), mac_addr(), "", 
                "Found httpd_user= in global Kismet configs (kismet.conf or "
                "kismet_http.conf).  This config has been replaced with a "
                "per-user config in ~/.kismet/kismet_http.conf.  Make sure "
                "to update your config files!");
    }

    global_config = false;

    conf_username = globalreg->kismet_config->FetchOpt("httpd_username");
    conf_password = globalreg->kismet_config->FetchOpt("httpd_password");

    if (conf_username != "" || conf_password != "") {
        int globalref;

        alertracker->DefineAlert("GLOBALHTTPDUSER", sat_second, 1, sat_second, 1);
        globalref = alertracker->ActivateConfiguredAlert("GLOBALHTTPDUSER", 
                "Found httpd_username= and httpd_password= in global Kismet "
                "configs (kismet.conf or kismet_http.conf).  Make sure that this "
                "file is readable only by the user launching Kismet.  The "
                "username and password in ~/.kismet/kismet_http.conf will be "
                "ignored.");
        alertracker->RaiseAlert(globalref, NULL, mac_addr(), mac_addr(),
                mac_addr(), mac_addr(), "", 
                "Found httpd_username= and httpd_password= in global Kismet "
                "configs (kismet.conf or kismet_http.conf).  Make sure that this "
                "file is readable only by the user launching Kismet.  The "
                "username and password in ~/.kismet/kismet_http.conf will be "
                "ignored.");

        global_config = true;
    } 

    if (conf_username != conf_password && 
            (conf_username == "" || conf_password == "")) {
        _MSG("Found httpd_username= or httpd_password= in the global Kismet "
                "configs (kismet.conf or kismet_http.conf), but BOTH must "
                "be defined globally when using global configs", MSGFLAG_FATAL);
        globalreg->fatal_condition = 1;
    }

    user_httpd_config = new ConfigFile(globalreg);

    string conf_dir_path_raw = globalreg->kismet_config->FetchOpt("configdir");
    string config_dir_path = 
        globalreg->kismet_config->ExpandLogPath(conf_dir_path_raw, "", "", 0, 1);

    user_httpd_config_file = config_dir_path + "/" + "kismet_httpd.conf";

    if (!global_config) {
        userdir_login();
    }

    activated = true;

    auto websession = 
        Globalreg::FetchGlobalAs<Kis_Httpd_Websession>(globalreg, "WEBSESSION");

    httpd->RegisterSessionHandler(websession);
}

void Kis_Httpd_Websession::userdir_login() {
    struct stat buf;
    if (stat(user_httpd_config_file.c_str(), &buf) == 0) {
        user_httpd_config->ParseConfig(user_httpd_config_file.c_str());

        conf_username = user_httpd_config->FetchOpt("httpd_username");
        conf_password = user_httpd_config->FetchOpt("httpd_password");
    }

    bool update_conf = false;

    if (conf_username == "") {
        conf_username = "kismet";
        update_conf = true;
    }

    if (conf_password == "") {
        FILE *urandom = fopen("/dev/urandom", "rb");

        if (urandom == NULL) {
            _MSG("Failed to open /dev/urandom to seed random, unable to generate "
                    "the Kismet web admin password.", MSGFLAG_FATAL);
            globalreg->fatal_condition = 1;
            return;
        }

        uint32_t seed;

        if (fread(&seed, sizeof(uint32_t), 1, urandom) != 1) {
            _MSG("Failed to read /dev/urandom to seed random, unable to generate "
                    "the Kismet web admin password.", MSGFLAG_FATAL);
            globalreg->fatal_condition = 1;
            fclose(urandom);
            return;
        }

        fclose(urandom);

        srand(seed);

        string chars = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789";
        string genpw;

        for (unsigned int x = 0; x < 16; x++) {
            genpw += chars[rand() % chars.length()];
        }

        conf_password = genpw;

        update_conf = true;
    }


    if (update_conf) {
        user_httpd_config->SetOpt("httpd_username", conf_username, true);
        user_httpd_config->SetOpt("httpd_password", conf_password, true);
        user_httpd_config->SaveConfig(user_httpd_config_file.c_str());

        shared_ptr<Alertracker> alertracker = 
            Globalreg::FetchGlobalAs<Alertracker>(globalreg, "ALERTTRACKER");

        _MSG("Kismet has generated a random login for the web UI; it has been "
                "saved in " + user_httpd_config_file + ".", MSGFLAG_INFO);

        int newloginref;

        alertracker->DefineAlert("NEWHTTPDUSER", sat_second, 1, sat_second, 1);
        newloginref = alertracker->ActivateConfiguredAlert("NEWHTTPDUSER", 
                "This is the first time you have run Kismet on this account.  A "
                "new password has been automatically generated, and is in " +
                user_httpd_config_file + ".  You will need this password to configure "
                "Kismet from the web interface.");
                
        alertracker->RaiseAlert(newloginref, NULL, mac_addr(), mac_addr(),
                mac_addr(), mac_addr(), "", 
                "This is the first time you have run Kismet on this account.  A "
                "new password has been automatically generated, and is in " +
                user_httpd_config_file + ".  You will need this password to configure "
                "Kismet from the web interface.");

        // Generate a local-only message
        _MSG("*** Kismet has generated a random password for the web UI.  To "
                "log in, use user 'kismet' and password '" + conf_password + "'. "
                "You can view or change the web password in " + user_httpd_config_file,
                MSGFLAG_INFO | MSGFLAG_LOCAL);
    }
}

Kis_Httpd_Websession::~Kis_Httpd_Websession() {

}

void Kis_Httpd_Websession::set_login(string in_username, string in_password) {
    stringstream str;

    conf_username = in_username;
    conf_password = in_password;

    str << in_username << ":" << in_password;


}

bool Kis_Httpd_Websession::validate_login(struct MHD_Connection *connection) {
    char *user;
    char *pass = NULL;

    if (!activated)
        return false;

    user = MHD_basic_auth_get_username_password(connection, &pass);

    if (user == NULL || pass == NULL || 
            conf_username != user || conf_password != pass) {
        return false;
    }

    return true;
}

bool Kis_Httpd_Websession::Httpd_VerifyPath(const char *path, const char *method) {
    if (strcmp(method, "GET") != 0)
        return false;

    string stripped = Httpd_StripSuffix(path);

    if (stripped == "/session/check_login")
        return true;

    if (stripped == "/session/check_session")
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

    string stripped = Httpd_StripSuffix(url);

    if (stripped == "/session/check_session") {
        if (httpd->HasValidSession(connection, true)) {
            stream << "Valid session";
        }
    }

    if (stripped == "/session/check_login") {
        // Never use the session to validate the login, check it manually
        // and reject it 
        if (!validate_login(connection->connection)) {
            stream << "Invalid login";
            connection->httpcode = 403;
        } else {
            // Generate a session for the login, it's successful
            httpd->HasValidSession(connection, false);
            stream << "Valid login";
        }
    }

    return;
}

