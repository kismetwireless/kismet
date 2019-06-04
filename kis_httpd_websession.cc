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

Kis_Httpd_Websession::Kis_Httpd_Websession() :
    Kis_Net_Httpd_CPPStream_Handler() {

    activated = false;

    user_config = false;
    global_config = false;
}

void Kis_Httpd_Websession::Deferred_Startup() {
    local_locker l(&mutex);

    auto alertracker = Globalreg::FetchMandatoryGlobalAs<Alertracker>();

    global_config = false;
    user_config = false;

    user_httpd_config = new ConfigFile(Globalreg::globalreg);
    auto conf_dir_path_raw = 
        Globalreg::globalreg->kismet_config->FetchOptDfl("httpd_auth_file", 
                "%h/.kismet/kismet_httpd.conf");

    user_httpd_config_file = 
        Globalreg::globalreg->kismet_config->ExpandLogPath(conf_dir_path_raw, "", "", 0, 1);

    conf_username = Globalreg::globalreg->kismet_config->FetchOpt("httpd_username");
    conf_password = Globalreg::globalreg->kismet_config->FetchOpt("httpd_password");

    if (conf_username != "" || conf_password != "") {
        int globalref;

        alertracker->DefineAlert("GLOBALHTTPDUSER", sat_second, 1, sat_second, 1);
        globalref = alertracker->ActivateConfiguredAlert("GLOBALHTTPDUSER", 
                fmt::format("Found httpd_username= and httpd_password= in a global Kismet config "
                "file, such as kismet.conf or kismet_site.conf.  Any login in {} will be "
                "ignored.", user_httpd_config_file));
        alertracker->RaiseAlert(globalref, NULL, mac_addr(), mac_addr(),
                mac_addr(), mac_addr(), "", 
                fmt::format("Found httpd_username= and httpd_password= in a global Kismet config "
                "file, such as kismet.conf or kismet_site.conf.  Any login in {} will be "
                "ignored.", user_httpd_config_file));

        if (conf_username == "")
            conf_username = "kismet";

        if (conf_password == "") {
            _MSG_FATAL("Found httpd_username= in a global config file, but no httpd_password= "
                    "directive.  Either define a username and password globally, or remove "
                    "any httpd_username= options from the Kismet config files.");
            Globalreg::globalreg->fatal_condition = 1;
        }

        global_config = true;
    } 

    if (!global_config) {
        userdir_login();
    }

    // Fetch our own shared pointer 
    auto websession = 
        Globalreg::FetchMandatoryGlobalAs<Kis_Httpd_Websession>();

    httpd->RegisterSessionHandler(websession);

    // Register as not requiring a login for these endpoints
    httpd->RegisterUnauthHandler(this);

    activated = true;
}

void Kis_Httpd_Websession::userdir_login() {
    // Parse the config file in the user directory, if it exists
    struct stat buf;
    if (stat(user_httpd_config_file.c_str(), &buf) == 0) {
        user_httpd_config->ParseConfig(user_httpd_config_file.c_str());

        conf_username = user_httpd_config->FetchOpt("httpd_username");
        conf_password = user_httpd_config->FetchOpt("httpd_password");
    }

    // We use the user config - even if it's blank, we check that elsewhere
    user_config = true;

    if (conf_username == "") 
        conf_username = "kismet";

    if (conf_password == "")
        _MSG("This is the first time Kismet has been run as this user.  You will need to set an "
                "administrator password before you can use many features of Kismet.  Visit "
                "http://localhost:2501/ to configure the password, or consult the Kismet documentation "
                "to set a password manually.", MSGFLAG_INFO | MSGFLAG_LOCAL);
}

Kis_Httpd_Websession::~Kis_Httpd_Websession() {

}

void Kis_Httpd_Websession::set_login(std::string in_username, std::string in_password) {
    conf_username = in_username;
    conf_password = in_password;

    user_httpd_config->SetOpt("httpd_username", conf_username, true);
    user_httpd_config->SetOpt("httpd_password", conf_password, true);

    user_httpd_config->SaveConfig(user_httpd_config_file.c_str());
}

bool Kis_Httpd_Websession::validate_login(struct MHD_Connection *connection) {
    char *user;
    char *pass = nullptr;

    if (!activated)
        return false;

    // Don't allow blank passwords
    if (conf_username == "" || conf_password == "")
        return false;

    user = MHD_basic_auth_get_username_password(connection, &pass);

	constant_time_string_compare_ne compare;

    if (user == nullptr || pass == nullptr ||  compare(conf_username, user) || compare(conf_password, pass)) {
        if (user != nullptr) {
            free(user);
        }

        if (pass != nullptr) {
            free(pass);
        }

        return false;
    }

    if (user != nullptr) {
        free(user);
    }

    if (pass != nullptr) {
        free(pass);
    }

    return true;
}

bool Kis_Httpd_Websession::Httpd_VerifyPath(const char *path, const char *method) {
    std::string stripped = Httpd_StripSuffix(path);

    if (strcmp(method, "POST") == 0) {
        if (stripped == "/session/set_password")
            return true;
    } else if (strcmp(method, "GET") == 0) {
        if (stripped == "/session/check_login")
            return true;

        if (stripped == "/session/check_session")
            return true;

        if (stripped == "/session/check_setup_ok")
            return true;
    }

    return false;
}

void Kis_Httpd_Websession::Httpd_CreateStreamResponse(Kis_Net_Httpd *httpd,
        Kis_Net_Httpd_Connection *connection,
        const char *url, const char *method, const char *upload_data,
        size_t *upload_data_size, std::stringstream &stream) {

    if (strcmp(method, "GET") != 0) {
        return;
    }

    std::string stripped = Httpd_StripSuffix(url);

    if (stripped == "/session/check_session") {
        if (httpd->HasValidSession(connection, true)) {
            stream << "Valid session\n";
        }
    } else if (stripped == "/session/check_login") {
        local_locker l(&mutex);

        // Never use the session to validate the login, check it manually
        // and reject it 
        if (!validate_login(connection->connection)) {
            stream << "Invalid login\n";
            connection->httpcode = 403;
        } else {
            // Generate a session for the login, it's successful
            httpd->HasValidSession(connection, false);
            stream << "Valid login\n";
        }
    } else if (stripped == "/session/check_setup_ok") {
        if (global_config) {
            stream << "Login configured globally\n";
            connection->httpcode = 406;
        } else if (user_config && conf_password != "") {
            stream << "Login configured\n";
            connection->httpcode = 200;
        } else {
            stream << "Login not configured\n";
            connection->httpcode = 500;
        }
    }

    return;
}

int Kis_Httpd_Websession::Httpd_PostComplete(Kis_Net_Httpd_Connection *concls) {
    local_locker l(&mutex);

    auto stripped = kishttpd::StripSuffix(concls->url);

    if (stripped == "/session/set_password") {
        // Reject if we've got a global site config
        if (global_config) {
            concls->response_stream << "Login configured globally\n";
            concls->httpcode = 406;
            return MHD_YES;
        }

        // Require login if we've set the user config
        if (user_config && conf_password != "") {
            if (!httpd->HasValidSession(concls, true)) {
                return MHD_YES;
            }
        }

        // Look for user and pass
        std::string new_username;
        std::string new_password;

        if (concls->variable_cache.find("password") == concls->variable_cache.end()) {
            concls->response_stream << "password field required\n";
            concls->httpcode = 400;
            return MHD_YES;
        }

        new_password = concls->variable_cache["password"]->str();

        if (concls->variable_cache.find("username") != concls->variable_cache.end())
            new_username = concls->variable_cache["username"]->str();
        else
            new_username = conf_username;

        set_login(new_username, new_password);

        _MSG_INFO("A new administrator login has been set.");

        concls->response_stream << "Login changed.\n";
        concls->httpcode = 200;
        return MHD_YES;

    }

    concls->response_stream << "Unhandled request\n";
    concls->httpcode = 400;

    return MHD_YES;
}

