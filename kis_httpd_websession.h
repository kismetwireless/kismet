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

#ifndef __KIS_HTTPD_WEBSESSION_H__
#define __KIS_HTTPD_WEBSESSION_H__

#include "config.hpp"

#include <string>
#include "trackedelement.h"
#include "kis_net_microhttpd.h"
#include "globalregistry.h"

// We need to subclass the HTTPD handler directly because even though we can
// generally act like a stream, we need to be able to directly manipulate the
// response header
class Kis_Httpd_Websession : public Kis_Net_Httpd_CPPStream_Handler, 
    public LifetimeGlobal {
public:
    static shared_ptr<Kis_Httpd_Websession> 
        create_websession(GlobalRegistry *in_globalreg) {
        shared_ptr<Kis_Httpd_Websession> mon(new Kis_Httpd_Websession(in_globalreg));
        in_globalreg->RegisterLifetimeGlobal(mon);
        in_globalreg->InsertGlobal("WEBSESSION", mon);
        return mon;
    }

private:
    Kis_Httpd_Websession(GlobalRegistry *in_globalreg);

public:
    ~Kis_Httpd_Websession();

    virtual void activate_config();

    virtual bool Httpd_VerifyPath(const char *path, const char *method);

    virtual void Httpd_CreateStreamResponse(Kis_Net_Httpd *httpd,
            Kis_Net_Httpd_Connection *connection,
            const char *url, const char *method, const char *upload_data,
            size_t *upload_data_size, std::stringstream &stream);

    virtual void set_login(string in_username, string in_password);

    // Live-check a session login
    virtual bool validate_login(struct MHD_Connection *connection);

    // Get current l/p
    string get_username() { return conf_username; }
    string get_password() { return conf_password; }

protected:
    bool activated; 

    void userdir_login();

    GlobalRegistry *globalreg;

    string user_httpd_config_file;
    ConfigFile *user_httpd_config;

    bool global_config;
    string conf_username;
    string conf_password;

};

#endif

