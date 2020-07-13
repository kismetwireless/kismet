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

#include "config.h"

#include <string>
#include "trackedelement.h"
#include "kis_net_microhttpd.h"
#include "globalregistry.h"

// We need to subclass the HTTPD handler directly because even though we can
// generally act like a stream, we need to be able to directly manipulate the
// response header
class kis_httpd_websession : public kis_net_httpd_cppstream_handler, 
    public lifetime_global, public deferred_startup {
public:
    static std::string global_name() { return "WEBSESSION"; }

    static std::shared_ptr<kis_httpd_websession> 
        create_websession() {
        std::shared_ptr<kis_httpd_websession> mon(new kis_httpd_websession());
        Globalreg::globalreg->register_lifetime_global(mon);
        Globalreg::globalreg->register_deferred_global(mon);
        Globalreg::globalreg->insert_global(global_name(), mon);
        return mon;
    }

private:
    kis_httpd_websession();

public:
    ~kis_httpd_websession();

    virtual void trigger_deferred_startup() override;
    virtual void trigger_deferred_shutdown() override { };

    virtual bool httpd_verify_path(const char *path, const char *method) override;

    virtual void httpd_create_stream_response(kis_net_httpd *httpd,
            kis_net_httpd_connection *connection,
            const char *url, const char *method, const char *upload_data,
            size_t *upload_data_size, std::stringstream &stream) override;

    virtual KIS_MHD_RETURN httpd_post_complete(kis_net_httpd_connection *concls) override;

    virtual void set_login(std::string in_username, std::string in_password);

    // Live-check a session login
    virtual bool validate_login(struct MHD_Connection *connection);

    // Get current l/p
    std::string get_username() { return conf_username; }
    std::string get_password() { return conf_password; }

protected:
    kis_recursive_timed_mutex mutex;

    bool activated; 

    void userdir_login();

    bool global_config;
    bool user_config;

    std::string user_httpd_config_file;
    config_file *user_httpd_config;

    std::string conf_username;
    std::string conf_password;
};

#endif

