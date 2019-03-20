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

#ifndef __KIS_HTTPD_REGISTRY_H__
#define __KIS_HTTPD_REGISTRY_H__

#include "config.h"

#include <string>

#include "kis_mutex.h"
#include "trackedelement.h"
#include "kis_net_microhttpd.h"
#include "globalregistry.h"

/* Central registration system for providing dynamic JS modules to the web ui.
 *
 * Dynamic modules are processed by the plugin manager which will notify
 * the registry of modules registered via a plugin manifest
 *
 */

class Kis_Httpd_Registry : public Kis_Net_Httpd_CPPStream_Handler, 
    public LifetimeGlobal {
public:
    static std::string global_name() { return "WEBREGISTRY"; }

    static std::shared_ptr<Kis_Httpd_Registry> 
        create_http_registry(GlobalRegistry *in_globalreg) {
            std::shared_ptr<Kis_Httpd_Registry> mon(new Kis_Httpd_Registry(in_globalreg));
            in_globalreg->RegisterLifetimeGlobal(mon);
            in_globalreg->InsertGlobal(global_name(), mon);
            return mon;
    }

private:
    Kis_Httpd_Registry(GlobalRegistry *in_globalreg);

public:
    ~Kis_Httpd_Registry();

    // Register a javascript module
    virtual bool register_js_module(std::string in_module, std::string in_path);

    virtual bool Httpd_VerifyPath(const char *path, const char *method);

    virtual void Httpd_CreateStreamResponse(Kis_Net_Httpd *httpd,
            Kis_Net_Httpd_Connection *connection,
            const char *url, const char *method, const char *upload_data,
            size_t *upload_data_size, std::stringstream &stream);

protected:
    kis_recursive_timed_mutex reg_lock;

    GlobalRegistry *globalreg;

    bool allow_userplugins;

    std::map<std::string, std::string> js_module_path_map;
};

#endif

