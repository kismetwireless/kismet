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

#include "globalregistry.h"
#include "kis_mutex.h"
#include "kis_net_beast_httpd.h"
#include "trackedelement.h"

/* Central registration system for providing dynamic JS modules to the web ui.
 *
 * Dynamic modules are processed by the plugin manager which will notify
 * the registry of modules registered via a plugin manifest
 *
 */

class kis_httpd_registry : public lifetime_global {
public:
    static std::string global_name() { return "WEBREGISTRY"; }

    static std::shared_ptr<kis_httpd_registry> 
        create_http_registry() {
            std::shared_ptr<kis_httpd_registry> mon(new kis_httpd_registry());
            Globalreg::globalreg->register_lifetime_global(mon);
            Globalreg::globalreg->insert_global(global_name(), mon);
            return mon;
    }

private:
    kis_httpd_registry();

public:
    ~kis_httpd_registry();

    // Register a javascript module
    virtual bool register_js_module(std::string in_module, std::string in_path);

protected:
    kis_mutex reg_lock;

    global_registry *globalreg;

    bool allow_userplugins;

    std::map<std::string, std::string> js_module_path_map;
};

#endif

