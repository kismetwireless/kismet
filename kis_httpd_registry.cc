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

#include "messagebus.h"
#include "configfile.h"
#include "kis_httpd_registry.h"

Kis_Httpd_Registry::Kis_Httpd_Registry(GlobalRegistry *in_globalreg) :
    Kis_Net_Httpd_CPPStream_Handler(), 
    LifetimeGlobal() {

    globalreg = in_globalreg;

    Bind_Httpd_Server();
}

Kis_Httpd_Registry::~Kis_Httpd_Registry() {
    local_locker lock(&reg_lock);

}

bool Kis_Httpd_Registry::register_js_module(std::string in_module, std::string in_path) {
    local_locker lock(&reg_lock);

    if (js_module_path_map.find(in_module) != js_module_path_map.end()) {
        _MSG_ERROR("HTTPD Module Registry: Module '{}' already registered",
                in_module);
        return false;
    }

    // Hack around for re-homing kismet resources; alert on a leading '/' and fix it.
    if (in_path.length() == 0) {
        _MSG_ERROR("HTTPD Module Registry: Module {} with no path", in_module);
        return false;
    }

    if (in_path[0] == '/') {
        _MSG_ERROR("HTTPD Module Registry: Module {} starts with a '/', for newer "
                "Kismet systems this should be a relative path; check that your plugin "
                "is updated.  Kismet will automatically make this a relative path.",
                in_module);
        in_path = in_path.substr(1, in_path.length());
    }

    js_module_path_map[in_module] = in_path;

    return true;
}

bool Kis_Httpd_Registry::Httpd_VerifyPath(const char *path, const char *method) {
    if (strcmp(method, "GET") != 0)
        return false;

    if (!Httpd_CanSerialize(path))
        return false;

    if (strcmp(path, "/dynamic.json") == 0)
        return true;

    return false;
}

void Kis_Httpd_Registry::Httpd_CreateStreamResponse(Kis_Net_Httpd *httpd,
        Kis_Net_Httpd_Connection *connection,
        const char *path, const char *method, const char *upload_data,
        size_t *upload_data_size, std::stringstream &stream) {

    if (strcmp(method, "GET") != 0)
        return;

    if (strcmp(path, "/dynamic.json") == 0) {
        stream << "{\"dynamicjs\": [";

        bool f = true;
        for (auto m : js_module_path_map) {
            if (f)
                f = false;
            else
                stream << ",";

            stream << "{\"js\": \"" << m.second << "\", ";
            stream << "\"module\": \"" << m.first << "\"}";
        }
    }

    stream << "] }" << std::endl;

    return;
}


