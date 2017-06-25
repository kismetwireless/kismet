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

#include <pthread.h>

#include "messagebus.h"
#include "configfile.h"
#include "kis_httpd_registry.h"

Kis_Httpd_Registry::Kis_Httpd_Registry(GlobalRegistry *in_globalreg) :
    Kis_Net_Httpd_CPPStream_Handler(in_globalreg), 
    LifetimeGlobal() {

    globalreg = in_globalreg;

    pthread_mutexattr_t mutexattr;
    pthread_mutexattr_init(&mutexattr);
    pthread_mutexattr_settype(&mutexattr, PTHREAD_MUTEX_RECURSIVE);
    pthread_mutex_init(&reg_lock, &mutexattr);

}

Kis_Httpd_Registry::~Kis_Httpd_Registry() {
    local_eol_locker lock(&reg_lock);

    pthread_mutex_destroy(&reg_lock);
}

bool Kis_Httpd_Registry::register_js_module(string in_module, string in_path) {
    local_locker lock(&reg_lock);

    if (js_module_path_map.find(in_module) != js_module_path_map.end()) {
        _MSG("HTTPD Module Registry: Module '" + in_module + "' already "
                "registered", MSGFLAG_ERROR);
        return false;
    }

    js_module_path_map.emplace(in_module, in_path);

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

    stream << "] }" << endl;

    return;
}


