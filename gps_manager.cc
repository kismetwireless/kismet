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

#include "globalregistry.h"
#include "kis_net_microhttpd.h"
#include "messagebus.h"
#include "gps_manager.h"

GpsManager::GpsManager(GlobalRegistry *in_globalreg) {
    globalreg = in_globalreg;

    globalreg->InsertGlobal("GPS_MANAGER", this);

    httpd = (Kis_Net_Httpd *) globalreg->FetchGlobal("HTTPD_SERVER");
    httpd->RegisterHandler(this);

    pthread_mutex_init(&manager_locker, NULL);

    // Register the gps component
    _PCM(PACK_COMP_GPS) =
        globalreg->packetchain->RegisterPacketComponent("gps");

    // Register the packet chain hook
    globalreg->packetchain->RegisterHandler(&kis_gpspack_hook, this,
            CHAINPOS_POSTCAP, -100);
}

GpsManager::~GpsManager() {
    {
        local_locker lock(&manager_locker);
        globalreg->RemoveGlobal("GPS_MANAGER");
        httpd->RemoveHandler(this);

        map<string, gps_prototype *>::iterator i;
        for (i = prototype_map.begin(); i != prototype_map.end(); ++i) {
            delete i->second->builder;
            delete i->second;
        }

        globalreg->packetchain->RemoveHandler(&kis_gpspack_hook, CHAINPOS_POSTCAP);
    }

    pthread_mutex_destroy(&manager_locker);
}

void GpsManager::RegisterGpsPrototype(string in_name, string in_desc,
        Kis_Gps *in_builder,
        int in_priority) {
    local_locker lock(&manager_locker);

    string lname = StrLower(in_name);

    map<string, gps_prototype *>::iterator i = prototype_map.find(lname);

    if (i != prototype_map.end()) {
        _MSG("GpsManager tried to register GPS type " + in_name + " but it "
                "already exists", MSGFLAG_ERROR);
        return;
    }

    gps_prototype *proto = new gps_prototype();

    proto->type_name = in_name;
    proto->description = in_desc;
    proto->builder = in_builder;
    proto->priority = in_priority;

    prototype_map[lname] = proto;

    return;
}

void GpsManager::RemoveGpsPrototype(string in_name) {
    local_locker lock(&manager_locker);

    string lname = StrLower(in_name);
    map<string, gps_prototype *>::iterator i = prototype_map.find(lname);

    if (i == prototype_map.end())
        return;

    delete i->second->builder;
    delete i->second;
    prototype_map.erase(i);
}

int GpsManager::kis_gpspack_hook(CHAINCALL_PARMS) {
    // We're an 'external user' of gpsmanager despite being inside it,
    // so don't do thread locking - that's up to gpsmanager internals
    
    GpsManager *gpsmanager = (GpsManager *) auxdata;

    // Don't override if this packet already has a location, which could
    // come from a drone or from a PPI file
    if (in_pack->fetch(_PCM(PACK_COMP_GPS)) != NULL)
        return 1;

    kis_gps_packinfo *gpsloc = gpsmanager->GetBestLocation();

    if (gpsloc == NULL)
        return 0;

    in_pack->insert(_PCM(PACK_COMP_GPS), gpsloc);

    return 1;
}

bool GpsManager::Httpd_VerifyPath(const char *path, const char *method) {
    if (strcmp(method, "GET") != 0)
        return false;

    return false;
}

void GpsManager::Httpd_CreateStreamResponse(
        Kis_Net_Httpd *httpd __attribute__((unused)),
        struct MHD_Connection *connection __attribute__((unused)),
        const char *path, const char *method, 
        const char *upload_data __attribute__((unused)),
        size_t *upload_data_size __attribute__((unused)), 
        std::stringstream &stream) {

    return;
}

