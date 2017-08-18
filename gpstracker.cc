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
#include "gpstracker.h"
#include "kis_gps.h"
#include "configfile.h"

#include "gpsserial2.h"
#include "gpsgpsd2.h"
#include "gpsfake.h"
#include "gpsweb.h"

GpsTracker::GpsTracker(GlobalRegistry *in_globalreg) :
    Kis_Net_Httpd_CPPStream_Handler(in_globalreg) {

    globalreg = in_globalreg;

    // Register the gps component
    _PCM(PACK_COMP_GPS) =
        globalreg->packetchain->RegisterPacketComponent("gps");

    // Register the packet chain hook
    globalreg->packetchain->RegisterHandler(&kis_gpspack_hook, this,
            CHAINPOS_POSTCAP, -100);

    gps_prototypes.reset(new TrackerElement(TrackerVector));
    gps_prototypes_vec = TrackerElementVector(gps_prototypes);

    gps_instances.reset(new TrackerElement(TrackerVector));
    gps_instances_vec = TrackerElementVector(gps_instances);

    // Register the built-in GPS drivers
    register_gps_builder(SharedGpsBuilder(new GPSSerialV2Builder(globalreg)));
    register_gps_builder(SharedGpsBuilder(new GPSGpsdV2Builder(globalreg)));
    register_gps_builder(SharedGpsBuilder(new GPSFakeBuilder(globalreg)));
    register_gps_builder(SharedGpsBuilder(new GPSWebBuilder(globalreg)));

    // Process any gps options in the config file
    vector<string> gpsvec = globalreg->kismet_config->FetchOptVec("gps");
    for (auto g : gpsvec) {
        create_gps(g);
    }
}

GpsTracker::~GpsTracker() {
    local_eol_locker lock(&gpsmanager_mutex);

    globalreg->RemoveGlobal("GPSTRACKER");
    httpd->RemoveHandler(this);

    globalreg->packetchain->RemoveHandler(&kis_gpspack_hook, CHAINPOS_POSTCAP);
}

void GpsTracker::register_gps_builder(SharedGpsBuilder in_builder) {
    local_locker lock(&gpsmanager_mutex);

    for (auto x : gps_prototypes_vec) {
        SharedGpsBuilder gb = static_pointer_cast<KisGpsBuilder>(x);

        if (gb->get_gps_class() == in_builder->get_gps_class()) {
            _MSG("GPSTRACKER - tried to register a duplicate GPS driver for '" +
                    in_builder->get_gps_class() + "'", MSGFLAG_ERROR);
            return;
        }
    }

    gps_prototypes_vec.push_back(in_builder);
}

shared_ptr<KisGps> GpsTracker::create_gps(string in_definition) {
    local_locker lock(&gpsmanager_mutex);

    SharedGps gps;
    SharedGpsBuilder builder;

    size_t cpos = in_definition.find(":");
    string types;

    // Extract the type string
    if (cpos == string::npos) {
        types = in_definition;
    } else {
        types = in_definition.substr(0, cpos);
    }

    // Find a driver
    for (auto p : gps_prototypes_vec) {
        SharedGpsBuilder optbuilder = static_pointer_cast<KisGpsBuilder>(p);

        if (optbuilder->get_gps_class() == types) {
            builder = optbuilder;
            break;
        }
    }

    // Didn't find a builder... 
    if (builder == NULL) {
        _MSG("GPSTRACKER - Failed to find driver for gps type '" + types + "'",
                MSGFLAG_ERROR);
        return NULL;
    }

    // If it's a singleton make sure we don't have something built already
    if (builder->get_singleton()) {
        for (auto d : gps_instances_vec) {
            SharedGps igps = static_pointer_cast<KisGps>(d);

            if (igps->get_gps_prototype()->get_gps_class() == types) {
                _MSG("GPSTRACKER - Already defined a GPS of type '" + types + "', this "
                        "GPS driver cannot be defined multiple times.", MSGFLAG_ERROR);
                return NULL;
            }
        }
    }

    // Fetch an instance
    gps = builder->build_gps(builder);

    // Open it
    if (!gps->open_gps(in_definition)) {
        _MSG("GPSTRACKER - Failed to open GPS '" + gps->get_gps_name() + "'", MSGFLAG_ERROR);
        return NULL;
    }

    // Add it to the running GPS list
    gps_instances_vec.push_back(gps);

    return gps;
}

kis_gps_packinfo *GpsTracker::get_best_location() {
    local_locker lock(&gpsmanager_mutex);

    kis_gps_packinfo *location = NULL;

    for (auto d : gps_instances_vec) {

    }

    return location;
}

int GpsTracker::kis_gpspack_hook(CHAINCALL_PARMS) {
    // We're an 'external user' of GpsTracker despite being inside it,
    // so don't do thread locking - that's up to GpsTracker internals
    
    GpsTracker *gpstracker = (GpsTracker *) auxdata;

    // Don't override if this packet already has a location, which could
    // come from a drone or from a PPI file
    if (in_pack->fetch(_PCM(PACK_COMP_GPS)) != NULL)
        return 1;

    kis_gps_packinfo *gpsloc = gpstracker->get_best_location();

    if (gpsloc == NULL)
        return 0;

    // Insert into chain; we were given a new location
    in_pack->insert(_PCM(PACK_COMP_GPS), gpsloc);

    return 1;
}

bool GpsTracker::Httpd_VerifyPath(const char *path, const char *method) {
    if (strcmp(method, "GET") != 0)
        return false;

    return false;
}

void GpsTracker::Httpd_CreateStreamResponse(
        Kis_Net_Httpd *httpd __attribute__((unused)),
        Kis_Net_Httpd_Connection *connection __attribute__((unused)),
        const char *path, const char *method, 
        const char *upload_data __attribute__((unused)),
        size_t *upload_data_size __attribute__((unused)), 
        std::stringstream &stream) {

    return;
}

