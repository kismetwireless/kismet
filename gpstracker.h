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

#ifndef __GPSTRACKER_H__
#define __GPSTRACKER_H__

#include "config.h"


#include "kis_mutex.h"
#include "packetchain.h"
#include "globalregistry.h"
#include "kis_net_microhttpd.h"
#include "trackedlocation.h"

class KisGpsBuilder;
typedef std::shared_ptr<KisGpsBuilder> SharedGpsBuilder;

class KisGps;
typedef std::shared_ptr<KisGps> SharedGps;

// Packet info attached to each packet, if there isn't already GPS info present
class kis_gps_packinfo : public packet_component {
public:
	kis_gps_packinfo() {
		self_destruct = 1;
        lat = lon = alt = speed = heading = 0;
        precision = 0;
		fix = 0;
        tv.tv_sec = 0;
        tv.tv_usec = 0;
        error_x = 0;
        error_y = 0;
        error_v = 0;
	}

    kis_gps_packinfo(kis_gps_packinfo *src) {
        if (src != NULL) {
            self_destruct = src->self_destruct;

            lat = src->lat;
            lon = src->lon;
            alt = src->alt;
            speed = src->speed;
            heading = src->heading;
            precision = src->precision;
            fix = src->fix;
            tv.tv_sec = src->tv.tv_sec;
            tv.tv_usec = src->tv.tv_usec;
            gpsuuid = src->gpsuuid;
            gpsname = src->gpsname;
        }
    }

    std::shared_ptr<kis_tracked_location_triplet> as_tracked_triplet() {
        std::shared_ptr<kis_tracked_location_triplet> r =
            std::make_shared<kis_tracked_location_triplet>();

        r->set_lat(lat);
        r->set_lon(lon);
        r->set_alt(alt);
        r->set_speed(speed);
        r->set_heading(heading);
        r->set_fix(fix);
        r->set_valid(fix >= 2);
        r->set_error_x(error_x);
        r->set_error_y(error_y);
        r->set_error_v(error_v);
        r->set_time_sec(tv.tv_sec);
        r->set_time_usec(tv.tv_usec);

        return r;
    }

    double lat;
    double lon;
    double alt;
    double speed;
    double heading;

    // If we know it, how accurate our location is, in meters
    double precision;

    // If we know it, 2d vs 3d fix
    int fix;

    // If we know error values...
    double error_x, error_y, error_v;

    struct timeval tv;

    // GPS that created us
    uuid gpsuuid;

    // Name of GPS that created us
    std::string gpsname;
};

/* GPS manager which handles configuring GPS sources and deciding which one
 * is going to be used */
class GpsTracker : public Kis_Net_Httpd_CPPStream_Handler, public LifetimeGlobal {
public:
    static std::string global_name() { return "GPSTRACKER"; }

    static std::shared_ptr<GpsTracker> create_gpsmanager() {
        std::shared_ptr<GpsTracker> mon(new GpsTracker());
        Globalreg::globalreg->RegisterLifetimeGlobal(mon);
        Globalreg::globalreg->InsertGlobal(global_name(), mon);
        return mon;
    }

private:
    GpsTracker();

public:
    virtual ~GpsTracker();

    virtual bool Httpd_VerifyPath(const char *path, const char *method);

    virtual void Httpd_CreateStreamResponse(Kis_Net_Httpd *httpd,
            Kis_Net_Httpd_Connection *connection,
            const char *url, const char *method, const char *upload_data,
            size_t *upload_data_size, std::stringstream &stream);

    // Register a gps builer prototype
    void register_gps_builder(SharedGpsBuilder in_builder);

    // Create a GPS from a definition string
    std::shared_ptr<KisGps> create_gps(std::string in_definition);

    // Remove a GPS by UUID
    bool remove_gps(uuid in_uuid);

    // Set a primary GPS
    bool set_primary_gps(uuid in_uuid);

    // Get the 'best' location - returns a NEW gpspackinfo which the caller is 
    // responsible for deleting.
    kis_gps_packinfo *get_best_location();

    // Populate packets that don't have a GPS location
    static int kis_gpspack_hook(CHAINCALL_PARMS);

protected:
    kis_recursive_timed_mutex gpsmanager_mutex;

    std::shared_ptr<TrackerElementVector> gps_prototypes_vec;

    // GPS instances, as a vector, sorted by priority; we don't mind doing a 
    // linear search because we'll typically have very few GPS devices
    std::shared_ptr<TrackerElementVector> gps_instances_vec;

    // Extra field we insert into a location triplet
    int tracked_uuid_addition_id;

    // Logging function
    void log_snapshot_gps();

    // Do we log to the Kismet log?
    bool database_logging;
    // Timer for logging GPS path as a snapshot
    int log_snapshot_timer;

    int pack_comp_gps;
};

#endif

